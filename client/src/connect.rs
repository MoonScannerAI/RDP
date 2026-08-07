//! Connect supervisor: turns the UI's connect / disconnect intent into a
//! spawned-or-cancelled [`net::run_client`] on a shared tokio runtime.
//!
//! # Why a supervisor at all
//!
//! [`net::run_client`] owns the *whole* connection lifecycle (connect, auth,
//! stream, reconnect-on-drop) and it consumes a [`TransportEndpoints`] by value —
//! including the two outbound `mpsc::Receiver`s, which cannot be cloned. A single
//! `run_client` therefore cannot be restarted on the same channels, yet the UI
//! must be able to connect, disconnect, and connect *again* (to a different host,
//! or after a failure) without restarting the app.
//!
//! The supervisor squares that circle without touching `net.rs`:
//!
//! * **Inbound** (transport → UI: video / stats / route / state / control) uses
//!   `crossbeam` senders, which *are* cloneable. The supervisor keeps the
//!   originals for the whole app lifetime (so the UI-side receivers never see a
//!   closed channel) and hands each `run_client` a fresh clone.
//! * **Outbound** (UI → transport: input / control) cannot be cloned on the
//!   receiver side, so two long-lived *pump* tasks own the UI's real receivers
//!   for the app's lifetime and forward every message to the *currently active*
//!   connection through a swappable [`watch`] target. Disconnecting sets the
//!   target to `None` (dropping the per-connection sender, which lets
//!   `run_client` observe its input channel close) and raises the per-connection
//!   shutdown watch; reconnecting mints a brand-new per-connection channel.
//!
//! Net effect: the UI keeps one stable [`ClientSession`] for its whole life, the
//! decode thread keeps its one `video_rx`, the keyboard hook keeps its one
//! `input_tx`, and `run_client` is spawned and cancelled underneath all of them.
//!
//! [`ClientSession`]: crate::session::ClientSession

use std::sync::Arc;

use directdesk_shared::crypto::storage::SecretStore;
use directdesk_shared::protocol::{ControlMsg, QualityMode};
use directdesk_shared::stats::{ConnStats, TransportRoute};
use directdesk_shared::video::EncodedFrame;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::net::{self, ConnectParams};
use crate::session::{ConnectionState, TransportEndpoints, CONTROL_QUEUE_DEPTH, INPUT_QUEUE_DEPTH};
use directdesk_shared::protocol::InputMsg;

/// Stream capabilities advertised on every connect. Fixed for now; the host
/// clamps to what it can actually encode.
#[derive(Debug, Clone, Copy)]
pub struct StreamCaps {
    pub max_width: u32,
    pub max_height: u32,
    pub preferred_fps: u32,
    /// Ask hosts for lossless refinement of settled screen regions.
    ///
    /// A request only — the host answers with the intersection, so a host that
    /// lacks the feature or has it switched off simply never opens the stream
    /// and nothing changes. Default **true**: unlike background capture there
    /// is no privacy or surprise cost, and against every host shipped so far it
    /// is a no-op.
    pub lossless_tiles: bool,
}

impl Default for StreamCaps {
    fn default() -> Self {
        Self {
            max_width: 3840,
            max_height: 2160,
            // 0 = "no preference, host decides". The host now honours this
            // field (clamped so a client can only *lower* its rate, never
            // raise it); a hardcoded 60 here would be a lie dressed up as a
            // preference — indistinguishable from the user actually asking
            // for 60. 0 preserves today's behaviour bit-for-bit.
            preferred_fps: 0,
            lossless_tiles: true,
        }
    }
}

/// Everything the UI needs to describe a connection attempt; the supervisor
/// turns it into a [`ConnectParams`] together with its fixed [`StreamCaps`].
#[derive(Debug, Clone)]
pub struct ConnectRequest {
    pub host: String,
    pub udp_port: u16,
    pub tcp_port: u16,
    pub display_name: String,
    /// `Some` selects pairing mode (first contact); `None` is steady-state auth.
    pub pairing_code: Option<String>,
    pub quality: QualityMode,
}

impl ConnectRequest {
    fn into_params(self, caps: StreamCaps) -> ConnectParams {
        ConnectParams {
            host: self.host,
            udp_port: self.udp_port,
            tcp_port: self.tcp_port,
            pairing_code: self.pairing_code,
            display_name: self.display_name,
            quality: self.quality,
            max_width: caps.max_width,
            max_height: caps.max_height,
            preferred_fps: caps.preferred_fps,
            lossless_tiles: caps.lossless_tiles,
        }
    }
}

/// A live `run_client` task and the switch that stops it.
struct Active {
    shutdown: watch::Sender<bool>,
    join: JoinHandle<()>,
}

/// Drives `net::run_client` on a shared runtime in response to UI intent.
pub struct ConnectSupervisor {
    rt: tokio::runtime::Handle,
    store: Arc<dyn SecretStore>,
    caps: StreamCaps,

    // Inbound (transport -> UI). Originals held for the app's lifetime so the
    // UI-side receivers stay open; a clone is handed to each `run_client`.
    video_tx: crossbeam_channel::Sender<EncodedFrame>,
    stats_tx: crossbeam_channel::Sender<ConnStats>,
    route_tx: crossbeam_channel::Sender<Option<TransportRoute>>,
    state_tx: crossbeam_channel::Sender<ConnectionState>,
    control_in_tx: crossbeam_channel::Sender<ControlMsg>,
    tiles_tx: crossbeam_channel::Sender<directdesk_shared::tiles::TileMsg>,

    // Outbound (UI -> transport). The pumps forward to whichever sender is
    // installed here; `None` means "no active connection, drop the message".
    input_target: watch::Sender<Option<mpsc::Sender<InputMsg>>>,
    control_target: watch::Sender<Option<mpsc::Sender<ControlMsg>>>,

    current: Option<Active>,
}

impl ConnectSupervisor {
    /// Build the supervisor from the transport half of a [`ClientSession`] and a
    /// runtime handle to spawn onto. Spawns the two long-lived outbound pumps.
    ///
    /// [`ClientSession`]: crate::session::ClientSession
    pub fn new(
        rt: tokio::runtime::Handle,
        store: Arc<dyn SecretStore>,
        transport: TransportEndpoints,
        caps: StreamCaps,
    ) -> Self {
        let TransportEndpoints {
            video_tx,
            stats_tx,
            route_tx,
            state_tx,
            control_tx: control_in_tx,
            tiles_tx,
            input_rx,
            control_rx,
        } = transport;

        let (input_target, input_target_rx) = watch::channel(None);
        let (control_target, control_target_rx) = watch::channel(None);
        rt.spawn(outbound_pump(input_rx, input_target_rx));
        rt.spawn(outbound_pump(control_rx, control_target_rx));

        Self {
            rt,
            store,
            caps,
            video_tx,
            stats_tx,
            route_tx,
            state_tx,
            control_in_tx,
            tiles_tx,
            input_target,
            control_target,
            current: None,
        }
    }

    /// True while a `run_client` task is installed (connecting, connected, or
    /// reconnecting). Cleared by [`disconnect`](Self::disconnect).
    pub fn is_connected(&self) -> bool {
        self.current.is_some()
    }

    /// Update the fps the *next* `connect()` carries (a fresh connect, or a
    /// reconnect after a drop). Does not touch a currently-live connection —
    /// applying a choice live is the UI's job, by re-sending `StartStream`
    /// directly on the session's control channel.
    pub fn set_preferred_fps(&mut self, fps: u32) {
        self.caps.preferred_fps = fps;
    }

    /// Spawn `run_client` for `request`, cancelling any prior attempt first so a
    /// reconnect never leaves two drivers racing over the outbound pumps.
    pub fn connect(&mut self, request: ConnectRequest) {
        self.cancel_current();

        // Fresh per-connection outbound channels; the pumps forward into these.
        let (input_tx, input_rx) = mpsc::channel(INPUT_QUEUE_DEPTH);
        let (control_out_tx, control_out_rx) = mpsc::channel(CONTROL_QUEUE_DEPTH);
        let _ = self.input_target.send(Some(input_tx));
        let _ = self.control_target.send(Some(control_out_tx));

        let endpoints = TransportEndpoints {
            video_tx: self.video_tx.clone(),
            stats_tx: self.stats_tx.clone(),
            route_tx: self.route_tx.clone(),
            state_tx: self.state_tx.clone(),
            control_tx: self.control_in_tx.clone(),
            tiles_tx: self.tiles_tx.clone(),
            input_rx,
            control_rx: control_out_rx,
        };

        let params = request.into_params(self.caps);
        let store = self.store.clone();
        let (shutdown, shutdown_rx) = watch::channel(false);
        let join = self
            .rt
            .spawn(net::run_client(endpoints, params, store, shutdown_rx));
        self.current = Some(Active { shutdown, join });
    }

    /// Cancel the active connection and return the UI to the disconnected state.
    ///
    /// Raises the graceful shutdown watch and releases the outbound routing so
    /// `run_client` observes its input channel close; then emits
    /// [`ConnectionState::Disconnected`] on the (supervisor-owned) state channel
    /// so the UI leaves the streaming view immediately.
    pub fn disconnect(&mut self) {
        if let Some(active) = self.current.take() {
            let _ = active.shutdown.send(true);
            let _ = self.input_target.send(None);
            let _ = self.control_target.send(None);
            // Detach: `run_client` exits on the shutdown signal within its own
            // graceful window; we must not block the UI thread joining it.
            drop(active.join);
        }
        let _ = self.route_tx.send(None);
        let _ = self.state_tx.send(ConnectionState::Disconnected);
    }

    /// Hard-cancel any in-flight attempt without emitting UI state. Used on
    /// reconnect (a new attempt is about to install fresh state) and on drop.
    fn cancel_current(&mut self) {
        if let Some(active) = self.current.take() {
            let _ = active.shutdown.send(true);
            active.join.abort();
        }
    }
}

impl Drop for ConnectSupervisor {
    fn drop(&mut self) {
        self.cancel_current();
    }
}

/// Forward every message from the UI's real outbound receiver to whichever
/// per-connection sender is currently installed. Lives for the app's lifetime;
/// exits when the UI drops its sender (channel closed), which happens on app
/// shutdown. A `None` target drops the message (no active connection).
async fn outbound_pump<T>(
    mut rx: mpsc::Receiver<T>,
    target: watch::Receiver<Option<mpsc::Sender<T>>>,
) where
    T: Send + 'static,
{
    while let Some(msg) = rx.recv().await {
        // Clone the Option<Sender> so no borrow is held across the send.
        let sender = target.borrow().clone();
        if let Some(tx) = sender {
            let _ = tx.try_send(msg);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::ClientSession;
    use directdesk_shared::crypto::storage::MemoryStore;
    use directdesk_shared::input::InputEvent;

    fn request() -> ConnectRequest {
        ConnectRequest {
            // A literal, unroutable address: `run_client` will fail fast without
            // reaching any real host, which is all these bookkeeping tests need.
            host: "127.0.0.1".into(),
            udp_port: 47990,
            tcp_port: 47991,
            display_name: "test-client".into(),
            pairing_code: None,
            quality: QualityMode::Balanced,
        }
    }

    fn supervisor(rt: &tokio::runtime::Runtime) -> (ClientSession, ConnectSupervisor) {
        let (session, transport) = ClientSession::new();
        let store: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
        let sup =
            ConnectSupervisor::new(rt.handle().clone(), store, transport, StreamCaps::default());
        (session, sup)
    }

    #[test]
    fn connect_then_disconnect_toggles_active_and_emits_disconnected() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (session, mut sup) = supervisor(&rt);

        assert!(!sup.is_connected(), "idle at construction");
        sup.connect(request());
        assert!(sup.is_connected(), "active after connect");

        sup.disconnect();
        assert!(!sup.is_connected(), "idle after disconnect");

        // Disconnect emits a terminal Disconnected state on the UI channel.
        let mut saw_disconnected = false;
        while let Ok(state) = session.state_rx.try_recv() {
            if state == ConnectionState::Disconnected {
                saw_disconnected = true;
            }
        }
        assert!(saw_disconnected, "UI must be told it is Disconnected");
        // Route is cleared so the UI shows "—".
        let mut last_route = Some(TransportRoute::DirectUdp);
        while let Ok(r) = session.route_rx.try_recv() {
            last_route = r;
        }
        assert_eq!(last_route, None);
    }

    #[test]
    fn reconnect_replaces_the_active_attempt() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (_session, mut sup) = supervisor(&rt);

        sup.connect(request());
        assert!(sup.is_connected());
        // A second connect without an intervening disconnect must not panic and
        // must leave exactly one active attempt installed.
        sup.connect(request());
        assert!(sup.is_connected());
        sup.disconnect();
        assert!(!sup.is_connected());
    }

    #[tokio::test]
    async fn outbound_pump_routes_only_to_the_installed_target() {
        let (src_tx, src_rx) = mpsc::channel::<InputMsg>(16);
        let (target_tx, target_rx) = watch::channel(None);
        tokio::spawn(outbound_pump(src_rx, target_rx));

        // Install a target *before* sending, so the pump is guaranteed to see it
        // when it reads the message: it is delivered. Keep a local clone of the
        // sender so clearing the target below does not close the channel (which
        // would make `recv` return `None` rather than genuinely time out).
        let (dst_tx, mut dst_rx) = mpsc::channel::<InputMsg>(16);
        target_tx.send(Some(dst_tx.clone())).unwrap();
        src_tx
            .send(InputMsg::Event(InputEvent::MouseMove { x: 1, y: 2 }))
            .await
            .unwrap();
        let got = dst_rx.recv().await.unwrap();
        assert!(
            matches!(got, InputMsg::Event(InputEvent::MouseMove { x: 1, y: 2 })),
            "installed target receives the message"
        );

        // Clear the target *before* sending: the message is dropped, not queued.
        target_tx.send(None).unwrap();
        src_tx.send(InputMsg::ReleaseAll).await.unwrap();
        let dropped =
            tokio::time::timeout(std::time::Duration::from_millis(150), dst_rx.recv()).await;
        assert!(dropped.is_err(), "a cleared target drops the message");
    }
}
