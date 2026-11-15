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

use crate::monitors::MonitorChoice;
use crate::net::{self, ConnectParams};
use crate::session::{ConnectionState, TransportEndpoints, CONTROL_QUEUE_DEPTH, INPUT_QUEUE_DEPTH};
use directdesk_shared::protocol::InputMsg;

/// Stream capabilities advertised on every connect. Fixed for now; the host
/// clamps to what it can actually encode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// Ask hosts to stream their system audio.
    ///
    /// Default **true**, and the asymmetry with the host's default is
    /// deliberate rather than an oversight. On the host, *offering* audio is
    /// the deploy risk: it opens a capture stream on somebody's machine, so it
    /// stays off until an operator turns it on. On the client, *asking* costs
    /// nothing — the host's Hello reply is the intersection, so a host that
    /// lacks the feature, or has it switched off, simply never echoes the bit
    /// and never sends a datagram. Defaulting this to false would mean every
    /// user of an audio-enabled host had to find a second switch to get the
    /// feature the operator already turned on.
    pub system_audio: bool,
    /// Which outputs to ask the host for. Default `Primary` — a single
    /// stream, exactly today's behaviour; `Second`/`Both` take effect only
    /// once the host echoes `features::MULTI_MONITOR` and reports a second
    /// output, and degrade to the primary (with a note) when it does not.
    /// Seeded from [`crate::config::ClientConfig::monitor_choice`] and
    /// updated live by [`ConnectSupervisor::set_monitor_choice`].
    pub monitor_choice: MonitorChoice,
    /// Offer `features::MULTI_MONITOR` in the `Hello` at all.
    ///
    /// Default **true**: today's desktop client offers the bit unconditionally
    /// (see `ConnectParams::hello_features` for why that is deliberate). A
    /// client that can only ever show one window — a phone — clears it, so the
    /// host never sends a `MonitorList`, the handshake skips the selection
    /// exchange, and no second stream can ever be armed, whatever
    /// [`monitor_choice`](Self::monitor_choice) says.
    pub multi_monitor: bool,
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
            system_audio: true,
            monitor_choice: MonitorChoice::default(),
            multi_monitor: true,
        }
    }
}

impl StreamCaps {
    /// The preset for a touch device (Android): one window, no audio
    /// playback path, no lossless tiles, and a 30 fps ceiling to spare the
    /// battery and the hardware decoder. Everything else as [`Default`].
    pub fn touch_device() -> Self {
        Self {
            system_audio: false,
            lossless_tiles: false,
            multi_monitor: false,
            preferred_fps: 30,
            ..Self::default()
        }
    }
}

/// Everything the UI needs to describe a connection attempt; the supervisor
/// turns it into a [`ConnectParams`] together with its fixed [`StreamCaps`].
#[derive(Debug, Clone)]
pub struct ConnectRequest {
    pub host: String,
    pub udp_port: u16,
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
            pairing_code: self.pairing_code,
            display_name: self.display_name,
            quality: self.quality,
            max_width: caps.max_width,
            max_height: caps.max_height,
            preferred_fps: caps.preferred_fps,
            lossless_tiles: caps.lossless_tiles,
            system_audio: caps.system_audio,
            monitor_choice: caps.monitor_choice,
            multi_monitor: caps.multi_monitor,
        }
    }
}

/// A live `run_client` task and the switch that stops it.
struct Active {
    shutdown: watch::Sender<bool>,
    join: JoinHandle<()>,
}

/// A cloneable, thread-safe way to stop the connection the supervisor has
/// installed, for a thread that cannot borrow the supervisor: the touch
/// profile's background watchdog, which runs exactly when the UI thread does
/// not (Android has dropped the window, so no `disconnect` can happen there).
///
/// [`shut_down`](Self::shut_down) raises the same per-connection shutdown
/// watch [`ConnectSupervisor::disconnect`] raises, so the driver closes
/// gracefully (`Bye` to the host) and does not reconnect. It leaves the
/// supervisor's own bookkeeping to the UI thread: the next
/// [`ConnectSupervisor::connect`] or `disconnect` replaces it as usual.
#[derive(Clone, Default)]
pub struct DisconnectHandle {
    installed: Arc<parking_lot::Mutex<Option<watch::Sender<bool>>>>,
}

impl DisconnectHandle {
    /// A driver is installed, has not returned, and nobody has asked it to
    /// stop. `run_client` holds the only receiver, so a closed watch means
    /// it has exited.
    pub fn is_running(&self) -> bool {
        self.installed
            .lock()
            .as_ref()
            .is_some_and(|tx| !tx.is_closed() && !*tx.borrow())
    }

    /// Ask the installed driver to stop. `None` when nothing was running.
    pub fn shut_down(&self) -> Option<StoppingDriver> {
        let installed = self.installed.lock();
        let tx = installed
            .as_ref()
            .filter(|tx| !tx.is_closed() && !*tx.borrow())?;
        tx.send_replace(true);
        Some(StoppingDriver(tx.clone()))
    }

    fn install(&self, shutdown: Option<watch::Sender<bool>>) {
        *self.installed.lock() = shutdown;
    }
}

/// A driver [`DisconnectHandle::shut_down`] stopped, to wait out its graceful
/// close independently of whatever the supervisor installs next.
pub struct StoppingDriver(watch::Sender<bool>);

impl StoppingDriver {
    pub fn has_exited(&self) -> bool {
        self.0.is_closed()
    }
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
    audio_tx: crossbeam_channel::Sender<directdesk_shared::audio::AudioFrame>,
    /// The second monitor's frames. Held for the app's lifetime like every
    /// other inbound sender, even for the (overwhelmingly common) sessions
    /// that never negotiate a second stream: the UI's `video2_rx` must not see
    /// a closed channel just because this connection is single-monitor.
    video2_tx: crossbeam_channel::Sender<EncodedFrame>,

    // Outbound (UI -> transport). The pumps forward to whichever sender is
    // installed here; `None` means "no active connection, drop the message".
    input_target: watch::Sender<Option<mpsc::Sender<InputMsg>>>,
    control_target: watch::Sender<Option<mpsc::Sender<ControlMsg>>>,

    current: Option<Active>,
    /// Mirrors `current`'s shutdown switch for other threads.
    handle: DisconnectHandle,
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
            audio_tx,
            video2_tx,
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
            audio_tx,
            video2_tx,
            input_target,
            control_target,
            current: None,
            handle: DisconnectHandle::default(),
        }
    }

    /// True while a `run_client` task is installed (connecting, connected, or
    /// reconnecting). Cleared by [`disconnect`](Self::disconnect).
    pub fn is_connected(&self) -> bool {
        self.current.is_some()
    }

    /// A handle that can stop whichever connection is installed, from any
    /// thread. See [`DisconnectHandle`].
    pub fn disconnect_handle(&self) -> DisconnectHandle {
        self.handle.clone()
    }

    /// Update the fps the *next* `connect()` carries (a fresh connect, or a
    /// reconnect after a drop). Does not touch a currently-live connection —
    /// applying a choice live is the UI's job, by re-sending `StartStream`
    /// directly on the session's control channel.
    pub fn set_preferred_fps(&mut self, fps: u32) {
        self.caps.preferred_fps = fps;
    }

    /// Whether connects offer `MULTI_MONITOR` at all. When they do not (the
    /// touch preset), no `MonitorList` can ever arrive, so the UI hides the
    /// monitor picker rather than offer a choice that can only degrade.
    pub fn offers_multi_monitor(&self) -> bool {
        self.caps.multi_monitor
    }

    /// Update the monitor choice the *next* `connect()` carries, for the same
    /// reason and with the same scope as [`set_preferred_fps`](Self::set_preferred_fps):
    /// it does not touch a currently-live connection. Calling it is what makes
    /// `run_client`'s own internal reconnect re-negotiate the operator's
    /// latest choice rather than the one in effect when the driver started.
    ///
    /// # Why the mid-session re-send is not here
    ///
    /// `ControlMsg::SelectMonitors` is idempotent and re-sendable at any time,
    /// and the path for it already exists end to end: the UI's
    /// `ClientSession::send_control` feeds the outbound pump below, which
    /// hands it to whichever connection is live. What the supervisor does
    /// *not* have is the one fact that makes such a send safe — whether this
    /// session negotiated `features::MULTI_MONITOR`. That answer lives where
    /// the host's `MonitorList` lands (the UI's inbound control lane), and the
    /// gate is load-bearing rather than tidy: `SelectMonitors` is an appended
    /// discriminant, so a host that predates the feature does not skip it, it
    /// fails `decode_strict` and the control stream dies. So the send stays
    /// with the code that can prove the bit came back mutual, and the
    /// supervisor keeps only the reconnect-scoped choice.
    ///
    /// (The proof that a `SelectMonitors` sent that way does reach the live
    /// connection is `a_mid_session_selection_reaches_the_live_connection`.)
    pub fn set_monitor_choice(&mut self, choice: MonitorChoice) {
        self.caps.monitor_choice = choice;
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
            audio_tx: self.audio_tx.clone(),
            video2_tx: self.video2_tx.clone(),
            input_rx,
            control_rx: control_out_rx,
        };

        let params = request.into_params(self.caps);
        let store = self.store.clone();
        let (shutdown, shutdown_rx) = watch::channel(false);
        self.handle.install(Some(shutdown.clone()));
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
        self.handle.install(None);
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
        self.handle.install(None);
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

    /// The client asks for system audio by default and carries the ask into
    /// [`ConnectParams`]. Pinned because the default is a deliberate asymmetry
    /// with the host's (which is off): asking costs nothing, offering does.
    #[test]
    fn the_client_asks_for_system_audio_by_default_and_threads_it_through() {
        let caps = StreamCaps::default();
        assert!(caps.system_audio, "asking costs nothing; the host decides");
        let params = request().into_params(caps);
        assert!(params.system_audio);

        // And a client that declines carries the decline, so the Hello bit is
        // driven by the caps and nothing else.
        let quiet = StreamCaps {
            system_audio: false,
            ..StreamCaps::default()
        };
        assert!(!request().into_params(quiet).system_audio);
    }

    /// The desktop default is pinned field by field, so adding `multi_monitor`
    /// (or anything after it) cannot silently change what a Windows client
    /// asks for; and its `Hello` offer is exactly today's three bits.
    #[test]
    fn the_default_caps_and_their_hello_offer_are_unchanged() {
        use directdesk_shared::protocol::features;

        assert_eq!(
            StreamCaps::default(),
            StreamCaps {
                max_width: 3840,
                max_height: 2160,
                preferred_fps: 0,
                lossless_tiles: true,
                system_audio: true,
                monitor_choice: MonitorChoice::Primary,
                multi_monitor: true,
            }
        );
        assert_eq!(
            request()
                .into_params(StreamCaps::default())
                .hello_features(false),
            features::LOSSLESS_TILES | features::SYSTEM_AUDIO | features::MULTI_MONITOR
        );
    }

    /// The touch preset declines every optional layer in the `Hello` itself —
    /// asked through the real `into_params` + `hello_features`, not a copy —
    /// and differs from the default only where it says it does.
    #[test]
    fn touch_device_offers_no_audio_tiles_or_monitors() {
        use directdesk_shared::protocol::features;

        let touch = StreamCaps::touch_device();
        assert_eq!(
            touch,
            StreamCaps {
                system_audio: false,
                lossless_tiles: false,
                multi_monitor: false,
                preferred_fps: 30,
                ..StreamCaps::default()
            }
        );

        let params = request().into_params(touch);
        assert_eq!(params.preferred_fps, 30);
        let bits = params.hello_features(false);
        assert_eq!(bits & features::SYSTEM_AUDIO, 0, "no audio offer");
        assert_eq!(bits & features::LOSSLESS_TILES, 0, "no tiles offer");
        assert_eq!(bits & features::MULTI_MONITOR, 0, "no monitors offer");
        assert_eq!(bits, 0, "nothing else is offered either");
        // Pairing stays orthogonal to the caps.
        assert_eq!(
            params.hello_features(true),
            crate::net::FEATURE_PAIRING_REQUEST
        );
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

    /// The handle stops the installed driver from another thread through the
    /// driver's own shutdown watch, once, and reports when it has exited.
    #[test]
    fn the_disconnect_handle_stops_the_installed_driver_from_another_thread() {
        let handle = DisconnectHandle::default();
        assert!(!handle.is_running(), "nothing installed");
        assert!(handle.shut_down().is_none());

        // Stand-in for `run_client`: it owns the only receiver.
        let (tx, mut rx) = watch::channel(false);
        handle.install(Some(tx));
        assert!(handle.is_running());

        let remote = handle.clone();
        let stopping = std::thread::spawn(move || remote.shut_down())
            .join()
            .unwrap()
            .expect("a running driver was stopped");
        assert!(*rx.borrow_and_update(), "the driver sees the shutdown");
        assert!(!handle.is_running(), "asked to stop: no longer running");
        assert!(handle.shut_down().is_none(), "never asked twice");
        assert!(!stopping.has_exited());
        drop(rx); // `run_client` returns
        assert!(stopping.has_exited());
    }

    /// The supervisor keeps the handle pointing at exactly the driver it has
    /// installed: a new one on connect, none after disconnect.
    #[test]
    fn the_disconnect_handle_follows_connect_and_disconnect() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (_session, mut sup) = supervisor(&rt);
        let handle = sup.disconnect_handle();
        sup.connect(request());
        let first = handle.installed.lock().clone().expect("installed");
        sup.connect(request());
        let second = handle.installed.lock().clone().expect("installed");
        assert!(
            !first.same_channel(&second),
            "a reconnect installs a new driver"
        );
        assert!(*first.borrow(), "the replaced driver was told to stop");
        sup.disconnect();
        assert!(handle.installed.lock().is_none());
        assert!(!handle.is_running());
        assert!(handle.shut_down().is_none());
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

    /// The mid-session re-selection path, end to end through the seam the UI
    /// actually uses: `ClientSession::send_control` -> the app-lifetime pump ->
    /// the currently-installed connection. Pinned here because milestone C3
    /// reopens/closes the second window by re-sending `SelectMonitors` on it,
    /// and because the *other* half of that contract — that nothing sends it
    /// unless the host echoed `MULTI_MONITOR` — is only defensible if the send
    /// itself is known to work without a reconnect.
    #[tokio::test]
    async fn a_mid_session_selection_reaches_the_live_connection() {
        let (src_tx, src_rx) = mpsc::channel::<ControlMsg>(16);
        let (target_tx, target_rx) = watch::channel(None);
        tokio::spawn(outbound_pump(src_rx, target_rx));

        let (dst_tx, mut dst_rx) = mpsc::channel::<ControlMsg>(16);
        target_tx.send(Some(dst_tx.clone())).unwrap();

        src_tx
            .send(ControlMsg::SelectMonitors { ids: vec![0, 1] })
            .await
            .unwrap();
        match dst_rx.recv().await.unwrap() {
            ControlMsg::SelectMonitors { ids } => assert_eq!(ids, vec![0, 1]),
            other => panic!("wrong message reached the session: {other:?}"),
        }

        // Dropping back to the primary is the same path, and must not need a
        // reconnect either (closing the second window uses it).
        src_tx
            .send(ControlMsg::SelectMonitors { ids: vec![0] })
            .await
            .unwrap();
        match dst_rx.recv().await.unwrap() {
            ControlMsg::SelectMonitors { ids } => assert_eq!(ids, vec![0]),
            other => panic!("wrong message reached the session: {other:?}"),
        }
    }

    /// The choice reaches `ConnectParams` — the only route by which the
    /// handshake can learn it — and a later `set_monitor_choice` is what the
    /// *next* connect carries.
    #[test]
    fn the_monitor_choice_rides_caps_into_connect_params() {
        let caps = StreamCaps::default();
        assert_eq!(
            caps.monitor_choice,
            MonitorChoice::Primary,
            "today's default"
        );
        assert_eq!(
            request().into_params(caps).monitor_choice,
            MonitorChoice::Primary
        );

        let rt = tokio::runtime::Runtime::new().unwrap();
        let (_session, mut sup) = supervisor(&rt);
        sup.set_monitor_choice(MonitorChoice::Both);
        assert_eq!(
            request().into_params(sup.caps).monitor_choice,
            MonitorChoice::Both,
            "the next connect must carry the operator's latest choice"
        );
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
