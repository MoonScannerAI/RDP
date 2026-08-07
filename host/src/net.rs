//! The host's QUIC listener: accept, pair, authenticate, stream, inject.
//!
//! # Shape
//!
//! One background tokio runtime owns everything here. [`NetService::start`]
//! spawns a single accept loop and returns a [`NetHandle`] the UI drives with
//! [`NetCommand`]s and observes through [`NetEvent`]s and a
//! [`StatusSnapshot`]. Nothing in this module touches egui, and nothing in the
//! UI touches quinn.
//!
//! # One client at a time
//!
//! A second connection is not silently queued: it is told `AuthFail { "host
//! busy" }` on the control stream and the connection is closed with reason
//! `busy`. (The contract says "Bye busy"; before authentication the control
//! stream carries [`AuthMsg`] under the [`MAX_AUTH_MSG`] cap, so a
//! `ControlMsg::Bye` there would be a decode error on a correct client. Same
//! meaning, correct framing.)
//!
//! # Handshake
//!
//! ```text
//! client                                            host
//!   |-- Hello ---------------------------------------->|  validate_hello
//!   |<- Hello ------------------------------------------|
//!   |<- AuthMsg::ServerChallenge { nonce_s } -----------|  always sent first
//!   |                                                   |
//!   |   (A) already paired                              |
//!   |-- ClientAuth { pub, sig(nonce_s) } -------------->|  checked against the
//!   |-- ClientChallenge { nonce_c } ------------------->|  trusted-client list
//!   |<- ServerAuth { sig(nonce_c) } --------------------|
//!   |<- AuthOk -----------------------------------------|
//!   |                                                   |
//!   |   (B) first contact, host has an armed code       |
//!   |-- PairStart { spake_a } ------------------------->|  burns the code
//!   |<- PairResponse { spake_b } -----------------------|
//!   |-- PairConfirm { mac_client } -------------------->|
//!   |<- PairConfirm { mac_host } -----------------------|
//!   |<- PairComplete { host identity } -----------------|
//!   |-- ClientAuth { pub, sig(nonce_s) } -------------->|  binds the key to
//!   |-- ClientChallenge { nonce_c } ------------------->|  this session, then
//!   |<- ServerAuth { sig(nonce_c) } --------------------|  it is persisted
//!   |<- AuthOk -----------------------------------------|
//! ```
//!
//! The single `ServerChallenge` is what makes both branches one protocol: the
//! client picks the branch by which message it answers with, and the key a
//! brand-new client gets trusted under is the one it just proved possession of
//! on this TLS session — not one asserted in a pairing message.
//!
//! # Video
//!
//! Control and input ride [`QuicSession`], which already does framing,
//! `Ping`/`Pong`, `Bye` and input validation. Video does **not**: the driver's
//! queue drops the *newest* frame when it is full, which is exactly backwards
//! for a live desktop. [`egress::video_pump`] instead coalesces the encoder's
//! backlog and sends only the freshest frame, then asks for an IDR because
//! dropping a P-frame breaks the reference chain.
//!
//! # Rules
//!
//! - Input is released on *every* exit path from a session (see
//!   [`ReleaseGuard`]) — normal close, timeout, panic in a pump, or a dropped
//!   connection. A stuck Ctrl key on an unattended machine is a security bug.
//! - Failed authentication is throttled per source IP and logged with the
//!   attempted identity's fingerprint. Codes, signatures and key material are
//!   never logged.
//! - The media pipeline outlives a client so the next one does not wait for
//!   D3D11 and Media Foundation to spin up again.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crossbeam_channel::{Receiver as CbReceiver, Sender as CbSender};
use parking_lot::Mutex;
use quinn::Connection;
use tokio::sync::mpsc;

use directdesk_shared::adapt::{AdaptConfig, BitrateAdaptor};
use directdesk_shared::crypto::auth::{
    HostAuthenticator, TrustedPeer, TrustedPeers, TRUSTED_CLIENTS_KEY,
};
use directdesk_shared::crypto::pairing::PairingHost;
use directdesk_shared::crypto::storage::SecretStore;
use directdesk_shared::crypto::{fingerprint_short, HostIdentity};
use directdesk_shared::input::validate_event;
use directdesk_shared::protocol::{
    AuthMsg, Channel, Codec, ControlMsg, Hello, InputMsg, QualityMode, MAX_AUTH_MSG,
    PROTOCOL_VERSION,
};
use directdesk_shared::stats::{ConnStats, TransportRoute};
use directdesk_shared::transport::quic::{self, QuicParams, SessionStreams};
use directdesk_shared::transport::session::{
    QuicSession, Session, SessionConfig as DriverConfig, SessionEvent,
};
use directdesk_shared::{Error, Result};

use crate::session::{HostSession, SessionConfig as PipelineConfig, SessionState};

mod adaptation;
mod egress;
mod elevation;
mod pairing;

use egress::{tile_pump, video_pump};
use elevation::elevation_loop;

// The public surface of this module is `directdesk_host::net::X`, and the
// netsim baselines are pinned against exactly that list of names, so these
// re-exports are spelled out rather than globbed: adding to the surface should
// be a deliberate edit here, not a side effect of making something `pub` in a
// submodule.
pub use adaptation::{
    clamp_to_cap, congestion_signal, effective_cap, effective_fps, overrun_signal,
    tile_budget_kbps, tiles_strained, RateLimiter, TileThrottle, WindowDelivery,
    OVERRUN_MIN_FRAMES, OVERRUN_WARMUP_INTERVALS, STATUS_INTERVAL_MS, TILE_CEILING_BACKOFF,
    TILE_CEILING_CREEP_KBPS, TILE_CEILING_MIN_KBPS, TILE_CEILING_STEP_KBPS,
};
pub use egress::{coalesce_latest, pace_plan, wire_size, KEYFRAME_MIN_INTERVAL_MS, MIN_PACE_SLEEP};
pub use pairing::{
    AuthThrottle, PairingDisplay, PairingSlot, AUTH_FAIL_LIMIT, AUTH_FAIL_WINDOW_MS,
    AUTH_LOCKOUT_MS, HANDSHAKE_TIMEOUT_MS,
};

/// Floor on how often a *client's* `RequestKeyframe` is honoured. The client
/// only asks when its own decoder is stuck (a frame-id gap), and it rate-limits
/// itself; gating that a second time at 500 ms is what made recovery from a
/// scene-change stall take up to 1.5 s on a high-RTT link.
pub const CLIENT_KEYFRAME_MIN_INTERVAL_MS: u64 = 200;
/// QUIC application close code used for a rejected connection.
pub const CLOSE_CODE_REJECTED: u32 = 1;
/// QUIC application close code used for a deliberate host-side disconnect.
pub const CLOSE_CODE_DISCONNECT: u32 = 2;

/// The route this build can offer. QUIC over UDP only; the TCP fallback and
/// relay live in another wave and must never be claimed here.
pub const HOST_ROUTE: TransportRoute = TransportRoute::DirectUdp;

// ---------------------------------------------------------------------------
// Address discovery
// ---------------------------------------------------------------------------

/// Addresses a client could plausibly reach this host on.
///
/// Best effort and labelled as such in the UI: it resolves this machine's own
/// name and asks the routing table which source address a WAN-bound socket
/// would use. It never sends a packet (`connect` on UDP only sets the peer) and
/// it never claims an address is reachable from outside the LAN.
pub fn advertised_addresses(port: u16) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::new();

    if let Some(ip) = primary_local_ip() {
        out.push(SocketAddr::new(ip, port));
    }
    if let Ok(name) = std::env::var("COMPUTERNAME") {
        if let Ok(addrs) = (name.as_str(), port).to_socket_addrs() {
            out.extend(addrs);
        }
    }
    out.push(SocketAddr::new(IpAddr::from([127, 0, 0, 1]), port));

    out.retain(|a| !a.ip().is_unspecified() && !a.ip().is_multicast());
    out.sort_by_key(|a| (a.is_ipv6(), a.ip().is_loopback(), a.to_string()));
    out.dedup();
    out
}

/// The source address the OS would use for an off-box destination.
fn primary_local_ip() -> Option<IpAddr> {
    let sock = std::net::UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    // TEST-NET-1 and the discard port: `connect` on a UDP socket only records
    // the peer and picks a route, so nothing leaves the machine.
    sock.connect(("192.0.2.1", 9)).ok()?;
    Some(sock.local_addr().ok()?.ip())
}

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

/// Who is connected, for the UI and the tray tooltip.
#[derive(Debug, Clone)]
pub struct ClientInfo {
    pub name: String,
    /// Short fingerprint of the client's Ed25519 identity key.
    pub fingerprint: String,
    pub route: TransportRoute,
    pub peer: SocketAddr,
    pub connected_at: Instant,
}

/// Everything the UI renders. Written by the listener, read everywhere.
#[derive(Debug, Clone, Default)]
pub struct StatusSnapshot {
    /// `true` between a successful bind and the listener stopping.
    pub listening: bool,
    /// The socket the endpoint actually bound.
    pub bound: Option<SocketAddr>,
    /// Best-effort reachable addresses.
    pub addresses: Vec<SocketAddr>,
    pub host_name: String,
    /// Short fingerprint of this host's Ed25519 identity key.
    pub host_fingerprint: String,
    /// Short fingerprint of this host's TLS certificate pin.
    pub tls_pin: String,
    pub trusted_clients: usize,
    pub client: Option<ClientInfo>,
    /// Transport-observed numbers (RTT, loss, bandwidth).
    pub transport: ConnStats,
    /// Pipeline-observed numbers (capture/encode fps, encoder bitrate).
    pub pipeline: ConnStats,
    pub encoder: Option<String>,
    pub resolution: Option<(u32, u32)>,
    pub pipeline_state: Option<String>,
    pub secure_desktop: bool,
    /// Bitrate the adaptive controller currently asks the encoder for.
    pub target_kbps: u32,
    /// Quality mode in force for the live session. `None` when idle.
    pub quality_mode: Option<QualityMode>,
    /// Frame rate the encoder is actually running at (observed, not requested).
    pub target_fps: u32,
    /// Delivery/throughput over the most recent matched status window. Honest
    /// per-window figures, distinct from the lifetime counters below.
    pub delivery: WindowDelivery,
    /// Frames skipped by the latest-wins policy since the session started.
    pub frames_coalesced: u64,
    /// Frames skipped because the connection had no room for a whole one.
    pub frames_backpressured: u64,
    /// Frames whose pacing was abandoned part-way and the rest burst out,
    /// because spreading them further would have missed the emit deadline.
    /// Expected to track scene changes; a climbing count on a still desktop
    /// means the link (or the encoder) is in trouble.
    pub pace_deadline_bursts: u64,
    /// Longest a single frame took to put on the wire during the most recent
    /// status window, milliseconds. A gauge, not a total: it resets each window.
    pub emit_ms_max: u64,
    /// Frames dropped because they could not be fragmented at all (too many
    /// fragments, or over the frame-size limit). Should stay at zero.
    pub frames_unfragmentable: u64,
    pub frames_sent: u64,
    pub bytes_sent: u64,
    /// Client events that reached `SendInput` and were accepted. Counted at the
    /// injector, so it is evidence the whole input path works rather than that
    /// something was queued.
    pub input_injected: u64,
    pub last_error: Option<String>,
}

/// Notable things the listener did. The UI keeps a short log of these.
#[derive(Debug, Clone)]
pub enum NetEvent {
    Listening {
        bound: SocketAddr,
        addresses: Vec<SocketAddr>,
    },
    ListenFailed {
        detail: String,
    },
    Stopped,
    PairingArmed {
        grouped: String,
        ttl_ms: u64,
    },
    PairingCleared,
    Paired {
        name: String,
        fingerprint: String,
    },
    ClientConnected {
        name: String,
        fingerprint: String,
        peer: SocketAddr,
    },
    ClientDisconnected {
        reason: String,
    },
    AuthRejected {
        peer: IpAddr,
        detail: String,
    },
    LockedOut {
        peer: IpAddr,
        for_ms: u64,
    },
    Warning {
        detail: String,
    },
}

/// What the UI (or the tray) can ask the listener to do.
#[derive(Debug, Clone)]
pub enum NetCommand {
    /// Generate a code and open the 120-second pairing window.
    ArmPairing,
    CancelPairing,
    /// Close the current client's connection now. Input is released.
    DisconnectClient,
    SetQualityMode(QualityMode),
    SetBitrateCap(Option<u32>),
    /// Change the encoder's frame rate on the live pipeline. Never restarts the
    /// listener — see the note in the host UI's `apply_settings`.
    SetTargetFps(u32),
    Shutdown,
}

/// Settings the listener needs. Derived from [`crate::config::HostConfig`].
#[derive(Debug, Clone)]
pub struct NetConfig {
    pub bind: SocketAddr,
    /// Name a new identity is created under.
    pub host_name: String,
    pub quality_mode: QualityMode,
    pub bitrate_cap_kbps: Option<u32>,
    pub pipeline: PipelineConfig,
    pub quic: QuicParams,
    /// Operator opt-in for the SYSTEM UAC click-through. When `false` the host
    /// never offers elevation and never spawns the injector worker.
    pub uac_clickthrough: bool,
    /// Ceiling (seconds) on how long a single elevation arming stays valid.
    pub uac_arm_ttl_secs: u32,
    /// Blank the host desktop to solid black for the duration of each remote
    /// session and restore the previous wallpaper/color when it ends. See
    /// [`crate::config::HostConfig::blank_wallpaper_during_session`].
    pub blank_wallpaper_during_session: bool,
    /// Backstop ceiling (kbps) on lossless refinement traffic; `0` means the
    /// measured headroom is the only limit. See [`tile_budget_kbps`].
    pub tile_max_kbps: u32,
}

impl NetConfig {
    /// Build from the persisted host config.
    pub fn from_host_config(cfg: &crate::config::HostConfig) -> Self {
        Self {
            bind: SocketAddr::from(([0, 0, 0, 0], cfg.udp_port)),
            host_name: cfg.display_name.clone(),
            quality_mode: cfg.quality_mode,
            bitrate_cap_kbps: cfg.bitrate_cap_kbps,
            pipeline: cfg.pipeline(),
            quic: QuicParams::default(),
            uac_clickthrough: cfg.uac_clickthrough,
            uac_arm_ttl_secs: cfg.uac_arm_ttl_secs,
            blank_wallpaper_during_session: cfg.blank_wallpaper_during_session,
            tile_max_kbps: cfg.lossless_tile_max_kbps,
        }
    }
}

/// A running listener.
pub struct NetHandle {
    cmd: mpsc::UnboundedSender<NetCommand>,
    events: CbReceiver<NetEvent>,
    status: Arc<Mutex<StatusSnapshot>>,
    pairing: Arc<PairingSlot>,
    stopped: Arc<AtomicBool>,
}

impl std::fmt::Debug for NetHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetHandle")
            .field("stopped", &self.stopped.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl NetHandle {
    /// Queue a command. Silently ignored once the listener has stopped.
    pub fn command(&self, cmd: NetCommand) {
        if self.cmd.send(cmd).is_err() {
            tracing::debug!("net command dropped: listener is gone");
        }
    }

    /// A clonable command sender, for the tray thread.
    pub fn commander(&self) -> mpsc::UnboundedSender<NetCommand> {
        self.cmd.clone()
    }

    /// Next event, if any. Never blocks.
    pub fn try_event(&self) -> Option<NetEvent> {
        self.events.try_recv().ok()
    }

    pub fn status(&self) -> StatusSnapshot {
        self.status.lock().clone()
    }

    pub fn pairing(&self) -> Arc<PairingSlot> {
        self.pairing.clone()
    }

    /// The shared monotonic clock every state machine here is driven by.
    pub fn now_ms(&self) -> u64 {
        self.pairing.now_ms()
    }

    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Relaxed)
    }

    /// Ask the listener to stop. Returns immediately; the accept loop closes
    /// the endpoint, disconnects any client and releases input.
    pub fn shutdown(&self) {
        self.command(NetCommand::Shutdown);
    }
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

struct Inner {
    cfg: NetConfig,
    identity: Arc<HostIdentity>,
    store: Arc<dyn SecretStore>,
    trusted: Mutex<TrustedPeers>,
    pairing: Arc<PairingSlot>,
    throttle: Mutex<AuthThrottle>,
    status: Arc<Mutex<StatusSnapshot>>,
    events: CbSender<NetEvent>,
    busy: AtomicBool,
    current: Mutex<Option<Connection>>,
    pipeline: tokio::sync::Mutex<Option<Arc<HostSession>>>,
    quality: Mutex<QualityMode>,
    bitrate_cap: Mutex<Option<u32>>,
    /// Frame rate the next (or current) pipeline should run at. Live: changed by
    /// [`NetCommand::SetTargetFps`] and by a client's `preferred_fps`, and read
    /// by [`Inner::ensure_pipeline`] so a cold rebuild does not snap back to the
    /// persisted default.
    fps: Mutex<u32>,
}

impl Inner {
    fn now_ms(&self) -> u64 {
        self.pairing.now_ms()
    }

    fn emit(&self, ev: NetEvent) {
        // Events are advisory: a UI that is not draining must not stall the
        // listener.
        let _ = self.events.try_send(ev);
    }

    fn status_mut(&self, f: impl FnOnce(&mut StatusSnapshot)) {
        f(&mut self.status.lock());
    }

    /// Start the media pipeline if it is not already up, and keep it up.
    async fn ensure_pipeline(&self) -> Result<Arc<HostSession>> {
        let mut guard = self.pipeline.lock().await;
        if let Some(existing) = guard.as_ref() {
            if !matches!(
                existing.state(),
                SessionState::Failed(_) | SessionState::Stopped
            ) {
                return Ok(existing.clone());
            }
            tracing::warn!("media pipeline is dead; restarting it");
            *guard = None;
        }

        let mut cfg = self.cfg.pipeline.clone();
        // Build from the LIVE frame rate, not the persisted one: the pipeline is
        // a singleton that outlives any one client, so a cold rebuild after an
        // fps change would otherwise snap back to whatever host.json says.
        cfg.target_fps = *self.fps.lock();
        // `HostSession::start` blocks until D3D11 and the encoder are up.
        let session = tokio::task::spawn_blocking(move || HostSession::start(cfg))
            .await
            .map_err(|e| Error::Other(format!("pipeline start task: {e}")))??;
        let session = Arc::new(session);

        let desc = session.describe();
        self.status_mut(|s| {
            s.encoder = Some(desc.pipeline_summary());
            s.resolution = Some((desc.width, desc.height));
            s.pipeline_state = Some(format!("{:?}", session.state()));
        });
        tracing::info!("media pipeline up: {}", desc.pipeline_summary());
        *guard = Some(session.clone());
        Ok(session)
    }

    async fn stop_pipeline(&self) {
        let taken = self.pipeline.lock().await.take();
        if let Some(p) = taken {
            // Everything else holding an Arc is gone by the time we get here;
            // the last drop joins the media and input threads.
            drop(p);
            tracing::info!("media pipeline stopped");
        }
    }
}

/// Starts and owns the accept loop.
pub struct NetService;

impl NetService {
    /// Bind and start serving on `rt`.
    ///
    /// `status` and `pairing` are owned by the caller so they survive a
    /// listener restart (a port change, or the remote-access toggle).
    pub fn start(
        cfg: NetConfig,
        rt: &tokio::runtime::Handle,
        identity: Arc<HostIdentity>,
        store: Arc<dyn SecretStore>,
        status: Arc<Mutex<StatusSnapshot>>,
        pairing: Arc<PairingSlot>,
    ) -> NetHandle {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (ev_tx, ev_rx) = crossbeam_channel::bounded(256);
        let stopped = Arc::new(AtomicBool::new(false));

        let trusted = match TrustedPeers::load(&*store, TRUSTED_CLIENTS_KEY) {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("trusted-client list unreadable ({e}); starting empty");
                let _ = ev_tx.try_send(NetEvent::Warning {
                    detail: format!("trusted-client list unreadable: {e}"),
                });
                TrustedPeers::new()
            }
        };

        {
            let mut s = status.lock();
            s.host_name = identity.name().to_string();
            s.host_fingerprint = fingerprint_short(&identity.ed25519_pub());
            s.tls_pin = identity.tls().pin_short();
            s.trusted_clients = trusted.len();
            s.listening = false;
            s.client = None;
        }

        let inner = Arc::new(Inner {
            // These three read `cfg` before it is moved in below; keep them here.
            quality: Mutex::new(cfg.quality_mode),
            bitrate_cap: Mutex::new(cfg.bitrate_cap_kbps),
            fps: Mutex::new(cfg.pipeline.target_fps.max(1)),
            cfg,
            identity,
            store,
            trusted: Mutex::new(trusted),
            pairing: pairing.clone(),
            throttle: Mutex::new(AuthThrottle::new()),
            status: status.clone(),
            events: ev_tx,
            busy: AtomicBool::new(false),
            current: Mutex::new(None),
            pipeline: tokio::sync::Mutex::new(None),
        });

        let stopped_task = stopped.clone();
        rt.spawn(async move {
            accept_loop(inner, cmd_rx).await;
            stopped_task.store(true, Ordering::SeqCst);
        });

        NetHandle {
            cmd: cmd_tx,
            events: ev_rx,
            status,
            pairing,
            stopped,
        }
    }
}

async fn accept_loop(inner: Arc<Inner>, mut cmds: mpsc::UnboundedReceiver<NetCommand>) {
    let endpoint =
        match quic::server_endpoint(inner.cfg.bind, inner.identity.tls(), &inner.cfg.quic) {
            Ok(e) => e,
            Err(e) => {
                let detail = e.to_string();
                tracing::error!("listener bind failed: {detail}");
                inner.status_mut(|s| {
                    s.listening = false;
                    s.last_error = Some(detail.clone());
                });
                inner.emit(NetEvent::ListenFailed { detail });
                return;
            }
        };

    let bound = endpoint.local_addr().unwrap_or(inner.cfg.bind);
    let addresses = advertised_addresses(bound.port());
    inner.status_mut(|s| {
        s.listening = true;
        s.bound = Some(bound);
        s.addresses = addresses.clone();
        s.last_error = None;
    });
    tracing::info!(
        "listening on {bound} (advertising {} address(es))",
        addresses.len()
    );
    inner.emit(NetEvent::Listening { bound, addresses });

    loop {
        tokio::select! {
            cmd = cmds.recv() => {
                match cmd {
                    None | Some(NetCommand::Shutdown) => break,
                    Some(other) => handle_command(&inner, other),
                }
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let peer_ip = incoming.remote_address().ip();
                if let Some(for_ms) = inner.throttle.lock().locked_for_ms(&peer_ip, inner.now_ms()) {
                    tracing::warn!(peer = %peer_ip, "refusing connection: locked out for {for_ms} ms");
                    inner.emit(NetEvent::LockedOut { peer: peer_ip, for_ms });
                    incoming.refuse();
                    continue;
                }
                let inner = inner.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(inner.clone(), incoming).await {
                        tracing::warn!(peer = %peer_ip, "connection ended: {e}");
                    }
                });
            }
        }
    }

    // Shutting down: drop the client first so input is released before the
    // endpoint stops draining.
    if let Some(conn) = inner.current.lock().take() {
        conn.close(CLOSE_CODE_DISCONNECT.into(), b"host shutting down");
    }
    inner.pairing.clear();
    endpoint.close(0u32.into(), b"host shutting down");
    endpoint.wait_idle().await;
    inner.stop_pipeline().await;
    inner.status_mut(|s| {
        s.listening = false;
        s.client = None;
        s.bound = None;
    });
    inner.emit(NetEvent::Stopped);
    tracing::info!("listener stopped");
}

fn handle_command(inner: &Arc<Inner>, cmd: NetCommand) {
    match cmd {
        NetCommand::ArmPairing => {
            let armed = inner.pairing.arm(inner.now_ms());
            // The code itself is never logged — only that a window opened.
            tracing::info!("pairing window open for {} ms", armed.remaining_ms);
            inner.emit(NetEvent::PairingArmed {
                grouped: armed.grouped,
                ttl_ms: armed.remaining_ms,
            });
        }
        NetCommand::CancelPairing => {
            inner.pairing.clear();
            tracing::info!("pairing window cancelled");
            inner.emit(NetEvent::PairingCleared);
        }
        NetCommand::DisconnectClient => {
            let conn = inner.current.lock().clone();
            match conn {
                Some(conn) => {
                    tracing::info!("disconnecting client on request");
                    conn.close(CLOSE_CODE_DISCONNECT.into(), b"disconnected by host");
                }
                None => tracing::debug!("disconnect requested with no client connected"),
            }
        }
        NetCommand::SetQualityMode(mode) => {
            *inner.quality.lock() = mode;
            tracing::info!("quality mode set to {mode:?}");
        }
        NetCommand::SetBitrateCap(cap) => {
            *inner.bitrate_cap.lock() = cap;
            tracing::info!("bitrate cap set to {cap:?} kbps");
        }
        NetCommand::SetTargetFps(fps) => {
            let fps = effective_fps(fps, 0);
            *inner.fps.lock() = fps;
            tracing::info!("target frame rate set to {fps} fps");
            // The pipeline slot is an async mutex that `ensure_pipeline` holds
            // across a multi-second blocking `HostSession::start`. Awaiting it
            // here would stall the accept loop's `select!` — and with it every
            // incoming connection — so the hand-off is spawned instead. It
            // re-reads `inner.fps` rather than capturing `fps`, so two commands
            // racing still converge on the value that was stored last.
            let inner = inner.clone();
            tokio::spawn(async move {
                let want = *inner.fps.lock();
                if let Some(p) = inner.pipeline.lock().await.as_ref() {
                    p.set_fps(want);
                }
            });
        }
        NetCommand::Shutdown => unreachable!("handled by the accept loop"),
    }
}

/// Clears the "a client is connected" flag however the connection ends.
struct BusyGuard(Arc<Inner>);

impl Drop for BusyGuard {
    fn drop(&mut self) {
        *self.0.current.lock() = None;
        self.0.busy.store(false, Ordering::SeqCst);
        self.0.status_mut(|s| s.client = None);
    }
}

/// Releases every held key and button when a session ends, on every path.
struct ReleaseGuard(Arc<HostSession>);

impl Drop for ReleaseGuard {
    fn drop(&mut self) {
        self.0.release_all_input();
        // Stop refinement dead when the client goes away. The media pipeline is
        // a singleton that outlives every connection, and `status_loop` — the
        // only thing that ever lowers this — has just been aborted, so without
        // this the media thread would carry on compressing and queueing strips
        // at the departed client's measured budget, for a desktop nobody is
        // watching. Those stale bytes would then be the first thing the *next*
        // client's stream carried, ahead of its own `Reset`, competing with its
        // connect keyframe.
        self.0.set_tile_budget_kbps(0);
        tracing::info!("released all client-held input");
    }
}

async fn handle_connection(inner: Arc<Inner>, incoming: quinn::Incoming) -> Result<()> {
    let peer = incoming.remote_address();
    let conn = incoming
        .await
        .map_err(|e| Error::Transport(format!("handshake with {peer}: {e}")))?;

    if inner
        .busy
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        tracing::info!(peer = %peer, "refusing second client: host busy");
        reject_busy(&conn).await;
        return Ok(());
    }
    let _busy = BusyGuard(inner.clone());
    *inner.current.lock() = Some(conn.clone());

    let handshake = tokio::time::timeout(
        Duration::from_millis(HANDSHAKE_TIMEOUT_MS),
        authenticate(&inner, &conn),
    )
    .await;

    let (streams, client, negotiated_features) = match handshake {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            let locked = inner
                .throttle
                .lock()
                .record_failure(peer.ip(), inner.now_ms());
            tracing::warn!(peer = %peer, "authentication failed: {e}");
            inner.emit(NetEvent::AuthRejected {
                peer: peer.ip(),
                detail: e.to_string(),
            });
            if locked {
                inner.emit(NetEvent::LockedOut {
                    peer: peer.ip(),
                    for_ms: AUTH_LOCKOUT_MS,
                });
            }
            conn.close(CLOSE_CODE_REJECTED.into(), b"authentication failed");
            return Err(e);
        }
        Err(_) => {
            let locked = inner
                .throttle
                .lock()
                .record_failure(peer.ip(), inner.now_ms());
            tracing::warn!(peer = %peer, "authentication timed out");
            inner.emit(NetEvent::AuthRejected {
                peer: peer.ip(),
                detail: "handshake timed out".into(),
            });
            if locked {
                inner.emit(NetEvent::LockedOut {
                    peer: peer.ip(),
                    for_ms: AUTH_LOCKOUT_MS,
                });
            }
            conn.close(CLOSE_CODE_REJECTED.into(), b"handshake timeout");
            return Err(Error::Auth("handshake timed out".into()));
        }
    };

    inner.throttle.lock().record_success(&peer.ip());
    let fingerprint = client.fingerprint_short();
    tracing::info!(peer = %peer, client = %client.name, key = %fingerprint, "client authenticated");
    inner.status_mut(|s| {
        s.client = Some(ClientInfo {
            name: client.name.clone(),
            fingerprint: fingerprint.clone(),
            route: HOST_ROUTE,
            peer,
            connected_at: Instant::now(),
        });
        s.trusted_clients = s.trusted_clients.max(1);
    });
    inner.emit(NetEvent::ClientConnected {
        name: client.name.clone(),
        fingerprint,
        peer,
    });

    let reason = run_session(&inner, conn, streams, negotiated_features).await;
    tracing::info!(peer = %peer, "client disconnected: {reason}");
    inner.emit(NetEvent::ClientDisconnected { reason });
    Ok(())
}

/// The host's reply to a client `Hello`, advertising the **intersection** of
/// what the client asked for and what this host supports.
///
/// Answering with the intersection rather than the host's full capability set
/// means the client's check is a single bit test, and neither side can end up
/// believing a feature is on while the other thinks it is off. `offered` is
/// derived from config, so an operator turning a feature off is indistinguishable
/// from a host that never had it.
fn host_hello(client_features: u64, offered: u64) -> Hello {
    Hello {
        version: PROTOCOL_VERSION,
        features: client_features & offered,
        agent: concat!("directdesk-host ", env!("CARGO_PKG_VERSION")).to_string(),
    }
}

/// Feature bits this host is willing to turn on, given its configuration.
fn offered_features(cfg: &NetConfig) -> u64 {
    let mut bits = 0;
    if cfg.pipeline.lossless_tiles_enabled {
        bits |= directdesk_shared::protocol::features::LOSSLESS_TILES;
    }
    bits
}

/// Tell a second client the host is taken, in the framing it is expecting.
async fn reject_busy(conn: &Connection) {
    let deadline = Duration::from_millis(3_000);
    let _ = tokio::time::timeout(deadline, async {
        let mut streams = quic::accept_streams(conn).await?;
        let _ = quic::read_framed::<Hello>(&mut streams.control.1, MAX_AUTH_MSG).await;
        // A host that is turning this client away offers nothing: the session
        // is about to be closed, so advertising capabilities would be noise.
        quic::write_framed(&mut streams.control.0, &host_hello(0, 0)).await?;
        quic::write_framed(
            &mut streams.control.0,
            &AuthMsg::AuthFail {
                reason: "host busy: another client is connected".into(),
            },
        )
        .await?;
        Ok::<(), Error>(())
    })
    .await;
    conn.close(CLOSE_CODE_REJECTED.into(), b"busy");
}

/// Hello exchange plus the pairing-or-authentication branch.
///
/// Returns the session's streams, the client record, and the **negotiated
/// feature bits** on success. Every error path has already told the client
/// `AuthFail` with a deliberately vague reason: "not paired" and "bad
/// signature" must not be distinguishable.
///
/// Ordering note that the whole tile feature rests on: the client writes its
/// `Hello` blind, the host reads it *before* writing its own reply, and the
/// client reads the host's reply before doing anything else. So both ends know
/// the intersection before either acts on it, and the host opens the tile
/// stream only to a client that asked for it.
async fn authenticate(
    inner: &Arc<Inner>,
    conn: &Connection,
) -> Result<(SessionStreams, TrustedPeer, u64)> {
    let mut streams = quic::accept_streams(conn).await?;

    let hello: Hello = quic::read_framed(&mut streams.control.1, MAX_AUTH_MSG).await?;
    directdesk_shared::protocol::validate_hello(&hello)?;
    let negotiated = hello.features & offered_features(&inner.cfg);
    quic::write_framed(
        &mut streams.control.0,
        &host_hello(hello.features, offered_features(&inner.cfg)),
    )
    .await?;
    tracing::debug!(
        agent = %hello.agent,
        client_features = format_args!("{:#x}", hello.features),
        negotiated = format_args!("{negotiated:#x}"),
        "client hello accepted"
    );

    let exporter = quic::channel_binding(conn)?;
    let (mut authenticator, challenge) = HostAuthenticator::start(&exporter)?;
    quic::write_framed(&mut streams.control.0, &challenge).await?;

    let first: AuthMsg = quic::read_auth(&mut streams.control.1).await?;
    let outcome = match &first {
        AuthMsg::ClientAuth {
            client_ed25519_pub, ..
        } => {
            let attempted = fingerprint_short(client_ed25519_pub);
            let trusted = inner.trusted.lock().clone();
            match authenticator.on_client_auth(&first, &trusted) {
                Ok(peer) => Ok((peer, false)),
                Err(e) => {
                    tracing::warn!(key = %attempted, "rejected client identity: {e}");
                    Err(e)
                }
            }
        }
        AuthMsg::PairStart { .. } => pair(
            inner,
            &mut streams,
            &mut authenticator,
            &exporter,
            &first,
            &hello,
        )
        .await
        .map(|peer| (peer, true)),
        other => Err(Error::Auth(format!(
            "expected ClientAuth or PairStart, got {}",
            variant_name(other)
        ))),
    };

    let (peer, newly_paired) = match outcome {
        Ok(v) => v,
        Err(e) => {
            let _ = quic::write_framed(
                &mut streams.control.0,
                &AuthMsg::AuthFail {
                    reason: "authentication rejected".into(),
                },
            )
            .await;
            return Err(e);
        }
    };

    // Same tail for both branches: the client challenges us back.
    let client_challenge: AuthMsg = quic::read_auth(&mut streams.control.1).await?;
    let (server_auth, ok) =
        match authenticator.on_client_challenge(&client_challenge, inner.identity.signing_key()) {
            Ok(v) => v,
            Err(e) => {
                let _ = quic::write_framed(
                    &mut streams.control.0,
                    &AuthMsg::AuthFail {
                        reason: "authentication rejected".into(),
                    },
                )
                .await;
                return Err(e);
            }
        };
    quic::write_framed(&mut streams.control.0, &server_auth).await?;
    quic::write_framed(&mut streams.control.0, &ok).await?;

    if newly_paired {
        inner.emit(NetEvent::Paired {
            name: peer.name.clone(),
            fingerprint: peer.fingerprint_short(),
        });
    }
    Ok((streams, peer, negotiated))
}

/// The SPAKE2 exchange, then the client's proof of which key it owns.
async fn pair(
    inner: &Arc<Inner>,
    streams: &mut SessionStreams,
    authenticator: &mut HostAuthenticator,
    exporter: &directdesk_shared::crypto::Exporter,
    pair_start: &AuthMsg,
    hello: &Hello,
) -> Result<TrustedPeer> {
    let Some(armed) = inner.pairing.take(inner.now_ms()) else {
        return Err(Error::Pairing(
            "no pairing window is open on the host".into(),
        ));
    };
    // Whatever happens now, the code is burned: `take` removed it.
    inner.emit(NetEvent::PairingCleared);

    let mut host = PairingHost::with_code(armed.code, armed.armed_ms, armed.ttl_ms);
    let response = host.on_pair_start(pair_start, exporter, inner.now_ms())?;
    quic::write_framed(&mut streams.control.0, &response).await?;

    let confirm: AuthMsg = quic::read_auth(&mut streams.control.1).await?;
    let ours = host.on_pair_confirm(&confirm, inner.now_ms())?;
    quic::write_framed(&mut streams.control.0, &ours).await?;
    quic::write_framed(&mut streams.control.0, &inner.identity.pair_complete()).await?;
    tracing::info!("pairing confirmed; awaiting the client's identity proof");

    // Pairing proved the user typed the code. This proves which key belongs to
    // the machine that typed it — signed over the challenge nonce this
    // connection already issued, so it cannot be replayed from elsewhere.
    let client_auth: AuthMsg = quic::read_auth(&mut streams.control.1).await?;
    let AuthMsg::ClientAuth {
        client_ed25519_pub, ..
    } = &client_auth
    else {
        return Err(Error::Auth("expected ClientAuth after PairComplete".into()));
    };
    let name =
        crate::config::sanitize_name(&hello.agent).unwrap_or_else(|| "paired client".to_string());
    let candidate = host.accept_client(client_ed25519_pub, &name, wall_clock_ms())?;

    let mut provisional = TrustedPeers::new();
    provisional.upsert(candidate)?;
    let peer = authenticator.on_client_auth(&client_auth, &provisional)?;

    {
        let mut trusted = inner.trusted.lock();
        trusted.upsert(peer.clone())?;
        trusted.save(&*inner.store, TRUSTED_CLIENTS_KEY)?;
        inner.status_mut(|s| s.trusted_clients = trusted.len());
    }
    tracing::info!(client = %peer.name, key = %peer.fingerprint_short(), "new client paired");
    Ok(peer)
}

fn wall_clock_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn variant_name(msg: &AuthMsg) -> &'static str {
    match msg {
        AuthMsg::PairStart { .. } => "PairStart",
        AuthMsg::PairResponse { .. } => "PairResponse",
        AuthMsg::PairConfirm { .. } => "PairConfirm",
        AuthMsg::PairComplete { .. } => "PairComplete",
        AuthMsg::ClientAuth { .. } => "ClientAuth",
        AuthMsg::ServerChallenge { .. } => "ServerChallenge",
        AuthMsg::ServerAuth { .. } => "ServerAuth",
        AuthMsg::ClientChallenge { .. } => "ClientChallenge",
        AuthMsg::AuthOk => "AuthOk",
        AuthMsg::AuthFail { .. } => "AuthFail",
    }
}

// ---------------------------------------------------------------------------
// Live session
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct VideoCounters {
    frames_sent: AtomicU64,
    bytes_sent: AtomicU64,
    /// Frames skipped because a newer one was already waiting.
    coalesced: AtomicU64,
    /// Frames skipped because the connection had no room for all of them.
    backpressured: AtomicU64,
    /// Frames whose pacing hit the emit deadline and were burst out.
    pace_deadline_bursts: AtomicU64,
    /// Longest single-frame emission, milliseconds. Swapped back to zero by the
    /// status loop every window, so it is a per-window maximum, not a total.
    emit_ms_max: AtomicU64,
    /// Frames the fragmenter refused outright.
    frames_unfragmentable: AtomicU64,
    /// A *keyframe* was refused by the fragmenter. Latched here for the status
    /// loop, which reads-and-clears it and feeds the adaptor a full congestion
    /// event: without that the next IDR is just as big and the stream never
    /// recovers. A flag rather than a count — one is already the whole story.
    oversized_keyframe: AtomicBool,
}

/// Drive one authenticated client until the connection ends.
///
/// Returns the reason the session finished, for the log and the UI.
async fn run_session(
    inner: &Arc<Inner>,
    conn: Connection,
    streams: SessionStreams,
    negotiated_features: u64,
) -> String {
    let pipeline = match inner.ensure_pipeline().await {
        Ok(p) => p,
        Err(e) => {
            let detail = format!("media pipeline unavailable: {e}");
            tracing::error!("{detail}");
            inner.status_mut(|s| s.last_error = Some(detail.clone()));
            conn.close(CLOSE_CODE_REJECTED.into(), b"host pipeline unavailable");
            return detail;
        }
    };
    // Nothing below may return without this guard being dropped.
    let _release = ReleaseGuard(pipeline.clone());
    // The pipeline is a singleton that outlives any one connection, so a
    // reconnecting client inherits a grid that still believes the *previous*
    // client's tiles are resident. This client's store is empty. Reset
    // unconditionally — it costs one full refinement sweep on a screen we are
    // about to send a keyframe for anyway, and skipping it means a permanently
    // soft picture on every connection after the first.
    pipeline.reset_tiles();
    // Bandwidth saver: blank the desktop to black for the life of this
    // session and restore it on every exit path (this function's `String`
    // return covers all of them — success, error, timeout, disconnect). A
    // no-op guard when the config flag is off. Scoped to the session rather
    // than the pipeline because the pipeline outlives a single client.
    let _wallpaper =
        crate::wallpaper::WallpaperGuard::new(inner.cfg.blank_wallpaper_during_session);

    let driver_cfg = DriverConfig {
        heartbeat_ms: 2_000,
        stats_interval_ms: STATUS_INTERVAL_MS,
        control_capacity: 64,
        input_capacity: 512,
        // The host only ever *sends* video (`video_pump` below). Running the
        // driver's receive path here would keep a reassembler alive for
        // datagrams no client sends, and give the client a second, unlimited
        // route into `request_keyframe` — the `ControlMsg::RequestKeyframe`
        // path in `control_loop` is rate-limited, `SessionEvent::KeyframeNeeded`
        // is not.
        receive_video: false,
        ..DriverConfig::default()
    };
    let (session, receivers) =
        match QuicSession::start(conn.clone(), streams, HOST_ROUTE, driver_cfg) {
            Ok(v) => v,
            Err(e) => {
                let detail = format!("session driver failed to start: {e}");
                tracing::error!("{detail}");
                conn.close(CLOSE_CODE_REJECTED.into(), b"session start failed");
                return detail;
            }
        };
    let session = Arc::new(session);

    let streaming = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let counters = Arc::new(VideoCounters::default());
    let adaptor = Arc::new(Mutex::new(BitrateAdaptor::new(AdaptConfig::for_mode(
        *inner.quality.lock(),
    ))));

    let video = {
        let conn = conn.clone();
        let frames = pipeline.frames();
        let pipeline = pipeline.clone();
        let streaming = streaming.clone();
        let stop = stop.clone();
        let counters = counters.clone();
        std::thread::Builder::new()
            .name("dd-video-tx".into())
            .spawn(move || video_pump(conn, frames, pipeline, streaming, stop, counters))
            .ok()
    };
    if video.is_none() {
        tracing::error!("could not spawn the video sender thread");
    }

    // Elevation click-through: the control loop forwards `ArmElevation` here;
    // `elevation_loop` owns the state machine, the detector poll, and the SYSTEM
    // worker's lifecycle. It is NOT in `tasks` (which are hard-aborted): it is
    // stopped cooperatively via `stop` and awaited so it can tear the worker and
    // the input route down cleanly before the next client connects.
    let (arm_tx, arm_rx) = mpsc::unbounded_channel::<(bool, u32)>();
    let elevation = tokio::spawn(elevation_loop(
        inner.clone(),
        session.clone(),
        pipeline.clone(),
        arm_rx,
        stop.clone(),
    ));

    // Lossless refinement, only when BOTH ends asked for it. `negotiated_features`
    // is already the intersection, so this is a single bit test — and a client
    // that predates the feature never gets a stream opened at it.
    let tile_counters = Arc::new(TileCounters::default());
    let mut tasks = vec![
        tokio::spawn(input_loop(receivers.input, pipeline.clone())),
        tokio::spawn(control_loop(
            inner.clone(),
            receivers.control,
            session.clone(),
            pipeline.clone(),
            streaming.clone(),
            adaptor.clone(),
            arm_tx,
        )),
        tokio::spawn(status_loop(
            inner.clone(),
            session.clone(),
            pipeline.clone(),
            adaptor,
            counters.clone(),
            streaming.clone(),
            tile_counters.clone(),
        )),
        tokio::spawn(event_loop(
            inner.clone(),
            receivers.events,
            pipeline.clone(),
        )),
    ];

    if negotiated_features & directdesk_shared::protocol::features::LOSSLESS_TILES != 0 {
        tasks.push(tokio::spawn(tile_pump(
            conn.clone(),
            pipeline.tiles(),
            stop.clone(),
            tile_counters,
        )));
    }

    let reason = conn.closed().await.to_string();

    stop.store(true, Ordering::SeqCst);
    streaming.store(false, Ordering::SeqCst);
    for t in tasks {
        t.abort();
    }
    // Await (do not abort) the elevation loop so it tears down any live SYSTEM
    // worker and clears the input route before the next client connects.
    let _ = elevation.await;
    if let Some(v) = video {
        let _ = v.join();
    }
    // Explicit, not just the guard: input must be released before the next
    // client can possibly connect.
    pipeline.release_all_input();

    inner.status_mut(|s| {
        s.frames_sent = counters.frames_sent.load(Ordering::Relaxed);
        s.bytes_sent = counters.bytes_sent.load(Ordering::Relaxed);
        s.frames_coalesced = counters.coalesced.load(Ordering::Relaxed);
        s.frames_backpressured = counters.backpressured.load(Ordering::Relaxed);
        s.pace_deadline_bursts = counters.pace_deadline_bursts.load(Ordering::Relaxed);
        s.frames_unfragmentable = counters.frames_unfragmentable.load(Ordering::Relaxed);
        // A per-window gauge, like `delivery`: with no session there is no
        // window, so it reads zero rather than freezing at the last value.
        s.emit_ms_max = 0;
        s.transport = ConnStats::default();
        s.delivery = WindowDelivery::default();
        s.quality_mode = None;
    });
    reason
}

/// Inbound input. The driver has already decoded and validated; validating
/// again is cheap and keeps this the last line of defence before injection.
async fn input_loop(mut rx: mpsc::Receiver<InputMsg>, pipeline: Arc<HostSession>) {
    let tx = pipeline.input_sender();
    while let Some(msg) = rx.recv().await {
        match msg {
            InputMsg::Event(ev) => match validate_event(&ev) {
                Ok(()) => {
                    if tx.send(ev).is_err() {
                        tracing::warn!("input pipeline closed; stopping input forwarding");
                        return;
                    }
                }
                Err(e) => tracing::warn!("rejected input event: {e}"),
            },
            InputMsg::ReleaseAll => {
                tracing::info!("client asked for a full input release");
                pipeline.release_all_input();
            }
        }
    }
}

/// Session control from the client.
#[allow(clippy::too_many_arguments)]
async fn control_loop(
    inner: Arc<Inner>,
    mut rx: mpsc::Receiver<ControlMsg>,
    session: Arc<QuicSession>,
    pipeline: Arc<HostSession>,
    streaming: Arc<AtomicBool>,
    adaptor: Arc<Mutex<BitrateAdaptor>>,
    arm_tx: mpsc::UnboundedSender<(bool, u32)>,
) {
    let mut keyframes = RateLimiter::new(CLIENT_KEYFRAME_MIN_INTERVAL_MS);

    while let Some(msg) = rx.recv().await {
        let now = inner.now_ms();
        match msg {
            ControlMsg::StartStream {
                max_width,
                max_height,
                preferred_fps,
                quality_mode,
            } => {
                let (w, h) = pipeline.dimensions();
                tracing::info!(
                    "stream requested: client canvas {max_width}x{max_height} @ {preferred_fps} \
                     fps, {quality_mode:?}; host sends {w}x{h}"
                );
                *inner.quality.lock() = quality_mode;
                // The client's preference narrows the host's frame rate, never
                // widens it — same contract as `BitrateLimit` (`effective_cap`).
                // The host side of that is the LIVE value, not `cfg.pipeline`:
                // an operator who lowered the rate mid-session must not have it
                // undone by the next StartStream.
                let host_fps = *inner.fps.lock();
                let fps = effective_fps(host_fps, preferred_fps);
                *inner.fps.lock() = fps;
                pipeline.set_fps(fps);
                {
                    let mut a = adaptor.lock();
                    a.set_mode(quality_mode, now);
                    apply_bitrate(&inner, &pipeline, a.current());
                }
                pipeline.request_keyframe();
                streaming.store(true, Ordering::SeqCst);

                let cfg = ControlMsg::VideoConfig {
                    width: w,
                    height: h,
                    // The intended rate, not `pipeline.active_fps()`: `set_fps`
                    // lands on the media thread on its next pass (up to one
                    // frame away), so reading it back here would still report
                    // the old value. `active_fps()` is for the status path,
                    // where observed truth is what is wanted.
                    fps,
                    bitrate_kbps: adaptor.lock().current(),
                    codec: Codec::H264,
                };
                if let Err(e) = session.send_control(cfg) {
                    tracing::warn!("could not send VideoConfig: {e}");
                }
            }
            ControlMsg::StopStream => {
                tracing::info!("client stopped the stream");
                streaming.store(false, Ordering::SeqCst);
            }
            ControlMsg::RequestKeyframe => {
                if keyframes.allow(now) {
                    pipeline.request_keyframe();
                } else {
                    tracing::trace!("keyframe request rate-limited");
                }
            }
            ControlMsg::QualityChange(mode) => {
                tracing::info!("quality mode changed to {mode:?}");
                *inner.quality.lock() = mode;
                let mut a = adaptor.lock();
                a.set_mode(mode, now);
                apply_bitrate(&inner, &pipeline, a.current());
            }
            ControlMsg::BitrateLimit { max_kbps } => {
                tracing::info!("client asked for a bitrate limit of {max_kbps:?} kbps");
                // The client's request narrows, never widens, the host's cap.
                let effective = effective_cap(*inner.bitrate_cap.lock(), max_kbps);
                *inner.bitrate_cap.lock() = effective;
                apply_bitrate(&inner, &pipeline, adaptor.lock().current());
            }
            ControlMsg::ClipboardText(text) => {
                // Clipboard is a later milestone. Say so rather than pretending.
                tracing::info!(
                    "ignoring {} bytes of clipboard text (not implemented)",
                    text.len()
                );
            }
            ControlMsg::Stats(peer) => {
                inner.status_mut(|s| {
                    s.transport.fps_decode = peer.fps_decode;
                    s.transport.fps_present = peer.fps_present;
                });
            }
            ControlMsg::ArmElevation { one_shot, ttl_secs } => {
                if !inner.cfg.uac_clickthrough {
                    tracing::warn!("client armed elevation but uac_clickthrough is off; ignoring");
                } else {
                    tracing::info!("client armed elevation (one_shot={one_shot}, ttl={ttl_secs}s)");
                    // Hand it to the elevation loop; if that task is gone the
                    // session is ending anyway.
                    let _ = arm_tx.send((one_shot, ttl_secs));
                }
            }
            other => tracing::debug!("ignoring control message from client: {other:?}"),
        }
    }
}

fn apply_bitrate(inner: &Arc<Inner>, pipeline: &Arc<HostSession>, kbps: u32) {
    // A `BitrateLimit`/host cap is a hard ceiling on what the encoder is ever
    // asked for, applied on top of whatever the adaptor picked within its mode
    // range. The encoder never sees a value above the cap.
    let capped = clamp_to_cap(kbps, *inner.bitrate_cap.lock());
    pipeline.set_bitrate(capped);
    inner.status_mut(|s| s.target_kbps = capped);
}

#[derive(Default)]
struct TileCounters {
    strips_sent: AtomicU64,
    bytes_sent: AtomicU64,
    control_sent: AtomicU64,
}

/// Periodic host → client status, and the adaptive bitrate loop.
async fn status_loop(
    inner: Arc<Inner>,
    session: Arc<QuicSession>,
    pipeline: Arc<HostSession>,
    adaptor: Arc<Mutex<BitrateAdaptor>>,
    counters: Arc<VideoCounters>,
    streaming: Arc<AtomicBool>,
    tile_counters: Arc<TileCounters>,
) {
    let mut ticker = tokio::time::interval(Duration::from_millis(STATUS_INTERVAL_MS));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_paused: Option<bool> = None;
    let mut prev_sent = 0u64;
    let mut prev_bytes = 0u64;
    let mut prev_backpressured = 0u64;
    let mut prev_now = inner.now_ms();
    let mut tile_throttle = TileThrottle::new();
    let mut prev_tile_bytes = 0u64;
    let mut intervals = 0u32;

    loop {
        ticker.tick().await;
        if session.is_closed() {
            return;
        }
        let now = inner.now_ms();
        let transport = session.stats();
        let media = pipeline.stats();
        let state = pipeline.state();
        let paused = matches!(state, SessionState::Paused(_));

        // Merge: the transport owns RTT/loss/bandwidth, the pipeline owns the
        // capture and encode numbers. Neither invents the other's.
        let merged = ConnStats {
            rtt_ms: transport.rtt_ms,
            jitter_ms: transport.jitter_ms,
            loss: transport.loss,
            bandwidth_kbps: transport.bandwidth_kbps,
            fps_capture: media.fps_capture,
            fps_encode: media.fps_encode,
            fps_decode: 0.0,
            fps_present: 0.0,
            bitrate_kbps: media.bitrate_kbps,
            frames_dropped: media.frames_dropped,
            keyframes_requested: media.keyframes_requested,
            pipeline_ms: media.pipeline_ms,
            // End-to-end input confirmation: report how many client keystrokes
            // this host has actually injected, so the client can see whether the
            // keys it sent are landing here.
            input_injected: pipeline.input_events_injected(),
        };

        // Everything below is a delta over THIS window (a matched sliding
        // window, never a lifetime total), measured against the real elapsed
        // time so the throughput figure is honest even if a tick was skipped.
        let sent = counters.frames_sent.load(Ordering::Relaxed);
        let bytes = counters.bytes_sent.load(Ordering::Relaxed);
        let backpressured = counters.backpressured.load(Ordering::Relaxed);
        let pace_deadline_bursts = counters.pace_deadline_bursts.load(Ordering::Relaxed);
        // A gauge over this window only: take it and leave the counter at zero
        // so the next window measures itself rather than inheriting a spike.
        let emit_ms_max = counters.emit_ms_max.swap(0, Ordering::Relaxed);
        let win_sent = sent.saturating_sub(prev_sent);
        let win_backpressured = backpressured.saturating_sub(prev_backpressured);
        let delivery = WindowDelivery {
            sent: win_sent,
            offered: win_sent + win_backpressured,
            bytes: bytes.saturating_sub(prev_bytes),
            dt_ms: now.saturating_sub(prev_now),
        };
        prev_sent = sent;
        prev_bytes = bytes;
        prev_backpressured = backpressured;
        prev_now = now;
        intervals = intervals.saturating_add(1);

        // Backpressure is congestion the packet-level loss counter cannot see:
        // quinn accepted every datagram we offered and then dropped some itself.
        // It is a matched-window ratio, so it does not skew like the old
        // lifetime comparison did.
        let pressure = delivery.backpressure_ratio();

        // The encoder-vs-carried "overrun" is only a trustworthy congestion
        // signal once the stream has run a few windows AND actually sent a
        // meaningful number of frames this window. Before that (start-up, or a
        // window where the stream just stopped) the encoder bitrate is measured
        // over a full interval while the link carried almost nothing, and their
        // ratio is a window artifact that would drive the adaptor down for no
        // reason. Gate it; the adaptor is driven by the real ConnStats.loss.
        let warm = intervals > OVERRUN_WARMUP_INTERVALS && win_sent >= OVERRUN_MIN_FRAMES;
        let overrun = overrun_signal(media.bitrate_kbps, transport.bandwidth_kbps);
        // A keyframe the fragmenter refused outranks every measured signal:
        // nothing of it reached the wire, and the next IDR would be the same
        // size unless the bitrate comes down. Read-and-clear, then hand the
        // adaptor a full congestion event.
        let oversized_keyframe = counters.oversized_keyframe.swap(false, Ordering::Relaxed);
        let congestion = if oversized_keyframe {
            tracing::error!("a keyframe was too big to fragment; forcing a bitrate cut");
            1.0
        } else {
            congestion_signal(transport.loss, pressure, overrun, warm)
        };
        if let Some(next) = adaptor.lock().observe(now, congestion, transport.rtt_ms) {
            tracing::info!(
                "adaptive bitrate → {next} kbps (loss {:.1}%, send pressure {:.1}%, \
                 overrun {:.1}%{}: encoder {} kbps vs link {} kbps)",
                transport.loss * 100.0,
                pressure * 100.0,
                overrun * 100.0,
                if warm { "" } else { " [gated]" },
                media.bitrate_kbps,
                transport.bandwidth_kbps
            );
            apply_bitrate(&inner, &pipeline, next);
        }
        let quality_mode = *inner.quality.lock();

        let _ = session.send_control(ControlMsg::Stats(merged));
        let _ = session.send_control(ControlMsg::RouteReport(HOST_ROUTE));
        if last_paused != Some(paused) {
            last_paused = Some(paused);
            tracing::info!(
                "secure desktop {}",
                if paused { "active" } else { "cleared" }
            );
            let _ = session.send_control(ControlMsg::SecureDesktopActive(paused));
            if !paused {
                // The desktop we came back to may look nothing like the one we
                // left; the client needs a fresh IDR to resync.
                pipeline.request_keyframe();
            }
        }

        let injected = pipeline.input_events_injected();
        // Observed, not requested: a rebuild that failed must not be reported as
        // if it had taken.
        let active_fps = pipeline.active_fps();
        inner.status_mut(|s| {
            s.transport = transport;
            s.pipeline = merged;
            s.pipeline_state = Some(format!("{state:?}"));
            s.secure_desktop = paused;
            s.quality_mode = Some(quality_mode);
            s.target_fps = active_fps;
            s.delivery = delivery;
            s.frames_sent = sent;
            s.bytes_sent = bytes;
            s.frames_coalesced = counters.coalesced.load(Ordering::Relaxed);
            s.frames_backpressured = backpressured;
            s.pace_deadline_bursts = pace_deadline_bursts;
            s.frames_unfragmentable = counters.frames_unfragmentable.load(Ordering::Relaxed);
            s.emit_ms_max = emit_ms_max;
            s.input_injected = injected;
        });
        // Cumulative injected count beside the send rate: under full video load
        // this should keep climbing as the client types (proving input is not
        // starved by encode). It stalling while frames_sent races is the
        // signature of the input-priority bug.
        tracing::info!(
            input_injected = injected,
            frames_sent = sent,
            "host input diag"
        );

        // Refill the refinement allowance from this window's measurements. Done
        // here because every input is already computed once per second and
        // agrees with what the adaptor just decided — recomputing any of it
        // elsewhere would risk the two disagreeing.
        // What refinement actually spent over the window just closed. This is
        // the evidence the ceiling is learned from, so it must be a matched
        // delta over the same window as `delivery`, not a lifetime total.
        let tile_bytes_now = tile_counters.bytes_sent.load(Ordering::Relaxed);
        let tile_spent_kbps = {
            // `delivery.dt_ms`, not `now - prev_now`: `prev_now` was already
            // advanced above, so recomputing it here would always give zero.
            let dt_ms = delivery.dt_ms.max(1);
            let delta = tile_bytes_now.saturating_sub(prev_tile_bytes);
            ((delta * 8) / dt_ms) as u32
        };
        prev_tile_bytes = tile_bytes_now;

        let budget = tile_throttle.observe(
            tile_spent_kbps,
            adaptor.lock().current(),
            media.bitrate_kbps,
            pressure,
            transport.loss,
            oversized_keyframe,
            streaming.load(Ordering::Relaxed),
            inner.cfg.tile_max_kbps,
        );
        // Published to the media thread, which is the only place a strip can be
        // dropped safely — it owns the grid, so it can decline to *plan* work
        // rather than discard work it has already recorded as delivered.
        pipeline.set_tile_budget_kbps(budget);

        let tile_strips = tile_counters.strips_sent.load(Ordering::Relaxed);
        if tile_strips > 0 {
            // Hazard 6's observable signature, logged together on purpose: if
            // `backpressured` climbs while tile traffic flows and loss stays at
            // zero, tiles are stealing the congestion window from video and the
            // budget above is too generous.
            tracing::info!(
                tile_strips,
                tile_kbytes = tile_counters.bytes_sent.load(Ordering::Relaxed) / 1024,
                tile_spent_kbps,
                tile_budget_kbps = budget,
                tile_ceiling_kbps = tile_throttle.ceiling(),
                backpressured,
                loss = transport.loss,
                "tile diag"
            );
        }
    }
}

/// Driver-level events: warnings, peer `Bye`, keyframe requests from loss.
async fn event_loop(
    inner: Arc<Inner>,
    mut rx: mpsc::Receiver<SessionEvent>,
    pipeline: Arc<HostSession>,
) {
    while let Some(ev) = rx.recv().await {
        match ev {
            SessionEvent::KeyframeNeeded => pipeline.request_keyframe(),
            SessionEvent::PeerClosed { reason } => {
                tracing::info!("client said goodbye: {reason}");
            }
            SessionEvent::Warning { detail } => {
                tracing::warn!("session warning: {detail}");
                inner.emit(NetEvent::Warning { detail });
            }
            SessionEvent::Closed { reason } => {
                tracing::debug!("session closed: {reason}");
                return;
            }
            SessionEvent::Stats(_) => {}
        }
    }
}

/// The channel tag the host expects each inbound stream to open with.
///
/// Re-exported so the loopback test can assert the host and the shared crate
/// agree without reaching into `transport`'s internals.
pub fn expected_channels() -> [Channel; 2] {
    [Channel::Control, Channel::Input]
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- addresses ---------------------------------------------------------

    #[test]
    fn advertised_addresses_are_usable_and_include_loopback() {
        let addrs = advertised_addresses(47_990);
        assert!(!addrs.is_empty());
        assert!(addrs.iter().all(|a| a.port() == 47_990));
        assert!(addrs.iter().all(|a| !a.ip().is_unspecified()));
        assert!(addrs.iter().any(|a| a.ip().is_loopback()));
        let mut sorted = addrs.clone();
        sorted.dedup();
        assert_eq!(sorted.len(), addrs.len(), "no duplicates");
    }

    // -- config plumbing ---------------------------------------------------

    #[test]
    fn net_config_follows_host_config() {
        let hc = crate::config::HostConfig {
            udp_port: 50_000,
            bitrate_cap_kbps: Some(5_000),
            quality_mode: QualityMode::LowBandwidth,
            ..Default::default()
        };
        let nc = NetConfig::from_host_config(&hc);
        assert_eq!(nc.bind.port(), 50_000);
        assert!(nc.bind.ip().is_unspecified(), "bind on every interface");
        assert_eq!(nc.bitrate_cap_kbps, Some(5_000));
        assert_eq!(nc.quality_mode, QualityMode::LowBandwidth);
        assert!(nc.quic.validate().is_ok());
    }

    #[test]
    fn host_hello_matches_the_contract() {
        let h = host_hello(0, 0);
        assert_eq!(h.version, PROTOCOL_VERSION);
        assert!(directdesk_shared::protocol::validate_hello(&h).is_ok());
        assert!(h.agent.starts_with("directdesk-host"));
    }

    #[test]
    fn host_hello_advertises_the_intersection() {
        use directdesk_shared::protocol::features::LOSSLESS_TILES;

        // Both sides want it → on.
        assert_eq!(
            host_hello(LOSSLESS_TILES, LOSSLESS_TILES).features,
            LOSSLESS_TILES
        );
        // Client asks, host is not configured for it → off. This is the case
        // that must hold for rollout step 1, where the code ships inert.
        assert_eq!(host_hello(LOSSLESS_TILES, 0).features, 0);
        // Host offers, an older client never asked → off, and the host must
        // therefore never open the stream.
        assert_eq!(host_hello(0, LOSSLESS_TILES).features, 0);
        // A client advertising bits this host has never heard of must not cause
        // the host to echo them back as if it understood.
        assert_eq!(
            host_hello(u64::MAX, LOSSLESS_TILES).features,
            LOSSLESS_TILES
        );
    }

    #[test]
    fn offered_features_follow_config() {
        use directdesk_shared::protocol::features::LOSSLESS_TILES;

        let mut cfg =
            NetConfig::from_host_config(&crate::config::HostConfig::default().sanitized());
        assert_eq!(
            offered_features(&cfg) & LOSSLESS_TILES,
            0,
            "shipped default must offer nothing — rollout step 1 is byte-identical on the wire"
        );
        cfg.pipeline.lossless_tiles_enabled = true;
        assert_eq!(offered_features(&cfg) & LOSSLESS_TILES, LOSSLESS_TILES);
    }

    #[test]
    fn the_host_never_claims_a_route_it_does_not_have() {
        assert_eq!(HOST_ROUTE, TransportRoute::DirectUdp);
        assert!(HOST_ROUTE.is_direct());
    }

    #[test]
    fn auth_variant_names_are_distinct() {
        let names = [
            variant_name(&AuthMsg::AuthOk),
            variant_name(&AuthMsg::PairStart { spake_msg: vec![] }),
            variant_name(&AuthMsg::ClientAuth {
                client_ed25519_pub: [0; 32],
                sig: vec![],
            }),
        ];
        assert_eq!(names, ["AuthOk", "PairStart", "ClientAuth"]);
    }
}
