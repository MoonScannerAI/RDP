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
//!
//! [`AuthMsg`]: directdesk_shared::protocol::AuthMsg
//! [`MAX_AUTH_MSG`]: directdesk_shared::protocol::MAX_AUTH_MSG
//! [`QuicSession`]: directdesk_shared::transport::session::QuicSession
//! [`ReleaseGuard`]: serve::ReleaseGuard

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crossbeam_channel::{Receiver as CbReceiver, Sender as CbSender};
use parking_lot::Mutex;
use quinn::Connection;
use tokio::sync::mpsc;

use directdesk_shared::crypto::auth::{TrustedPeers, TRUSTED_CLIENTS_KEY};
use directdesk_shared::crypto::storage::SecretStore;
use directdesk_shared::crypto::{fingerprint_short, HostIdentity};
use directdesk_shared::protocol::{Channel, QualityMode};
use directdesk_shared::stats::{ConnStats, TransportRoute};
use directdesk_shared::transport::quic::QuicParams;
use directdesk_shared::{Error, Result};

use crate::session::{HostSession, SessionConfig as PipelineConfig, SessionState};

mod adaptation;
mod audio;
mod egress;
mod elevation;
mod handshake;
mod pairing;
mod serve;

use handshake::accept_loop;

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
pub use serve::CLIENT_KEYFRAME_MIN_INTERVAL_MS;

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

/// What the system-audio sender is actually doing right now.
///
/// Four of these five states all look like "audio doesn't work" from the
/// client's chair, and they have completely different causes and fixes. Without
/// a report that tells them apart, the only evidence a support conversation can
/// produce is "I hear nothing", which is unfalsifiable: it is equally consistent
/// with a machine that has no playback device, a machine sitting at its lock
/// screen, a machine playing nothing, and a machine whose packets are all being
/// dropped for want of send-buffer room.
///
/// Deliberately **not** in [`ConnStats`]: that struct's encoding is pinned
/// byte-for-byte by the anti-brick suite and is exchanged with already-deployed
/// peers, so a field added there would fail every session on its first stats
/// tick. This is host-local diagnostics and never crosses the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AudioStatus {
    /// The feature is off, or no client has negotiated it. No thread is running.
    #[default]
    Disabled,
    /// The thread is running but cannot open a capture endpoint: no playback
    /// device, an unsupported mix format (5.1, 96 kHz), the Windows Audio
    /// service down, or the AAC MFT refusing to start. Retried with backoff.
    NoEndpoint,
    /// Capture is healthy and deliberately silenced, because the host is on the
    /// secure desktop (UAC prompt, lock screen, Ctrl-Alt-Del).
    Muted,
    /// Capture is healthy and the desktop is silent, so nothing is being sent.
    /// This is the normal resting state and costs zero bandwidth.
    Idle,
    /// Packets are going out.
    Streaming,
}

impl AudioStatus {
    /// Wire-free encoding for the sender thread's [`AtomicU8`]. These numbers
    /// never leave the process, so they carry no compatibility obligation.
    fn as_u8(self) -> u8 {
        match self {
            AudioStatus::Disabled => 0,
            AudioStatus::NoEndpoint => 1,
            AudioStatus::Muted => 2,
            AudioStatus::Idle => 3,
            AudioStatus::Streaming => 4,
        }
    }

    /// Inverse of [`AudioStatus::as_u8`]. An unknown byte reads as
    /// [`AudioStatus::Disabled`] rather than panicking — a diagnostic must
    /// never be the thing that takes a session down.
    fn from_u8(v: u8) -> Self {
        match v {
            1 => AudioStatus::NoEndpoint,
            2 => AudioStatus::Muted,
            3 => AudioStatus::Idle,
            4 => AudioStatus::Streaming,
            _ => AudioStatus::Disabled,
        }
    }
}

/// What the **second** video stream is doing, when a client has selected a
/// second monitor.
///
/// Deliberately **not** in [`ConnStats`], for exactly the reason [`AudioStatus`]
/// is not: that struct's encoding is pinned byte-for-byte by the anti-brick
/// suite and is decoded positionally by already-deployed peers, so a field added
/// there would fail every session on its first stats tick. The client learns a
/// secondary stream's format from `ControlMsg::StreamConfig` and its health from
/// the frames arriving; this is the *host* operator's view, and it never crosses
/// the wire.
///
/// It exists because "the second monitor is black" has the same shape as the
/// audio problem: a pipeline that would not build, a monitor that was
/// unplugged, an encoder that fell back to software and cannot keep up, and a
/// stream whose every frame is being dropped for want of send-buffer room all
/// look identical from the client's chair, and have completely different fixes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecondaryStreamStatus {
    /// Which monitor this stream carries, as an id in the session's
    /// `MonitorList`. Session-scoped, not stable across reconnects.
    pub monitor_id: u8,
    pub resolution: (u32, u32),
    pub encoder: String,
    /// `false` means this stream fell back to a software encoder — the single
    /// most likely reason a second monitor is smooth on its own and stuttering
    /// beside the first.
    pub hardware_encoder: bool,
    /// The pipeline's own `SessionState`, formatted.
    pub state: String,
    /// This stream's share of the session's one adaptive budget. See
    /// `adaptation::split_bitrate`.
    pub target_kbps: u32,
    /// Observed, not requested.
    pub fps: u32,
    pub frames_sent: u64,
    pub bytes_sent: u64,
    /// Frames this stream skipped because the connection had no room for a
    /// whole one. Climbing here while the primary's stays flat is the two
    /// streams' reserves fighting over a link that cannot carry both.
    pub backpressured: u64,
}

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
    /// What the system-audio sender is doing. See [`AudioStatus`] for why this
    /// is five states and not a bool.
    pub audio_status: AudioStatus,
    /// Audio packets that reached `send_datagram`. Duplicates sent for
    /// redundancy are *not* counted here — see `audio_bytes_sent`.
    pub audio_packets_sent: u64,
    /// Audio bytes handed to `send_datagram`, redundant copies included, so
    /// this is the real cost of the feature on the link.
    pub audio_bytes_sent: u64,
    /// Audio packets dropped because sending one would have eaten into the
    /// send-buffer headroom the video pump's own precheck had already counted
    /// on. This climbing while `frames_backpressured` stays flat is the feature
    /// working exactly as designed: audio yields, the picture does not stutter.
    pub audio_backpressured: u64,
    /// Access units the encoder produced that were deliberately not sent
    /// because the desktop was silent or the host was on the secure desktop. A
    /// silent desktop costs zero bandwidth, and this is the evidence of it.
    pub audio_silent_suppressed: u64,
    /// The second video stream, when there is one. See
    /// [`SecondaryStreamStatus`] — host-local diagnostics, never on the wire.
    pub secondary: Option<SecondaryStreamStatus>,
    /// Every output this host can capture, as last enumerated for the session's
    /// `MonitorList`. Empty when multi-monitor is off or no client is
    /// connected. Host-local: the *client* gets this as `ControlMsg::
    /// MonitorList`, and this copy is what the host's own UI labels its
    /// outputs with.
    pub monitors: Vec<directdesk_shared::protocol::MonitorInfo>,
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
    // ---- system audio ----------------------------------------------------
    //
    // These four sit on `NetConfig` directly and NOT inside `NetConfig::pipeline`,
    // deliberately. `pipeline` is `crate::session::SessionConfig` — the media
    // pipeline's own configuration, handed to `HostSession::start` and read by
    // the media thread. Audio never touches the media pipeline: it is captured,
    // encoded and sent by one thread of its own in `net::audio` that has no
    // `HostSession` at all. Putting the knobs in `pipeline` would hand them to
    // the one component that has no use for them, and would rebuild the whole
    // D3D11/MF pipeline whenever one changed. Same precedent as
    // `uac_clickthrough` and `tile_max_kbps` above.
    /// Operator opt-in for system-audio capture. When `false` the host never
    /// offers [`features::SYSTEM_AUDIO`], so the bit is never mutual and the
    /// sender thread is never spawned.
    ///
    /// [`features::SYSTEM_AUDIO`]: directdesk_shared::protocol::features::SYSTEM_AUDIO
    pub system_audio_enabled: bool,
    /// Target AAC bitrate (kbps). See [`crate::config::HostConfig::system_audio_kbps`].
    pub system_audio_kbps: u32,
    /// Re-send each audio packet once, one packet later.
    pub system_audio_redundancy: bool,
    /// Loopback capture or the diagnostic tone.
    pub system_audio_source: crate::config::AudioSource,
    // ---- multiple monitors ----------------------------------------------
    //
    // On `NetConfig` and not inside `NetConfig::pipeline` for the same reason
    // the audio knobs above are: `pipeline` is the *persistent primary*
    // pipeline's configuration, and this flag decides what the session's
    // control plane offers and which extra pipelines it may build. Handing it
    // to `HostSession::start` would tie a wire-negotiation decision to a
    // D3D11/MF rebuild.
    /// Operator opt-in for multiple monitors. When `false` the host never
    /// offers [`features::MULTI_MONITOR`], so the bit is never mutual, no
    /// `MonitorList` is written, no second stream is ever built, and the wire
    /// is byte-identical to a host that predates the feature.
    ///
    /// [`features::MULTI_MONITOR`]: directdesk_shared::protocol::features::MULTI_MONITOR
    pub multi_monitor_enabled: bool,
}

/// Datagram send buffer used when a session may carry **two** video streams.
///
/// The single-stream default ([`DEFAULT_DATAGRAM_SEND_BUFFER`], 2 MiB) is sized
/// against one worst-case frame's reserve plus room to pace it out. With a
/// second video producer on the same datagram path both pumps hold a reserve
/// (see [`egress::video_pump`]'s precheck and [`audio`]'s `has_room`), and at a
/// 1200-byte MTU one worst-case frame is already 676,800 bytes — two of those
/// plus a frame in flight does not fit 2 MiB with anything left over for audio.
/// Doubling it is host-local: the datagram send buffer is one endpoint's own
/// queue and is never negotiated, so raising it changes no byte on the wire.
///
/// [`DEFAULT_DATAGRAM_SEND_BUFFER`]: directdesk_shared::transport::quic::DEFAULT_DATAGRAM_SEND_BUFFER
pub const MULTI_MONITOR_DATAGRAM_SEND_BUFFER: usize = 4 * 1024 * 1024;

impl NetConfig {
    /// Build from the persisted host config.
    pub fn from_host_config(cfg: &crate::config::HostConfig) -> Self {
        let mut quic = QuicParams::default();
        if cfg.multi_monitor_enabled {
            quic.datagram_send_buffer = MULTI_MONITOR_DATAGRAM_SEND_BUFFER;
        }
        Self {
            bind: SocketAddr::from(([0, 0, 0, 0], cfg.udp_port)),
            host_name: cfg.display_name.clone(),
            quality_mode: cfg.quality_mode,
            bitrate_cap_kbps: cfg.bitrate_cap_kbps,
            pipeline: cfg.pipeline(),
            quic,
            uac_clickthrough: cfg.uac_clickthrough,
            uac_arm_ttl_secs: cfg.uac_arm_ttl_secs,
            blank_wallpaper_during_session: cfg.blank_wallpaper_during_session,
            tile_max_kbps: cfg.lossless_tile_max_kbps,
            system_audio_enabled: cfg.system_audio_enabled,
            system_audio_kbps: cfg.system_audio_kbps,
            system_audio_redundancy: cfg.system_audio_redundancy,
            system_audio_source: cfg.system_audio_source,
            multi_monitor_enabled: cfg.multi_monitor_enabled,
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

// ---------------------------------------------------------------------------
// Session counters
// ---------------------------------------------------------------------------

// Written by the pumps in `egress`, read and reset by `serve::status_loop`.
// They stay here because they are the one piece of state those two modules
// share, and `StatusSnapshot` — which is also here — is where they end up.

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

#[derive(Default)]
struct TileCounters {
    strips_sent: AtomicU64,
    bytes_sent: AtomicU64,
    control_sent: AtomicU64,
}

/// Written by the `dd-audio-tx` thread in [`audio`], read by
/// `serve::status_loop`.
///
/// Deliberately **not** merged into [`ConnStats`]: see [`AudioStatus`].
#[derive(Default)]
struct AudioCounters {
    packets_sent: AtomicU64,
    /// Includes redundant copies; `packets_sent` does not.
    bytes_sent: AtomicU64,
    /// Packets dropped rather than displace video's already-counted headroom.
    backpressured: AtomicU64,
    /// Access units encoded (to keep the MDCT state coherent) but not sent.
    silent_suppressed: AtomicU64,
    /// An [`AudioStatus`] via [`AudioStatus::as_u8`]. A gauge, not a counter:
    /// the sender overwrites it, and the status loop only ever reads it.
    status: AtomicU8,
}

impl AudioCounters {
    fn set_status(&self, s: AudioStatus) {
        self.status.store(s.as_u8(), Ordering::Relaxed);
    }

    fn status(&self) -> AudioStatus {
        AudioStatus::from_u8(self.status.load(Ordering::Relaxed))
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
    fn audio_settings_reach_net_config_without_touching_the_pipeline() {
        use crate::config::AudioSource;

        let hc = crate::config::HostConfig {
            system_audio_enabled: true,
            system_audio_kbps: 128,
            system_audio_redundancy: true,
            system_audio_source: AudioSource::TestTone,
            ..Default::default()
        }
        .sanitized();
        let nc = NetConfig::from_host_config(&hc);
        assert!(nc.system_audio_enabled);
        assert_eq!(nc.system_audio_kbps, 128);
        assert!(nc.system_audio_redundancy);
        assert_eq!(nc.system_audio_source, AudioSource::TestTone);

        // And the shipped default carries none of it, which is what makes the
        // rollout's first step a no-op on the wire.
        let off = NetConfig::from_host_config(&crate::config::HostConfig::default().sanitized());
        assert!(!off.system_audio_enabled);
    }

    #[test]
    fn multi_monitor_reaches_net_config_and_widens_only_the_send_buffer() {
        use directdesk_shared::transport::quic::DEFAULT_DATAGRAM_SEND_BUFFER;

        // Shipped default: off, and the transport parameters are the ones every
        // already-deployed peer sees today.
        let off = NetConfig::from_host_config(&crate::config::HostConfig::default().sanitized());
        assert!(!off.multi_monitor_enabled);
        assert_eq!(off.quic, QuicParams::default());

        let on = NetConfig::from_host_config(
            &crate::config::HostConfig {
                multi_monitor_enabled: true,
                ..Default::default()
            }
            .sanitized(),
        );
        assert!(on.multi_monitor_enabled);
        // Two video producers each hold a worst-case-frame reserve, so the
        // single-stream buffer is not big enough for both plus audio.
        assert_eq!(
            on.quic.datagram_send_buffer,
            MULTI_MONITOR_DATAGRAM_SEND_BUFFER
        );
        assert!(on.quic.datagram_send_buffer > DEFAULT_DATAGRAM_SEND_BUFFER);
        assert!(on.quic.validate().is_ok());
        // ...and nothing else about the transport moved. The send buffer is a
        // local queue and is never negotiated; every parameter the peer can
        // observe must stay exactly as it was.
        assert_eq!(
            QuicParams {
                datagram_send_buffer: DEFAULT_DATAGRAM_SEND_BUFFER,
                ..on.quic.clone()
            },
            QuicParams::default(),
            "enabling multi-monitor changed a transport parameter other than \
             the host-local datagram send buffer"
        );
    }

    #[test]
    fn audio_status_survives_the_atomic_round_trip() {
        for s in [
            AudioStatus::Disabled,
            AudioStatus::NoEndpoint,
            AudioStatus::Muted,
            AudioStatus::Idle,
            AudioStatus::Streaming,
        ] {
            assert_eq!(AudioStatus::from_u8(s.as_u8()), s);
        }
        // Distinct codes, or two realities would report as one — which is the
        // entire reason this enum exists rather than a bool.
        let codes: Vec<u8> = [
            AudioStatus::Disabled,
            AudioStatus::NoEndpoint,
            AudioStatus::Muted,
            AudioStatus::Idle,
            AudioStatus::Streaming,
        ]
        .iter()
        .map(|s| s.as_u8())
        .collect();
        let mut sorted = codes.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), codes.len());

        // A byte nobody assigned must read as "off", never panic: this is a
        // diagnostic, and a diagnostic may not be what ends a session.
        assert_eq!(AudioStatus::from_u8(200), AudioStatus::Disabled);
        assert_eq!(AudioStatus::default(), AudioStatus::Disabled);

        let c = AudioCounters::default();
        assert_eq!(c.status(), AudioStatus::Disabled);
        c.set_status(AudioStatus::Streaming);
        assert_eq!(c.status(), AudioStatus::Streaming);
    }

    #[test]
    fn audio_diagnostics_are_host_local_and_never_touch_conn_stats() {
        // ConnStats rides inside `ControlMsg::Stats` and is decoded
        // positionally by already-deployed peers, so an audio field added
        // *there* would fail every session on its first stats tick — the
        // anti-brick suite pins its encoding for exactly that reason. The audio
        // counters therefore live on StatusSnapshot, which never crosses the
        // wire. Recording a full set of them must leave both embedded
        // `ConnStats` bit-identical to a default one.
        let s = StatusSnapshot {
            audio_status: AudioStatus::Streaming,
            audio_packets_sent: 1_234,
            audio_bytes_sent: 567_890,
            audio_backpressured: 7,
            audio_silent_suppressed: 42,
            ..Default::default()
        };

        assert_eq!(
            s.transport,
            ConnStats::default(),
            "an audio counter reached the wire stats struct"
        );
        assert_eq!(s.pipeline, ConnStats::default());
    }

    #[test]
    fn multi_monitor_diagnostics_are_host_local_and_never_touch_conn_stats() {
        // Same guard as `audio_diagnostics_are_host_local_...` above, and for
        // the same reason: `ConnStats` rides inside `ControlMsg::Stats`, is
        // decoded positionally by already-deployed peers, and is pinned
        // byte-for-byte by the anti-brick suite. A second monitor's numbers
        // therefore live on `StatusSnapshot`, which never crosses the wire —
        // what the *client* is told about a secondary stream is
        // `ControlMsg::StreamConfig`, a message of its own that only a peer
        // which negotiated MULTI_MONITOR ever receives.
        //
        // The merge that does reach the wire is `serve::merge_media_stats`,
        // which folds both pipelines into the existing fields and adds none.
        let s = StatusSnapshot {
            secondary: Some(SecondaryStreamStatus {
                monitor_id: 1,
                resolution: (2_560, 1_440),
                encoder: "NVIDIA H.264".into(),
                hardware_encoder: true,
                state: "Running".into(),
                target_kbps: 4_000,
                fps: 60,
                frames_sent: 9_001,
                bytes_sent: 123_456_789,
                backpressured: 12,
            }),
            monitors: vec![directdesk_shared::protocol::MonitorInfo {
                id: 0,
                width: 2_560,
                height: 1_600,
                origin_x: 0,
                origin_y: 0,
                is_primary: true,
                name: r"\\.\DISPLAY1".into(),
            }],
            ..Default::default()
        };

        assert_eq!(
            s.transport,
            ConnStats::default(),
            "a multi-monitor field reached the wire stats struct"
        );
        assert_eq!(s.pipeline, ConnStats::default());

        // And the shipped default carries neither, so an idle host reports
        // exactly what it always did.
        let idle = StatusSnapshot::default();
        assert!(idle.secondary.is_none());
        assert!(idle.monitors.is_empty());
    }

    // -- route -------------------------------------------------------------

    #[test]
    fn the_host_never_claims_a_route_it_does_not_have() {
        assert_eq!(HOST_ROUTE, TransportRoute::DirectUdp);
        assert!(HOST_ROUTE.is_direct());
    }
}
