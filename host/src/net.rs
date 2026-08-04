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
//! for a live desktop. [`video_pump`] instead coalesces the encoder's backlog
//! and sends only the freshest frame, then asks for an IDR because dropping a
//! P-frame breaks the reference chain.
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

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use crossbeam_channel::{Receiver as CbReceiver, Sender as CbSender};
use parking_lot::Mutex;
use quinn::Connection;
use tokio::sync::mpsc;

use directdesk_shared::adapt::{AdaptConfig, BitrateAdaptor};
use directdesk_shared::crypto::auth::{
    HostAuthenticator, TrustedPeer, TrustedPeers, TRUSTED_CLIENTS_KEY,
};
use directdesk_shared::crypto::pairing::{PairingCode, PairingHost, PAIRING_TTL_MS};
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
use directdesk_shared::video::{fragment_frame_fec, EncodedFrame};
use directdesk_shared::{Error, Result};

use crate::session::{HostSession, SessionConfig as PipelineConfig, SessionState};

/// Wall-clock budget for everything from `accept_streams` to `AuthOk`.
pub const HANDSHAKE_TIMEOUT_MS: u64 = 15_000;
/// Consecutive authentication failures from one address before a lockout.
pub const AUTH_FAIL_LIMIT: u32 = 3;
/// How long an address stays locked out after [`AUTH_FAIL_LIMIT`] failures.
pub const AUTH_LOCKOUT_MS: u64 = 30_000;
/// Failures older than this stop counting toward the limit.
pub const AUTH_FAIL_WINDOW_MS: u64 = 60_000;
/// Floor on how often a client's `RequestKeyframe` is honoured.
pub const KEYFRAME_MIN_INTERVAL_MS: u64 = 500;
/// Period of the host's `Stats` / `RouteReport` broadcast.
pub const STATUS_INTERVAL_MS: u64 = 1_000;
/// Status windows a stream must run before the encoder-vs-carried `overrun`
/// diagnostic is trusted to move the adaptor. The first windows measure the
/// encoder over a full interval while the transport has barely begun carrying
/// the stream, so their ratio is a window artifact — not congestion. Gating on
/// it is what stops the spurious start-up downshift.
pub const OVERRUN_WARMUP_INTERVALS: u32 = 3;
/// Frames that must actually have gone out in a window for that window's
/// `overrun` ratio to mean anything. A window where we barely sent (idle, or a
/// stream that just stopped) cannot report meaningful carried bitrate.
pub const OVERRUN_MIN_FRAMES: u64 = 5;
/// QUIC application close code used for a rejected connection.
pub const CLOSE_CODE_REJECTED: u32 = 1;
/// QUIC application close code used for a deliberate host-side disconnect.
pub const CLOSE_CODE_DISCONNECT: u32 = 2;

/// The route this build can offer. QUIC over UDP only; the TCP fallback and
/// relay live in another wave and must never be claimed here.
pub const HOST_ROUTE: TransportRoute = TransportRoute::DirectUdp;

// ---------------------------------------------------------------------------
// Pairing window
// ---------------------------------------------------------------------------

/// What the UI needs to render an armed pairing code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingDisplay {
    /// The eight digits, already grouped as `1234 5678`.
    pub grouped: String,
    /// The raw digits. Present because the UI must display them and the
    /// loopback test must be able to type them; never logged.
    pub digits: String,
    /// Milliseconds until the code stops being accepted.
    pub remaining_ms: u64,
}

struct Armed {
    code: PairingCode,
    armed_ms: u64,
    ttl_ms: u64,
}

/// The host's single pairing window, and the monotonic clock everything else
/// in this module is timed against.
///
/// Shared between the UI (which arms it and shows the countdown) and the
/// listener (which consumes it). The state machine itself takes `now_ms` on
/// every call, so expiry is testable without sleeping; [`Self::now_ms`] is the
/// one place that reads a clock, and it is an [`Instant`], never the wall
/// clock, so a system time change cannot extend or void a pairing window.
///
/// Both halves share one slot precisely so the countdown the user is reading
/// and the deadline the listener enforces cannot drift apart.
pub struct PairingSlot {
    inner: Mutex<Option<Armed>>,
    clock: Instant,
}

impl Default for PairingSlot {
    fn default() -> Self {
        Self {
            inner: Mutex::new(None),
            clock: Instant::now(),
        }
    }
}

impl std::fmt::Debug for PairingSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let armed = self.inner.lock().is_some();
        f.debug_struct("PairingSlot")
            .field("armed", &armed)
            .finish()
    }
}

impl PairingSlot {
    pub fn new() -> Self {
        Self::default()
    }

    /// Milliseconds since this slot was created. The shared time base for the
    /// pairing window, the authentication throttle and every rate limiter.
    pub fn now_ms(&self) -> u64 {
        self.clock.elapsed().as_millis() as u64
    }

    /// Arm with a fresh random code, replacing anything already armed.
    pub fn arm(&self, now_ms: u64) -> PairingDisplay {
        self.arm_with(PairingCode::generate(), now_ms, PAIRING_TTL_MS)
    }

    /// Arm with a specific code and TTL. Used by tests.
    pub fn arm_with(&self, code: PairingCode, now_ms: u64, ttl_ms: u64) -> PairingDisplay {
        let display = PairingDisplay {
            grouped: code.display_grouped(),
            digits: code.expose().to_string(),
            remaining_ms: ttl_ms,
        };
        *self.inner.lock() = Some(Armed {
            code,
            armed_ms: now_ms,
            ttl_ms,
        });
        display
    }

    /// The armed code, or `None` when nothing is armed or it has expired.
    ///
    /// Expiry is evaluated lazily here so the UI's countdown and the
    /// listener's acceptance decision can never disagree.
    pub fn snapshot(&self, now_ms: u64) -> Option<PairingDisplay> {
        let mut guard = self.inner.lock();
        let armed = guard.as_ref()?;
        match remaining_ms(armed, now_ms) {
            Some(remaining_ms) => Some(PairingDisplay {
                grouped: armed.code.display_grouped(),
                digits: armed.code.expose().to_string(),
                remaining_ms,
            }),
            None => {
                *guard = None;
                None
            }
        }
    }

    /// Whether a live code is armed right now.
    pub fn is_armed(&self, now_ms: u64) -> bool {
        self.snapshot(now_ms).is_some()
    }

    /// Consume the code. Single use: a second `PairStart` finds nothing.
    fn take(&self, now_ms: u64) -> Option<Armed> {
        let mut guard = self.inner.lock();
        let armed = guard.take()?;
        remaining_ms(&armed, now_ms).map(|_| armed)
    }

    /// Cancel an armed code (user pressed Cancel, or pairing finished).
    pub fn clear(&self) {
        *self.inner.lock() = None;
    }
}

fn remaining_ms(armed: &Armed, now_ms: u64) -> Option<u64> {
    let deadline = armed.armed_ms.saturating_add(armed.ttl_ms);
    if now_ms > deadline {
        None
    } else {
        Some(deadline - now_ms)
    }
}

// ---------------------------------------------------------------------------
// Failed-authentication throttle
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct FailRecord {
    failures: u32,
    last_fail_ms: u64,
    locked_until_ms: u64,
}

/// Per-source-address lockout after repeated authentication failures.
///
/// Pairing codes are eight digits and single-use, and the trusted-key check is
/// a signature verification — neither is guessable online. This exists to make
/// a scripted attempt expensive and, more usefully, to make the attempt
/// *visible* in the UI and the log.
#[derive(Debug, Default)]
pub struct AuthThrottle {
    peers: HashMap<IpAddr, FailRecord>,
}

impl AuthThrottle {
    pub fn new() -> Self {
        Self::default()
    }

    /// Milliseconds this address must wait, or `None` if it may try now.
    pub fn locked_for_ms(&self, ip: &IpAddr, now_ms: u64) -> Option<u64> {
        let rec = self.peers.get(ip)?;
        (rec.locked_until_ms > now_ms).then(|| rec.locked_until_ms - now_ms)
    }

    /// Record a failure. Returns `true` when this failure triggered a lockout.
    pub fn record_failure(&mut self, ip: IpAddr, now_ms: u64) -> bool {
        self.gc(now_ms);
        let rec = self.peers.entry(ip).or_insert(FailRecord {
            failures: 0,
            last_fail_ms: now_ms,
            locked_until_ms: 0,
        });
        // A long-quiet address starts over rather than accumulating forever.
        if now_ms.saturating_sub(rec.last_fail_ms) > AUTH_FAIL_WINDOW_MS {
            rec.failures = 0;
        }
        rec.failures += 1;
        rec.last_fail_ms = now_ms;
        if rec.failures >= AUTH_FAIL_LIMIT {
            rec.failures = 0;
            rec.locked_until_ms = now_ms.saturating_add(AUTH_LOCKOUT_MS);
            true
        } else {
            false
        }
    }

    /// A successful authentication clears the address's history.
    pub fn record_success(&mut self, ip: &IpAddr) {
        self.peers.remove(ip);
    }

    /// Number of addresses currently being tracked.
    pub fn tracked(&self) -> usize {
        self.peers.len()
    }

    fn gc(&mut self, now_ms: u64) {
        self.peers.retain(|_, r| {
            r.locked_until_ms > now_ms
                || now_ms.saturating_sub(r.last_fail_ms) <= AUTH_FAIL_WINDOW_MS
        });
    }
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

/// "At most once per interval", with the clock injected.
#[derive(Debug, Clone, Copy)]
pub struct RateLimiter {
    min_interval_ms: u64,
    last_ms: Option<u64>,
}

impl RateLimiter {
    pub fn new(min_interval_ms: u64) -> Self {
        Self {
            min_interval_ms,
            last_ms: None,
        }
    }

    /// Whether the action may run now; records the time when it may.
    pub fn allow(&mut self, now_ms: u64) -> bool {
        match self.last_ms {
            Some(last) if now_ms.saturating_sub(last) < self.min_interval_ms => false,
            _ => {
                self.last_ms = Some(now_ms);
                true
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Frame drop policy
// ---------------------------------------------------------------------------

/// Bytes a frame will occupy in the datagram send buffer once fragmented.
///
/// [`fragment_frame`] splits the payload into `mtu - FRAG_HEADER_LEN` chunks
/// and puts a header on each, so the buffered total is the payload plus one
/// header per fragment.
pub fn wire_size(frame: &EncodedFrame, mtu: usize) -> usize {
    use directdesk_shared::video::FRAG_HEADER_LEN;
    let chunk = mtu.saturating_sub(FRAG_HEADER_LEN).max(1);
    let frags = frame.data.len().div_ceil(chunk);
    frame.data.len() + frags * FRAG_HEADER_LEN
}

/// How far the encoder is outrunning what the connection actually carries,
/// expressed as the 0..1 congestion signal [`BitrateAdaptor`] expects.
///
/// This is the signal that packet loss cannot provide. QUIC datagrams are
/// unreliable by design: when the congestion controller cannot place them,
/// quinn discards them itself, without an error, without filling its send
/// buffer, and — because nothing was ever put on the wire — without a single
/// lost *packet*. A host watching only `loss` therefore sees a perfectly clean
/// link while half its video evaporates. Comparing what the encoder produced
/// against what the transport moved is what makes that visible.
///
/// The 15% slack keeps normal measurement noise and protocol overhead from
/// being mistaken for congestion.
pub fn overrun_signal(encoder_kbps: u32, carried_kbps: u32) -> f32 {
    if encoder_kbps == 0 || carried_kbps == 0 {
        return 0.0;
    }
    let produced = encoder_kbps as f32;
    let carried = carried_kbps as f32;
    if produced <= carried * 1.15 {
        return 0.0;
    }
    ((produced - carried) / produced).clamp(0.0, 1.0)
}

/// Host-side delivery over a **single matched status window**.
///
/// Every field is a delta measured across the *same* interval — never a
/// lifetime total. The old diagnostic compared a session-lifetime send count
/// against a one-second client report, so a link that had been up for a minute
/// looked ~50% "lossy" the instant the client's window began. Deltas over one
/// shared window cannot drift like that.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct WindowDelivery {
    /// Frames actually put on the wire this window.
    pub sent: u64,
    /// Frames offered to the link this window: sent plus those the link had no
    /// room for. Frames merely coalesced (a newer one superseded them) are not
    /// offered and so are not counted here.
    pub offered: u64,
    /// Bytes put on the wire this window.
    pub bytes: u64,
    /// Length of the window, milliseconds.
    pub dt_ms: u64,
}

impl WindowDelivery {
    /// Fraction of offered frames that actually reached the wire, `0.0..=1.0`.
    /// An idle window (`offered == 0`) delivered everything it was asked to, so
    /// it reads `1.0` rather than dividing by zero into a false shortfall.
    pub fn delivery_ratio(&self) -> f32 {
        if self.offered == 0 {
            1.0
        } else {
            (self.sent as f32 / self.offered as f32).clamp(0.0, 1.0)
        }
    }

    /// Fraction of offered frames the link had no room for, `0.0..=1.0`. This is
    /// congestion quinn's packet-loss counter cannot see (the frame was never
    /// sent) and the receiver's reassembler cannot see either (nothing to
    /// reassemble), so it is a genuine, matched-window congestion signal.
    pub fn backpressure_ratio(&self) -> f32 {
        if self.offered == 0 {
            0.0
        } else {
            (self.offered.saturating_sub(self.sent) as f32 / self.offered as f32).clamp(0.0, 1.0)
        }
    }

    /// Throughput actually carried this window, kbps. Bytes over the real
    /// elapsed window, not a nominal tick length.
    pub fn throughput_kbps(&self) -> u32 {
        if self.dt_ms == 0 {
            0
        } else {
            ((self.bytes as f64 * 8.0) / self.dt_ms as f64).min(u32::MAX as f64) as u32
        }
    }
}

/// The single congestion number the [`BitrateAdaptor`] observes for one window.
///
/// `loss` is the transport's real, matched-window application-level loss — the
/// [`ConnStats::loss`] that already folds in the receiver's silent-datagram
/// accounting *and* quinn's packet loss upstream. `backpressure` is host frames
/// the link had no room for this window. `overrun` is the encoder-vs-carried
/// *diagnostic*, and is only folded in once `warm`: before warm-up its two
/// inputs are measured over mismatched, half-empty windows and their ratio is
/// meaningless, so feeding it to the adaptor is exactly the spurious-downshift
/// bug. The adaptor is therefore *driven by the real loss*, with the diagnostic
/// gated out until it can be trusted.
pub fn congestion_signal(loss: f32, backpressure: f32, overrun: f32, warm: bool) -> f32 {
    let overrun = if warm { overrun } else { 0.0 };
    loss.max(backpressure).max(overrun).clamp(0.0, 1.0)
}

/// Combine the host's standing cap with a client's `BitrateLimit`. A client can
/// only narrow the cap, never widen it.
pub fn effective_cap(host_cap: Option<u32>, client_limit: Option<u32>) -> Option<u32> {
    match (host_cap, client_limit) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, b) => b,
    }
}

/// Clamp a bitrate target to a hard cap, if one is set.
pub fn clamp_to_cap(kbps: u32, cap: Option<u32>) -> u32 {
    match cap {
        Some(c) => kbps.min(c),
        None => kbps,
    }
}

/// Latest-wins: keep the newest frame the encoder has produced and report how
/// many older ones were skipped.
///
/// The queue behind `rx` is the encoder's output. If we are keeping up it is
/// empty and nothing is dropped. If we are behind — a slow link, a big IDR
/// still being fragmented — every queued frame except the last is already
/// stale, and sending it would only delay the one the user actually wants.
pub fn coalesce_latest(first: EncodedFrame, rx: &CbReceiver<EncodedFrame>) -> (EncodedFrame, u32) {
    let mut newest = first;
    let mut dropped = 0u32;
    while let Ok(next) = rx.try_recv() {
        dropped += 1;
        newest = next;
    }
    (newest, dropped)
}

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
    /// Delivery/throughput over the most recent matched status window. Honest
    /// per-window figures, distinct from the lifetime counters below.
    pub delivery: WindowDelivery,
    /// Frames skipped by the latest-wins policy since the session started.
    pub frames_coalesced: u64,
    /// Frames skipped because the connection had no room for a whole one.
    pub frames_backpressured: u64,
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

        let cfg = self.cfg.pipeline.clone();
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
            quality: Mutex::new(cfg.quality_mode),
            bitrate_cap: Mutex::new(cfg.bitrate_cap_kbps),
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

    let (streams, client) = match handshake {
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

    let reason = run_session(&inner, conn, streams).await;
    tracing::info!(peer = %peer, "client disconnected: {reason}");
    inner.emit(NetEvent::ClientDisconnected { reason });
    Ok(())
}

fn host_hello() -> Hello {
    Hello {
        version: PROTOCOL_VERSION,
        features: 0,
        agent: concat!("directdesk-host ", env!("CARGO_PKG_VERSION")).to_string(),
    }
}

/// Tell a second client the host is taken, in the framing it is expecting.
async fn reject_busy(conn: &Connection) {
    let deadline = Duration::from_millis(3_000);
    let _ = tokio::time::timeout(deadline, async {
        let mut streams = quic::accept_streams(conn).await?;
        let _ = quic::read_framed::<Hello>(&mut streams.control.1, MAX_AUTH_MSG).await;
        quic::write_framed(&mut streams.control.0, &host_hello()).await?;
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
/// Returns the session's streams and the client record on success. Every error
/// path has already told the client `AuthFail` with a deliberately vague
/// reason: "not paired" and "bad signature" must not be distinguishable.
async fn authenticate(
    inner: &Arc<Inner>,
    conn: &Connection,
) -> Result<(SessionStreams, TrustedPeer)> {
    let mut streams = quic::accept_streams(conn).await?;

    let hello: Hello = quic::read_framed(&mut streams.control.1, MAX_AUTH_MSG).await?;
    directdesk_shared::protocol::validate_hello(&hello)?;
    quic::write_framed(&mut streams.control.0, &host_hello()).await?;
    tracing::debug!(agent = %hello.agent, "client hello accepted");

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
    Ok((streams, peer))
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
}

/// Drive one authenticated client until the connection ends.
///
/// Returns the reason the session finished, for the log and the UI.
async fn run_session(inner: &Arc<Inner>, conn: Connection, streams: SessionStreams) -> String {
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

    let driver_cfg = DriverConfig {
        heartbeat_ms: 2_000,
        stats_interval_ms: STATUS_INTERVAL_MS,
        control_capacity: 64,
        input_capacity: 512,
        video_capacity: 8,
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
        let fps = inner.cfg.pipeline.target_fps.max(1);
        std::thread::Builder::new()
            .name("dd-video-tx".into())
            .spawn(move || video_pump(conn, frames, pipeline, streaming, stop, counters, fps))
            .ok()
    };
    if video.is_none() {
        tracing::error!("could not spawn the video sender thread");
    }

    let tasks = vec![
        tokio::spawn(input_loop(receivers.input, pipeline.clone())),
        tokio::spawn(control_loop(
            inner.clone(),
            receivers.control,
            session.clone(),
            pipeline.clone(),
            streaming.clone(),
            adaptor.clone(),
        )),
        tokio::spawn(status_loop(
            inner.clone(),
            session.clone(),
            pipeline.clone(),
            adaptor,
            counters.clone(),
        )),
        tokio::spawn(event_loop(
            inner.clone(),
            receivers.events,
            pipeline.clone(),
        )),
    ];

    let reason = conn.closed().await.to_string();

    stop.store(true, Ordering::SeqCst);
    streaming.store(false, Ordering::SeqCst);
    for t in tasks {
        t.abort();
    }
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
        s.transport = ConnStats::default();
        s.delivery = WindowDelivery::default();
        s.quality_mode = None;
    });
    reason
}

/// Below this fragment count a frame is small enough to send in one go; pacing
/// only matters for the big multi-datagram frames (keyframes, heavy motion)
/// that otherwise hit the link as a loss-inducing burst.
const PACING_MIN_FRAGS: usize = 8;
/// Datagrams per paced sub-burst (one `send_datagram` batch between sleeps).
const PACING_BATCH: usize = 4;
/// FEC block size K: one XOR-parity fragment is appended per this many data
/// fragments, so any single lost data fragment in a block is reconstructed by
/// the receiver with no keyframe stall. `0` would disable FEC.
const FEC_BLOCK_SIZE: u8 = 10;

/// RAII: raise the Windows timer resolution to 1 ms for the video sender's
/// lifetime so the sub-frame pacing sleeps are actually honoured — the default
/// ~15 ms scheduler tick would round a 2 ms sleep up to 15 ms and wildly
/// over-pace. Restored on drop.
struct TimerResolution;
impl TimerResolution {
    fn acquire() -> Self {
        // SAFETY: documented winmm call, paired with timeEndPeriod(1) in Drop.
        unsafe {
            let _ = windows::Win32::Media::timeBeginPeriod(1);
        }
        TimerResolution
    }
}
impl Drop for TimerResolution {
    fn drop(&mut self) {
        // SAFETY: matches the timeBeginPeriod(1) from acquire().
        unsafe {
            let _ = windows::Win32::Media::timeEndPeriod(1);
        }
    }
}

/// Fragment encoded frames into datagrams, newest-first.
fn video_pump(
    conn: Connection,
    frames: CbReceiver<EncodedFrame>,
    pipeline: Arc<HostSession>,
    streaming: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    counters: Arc<VideoCounters>,
    target_fps: u32,
) {
    crate::session::lower_video_thread_priority("video-tx");
    let _timer = TimerResolution::acquire();
    // Spread a frame's fragments across ~60% of a frame interval so the next
    // frame is still not due when we finish, i.e. pacing adds smoothing without
    // adding steady-state latency.
    let pace_window = Duration::from_micros(1_000_000 / target_fps.max(1) as u64) * 3 / 5;
    let start = Instant::now();
    let mut idr = RateLimiter::new(KEYFRAME_MIN_INTERVAL_MS);

    while !stop.load(Ordering::Relaxed) {
        let frame = match frames.recv_timeout(Duration::from_millis(200)) {
            Ok(f) => f,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        };
        if !streaming.load(Ordering::Relaxed) {
            // Not streaming: the frame is discarded here rather than left to
            // rot in the queue, so the encoder's eviction stays meaningful.
            continue;
        }

        let (frame, dropped) = coalesce_latest(frame, &frames);
        if dropped > 0 {
            counters
                .coalesced
                .fetch_add(dropped as u64, Ordering::Relaxed);
            // Skipping a P-frame breaks the client's reference chain. Ask for
            // an IDR, but not more than twice a second or a congested link
            // turns into a keyframe storm.
            if idr.allow(start.elapsed().as_millis() as u64) {
                pipeline.request_keyframe();
            }
        }

        let mtu = match conn.max_datagram_size() {
            Some(m) => m,
            None => {
                tracing::error!("peer stopped accepting datagrams; video cannot continue");
                break;
            }
        };

        // Do not offer a frame the connection cannot take whole.
        //
        // `send_datagram` never blocks and never refuses: when its buffer is
        // full quinn silently evicts the *oldest* queued datagrams to make
        // room. Offering more than fits therefore does not drop this frame, it
        // shreds the one already in flight — and a frame missing one fragment
        // is as useless as a frame that never arrived, so the result is two
        // wasted frames instead of one. Skipping cleanly here costs one frame
        // and keeps every frame that is sent decodable.
        if conn.datagram_send_buffer_space() < wire_size(&frame, mtu) {
            counters.backpressured.fetch_add(1, Ordering::Relaxed);
            if idr.allow(start.elapsed().as_millis() as u64) {
                pipeline.request_keyframe();
            }
            continue;
        }

        // FEC parity fragments are appended after the data fragments. The
        // buffer-space precheck above still guards only the DATA frame; the
        // parity is best-effort, so if it cannot be placed the frame is still
        // whole and decodable on its own.
        let frags = match fragment_frame_fec(&frame, mtu, FEC_BLOCK_SIZE) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!("cannot fragment frame {}: {e}", frame.frame_id);
                continue;
            }
        };

        let mut bytes = 0u64;
        let mut failed = false;
        let n = frags.len();
        // Small frames go out immediately; large ones are spread so a keyframe
        // burst can't tail-drop (which would make quinn evict older queued
        // datagrams and shred an in-flight frame).
        let gap = if n > PACING_MIN_FRAGS {
            let batches = (n as u32).div_ceil(PACING_BATCH as u32).max(1);
            pace_window / batches
        } else {
            Duration::ZERO
        };
        for (i, frag) in frags.into_iter().enumerate() {
            if !gap.is_zero() && i > 0 && i % PACING_BATCH == 0 {
                std::thread::sleep(gap);
            }
            bytes += frag.len() as u64;
            if let Err(e) = conn.send_datagram(Bytes::from(frag)) {
                match e {
                    quinn::SendDatagramError::ConnectionLost(_) => failed = true,
                    other => tracing::warn!("datagram dropped: {other}"),
                }
                break;
            }
        }
        if failed {
            break;
        }
        counters.frames_sent.fetch_add(1, Ordering::Relaxed);
        counters.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }
    tracing::debug!("video sender finished");
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
async fn control_loop(
    inner: Arc<Inner>,
    mut rx: mpsc::Receiver<ControlMsg>,
    session: Arc<QuicSession>,
    pipeline: Arc<HostSession>,
    streaming: Arc<AtomicBool>,
    adaptor: Arc<Mutex<BitrateAdaptor>>,
) {
    let mut keyframes = RateLimiter::new(KEYFRAME_MIN_INTERVAL_MS);

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
                    fps: inner.cfg.pipeline.target_fps,
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

/// Periodic host → client status, and the adaptive bitrate loop.
async fn status_loop(
    inner: Arc<Inner>,
    session: Arc<QuicSession>,
    pipeline: Arc<HostSession>,
    adaptor: Arc<Mutex<BitrateAdaptor>>,
    counters: Arc<VideoCounters>,
) {
    let mut ticker = tokio::time::interval(Duration::from_millis(STATUS_INTERVAL_MS));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_paused: Option<bool> = None;
    let mut prev_sent = 0u64;
    let mut prev_bytes = 0u64;
    let mut prev_backpressured = 0u64;
    let mut prev_now = inner.now_ms();
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
        let congestion = congestion_signal(transport.loss, pressure, overrun, warm);
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
        inner.status_mut(|s| {
            s.transport = transport;
            s.pipeline = merged;
            s.pipeline_state = Some(format!("{state:?}"));
            s.secure_desktop = paused;
            s.quality_mode = Some(quality_mode);
            s.delivery = delivery;
            s.frames_sent = sent;
            s.bytes_sent = bytes;
            s.frames_coalesced = counters.coalesced.load(Ordering::Relaxed);
            s.frames_backpressured = backpressured;
            s.input_injected = injected;
        });
        // Cumulative injected count beside the send rate: under full video load
        // this should keep climbing as the client types (proving input is not
        // starved by encode). It stalling while frames_sent races is the
        // signature of the input-priority bug.
        tracing::info!(input_injected = injected, frames_sent = sent, "host input diag");
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
    use directdesk_shared::crypto::pairing::PAIRING_CODE_DIGITS;
    // Data-only fragmenter: `wire_size` models exactly its output, so the tests
    // that pin that relationship exercise it directly.
    use directdesk_shared::video::fragment_frame;

    // -- pairing window ----------------------------------------------------

    #[test]
    fn pairing_code_is_eight_digits_and_grouped() {
        let slot = PairingSlot::new();
        let d = slot.arm(0);
        assert_eq!(d.digits.len(), PAIRING_CODE_DIGITS);
        assert!(d.digits.bytes().all(|b| b.is_ascii_digit()));
        assert_eq!(d.grouped, format!("{} {}", &d.digits[..4], &d.digits[4..]));
        assert_eq!(d.remaining_ms, PAIRING_TTL_MS);
    }

    #[test]
    fn pairing_window_expires_on_the_injected_clock() {
        let slot = PairingSlot::new();
        slot.arm_with(PairingCode::parse("12345678").unwrap(), 1_000, 120_000);
        assert!(slot.is_armed(1_000));
        assert!(slot.is_armed(121_000), "the last millisecond still counts");
        assert!(!slot.is_armed(121_001));
        // Expiry is sticky: the slot cleared itself on the way past.
        assert!(!slot.is_armed(1_000));
    }

    #[test]
    fn pairing_countdown_shrinks() {
        let slot = PairingSlot::new();
        slot.arm_with(PairingCode::parse("11112222").unwrap(), 0, 10_000);
        assert_eq!(slot.snapshot(0).unwrap().remaining_ms, 10_000);
        assert_eq!(slot.snapshot(7_500).unwrap().remaining_ms, 2_500);
        assert!(slot.snapshot(10_001).is_none());
    }

    #[test]
    fn pairing_code_is_single_use() {
        let slot = PairingSlot::new();
        slot.arm_with(PairingCode::parse("87654321").unwrap(), 0, 120_000);
        let first = slot.take(10).expect("first use");
        assert_eq!(first.code.expose(), "87654321");
        assert!(
            slot.take(20).is_none(),
            "a second PairStart must find nothing"
        );
        assert!(!slot.is_armed(20));
    }

    #[test]
    fn expired_code_cannot_be_taken() {
        let slot = PairingSlot::new();
        slot.arm_with(PairingCode::parse("13571357").unwrap(), 0, 1_000);
        assert!(slot.take(1_001).is_none());
    }

    #[test]
    fn arming_replaces_the_previous_code() {
        let slot = PairingSlot::new();
        slot.arm_with(PairingCode::parse("11111111").unwrap(), 0, 120_000);
        slot.arm_with(PairingCode::parse("22222222").unwrap(), 5_000, 120_000);
        assert_eq!(slot.snapshot(5_000).unwrap().digits, "22222222");
        assert_eq!(slot.snapshot(5_000).unwrap().remaining_ms, 120_000);
    }

    #[test]
    fn cancel_clears_the_window() {
        let slot = PairingSlot::new();
        slot.arm(0);
        slot.clear();
        assert!(!slot.is_armed(0));
    }

    #[test]
    fn pairing_slot_debug_never_shows_the_code() {
        let slot = PairingSlot::new();
        let d = slot.arm(0);
        let s = format!("{slot:?}");
        assert!(!s.contains(&d.digits), "{s}");
        assert!(s.contains("armed: true"));
    }

    // -- throttle ----------------------------------------------------------

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, n])
    }

    #[test]
    fn three_failures_lock_the_address_out() {
        let mut t = AuthThrottle::new();
        assert!(t.locked_for_ms(&ip(1), 0).is_none());
        assert!(!t.record_failure(ip(1), 0));
        assert!(!t.record_failure(ip(1), 100));
        assert!(
            t.locked_for_ms(&ip(1), 100).is_none(),
            "two strikes is not a lockout"
        );
        assert!(t.record_failure(ip(1), 200));
        assert_eq!(t.locked_for_ms(&ip(1), 200), Some(AUTH_LOCKOUT_MS));
    }

    #[test]
    fn lockout_expires() {
        let mut t = AuthThrottle::new();
        for i in 0..AUTH_FAIL_LIMIT as u64 {
            t.record_failure(ip(2), i);
        }
        assert!(t.locked_for_ms(&ip(2), AUTH_LOCKOUT_MS).is_some());
        assert!(t.locked_for_ms(&ip(2), AUTH_LOCKOUT_MS + 3).is_none());
    }

    #[test]
    fn lockout_is_per_address() {
        let mut t = AuthThrottle::new();
        for i in 0..AUTH_FAIL_LIMIT as u64 {
            t.record_failure(ip(3), i);
        }
        assert!(t.locked_for_ms(&ip(3), 0).is_some());
        assert!(t.locked_for_ms(&ip(4), 0).is_none());
    }

    #[test]
    fn old_failures_stop_counting() {
        let mut t = AuthThrottle::new();
        assert!(!t.record_failure(ip(5), 0));
        assert!(!t.record_failure(ip(5), AUTH_FAIL_WINDOW_MS + 1));
        assert!(
            !t.record_failure(ip(5), AUTH_FAIL_WINDOW_MS + 2),
            "the first failure aged out, so this is only the second"
        );
    }

    #[test]
    fn success_clears_the_history() {
        let mut t = AuthThrottle::new();
        t.record_failure(ip(6), 0);
        t.record_failure(ip(6), 1);
        t.record_success(&ip(6));
        assert_eq!(t.tracked(), 0);
        assert!(
            !t.record_failure(ip(6), 2),
            "counting restarts after a success"
        );
    }

    #[test]
    fn a_locked_out_address_can_be_locked_out_again() {
        let mut t = AuthThrottle::new();
        for i in 0..AUTH_FAIL_LIMIT as u64 {
            t.record_failure(ip(7), i);
        }
        let after = AUTH_LOCKOUT_MS + 10;
        for i in 0..AUTH_FAIL_LIMIT as u64 {
            t.record_failure(ip(7), after + i);
        }
        assert!(t.locked_for_ms(&ip(7), after + 10).is_some());
    }

    // -- rate limiter ------------------------------------------------------

    #[test]
    fn rate_limiter_allows_then_blocks() {
        let mut r = RateLimiter::new(500);
        assert!(r.allow(0));
        assert!(!r.allow(1));
        assert!(!r.allow(499));
        assert!(r.allow(500));
        assert!(!r.allow(999));
        assert!(r.allow(1_000));
    }

    #[test]
    fn rate_limiter_first_call_always_passes() {
        let mut r = RateLimiter::new(500);
        assert!(r.allow(9_999_999));
    }

    // -- drop policy -------------------------------------------------------

    fn frame(id: u32, keyframe: bool) -> EncodedFrame {
        EncodedFrame {
            frame_id: id,
            keyframe,
            timestamp_ms: id,
            data: vec![0xAB; 32],
        }
    }

    #[test]
    fn coalesce_keeps_nothing_when_the_queue_is_empty() {
        let (_tx, rx) = crossbeam_channel::unbounded::<EncodedFrame>();
        let (kept, dropped) = coalesce_latest(frame(1, true), &rx);
        assert_eq!(kept.frame_id, 1);
        assert_eq!(dropped, 0);
    }

    #[test]
    fn coalesce_drops_stale_frames_not_fresh_ones() {
        let (tx, rx) = crossbeam_channel::unbounded::<EncodedFrame>();
        for id in 2..=6 {
            tx.send(frame(id, false)).unwrap();
        }
        let (kept, dropped) = coalesce_latest(frame(1, true), &rx);
        assert_eq!(
            kept.frame_id, 6,
            "the newest frame is the one that survives"
        );
        assert_eq!(dropped, 5, "one taken plus four queued were skipped");
        assert!(rx.is_empty());
    }

    #[test]
    fn overrun_is_silent_when_the_link_keeps_up() {
        assert_eq!(overrun_signal(8_000, 8_000), 0.0);
        assert_eq!(
            overrun_signal(8_000, 9_000),
            0.0,
            "headroom is not congestion"
        );
        assert_eq!(overrun_signal(8_000, 7_500), 0.0, "within the 15% slack");
    }

    #[test]
    fn overrun_reports_the_shortfall_when_the_encoder_outruns_the_link() {
        // The measured case: a 13 Mbps encoder on a link carrying 7.3 Mbps.
        let s = overrun_signal(13_000, 7_313);
        assert!(s > 0.4 && s < 0.5, "got {s}");
        // Well past the adaptor's 2% congestion threshold, so it will back off.
        assert!(s > 0.02);
    }

    #[test]
    fn overrun_needs_both_numbers_to_mean_anything() {
        assert_eq!(overrun_signal(0, 5_000), 0.0);
        assert_eq!(
            overrun_signal(5_000, 0),
            0.0,
            "an unmeasured link is not a congested one"
        );
    }

    #[test]
    fn overrun_stays_in_the_unit_range() {
        for (e, c) in [(1u32, 1u32), (u32::MAX, 1), (1, u32::MAX), (12_000, 300)] {
            let s = overrun_signal(e, c);
            assert!((0.0..=1.0).contains(&s), "{e}/{c} gave {s}");
        }
    }

    #[test]
    fn overrun_drives_the_adaptor_downward() {
        // The whole point: this signal must actually move the bitrate.
        let mut a = BitrateAdaptor::new(AdaptConfig::for_mode(QualityMode::Balanced));
        let start = a.current();
        assert_eq!(a.observe(0, 0.0, 1.0), None, "establish a baseline");
        let signal = overrun_signal(13_000, 7_313);
        let next = a
            .observe(1_500, signal, 1.0)
            .expect("an overrun must lower the bitrate");
        assert!(next < start, "{next} should be below {start}");
    }

    #[test]
    fn wire_size_matches_what_fragmenting_actually_produces() {
        let mtu = 1_200;
        for len in [1usize, 100, 1_186, 1_187, 5_000, 145_000] {
            let f = EncodedFrame {
                frame_id: 1,
                keyframe: false,
                timestamp_ms: 0,
                data: vec![0u8; len],
            };
            let actual: usize = fragment_frame(&f, mtu)
                .unwrap()
                .iter()
                .map(|d| d.len())
                .sum();
            assert_eq!(wire_size(&f, mtu), actual, "len {len}");
        }
    }

    #[test]
    fn wire_size_never_underestimates() {
        // The backpressure check must not be optimistic: an underestimate would
        // let a frame in that displaces the one already in flight.
        let f = EncodedFrame {
            frame_id: 1,
            keyframe: true,
            timestamp_ms: 0,
            data: vec![0u8; 50_000],
        };
        assert!(wire_size(&f, 1_200) > f.data.len());
        assert!(
            wire_size(&f, 1_200) > wire_size(&f, 1_400),
            "smaller MTU means more headers"
        );
    }

    #[test]
    fn coalesce_reports_enough_drops_to_trigger_an_idr() {
        let (tx, rx) = crossbeam_channel::unbounded::<EncodedFrame>();
        tx.send(frame(2, false)).unwrap();
        let (_, dropped) = coalesce_latest(frame(1, false), &rx);
        assert!(
            dropped > 0,
            "any drop must be visible so a keyframe can be requested"
        );
    }

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
        let h = host_hello();
        assert_eq!(h.version, PROTOCOL_VERSION);
        assert!(directdesk_shared::protocol::validate_hello(&h).is_ok());
        assert!(h.agent.starts_with("directdesk-host"));
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

    // -- M5: windowed delivery reporting -----------------------------------

    #[test]
    fn window_delivery_is_matched_window_math() {
        let d = WindowDelivery {
            sent: 45,
            offered: 60,
            bytes: 1_000_000,
            dt_ms: 1_000,
        };
        assert!((d.delivery_ratio() - 0.75).abs() < 1e-6);
        assert!((d.backpressure_ratio() - 0.25).abs() < 1e-6);
        // 1,000,000 bytes in 1 s = 8,000 kbps.
        assert_eq!(d.throughput_kbps(), 8_000);
    }

    #[test]
    fn idle_window_reports_full_delivery_not_loss() {
        // The old bug read a lifetime send count against a fresh client window
        // and called a healthy link ~50% lossy. A matched window with nothing
        // offered delivered everything it was asked to.
        let idle = WindowDelivery {
            sent: 0,
            offered: 0,
            bytes: 0,
            dt_ms: 1_000,
        };
        assert_eq!(idle.delivery_ratio(), 1.0);
        assert_eq!(idle.backpressure_ratio(), 0.0);
        assert_eq!(idle.throughput_kbps(), 0);
    }

    #[test]
    fn window_delivery_cannot_divide_by_a_zero_length_window() {
        let z = WindowDelivery {
            sent: 10,
            offered: 10,
            bytes: 500,
            dt_ms: 0,
        };
        assert_eq!(z.throughput_kbps(), 0);
    }

    // -- M5: congestion signal + overrun gating ----------------------------

    #[test]
    fn congestion_ignores_overrun_until_warm() {
        // Cold: a big overrun ratio is discarded; only real loss/backpressure
        // count. This is what stops the spurious start-up downshift.
        assert_eq!(congestion_signal(0.0, 0.0, 0.9, false), 0.0);
        assert!((congestion_signal(0.05, 0.0, 0.9, false) - 0.05).abs() < 1e-6);
        assert!((congestion_signal(0.0, 0.2, 0.9, false) - 0.2).abs() < 1e-6);
        // Warm: the overrun is folded in.
        assert!((congestion_signal(0.0, 0.0, 0.9, true) - 0.9).abs() < 1e-6);
        // Real loss wins whenever it is larger, warm or not.
        assert!((congestion_signal(0.5, 0.1, 0.2, true) - 0.5).abs() < 1e-6);
    }

    // -- M5: bitrate caps --------------------------------------------------

    #[test]
    fn caps_narrow_but_never_widen() {
        assert_eq!(effective_cap(None, None), None);
        assert_eq!(effective_cap(Some(5_000), None), Some(5_000));
        assert_eq!(effective_cap(None, Some(3_000)), Some(3_000));
        assert_eq!(
            effective_cap(Some(5_000), Some(3_000)),
            Some(3_000),
            "client narrows"
        );
        assert_eq!(
            effective_cap(Some(2_000), Some(9_000)),
            Some(2_000),
            "client cannot widen"
        );
        assert_eq!(clamp_to_cap(8_000, Some(3_000)), 3_000);
        assert_eq!(clamp_to_cap(2_000, Some(3_000)), 2_000);
        assert_eq!(clamp_to_cap(8_000, None), 8_000);
    }

    #[test]
    fn bitrate_limit_clamps_the_adaptor_output() {
        // The adaptor free-runs in Balanced (start 8000). A 3000 kbps client
        // limit must be a hard ceiling on what the encoder is actually asked for.
        let a = BitrateAdaptor::new(AdaptConfig::for_mode(QualityMode::Balanced));
        let cap = effective_cap(None, Some(3_000));
        assert_eq!(clamp_to_cap(a.current(), cap), 3_000);
    }

    // -- M5: adaptor drive (synthetic status windows) ----------------------

    /// One synthetic `status_loop` window.
    struct Window {
        loss: f32,
        sent: u64,
        backpressured: u64,
        encoder_kbps: u32,
        carried_kbps: u32,
    }

    /// Reproduce the adaptor drive from `status_loop` without a live
    /// connection: build the exact congestion number the loop would and observe
    /// the adaptor. Returns (current target, Some(new) when it changed).
    fn drive(a: &mut BitrateAdaptor, w: &Window, now_ms: u64, interval: u32) -> (u32, Option<u32>) {
        let delivery = WindowDelivery {
            sent: w.sent,
            offered: w.sent + w.backpressured,
            bytes: 0,
            dt_ms: STATUS_INTERVAL_MS,
        };
        let warm = interval > OVERRUN_WARMUP_INTERVALS && w.sent >= OVERRUN_MIN_FRAMES;
        let overrun = overrun_signal(w.encoder_kbps, w.carried_kbps);
        let congestion = congestion_signal(w.loss, delivery.backpressure_ratio(), overrun, warm);
        let changed = a.observe(now_ms, congestion, 50.0);
        (a.current(), changed)
    }

    #[test]
    fn adaptor_backs_off_on_real_loss_then_recovers() {
        let mut a = BitrateAdaptor::new(AdaptConfig::for_mode(QualityMode::Balanced));
        let start = a.current();
        let clean = Window {
            loss: 0.0,
            sent: 60,
            backpressured: 0,
            encoder_kbps: 8_000,
            carried_kbps: 8_000,
        };
        drive(&mut a, &clean, 0, 1);
        // A window of real transport loss backs the target off.
        let lossy = Window {
            loss: 0.08,
            sent: 60,
            backpressured: 0,
            encoder_kbps: 8_000,
            carried_kbps: 8_000,
        };
        let (after, changed) = drive(&mut a, &lossy, 1_100, 2);
        assert!(
            changed.is_some() && after < start,
            "loss must lower the target ({after} < {start})"
        );
        // Clean windows then raise it back up.
        let mut t = 2_000;
        let mut raised = None;
        for i in 3..40 {
            t += 1_000;
            if let (_, Some(v)) = drive(&mut a, &clean, t, i) {
                raised = Some(v);
                break;
            }
        }
        assert!(
            raised.unwrap() > after,
            "clean windows raise the target back up"
        );
    }

    #[test]
    fn startup_overrun_does_not_spuriously_downshift() {
        let mut a = BitrateAdaptor::new(AdaptConfig::for_mode(QualityMode::Balanced));
        let start = a.current();
        // Encoder 12 Mbps but the link "carried" only 2 Mbps because the stream
        // just began — a pure window artifact, with no real loss.
        let w = Window {
            loss: 0.0,
            sent: 60,
            backpressured: 0,
            encoder_kbps: 12_000,
            carried_kbps: 2_000,
        };
        let mut t = 0;
        for i in 1..=OVERRUN_WARMUP_INTERVALS {
            t += 500;
            let (cur, changed) = drive(&mut a, &w, t, i);
            assert_eq!(
                cur, start,
                "a gated overrun must not move the adaptor during warm-up"
            );
            assert!(changed.is_none());
        }
        // Once warm, the same sustained overrun IS treated as congestion.
        t += 1_100;
        let (cur, changed) = drive(&mut a, &w, t, OVERRUN_WARMUP_INTERVALS + 1);
        assert!(
            changed.is_some() && cur < start,
            "a warm, sustained overrun backs off"
        );
    }

    #[test]
    fn quality_mode_switch_applies_ceiling_and_floor() {
        // Ramp to the Motion ceiling, then switch to LowBandwidth: the current
        // target clamps down into the new, lower range.
        let mut a = BitrateAdaptor::new(AdaptConfig::for_mode(QualityMode::Motion));
        let clean = Window {
            loss: 0.0,
            sent: 60,
            backpressured: 0,
            encoder_kbps: 1,
            carried_kbps: 1,
        };
        let mut t = 0;
        for i in 1..200 {
            t += 2_100;
            drive(&mut a, &clean, t, i);
        }
        assert_eq!(
            a.current(),
            AdaptConfig::for_mode(QualityMode::Motion).ceiling_kbps
        );
        a.set_mode(QualityMode::LowBandwidth, t);
        assert_eq!(
            a.current(),
            AdaptConfig::for_mode(QualityMode::LowBandwidth).ceiling_kbps,
            "clamped down to the new ceiling",
        );

        // A mode with a higher floor lifts a floored-out target up to it.
        let mut b = BitrateAdaptor::new(AdaptConfig::for_mode(QualityMode::LowBandwidth));
        let heavy = Window {
            loss: 0.9,
            sent: 10,
            backpressured: 0,
            encoder_kbps: 1,
            carried_kbps: 1,
        };
        for i in 1..200u32 {
            drive(&mut b, &heavy, i as u64 * 1_100, i);
        }
        assert_eq!(
            b.current(),
            AdaptConfig::for_mode(QualityMode::LowBandwidth).floor_kbps
        );
        b.set_mode(QualityMode::Motion, 999_999);
        assert_eq!(
            b.current(),
            AdaptConfig::for_mode(QualityMode::Motion).floor_kbps,
            "lifted up to the new floor",
        );
    }
}
