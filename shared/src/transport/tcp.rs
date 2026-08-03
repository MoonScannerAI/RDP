//! The TCP/TLS fallback transport.
//!
//! When UDP is blackholed — hotel Wi-Fi, corporate egress filters, some mobile
//! carriers — QUIC never completes and DirectDesk has to fall back to something
//! that looks like ordinary HTTPS traffic. This module is that something: one
//! TCP connection, TLS 1.3 with the *same* certificate, the *same* SPKI pinning
//! and the *same* ALPN as the QUIC path, carrying all three logical channels.
//!
//! # Same interface, deliberately
//!
//! [`TcpSession`] implements [`Session`], hands out the same
//! [`SessionReceivers`], and produces the same [`SessionEvent`]s as
//! [`crate::transport::session::QuicSession`]. Everything above the transport —
//! pairing, auth, the media pipeline, the UI — is written against that trait and
//! does not know or care which one it got. [`TlsTcpConn::channel_binding`] uses
//! [`EXPORTER_LABEL`] and [`EXPORTER_CONTEXT`], byte for byte the values the
//! QUIC path uses, so pairing and authentication transcripts are identical
//! across transports.
//!
//! # Framing and multiplexing
//!
//! One stream carries three channels, so every message is tagged:
//!
//! ```text
//! offset size field
//! 0      1    channel tag (postcard encoding of `Channel`)
//! 1      4    body length, u32 little-endian
//! 5      n    body
//! ```
//!
//! The tag comes first because it selects the length cap: the reader knows
//! whether it is looking at a 64 KiB control message or a 2 MiB video frame
//! *before* it validates the length, and it validates the length before it
//! allocates a single byte of body. See [`channel_limit`].
//!
//! Control and input bodies are exactly what [`crate::protocol::encode_framed`]
//! produces. Video bodies are a small postcard [`MediaHeader`] followed by the
//! raw encoded bytes — TCP is reliable and ordered, so the QUIC path's
//! fragmentation and reassembly are pure overhead here, but the frame's
//! identity (`frame_id`, `keyframe`, `timestamp_ms`) still has to survive, and
//! the decoder still needs it.
//!
//! # Priority: the whole point of this module
//!
//! QUIC gives input priority for free: separate streams, and
//! [`PRIORITY_INPUT`](crate::transport::PRIORITY_INPUT) tells the stack which to
//! serve first. TCP gives us one byte-ordered pipe and no such lever, so the
//! policy is implemented explicitly in [`writer_loop`]:
//!
//! 1. **Strict priority.** Every iteration drains control first, then input,
//!    and only reaches for video when both are empty. A key-up event can never
//!    queue behind a video backlog.
//! 2. **Latest-wins video.** The outbound video queue is
//!    [`DEFAULT_VIDEO_QUEUE_DEPTH`] frames deep and drops the **oldest** frame
//!    when full — the opposite of a normal channel, and the correct choice: an
//!    old frame is worth less than the new one behind it, and sending it costs
//!    the new one its latency.
//! 3. **IDR after drops.** Dropping a frame breaks the peer's decode chain, so
//!    the sender raises [`SessionEvent::KeyframeNeeded`] for its own encoder,
//!    rate-limited exactly like [`crate::transport::reassembly`] rate-limits its
//!    keyframe requests.
//!
//! **The one honest limit.** Priority is applied at message boundaries. A video
//! frame already being written cannot be preempted mid-message without
//! corrupting the stream, so an input event can be delayed by at most *one*
//! in-flight frame — never by the queue behind it, which is the difference
//! between tens of milliseconds and seconds. The loopback test
//! `input_beats_the_queued_video_backlog` pins that behaviour down.
//!
//! # Keepalive
//!
//! `TCP_NODELAY` is on: Nagle's algorithm exists to coalesce small writes, and
//! coalescing input events is precisely the wrong trade here.
//!
//! Liveness is handled at the application layer by the session heartbeat
//! ([`SessionConfig::heartbeat_ms`]) plus a read idle timeout
//! ([`TcpParams::idle_timeout_ms`]), rather than by `SO_KEEPALIVE`. That is a
//! deliberate choice, not an omission: socket keepalive needs `socket2` or raw
//! `setsockopt`, its intervals are OS-tunable and often measured in *hours*, and
//! it cannot distinguish a live socket from a wedged peer process. The
//! heartbeat measures RTT, holds NAT mappings open, and detects a hung peer, all
//! on intervals we choose and both transports share.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};

use crate::crypto::identity::TlsIdentity;
use crate::crypto::tls::{self, ServerPinning};
use crate::crypto::{EXPORTER_CONTEXT, EXPORTER_LABEL, Exporter, SpkiHash};
use crate::error::{Error, Result};
use crate::protocol::{
    ALPN, Channel, ControlMsg, InputMsg, MAX_AUTH_MSG, MAX_CONTROL_MSG, decode_strict,
    encode_framed, parse_frame_len,
};
use crate::stats::{ConnStats, TransportRoute};
use crate::transport::session::{
    Session, SessionConfig, SessionEvent, SessionReceivers, ewma_jitter,
};
use crate::transport::{channel_tag, parse_channel_tag};
use crate::video::{EncodedFrame, MAX_FRAME_BYTES};

/// Bytes of framing ahead of every message: one channel tag, one u32 length.
pub const FRAME_HEADER_LEN: usize = 5;

/// Cap on a media message body: a whole encoded frame plus its small header.
pub const MAX_MEDIA_MSG: usize = MAX_FRAME_BYTES + 64;

/// TCP connect + TLS handshake timeout.
pub const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 5_000;

/// Close the session if no byte arrives for this long. Three heartbeats.
pub const DEFAULT_IDLE_TIMEOUT_MS: u64 = 15_000;

/// Outbound video queue depth. Small on purpose: a deep video queue is latency
/// wearing a hat.
pub const DEFAULT_VIDEO_QUEUE_DEPTH: usize = 2;

/// Minimum spacing between local IDR signals, matching the reassembler's
/// keyframe-request rate limit.
pub const DEFAULT_IDR_MIN_INTERVAL_MS: u64 = 500;

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

/// Tunables for the TCP transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpParams {
    /// TCP connect + TLS handshake timeout in milliseconds.
    pub connect_timeout_ms: u64,
    /// Close the session after this long with no inbound byte. `0` disables.
    pub idle_timeout_ms: u64,
    /// Outbound video queue depth. Must be non-zero.
    pub video_queue_depth: usize,
    /// Minimum spacing between local IDR signals. `0` means every drop signals.
    pub idr_min_interval_ms: u64,
    /// Disable Nagle. Should stay `true`; exposed for experiments.
    pub nodelay: bool,
}

impl Default for TcpParams {
    fn default() -> Self {
        Self {
            connect_timeout_ms: DEFAULT_CONNECT_TIMEOUT_MS,
            idle_timeout_ms: DEFAULT_IDLE_TIMEOUT_MS,
            video_queue_depth: DEFAULT_VIDEO_QUEUE_DEPTH,
            idr_min_interval_ms: DEFAULT_IDR_MIN_INTERVAL_MS,
            nodelay: true,
        }
    }
}

impl TcpParams {
    /// Reject configurations that would stall or spin.
    pub fn validate(&self) -> Result<()> {
        if self.connect_timeout_ms == 0 {
            return Err(Error::Invalid("tcp connect timeout must be non-zero".into()));
        }
        if self.video_queue_depth == 0 {
            return Err(Error::Invalid("tcp video queue depth must be non-zero".into()));
        }
        Ok(())
    }
}

/// Capped exponential backoff for [`connect_with_retry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Total attempts, including the first. Must be non-zero.
    pub max_attempts: u32,
    /// Delay before the second attempt.
    pub initial_backoff_ms: u64,
    /// Ceiling on the delay. Without one, a long-lived reconnect loop drifts
    /// into hour-long sleeps and the session never comes back.
    pub max_backoff_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self { max_attempts: 5, initial_backoff_ms: 250, max_backoff_ms: 4_000 }
    }
}

impl RetryPolicy {
    /// Delay before attempt number `attempt` (1-based; attempt 1 never waits).
    pub fn backoff_ms(&self, attempt: u32) -> u64 {
        if attempt <= 1 {
            return 0;
        }
        let shift = (attempt - 2).min(31);
        self.initial_backoff_ms.saturating_mul(1u64 << shift).min(self.max_backoff_ms)
    }
}

// ---------------------------------------------------------------------------
// Wire format
// ---------------------------------------------------------------------------

/// The metadata that rides in front of a video frame's bytes.
///
/// Postcard-encoded and varint-packed, so it costs 3–7 bytes in practice. The
/// body is `MediaHeader || frame bytes`; the decoder recovers the split from
/// postcard's own framing, not from a fixed offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaHeader {
    /// Sender's frame counter. Wraps.
    pub frame_id: u32,
    /// Whether this frame is an IDR.
    pub keyframe: bool,
    /// Sender-monotonic capture timestamp in milliseconds. Wraps.
    pub timestamp_ms: u32,
}

/// The pre-allocation length cap for a channel.
///
/// Control and input are small structured messages; video is a whole encoded
/// frame. Applying the control cap to video would break streaming, and applying
/// the video cap to control would let a peer make us allocate 2 MiB for a
/// `Ping`.
pub fn channel_limit(channel: Channel) -> usize {
    match channel {
        Channel::Control | Channel::Input => MAX_CONTROL_MSG,
        Channel::Media => MAX_MEDIA_MSG,
    }
}

/// Encode a control-plane or input message as a tagged, length-prefixed frame.
pub fn encode_tagged<T: Serialize>(channel: Channel, msg: &T) -> Result<Vec<u8>> {
    if matches!(channel, Channel::Media) {
        return Err(Error::Invalid("use encode_media for the media channel".into()));
    }
    let framed = encode_framed(msg)?;
    let mut out = Vec::with_capacity(1 + framed.len());
    out.push(channel_tag(channel)?);
    out.extend_from_slice(&framed);
    Ok(out)
}

/// Encode one [`EncodedFrame`] as a single tagged, length-prefixed frame.
///
/// No fragmentation: TCP already delivers a byte stream in order, so splitting
/// a frame would only add header overhead and a reassembly step that can never
/// fail.
pub fn encode_media(frame: &EncodedFrame) -> Result<Vec<u8>> {
    if frame.data.is_empty() {
        return Err(Error::Invalid("empty frame".into()));
    }
    if frame.data.len() > MAX_FRAME_BYTES {
        return Err(Error::Oversized { got: frame.data.len(), limit: MAX_FRAME_BYTES });
    }
    let header = postcard::to_stdvec(&MediaHeader {
        frame_id: frame.frame_id,
        keyframe: frame.keyframe,
        timestamp_ms: frame.timestamp_ms,
    })?;
    let body_len = header.len() + frame.data.len();
    if body_len > MAX_MEDIA_MSG {
        return Err(Error::Oversized { got: body_len, limit: MAX_MEDIA_MSG });
    }
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + body_len);
    out.push(channel_tag(Channel::Media)?);
    out.extend_from_slice(&(body_len as u32).to_le_bytes());
    out.extend_from_slice(&header);
    out.extend_from_slice(&frame.data);
    Ok(out)
}

/// Decode a media message body back into a frame.
pub fn decode_media(body: &[u8]) -> Result<EncodedFrame> {
    let (header, rest) = postcard::take_from_bytes::<MediaHeader>(body)?;
    if rest.is_empty() {
        return Err(Error::Invalid("media message carries no frame data".into()));
    }
    if rest.len() > MAX_FRAME_BYTES {
        return Err(Error::Oversized { got: rest.len(), limit: MAX_FRAME_BYTES });
    }
    Ok(EncodedFrame {
        frame_id: header.frame_id,
        keyframe: header.keyframe,
        timestamp_ms: header.timestamp_ms,
        data: rest.to_vec(),
    })
}

/// Read one tagged frame, refusing an oversized length before allocating.
///
/// `extra_cap` tightens the channel's own limit — that is how the handshake
/// enforces [`MAX_AUTH_MSG`] *before* the body buffer exists, rather than
/// allocating 64 KiB and complaining afterwards.
async fn read_tagged_capped<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    extra_cap: usize,
) -> Result<(Channel, Vec<u8>)> {
    let mut head = [0u8; FRAME_HEADER_LEN];
    reader
        .read_exact(&mut head)
        .await
        .map_err(|e| Error::Transport(format!("tcp read (header): {e}")))?;
    let channel = parse_channel_tag(head[0])?;
    // Cap first, allocate second. A hostile 4 GiB prefix costs us nothing.
    let limit = channel_limit(channel).min(extra_cap);
    let len = parse_frame_len([head[1], head[2], head[3], head[4]], limit)?;
    let mut body = vec![0u8; len];
    reader
        .read_exact(&mut body)
        .await
        .map_err(|e| Error::Transport(format!("tcp read (body): {e}")))?;
    Ok((channel, body))
}

/// Read one tagged frame under the channel's own cap.
async fn read_tagged<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<(Channel, Vec<u8>)> {
    read_tagged_capped(reader, usize::MAX).await
}

// ---------------------------------------------------------------------------
// Connection establishment
// ---------------------------------------------------------------------------

/// An established, authenticated TLS-over-TCP connection.
///
/// Handed to [`TcpSession::start`] once pairing or authentication has run over
/// it with [`Self::write_framed`] / [`Self::read_framed`].
pub struct TlsTcpConn {
    stream: TlsStream<TcpStream>,
    peer: SocketAddr,
    server: bool,
}

impl std::fmt::Debug for TlsTcpConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsTcpConn")
            .field("peer", &self.peer)
            .field("role", &if self.server { "server" } else { "client" })
            .finish()
    }
}

impl TlsTcpConn {
    /// The peer's address.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// Whether this end accepted the connection.
    pub fn is_server(&self) -> bool {
        self.server
    }

    /// The negotiated ALPN protocol. Must be [`ALPN`].
    pub fn alpn(&self) -> Option<Vec<u8>> {
        let state = match &self.stream {
            TlsStream::Client(s) => s.get_ref().1.alpn_protocol(),
            TlsStream::Server(s) => s.get_ref().1.alpn_protocol(),
        };
        state.map(|p| p.to_vec())
    }

    /// The RFC 5705 channel binding for this connection.
    ///
    /// Identical construction to [`crate::transport::quic::channel_binding`] —
    /// same label, same context, same length — so pairing and auth transcripts
    /// do not depend on which transport won the race.
    pub fn channel_binding(&self) -> Result<Exporter> {
        let mut out = [0u8; 32];
        let res = match &self.stream {
            TlsStream::Client(s) => s.get_ref().1.export_keying_material(
                &mut out[..],
                EXPORTER_LABEL,
                Some(EXPORTER_CONTEXT),
            ),
            TlsStream::Server(s) => s.get_ref().1.export_keying_material(
                &mut out[..],
                EXPORTER_LABEL,
                Some(EXPORTER_CONTEXT),
            ),
        };
        res.map_err(|e| Error::Crypto(format!("export_keying_material: {e:?}")))?;
        crate::crypto::check_exporter(&out)?;
        Ok(out)
    }

    /// The peer's TLS pin as observed on this connection.
    ///
    /// Only meaningful on the client side, where the server presents a
    /// certificate.
    pub fn peer_spki_pin(&self) -> Result<SpkiHash> {
        let certs = match &self.stream {
            TlsStream::Client(s) => s.get_ref().1.peer_certificates(),
            TlsStream::Server(s) => s.get_ref().1.peer_certificates(),
        };
        let chain = certs.ok_or_else(|| Error::Crypto("connection has no peer certificate".into()))?;
        let first = chain.first().ok_or_else(|| Error::Crypto("empty certificate chain".into()))?;
        crate::crypto::spki_sha256_from_cert_der(first.as_ref())
    }

    /// Write one tagged, length-prefixed message.
    pub async fn write_framed<T: Serialize>(&mut self, channel: Channel, msg: &T) -> Result<()> {
        let bytes = encode_tagged(channel, msg)?;
        self.stream
            .write_all(&bytes)
            .await
            .map_err(|e| Error::Transport(format!("tcp write: {e}")))?;
        self.stream.flush().await.map_err(|e| Error::Transport(format!("tcp flush: {e}")))
    }

    /// Read one tagged message, refusing anything over `limit`.
    ///
    /// Returns the channel it arrived on so the caller can reject traffic that
    /// does not belong in the current phase.
    pub async fn read_framed<T: DeserializeOwned>(
        &mut self,
        limit: usize,
    ) -> Result<(Channel, T)> {
        let (channel, body) = read_tagged_capped(&mut self.stream, limit).await?;
        Ok((channel, decode_strict::<T>(&body)?))
    }

    /// Read one raw tagged message: the channel and its undecoded body.
    pub async fn read_any(&mut self) -> Result<(Channel, Vec<u8>)> {
        read_tagged(&mut self.stream).await
    }

    /// Read a handshake message with the (much smaller) authentication cap.
    ///
    /// Refuses anything that did not arrive on the control channel: the media
    /// and input channels have no business carrying auth.
    pub async fn read_auth<T: DeserializeOwned>(&mut self) -> Result<T> {
        let (channel, msg) = self.read_framed::<T>(MAX_AUTH_MSG).await?;
        if channel != Channel::Control {
            return Err(Error::Protocol(format!("auth message on the {channel:?} channel")));
        }
        Ok(msg)
    }
}

/// Bind a fallback listener. Use [`crate::protocol::DEFAULT_TCP_PORT`] unless
/// the user configured otherwise.
pub async fn listener(bind: SocketAddr) -> Result<TcpListener> {
    TcpListener::bind(bind).await.map_err(|e| Error::Transport(format!("tcp bind {bind}: {e}")))
}

/// Build the host-side TLS acceptor once, for the lifetime of the listener.
///
/// [`TlsAcceptor`] is a cheap handle around a shared `rustls::ServerConfig`, so
/// clone it per connection rather than rebuilding the certificate state on every
/// accept.
pub fn acceptor(identity: &TlsIdentity) -> Result<TlsAcceptor> {
    Ok(TlsAcceptor::from(tls::server_config(identity)?))
}

/// Accept one connection and complete the TLS handshake as the host.
pub async fn accept(
    listener: &TcpListener,
    acceptor: &TlsAcceptor,
    params: &TcpParams,
) -> Result<TlsTcpConn> {
    params.validate()?;
    let (sock, peer) = listener
        .accept()
        .await
        .map_err(|e| Error::Transport(format!("tcp accept: {e}")))?;
    tune(&sock, params)?;

    let tls = tokio::time::timeout(
        Duration::from_millis(params.connect_timeout_ms),
        acceptor.accept(sock),
    )
    .await
    .map_err(|_| Error::Transport(format!("tls handshake with {peer} timed out")))?
    .map_err(|e| Error::Transport(format!("tls handshake with {peer}: {e}")))?;

    let conn = TlsTcpConn { stream: TlsStream::Server(tls), peer, server: true };
    check_alpn(&conn)?;
    Ok(conn)
}

/// Connect to a host over TCP and complete the TLS handshake with pinning.
///
/// The SNI is the fixed [`tls::SNI_NAME`]; the trust decision is made entirely
/// by the pinning verifier, exactly as on the QUIC path.
pub async fn connect(
    addr: SocketAddr,
    pinning: ServerPinning,
    params: &TcpParams,
) -> Result<TlsTcpConn> {
    params.validate()?;
    let timeout = Duration::from_millis(params.connect_timeout_ms);
    let started = Instant::now();

    let sock = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| Error::Transport(format!("tcp connect {addr} timed out")))?
        .map_err(|e| Error::Transport(format!("tcp connect {addr}: {e}")))?;
    tune(&sock, params)?;

    let connector = TlsConnector::from(tls::client_config(pinning)?);
    // The handshake gets whatever is left of the budget, not a fresh one.
    let remaining = timeout.saturating_sub(started.elapsed());
    if remaining.is_zero() {
        return Err(Error::Transport(format!("no time left for the tls handshake with {addr}")));
    }
    let tls = tokio::time::timeout(remaining, connector.connect(tls::sni()?, sock))
        .await
        .map_err(|_| Error::Transport(format!("tls handshake with {addr} timed out")))?
        .map_err(|e| Error::Transport(format!("tls handshake with {addr}: {e}")))?;

    let conn = TlsTcpConn { stream: TlsStream::Client(tls), peer: addr, server: false };
    check_alpn(&conn)?;
    Ok(conn)
}

/// [`connect`] with capped exponential backoff.
///
/// The reconnect path after a network blip. Returns the last error if every
/// attempt fails.
pub async fn connect_with_retry(
    addr: SocketAddr,
    pinning: ServerPinning,
    params: &TcpParams,
    retry: RetryPolicy,
) -> Result<TlsTcpConn> {
    if retry.max_attempts == 0 {
        return Err(Error::Invalid("retry policy must allow at least one attempt".into()));
    }
    let mut last = Error::Transport("no connection attempt was made".into());
    for attempt in 1..=retry.max_attempts {
        let wait = retry.backoff_ms(attempt);
        if wait > 0 {
            tokio::time::sleep(Duration::from_millis(wait)).await;
        }
        match connect(addr, pinning.clone(), params).await {
            Ok(conn) => return Ok(conn),
            Err(e) => last = e,
        }
    }
    Err(Error::Transport(format!(
        "tcp connect to {addr} failed after {} attempts: {last}",
        retry.max_attempts
    )))
}

fn tune(sock: &TcpStream, params: &TcpParams) -> Result<()> {
    sock.set_nodelay(params.nodelay)
        .map_err(|e| Error::Transport(format!("set_nodelay: {e}")))
}

fn check_alpn(conn: &TlsTcpConn) -> Result<()> {
    match conn.alpn() {
        Some(p) if p == ALPN => Ok(()),
        other => Err(Error::Protocol(format!(
            "peer negotiated ALPN {other:?}, expected {:?}",
            std::str::from_utf8(ALPN).unwrap_or("directdesk/1")
        ))),
    }
}

// ---------------------------------------------------------------------------
// The outbound video queue
// ---------------------------------------------------------------------------

/// A bounded, latest-wins frame queue that drops the **oldest** entry when full.
///
/// `tokio::sync::mpsc` drops the *newest* on a full queue, which is backwards
/// for video: the frame that just arrived is the only one still worth sending.
struct VideoQueue {
    inner: Mutex<VecDeque<EncodedFrame>>,
    depth: usize,
    notify: Notify,
    closed: AtomicBool,
}

impl VideoQueue {
    fn new(depth: usize) -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(depth + 1)),
            depth,
            notify: Notify::new(),
            closed: AtomicBool::new(false),
        }
    }

    /// Enqueue a frame, returning how many stale frames had to be discarded.
    fn push(&self, frame: EncodedFrame) -> usize {
        let dropped = {
            let mut q = self.inner.lock();
            let mut dropped = 0;
            while q.len() >= self.depth {
                q.pop_front();
                dropped += 1;
            }
            q.push_back(frame);
            dropped
        };
        self.notify.notify_one();
        dropped
    }

    fn try_pop(&self) -> Option<EncodedFrame> {
        self.inner.lock().pop_front()
    }

    /// Wait for a frame. `None` once the queue is closed and drained.
    ///
    /// Cancel-safe: the `Notified` future is armed before the emptiness check,
    /// so a push racing with this cannot be missed.
    async fn pop(&self) -> Option<EncodedFrame> {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(frame) = self.try_pop() {
                return Some(frame);
            }
            if self.closed.load(Ordering::SeqCst) {
                return None;
            }
            notified.await;
        }
    }

    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().len()
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct Counters {
    video_frames_dropped_local: AtomicU64,
    idr_signals: AtomicU64,
    bytes_tx: AtomicU64,
    bytes_rx: AtomicU64,
}

struct Shared {
    peer: SocketAddr,
    exporter: Option<Exporter>,
    started: Instant,
    closed: AtomicBool,
    /// Set by `close`; tells the writer to drain what it has and hang up.
    shutdown: AtomicBool,
    shutdown_signal: Notify,
    stats: Mutex<ConnStats>,
    pending_ping: Mutex<Option<(u64, Instant)>>,
    last_idr_ms: Mutex<Option<u64>>,
    idr_min_interval_ms: u64,
    counters: Counters,
    control_out: mpsc::Sender<ControlMsg>,
    input_out: mpsc::Sender<InputMsg>,
    video_out: Arc<VideoQueue>,
    events: mpsc::Sender<SessionEvent>,
}

impl Shared {
    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    fn emit(&self, ev: SessionEvent) {
        let _ = self.events.try_send(ev);
    }

    fn mark_closed(&self, reason: &str) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            self.emit(SessionEvent::Closed { reason: reason.to_string() });
        }
        self.video_out.close();
        self.shutdown.store(true, Ordering::SeqCst);
        self.shutdown_signal.notify_waiters();
    }

    fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        self.shutdown_signal.notify_waiters();
    }

    /// Rate-limited local IDR demand, same policy as the reassembler's
    /// keyframe-request throttle.
    fn arm_idr(&self) -> bool {
        let now = self.now_ms();
        let mut last = self.last_idr_ms.lock();
        let allowed = match *last {
            None => true,
            // A clock that appears to run backwards must re-arm, never starve.
            Some(prev) if now < prev => true,
            Some(prev) => now - prev >= self.idr_min_interval_ms,
        };
        if allowed {
            *last = Some(now);
        }
        allowed
    }
}

/// A session driven over one TLS-over-TCP connection.
pub struct TcpSession {
    shared: Arc<Shared>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl std::fmt::Debug for TcpSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpSession")
            .field("peer", &self.shared.peer)
            .field("closed", &self.shared.closed.load(Ordering::Relaxed))
            .finish()
    }
}

impl TcpSession {
    /// Spawn the driver tasks for an established connection.
    ///
    /// Must be called from inside a tokio runtime. The receive halves are handed
    /// out here, once, exactly as [`crate::transport::session::QuicSession`]
    /// does.
    pub fn start(
        conn: TlsTcpConn,
        params: TcpParams,
        config: SessionConfig,
    ) -> Result<(Self, SessionReceivers)> {
        params.validate()?;
        config.validate()?;

        let peer = conn.peer_addr();
        // Captured now: the halves below take ownership of the TLS state, and
        // the binding must stay available for diagnostics afterwards.
        let exporter = conn.channel_binding().ok();

        let (control_out_tx, control_out_rx) = mpsc::channel(config.control_capacity);
        let (control_in_tx, control_in_rx) = mpsc::channel(config.control_capacity);
        let (input_out_tx, input_out_rx) = mpsc::channel(config.input_capacity);
        let (input_in_tx, input_in_rx) = mpsc::channel(config.input_capacity);
        let (video_in_tx, video_in_rx) = mpsc::channel(config.video_capacity);
        let (events_tx, events_rx) = mpsc::channel(config.control_capacity);

        let shared = Arc::new(Shared {
            peer,
            exporter,
            started: Instant::now(),
            closed: AtomicBool::new(false),
            shutdown: AtomicBool::new(false),
            shutdown_signal: Notify::new(),
            stats: Mutex::new(ConnStats::default()),
            pending_ping: Mutex::new(None),
            last_idr_ms: Mutex::new(None),
            idr_min_interval_ms: params.idr_min_interval_ms,
            counters: Counters::default(),
            control_out: control_out_tx,
            input_out: input_out_tx,
            video_out: Arc::new(VideoQueue::new(params.video_queue_depth)),
            events: events_tx,
        });

        let (reader, writer) = tokio::io::split(conn.stream);

        let mut tasks = Vec::with_capacity(4);
        tasks.push(tokio::spawn(writer_loop(
            shared.clone(),
            writer,
            control_out_rx,
            input_out_rx,
        )));
        tasks.push(tokio::spawn(reader_loop(
            shared.clone(),
            reader,
            control_in_tx,
            input_in_tx,
            video_in_tx,
            params.idle_timeout_ms,
        )));
        if config.heartbeat_ms > 0 {
            tasks.push(tokio::spawn(heartbeat_loop(shared.clone(), config.heartbeat_ms)));
        }
        if config.stats_interval_ms > 0 {
            tasks.push(tokio::spawn(stats_loop(shared.clone(), config.stats_interval_ms)));
        }

        let session = Self { shared, tasks: Mutex::new(tasks) };
        let receivers = SessionReceivers {
            control: control_in_rx,
            input: input_in_rx,
            video: video_in_rx,
            events: events_rx,
        };
        Ok((session, receivers))
    }

    /// Number of video frames dropped locally because the send queue was full.
    pub fn frames_dropped_local(&self) -> u64 {
        self.shared.counters.video_frames_dropped_local.load(Ordering::Relaxed)
    }

    /// Number of times a drop raised [`SessionEvent::KeyframeNeeded`] for the
    /// local encoder. Lower than [`Self::frames_dropped_local`] because the
    /// signal is rate-limited.
    pub fn idr_signals(&self) -> u64 {
        self.shared.counters.idr_signals.load(Ordering::Relaxed)
    }

    /// Bytes written to and read from the socket, including framing.
    pub fn byte_counts(&self) -> (u64, u64) {
        (
            self.shared.counters.bytes_tx.load(Ordering::Relaxed),
            self.shared.counters.bytes_rx.load(Ordering::Relaxed),
        )
    }

    /// The peer's address.
    pub fn peer_addr(&self) -> SocketAddr {
        self.shared.peer
    }

    /// The channel binding captured at session start.
    pub fn channel_binding(&self) -> Result<Exporter> {
        self.shared
            .exporter
            .ok_or_else(|| Error::Crypto("no channel binding was captured".into()))
    }

    /// Shut down in a way the peer actually sees.
    ///
    /// Queues a `Bye`, waits (bounded) for the writer to put it on the wire,
    /// then closes. Unlike QUIC there is no CONNECTION_CLOSE frame to carry the
    /// reason, so on TCP the structured `Bye` is the *only* way the peer learns
    /// why — which makes this the path every normal shutdown should take.
    pub async fn close_graceful(&self, reason: &str, grace: Duration) {
        let _ = self.shared.control_out.try_send(ControlMsg::Bye { reason: reason.to_string() });
        let deadline = Instant::now() + grace;
        while self.shared.control_out.capacity() < self.shared.control_out.max_capacity()
            && Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        // Give the writer a moment to flush the byte it just dequeued.
        tokio::time::sleep(Duration::from_millis(5)).await;
        self.shared.mark_closed(reason);
    }
}

impl Drop for TcpSession {
    fn drop(&mut self) {
        self.shared.mark_closed("session dropped");
        for t in self.tasks.lock().drain(..) {
            t.abort();
        }
    }
}

impl Session for TcpSession {
    fn route(&self) -> TransportRoute {
        TransportRoute::DirectTcp
    }

    fn stats(&self) -> ConnStats {
        *self.shared.stats.lock()
    }

    fn send_control(&self, msg: ControlMsg) -> Result<()> {
        self.shared
            .control_out
            .try_send(msg)
            .map_err(|e| Error::Transport(format!("control queue: {e}")))
    }

    fn send_input(&self, msg: InputMsg) -> Result<()> {
        self.shared
            .input_out
            .try_send(msg)
            .map_err(|e| Error::Transport(format!("input queue: {e}")))
    }

    fn send_video(&self, frame: EncodedFrame) -> Result<()> {
        if self.shared.closed.load(Ordering::SeqCst) {
            return Err(Error::Transport("session is closed".into()));
        }
        let dropped = self.shared.video_out.push(frame) as u64;
        if dropped > 0 {
            self.shared
                .counters
                .video_frames_dropped_local
                .fetch_add(dropped, Ordering::Relaxed);
            // The peer's decode chain now has a hole in it. Only this side can
            // fix that, by encoding an IDR — so the signal is local, not a
            // `RequestKeyframe` aimed at the peer, which would ask the wrong
            // party for the wrong thing.
            if self.shared.arm_idr() {
                self.shared.counters.idr_signals.fetch_add(1, Ordering::Relaxed);
                self.shared.emit(SessionEvent::KeyframeNeeded);
            }
        }
        Ok(())
    }

    fn close(&self, reason: &str) {
        // Synchronous: queue the `Bye` and ask the writer to drain and hang up.
        // The writer flushes what is already queued before shutting the socket,
        // so the `Bye` usually makes it out even on this path.
        let _ = self.shared.control_out.try_send(ControlMsg::Bye { reason: reason.to_string() });
        if !self.shared.closed.swap(true, Ordering::SeqCst) {
            self.shared.emit(SessionEvent::Closed { reason: reason.to_string() });
        }
        self.shared.video_out.close();
        self.shared.request_shutdown();
    }

    fn is_closed(&self) -> bool {
        self.shared.closed.load(Ordering::SeqCst)
    }
}

// ---------------------------------------------------------------------------
// Tasks
// ---------------------------------------------------------------------------

/// What the writer decided to send next.
enum Outbound {
    Control(ControlMsg),
    Input(InputMsg),
    Media(EncodedFrame),
    /// `close` was called, or every sender is gone.
    Stop,
}

/// Pick the next thing to write, strictly by priority.
///
/// Control and input are drained without waiting before video is even
/// considered; only when both are empty does the writer look at the video
/// queue, and only when all three are empty does it park.
async fn next_outbound(
    shared: &Shared,
    control_rx: &mut mpsc::Receiver<ControlMsg>,
    input_rx: &mut mpsc::Receiver<InputMsg>,
) -> Outbound {
    loop {
        if let Ok(msg) = control_rx.try_recv() {
            return Outbound::Control(msg);
        }
        if let Ok(msg) = input_rx.try_recv() {
            return Outbound::Input(msg);
        }
        // Shutdown is checked *after* control and input so a queued `Bye` (or
        // a last key-up) still reaches the peer.
        if shared.shutdown.load(Ordering::SeqCst) {
            return Outbound::Stop;
        }
        if let Some(frame) = shared.video_out.try_pop() {
            return Outbound::Media(frame);
        }

        tokio::select! {
            biased;
            msg = control_rx.recv() => match msg {
                Some(m) => return Outbound::Control(m),
                None => return Outbound::Stop,
            },
            msg = input_rx.recv() => match msg {
                Some(m) => return Outbound::Input(m),
                None => return Outbound::Stop,
            },
            _ = shared.shutdown_signal.notified() => continue,
            frame = shared.video_out.pop() => match frame {
                Some(f) => return Outbound::Media(f),
                None => continue,
            },
        }
    }
}

async fn writer_loop(
    shared: Arc<Shared>,
    mut writer: WriteHalf<TlsStream<TcpStream>>,
    mut control_rx: mpsc::Receiver<ControlMsg>,
    mut input_rx: mpsc::Receiver<InputMsg>,
) {
    loop {
        let bytes = match next_outbound(&shared, &mut control_rx, &mut input_rx).await {
            Outbound::Control(m) => encode_tagged(Channel::Control, &m),
            Outbound::Input(m) => encode_tagged(Channel::Input, &m),
            Outbound::Media(f) => encode_media(&f),
            Outbound::Stop => break,
        };
        let bytes = match bytes {
            Ok(b) => b,
            Err(e) => {
                // An unencodable message is a local bug, not a reason to kill a
                // working session.
                shared.emit(SessionEvent::Warning { detail: format!("encode: {e}") });
                continue;
            }
        };
        if let Err(e) = writer.write_all(&bytes).await {
            shared.emit(SessionEvent::Warning { detail: format!("tcp write: {e}") });
            shared.mark_closed("tcp write failed");
            return;
        }
        shared.counters.bytes_tx.fetch_add(bytes.len() as u64, Ordering::Relaxed);
        if let Err(e) = writer.flush().await {
            shared.emit(SessionEvent::Warning { detail: format!("tcp flush: {e}") });
            shared.mark_closed("tcp flush failed");
            return;
        }
    }
    // A clean half-close is how the peer's reader learns this was deliberate
    // rather than a network failure.
    let _ = writer.shutdown().await;
}

async fn reader_loop(
    shared: Arc<Shared>,
    mut reader: ReadHalf<TlsStream<TcpStream>>,
    control_tx: mpsc::Sender<ControlMsg>,
    input_tx: mpsc::Sender<InputMsg>,
    video_tx: mpsc::Sender<EncodedFrame>,
    idle_timeout_ms: u64,
) {
    loop {
        let read = if idle_timeout_ms > 0 {
            match tokio::time::timeout(
                Duration::from_millis(idle_timeout_ms),
                read_tagged(&mut reader),
            )
            .await
            {
                Ok(r) => r,
                Err(_) => {
                    // Abandoning a partial read is fine: we never resume.
                    shared.mark_closed("tcp idle timeout");
                    return;
                }
            }
        } else {
            read_tagged(&mut reader).await
        };

        let (channel, body) = match read {
            Ok(v) => v,
            Err(e) => {
                shared.mark_closed(&format!("tcp connection closed: {e}"));
                return;
            }
        };
        shared
            .counters
            .bytes_rx
            .fetch_add((FRAME_HEADER_LEN + body.len()) as u64, Ordering::Relaxed);

        match channel {
            Channel::Control => {
                let msg: ControlMsg = match decode_strict(&body) {
                    Ok(m) => m,
                    Err(e) => {
                        shared.mark_closed(&format!("bad control message: {e}"));
                        return;
                    }
                };
                if !handle_control(&shared, msg, &control_tx).await {
                    return;
                }
            }
            Channel::Input => {
                let msg: InputMsg = match decode_strict(&body) {
                    Ok(m) => m,
                    Err(e) => {
                        shared.mark_closed(&format!("bad input message: {e}"));
                        return;
                    }
                };
                // Validate before handing an event to something that injects it.
                if let InputMsg::Event(ev) = &msg {
                    if let Err(e) = crate::input::validate_event(ev) {
                        shared
                            .emit(SessionEvent::Warning { detail: format!("bad input event: {e}") });
                        continue;
                    }
                }
                if input_tx.send(msg).await.is_err() {
                    shared.mark_closed("input receiver dropped");
                    return;
                }
            }
            Channel::Media => {
                match decode_media(&body) {
                    Ok(frame) => {
                        // Receive-side backpressure stays droppable: a frame the
                        // decoder cannot keep up with is not worth stalling the
                        // control channel for.
                        if video_tx.try_send(frame).is_err() {
                            shared.emit(SessionEvent::Warning {
                                detail: "video receive queue full; frame dropped".into(),
                            });
                        }
                    }
                    Err(e) => shared
                        .emit(SessionEvent::Warning { detail: format!("bad video frame: {e}") }),
                }
            }
        }
    }
}

/// Returns `false` when the reader should stop.
async fn handle_control(
    shared: &Arc<Shared>,
    msg: ControlMsg,
    tx: &mpsc::Sender<ControlMsg>,
) -> bool {
    match msg {
        ControlMsg::Ping { token } => {
            if shared.control_out.try_send(ControlMsg::Pong { token }).is_err() {
                shared.emit(SessionEvent::Warning {
                    detail: "could not answer Ping: control queue full".into(),
                });
            }
            true
        }
        ControlMsg::Pong { token } => {
            let matched = {
                let mut pending = shared.pending_ping.lock();
                match *pending {
                    Some((expected, sent_at)) if expected == token => {
                        *pending = None;
                        Some(sent_at.elapsed())
                    }
                    _ => None,
                }
            };
            match matched {
                Some(rtt) => {
                    let mut stats = shared.stats.lock();
                    let rtt_ms = rtt.as_secs_f32() * 1000.0;
                    stats.jitter_ms = ewma_jitter(stats.jitter_ms, stats.rtt_ms, rtt_ms);
                    stats.rtt_ms = rtt_ms;
                }
                None => shared
                    .emit(SessionEvent::Warning { detail: format!("unmatched Pong token {token}") }),
            }
            true
        }
        ControlMsg::Bye { reason } => {
            shared.emit(SessionEvent::PeerClosed { reason: reason.clone() });
            shared.mark_closed(&format!("peer said bye: {reason}"));
            false
        }
        ControlMsg::Stats(peer) => {
            // Peer stats are informational and attacker-influenced.
            if crate::stats::validate_stats(&peer) {
                tx.send(ControlMsg::Stats(peer)).await.is_ok()
            } else {
                shared
                    .emit(SessionEvent::Warning { detail: "discarded implausible peer stats".into() });
                true
            }
        }
        other => {
            if tx.send(other).await.is_err() {
                shared.mark_closed("control receiver dropped");
                return false;
            }
            true
        }
    }
}

async fn heartbeat_loop(shared: Arc<Shared>, interval_ms: u64) {
    let mut ticker = tokio::time::interval(Duration::from_millis(interval_ms));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut token: u64 = 1;
    loop {
        ticker.tick().await;
        if shared.closed.load(Ordering::SeqCst) {
            return;
        }
        *shared.pending_ping.lock() = Some((token, Instant::now()));
        if shared.control_out.try_send(ControlMsg::Ping { token }).is_err() {
            shared
                .emit(SessionEvent::Warning { detail: "heartbeat skipped: control queue full".into() });
        }
        token = token.wrapping_add(1);
    }
}

async fn stats_loop(shared: Arc<Shared>, interval_ms: u64) {
    let mut ticker = tokio::time::interval(Duration::from_millis(interval_ms));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut prev_bytes = 0u64;
    let mut prev_at = Instant::now();

    loop {
        ticker.tick().await;
        if shared.closed.load(Ordering::SeqCst) {
            return;
        }
        let bytes = shared.counters.bytes_tx.load(Ordering::Relaxed)
            + shared.counters.bytes_rx.load(Ordering::Relaxed);
        let dt_ms = prev_at.elapsed().as_millis() as u64;
        prev_at = Instant::now();

        let snapshot = {
            let mut stats = shared.stats.lock();
            stats.bandwidth_kbps = if dt_ms == 0 {
                0
            } else {
                ((bytes.saturating_sub(prev_bytes) as f64 * 8.0) / dt_ms as f64)
                    .min(u32::MAX as f64) as u32
            };
            // TCP retransmits below us: any loss it hides is invisible here and
            // reporting a guess would be dishonest. RTT comes from the
            // heartbeat, which measures the whole path including the peer.
            stats.loss = 0.0;
            stats.frames_dropped =
                shared.counters.video_frames_dropped_local.load(Ordering::Relaxed) as u32;
            stats.keyframes_requested = shared.counters.idr_signals.load(Ordering::Relaxed) as u32;
            *stats
        };
        prev_bytes = bytes;
        shared.emit(SessionEvent::Stats(snapshot));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::HostIdentity;
    use crate::protocol::{AuthMsg, QualityMode};

    fn loopback() -> SocketAddr {
        "127.0.0.1:0".parse().expect("literal address")
    }

    fn frame(id: u32, len: usize) -> EncodedFrame {
        EncodedFrame {
            frame_id: id,
            keyframe: id == 0,
            timestamp_ms: id * 16,
            data: (0..len).map(|i| (i as u32 % 251) as u8).collect(),
        }
    }

    // -----------------------------------------------------------------
    // Pure units
    // -----------------------------------------------------------------

    #[test]
    fn params_validation() {
        assert!(TcpParams::default().validate().is_ok());
        assert!(TcpParams { connect_timeout_ms: 0, ..Default::default() }.validate().is_err());
        assert!(TcpParams { video_queue_depth: 0, ..Default::default() }.validate().is_err());
    }

    #[test]
    fn retry_backoff_grows_then_caps() {
        let r = RetryPolicy { max_attempts: 8, initial_backoff_ms: 250, max_backoff_ms: 4_000 };
        assert_eq!(r.backoff_ms(1), 0, "the first attempt never waits");
        assert_eq!(r.backoff_ms(2), 250);
        assert_eq!(r.backoff_ms(3), 500);
        assert_eq!(r.backoff_ms(4), 1_000);
        assert_eq!(r.backoff_ms(5), 2_000);
        assert_eq!(r.backoff_ms(6), 4_000);
        assert_eq!(r.backoff_ms(7), 4_000, "capped, not doubling forever");
        assert_eq!(r.backoff_ms(u32::MAX), 4_000, "no overflow at absurd attempt counts");
    }

    #[test]
    fn channel_limits_are_per_channel() {
        assert_eq!(channel_limit(Channel::Control), MAX_CONTROL_MSG);
        assert_eq!(channel_limit(Channel::Input), MAX_CONTROL_MSG);
        assert_eq!(channel_limit(Channel::Media), MAX_MEDIA_MSG);
        assert!(
            channel_limit(Channel::Media) > channel_limit(Channel::Control),
            "a Ping must never be allowed to make us allocate a frame buffer"
        );
    }

    #[test]
    fn tagged_frames_carry_their_channel() {
        let bytes = encode_tagged(Channel::Input, &InputMsg::ReleaseAll).unwrap();
        assert_eq!(parse_channel_tag(bytes[0]).unwrap(), Channel::Input);
        let len = parse_frame_len(bytes[1..5].try_into().unwrap(), MAX_CONTROL_MSG).unwrap();
        assert_eq!(len, bytes.len() - FRAME_HEADER_LEN);
        let back: InputMsg = decode_strict(&bytes[FRAME_HEADER_LEN..]).unwrap();
        assert!(matches!(back, InputMsg::ReleaseAll));
        // Media has its own encoder because it needs its own cap.
        assert!(encode_tagged(Channel::Media, &InputMsg::ReleaseAll).is_err());
    }

    #[test]
    fn media_roundtrip_preserves_frame_identity() {
        let original = EncodedFrame {
            frame_id: 4_294_967_290,
            keyframe: true,
            timestamp_ms: 987_654,
            data: (0..5_000u32).map(|i| (i % 251) as u8).collect(),
        };
        let wire = encode_media(&original).unwrap();
        assert_eq!(parse_channel_tag(wire[0]).unwrap(), Channel::Media);
        let len = parse_frame_len(wire[1..5].try_into().unwrap(), MAX_MEDIA_MSG).unwrap();
        assert_eq!(len, wire.len() - FRAME_HEADER_LEN);
        let back = decode_media(&wire[FRAME_HEADER_LEN..]).unwrap();
        assert_eq!(back.frame_id, original.frame_id);
        assert!(back.keyframe);
        assert_eq!(back.timestamp_ms, original.timestamp_ms);
        assert_eq!(back.data, original.data);
    }

    #[test]
    fn media_encoder_rejects_empty_and_oversized_frames() {
        let empty = EncodedFrame { frame_id: 1, keyframe: false, timestamp_ms: 0, data: vec![] };
        assert!(encode_media(&empty).is_err());
        let huge = EncodedFrame {
            frame_id: 1,
            keyframe: false,
            timestamp_ms: 0,
            data: vec![0u8; MAX_FRAME_BYTES + 1],
        };
        assert!(matches!(encode_media(&huge), Err(Error::Oversized { .. })));
        // A body with a header but no payload is not a frame.
        let header = postcard::to_stdvec(&MediaHeader {
            frame_id: 1,
            keyframe: false,
            timestamp_ms: 0,
        })
        .unwrap();
        assert!(decode_media(&header).is_err());
    }

    #[test]
    fn video_queue_drops_the_oldest_and_keeps_the_newest() {
        let q = VideoQueue::new(2);
        assert_eq!(q.push(frame(0, 8)), 0);
        assert_eq!(q.push(frame(1, 8)), 0);
        assert_eq!(q.len(), 2);
        // Full: the *oldest* goes, not the arrival.
        assert_eq!(q.push(frame(2, 8)), 1);
        assert_eq!(q.push(frame(3, 8)), 1);
        assert_eq!(q.len(), 2);
        assert_eq!(q.try_pop().unwrap().frame_id, 2);
        assert_eq!(q.try_pop().unwrap().frame_id, 3);
        assert!(q.try_pop().is_none());
    }

    #[tokio::test]
    async fn video_queue_pop_wakes_and_then_closes() {
        let q = Arc::new(VideoQueue::new(2));
        let q2 = q.clone();
        let waiter = tokio::spawn(async move { q2.pop().await.map(|f| f.frame_id) });
        tokio::task::yield_now().await;
        q.push(frame(9, 8));
        assert_eq!(waiter.await.unwrap(), Some(9));

        let q3 = q.clone();
        let waiter = tokio::spawn(async move { q3.pop().await.map(|f| f.frame_id) });
        tokio::task::yield_now().await;
        q.close();
        assert_eq!(waiter.await.unwrap(), None, "a closed, drained queue ends the writer");
    }

    // -----------------------------------------------------------------
    // Real TCP + TLS on loopback
    // -----------------------------------------------------------------

    /// Bring up a host listener and a pinned client, returning both ends.
    async fn pair(id: &HostIdentity, params: TcpParams) -> (TlsTcpConn, TlsTcpConn) {
        let listener = listener(loopback()).await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let acceptor = acceptor(id.tls()).expect("acceptor");
        let p = params.clone();
        let host = tokio::spawn(async move { accept(&listener, &acceptor, &p).await });
        let client = connect(addr, ServerPinning::Pinned(*id.spki_sha256()), &params)
            .await
            .expect("client handshake");
        let host = host.await.expect("host task").expect("host handshake");
        (host, client)
    }

    #[tokio::test]
    async fn handshake_pins_and_both_ends_agree_on_the_exporter() {
        let id = HostIdentity::generate("tcp-host").unwrap();
        let (host, client) = pair(&id, TcpParams::default()).await;

        assert_eq!(client.alpn().as_deref(), Some(ALPN), "ALPN must match the QUIC path");
        assert_eq!(host.alpn().as_deref(), Some(ALPN));
        assert_eq!(client.peer_spki_pin().unwrap(), *id.spki_sha256());
        assert!(host.is_server() && !client.is_server());

        let a = host.channel_binding().expect("host exporter");
        let b = client.channel_binding().expect("client exporter");
        assert_eq!(a, b, "both ends must derive the same channel binding");
        assert_ne!(a, [0u8; 32]);
    }

    #[tokio::test]
    async fn a_wrong_pin_is_refused() {
        let id = HostIdentity::generate("real").unwrap();
        let impostor = HostIdentity::generate("impostor").unwrap();
        let listener = listener(loopback()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = acceptor(id.tls()).expect("acceptor");
        let host = tokio::spawn(async move {
            let _ = accept(&listener, &acceptor, &TcpParams::default()).await;
        });

        let res = tokio::time::timeout(
            Duration::from_secs(10),
            connect(addr, ServerPinning::Pinned(*impostor.spki_sha256()), &TcpParams::default()),
        )
        .await
        .expect("connect attempt should not hang");
        assert!(res.is_err(), "handshake must fail on a pin mismatch");
        host.abort();
    }

    #[tokio::test]
    async fn auth_messages_ride_the_control_channel_under_the_auth_cap() {
        let id = HostIdentity::generate("auth-host").unwrap();
        let (mut host, mut client) = pair(&id, TcpParams::default()).await;

        client
            .write_framed(Channel::Control, &AuthMsg::PairStart { spake_msg: vec![0xAB; 33] })
            .await
            .expect("write auth");
        let msg: AuthMsg = host.read_auth().await.expect("read auth");
        assert!(matches!(msg, AuthMsg::PairStart { .. }));

        // A control-sized message is legal on the control channel but must be
        // refused when the auth cap is in force — same rule as the QUIC path.
        host.write_framed(
            Channel::Control,
            &ControlMsg::ClipboardText("x".repeat(MAX_AUTH_MSG + 100)),
        )
        .await
        .expect("write big");
        let err = client.read_auth::<ControlMsg>().await.unwrap_err();
        assert!(matches!(err, Error::Oversized { .. }), "got {err:?}");
    }

    #[tokio::test]
    async fn all_three_channels_move_in_both_directions() {
        let id = HostIdentity::generate("chan-host").unwrap();
        let (host, client) = pair(&id, TcpParams::default()).await;

        let cfg = SessionConfig { heartbeat_ms: 100, stats_interval_ms: 100, ..Default::default() };
        let (host_session, mut host_rx) =
            TcpSession::start(host, TcpParams::default(), cfg.clone()).expect("host session");
        let (client_session, mut client_rx) =
            TcpSession::start(client, TcpParams::default(), cfg).expect("client session");

        assert_eq!(client_session.route(), TransportRoute::DirectTcp);

        client_session
            .send_control(ControlMsg::StartStream {
                max_width: 1920,
                max_height: 1080,
                preferred_fps: 60,
                quality_mode: QualityMode::Balanced,
            })
            .expect("send control");
        client_session.send_input(InputMsg::ReleaseAll).expect("send input");

        let msg = tokio::time::timeout(Duration::from_secs(10), host_rx.control.recv())
            .await
            .expect("control timeout")
            .expect("control closed");
        assert!(matches!(msg, ControlMsg::StartStream { .. }));
        let input = tokio::time::timeout(Duration::from_secs(10), host_rx.input.recv())
            .await
            .expect("input timeout")
            .expect("input closed");
        assert!(matches!(input, InputMsg::ReleaseAll));

        // A frame far larger than any QUIC datagram, in one message.
        host_session.send_video(frame(42, 300_000)).expect("send video");
        let got = tokio::time::timeout(Duration::from_secs(10), client_rx.video.recv())
            .await
            .expect("video timeout")
            .expect("video closed");
        assert_eq!(got.frame_id, 42);
        assert!(!got.keyframe, "metadata must survive the trip, not be invented");
        assert_eq!(got.timestamp_ms, 42 * 16);
        assert_eq!(got.data.len(), 300_000);
        assert!(got.data.iter().enumerate().all(|(i, b)| *b == (i as u32 % 251) as u8));

        // The heartbeat should have produced a real RTT measurement.
        tokio::time::sleep(Duration::from_millis(500)).await;
        let stats = client_session.stats();
        assert!(crate::stats::validate_stats(&stats), "{stats:?}");
        assert!(!client_session.is_closed());

        let (tx, rx) = client_session.byte_counts();
        assert!(tx > 0 && rx > 0, "tx {tx} rx {rx}");
    }

    /// The point of the module: a video backlog must never delay input.
    ///
    /// The host end deliberately never reads, so after the first frame the
    /// client's writer is wedged inside `write_all` with the socket buffers
    /// full — the worst case this transport has. The backlog and then the input
    /// event are queued behind that wedge with no `await` in between, so on the
    /// current-thread runtime the writer provably cannot have moved while they
    /// were queued.
    ///
    /// What must come out: the input event, then the two surviving frames.
    #[tokio::test]
    async fn input_beats_the_queued_video_backlog() {
        const FRAMES: u32 = 24;
        const FRAME_BYTES: usize = 512 * 1024;

        let id = HostIdentity::generate("prio-host").unwrap();
        let (mut host, client) = pair(&id, TcpParams::default()).await;

        // No heartbeat and no stats: the only control traffic should be ours.
        let cfg = SessionConfig { heartbeat_ms: 0, stats_interval_ms: 0, ..Default::default() };
        let (session, mut rx) =
            TcpSession::start(client, TcpParams::default(), cfg).expect("client session");

        // Phase 1: wedge the writer. Half a megabyte cannot fit in loopback
        // socket buffers, so the writer blocks part-way through frame 0 and
        // stays there until the host reads — which it will not, yet.
        session.send_video(frame(0, FRAME_BYTES)).expect("queue video");
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Phase 2: pile up a backlog and then an input event behind the wedge.
        for n in 1..FRAMES {
            session.send_video(frame(n, FRAME_BYTES)).expect("queue video");
        }
        session.send_input(InputMsg::ReleaseAll).expect("queue input");

        let dropped = session.frames_dropped_local();
        assert!(
            dropped >= u64::from(FRAMES) - DEFAULT_VIDEO_QUEUE_DEPTH as u64 - 2,
            "expected almost every frame to be dropped, got {dropped} of {FRAMES}"
        );
        assert!(session.idr_signals() >= 1, "dropping frames must ask the encoder for an IDR");
        let mut saw_keyframe_event = false;
        while let Ok(ev) = rx.events.try_recv() {
            if matches!(ev, SessionEvent::KeyframeNeeded) {
                saw_keyframe_event = true;
            }
        }
        assert!(saw_keyframe_event, "the drop must surface as a KeyframeNeeded event");

        // Now let the host drain, recording the order things arrive in.
        let mut media_before_input = 0usize;
        let mut media_after_input = 0usize;
        let mut media_ids = Vec::new();
        let mut saw_input = false;
        for _ in 0..(FRAMES as usize + 4) {
            let (channel, body) =
                tokio::time::timeout(Duration::from_secs(10), host.read_any())
                    .await
                    .expect("read timeout")
                    .expect("read failed");
            match channel {
                Channel::Media => {
                    media_ids.push(decode_media(&body).expect("decode media").frame_id);
                    if saw_input {
                        media_after_input += 1;
                    } else {
                        media_before_input += 1;
                    }
                }
                Channel::Input => {
                    saw_input = true;
                    break;
                }
                Channel::Control => panic!("no control traffic was sent"),
            }
        }
        assert!(saw_input, "the input event never arrived");
        assert!(
            media_before_input <= 1,
            "input queued behind {media_before_input} video frames; \
             at most one (the frame already on the wire) is acceptable"
        );

        // Drain the tail so we can prove which frames survived.
        while let Ok(Ok((channel, body))) =
            tokio::time::timeout(Duration::from_millis(500), host.read_any()).await
        {
            if channel == Channel::Media {
                media_ids.push(decode_media(&body).expect("decode media").frame_id);
                media_after_input += 1;
            }
        }

        assert!(media_after_input >= 1, "the surviving backlog must arrive after the input");
        assert!(
            media_ids.len() <= DEFAULT_VIDEO_QUEUE_DEPTH + 1,
            "the backlog must have been dropped, not buffered: {media_ids:?}"
        );
        // Latest-wins: whatever survived is the newest, never the oldest.
        assert!(
            media_ids.contains(&(FRAMES - 2)) && media_ids.contains(&(FRAMES - 1)),
            "the two newest frames must survive, got {media_ids:?}"
        );
        assert!(
            media_ids.iter().all(|id| *id == 0 || *id >= FRAMES - 2),
            "only the newest frames (or one already on the wire) may survive: {media_ids:?}"
        );
    }

    #[tokio::test]
    async fn bye_round_trips_and_closes_both_ends() {
        let id = HostIdentity::generate("bye-host").unwrap();
        let (host, client) = pair(&id, TcpParams::default()).await;

        let (host_session, _host_rx) =
            TcpSession::start(host, TcpParams::default(), SessionConfig::default())
                .expect("host session");
        let (client_session, mut client_rx) =
            TcpSession::start(client, TcpParams::default(), SessionConfig::default())
                .expect("client session");

        host_session.close_graceful("host is going away", Duration::from_secs(2)).await;

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut saw_bye = false;
        while Instant::now() < deadline && !saw_bye {
            match tokio::time::timeout(Duration::from_millis(500), client_rx.events.recv()).await {
                Ok(Some(SessionEvent::PeerClosed { reason })) => {
                    assert_eq!(reason, "host is going away");
                    saw_bye = true;
                }
                Ok(Some(_)) => continue,
                Ok(None) => break,
                Err(_) => continue,
            }
        }
        assert!(saw_bye, "expected a structured ControlMsg::Bye from the peer");
        assert!(client_session.is_closed(), "receiving Bye must close the session");
        assert!(host_session.is_closed());
    }

    /// A hostile length prefix must be refused before anything is allocated,
    /// and must kill the session rather than the process.
    #[tokio::test]
    async fn an_oversized_length_prefix_is_refused() {
        let id = HostIdentity::generate("cap-host").unwrap();
        let (host, mut client) = pair(&id, TcpParams::default()).await;

        let cfg = SessionConfig { heartbeat_ms: 0, stats_interval_ms: 0, ..Default::default() };
        let (host_session, mut host_rx) =
            TcpSession::start(host, TcpParams::default(), cfg).expect("host session");

        // Claim a 3 GiB media body. `parse_frame_len` must reject it on sight.
        let mut hostile = vec![channel_tag(Channel::Media).unwrap()];
        hostile.extend_from_slice(&(3_000_000_000u32).to_le_bytes());
        client.stream.write_all(&hostile).await.expect("write hostile prefix");
        client.stream.flush().await.expect("flush");

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut closed = false;
        while Instant::now() < deadline && !closed {
            match tokio::time::timeout(Duration::from_millis(500), host_rx.events.recv()).await {
                Ok(Some(SessionEvent::Closed { .. })) => closed = true,
                Ok(Some(_)) => continue,
                Ok(None) => break,
                Err(_) => continue,
            }
        }
        assert!(closed, "an oversized frame must close the session");
        assert!(host_session.is_closed());
    }

    #[tokio::test]
    async fn connect_with_retry_gives_up_with_a_useful_error() {
        // Bind and immediately drop, so the port is (almost certainly) dead.
        let dead = {
            let l = listener(loopback()).await.unwrap();
            l.local_addr().unwrap()
        };
        let id = HostIdentity::generate("nobody").unwrap();
        let retry =
            RetryPolicy { max_attempts: 3, initial_backoff_ms: 1, max_backoff_ms: 4 };
        let params = TcpParams { connect_timeout_ms: 500, ..Default::default() };
        let err = connect_with_retry(dead, ServerPinning::Pinned(*id.spki_sha256()), &params, retry)
            .await
            .expect_err("nothing is listening");
        let text = err.to_string();
        assert!(text.contains("after 3 attempts"), "{text}");

        let none = RetryPolicy { max_attempts: 0, ..Default::default() };
        assert!(
            connect_with_retry(dead, ServerPinning::Pinned(*id.spki_sha256()), &params, none)
                .await
                .is_err()
        );
    }
}
