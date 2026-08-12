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
//! produces. A video frame is split into **segments** of at most [`SEGMENT_MAX`]
//! bytes, each carried as its own Media-channel message: a small postcard
//! [`MediaHeader`] (frame identity plus `segment_index` / `segment_count` /
//! `last`) followed by that slice of the encoded bytes. TCP is reliable and
//! ordered, so — unlike the QUIC path's out-of-order fragment reassembly — the
//! segments of a frame always arrive contiguous and in index order; the receiver
//! ([`MediaReassembler`]) only has to concatenate them and guard against a frame
//! that was abandoned mid-flight. The reason to segment at all is *not*
//! reliability, it is priority — see below.
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
//! **The one honest limit.** Priority is applied at message boundaries, and a
//! message is now a single *segment*, not a whole frame. [`writer_loop`] drains
//! control and input before **every** segment, so an input event can be delayed
//! by at most *one* in-flight segment ([`SEGMENT_MAX`], ~64 KiB) — never by the
//! rest of a 2 MiB keyframe, and never by the queue behind it. That is the
//! difference between a few milliseconds and, on a slow uplink, hundreds. The
//! loopback tests `input_beats_the_queued_video_backlog` and
//! `input_interleaves_within_a_multi_segment_frame` pin that behaviour down,
//! measuring the delivery order to prove input rides out ahead of the bulk of a
//! frame that is already being transmitted.
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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};

use crate::crypto::identity::TlsIdentity;
use crate::crypto::tls::{self, ServerPinning};
use crate::crypto::{Exporter, SpkiHash, EXPORTER_CONTEXT, EXPORTER_LABEL};
use crate::error::{Error, Result};
use crate::protocol::{
    decode_strict, encode_framed, parse_frame_len, Channel, ControlMsg, InputMsg, ALPN,
    MAX_AUTH_MSG, MAX_CONTROL_MSG,
};
use crate::stats::{ConnStats, TransportRoute};
use crate::transport::session::{
    ewma_jitter, Session, SessionConfig, SessionEvent, SessionReceivers,
};
use crate::transport::{channel_tag, parse_channel_tag};
use crate::video::{EncodedFrame, MAX_FRAME_BYTES};

/// Bytes of framing ahead of every message: one channel tag, one u32 length.
pub const FRAME_HEADER_LEN: usize = 5;

/// Cap on a media message body: a whole encoded frame plus its small header.
///
/// A single segment is far smaller than this ([`SEGMENT_MAX`] plus a header), but
/// the cap stays frame-sized so the reader's pre-allocation guard tolerates a
/// peer that legitimately sends a large single-segment frame, and so
/// [`channel_limit`] keeps its "a `Ping` must never make us allocate a video
/// buffer" invariant. Per-frame byte accounting is enforced during reassembly.
pub const MAX_MEDIA_MSG: usize = MAX_FRAME_BYTES + 64;

/// Largest payload a single media segment carries.
///
/// Sized to [`MAX_CONTROL_MSG`] (64 KiB) deliberately: a video segment is then
/// never larger than the largest control or input message, so an input event
/// queued while a frame is mid-flight waits behind at most one segment on the
/// wire — tens of KiB, a few milliseconds even on a constrained uplink — instead
/// of a whole 2 MiB keyframe. It is small enough that the writer revisits the
/// control/input queues often, and large enough that the per-segment header
/// (~18 bytes postcard) and TLS record framing stay well under 0.1% overhead.
pub const SEGMENT_MAX: usize = MAX_CONTROL_MSG;

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
            return Err(Error::Invalid(
                "tcp connect timeout must be non-zero".into(),
            ));
        }
        if self.video_queue_depth == 0 {
            return Err(Error::Invalid(
                "tcp video queue depth must be non-zero".into(),
            ));
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
        Self {
            max_attempts: 5,
            initial_backoff_ms: 250,
            max_backoff_ms: 4_000,
        }
    }
}

impl RetryPolicy {
    /// Delay before attempt number `attempt` (1-based; attempt 1 never waits).
    pub fn backoff_ms(&self, attempt: u32) -> u64 {
        if attempt <= 1 {
            return 0;
        }
        let shift = (attempt - 2).min(31);
        self.initial_backoff_ms
            .saturating_mul(1u64 << shift)
            .min(self.max_backoff_ms)
    }
}

// ---------------------------------------------------------------------------
// Wire format
// ---------------------------------------------------------------------------

/// The metadata that rides in front of one *segment* of a video frame.
///
/// Postcard-encoded and varint-packed, so it costs a handful of bytes in
/// practice. The body is `MediaHeader || segment bytes`; the decoder recovers
/// the split from postcard's own framing, not from a fixed offset. Every segment
/// of a frame repeats the frame's identity (`frame_id`, `keyframe`,
/// `timestamp_ms`) so a receiver can detect a segment that contradicts the frame
/// it is assembling, and carries its position (`segment_index` of
/// `segment_count`, plus a redundant `last` flag) so reassembly needs no
/// look-ahead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaHeader {
    /// Sender's frame counter. Wraps.
    pub frame_id: u32,
    /// Whether this frame is an IDR.
    pub keyframe: bool,
    /// Sender-monotonic capture timestamp in milliseconds. Wraps.
    pub timestamp_ms: u32,
    /// 0-based position of this segment within the frame.
    pub segment_index: u16,
    /// Total number of segments the frame was split into. Always `>= 1`.
    pub segment_count: u16,
    /// True on the final segment, i.e. `segment_index + 1 == segment_count`.
    /// Redundant with the two counts, and cross-checked against them, but it lets
    /// the reader recognise completion without arithmetic on hostile input.
    pub last: bool,
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
        return Err(Error::Invalid(
            "use encode_media for the media channel".into(),
        ));
    }
    let framed = encode_framed(msg)?;
    let mut out = Vec::with_capacity(1 + framed.len());
    out.push(channel_tag(channel)?);
    out.extend_from_slice(&framed);
    Ok(out)
}

/// Encode one [`EncodedFrame`] as an ordered list of tagged, length-prefixed
/// Media-channel messages — one per [`SEGMENT_MAX`]-byte segment.
///
/// Each returned buffer is a complete wire message (`tag || len || MediaHeader ||
/// segment bytes`). Emitting them as *separate* messages is the whole point: the
/// writer yields to the control and input queues between segments, so a large
/// frame can never head-of-line-block an input event by more than one segment.
/// A single-segment frame produces a one-element list, so small frames pay no
/// segmentation cost beyond a two-field-larger header.
pub fn encode_media_segments(frame: &EncodedFrame) -> Result<Vec<Vec<u8>>> {
    if frame.data.is_empty() {
        return Err(Error::Invalid("empty frame".into()));
    }
    if frame.data.len() > MAX_FRAME_BYTES {
        return Err(Error::Oversized {
            got: frame.data.len(),
            limit: MAX_FRAME_BYTES,
        });
    }
    let count = frame.data.len().div_ceil(SEGMENT_MAX);
    debug_assert!(count >= 1, "a non-empty frame has at least one segment");
    if count > u16::MAX as usize {
        // Unreachable while MAX_FRAME_BYTES / SEGMENT_MAX <= 32, but keep the
        // wire-format's own limit honest rather than silently truncating a cast.
        return Err(Error::Oversized {
            got: count,
            limit: u16::MAX as usize,
        });
    }
    let tag = channel_tag(Channel::Media)?;
    let mut out = Vec::with_capacity(count);
    for (i, chunk) in frame.data.chunks(SEGMENT_MAX).enumerate() {
        let header = postcard::to_stdvec(&MediaHeader {
            frame_id: frame.frame_id,
            keyframe: frame.keyframe,
            timestamp_ms: frame.timestamp_ms,
            segment_index: i as u16,
            segment_count: count as u16,
            last: i + 1 == count,
        })?;
        let body_len = header.len() + chunk.len();
        if body_len > MAX_MEDIA_MSG {
            return Err(Error::Oversized {
                got: body_len,
                limit: MAX_MEDIA_MSG,
            });
        }
        let mut msg = Vec::with_capacity(FRAME_HEADER_LEN + body_len);
        msg.push(tag);
        msg.extend_from_slice(&(body_len as u32).to_le_bytes());
        msg.extend_from_slice(&header);
        msg.extend_from_slice(chunk);
        out.push(msg);
    }
    Ok(out)
}

/// Decode one media message body into its [`MediaHeader`] and segment payload.
///
/// Validates only what is intrinsic to a single segment: the counts are
/// self-consistent (`segment_index < segment_count`, `last` agrees with the
/// index), and the payload is non-empty and within [`MAX_FRAME_BYTES`]. Whether
/// the segment fits the *frame in progress* is the reassembler's job.
pub fn decode_media_segment(body: &[u8]) -> Result<(MediaHeader, &[u8])> {
    let (header, rest) = postcard::take_from_bytes::<MediaHeader>(body)?;
    if header.segment_count == 0 {
        return Err(Error::Invalid("media segment_count is zero".into()));
    }
    if header.segment_index >= header.segment_count {
        return Err(Error::Invalid(format!(
            "media segment_index {} >= segment_count {}",
            header.segment_index, header.segment_count
        )));
    }
    if header.last != (header.segment_index + 1 == header.segment_count) {
        return Err(Error::Invalid(
            "media segment last-flag contradicts its index".into(),
        ));
    }
    if rest.is_empty() {
        return Err(Error::Invalid("media segment carries no data".into()));
    }
    if rest.len() > MAX_FRAME_BYTES {
        return Err(Error::Oversized {
            got: rest.len(),
            limit: MAX_FRAME_BYTES,
        });
    }
    Ok((header, rest))
}

/// One frame being reassembled from its in-order segments.
struct PartialMedia {
    frame_id: u32,
    keyframe: bool,
    timestamp_ms: u32,
    segment_count: u16,
    /// The next `segment_index` expected; equals the number of segments stored.
    next_index: u16,
    buf: Vec<u8>,
}

/// Reassembles the reliable-channel media segments of one connection back into
/// whole [`EncodedFrame`]s.
///
/// The reliable, ordered channel makes this far simpler than the datagram
/// [`crate::transport::reassembly::Reassembler`]: at most one frame is ever in
/// flight, its segments arrive in index order, and none are lost. The only
/// events to handle are a frame that never finished before a *newer* frame began
/// (latest-wins on the reliable path too — a stale half-frame is useless to the
/// decoder), a gap in the frame-id sequence (the sender's latest-wins queue
/// dropped whole frames), and hostile or corrupt segments. Any of the first two
/// arms a keyframe demand; the last is refused without disturbing an unrelated
/// frame in progress, exactly like the datagram path.
#[derive(Default)]
struct MediaReassembler {
    active: Option<PartialMedia>,
    /// Frame id whose first segment we last accepted, for gap detection.
    last_started: Option<u32>,
    /// Partial frames abandoned since the last drain.
    drops: u64,
    /// Whether a drop or gap since the last drain should raise a keyframe demand.
    idr: bool,
}

impl MediaReassembler {
    fn new() -> Self {
        Self::default()
    }

    /// Feed one decoded segment. Returns the completed frame when this segment
    /// was the last one, `Ok(None)` while a frame is still assembling, or `Err`
    /// for a segment that cannot belong to any frame we could deliver. Errors
    /// never poison an unrelated frame in progress; the caller logs and carries
    /// on.
    fn push(&mut self, header: MediaHeader, payload: &[u8]) -> Result<Option<EncodedFrame>> {
        if header.segment_index == 0 {
            Ok(self.begin_frame(header, payload))
        } else {
            self.continue_frame(header, payload)
        }
    }

    /// Start assembling a new frame from its opening segment.
    fn begin_frame(&mut self, header: MediaHeader, payload: &[u8]) -> Option<EncodedFrame> {
        // A frame still assembling when a newer one starts never completed: drop
        // it. On the reliable path the sender emits a frame's segments
        // contiguously, so this only fires on an abandoned/renumbered stream, but
        // handling it keeps a stale half-frame from ever reaching the decoder.
        if self.active.take().is_some() {
            self.drops += 1;
            self.idr = true;
        }
        // A jump in the frame-id sequence means the sender dropped whole frames
        // (its own latest-wins queue). The decode chain has a hole; ask for a
        // fresh anchor. The first frame ever seen has no predecessor and is not a
        // gap.
        if let Some(prev) = self.last_started {
            if header.frame_id != prev.wrapping_add(1) {
                self.idr = true;
            }
        }
        self.last_started = Some(header.frame_id);

        if header.segment_count == 1 {
            return Some(EncodedFrame {
                frame_id: header.frame_id,
                keyframe: header.keyframe,
                timestamp_ms: header.timestamp_ms,
                data: payload.to_vec(),
            });
        }
        let mut buf = Vec::with_capacity(payload.len());
        buf.extend_from_slice(payload);
        self.active = Some(PartialMedia {
            frame_id: header.frame_id,
            keyframe: header.keyframe,
            timestamp_ms: header.timestamp_ms,
            segment_count: header.segment_count,
            next_index: 1,
            buf,
        });
        None
    }

    /// Append a non-opening segment to the frame in progress.
    fn continue_frame(
        &mut self,
        header: MediaHeader,
        payload: &[u8],
    ) -> Result<Option<EncodedFrame>> {
        // Copy out everything we need so the immutable borrow ends before any
        // mutation of `self.active` below.
        let (frame_id, segment_count, keyframe, timestamp_ms, next_index, cur_len) =
            match self.active.as_ref() {
                Some(a) => (
                    a.frame_id,
                    a.segment_count,
                    a.keyframe,
                    a.timestamp_ms,
                    a.next_index,
                    a.buf.len(),
                ),
                None => {
                    // A mid-frame segment with no frame in progress: its opening
                    // segment was lost or dropped. Unusable, and a hole in the
                    // decode chain.
                    self.idr = true;
                    return Err(Error::Invalid(
                        "media segment continues a frame that never started".into(),
                    ));
                }
            };

        if header.frame_id != frame_id
            || header.segment_count != segment_count
            || header.keyframe != keyframe
            || header.timestamp_ms != timestamp_ms
        {
            // The segment does not belong to the frame we are assembling. On an
            // ordered stream that means corruption; abandon the partial.
            self.active = None;
            self.drops += 1;
            self.idr = true;
            return Err(Error::Invalid(
                "media segment contradicts the frame in progress".into(),
            ));
        }
        if header.segment_index != next_index {
            self.active = None;
            self.drops += 1;
            self.idr = true;
            return Err(Error::Invalid(format!(
                "media segment {} arrived out of order (expected {next_index})",
                header.segment_index
            )));
        }
        let total = cur_len.saturating_add(payload.len());
        if total > MAX_FRAME_BYTES {
            self.active = None;
            self.drops += 1;
            self.idr = true;
            return Err(Error::Oversized {
                got: total,
                limit: MAX_FRAME_BYTES,
            });
        }

        let active = self.active.as_mut().expect("active frame present");
        active.buf.extend_from_slice(payload);
        active.next_index += 1;
        if active.next_index == active.segment_count {
            let done = self.active.take().expect("active frame present");
            return Ok(Some(EncodedFrame {
                frame_id: done.frame_id,
                keyframe: done.keyframe,
                timestamp_ms: done.timestamp_ms,
                data: done.buf,
            }));
        }
        Ok(None)
    }

    /// Number of partial frames dropped since the previous call; clears it.
    fn take_drops(&mut self) -> u64 {
        std::mem::take(&mut self.drops)
    }

    /// Whether a drop or gap since the previous call should raise a keyframe
    /// demand; clears it.
    fn take_idr(&mut self) -> bool {
        std::mem::take(&mut self.idr)
    }
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
        let chain =
            certs.ok_or_else(|| Error::Crypto("connection has no peer certificate".into()))?;
        let first = chain
            .first()
            .ok_or_else(|| Error::Crypto("empty certificate chain".into()))?;
        crate::crypto::spki_sha256_from_cert_der(first.as_ref())
    }

    /// Write one tagged, length-prefixed message.
    pub async fn write_framed<T: Serialize>(&mut self, channel: Channel, msg: &T) -> Result<()> {
        let bytes = encode_tagged(channel, msg)?;
        self.stream
            .write_all(&bytes)
            .await
            .map_err(|e| Error::Transport(format!("tcp write: {e}")))?;
        self.stream
            .flush()
            .await
            .map_err(|e| Error::Transport(format!("tcp flush: {e}")))
    }

    /// Read one tagged message, refusing anything over `limit`.
    ///
    /// Returns the channel it arrived on so the caller can reject traffic that
    /// does not belong in the current phase.
    pub async fn read_framed<T: DeserializeOwned>(&mut self, limit: usize) -> Result<(Channel, T)> {
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
            return Err(Error::Protocol(format!(
                "auth message on the {channel:?} channel"
            )));
        }
        Ok(msg)
    }
}

/// Bind a fallback listener. Use [`crate::protocol::DEFAULT_TCP_PORT`] unless
/// the user configured otherwise.
pub async fn listener(bind: SocketAddr) -> Result<TcpListener> {
    TcpListener::bind(bind)
        .await
        .map_err(|e| Error::Transport(format!("tcp bind {bind}: {e}")))
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

    let conn = TlsTcpConn {
        stream: TlsStream::Server(tls),
        peer,
        server: true,
    };
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
        return Err(Error::Transport(format!(
            "no time left for the tls handshake with {addr}"
        )));
    }
    let tls = tokio::time::timeout(remaining, connector.connect(tls::sni()?, sock))
        .await
        .map_err(|_| Error::Transport(format!("tls handshake with {addr} timed out")))?
        .map_err(|e| Error::Transport(format!("tls handshake with {addr}: {e}")))?;

    let conn = TlsTcpConn {
        stream: TlsStream::Client(tls),
        peer: addr,
        server: false,
    };
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
        return Err(Error::Invalid(
            "retry policy must allow at least one attempt".into(),
        ));
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
    video_frames_reassembly_dropped: AtomicU64,
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
            self.emit(SessionEvent::Closed {
                reason: reason.to_string(),
            });
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
        // The second monitor's stream never arrives here either, and for a
        // reason one step stronger than audio's: it is identified by a *video
        // datagram* flag (`crate::video::FLAG_STREAM1`), and this transport has
        // no datagram path at all. `encode_media_segments` muxes one video
        // stream inline on the byte stream that also carries control and input,
        // and there is no segment kind for a second one. So the sender is
        // dropped where it is made and `rx.video1` is closed from the start,
        // exactly as `SessionConfig::receive_video_1` being off would leave it.
        let (video1_in_tx, video1_in_rx) = mpsc::channel(config.video_capacity);
        drop(video1_in_tx);
        // Audio never arrives on this transport, so the sender is dropped the
        // moment it is made and `rx.audio` is closed from the start.
        //
        // Not a policy choice and not affected by `SessionConfig::receive_audio`
        // — the same limitation `receive_video` has here, for the same reason.
        // Audio is a *datagram* format (see `crate::audio`), and TCP has no
        // datagram path at all: `encode_media_segments` muxes video inline on
        // the one byte stream that also carries control and input, and there is
        // no segment kind on that stream for an AAC access unit. A caller that
        // asks a `TcpSession` for audio therefore gets a receiver that says
        // `None` immediately, rather than one that waits forever for packets
        // this transport is structurally unable to deliver.
        let (audio_in_tx, audio_in_rx) = mpsc::channel(config.audio_capacity);
        drop(audio_in_tx);
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
            tasks.push(tokio::spawn(heartbeat_loop(
                shared.clone(),
                config.heartbeat_ms,
            )));
        }
        if config.stats_interval_ms > 0 {
            tasks.push(tokio::spawn(stats_loop(
                shared.clone(),
                config.stats_interval_ms,
            )));
        }

        let session = Self {
            shared,
            tasks: Mutex::new(tasks),
        };
        let receivers = SessionReceivers {
            control: control_in_rx,
            input: input_in_rx,
            video: video_in_rx,
            video1: video1_in_rx,
            audio: audio_in_rx,
            events: events_rx,
        };
        Ok((session, receivers))
    }

    /// Queue a video frame. Drops the oldest when the queue is full (see the
    /// module docs on latest-wins) and never blocks.
    ///
    /// Inherent, not part of [`Session`]: video egress is transport-specific and
    /// the QUIC side deliberately has none — a datagram sender needs FEC,
    /// pacing and a send-buffer precheck, all of which live in the host's
    /// `video_pump`. TCP's media path is a different animal (ordered stream
    /// segments, see [`encode_media_segments`]) and *is* the real sender for
    /// this transport, so it stays — just not behind a trait that would imply
    /// every transport has one.
    pub fn send_video(&self, frame: EncodedFrame) -> Result<()> {
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
                self.shared
                    .counters
                    .idr_signals
                    .fetch_add(1, Ordering::Relaxed);
                self.shared.emit(SessionEvent::KeyframeNeeded);
            }
        }
        Ok(())
    }

    /// Number of video frames dropped locally because the send queue was full.
    pub fn frames_dropped_local(&self) -> u64 {
        self.shared
            .counters
            .video_frames_dropped_local
            .load(Ordering::Relaxed)
    }

    /// Number of times a drop raised [`SessionEvent::KeyframeNeeded`] for the
    /// local encoder. Lower than [`Self::frames_dropped_local`] because the
    /// signal is rate-limited.
    pub fn idr_signals(&self) -> u64 {
        self.shared.counters.idr_signals.load(Ordering::Relaxed)
    }

    /// Partial video frames abandoned by the receive-side reassembler: a newer
    /// frame's segments began before the current frame finished, or a segment
    /// was malformed, out of order, or contradicted the frame in progress. Each
    /// such drop leaves a hole in the decode chain and arms a rate-limited
    /// [`SessionEvent::KeyframeNeeded`].
    pub fn frames_reassembly_dropped(&self) -> u64 {
        self.shared
            .counters
            .video_frames_reassembly_dropped
            .load(Ordering::Relaxed)
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
        let _ = self.shared.control_out.try_send(ControlMsg::Bye {
            reason: reason.to_string(),
        });
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

    fn close(&self, reason: &str) {
        // Synchronous: queue the `Bye` and ask the writer to drain and hang up.
        // The writer flushes what is already queued before shutting the socket,
        // so the `Bye` usually makes it out even on this path.
        let _ = self.shared.control_out.try_send(ControlMsg::Bye {
            reason: reason.to_string(),
        });
        if !self.shared.closed.swap(true, Ordering::SeqCst) {
            self.shared.emit(SessionEvent::Closed {
                reason: reason.to_string(),
            });
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

/// Write one buffer and flush it, updating the byte counter. Returns `false`
/// once the socket is dead (the session is already marked closed); the caller
/// must then stop.
async fn write_all_counted(
    shared: &Shared,
    writer: &mut WriteHalf<TlsStream<TcpStream>>,
    bytes: &[u8],
) -> bool {
    if let Err(e) = writer.write_all(bytes).await {
        shared.emit(SessionEvent::Warning {
            detail: format!("tcp write: {e}"),
        });
        shared.mark_closed("tcp write failed");
        return false;
    }
    shared
        .counters
        .bytes_tx
        .fetch_add(bytes.len() as u64, Ordering::Relaxed);
    if let Err(e) = writer.flush().await {
        shared.emit(SessionEvent::Warning {
            detail: format!("tcp flush: {e}"),
        });
        shared.mark_closed("tcp flush failed");
        return false;
    }
    true
}

/// Encode and send a control/input message. Returns `false` only on a fatal
/// socket error (the caller must stop); an *encode* failure is a local bug, not
/// a reason to kill a working session, so it is warned about and swallowed.
async fn send_tagged<T: Serialize>(
    shared: &Shared,
    writer: &mut WriteHalf<TlsStream<TcpStream>>,
    channel: Channel,
    msg: &T,
) -> bool {
    match encode_tagged(channel, msg) {
        Ok(bytes) => write_all_counted(shared, writer, &bytes).await,
        Err(e) => {
            shared.emit(SessionEvent::Warning {
                detail: format!("encode: {e}"),
            });
            true
        }
    }
}

async fn writer_loop(
    shared: Arc<Shared>,
    mut writer: WriteHalf<TlsStream<TcpStream>>,
    mut control_rx: mpsc::Receiver<ControlMsg>,
    mut input_rx: mpsc::Receiver<InputMsg>,
) {
    // Segments of the video frame currently being transmitted. They are strictly
    // lower priority than control and input, so those queues are drained before
    // *each* segment below — that is what bounds an input event's delay to one
    // segment instead of a whole frame. A new frame is only pulled from
    // `video_out` once this is empty, so a frame is never interleaved with
    // another frame's segments, only with higher-priority control/input.
    let mut pending: VecDeque<Vec<u8>> = VecDeque::new();

    loop {
        // Strict priority, re-evaluated before every segment.
        if let Ok(m) = control_rx.try_recv() {
            if !send_tagged(&shared, &mut writer, Channel::Control, &m).await {
                return;
            }
            continue;
        }
        if let Ok(m) = input_rx.try_recv() {
            if !send_tagged(&shared, &mut writer, Channel::Input, &m).await {
                return;
            }
            continue;
        }
        // Shutdown is checked after control/input so a queued `Bye` (or a last
        // key-up) still reaches the peer. Any half-sent frame is abandoned — we
        // are closing, and a stale partial frame is useless to the peer.
        if shared.shutdown.load(Ordering::SeqCst) {
            break;
        }
        if let Some(seg) = pending.pop_front() {
            if !write_all_counted(&shared, &mut writer, &seg).await {
                return;
            }
            continue;
        }
        // Nothing pending and nothing higher priority is ready: block for work.
        match next_outbound(&shared, &mut control_rx, &mut input_rx).await {
            Outbound::Control(m) => {
                if !send_tagged(&shared, &mut writer, Channel::Control, &m).await {
                    return;
                }
            }
            Outbound::Input(m) => {
                if !send_tagged(&shared, &mut writer, Channel::Input, &m).await {
                    return;
                }
            }
            Outbound::Media(f) => match encode_media_segments(&f) {
                // Queue the segments; the loop head sends them one at a time,
                // draining control/input in between.
                Ok(segs) => pending.extend(segs),
                Err(e) => shared.emit(SessionEvent::Warning {
                    detail: format!("encode: {e}"),
                }),
            },
            Outbound::Stop => break,
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
    let mut media = MediaReassembler::new();
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
                        shared.emit(SessionEvent::Warning {
                            detail: format!("bad input event: {e}"),
                        });
                        continue;
                    }
                }
                if input_tx.send(msg).await.is_err() {
                    shared.mark_closed("input receiver dropped");
                    return;
                }
            }
            Channel::Media => {
                match decode_media_segment(&body) {
                    Ok((header, payload)) => match media.push(header, payload) {
                        Ok(Some(frame)) => {
                            // Receive-side backpressure stays droppable: a frame
                            // the decoder cannot keep up with is not worth
                            // stalling the control channel for.
                            if video_tx.try_send(frame).is_err() {
                                shared.emit(SessionEvent::Warning {
                                    detail: "video receive queue full; frame dropped".into(),
                                });
                            }
                        }
                        Ok(None) => {}
                        Err(e) => shared.emit(SessionEvent::Warning {
                            detail: format!("bad video segment: {e}"),
                        }),
                    },
                    Err(e) => shared.emit(SessionEvent::Warning {
                        detail: format!("bad video segment: {e}"),
                    }),
                }
                // A dropped partial or a frame-id gap leaves the decoder without
                // a valid reference. Count the drops and raise a rate-limited
                // keyframe demand — the same signal the datagram reassembler
                // raises on a lost fragment.
                let drops = media.take_drops();
                if drops > 0 {
                    shared
                        .counters
                        .video_frames_reassembly_dropped
                        .fetch_add(drops, Ordering::Relaxed);
                }
                if media.take_idr() && shared.arm_idr() {
                    shared.counters.idr_signals.fetch_add(1, Ordering::Relaxed);
                    shared.emit(SessionEvent::KeyframeNeeded);
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
            if shared
                .control_out
                .try_send(ControlMsg::Pong { token })
                .is_err()
            {
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
                None => shared.emit(SessionEvent::Warning {
                    detail: format!("unmatched Pong token {token}"),
                }),
            }
            true
        }
        ControlMsg::Bye { reason } => {
            shared.emit(SessionEvent::PeerClosed {
                reason: reason.clone(),
            });
            shared.mark_closed(&format!("peer said bye: {reason}"));
            false
        }
        ControlMsg::Stats(peer) => {
            // Peer stats are informational and attacker-influenced.
            if crate::stats::validate_stats(&peer) {
                tx.send(ControlMsg::Stats(peer)).await.is_ok()
            } else {
                shared.emit(SessionEvent::Warning {
                    detail: "discarded implausible peer stats".into(),
                });
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
        if shared
            .control_out
            .try_send(ControlMsg::Ping { token })
            .is_err()
        {
            shared.emit(SessionEvent::Warning {
                detail: "heartbeat skipped: control queue full".into(),
            });
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
            stats.frames_dropped = shared
                .counters
                .video_frames_dropped_local
                .load(Ordering::Relaxed) as u32;
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
        assert!(TcpParams {
            connect_timeout_ms: 0,
            ..Default::default()
        }
        .validate()
        .is_err());
        assert!(TcpParams {
            video_queue_depth: 0,
            ..Default::default()
        }
        .validate()
        .is_err());
    }

    #[test]
    fn retry_backoff_grows_then_caps() {
        let r = RetryPolicy {
            max_attempts: 8,
            initial_backoff_ms: 250,
            max_backoff_ms: 4_000,
        };
        assert_eq!(r.backoff_ms(1), 0, "the first attempt never waits");
        assert_eq!(r.backoff_ms(2), 250);
        assert_eq!(r.backoff_ms(3), 500);
        assert_eq!(r.backoff_ms(4), 1_000);
        assert_eq!(r.backoff_ms(5), 2_000);
        assert_eq!(r.backoff_ms(6), 4_000);
        assert_eq!(r.backoff_ms(7), 4_000, "capped, not doubling forever");
        assert_eq!(
            r.backoff_ms(u32::MAX),
            4_000,
            "no overflow at absurd attempt counts"
        );
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

    /// Strip the tag+len framing and decode one segment message body.
    fn decode_seg(msg: &[u8]) -> (MediaHeader, Vec<u8>) {
        assert_eq!(parse_channel_tag(msg[0]).unwrap(), Channel::Media);
        let len = parse_frame_len(msg[1..5].try_into().unwrap(), MAX_MEDIA_MSG).unwrap();
        assert_eq!(len, msg.len() - FRAME_HEADER_LEN);
        let (header, payload) = decode_media_segment(&msg[FRAME_HEADER_LEN..]).unwrap();
        (header, payload.to_vec())
    }

    /// Encode a frame, then reassemble it through a fresh reassembler.
    fn roundtrip(frame: &EncodedFrame) -> EncodedFrame {
        let segs = encode_media_segments(frame).expect("encode segments");
        let mut r = MediaReassembler::new();
        let mut out = None;
        for msg in &segs {
            let (header, payload) = decode_seg(msg);
            if let Some(f) = r.push(header, &payload).expect("push segment") {
                out = Some(f);
            }
        }
        out.expect("frame completed")
    }

    #[test]
    fn media_roundtrip_preserves_frame_identity() {
        // A frame large enough to need several segments (~5000 / 65536 would be
        // one, so force many by exceeding SEGMENT_MAX).
        let original = EncodedFrame {
            frame_id: 4_294_967_290,
            keyframe: true,
            timestamp_ms: 987_654,
            data: (0..(SEGMENT_MAX * 3 + 17) as u32)
                .map(|i| (i % 251) as u8)
                .collect(),
        };
        let segs = encode_media_segments(&original).unwrap();
        assert_eq!(segs.len(), 4, "3 full segments plus a remainder");
        // Every segment is a well-formed, in-cap Media message no larger than
        // one segment plus its header.
        for (i, msg) in segs.iter().enumerate() {
            let (header, payload) = decode_seg(msg);
            assert_eq!(header.frame_id, original.frame_id);
            assert_eq!(header.segment_index as usize, i);
            assert_eq!(header.segment_count, 4);
            assert_eq!(header.last, i == 3);
            assert!(payload.len() <= SEGMENT_MAX);
        }
        let back = roundtrip(&original);
        assert_eq!(back.frame_id, original.frame_id);
        assert!(back.keyframe);
        assert_eq!(back.timestamp_ms, original.timestamp_ms);
        assert_eq!(back.data, original.data);

        // A frame that fits in one segment stays a single message and completes
        // on its opening segment.
        let small = frame(7, 1000);
        let one = encode_media_segments(&small).unwrap();
        assert_eq!(one.len(), 1);
        let back = roundtrip(&small);
        assert_eq!(back.data, small.data);
    }

    #[test]
    fn media_encoder_rejects_empty_and_oversized_frames() {
        let empty = EncodedFrame {
            frame_id: 1,
            keyframe: false,
            timestamp_ms: 0,
            data: vec![],
        };
        assert!(encode_media_segments(&empty).is_err());
        let huge = EncodedFrame {
            frame_id: 1,
            keyframe: false,
            timestamp_ms: 0,
            data: vec![0u8; MAX_FRAME_BYTES + 1],
        };
        assert!(matches!(
            encode_media_segments(&huge),
            Err(Error::Oversized { .. })
        ));
        // A body with a header but no payload is not a segment.
        let header = postcard::to_stdvec(&MediaHeader {
            frame_id: 1,
            keyframe: false,
            timestamp_ms: 0,
            segment_index: 0,
            segment_count: 1,
            last: true,
        })
        .unwrap();
        assert!(decode_media_segment(&header).is_err());
        // A header whose last-flag disagrees with its counts is refused.
        let bad = postcard::to_stdvec(&MediaHeader {
            frame_id: 1,
            keyframe: false,
            timestamp_ms: 0,
            segment_index: 0,
            segment_count: 3,
            last: true,
        })
        .unwrap();
        let mut body = bad;
        body.push(0x11); // one payload byte, so only the last-flag is wrong
        assert!(decode_media_segment(&body).is_err());
    }

    #[test]
    fn reassembler_handles_gaps_drops_and_corruption() {
        // Helper: the segment messages for a frame, pre-decoded.
        fn segs(id: u32, keyframe: bool, ts: u32, len: usize) -> Vec<(MediaHeader, Vec<u8>)> {
            let f = EncodedFrame {
                frame_id: id,
                keyframe,
                timestamp_ms: ts,
                data: (0..len as u32).map(|i| (i % 251) as u8).collect(),
            };
            encode_media_segments(&f)
                .unwrap()
                .iter()
                .map(|m| decode_seg(m))
                .collect()
        }

        // A gap in frame ids (sender dropped whole frames) raises the IDR demand.
        let mut r = MediaReassembler::new();
        let a = segs(10, true, 10, SEGMENT_MAX * 2);
        assert!(r.push(a[0].0, &a[0].1).unwrap().is_none());
        assert!(r.push(a[1].0, &a[1].1).unwrap().is_some());
        assert!(!r.take_idr(), "a clean first frame demands nothing");
        let b = segs(13, false, 13, 32); // id jumped 10 -> 13
        assert!(r.push(b[0].0, &b[0].1).unwrap().is_some());
        assert!(r.take_idr(), "a frame-id gap must demand a keyframe");
        assert_eq!(
            r.take_drops(),
            0,
            "a gap with nothing half-built drops nothing"
        );

        // A newer frame starting mid-way drops the abandoned partial.
        let mut r = MediaReassembler::new();
        let c = segs(1, true, 1, SEGMENT_MAX * 3);
        assert!(r.push(c[0].0, &c[0].1).unwrap().is_none());
        assert!(r.push(c[1].0, &c[1].1).unwrap().is_none());
        let d = segs(2, false, 2, 64);
        assert!(
            r.push(d[0].0, &d[0].1).unwrap().is_some(),
            "single-seg frame 2 completes"
        );
        assert_eq!(r.take_drops(), 1, "the half-built frame 1 was dropped");
        assert!(r.take_idr());

        // Out-of-order and contradictory segments are refused; the frame in
        // progress is abandoned but the connection survives.
        let mut r = MediaReassembler::new();
        let e = segs(5, false, 5, SEGMENT_MAX * 2);
        assert!(r.push(e[0].0, &e[0].1).unwrap().is_none());
        let mut wrong_ts = e[1].0;
        wrong_ts.timestamp_ms = 999;
        assert!(
            r.push(wrong_ts, &e[1].1).is_err(),
            "contradictory timestamp is rejected"
        );
        assert_eq!(r.take_drops(), 1);
        assert!(r.take_idr());

        // Per-frame byte cap: a segment that would push the frame over
        // MAX_FRAME_BYTES is refused (forged 2-segment frame, each near cap).
        let mut r = MediaReassembler::new();
        let big = MAX_FRAME_BYTES - 8;
        let h0 = MediaHeader {
            frame_id: 9,
            keyframe: true,
            timestamp_ms: 9,
            segment_index: 0,
            segment_count: 2,
            last: false,
        };
        assert!(r.push(h0, &vec![0u8; big]).unwrap().is_none());
        let h1 = MediaHeader {
            segment_index: 1,
            last: true,
            ..h0
        };
        let err = r.push(h1, &[0u8; 64]).unwrap_err();
        assert!(
            matches!(err, Error::Oversized { .. }),
            "byte cap must trip: {err:?}"
        );
        assert_eq!(r.take_drops(), 1);
        assert!(r.take_idr());
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
        assert_eq!(
            waiter.await.unwrap(),
            None,
            "a closed, drained queue ends the writer"
        );
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

        assert_eq!(
            client.alpn().as_deref(),
            Some(ALPN),
            "ALPN must match the QUIC path"
        );
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
            connect(
                addr,
                ServerPinning::Pinned(*impostor.spki_sha256()),
                &TcpParams::default(),
            ),
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
            .write_framed(
                Channel::Control,
                &AuthMsg::PairStart {
                    spake_msg: vec![0xAB; 33],
                },
            )
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

        let cfg = SessionConfig {
            heartbeat_ms: 100,
            stats_interval_ms: 100,
            ..Default::default()
        };
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
        client_session
            .send_input(InputMsg::ReleaseAll)
            .expect("send input");

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
        host_session
            .send_video(frame(42, 300_000))
            .expect("send video");
        let got = tokio::time::timeout(Duration::from_secs(10), client_rx.video.recv())
            .await
            .expect("video timeout")
            .expect("video closed");
        assert_eq!(got.frame_id, 42);
        assert!(
            !got.keyframe,
            "metadata must survive the trip, not be invented"
        );
        assert_eq!(got.timestamp_ms, 42 * 16);
        assert_eq!(got.data.len(), 300_000);
        assert!(got
            .data
            .iter()
            .enumerate()
            .all(|(i, b)| *b == (i as u32 % 251) as u8));

        // The heartbeat should have produced a real RTT measurement.
        tokio::time::sleep(Duration::from_millis(500)).await;
        let stats = client_session.stats();
        assert!(crate::stats::validate_stats(&stats), "{stats:?}");
        assert!(!client_session.is_closed());

        let (tx, rx) = client_session.byte_counts();
        assert!(tx > 0 && rx > 0, "tx {tx} rx {rx}");
    }

    /// The point of the module: a video backlog must never delay input, and with
    /// segmentation input overtakes even the *segments* of a frame already on the
    /// wire.
    ///
    /// The host end deliberately never reads, so the client's writer is wedged
    /// inside `write_all` part-way through frame 0's segments with the socket
    /// buffers full — the worst case this transport has. The backlog and then the
    /// input event are queued behind that wedge. Because the writer consults the
    /// control/input queues before every segment, the input is written the moment
    /// the wedged segment drains — ahead of frame 0's *remaining* segments and of
    /// the entire backlog.
    ///
    /// What must come out first: some segments of frame 0 (only the ones already
    /// committed to the socket buffer), then the input event, then the rest.
    #[tokio::test]
    async fn input_beats_the_queued_video_backlog() {
        const FRAMES: u32 = 24;
        const FRAME_BYTES: usize = 512 * 1024; // 8 segments per frame.

        let id = HostIdentity::generate("prio-host").unwrap();
        let (mut host, client) = pair(&id, TcpParams::default()).await;

        // No heartbeat and no stats: the only control traffic should be ours.
        let cfg = SessionConfig {
            heartbeat_ms: 0,
            stats_interval_ms: 0,
            ..Default::default()
        };
        let (session, mut rx) =
            TcpSession::start(client, TcpParams::default(), cfg).expect("client session");

        // Phase 1: wedge the writer. Half a megabyte cannot fit in loopback
        // socket buffers, so the writer blocks part-way through frame 0's
        // segments and stays there until the host reads — which it will not, yet.
        session
            .send_video(frame(0, FRAME_BYTES))
            .expect("queue video");
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Phase 2: pile up a backlog and then an input event behind the wedge.
        for n in 1..FRAMES {
            session
                .send_video(frame(n, FRAME_BYTES))
                .expect("queue video");
        }
        session
            .send_input(InputMsg::ReleaseAll)
            .expect("queue input");

        let dropped = session.frames_dropped_local();
        assert!(
            dropped >= u64::from(FRAMES) - DEFAULT_VIDEO_QUEUE_DEPTH as u64 - 2,
            "expected almost every frame to be dropped, got {dropped} of {FRAMES}"
        );
        assert!(
            session.idr_signals() >= 1,
            "dropping frames must ask the encoder for an IDR"
        );
        let mut saw_keyframe_event = false;
        while let Ok(ev) = rx.events.try_recv() {
            if matches!(ev, SessionEvent::KeyframeNeeded) {
                saw_keyframe_event = true;
            }
        }
        assert!(
            saw_keyframe_event,
            "the drop must surface as a KeyframeNeeded event"
        );

        // Now let the host drain, recording the order segments arrive in.
        let mut ids_before_input = Vec::new();
        let mut all_ids = Vec::new();
        let mut saw_input = false;
        for _ in 0..(FRAMES as usize * 8 + 8) {
            let (channel, body) = tokio::time::timeout(Duration::from_secs(10), host.read_any())
                .await
                .expect("read timeout")
                .expect("read failed");
            match channel {
                Channel::Media => {
                    let fid = decode_media_segment(&body)
                        .expect("decode segment")
                        .0
                        .frame_id;
                    all_ids.push(fid);
                    if !saw_input {
                        ids_before_input.push(fid);
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
        // The measured guarantee: nothing but frame 0 (the frame already on the
        // wire) may precede the input — no backlog frame, not even a later
        // segment of frame 0 beyond the one segment already committed.
        assert!(
            ids_before_input.iter().all(|id| *id == 0),
            "only the in-flight frame 0 may precede the input, got {ids_before_input:?}"
        );

        // Drain the tail so we can prove which frames survived.
        while let Ok(Ok((channel, body))) =
            tokio::time::timeout(Duration::from_millis(500), host.read_any()).await
        {
            if channel == Channel::Media {
                all_ids.push(
                    decode_media_segment(&body)
                        .expect("decode segment")
                        .0
                        .frame_id,
                );
            }
        }

        assert!(
            all_ids.iter().any(|id| *id != 0),
            "the surviving backlog must arrive after the input"
        );
        let mut distinct: Vec<u32> = all_ids.clone();
        distinct.sort_unstable();
        distinct.dedup();
        // Latest-wins: only frame 0 (already on the wire) and the two newest
        // frames survive; the rest of the backlog was dropped, not buffered.
        assert!(
            distinct.iter().all(|id| *id == 0 || *id >= FRAMES - 2),
            "only the newest frames (or the one already on the wire) may survive: {distinct:?}"
        );
        assert!(
            distinct.contains(&(FRAMES - 2)) && distinct.contains(&(FRAMES - 1)),
            "the two newest frames must survive, got {distinct:?}"
        );
    }

    /// Input must overtake a frame that is *mid-transmission*, not merely a queue
    /// of whole frames. One 2 MiB frame is 32 segments; an input queued while it
    /// is being written must ride out ahead of the bulk of those segments, its
    /// delay bounded by the few already committed to the socket buffer — one
    /// segment of writer latency — rather than the whole frame.
    #[tokio::test]
    async fn input_interleaves_within_a_multi_segment_frame() {
        const FRAME_BYTES: usize = 2 * 1024 * 1024;
        let segment_count = FRAME_BYTES.div_ceil(SEGMENT_MAX);
        assert_eq!(segment_count, 32, "2 MiB at 64 KiB is 32 segments");

        let id = HostIdentity::generate("mid-frame-host").unwrap();
        let (mut host, client) = pair(&id, TcpParams::default()).await;

        let cfg = SessionConfig {
            heartbeat_ms: 0,
            stats_interval_ms: 0,
            ..Default::default()
        };
        let (session, _rx) =
            TcpSession::start(client, TcpParams::default(), cfg).expect("client session");

        // Queue the big frame. With the host not reading, the writer soon blocks
        // mid-frame with the socket buffers full — only a handful of segments
        // have been handed to the OS.
        session
            .send_video(frame(1, FRAME_BYTES))
            .expect("queue video");
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Queue an input behind the wedge. The writer checks the input queue
        // between segments, so this cannot wait for the whole frame.
        session
            .send_input(InputMsg::ReleaseAll)
            .expect("queue input");

        let mut before = 0usize;
        let mut after = 0usize;
        let mut total_media = 0usize;
        let mut saw_input = false;
        loop {
            let read = tokio::time::timeout(Duration::from_secs(10), host.read_any()).await;
            let (channel, body) = match read {
                Ok(Ok(v)) => v,
                _ => break,
            };
            match channel {
                Channel::Media => {
                    let h = decode_media_segment(&body).expect("decode segment").0;
                    assert_eq!(h.frame_id, 1);
                    assert_eq!(h.segment_count as usize, segment_count);
                    total_media += 1;
                    if saw_input {
                        after += 1;
                    } else {
                        before += 1;
                    }
                }
                Channel::Input => saw_input = true,
                Channel::Control => panic!("no control traffic was sent"),
            }
            if saw_input && total_media >= segment_count {
                break;
            }
        }

        assert!(saw_input, "the input event never arrived");
        assert_eq!(
            total_media, segment_count,
            "the whole frame must still be delivered, in {segment_count} segments"
        );
        // MEASURED evidence that input's delay is ~one segment, not one frame:
        // the input landed with the great majority of the frame's segments still
        // behind it. `before` is only the segments already committed to the
        // socket buffer when the input was queued (a handful of ~64 KiB
        // segments), never all 32.
        assert!(
            before < after,
            "input must beat most of the frame's segments (before={before}, after={after})"
        );
        assert!(
            after >= segment_count / 2,
            "the majority of the frame must arrive after the input (before={before}, after={after})"
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

        host_session
            .close_graceful("host is going away", Duration::from_secs(2))
            .await;

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
        assert!(
            saw_bye,
            "expected a structured ControlMsg::Bye from the peer"
        );
        assert!(
            client_session.is_closed(),
            "receiving Bye must close the session"
        );
        assert!(host_session.is_closed());
    }

    /// A hostile length prefix must be refused before anything is allocated,
    /// and must kill the session rather than the process.
    #[tokio::test]
    async fn an_oversized_length_prefix_is_refused() {
        let id = HostIdentity::generate("cap-host").unwrap();
        let (host, mut client) = pair(&id, TcpParams::default()).await;

        let cfg = SessionConfig {
            heartbeat_ms: 0,
            stats_interval_ms: 0,
            ..Default::default()
        };
        let (host_session, mut host_rx) =
            TcpSession::start(host, TcpParams::default(), cfg).expect("host session");

        // Claim a 3 GiB media body. `parse_frame_len` must reject it on sight.
        let mut hostile = vec![channel_tag(Channel::Media).unwrap()];
        hostile.extend_from_slice(&(3_000_000_000u32).to_le_bytes());
        client
            .stream
            .write_all(&hostile)
            .await
            .expect("write hostile prefix");
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
        let retry = RetryPolicy {
            max_attempts: 3,
            initial_backoff_ms: 1,
            max_backoff_ms: 4,
        };
        let params = TcpParams {
            connect_timeout_ms: 500,
            ..Default::default()
        };
        let err = connect_with_retry(
            dead,
            ServerPinning::Pinned(*id.spki_sha256()),
            &params,
            retry,
        )
        .await
        .expect_err("nothing is listening");
        let text = err.to_string();
        assert!(text.contains("after 3 attempts"), "{text}");

        let none = RetryPolicy {
            max_attempts: 0,
            ..Default::default()
        };
        assert!(connect_with_retry(
            dead,
            ServerPinning::Pinned(*id.spki_sha256()),
            &params,
            none
        )
        .await
        .is_err());
    }
}
