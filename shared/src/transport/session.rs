//! The session driver: a live connection turned into typed channels.
//!
//! # What this owns
//!
//! [`QuicSession::start`] takes an established [`quinn::Connection`] plus its
//! two reliable streams and spawns the tasks that actually move bytes:
//!
//! | Task | Direction | Job |
//! |------|-----------|-----|
//! | control writer | out | drains the control queue onto the control stream |
//! | control reader | in | decodes control messages, answers `Ping`, matches `Pong` |
//! | input writer / reader | both | same, for [`InputMsg`] |
//! | video sender | out | fragments [`EncodedFrame`]s into datagrams |
//! | video receiver | in | reassembles datagrams, requests keyframes on loss |
//! | heartbeat | out | periodic `Ping` for liveness and RTT |
//! | stats sampler | — | turns `Connection::stats()` into [`ConnStats`] |
//!
//! Everything above the transport talks to [`SessionReceivers`] and the
//! [`Session`] trait and never touches quinn.
//!
//! # Why a trait
//!
//! The TCP/TLS fallback in a later milestone has to present the same interface,
//! so the useful surface is deliberately transport-agnostic: three typed send
//! methods, four typed receivers, a stats snapshot, and a close. Nothing in
//! [`Session`] mentions QUIC, and nothing in it is `async` — which keeps it
//! object-safe, so callers can hold a `Box<dyn Session>` and swap transports at
//! runtime.
//!
//! # Backpressure policy, stated plainly
//!
//! - Control and input are **reliable**: a full queue is an error the caller
//!   sees, never a silent drop. Losing a key-up event leaves a key stuck down.
//! - Video is **droppable**: a full queue drops the frame and counts it. A
//!   video frame that arrives late is worth less than nothing, because it
//!   delays the one behind it.
//!
//! # Time
//!
//! This module is the one place in the transport layer that reads a real clock,
//! because it is the thing that owns real timers. It uses [`Instant`] only —
//! never the wall clock — so a system time change cannot stall a session. The
//! reassembler underneath it still takes an injected `now_ms`, measured from
//! session start, which is what keeps its own tests deterministic.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use quinn::{Connection, RecvStream, SendStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::error::{Error, Result};
use crate::protocol::{ControlMsg, InputMsg};
use crate::stats::{ConnStats, TransportRoute};
use crate::transport::quic::{self, SessionStreams};
use crate::transport::reassembly::{Reassembler, ReassemblyConfig};
use crate::video::EncodedFrame;

/// Something the driver noticed that is not itself a protocol message.
#[derive(Debug, Clone)]
pub enum SessionEvent {
    /// A fresh statistics sample.
    Stats(ConnStats),
    /// The receiver lost fragments and needs an IDR. The driver has already
    /// asked the peer; this is for the local UI and for the encoder if the
    /// local side happens to be the sender.
    KeyframeNeeded,
    /// The peer sent `Bye`.
    PeerClosed { reason: String },
    /// A non-fatal error on one of the channels.
    Warning { detail: String },
    /// The session is finished; no further events will arrive.
    Closed { reason: String },
}

/// Driver tunables.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Heartbeat interval in milliseconds. `0` disables heartbeats.
    pub heartbeat_ms: u64,
    /// Statistics sampling interval in milliseconds. `0` disables sampling.
    pub stats_interval_ms: u64,
    /// Queue depth for outbound and inbound control messages.
    pub control_capacity: usize,
    /// Queue depth for input messages.
    pub input_capacity: usize,
    /// Queue depth for video frames in each direction.
    pub video_capacity: usize,
    /// Reassembly policy for inbound video.
    pub reassembly: ReassemblyConfig,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            heartbeat_ms: 2_000,
            stats_interval_ms: 1_000,
            control_capacity: 64,
            input_capacity: 256,
            // Small on purpose: a deep video queue is just latency in disguise.
            video_capacity: 8,
            reassembly: ReassemblyConfig::default(),
        }
    }
}

impl SessionConfig {
    /// Reject configurations that would deadlock or spin.
    pub fn validate(&self) -> Result<()> {
        if self.control_capacity == 0 || self.input_capacity == 0 || self.video_capacity == 0 {
            return Err(Error::Invalid("session queue capacities must be non-zero".into()));
        }
        Ok(())
    }
}

/// The receive halves handed to the application, once, at session start.
pub struct SessionReceivers {
    /// Inbound control messages. `Ping`/`Pong` are consumed by the driver and
    /// never appear here.
    pub control: mpsc::Receiver<ControlMsg>,
    /// Inbound input messages.
    pub input: mpsc::Receiver<InputMsg>,
    /// Inbound reassembled video frames.
    pub video: mpsc::Receiver<EncodedFrame>,
    /// Driver events.
    pub events: mpsc::Receiver<SessionEvent>,
}

impl std::fmt::Debug for SessionReceivers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionReceivers { .. }")
    }
}

/// A running session, independent of transport.
///
/// Implemented by [`QuicSession`] now and by the TCP fallback later.
pub trait Session: Send + Sync {
    /// The route this session believes it is using. Never optimistic: a
    /// relayed session must report [`TransportRoute::Relayed`].
    fn route(&self) -> TransportRoute;
    /// The most recent statistics sample.
    fn stats(&self) -> ConnStats;
    /// Queue a control message. Fails rather than dropping.
    fn send_control(&self, msg: ControlMsg) -> Result<()>;
    /// Queue an input message. Fails rather than dropping.
    fn send_input(&self, msg: InputMsg) -> Result<()>;
    /// Queue a video frame. Drops when the queue is full (see module docs).
    fn send_video(&self, frame: EncodedFrame) -> Result<()>;
    /// Close gracefully with a reason the peer will see.
    fn close(&self, reason: &str);
    /// Whether the session has been closed locally or by the peer.
    fn is_closed(&self) -> bool;
}

/// Counters the driver keeps that are not part of [`ConnStats`].
#[derive(Debug, Default)]
struct Counters {
    video_frames_dropped_local: AtomicU64,
    keyframes_requested: AtomicU64,
}

struct Shared {
    conn: Connection,
    route: TransportRoute,
    started: Instant,
    closed: AtomicBool,
    stats: Mutex<ConnStats>,
    /// Token and send time of the outstanding heartbeat, if any.
    pending_ping: Mutex<Option<(u64, Instant)>>,
    counters: Counters,
    control_out: mpsc::Sender<ControlMsg>,
    input_out: mpsc::Sender<InputMsg>,
    video_out: mpsc::Sender<EncodedFrame>,
    events: mpsc::Sender<SessionEvent>,
}

impl Shared {
    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    fn emit(&self, ev: SessionEvent) {
        // Events are advisory. If nobody is draining them, dropping is correct.
        let _ = self.events.try_send(ev);
    }

    fn mark_closed(&self, reason: &str) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            self.emit(SessionEvent::Closed { reason: reason.to_string() });
        }
    }
}

/// A session driven over QUIC.
pub struct QuicSession {
    shared: Arc<Shared>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl std::fmt::Debug for QuicSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicSession")
            .field("route", &self.shared.route)
            .field("closed", &self.shared.closed.load(Ordering::Relaxed))
            .finish()
    }
}

impl QuicSession {
    /// Spawn the driver tasks for an established connection.
    ///
    /// Must be called from inside a tokio runtime.
    pub fn start(
        conn: Connection,
        streams: SessionStreams,
        route: TransportRoute,
        config: SessionConfig,
    ) -> Result<(Self, SessionReceivers)> {
        config.validate()?;

        let (control_out_tx, control_out_rx) = mpsc::channel(config.control_capacity);
        let (control_in_tx, control_in_rx) = mpsc::channel(config.control_capacity);
        let (input_out_tx, input_out_rx) = mpsc::channel(config.input_capacity);
        let (input_in_tx, input_in_rx) = mpsc::channel(config.input_capacity);
        let (video_out_tx, video_out_rx) = mpsc::channel(config.video_capacity);
        let (video_in_tx, video_in_rx) = mpsc::channel(config.video_capacity);
        let (events_tx, events_rx) = mpsc::channel(config.control_capacity);

        let shared = Arc::new(Shared {
            conn: conn.clone(),
            route,
            started: Instant::now(),
            closed: AtomicBool::new(false),
            stats: Mutex::new(ConnStats::default()),
            pending_ping: Mutex::new(None),
            counters: Counters::default(),
            control_out: control_out_tx,
            input_out: input_out_tx,
            video_out: video_out_tx,
            events: events_tx,
        });

        let (control_send, control_recv) = streams.control;
        let (input_send, input_recv) = streams.input;

        let mut tasks = Vec::with_capacity(8);
        tasks.push(tokio::spawn(write_loop(
            shared.clone(),
            control_send,
            control_out_rx,
            "control",
        )));
        tasks.push(tokio::spawn(control_read_loop(
            shared.clone(),
            control_recv,
            control_in_tx,
        )));
        tasks.push(tokio::spawn(write_loop(shared.clone(), input_send, input_out_rx, "input")));
        tasks.push(tokio::spawn(input_read_loop(shared.clone(), input_recv, input_in_tx)));
        tasks.push(tokio::spawn(video_send_loop(shared.clone(), video_out_rx)));
        tasks.push(tokio::spawn(video_recv_loop(
            shared.clone(),
            video_in_tx,
            config.reassembly,
        )));
        if config.heartbeat_ms > 0 {
            tasks.push(tokio::spawn(heartbeat_loop(shared.clone(), config.heartbeat_ms)));
        }
        if config.stats_interval_ms > 0 {
            tasks.push(tokio::spawn(stats_loop(shared.clone(), config.stats_interval_ms)));
        }
        tasks.push(tokio::spawn(closed_watch(shared.clone())));

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

    /// Number of keyframe requests this side has sent.
    pub fn keyframes_requested(&self) -> u64 {
        self.shared.counters.keyframes_requested.load(Ordering::Relaxed)
    }

    /// The underlying connection, for callers that need `export_keying_material`
    /// or the peer address.
    pub fn connection(&self) -> &Connection {
        &self.shared.conn
    }

    /// Shut down in a way the peer actually sees.
    ///
    /// [`Session::close`] is the synchronous escape hatch: it queues a `Bye`
    /// and immediately closes the connection, which in QUIC discards any stream
    /// data still buffered. The peer learns the reason from the
    /// CONNECTION_CLOSE frame, but the structured `ControlMsg::Bye` usually
    /// loses the race.
    ///
    /// This version gives the `Bye` a real chance: queue it, wait (bounded) for
    /// the writer to drain, then wait (bounded) for the peer to close in
    /// response before closing locally. Use it whenever there is an async
    /// context available — which is every normal shutdown path.
    pub async fn close_graceful(&self, reason: &str, grace: Duration) {
        let _ = self.shared.control_out.try_send(ControlMsg::Bye { reason: reason.to_string() });

        let deadline = Instant::now() + grace;
        // Phase 1: let the writer task drain the queue onto the stream.
        while self.shared.control_out.capacity() < self.shared.control_out.max_capacity()
            && Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        // Phase 2: a well-behaved peer closes on receiving `Bye`. Waiting for
        // that is what makes the shutdown mutual rather than a race.
        let remaining = deadline.saturating_duration_since(Instant::now());
        if !remaining.is_zero() {
            let _ = tokio::time::timeout(remaining, self.shared.conn.closed()).await;
        }

        self.shared.mark_closed(reason);
        self.shared.conn.close(0u32.into(), reason.as_bytes());
    }
}

impl Drop for QuicSession {
    fn drop(&mut self) {
        self.shared.mark_closed("session dropped");
        for t in self.tasks.lock().drain(..) {
            t.abort();
        }
    }
}

impl Session for QuicSession {
    fn route(&self) -> TransportRoute {
        self.shared.route
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
        match self.shared.video_out.try_send(frame) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Deliberate: a queued video frame is stale latency.
                self.shared.counters.video_frames_dropped_local.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => Err(Error::Transport(format!("video queue: {e}"))),
        }
    }

    fn close(&self, reason: &str) {
        // Synchronous and immediate. The queued `Bye` will usually lose the
        // race against the connection close discarding buffered stream data —
        // the peer still learns the reason from the CONNECTION_CLOSE frame.
        // Prefer [`QuicSession::close_graceful`] when an async context exists.
        let _ = self.shared.control_out.try_send(ControlMsg::Bye { reason: reason.to_string() });
        self.shared.mark_closed(reason);
        self.shared.conn.close(0u32.into(), reason.as_bytes());
    }

    fn is_closed(&self) -> bool {
        self.shared.closed.load(Ordering::SeqCst)
    }
}

// ---------------------------------------------------------------------------
// Tasks
// ---------------------------------------------------------------------------

async fn write_loop<T: serde::Serialize + Send + 'static>(
    shared: Arc<Shared>,
    mut stream: SendStream,
    mut rx: mpsc::Receiver<T>,
    label: &'static str,
) {
    while let Some(msg) = rx.recv().await {
        if let Err(e) = quic::write_framed(&mut stream, &msg).await {
            shared.emit(SessionEvent::Warning { detail: format!("{label} write: {e}") });
            shared.mark_closed(&format!("{label} stream write failed"));
            return;
        }
    }
    let _ = stream.finish();
}

async fn control_read_loop(
    shared: Arc<Shared>,
    mut stream: RecvStream,
    tx: mpsc::Sender<ControlMsg>,
) {
    loop {
        let msg: ControlMsg = match quic::read_control(&mut stream).await {
            Ok(m) => m,
            Err(e) => {
                shared.mark_closed(&format!("control stream closed: {e}"));
                return;
            }
        };

        match msg {
            ControlMsg::Ping { token } => {
                // Answer immediately; never surface to the application.
                if shared.control_out.try_send(ControlMsg::Pong { token }).is_err() {
                    shared.emit(SessionEvent::Warning {
                        detail: "could not answer Ping: control queue full".into(),
                    });
                }
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
            }
            ControlMsg::Bye { reason } => {
                shared.emit(SessionEvent::PeerClosed { reason: reason.clone() });
                shared.mark_closed(&format!("peer said bye: {reason}"));
                return;
            }
            ControlMsg::Stats(peer) => {
                // Peer stats are informational and attacker-influenced; drop
                // anything implausible instead of rendering garbage.
                if crate::stats::validate_stats(&peer) {
                    if tx.send(ControlMsg::Stats(peer)).await.is_err() {
                        return;
                    }
                } else {
                    shared.emit(SessionEvent::Warning {
                        detail: "discarded implausible peer stats".into(),
                    });
                }
            }
            other => {
                if tx.send(other).await.is_err() {
                    shared.mark_closed("control receiver dropped");
                    return;
                }
            }
        }
    }
}

async fn input_read_loop(
    shared: Arc<Shared>,
    mut stream: RecvStream,
    tx: mpsc::Sender<InputMsg>,
) {
    loop {
        let msg: InputMsg = match quic::read_control(&mut stream).await {
            Ok(m) => m,
            Err(e) => {
                shared.mark_closed(&format!("input stream closed: {e}"));
                return;
            }
        };
        // Validate before handing an event to something that will inject it.
        if let InputMsg::Event(ev) = &msg {
            if let Err(e) = crate::input::validate_event(ev) {
                shared.emit(SessionEvent::Warning { detail: format!("bad input event: {e}") });
                continue;
            }
        }
        if tx.send(msg).await.is_err() {
            shared.mark_closed("input receiver dropped");
            return;
        }
    }
}

async fn video_send_loop(shared: Arc<Shared>, mut rx: mpsc::Receiver<EncodedFrame>) {
    while let Some(frame) = rx.recv().await {
        let mtu = match quic::max_datagram(&shared.conn) {
            Ok(m) => m,
            Err(e) => {
                shared.emit(SessionEvent::Warning { detail: format!("no datagrams: {e}") });
                shared.mark_closed("peer does not support datagrams");
                return;
            }
        };
        let frags = match crate::video::fragment_frame(&frame, mtu) {
            Ok(f) => f,
            Err(e) => {
                shared.emit(SessionEvent::Warning { detail: format!("fragment: {e}") });
                continue;
            }
        };
        for frag in frags {
            if let Err(e) = shared.conn.send_datagram(bytes::Bytes::from(frag)) {
                shared.emit(SessionEvent::Warning { detail: format!("send datagram: {e}") });
                break;
            }
        }
    }
}

async fn video_recv_loop(
    shared: Arc<Shared>,
    tx: mpsc::Sender<EncodedFrame>,
    config: ReassemblyConfig,
) {
    let mut reassembler = Reassembler::new(config);
    loop {
        let datagram = match shared.conn.read_datagram().await {
            Ok(d) => d,
            Err(e) => {
                shared.mark_closed(&format!("datagram stream closed: {e}"));
                return;
            }
        };
        let now_ms = shared.now_ms();

        if let Err(e) = reassembler.push(&datagram, now_ms) {
            // A malformed datagram is logged and ignored. It must never kill
            // the session: anyone on the path can inject one.
            shared.emit(SessionEvent::Warning { detail: format!("bad video datagram: {e}") });
        }

        while let Some(frame) = reassembler.pop_frame() {
            if tx.try_send(frame).is_err() {
                shared.emit(SessionEvent::Warning {
                    detail: "video receive queue full; frame dropped".into(),
                });
            }
        }

        if reassembler.take_keyframe_request(now_ms) {
            shared.counters.keyframes_requested.fetch_add(1, Ordering::Relaxed);
            let _ = shared.control_out.try_send(ControlMsg::RequestKeyframe);
            shared.emit(SessionEvent::KeyframeNeeded);
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
        // A still-outstanding ping means the peer missed the last one. Replace
        // it rather than accumulating state.
        *shared.pending_ping.lock() = Some((token, Instant::now()));
        if shared.control_out.try_send(ControlMsg::Ping { token }).is_err() {
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
    let mut prev = StatsSample::from_quinn(&shared.conn.stats());
    let mut prev_at = Instant::now();

    loop {
        ticker.tick().await;
        if shared.closed.load(Ordering::SeqCst) {
            return;
        }
        let cur = StatsSample::from_quinn(&shared.conn.stats());
        let dt_ms = prev_at.elapsed().as_millis() as u64;
        prev_at = Instant::now();

        let snapshot = {
            let mut stats = shared.stats.lock();
            let sampled = delta_stats(&prev, &cur, dt_ms, stats.jitter_ms);
            // The heartbeat measures RTT more directly than quinn's estimate
            // once a Pong has landed, so keep whichever we have.
            let rtt_ms = if stats.rtt_ms > 0.0 { stats.rtt_ms } else { sampled.rtt_ms };
            stats.rtt_ms = rtt_ms;
            stats.jitter_ms = sampled.jitter_ms;
            stats.loss = sampled.loss;
            stats.bandwidth_kbps = sampled.bandwidth_kbps;
            stats.keyframes_requested =
                shared.counters.keyframes_requested.load(Ordering::Relaxed) as u32;
            stats.frames_dropped =
                shared.counters.video_frames_dropped_local.load(Ordering::Relaxed) as u32;
            *stats
        };
        prev = cur;
        shared.emit(SessionEvent::Stats(snapshot));
    }
}

async fn closed_watch(shared: Arc<Shared>) {
    let reason = shared.conn.closed().await;
    shared.mark_closed(&format!("connection closed: {reason}"));
}

// ---------------------------------------------------------------------------
// Stats mapping (pure, so it can be tested without a connection)
// ---------------------------------------------------------------------------

/// The handful of numbers we pull out of `quinn::ConnectionStats`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StatsSample {
    /// Smoothed RTT in microseconds.
    pub rtt_us: u64,
    /// Cumulative packets sent on the current path.
    pub sent_packets: u64,
    /// Cumulative packets declared lost on the current path.
    pub lost_packets: u64,
    /// Cumulative UDP bytes received.
    pub rx_bytes: u64,
    /// Cumulative UDP bytes sent.
    pub tx_bytes: u64,
}

impl StatsSample {
    /// Extract a sample from quinn's cumulative counters.
    pub fn from_quinn(s: &quinn::ConnectionStats) -> Self {
        Self {
            rtt_us: s.path.rtt.as_micros() as u64,
            sent_packets: s.path.sent_packets,
            lost_packets: s.path.lost_packets,
            rx_bytes: s.udp_rx.bytes,
            tx_bytes: s.udp_tx.bytes,
        }
    }
}

/// Smoothing factor for the jitter estimate (RFC 3550 uses 1/16).
const JITTER_ALPHA: f32 = 1.0 / 16.0;

/// Update the jitter estimate from consecutive RTT samples.
pub fn ewma_jitter(prev_jitter_ms: f32, prev_rtt_ms: f32, rtt_ms: f32) -> f32 {
    if prev_rtt_ms <= 0.0 {
        return 0.0;
    }
    let delta = (rtt_ms - prev_rtt_ms).abs();
    prev_jitter_ms + JITTER_ALPHA * (delta - prev_jitter_ms)
}

/// Turn two cumulative samples into a windowed [`ConnStats`].
///
/// Only the fields the transport can actually observe are filled; the capture,
/// encode, decode and present rates belong to the media pipeline and are left
/// at zero here.
pub fn delta_stats(
    prev: &StatsSample,
    cur: &StatsSample,
    dt_ms: u64,
    prev_jitter_ms: f32,
) -> ConnStats {
    let rtt_ms = cur.rtt_us as f32 / 1000.0;
    let prev_rtt_ms = prev.rtt_us as f32 / 1000.0;

    let sent = cur.sent_packets.saturating_sub(prev.sent_packets);
    let lost = cur.lost_packets.saturating_sub(prev.lost_packets);
    let loss = if sent == 0 { 0.0 } else { (lost as f32 / sent as f32).clamp(0.0, 1.0) };

    let bytes = cur
        .rx_bytes
        .saturating_sub(prev.rx_bytes)
        .saturating_add(cur.tx_bytes.saturating_sub(prev.tx_bytes));
    let bandwidth_kbps = if dt_ms == 0 {
        0
    } else {
        // bytes/ms * 8 = kbit/s
        ((bytes as f64 * 8.0) / dt_ms as f64).min(u32::MAX as f64) as u32
    };

    ConnStats {
        rtt_ms,
        jitter_ms: ewma_jitter(prev_jitter_ms, prev_rtt_ms, rtt_ms),
        loss,
        bandwidth_kbps,
        ..ConnStats::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::HostIdentity;
    use crate::crypto::tls::ServerPinning;
    use crate::transport::quic::QuicParams;
    use crate::video::EncodedFrame;

    #[test]
    fn config_validation() {
        assert!(SessionConfig::default().validate().is_ok());
        let bad = SessionConfig { video_capacity: 0, ..SessionConfig::default() };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn jitter_starts_at_zero_and_converges() {
        assert_eq!(ewma_jitter(0.0, 0.0, 50.0), 0.0, "no previous RTT means no jitter yet");
        let j1 = ewma_jitter(0.0, 20.0, 30.0);
        assert!(j1 > 0.0 && j1 < 10.0);
        // A steady RTT decays the estimate back toward zero.
        let mut j = 5.0;
        for _ in 0..200 {
            j = ewma_jitter(j, 20.0, 20.0);
        }
        assert!(j < 0.01, "jitter should decay to ~0, got {j}");
    }

    #[test]
    fn delta_stats_computes_loss_and_bandwidth() {
        let prev = StatsSample {
            rtt_us: 20_000,
            sent_packets: 1_000,
            lost_packets: 10,
            rx_bytes: 0,
            tx_bytes: 0,
        };
        let cur = StatsSample {
            rtt_us: 25_000,
            sent_packets: 1_100,
            lost_packets: 15,
            rx_bytes: 125_000,
            tx_bytes: 0,
        };
        let s = delta_stats(&prev, &cur, 1_000, 0.0);
        assert!((s.rtt_ms - 25.0).abs() < 0.001);
        assert!((s.loss - 0.05).abs() < 1e-6, "5 lost of 100 sent");
        assert_eq!(s.bandwidth_kbps, 1_000, "125 kB in 1 s is 1000 kbit/s");
        assert!(crate::stats::validate_stats(&s));
    }

    #[test]
    fn delta_stats_handles_zero_and_reset_counters() {
        let z = StatsSample::default();
        let s = delta_stats(&z, &z, 0, 0.0);
        assert_eq!(s.loss, 0.0);
        assert_eq!(s.bandwidth_kbps, 0);
        assert!(crate::stats::validate_stats(&s));

        // Counters going backwards (should not happen, but must not panic or
        // produce NaN) are absorbed by the saturating arithmetic.
        let high = StatsSample { sent_packets: 10, lost_packets: 5, ..Default::default() };
        let low = StatsSample::default();
        let s = delta_stats(&high, &low, 100, 0.0);
        assert!(crate::stats::validate_stats(&s));
    }

    #[test]
    fn loss_is_clamped_to_unit_range() {
        let prev = StatsSample { sent_packets: 100, lost_packets: 0, ..Default::default() };
        let cur = StatsSample { sent_packets: 110, lost_packets: 500, ..Default::default() };
        let s = delta_stats(&prev, &cur, 1000, 0.0);
        assert!((0.0..=1.0).contains(&s.loss));
        assert!(crate::stats::validate_stats(&s));
    }

    /// End-to-end over loopback QUIC: control round trip, heartbeat RTT, input,
    /// and a fragmented video frame reassembled on the far side.
    #[tokio::test]
    async fn loopback_session_moves_all_three_channels() {
        let id = HostIdentity::generate("session-host").unwrap();
        let params = QuicParams::default();
        let server = quic::server_endpoint("127.0.0.1:0".parse().unwrap(), id.tls(), &params)
            .unwrap();
        let server_addr = server.local_addr().unwrap();

        let host_task = tokio::spawn(async move {
            let conn = server.accept().await.expect("incoming").await.expect("handshake");
            let streams = quic::accept_streams(&conn).await.expect("accept streams");
            let (session, mut rx) = QuicSession::start(
                conn,
                streams,
                TransportRoute::DirectUdp,
                SessionConfig { heartbeat_ms: 100, stats_interval_ms: 100, ..Default::default() },
            )
            .expect("host session");

            // Wait for the client's StartStream, then answer with video.
            let msg = tokio::time::timeout(Duration::from_secs(10), rx.control.recv())
                .await
                .expect("control timeout")
                .expect("control closed");
            assert!(matches!(msg, ControlMsg::StartStream { .. }));

            let input = tokio::time::timeout(Duration::from_secs(10), rx.input.recv())
                .await
                .expect("input timeout")
                .expect("input closed");
            assert!(matches!(input, InputMsg::ReleaseAll));

            // A frame large enough to require several datagrams.
            session
                .send_video(EncodedFrame {
                    frame_id: 42,
                    keyframe: true,
                    timestamp_ms: 1234,
                    data: (0..8000u32).map(|i| (i % 251) as u8).collect(),
                })
                .expect("send video");

            // Keep the session alive while the client drains.
            tokio::time::sleep(Duration::from_secs(3)).await;
            session.stats()
        });

        let client_ep = quic::client_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            ServerPinning::Pinned(*id.spki_sha256()),
            &params,
        )
        .unwrap();
        let conn = quic::connect(&client_ep, server_addr).await.expect("connect");
        let streams = quic::open_streams(&conn).await.expect("open streams");
        let (session, mut rx) = QuicSession::start(
            conn,
            streams,
            TransportRoute::DirectUdp,
            SessionConfig { heartbeat_ms: 100, stats_interval_ms: 100, ..Default::default() },
        )
        .expect("client session");

        session
            .send_control(ControlMsg::StartStream {
                max_width: 1920,
                max_height: 1080,
                preferred_fps: 60,
                quality_mode: crate::protocol::QualityMode::Balanced,
            })
            .expect("send control");
        session.send_input(InputMsg::ReleaseAll).expect("send input");

        let frame = tokio::time::timeout(Duration::from_secs(10), rx.video.recv())
            .await
            .expect("video timeout")
            .expect("video closed");
        assert_eq!(frame.frame_id, 42);
        assert!(frame.keyframe);
        assert_eq!(frame.timestamp_ms, 1234);
        assert_eq!(frame.data.len(), 8000);
        assert!(frame.data.iter().enumerate().all(|(i, b)| *b == (i as u32 % 251) as u8));

        // The heartbeat should have produced a real RTT measurement by now.
        tokio::time::sleep(Duration::from_millis(600)).await;
        let stats = session.stats();
        assert!(stats.rtt_ms >= 0.0 && stats.rtt_ms < 5_000.0, "rtt {}", stats.rtt_ms);
        assert!(crate::stats::validate_stats(&stats));
        assert!(!session.is_closed());

        let host_stats =
            tokio::time::timeout(Duration::from_secs(15), host_task).await.unwrap().unwrap();
        assert!(crate::stats::validate_stats(&host_stats));

        session.close("test done");
        assert!(session.is_closed());
        client_ep.wait_idle().await;
    }

    /// A `Bye` from the peer must close the session and surface the reason.
    #[tokio::test]
    async fn peer_bye_closes_the_session() {
        let id = HostIdentity::generate("bye-host").unwrap();
        let params = QuicParams::default();
        let server = quic::server_endpoint("127.0.0.1:0".parse().unwrap(), id.tls(), &params)
            .unwrap();
        let server_addr = server.local_addr().unwrap();

        let host_task = tokio::spawn(async move {
            let conn = server.accept().await.expect("incoming").await.expect("handshake");
            let streams = quic::accept_streams(&conn).await.expect("accept streams");
            let (session, _rx) = QuicSession::start(
                conn,
                streams,
                TransportRoute::DirectUdp,
                SessionConfig::default(),
            )
            .expect("host session");
            tokio::time::sleep(Duration::from_millis(200)).await;
            session.close_graceful("host is going away", Duration::from_secs(5)).await;
        });

        let client_ep = quic::client_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            ServerPinning::Pinned(*id.spki_sha256()),
            &params,
        )
        .unwrap();
        let conn = quic::connect(&client_ep, server_addr).await.expect("connect");
        let streams = quic::open_streams(&conn).await.expect("open streams");
        let (session, mut rx) =
            QuicSession::start(conn, streams, TransportRoute::DirectUdp, SessionConfig::default())
                .expect("client session");

        // `close_graceful` must actually deliver the structured `Bye`, not just
        // slam the connection shut — that is the whole point of it existing.
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut saw_bye = false;
        while Instant::now() < deadline && !saw_bye {
            match tokio::time::timeout(Duration::from_millis(500), rx.events.recv()).await {
                Ok(Some(SessionEvent::PeerClosed { reason })) => {
                    assert_eq!(reason, "host is going away");
                    saw_bye = true;
                }
                Ok(Some(_)) => continue,
                Ok(None) => break,
                Err(_) => continue,
            }
        }
        assert!(saw_bye, "expected a ControlMsg::Bye from the peer");
        assert!(session.is_closed(), "receiving Bye must close the session");

        host_task.abort();
        client_ep.wait_idle().await;
    }
}
