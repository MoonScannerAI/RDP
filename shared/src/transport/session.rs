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
//! | datagram receiver | in | demuxes audio from video, reassembles video, requests keyframes on loss |
//! | heartbeat | out | periodic `Ping` for liveness and RTT |
//! | stats sampler | — | turns `Connection::stats()` into [`ConnStats`] |
//!
//! Everything above the transport talks to [`SessionReceivers`] and the
//! [`Session`] trait and never touches quinn.
//!
//! # There is no video *sender* here, on purpose
//!
//! Video egress lives in the host's `video_pump`, not in this driver. That is
//! where the things a real sender needs already are: FEC parity, pacing across
//! the frame interval, a `datagram_send_buffer_space` precheck so a frame is
//! never offered piecemeal, and latest-wins coalescing of the encoder queue. A
//! second, simpler egress path in here would be a worse copy of it that quietly
//! competed for the same datagram buffer, so the driver only *receives* video.
//! Senders fragment with [`crate::video::fragment_frame_fec`] and call
//! [`Connection::send_datagram`] themselves.
//!
//! # One datagram path, two kinds of media
//!
//! Audio and video share the unreliable QUIC datagram path, so
//! `datagram_recv_loop` — the only `read_datagram` caller in the workspace —
//! is also the demux. Every datagram is classified by
//! [`crate::audio::is_audio_datagram`] *before* anything parses it, and audio
//! is routed to its own channel rather than into the video [`Reassembler`].
//!
//! The classification is unconditional; only delivery is gated on
//! [`SessionConfig::receive_audio`]. See the comment at the demux itself for
//! why both of those properties are load-bearing rather than stylistic.
//!
//! # Why a trait
//!
//! The TCP/TLS fallback in a later milestone has to present the same interface,
//! so the useful surface is deliberately transport-agnostic: two typed send
//! methods, four typed receivers, a stats snapshot, and a close. Nothing in
//! [`Session`] mentions QUIC, and nothing in it is `async` — which keeps it
//! object-safe, so callers can hold a `Box<dyn Session>` and swap transports at
//! runtime.
//!
//! # Backpressure policy, stated plainly
//!
//! - Control and input are **reliable**: a full queue is an error the caller
//!   sees, never a silent drop. Losing a key-up event leaves a key stuck down.
//! - Inbound video is **droppable**: a full receive queue drops the reassembled
//!   frame and warns. A video frame that arrives late is worth less than
//!   nothing, because it delays the one behind it.
//! - Inbound audio is **droppable** for the same reason: a full queue drops the
//!   packet and warns. Twenty milliseconds of audio delivered late is a
//!   deepening lip-sync offset, not a recovered sound.
//!
//! # Time
//!
//! This module is the one place in the transport layer that reads a real clock,
//! because it is the thing that owns real timers. It uses [`Instant`] only —
//! never the wall clock — so a system time change cannot stall a session. The
//! reassembler underneath it still takes an injected `now_ms`, measured from
//! session start, which is what keeps its own tests deterministic.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use quinn::{Connection, RecvStream, SendStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::audio::{self, AudioFrame};
use crate::error::{Error, Result};
use crate::protocol::{ControlMsg, InputMsg};
use crate::stats::{ConnStats, TransportRoute};
use crate::transport::quic::{self, SessionStreams};
use crate::transport::reassembly::{Reassembler, ReassemblyConfig, ReassemblyStats};
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
    /// Queue depth for inbound video frames.
    pub video_capacity: usize,
    /// Queue depth for inbound audio packets.
    ///
    /// Counted in packets, not milliseconds: at ~20 ms per AAC-LC access unit
    /// the default 32 is a little over half a second of slack, which is far
    /// more than a healthy consumer needs and still small enough that a stalled
    /// one cannot hoard audio the player would never have used anyway.
    pub audio_capacity: usize,
    /// Reassembly policy for inbound video.
    pub reassembly: ReassemblyConfig,
    /// Whether to run the inbound video path at all.
    ///
    /// Video in DirectDesk is **one-directional**: the host sends, the client
    /// receives, and no client ever puts a video datagram on the wire. A host
    /// that spawns the receive loop therefore keeps a whole [`Reassembler`]
    /// alive for datagrams that never arrive — and, worse, hands the peer a
    /// second route into its encoder: on a fragment gap the loop emits
    /// [`SessionEvent::KeyframeNeeded`], which the host turns straight into a
    /// `request_keyframe()` with **no** rate limit, unlike the intended
    /// `ControlMsg::RequestKeyframe` path, which is limited.
    ///
    /// Defaults to `true` so a plain [`Session`] is a receiver — that is what
    /// every client is, and what the host's own integration tests act as. Only
    /// the host's real serving path sets it to `false`.
    ///
    /// QUIC only. `transport::tcp::TcpSession` carries media on the same byte
    /// stream as control and input, so its reader cannot decline to see it and
    /// this flag has no effect there. (Deliberately not an intra-doc link:
    /// `tcp` is behind the `transport-tcp` feature and is off in a default
    /// build, so a link here would be a broken-intra-doc-link warning that
    /// `tools/check.ps1` does not run `cargo doc` to catch.)
    pub receive_video: bool,

    /// Whether to **deliver** inbound audio to the application.
    ///
    /// Audio is one-directional like video — the host captures its own render
    /// endpoint and sends, the client plays — but unlike video it defaults to
    /// `false`, because it is negotiated per session by a feature bit and costs
    /// the receiving side a decoder and an output device. A session that never
    /// asked for audio should not be handed packets it would only drop.
    ///
    /// **This gates delivery only, never the demux.** `datagram_recv_loop`
    /// classifies every datagram with [`crate::audio::is_audio_datagram`]
    /// whatever this is set to; with the flag off, audio is routed away from
    /// the video path and then discarded rather than queued. Gating the
    /// classification instead would send audio into [`Reassembler::push`] on
    /// any session that did not negotiate it, where it would be refused by
    /// `FragHeader::decode` and counted as `fragments_rejected` — a diagnostic
    /// that reads as video corruption for something that is nothing of the
    /// kind, and that sits one widened flag mask away from being far worse
    /// (see [`crate::video::FLAG_AUDIO`]).
    ///
    /// QUIC only. `transport::tcp::TcpSession` carries media inline on the same
    /// byte stream as control and input and has no datagram path at all, so it
    /// can never see an audio datagram and this flag has no effect there.
    /// (Deliberately not an intra-doc link, for the reason given on
    /// [`SessionConfig::receive_video`].)
    pub receive_audio: bool,
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
            audio_capacity: 32,
            reassembly: ReassemblyConfig::default(),
            receive_video: true,
            receive_audio: false,
        }
    }
}

impl SessionConfig {
    /// Reject configurations that would deadlock or spin.
    ///
    /// Every capacity is checked, including `audio_capacity`: a zero is not a
    /// tolerable "no queue" setting but an immediate panic inside
    /// [`tokio::sync::mpsc::channel`], which would take down whichever task
    /// called [`QuicSession::start`] rather than returning an error the caller
    /// could report.
    pub fn validate(&self) -> Result<()> {
        if self.control_capacity == 0
            || self.input_capacity == 0
            || self.video_capacity == 0
            || self.audio_capacity == 0
        {
            return Err(Error::Invalid(
                "session queue capacities must be non-zero".into(),
            ));
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
    /// Inbound reassembled video frames. Yields `None` immediately when the
    /// session was started with [`SessionConfig::receive_video`] off.
    pub video: mpsc::Receiver<EncodedFrame>,
    /// Inbound audio packets. Yields `None` immediately when the session was
    /// started with [`SessionConfig::receive_audio`] off — which is the
    /// default, so most sessions see a closed receiver here.
    pub audio: mpsc::Receiver<AudioFrame>,
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
    /// Close gracefully with a reason the peer will see.
    fn close(&self, reason: &str);
    /// Whether the session has been closed locally or by the peer.
    fn is_closed(&self) -> bool;
}

/// Counters the driver keeps that are not part of [`ConnStats`].
#[derive(Debug, Default)]
struct Counters {
    keyframes_requested: AtomicU64,
    /// Input messages actually framed onto the wire by the input `write_loop`.
    /// On the client this is the transmit-side twin of the hook's enqueue count
    /// (`keys`): if enqueued keeps climbing while this stalls, the client's own
    /// send path is starved (e.g. by decode/render), not just the host.
    input_events_written: AtomicU64,
}

struct Shared {
    conn: Connection,
    route: TransportRoute,
    started: Instant,
    closed: AtomicBool,
    stats: Mutex<ConnStats>,
    /// The inbound video reassembler's cumulative counters, republished after
    /// every datagram so the stats sampler can turn them into a true
    /// application-level delivery-loss figure — one that includes quinn's
    /// silent datagram discards, which never touch its packet-loss counter.
    reassembly: Mutex<ReassemblyStats>,
    /// Token and send time of the outstanding heartbeat, if any.
    pending_ping: Mutex<Option<(u64, Instant)>>,
    counters: Counters,
    control_out: mpsc::Sender<ControlMsg>,
    input_out: mpsc::Sender<InputMsg>,
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
            self.emit(SessionEvent::Closed {
                reason: reason.to_string(),
            });
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
        // Created even when `receive_video` is off, so `SessionReceivers` keeps
        // one shape for every caller. Dropping the unused sender below is what
        // makes `rx.video.recv()` return `None` straight away.
        let (video_in_tx, video_in_rx) = mpsc::channel(config.video_capacity);
        // Same for audio, which is off by default: the channel always exists,
        // and it is the sender's fate that differs.
        let (audio_in_tx, audio_in_rx) = mpsc::channel(config.audio_capacity);
        let (events_tx, events_rx) = mpsc::channel(config.control_capacity);

        let shared = Arc::new(Shared {
            conn: conn.clone(),
            route,
            started: Instant::now(),
            closed: AtomicBool::new(false),
            stats: Mutex::new(ConnStats::default()),
            reassembly: Mutex::new(ReassemblyStats::default()),
            pending_ping: Mutex::new(None),
            counters: Counters::default(),
            control_out: control_out_tx,
            input_out: input_out_tx,
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
        tasks.push(tokio::spawn(write_loop(
            shared.clone(),
            input_send,
            input_out_rx,
            "input",
        )));
        tasks.push(tokio::spawn(input_read_loop(
            shared.clone(),
            input_recv,
            input_in_tx,
        )));
        // `then_some` moves each sender into the `Some` or drops it on the
        // spot, which is precisely the gate: a `None` here means the matching
        // receiver is already closed and the loop has nowhere to put that kind
        // of datagram. The video half carries its reassembly policy with it so
        // that the loop cannot build a `Reassembler` it has no channel for.
        let video_sink = config
            .receive_video
            .then_some((video_in_tx, config.reassembly));
        let audio_sink = config.receive_audio.then_some(audio_in_tx);
        if config.receive_video || config.receive_audio {
            tasks.push(tokio::spawn(datagram_recv_loop(
                shared.clone(),
                video_sink,
                audio_sink,
            )));
        }
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
        tasks.push(tokio::spawn(closed_watch(shared.clone())));

        let session = Self {
            shared,
            tasks: Mutex::new(tasks),
        };
        let receivers = SessionReceivers {
            control: control_in_rx,
            input: input_in_rx,
            video: video_in_rx,
            audio: audio_in_rx,
            events: events_rx,
        };
        Ok((session, receivers))
    }

    /// Number of keyframe requests this side has sent.
    pub fn keyframes_requested(&self) -> u64 {
        self.shared
            .counters
            .keyframes_requested
            .load(Ordering::Relaxed)
    }

    /// Input messages actually framed onto the wire (transmit side). On the
    /// client, compare against the hook's enqueue count to tell a starved local
    /// send path apart from a starved host.
    pub fn input_events_written(&self) -> u64 {
        self.shared
            .counters
            .input_events_written
            .load(Ordering::Relaxed)
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
        let _ = self.shared.control_out.try_send(ControlMsg::Bye {
            reason: reason.to_string(),
        });

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

    fn close(&self, reason: &str) {
        // Synchronous and immediate. The queued `Bye` will usually lose the
        // race against the connection close discarding buffered stream data —
        // the peer still learns the reason from the CONNECTION_CLOSE frame.
        // Prefer [`QuicSession::close_graceful`] when an async context exists.
        let _ = self.shared.control_out.try_send(ControlMsg::Bye {
            reason: reason.to_string(),
        });
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
            shared.emit(SessionEvent::Warning {
                detail: format!("{label} write: {e}"),
            });
            shared.mark_closed(&format!("{label} stream write failed"));
            return;
        }
        // Transmit-side twin of the client's enqueue counter, for diagnosing
        // whether the sender's own path (not the network or the host) is where
        // keystrokes stall under load.
        if label == "input" {
            shared
                .counters
                .input_events_written
                .fetch_add(1, Ordering::Relaxed);
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
                if shared
                    .control_out
                    .try_send(ControlMsg::Pong { token })
                    .is_err()
                {
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
                shared.emit(SessionEvent::PeerClosed {
                    reason: reason.clone(),
                });
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

async fn input_read_loop(shared: Arc<Shared>, mut stream: RecvStream, tx: mpsc::Sender<InputMsg>) {
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
                shared.emit(SessionEvent::Warning {
                    detail: format!("bad input event: {e}"),
                });
                continue;
            }
        }
        if tx.send(msg).await.is_err() {
            shared.mark_closed("input receiver dropped");
            return;
        }
    }
}

/// The one `read_datagram` caller in the workspace: receive every media
/// datagram, decide which medium it is, and hand it to that medium's channel.
///
/// `video` is `Some` only when [`SessionConfig::receive_video`] is set, and
/// carries the reassembly policy so the [`Reassembler`] — much the most
/// expensive state in this loop — is built only when there is somewhere for
/// its frames to go. `audio` is `Some` only when
/// [`SessionConfig::receive_audio`] is set. Both `None` is not a state
/// [`QuicSession::start`] produces: it does not spawn this loop at all then.
async fn datagram_recv_loop(
    shared: Arc<Shared>,
    video: Option<(mpsc::Sender<EncodedFrame>, ReassemblyConfig)>,
    audio_tx: Option<mpsc::Sender<AudioFrame>>,
) {
    let mut video = video.map(|(tx, config)| (tx, Reassembler::new(config)));
    loop {
        let datagram = match shared.conn.read_datagram().await {
            Ok(d) => d,
            Err(e) => {
                shared.mark_closed(&format!("datagram stream closed: {e}"));
                return;
            }
        };

        // --- Media demux, ahead of every parser and every allocation ---
        //
        // `is_audio_datagram` reads byte 8 through `.get()`, never `[8]`. That
        // is not defensive habit, it is required: a QUIC DATAGRAM frame may
        // legitimately carry a zero-length payload, and anyone on the path can
        // inject one, so `datagram` here can be any length at all — including
        // empty. An index panic on that byte would be a *silent* kill.
        //
        // Silent because of how this task is owned. It is a bare
        // `tokio::spawn` whose `JoinHandle` is only ever `abort()`ed in
        // `Drop`; nothing joins it and nothing observes a panic, so
        // `mark_closed` would never run. `is_closed()` would stay false, the
        // heartbeat and stats loops would go on ticking, the client UI would
        // go on reading Connected, and the reconnect path would never fire.
        // Video frozen for the life of the process, with every indicator
        // green — which is strictly worse than a crash, because a crash gets
        // reported.
        //
        // The classification is deliberately UNCONDITIONAL: it does not
        // consult `receive_audio`. Only *delivery* is gated, by `audio_tx`
        // being `None`. If the demux were gated too, a host that emitted audio
        // outside the negotiation would push it into `Reassembler::push`,
        // where `FragHeader::decode` refuses it and `fragments_rejected`
        // climbs — a counter that reads as "the video wire is corrupt" for
        // traffic that is perfectly well formed and merely unwanted. Route
        // audio away always; `receive_audio` decides only who receives it.
        if audio::is_audio_datagram(&datagram) {
            if let Some(tx) = audio_tx.as_ref() {
                match audio::decode_packet(&datagram) {
                    Ok(packet) => {
                        if tx.try_send(AudioFrame::from_packet(&packet)).is_err() {
                            // Same policy as video: audio delivered late is a
                            // widening sync offset, not a recovered sound.
                            shared.emit(SessionEvent::Warning {
                                detail: "audio receive queue full; packet dropped".into(),
                            });
                        }
                    }
                    Err(e) => {
                        // Malformed audio is dropped, never fatal — anyone on
                        // the path can inject a datagram with this bit set.
                        shared.emit(SessionEvent::Warning {
                            detail: format!("bad audio datagram: {e}"),
                        });
                    }
                }
            }
            // Audio was not negotiated: the datagram has still been kept away
            // from the reassembler, which is the point, and is now discarded
            // without a warning. One warning per unwanted packet, fifty times
            // a second, is a log flood rather than a diagnostic.
            continue;
        }

        let Some((tx, reassembler)) = video.as_mut() else {
            // Audio-only session. A video datagram is not ours to reassemble
            // and there is nowhere to put the result; silently ignored, for
            // the same anti-flood reason as above.
            continue;
        };
        let now_ms = shared.now_ms();

        if let Err(e) = reassembler.push(&datagram, now_ms) {
            // A malformed datagram is logged and ignored. It must never kill
            // the session: anyone on the path can inject one.
            shared.emit(SessionEvent::Warning {
                detail: format!("bad video datagram: {e}"),
            });
        }

        while let Some(frame) = reassembler.pop_frame() {
            if tx.try_send(frame).is_err() {
                shared.emit(SessionEvent::Warning {
                    detail: "video receive queue full; frame dropped".into(),
                });
            }
        }

        if reassembler.take_keyframe_request(now_ms) {
            shared
                .counters
                .keyframes_requested
                .fetch_add(1, Ordering::Relaxed);
            let _ = shared.control_out.try_send(ControlMsg::RequestKeyframe);
            shared.emit(SessionEvent::KeyframeNeeded);
        }

        // Publish the reassembler's counters for the stats sampler. Cheap: a
        // `Copy` of a handful of `u64`s under an uncontended lock, once per
        // datagram.
        *shared.reassembly.lock() = reassembler.stats();
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
    let mut prev = StatsSample::from_quinn(&shared.conn.stats());
    let mut prev_reasm = *shared.reassembly.lock();
    let mut prev_at = Instant::now();

    loop {
        ticker.tick().await;
        if shared.closed.load(Ordering::SeqCst) {
            return;
        }
        let cur = StatsSample::from_quinn(&shared.conn.stats());
        let cur_reasm = *shared.reassembly.lock();
        let dt_ms = prev_at.elapsed().as_millis() as u64;
        prev_at = Instant::now();

        let snapshot = {
            let mut stats = shared.stats.lock();
            let sampled = delta_stats(&prev, &cur, dt_ms, stats.jitter_ms);
            // The heartbeat measures RTT more directly than quinn's estimate
            // once a Pong has landed, so keep whichever we have.
            let rtt_ms = if stats.rtt_ms > 0.0 {
                stats.rtt_ms
            } else {
                sampled.rtt_ms
            };
            stats.rtt_ms = rtt_ms;
            stats.jitter_ms = sampled.jitter_ms;
            // True delivery loss. `sampled.loss` is quinn's packet-loss counter,
            // which never sees a silently discarded datagram; `video_loss` is
            // derived from the receiver's own fragment/frame accounting and does.
            // Take the larger so neither source can hide loss from the adaptor.
            stats.loss = video_loss(&prev_reasm, &cur_reasm).max(sampled.loss);
            stats.bandwidth_kbps = sampled.bandwidth_kbps;
            stats.keyframes_requested =
                shared.counters.keyframes_requested.load(Ordering::Relaxed) as u32;
            // `stats.frames_dropped` is deliberately left alone. The wire field
            // stays — it is pinned byte-for-byte by the anti-brick suite in
            // `crate::protocol` — but the transport no longer has a send queue
            // to drop frames from, so it has no honest number to put there. The
            // media pipeline does, and the host overwrites this field from
            // `HostSession::stats()` before the sample goes out.
            *stats
        };
        prev = cur;
        prev_reasm = cur_reasm;
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

/// Windowed application-level video **delivery loss**, in `0.0..=1.0`.
///
/// This is the number quinn cannot give us. QUIC datagrams are unreliable and
/// unacknowledged: when the send path or the kernel socket buffer cannot place
/// one, it is dropped without ever becoming a tracked "packet", so
/// `Connection::stats().path.lost_packets` stays at zero while video is
/// vanishing. The receiver, however, *can* see the hole — a frame that never
/// gets all its fragments cannot be reassembled and is abandoned. Comparing two
/// [`ReassemblyStats`] snapshots turns that into a fraction.
///
/// A frame is counted as *lost* when it was abandoned for want of fragments
/// (`frames_dropped_incomplete`) or left behind by newer frames before it could
/// finish (`frames_dropped_stale`) — both mean data that was sent did not
/// arrive in time to decode. Frames merely skipped by the latest-wins policy or
/// dropped as reordered stragglers are **not** loss: those arrived complete and
/// were discarded on purpose, so including them would slander a healthy link.
///
/// ```text
/// loss = (Δincomplete + Δstale) / (Δcompleted + Δincomplete + Δstale)
/// ```
///
/// The denominator is every frame the receiver could account for in the window,
/// so with no video traffic the result is a clean `0.0`. It reads only
/// [`ReassemblyStats`], so the TCP fallback — which will run the same
/// reassembler — can feed it identically.
pub fn video_loss(prev: &ReassemblyStats, cur: &ReassemblyStats) -> f32 {
    let completed = cur.frames_completed.saturating_sub(prev.frames_completed);
    let incomplete = cur
        .frames_dropped_incomplete
        .saturating_sub(prev.frames_dropped_incomplete);
    let stale = cur
        .frames_dropped_stale
        .saturating_sub(prev.frames_dropped_stale);

    let lost = incomplete.saturating_add(stale);
    let total = completed.saturating_add(lost);
    if total == 0 {
        return 0.0;
    }
    (lost as f32 / total as f32).clamp(0.0, 1.0)
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
    let loss = if sent == 0 {
        0.0
    } else {
        (lost as f32 / sent as f32).clamp(0.0, 1.0)
    };

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
    // Test-only: the driver demuxes and forwards audio without ever naming a
    // concrete format or building a packet, so importing these at module scope
    // would be genuinely unused in production code.
    use crate::audio::{AudioFormat, AudioPacket};
    use crate::crypto::tls::ServerPinning;
    use crate::crypto::HostIdentity;
    use crate::transport::quic::QuicParams;
    use crate::video::EncodedFrame;

    /// The sender half of the video path, which the driver deliberately does not
    /// own: fragment and put each fragment on the wire as its own datagram.
    /// This is `host::net::video_pump` in miniature, minus the pacing and the
    /// backpressure precheck that only a real encoder feed needs.
    fn send_frame(conn: &Connection, frame: &EncodedFrame) {
        let mtu = quic::max_datagram(conn).expect("datagrams");
        for f in crate::video::fragment_frame_fec(frame, mtu, 0).expect("fragment") {
            conn.send_datagram(bytes::Bytes::from(f)).expect("datagram");
        }
    }

    /// The sender half of the audio path, which the driver does not own either.
    /// There is no `fragment_*` step to mirror: one AAC-LC access unit is one
    /// datagram, always, so an audio packet is either delivered whole or lost.
    fn send_audio(conn: &Connection, seq: u32, payload: &[u8]) {
        let bytes = crate::audio::encode_packet(&AudioPacket {
            seq,
            capture_ms: 1_000 + seq,
            discontinuity: false,
            format: AudioFormat::Stereo48k,
            payload,
        })
        .expect("encode audio");
        conn.send_datagram(bytes::Bytes::from(bytes))
            .expect("datagram");
    }

    /// Field-by-field frame equality. [`EncodedFrame`] does not derive
    /// `PartialEq`, and a reassembly test that compared only `frame_id` would
    /// pass on a frame whose bytes had been shuffled — which is most of what
    /// these tests are actually watching for.
    fn assert_same_frame(got: &EncodedFrame, want: &EncodedFrame) {
        assert_eq!(got.frame_id, want.frame_id, "frame_id");
        assert_eq!(got.keyframe, want.keyframe, "keyframe flag");
        assert_eq!(got.timestamp_ms, want.timestamp_ms, "timestamp_ms");
        assert_eq!(
            got.data, want.data,
            "frame {} did not reassemble byte for byte",
            want.frame_id
        );
    }

    #[test]
    fn config_validation() {
        assert!(SessionConfig::default().validate().is_ok());
        let bad = SessionConfig {
            video_capacity: 0,
            ..SessionConfig::default()
        };
        assert!(bad.validate().is_err());
        // `audio_capacity` too: `mpsc::channel(0)` panics rather than erroring,
        // and a panic inside `start` is not something a caller can report.
        let bad_audio = SessionConfig {
            audio_capacity: 0,
            ..SessionConfig::default()
        };
        assert!(bad_audio.validate().is_err());
        // Off by default, so no session pays for audio it did not negotiate.
        assert!(!SessionConfig::default().receive_audio);
    }

    #[test]
    fn jitter_starts_at_zero_and_converges() {
        assert_eq!(
            ewma_jitter(0.0, 0.0, 50.0),
            0.0,
            "no previous RTT means no jitter yet"
        );
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
        let high = StatsSample {
            sent_packets: 10,
            lost_packets: 5,
            ..Default::default()
        };
        let low = StatsSample::default();
        let s = delta_stats(&high, &low, 100, 0.0);
        assert!(crate::stats::validate_stats(&s));
    }

    #[test]
    fn video_loss_zero_when_no_frames_and_when_all_complete() {
        let z = ReassemblyStats::default();
        // No traffic at all: a clean zero, never a divide-by-zero.
        assert_eq!(video_loss(&z, &z), 0.0);

        // 100 frames completed, nothing dropped: no loss.
        let cur = ReassemblyStats {
            frames_completed: 100,
            ..z
        };
        assert_eq!(video_loss(&z, &cur), 0.0);
    }

    #[test]
    fn video_loss_counts_incomplete_and_stale_only() {
        let prev = ReassemblyStats::default();
        // Window: 90 delivered, 8 abandoned incomplete, 2 aged out stale ->
        // 10 lost of 100 accounted = 0.10.
        let cur = ReassemblyStats {
            frames_completed: 90,
            frames_dropped_incomplete: 8,
            frames_dropped_stale: 2,
            // These must NOT count as loss: they arrived complete and were
            // dropped deliberately.
            frames_skipped_latest_wins: 50,
            frames_dropped_reorder: 5,
            ..prev
        };
        assert!(
            (video_loss(&prev, &cur) - 0.10).abs() < 1e-6,
            "{}",
            video_loss(&prev, &cur)
        );
    }

    #[test]
    fn video_loss_is_windowed_via_deltas() {
        // Cumulative counters: only the change since the previous sample counts.
        let prev = ReassemblyStats {
            frames_completed: 500,
            frames_dropped_incomplete: 20,
            ..ReassemblyStats::default()
        };
        // This window: +10 completed, +10 incomplete -> 0.5, regardless of the
        // large history already accrued.
        let cur = ReassemblyStats {
            frames_completed: 510,
            frames_dropped_incomplete: 30,
            ..prev
        };
        assert!((video_loss(&prev, &cur) - 0.5).abs() < 1e-6);
    }

    #[test]
    fn video_loss_half_datagrams_lost_reads_as_heavy_loss() {
        // The bug this whole change is about: ~half the datagrams silently
        // vanish, so almost every multi-fragment frame fails to assemble. quinn
        // reports 0.00 loss; the reassembler-derived figure does not.
        let prev = ReassemblyStats::default();
        let cur = ReassemblyStats {
            frames_completed: 118,
            frames_dropped_incomplete: 114,
            ..prev
        };
        let loss = video_loss(&prev, &cur);
        assert!(loss > 0.4, "expected heavy loss, got {loss}");
        assert!((0.0..=1.0).contains(&loss));
        let s = ConnStats {
            loss,
            ..ConnStats::default()
        };
        assert!(crate::stats::validate_stats(&s));
    }

    #[test]
    fn video_loss_absorbs_counter_resets() {
        // Counters going backwards (a reset that must never happen, but must not
        // panic or produce NaN/negative) saturate to a clean zero.
        let high = ReassemblyStats {
            frames_completed: 100,
            frames_dropped_incomplete: 50,
            ..ReassemblyStats::default()
        };
        let low = ReassemblyStats::default();
        let loss = video_loss(&high, &low);
        assert_eq!(loss, 0.0);
        assert!(loss.is_finite());
    }

    #[test]
    fn loss_is_clamped_to_unit_range() {
        let prev = StatsSample {
            sent_packets: 100,
            lost_packets: 0,
            ..Default::default()
        };
        let cur = StatsSample {
            sent_packets: 110,
            lost_packets: 500,
            ..Default::default()
        };
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
        let server =
            quic::server_endpoint("127.0.0.1:0".parse().unwrap(), id.tls(), &params).unwrap();
        let server_addr = server.local_addr().unwrap();

        let host_task = tokio::spawn(async move {
            let conn = server
                .accept()
                .await
                .expect("incoming")
                .await
                .expect("handshake");
            let streams = quic::accept_streams(&conn).await.expect("accept streams");
            let (session, mut rx) = QuicSession::start(
                conn,
                streams,
                TransportRoute::DirectUdp,
                SessionConfig {
                    heartbeat_ms: 100,
                    stats_interval_ms: 100,
                    ..Default::default()
                },
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

            // A frame large enough to require several datagrams, put on the wire
            // the way the host really does it — the driver has no send path.
            send_frame(
                session.connection(),
                &EncodedFrame {
                    frame_id: 42,
                    keyframe: true,
                    timestamp_ms: 1234,
                    data: (0..8000u32).map(|i| (i % 251) as u8).collect(),
                },
            );

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
        let conn = quic::connect(&client_ep, server_addr)
            .await
            .expect("connect");
        let streams = quic::open_streams(&conn).await.expect("open streams");
        let (session, mut rx) = QuicSession::start(
            conn,
            streams,
            TransportRoute::DirectUdp,
            SessionConfig {
                heartbeat_ms: 100,
                stats_interval_ms: 100,
                ..Default::default()
            },
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
        session
            .send_input(InputMsg::ReleaseAll)
            .expect("send input");

        let frame = tokio::time::timeout(Duration::from_secs(10), rx.video.recv())
            .await
            .expect("video timeout")
            .expect("video closed");
        assert_eq!(frame.frame_id, 42);
        assert!(frame.keyframe);
        assert_eq!(frame.timestamp_ms, 1234);
        assert_eq!(frame.data.len(), 8000);
        assert!(frame
            .data
            .iter()
            .enumerate()
            .all(|(i, b)| *b == (i as u32 % 251) as u8));

        // The heartbeat should have produced a real RTT measurement by now.
        tokio::time::sleep(Duration::from_millis(600)).await;
        let stats = session.stats();
        assert!(
            stats.rtt_ms >= 0.0 && stats.rtt_ms < 5_000.0,
            "rtt {}",
            stats.rtt_ms
        );
        assert!(crate::stats::validate_stats(&stats));
        assert!(!session.is_closed());

        let host_stats = tokio::time::timeout(Duration::from_secs(15), host_task)
            .await
            .unwrap()
            .unwrap();
        assert!(crate::stats::validate_stats(&host_stats));

        session.close("test done");
        assert!(session.is_closed());
        client_ep.wait_idle().await;
    }

    /// With [`SessionConfig::receive_video`] off there is no reassembler and no
    /// datagram reader — the sender half of the video channel is never created,
    /// so `rx.video` is closed from the start rather than merely idle. That is
    /// the difference a caller can actually observe, and it is what lets the
    /// host stop paying for an inbound path nothing uses.
    #[tokio::test]
    async fn receive_video_false_spawns_no_reassembler() {
        let id = HostIdentity::generate("no-recv-host").unwrap();
        let params = QuicParams::default();
        let server =
            quic::server_endpoint("127.0.0.1:0".parse().unwrap(), id.tls(), &params).unwrap();
        let server_addr = server.local_addr().unwrap();

        let host_task = tokio::spawn(async move {
            let conn = server
                .accept()
                .await
                .expect("incoming")
                .await
                .expect("handshake");
            let streams = quic::accept_streams(&conn).await.expect("accept streams");
            let (session, mut rx) = QuicSession::start(
                conn,
                streams,
                TransportRoute::DirectUdp,
                SessionConfig {
                    heartbeat_ms: 0,
                    stats_interval_ms: 0,
                    receive_video: false,
                    ..Default::default()
                },
            )
            .expect("host session");

            // Closed immediately, without waiting for anything: the loop that
            // would have held the sender was never spawned.
            let got = tokio::time::timeout(Duration::from_secs(10), rx.video.recv())
                .await
                .expect("video receiver should close, not hang");
            assert!(got.is_none(), "no video should ever be delivered");
            // Everything else still works; only the video path is gone. Stay up
            // long enough for the client's datagrams to arrive and be ignored —
            // closing straight away would only prove the receiver was gone
            // because the connection was.
            tokio::time::sleep(Duration::from_millis(500)).await;
            assert!(!session.is_closed());
            session.close("test done");
        });

        let client_ep = quic::client_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            ServerPinning::Pinned(*id.spki_sha256()),
            &params,
        )
        .unwrap();
        let conn = quic::connect(&client_ep, server_addr)
            .await
            .expect("connect");
        let streams = quic::open_streams(&conn).await.expect("open streams");
        let (session, _rx) = QuicSession::start(
            conn,
            streams,
            TransportRoute::DirectUdp,
            SessionConfig::default(),
        )
        .expect("client session");

        // Datagrams sent at a peer that is not listening must be inert: they are
        // discarded by quinn, not queued, and nothing on either side notices.
        send_frame(
            session.connection(),
            &EncodedFrame {
                frame_id: 1,
                keyframe: true,
                timestamp_ms: 0,
                data: vec![7u8; 8000],
            },
        );

        tokio::time::timeout(Duration::from_secs(15), host_task)
            .await
            .unwrap()
            .unwrap();
        client_ep.wait_idle().await;
    }

    /// With [`SessionConfig::receive_audio`] off — the default — the audio
    /// sender is never handed to the receive loop, so `rx.audio` is closed from
    /// the start rather than merely idle. Exactly what
    /// `receive_video_false_spawns_no_reassembler` pins for the video half.
    ///
    /// The second half of this test is the more interesting one. The host sends
    /// real audio datagrams at a client that did not ask for them, and the
    /// client's video still arrives byte-for-byte. That is the *unconditional*
    /// demux observed from outside: the flag suppresses delivery, not
    /// classification, so those datagrams are routed away from
    /// [`Reassembler::push`] even on a session with audio switched off. Gate
    /// the demux on the flag instead and they would land in
    /// `FragHeader::decode`'s rejection path —
    /// `an_audio_datagram_never_disturbs_a_reassembler` spells out what that
    /// costs, and how much worse than a bad counter it is one flag mask away
    /// from being.
    #[tokio::test]
    async fn receive_audio_false_closes_the_audio_receiver() {
        let id = HostIdentity::generate("no-audio-host").unwrap();
        let params = QuicParams::default();
        let server =
            quic::server_endpoint("127.0.0.1:0".parse().unwrap(), id.tls(), &params).unwrap();
        let server_addr = server.local_addr().unwrap();

        let host_task = tokio::spawn(async move {
            let conn = server
                .accept()
                .await
                .expect("incoming")
                .await
                .expect("handshake");
            let streams = quic::accept_streams(&conn).await.expect("accept streams");
            let (session, mut rx) = QuicSession::start(
                conn,
                streams,
                TransportRoute::DirectUdp,
                SessionConfig {
                    heartbeat_ms: 0,
                    stats_interval_ms: 0,
                    // A pure sender: it neither receives video nor audio.
                    receive_video: false,
                    receive_audio: false,
                    ..Default::default()
                },
            )
            .expect("host session");

            // Rendezvous, so the datagrams below cannot race the client's
            // session coming up.
            let msg = tokio::time::timeout(Duration::from_secs(10), rx.control.recv())
                .await
                .expect("control timeout")
                .expect("control closed");
            assert!(matches!(msg, ControlMsg::StartStream { .. }));

            // Audio before, during and after the video frame, at a client that
            // never negotiated any of it.
            for seq in 0..4u32 {
                send_audio(session.connection(), seq, &[0xA5; 48]);
            }
            send_frame(
                session.connection(),
                &EncodedFrame {
                    frame_id: 11,
                    keyframe: true,
                    timestamp_ms: 77,
                    data: (0..8000u32).map(|i| (i % 251) as u8).collect(),
                },
            );
            for seq in 4..8u32 {
                send_audio(session.connection(), seq, &[0xA5; 48]);
            }

            // Stay up while the client drains: closing straight away would only
            // prove the audio receiver was closed because the session was.
            tokio::time::sleep(Duration::from_secs(2)).await;
            assert!(!session.is_closed());
        });

        let client_ep = quic::client_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            ServerPinning::Pinned(*id.spki_sha256()),
            &params,
        )
        .unwrap();
        let conn = quic::connect(&client_ep, server_addr)
            .await
            .expect("connect");
        let streams = quic::open_streams(&conn).await.expect("open streams");
        // Plain `default()`: `receive_audio` is false without anyone saying so,
        // which is the state every existing caller is already in.
        let (session, mut rx) = QuicSession::start(
            conn,
            streams,
            TransportRoute::DirectUdp,
            SessionConfig::default(),
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

        // Closed, not idle: the sender was dropped at `start`, so this returns
        // without waiting for anything.
        let got = tokio::time::timeout(Duration::from_secs(10), rx.audio.recv())
            .await
            .expect("audio receiver should close, not hang");
        assert!(got.is_none(), "no audio should ever be delivered");

        // And the video path is untouched by the audio that just went past it.
        let frame = tokio::time::timeout(Duration::from_secs(10), rx.video.recv())
            .await
            .expect("video timeout")
            .expect("video closed");
        assert_eq!(frame.frame_id, 11);
        assert!(frame.keyframe);
        assert_eq!(frame.timestamp_ms, 77);
        assert_eq!(frame.data.len(), 8000);
        assert!(
            frame
                .data
                .iter()
                .enumerate()
                .all(|(i, b)| *b == (i as u32 % 251) as u8),
            "the frame reassembled with audio interleaved through it"
        );
        assert!(!session.is_closed());

        tokio::time::timeout(Duration::from_secs(15), host_task)
            .await
            .unwrap()
            .unwrap();

        session.close("test done");
        client_ep.wait_idle().await;
    }

    /// Audio and video interleaved on the one datagram path, over loopback
    /// QUIC: each comes out on its own channel, undamaged.
    ///
    /// The interleaving is the substance. Audio packets are sent *between* the
    /// fragments of a frame, not merely between frames, because a stray
    /// datagram arriving mid-frame is the one that would land on a live
    /// reassembly slot. A second frame follows all of it, so the reassembler
    /// has to still be in a fit state to start a new frame afterwards.
    #[tokio::test]
    async fn loopback_session_demuxes_interleaved_audio_and_video() {
        // Audio packets sent, and the number the client must see, in order.
        const AUDIO_PACKETS: u32 = 12;
        // Payload bytes per audio packet. Every byte is the sequence number, so
        // a swapped pair shows up as a content mismatch and not merely an
        // ordering one.
        const AUDIO_PAYLOAD_LEN: usize = 48;

        fn video_frame(id: u32) -> EncodedFrame {
            EncodedFrame {
                frame_id: id,
                keyframe: id == 7,
                timestamp_ms: 900 + id,
                data: (0..8000u32)
                    .map(|i| (i.wrapping_add(id) % 251) as u8)
                    .collect(),
            }
        }

        let id = HostIdentity::generate("audio-demux-host").unwrap();
        let params = QuicParams::default();
        let server =
            quic::server_endpoint("127.0.0.1:0".parse().unwrap(), id.tls(), &params).unwrap();
        let server_addr = server.local_addr().unwrap();

        let host_task = tokio::spawn(async move {
            let conn = server
                .accept()
                .await
                .expect("incoming")
                .await
                .expect("handshake");
            let streams = quic::accept_streams(&conn).await.expect("accept streams");
            let (session, mut rx) = QuicSession::start(
                conn,
                streams,
                TransportRoute::DirectUdp,
                SessionConfig {
                    heartbeat_ms: 0,
                    stats_interval_ms: 0,
                    receive_video: false,
                    receive_audio: false,
                    ..Default::default()
                },
            )
            .expect("host session");

            let msg = tokio::time::timeout(Duration::from_secs(10), rx.control.recv())
                .await
                .expect("control timeout")
                .expect("control closed");
            assert!(matches!(msg, ControlMsg::StartStream { .. }));

            let conn = session.connection();
            let mtu = quic::max_datagram(conn).expect("datagrams");
            let frame_a = video_frame(7);
            let frags = crate::video::fragment_frame_fec(&frame_a, mtu, 0).expect("fragment");
            assert!(frags.len() > 1, "the fixture must need reassembly");

            // One audio packet before each video fragment, so the demux runs
            // in the middle of a frame rather than only at its boundaries.
            for seq in 0..AUDIO_PACKETS {
                send_audio(conn, seq, &[seq as u8; AUDIO_PAYLOAD_LEN]);
                if let Some(f) = frags.get(seq as usize) {
                    conn.send_datagram(bytes::Bytes::from(f.clone()))
                        .expect("datagram");
                }
            }
            for f in frags.iter().skip(AUDIO_PACKETS as usize) {
                conn.send_datagram(bytes::Bytes::from(f.clone()))
                    .expect("datagram");
            }

            // A whole frame after all the audio has gone by.
            send_frame(conn, &video_frame(8));

            tokio::time::sleep(Duration::from_secs(3)).await;
            assert!(!session.is_closed());
        });

        let client_ep = quic::client_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            ServerPinning::Pinned(*id.spki_sha256()),
            &params,
        )
        .unwrap();
        let conn = quic::connect(&client_ep, server_addr)
            .await
            .expect("connect");
        let streams = quic::open_streams(&conn).await.expect("open streams");
        let (session, mut rx) = QuicSession::start(
            conn,
            streams,
            TransportRoute::DirectUdp,
            SessionConfig {
                heartbeat_ms: 0,
                stats_interval_ms: 0,
                receive_audio: true,
                ..Default::default()
            },
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

        // Video first: both frames, byte for byte, despite the audio threaded
        // through the first one's fragments.
        for id in [7u32, 8] {
            let frame = tokio::time::timeout(Duration::from_secs(10), rx.video.recv())
                .await
                .expect("video timeout")
                .expect("video closed");
            assert_same_frame(&frame, &video_frame(id));
        }

        // Audio: every packet, in sequence order, with its header fields and
        // payload intact. `audio_capacity` is 32 by default, comfortably more
        // than AUDIO_PACKETS, so nothing here is testing the drop policy.
        for seq in 0..AUDIO_PACKETS {
            let packet = tokio::time::timeout(Duration::from_secs(10), rx.audio.recv())
                .await
                .expect("audio timeout")
                .expect("audio closed");
            assert_eq!(packet.seq, seq, "audio arrived out of order");
            assert_eq!(packet.capture_ms, 1_000 + seq);
            assert!(!packet.discontinuity);
            assert_eq!(packet.format, AudioFormat::Stereo48k);
            assert_eq!(packet.data, vec![seq as u8; AUDIO_PAYLOAD_LEN]);
        }

        assert!(!session.is_closed());
        tokio::time::timeout(Duration::from_secs(15), host_task)
            .await
            .unwrap()
            .unwrap();
        session.close("test done");
        client_ep.wait_idle().await;
    }

    /// The proof that `Reassembler::adopt_numbering` is unreachable from audio.
    ///
    /// This is the failure the demux exists to prevent, stated at the level of
    /// the thing that would break. An audio packet's bytes 0..4 are a
    /// *sequence number* — a number line with no relationship whatever to a
    /// video `frame_id` — so a run of audio datagrams read as video fragments
    /// looks to `accept_frame_id` like a run of consecutive, mutually agreeing
    /// out-of-window frame ids. That is precisely its signature for a
    /// legitimate encoder renumbering, so past `resync_after` (8) of them it
    /// calls `adopt_numbering`: every live slot dropped, every ready frame
    /// dropped, the window relocated to a number line the sender is not on, and
    /// a keyframe demanded. Video stalls, and nothing logs an error.
    ///
    /// So: two real video frames with a hundred real audio datagrams pushed
    /// straight into a `Reassembler` between them, with no demux in front of it
    /// at all. Both frames must still reassemble byte for byte, the audio must
    /// move exactly one counter, and [`video_loss`] — the figure the adaptor
    /// steers on — must stay a clean zero. The control group at the end clears
    /// the one bit that carried the whole rejection and shows the same
    /// datagrams wrecking a reassembler, so this is a test of a mechanism and
    /// not of an accident.
    ///
    /// It lives beside the demux rather than in `reassembly.rs` because the
    /// property is the demux's, and because `video_loss` — where a stall like
    /// this would have to become visible — is defined in this module.
    #[test]
    fn an_audio_datagram_never_disturbs_a_reassembler() {
        // Enough to clear `resync_after` (8) more than ten times over.
        const AUDIO_COUNT: u32 = 100;

        fn video_frame(id: u32, keyframe: bool) -> EncodedFrame {
            EncodedFrame {
                frame_id: id,
                keyframe,
                timestamp_ms: 1_000 + id,
                data: (0..4000u32)
                    .map(|i| (i.wrapping_add(id) % 251) as u8)
                    .collect(),
            }
        }

        fn frags_of(frame: &EncodedFrame) -> Vec<Vec<u8>> {
            crate::video::fragment_frame_fec(frame, 1200, 0).expect("fragment")
        }

        // Audio datagrams whose sequence numbers are far outside the video
        // window *and* within `max_forward_jump` of each other. Both halves
        // matter: scattered ids would never accumulate a run, so the test would
        // pass without ever approaching the mechanism it is about.
        fn audio_datagrams() -> Vec<Vec<u8>> {
            (0..AUDIO_COUNT)
                .map(|i| {
                    let payload = [0x5A; 64];
                    crate::audio::encode_packet(&AudioPacket {
                        seq: 0x4000_0000u32.wrapping_add(i),
                        // Read as a video header this lands frag_index = 0 and
                        // frag_count = 1, so the disguised control group below
                        // is refused by the flag check alone rather than by
                        // some unrelated geometry rule. Same fixture reasoning
                        // as `audio::tests::a_real_audio_packet_is_rejected_by_
                        // the_video_decoder`.
                        capture_ms: 0x0001_0000,
                        discontinuity: false,
                        format: AudioFormat::Stereo48k,
                        payload: &payload,
                    })
                    .expect("encode audio")
                })
                .collect()
        }

        let frame_a = video_frame(100, true);
        let frame_b = video_frame(101, false);
        let frags_a = frags_of(&frame_a);
        let frags_b = frags_of(&frame_b);
        assert!(frags_a.len() > 1, "the fixture must need reassembly");
        assert!(
            (frags_b.len() as u32) < ReassemblyConfig::default().resync_after,
            "frame B must be too short to trip a resync run on its own, or the \
             control group below would be measuring its own fixture"
        );

        let mut r = Reassembler::new(ReassemblyConfig::default());
        for f in &frags_a {
            r.push(f, 0).expect("video fragment");
        }
        assert_same_frame(&r.pop_frame().expect("frame A"), &frame_a);
        let before = r.stats();

        for datagram in &audio_datagrams() {
            assert!(
                audio::is_audio_datagram(datagram),
                "the real demux would have routed this away before it got here"
            );
            assert!(
                r.push(datagram, 0).is_err(),
                "an audio datagram must never be accepted as a video fragment"
            );
        }

        // The whole claim, in one comparison: a hundred audio datagrams may
        // move the rejection count and may move nothing else. Not the window,
        // not the slots, not the ready queue, not a single frame counter.
        assert_eq!(
            r.stats(),
            ReassemblyStats {
                fragments_rejected: before.fragments_rejected + u64::from(AUDIO_COUNT),
                ..before
            },
            "audio disturbed reassembler state beyond the rejection count"
        );

        for f in &frags_b {
            r.push(f, 0).expect("video fragment");
        }
        assert_same_frame(&r.pop_frame().expect("frame B"), &frame_b);

        let after = r.stats();
        assert_eq!(after.frames_completed, before.frames_completed + 1);
        assert_eq!(after.frames_dropped_incomplete, 0);
        assert_eq!(after.frames_dropped_stale, 0);
        assert_eq!(
            video_loss(&before, &after),
            0.0,
            "a hundred audio datagrams between two frames read as video loss"
        );
        // `adopt_numbering` raises `need_keyframe`. Frame A was a keyframe and
        // frame B followed it with no gap, so a demand here could only have
        // come from the audio.
        assert!(
            !r.take_keyframe_request(0),
            "the audio raised a keyframe demand, which means it reached adopt_numbering"
        );

        // --- Control group: prove the premise instead of asserting it ---
        //
        // The same datagrams with `FLAG_AUDIO` cleared — the only thing wrong
        // with them as far as `FragHeader::decode` is concerned — do exactly
        // the damage described above. Without this, the assertions so far would
        // be equally satisfied by a fixture that could never have hurt anything.
        let mut r2 = Reassembler::new(ReassemblyConfig::default());
        for f in &frags_a {
            r2.push(f, 0).expect("video fragment");
        }
        assert_same_frame(&r2.pop_frame().expect("frame A"), &frame_a);
        assert!(
            !r2.take_keyframe_request(0),
            "clean before the disguised run"
        );

        for datagram in &audio_datagrams() {
            let mut disguised = datagram.clone();
            disguised[crate::audio::AUDIO_FLAGS_OFFSET] &= !crate::audio::FLAG_AUDIO;
            let _ = r2.push(&disguised, 0);
        }
        assert!(
            r2.take_keyframe_request(0),
            "the fixture must be able to trip the resync once the audio bit is gone, \
             or this test proves nothing about that bit"
        );

        let wrecked = r2.stats();
        for f in &frags_b {
            let _ = r2.push(f, 0);
        }
        assert_eq!(
            r2.stats().fragments_rejected,
            wrecked.fragments_rejected + frags_b.len() as u64,
            "with the window moved onto the audio's number line, every fragment of \
             frame B is refused — a video stall for the life of the session, with \
             no error logged anywhere"
        );
        while let Some(frame) = r2.pop_frame() {
            assert_ne!(
                frame.data, frame_b.data,
                "frame B must not have survived the forged renumbering"
            );
        }
    }

    /// A `Bye` from the peer must close the session and surface the reason.
    #[tokio::test]
    async fn peer_bye_closes_the_session() {
        let id = HostIdentity::generate("bye-host").unwrap();
        let params = QuicParams::default();
        let server =
            quic::server_endpoint("127.0.0.1:0".parse().unwrap(), id.tls(), &params).unwrap();
        let server_addr = server.local_addr().unwrap();

        let host_task = tokio::spawn(async move {
            let conn = server
                .accept()
                .await
                .expect("incoming")
                .await
                .expect("handshake");
            let streams = quic::accept_streams(&conn).await.expect("accept streams");
            let (session, _rx) = QuicSession::start(
                conn,
                streams,
                TransportRoute::DirectUdp,
                SessionConfig::default(),
            )
            .expect("host session");
            tokio::time::sleep(Duration::from_millis(200)).await;
            session
                .close_graceful("host is going away", Duration::from_secs(5))
                .await;
        });

        let client_ep = quic::client_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            ServerPinning::Pinned(*id.spki_sha256()),
            &params,
        )
        .unwrap();
        let conn = quic::connect(&client_ep, server_addr)
            .await
            .expect("connect");
        let streams = quic::open_streams(&conn).await.expect("open streams");
        let (session, mut rx) = QuicSession::start(
            conn,
            streams,
            TransportRoute::DirectUdp,
            SessionConfig::default(),
        )
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
