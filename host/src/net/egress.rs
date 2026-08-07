//! The media send path: what turns an encoded frame into datagrams on the wire,
//! and what carries the refinement strips travelling beside them.
//!
//! Two pumps live here and they are deliberately different animals.
//! [`video_pump`] is a dedicated OS thread that holds the Windows timer
//! resolution at 1 ms, because pacing a keyframe's fragments needs sleeps the
//! scheduler will actually honour. [`tile_pump`] is an ordinary abortable tokio
//! task, because refinement is a background trickle with no deadline to miss.
//!
//! What they share is the constraint that makes this the sharp half of a
//! session: `send_datagram` neither blocks nor refuses — when its buffer is full
//! quinn evicts the *oldest* queued datagrams instead. Offering more than fits
//! therefore does not drop the frame being offered, it shreds the one already in
//! flight. [`wire_size`], [`pace_plan`] and the FEC block size exist to keep
//! that from happening.
//!
//! What belongs here is everything between "the encoder produced a frame" and
//! "the bytes are quinn's problem". What does not: the counters these pumps
//! write are owned by [`crate::net`], next to the status loop that reads and
//! resets them, and every decision about *how much* to send is made in
//! [`super::adaptation`]. This module spends the budget; it never sets it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use crossbeam_channel::Receiver as CbReceiver;
use quinn::Connection;

use directdesk_shared::transport::quic;
use directdesk_shared::video::{fragment_frame_fec, EncodedFrame};

use crate::session::HostSession;

use super::adaptation::RateLimiter;
use super::{TileCounters, VideoCounters};

/// Floor on how often the video pump asks for an IDR *of its own accord*
/// (coalesced frames, backpressure, a frame it could not fragment). These are
/// self-inflicted requests on an already-struggling link, so they stay rare.
pub const KEYFRAME_MIN_INTERVAL_MS: u64 = 500;

// ---------------------------------------------------------------------------
// Frame drop policy
// ---------------------------------------------------------------------------

/// Bytes a frame will occupy in the datagram send buffer once fragmented.
///
/// [`fragment_frame`] splits the payload into `mtu - FRAG_HEADER_LEN` chunks
/// and puts a header on each, so the data total is the payload plus one header
/// per fragment. [`fragment_frame_fec`] then adds one XOR-parity fragment per
/// `fec_block` data fragments, and a parity payload is always a *full* chunk
/// wide — it is the XOR of chunk-padded pieces — so parity costs a header plus
/// the whole chunk, not an average share of the payload. Counting it is what
/// keeps the backpressure precheck from under-estimating ~10% and letting
/// quinn evict the datagrams already in flight.
///
/// `fec_block == 0` (or a single data fragment) models the data-only
/// fragmenter, which is exactly what [`fragment_frame_fec`] emits in that case.
pub fn wire_size(frame: &EncodedFrame, mtu: usize, fec_block: u8) -> usize {
    use directdesk_shared::video::FRAG_HEADER_LEN;
    let chunk = mtu.saturating_sub(FRAG_HEADER_LEN).max(1);
    let frags = frame.data.len().div_ceil(chunk);
    let data = frame.data.len() + frags * FRAG_HEADER_LEN;
    if fec_block == 0 || frags <= 1 {
        return data;
    }
    let parity = frags.div_ceil(fec_block as usize);
    data + parity * (FRAG_HEADER_LEN + chunk)
}

/// Upper bound on [`wire_size`] over *every* frame the fragmenter would accept
/// at `mtu`: [`MAX_FRAGS_PER_FRAME`] full data fragments plus their parity.
///
/// This exists so a second producer on the datagram path can reserve enough
/// room for the frame the video pump is *currently* paying out without knowing
/// anything about that frame. See [`super::audio`]: its send loop passes this
/// function's result straight in as the `reserve` argument of its `has_room`
/// precheck, recomputed per packet from the connection's current MTU (there is
/// no constant — path-MTU discovery can move the answer mid-session). The
/// reason it has to be an upper bound rather than the actual frame's size is
/// that the two threads never meet.
///
/// Note the bound comes from the fragment *count* limit, not from
/// `MAX_FRAME_BYTES`: 512 fragments at a 1200-byte MTU is 607 KB of payload,
/// well under the 2 MiB frame ceiling, so the fragment cap is what binds first
/// at every MTU the fragmenter will serve.
pub fn max_frame_wire_size(mtu: usize) -> usize {
    use directdesk_shared::video::{FRAG_HEADER_LEN, MAX_FRAGS_PER_FRAME};
    let chunk = mtu.saturating_sub(FRAG_HEADER_LEN).max(1);
    let frags = MAX_FRAGS_PER_FRAME as usize;
    let data = frags * (chunk + FRAG_HEADER_LEN);
    let parity = frags.div_ceil(FEC_BLOCK_SIZE as usize);
    data + parity * (FRAG_HEADER_LEN + chunk)
}

/// Shortest sleep Windows can actually honour, even with the 1 ms timer
/// resolution the video sender holds. Asking for less does not pace the burst,
/// it just rounds every gap up — which is how a 285-fragment scene-change frame
/// turned a 10 ms pacing window into a 35–200 ms stall.
pub const MIN_PACE_SLEEP: Duration = Duration::from_millis(1);

/// How to spread `n` fragments of one frame across `pace_window`: how many
/// datagrams go out back-to-back, and how long to sleep between those batches.
///
/// A zero gap means "no pacing, send the lot" — either the frame is small
/// enough not to need smoothing, or the window is too short to be divided into
/// sleeps the OS could honour. The batch count is capped at the window's whole
/// milliseconds precisely so every gap this returns is one Windows can serve:
/// a big frame is then paced *coarsely* instead of being paced into a stall.
pub fn pace_plan(n: usize, pace_window: Duration) -> (usize, Duration) {
    if n <= PACING_MIN_FRAGS {
        return (n.max(1), Duration::ZERO);
    }
    let max_batches = pace_window.as_millis().max(1) as usize;
    let batches = n.div_ceil(PACING_BATCH).clamp(1, max_batches);
    let batch_len = n.div_ceil(batches).max(1);
    let gap = pace_window / batches as u32;
    if gap < MIN_PACE_SLEEP {
        (n, Duration::ZERO)
    } else {
        (batch_len, gap)
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
pub(super) fn video_pump(
    conn: Connection,
    frames: CbReceiver<EncodedFrame>,
    pipeline: Arc<HostSession>,
    streaming: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    counters: Arc<VideoCounters>,
) {
    crate::session::lower_video_thread_priority("video-tx");
    let _timer = TimerResolution::acquire();
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

        // Spread a frame's fragments across ~60% of a frame interval so the next
        // frame is still not due when we finish, i.e. pacing adds smoothing
        // without adding steady-state latency. Recomputed per frame (one relaxed
        // atomic load) because the frame rate is live: at 15 fps the window is
        // 40 ms rather than 10 ms, which is exactly the extra smoothing a
        // residential uplink needs to get a big IDR out without tail-dropping.
        let pace_window =
            Duration::from_micros(1_000_000 / pipeline.active_fps().max(1) as u64) * 3 / 5;

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
        if conn.datagram_send_buffer_space() < wire_size(&frame, mtu, FEC_BLOCK_SIZE) {
            counters.backpressured.fetch_add(1, Ordering::Relaxed);
            if idr.allow(start.elapsed().as_millis() as u64) {
                pipeline.request_keyframe();
            }
            continue;
        }

        // The precheck above covers the data fragments *and* their parity, so
        // what follows fits whole at the instant it was measured.
        //
        // That used to be the end of the story — "nothing this frame sends can
        // displace the datagrams already queued for the previous one" — and it
        // stopped being true the moment a second producer appeared on this
        // path. The check above and the last `send_datagram` below are
        // separated by the pacing sleeps, which at 15 fps run to ~133 ms, so
        // any other thread sending in that window spends headroom this frame
        // has already counted, and quinn's eviction then shreds the frame in
        // flight rather than refusing the newcomer.
        //
        // The invariant is now one-sided and enforced on the *other* side:
        // `net::audio` prechecks with `max_frame_wire_size` held back on top of
        // its own packet, so audio can never take the room this frame reserved.
        // Video reserves nothing in return and does not need to — one worst-case
        // frame of slack covers whatever audio could have queued meanwhile.
        // Any future third producer on the datagram path owes the same reserve.
        let frags = match fragment_frame_fec(&frame, mtu, FEC_BLOCK_SIZE) {
            Ok(f) => f,
            Err(e) => {
                counters
                    .frames_unfragmentable
                    .fetch_add(1, Ordering::Relaxed);
                if frame.keyframe {
                    // A keyframe we cannot fragment is a hard freeze, not a
                    // dropped frame: every later P-frame references an IDR the
                    // client never received, and the IDR we are about to ask
                    // for would be exactly as big. Latch it so the adaptor
                    // treats this as full congestion and the next one is
                    // smaller — that is the loop-termination guard.
                    counters.oversized_keyframe.store(true, Ordering::Relaxed);
                    tracing::error!(
                        frame_id = frame.frame_id,
                        bytes = frame.data.len(),
                        keyframe = frame.keyframe,
                        "cannot fragment keyframe ({e}); cutting bitrate so the next IDR fits"
                    );
                } else {
                    tracing::warn!(
                        frame_id = frame.frame_id,
                        bytes = frame.data.len(),
                        keyframe = frame.keyframe,
                        "cannot fragment frame ({e}); dropping it"
                    );
                }
                // Dropping a frame breaks the client's reference chain just as
                // coalescing does, so it earns an IDR through the same limiter.
                if idr.allow(start.elapsed().as_millis() as u64) {
                    pipeline.request_keyframe();
                }
                continue;
            }
        };

        let mut bytes = 0u64;
        let mut failed = false;
        let n = frags.len();
        // Small frames go out immediately; large ones are spread so a keyframe
        // burst can't tail-drop (which would make quinn evict older queued
        // datagrams and shred an in-flight frame).
        let (batch_len, gap) = pace_plan(n, pace_window);
        // Pacing is smoothing, not a contract. A scene change makes one frame
        // 6-18x normal size, and holding the sleeps for all of it is what backs
        // the encoder queue up until frames are evicted — the freeze. Past
        // twice the window we stop pacing and get the frame out: a burst costs
        // some loss, a stall costs the picture.
        let emit_start = Instant::now();
        let deadline = emit_start + pace_window * 2;
        let mut burst = false;
        for (i, frag) in frags.into_iter().enumerate() {
            if !gap.is_zero() && !burst && i > 0 && i % batch_len == 0 {
                if Instant::now() + gap <= deadline {
                    std::thread::sleep(gap);
                } else {
                    burst = true;
                }
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
        let emit_ms = emit_start.elapsed().as_millis() as u64;
        counters.emit_ms_max.fetch_max(emit_ms, Ordering::Relaxed);
        if burst {
            counters
                .pace_deadline_bursts
                .fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                frame_id = frame.frame_id,
                frags = n,
                emit_ms,
                "pacing deadline passed; burst the rest of the frame"
            );
        }
        if failed {
            break;
        }
        counters.frames_sent.fetch_add(1, Ordering::Relaxed);
        counters.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }
    tracing::debug!("video sender finished");
}

/// How long the pump sleeps when the tile queue is empty. Tiles are a
/// background trickle, not a paced real-time stream, so a coarse poll costs
/// nothing and keeps this an ordinary abortable tokio task.
const TILE_POLL_MS: u64 = 15;

/// Ship refinement messages to the client on the bulk unidirectional stream.
///
/// Lives in `tasks`, so it is aborted when the session ends. That is exactly
/// right: an aborted pump simply stops renewing leases, every outstanding tile
/// expires on the client, and the picture reverts to plain H.264. There is no
/// cleanup to get wrong.
///
/// Failure policy throughout: **this task may degrade the picture, never the
/// session.** Any stream error stops the pump and leaves the connection alive.
/// Note what this task deliberately does **not** do: it never drops a message.
///
/// The budget is spent by the media thread *before* a strip is queued, because
/// only the media thread owns the grid. If this task dropped a queued strip,
/// the grid would already have recorded it as delivered (`commit_sent`), the
/// hash guard would suppress every re-send, and that square of the screen would
/// stay soft forever — the same class of bug as a reconnect inheriting a stale
/// grid, and just as invisible in testing.
///
/// Congestion is therefore handled by *waiting*, not discarding: this task
/// stalls, the bounded queue fills, and the media thread's `try_send` fails and
/// calls `abandon`, which leaves the tile eligible for a later pass. Every link
/// in that chain fails toward "send it again", never toward "assume it landed".
pub(super) async fn tile_pump(
    conn: Connection,
    tiles: CbReceiver<directdesk_shared::tiles::TileMsg>,
    stop: Arc<AtomicBool>,
    counters: Arc<TileCounters>,
) {
    use directdesk_shared::tiles::TileMsg;

    let mut send = match quic::open_bulk(&conn).await {
        Ok(s) => s,
        Err(e) => {
            // The client agreed to the feature but the stream would not open.
            // Nothing else about the session is affected.
            tracing::warn!("lossless tiles disabled for this session: {e}");
            return;
        }
    };
    tracing::info!("lossless tile stream open");

    while !stop.load(Ordering::Relaxed) {
        // Deliberately no congestion check here. Throttling happens twice
        // already, both in places that can decline work rather than destroy it:
        // `status_loop` zeroes the budget on any strain, and the media thread
        // spends that budget before it plans a strip. A check *here* could only
        // act on a message already dequeued — and dropping it would be the one
        // failure this feature must not have. Congestion instead arrives as
        // natural backpressure: `write_framed` awaits, this queue fills, and the
        // media thread's `try_send` fails into `abandon`, which retries later.
        let msg = match tiles.try_recv() {
            Ok(m) => m,
            Err(crossbeam_channel::TryRecvError::Empty) => {
                tokio::time::sleep(Duration::from_millis(TILE_POLL_MS)).await;
                continue;
            }
            Err(crossbeam_channel::TryRecvError::Disconnected) => break,
        };

        match &msg {
            TileMsg::Strip { data, .. } => {
                counters.strips_sent.fetch_add(1, Ordering::Relaxed);
                counters
                    .bytes_sent
                    .fetch_add(data.len() as u64, Ordering::Relaxed);
            }
            _ => {
                counters.control_sent.fetch_add(1, Ordering::Relaxed);
            }
        }

        if let Err(e) = quic::write_framed(&mut send, &msg).await {
            tracing::warn!("tile stream write failed, refinement off: {e}");
            break;
        }
    }

    // Best-effort tidy: a clean finish lets the client's reader end without
    // logging an error. Failure here is irrelevant, the session owns the
    // connection.
    let _ = send.finish();
}

#[cfg(test)]
mod tests {
    use super::*;
    // Data-only fragmenter: `wire_size` models exactly its output, so the tests
    // that pin that relationship exercise it directly.
    use directdesk_shared::video::fragment_frame;

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
            assert_eq!(wire_size(&f, mtu, 0), actual, "len {len}");
        }
    }

    #[test]
    fn wire_size_counts_the_fec_parity_too() {
        // Under-counting parity is what let quinn evict in-flight datagrams:
        // the model must match what actually goes on the wire, byte for byte.
        let mtu = 1_200;
        for len in [1usize, 100, 1_186, 1_187, 5_000, 145_000] {
            let f = EncodedFrame {
                frame_id: 1,
                keyframe: true,
                timestamp_ms: 0,
                data: vec![0u8; len],
            };
            let actual: usize = fragment_frame_fec(&f, mtu, FEC_BLOCK_SIZE)
                .unwrap()
                .iter()
                .map(|d| d.len())
                .sum();
            assert_eq!(wire_size(&f, mtu, FEC_BLOCK_SIZE), actual, "len {len}");
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
        assert!(wire_size(&f, 1_200, 0) > f.data.len());
        assert!(
            wire_size(&f, 1_200, 0) > wire_size(&f, 1_400, 0),
            "smaller MTU means more headers"
        );
        assert!(
            wire_size(&f, 1_200, FEC_BLOCK_SIZE) > wire_size(&f, 1_200, 0),
            "parity is not free"
        );
    }

    #[test]
    fn max_frame_wire_size_bounds_every_frame_the_fragmenter_accepts() {
        // The audio sender holds this many bytes back on every send so it
        // cannot consume headroom the video pump's precheck already counted.
        // If it ever under-estimates, enabling audio silently starts shredding
        // keyframes on constrained links — the exact failure it exists to
        // prevent — so it is checked against what fragmenting really produces,
        // across the MTUs quinn can hand us and frames up to the point where
        // the fragment-count limit refuses them.
        for mtu in [576usize, 1_200, 1_400, 1_500, 9_000] {
            let bound = max_frame_wire_size(mtu);
            for len in [1usize, 1_000, 50_000, 145_000, 600_000, 2 * 1024 * 1024] {
                let f = EncodedFrame {
                    frame_id: 1,
                    keyframe: true,
                    timestamp_ms: 0,
                    data: vec![0u8; len],
                };
                // Only frames the fragmenter would actually emit matter: one it
                // refuses is never offered to the connection at all.
                if fragment_frame_fec(&f, mtu, FEC_BLOCK_SIZE).is_ok() {
                    assert!(
                        wire_size(&f, mtu, FEC_BLOCK_SIZE) <= bound,
                        "mtu {mtu} len {len}: {} exceeds the reserve {bound}",
                        wire_size(&f, mtu, FEC_BLOCK_SIZE)
                    );
                }
            }
        }

        // And it must leave the audio sender somewhere to stand: a reserve at
        // or above the whole datagram send buffer would mean audio never sends
        // a single packet, which would look exactly like a broken feature.
        let reserve = max_frame_wire_size(1_200);
        assert_eq!(
            reserve, 676_800,
            "the documented reserve at a 1200-byte MTU"
        );
        assert!(
            reserve < directdesk_shared::transport::quic::DEFAULT_DATAGRAM_SEND_BUFFER / 2,
            "a {reserve}-byte reserve would starve audio outright"
        );
    }

    // -- pacing ------------------------------------------------------------

    #[test]
    fn small_frames_are_not_paced() {
        let (batch, gap) = pace_plan(4, Duration::from_millis(10));
        assert_eq!(gap, Duration::ZERO, "a 4-fragment frame just goes out");
        assert_eq!(batch, 4);
    }

    #[test]
    fn ordinary_frames_keep_the_old_plan() {
        // The behaviour this replaces: one batch per PACING_BATCH fragments,
        // the window split evenly between them. Nothing normal-sized changes.
        let (batch, gap) = pace_plan(16, Duration::from_millis(10));
        assert_eq!(batch, PACING_BATCH);
        assert_eq!(gap, Duration::from_micros(2_500));
    }

    #[test]
    fn a_scene_change_frame_is_paced_coarsely_not_impossibly() {
        // 285 fragments is a real minimise-to-desktop frame. The old plan asked
        // for 72 gaps of 138us inside a 10ms window; Windows rounds each up and
        // the frame takes 35-200ms. Fewer, honourable gaps instead.
        let window = Duration::from_millis(10);
        let (batch, gap) = pace_plan(285, window);
        assert!(
            gap >= MIN_PACE_SLEEP,
            "{gap:?} is a sleep Windows can serve"
        );
        let batches = 285usize.div_ceil(batch);
        assert!(
            gap * batches as u32 <= window,
            "pacing {batches} batches of {gap:?} must fit the window"
        );
        assert!(batch * batches >= 285, "every fragment must be covered");
    }

    #[test]
    fn pace_plan_gaps_are_always_sleepable_and_fit_the_window() {
        for fps in [30u32, 60, 120, 240] {
            // Exactly how video_pump derives its window.
            let window = Duration::from_micros(1_000_000 / fps as u64) * 3 / 5;
            for n in 1..=512usize {
                let (batch, gap) = pace_plan(n, window);
                assert!(batch >= 1, "n {n} fps {fps}: empty batch");
                assert!(
                    gap.is_zero() || gap >= MIN_PACE_SLEEP,
                    "n {n} fps {fps}: {gap:?} is below the sleep floor"
                );
                let batches = n.div_ceil(batch);
                assert!(batch * batches >= n, "n {n} fps {fps}: fragments lost");
                // Sleeps happen *between* batches, so the bound is generous.
                assert!(
                    gap * batches as u32 <= window,
                    "n {n} fps {fps}: {batches} x {gap:?} overruns {window:?}"
                );
            }
        }
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
}
