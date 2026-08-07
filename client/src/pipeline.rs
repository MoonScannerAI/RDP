//! Background threads that feed the presentation slot.
//!
//! Two sources exist:
//!
//! * [`spawn_decode_thread`] — the real path: encoded frames from the transport
//!   through the Media Foundation decoder.
//! * [`spawn_demo_source`] — `--loopback-demo`: synthetic RGBA frames pushed
//!   straight into the slot, bypassing H.264 entirely, so the whole UI / input
//!   / render loop is exercisable with no network and no host.
//!
//! A third, optional thread — [`Pipeline::attach_tile_thread`] — feeds the
//! lossless refinement store the decode thread composites from.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, RecvTimeoutError};
use directdesk_shared::protocol::ControlMsg;
use directdesk_shared::tiles::TileMsg;
use directdesk_shared::traits::{Decoder, PixelFormat, RawFrame};
use directdesk_shared::video::EncodedFrame;
use parking_lot::Mutex;
use tokio::sync::mpsc;

use crate::renderer::FrameSlot;
use crate::tiles::{composite_tiles, Tile, TileStore};

/// Shared status a background source publishes for the diagnostics panel.
#[derive(Default)]
pub struct SourceStatus {
    description: Mutex<String>,
    error: Mutex<Option<String>>,
    /// Delta frames [`KeyframeGate`] refused (gap or awaiting IDR after one).
    /// Not read by the diagnostics panel yet — the getter exists so wiring
    /// it in is a one-line addition elsewhere.
    frames_gated: AtomicU64,
}

impl SourceStatus {
    pub fn description(&self) -> String {
        self.description.lock().clone()
    }

    pub fn error(&self) -> Option<String> {
        self.error.lock().clone()
    }

    /// Count of delta frames dropped by [`KeyframeGate`] pending a keyframe.
    pub fn frames_gated(&self) -> u64 {
        self.frames_gated.load(Ordering::Relaxed)
    }

    fn set_description(&self, text: impl Into<String>) {
        *self.description.lock() = text.into();
    }

    fn set_error(&self, text: Option<String>) {
        *self.error.lock() = text;
    }

    fn record_frame_gated(&self) {
        self.frames_gated.fetch_add(1, Ordering::Relaxed);
    }
}

/// Refuses delta frames until a keyframe re-establishes the reference chain.
///
/// A P-frame decoded against the wrong (or a missing) reference doesn't
/// error — Media Foundation happily produces a *smeared* picture that looks
/// plausible but is wrong. That is worse than showing nothing new: the gate
/// gap-checks `frame_id` before every decode call and refuses anything that
/// isn't a keyframe or the immediate successor of the last admitted frame,
/// so the caller freezes on the last good picture instead of smearing until
/// the next keyframe arrives.
#[derive(Debug, Default)]
struct KeyframeGate {
    last_id: Option<u32>,
    waiting: bool,
}

impl KeyframeGate {
    /// Decide whether `frame_id` may be handed to the decoder.
    ///
    /// Returns `(decode, request_keyframe_now)`:
    /// - A keyframe is always admitted; it resets the chain and clears
    ///   `waiting` regardless of what came before.
    /// - A delta frame is admitted only when it is exactly
    ///   `last_id.wrapping_add(1)` *and* the gate isn't already waiting.
    /// - Anything else (a gap, no chain yet, or already waiting) is
    ///   refused. `request_keyframe_now` is `true` only on the transition
    ///   into `waiting`, so a stalled sender is asked once, not every frame.
    fn admit(&mut self, frame_id: u32, keyframe: bool) -> (bool, bool) {
        if keyframe {
            self.waiting = false;
            self.last_id = Some(frame_id);
            return (true, false);
        }
        let contiguous = self
            .last_id
            .is_some_and(|id| frame_id == id.wrapping_add(1));
        if !self.waiting && contiguous {
            self.last_id = Some(frame_id);
            return (true, false);
        }
        let entering_wait = !self.waiting;
        self.waiting = true;
        (false, entering_wait)
    }
}

/// Pump `rx` into `on_item` until it disconnects or `stop` is set.
///
/// The shape shared by every background thread in this file: a 100ms
/// `recv_timeout` poll so the stop flag is noticed promptly without a busy
/// loop, a `Timeout` is not itself a reason to stop, and a disconnected
/// sender always is.
fn recv_until_stopped<T>(rx: &Receiver<T>, stop: &AtomicBool, mut on_item: impl FnMut(T)) {
    loop {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(item) => on_item(item),
            Err(RecvTimeoutError::Timeout) => {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}

/// Owns the background threads and stops them on drop.
pub struct Pipeline {
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
    pub status: Arc<SourceStatus>,
    /// Lossless refinement tiles the decode thread paints over each frame.
    ///
    /// Created here rather than handed in because the decode thread is spawned
    /// from `main`, before the UI exists, and the store must be live from that
    /// thread's first frame. The UI takes a clone via [`Pipeline::tiles`] to
    /// invalidate it and to read the diagnostics gauges.
    tiles: Arc<TileStore>,
    /// Tints composited tiles so coverage is visible during bring-up. Read on
    /// the decode thread once per frame, written by the UI toggle.
    tile_highlight: Arc<AtomicBool>,
}

impl Pipeline {
    fn new(status: Arc<SourceStatus>, stop: Arc<AtomicBool>) -> Self {
        Self {
            stop,
            threads: Vec::new(),
            status,
            tiles: Arc::new(TileStore::new()),
            tile_highlight: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The refinement store this pipeline composites from.
    pub fn tiles(&self) -> Arc<TileStore> {
        self.tiles.clone()
    }

    /// Whether composited tiles are being tinted.
    pub fn tile_highlight(&self) -> bool {
        self.tile_highlight.load(Ordering::Relaxed)
    }

    pub fn set_tile_highlight(&self, on: bool) {
        self.tile_highlight.store(on, Ordering::Relaxed);
    }

    /// Spawn the thread that applies inbound [`TileMsg`]s to the store.
    ///
    /// A thread of its own, not a branch of the decode loop, for two reasons.
    /// Tile arrival is bursty and unbounded by the frame clock — a screen that
    /// has just settled emits a wave of strips — and inflating those on the
    /// paced real-time decode loop is how frames get dropped. It also keeps
    /// untrusted, attacker-influenced input off the thread that owns the Media
    /// Foundation decoder, whose COM state is thread-affine.
    ///
    /// Joins with the rest of the pipeline: it watches the same stop flag and
    /// its handle goes on the same `threads` vec, so [`Pipeline::shutdown`]
    /// (and therefore `Drop`) already covers it.
    pub fn attach_tile_thread(&mut self, tiles_rx: Receiver<TileMsg>) {
        let store = self.tiles.clone();
        let stop = self.stop.clone();
        let handle = std::thread::Builder::new()
            .name("directdesk-tiles".into())
            .spawn(move || {
                recv_until_stopped(&tiles_rx, &stop, |msg| {
                    // `apply` validates geometry, decompresses, and refuses
                    // anything it does not like. Nothing it can return is
                    // fatal, so its outcome is a counter, not control flow.
                    store.apply(msg);
                });
                tracing::info!("tile thread exiting");
            })
            .expect("spawn tile thread");
        self.threads.push(handle);
    }

    pub fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for handle in self.threads.drain(..) {
            let _ = handle.join();
        }
    }
}

impl Drop for Pipeline {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Decode thread: owns the MF decoder for its whole life (COM is per-thread).
///
/// Decodes **every** frame it receives, in order. It never inspects timestamps
/// to decide whether decoding is "worth it" — that decision belongs to the
/// presenter, after decoding.
pub fn spawn_decode_thread(
    video_rx: Receiver<EncodedFrame>,
    slot: Arc<FrameSlot>,
    control_tx: mpsc::Sender<ControlMsg>,
    repaint: impl Fn() + Send + 'static,
) -> Pipeline {
    let status = Arc::new(SourceStatus::default());
    let stop = Arc::new(AtomicBool::new(false));
    let mut pipeline = Pipeline::new(status.clone(), stop.clone());
    let tiles = pipeline.tiles.clone();
    let tile_highlight = pipeline.tile_highlight.clone();

    let handle = std::thread::Builder::new()
        .name("directdesk-decode".into())
        .spawn(move || {
            let mut decode_loop =
                DecodeLoop::new(status, tiles, tile_highlight, slot, control_tx, repaint);
            recv_until_stopped(&video_rx, &stop, |frame| decode_loop.handle_frame(frame));
            tracing::info!("decode thread exiting");
        })
        .expect("spawn decode thread");

    pipeline.threads.push(handle);
    pipeline
}

/// Per-frame decode state, owned by the decode thread for its whole life.
///
/// Splitting this out of the thread closure turns what was the deepest
/// nesting in the crate — closure -> loop -> match recv -> Ok arm -> match
/// decode -> Ok arm -> for -> if let Err — into a thin `recv`/stop loop
/// ([`recv_until_stopped`]) plus one shallow method. [`DecodeLoop::handle_frame`]
/// is the whole per-frame pipeline: keyframe-gate, decode, composite live
/// refinement tiles, publish. It is callable directly from tests with a
/// `NullDecoder` or a small scripted double, with no Media Foundation and no
/// channel involved.
struct DecodeLoop<R> {
    /// `None` when the decoder failed to construct (e.g. a platform without
    /// Media Foundation); every frame is then a no-op, same as before this
    /// type existed.
    decoder: Option<Box<dyn Decoder>>,
    gate: KeyframeGate,
    /// Hoisted so the per-frame cost of a snapshot is a memcpy of `Arc`
    /// pointers into an already-grown buffer, never an allocation.
    scratch: Vec<Arc<Tile>>,
    status: Arc<SourceStatus>,
    tiles: Arc<TileStore>,
    tile_highlight: Arc<AtomicBool>,
    control_tx: mpsc::Sender<ControlMsg>,
    slot: Arc<FrameSlot>,
    repaint: R,
}

impl<R: Fn() + Send + 'static> DecodeLoop<R> {
    fn new(
        status: Arc<SourceStatus>,
        tiles: Arc<TileStore>,
        tile_highlight: Arc<AtomicBool>,
        slot: Arc<FrameSlot>,
        control_tx: mpsc::Sender<ControlMsg>,
        repaint: R,
    ) -> Self {
        let decoder: Option<Box<dyn Decoder>> = match crate::decoder::new_decoder() {
            Ok(d) => {
                #[cfg(windows)]
                status.set_description(
                    "MF H.264 (CLSID_MSH264DecoderMFT), NV12→RGBA8 BT.709 limited".to_string(),
                );
                #[cfg(not(windows))]
                status.set_description("H.264 decoder".to_string());
                Some(d)
            }
            Err(e) => {
                tracing::error!("decoder unavailable: {e}");
                status.set_description("unavailable".to_string());
                status.set_error(Some(e.to_string()));
                None
            }
        };
        Self {
            decoder,
            gate: KeyframeGate::default(),
            scratch: Vec::new(),
            status,
            tiles,
            tile_highlight,
            control_tx,
            slot,
            repaint,
        }
    }

    /// Handle one received encoded frame end to end.
    ///
    /// Keyframe-gates it, decodes it, composites the live refinement tiles
    /// onto every decoded picture, and publishes each to the slot. A gate
    /// gap and a decode error both recover the same way: flush the decoder
    /// and ask the host for a fresh keyframe (see
    /// [`flush_and_request_keyframe`]).
    fn handle_frame(&mut self, frame: EncodedFrame) {
        let Some(decoder) = self.decoder.as_mut() else {
            return;
        };

        let (admitted, request_keyframe_now) = self.gate.admit(frame.frame_id, frame.keyframe);
        if !admitted {
            self.status.record_frame_gated();
            tracing::debug!(
                frame_id = frame.frame_id,
                keyframe = frame.keyframe,
                "dropping delta frame after gap; awaiting IDR"
            );
            if request_keyframe_now {
                // Entering the wait: flush the stale reference chain once
                // and ask for a fresh IDR. `request_keyframe_now` is only
                // true on the transition into waiting, so a stalled sender
                // is asked once, not on every dropped frame.
                flush_and_request_keyframe(&mut **decoder, &self.control_tx);
            }
            return;
        }

        match decoder.decode(&frame) {
            Ok(frames) => {
                let produced = frames.len();
                for mut raw in frames {
                    // The tile overlay is *persistent* state while a
                    // decoded frame is transient — the decoder hands back a
                    // fresh buffer every time — so the live tile set has to
                    // be re-blitted onto every frame, right here, before
                    // the frame is published. Doing it downstream (in the
                    // presenter) would mean repainting on every *repaint*
                    // instead of every frame, and would put a pixel loop on
                    // the UI thread.
                    composite_onto(
                        &mut raw,
                        &self.tiles,
                        &mut self.scratch,
                        self.tile_highlight.load(Ordering::Relaxed),
                    );
                    self.slot.publish(raw);
                }
                if produced > 0 {
                    (self.repaint)();
                }
            }
            Err(e) => {
                tracing::warn!(frame_id = frame.frame_id, "decode failed: {e}");
                self.status.set_error(Some(e.to_string()));
                // Corrupt state: only a fresh IDR can recover. Flushing
                // alone drops the bad reference chain but leaves the
                // decoder starved until the host happens to send a
                // keyframe — so ask for one.
                flush_and_request_keyframe(&mut **decoder, &self.control_tx);
            }
        }
    }
}

/// Flush the decoder's stale reference chain and ask the host for a fresh
/// IDR keyframe.
///
/// The one recovery move for both ways [`DecodeLoop::handle_frame`] can find
/// itself unable to proceed: a keyframe-gate gap (frames lost in flight) and
/// a decode error (Media Foundation rejected a frame outright). Either way,
/// flushing alone would leave the decoder starved until the host happens to
/// send a keyframe on its own, so ask for one explicitly. `try_send` never
/// blocks this thread; a full control queue already has a keyframe request
/// pending, so dropping this one is harmless.
fn flush_and_request_keyframe(decoder: &mut dyn Decoder, control_tx: &mpsc::Sender<ControlMsg>) {
    decoder.flush();
    if let Err(err) = control_tx.try_send(ControlMsg::RequestKeyframe) {
        tracing::warn!("keyframe request dropped: {err}");
    }
}

/// Paint the live refinement tiles over one freshly decoded frame.
///
/// Split out of the decode loop so the format guard, the disarmed case and the
/// reuse of `scratch` are testable without standing up a decoder. Returns
/// `None` when nothing was painted at all (wrong pixel format, or the store is
/// disarmed), so a caller can tell "no tiles" from "tiles, none of them valid".
///
/// Only `Rgba8` is touched. [`composite_tiles`] writes RGBA — the shared codec
/// does the channel swap once, at admission — so blitting onto a `Bgra8` frame
/// would transpose red and blue on every tile: a silent colour corruption
/// rather than an error. Today's Media Foundation decoder always emits `Rgba8`
/// (`renderer` still accepts either), and this guard makes that an assumption
/// the compositor *states* rather than one it inherits.
fn composite_onto(
    frame: &mut RawFrame,
    tiles: &TileStore,
    scratch: &mut Vec<Arc<Tile>>,
    highlight: bool,
) -> Option<crate::tiles::CompositeStats> {
    if frame.format != PixelFormat::Rgba8 {
        return None;
    }
    // Drop anything whose lease has run out BEFORE snapshotting.
    //
    // Not an optimisation — a correctness requirement. The host stops revoking
    // a tile once its lease lapses (`begin_pass` returns it to `Moving` with no
    // revocation, on the stated assumption that the client has already dropped
    // it). If we merely declined to paint it, a later `Renew` would revive
    // pixels the host had written off. Expiry has to mean gone.
    tiles.sweep_expired(frame.timestamp_ms);

    // Snapshot `Arc` handles under the store's lock, then blit lock-free: the
    // tile thread must never be blocked behind a pixel loop.
    let size = tiles.snapshot_into(scratch)?;
    Some(composite_tiles(
        &mut frame.data,
        frame.width,
        frame.height,
        frame.timestamp_ms,
        size,
        scratch,
        highlight,
    ))
}

/// `--loopback-demo`: synthetic RGBA frames at `fps`, no H.264 involved.
///
/// This exists to exercise the render + input + stats loop end to end with no
/// host and no network. It is NOT a decoder test: it deliberately bypasses the
/// decoder, and the diagnostics panel says so.
pub fn spawn_demo_source(
    slot: Arc<FrameSlot>,
    fps: u32,
    repaint: impl Fn() + Send + 'static,
) -> Pipeline {
    const WIDTH: u32 = 1280;
    const HEIGHT: u32 = 720;

    let status = Arc::new(SourceStatus::default());
    status.set_description(format!(
        "loopback demo: synthetic RGBA {WIDTH}x{HEIGHT} @ {fps} fps (decoder BYPASSED)"
    ));
    let stop = Arc::new(AtomicBool::new(false));
    let mut pipeline = Pipeline::new(status, stop.clone());

    let interval = Duration::from_nanos(1_000_000_000 / fps.max(1) as u64);
    let handle = std::thread::Builder::new()
        .name("directdesk-demo".into())
        .spawn(move || {
            let start = Instant::now();
            let mut tick: u32 = 0;
            let mut next = Instant::now();
            while !stop.load(Ordering::Relaxed) {
                let frame = synth_frame(WIDTH, HEIGHT, tick, start.elapsed().as_millis() as u32);
                slot.publish(frame);
                repaint();
                tick = tick.wrapping_add(1);

                next += interval;
                let now = Instant::now();
                if next > now {
                    std::thread::sleep(next - now);
                } else {
                    next = now; // fell behind; do not spiral
                }
            }
            tracing::info!(frames = tick, "demo source exiting");
        })
        .expect("spawn demo thread");

    pipeline.threads.push(handle);
    pipeline
}

/// Animated gradient with a sweeping bar and a binary tick counter, so motion
/// and frame rate are verifiable by eye as well as by counter.
fn synth_frame(width: u32, height: u32, tick: u32, timestamp_ms: u32) -> RawFrame {
    let (w, h) = (width as usize, height as usize);
    let mut data = vec![0u8; w * h * 4];

    // Per-column values depend only on x — hoisted out of the pixel loop.
    let phase = tick % 256;
    let mut col_rb = vec![(0u8, 0u8); w];
    for (x, slot) in col_rb.iter_mut().enumerate() {
        let r = (x * 255 / w.max(1)) as u8;
        let b = (((x * 255 / w.max(1)) as u32 + phase) % 256) as u8;
        *slot = (r, b);
    }

    let bar = (tick as usize * 7) % w;
    let bar_end = (bar + 12).min(w);

    for y in 0..h {
        let g = (y * 255 / h.max(1)) as u8;
        let row = &mut data[y * w * 4..(y + 1) * w * 4];
        for (x, px) in row.chunks_exact_mut(4).enumerate() {
            let (r, b) = col_rb[x];
            px[0] = r;
            px[1] = g;
            px[2] = b;
            px[3] = 255;
        }
        // Sweeping white bar: unmistakable motion.
        for px in row[bar * 4..bar_end * 4].chunks_exact_mut(4) {
            px[0] = 255;
            px[1] = 255;
            px[2] = 255;
        }
    }

    // Binary tick counter along the top-left: 16 blocks, LSB first.
    for bit in 0..16u32 {
        let on = tick & (1 << bit) != 0;
        let x0 = 8 + bit as usize * 20;
        let x1 = (x0 + 16).min(w);
        for y in 8..24.min(h) {
            for x in x0..x1 {
                let i = (y * w + x) * 4;
                let v = if on { 255 } else { 24 };
                data[i] = v;
                data[i + 1] = v;
                data[i + 2] = v;
            }
        }
    }

    RawFrame {
        width,
        height,
        format: PixelFormat::Rgba8,
        data,
        timestamp_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use directdesk_shared::error::Error;
    use directdesk_shared::tiles::{compress_strip, TILE_EDGE};
    use directdesk_shared::traits::NullDecoder;
    use std::collections::VecDeque;

    /// A flat opaque frame, so any painted pixel is unmistakable.
    fn rgba_frame(width: u32, height: u32, timestamp_ms: u32) -> RawFrame {
        RawFrame {
            width,
            height,
            format: PixelFormat::Rgba8,
            data: vec![7u8; width as usize * height as usize * 4],
            timestamp_ms,
        }
    }

    /// A store armed for `w`x`h` holding one lossless tile at the origin.
    fn store_with_one_tile(w: u32, h: u32) -> Arc<TileStore> {
        let store = Arc::new(TileStore::new());
        store.apply(TileMsg::Reset {
            width: w,
            height: h,
            edge: TILE_EDGE,
        });
        // BGRA source; the shared codec swaps to RGBA at admission.
        let src = vec![200u8; w as usize * h as usize * 4];
        let (codec, data) =
            compress_strip(&src, w as usize * 4, 0, 0, TILE_EDGE, TILE_EDGE, 6).unwrap();
        let out = store.apply(TileMsg::Strip {
            x: 0,
            y: 0,
            w: TILE_EDGE,
            h: TILE_EDGE,
            codec,
            valid_from_ms: 0,
            lease_ms: 10_000,
            data,
        });
        assert_eq!(out.admitted, 1, "test fixture must admit its tile");
        store
    }

    #[test]
    fn composite_onto_is_a_noop_while_the_store_is_disarmed() {
        // The overwhelmingly common case: no host support, or a session that
        // has not been re-armed yet. It must not touch the decoded frame.
        let store = TileStore::new();
        let mut scratch = Vec::new();
        let mut frame = rgba_frame(64, 64, 0);
        let before = frame.data.clone();
        assert!(composite_onto(&mut frame, &store, &mut scratch, false).is_none());
        assert_eq!(frame.data, before);
    }

    #[test]
    fn composite_onto_refuses_a_frame_that_is_not_rgba() {
        let store = store_with_one_tile(64, 64);
        let mut scratch = Vec::new();

        let mut bgra = rgba_frame(64, 64, 5);
        bgra.format = PixelFormat::Bgra8;
        let before = bgra.data.clone();
        assert!(composite_onto(&mut bgra, &store, &mut scratch, false).is_none());
        assert_eq!(bgra.data, before, "a BGRA frame would be colour-swapped");

        // The identical frame as RGBA *is* painted — so it is the format guard
        // that stopped it above, not an empty store.
        let mut rgba = rgba_frame(64, 64, 5);
        let stats = composite_onto(&mut rgba, &store, &mut scratch, false).unwrap();
        assert_eq!(stats.painted, 1);
        assert_ne!(rgba.data, before);
    }

    #[test]
    fn composite_onto_paints_live_tiles_and_reuses_the_scratch_buffer() {
        let store = store_with_one_tile(128, 64);
        let mut scratch = Vec::new();

        let mut frame = rgba_frame(128, 64, 100);
        let stats = composite_onto(&mut frame, &store, &mut scratch, false).unwrap();
        assert_eq!(stats.painted, 1);
        assert_eq!(
            stats.covered_px,
            u64::from(TILE_EDGE) * u64::from(TILE_EDGE)
        );
        // Inside the tile is the lossless colour; outside is the frame's own.
        assert_eq!(&frame.data[0..4], &[200, 200, 200, 255]);
        assert_eq!(frame.data[(64 * 4) as usize], 7);

        // The snapshot buffer is reused, not regrown, on every subsequent frame.
        let capacity = scratch.capacity();
        assert_eq!(scratch.len(), 1);
        for ts in 101..110 {
            let mut next = rgba_frame(128, 64, ts);
            composite_onto(&mut next, &store, &mut scratch, false).unwrap();
        }
        assert_eq!(scratch.len(), 1);
        assert_eq!(
            scratch.capacity(),
            capacity,
            "steady state must not allocate"
        );
    }

    #[test]
    fn composite_onto_evicts_tiles_whose_lease_has_run_out() {
        // A frame timestamped past the lease leaves the decoded picture alone —
        // stale refinement is worse than none.
        //
        // And the tile is *evicted*, not merely skipped. The host stops
        // revoking a tile once its lease lapses, on the stated assumption that
        // the client has dropped it; leaving it resident would let a later
        // `Renew` revive pixels the host had written off. So the assertion here
        // is on `resident_tiles`, not on `skipped_expired` — by the time the
        // blit runs there is nothing left to skip.
        let store = store_with_one_tile(64, 64);
        assert_eq!(store.resident_tiles(), 1);

        let mut scratch = Vec::new();
        let mut frame = rgba_frame(64, 64, 50_000);
        let before = frame.data.clone();
        let stats = composite_onto(&mut frame, &store, &mut scratch, false).unwrap();
        assert_eq!(stats.painted, 0);
        assert_eq!(stats.skipped_expired, 0);
        assert_eq!(store.resident_tiles(), 0, "the lapsed tile must be gone");
        assert_eq!(frame.data, before);
    }

    /// Decoder test double: pops one canned response per call and counts
    /// `flush()`, so `DecodeLoop::handle_frame`'s error-recovery path is
    /// pinned without Media Foundation. `NullDecoder` (shared crate) covers
    /// the always-succeeds case; this covers the always-fails one.
    struct ScriptedDecoder {
        responses: VecDeque<directdesk_shared::error::Result<Vec<RawFrame>>>,
        flushes: Arc<AtomicU64>,
    }

    impl Decoder for ScriptedDecoder {
        fn decode(
            &mut self,
            frame: &EncodedFrame,
        ) -> directdesk_shared::error::Result<Vec<RawFrame>> {
            self.responses.pop_front().unwrap_or_else(|| {
                panic!(
                    "ScriptedDecoder ran out of scripted responses for frame {}",
                    frame.frame_id
                )
            })
        }

        fn flush(&mut self) {
            self.flushes.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Assemble a [`DecodeLoop`] directly from its fields, bypassing
    /// `DecodeLoop::new`'s `crate::decoder::new_decoder()` call so tests can
    /// hand it a test double instead of the real Media Foundation decoder.
    fn decode_loop_for_test<R: Fn() + Send + 'static>(
        decoder: Box<dyn Decoder>,
        status: Arc<SourceStatus>,
        control_tx: mpsc::Sender<ControlMsg>,
        slot: Arc<FrameSlot>,
        repaint: R,
    ) -> DecodeLoop<R> {
        DecodeLoop {
            decoder: Some(decoder),
            gate: KeyframeGate::default(),
            scratch: Vec::new(),
            status,
            tiles: Arc::new(TileStore::new()),
            tile_highlight: Arc::new(AtomicBool::new(false)),
            control_tx,
            slot,
            repaint,
        }
    }

    #[test]
    fn handle_frame_decodes_and_forwards_a_normal_frame() {
        // The common case: an admitted frame decodes cleanly and its output
        // reaches the slot with no keyframe request along the way.
        let slot = Arc::new(FrameSlot::new());
        let (control_tx, mut control_rx) = mpsc::channel(4);
        let mut decode_loop = decode_loop_for_test(
            Box::new(NullDecoder),
            Arc::new(SourceStatus::default()),
            control_tx,
            slot.clone(),
            || {},
        );

        decode_loop.handle_frame(EncodedFrame {
            frame_id: 1,
            keyframe: true,
            timestamp_ms: 42,
            data: vec![9, 9, 9, 9],
        });

        assert_eq!(slot.decoded_count(), 1);
        let (frame, _gen, _arrived) = slot.take_newer_than(0).expect("a frame was published");
        assert_eq!(frame.data, vec![9, 9, 9, 9]);
        assert_eq!(frame.timestamp_ms, 42);
        assert!(
            control_rx.try_recv().is_err(),
            "a clean decode must not ask for a keyframe"
        );
    }

    #[test]
    fn handle_frame_on_decode_error_flushes_and_requests_a_keyframe() {
        // Corrupt decoder state can only be recovered by a fresh IDR:
        // flushing alone would leave the decoder starved until the host
        // happens to send one, so the error path must also ask for it.
        let flushes = Arc::new(AtomicU64::new(0));
        let decoder = ScriptedDecoder {
            responses: VecDeque::from(vec![Err(Error::Decoder("boom".into()))]),
            flushes: flushes.clone(),
        };
        let status = Arc::new(SourceStatus::default());
        let slot = Arc::new(FrameSlot::new());
        let (control_tx, mut control_rx) = mpsc::channel(4);
        let mut decode_loop = decode_loop_for_test(
            Box::new(decoder),
            status.clone(),
            control_tx,
            slot.clone(),
            || {},
        );

        // Keyframe so the frame clears the gate and actually reaches decode().
        decode_loop.handle_frame(EncodedFrame {
            frame_id: 1,
            keyframe: true,
            timestamp_ms: 0,
            data: vec![],
        });

        assert_eq!(
            flushes.load(Ordering::Relaxed),
            1,
            "must flush on decode error"
        );
        assert!(
            matches!(control_rx.try_recv(), Ok(ControlMsg::RequestKeyframe)),
            "must ask the host for a fresh IDR"
        );
        assert_eq!(slot.decoded_count(), 0, "nothing was produced to publish");
        assert!(status.error().is_some());
    }

    #[test]
    fn recv_until_stopped_breaks_on_the_next_tick_once_stop_is_set() {
        // Pins the loop shape shared by both background threads in this
        // file (folded here from the near-identical recv_timeout blocks
        // that used to live in the tile thread and the decode thread): once
        // `stop` is set, the call must return on the next 100ms timeout
        // tick rather than hang waiting for a sender — no disconnect
        // required.
        let (tx, rx) = crossbeam_channel::unbounded::<u32>();
        let stop = AtomicBool::new(true);
        let mut received = Vec::new();

        recv_until_stopped(&rx, &stop, |item| received.push(item));

        assert!(received.is_empty(), "must not block waiting for an item");
        drop(tx); // kept alive across the call so this is Timeout, not Disconnected
    }

    #[test]
    fn tile_thread_applies_messages_and_stops_with_the_pipeline() {
        let mut pipeline = Pipeline::new(
            Arc::new(SourceStatus::default()),
            Arc::new(AtomicBool::new(false)),
        );
        let tiles = pipeline.tiles();
        let (tx, rx) = crossbeam_channel::bounded(8);
        pipeline.attach_tile_thread(rx);

        assert!(!tiles.is_armed());
        tx.send(TileMsg::Reset {
            width: 128,
            height: 64,
            edge: TILE_EDGE,
        })
        .unwrap();

        let deadline = Instant::now() + Duration::from_secs(3);
        while !tiles.is_armed() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(tiles.is_armed(), "tile thread must have applied the Reset");
        assert_eq!(tiles.store_size(), (128, 64));

        // Shares the pipeline's stop flag, so this returns rather than hanging.
        pipeline.shutdown();
    }

    #[test]
    fn tile_highlight_defaults_off_and_round_trips() {
        let pipeline = Pipeline::new(
            Arc::new(SourceStatus::default()),
            Arc::new(AtomicBool::new(false)),
        );
        assert!(!pipeline.tile_highlight(), "a diagnostic aid is opt-in");
        pipeline.set_tile_highlight(true);
        assert!(pipeline.tile_highlight());
    }

    #[test]
    fn synth_frame_is_well_formed_rgba() {
        let f = synth_frame(64, 32, 0, 0);
        assert_eq!(f.format, PixelFormat::Rgba8);
        assert_eq!(f.width, 64);
        assert_eq!(f.height, 32);
        assert_eq!(f.data.len(), 64 * 32 * 4);
        assert!(
            f.data.chunks_exact(4).all(|p| p[3] == 255),
            "must be opaque"
        );
    }

    #[test]
    fn synth_frame_actually_animates() {
        // If consecutive frames were identical the demo would prove nothing.
        let a = synth_frame(64, 32, 10, 0);
        let b = synth_frame(64, 32, 11, 33);
        assert_ne!(a.data, b.data);
    }

    #[test]
    fn keyframe_gate_admits_keyframe_and_resets() {
        let mut gate = KeyframeGate::default();
        assert_eq!(gate.admit(100, true), (true, false));
        assert_eq!(gate.last_id, Some(100));
        assert!(!gate.waiting);
    }

    #[test]
    fn keyframe_gate_admits_contiguous_deltas() {
        let mut gate = KeyframeGate::default();
        assert_eq!(gate.admit(1, true), (true, false));
        assert_eq!(gate.admit(2, false), (true, false));
        assert_eq!(gate.admit(3, false), (true, false));
        assert_eq!(gate.last_id, Some(3));
        assert!(!gate.waiting);
    }

    #[test]
    fn keyframe_gate_gap_requests_once_then_holds() {
        let mut gate = KeyframeGate::default();
        assert_eq!(gate.admit(1, true), (true, false));
        // Frame 2 is lost; frame 3 arrives next — a gap.
        assert_eq!(gate.admit(3, false), (false, true));
        assert!(gate.waiting);
        // Further deltas while waiting are dropped without re-requesting.
        assert_eq!(gate.admit(4, false), (false, false));
        assert_eq!(gate.admit(5, false), (false, false));
    }

    #[test]
    fn keyframe_gate_with_no_prior_chain_gaps_on_first_delta() {
        let mut gate = KeyframeGate::default();
        // A delta frame with no keyframe ever seen has no chain to extend.
        assert_eq!(gate.admit(42, false), (false, true));
        assert!(gate.waiting);
        assert_eq!(gate.admit(43, false), (false, false));
    }

    #[test]
    fn keyframe_gate_keyframe_after_gap_readmits() {
        let mut gate = KeyframeGate::default();
        assert_eq!(gate.admit(1, true), (true, false));
        assert_eq!(gate.admit(3, false), (false, true)); // gap -> waiting
        assert_eq!(gate.admit(4, false), (false, false)); // still waiting
        assert_eq!(gate.admit(50, true), (true, false)); // IDR readmits
        assert!(!gate.waiting);
        assert_eq!(gate.last_id, Some(50));
        // Chain resumes from the new keyframe.
        assert_eq!(gate.admit(51, false), (true, false));
    }

    #[test]
    fn keyframe_gate_wraps_at_u32_boundary() {
        let mut gate = KeyframeGate::default();
        assert_eq!(gate.admit(u32::MAX, true), (true, false));
        // u32::MAX.wrapping_add(1) == 0, so 0 is the contiguous successor.
        assert_eq!(gate.admit(0, false), (true, false));
        assert_eq!(gate.admit(1, false), (true, false));
        assert_eq!(gate.last_id, Some(1));
    }

    #[test]
    fn demo_source_pumps_frames_into_the_slot() {
        let slot = Arc::new(FrameSlot::new());
        let mut pipeline = spawn_demo_source(slot.clone(), 200, || {});
        let deadline = Instant::now() + Duration::from_secs(3);
        while slot.decoded_count() < 5 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        pipeline.shutdown();
        assert!(
            slot.decoded_count() >= 5,
            "only {} frames",
            slot.decoded_count()
        );
        assert_eq!(slot.remote_dims(), Some((1280, 720)));
    }
}
