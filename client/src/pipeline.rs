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
//! Further optional threads hang off the same [`Pipeline`]:
//!
//! * [`Pipeline::attach_tile_thread`] — feeds the lossless refinement store the
//!   decode thread composites from.
//! * [`Pipeline::attach_audio_thread`] — the system-audio playback path: jitter
//!   buffer, AAC-LC decoder, WASAPI endpoint, and the two controllers that keep
//!   the latency honest.
//! * [`Pipeline::attach_decode_thread`] — a second, independent decode path
//!   for the second monitor's video stream (own gate, own frame_id space,
//!   lazy decoder construction).
//! * [`Pipeline::attach_demo_thread`] — the demo twin of the above:
//!   `--demo-second-window` feeds the second monitor's slot a synthetic
//!   picture instead, so the second-window path is exercisable with no host.
//!
//! All of them share one stop flag and one join list, so [`Pipeline::shutdown`]
//! (and therefore `Drop`) covers every thread this module ever spawns.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, RecvTimeoutError};
use directdesk_shared::audio::jitter::{
    AudioJitterBuffer, DriftCorrection, DriftCorrector, JitterConfig,
};
use directdesk_shared::audio::{AudioFormat, AudioFrame, AudioPacket};
use directdesk_shared::error::{Error, Result};
use directdesk_shared::protocol::ControlMsg;
use directdesk_shared::tiles::TileMsg;
use directdesk_shared::traits::{Decoder, PixelFormat, RawFrame};
use directdesk_shared::video::EncodedFrame;
use parking_lot::Mutex;
use tokio::sync::mpsc;

use crate::audio_decoder::{new_audio_decoder, AudioDecode, AAC_FRAME_SAMPLES};
use crate::audio_render::{new_pcm_sink, PcmSink};
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
    /// Gauges published by the audio thread. Created unconditionally so the
    /// diagnostics panel has something to read whether or not audio was ever
    /// negotiated — it reports `None` until the first packet is handled, which
    /// is the honest answer for "we have measured nothing".
    audio: Arc<AudioStatus>,
}

impl Pipeline {
    fn new(status: Arc<SourceStatus>, stop: Arc<AtomicBool>) -> Self {
        Self {
            stop,
            threads: Vec::new(),
            status,
            tiles: Arc::new(TileStore::new()),
            tile_highlight: Arc::new(AtomicBool::new(false)),
            audio: Arc::new(AudioStatus::default()),
        }
    }

    /// What the audio thread has measured, or `None` if it has measured
    /// nothing yet (never attached, or no packet has arrived).
    pub fn audio_snapshot(&self) -> Option<AudioSnapshot> {
        self.audio.snapshot()
    }

    /// The last audio decoder / endpoint failure, if there was one. A session
    /// with audio degraded to silence says so here rather than only in the log.
    pub fn audio_error(&self) -> Option<String> {
        self.audio.error()
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

    /// Spawn the thread that plays inbound system audio.
    ///
    /// A thread of its own for the same two reasons the tile thread is one, and
    /// a third that is specific to audio. Playback is paced by a clock that has
    /// nothing to do with the video frame rate — one AAC-LC access unit every
    /// ~21 ms — so pacing it off the decode loop would make every dropped video
    /// frame an audible glitch. Media Foundation's AAC decoder and WASAPI's
    /// render client are both COM objects with thread-affine apartments, so
    /// they want a thread whose whole life they own. And a wedged audio path
    /// must not be able to stall the picture, which is the whole reason audio
    /// is treated as a bonus layer end to end (see `net::forward_audio`).
    ///
    /// Joins with the rest of the pipeline: same stop flag, same `threads` vec,
    /// so [`Pipeline::shutdown`] (and therefore `Drop`) already covers it.
    ///
    /// Safe to call on a session that never negotiated audio: the channel
    /// simply stays empty and the thread parks on the 100 ms poll in
    /// [`recv_until_stopped`], building no decoder and opening no endpoint
    /// (both are constructed lazily, from the first packet's format).
    pub fn attach_audio_thread(&mut self, audio_rx: Receiver<AudioFrame>) {
        let status = self.audio.clone();
        let stop = self.stop.clone();
        let handle = std::thread::Builder::new()
            .name("directdesk-audio".into())
            .spawn(move || {
                let mut audio = AudioLoop::new(status);
                recv_until_stopped(&audio_rx, &stop, |frame| audio.handle_frame(frame));
                audio.shutdown();
                tracing::info!("audio thread exiting");
            })
            .expect("spawn audio thread");
        self.threads.push(handle);
    }

    /// Spawn a **second** decode thread for the second monitor's video stream.
    ///
    /// The stream-1 twin of [`spawn_decode_thread`]'s thread, attached to the
    /// pipeline that already owns stream 0 so one stop flag and one join list
    /// still cover every thread this module spawns. Returns that stream's own
    /// [`SourceStatus`] — the caller keeps it for per-stream diagnostics, since
    /// [`Pipeline::status`] belongs to stream 0 and merging the two would make
    /// every gauge a lie about both.
    ///
    /// Three properties make this safe to attach unconditionally at startup,
    /// which is what lets `main` wire it once instead of racing the handshake:
    ///
    /// * **Its own [`DecodeLoop`]**, hence its own [`KeyframeGate`] and its own
    ///   `frame_id` space. The two streams are two independent encoders; a gap
    ///   on one must never gate the other.
    /// * **A fresh, empty [`TileStore`]** rather than `self.tiles`. The store is
    ///   never armed (only stream 0's `Reset` arms one, and that one is a
    ///   different object), so `composite_onto` returns early on every frame —
    ///   the "lossless refinement tiles are stream-0 only" rule costs zero new
    ///   code and cannot be violated by a host that sends tiles anyway.
    /// * **A lazily built decoder** (see [`DecodeLoop::ensure_decoder`]): a
    ///   single-monitor session never receives a stream-1 frame, so it never
    ///   builds a second Media Foundation MFT or enters a second COM apartment.
    ///   The thread costs one parked 100 ms poll, exactly like the audio thread
    ///   on a session that never negotiated audio.
    pub fn attach_decode_thread(
        &mut self,
        video_rx: Receiver<EncodedFrame>,
        slot: Arc<FrameSlot>,
        control_tx: mpsc::Sender<ControlMsg>,
        repaint: impl Fn() + Send + 'static,
    ) -> Arc<SourceStatus> {
        let status = Arc::new(SourceStatus::default());
        let thread_status = status.clone();
        let stop = self.stop.clone();
        // Deliberately NOT `self.tiles`: see the doc comment above.
        let tiles = Arc::new(TileStore::new());
        let tile_highlight = Arc::new(AtomicBool::new(false));
        let handle = std::thread::Builder::new()
            .name("directdesk-decode-1".into())
            .spawn(move || {
                let mut decode_loop = DecodeLoop::new(
                    crate::decoder::new_decoder,
                    thread_status,
                    tiles,
                    tile_highlight,
                    slot,
                    control_tx,
                    repaint,
                );
                recv_until_stopped(&video_rx, &stop, |frame| decode_loop.handle_frame(frame));
                tracing::info!("second decode thread exiting");
            })
            .expect("spawn second decode thread");
        self.threads.push(handle);
        status
    }

    /// Spawn a **second** synthetic source for `--demo-second-window`: the
    /// demo twin of [`Pipeline::attach_decode_thread`], riding this
    /// pipeline's existing stop flag and join list (so
    /// [`Pipeline::shutdown`], and therefore `Drop`, already covers it) with
    /// its own [`SourceStatus`] so the second window's diagnostics are never
    /// a lie about the first window's.
    ///
    /// Exists to prove the second-window / second-slot path — open, focus,
    /// close, per-stream diagnostics, the periodic log line — with no
    /// transport and no host at all. `--loopback-demo` already does this for
    /// the primary window; this extends the same idea to the second one.
    pub fn attach_demo_thread(
        &mut self,
        slot: Arc<FrameSlot>,
        fps: u32,
        repaint: impl Fn() + Send + 'static,
    ) -> Arc<SourceStatus> {
        let status = Arc::new(SourceStatus::default());
        let handle = spawn_demo_thread(
            slot,
            fps,
            DemoPattern::Secondary,
            status.clone(),
            self.stop.clone(),
            repaint,
        );
        self.threads.push(handle);
        status
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
            let mut decode_loop = DecodeLoop::new(
                crate::decoder::new_decoder,
                status,
                tiles,
                tile_highlight,
                slot,
                control_tx,
                repaint,
            );
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
/// How a [`DecodeLoop`] obtains its decoder, called at most once, on the first
/// frame that reaches it.
///
/// A plain `fn` pointer for the same reason [`OpenSink`] is one: the production
/// build sets it once, from a path that never captures, so it should not cost an
/// allocation — and it gives the tests a seam to count constructions with,
/// which is the only way "no decoder is built until the first frame" is
/// observable at all.
type NewDecoder = fn() -> Result<Box<dyn Decoder>>;

/// A [`DecodeLoop`]'s decoder, which does not exist until the first frame.
enum DecoderState {
    /// Nothing has arrived yet, so nothing has been built. The whole point of
    /// the second decode path: a single-monitor session parks here forever.
    NotBuilt,
    Ready(Box<dyn Decoder>),
    /// Construction was attempted and failed (e.g. a platform without Media
    /// Foundation). Every frame is then a no-op, same as before the build
    /// became lazy — and, importantly, it is never retried: a decoder that
    /// cannot be created will not start working on frame 200, and retrying
    /// would turn one logged error into one per frame.
    Unavailable,
}

struct DecodeLoop<R> {
    decoder: DecoderState,
    /// Deferred construction, see [`NewDecoder`] and
    /// [`DecodeLoop::ensure_decoder`].
    new_decoder: NewDecoder,
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

/// What [`SourceStatus::description`] reads before the first frame has arrived.
///
/// The decoder is built lazily, so there is genuinely nothing measured to
/// report yet — and the diagnostics panel's HONESTY RULE means saying so beats
/// naming a Media Foundation MFT that has not been created.
const DECODER_PENDING: &str = "H.264 — decoder is created on the first frame";

impl<R: Fn() + Send + 'static> DecodeLoop<R> {
    fn new(
        new_decoder: NewDecoder,
        status: Arc<SourceStatus>,
        tiles: Arc<TileStore>,
        tile_highlight: Arc<AtomicBool>,
        slot: Arc<FrameSlot>,
        control_tx: mpsc::Sender<ControlMsg>,
        repaint: R,
    ) -> Self {
        status.set_description(DECODER_PENDING.to_string());
        Self {
            decoder: DecoderState::NotBuilt,
            new_decoder,
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

    /// Build the decoder if this is the first frame, and report whether one is
    /// available at all.
    ///
    /// Deferring construction out of [`DecodeLoop::new`] is what makes a second
    /// decode thread free to attach unconditionally: a session that streams one
    /// monitor never receives a stream-1 frame, so it never pays for a second MF
    /// H.264 MFT or a second COM apartment. Construction happens **on the decode
    /// thread**, which is also where it has to happen — the MFT's apartment is
    /// thread-affine (see `decoder.rs`), so building it from the spawning thread
    /// would be wrong regardless of cost.
    ///
    /// Idempotent and non-retrying: exactly one attempt is ever made.
    fn ensure_decoder(&mut self) -> bool {
        if matches!(self.decoder, DecoderState::NotBuilt) {
            self.decoder = match (self.new_decoder)() {
                Ok(d) => {
                    #[cfg(windows)]
                    self.status.set_description(
                        "MF H.264 (CLSID_MSH264DecoderMFT), NV12→RGBA8 BT.709 limited".to_string(),
                    );
                    #[cfg(not(windows))]
                    self.status.set_description("H.264 decoder".to_string());
                    DecoderState::Ready(d)
                }
                Err(e) => {
                    tracing::error!("decoder unavailable: {e}");
                    self.status.set_description("unavailable".to_string());
                    self.status.set_error(Some(e.to_string()));
                    DecoderState::Unavailable
                }
            };
        }
        matches!(self.decoder, DecoderState::Ready(_))
    }

    /// Handle one received encoded frame end to end.
    ///
    /// Keyframe-gates it, decodes it, composites the live refinement tiles
    /// onto every decoded picture, and publishes each to the slot. A gate
    /// gap and a decode error both recover the same way: flush the decoder
    /// and ask the host for a fresh keyframe (see
    /// [`flush_and_request_keyframe`]).
    fn handle_frame(&mut self, frame: EncodedFrame) {
        if !self.ensure_decoder() {
            return;
        }

        let (admitted, request_keyframe_now) = self.gate.admit(frame.frame_id, frame.keyframe);
        // `ensure_decoder` just returned true, so this always matches. Matching
        // rather than unwrapping is what splits the borrow of `self.decoder`
        // from `self.gate` above and `self.status` / `self.slot` below.
        let DecoderState::Ready(decoder) = &mut self.decoder else {
            return;
        };
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

// ---------------------------------------------------------------------------
// System audio
// ---------------------------------------------------------------------------

/// What the audio thread has actually measured.
///
/// Every number here is one this client observed itself; there is no host side
/// to the audio panel. The `Option` fields are `None` when the thing that would
/// produce them does not exist — no endpoint was opened, say — so the
/// diagnostics panel can honour its HONESTY RULE and render "—" instead of a
/// zero that reads as a measurement.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AudioSnapshot {
    /// Network-domain jitter buffer occupancy, ms.
    pub buffered_ms: u32,
    /// The depth controller's current target for that occupancy, ms.
    pub target_ms: u32,
    /// Access units handed to the jitter buffer, accepted or not.
    pub packets_received: u64,
    /// Access units the jitter buffer handed back in order.
    pub packets_delivered: u64,
    /// Sequence numbers that never arrived, or arrived too late to be used.
    pub lost: u64,
    /// Access units that arrived behind the jitter buffer's read point and were
    /// dropped unplayed.
    ///
    /// Ordinarily a small number on a reordering link and nothing to act on.
    /// It is published because it is the **only** gauge that moves in the one
    /// failure mode that is otherwise completely silent: a peer that emits a
    /// `seq` far ahead of its own stream (a host bug — QUIC authenticates these,
    /// so it is not an injected datagram) seeds the buffer's read point at that
    /// value, and every genuine packet after it reads late forever. In that
    /// state `underruns` does not move, the depth target *decays* as if all were
    /// well, `packets_received` keeps climbing, and audio is simply gone. With
    /// this row, "received rising, delivered flat, late rising in lockstep" says
    /// it outright. See `AudioJitterBuffer`'s "known limitation" docs.
    pub late: u64,
    /// Times the jitter buffer was asked for audio and had none.
    pub underruns: u64,
    /// Times the endpoint buffer was found dry at write time. `None` when no
    /// endpoint was ever opened — which is a different fact from "opened and
    /// never underran", and must not render as the same number.
    pub device_underruns: Option<u64>,
    /// Output latency read from the endpoint, ms. `None` for the same reason.
    pub device_latency_ms: Option<u32>,
    /// Frames dropped or inserted to correct clock drift, both domains.
    pub drift_corrections: u64,
}

/// Shared audio gauges: written by the audio thread, read by the UI.
///
/// The audio mirror of [`SourceStatus`], but built on one `Mutex<Option<_>>`
/// rather than a spread of atomics. The whole snapshot is published at once so
/// the panel can never show a depth from one packet next to a packet count from
/// another, and `None` — the state before the first packet — is representable,
/// which a pile of `AtomicU64`s cannot do without inventing a sentinel.
#[derive(Default)]
pub struct AudioStatus {
    snapshot: Mutex<Option<AudioSnapshot>>,
    description: Mutex<String>,
    error: Mutex<Option<String>>,
}

impl AudioStatus {
    /// The latest published gauges, or `None` before the first packet.
    pub fn snapshot(&self) -> Option<AudioSnapshot> {
        *self.snapshot.lock()
    }

    /// Human-readable decoder/endpoint description, empty before either exists.
    pub fn description(&self) -> String {
        self.description.lock().clone()
    }

    pub fn error(&self) -> Option<String> {
        self.error.lock().clone()
    }

    fn publish(&self, snapshot: AudioSnapshot) {
        *self.snapshot.lock() = Some(snapshot);
    }

    fn set_description(&self, text: impl Into<String>) {
        *self.description.lock() = text.into();
    }

    fn set_error(&self, text: Option<String>) {
        *self.error.lock() = text;
    }
}

/// The one place this crate reads an [`AudioFrame`]'s access unit.
///
/// Both the jitter buffer (which wants a borrowed [`AudioPacket`]) and the
/// decoder (which wants `&[u8]`) need these bytes, and the frame type is shared
/// with the transport, so the field is named exactly once.
#[inline]
fn access_unit(frame: &AudioFrame) -> &[u8] {
    &frame.data
}

/// Hand one decoded frame to the endpoint, dropping whatever did not fit.
///
/// [`PcmSink::write`] deliberately does not buffer — a second ring in front of
/// the endpoint would add latency `GetCurrentPadding` cannot see, and that
/// number is exactly what the drift corrector steers on — so it takes what fits
/// and leaves the rest with us. A short write therefore means the endpoint
/// buffer is genuinely full, i.e. we are ~400 ms behind; holding the remainder
/// would only push us further behind, so it is dropped. Whole frames only, so a
/// drop cannot rotate the channel assignment of everything after it.
///
/// A short write is normal and returns `Ok`. An `Err` is not: it means the
/// endpoint stopped accepting audio altogether, which on Windows is what
/// plugging in headphones looks like from here. That is a fact about the
/// device, not about this frame, so it is returned rather than logged — see
/// [`AudioLoop::write_to_sink`], which is the only caller and which retires the
/// endpoint on it.
fn write_pcm(sink: &mut dyn PcmSink, pcm: &[i16]) -> Result<()> {
    if pcm.is_empty() {
        return Ok(());
    }
    let frames = sink.write(pcm)?;
    let channels = usize::from(sink.format().channels()).max(1);
    let offered = pcm.len() / channels;
    if (frames as usize) < offered {
        tracing::trace!(
            taken = frames,
            offered,
            "endpoint buffer full; dropping the tail of an audio frame"
        );
    }
    Ok(())
}

/// First delay before re-opening a render endpoint that faulted.
///
/// Deliberately the same 500 ms / 15 s pair as the host's capture-side rebuild
/// loop (`host::net::audio::REBUILD_BACKOFF_MIN`/`MAX`): the two sides are
/// recovering from the same class of event — a WASAPI endpoint invalidated by a
/// device change — and there is no reason for them to disagree about how eager
/// to be about it.
const SINK_REOPEN_BACKOFF_MIN_MS: u64 = 500;
/// Ceiling on that backoff. A client with no playback device at all must not
/// spend the session retrying, but a headset plugged in two minutes into a call
/// must start working without a reconnect.
const SINK_REOPEN_BACKOFF_MAX_MS: u64 = 15_000;

/// How a replacement render endpoint is opened.
///
/// Always [`new_pcm_sink`] in production. It is a field rather than a direct
/// call for the same reason `AudioLoop` takes its decoder and sink as trait
/// objects: so `audio_loop_for_test` can drive the fault-and-recover path
/// headless. Without the seam the re-open — the part most likely to be wrong,
/// because "retry forever at packet rate" is the obvious mistake — would be the
/// one piece of this loop no test could reach.
type OpenSink = fn(AudioFormat) -> Result<Box<dyn PcmSink>>;

/// Per-packet audio state, owned by the audio thread for its whole life.
///
/// The audio mirror of [`DecodeLoop`], split out for the same reason: so the
/// whole playback path — jitter buffer, decoder, endpoint, and the two
/// controllers that steer them — is drivable from a test with no Media
/// Foundation, no WASAPI and no host. See `audio_loop_for_test`.
///
/// # Which buffer the drift corrector watches, and why it is not the obvious one
///
/// There are two elastic buffers here, and only one of them carries clock drift
/// in *this* architecture. [`AudioJitterBuffer`] owns the network-domain one and
/// runs a [`DriftCorrector`] over its own occupancy — but that corrector is
/// specified for a caller that pops **once per DAC period**. This loop is
/// **packet driven**: pops happen because a datagram arrived, not because a
/// playback clock ticked. `handle_frame_at` therefore holds that window at its
/// depth target explicitly, by draining to it on every arrival; see the pacing
/// contract documented there and on [`AudioJitterBuffer`] itself. Occupancy
/// consequently does not move with the crystals — it moves only when the depth
/// controller moves the target. The difference between the host's capture clock
/// and this machine's DAC clock accumulates in the *device-domain* buffer
/// instead — the endpoint is filled at the host's rate and emptied at ours —
/// which is exactly what [`PcmSink::padding_frames`] reports.
///
/// (An earlier version of this comment claimed the window's occupancy was
/// "pinned at whatever the prebuffer filled it to and never moves" as a
/// *consequence* of packet pacing. It is not: packet pacing on its own makes
/// occupancy a ratchet in both directions. It is pinned because the drain in
/// `handle_frame_at` pins it, and that is load-bearing rather than incidental.)
///
/// This loop therefore runs its own [`DriftCorrector`] over the endpoint's
/// latency and acts on that, and deliberately does **not** act on the `drift`
/// half of [`AudioJitterBuffer::observe`]'s return. That is a knowing departure
/// from [`DriftCorrection`]'s "a command, not advice" contract, and the reason
/// is that obeying it here is not conservative but actively wrong: with the
/// window sitting a little under the target — which is the *normal* state, the
/// prebuffer level is `target` minus the one packet just popped — the
/// network-domain corrector reads a permanent shallow excursion and would
/// command a 21 ms silence insertion every two seconds, forever. That is a
/// click every two seconds bought by measuring the wrong buffer. The depth
/// controller half of the same call **is** consumed: an underrun is a real
/// event on the real window, and the target it produces is what the
/// device-domain corrector steers towards.
///
/// The consequence is that `JitterStats::drift_drops` / `drift_inserts` count
/// commands this loop did not obey, so [`AudioSnapshot::drift_corrections`]
/// reports only the corrections that were actually applied. Counting the
/// unobeyed ones would put a number in the panel that no audio ever passed
/// through.
struct AudioLoop {
    jitter: AudioJitterBuffer,
    /// `None` when no decoder could be built for the current format. Every
    /// packet is then a no-op — exactly how [`DecodeLoop`] treats a missing
    /// video decoder. Audio degrades to silence; it never panics, and it never
    /// ends the thread.
    decoder: Option<Box<dyn AudioDecode>>,
    /// `None` when no endpoint could be opened, or when a live one faulted.
    /// Unlike the decoder this one is retried — see `try_reopen_sink`.
    sink: Option<Box<dyn PcmSink>>,
    /// How `sink` gets (re)built. See [`OpenSink`].
    open_sink: OpenSink,
    /// When `sink` may next be re-opened, on this loop's clock. `None` means
    /// there is nothing to re-open: either the endpoint is live, or no format
    /// has been seen yet.
    sink_retry_at_ms: Option<u64>,
    /// Current re-open delay, doubled on each failed attempt and reset on
    /// success. The whole point of the pair: without it, a client whose default
    /// endpoint has gone would re-open it at packet rate — fifty attempts a
    /// second, each one a COM activation.
    sink_backoff_ms: u64,
    /// The format `decoder` and `sink` were built for, `None` before the first
    /// packet. Construction is necessarily lazy: both are bound to one format
    /// for life, and the format arrives *with* a packet (it is a per-packet
    /// header field, not a stream announcement).
    format: Option<AudioFormat>,
    /// Device-domain corrector — see the type's docs.
    drift: DriftCorrector,
    /// Set by `PushOutcome::BufferedFlushDecoder`; consumed immediately before
    /// the next decode rather than on the spot, so a packet the drift corrector
    /// drops cannot swallow the flush.
    flush_pending: bool,
    /// Set by [`DriftCorrection::DropFrame`]; consumed by the next pop.
    drop_pending: bool,
    /// Device-domain corrections actually applied. The network-domain ones are
    /// already counted inside `JitterStats`.
    device_corrections: u64,
    /// Origin for the monotonic `now_ms` the two controllers are clocked on.
    epoch: Instant,
    status: Arc<AudioStatus>,
}

impl AudioLoop {
    fn new(status: Arc<AudioStatus>) -> Self {
        let config = JitterConfig::default();
        Self {
            jitter: AudioJitterBuffer::new(config),
            decoder: None,
            sink: None,
            open_sink: new_pcm_sink,
            sink_retry_at_ms: None,
            sink_backoff_ms: SINK_REOPEN_BACKOFF_MIN_MS,
            format: None,
            drift: DriftCorrector::new(&config),
            flush_pending: false,
            drop_pending: false,
            device_corrections: 0,
            epoch: Instant::now(),
            status,
        }
    }

    /// Handle one received access unit, on the loop's own monotonic clock.
    fn handle_frame(&mut self, frame: AudioFrame) {
        let now_ms = self.epoch.elapsed().as_millis() as u64;
        self.handle_frame_at(now_ms, frame);
    }

    /// [`AudioLoop::handle_frame`] with the clock injected.
    ///
    /// Split out for the same reason every timed decision in
    /// `directdesk_shared::audio::jitter` takes `now_ms`: the depth controller
    /// decays over ten seconds and the drift corrector samples every two, so a
    /// test that could not move the clock could not reach either of them.
    fn handle_frame_at(&mut self, now_ms: u64, frame: AudioFrame) {
        self.ensure_format(now_ms, frame.format);
        self.try_reopen_sink(now_ms);

        // The jitter buffer speaks the *wire* type, which borrows its payload;
        // the channel hands us the owned one. Rebuilding the borrowed view here
        // copies nothing and preserves the buffer's "allocate only on
        // acceptance" property — a duplicate or a late arrival still costs no
        // allocation at all.
        let packet = AudioPacket {
            seq: frame.seq,
            capture_ms: frame.capture_ms,
            discontinuity: frame.discontinuity,
            format: frame.format,
            payload: access_unit(&frame),
        };
        let outcome = self.jitter.push(&packet);
        if outcome.needs_decoder_flush() {
            // AAC-LC carries filterbank overlap from the previous frame, so
            // running the decoder across a capture gap smears instead of
            // cutting. The window also just emptied for a reason that has
            // nothing to do with anyone's crystal, so the device-domain
            // corrector must re-seed rather than read the gap as drift.
            self.flush_pending = true;
            self.drift.reset();
        }

        // --- The pacing contract ------------------------------------------
        //
        // THIS BUFFER IS PACKET DRIVEN HERE, NOT DAC DRIVEN. `pop` happens
        // because a datagram arrived, not because a playback clock ticked —
        // the real playback clock is four hundred milliseconds downstream,
        // inside WASAPI's render buffer, and this thread never sees it tick.
        // `AudioJitterBuffer`'s docs spell the contract out; both halves of it
        // are here because each one is a shipped bug if it is dropped.
        //
        // 1. Pop only for a packet that was ACCEPTED. A discard is not a period
        //    of audio. `system_audio_redundancy` re-sends packet N-1 behind
        //    packet N, so half of all arrivals are duplicates by design; a pop
        //    per arrival would run two pops against one push, drain the
        //    prebuffer in ~85 ms, starve, refill in silence and repeat. The
        //    feature that exists to repair a lossy link would chop the audio
        //    several times a second on exactly the links it was turned on for.
        //
        // 2. Then KEEP POPPING while the window is above its depth target. Every
        //    period the buffer withholds — a 40 ms reorder wait around a lost
        //    packet — is a push with no matching pop, and without a catch-up
        //    path that packet of occupancy is permanent: a packet-paced consumer
        //    can otherwise never take two in one period. It ratchets, ~2 packets
        //    per loss, until the window is full, and only a reconnect clears it.
        //    Draining costs nothing: it moves audio from the network buffer into
        //    the device buffer, which is where a packet-paced caller wants its
        //    slack anyway. It discards nothing.
        //
        // The drain is gated on having actually played something. If the buffer
        // is withholding it has already said so — once — by counting a starve;
        // asking again inside the same arrival would report the same silent
        // period twice and inflate the number the diagnostics panel shows.
        //
        // Termination: every iteration either pops (which strictly shrinks the
        // window) or breaks.
        //
        // Popped frames are bound to a local rather than used as an `if let`
        // scrutinee: the buffer's borrow must end before `play` takes
        // `&mut self` again.
        let mut played = false;
        if outcome.was_buffered() {
            let popped = self.jitter.pop(now_ms);
            if let Some(popped) = popped {
                self.play(now_ms, popped);
                played = true;
            }
        }
        while played && self.jitter.buffered_ms() > self.jitter.target_ms() as f32 {
            let popped = self.jitter.pop(now_ms);
            let Some(popped) = popped else { break };
            self.play(now_ms, popped);
        }

        // The depth controller, once per packet. `observe` also consumes the
        // buffer's underrun flag, so it must run every period whether or not
        // anything popped — a period that starved is precisely the one it needs
        // to hear about. Its `drift` half is discarded on purpose; see this
        // type's docs for which buffer actually carries drift here.
        let adjust = self.jitter.observe(now_ms);
        if let Some(target_ms) = adjust.target_ms {
            tracing::debug!(target_ms, "audio jitter depth target moved");
        }

        // The drift corrector, steering the *endpoint's* fill towards the depth
        // controller's target. `latency_ms` is derived from `padding_frames`,
        // which is the endpoint's real queue depth rather than an estimate, so
        // there is nothing here to model or to get wrong.
        let device_latency_ms = self.sink.as_ref().and_then(|s| s.latency_ms().ok());
        let target_ms = self.jitter.target_ms();
        let device_drift =
            device_latency_ms.and_then(|ms| self.drift.observe(now_ms, ms as f32, target_ms));
        match device_drift {
            Some(DriftCorrection::DropFrame) => {
                // Deferred to the next pop rather than done here: the packet
                // for this period has already been played.
                self.drop_pending = true;
                self.device_corrections += 1;
            }
            Some(DriftCorrection::InsertSilence) => {
                self.insert_silence(now_ms);
                self.device_corrections += 1;
            }
            None => {}
        }

        self.publish(device_latency_ms);
    }

    /// Build (or rebuild) the decoder and endpoint for `format`.
    ///
    /// A format change mid-session is the ordinary path, not an exception — the
    /// operator moving the host's default output to a Bluetooth headset changes
    /// the capture mix underneath us — and the answer to it is a new decoder
    /// and a new render stream, because an MFT's input type and an
    /// `IAudioClient`'s `WAVEFORMATEX` are both fixed for the object's life.
    ///
    /// Neither failure ends the thread: the loop runs on as a no-op sink. That
    /// mirrors how [`DecodeLoop::new`] handles `new_decoder()` failing, and it
    /// is the only acceptable policy for a layer the session does not depend on.
    /// `self.format` is set even on failure, so a host streaming a format this
    /// machine cannot play does not re-attempt (and re-log) fifty times a
    /// second.
    ///
    /// The two failures are then treated differently, and deliberately so:
    ///
    /// * A **decoder** failure is permanent. There is no such thing as an AAC
    ///   MFT that turns up halfway through a call, so it is logged once and
    ///   that is the end of it.
    /// * An **endpoint** failure is not. "No default render endpoint" is the
    ///   state of a laptop whose user has not plugged their headset in yet, and
    ///   it resolves on its own. It is handed to `try_reopen_sink`, which
    ///   retries behind a backoff — the same answer the host's capture side
    ///   already gives to the same condition.
    fn ensure_format(&mut self, now_ms: u64, format: AudioFormat) {
        if self.format == Some(format) {
            return;
        }
        if let Some(sink) = self.sink.as_mut() {
            tracing::info!(
                "audio format changed to {} Hz {} ch; rebuilding decoder and endpoint",
                format.sample_rate(),
                format.channels()
            );
            if let Err(e) = sink.stop() {
                tracing::debug!("stopping the old audio endpoint failed: {e}");
            }
        }
        // Release the old pair before building the new one, so two render
        // streams are never open on the same endpoint at once.
        self.decoder = None;
        self.sink = None;
        self.format = Some(format);
        self.flush_pending = false;
        self.drop_pending = false;
        self.drift.reset();
        self.sink_backoff_ms = SINK_REOPEN_BACKOFF_MIN_MS;
        self.sink_retry_at_ms = None;

        match new_audio_decoder(format) {
            Ok(decoder) => {
                self.status.set_description(decoder.describe());
                self.decoder = Some(decoder);
            }
            Err(e) => {
                tracing::error!("audio decoder unavailable: {e}");
                self.status.set_description("unavailable");
                self.status.set_error(Some(e.to_string()));
            }
        }
        match self.open_started_sink(format) {
            Ok(sink) => self.sink = Some(sink),
            Err(e) => {
                tracing::error!("audio endpoint unavailable: {e}");
                self.status.set_error(Some(e.to_string()));
                self.schedule_sink_retry(now_ms);
            }
        }
    }

    /// Open an endpoint for `format` and start it, as one fallible step.
    ///
    /// A sink that opened but would not start is not a sink: leaving it in
    /// `self.sink` would give the loop something that accepts writes and plays
    /// none of them, which is worse than no endpoint at all because the
    /// diagnostics would show one.
    fn open_started_sink(&self, format: AudioFormat) -> Result<Box<dyn PcmSink>> {
        let mut sink = (self.open_sink)(format)?;
        sink.start()?;
        Ok(sink)
    }

    /// Arm the next re-open attempt and widen the backoff for the one after.
    fn schedule_sink_retry(&mut self, now_ms: u64) {
        self.sink_retry_at_ms = Some(now_ms.saturating_add(self.sink_backoff_ms));
        self.sink_backoff_ms = (self.sink_backoff_ms * 2).min(SINK_REOPEN_BACKOFF_MAX_MS);
    }

    /// The endpoint stopped accepting audio. Retire it and arrange a re-open.
    ///
    /// This is the client's half of a condition the host has always handled:
    /// `AUDCLNT_E_DEVICE_INVALIDATED` and its relatives (see
    /// `host::audio_capture::is_recoverable_hresult`) are what plugging in
    /// headphones, connecting a Bluetooth headset, an exclusive-mode application
    /// seizing the device, or the Windows Audio service restarting look like
    /// from inside a live `IAudioClient`. Every one of them is followed moments
    /// later by a perfectly good *new* default endpoint. The host drops its
    /// capture stream and builds another; until now this loop logged a line and
    /// carried on writing into a dead handle for the rest of the session — about
    /// fifty warn lines a second, with `audio_error` still `None` and the packet
    /// counters still climbing, so the diagnostics panel showed a healthy stream
    /// playing to nobody.
    ///
    /// The HRESULT is deliberately not inspected. By the time an error reaches
    /// here the endpoint has already refused audio, and the recovery for "the
    /// device went away" and for "this device is broken" is the same move: drop
    /// it, try again later, back off if later keeps failing. Classifying would
    /// buy a way to give up permanently, which is not an improvement.
    ///
    /// Re-opening is deliberately *not* done by clearing `self.format`. That
    /// would route recovery back through `ensure_format`, which runs on every
    /// packet — so a client with no endpoint would attempt a COM activation ~48
    /// times a second, forever, and rebuild a perfectly good decoder each time.
    fn fault_sink(&mut self, now_ms: u64, e: Error) {
        let text = e.to_string();
        tracing::warn!("audio endpoint failed ({text}); closing it and retrying");
        self.status.set_error(Some(text));
        if let Some(sink) = self.sink.as_mut() {
            if let Err(e) = sink.stop() {
                tracing::debug!("stopping the failed audio endpoint: {e}");
            }
        }
        self.sink = None;
        self.schedule_sink_retry(now_ms);
    }

    /// Re-open a faulted endpoint, at most once per backoff interval.
    fn try_reopen_sink(&mut self, now_ms: u64) {
        if self.sink.is_some() {
            return;
        }
        let (Some(due), Some(format)) = (self.sink_retry_at_ms, self.format) else {
            return;
        };
        if now_ms < due {
            return;
        }
        match self.open_started_sink(format) {
            Ok(sink) => {
                tracing::info!("audio endpoint re-opened");
                self.sink = Some(sink);
                self.sink_retry_at_ms = None;
                self.sink_backoff_ms = SINK_REOPEN_BACKOFF_MIN_MS;
                // The new endpoint is empty and the device-domain corrector's
                // average describes a buffer that no longer exists; feeding it
                // the new one's near-zero fill would read as an enormous
                // negative drift.
                self.drift.reset();
                // Clearing the whole error is safe rather than optimistic: the
                // only other producer is a decode failure, and a decoder that
                // is still failing re-reports on the very next access unit.
                self.status.set_error(None);
            }
            Err(e) => {
                // Debug, not warn: this repeats until the device comes back,
                // and the state is already visible as `audio_error` plus the
                // `None` device gauges.
                tracing::debug!("audio endpoint still unavailable: {e}");
                self.status.set_error(Some(e.to_string()));
                self.schedule_sink_retry(now_ms);
            }
        }
    }

    /// Play `pcm`, retiring the endpoint if it has stopped accepting audio.
    ///
    /// The one place PCM meets the device, so the one place a device fault can
    /// be noticed. `insert_silence` goes through it for exactly that reason: a
    /// silence insertion is a real write to a real endpoint and can fail the
    /// same way.
    fn write_to_sink(&mut self, now_ms: u64, pcm: &[i16]) {
        // The result is taken out before anything else touches `self`, so the
        // borrow of `self.sink` ends before `fault_sink` needs `&mut self`.
        let result = match self.sink.as_mut() {
            Some(sink) => write_pcm(&mut **sink, pcm),
            None => return,
        };
        if let Err(e) = result {
            self.fault_sink(now_ms, e);
        }
    }

    /// Decode one popped access unit and play it.
    fn play(&mut self, now_ms: u64, popped: AudioFrame) {
        if self.drop_pending {
            // The drift corrector asked for one frame of audio to disappear.
            // Discarding it before the decoder is the cheapest of the places
            // `DriftCorrection::DropFrame` permits. The pending flush is
            // deliberately *not* consumed here: the next packet still needs it.
            self.drop_pending = false;
            return;
        }
        let Some(decoder) = self.decoder.as_mut() else {
            return;
        };
        if self.flush_pending {
            decoder.flush();
            self.flush_pending = false;
        }
        let pcm = match decoder.submit(access_unit(&popped)) {
            Ok(pcm) => pcm,
            Err(e) => {
                // One bad access unit is one click. AAC-LC frames are
                // independently decodable, so there is nothing to recover and
                // nothing to ask the host for — the next packet decodes on its
                // own.
                tracing::warn!(seq = popped.seq, "audio decode failed: {e}");
                self.status.set_error(Some(e.to_string()));
                return;
            }
        };
        self.write_to_sink(now_ms, &pcm);
    }

    /// Play one frame period of silence without consuming a packet — the other
    /// half of [`DriftCorrection`]'s accounting.
    fn insert_silence(&mut self, now_ms: u64) {
        let Some(format) = self.format else {
            return;
        };
        if self.sink.is_none() {
            return;
        }
        // One AAC-LC frame: 1024 samples per channel, 21.33 ms at 48 kHz — the
        // unit `DriftCorrection` accounts in.
        let silence = vec![0i16; AAC_FRAME_SAMPLES * usize::from(format.channels())];
        self.write_to_sink(now_ms, &silence);
    }

    fn publish(&self, device_latency_ms: Option<u32>) {
        let stats = self.jitter.stats();
        self.status.publish(AudioSnapshot {
            buffered_ms: self.jitter.buffered_ms().round() as u32,
            target_ms: self.jitter.target_ms(),
            packets_received: stats.received,
            packets_delivered: stats.delivered,
            lost: stats.lost,
            late: stats.late,
            underruns: stats.underrun,
            device_underruns: self.sink.as_ref().map(|sink| sink.underruns()),
            device_latency_ms,
            // Applied, not commanded — see the type docs. `stats.drift_drops`
            // and `stats.drift_inserts` are the network-domain corrector's
            // unobeyed commands and are deliberately not summed in.
            drift_corrections: self.device_corrections,
        });
    }

    /// Stop the endpoint on the way out. Whatever is still queued is left in
    /// place; the stream is about to be released anyway.
    fn shutdown(&mut self) {
        if let Some(sink) = self.sink.as_mut() {
            if let Err(e) = sink.stop() {
                tracing::debug!("audio endpoint stop failed: {e}");
            }
        }
    }
}

/// Which synthetic picture a demo thread paints.
///
/// Exists solely so `--demo-second-window` can feed the second monitor's
/// frame slot a picture nobody could mistake for the primary window's — a
/// mirrored gradient with the animated channel swapped, and the sweep bar
/// reversed in both direction and colour — without needing a real second
/// monitor, a second decoder, or a second host stream. The underlying motion
/// (tick-driven gradient + sweep + binary counter) is otherwise identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DemoPattern {
    /// `--loopback-demo`'s primary window.
    Primary,
    /// `--demo-second-window`'s second window.
    Secondary,
}

impl DemoPattern {
    fn thread_name(self) -> &'static str {
        match self {
            DemoPattern::Primary => "directdesk-demo",
            DemoPattern::Secondary => "directdesk-demo-1",
        }
    }

    /// Prefix for [`SourceStatus::description`], so the diagnostics panel
    /// and the log both say which window's synthetic source this is —
    /// mirrors [`DECODER_PENDING`]'s job on the real decode path.
    fn description_prefix(self) -> &'static str {
        match self {
            DemoPattern::Primary => "loopback demo",
            DemoPattern::Secondary => "loopback demo (2nd window)",
        }
    }
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
    let status = Arc::new(SourceStatus::default());
    let stop = Arc::new(AtomicBool::new(false));
    let mut pipeline = Pipeline::new(status.clone(), stop.clone());
    let handle = spawn_demo_thread(slot, fps, DemoPattern::Primary, status, stop, repaint);
    pipeline.threads.push(handle);
    pipeline
}

/// The synthetic-source thread body, shared by [`spawn_demo_source`] (which
/// mints the primary window's own [`Pipeline`]) and
/// [`Pipeline::attach_demo_thread`] (a second source riding the primary
/// pipeline's existing stop flag and join list — the demo twin of
/// [`Pipeline::attach_decode_thread`]).
fn spawn_demo_thread(
    slot: Arc<FrameSlot>,
    fps: u32,
    pattern: DemoPattern,
    status: Arc<SourceStatus>,
    stop: Arc<AtomicBool>,
    repaint: impl Fn() + Send + 'static,
) -> JoinHandle<()> {
    const WIDTH: u32 = 1280;
    const HEIGHT: u32 = 720;
    status.set_description(format!(
        "{}: synthetic RGBA {WIDTH}x{HEIGHT} @ {fps} fps (decoder BYPASSED)",
        pattern.description_prefix()
    ));

    let interval = Duration::from_nanos(1_000_000_000 / fps.max(1) as u64);
    std::thread::Builder::new()
        .name(pattern.thread_name().into())
        .spawn(move || {
            let start = Instant::now();
            let mut tick: u32 = 0;
            let mut next = Instant::now();
            while !stop.load(Ordering::Relaxed) {
                let frame = synth_frame(
                    WIDTH,
                    HEIGHT,
                    tick,
                    start.elapsed().as_millis() as u32,
                    pattern,
                );
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
            tracing::info!(
                frames = tick,
                pattern = format_args!("{pattern:?}"),
                "demo source exiting"
            );
        })
        .expect("spawn demo thread")
}

/// Animated gradient with a sweeping bar and a binary tick counter, so motion
/// and frame rate are verifiable by eye as well as by counter.
///
/// `pattern` mirrors the x-axis gradient, swaps which channel phase-shifts,
/// and reverses the sweep bar's direction and colour for
/// [`DemoPattern::Secondary`] — see the type's doc for why.
fn synth_frame(
    width: u32,
    height: u32,
    tick: u32,
    timestamp_ms: u32,
    pattern: DemoPattern,
) -> RawFrame {
    let (w, h) = (width as usize, height as usize);
    let mut data = vec![0u8; w * h * 4];
    let mirrored = pattern == DemoPattern::Secondary;

    // Per-column values depend only on x — hoisted out of the pixel loop.
    let phase = tick % 256;
    let mut col_rb = vec![(0u8, 0u8); w];
    for (x, slot) in col_rb.iter_mut().enumerate() {
        let gx = if mirrored { w.saturating_sub(1) - x } else { x };
        let base = (gx * 255 / w.max(1)) as u8;
        let animated = (((gx * 255 / w.max(1)) as u32 + phase) % 256) as u8;
        // Primary animates blue; Secondary mirrors x AND animates red
        // instead — a colour swap on top of the mirror, so the two pictures
        // are never a simple rotation of one another.
        *slot = if mirrored {
            (animated, base)
        } else {
            (base, animated)
        };
    }

    let sweep = (tick as usize * 7) % w;
    let bar = if mirrored {
        w.saturating_sub(1).saturating_sub(sweep)
    } else {
        sweep
    };
    let bar_end = (bar + 12).min(w);
    // White sweeping right for Primary; cyan sweeping left for Secondary.
    let bar_color: [u8; 3] = if mirrored {
        [0, 220, 255]
    } else {
        [255, 255, 255]
    };

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
        // Sweeping bar: unmistakable motion, and its colour/direction is the
        // other half of what tells the two windows apart at a glance.
        for px in row[bar * 4..bar_end * 4].chunks_exact_mut(4) {
            px[0] = bar_color[0];
            px[1] = bar_color[1];
            px[2] = bar_color[2];
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
    use crate::audio_decoder::NullAudioDecoder;
    use crate::audio_render::{ms_to_frames, RecordingSink};
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
            decoder: DecoderState::Ready(decoder),
            // Already `Ready`, so `ensure_decoder` must never reach for this.
            // Panicking rather than returning something usable is what makes
            // "the injected double is the decoder that ran" an assertion
            // instead of an assumption.
            new_decoder: || panic!("a DecodeLoop handed a decoder must not build another"),
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

    thread_local! {
        /// How many times [`counting_new_decoder`] has been called on this
        /// thread. Same thread-local seam (and same rationale) as
        /// `OPEN_FAILURES` below: [`NewDecoder`] is a plain `fn` pointer, which
        /// cannot capture, and libtest gives each `#[test]` its own thread.
        static DECODERS_BUILT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
        /// Whether [`counting_new_decoder`] should fail instead of succeeding.
        static DECODER_BUILD_FAILS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    fn counting_new_decoder() -> directdesk_shared::error::Result<Box<dyn Decoder>> {
        DECODERS_BUILT.with(|c| c.set(c.get() + 1));
        if DECODER_BUILD_FAILS.with(|c| c.get()) {
            return Err(Error::Decoder("no H.264 decoder (test)".into()));
        }
        Ok(Box::new(NullDecoder))
    }

    fn decoders_built() -> u32 {
        DECODERS_BUILT.with(|c| c.get())
    }

    fn reset_decoder_seam(fails: bool) {
        DECODERS_BUILT.with(|c| c.set(0));
        DECODER_BUILD_FAILS.with(|c| c.set(fails));
    }

    /// A [`DecodeLoop`] that has **not** built its decoder yet, so the laziness
    /// itself is under test rather than assumed. The counterpart to
    /// [`decode_loop_for_test`], which injects a ready-made one.
    fn lazy_decode_loop_for_test<R: Fn() + Send + 'static>(
        status: Arc<SourceStatus>,
        control_tx: mpsc::Sender<ControlMsg>,
        slot: Arc<FrameSlot>,
        repaint: R,
    ) -> DecodeLoop<R> {
        DecodeLoop::new(
            counting_new_decoder,
            status,
            Arc::new(TileStore::new()),
            Arc::new(AtomicBool::new(false)),
            slot,
            control_tx,
            repaint,
        )
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
    fn no_decoder_is_built_until_the_first_frame_arrives() {
        // The property that makes a second decode thread free to attach at
        // startup: a single-monitor session never gets a stream-1 frame, so it
        // must never pay for a second Media Foundation MFT or COM apartment.
        reset_decoder_seam(false);
        let slot = Arc::new(FrameSlot::new());
        let status = Arc::new(SourceStatus::default());
        let (control_tx, _control_rx) = mpsc::channel(4);
        let mut decode_loop =
            lazy_decode_loop_for_test(status.clone(), control_tx, slot.clone(), || {});

        assert_eq!(decoders_built(), 0, "construction must not happen in new()");
        assert_eq!(
            status.description(),
            DECODER_PENDING,
            "the panel must say what is actually true before the first frame"
        );
        assert!(status.error().is_none());

        decode_loop.handle_frame(EncodedFrame {
            frame_id: 1,
            keyframe: true,
            timestamp_ms: 0,
            data: vec![1, 2, 3, 4],
        });
        assert_eq!(decoders_built(), 1, "the first frame builds the decoder");
        assert_eq!(slot.decoded_count(), 1);
        assert_ne!(
            status.description(),
            DECODER_PENDING,
            "the description must be replaced once something real exists"
        );

        // Every later frame reuses it — a per-frame construction would be a
        // catastrophic regression that still passed a "decodes a frame" test.
        decode_loop.handle_frame(EncodedFrame {
            frame_id: 2,
            keyframe: false,
            timestamp_ms: 1,
            data: vec![5, 6, 7, 8],
        });
        assert_eq!(decoders_built(), 1, "the decoder is built at most once");
        assert_eq!(slot.decoded_count(), 2);
    }

    #[test]
    fn a_decoder_that_cannot_be_built_is_tried_once_and_reported() {
        // Laziness must not turn "no decoder on this platform" into a silent
        // failure, nor into one construction attempt (and one log line) per
        // frame for the rest of the session.
        reset_decoder_seam(true);
        let slot = Arc::new(FrameSlot::new());
        let status = Arc::new(SourceStatus::default());
        let (control_tx, mut control_rx) = mpsc::channel(4);
        let mut decode_loop =
            lazy_decode_loop_for_test(status.clone(), control_tx, slot.clone(), || {});

        for frame_id in 1..=3 {
            decode_loop.handle_frame(EncodedFrame {
                frame_id,
                keyframe: true,
                timestamp_ms: 0,
                data: vec![9; 4],
            });
        }

        assert_eq!(decoders_built(), 1, "a failed build is never retried");
        assert_eq!(status.description(), "unavailable");
        assert!(status.error().is_some(), "the failure must be visible");
        assert_eq!(slot.decoded_count(), 0, "every frame is a no-op");
        assert!(
            control_rx.try_recv().is_err(),
            "a missing decoder is not something a keyframe can fix"
        );
        reset_decoder_seam(false);
    }

    #[test]
    fn two_decode_loops_gate_their_streams_independently() {
        // The two video streams are two independent encoders with two
        // independent `frame_id` spaces. If they shared a `KeyframeGate`,
        // stream 1's ids would read as a permanent gap in stream 0 and each
        // stream would gate the other into a frozen picture.
        let slot0 = Arc::new(FrameSlot::new());
        let slot1 = Arc::new(FrameSlot::new());
        let status0 = Arc::new(SourceStatus::default());
        let status1 = Arc::new(SourceStatus::default());
        let (tx0, mut rx0) = mpsc::channel(4);
        let (tx1, mut rx1) = mpsc::channel(4);
        let mut loop0 = decode_loop_for_test(
            Box::new(NullDecoder),
            status0.clone(),
            tx0,
            slot0.clone(),
            || {},
        );
        let mut loop1 = decode_loop_for_test(
            Box::new(NullDecoder),
            status1.clone(),
            tx1,
            slot1.clone(),
            || {},
        );

        // Stream 0 opens with an IDR and continues contiguously.
        loop0.handle_frame(EncodedFrame {
            frame_id: 100,
            keyframe: true,
            timestamp_ms: 0,
            data: vec![1; 4],
        });
        loop0.handle_frame(EncodedFrame {
            frame_id: 101,
            keyframe: false,
            timestamp_ms: 1,
            data: vec![2; 4],
        });

        // Stream 1 has not seen its own IDR yet, so its deltas are refused —
        // interleaved with, and using ids adjacent to, stream 0's.
        loop1.handle_frame(EncodedFrame {
            frame_id: 101,
            keyframe: false,
            timestamp_ms: 0,
            data: vec![3; 4],
        });
        loop1.handle_frame(EncodedFrame {
            frame_id: 102,
            keyframe: false,
            timestamp_ms: 1,
            data: vec![4; 4],
        });

        assert_eq!(slot0.decoded_count(), 2, "stream 0 is unaffected");
        assert_eq!(status0.frames_gated(), 0);
        assert!(
            rx0.try_recv().is_err(),
            "stream 0 must not be dragged into stream 1's recovery"
        );

        assert_eq!(slot1.decoded_count(), 0, "stream 1 has no reference chain");
        assert_eq!(status1.frames_gated(), 2);
        assert!(
            matches!(rx1.try_recv(), Ok(ControlMsg::RequestKeyframe)),
            "stream 1 asks for its own IDR"
        );

        // And stream 1 recovers on its own IDR without touching stream 0.
        loop1.handle_frame(EncodedFrame {
            frame_id: 7,
            keyframe: true,
            timestamp_ms: 2,
            data: vec![5; 4],
        });
        assert_eq!(slot1.decoded_count(), 1);
        assert_eq!(slot0.decoded_count(), 2);
    }

    #[test]
    fn the_second_decode_thread_is_inert_and_has_its_own_status() {
        // Attaching the second decode path unconditionally at startup is only
        // safe if a session that never streams a second monitor pays nothing
        // for it: no decoder, no frames, no shared diagnostics.
        let (video_tx, video_rx) = crossbeam_channel::unbounded::<EncodedFrame>();
        let (control_tx, _control_rx) = mpsc::channel(4);
        let slot2 = Arc::new(FrameSlot::new());
        let mut pipeline = Pipeline::new(
            Arc::new(SourceStatus::default()),
            Arc::new(AtomicBool::new(false)),
        );
        let status1 = pipeline.attach_decode_thread(video_rx, slot2.clone(), control_tx, || {});

        assert!(
            !Arc::ptr_eq(&pipeline.status, &status1),
            "stream 1 must not publish into stream 0's gauges"
        );
        // No frame was ever sent, so the thread parked on its poll without
        // building anything. `shutdown` joins it, which is also what makes
        // this assertion race-free.
        pipeline.shutdown();
        assert_eq!(slot2.decoded_count(), 0);
        assert_eq!(status1.description(), DECODER_PENDING);
        assert!(status1.error().is_none());
        drop(video_tx);
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

    // -- system audio ------------------------------------------------------

    /// Share a test double with the [`AudioLoop`] that owns it.
    ///
    /// The loop takes its decoder and sink as `Box<dyn _>`, which a test cannot
    /// look back inside afterwards. These two wrappers hand the loop a handle
    /// and keep one, so assertions can be made against the *real* doubles —
    /// `NullAudioDecoder` and `RecordingSink`, with their real whole-frame
    /// rules and admission arithmetic — rather than against a stub written to
    /// make the test pass.
    #[derive(Clone)]
    struct SharedNullDecoder(Arc<Mutex<NullAudioDecoder>>);

    impl SharedNullDecoder {
        fn new(format: AudioFormat) -> Self {
            Self(Arc::new(Mutex::new(NullAudioDecoder::new(format))))
        }
        fn submits(&self) -> u64 {
            self.0.lock().submits()
        }
        fn flushes(&self) -> u64 {
            self.0.lock().flushes()
        }
    }

    impl AudioDecode for SharedNullDecoder {
        fn submit(&mut self, access_unit: &[u8]) -> directdesk_shared::error::Result<Vec<i16>> {
            self.0.lock().submit(access_unit)
        }
        fn flush(&mut self) {
            self.0.lock().flush();
        }
        fn format(&self) -> AudioFormat {
            self.0.lock().format()
        }
        fn describe(&self) -> String {
            self.0.lock().describe()
        }
    }

    #[derive(Clone)]
    struct SharedSink(Arc<Mutex<RecordingSink>>);

    impl SharedSink {
        fn new(format: AudioFormat) -> Self {
            Self(Arc::new(Mutex::new(RecordingSink::new(format))))
        }
        fn written(&self) -> Vec<i16> {
            self.0.lock().written().to_vec()
        }
        /// Queue a full endpoint buffer of audio, i.e. 400 ms of output
        /// latency. What a client whose DAC crystal runs slow looks like after
        /// a few hours of drift.
        fn prefill(&self) {
            let mut inner = self.0.lock();
            inner.start().unwrap();
            let frames = inner.buffer_frames() as usize;
            let channels = usize::from(inner.format().channels());
            let taken = inner.write(&vec![0i16; frames * channels]).unwrap();
            assert_eq!(taken as usize, frames, "the prefill must fill the buffer");
        }

        /// Queue `ms` of output latency, so the device-domain drift corrector
        /// starts *inside* its deadband. A long run that starts at zero latency
        /// walks there by inserting silence, which is correct behaviour and
        /// pure noise in a test about something else.
        fn prefill_ms(&self, ms: u32) {
            let mut inner = self.0.lock();
            inner.start().unwrap();
            let frames = ms_to_frames(ms, inner.format().sample_rate()) as usize;
            let channels = usize::from(inner.format().channels());
            inner.write(&vec![0i16; frames * channels]).unwrap();
        }

        /// Simulate the audio engine playing `frames` out of the endpoint.
        fn drain(&self, frames: u32) {
            self.0.lock().drain(frames);
        }
    }

    impl PcmSink for SharedSink {
        fn format(&self) -> AudioFormat {
            self.0.lock().format()
        }
        fn buffer_frames(&self) -> u32 {
            self.0.lock().buffer_frames()
        }
        fn padding_frames(&self) -> directdesk_shared::error::Result<u32> {
            self.0.lock().padding_frames()
        }
        fn write(&mut self, pcm: &[i16]) -> directdesk_shared::error::Result<u32> {
            self.0.lock().write(pcm)
        }
        fn start(&mut self) -> directdesk_shared::error::Result<()> {
            self.0.lock().start()
        }
        fn stop(&mut self) -> directdesk_shared::error::Result<()> {
            self.0.lock().stop()
        }
        fn underruns(&self) -> u64 {
            self.0.lock().underruns()
        }
        fn describe(&self) -> String {
            self.0.lock().describe()
        }
    }

    /// An [`AudioDecode`] that refuses every access unit, counting the attempts.
    /// `NullAudioDecoder` covers the always-succeeds case; this covers the
    /// always-fails one, exactly as `ScriptedDecoder` does for video.
    struct FailingAudioDecoder {
        format: AudioFormat,
        submits: Arc<AtomicU64>,
    }

    impl AudioDecode for FailingAudioDecoder {
        fn submit(&mut self, _access_unit: &[u8]) -> directdesk_shared::error::Result<Vec<i16>> {
            self.submits.fetch_add(1, Ordering::Relaxed);
            Err(Error::Decoder("boom".into()))
        }
        fn flush(&mut self) {}
        fn format(&self) -> AudioFormat {
            self.format
        }
        fn describe(&self) -> String {
            "always fails (test double)".into()
        }
    }

    /// A sink that plays normally until [`FaultingSink::kill`], then refuses
    /// everything — which is exactly what a live `IAudioClient` does the moment
    /// its endpoint is invalidated underneath it, whether by headphones going
    /// in, a Bluetooth headset connecting, an exclusive-mode application
    /// seizing the device, or the Windows Audio service restarting.
    #[derive(Clone)]
    struct FaultingSink {
        inner: SharedSink,
        dead: Arc<AtomicBool>,
        /// Writes refused since the fault. The number that must stop moving:
        /// the old loop wrote into the dead handle ~48 times a second for the
        /// rest of the session.
        refusals: Arc<AtomicU64>,
    }

    impl FaultingSink {
        fn new(format: AudioFormat) -> Self {
            Self {
                inner: SharedSink::new(format),
                dead: Arc::new(AtomicBool::new(false)),
                refusals: Arc::new(AtomicU64::new(0)),
            }
        }
        fn kill(&self) {
            self.dead.store(true, Ordering::Relaxed);
        }
        fn refusals(&self) -> u64 {
            self.refusals.load(Ordering::Relaxed)
        }
        fn invalidated() -> Error {
            Error::Other("audio render: device invalidated (test)".into())
        }
    }

    impl PcmSink for FaultingSink {
        fn format(&self) -> AudioFormat {
            self.inner.format()
        }
        fn buffer_frames(&self) -> u32 {
            self.inner.buffer_frames()
        }
        fn padding_frames(&self) -> directdesk_shared::error::Result<u32> {
            if self.dead.load(Ordering::Relaxed) {
                return Err(Self::invalidated());
            }
            self.inner.padding_frames()
        }
        fn write(&mut self, pcm: &[i16]) -> directdesk_shared::error::Result<u32> {
            if self.dead.load(Ordering::Relaxed) {
                self.refusals.fetch_add(1, Ordering::Relaxed);
                return Err(Self::invalidated());
            }
            self.inner.write(pcm)
        }
        fn start(&mut self) -> directdesk_shared::error::Result<()> {
            self.inner.start()
        }
        fn stop(&mut self) -> directdesk_shared::error::Result<()> {
            // Stopping an invalidated client fails too, which is the path that
            // must be logged rather than propagated.
            if self.dead.load(Ordering::Relaxed) {
                return Err(Self::invalidated());
            }
            self.inner.stop()
        }
        fn underruns(&self) -> u64 {
            self.inner.underruns()
        }
        fn describe(&self) -> String {
            "faulting endpoint (test double)".into()
        }
    }

    thread_local! {
        /// Sinks [`test_open_sink`] has handed out, oldest first.
        ///
        /// [`OpenSink`] is a plain `fn` pointer — a field the production build
        /// sets once should not cost an allocation — and a `fn` cannot capture,
        /// so the tests' side channel is a thread-local. Each `#[test]` runs on
        /// its own thread, so no two share one.
        static OPENED_SINKS: std::cell::RefCell<Vec<SharedSink>> =
            const { std::cell::RefCell::new(Vec::new()) };
        /// Opens [`test_open_sink`] should fail before it starts succeeding —
        /// a client with no default render endpoint yet.
        static OPEN_FAILURES: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
        /// Opens attempted, successful or not.
        static OPEN_ATTEMPTS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    }

    fn test_open_sink(format: AudioFormat) -> directdesk_shared::error::Result<Box<dyn PcmSink>> {
        OPEN_ATTEMPTS.with(|c| c.set(c.get() + 1));
        let remaining = OPEN_FAILURES.with(|c| c.get());
        if remaining > 0 {
            OPEN_FAILURES.with(|c| c.set(remaining - 1));
            return Err(Error::Other(
                "audio render: no default endpoint (test)".into(),
            ));
        }
        let sink = SharedSink::new(format);
        OPENED_SINKS.with(|s| s.borrow_mut().push(sink.clone()));
        Ok(Box::new(sink))
    }

    fn open_attempts() -> u32 {
        OPEN_ATTEMPTS.with(|c| c.get())
    }

    /// Clear the seam's thread-local state and arm `failures` failed opens.
    ///
    /// Belt and braces: libtest normally gives every test its own thread, but
    /// `--test-threads=1` does not, and a counter leaked from a previous test
    /// would fail these in a way that looks exactly like a bug in the code under
    /// test rather than in the fixture.
    fn reset_open_sink_seam(failures: u32) {
        OPENED_SINKS.with(|s| s.borrow_mut().clear());
        OPEN_FAILURES.with(|c| c.set(failures));
        OPEN_ATTEMPTS.with(|c| c.set(0));
    }

    fn opened_sinks() -> usize {
        OPENED_SINKS.with(|s| s.borrow().len())
    }

    fn opened_sink(index: usize) -> SharedSink {
        OPENED_SINKS.with(|s| s.borrow()[index].clone())
    }

    /// Assemble an [`AudioLoop`] directly from its fields, bypassing
    /// `AudioLoop::ensure_format`'s calls into Media Foundation and WASAPI so a
    /// test can hand it `NullAudioDecoder` + `RecordingSink` instead. The audio
    /// twin of `decode_loop_for_test`, and the whole reason the playback path
    /// is exercisable headless.
    fn audio_loop_for_test(
        format: AudioFormat,
        decoder: Option<Box<dyn AudioDecode>>,
        sink: Option<Box<dyn PcmSink>>,
    ) -> AudioLoop {
        // `prebuffer: false` for the same reason `jitter.rs`'s own `plain()`
        // fixture turns it off: these tests are about the decode/play chain,
        // and leaving the prebuffer in would make every one of them also a
        // latency test with four packets of setup before anything happens.
        // `audio_loop_with_config` is for the tests that must run the shipped
        // default instead, prebuffer and all.
        let config = JitterConfig {
            prebuffer: false,
            ..JitterConfig::default()
        };
        audio_loop_with_config(config, format, decoder, sink)
    }

    fn audio_loop_with_config(
        config: JitterConfig,
        format: AudioFormat,
        decoder: Option<Box<dyn AudioDecode>>,
        sink: Option<Box<dyn PcmSink>>,
    ) -> AudioLoop {
        AudioLoop {
            jitter: AudioJitterBuffer::new(config),
            decoder,
            sink,
            // Never `new_pcm_sink`: a re-open in a test must reach a double,
            // for exactly the reason `format` is pre-set below.
            open_sink: test_open_sink,
            sink_retry_at_ms: None,
            sink_backoff_ms: SINK_REOPEN_BACKOFF_MIN_MS,
            // Pre-set, so `ensure_format` short-circuits and the real platform
            // constructors are never reached.
            format: Some(format),
            drift: DriftCorrector::new(&config),
            flush_pending: false,
            drop_pending: false,
            device_corrections: 0,
            epoch: Instant::now(),
            status: Arc::new(AudioStatus::default()),
        }
    }

    /// One access unit, as it arrives from the transport.
    fn au(seq: u32, format: AudioFormat) -> AudioFrame {
        AudioFrame {
            seq,
            capture_ms: seq.wrapping_mul(21),
            discontinuity: false,
            format,
            data: vec![0xDE, 0xAD],
        }
    }

    #[test]
    fn an_access_unit_flows_from_the_jitter_buffer_through_the_decoder_into_the_sink() {
        let format = AudioFormat::Stereo48k;
        let decoder = SharedNullDecoder::new(format);
        let sink = SharedSink::new(format);
        let mut audio = audio_loop_for_test(
            format,
            Some(Box::new(decoder.clone())),
            Some(Box::new(sink.clone())),
        );

        audio.handle_frame_at(0, au(0, format));

        assert_eq!(decoder.submits(), 1, "the popped unit reached the decoder");
        let written = sink.written();
        assert_eq!(
            written.len(),
            AAC_FRAME_SAMPLES * 2,
            "one AAC frame of interleaved stereo PCM reached the endpoint"
        );
        assert!(
            written.iter().any(|&s| s != 0),
            "the decoder's ramp must arrive; a zeroed buffer would pass a \
             length check while proving nothing was ever written"
        );

        let snap = audio.status.snapshot().expect("gauges are published");
        assert_eq!(snap.packets_received, 1);
        assert_eq!(snap.packets_delivered, 1);
        assert_eq!(snap.lost, 0);
        assert_eq!(snap.underruns, 0);
        assert_eq!(snap.device_underruns, Some(0));

        // And it keeps flowing: three more units, three more frames of PCM,
        // appended in order rather than replacing what was there.
        for seq in 1..4u32 {
            audio.handle_frame_at(u64::from(seq) * 21, au(seq, format));
        }
        assert_eq!(decoder.submits(), 4);
        assert_eq!(sink.written().len(), 4 * AAC_FRAME_SAMPLES * 2);
        assert_eq!(
            audio.status.snapshot().unwrap().packets_delivered,
            4,
            "every unit was delivered, none held or lost"
        );
    }

    #[test]
    fn a_discontinuity_flushes_the_decoder_before_the_next_access_unit() {
        let format = AudioFormat::Stereo48k;
        let decoder = SharedNullDecoder::new(format);
        let sink = SharedSink::new(format);
        let mut audio = audio_loop_for_test(
            format,
            Some(Box::new(decoder.clone())),
            Some(Box::new(sink.clone())),
        );

        audio.handle_frame_at(0, au(0, format));
        assert_eq!(decoder.flushes(), 0, "an ordinary packet must not flush");

        // The host restarted capture: the stream we were following is gone, and
        // the decoder still holds filterbank overlap from before the gap.
        let mut gap = au(1, format);
        gap.discontinuity = true;
        audio.handle_frame_at(21, gap);

        assert_eq!(
            decoder.flushes(),
            1,
            "the pre-gap samples must be dropped, not played after the gap"
        );
        assert_eq!(
            decoder.submits(),
            2,
            "and the post-gap unit is still decoded — AAC-LC frames are \
             independently decodable, so there is no keyframe-style wait"
        );

        // Once, not on every packet that follows.
        audio.handle_frame_at(42, au(2, format));
        assert_eq!(decoder.flushes(), 1);
        assert_eq!(decoder.submits(), 3);
    }

    #[test]
    fn a_decoder_failure_degrades_to_silence_without_stopping_the_thread() {
        let format = AudioFormat::Mono48k;
        let submits = Arc::new(AtomicU64::new(0));
        let sink = SharedSink::new(format);
        let mut audio = audio_loop_for_test(
            format,
            Some(Box::new(FailingAudioDecoder {
                format,
                submits: submits.clone(),
            })),
            Some(Box::new(sink.clone())),
        );

        for seq in 0..8u32 {
            audio.handle_frame_at(u64::from(seq) * 21, au(seq, format));
        }

        assert_eq!(
            submits.load(Ordering::Relaxed),
            8,
            "every unit was still offered — the loop did not give up"
        );
        assert!(
            sink.written().is_empty(),
            "a failing decoder produces silence, never noise"
        );
        assert!(
            audio.status.error().is_some(),
            "and the failure is reported, not swallowed"
        );
        let snap = audio.status.snapshot().expect("gauges are published");
        assert_eq!(snap.packets_received, 8, "the pump kept pumping");
        assert_eq!(snap.packets_delivered, 8);

        // The other failure shape — no decoder at all, as on a machine without
        // Media Foundation — must behave identically rather than panic.
        let quiet_sink = SharedSink::new(format);
        let mut headless = audio_loop_for_test(format, None, Some(Box::new(quiet_sink.clone())));
        for seq in 0..4u32 {
            headless.handle_frame_at(u64::from(seq) * 21, au(seq, format));
        }
        assert!(quiet_sink.written().is_empty());
        assert_eq!(headless.status.snapshot().unwrap().packets_delivered, 4);

        // And with neither decoder nor endpoint the loop still runs and still
        // publishes honest gauges: no endpoint means no number, not a zero.
        let mut deaf = audio_loop_for_test(format, None, None);
        deaf.handle_frame_at(0, au(0, format));
        let snap = deaf.status.snapshot().unwrap();
        assert_eq!(snap.device_underruns, None);
        assert_eq!(snap.device_latency_ms, None);
        assert_eq!(snap.packets_delivered, 1);
    }

    /// The judgment call in [`AudioLoop`]'s docs, pinned: the corrector reads
    /// the *endpoint's* fill, not the jitter window's, and one excursion buys
    /// exactly one dropped frame.
    #[test]
    fn a_deep_endpoint_buffer_drops_exactly_one_frame_of_audio() {
        let format = AudioFormat::Stereo48k;
        let decoder = SharedNullDecoder::new(format);
        let sink = SharedSink::new(format);
        sink.prefill(); // 400 ms queued, far past the deadband's deep edge

        let mut audio = audio_loop_for_test(
            format,
            Some(Box::new(decoder.clone())),
            Some(Box::new(sink.clone())),
        );

        // One sample is not evidence of drift: the first observation only seeds
        // the average.
        audio.handle_frame_at(0, au(0, format));
        assert_eq!(decoder.submits(), 1);
        assert_eq!(audio.status.snapshot().unwrap().drift_corrections, 0);

        // Two seconds on, the corrector has its second sample and commands a
        // drop — but this period's packet has already played.
        audio.handle_frame_at(2_000, au(1, format));
        assert_eq!(decoder.submits(), 2);
        assert_eq!(audio.status.snapshot().unwrap().drift_corrections, 1);
        assert_eq!(
            audio.status.snapshot().unwrap().device_latency_ms,
            Some(400),
            "the latency is read from the endpoint, not modelled"
        );

        // The command lands on the next packet, which never reaches the decoder.
        audio.handle_frame_at(2_021, au(2, format));
        assert_eq!(
            decoder.submits(),
            2,
            "one frame's worth of audio left the pipeline"
        );

        // Exactly one. The corrector cannot sample again for another two
        // seconds, so the packets after it play normally.
        audio.handle_frame_at(2_042, au(3, format));
        assert_eq!(decoder.submits(), 3);
        assert_eq!(audio.status.snapshot().unwrap().drift_corrections, 1);
    }

    /// The shipped `JitterConfig::default()` — prebuffer and all — through the
    /// shipped packet-driven caller, on the arrival pattern
    /// `system_audio_redundancy` puts on the wire.
    ///
    /// That combination had no coverage anywhere. Every other test in this
    /// module turns the prebuffer off to keep the decode/play chain in focus,
    /// and the jitter buffer's own long-run tests pop once per DAC tick, which
    /// models a caller this codebase does not contain. The gap is what let
    /// "zero client code — the reorder window already discards duplicates" be
    /// true on paper while each duplicate still cost a `pop`: two pops per
    /// period against one accepted push, a four-packet prebuffer drained in
    /// ~85 ms, a starve, a refill in silence, and around again — audio chopped
    /// several times a second by the feature that exists to repair a lossy
    /// link, with nothing in the log to say why.
    #[test]
    fn a_redundant_stream_plays_straight_through_at_the_shipped_defaults() {
        let cfg = JitterConfig::default();
        let format = AudioFormat::Stereo48k;
        let decoder = SharedNullDecoder::new(format);
        let sink = SharedSink::new(format);
        // Start the endpoint at the depth target so the device-domain corrector
        // sits inside its deadband for the whole run; its behaviour has its own
        // test and is not what this one is measuring.
        sink.prefill_ms(cfg.target_start_ms);
        let baseline = sink.written().len();

        let mut audio = audio_loop_with_config(
            cfg,
            format,
            Some(Box::new(decoder.clone())),
            Some(Box::new(sink.clone())),
        );

        let count = 200u32; // ~4.2 s
        for seq in 0..count {
            let now = u64::from(seq) * 21;
            let before = sink.written().len();
            audio.handle_frame_at(now, au(seq, format));
            if seq > 0 {
                // "having sent packet N, send N-1 again behind it"
                audio.handle_frame_at(now, au(seq - 1, format));
            }
            // The DAC plays exactly what it was handed this period, so the
            // endpoint's depth stays at the prefill and the device-domain
            // corrector stays idle. That corrector has its own test; letting it
            // fire here would only add silence this test would have to account
            // for, and would tell us nothing about the pacing under test.
            let frames = (sink.written().len() - before) / 2; // stereo
            sink.drain(frames as u32);
        }

        let snap = audio.status.snapshot().expect("gauges are published");
        assert_eq!(
            snap.underruns, 0,
            "a duplicate is not a period of missing audio, so nothing may starve"
        );
        assert_eq!(snap.lost, 0);
        assert_eq!(snap.late, 0);
        assert_eq!(
            snap.target_ms, cfg.target_start_ms,
            "nothing starved, so the depth controller had no reason to move"
        );
        assert_eq!(
            snap.packets_received,
            u64::from(count * 2 - 1),
            "every arrival, duplicates included, reached the buffer"
        );
        assert_eq!(
            snap.packets_delivered,
            u64::from(count - 3),
            "each unique unit exactly once, with the prebuffer's worth still held"
        );
        assert!(
            snap.buffered_ms <= cfg.target_start_ms,
            "the window must sit at its target rather than draining away from \
             it: {} ms against a {} ms target",
            snap.buffered_ms,
            cfg.target_start_ms
        );
        assert_eq!(
            decoder.submits(),
            snap.packets_delivered,
            "every delivered unit was decoded, none swallowed by a correction"
        );
        assert_eq!(
            sink.written().len() - baseline,
            decoder.submits() as usize * AAC_FRAME_SAMPLES * 2,
            "and every decoded frame reached the endpoint whole"
        );
        assert_eq!(
            snap.drift_corrections, 0,
            "the endpoint sat at its target throughout"
        );
    }

    /// Plugging headphones into the *client* used to kill remote audio for the
    /// rest of the session, silently.
    ///
    /// `AUDCLNT_E_DEVICE_INVALIDATED` and its relatives (see
    /// `host::audio_capture::is_recoverable_hresult`) are what a device change
    /// looks like from inside a live `IAudioClient`, and they are always
    /// followed moments later by a perfectly good new default endpoint. The
    /// host has always dropped its capture stream and built another. This loop
    /// used to log `audio write failed` and keep writing into the dead handle —
    /// about fifty warn lines a second — with `audio_error` still `None` and
    /// the packet counters still climbing, so the diagnostics panel showed a
    /// healthy stream playing to nobody.
    #[test]
    fn an_invalidated_endpoint_is_reported_retired_and_re_opened_behind_a_backoff() {
        reset_open_sink_seam(0);
        let format = AudioFormat::Mono48k;
        let decoder = SharedNullDecoder::new(format);
        let faulty = FaultingSink::new(format);
        let mut audio = audio_loop_for_test(
            format,
            Some(Box::new(decoder.clone())),
            Some(Box::new(faulty.clone())),
        );

        audio.handle_frame_at(0, au(0, format));
        assert!(
            audio.status.error().is_none(),
            "a healthy endpoint reports nothing"
        );

        // The user plugs in headphones.
        faulty.kill();
        audio.handle_frame_at(21, au(1, format));

        assert!(
            audio.status.error().is_some(),
            "the failure must reach the panel; `audio_error` staying None while \
             the counters climb is the diagnostics lying about a dead stream"
        );
        assert!(
            audio.sink.is_none(),
            "the dead endpoint must be retired, not written to for the rest of \
             the session"
        );
        assert_eq!(faulty.refusals(), 1, "one refusal, then no more attempts");
        let snap = audio.status.snapshot().unwrap();
        assert_eq!(
            snap.device_latency_ms, None,
            "and the device gauges go back to `None`, not to a stale number"
        );
        assert_eq!(snap.device_underruns, None);

        // Packets keep arriving 21 ms apart. None of them may re-open anything:
        // that is a COM activation, and doing it at packet rate is the obvious
        // wrong fix.
        for seq in 2..24u32 {
            audio.handle_frame_at(u64::from(seq) * 21, au(seq, format));
        }
        assert_eq!(
            faulty.refusals(),
            1,
            "nothing may be written to the retired endpoint"
        );
        assert_eq!(open_attempts(), 0, "no re-open before the backoff expires");
        assert_eq!(
            decoder.submits(),
            24,
            "audio still decodes throughout — the endpoint is gone, the loop is not"
        );

        // Once it expires, the very next packet re-opens. Once.
        audio.handle_frame_at(21 + SINK_REOPEN_BACKOFF_MIN_MS, au(24, format));
        assert_eq!(open_attempts(), 1);
        assert_eq!(opened_sinks(), 1);
        assert!(audio.sink.is_some());
        assert_eq!(
            audio.sink_backoff_ms, SINK_REOPEN_BACKOFF_MIN_MS,
            "a successful re-open resets the backoff for the next fault"
        );
        assert!(
            audio.status.error().is_none(),
            "and a recovered endpoint clears the fault it reported"
        );

        // Audio really flows into the replacement, not just into `Some(_)`.
        let fresh = opened_sink(0);
        let before = fresh.written().len();
        audio.handle_frame_at(42 + SINK_REOPEN_BACKOFF_MIN_MS, au(25, format));
        assert_eq!(
            fresh.written().len() - before,
            AAC_FRAME_SAMPLES,
            "one mono AAC frame of PCM into the new endpoint"
        );
    }

    /// A client with no playback device at all must not spend the session
    /// retrying, and one that gets a device back at minute two must start
    /// working without a reconnect. Both come from the same doubling backoff.
    #[test]
    fn repeated_re_open_failures_widen_the_backoff_rather_than_retrying_forever() {
        // Three failed opens, then a device: a laptop whose user plugs their
        // headset in a few seconds into the call.
        reset_open_sink_seam(3);
        let format = AudioFormat::Mono48k;
        let faulty = FaultingSink::new(format);
        let mut audio = audio_loop_for_test(
            format,
            Some(Box::new(SharedNullDecoder::new(format))),
            Some(Box::new(faulty.clone())),
        );

        audio.handle_frame_at(0, au(0, format));
        faulty.kill();
        audio.handle_frame_at(21, au(1, format));
        assert_eq!(audio.sink_retry_at_ms, Some(521), "500 ms after the fault");
        assert_eq!(audio.sink_backoff_ms, 1_000);

        // A steady stream of packets across the whole first interval buys
        // exactly one attempt, not one per packet.
        for seq in 2..24u32 {
            audio.handle_frame_at(u64::from(seq) * 21, au(seq, format));
        }
        assert_eq!(open_attempts(), 0);

        for (attempt, (at_ms, next_due, next_backoff)) in [
            (521u64, 1_521u64, 2_000u64),
            (1_521, 3_521, 4_000),
            (3_521, 7_521, 8_000),
        ]
        .into_iter()
        .enumerate()
        {
            audio.handle_frame_at(at_ms, au(100 + attempt as u32, format));
            assert_eq!(open_attempts(), attempt as u32 + 1);
            assert!(audio.sink.is_none(), "attempt {attempt} must still fail");
            assert_eq!(audio.sink_retry_at_ms, Some(next_due));
            assert_eq!(audio.sink_backoff_ms, next_backoff);
        }

        // The device is finally there.
        audio.handle_frame_at(7_521, au(200, format));
        assert_eq!(open_attempts(), 4);
        assert!(audio.sink.is_some());
        assert_eq!(audio.sink_retry_at_ms, None);
        assert_eq!(audio.sink_backoff_ms, SINK_REOPEN_BACKOFF_MIN_MS);
        assert!(audio.status.error().is_none());
    }

    #[test]
    fn the_audio_thread_stops_with_the_pipeline_and_measures_nothing_until_fed() {
        let mut pipeline = Pipeline::new(
            Arc::new(SourceStatus::default()),
            Arc::new(AtomicBool::new(false)),
        );
        let (tx, rx) = crossbeam_channel::bounded::<AudioFrame>(8);
        pipeline.attach_audio_thread(rx);

        // Nothing has been measured, so the panel gets `None` — never a row of
        // zeros that would read as "audio is fine and perfectly silent". This
        // also proves attaching alone opens no endpoint and builds no decoder:
        // both are constructed from the first packet's format, and none arrived.
        assert!(pipeline.audio_snapshot().is_none());
        assert!(pipeline.audio_error().is_none());

        // Shares the pipeline's stop flag, so this returns rather than hanging.
        pipeline.shutdown();
        drop(tx);
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
        for pattern in [DemoPattern::Primary, DemoPattern::Secondary] {
            let f = synth_frame(64, 32, 0, 0, pattern);
            assert_eq!(f.format, PixelFormat::Rgba8);
            assert_eq!(f.width, 64);
            assert_eq!(f.height, 32);
            assert_eq!(f.data.len(), 64 * 32 * 4);
            assert!(
                f.data.chunks_exact(4).all(|p| p[3] == 255),
                "must be opaque ({pattern:?})"
            );
        }
    }

    #[test]
    fn synth_frame_actually_animates() {
        // If consecutive frames were identical the demo would prove nothing.
        let a = synth_frame(64, 32, 10, 0, DemoPattern::Primary);
        let b = synth_frame(64, 32, 11, 33, DemoPattern::Primary);
        assert_ne!(a.data, b.data);

        let a = synth_frame(64, 32, 10, 0, DemoPattern::Secondary);
        let b = synth_frame(64, 32, 11, 33, DemoPattern::Secondary);
        assert_ne!(a.data, b.data);
    }

    /// `--demo-second-window`'s whole reason to exist: the two windows must
    /// never be confusable at a glance. Same tick, same timestamp — the only
    /// thing that can account for a difference is `pattern`.
    #[test]
    fn the_two_demo_patterns_are_never_the_same_picture() {
        let primary = synth_frame(64, 32, 3, 100, DemoPattern::Primary);
        let secondary = synth_frame(64, 32, 3, 100, DemoPattern::Secondary);
        assert_ne!(primary.data, secondary.data);
    }

    /// `DemoPattern`'s two labels must never collide — a thread-name clash
    /// would be silently confusing in `tracing`/process-list output, and an
    /// identical description would defeat the whole point of tagging one
    /// "(2nd window)" in the diagnostics panel.
    #[test]
    fn demo_pattern_labels_are_distinct() {
        assert_ne!(
            DemoPattern::Primary.thread_name(),
            DemoPattern::Secondary.thread_name()
        );
        assert_ne!(
            DemoPattern::Primary.description_prefix(),
            DemoPattern::Secondary.description_prefix()
        );
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

    /// `--demo-second-window`: a second synthetic source, attached to the
    /// *same* pipeline as the primary demo source, feeding a *different*
    /// slot with its own `SourceStatus` — proving the two are independent
    /// (own counters, own description) and that `Pipeline::shutdown` stops
    /// both threads, not just the one it was originally built with.
    #[test]
    fn attach_demo_thread_feeds_its_own_slot_independently_of_the_primary() {
        let slot1 = Arc::new(FrameSlot::new());
        let slot2 = Arc::new(FrameSlot::new());
        let mut pipeline = spawn_demo_source(slot1.clone(), 200, || {});
        let stream1_status = pipeline.attach_demo_thread(slot2.clone(), 200, || {});

        let deadline = Instant::now() + Duration::from_secs(3);
        while (slot1.decoded_count() < 5 || slot2.decoded_count() < 5) && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        pipeline.shutdown();

        assert!(
            slot1.decoded_count() >= 5,
            "primary: {}",
            slot1.decoded_count()
        );
        assert!(
            slot2.decoded_count() >= 5,
            "secondary: {}",
            slot2.decoded_count()
        );
        assert_eq!(slot2.remote_dims(), Some((1280, 720)));
        // Its own status, distinguishable in the diagnostics panel and the
        // log from the primary window's `pipeline.status`.
        assert!(stream1_status.description().contains("2nd window"));
        assert_eq!(
            stream1_status.frames_gated(),
            0,
            "demo bypasses the gate entirely"
        );
    }
}
