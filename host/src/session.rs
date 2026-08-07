//! Pipeline orchestration: capture -> convert -> encode -> `EncodedFrame`s out,
//! `InputEvent`s in.
//!
//! No networking lives here by design. The transport wave attaches to
//! [`HostSession::frames`] and [`HostSession::input_sender`] and nothing else
//! needs to change.
//!
//! Threading:
//! * one **media thread** owning capture, converter and encoder (all of which
//!   are thread-affine COM objects, so they are created on and never leave it);
//! * one **input thread** owning the injector, so a slow encode never delays a
//!   mouse move.
//!
//! On the secure desktop (UAC prompt, lock screen) capture legitimately fails.
//! The session parks in [`SessionState::Paused`], releases every held key, and
//! resumes automatically when the user desktop returns.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crossbeam_channel::{bounded, unbounded, Receiver, Sender};
use directdesk_shared::input::InputEvent;
use directdesk_shared::stats::ConnStats;
use directdesk_shared::tiles::{compress_strip, TileMsg};
use directdesk_shared::traits::{Encoder, InputInjector};
use directdesk_shared::video::{EncodedFrame, FRAG_HEADER_LEN, MAX_FRAGS_PER_FRAME};
use directdesk_shared::{Error, Result};
use parking_lot::Mutex;

use crate::capture::{pause_reason, DdaCapture};
use crate::convert::{bgra_to_nv12, GpuConverter};
use crate::input_inject::WinInjector;
use crate::mf_encoder::{
    EncoderConfig, FrameInput, MfH264Encoder, MAX_STATIC_REFINE_QUALITY, MIN_STATIC_REFINE_QUALITY,
};
use crate::mfinit::MfThread;
use crate::tiles::{hash_plan_tiles, DirtyRect, GridStats, MoveRect, TileGrid};

#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Upper bound on emitted frames per second.
    pub target_fps: u32,
    pub bitrate_kbps: u32,
    pub gop_seconds: u32,
    /// Re-emit the last image after this long with no desktop change, so the
    /// stream (and the receiver's decoder) never goes silent. 0 disables.
    pub idle_repeat_ms: u32,
    /// Skip the GPU video processor and always convert on the CPU. Diagnostics.
    pub force_cpu_convert: bool,
    /// Depth of the outbound encoded-frame queue. Oldest is dropped when full.
    pub frame_queue_depth: usize,
    /// How long the desktop must sit unchanged before the encoder is given one
    /// settle keyframe (see `media_thread`). 0 disables the settle entirely.
    ///
    /// Without it, a still screen is frozen at whatever quality the one frame
    /// that drew it happened to achieve — if that frame landed mid-scroll with
    /// rate control still paying off the burst, the text stays soft forever,
    /// because a repeated frame is just an all-skip P-frame reproducing the
    /// same picture. One refresh after things settle is what lets text sharpen.
    pub static_settle_ms: u32,
    /// `AVEncCommonQuality` (0..=100) the one settle keyframe of each idle
    /// period is encoded at, in constant-quality mode instead of at the
    /// streaming bitrate. `0` disables the refinement — the settle keyframe is
    /// still sent, just inside the ordinary rate-control budget.
    ///
    /// This is the MJPEG-shaped part of the design: while the screen is static
    /// we have the whole idle period and the idle bandwidth, so we buy one
    /// frame at a fixed quality rather than at a fixed price. See the design
    /// note in `mf_encoder` above `refine_settings`.
    pub static_refine_quality: u32,
    /// Refine settled regions losslessly on a side stream (see [`crate::tiles`]
    /// and `HostConfig::lossless_tiles_enabled`). Off unless both the operator
    /// and the connected client opted in.
    pub lossless_tiles_enabled: bool,
    /// How long (ms) a tile must sit unchanged before it is eligible.
    pub lossless_tile_settle_ms: u32,
    /// deflate level for tile payloads (1..=9).
    pub lossless_tile_deflate_level: u32,
    /// How long (ms) a refined tile stays paintable without renewal.
    pub lossless_tile_lease_ms: u32,
    /// Strips compressed per refinement pass, bounding how much of the frame
    /// budget's idle slack the pass may consume.
    pub lossless_tiles_per_pass: u32,
}

/// How long the desktop must sit unchanged before the encoder is given one
/// settle keyframe (see `media_thread`). 0 disables the settle entirely.
///
/// Expressed in time, not in a count of repeat frames, so it means the same
/// thing at 15 fps as at 60 and does not move when `idle_repeat_ms` is tuned.
/// ~700 ms is comfortably longer than a scroll or a window drag — those keep
/// producing changed frames, so they never reach the settle — but short enough
/// that a user who stops to read has sharp text before they have finished
/// finding their place on the line.
pub const STATIC_SETTLE_MS: u32 = 700;

/// Smallest QUIC datagram we are willing to assume when sizing the refinement
/// frame. Real paths negotiate more; assuming less than we get is the safe
/// direction, because the number below is a *ceiling* on how big a frame we are
/// prepared to emit.
const MIN_ASSUMED_DATAGRAM: usize = 1_200;

/// The largest encoded frame the fragmenter will carry at that datagram size.
///
/// `shared::video::fragment*` refuses any frame needing more than
/// [`MAX_FRAGS_PER_FRAME`] datagrams. A refused *keyframe* is not a dropped
/// frame, it is a frozen picture: `host::net` logs it, latches
/// `oversized_keyframe`, and hands the adaptor a full congestion event, which
/// cuts the bitrate. An unbounded refinement frame would therefore produce no
/// picture *and* make the stream worse — exactly self-defeating.
pub const FRAGMENTER_FRAME_LIMIT_BYTES: usize =
    MAX_FRAGS_PER_FRAME as usize * (MIN_ASSUMED_DATAGRAM - FRAG_HEADER_LEN);

/// Ceiling we hold a refinement frame to: 40% of what the fragmenter would
/// physically accept.
///
/// Not 100%, for two reasons. The frame also has to *fit through a residential
/// uplink* in one pacing window without causing the loss that would make the
/// adaptor back off — a ~240 KB burst is already ~2 Mbit on the wire. And the
/// margin leaves room for FEC parity and for a path whose datagram size is
/// smaller than the estimate. Exceeding this is not fatal on the frame that
/// does it (we cannot un-encode it) — it lowers the quality of every later
/// refinement, see [`adapt_refine_quality`].
pub const STATIC_REFINE_MAX_BYTES: usize = FRAGMENTER_FRAME_LIMIT_BYTES * 2 / 5;

/// How much quality one oversized refinement costs the next one.
const REFINE_QUALITY_STEP: u32 = 8;

/// The quality the *next* refinement should use, having seen this one come out
/// at `bytes`.
///
/// Pure so the back-off ladder can be tested. Monotonically downward and
/// terminating: a refinement that overshoots [`STATIC_REFINE_MAX_BYTES`] costs
/// [`REFINE_QUALITY_STEP`], and one that still overshoots at the bottom of the
/// permitted band turns the feature off for the rest of the session (`0`)
/// rather than looping forever on a screen that simply cannot be refined
/// cheaply. Never ratchets back up: this is a safety valve, not a controller,
/// and an oscillating one would put a large frame on the wire every time it
/// probed upward.
fn adapt_refine_quality(current: u32, bytes: usize, ceiling: usize) -> u32 {
    if current == 0 || bytes <= ceiling {
        return current;
    }
    if current <= MIN_STATIC_REFINE_QUALITY {
        return 0;
    }
    current
        .saturating_sub(REFINE_QUALITY_STEP)
        .max(MIN_STATIC_REFINE_QUALITY)
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            target_fps: 60,
            bitrate_kbps: 12_000,
            gop_seconds: 4,
            // A still desktop only needs a low-rate keepalive, not ~30 identical
            // full-frame re-encodes/sec. 250 ms (~4/s) cuts static-screen
            // bandwidth; the keepalives are ordinary re-sent frames, and exactly
            // one of them per idle period is promoted to an IDR so the picture
            // converges (see the settle logic in media_thread).
            idle_repeat_ms: 250,
            force_cpu_convert: false,
            frame_queue_depth: 8,
            static_settle_ms: STATIC_SETTLE_MS,
            static_refine_quality: crate::mf_encoder::DEFAULT_STATIC_REFINE_QUALITY,
            lossless_tiles_enabled: false,
            lossless_tile_settle_ms: 900,
            lossless_tile_deflate_level: 6,
            lossless_tile_lease_ms: 4_000,
            lossless_tiles_per_pass: 32,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    Starting,
    Running,
    /// Capture is unavailable for a stated, recoverable reason.
    Paused(String),
    Failed(String),
    Stopped,
}

impl SessionState {
    pub fn is_live(&self) -> bool {
        matches!(self, SessionState::Running | SessionState::Paused(_))
    }
}

/// Everything the UI and the transport want to display about the pipeline.
#[derive(Debug, Clone)]
pub struct SessionDescription {
    pub adapter: String,
    pub adapter_luid: u64,
    pub output: String,
    pub monitor_origin: (i32, i32),
    pub encoder: String,
    pub width: u32,
    pub height: u32,
    /// NV12 conversion runs on the D3D11 video processor.
    pub gpu_convert: bool,
    /// The encoder MFT takes GPU textures (no readback at all).
    pub gpu_encode_input: bool,
    pub hardware_encoder: bool,
}

impl SessionDescription {
    /// One-line honest summary of which paths are actually active.
    pub fn pipeline_summary(&self) -> String {
        format!(
            "{}x{} | {} | convert: {} | encoder input: {}",
            self.width,
            self.height,
            self.encoder,
            if self.gpu_convert {
                "GPU VideoProcessor"
            } else {
                "CPU BT.709"
            },
            if self.gpu_encode_input {
                "GPU texture"
            } else {
                "CPU NV12"
            },
        )
    }
}

#[derive(Default)]
struct Counters {
    captured: AtomicU64,
    encoded: AtomicU64,
    dropped: AtomicU64,
    bytes: AtomicU64,
    keyframes: AtomicU64,
    /// Client events that reached `SendInput` and were accepted by it. This is
    /// the observable end of the input path — the transport layer counts what
    /// it *forwarded*, which is not the same thing.
    input_injected: AtomicU64,
}

struct Shared {
    stats: Mutex<ConnStats>,
    state: Mutex<SessionState>,
    desc: Mutex<Option<SessionDescription>>,
    counters: Counters,
    stop: AtomicBool,
    keyframe_req: AtomicBool,
    /// Take-and-clear request to throw away all tile state and start the grid
    /// over, in the same idiom as [`Shared::keyframe_req`].
    ///
    /// This exists because `HostSession` **outlives a client connection**
    /// (`Inner::ensure_pipeline` hands a reconnecting client the session that
    /// is already running). Without it, a client that reconnects holds zero
    /// tiles while the grid still believes every tile is `Refined`, so the
    /// hash guard suppresses every re-send and the screen stays permanently
    /// soft. The symptom is nasty precisely because it is invisible in
    /// testing: perfect on the first connection, broken on every one after.
    tiles_reset_req: AtomicBool,
    /// Bandwidth (kbps) refinement tiles may spend, republished every status
    /// tick by the network layer from measured spare headroom.
    ///
    /// Read by the media thread rather than enforced at the pump, because only
    /// the media thread owns the grid: a strip discarded *after* it was queued
    /// would already have been recorded as delivered (`commit_sent`), the hash
    /// guard would suppress every re-send, and that square would stay soft
    /// forever. Spending the budget before planning keeps the whole chain
    /// failing toward "send it again".
    tile_budget_kbps: AtomicU32,
    bitrate_req: AtomicU32,
    /// Pending frame-rate change, take-and-clear like [`Shared::bitrate_req`]:
    /// `0` means nothing is pending. Applied by the media thread, which is the
    /// only thread allowed to touch the (thread-affine) encoder.
    fps_req: AtomicU32,
    /// The frame rate actually in force. Published by the media thread once a
    /// rebuild succeeded, so readers (the video pump's pacing, the status
    /// snapshot) observe truth rather than a request that may have failed.
    fps_now: AtomicU32,
    /// While `true`, client input is routed to the SYSTEM UAC worker instead of
    /// the local injector. Observability only — the actual switch is serialized
    /// on the input thread via [`InputCtl::ElevationRoute`], so local injection
    /// and worker forwarding can never both fire for one event (no double
    /// injection, no mouse fighting).
    elevation_active: AtomicBool,
}

impl Shared {
    fn set_state(&self, s: SessionState) {
        let mut cur = self.state.lock();
        if *cur != s {
            tracing::info!("session state: {:?} -> {:?}", *cur, s);
            *cur = s;
        }
    }
}

/// Messages the input thread understands beyond raw events.
enum InputCtl {
    Geometry {
        w: u32,
        h: u32,
        origin: (i32, i32),
    },
    ReleaseAll,
    /// Enter (`Some`) or leave (`None`) the exclusive elevation route. While a
    /// sink is installed, input events are forwarded to it and NOT injected
    /// locally. Entering and leaving both release everything held locally first,
    /// so no key/button is left stuck on either side of the handoff.
    ElevationRoute(Option<Sender<InputEvent>>),
    Stop,
}

/// Depth of the media→network tile queue.
///
/// Deep enough that a pump briefly behind the media thread does not cost
/// refinement work already done, shallow enough that a *stalled* pump cannot
/// accumulate megabytes of pixels for a screen that has since changed. The
/// refinement pass reserves [`TILE_QUEUE_REVOKE_RESERVE`] of these slots so a
/// revocation is never crowded out by the strips it supersedes.
pub const TILE_QUEUE_DEPTH: usize = 64;

/// Queue slots the strip planner must leave free for revocations.
///
/// Ordering policy: **strips are droppable before they are queued; revocations
/// are never dropped.** Dropping a strip is always safe — the client simply
/// keeps showing H.264 for that square. Dropping a revocation is the one
/// failure this feature must not have, because the client would go on
/// compositing pixels the host has already repainted.
pub const TILE_QUEUE_REVOKE_RESERVE: usize = 8;

const _: () = assert!(TILE_QUEUE_REVOKE_RESERVE < TILE_QUEUE_DEPTH);

pub struct HostSession {
    frames_rx: Receiver<EncodedFrame>,
    tiles_rx: Receiver<directdesk_shared::tiles::TileMsg>,
    input_tx: Sender<InputEvent>,
    input_ctl: Sender<InputCtl>,
    shared: Arc<Shared>,
    media: Option<JoinHandle<()>>,
    input: Option<JoinHandle<()>>,
    desc: SessionDescription,
}

impl HostSession {
    /// Start the pipeline. Blocks until capture and the encoder are up (or have
    /// definitively failed), so a successful return means frames are coming.
    pub fn start(cfg: SessionConfig) -> Result<Self> {
        let shared = Arc::new(Shared {
            stats: Mutex::new(ConnStats::default()),
            state: Mutex::new(SessionState::Starting),
            desc: Mutex::new(None),
            counters: Counters::default(),
            stop: AtomicBool::new(false),
            keyframe_req: AtomicBool::new(true), // first frame should be an IDR
            tiles_reset_req: AtomicBool::new(true), // no client holds tiles yet
            // Nothing until the first status tick measures real headroom:
            // refinement must never be the thing that discovers the link's
            // limits.
            tile_budget_kbps: AtomicU32::new(0),
            bitrate_req: AtomicU32::new(0),
            fps_req: AtomicU32::new(0),
            fps_now: AtomicU32::new(cfg.target_fps.max(1)),
            elevation_active: AtomicBool::new(false),
        });

        let (frames_tx, frames_rx) = bounded::<EncodedFrame>(cfg.frame_queue_depth.max(1));
        let (tiles_tx, tiles_rx) = bounded::<directdesk_shared::tiles::TileMsg>(TILE_QUEUE_DEPTH);
        let (init_tx, init_rx) = bounded::<Result<SessionDescription>>(1);
        let (input_tx, input_rx) = unbounded::<InputEvent>();
        let (ctl_tx, ctl_rx) = unbounded::<InputCtl>();

        let media = {
            let shared = shared.clone();
            let cfg = cfg.clone();
            let drop_rx = frames_rx.clone();
            let ctl_tx = ctl_tx.clone();
            std::thread::Builder::new()
                .name("dd-media".into())
                .spawn(move || {
                    media_thread(cfg, shared, frames_tx, tiles_tx, drop_rx, init_tx, ctl_tx)
                })
                .map_err(|e| Error::Other(format!("spawn media thread: {e}")))?
        };

        let desc = init_rx
            .recv()
            .map_err(|_| Error::Capture("media thread died during startup".into()))??;

        let input = {
            let shared = shared.clone();
            let d = desc.clone();
            std::thread::Builder::new()
                .name("dd-input".into())
                .spawn(move || input_thread(d, shared, input_rx, ctl_rx))
                .map_err(|e| Error::Other(format!("spawn input thread: {e}")))?
        };

        Ok(Self {
            frames_rx,
            tiles_rx,
            input_tx,
            input_ctl: ctl_tx,
            shared,
            media: Some(media),
            input: Some(input),
            desc,
        })
    }

    /// Encoded H.264 (Annex-B) frames, newest-wins when the consumer lags.
    pub fn frames(&self) -> Receiver<EncodedFrame> {
        self.frames_rx.clone()
    }

    /// Lossless refinement messages produced by the media thread.
    ///
    /// Empty unless the session was configured with `lossless_tiles_enabled`.
    /// The network pump drains this; if nothing does, the queue simply fills
    /// and the media thread stops planning strips — the video path is
    /// unaffected either way.
    pub fn tiles(&self) -> Receiver<directdesk_shared::tiles::TileMsg> {
        self.tiles_rx.clone()
    }

    /// Sink for client input. Events are validated and injected in order.
    pub fn input_sender(&self) -> Sender<InputEvent> {
        self.input_tx.clone()
    }

    /// Ask the encoder for an IDR on the next frame (new viewer, packet loss).
    pub fn request_keyframe(&self) {
        self.shared.keyframe_req.store(true, Ordering::Relaxed);
    }

    /// Throw away all tile state so the whole screen is refined again.
    ///
    /// **Must be called for every newly connected client**, because the media
    /// pipeline is a singleton that outlives any one connection: the incoming
    /// client's tile store is empty, and a grid that still remembers the last
    /// client's `Refined` tiles would never re-send them. Also the right call
    /// on a resolution change and on returning from the secure desktop, where
    /// the tiles describe a screen that no longer exists.
    pub fn reset_tiles(&self) {
        self.shared.tiles_reset_req.store(true, Ordering::Relaxed);
    }

    /// Publish the bandwidth (kbps) refinement may spend, measured by the
    /// network layer's status tick. `0` stops refinement entirely.
    pub fn set_tile_budget_kbps(&self, kbps: u32) {
        self.shared.tile_budget_kbps.store(kbps, Ordering::Relaxed);
    }

    /// Bytes of tile payload allowed per refinement pass at the current budget.
    ///
    /// The budget is a per-second allowance; a pass runs at most once per
    /// captured frame, so the per-pass share is the allowance divided by the
    /// frame rate. Deliberately computed from the *live* rate rather than the
    /// configured one, so lowering fps does not silently multiply tile traffic.
    pub fn tile_pass_bytes(&self) -> usize {
        tile_pass_bytes(
            self.shared.tile_budget_kbps.load(Ordering::Relaxed),
            self.shared.fps_now.load(Ordering::Relaxed),
        )
    }

    /// Change the encoder's target bitrate; applied on the next frame.
    pub fn set_bitrate(&self, kbps: u32) {
        self.shared
            .bitrate_req
            .store(kbps.max(1), Ordering::Relaxed);
    }

    /// Change the encoder's frame rate; applied on the next media-thread pass.
    ///
    /// Unlike [`set_bitrate`] this rebuilds the encoder (MF fixes the frame rate
    /// at media-type negotiation), so it is not free — but it is a live change:
    /// capture, the D3D device and the session description are untouched, and a
    /// failed rebuild leaves the session running at the old rate.
    ///
    /// [`set_bitrate`]: HostSession::set_bitrate
    pub fn set_fps(&self, fps: u32) {
        let want = fps.clamp(crate::config::MIN_TARGET_FPS, crate::config::MAX_TARGET_FPS);
        self.shared.fps_req.store(want, Ordering::Relaxed);
    }

    /// The frame rate the encoder is actually running at.
    ///
    /// Observed truth, not the last request: a [`set_fps`] whose rebuild failed
    /// (or has not landed yet — it takes up to one frame) still reads the old
    /// value here.
    ///
    /// [`set_fps`]: HostSession::set_fps
    pub fn active_fps(&self) -> u32 {
        self.shared.fps_now.load(Ordering::Relaxed).max(1)
    }

    /// Release every key/button currently held on behalf of the client.
    pub fn release_all_input(&self) {
        let _ = self.input_ctl.send(InputCtl::ReleaseAll);
    }

    /// Begin routing client input to the SYSTEM UAC worker via `sink` instead of
    /// the local injector. The input thread releases everything it holds locally
    /// before the switch, so no local key/button is left down while the remote
    /// worker takes over. Exclusive: while routing, the local injector is never
    /// called for input events.
    pub fn begin_elevation_route(&self, sink: Sender<InputEvent>) {
        self.shared.elevation_active.store(true, Ordering::SeqCst);
        let _ = self.input_ctl.send(InputCtl::ElevationRoute(Some(sink)));
    }

    /// Stop routing to the worker and resume local injection. Releases anything
    /// held locally again (belt and braces) and forces a keyframe, matching the
    /// resume-from-pause pattern, since the desktop under a just-dismissed
    /// consent dialog may look different.
    pub fn end_elevation_route(&self) {
        self.shared.elevation_active.store(false, Ordering::SeqCst);
        let _ = self.input_ctl.send(InputCtl::ElevationRoute(None));
        self.request_keyframe();
    }

    /// Whether input is currently routed to the SYSTEM worker.
    pub fn elevation_active(&self) -> bool {
        self.shared.elevation_active.load(Ordering::SeqCst)
    }

    pub fn stats(&self) -> ConnStats {
        *self.shared.stats.lock()
    }

    pub fn state(&self) -> SessionState {
        self.shared.state.lock().clone()
    }

    pub fn describe(&self) -> SessionDescription {
        self.shared
            .desc
            .lock()
            .clone()
            .unwrap_or_else(|| self.desc.clone())
    }

    pub fn dimensions(&self) -> (u32, u32) {
        (self.desc.width, self.desc.height)
    }

    pub fn frames_encoded(&self) -> u64 {
        self.shared.counters.encoded.load(Ordering::Relaxed)
    }

    pub fn frames_captured(&self) -> u64 {
        self.shared.counters.captured.load(Ordering::Relaxed)
    }

    pub fn bytes_encoded(&self) -> u64 {
        self.shared.counters.bytes.load(Ordering::Relaxed)
    }

    pub fn keyframes_sent(&self) -> u64 {
        self.shared.counters.keyframes.load(Ordering::Relaxed)
    }

    /// Client input events actually injected into the desktop.
    ///
    /// Counted at the far end of the input thread, after `SendInput` reported
    /// success, so it proves the whole path — not merely that something was
    /// queued.
    pub fn input_events_injected(&self) -> u64 {
        self.shared.counters.input_injected.load(Ordering::Relaxed)
    }

    /// Stop both threads and wait for them. Idempotent via `Drop`.
    pub fn shutdown(mut self) {
        self.stop_inner();
    }

    fn stop_inner(&mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
        let _ = self.input_ctl.send(InputCtl::Stop);
        if let Some(h) = self.media.take() {
            let _ = h.join();
        }
        if let Some(h) = self.input.take() {
            let _ = h.join();
        }
        self.shared.set_state(SessionState::Stopped);
    }
}

impl Drop for HostSession {
    fn drop(&mut self) {
        self.stop_inner();
    }
}

// ---- media thread ------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn media_thread(
    cfg: SessionConfig,
    shared: Arc<Shared>,
    frames_tx: Sender<EncodedFrame>,
    tiles_tx: Sender<TileMsg>,
    drop_rx: Receiver<EncodedFrame>,
    init_tx: Sender<Result<SessionDescription>>,
    ctl_tx: Sender<InputCtl>,
) {
    lower_video_thread_priority("capture/encode");
    let _mf = match MfThread::enter() {
        Ok(g) => g,
        Err(e) => {
            let _ = init_tx.send(Err(e));
            return;
        }
    };

    let built = build_pipeline(&cfg);
    let (mut capture, mut converter, mut encoder, desc) = match built {
        Ok(v) => v,
        Err(e) => {
            shared.set_state(SessionState::Failed(e.to_string()));
            let _ = init_tx.send(Err(e));
            return;
        }
    };

    *shared.desc.lock() = Some(desc.clone());
    shared.set_state(SessionState::Running);
    let _ = ctl_tx.send(InputCtl::Geometry {
        w: desc.width,
        h: desc.height,
        origin: desc.monitor_origin,
    });
    if init_tx.send(Ok(desc.clone())).is_err() {
        return;
    }

    let mut cur_fps = cfg.target_fps.max(1);
    let mut cur_bitrate = cfg.bitrate_kbps.max(1);
    let mut frame_budget = frame_budget(cur_fps);
    shared.fps_now.store(cur_fps, Ordering::Relaxed);
    let mut cpu_bgra: Vec<u8> = Vec::new();
    let mut cpu_nv12: Vec<u8> = Vec::new();
    let mut gpu_convert_ok = converter.is_some();
    let gpu_texture_input = desc.gpu_encode_input;

    let mut win_start = Instant::now();
    let mut win_captured = 0u32;
    let mut win_encoded = 0u32;
    let mut win_bytes = 0u64;
    let mut win_pipeline_ms = 0f32;
    let mut paused_since: Option<Instant> = None;
    // When the desktop last started being unchanged, and whether this idle
    // period has already had its one settle keyframe.
    let mut static_since: Option<Instant> = None;
    let mut settle_sent = false;
    let settle_delay = Duration::from_millis(cfg.static_settle_ms as u64);
    // Quality the next refinement frame is encoded at; 0 = feature off. Clamped
    // here so a `SessionConfig` built by hand (selftest, tests, an out-of-range
    // host.json that skipped `sanitized`) cannot ask for something silly.
    let mut refine_quality = match cfg.static_refine_quality {
        0 => 0,
        q => q.clamp(MIN_STATIC_REFINE_QUALITY, MAX_STATIC_REFINE_QUALITY),
    };
    // The encoder is currently parked in constant-quality mode. Exactly one
    // loop iteration long, by construction — see the restore at the top.
    let mut refine_armed = false;
    // A refinement frame has been submitted and we have not yet seen the
    // keyframe it produced, whose size we want to log and police.
    let mut refine_pending = false;

    // --- lossless tile refinement state ------------------------------------
    //
    // `None` when the feature is off, and that is the *whole* switch: every
    // tile branch below is guarded by this option, so a session with
    // `lossless_tiles_enabled == false` allocates no grid, never reads pixels
    // back for tiles, never compresses anything and never touches `tiles_tx`.
    // The cost on the media thread is one null check per frame.
    //
    // The grid is armed on the capture clock, but no frame has been captured
    // yet, so it is stamped at 0 and immediately re-armed for real: `Shared`
    // starts `tiles_reset_req` set, so the first frame through the loop issues
    // a `Reset` at that frame's own timestamp.
    let mut grid = cfg
        .lossless_tiles_enabled
        .then(|| TileGrid::new(desc.width, desc.height, 0));
    // Reusable translation buffers for DXGI's per-frame change report. Held
    // out here so a busy desktop does not allocate two vectors per frame on
    // the thread that must not miss a capture deadline.
    let mut dirty_scratch: Vec<DirtyRect> = Vec::new();
    let mut move_scratch: Vec<MoveRect> = Vec::new();
    let mut tile_win = TileWindow::default();
    let mut tile_win_start = Instant::now();
    // Tile ids whose `Revoke` the queue refused. See [`drain_revocations`]: the
    // grid cannot hold them for us, so this is the only place they survive
    // between passes.
    let mut revoke_retry: Vec<u32> = Vec::new();
    // Carried-over tile allowance; see `tile_bucket_cap`.
    let mut tile_bucket: usize = 0;

    while !shared.stop.load(Ordering::Relaxed) {
        let tick = Instant::now();

        // --- refinement restore (structural) ---------------------------------
        //
        // First statement of the loop body, before any `continue`, any error
        // path and any early `break` can be reached, and unconditional. That is
        // the whole guarantee: whatever happened on the iteration that armed it
        // — the capture failed, the encode errored, the frame was dropped for
        // want of an input credit, the encoder produced nothing — constant
        // quality lasted that one iteration and no more.
        //
        // Getting this wrong is not a cosmetic bug. Left armed, the encoder
        // ignores every mean/peak write, so the adaptor loses its only lever on
        // a residential uplink at ~258 ms RTT and cannot back off from
        // congestion. `MfH264Encoder::set_bitrate` forces the same restore as a
        // second line of defence.
        if refine_armed {
            refine_armed = false;
            encoder.end_static_refinement();
        }

        let bitrate = shared.bitrate_req.swap(0, Ordering::Relaxed);
        if bitrate > 0 {
            let _ = encoder.set_bitrate(bitrate);
            // Remembered so an encoder rebuilt for a frame-rate change starts at
            // the rate in force, not the one the config booted with.
            cur_bitrate = bitrate;
        }

        // Live frame-rate change. MF pins the frame rate in the negotiated
        // media type, so the only way to move it is a new encoder — but only
        // the encoder: capture, the D3D device and the SessionDescription are
        // unchanged, which is why this never touches build_pipeline.
        //
        // Build-then-swap: `encoder` keeps the working MFT until the new one is
        // fully constructed, so a vendor MFT that refuses to activate at the
        // requested rate costs a log line and nothing else.
        let want_fps = shared.fps_req.swap(0, Ordering::Relaxed);
        if want_fps > 0 && want_fps != cur_fps {
            match rebuild_encoder(&cfg, &capture, want_fps, cur_bitrate) {
                Ok(mut new_encoder) => {
                    // The requirement is one-directional. When the live pipeline
                    // hands the encoder D3D textures, a replacement that cannot
                    // take them would be fed the wrong input kind, so refuse. The
                    // reverse is harmless: an encoder that *could* take textures
                    // is perfectly happy being fed CPU NV12, which is what a
                    // pipeline without a GPU converter does. Demanding equality
                    // here would make the whole fps control inert on those hosts.
                    if gpu_texture_input && !new_encoder.accepts_textures() {
                        tracing::warn!(
                            "refusing {cur_fps} -> {want_fps} fps: the live pipeline submits GPU \
                             textures and the rebuilt encoder only accepts CPU NV12"
                        );
                    } else {
                        // Carry numbering forward so the rebuild is invisible to
                        // the receiver's reassembler instead of costing it a
                        // resync_after adoption window plus a forced keyframe.
                        new_encoder.resume_numbering_from(&encoder);
                        encoder = new_encoder;
                        cur_fps = want_fps;
                        frame_budget = self::frame_budget(cur_fps);
                        shared.fps_now.store(cur_fps, Ordering::Relaxed);
                        // A brand-new encoder has no reference chain the client
                        // can use; give it a fresh IDR immediately.
                        shared.keyframe_req.store(true, Ordering::Relaxed);
                        tracing::info!("encoder rebuilt at {cur_fps} fps");
                    }
                }
                Err(e) => tracing::warn!(
                    "could not rebuild the encoder at {want_fps} fps ({e}); staying at {cur_fps}"
                ),
            }
        }

        if shared.keyframe_req.swap(false, Ordering::Relaxed) {
            encoder.request_keyframe();
        }

        let acquired = capture.acquire(8);
        let frame = match acquired {
            Ok(Some(f)) => f,
            Ok(None) => {
                if let Some(reason) = pause_reason(capture.state()) {
                    enter_pause(&shared, &ctl_tx, &mut paused_since, reason);
                } else if paused_since.is_some() {
                    paused_since = None;
                    shared.set_state(SessionState::Running);
                }
                maybe_report(
                    &shared,
                    &mut win_start,
                    &mut win_captured,
                    &mut win_encoded,
                    &mut win_bytes,
                    &mut win_pipeline_ms,
                );
                continue;
            }
            Err(e) => {
                // `capture.state()` — not `e`'s text — is authoritative here:
                // `acquire`/`recreate_duplication` always set `self.state`
                // before returning an error, so `pause_reason` sees the same
                // typed state the `Ok(None)` arm above does. See
                // `pause_reason`'s doc comment for why the error message
                // itself must not be parsed for this.
                if let Some(reason) = pause_reason(capture.state()) {
                    enter_pause(&shared, &ctl_tx, &mut paused_since, reason);
                    std::thread::sleep(Duration::from_millis(100));
                } else {
                    tracing::warn!("capture error: {e}");
                    std::thread::sleep(Duration::from_millis(50));
                }
                continue;
            }
        };

        let resumed = paused_since.take().is_some();
        if resumed {
            shared.set_state(SessionState::Running);
            // The desktop we return to may differ wildly; force a fresh IDR.
            encoder.request_keyframe();
        }

        shared.counters.captured.fetch_add(1, Ordering::Relaxed);
        win_captured += 1;
        let ts = frame.timestamp_ms;
        let repeated = frame.repeated;

        // --- tile dirty pass --------------------------------------------------
        //
        // Deliberately at the top of the loop body, *before* convert and encode:
        // a tile whose pixels changed must be back in `Moving` before the encoder
        // has even seen the frame that changed them. Marking after the encode
        // would leave a window in which the refinement pass could plan a strip
        // from a frame the grid still believes is settled.
        //
        // It also has to be here for a second reason: the dirty rects die with
        // `frame`, which is dropped below.
        if let Some(g) = grid.as_mut() {
            // Geometry before content. Tile ids are `row * cols + col` on both
            // sides, so an id minted against the old grid width aliases a live
            // tile at the new one; the client must be re-armed before any strip
            // for the new geometry can arrive.
            //
            // The reset request is consumed unconditionally (take-and-clear, the
            // same idiom as `keyframe_req`) because a resize rebuilds the grid
            // from scratch, which is a strict superset of what a reset does —
            // leaving the flag set would only buy a redundant reset next frame.
            let want_reset = shared.tiles_reset_req.swap(false, Ordering::Relaxed);
            let rearm = match g.resize(frame.width, frame.height, ts) {
                Some(msg) => Some(msg),
                None if want_reset => Some(g.reset(ts)),
                None => None,
            };
            if let Some(msg) = rearm {
                tile_win.note_control(&msg);
                match send_tile_control(&tiles_tx, msg) {
                    // A `Reset` is the maximal revoke: it retracts every tile
                    // the client holds, so anything still waiting in
                    // `revoke_retry` has just been superseded by something
                    // strictly stronger.
                    Ok(()) => revoke_retry.clear(),
                    Err(_) => {
                        // The grid now believes the client holds nothing while
                        // the client still holds the previous generation's
                        // tiles. Re-arm the request so the next frame retries;
                        // until it lands the client's stale tiles are bounded by
                        // their lease. `revoke_retry` is deliberately *not*
                        // cleared here — nothing has been retracted yet.
                        shared.tiles_reset_req.store(true, Ordering::Relaxed);
                    }
                }
            }

            if resumed {
                // Coming back from the secure desktop, the picture underneath a
                // just-dismissed UAC dialog may be anything at all, and the
                // duplication we resumed on has no memory of what the client was
                // last shown. Do not believe the first change report — mark
                // everything, exactly as `capture` does for the video path.
                g.mark_all_dirty(ts);
            } else {
                let dirty = translate_dirty(frame.dirty_rects.as_deref(), &mut dirty_scratch);
                let moves = translate_moves(frame.move_rects.as_deref(), &mut move_scratch);
                g.mark_frame(dirty, moves, ts);
            }

            // Retract stale tiles *now*, not at the next refinement pass.
            //
            // The pass below only runs on idle frames, so a revocation queued
            // here would otherwise sit unsent for the entire duration of a
            // scroll or a window drag, and the client would go on compositing
            // pixels the host has already repainted — over live video, for as
            // long as the motion lasts. That is precisely the failure the whole
            // design works hardest to avoid, so this drain is unconditional.
            //
            // It is nearly free in steady state: once nothing is `Refined` or
            // `Settling` the grid stops queueing revocations at all, so a long
            // scroll costs one message on its first frame and nothing after.
            drain_revocations(
                g,
                &tiles_tx,
                &mut tile_win,
                &mut revoke_retry,
                &shared.tiles_reset_req,
                ts,
            );
        }

        // --- static-scene settle ---------------------------------------------
        //
        // A repeated frame is coded as an all-skip P-frame, which reproduces the
        // previous picture exactly. That is bandwidth-perfect and quality-frozen:
        // whatever the *one* frame that drew the current screen achieved is what
        // the user stares at forever. If that frame landed right after a scroll,
        // with rate control still paying off the burst, the text stays soft and
        // nothing in the pipeline will ever refine it.
        //
        // So once the screen has genuinely settled, send exactly ONE keyframe,
        // then latch until the desktop actually changes again.
        //
        // The older note here warned that forcing an IDR on *every* keepalive
        // pulsed visibly on coloured backgrounds. That was real, and it was a
        // property of periodic re-encoding under CBR: each IDR re-quantized the
        // whole image to a different fixed bit budget, so the image breathed. Two
        // things remove it. One IDR per idle period cannot be periodic — there is
        // no second one to differ from — and under peak-constrained VBR with a QP
        // ceiling (see mf_encoder) the settle frame is encoded at better quality
        // than the frame it replaces, not merely differently. A single step up in
        // sharpness is what we want the user to see.
        if repeated {
            let since = *static_since.get_or_insert(tick);
            if should_settle(since.elapsed(), settle_delay, settle_sent) {
                settle_sent = true;
                encoder.request_keyframe();
                // ...and, if refinement is on, buy that one keyframe at a fixed
                // *quality* instead of at the streaming bitrate. Without this
                // the settle IDR is still quantized to fit the mean, which on a
                // detailed 1080p screen leaves it about as soft as the picture
                // it replaced — the actual gap against an MJPEG KVM.
                //
                // Deliberately reusing the existing `settle_sent` latch as the
                // one-per-idle-period mechanism rather than adding a second: a
                // refinement that repeated would be periodic re-quantization,
                // which is the visible "breathing" this design already rejects.
                if refine_quality > 0 {
                    let s = encoder.begin_static_refinement(refine_quality);
                    refine_armed = true;
                    refine_pending = true;
                    tracing::debug!(
                        quality = s.quality,
                        min_qp = s.min_qp,
                        max_qp = s.max_qp,
                        "static refinement armed"
                    );
                }
                tracing::debug!(
                    "desktop static for {} ms; sending one settle keyframe",
                    since.elapsed().as_millis()
                );
            }
        } else {
            static_since = None;
            settle_sent = false;
        }

        // --- convert + encode -------------------------------------------------
        //
        // Set when the CPU fallback below stages this very frame into
        // `cpu_bgra`, so the refinement pass can reuse those bytes instead of
        // paying for a second whole-frame readback of pixels it already has.
        let mut bgra_is_current = false;
        let encoded = 'encode: {
            if gpu_convert_ok {
                if let Some(conv) = converter.as_mut() {
                    match conv.convert(&frame.texture) {
                        Ok(nv12_tex) => {
                            if gpu_texture_input {
                                break 'encode encoder.submit(FrameInput::Texture(&nv12_tex), ts);
                            }
                            match conv.readback_nv12(&nv12_tex, &mut cpu_nv12) {
                                Ok(()) => {
                                    break 'encode encoder.submit(FrameInput::Nv12(&cpu_nv12), ts)
                                }
                                Err(e) => {
                                    tracing::warn!("NV12 readback failed, dropping to CPU: {e}");
                                    gpu_convert_ok = false;
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("GPU convert failed, dropping to CPU path: {e}");
                            gpu_convert_ok = false;
                        }
                    }
                }
            }
            // CPU fallback: readback BGRA, convert, feed CPU NV12.
            if let Err(e) = capture.readback_bgra(&mut cpu_bgra) {
                break 'encode Err(e);
            }
            bgra_is_current = true;
            let stride = frame.width as usize * 4;
            if let Err(e) =
                bgra_to_nv12(&cpu_bgra, stride, frame.width, frame.height, &mut cpu_nv12)
            {
                break 'encode Err(e);
            }
            encoder.submit(FrameInput::Nv12(&cpu_nv12), ts)
        };

        drop(frame);

        let first = match encoded {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!("encode error: {e}");
                shared.counters.dropped.fetch_add(1, Ordering::Relaxed);
                None
            }
        };

        // A hardware encoder is a pipeline: it may hand back zero frames now and
        // two later. Drain everything it has ready, or throughput silently halves.
        let elapsed = tick.elapsed().as_secs_f32() * 1000.0;
        let mut emitted = 0u32;
        let mut ready = first;
        while let Some(ef) = ready.take() {
            emitted += 1;
            win_encoded += 1;
            win_bytes += ef.data.len() as u64;
            shared.counters.encoded.fetch_add(1, Ordering::Relaxed);
            shared
                .counters
                .bytes
                .fetch_add(ef.data.len() as u64, Ordering::Relaxed);
            if ef.keyframe {
                shared.counters.keyframes.fetch_add(1, Ordering::Relaxed);
                // The refinement's whole effect is "this frame is bigger and
                // sharper". Log the size at INFO so host.log alone answers
                // whether it worked — a refinement that comes out the same size
                // as an ordinary IDR means the MFT ignored the mode (the
                // software encoder does), and one that comes out huge is about
                // to be policed below.
                if refine_pending {
                    refine_pending = false;
                    let bytes = ef.data.len();
                    tracing::info!(
                        bytes,
                        quality = refine_quality,
                        ceiling = STATIC_REFINE_MAX_BYTES,
                        "static refinement keyframe emitted"
                    );
                    let next = adapt_refine_quality(refine_quality, bytes, STATIC_REFINE_MAX_BYTES);
                    if next != refine_quality {
                        if next == 0 {
                            tracing::warn!(
                                bytes,
                                "refinement frames stay oversized at the lowest quality; \
                                 disabling static refinement for this session"
                            );
                        } else {
                            tracing::warn!(
                                bytes,
                                from = refine_quality,
                                to = next,
                                "refinement frame exceeded its size ceiling; lowering quality"
                            );
                        }
                        refine_quality = next;
                    }
                }
            }
            if let Err(full) = frames_tx.try_send(ef) {
                // Queue full: evict the oldest so the consumer always gets the
                // freshest picture, then re-send. Without the retry the *newest*
                // frame is the one lost, which is exactly backwards.
                let _ = drop_rx.try_recv();
                shared.counters.dropped.fetch_add(1, Ordering::Relaxed);
                let _ = frames_tx.try_send(full.into_inner());
            }
            ready = encoder.poll_output();
        }
        win_pipeline_ms += elapsed * emitted as f32;

        maybe_report(
            &shared,
            &mut win_start,
            &mut win_captured,
            &mut win_encoded,
            &mut win_bytes,
            &mut win_pipeline_ms,
        );

        // --- tile refinement pass ---------------------------------------------
        //
        // After the encoder drain and before the frame-budget sleep, for two
        // reasons that both matter:
        //
        // * the capture's texture still holds exactly the pixels the encoder
        //   just coded, so the lossless strip and the H.264 frame describe the
        //   same instant. Reading back later would race the desktop and put
        //   pixels on the wire under a `valid_from_ms` they do not belong to;
        // * the sleep immediately below is genuine idle headroom. On a repeated
        //   frame at 60 fps the loop has typically spent well under 2 ms of its
        //   16.6 ms budget, so the pass spends time the pipeline was about to
        //   throw away. Because `spent` is measured *after* this, the pass eats
        //   into the sleep rather than extending the frame period.
        //
        // Gated on `repeated`: v1 refines strictly on idle frames. It costs a
        // little convergence latency at the tail of a motion burst and in
        // exchange the pass can never compete with a frame that has real work
        // to do. Note that this gate covers only the *expensive* half —
        // revocations are drained unconditionally at the top of the loop.
        if let Some(g) = grid.as_mut() {
            if repeated {
                tile_refine_pass(
                    g,
                    &mut capture,
                    &mut cpu_bgra,
                    bgra_is_current,
                    &tiles_tx,
                    &cfg,
                    ts,
                    tile_pass_bytes(
                        shared.tile_budget_kbps.load(Ordering::Relaxed),
                        shared.fps_now.load(Ordering::Relaxed),
                    ),
                    &mut tile_bucket,
                    &mut tile_win,
                    &mut revoke_retry,
                    &shared.tiles_reset_req,
                );
            }
            if tile_win_start.elapsed() >= TILE_REPORT_EVERY {
                log_tile_window(&tile_win, g.stats());
                tile_win = TileWindow::default();
                tile_win_start = Instant::now();
            }
        }

        let spent = tick.elapsed();
        if spent < frame_budget {
            std::thread::sleep(frame_budget - spent);
        }
    }

    shared.set_state(SessionState::Stopped);
}

// ---- lossless tile refinement --------------------------------------------

/// How often the refinement pass reports what it has been doing.
const TILE_REPORT_EVERY: Duration = Duration::from_secs(1);

/// Translate DXGI's dirty rects into the pure type [`crate::tiles`] works in.
///
/// Four field copies and no arithmetic, by design: [`DirtyRect`] was given
/// DXGI's own signed, half-open left/top/right/bottom shape precisely so that
/// this boundary cannot introduce a sign error or an off-by-one. Every
/// degenerate case — an inverted rect, a negative origin, a rect larger than
/// the frame — is normalised inside the grid, once, where it is tested.
///
/// The `Option` is carried through **untouched**. `None` means the driver could
/// not answer, which the grid turns into "assume the entire screen changed";
/// `Some(&[])` means it answered "nothing changed". Collapsing those two into
/// an empty list is the single most dangerous mistake available on this path —
/// it would refine pixels that no longer exist — so nothing here invents one.
fn translate_dirty<'a>(
    src: Option<&[windows::Win32::Foundation::RECT]>,
    out: &'a mut Vec<DirtyRect>,
) -> Option<&'a [DirtyRect]> {
    let src = src?;
    out.clear();
    out.extend(
        src.iter()
            .map(|r| DirtyRect::ltrb(r.left, r.top, r.right, r.bottom)),
    );
    Some(&out[..])
}

/// Translate DXGI's move rects, under the same `None`-vs-empty contract as
/// [`translate_dirty`]. The two lists come from the same per-frame metadata
/// block and fail together.
fn translate_moves<'a>(
    src: Option<&[windows::Win32::Graphics::Dxgi::DXGI_OUTDUPL_MOVE_RECT]>,
    out: &'a mut Vec<MoveRect>,
) -> Option<&'a [MoveRect]> {
    let src = src?;
    out.clear();
    out.extend(src.iter().map(|m| {
        let d = m.DestinationRect;
        MoveRect::new(
            m.SourcePoint.x,
            m.SourcePoint.y,
            DirtyRect::ltrb(d.left, d.top, d.right, d.bottom),
        )
    }));
    Some(&out[..])
}

/// How many strips one refinement pass may plan.
///
/// Two independent limits, and the pass takes the smaller of them:
///
/// * `per_pass` — the configured work-and-bandwidth budget for a single pass;
/// * whatever the tile queue has left **after reserving `reserve` slots**, so
///   the revocation that supersedes these strips can never be crowded out by
///   the strips themselves.
///
/// That second limit is the whole ordering policy in one expression. Strips are
/// droppable *before* they are queued — a dropped strip merely leaves the client
/// showing H.264 for that square — but a dropped revocation leaves the client
/// compositing pixels the host has already repainted, for as long as the lease
/// runs. Keeping a floor of free slots means the planner can never put the
/// queue into the state where that becomes possible.
///
/// Pure and free-standing because it is the easy thing to get subtly wrong and
/// the hard thing to observe: an off-by-one that lets the planner fill the queue
/// shows up as stale pixels under a lease, not as a crash. Note the saturating
/// arithmetic — a queue fuller than the reserve line, or a `reserve` larger than
/// the whole queue, must answer "plan nothing", never wrap into a huge budget.
/// Bytes of tile payload one refinement pass may queue.
///
/// The network layer publishes a per-*second* allowance; a pass runs at most
/// once per captured frame, so the per-pass share is that allowance divided by
/// the frame rate. Taken from the *live* rate rather than the configured one,
/// so lowering fps does not silently multiply tile traffic per pass.
/// Ceiling on the carried-over allowance.
///
/// The per-pass share of a small budget is smaller than a single strip: at the
/// throttle's 500 kbps floor and 60 fps it is 1041 bytes, while a strip of text
/// is 1-4 KiB. Spent strictly per pass, every strip would be refused forever,
/// nothing would ever be sent, and the throttle — which grows its ceiling only
/// on evidence of spending — would stay floored permanently. So the allowance
/// accumulates until a strip fits.
///
/// Capped at one worst-case strip plus a pass, which is the least that
/// guarantees any legal strip eventually becomes affordable while bounding how
/// much a long-idle period may hoard and release in one burst.
fn tile_bucket_cap(pass_bytes: usize) -> usize {
    directdesk_shared::tiles::MAX_STRIP_ENCODED.saturating_add(pass_bytes)
}

fn tile_pass_bytes(budget_kbps: u32, fps_now: u32) -> usize {
    let per_second = u64::from(budget_kbps) * 1000 / 8;
    (per_second / u64::from(fps_now.max(1))) as usize
}

fn strip_budget(per_pass: u32, queued: usize, capacity: usize, reserve: usize) -> usize {
    capacity
        .saturating_sub(reserve)
        .saturating_sub(queued)
        .min(per_pass as usize)
}

/// How long before a lease expires a refined tile becomes eligible for renewal.
///
/// A third of the lease. Long enough that several idle frames — and therefore
/// several refinement passes — fall inside the window even at a low frame rate
/// and with the per-pass budget spreading a large screen over many passes;
/// short enough that renewals are a minority of a static screen's tile traffic
/// rather than its bulk. Floored at 1 ms so a pathologically short lease still
/// has a non-empty window instead of one that opens exactly at the instant
/// `begin_pass` has already dropped the tile.
fn renew_lead_ms(lease_ms: u32) -> u32 {
    (lease_ms / 3).max(1)
}

/// Put a message that may **not** be dropped on the tile queue.
///
/// `Revoke` and `Reset` are the two messages whose loss can leave the client
/// painting pixels the host no longer has. [`strip_budget`] reserves
/// [`TILE_QUEUE_REVOKE_RESERVE`] slots precisely so this cannot happen, so a
/// failure here means the network pump has been stalled long enough to fill
/// even the reserve. That earns a `warn`, not a `debug`: it is the one drop in
/// this feature with a visible consequence, and it is bounded only by the tile
/// lease (and by the re-send that follows, since a revoked tile is back in
/// `Moving` and will be planned again).
///
/// `Ok(())` once the message is on the queue. `Err(msg)` hands the message
/// straight back rather than dropping it, so a caller that cannot afford to lose
/// it can retry on the next pass — losing it silently is precisely the failure
/// this signature exists to make impossible.
fn send_tile_control(tx: &Sender<TileMsg>, msg: TileMsg) -> std::result::Result<(), TileMsg> {
    let what = match &msg {
        TileMsg::Reset { .. } => "reset",
        TileMsg::Revoke { .. } => "revoke",
        _ => "control message",
    };
    match tx.try_send(msg) {
        Ok(()) => Ok(()),
        Err(e) => {
            tracing::warn!(
                queued = tx.len(),
                "tile queue full: dropped a {what}; the client may composite stale tiles \
                 until their lease expires"
            );
            Err(e.into_inner())
        }
    }
}

/// Put the grid's pending revocations on the wire, keeping whatever the queue
/// refused so the next pass retries it.
///
/// `TileGrid::take_revocations` **consumes** the pending set — it `mem::take`s
/// the id list and clears every tile's `revoke_pending` flag — so unlike a
/// `Strip`, this message cannot simply be dropped when the queue is full. The
/// ids would be gone for good and the client would go on compositing tiles the
/// host has already retracted, bounded only by the lease.
///
/// The grid cannot take them back, and `mark_tiles_dirty` only looks like the
/// way to re-queue them: every id in a revocation has already been driven to
/// `TileState::Moving`, and `touch` queues a revoke only for a tile it finds
/// `Refined` or `Settling`, so re-marking them is a no-op on the pending set.
/// Re-driving them therefore happens *here*, by holding the ids in `retry` and
/// merging them into the next pass's revocation. This is also why `retry` is
/// owned by the media thread rather than by the grid — no host-side state can
/// express "revoked, but not yet told".
///
/// A dropped `Reset` is the one case that cannot be expressed as an id list:
/// `take_revocations` already re-armed the grid, so only a fresh `Reset` puts
/// the two sides back in agreement. That path re-arms `reset_req` instead,
/// exactly as the resize path does, and keeps `retry` intact because nothing has
/// been retracted yet.
fn drain_revocations(
    grid: &mut TileGrid,
    tx: &Sender<TileMsg>,
    win: &mut TileWindow,
    retry: &mut Vec<u32>,
    reset_req: &AtomicBool,
    now_ms: u32,
) {
    let msg = match grid.take_revocations(now_ms) {
        // Merge in what a previous pass could not queue, so the client sees one
        // message rather than two and the ids stay in raster order.
        Some(TileMsg::Revoke { mut ids }) => {
            if !retry.is_empty() {
                ids.append(retry);
                ids.sort_unstable();
                ids.dedup();
            }
            TileMsg::Revoke { ids }
        }
        // A `Reset` retracts everything, held ids included — but they are only
        // safe to forget once it is actually queued, which is decided below.
        Some(other) => other,
        None if !retry.is_empty() => TileMsg::Revoke {
            ids: std::mem::take(retry),
        },
        None => return,
    };
    win.note_control(&msg);
    let was_reset = matches!(msg, TileMsg::Reset { .. });
    match send_tile_control(tx, msg) {
        Ok(()) => {
            if was_reset {
                retry.clear();
            }
        }
        // Hold the ids for the next pass; `send_tile_control` handed them back
        // precisely so this is possible, and it has already logged the drop.
        //
        // Residual, stated accurately: if a held id is re-sent as a strip
        // before the retry flushes, the retry retracts a tile that is now
        // legitimately refined. That is NOT "bounded by one lease" — the host
        // believes the tile is `Refined` and `plan_reverify`/`commit_renewed`
        // keep extending its lease, so `begin_pass`'s expiry path never fires
        // and it is never re-sent. The region stays on H.264 until its pixels
        // actually change or the session resets.
        //
        // Kept because it needs a one-frame race (the top-of-frame drain must
        // fail on a full queue *and* the pump must free more than the revoke
        // reserve during convert/encode), and because it errs toward
        // over-revoking, which is the direction the grid's governing invariant
        // explicitly prefers. Excluding ids committed this pass would close it
        // if it is ever observed.
        Err(TileMsg::Revoke { ids }) => *retry = ids,
        Err(_) => reset_req.store(true, Ordering::Relaxed),
    }
}

/// A window of refinement activity, for the periodic diagnostic line.
#[derive(Default)]
struct TileWindow {
    strips: u32,
    renewed: u32,
    revoked: u32,
    resets: u32,
    /// Strips planned and compressed, then thrown away because the queue was
    /// full. Nonzero means the pass is outrunning the pump and CPU is being
    /// spent on pixels that never leave this thread.
    backpressured: u32,
    /// Strips declined because the link had no spare bandwidth this pass.
    /// Distinct from `backpressured`: this one is the throttle working as
    /// intended, not the pump falling behind.
    budget_held: u32,
    /// BGR bytes the queued strips covered, before compression.
    raw_bytes: u64,
    /// Bytes actually queued for the wire.
    wire_bytes: u64,
}

impl TileWindow {
    fn note_control(&mut self, msg: &TileMsg) {
        match msg {
            TileMsg::Reset { .. } => self.resets += 1,
            TileMsg::Revoke { ids } => self.revoked += ids.len() as u32,
            _ => {}
        }
    }

    /// Compressed size as a fraction of the raw BGR the strips covered.
    ///
    /// This is the number that says whether the feature is actually working.
    /// Monochrome text through the adaptive row filter plus deflate lands at
    /// roughly 0.02-0.08. Anything above ~0.3 means alpha is reaching the
    /// compressor or the row filter is not being applied, and the "cheap"
    /// lossless traffic is costing far more than the refinement is worth.
    fn ratio(&self) -> f64 {
        if self.raw_bytes == 0 {
            0.0
        } else {
            self.wire_bytes as f64 / self.raw_bytes as f64
        }
    }

    fn is_quiet(&self) -> bool {
        self.strips == 0
            && self.renewed == 0
            && self.revoked == 0
            && self.resets == 0
            && self.backpressured == 0
    }
}

/// Report a window of refinement activity.
///
/// Two levels on purpose. A window that actually put pixels on the wire (or
/// failed to) goes to `info`, so `host.log` alone answers "is the codec
/// working and what ratio is it achieving" during the convergence phase that
/// matters. Once the screen has converged only renewals remain, and a
/// once-a-second line about them forever would be noise, so that drops to
/// `debug`. A window in which nothing at all happened is not logged.
fn log_tile_window(win: &TileWindow, stats: GridStats) {
    if win.is_quiet() {
        return;
    }
    if win.strips > 0 || win.backpressured > 0 || win.budget_held > 0 {
        tracing::info!(
            strips = win.strips,
            renewed = win.renewed,
            revoked = win.revoked,
            resets = win.resets,
            backpressured = win.backpressured,
            budget_held = win.budget_held,
            refined = stats.refined,
            moving = stats.moving,
            settling = stats.settling,
            pending_revokes = stats.pending_revokes,
            wire_kib = win.wire_bytes / 1024,
            ratio = win.ratio(),
            "lossless tile refinement"
        );
    } else {
        tracing::debug!(
            renewed = win.renewed,
            revoked = win.revoked,
            resets = win.resets,
            refined = stats.refined,
            moving = stats.moving,
            pending_revokes = stats.pending_revokes,
            "lossless tiles holding"
        );
    }
}

/// One lossless refinement pass: send pixel-exact strips for everything that
/// has settled, renew the leases about to run out, and retract whatever
/// re-verification found stale.
///
/// The pass structure is the one specified in [`crate::tiles`]'s module doc and
/// deviating from it is not safe: every plan handed out by `plan_strips` claims
/// its tiles, so every plan must be resolved by `commit_sent` or `abandon`
/// before this function returns, or the next pass revokes them.
#[allow(clippy::too_many_arguments)]
fn tile_refine_pass(
    grid: &mut TileGrid,
    capture: &mut DdaCapture,
    cpu_bgra: &mut Vec<u8>,
    bgra_is_current: bool,
    tiles_tx: &Sender<TileMsg>,
    cfg: &SessionConfig,
    now_ms: u32,
    // Bytes of tile payload the network layer's measured spare bandwidth
    // affords this pass. `0` means send nothing.
    pass_bytes: usize,
    // Carried-over allowance, so a per-pass share smaller than one strip still
    // adds up to something sendable. See `tile_bucket_cap`.
    bucket: &mut usize,
    win: &mut TileWindow,
    // Revocations a previous pass could not queue, carried by the media thread
    // across frames. See [`drain_revocations`].
    revoke_retry: &mut Vec<u32>,
    reset_req: &AtomicBool,
) {
    // ONE whole-frame readback, never a map per tile.
    //
    // This looks wasteful and is not. Each `Map` on a staging texture is a
    // CPU/GPU synchronisation point, so the per-map cost dominates completely:
    // a single 1080p BGRA transfer runs ~2-4 ms, while the ~120 sub-rect maps
    // a tile-at-a-time extraction would need run ~12-24 ms — and would not fit
    // in the frame budget's idle slack at all. There is deliberately no
    // per-tile `CopySubresourceRegion` path.
    //
    // Skipped outright when the CPU convert fallback already staged this very
    // frame into this very buffer.
    if !bgra_is_current {
        if let Err(e) = capture.readback_bgra(cpu_bgra) {
            tracing::debug!("tile readback failed; skipping this refinement pass: {e}");
            return;
        }
    }

    // `readback_bgra` produces a tightly-packed buffer at the capture's own
    // dimensions, which is what the grid was sized from.
    let (width, height) = grid.dimensions();
    let stride = width as usize * 4;
    let want = stride.saturating_mul(height as usize);
    if want == 0 || cpu_bgra.len() < want {
        // Checked once here rather than discovered per strip: a short buffer
        // makes every hash and every compress fail individually, which would
        // burn the whole pass planning and abandoning work that cannot succeed.
        tracing::debug!(
            got = cpu_bgra.len(),
            want,
            "tile readback does not match the grid; skipping the pass"
        );
        return;
    }
    let bgra: &[u8] = &cpu_bgra[..];
    let lease_ms = cfg.lossless_tile_lease_ms;
    let level = cfg.lossless_tile_deflate_level.clamp(1, 9) as u8;
    let capacity = tiles_tx.capacity().unwrap_or(usize::MAX);

    // -- strips ------------------------------------------------------------
    // Two independent limits, and both must hold: the queue must keep room for
    // a revocation, and the link must have the bandwidth to spare. A zero
    // bandwidth budget plans nothing but still runs the pass below, because
    // `plan_strips` calls `begin_pass` and that is what expires leases and
    // sweeps unresolved tiles — freezing the state machine under congestion is
    // exactly when stale pixels would linger.
    *bucket = bucket
        .saturating_add(pass_bytes)
        .min(tile_bucket_cap(pass_bytes));
    let allowance = *bucket;
    let budget = if allowance == 0 {
        0
    } else {
        strip_budget(
            cfg.lossless_tiles_per_pass,
            tiles_tx.len(),
            capacity,
            TILE_QUEUE_REVOKE_RESERVE,
        )
    };
    let mut spent_bytes = 0usize;
    // Called even when the budget is zero. `plan_strips` runs `begin_pass`
    // first, and that is what expires leases and sweeps tiles whose fate was
    // never reported — skipping it under backpressure would freeze the state
    // machine exactly when it most needs to move.
    let plans = grid.plan_strips(now_ms, cfg.lossless_tile_settle_ms, budget);
    let mut stalled = false;
    for plan in &plans {
        if stalled {
            // The queue filled mid-pass. Everything still claimed has to be
            // released explicitly: a plan left `Settling` is revoked at the
            // start of the next pass, which spends a revocation retracting a
            // tile the client was never sent.
            grid.abandon(plan);
            continue;
        }
        let Some(hashes) = hash_plan_tiles(bgra, stride, plan) else {
            // Cannot hash means cannot suppress the next re-send safely, so do
            // not send at all — the tile stays on H.264 and is retried.
            grid.abandon(plan);
            continue;
        };
        let (codec, data) =
            match compress_strip(bgra, stride, plan.x, plan.y, plan.w, plan.h, level) {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!("tile strip compress failed: {e}");
                    grid.abandon(plan);
                    continue;
                }
            };
        let wire = data.len() as u64;
        // Spend the bandwidth budget here, BEFORE queueing — the only point at
        // which a strip can still be declined safely. Past `try_send` the grid
        // records it as delivered, so anything downstream that discarded it
        // would leave that square soft until the client reconnects.
        if spent_bytes.saturating_add(data.len()) > allowance {
            grid.abandon(plan);
            win.budget_held += 1;
            stalled = true;
            continue;
        }
        let msg = TileMsg::Strip {
            x: plan.x,
            y: plan.y,
            w: plan.w,
            h: plan.h,
            codec,
            valid_from_ms: now_ms,
            lease_ms,
            data,
        };
        // `commit_sent` happens ONLY after the message is actually queued.
        // Recording a strip as delivered when it never left this thread is how
        // a tile goes permanently soft: the recorded hash then makes
        // `strip_matches_sent` suppress the very re-send the client needs.
        if tiles_tx.try_send(msg).is_ok() {
            grid.commit_sent(plan, &hashes, now_ms, lease_ms);
            spent_bytes = spent_bytes.saturating_add(wire as usize);
            *bucket = bucket.saturating_sub(wire as usize);
            win.strips += 1;
            win.wire_bytes += wire;
            win.raw_bytes += u64::from(plan.w) * u64::from(plan.h) * 3;
        } else {
            grid.abandon(plan);
            win.backpressured += 1;
            stalled = true;
        }
    }

    // -- renewals ----------------------------------------------------------
    //
    // Re-hash before extending a lease. A blind renew would extend the life of
    // pixels nobody re-checked, so one dirty rect the driver failed to report
    // would become permanently wrong pixels — the exact outcome leases exist to
    // bound. The budget is recomputed because the strips above just consumed
    // queue slots, and a `Renew` occupies a slot like anything else.
    let budget = strip_budget(
        cfg.lossless_tiles_per_pass,
        tiles_tx.len(),
        capacity,
        TILE_QUEUE_REVOKE_RESERVE,
    );
    for plan in grid.plan_reverify(now_ms, renew_lead_ms(lease_ms), budget) {
        let Some(hashes) = hash_plan_tiles(bgra, stride, &plan) else {
            grid.mark_tiles_dirty(plan.ids(), now_ms);
            continue;
        };
        if !grid.strip_matches_sent(&plan, &hashes) {
            // The pixels moved without the driver saying so. Back to `Moving`,
            // and `touch` queues the revoke the drain below sends. These tiles
            // were stamped at `now_ms`, so they cannot have been in this pass's
            // strips — there is no strip-then-revoke of the same tile here.
            grid.mark_tiles_dirty(plan.ids(), now_ms);
            continue;
        }
        let valid_through_ms = now_ms.wrapping_add(lease_ms);
        let renew = TileMsg::Renew {
            ids: plan.ids().to_vec(),
            valid_through_ms,
        };
        if tiles_tx.try_send(renew).is_err() {
            // Not renewed and nothing to retract: an unrenewed lease simply
            // runs out, the client drops the tile itself, and `begin_pass` puts
            // it back in `Moving` for a fresh send. Stop — the queue is full.
            break;
        }
        grid.commit_renewed(plan.ids(), valid_through_ms);
        win.renewed += plan.tiles();
    }

    // -- revocations -------------------------------------------------------
    //
    // Last, and never dropped. Catches what the renewal sweep just marked, plus
    // (belt and braces) anything `begin_pass` swept up because a previous pass
    // failed to resolve a plan. Anything the queue still refuses is held in
    // `revoke_retry` and goes out at the top of the next frame.
    drain_revocations(grid, tiles_tx, win, revoke_retry, reset_req, now_ms);
}

fn enter_pause(
    shared: &Arc<Shared>,
    ctl_tx: &Sender<InputCtl>,
    paused_since: &mut Option<Instant>,
    why: &str,
) {
    if paused_since.is_none() {
        *paused_since = Some(Instant::now());
        shared.set_state(SessionState::Paused(why.to_string()));
        // Never leave keys held while the user is at a UAC prompt.
        let _ = ctl_tx.send(InputCtl::ReleaseAll);
    }
}

fn maybe_report(
    shared: &Arc<Shared>,
    win_start: &mut Instant,
    captured: &mut u32,
    encoded: &mut u32,
    bytes: &mut u64,
    pipeline_ms: &mut f32,
) {
    let elapsed = win_start.elapsed();
    if elapsed < Duration::from_millis(500) {
        return;
    }
    let secs = elapsed.as_secs_f32().max(f32::EPSILON);
    let mut s = shared.stats.lock();
    s.fps_capture = *captured as f32 / secs;
    s.fps_encode = *encoded as f32 / secs;
    s.bitrate_kbps = ((*bytes as f64 * 8.0 / secs as f64) / 1000.0) as u32;
    s.pipeline_ms = if *encoded > 0 {
        *pipeline_ms / *encoded as f32
    } else {
        0.0
    };
    s.frames_dropped = shared.counters.dropped.load(Ordering::Relaxed) as u32;
    s.keyframes_requested = shared.counters.keyframes.load(Ordering::Relaxed) as u32;
    drop(s);

    *win_start = Instant::now();
    *captured = 0;
    *encoded = 0;
    *bytes = 0;
    *pipeline_ms = 0.0;
}

/// How long one frame is allowed to take before the media loop sleeps out the
/// rest of it. `0` is treated as 1 — the loop must never divide by zero, and a
/// config that says "no frames" means nothing sensible.
fn frame_budget(fps: u32) -> Duration {
    Duration::from_micros(1_000_000 / fps.max(1) as u64)
}

/// Is this the moment to spend the one settle keyframe of this idle period?
///
/// Pure so the decision can be tested without a desktop: `static_for` is how
/// long the image has been unchanged, `delay` is the configured settle (zero
/// disables), `already_sent` is the latch that keeps it one-shot.
fn should_settle(static_for: Duration, delay: Duration, already_sent: bool) -> bool {
    !delay.is_zero() && !already_sent && static_for >= delay
}

/// A new encoder for the live capture, at `want` fps.
///
/// Deliberately *only* the encoder: it mirrors the `EncoderConfig` block of
/// [`build_pipeline`] and reuses the existing capture's D3D device, so nothing
/// about the capture, the adapter or the published [`SessionDescription`]
/// changes. Calling `build_pipeline` here instead would construct a second
/// `DdaCapture` — a duplicate desktop duplication, which is exactly the thing a
/// live frame-rate change must not do.
///
/// `bitrate_kbps` is the rate currently in force (the adaptor's, not the
/// config's): rebuilding at `cfg.bitrate_kbps` would silently undo every
/// adaptive step taken so far and hold the wrong rate until the adaptor next
/// happens to change its mind.
fn rebuild_encoder(
    cfg: &SessionConfig,
    capture: &DdaCapture,
    want: u32,
    bitrate_kbps: u32,
) -> Result<MfH264Encoder> {
    let (w, h) = {
        use directdesk_shared::traits::FrameSource;
        capture.dimensions()
    };
    let info = capture.adapter_info().clone();
    let enc_cfg = EncoderConfig {
        width: w,
        height: h,
        fps: want.max(1),
        bitrate_kbps: bitrate_kbps.max(1),
        gop_seconds: cfg.gop_seconds.max(1),
        adapter_luid: Some(info.luid),
        adapter_vendor_id: Some(info.vendor_id),
        adapter_name: info.short(),
    };
    MfH264Encoder::new(enc_cfg, Some(capture.device()))
}

type Pipeline = (
    DdaCapture,
    Option<GpuConverter>,
    MfH264Encoder,
    SessionDescription,
);

fn build_pipeline(cfg: &SessionConfig) -> Result<Pipeline> {
    let mut capture = DdaCapture::new()?;
    if cfg.idle_repeat_ms == 0 {
        capture.set_repeat_after(Duration::MAX);
    } else {
        capture.set_repeat_after(Duration::from_millis(cfg.idle_repeat_ms as u64));
    }
    let (w, h) = {
        use directdesk_shared::traits::FrameSource;
        capture.dimensions()
    };
    let info = capture.adapter_info().clone();

    let converter = if cfg.force_cpu_convert {
        tracing::info!("GPU conversion disabled by config; using CPU BT.709");
        None
    } else {
        match GpuConverter::new(capture.device(), capture.context(), w, h) {
            Ok(c) => Some(c),
            Err(e) => {
                tracing::warn!("GPU NV12 converter unavailable ({e}); using CPU BT.709");
                None
            }
        }
    };

    let enc_cfg = EncoderConfig {
        width: w,
        height: h,
        fps: cfg.target_fps.max(1),
        bitrate_kbps: cfg.bitrate_kbps.max(1),
        gop_seconds: cfg.gop_seconds.max(1),
        adapter_luid: Some(info.luid),
        adapter_vendor_id: Some(info.vendor_id),
        adapter_name: info.short(),
    };
    let encoder = MfH264Encoder::new(enc_cfg, Some(capture.device()))?;

    let desc = SessionDescription {
        adapter: info.name.clone(),
        adapter_luid: info.luid,
        output: info.output_name.clone(),
        monitor_origin: info.origin,
        encoder: encoder.describe(),
        width: w,
        height: h,
        gpu_convert: converter.is_some(),
        gpu_encode_input: converter.is_some() && encoder.accepts_textures(),
        hardware_encoder: encoder.path().is_hardware(),
    };
    tracing::info!("pipeline: {}", desc.pipeline_summary());
    Ok((capture, converter, encoder, desc))
}

// ---- input thread ------------------------------------------------------------

/// Nudge the injection thread above the capture/encode/video-egress threads
/// so `SendInput` preempts them under full video load. This enforces the app's
/// core "input takes priority over video" invariant at the OS scheduler.
/// Best-effort: a failure just leaves it at normal priority.
fn raise_input_thread_priority() {
    use windows::Win32::System::Threading::{
        GetCurrentThread, SetThreadPriority, THREAD_PRIORITY_ABOVE_NORMAL,
    };
    // SAFETY: GetCurrentThread returns a pseudo-handle to this very thread; the
    // priority set is a documented, side-effect-free scheduler hint.
    unsafe {
        if let Err(e) = SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL) {
            tracing::warn!("could not raise input-thread priority: {e}");
        }
    }
}

/// Drop a video thread (capture/encode or datagram sender) below normal so it
/// yields the CPU to the network runtime and input path. On a weak host, full
/// 1080p capture+encode+send otherwise saturates every core and starves the
/// async input-ingress tasks (input_read_loop -> input_loop) and the QUIC
/// driver's receive side — the observed bug where typed keys did not inject
/// until the client minimized and video stopped. The other half of the
/// invariant that [`raise_input_thread_priority`] enforces from the top.
pub(crate) fn lower_video_thread_priority(what: &str) {
    use windows::Win32::System::Threading::{
        GetCurrentThread, SetThreadPriority, THREAD_PRIORITY_BELOW_NORMAL,
    };
    // SAFETY: pseudo-handle to this thread; priority is a scheduler hint only.
    unsafe {
        if let Err(e) = SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL) {
            tracing::warn!("could not lower {what}-thread priority: {e}");
        }
    }
}

fn input_thread(
    desc: SessionDescription,
    shared: Arc<Shared>,
    events: Receiver<InputEvent>,
    ctl: Receiver<InputCtl>,
) {
    raise_input_thread_priority();
    let mut injector = WinInjector::new(desc.width, desc.height, desc.monitor_origin);
    // When `Some`, input is routed here (to the SYSTEM UAC worker) and NOT
    // injected locally. Owned by this thread so the choice is made in one place.
    let mut route: Option<Sender<InputEvent>> = None;
    loop {
        if shared.stop.load(Ordering::Relaxed) {
            break;
        }
        crossbeam_channel::select! {
            recv(events) -> msg => match msg {
                Ok(ev) => {
                    if let Some(sink) = &route {
                        // Exclusive: forward to the worker, never inject locally.
                        if sink.send(ev).is_err() {
                            // The worker side is gone; stop routing and fall back
                            // to local injection for subsequent events.
                            tracing::warn!("elevation route sink closed; reverting to local injection");
                            route = None;
                            let _ = injector.release_all();
                        }
                    } else {
                        match injector.inject(&ev) {
                            Ok(()) => {
                                shared.counters.input_injected.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(e) => tracing::warn!("input injection failed: {e}"),
                        }
                    }
                }
                Err(_) => break,
            },
            recv(ctl) -> msg => match msg {
                Ok(InputCtl::Geometry { w, h, origin }) => injector.set_frame(w, h, origin),
                Ok(InputCtl::ReleaseAll) => {
                    if let Err(e) = injector.release_all() {
                        tracing::warn!("release_all failed: {e}");
                    }
                }
                Ok(InputCtl::ElevationRoute(sink)) => {
                    // Release everything held locally before *and* after the
                    // handoff so no key/button is stuck on either side.
                    if let Err(e) = injector.release_all() {
                        tracing::warn!("release_all before route switch failed: {e}");
                    }
                    route = sink;
                }
                Ok(InputCtl::Stop) => break,
                Err(_) => break,
            },
            default(Duration::from_millis(100)) => {}
        }
    }
    let _ = injector.release_all();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_sane() {
        let c = SessionConfig::default();
        assert!(c.target_fps > 0 && c.frame_queue_depth > 0);
        assert!(c.bitrate_kbps > 0);
    }

    #[test]
    fn frame_budget_follows_the_frame_rate() {
        assert_eq!(frame_budget(1), Duration::from_millis(1_000));
        assert_eq!(frame_budget(15), Duration::from_micros(66_666));
        assert_eq!(frame_budget(60), Duration::from_micros(16_666));
        assert_eq!(frame_budget(240), Duration::from_micros(4_166));
        // Lower fps means a bigger budget — the whole point of the control.
        assert!(frame_budget(15) > frame_budget(60));
    }

    #[test]
    fn frame_budget_never_divides_by_zero() {
        assert_eq!(frame_budget(0), frame_budget(1));
    }

    #[test]
    fn settle_fires_once_after_the_delay() {
        let delay = Duration::from_millis(700);
        assert!(!should_settle(Duration::from_millis(699), delay, false));
        assert!(should_settle(Duration::from_millis(700), delay, false));
        assert!(should_settle(Duration::from_secs(30), delay, false));
        // Latched: no second settle until a real frame clears the flag.
        assert!(!should_settle(Duration::from_secs(30), delay, true));
    }

    // The bound only means anything if it is comfortably below the size at
    // which a keyframe is refused outright (no picture, plus a forced bitrate
    // cut) — and still big enough that a refinement is worth doing at all: a
    // sharp 1080p intra frame is well over 100 KB. Both relations are between
    // constants, so they are checked when the crate compiles rather than when
    // someone remembers to run the tests.
    const _: () = assert!(STATIC_REFINE_MAX_BYTES * 2 < FRAGMENTER_FRAME_LIMIT_BYTES);
    const _: () = assert!(STATIC_REFINE_MAX_BYTES > 128 * 1024);

    #[test]
    fn refinement_ceiling_derivation_is_what_it_claims() {
        assert_eq!(FRAGMENTER_FRAME_LIMIT_BYTES, 512 * (1200 - 14));
        assert_eq!(MAX_FRAGS_PER_FRAME, 512);
        assert_eq!(FRAG_HEADER_LEN, 14);
        assert_eq!(STATIC_REFINE_MAX_BYTES, 242_892);
    }

    #[test]
    fn refinement_quality_backs_off_only_when_oversized() {
        let ceiling = STATIC_REFINE_MAX_BYTES;
        // Within budget: untouched, no drift.
        assert_eq!(adapt_refine_quality(88, 100_000, ceiling), 88);
        assert_eq!(adapt_refine_quality(88, ceiling, ceiling), 88);
        // Over budget: one step down.
        assert_eq!(
            adapt_refine_quality(88, ceiling + 1, ceiling),
            88 - REFINE_QUALITY_STEP
        );
        // Never below the permitted band...
        assert_eq!(
            adapt_refine_quality(MIN_STATIC_REFINE_QUALITY + 1, ceiling + 1, ceiling),
            MIN_STATIC_REFINE_QUALITY
        );
        // ...and at the bottom, off rather than an infinite ladder.
        assert_eq!(
            adapt_refine_quality(MIN_STATIC_REFINE_QUALITY, ceiling + 1, ceiling),
            0
        );
        // Disabled stays disabled whatever is observed.
        assert_eq!(adapt_refine_quality(0, usize::MAX, ceiling), 0);
    }

    #[test]
    fn refinement_backoff_terminates() {
        // Worst case — every refinement oversized — must reach 0 in a few
        // steps and stay there, never oscillate.
        let mut q = MAX_STATIC_REFINE_QUALITY;
        for _ in 0..32 {
            q = adapt_refine_quality(q, usize::MAX, STATIC_REFINE_MAX_BYTES);
        }
        assert_eq!(q, 0);
    }

    #[test]
    fn settle_delay_of_zero_disables_it() {
        assert!(!should_settle(
            Duration::from_secs(60),
            Duration::ZERO,
            false
        ));
    }

    // Long enough to outlast a scroll, short enough not to outlast a pause.
    const _: () = assert!(STATIC_SETTLE_MS >= 300 && STATIC_SETTLE_MS <= 2_000);

    #[test]
    fn state_liveness() {
        assert!(SessionState::Running.is_live());
        assert!(SessionState::Paused("secure desktop".into()).is_live());
        assert!(!SessionState::Stopped.is_live());
        assert!(!SessionState::Failed("x".into()).is_live());
    }

    // -- lossless tile wiring ------------------------------------------------

    #[test]
    fn a_zero_budget_sends_nothing_and_never_divides_by_zero() {
        // The strain case: `status_loop` zeroes the allowance the moment the
        // link shows backpressure or loss, and refinement must stop dead
        // rather than merely slow down.
        assert_eq!(tile_pass_bytes(0, 60), 0);
        // fps is read live and can legitimately be 0 before the first rebuild
        // publishes a rate.
        assert_eq!(tile_pass_bytes(8_000, 0), tile_pass_bytes(8_000, 1));
    }

    #[test]
    fn pass_bytes_divide_the_second_allowance_by_the_live_frame_rate() {
        // 8000 kbps = 1_000_000 B/s; at 60 fps a single pass may queue ~16 KiB.
        assert_eq!(tile_pass_bytes(8_000, 60), 16_666);
        // Halving the frame rate must not double the per-second spend — the
        // per-pass share grows precisely because there are half as many passes.
        assert_eq!(tile_pass_bytes(8_000, 30), 33_333);
        // The per-second spend must come out the same at any frame rate: the
        // per-pass share grows precisely because there are fewer passes. Only
        // the flooring differs, and it can lose at most `fps - 1` bytes/second.
        for fps in [15u32, 30, 60, 144] {
            let per_second = tile_pass_bytes(8_000, fps) * fps as usize;
            assert!(
                (1_000_000 - fps as usize) < per_second && per_second <= 1_000_000,
                "at {fps} fps the per-second spend drifted to {per_second}"
            );
        }
    }

    #[test]
    fn the_allowance_accumulates_until_a_real_strip_fits() {
        // The livelock this bucket exists to prevent. At the throttle's floor
        // (500 kbps) and the default 60 fps, one pass affords 1041 bytes — less
        // than a single strip of text, which the module's own compression
        // figures put at 1-4 KiB. Spent strictly per pass, every strip is
        // refused, nothing is ever sent, `spent_kbps` stays 0, and the throttle
        // (which grows only on evidence of spending) stays floored forever. The
        // feature would burn a whole-frame readback, hash and deflate on every
        // idle frame and emit nothing.
        let pass = tile_pass_bytes(TILE_CEILING_FLOOR_KBPS_FOR_TEST, 60);
        assert!(
            pass < 4_096,
            "precondition: a floored per-pass share really is smaller than a strip ({pass})"
        );

        let mut bucket = 0usize;
        let cap = tile_bucket_cap(pass);
        let mut passes = 0;
        while bucket < 4_096 {
            bucket = bucket.saturating_add(pass).min(cap);
            passes += 1;
            assert!(passes < 1_000, "the allowance never reached one strip");
        }
        // A few frames, not forever.
        assert!(passes <= 8, "took {passes} passes to afford a 4 KiB strip");

        // And the cap always admits the worst legal strip, so no strip can be
        // permanently unaffordable at any budget.
        assert!(tile_bucket_cap(0) >= directdesk_shared::tiles::MAX_STRIP_ENCODED);
    }

    /// The throttle's floor, mirrored here so this test states the coupling it
    /// depends on rather than hiding it behind a literal.
    const TILE_CEILING_FLOOR_KBPS_FOR_TEST: u32 = crate::net::TILE_CEILING_MIN_KBPS;

    #[test]
    fn strip_budget_never_spends_the_revoke_reserve() {
        let cap = TILE_QUEUE_DEPTH;
        let res = TILE_QUEUE_REVOKE_RESERVE;
        // Empty queue: the configured per-pass budget is the only limit.
        assert_eq!(strip_budget(32, 0, cap, res), 32);
        // ...until the reserve is all that is left of the queue.
        assert_eq!(strip_budget(1_000, 0, cap, res), cap - res);
        // Whatever is already queued comes off the top, so repeated passes
        // cannot walk the queue past the reserve line one pass at a time.
        assert_eq!(strip_budget(1_000, 10, cap, res), cap - res - 10);
        assert_eq!(strip_budget(1_000, cap - res, cap, res), 0);
        // At and past the line the answer is 0 — never a wrap-around into a
        // budget the size of the address space.
        assert_eq!(strip_budget(1_000, cap, cap, res), 0);
        assert_eq!(strip_budget(1_000, usize::MAX, cap, res), 0);
        // A reserve larger than the whole queue leaves nothing and must not
        // underflow either.
        assert_eq!(strip_budget(1_000, 0, 4, 8), 0);
        // A zero per-pass configuration plans nothing at all.
        assert_eq!(strip_budget(0, 0, cap, res), 0);
    }

    #[test]
    fn strip_budget_always_leaves_room_for_a_revocation() {
        // The ordering policy stated as a property: however many passes run
        // back to back against a pump that never drains, the reserve is still
        // free for the revocation that supersedes the strips just queued.
        let mut queued = 0usize;
        for _ in 0..64 {
            queued += strip_budget(
                u32::MAX,
                queued,
                TILE_QUEUE_DEPTH,
                TILE_QUEUE_REVOKE_RESERVE,
            );
            assert!(
                TILE_QUEUE_DEPTH - queued >= TILE_QUEUE_REVOKE_RESERVE,
                "a revocation must always fit: {queued} of {TILE_QUEUE_DEPTH} slots used"
            );
        }
    }

    #[test]
    fn strip_budget_handles_an_unbounded_queue() {
        // `Sender::capacity` answers `None` for an unbounded channel; the call
        // site substitutes `usize::MAX`, which must degrade to "the per-pass
        // budget is the only limit" rather than overflow.
        assert_eq!(
            strip_budget(32, 0, usize::MAX, TILE_QUEUE_REVOKE_RESERVE),
            32
        );
    }

    #[test]
    fn renew_lead_opens_the_window_well_before_expiry() {
        // Early enough that several idle frames (and so several passes) fall
        // inside the window, and a minority of the lease so renewals never
        // become the bulk of a static screen's tile traffic.
        for lease in [1_000u32, 4_000, 30_000] {
            let lead = renew_lead_ms(lease);
            assert!(lead >= 300, "lease {lease} gives only {lead} ms of lead");
            assert!(lead * 2 < lease, "lease {lease} spends {lead} ms renewing");
        }
        // Never zero: a zero lead opens the window at the exact instant
        // `begin_pass` has already expired the tile, so it would never renew.
        assert!(renew_lead_ms(0) > 0);
        assert!(renew_lead_ms(1) > 0);
    }

    #[test]
    fn rect_translation_preserves_the_none_contract() {
        use windows::Win32::Foundation::RECT;
        let mut scratch = Vec::new();
        // `None` must stay `None`. The grid turns it into "the whole screen
        // changed"; collapsing it to an empty list would refine stale pixels.
        assert!(translate_dirty(None, &mut scratch).is_none());
        // `Some(&[])` is a real answer and has to survive as one.
        assert_eq!(translate_dirty(Some(&[]), &mut scratch), Some(&[][..]));
        let r = RECT {
            left: 1,
            top: 2,
            right: 3,
            bottom: 4,
        };
        assert_eq!(
            translate_dirty(Some(&[r]), &mut scratch),
            Some(&[DirtyRect::ltrb(1, 2, 3, 4)][..])
        );
        // The scratch buffer is reused across frames, so a shorter list must
        // not leave the previous frame's rects visible behind it.
        assert_eq!(translate_dirty(Some(&[]), &mut scratch), Some(&[][..]));
    }

    #[test]
    fn move_rect_translation_keeps_the_source_point() {
        use windows::Win32::Foundation::{POINT, RECT};
        use windows::Win32::Graphics::Dxgi::DXGI_OUTDUPL_MOVE_RECT;
        let mut scratch = Vec::new();
        assert!(translate_moves(None, &mut scratch).is_none());
        let m = DXGI_OUTDUPL_MOVE_RECT {
            SourcePoint: POINT { x: 10, y: 20 },
            DestinationRect: RECT {
                left: 100,
                top: 200,
                right: 164,
                bottom: 264,
            },
        };
        let got = translate_moves(Some(&[m]), &mut scratch).unwrap();
        assert_eq!(
            got,
            [MoveRect::new(10, 20, DirtyRect::ltrb(100, 200, 164, 264))]
        );
        // The grid marks *both* ends of a blit, so the source region has to be
        // recoverable from what this hands it.
        assert_eq!(got[0].source(), DirtyRect::ltrb(10, 20, 74, 84));
    }

    #[test]
    fn tile_window_ratio_reads_as_a_fraction() {
        let mut w = TileWindow::default();
        // Nothing measured is 0.0, not a division by zero.
        assert_eq!(w.ratio(), 0.0);
        assert!(w.is_quiet());
        w.strips = 1;
        w.raw_bytes = 1_000;
        w.wire_bytes = 40;
        assert!(!w.is_quiet());
        assert!((w.ratio() - 0.04).abs() < 1e-9);
    }

    #[test]
    fn tile_window_counts_control_messages() {
        let mut w = TileWindow::default();
        w.note_control(&TileMsg::Reset {
            width: 1920,
            height: 1080,
            edge: 64,
        });
        w.note_control(&TileMsg::Revoke { ids: vec![1, 2, 3] });
        assert_eq!((w.resets, w.revoked), (1, 3));
        assert!(!w.is_quiet());
    }

    // -- revocations survive a full queue ------------------------------------

    /// A grid the client is fully refined against, so touching a tile queues a
    /// revocation exactly the way a real dirty rect would. The lease is set far
    /// beyond anything these tests use so nothing expires underneath them.
    fn refined_grid(w: u32, h: u32) -> TileGrid {
        let mut g = TileGrid::new(w, h, 0);
        for p in g.plan_strips(0, 0, usize::MAX) {
            g.commit_sent(&p, &vec![0u64; p.ids().len()], 0, u32::MAX / 4);
        }
        assert_eq!(g.stats().moving, 0, "the whole grid should be refined");
        g
    }

    /// A tile queue with no room left in it, plus its receiver.
    fn full_queue() -> (Sender<TileMsg>, Receiver<TileMsg>) {
        let (tx, rx) = bounded::<TileMsg>(1);
        tx.try_send(TileMsg::Renew {
            ids: Vec::new(),
            valid_through_ms: 0,
        })
        .expect("the queue starts empty");
        (tx, rx)
    }

    #[test]
    fn a_revoke_the_queue_refuses_is_retried_not_lost() {
        // 256x64 is 4 x 1 tiles; one of them goes stale.
        let mut g = refined_grid(256, 64);
        g.mark_tiles_dirty(&[1], 10);
        assert_eq!(g.stats().pending_revokes, 1);

        let (tx, rx) = full_queue();
        let reset_req = AtomicBool::new(false);
        let mut retry = Vec::new();
        let mut win = TileWindow::default();

        // `take_revocations` consumes the grid's pending set, so once the send
        // fails `retry` is the *only* place that id still exists. Losing it
        // leaves the client compositing a tile the host has retracted.
        drain_revocations(&mut g, &tx, &mut win, &mut retry, &reset_req, 10);
        assert_eq!(g.stats().pending_revokes, 0, "the grid gave it up");
        assert_eq!(retry, vec![1], "so it must have been kept here");
        assert!(
            !reset_req.load(Ordering::Relaxed),
            "a revoke is not a reset"
        );

        // Make room: the next pass sends it even though the grid itself now has
        // nothing pending at all.
        rx.try_recv().expect("drain the queue");
        drain_revocations(&mut g, &tx, &mut win, &mut retry, &reset_req, 20);
        assert!(retry.is_empty(), "handed over, not held twice");
        match rx.try_recv() {
            Ok(TileMsg::Revoke { ids }) => assert_eq!(ids, vec![1]),
            other => panic!("want the deferred revoke on the wire, got {other:?}"),
        }
    }

    #[test]
    fn a_deferred_revoke_merges_with_the_next_one() {
        // 512x64 is 8 x 1 tiles, so two ids stay under the reset threshold.
        let mut g = refined_grid(512, 64);
        g.mark_tiles_dirty(&[3], 10);

        let (tx, rx) = full_queue();
        let reset_req = AtomicBool::new(false);
        let mut retry = Vec::new();
        let mut win = TileWindow::default();
        drain_revocations(&mut g, &tx, &mut win, &mut retry, &reset_req, 10);
        assert_eq!(retry, vec![3]);

        rx.try_recv().expect("drain the queue");
        g.mark_tiles_dirty(&[1], 20);
        drain_revocations(&mut g, &tx, &mut win, &mut retry, &reset_req, 20);
        assert!(retry.is_empty());
        match rx.try_recv() {
            // One message, sorted: the client applies a revoke set, not a queue
            // of them.
            Ok(TileMsg::Revoke { ids }) => assert_eq!(ids, vec![1, 3]),
            other => panic!("want one merged revoke, got {other:?}"),
        }
    }

    #[test]
    fn a_reset_the_queue_refuses_re_arms_the_request() {
        let mut g = refined_grid(256, 64);
        // Past half the grid, `take_revocations` collapses into a `Reset` and
        // re-arms the grid to match. An id list cannot express that, so the
        // dropped message has to come back as a fresh reset request.
        g.mark_tiles_dirty(&[0, 1, 2], 10);
        let (tx, _rx) = full_queue();
        let reset_req = AtomicBool::new(false);
        let mut retry = vec![9]; // held over from some earlier pass
        let mut win = TileWindow::default();

        drain_revocations(&mut g, &tx, &mut win, &mut retry, &reset_req, 10);
        assert!(
            reset_req.load(Ordering::Relaxed),
            "the next frame must retry the reset"
        );
        assert_eq!(retry, vec![9], "nothing was retracted, so nothing is stale");

        // With room on the queue the reset lands, and only *then* are the held
        // ids safe to forget — a reset retracts everything they named.
        let mut g = refined_grid(256, 64);
        g.mark_tiles_dirty(&[0, 1, 2], 10);
        let (tx, rx) = bounded::<TileMsg>(1);
        drain_revocations(&mut g, &tx, &mut win, &mut retry, &reset_req, 10);
        assert!(matches!(rx.try_recv(), Ok(TileMsg::Reset { .. })));
        assert!(retry.is_empty());
    }

    #[test]
    fn tiles_are_off_in_the_default_pipeline_config() {
        // The whole refinement path hangs off this one flag: `grid` stays
        // `None`, so nothing is allocated, no pixels are read back for tiles
        // and `tiles_tx` is never touched.
        assert!(!SessionConfig::default().lossless_tiles_enabled);
    }

    #[test]
    fn summary_states_the_real_paths() {
        let d = SessionDescription {
            adapter: "Intel(R) Arc(TM) Graphics".into(),
            adapter_luid: 0x1234,
            output: r"\\.\DISPLAY1".into(),
            monitor_origin: (0, 0),
            encoder: "MF H.264 \"X\"".into(),
            width: 1920,
            height: 1080,
            gpu_convert: false,
            gpu_encode_input: false,
            hardware_encoder: true,
        };
        let s = d.pipeline_summary();
        assert!(s.contains("CPU BT.709"), "{s}");
        assert!(s.contains("CPU NV12"), "{s}");
    }
}
