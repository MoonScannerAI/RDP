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
use directdesk_shared::traits::{Encoder, InputInjector};
use directdesk_shared::video::{EncodedFrame, FRAG_HEADER_LEN, MAX_FRAGS_PER_FRAME};
use directdesk_shared::{Error, Result};
use parking_lot::Mutex;

use crate::capture::{CaptureState, DdaCapture};
use crate::convert::{bgra_to_nv12, GpuConverter};
use crate::input_inject::WinInjector;
use crate::mf_encoder::{
    EncoderConfig, FrameInput, MfH264Encoder, MAX_STATIC_REFINE_QUALITY, MIN_STATIC_REFINE_QUALITY,
};
use crate::mfinit::MfThread;

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
    Geometry { w: u32, h: u32, origin: (i32, i32) },
    ReleaseAll,
    /// Enter (`Some`) or leave (`None`) the exclusive elevation route. While a
    /// sink is installed, input events are forwarded to it and NOT injected
    /// locally. Entering and leaving both release everything held locally first,
    /// so no key/button is left stuck on either side of the handoff.
    ElevationRoute(Option<Sender<InputEvent>>),
    Stop,
}

pub struct HostSession {
    frames_rx: Receiver<EncodedFrame>,
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
            bitrate_req: AtomicU32::new(0),
            fps_req: AtomicU32::new(0),
            fps_now: AtomicU32::new(cfg.target_fps.max(1)),
            elevation_active: AtomicBool::new(false),
        });

        let (frames_tx, frames_rx) = bounded::<EncodedFrame>(cfg.frame_queue_depth.max(1));
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
                .spawn(move || media_thread(cfg, shared, frames_tx, drop_rx, init_tx, ctl_tx))
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

    /// Sink for client input. Events are validated and injected in order.
    pub fn input_sender(&self) -> Sender<InputEvent> {
        self.input_tx.clone()
    }

    /// Ask the encoder for an IDR on the next frame (new viewer, packet loss).
    pub fn request_keyframe(&self) {
        self.shared.keyframe_req.store(true, Ordering::Relaxed);
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
        let want = fps.clamp(
            crate::config::MIN_TARGET_FPS,
            crate::config::MAX_TARGET_FPS,
        );
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
                Err(e) => tracing::warn!("could not rebuild the encoder at {want_fps} fps ({e}); staying at {cur_fps}"),
            }
        }

        if shared.keyframe_req.swap(false, Ordering::Relaxed) {
            encoder.request_keyframe();
        }

        let acquired = capture.acquire(8);
        let frame = match acquired {
            Ok(Some(f)) => f,
            Ok(None) => {
                if capture.state() == CaptureState::SecureDesktop {
                    enter_pause(&shared, &ctl_tx, &mut paused_since, "secure desktop");
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
            Err(Error::Capture(msg)) if msg == "secure desktop" => {
                enter_pause(&shared, &ctl_tx, &mut paused_since, "secure desktop");
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(e) => {
                tracing::warn!("capture error: {e}");
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
        };

        if paused_since.take().is_some() {
            shared.set_state(SessionState::Running);
            // The desktop we return to may differ wildly; force a fresh IDR.
            encoder.request_keyframe();
        }

        shared.counters.captured.fetch_add(1, Ordering::Relaxed);
        win_captured += 1;
        let ts = frame.timestamp_ms;

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
        if frame.repeated {
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

        let spent = tick.elapsed();
        if spent < frame_budget {
            std::thread::sleep(frame_budget - spent);
        }
    }

    shared.set_state(SessionState::Stopped);
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
