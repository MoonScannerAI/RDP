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
use directdesk_shared::video::EncodedFrame;
use directdesk_shared::{Error, Result};
use parking_lot::Mutex;

use crate::capture::{CaptureState, DdaCapture};
use crate::convert::{bgra_to_nv12, GpuConverter};
use crate::input_inject::WinInjector;
use crate::mf_encoder::{EncoderConfig, FrameInput, MfH264Encoder};
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
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            target_fps: 60,
            bitrate_kbps: 12_000,
            gop_seconds: 4,
            // A still desktop only needs a low-rate keepalive, not ~30 identical
            // full-frame re-encodes/sec. 250 ms (~4/s) cuts static-screen
            // bandwidth; the keepalives are ordinary re-sent frames, not forced
            // IDRs (see media_thread) — periodic IDRs come from the GOP.
            idle_repeat_ms: 250,
            force_cpu_convert: false,
            frame_queue_depth: 8,
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

    let frame_budget = Duration::from_micros(1_000_000 / cfg.target_fps.max(1) as u64);
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

    while !shared.stop.load(Ordering::Relaxed) {
        let tick = Instant::now();

        let bitrate = shared.bitrate_req.swap(0, Ordering::Relaxed);
        if bitrate > 0 {
            let _ = encoder.set_bitrate(bitrate);
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

        // NOTE: idle keepalives are left as ordinary P-frames on purpose. Forcing
        // an IDR on every static-screen keepalive made each one re-quantize the
        // whole image slightly differently under CBR, which shows up as a visible
        // flicker/pulse on colored backgrounds (invisible on white). P-frames of
        // an unchanged image reproduce identical pixels, so they stay stable; loss
        // recovery on a static screen is handled reactively by the client's
        // existing keyframe request when it detects a dropped fragment.

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
