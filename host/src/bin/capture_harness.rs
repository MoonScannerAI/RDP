//! `capture_harness` — the M1 de-risk gate.
//!
//! Runs the entire host media stack in one process and puts the result on
//! screen: DDA capture -> D3D11 NV12 conversion -> Media Foundation H.264
//! encode -> **decode again right here** -> RGBA -> egui window.
//!
//! Decoding our own output is the point: it proves the bitstream is real,
//! Annex-B, and startable from a keyframe, which no amount of "the encoder
//! returned bytes" ever proves.
//!
//! Keys: `Esc` quits, `K` forces an IDR.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use directdesk_host::capture::CaptureState;
use directdesk_host::config::HostConfig;
use directdesk_host::convert::bgra_to_nv12;
use directdesk_host::mf_encoder::FrameInput;
use directdesk_host::mfinit::MfThread;
use directdesk_host::session::build_pipeline;
use directdesk_shared::traits::{Encoder, FrameSource};
use parking_lot::Mutex;

// A bin crate root resolves `mod` relative to `src/bin/`, and anything named
// `src/bin/*.rs` would be auto-discovered as another binary — so point at the
// subdirectory explicitly.
#[path = "capture_harness/decoder.rs"]
mod decoder;
use decoder::MfH264Decoder;

/// Present at most this many pixels across; larger desktops are box-filtered
/// down so the CPU RGBA upload does not dominate the measurement.
const MAX_PRESENT_WIDTH: u32 = 1600;

#[derive(Default, Clone)]
struct Hud {
    adapter: String,
    output: String,
    encoder: String,
    decoder: String,
    convert_path: String,
    encoder_input: String,
    width: u32,
    height: u32,
    dec_width: u32,
    dec_height: u32,
    /// Encoded timestamp minus decoded timestamp, in ms. Should be 0.
    ts_drift_ms: i64,

    fps_capture: f32,
    fps_encode: f32,
    fps_decode: f32,
    kbps: f32,
    ms_capture: f32,
    ms_convert: f32,
    ms_encode: f32,
    ms_decode: f32,
    ms_present_prep: f32,

    frames_captured: u64,
    frames_encoded: u64,
    frames_decoded: u64,
    keyframes: u64,
    bytes: u64,
    /// Frames the encoder MFT refused for lack of an input credit.
    enc_no_credit: u64,
    /// Total ms blocked waiting for an encoder input credit.
    enc_wait_ms: f32,
    /// Best (lowest) mean-absolute-error between the captured desktop and the
    /// decoded picture, 0..255 per channel. Only populated with `--verify`.
    best_mae: f32,
    /// Mean luma of the most recent decoded picture; catches all-black output.
    mean_luma: f32,
    verified_frames: u64,
    state: String,
    error: Option<String>,
}

struct Presented {
    rgba: Vec<u8>,
    w: usize,
    h: usize,
    seq: u64,
}

struct Shared {
    hud: Mutex<Hud>,
    /// Newest frame wins: the worker overwrites, the UI takes.
    frame: Mutex<Option<Presented>>,
    stop: AtomicBool,
    want_key: AtomicBool,
    /// Decoded frames actually uploaded to a GPU texture and drawn.
    ui_uploads: AtomicU32,
    /// egui repaints. Both counters being non-zero is what proves the window is
    /// live rather than merely open.
    ui_repaints: AtomicU32,
}

/// Render a frame's dirty/move rect list for the `--dirty` trace.
///
/// `NONE` is the case worth watching on real hardware: it means DXGI would not
/// hand over the metadata, so the consumer must treat the whole surface as
/// changed. A count (including `0`) means the driver answered and "nothing
/// changed" can be trusted. Confusing the two is what this printout exists to
/// catch.
fn rect_state<T>(rects: &Option<Vec<T>>) -> String {
    match rects {
        Some(v) => v.len().to_string(),
        None => "NONE".to_string(),
    }
}

fn arg_seconds() -> Option<u64> {
    std::env::args()
        .skip_while(|a| a != "--seconds")
        .nth(1)
        .and_then(|s| s.parse::<u64>().ok())
}

fn main() -> anyhow::Result<()> {
    // Must precede any screen-geometry query and any window creation.
    directdesk_host::capture::set_process_dpi_aware();
    let _guard = directdesk_shared::logging::init(
        "capture_harness",
        directdesk_shared::logging::default_log_dir(),
    );
    tracing::info!("capture_harness starting");

    let shared = Arc::new(Shared {
        hud: Mutex::new(Hud::default()),
        frame: Mutex::new(None),
        stop: AtomicBool::new(false),
        want_key: AtomicBool::new(true),
        ui_uploads: AtomicU32::new(0),
        ui_repaints: AtomicU32::new(0),
    });

    let worker = {
        let shared = shared.clone();
        std::thread::Builder::new()
            .name("harness-media".into())
            .spawn(move || {
                if let Err(e) = pipeline(&shared) {
                    tracing::error!("pipeline failed: {e}");
                    shared.hud.lock().error = Some(e.to_string());
                }
            })?
    };

    // Headless mode: no window, just log counters. Useful over SSH/CI.
    if std::env::args().any(|a| a == "--headless") {
        let secs = arg_seconds().unwrap_or(6);
        for _ in 0..secs {
            std::thread::sleep(Duration::from_secs(1));
            let h = shared.hud.lock().clone();
            println!(
                "cap {:.1} enc {:.1} dec {:.1} fps | {:.0} kbps | ms cap {:.2} conv {:.2} enc {:.2} dec {:.2} present {:.2} | c/e/d {}/{}/{} | nocredit {} waited {:.0}ms",
                h.fps_capture,
                h.fps_encode,
                h.fps_decode,
                h.kbps,
                h.ms_capture,
                h.ms_convert,
                h.ms_encode,
                h.ms_decode,
                h.ms_present_prep,
                h.frames_captured,
                h.frames_encoded,
                h.frames_decoded,
                h.enc_no_credit,
                h.enc_wait_ms,
            );
        }
        shared.stop.store(true, Ordering::Relaxed);
        let _ = worker.join();
        let h = shared.hud.lock().clone();
        println!("adapter : {}", h.adapter);
        println!("capture : {}x{} {}", h.width, h.height, h.output);
        println!("convert : {}", h.convert_path);
        println!("encoder : {}", h.encoder);
        println!("enc in  : {}", h.encoder_input);
        println!("decoder : {}", h.decoder);
        let mut ok = h.frames_decoded > 0 && h.bytes > 0 && h.frames_encoded > 0;
        if h.verified_frames > 0 {
            println!(
                "verify  : best MAE {:.2}/255 over {} frames, decoded mean luma {:.1}",
                h.best_mae, h.verified_frames, h.mean_luma
            );
            // A correct round trip is a few units off; anything above ~12 means
            // we are not actually showing the captured desktop.
            ok &= h.best_mae < 12.0 && h.mean_luma > 1.0;
        }
        println!("{}", if ok { "PASS" } else { "FAIL" });
        std::process::exit(if ok { 0 } else { 1 });
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1400.0, 900.0])
            .with_title("DirectDesk capture harness"),
        ..Default::default()
    };

    // `--seconds N` closes the window automatically, so the GUI path can be
    // exercised unattended and still report what it did.
    if let Some(secs) = arg_seconds() {
        let shared = shared.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(secs));
            shared.stop.store(true, Ordering::Relaxed);
        });
    }

    let ui_shared = shared.clone();
    let res = eframe::run_native(
        "DirectDesk capture harness",
        options,
        Box::new(move |cc| Ok(Box::new(HarnessApp::new(cc, ui_shared)))),
    );

    shared.stop.store(true, Ordering::Relaxed);
    let _ = worker.join();

    let h = shared.hud.lock().clone();
    println!("adapter : {}", h.adapter);
    println!("capture : {}x{} {}", h.width, h.height, h.output);
    println!("convert : {}", h.convert_path);
    println!("encoder : {}", h.encoder);
    println!("enc in  : {}", h.encoder_input);
    println!("decoder : {}", h.decoder);
    println!(
        "frames  : captured {} encoded {} decoded {} keyframes {} bytes {}",
        h.frames_captured, h.frames_encoded, h.frames_decoded, h.keyframes, h.bytes
    );
    println!(
        "window  : {} texture uploads over {} repaints",
        shared.ui_uploads.load(Ordering::Relaxed),
        shared.ui_repaints.load(Ordering::Relaxed)
    );
    res.map_err(|e| anyhow::anyhow!("eframe: {e}"))
}

// ---- the media pipeline ------------------------------------------------------

fn pipeline(shared: &Arc<Shared>) -> anyhow::Result<()> {
    let _mf = MfThread::enter().map_err(|e| anyhow::anyhow!("{e}"))?;

    // Same knobs production uses, taken from the same place production takes
    // them — not a second, hand-tuned copy that quietly drifts out of date.
    // capture/convert/encode come from `build_pipeline` itself rather than a
    // re-implementation, for the same reason: this harness is the instrument
    // the DXGI dirty-rect check in docs/TEST_REPORT.md relies on, and an
    // instrument that measures a pipeline nobody ships is worse than no
    // instrument. See docs/TEST_REPORT.md for the values this replaced
    // (idle repeat 33 ms, fps 60, bitrate 15000 kbps).
    let cfg = HostConfig::default().sanitized().pipeline();
    let (mut capture, mut converter, mut encoder, desc) =
        build_pipeline(&cfg).map_err(|e| anyhow::anyhow!("{e}"))?;
    let (w, h) = capture.dimensions();

    let mut decoder = MfH264Decoder::new(w, h).map_err(|e| anyhow::anyhow!("{e}"))?;

    // `build_pipeline` already computed this (`converter.is_some() &&
    // encoder.accepts_textures()`) to fill in `desc.gpu_encode_input`; read it
    // back off the description instead of recomputing it.
    let gpu_texture_input = desc.gpu_encode_input;
    {
        let mut hud = shared.hud.lock();
        hud.adapter = format!("{} (LUID {:#x})", desc.adapter, desc.adapter_luid);
        hud.output = desc.output.clone();
        hud.encoder = encoder.describe();
        hud.decoder = decoder.describe();
        hud.convert_path = if converter.is_some() {
            "GPU D3D11 VideoProcessor".into()
        } else {
            "CPU BT.709".into()
        };
        hud.encoder_input = if gpu_texture_input {
            "GPU texture".into()
        } else {
            "CPU NV12".into()
        };
        hud.width = w;
        hud.height = h;
        hud.state = "running".into();
        hud.best_mae = f32::MAX;
    }

    let mut gpu_ok = converter.is_some();
    let mut cpu_bgra = Vec::new();
    let mut cpu_nv12 = Vec::new();
    let mut rgba = Vec::new();
    let mut reference: Vec<u8> = Vec::new();
    let verify = std::env::args().any(|a| a == "--verify");
    let trace_dirty = std::env::args().any(|a| a == "--dirty");

    let mut win = Window::default();
    let mut seq = 0u64;
    let (mut tot_cap, mut tot_enc, mut tot_dec, mut tot_key, mut tot_bytes) =
        (0u64, 0u64, 0u64, 0u64, 0u64);

    while !shared.stop.load(Ordering::Relaxed) {
        if shared.want_key.swap(false, Ordering::Relaxed) {
            encoder.request_keyframe();
        }

        let t_cap = Instant::now();
        let frame = match capture.acquire(8) {
            Ok(Some(f)) => f,
            Ok(None) => {
                if capture.state() == CaptureState::SecureDesktop {
                    shared.hud.lock().state = "paused (secure desktop)".into();
                }
                continue;
            }
            Err(e) => {
                shared.hud.lock().state = format!("capture: {e}");
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
        };
        let ms_capture = t_cap.elapsed().as_secs_f32() * 1000.0;
        tot_cap += 1;
        let ts = frame.timestamp_ms;

        if trace_dirty {
            println!(
                "frame {tot_cap}: repeated={} dirty={} move={} accum={}",
                frame.repeated,
                rect_state(&frame.dirty_rects),
                rect_state(&frame.move_rects),
                frame.accumulated_frames
            );
        }

        // Keep an untouched copy of what we captured so the decoded picture can
        // be compared against ground truth rather than merely counted.
        if verify {
            if let Err(e) = capture.readback_bgra(&mut reference) {
                tracing::warn!("verify readback failed: {e}");
            }
        }

        // convert
        let t_conv = Instant::now();
        let mut texture_for_encoder = None;
        if gpu_ok {
            if let Some(c) = converter.as_mut() {
                match c.convert(&frame.texture) {
                    Ok(t) => texture_for_encoder = Some(t),
                    Err(e) => {
                        tracing::warn!("GPU convert failed, falling back to CPU: {e}");
                        gpu_ok = false;
                        shared.hud.lock().convert_path = "CPU BT.709 (GPU path failed)".into();
                    }
                }
            }
        }
        if texture_for_encoder.is_none() {
            capture
                .readback_bgra(&mut cpu_bgra)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            bgra_to_nv12(&cpu_bgra, w as usize * 4, w, h, &mut cpu_nv12)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
        }
        let ms_convert = t_conv.elapsed().as_secs_f32() * 1000.0;

        // encode
        let t_enc = Instant::now();
        let encoded = match (&texture_for_encoder, gpu_texture_input) {
            (Some(tex), true) => encoder.submit(FrameInput::Texture(tex), ts),
            (Some(tex), false) => {
                let c = converter.as_mut().expect("converter present");
                match c.readback_nv12(tex, &mut cpu_nv12) {
                    Ok(()) => encoder.submit(FrameInput::Nv12(&cpu_nv12), ts),
                    Err(e) => Err(e),
                }
            }
            (None, _) => encoder.submit(FrameInput::Nv12(&cpu_nv12), ts),
        };
        let ms_encode = t_enc.elapsed().as_secs_f32() * 1000.0;
        drop(frame);

        let first = match encoded {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!("encode: {e}");
                None
            }
        };
        if first.is_none() {
            win.tick_capture(ms_capture, ms_convert);
            win.maybe_publish(shared, tot_cap, tot_enc, tot_dec, tot_key, tot_bytes);
            continue;
        }

        // Drain every frame the encoder has ready, not just the first.
        let mut ready = first;
        let mut ms_decode_total = 0.0f32;
        let mut ms_prep_total = 0.0f32;
        let mut bytes_this_tick = 0usize;
        let mut pics_this_tick = 0usize;
        let mut enc_this_tick = 0usize;

        while let Some(ef) = ready.take() {
            tot_enc += 1;
            enc_this_tick += 1;
            tot_bytes += ef.data.len() as u64;
            bytes_this_tick += ef.data.len();
            if ef.keyframe {
                tot_key += 1;
            }

            let t_dec = Instant::now();
            let decoded = decoder.decode(&ef);
            ms_decode_total += t_dec.elapsed().as_secs_f32() * 1000.0;
            let pictures = match decoded {
                Ok(p) => p,
                Err(e) => {
                    // A decode failure means our own bitstream confused the
                    // decoder. Reset it and demand a fresh IDR rather than
                    // showing garbage.
                    tracing::warn!("decode: {e}");
                    decoder.flush();
                    encoder.request_keyframe();
                    shared.hud.lock().error = Some(format!("decode: {e}"));
                    Vec::new()
                }
            };

            let t_prep = Instant::now();
            for pic in &pictures {
                tot_dec += 1;
                pics_this_tick += 1;
                let step = if pic.width > MAX_PRESENT_WIDTH { 2 } else { 1 };
                let (pw, ph) = decoder::nv12_to_rgba(pic, step, &mut rgba);

                if verify && !reference.is_empty() {
                    let (mae, luma) =
                        compare_to_source(&rgba, pw, ph, &reference, w, step as usize);
                    let mut hud = shared.hud.lock();
                    hud.best_mae = hud.best_mae.min(mae);
                    hud.mean_luma = luma;
                    hud.verified_frames += 1;
                }

                seq += 1;
                *shared.frame.lock() = Some(Presented {
                    rgba: rgba.clone(),
                    w: pw,
                    h: ph,
                    seq,
                });
                let mut hud = shared.hud.lock();
                hud.dec_width = pic.width;
                hud.dec_height = pic.height;
                // Timestamps must survive encode+decode intact; drift means the
                // codec is reordering or dropping presentation times.
                hud.ts_drift_ms = ef.timestamp_ms as i64 - pic.timestamp_ms as i64;
            }
            ms_prep_total += t_prep.elapsed().as_secs_f32() * 1000.0;
            ready = encoder.poll_output();
        }

        win.tick_full(
            ms_capture,
            ms_convert,
            ms_encode,
            ms_decode_total,
            ms_prep_total,
            bytes_this_tick,
            pics_this_tick,
            enc_this_tick,
        );
        win.maybe_publish(shared, tot_cap, tot_enc, tot_dec, tot_key, tot_bytes);
        let (no_credit, waited) = encoder.backpressure();
        let mut hud = shared.hud.lock();
        hud.state = "running".into();
        hud.enc_no_credit = no_credit;
        hud.enc_wait_ms = waited.as_secs_f32() * 1000.0;
    }
    Ok(())
}

/// Compare a decoded RGBA image against the BGRA frame it came from.
///
/// Returns `(mean_absolute_error, mean_luma)`. MAE is per colour channel in
/// 0..255 units — a correct H.264 round trip through 4:2:0 lands in the low
/// single digits on real desktop content; a black, garbage or misaligned image
/// lands in the tens or hundreds. This is what makes "the desktop is really
/// mirrored" a measurement rather than an impression.
fn compare_to_source(
    rgba: &[u8],
    rw: usize,
    rh: usize,
    bgra: &[u8],
    src_w: u32,
    step: usize,
) -> (f32, f32) {
    let src_stride = src_w as usize * 4;
    let mut err = 0u64;
    let mut luma = 0u64;
    let mut n = 0u64;
    for oy in 0..rh {
        let sy = oy * step;
        if (sy + 1) * src_stride > bgra.len() {
            break;
        }
        for ox in 0..rw {
            let sx = ox * step;
            let si = sy * src_stride + sx * 4;
            let di = (oy * rw + ox) * 4;
            if si + 3 >= bgra.len() || di + 3 >= rgba.len() {
                break;
            }
            let (sb, sg, sr) = (bgra[si] as i32, bgra[si + 1] as i32, bgra[si + 2] as i32);
            let (dr, dg, db) = (rgba[di] as i32, rgba[di + 1] as i32, rgba[di + 2] as i32);
            err += (sr - dr).unsigned_abs() as u64;
            err += (sg - dg).unsigned_abs() as u64;
            err += (sb - db).unsigned_abs() as u64;
            luma += ((dr * 77 + dg * 150 + db * 29) >> 8) as u64;
            n += 1;
        }
    }
    if n == 0 {
        return (f32::MAX, 0.0);
    }
    (err as f32 / (n * 3) as f32, luma as f32 / n as f32)
}

/// One-second rolling measurement window.
struct Window {
    start: Instant,
    cap: u32,
    enc: u32,
    dec: u32,
    bytes: u64,
    ms_capture: f32,
    ms_convert: f32,
    ms_encode: f32,
    ms_decode: f32,
    ms_prep: f32,
}

impl Default for Window {
    fn default() -> Self {
        Self {
            start: Instant::now(),
            cap: 0,
            enc: 0,
            dec: 0,
            bytes: 0,
            ms_capture: 0.0,
            ms_convert: 0.0,
            ms_encode: 0.0,
            ms_decode: 0.0,
            ms_prep: 0.0,
        }
    }
}

impl Window {
    fn tick_capture(&mut self, cap: f32, conv: f32) {
        self.cap += 1;
        self.ms_capture += cap;
        self.ms_convert += conv;
    }

    #[allow(clippy::too_many_arguments)]
    fn tick_full(
        &mut self,
        cap: f32,
        conv: f32,
        enc: f32,
        dec: f32,
        prep: f32,
        bytes: usize,
        pics: usize,
        encoded: usize,
    ) {
        self.cap += 1;
        // Count encoded *frames*, not loop iterations — one tick can drain two.
        self.enc += encoded as u32;
        self.dec += pics as u32;
        self.bytes += bytes as u64;
        self.ms_capture += cap;
        self.ms_convert += conv;
        self.ms_encode += enc;
        self.ms_decode += dec;
        self.ms_prep += prep;
    }

    fn maybe_publish(
        &mut self,
        shared: &Arc<Shared>,
        tot_cap: u64,
        tot_enc: u64,
        tot_dec: u64,
        tot_key: u64,
        tot_bytes: u64,
    ) {
        let el = self.start.elapsed();
        if el < Duration::from_millis(500) {
            return;
        }
        let secs = el.as_secs_f32();
        let n = self.cap.max(1) as f32;
        let e = self.enc.max(1) as f32;
        let d = self.dec.max(1) as f32;
        {
            let mut hud = shared.hud.lock();
            hud.fps_capture = self.cap as f32 / secs;
            hud.fps_encode = self.enc as f32 / secs;
            hud.fps_decode = self.dec as f32 / secs;
            hud.kbps = self.bytes as f32 * 8.0 / secs / 1000.0;
            hud.ms_capture = self.ms_capture / n;
            hud.ms_convert = self.ms_convert / n;
            hud.ms_encode = self.ms_encode / e;
            hud.ms_decode = self.ms_decode / e;
            hud.ms_present_prep = self.ms_prep / d;
            hud.frames_captured = tot_cap;
            hud.frames_encoded = tot_enc;
            hud.frames_decoded = tot_dec;
            hud.keyframes = tot_key;
            hud.bytes = tot_bytes;
        }
        *self = Window::default();
    }
}

// ---- egui front end ----------------------------------------------------------

struct HarnessApp {
    shared: Arc<Shared>,
    tex: Option<egui::TextureHandle>,
    last_seq: u64,
    ui_frames: u32,
    ui_window: Instant,
    ui_fps: f32,
}

impl HarnessApp {
    fn new(_cc: &eframe::CreationContext<'_>, shared: Arc<Shared>) -> Self {
        Self {
            shared,
            tex: None,
            last_seq: 0,
            ui_frames: 0,
            ui_window: Instant::now(),
            ui_fps: 0.0,
        }
    }
}

impl eframe::App for HarnessApp {
    fn ui(&mut self, root: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = root.ctx().clone();
        let ctx = &ctx;
        self.shared.ui_repaints.fetch_add(1, Ordering::Relaxed);
        ctx.input(|i| {
            if i.key_pressed(egui::Key::Escape) {
                self.shared.stop.store(true, Ordering::Relaxed);
            }
            if i.key_pressed(egui::Key::K) {
                self.shared.want_key.store(true, Ordering::Relaxed);
            }
        });
        if self.shared.stop.load(Ordering::Relaxed) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }

        // Newest frame wins: take whatever the worker last left behind.
        if let Some(p) = self.shared.frame.lock().take() {
            if p.seq != self.last_seq {
                self.last_seq = p.seq;
                let image = egui::ColorImage::from_rgba_unmultiplied([p.w, p.h], &p.rgba);
                match &mut self.tex {
                    Some(t) => t.set(image, egui::TextureOptions::LINEAR),
                    None => {
                        self.tex =
                            Some(ctx.load_texture("desktop", image, egui::TextureOptions::LINEAR))
                    }
                }
                self.shared.ui_uploads.fetch_add(1, Ordering::Relaxed);
            }
        }

        self.ui_frames += 1;
        if self.ui_window.elapsed() >= Duration::from_millis(500) {
            self.ui_fps = self.ui_frames as f32 / self.ui_window.elapsed().as_secs_f32();
            self.ui_frames = 0;
            self.ui_window = Instant::now();
        }

        let hud = self.shared.hud.lock().clone();
        egui::Panel::top("hud").show(root, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.strong("adapter:");
                ui.label(&hud.adapter);
                ui.separator();
                ui.strong("output:");
                ui.label(&hud.output);
                ui.separator();
                ui.strong("size:");
                ui.label(format!("{}x{}", hud.width, hud.height));
            });
            ui.horizontal_wrapped(|ui| {
                ui.strong("encoder:");
                ui.label(&hud.encoder);
            });
            ui.horizontal_wrapped(|ui| {
                ui.strong("decoder:");
                ui.label(&hud.decoder);
                ui.separator();
                ui.label(format!("{}x{}", hud.dec_width, hud.dec_height));
                ui.separator();
                ui.label(format!("ts drift {} ms", hud.ts_drift_ms));
            });
            ui.horizontal_wrapped(|ui| {
                ui.strong("convert:");
                ui.label(&hud.convert_path);
                ui.separator();
                ui.strong("enc input:");
                ui.label(&hud.encoder_input);
            });
            ui.horizontal_wrapped(|ui| {
                ui.strong("fps:");
                ui.label(format!(
                    "cap {:.1} | enc {:.1} | dec {:.1} | ui {:.1}",
                    hud.fps_capture, hud.fps_encode, hud.fps_decode, self.ui_fps
                ));
                ui.separator();
                ui.strong("bitrate:");
                ui.label(format!("{:.0} kbps", hud.kbps));
            });
            ui.horizontal_wrapped(|ui| {
                ui.strong("ms:");
                ui.label(format!(
                    "capture {:.2} | convert {:.2} | encode {:.2} | decode {:.2} | present {:.2}",
                    hud.ms_capture,
                    hud.ms_convert,
                    hud.ms_encode,
                    hud.ms_decode,
                    hud.ms_present_prep
                ));
            });
            ui.horizontal_wrapped(|ui| {
                ui.strong("totals:");
                ui.label(format!(
                    "captured {} | encoded {} | decoded {} | keyframes {} | bytes {}",
                    hud.frames_captured,
                    hud.frames_encoded,
                    hud.frames_decoded,
                    hud.keyframes,
                    hud.bytes
                ));
                ui.separator();
                ui.strong("state:");
                ui.label(&hud.state);
            });
            if let Some(err) = &hud.error {
                ui.colored_label(egui::Color32::RED, err);
            }
            ui.label("Esc quits  •  K forces an IDR");
        });

        egui::CentralPanel::default().show(root, |ui| match &self.tex {
            Some(tex) => {
                let avail = ui.available_size();
                let ts = tex.size_vec2();
                let scale = (avail.x / ts.x).min(avail.y / ts.y).max(0.01);
                let size = egui::vec2(ts.x * scale, ts.y * scale);
                ui.centered_and_justified(|ui| {
                    ui.image(egui::load::SizedTexture::new(tex.id(), size));
                });
            }
            None => {
                ui.centered_and_justified(|ui| ui.label("waiting for the first decoded frame…"));
            }
        });

        ctx.request_repaint();
    }
}
