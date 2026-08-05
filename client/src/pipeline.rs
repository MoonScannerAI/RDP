//! Background threads that feed the presentation slot.
//!
//! Two sources exist:
//!
//! * [`spawn_decode_thread`] — the real path: encoded frames from the transport
//!   through the Media Foundation decoder.
//! * [`spawn_demo_source`] — `--loopback-demo`: synthetic RGBA frames pushed
//!   straight into the slot, bypassing H.264 entirely, so the whole UI / input
//!   / render loop is exercisable with no network and no host.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, RecvTimeoutError};
use directdesk_shared::protocol::ControlMsg;
use directdesk_shared::traits::{Decoder, PixelFormat, RawFrame};
use directdesk_shared::video::EncodedFrame;
use parking_lot::Mutex;
use tokio::sync::mpsc;

use crate::renderer::FrameSlot;

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

/// Owns the background threads and stops them on drop.
pub struct Pipeline {
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
    pub status: Arc<SourceStatus>,
}

impl Pipeline {
    fn new(status: Arc<SourceStatus>, stop: Arc<AtomicBool>) -> Self {
        Self {
            stop,
            threads: Vec::new(),
            status,
        }
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

    let handle = std::thread::Builder::new()
        .name("directdesk-decode".into())
        .spawn(move || {
            let mut decoder: Option<Box<dyn Decoder>> = match crate::decoder::new_decoder() {
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

            let mut gate = KeyframeGate::default();

            loop {
                match video_rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(frame) => {
                        let Some(decoder) = decoder.as_mut() else {
                            continue;
                        };

                        let (admitted, request_keyframe_now) =
                            gate.admit(frame.frame_id, frame.keyframe);
                        if !admitted {
                            status.record_frame_gated();
                            tracing::debug!(
                                frame_id = frame.frame_id,
                                keyframe = frame.keyframe,
                                "dropping delta frame after gap; awaiting IDR"
                            );
                            if request_keyframe_now {
                                // Entering the wait: flush the stale reference
                                // chain once and ask for a fresh IDR. Same
                                // mechanism as the decode-error path below —
                                // `try_send` never blocks this thread, and a
                                // full control queue already has a keyframe
                                // request pending.
                                decoder.flush();
                                if let Err(err) =
                                    control_tx.try_send(ControlMsg::RequestKeyframe)
                                {
                                    tracing::warn!("keyframe request dropped: {err}");
                                }
                            }
                            continue;
                        }

                        match decoder.decode(&frame) {
                            Ok(frames) => {
                                let produced = frames.len();
                                for raw in frames {
                                    slot.publish(raw);
                                }
                                if produced > 0 {
                                    repaint();
                                }
                            }
                            Err(e) => {
                                tracing::warn!(frame_id = frame.frame_id, "decode failed: {e}");
                                status.set_error(Some(e.to_string()));
                                // Corrupt state: only a fresh IDR can recover.
                                // Flushing alone drops the bad reference chain
                                // but leaves the decoder starved until the host
                                // happens to send a keyframe — so ask for one.
                                // `try_send` never blocks this thread; a full
                                // control queue already has a keyframe request
                                // pending, so dropping this one is harmless.
                                decoder.flush();
                                if let Err(err) = control_tx.try_send(ControlMsg::RequestKeyframe) {
                                    tracing::warn!("keyframe request dropped: {err}");
                                }
                            }
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        if stop.load(Ordering::Relaxed) {
                            break;
                        }
                    }
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            }
            tracing::info!("decode thread exiting");
        })
        .expect("spawn decode thread");

    pipeline.threads.push(handle);
    pipeline
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
