//! Presentation: a latest-wins frame slot written by the decode thread and
//! drained by the egui frame loop, plus the texture upload + letterboxed draw.
//!
//! LATENCY POLICY (matches the decoder's): every frame is decoded, in order.
//! Frames are only ever discarded **here**, at present time, when a newer one
//! has already arrived. That discard is counted so the diagnostics panel can
//! show it honestly.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use directdesk_shared::geometry::fit_rect;
use directdesk_shared::traits::{PixelFormat, RawFrame};
use parking_lot::Mutex;

/// One decoded frame waiting to be shown.
struct Slotted {
    frame: RawFrame,
    generation: u64,
    arrived: Instant,
}

/// Single-producer / single-consumer latest-wins hand-off.
///
/// The producer (decode thread) never blocks on the consumer; if the UI is
/// slow, the older frame is dropped rather than queued, which is exactly the
/// behaviour a remote desktop wants — the newest pixels are the only ones that
/// matter.
pub struct FrameSlot {
    inner: Mutex<Option<Slotted>>,
    generation: AtomicU64,
    decoded: AtomicU64,
    presented: AtomicU64,
    dropped_at_present: AtomicU64,
    width: AtomicU32,
    height: AtomicU32,
}

impl Default for FrameSlot {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameSlot {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(None),
            generation: AtomicU64::new(0),
            decoded: AtomicU64::new(0),
            presented: AtomicU64::new(0),
            dropped_at_present: AtomicU64::new(0),
            width: AtomicU32::new(0),
            height: AtomicU32::new(0),
        }
    }

    /// Publish a freshly decoded frame. Called from the decode thread.
    pub fn publish(&self, frame: RawFrame) {
        self.publish_at(frame, Instant::now());
    }

    pub fn publish_at(&self, frame: RawFrame, now: Instant) {
        let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        self.width.store(frame.width, Ordering::Relaxed);
        self.height.store(frame.height, Ordering::Relaxed);
        self.decoded.fetch_add(1, Ordering::Relaxed);

        let mut guard = self.inner.lock();
        if guard.is_some() {
            // The previous frame was never shown. This is the ONLY place a
            // decoded frame is discarded.
            self.dropped_at_present.fetch_add(1, Ordering::Relaxed);
        }
        *guard = Some(Slotted { frame, generation, arrived: now });
    }

    /// Consume the pending frame if it is newer than `last_generation`.
    pub fn take_newer_than(&self, last_generation: u64) -> Option<(RawFrame, u64, Instant)> {
        let mut guard = self.inner.lock();
        match guard.as_ref() {
            Some(s) if s.generation > last_generation => {
                let s = guard.take().expect("checked above");
                self.presented.fetch_add(1, Ordering::Relaxed);
                Some((s.frame, s.generation, s.arrived))
            }
            _ => None,
        }
    }

    /// Current remote frame dimensions, or `None` before the first frame.
    /// Input normalization must use these — never the local window size.
    pub fn remote_dims(&self) -> Option<(u32, u32)> {
        let w = self.width.load(Ordering::Relaxed);
        let h = self.height.load(Ordering::Relaxed);
        (w > 0 && h > 0).then_some((w, h))
    }

    pub fn decoded_count(&self) -> u64 {
        self.decoded.load(Ordering::Relaxed)
    }

    pub fn presented_count(&self) -> u64 {
        self.presented.load(Ordering::Relaxed)
    }

    pub fn dropped_at_present(&self) -> u64 {
        self.dropped_at_present.load(Ordering::Relaxed)
    }

    /// Forget any pending frame (used on stream restart / disconnect).
    pub fn clear(&self) {
        *self.inner.lock() = None;
    }
}

/// Converts a monotonically increasing counter into a smoothed rate (Hz).
#[derive(Debug, Clone)]
pub struct RateMeter {
    window: Duration,
    last_at: Instant,
    last_count: u64,
    rate: f32,
}

impl RateMeter {
    pub fn new(now: Instant) -> Self {
        Self { window: Duration::from_millis(500), last_at: now, last_count: 0, rate: 0.0 }
    }

    /// Feed the cumulative counter; recomputes at most once per window.
    pub fn sample(&mut self, now: Instant, cumulative: u64) -> f32 {
        let elapsed = now.saturating_duration_since(self.last_at);
        if elapsed >= self.window {
            let delta = cumulative.saturating_sub(self.last_count);
            self.rate = delta as f32 / elapsed.as_secs_f32();
            self.last_at = now;
            self.last_count = cumulative;
        }
        self.rate
    }

    pub fn rate(&self) -> f32 {
        self.rate
    }
}

/// Where the video is actually drawn, and what it maps to on the host.
/// Input mapping consumes exactly this so the pointer math can never disagree
/// with the pixels on screen.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct VideoView {
    pub rect: egui::Rect,
    pub remote_w: u32,
    pub remote_h: u32,
}

/// Owns the egui texture and the presentation counters.
pub struct Presenter {
    texture: Option<egui::TextureHandle>,
    tex_size: [usize; 2],
    last_generation: u64,
    last_arrived: Option<Instant>,
    decode_meter: RateMeter,
    present_meter: RateMeter,
    warned_format: bool,
}

impl Presenter {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            texture: None,
            tex_size: [0, 0],
            last_generation: 0,
            last_arrived: None,
            decode_meter: RateMeter::new(now),
            present_meter: RateMeter::new(now),
            warned_format: false,
        }
    }

    /// Pull the newest frame (if any) and upload it. Cheap when idle.
    pub fn update(&mut self, ctx: &egui::Context, slot: &FrameSlot) {
        if let Some((frame, generation, arrived)) = slot.take_newer_than(self.last_generation) {
            match self.build_color_image(&frame) {
                Some(image) => {
                    self.tex_size = image.size;
                    match &mut self.texture {
                        Some(tex) if tex.size() == image.size => {
                            tex.set(image, egui::TextureOptions::LINEAR);
                        }
                        slot_tex => {
                            *slot_tex =
                                Some(ctx.load_texture("directdesk_video", image, egui::TextureOptions::LINEAR));
                        }
                    }
                    self.last_generation = generation;
                    self.last_arrived = Some(arrived);
                }
                None => {
                    // Still advance so we do not spin on an undecodable frame.
                    self.last_generation = generation;
                }
            }
        }

        let now = Instant::now();
        self.decode_meter.sample(now, slot.decoded_count());
        self.present_meter.sample(now, slot.presented_count());
    }

    /// Takes `&mut self` so the "unrenderable format" warning fires only once.
    fn build_color_image(&mut self, frame: &RawFrame) -> Option<egui::ColorImage> {
        let size = [frame.width as usize, frame.height as usize];
        let expected = size[0].checked_mul(size[1])?.checked_mul(4)?;
        match frame.format {
            PixelFormat::Rgba8 if frame.data.len() == expected => {
                Some(egui::ColorImage::from_rgba_unmultiplied(size, &frame.data))
            }
            PixelFormat::Bgra8 if frame.data.len() == expected => {
                let mut rgba = frame.data.clone();
                for px in rgba.chunks_exact_mut(4) {
                    px.swap(0, 2);
                }
                Some(egui::ColorImage::from_rgba_unmultiplied(size, &rgba))
            }
            other => {
                if !self.warned_format {
                    self.warned_format = true;
                    tracing::error!(
                        "presenter got {other:?} {}x{} ({} bytes, expected {expected}) — not renderable",
                        frame.width,
                        frame.height,
                        frame.data.len()
                    );
                }
                None
            }
        }
    }

    /// Draw the video letterboxed inside `ui`'s available space.
    ///
    /// Returns the whole viewport (the black area, used to decide whether the
    /// pointer is over the remote screen at all) and the exact rect the video
    /// occupies inside it. Input mapping consumes the latter, so the pointer
    /// math cannot drift from what was drawn.
    pub fn draw(&self, ui: &mut egui::Ui) -> (egui::Rect, Option<VideoView>) {
        let (viewport, _) = ui.allocate_exact_size(ui.available_size(), egui::Sense::hover());
        let painter = ui.painter_at(viewport);
        painter.rect_filled(viewport, 0.0, egui::Color32::BLACK);
        (viewport, self.draw_video(&painter, viewport))
    }

    fn draw_video(&self, painter: &egui::Painter, viewport: egui::Rect) -> Option<VideoView> {
        let texture = self.texture.as_ref()?;
        let (src_w, src_h) = (self.tex_size[0] as u32, self.tex_size[1] as u32);
        let (x, y, w, h) = fit_rect(
            src_w,
            src_h,
            viewport.width().max(0.0) as u32,
            viewport.height().max(0.0) as u32,
        );
        if w == 0 || h == 0 {
            return None;
        }
        let rect = egui::Rect::from_min_size(
            viewport.min + egui::vec2(x as f32, y as f32),
            egui::vec2(w as f32, h as f32),
        );
        painter.image(
            texture.id(),
            rect,
            egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
            egui::Color32::WHITE,
        );
        Some(VideoView { rect, remote_w: src_w, remote_h: src_h })
    }

    pub fn has_frame(&self) -> bool {
        self.texture.is_some()
    }

    pub fn fps_decode(&self) -> f32 {
        self.decode_meter.rate()
    }

    pub fn fps_present(&self) -> f32 {
        self.present_meter.rate()
    }

    /// Age of the frame currently on screen, in ms. This is the client-side
    /// half of the latency budget (decode-complete → still displayed).
    pub fn present_age_ms(&self) -> Option<f32> {
        self.last_arrived.map(|t| t.elapsed().as_secs_f32() * 1000.0)
    }

    pub fn frame_size(&self) -> Option<(u32, u32)> {
        (self.tex_size[0] > 0).then(|| (self.tex_size[0] as u32, self.tex_size[1] as u32))
    }

    /// Drop the presented image (stream stopped / reconnecting).
    pub fn reset(&mut self) {
        self.texture = None;
        self.tex_size = [0, 0];
        self.last_generation = 0;
        self.last_arrived = None;
    }
}

impl Default for Presenter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(w: u32, h: u32, tag: u8) -> RawFrame {
        RawFrame {
            width: w,
            height: h,
            format: PixelFormat::Rgba8,
            data: vec![tag; (w * h * 4) as usize],
            timestamp_ms: tag as u32,
        }
    }

    #[test]
    fn latest_wins_and_counts_the_drop() {
        let slot = FrameSlot::new();
        slot.publish(frame(2, 2, 1));
        slot.publish(frame(2, 2, 2));
        // Second publish superseded an unshown frame.
        assert_eq!(slot.dropped_at_present(), 1);
        assert_eq!(slot.decoded_count(), 2);

        let (got, generation, _) = slot.take_newer_than(0).unwrap();
        assert_eq!(got.data[0], 2, "must present the NEWEST frame");
        assert_eq!(generation, 2);
        assert_eq!(slot.presented_count(), 1);
    }

    #[test]
    fn consumed_frame_is_not_counted_as_dropped() {
        let slot = FrameSlot::new();
        slot.publish(frame(2, 2, 1));
        let (_, generation, _) = slot.take_newer_than(0).unwrap();
        slot.publish(frame(2, 2, 2));
        assert_eq!(slot.dropped_at_present(), 0);
        assert!(slot.take_newer_than(generation).is_some());
    }

    #[test]
    fn take_returns_none_without_a_newer_frame() {
        let slot = FrameSlot::new();
        assert!(slot.take_newer_than(0).is_none());
        slot.publish(frame(2, 2, 1));
        let (_, generation, _) = slot.take_newer_than(0).unwrap();
        assert!(slot.take_newer_than(generation).is_none());
    }

    #[test]
    fn remote_dims_track_the_stream() {
        let slot = FrameSlot::new();
        assert_eq!(slot.remote_dims(), None);
        slot.publish(frame(1920, 1080, 1));
        assert_eq!(slot.remote_dims(), Some((1920, 1080)));
        // A resolution change must be visible immediately for input mapping.
        slot.publish(frame(1280, 720, 2));
        assert_eq!(slot.remote_dims(), Some((1280, 720)));
    }

    #[test]
    fn rate_meter_measures_over_its_window() {
        let t0 = Instant::now();
        let mut m = RateMeter::new(t0);
        // Below the window: no update yet.
        assert_eq!(m.sample(t0 + Duration::from_millis(100), 6), 0.0);
        // One second later, 60 frames => 60 fps.
        let r = m.sample(t0 + Duration::from_millis(1000), 60);
        assert!((r - 60.0).abs() < 0.001, "rate={r}");
    }

    #[test]
    fn clear_discards_pending() {
        let slot = FrameSlot::new();
        slot.publish(frame(2, 2, 1));
        slot.clear();
        assert!(slot.take_newer_than(0).is_none());
    }
}
