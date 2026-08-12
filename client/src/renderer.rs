//! Presentation: a latest-wins frame slot written by the decode thread and
//! drained by the egui frame loop, plus the texture upload + letterboxed draw.
//!
//! LATENCY POLICY (matches the decoder's): every frame is decoded, in order.
//! Frames are only ever discarded **here**, at present time, when a newer one
//! has already arrived. That discard is counted so the diagnostics panel can
//! show it honestly.

use std::cell::Cell;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use directdesk_shared::geometry::fit_rect;
use directdesk_shared::traits::{PixelFormat, RawFrame};
use parking_lot::Mutex;

/// Texture filtering for the video surface: nearest on magnification, linear
/// on minification.
///
/// Upscaling text with a linear filter is what makes a remote desktop look
/// like a photocopy of a photocopy, so nearest keeps glyph edges hard.
/// Minifying with nearest aliases badly through thin strokes, so downscale
/// stays linear. Both `tex.set` and `ctx.load_texture` call sites must use
/// this constant, or the filter silently flips whenever the host resolution
/// changes and the texture is reallocated instead of updated in place.
/// How close to a whole-number scale we still call "integer".
const INTEGER_SCALE_TOLERANCE: f32 = 0.02;

/// How close to exactly 1.0 the diagnostic label calls "1:1 exact". Tighter
/// than `INTEGER_SCALE_TOLERANCE` above: that tolerance decides a texture
/// filter (a little slack there is free), this one answers "is the user's
/// text actually pixel-exact right now", so it should not flatter a scale
/// that is merely close.
const EXACT_SCALE_TOLERANCE: f32 = 0.005;

/// Texture filtering for the video, chosen from the scale it is actually drawn
/// at.
///
/// Nearest keeps glyph edges hard, but only when each host pixel maps to a whole
/// number of screen pixels. At a fractional scale it duplicates some pixel
/// columns and not others, so stroke weights come out uneven — visibly worse
/// than the blur it replaced. Linear is the right default everywhere else,
/// including all minification, where nearest drops whole scanlines through thin
/// strokes.
///
/// `scale` is drawn width / source width, in physical pixels.
fn video_texture_options(scale: f32) -> egui::TextureOptions {
    let crisp = scale.is_finite()
        && scale >= 1.0 - INTEGER_SCALE_TOLERANCE
        && (scale - scale.round()).abs() <= INTEGER_SCALE_TOLERANCE;
    egui::TextureOptions {
        magnification: if crisp {
            egui::TextureFilter::Nearest
        } else {
            egui::TextureFilter::Linear
        },
        // Unconditional, including when the window cannot reach 1:1 at all:
        // nearest minification drops whole scanlines through thin strokes
        // (it samples one texel and discards the rest that mapped onto the
        // same screen pixel), which is worse than the slight blur linear
        // gives. There is no scale at which nearest minification is the
        // right call for text.
        minification: egui::TextureFilter::Linear,
        wrap_mode: egui::TextureWrapMode::ClampToEdge,
        mipmap_mode: None,
    }
}

/// Whether `scale` (drawn width / source width) is close enough to a whole
/// number — 1.0, 2.0, 3.0, ... — to call the video pixel-exact. Generalised
/// from the original "close to exactly 1.0" check: any integer scale draws
/// each host pixel as a whole block of screen pixels, so it is just as crisp
/// as 1:1, not merely "close" to it.
///
/// `scale.round() >= 1.0` is the guard that keeps this from calling a
/// near-zero minification scale "exact" just because it happens to round
/// to 0.0 within tolerance — there is no such thing as an exact 0x.
pub fn is_exact_scale(scale: f32) -> bool {
    scale.is_finite()
        && scale.round() >= 1.0
        && (scale - scale.round()).abs() <= EXACT_SCALE_TOLERANCE
}

/// Formats the current draw scale for the toolbar/diagnostics: "1:1 exact" at
/// unit scale, "Nx exact" at a whole multiple, otherwise "N.NNx" — the whole
/// point is that a fractional scale (the thing that makes text blurry) is
/// never silently hidden.
pub fn describe_scale(scale: f32) -> String {
    if !scale.is_finite() {
        "—".to_string()
    } else if is_exact_scale(scale) {
        let n = scale.round() as i64;
        if n <= 1 {
            "1:1 exact".to_string()
        } else {
            format!("{n}x exact")
        }
    } else {
        format!("{scale:.2}x")
    }
}

/// Snaps a points-space coordinate to the nearest whole physical pixel, then
/// converts back to points.
///
/// `viewport.min` (the bottom edge of the toolbar panel) is not guaranteed to
/// land on a whole device pixel when `ppp` is fractional (e.g. 1.5 at 150%
/// scaling) — its point value times `ppp` generally isn't an integer. Left
/// alone, that means the video rect's origin can sit half a physical pixel
/// off *even at scale exactly 1.0*, so the texture is sampled at a half-texel
/// offset and strokes come out with uneven weight — the very artifact this
/// whole feature exists to remove. Snapping the final origin (not the pre-fit
/// math) fixes it without perturbing `fit_rect`'s physical-pixel sizing.
fn snap_to_physical_pixel(points: f32, ppp: f32) -> f32 {
    (points * ppp).round() / ppp
}

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
        *guard = Some(Slotted {
            frame,
            generation,
            arrived: now,
        });
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
        Self {
            window: Duration::from_millis(500),
            last_at: now,
            last_count: 0,
            rate: 0.0,
        }
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

/// egui texture name for the main window's video surface.
///
/// **Load-bearing string.** `Context::load_texture` keys the managed texture by
/// this name, so it is effectively the main window's video surface identity for
/// the whole process. It is spelled out as a constant rather than inlined
/// because a second window now exists with its own name, and the two must never
/// collide — two `Presenter`s sharing one name would fight over a single
/// texture and each would upload over the other's picture every frame.
pub const MAIN_VIDEO_TEXTURE: &str = "directdesk_video";

/// egui texture name for the second monitor's window. See
/// [`MAIN_VIDEO_TEXTURE`] for why these are distinct.
pub const SECOND_VIDEO_TEXTURE: &str = "directdesk_video_1";

/// Owns the egui texture and the presentation counters.
pub struct Presenter {
    /// Which managed texture this presenter uploads into — see
    /// [`MAIN_VIDEO_TEXTURE`]. `&'static str` rather than `String` because
    /// there are exactly two, both compile-time constants, and the upload path
    /// runs once per frame.
    texture_name: &'static str,
    texture: Option<egui::TextureHandle>,
    tex_size: [usize; 2],
    last_generation: u64,
    last_arrived: Option<Instant>,
    decode_meter: RateMeter,
    present_meter: RateMeter,
    warned_format: bool,
    /// Scale the last frame was drawn at, written by `draw_video` and read when
    /// the next frame is uploaded. `Cell` because drawing takes `&self`. One
    /// frame of lag after a resize is imperceptible and costs nothing.
    last_scale: Cell<f32>,
}

impl Presenter {
    /// `texture_name` must be [`MAIN_VIDEO_TEXTURE`] or [`SECOND_VIDEO_TEXTURE`]
    /// — one per window, never shared (see [`MAIN_VIDEO_TEXTURE`]).
    pub fn new(texture_name: &'static str) -> Self {
        let now = Instant::now();
        Self {
            texture_name,
            texture: None,
            tex_size: [0, 0],
            last_generation: 0,
            last_arrived: None,
            decode_meter: RateMeter::new(now),
            present_meter: RateMeter::new(now),
            warned_format: false,
            last_scale: Cell::new(1.0),
        }
    }

    /// Pull the newest frame (if any) and upload it. Cheap when idle.
    pub fn update(&mut self, ctx: &egui::Context, slot: &FrameSlot) {
        if let Some((frame, generation, arrived)) = slot.take_newer_than(self.last_generation) {
            match self.build_color_image(&frame) {
                Some(image) => {
                    self.tex_size = image.size;
                    let opts = video_texture_options(self.last_scale.get());
                    match &mut self.texture {
                        Some(tex) if tex.size() == image.size => {
                            tex.set(image, opts);
                        }
                        slot_tex => {
                            *slot_tex = Some(ctx.load_texture(self.texture_name, image, opts));
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
        let ppp = ui.ctx().pixels_per_point();
        (viewport, self.draw_video(&painter, viewport, ppp))
    }

    fn draw_video(
        &self,
        painter: &egui::Painter,
        viewport: egui::Rect,
        ppp: f32,
    ) -> Option<VideoView> {
        let texture = self.texture.as_ref()?;
        let (src_w, src_h) = (self.tex_size[0] as u32, self.tex_size[1] as u32);
        // fit_rect is unit-agnostic; feed it PHYSICAL pixels, not egui points,
        // or a 1:1-sized host frame gets resampled against a too-small box on
        // any scaled display (e.g. 1920 points == 2880 physical px at 150%).
        // That resample is a permanent softness floor no texture filter fixes.
        let ppp = if ppp.is_finite() { ppp.max(0.1) } else { 1.0 };
        let dst_w_px = (viewport.width().max(0.0) * ppp) as u32;
        let dst_h_px = (viewport.height().max(0.0) * ppp) as u32;
        let (x_px, y_px, w_px, h_px) = fit_rect(src_w, src_h, dst_w_px, dst_h_px);
        if w_px == 0 || h_px == 0 {
            return None;
        }
        // Record what the next upload should filter for. Measured from the rect
        // we are about to draw, so it can never disagree with what is on screen.
        if src_w > 0 {
            self.last_scale.set(w_px as f32 / src_w as f32);
        }
        // Convert back to points: VideoView.rect must stay in points because
        // input_capture's pointer mapping consumes it directly against egui
        // pointer positions, which are always in points.
        let (x, y, w, h) = (
            x_px as f32 / ppp,
            y_px as f32 / ppp,
            w_px as f32 / ppp,
            h_px as f32 / ppp,
        );
        // Snap the origin onto a whole physical pixel (see `snap_to_physical_pixel`);
        // the size is left as-is since it came from `w_px`/`h_px`, already whole
        // physical pixels, so an integer origin plus that size lands the far edge
        // on a whole physical pixel too.
        let origin = viewport.min + egui::vec2(x, y);
        let origin = egui::pos2(
            snap_to_physical_pixel(origin.x, ppp),
            snap_to_physical_pixel(origin.y, ppp),
        );
        let rect = egui::Rect::from_min_size(origin, egui::vec2(w, h));
        painter.image(
            texture.id(),
            rect,
            egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
            egui::Color32::WHITE,
        );
        Some(VideoView {
            rect,
            remote_w: src_w,
            remote_h: src_h,
        })
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
        self.last_arrived
            .map(|t| t.elapsed().as_secs_f32() * 1000.0)
    }

    pub fn frame_size(&self) -> Option<(u32, u32)> {
        (self.tex_size[0] > 0).then(|| (self.tex_size[0] as u32, self.tex_size[1] as u32))
    }

    /// The scale the video was actually drawn at last frame (drawn width /
    /// source width, physical pixels). `1.0` before anything has been drawn.
    /// Feeds the "am I at 1:1?" toolbar diagnostic.
    pub fn last_scale(&self) -> f32 {
        self.last_scale.get()
    }

    /// The managed-texture name this presenter uploads into.
    pub fn texture_name(&self) -> &'static str {
        self.texture_name
    }

    /// Drop the presented image (stream stopped / reconnecting).
    pub fn reset(&mut self) {
        self.texture = None;
        self.tex_size = [0, 0];
        self.last_generation = 0;
        self.last_arrived = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nearest_is_only_used_where_it_actually_helps() {
        use egui::TextureFilter::{Linear, Nearest};
        // 1:1 and whole multiples: every host pixel lands on a whole number of
        // screen pixels, so nearest keeps glyph edges hard.
        assert_eq!(video_texture_options(1.0).magnification, Nearest);
        assert_eq!(video_texture_options(2.0).magnification, Nearest);
        assert_eq!(video_texture_options(3.0).magnification, Nearest);
        assert_eq!(video_texture_options(1.995).magnification, Nearest);
        // Fractional upscales duplicate some columns and not others, which reads
        // as uneven stroke weight — worse than the blur it would replace.
        assert_eq!(video_texture_options(1.333).magnification, Linear);
        assert_eq!(video_texture_options(1.5).magnification, Linear);
        // Minification always stays linear; nearest drops scanlines through
        // thin strokes.
        assert_eq!(video_texture_options(0.75).magnification, Linear);
        assert_eq!(video_texture_options(1.0).minification, Linear);
        // A nonsense scale must not panic or pick nearest.
        assert_eq!(video_texture_options(f32::NAN).magnification, Linear);
    }

    #[test]
    fn the_two_windows_never_share_a_managed_texture() {
        // Two `Presenter`s under one name would each upload over the other's
        // picture every frame, so this pair must stay distinct — and the main
        // window's name must stay EXACTLY what it has always been, since that
        // is the identity egui's texture manager has been keyed on since M1.
        assert_eq!(MAIN_VIDEO_TEXTURE, "directdesk_video");
        assert_eq!(SECOND_VIDEO_TEXTURE, "directdesk_video_1");
        assert_ne!(MAIN_VIDEO_TEXTURE, SECOND_VIDEO_TEXTURE);
        assert_eq!(
            Presenter::new(SECOND_VIDEO_TEXTURE).texture_name(),
            SECOND_VIDEO_TEXTURE,
            "the ctor argument is what reaches load_texture"
        );
    }

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

    #[test]
    fn snap_to_physical_pixel_lands_on_a_whole_device_pixel() {
        // 150% scaling: a toolbar height in points rarely times out to a whole
        // device pixel. 613.0 points * 1.5 = 919.5 physical px — exactly the
        // half-texel case this exists to fix.
        let ppp = 1.5;
        let snapped = snap_to_physical_pixel(613.0, ppp);
        let px = snapped * ppp;
        assert!(
            (px - px.round()).abs() < 1e-4,
            "snapped point {snapped} * ppp {ppp} = {px} is not a whole physical pixel"
        );
    }

    #[test]
    fn snap_to_physical_pixel_is_a_no_op_at_integer_scale() {
        // At ppp = 1.0 every point is already a whole physical pixel.
        assert_eq!(snap_to_physical_pixel(42.0, 1.0), 42.0);
    }

    #[test]
    fn snap_to_physical_pixel_moves_by_less_than_one_physical_pixel() {
        // Snapping must never move the origin by more than the rounding error
        // it is fixing — otherwise it would introduce its own visible shift.
        let ppp = 1.5;
        let points = 613.333;
        let snapped = snap_to_physical_pixel(points, ppp);
        assert!(((snapped - points) * ppp).abs() <= 0.5 + 1e-4);
    }

    #[test]
    fn describe_scale_says_exact_at_one() {
        assert_eq!(describe_scale(1.0), "1:1 exact");
        // Within tolerance of 1.0 still reads as exact.
        assert_eq!(describe_scale(1.003), "1:1 exact");
    }

    #[test]
    fn describe_scale_says_exact_at_higher_integer_scales() {
        // 2x and 3x are just as crisp as 1:1 (nearest-filtered pixel
        // doubling/tripling), so they get the same approving label, not the
        // fractional-scale warning format.
        assert_eq!(describe_scale(2.0), "2x exact");
        assert_eq!(describe_scale(3.0), "3x exact");
        // Within tolerance of a higher integer still reads as exact.
        assert_eq!(describe_scale(1.997), "2x exact");
    }

    #[test]
    fn describe_scale_shows_the_fraction_otherwise() {
        assert_eq!(describe_scale(1.3333), "1.33x");
        assert_eq!(describe_scale(0.75), "0.75x");
    }

    #[test]
    fn describe_scale_handles_nonsense() {
        assert_eq!(describe_scale(f32::NAN), "—");
    }

    #[test]
    fn is_exact_scale_matches_describe_scale() {
        assert!(is_exact_scale(1.0));
        assert!(is_exact_scale(0.996));
        assert!(!is_exact_scale(1.333));
        assert!(!is_exact_scale(f32::NAN));
    }

    #[test]
    fn is_exact_scale_is_true_at_any_crisp_integer() {
        assert!(is_exact_scale(2.0));
        assert!(is_exact_scale(3.0));
        // A fractional scale between two integers is exact at neither.
        assert!(!is_exact_scale(2.5));
    }
}
