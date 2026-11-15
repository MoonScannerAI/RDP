//! Platform-neutral bookkeeping for the MediaCodec decoder.
//!
//! Everything here is plain Rust with no NDK types, so it is compiled (and its
//! tests run) on Windows as part of `cargo test --workspace`, while
//! `mediacodec.rs` — the part that actually talks to `AMediaCodec` — only
//! exists on Android.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use directdesk_client::yuv::{Chroma, PlaneLayout};

/// `MediaCodecInfo.CodecCapabilities.COLOR_FormatYUV420Flexible`. Not a
/// layout: an output format that names it (Codec2 decoders echo it when it
/// was requested at configure — the emulator's `c2.goldfish.h264.decoder`
/// does — and some devices report it unasked) describes the real layout in
/// its `image-data` buffer instead; see [`layout_from_image_data`]. The
/// decoder therefore does not request it.
pub const COLOR_FORMAT_YUV420_FLEXIBLE: i32 = 0x7F42_0888;

/// `COLOR_FormatYUV420Planar` (I420) and `COLOR_FormatYUV420SemiPlanar`
/// (NV12): the two layouts `yuv::layout_from_format` names by number.
const COLOR_FORMAT_YUV420_PLANAR: i32 = 19;
const COLOR_FORMAT_YUV420_SEMIPLANAR: i32 = 21;
/// `COLOR_FormatYUV420PackedPlanar` / `COLOR_FormatYUV420PackedSemiPlanar`:
/// "packed" only promises no padding between the planes, which the stride and
/// slice-height keys already describe, so they are I420 / NV12.
const COLOR_FORMAT_YUV420_PACKED_PLANAR: i32 = 20;
const COLOR_FORMAT_YUV420_PACKED_SEMIPLANAR: i32 = 39;

/// Map MediaCodec color-format aliases onto the value
/// `yuv::layout_from_format` understands; everything else passes through.
pub fn normalize_color_format(color_format: i32) -> i32 {
    match color_format {
        COLOR_FORMAT_YUV420_PACKED_PLANAR => COLOR_FORMAT_YUV420_PLANAR,
        COLOR_FORMAT_YUV420_PACKED_SEMIPLANAR => COLOR_FORMAT_YUV420_SEMIPLANAR,
        other => other,
    }
}

/// Whether `yuv::layout_from_format` can convert this (already normalized)
/// color format at all, independent of any picture geometry: it is asked
/// for a trivially valid 2x2 layout, so only the format itself can fail.
/// Asking `yuv` rather than copying its list keeps the two from drifting.
pub fn color_format_supported(color_format: i32) -> bool {
    directdesk_client::yuv::layout_from_format(color_format, 2, 2, 0, 0, None).is_ok()
}

/// Parse the `debug.directdesk.color_format` override (decimal or `0x` hex):
/// the color format to request at configure. `None` — request nothing, let
/// the codec pick its native default — when unparseable or 0. A test hook:
/// `2135033992` forces the YUV420Flexible + `image-data` path on a codec that
/// would otherwise report a plain format.
pub fn parse_color_format_override(value: &str) -> Option<i32> {
    let value = value.trim();
    let parsed = match value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Some(hex) => u32::from_str_radix(hex, 16).ok().map(|v| v as i32),
        None => value.parse::<i32>().ok(),
    };
    parsed.filter(|v| *v != 0)
}

/// `sizeof(MediaImage2)`.
///
/// `MediaImage2` is the struct an output format's `image-data` buffer holds
/// (the layout `MediaCodec.getOutputImage` reads). From AOSP
/// `frameworks/native/headers/media_plugin/media/hardware/VideoAPI.h`, written
/// from memory — `__attribute__((__packed__))`, every field 32-bit, native
/// (little) endian:
///
/// | offset | field                                    |
/// |-------:|------------------------------------------|
/// |      0 | `Type mType` (uint32: 0 unknown, 1 YUV, 2 YUVA, 3 RGB, 4 RGBA, 5 Y) |
/// |      4 | `uint32_t mNumPlanes`                    |
/// |      8 | `uint32_t mWidth` (largest plane, unpadded) |
/// |     12 | `uint32_t mHeight`                       |
/// |     16 | `uint32_t mBitDepth` (usable bits)       |
/// |     20 | `uint32_t mBitDepthAllocated` (8 or 16)  |
/// |     24 | `PlaneInfo mPlane[4]`, 20 bytes each: `uint32_t mOffset`, `int32_t mColInc`, `int32_t mRowInc`, `uint32_t mHorizSubsampling`, `uint32_t mVertSubsampling` |
///
/// 6 * 4 + 4 * 20 = 104 bytes, which is also the only `image-data` length
/// the framework's own `MediaCodec.MediaImage` accepts. (The older 80-byte
/// `MediaImage` has no `mBitDepthAllocated` and 3 planes; the framework
/// converts it before publishing `image-data`.)
///
/// `mOffset` counts from the output buffer's range offset (the
/// `AMediaCodecBufferInfo.offset` the decoder already slices from), as
/// `getOutputImage` positions it. In practice the Y plane is at 0 there.
pub const MEDIA_IMAGE2_SIZE: usize = 104;

/// `MediaImage2::MEDIA_IMAGE_TYPE_YUV`.
const MEDIA_IMAGE_TYPE_YUV: u32 = 1;

/// Largest picture dimension accepted from `image-data` (`yuv`'s own bound).
const MAX_IMAGE_DIM: u32 = 16384;

/// `MediaImage2::PlaneInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ImagePlane {
    pub offset: u32,
    pub col_inc: i32,
    pub row_inc: i32,
    pub horiz_subsampling: u32,
    pub vert_subsampling: u32,
}

/// A decoded `MediaImage2` (see [`MEDIA_IMAGE2_SIZE`] for the byte layout).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaImage2 {
    pub image_type: u32,
    pub num_planes: u32,
    pub width: u32,
    pub height: u32,
    pub bit_depth: u32,
    pub bit_depth_allocated: u32,
    /// Y, U, V, (A).
    pub planes: [ImagePlane; 4],
}

impl MediaImage2 {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != MEDIA_IMAGE2_SIZE {
            return Err(format!(
                "image-data is {} bytes, not a {MEDIA_IMAGE2_SIZE}-byte MediaImage2",
                bytes.len()
            ));
        }
        let word = |i: usize| {
            let mut w = [0u8; 4];
            w.copy_from_slice(&bytes[i * 4..i * 4 + 4]);
            w
        };
        let u = |i: usize| u32::from_ne_bytes(word(i));
        let s = |i: usize| i32::from_ne_bytes(word(i));
        let plane = |p: usize| {
            let b = 6 + 5 * p;
            ImagePlane {
                offset: u(b),
                col_inc: s(b + 1),
                row_inc: s(b + 2),
                horiz_subsampling: u(b + 3),
                vert_subsampling: u(b + 4),
            }
        };
        Ok(Self {
            image_type: u(0),
            num_planes: u(1),
            width: u(2),
            height: u(3),
            bit_depth: u(4),
            bit_depth_allocated: u(5),
            planes: [plane(0), plane(1), plane(2), plane(3)],
        })
    }

    /// The [`PlaneLayout`] this image describes, plus its conventional name
    /// (NV12, NV21, I420, YV12) for the log.
    ///
    /// Accepted: 3-plane 8-bit YUV 4:2:0 (Y 1x1, U and V 2x2 subsampled),
    /// Y column increment 1, equal U/V row increments, and chroma that is
    /// either interleaved (both column increments 2, V at U+1 = NV12 or U at
    /// V+1 = NV21) or planar (both 1, non-overlapping; U first = I420, V
    /// first = YV12). Everything else is an error saying what was found.
    ///
    /// `crop` is the output format's inclusive (left, top, right, bottom);
    /// like `Image.setCropRect` it is intersected with the image bounds, and
    /// the default is the whole image.
    pub fn plane_layout(
        &self,
        crop: Option<(i32, i32, i32, i32)>,
    ) -> Result<(PlaneLayout, &'static str), String> {
        if self.image_type != MEDIA_IMAGE_TYPE_YUV {
            return Err(format!(
                "MediaImage2 type {} is not YUV ({MEDIA_IMAGE_TYPE_YUV})",
                self.image_type
            ));
        }
        if self.num_planes != 3 {
            return Err(format!(
                "MediaImage2 has {} planes; YUV 4:2:0 needs 3",
                self.num_planes
            ));
        }
        if self.bit_depth != 8 || self.bit_depth_allocated != 8 {
            return Err(format!(
                "{}-bit YUV in {}-bit samples is not supported (8-bit only)",
                self.bit_depth, self.bit_depth_allocated
            ));
        }
        let (w, h) = (self.width, self.height);
        if !(1..=MAX_IMAGE_DIM).contains(&w) || !(1..=MAX_IMAGE_DIM).contains(&h) {
            return Err(format!("MediaImage2 size {w}x{h} out of range"));
        }
        let [y, u, v, _] = self.planes;
        let sub = |p: &ImagePlane| (p.horiz_subsampling, p.vert_subsampling);
        if sub(&y) != (1, 1) || sub(&u) != (2, 2) || sub(&v) != (2, 2) {
            return Err(format!(
                "subsampling Y {:?} U {:?} V {:?} is not 4:2:0",
                sub(&y),
                sub(&u),
                sub(&v)
            ));
        }
        if y.col_inc != 1 {
            return Err(format!(
                "Y column increment {} is not 1 (packed formats are not supported)",
                y.col_inc
            ));
        }
        // w <= MAX_IMAGE_DIM, so the casts below are lossless.
        if y.row_inc < w as i32 {
            return Err(format!("Y row increment {} < width {w}", y.row_inc));
        }
        if u.row_inc != v.row_inc || u.row_inc <= 0 {
            return Err(format!(
                "chroma row increments U {} V {} are unequal or not positive",
                u.row_inc, v.row_inc
            ));
        }
        let uv_stride = u.row_inc as usize;
        let (cw, ch) = (w.div_ceil(2) as usize, h.div_ceil(2) as usize);
        let (chroma, chroma_offset, v_offset, name) = match (u.col_inc, v.col_inc) {
            (2, 2) => {
                if uv_stride < 2 * cw {
                    return Err(format!(
                        "interleaved chroma row increment {uv_stride} < {}",
                        2 * cw
                    ));
                }
                if v.offset.checked_sub(u.offset) == Some(1) {
                    (Chroma::InterleavedUv, u.offset, 0, "NV12")
                } else if u.offset.checked_sub(v.offset) == Some(1) {
                    (Chroma::InterleavedVu, v.offset, 0, "NV21")
                } else {
                    return Err(format!(
                        "interleaved chroma planes are not adjacent (U at {}, V at {})",
                        u.offset, v.offset
                    ));
                }
            }
            (1, 1) => {
                if uv_stride < cw {
                    return Err(format!("planar chroma row increment {uv_stride} < {cw}"));
                }
                let span = uv_stride * (ch - 1) + cw;
                let (lo, hi) = (u.offset.min(v.offset), u.offset.max(v.offset));
                if ((hi - lo) as usize) < span {
                    return Err(format!(
                        "planar chroma planes overlap (U at {}, V at {}, {span} bytes each)",
                        u.offset, v.offset
                    ));
                }
                let name = if u.offset < v.offset { "I420" } else { "YV12" };
                (Chroma::Planar, u.offset, v.offset, name)
            }
            (cu, cv) => {
                return Err(format!(
                    "chroma column increments U {cu} V {cv} are neither planar (1) nor \
                     interleaved (2)"
                ))
            }
        };
        let (iw, ih) = (w as i32, h as i32);
        let (l, t, r, b) = crop.unwrap_or((0, 0, iw - 1, ih - 1));
        let (l, t, r, b) = (l.max(0), t.max(0), r.min(iw - 1), b.min(ih - 1));
        if r < l || b < t {
            return Err(format!(
                "crop {crop:?} does not intersect the {w}x{h} image"
            ));
        }
        let layout = PlaneLayout {
            chroma,
            y_offset: y.offset as usize,
            y_stride: y.row_inc as usize,
            u_offset: chroma_offset as usize,
            v_offset: v_offset as usize,
            uv_stride,
            crop_x: l as u32,
            crop_y: t as u32,
            crop_w: (r - l + 1) as u32,
            crop_h: (b - t + 1) as u32,
        };
        Ok((layout, name))
    }
}

/// [`MediaImage2::parse`] then [`MediaImage2::plane_layout`].
pub fn layout_from_image_data(
    bytes: &[u8],
    crop: Option<(i32, i32, i32, i32)>,
) -> Result<(PlaneLayout, &'static str), String> {
    MediaImage2::parse(bytes)?.plane_layout(crop)
}

/// After an unconvertible output format: how long before a keyframe may
/// build a fresh codec on its own, and the minimum gap between two such
/// failures being surfaced as decode errors.
pub const UNSUPPORTED_RETRY: Duration = Duration::from_secs(5);

/// Retry policy for codecs whose output format `yuv` cannot convert.
///
/// Such a codec is dropped at once. The next codec is built by a keyframe
/// only when one of these holds — so a reconnect (which flushes) or a host
/// keyframe recovers, but a permanently unconvertible decoder costs a few
/// codec builds per [`UNSUPPORTED_RETRY`], not one per frame:
///
/// * there was a [`flush`](Self::on_flush) since the failure;
/// * [`UNSUPPORTED_RETRY`] has passed since the failure;
/// * the keyframe's SPS size differs from the failed codec's.
///
/// A failure is surfaced as a decode error (which makes the pipeline flush
/// and request one keyframe) at most once per [`UNSUPPORTED_RETRY`]; the
/// others decode to nothing. That bounds the feedback loop error -> flush ->
/// retry -> failure: the retry right after a reported failure fails
/// silently, and nothing else asks for a keyframe.
#[derive(Debug, Default)]
pub struct UnsupportedBackoff {
    /// Last failure (when, at which SPS size) that still blocks building.
    blocked: Option<(Instant, (u32, u32))>,
    /// When a failure was last surfaced as an error.
    reported: Option<Instant>,
}

impl UnsupportedBackoff {
    /// A codec's output turned out unconvertible (and has been dropped).
    /// Returns whether to surface this failure as a decode error.
    pub fn on_failure(&mut self, now: Instant, sps_size: (u32, u32)) -> bool {
        self.blocked = Some((now, sps_size));
        let report = self
            .reported
            .is_none_or(|t| now.saturating_duration_since(t) >= UNSUPPORTED_RETRY);
        if report {
            self.reported = Some(now);
        }
        report
    }

    /// The decoder was flushed: the next keyframe may retry at once.
    pub fn on_flush(&mut self) {
        self.blocked = None;
    }

    /// May a keyframe with this SPS size build a codec now? Building one
    /// (see [`UnsupportedBackoff::on_built`]) is the retry.
    pub fn may_build(&self, now: Instant, sps_size: (u32, u32)) -> bool {
        match self.blocked {
            None => true,
            Some((at, size)) => {
                size != sps_size || now.saturating_duration_since(at) >= UNSUPPORTED_RETRY
            }
        }
    }

    /// A codec was built: the retry is under way.
    pub fn on_built(&mut self) {
        self.blocked = None;
    }

    /// Whether keyframes are currently held back from building a codec.
    pub fn is_blocked(&self) -> bool {
        self.blocked.is_some()
    }
}

/// Decides which frames may be queued into the codec: after a flush, or on a
/// brand-new codec, nothing but a keyframe has a valid reference, so delta
/// frames are held back until one keyframe has gone in. Queuing them would
/// at best waste the codec's time and at worst produce smeared pictures.
#[derive(Debug)]
pub struct IdrGate {
    awaiting: bool,
    skipped: u64,
}

impl IdrGate {
    /// Starts out awaiting: there is no codec, let alone a reference.
    pub fn new() -> Self {
        Self {
            awaiting: true,
            skipped: 0,
        }
    }

    /// The codec lost its references (flush, codec created or dropped).
    pub fn reset(&mut self) {
        self.awaiting = true;
    }

    /// May this frame be queued? A refused delta frame is counted.
    pub fn admit(&mut self, keyframe: bool) -> bool {
        if keyframe || !self.awaiting {
            true
        } else {
            self.skipped += 1;
            false
        }
    }

    /// A frame was actually queued into the codec. Only a keyframe ends the
    /// wait — a keyframe that failed to queue leaves it in place.
    pub fn on_queued(&mut self, keyframe: bool) {
        if keyframe {
            self.awaiting = false;
        }
    }

    #[cfg(test)]
    pub fn awaiting(&self) -> bool {
        self.awaiting
    }

    /// Delta frames refused so far.
    pub fn skipped(&self) -> u64 {
        self.skipped
    }
}

impl Default for IdrGate {
    fn default() -> Self {
        Self::new()
    }
}

/// After this many consecutive failed `decode` calls the codec is dropped;
/// the next keyframe builds a fresh one.
pub const ERROR_LIMIT: u32 = 3;

/// Cap on frames remembered as "queued, not yet output". A healthy decoder
/// holds 1-5 (the emulator's goldfish decoder peaks around 5); anything past
/// this was dropped inside the codec and is forgotten oldest-first.
const PTS_MAP_CAP: usize = 64;

/// One frame queued into the codec, waiting for its picture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pending {
    pub pts_us: u64,
    /// The sender's `EncodedFrame::timestamp_ms`, handed back on the
    /// matching `RawFrame` so end-to-end latency stays measurable.
    pub timestamp_ms: u32,
    pub queued_at: Instant,
}

/// Maps codec presentation timestamps back to sender timestamps.
///
/// MediaCodec only carries a `u64` pts through the pipeline, so each input
/// gets a fresh, strictly increasing pts (microseconds since the codec was
/// built — realistic values for codecs that look at them) and this map
/// remembers which sender frame it was. Output order equals input order for
/// the host's stream (no B-frames), so lookups pop from the front.
#[derive(Debug)]
pub struct PtsMap {
    origin: Instant,
    last_pts_us: Option<u64>,
    pending: VecDeque<Pending>,
    /// Frames that went in and never came out (skipped by a later output, or
    /// evicted by the cap). Cleared frames from a `flush` are not counted.
    dropped: u64,
    /// Fallback timestamp for an output whose pts is unknown.
    last_timestamp_ms: u32,
}

impl PtsMap {
    pub fn new(origin: Instant) -> Self {
        Self {
            origin,
            last_pts_us: None,
            pending: VecDeque::new(),
            dropped: 0,
            last_timestamp_ms: 0,
        }
    }

    /// Record a frame about to be queued and return the pts to queue it with.
    pub fn push(&mut self, now: Instant, timestamp_ms: u32) -> u64 {
        let elapsed = u64::try_from(now.saturating_duration_since(self.origin).as_micros())
            .unwrap_or(u64::MAX / 2);
        let pts_us = match self.last_pts_us {
            Some(last) => elapsed.max(last + 1),
            None => elapsed,
        };
        self.last_pts_us = Some(pts_us);
        if self.pending.len() >= PTS_MAP_CAP {
            self.pending.pop_front();
            self.dropped += 1;
        }
        self.pending.push_back(Pending {
            pts_us,
            timestamp_ms,
            queued_at: now,
        });
        self.last_timestamp_ms = timestamp_ms;
        pts_us
    }

    /// Resolve an output pts. Earlier pending entries were dropped by the
    /// codec and are discarded (and counted). `None` for a pts this map never
    /// issued or already forgot.
    pub fn take(&mut self, pts_us: u64) -> Option<Pending> {
        while let Some(front) = self.pending.front() {
            if front.pts_us < pts_us {
                self.pending.pop_front();
                self.dropped += 1;
            } else if front.pts_us == pts_us {
                return self.pending.pop_front();
            } else {
                return None;
            }
        }
        None
    }

    /// Timestamp to use for an output whose pts did not resolve: the newest
    /// input's, which is the best available upper bound.
    pub fn fallback_timestamp_ms(&self) -> u32 {
        self.last_timestamp_ms
    }

    /// Forget everything in flight (codec flush). The pts counter keeps
    /// increasing so a stale output can never alias a new input.
    pub fn clear(&mut self) {
        self.pending.clear();
    }

    pub fn in_flight(&self) -> usize {
        self.pending.len()
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}

/// Counts consecutive failed `decode` calls.
#[derive(Debug, Default)]
pub struct ErrorStreak {
    consecutive: u32,
}

impl ErrorStreak {
    /// Record a failure. Returns `true` exactly when the streak reaches
    /// [`ERROR_LIMIT`] — the caller then drops the codec — and restarts it.
    pub fn fail(&mut self) -> bool {
        self.consecutive += 1;
        if self.consecutive >= ERROR_LIMIT {
            self.consecutive = 0;
            true
        } else {
            false
        }
    }

    pub fn ok(&mut self) {
        self.consecutive = 0;
    }

    #[cfg(test)]
    pub fn consecutive(&self) -> u32 {
        self.consecutive
    }
}

/// The output-format keys `yuv::layout_from_format` needs, pulled out of an
/// `AMediaFormat` through a lookup function so the extraction rules are
/// testable without one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputFormatKeys {
    pub color_format: i32,
    pub width: i32,
    pub height: i32,
    /// 0 when the codec did not report it (`layout_from_format` falls back
    /// to `width` for anything <= 0).
    pub stride: i32,
    /// 0 when the codec did not report it (falls back to `height`).
    pub slice_height: i32,
    /// Inclusive (left, top, right, bottom): the codec's own crop, or the
    /// SPS-size fallback (see [`OutputFormatKeys::read`]).
    pub crop: Option<(i32, i32, i32, i32)>,
}

impl OutputFormatKeys {
    /// `get_i32` reads one int32 key. `crop_rect` is the API-28 `"crop"` rect
    /// when it could be read; otherwise the four Java-style `crop-*` int keys
    /// are tried, and only all four together count.
    ///
    /// When neither yields a crop — always the case on API 26/27, where the
    /// crop is stored as a rect the NDK cannot read and the int keys do not
    /// exist — and the codec's picture is larger than `sps_size` (the
    /// display size after SPS cropping, which the codec was configured
    /// with), the visible picture is taken to be the top-left `sps_size`
    /// rectangle: a 1920x1088 output then yields 1920x1080, not 8 rows of
    /// padding.
    pub fn read(
        get_i32: impl Fn(&str) -> Option<i32>,
        crop_rect: Option<(i32, i32, i32, i32)>,
        sps_size: (u32, u32),
    ) -> Result<Self, String> {
        let color_format = get_i32("color-format").ok_or("output format has no color-format")?;
        let width = get_i32("width")
            .filter(|w| *w > 0)
            .ok_or("output format has no width")?;
        let height = get_i32("height")
            .filter(|h| *h > 0)
            .ok_or("output format has no height")?;
        let crop = crop_rect
            .or_else(|| {
                Some((
                    get_i32("crop-left")?,
                    get_i32("crop-top")?,
                    get_i32("crop-right")?,
                    get_i32("crop-bottom")?,
                ))
            })
            .or_else(|| sps_crop(width, height, sps_size));
        Ok(Self {
            color_format,
            width,
            height,
            stride: get_i32("stride").unwrap_or(0),
            slice_height: get_i32("slice-height").unwrap_or(0),
            crop,
        })
    }
}

/// The top-left `sps_size` rectangle of a `width x height` picture, when that
/// picture is strictly larger (never larger in one dimension and smaller in
/// the other, which no padding explains).
fn sps_crop(width: i32, height: i32, sps_size: (u32, u32)) -> Option<(i32, i32, i32, i32)> {
    let sps_w = i32::try_from(sps_size.0).ok().filter(|w| *w > 0)?;
    let sps_h = i32::try_from(sps_size.1).ok().filter(|h| *h > 0)?;
    let padded = sps_w <= width && sps_h <= height && (sps_w, sps_h) != (width, height);
    padded.then_some((0, 0, sps_w - 1, sps_h - 1))
}

/// `max-input-size` for a `width x height` stream: an uncompressed 4:2:0
/// frame bounds any sane H.264 access unit, with a 1 MiB floor for small
/// streams whose IDRs can still be large at high bitrates.
pub fn max_input_size(width: u32, height: u32) -> i32 {
    let raw = u64::from(width)
        .saturating_mul(u64::from(height))
        .saturating_mul(3)
        / 2;
    raw.max(1 << 20).min(i32::MAX as u64) as i32
}

/// Which optional low-latency keys a configure attempt sets. Tried in order;
/// the codec is rebuilt with fewer hints until one configures.
///
/// There is deliberately no tier with `priority = 0` + a high
/// `operating-rate`: some vendor decoders are reported (Moonlight's
/// experience) to *crash* on that combination rather than fail configure,
/// and a crash is not something this ladder can recover from. The
/// `low-latency` flags are what matter for a single-frame-in-flight stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LatencyTier {
    /// Low-latency flags only; no realtime/operating-rate demands.
    LowLatencyOnly,
    /// No optional keys at all.
    Plain,
}

impl LatencyTier {
    pub const LADDER: [LatencyTier; 2] = [LatencyTier::LowLatencyOnly, LatencyTier::Plain];

    /// The int32 keys this tier adds to the format. Unknown keys (the vendor
    /// one on non-Qualcomm decoders) are ignored by the codec.
    pub fn keys(self) -> &'static [(&'static str, i32)] {
        match self {
            LatencyTier::LowLatencyOnly => &[
                ("low-latency", 1),
                ("vendor.qti-ext-dec-low-latency.enable", 1),
            ],
            LatencyTier::Plain => &[],
        }
    }
}

/// Counters for the periodic one-line summary.
#[derive(Debug)]
pub struct DecodeStats {
    interval: Duration,
    window_start: Instant,
    pub frames_in: u64,
    pub frames_out: u64,
    window_out: u64,
    window_max_in_flight: usize,
    window_max_latency: Option<Duration>,
    pub last_latency: Option<Duration>,
    pub errors: u64,
    pub codecs_built: u64,
}

impl DecodeStats {
    pub fn new(now: Instant, interval: Duration) -> Self {
        Self {
            interval,
            window_start: now,
            frames_in: 0,
            frames_out: 0,
            window_out: 0,
            window_max_in_flight: 0,
            window_max_latency: None,
            last_latency: None,
            errors: 0,
            codecs_built: 0,
        }
    }

    pub fn on_input(&mut self, in_flight: usize) {
        self.frames_in += 1;
        self.window_max_in_flight = self.window_max_in_flight.max(in_flight);
    }

    pub fn on_output(&mut self, latency: Option<Duration>) {
        self.frames_out += 1;
        self.window_out += 1;
        if let Some(l) = latency {
            self.last_latency = Some(l);
            self.window_max_latency = Some(self.window_max_latency.map_or(l, |m| m.max(l)));
        }
    }

    /// The summary line if a full interval has passed since the last one;
    /// starts a new window when it returns `Some`.
    pub fn summary_due(&mut self, now: Instant, in_flight: usize, dropped: u64) -> Option<String> {
        let elapsed = now.saturating_duration_since(self.window_start);
        if elapsed < self.interval {
            return None;
        }
        let fps = self.window_out as f64 / elapsed.as_secs_f64();
        let ms = |d: Option<Duration>| match d {
            Some(d) => format!("{:.1}", d.as_secs_f64() * 1000.0),
            None => "-".to_string(),
        };
        let line = format!(
            "mediacodec: in={} out={} out_fps={:.1} in_flight={} max_in_flight={} \
             latency_ms last={} max={} dropped={} errors={} codecs={}",
            self.frames_in,
            self.frames_out,
            fps,
            in_flight,
            self.window_max_in_flight,
            ms(self.last_latency),
            ms(self.window_max_latency),
            dropped,
            self.errors,
            self.codecs_built,
        );
        self.window_start = now;
        self.window_out = 0;
        self.window_max_in_flight = in_flight;
        self.window_max_latency = None;
        Some(line)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn pts_is_strictly_increasing_even_for_simultaneous_inputs() {
        let t0 = Instant::now();
        let mut m = PtsMap::new(t0);
        let a = m.push(t0, 1);
        let b = m.push(t0, 2);
        let c = m.push(t0 + ms(5), 3);
        assert!(a < b && b < c);
        assert_eq!(c, 5_000);
    }

    #[test]
    fn take_returns_matching_frame_and_counts_skipped_ones_as_dropped() {
        let t0 = Instant::now();
        let mut m = PtsMap::new(t0);
        let p1 = m.push(t0, 100);
        let p2 = m.push(t0 + ms(1), 200);
        let p3 = m.push(t0 + ms(2), 300);
        assert_eq!(m.in_flight(), 3);
        assert_eq!(m.take(p1).map(|p| p.timestamp_ms), Some(100));
        // p2 never comes out: p3 resolves and p2 is counted as dropped.
        assert_eq!(m.take(p3).map(|p| p.timestamp_ms), Some(300));
        assert_eq!(m.dropped(), 1);
        assert_eq!(m.in_flight(), 0);
        assert_eq!(m.take(p2), None);
    }

    #[test]
    fn unknown_pts_does_not_consume_pending_frames() {
        let t0 = Instant::now();
        let mut m = PtsMap::new(t0);
        let p1 = m.push(t0 + ms(10), 7);
        assert_eq!(m.take(p1 - 1), None);
        assert_eq!(m.in_flight(), 1);
        assert_eq!(m.fallback_timestamp_ms(), 7);
    }

    #[test]
    fn clear_forgets_in_flight_without_counting_drops_and_pts_keeps_rising() {
        let t0 = Instant::now();
        let mut m = PtsMap::new(t0);
        let p1 = m.push(t0 + ms(3), 1);
        m.clear();
        assert_eq!(m.in_flight(), 0);
        assert_eq!(m.dropped(), 0);
        // Same wall time after a flush still yields a fresh pts.
        let p2 = m.push(t0 + ms(3), 2);
        assert!(p2 > p1);
        assert_eq!(m.take(p1), None);
        assert_eq!(m.take(p2).map(|p| p.timestamp_ms), Some(2));
    }

    #[test]
    fn map_is_capped() {
        let t0 = Instant::now();
        let mut m = PtsMap::new(t0);
        for i in 0..(PTS_MAP_CAP as u32 + 10) {
            m.push(t0, i);
        }
        assert_eq!(m.in_flight(), PTS_MAP_CAP);
        assert_eq!(m.dropped(), 10);
    }

    #[test]
    fn error_streak_trips_at_limit_and_resets_on_success() {
        let mut e = ErrorStreak::default();
        assert!(!e.fail());
        assert!(!e.fail());
        e.ok();
        assert_eq!(e.consecutive(), 0);
        assert!(!e.fail());
        assert!(!e.fail());
        assert!(e.fail(), "third consecutive failure drops the codec");
        assert_eq!(e.consecutive(), 0, "streak restarts after tripping");
    }

    fn lookup(pairs: &[(&str, i32)]) -> impl Fn(&str) -> Option<i32> {
        let map: HashMap<String, i32> = pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect();
        move |k| map.get(k).copied()
    }

    #[test]
    fn format_keys_from_goldfish_like_format() {
        let get = lookup(&[
            ("color-format", 19),
            ("width", 2560),
            ("height", 1600),
            ("stride", 2560),
            ("slice-height", 1600),
        ]);
        let k = OutputFormatKeys::read(&get, Some((0, 0, 2559, 1599)), (2560, 1600)).unwrap();
        assert_eq!(k.color_format, 19);
        assert_eq!(
            (k.width, k.height, k.stride, k.slice_height),
            (2560, 1600, 2560, 1600)
        );
        assert_eq!(k.crop, Some((0, 0, 2559, 1599)));
    }

    #[test]
    fn format_keys_fall_back_to_java_style_crop_and_missing_stride() {
        let get = lookup(&[
            ("color-format", 21),
            ("width", 1920),
            ("height", 1088),
            ("crop-left", 0),
            ("crop-top", 0),
            ("crop-right", 1919),
            ("crop-bottom", 1079),
        ]);
        // The codec's crop wins over the SPS fallback even when they differ.
        let k = OutputFormatKeys::read(&get, None, (1600, 900)).unwrap();
        assert_eq!(k.crop, Some((0, 0, 1919, 1079)));
        assert_eq!((k.stride, k.slice_height), (0, 0));
    }

    #[test]
    fn format_keys_partial_crop_is_ignored_and_required_keys_enforced() {
        let get = lookup(&[
            ("color-format", 21),
            ("width", 64),
            ("height", 64),
            ("crop-left", 2),
        ]);
        assert_eq!(
            OutputFormatKeys::read(&get, None, (64, 64)).unwrap().crop,
            None
        );
        let no_color = lookup(&[("width", 64), ("height", 64)]);
        assert!(OutputFormatKeys::read(no_color, None, (64, 64)).is_err());
        let zero_w = lookup(&[("color-format", 19), ("width", 0), ("height", 64)]);
        assert!(OutputFormatKeys::read(zero_w, None, (64, 64)).is_err());
    }

    #[test]
    fn missing_crop_falls_back_to_the_sps_size_on_a_padded_picture() {
        // API 26/27: no "crop" rect, no crop-* ints, 16-row-aligned height.
        let get = lookup(&[
            ("color-format", 21),
            ("width", 1920),
            ("height", 1088),
            ("stride", 1920),
            ("slice-height", 1088),
        ]);
        let k = OutputFormatKeys::read(&get, None, (1920, 1080)).unwrap();
        assert_eq!(k.crop, Some((0, 0, 1919, 1079)));
        let layout = directdesk_client::yuv::layout_from_format(
            k.color_format,
            k.width,
            k.height,
            k.stride,
            k.slice_height,
            k.crop,
        )
        .unwrap();
        assert_eq!((layout.crop_w, layout.crop_h), (1920, 1080));
    }

    #[test]
    fn sps_fallback_only_for_a_strictly_padded_picture() {
        // Same size: the full frame (None) is already right.
        assert_eq!(sps_crop(1920, 1080, (1920, 1080)), None);
        // Padded in either or both dimensions.
        assert_eq!(sps_crop(1920, 1088, (1920, 1080)), Some((0, 0, 1919, 1079)));
        assert_eq!(sps_crop(1376, 768, (1366, 768)), Some((0, 0, 1365, 767)));
        assert_eq!(sps_crop(1920, 1088, (1918, 1080)), Some((0, 0, 1917, 1079)));
        // Codec picture smaller than the SPS in any dimension: no guess.
        assert_eq!(sps_crop(1920, 1072, (1920, 1080)), None);
        assert_eq!(sps_crop(1936, 1072, (1920, 1080)), None);
        // Degenerate SPS sizes never produce a rect.
        assert_eq!(sps_crop(64, 64, (0, 0)), None);
        assert_eq!(sps_crop(64, 64, (u32::MAX, 8)), None);
    }

    #[test]
    fn packed_color_format_aliases_map_to_supported_layouts() {
        assert_eq!(normalize_color_format(20), 19);
        assert_eq!(normalize_color_format(39), 21);
        for passthrough in [
            19,
            21,
            0x7FA3_0C00,
            0x7FA3_0C04,
            COLOR_FORMAT_YUV420_FLEXIBLE,
        ] {
            assert_eq!(normalize_color_format(passthrough), passthrough);
        }
        for cf in [19, 20, 21, 39, 0x7FA3_0C00, 0x7FA3_0C04] {
            assert!(
                color_format_supported(normalize_color_format(cf)),
                "{cf:#x} should convert"
            );
        }
        // Raw aliases are not something yuv knows by itself...
        assert!(!color_format_supported(20));
        assert!(!color_format_supported(39));
        // ...and neither is "flexible" (needs the Image API) or garbage.
        assert!(!color_format_supported(COLOR_FORMAT_YUV420_FLEXIBLE));
        assert!(!color_format_supported(0));
    }

    #[test]
    fn idr_gate_holds_delta_frames_until_a_keyframe_is_queued() {
        let mut g = IdrGate::new();
        // Fresh: nothing to reference yet.
        assert!(g.awaiting());
        assert!(!g.admit(false));
        assert!(!g.admit(false));
        assert_eq!(g.skipped(), 2);
        // A keyframe is admitted, but only queuing it ends the wait.
        assert!(g.admit(true));
        assert!(g.awaiting(), "admitted is not queued");
        assert!(!g.admit(false));
        g.on_queued(true);
        assert!(!g.awaiting());
        assert!(g.admit(false));
        g.on_queued(false);
        assert!(g.admit(false));
        assert_eq!(g.skipped(), 3);
        // Flush (or a new codec): back to waiting.
        g.reset();
        assert!(!g.admit(false));
        // Queuing a delta frame never ends the wait.
        g.on_queued(false);
        assert!(g.awaiting());
        assert!(g.admit(true));
        g.on_queued(true);
        assert!(g.admit(false));
        assert_eq!(g.skipped(), 4);
    }

    /// A `MediaImage2` as the framework lays it out: YUV, 3 planes, 8-bit,
    /// then Y/U/V `(offset, col_inc, row_inc, horiz_sub, vert_sub)` and an
    /// all-zero 4th plane.
    fn image_bytes(w: u32, h: u32, planes: [(u32, i32, i32, u32, u32); 3]) -> Vec<u8> {
        let mut words: Vec<u32> = vec![1, 3, w, h, 8, 8];
        for (off, col, row, hs, vs) in planes {
            words.extend([off, col as u32, row as u32, hs, vs]);
        }
        words.extend([0u32; 5]);
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_ne_bytes()).collect();
        assert_eq!(bytes.len(), MEDIA_IMAGE2_SIZE);
        bytes
    }

    /// Overwrite 32-bit word `index` (see the table on [`MEDIA_IMAGE2_SIZE`]).
    fn with_word(mut bytes: Vec<u8>, index: usize, value: u32) -> Vec<u8> {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&value.to_ne_bytes());
        bytes
    }

    /// Codec2-style NV12 for a `w x h` picture with row stride `stride` and
    /// `slice` luma rows.
    fn nv12_image(w: u32, h: u32, stride: i32, slice: u32) -> Vec<u8> {
        let uv = stride as u32 * slice;
        image_bytes(
            w,
            h,
            [
                (0, 1, stride, 1, 1),
                (uv, 2, stride, 2, 2),
                (uv + 1, 2, stride, 2, 2),
            ],
        )
    }

    #[test]
    fn media_image2_field_order_and_size() {
        // Every word distinct, so a swapped or shifted field shows up.
        let bytes: Vec<u8> = (0u32..26).flat_map(|i| (100 + i).to_ne_bytes()).collect();
        assert_eq!(bytes.len(), 104);
        let m = MediaImage2::parse(&bytes).unwrap();
        assert_eq!(
            (m.image_type, m.num_planes, m.width, m.height),
            (100, 101, 102, 103)
        );
        assert_eq!((m.bit_depth, m.bit_depth_allocated), (104, 105));
        for (p, plane) in m.planes.iter().enumerate() {
            let b = 106 + 5 * p as u32;
            assert_eq!(
                *plane,
                ImagePlane {
                    offset: b,
                    col_inc: b as i32 + 1,
                    row_inc: b as i32 + 2,
                    horiz_subsampling: b + 3,
                    vert_subsampling: b + 4,
                },
                "plane {p}"
            );
        }
        // Increments are signed.
        let neg = with_word(nv12_image(64, 64, 64, 64), 8, (-64i32) as u32);
        assert_eq!(MediaImage2::parse(&neg).unwrap().planes[0].row_inc, -64);
    }

    #[test]
    fn image_data_nv12_codec2_style() {
        let bytes = nv12_image(2560, 1600, 2560, 1600);
        let (l, name) = layout_from_image_data(&bytes, Some((0, 0, 2559, 1599))).unwrap();
        assert_eq!(name, "NV12");
        assert_eq!(l.chroma, Chroma::InterleavedUv);
        assert_eq!((l.y_offset, l.y_stride), (0, 2560));
        assert_eq!((l.u_offset, l.uv_stride), (2560 * 1600, 2560));
        assert_eq!((l.crop_x, l.crop_y, l.crop_w, l.crop_h), (0, 0, 2560, 1600));
        // Same thing as the color-format path produces for NV12 (21).
        let by_key =
            directdesk_client::yuv::layout_from_format(21, 2560, 1600, 2560, 1600, None).unwrap();
        assert_eq!(l, by_key);
    }

    #[test]
    fn image_data_nv21() {
        let (stride, slice) = (1920u32, 1088u32);
        let vu = stride * slice;
        let bytes = image_bytes(
            1920,
            1088,
            [
                (0, 1, stride as i32, 1, 1),
                (vu + 1, 2, stride as i32, 2, 2),
                (vu, 2, stride as i32, 2, 2),
            ],
        );
        let (l, name) = layout_from_image_data(&bytes, Some((0, 0, 1919, 1079))).unwrap();
        assert_eq!(name, "NV21");
        assert_eq!(l.chroma, Chroma::InterleavedVu);
        // The interleaved plane starts at its first byte, which is V.
        assert_eq!((l.u_offset, l.uv_stride), (vu as usize, 1920));
        assert_eq!((l.crop_w, l.crop_h), (1920, 1080));
    }

    /// I420 and its YV12 twin (V plane first) for a 60x40 picture with a
    /// 64-byte luma stride, 48 luma rows and a 32-byte chroma stride.
    fn planar_images() -> (Vec<u8>, Vec<u8>) {
        let (ys, cs) = (64i32, 32i32);
        let first = 64 * 48;
        let second = first + 32 * 24;
        let i420 = image_bytes(
            60,
            40,
            [
                (0, 1, ys, 1, 1),
                (first, 1, cs, 2, 2),
                (second, 1, cs, 2, 2),
            ],
        );
        let yv12 = image_bytes(
            60,
            40,
            [
                (0, 1, ys, 1, 1),
                (second, 1, cs, 2, 2),
                (first, 1, cs, 2, 2),
            ],
        );
        (i420, yv12)
    }

    #[test]
    fn image_data_i420_and_yv12() {
        let (i420, yv12) = planar_images();
        let (l, name) = layout_from_image_data(&i420, None).unwrap();
        assert_eq!(name, "I420");
        assert_eq!(l.chroma, Chroma::Planar);
        assert_eq!((l.y_stride, l.uv_stride), (64, 32));
        assert_eq!((l.u_offset, l.v_offset), (64 * 48, 64 * 48 + 32 * 24));
        assert_eq!((l.crop_w, l.crop_h), (60, 40));

        let (l2, name) = layout_from_image_data(&yv12, None).unwrap();
        assert_eq!(name, "YV12");
        assert_eq!(l2.chroma, Chroma::Planar);
        assert_eq!((l2.u_offset, l2.v_offset), (l.v_offset, l.u_offset));
    }

    #[test]
    fn image_data_layouts_convert_like_their_nv12_equivalent() {
        use directdesk_client::yuv::yuv420_to_rgba;
        // One picture (60x40, padded) stored four ways; all must convert to
        // the same pixels as the NV12 copy read through the color-format path.
        let (w, h, ys, slice, cs) = (60usize, 40usize, 64usize, 48usize, 32usize);
        let mut seed = 0x5eed_u32;
        let mut byte = || {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            (seed >> 16) as u8
        };
        let luma: Vec<u8> = (0..ys * slice).map(|_| byte()).collect();
        let (cw, ch) = (w / 2, h / 2);
        let u: Vec<u8> = (0..cw * ch).map(|_| byte()).collect();
        let v: Vec<u8> = (0..cw * ch).map(|_| byte()).collect();

        let interleaved = |vu: bool| {
            let mut buf = luma.clone();
            let mut plane = vec![0u8; ys * slice / 2];
            for r in 0..ch {
                for c in 0..cw {
                    let (a, b) = (u[r * cw + c], v[r * cw + c]);
                    let px = &mut plane[r * ys + 2 * c..][..2];
                    px.copy_from_slice(&if vu { [b, a] } else { [a, b] });
                }
            }
            buf.extend_from_slice(&plane);
            buf
        };
        let planar = |v_first: bool| {
            let mut buf = luma.clone();
            let pad = |p: &[u8]| {
                let mut out = vec![0u8; cs * (slice / 2)];
                for r in 0..ch {
                    out[r * cs..r * cs + cw].copy_from_slice(&p[r * cw..(r + 1) * cw]);
                }
                out
            };
            let (a, b) = if v_first { (&v, &u) } else { (&u, &v) };
            buf.extend_from_slice(&pad(&a[..]));
            buf.extend_from_slice(&pad(&b[..]));
            buf
        };

        let nv12 = interleaved(false);
        let reference =
            directdesk_client::yuv::layout_from_format(21, 60, 40, 64, 48, None).unwrap();
        let mut want = Vec::new();
        yuv420_to_rgba(&nv12, &reference, &mut want).unwrap();

        let uv = (ys * slice) as u32;
        let first = uv;
        let second = uv + (cs * slice / 2) as u32;
        let (yp, cs32) = ((0, 1, ys as i32, 1, 1), cs as i32);
        let cases = [
            (
                "NV12",
                nv12.clone(),
                image_bytes(60, 40, [yp, (uv, 2, 64, 2, 2), (uv + 1, 2, 64, 2, 2)]),
            ),
            (
                "NV21",
                interleaved(true),
                image_bytes(60, 40, [yp, (uv + 1, 2, 64, 2, 2), (uv, 2, 64, 2, 2)]),
            ),
            (
                "I420",
                planar(false),
                image_bytes(
                    60,
                    40,
                    [yp, (first, 1, cs32, 2, 2), (second, 1, cs32, 2, 2)],
                ),
            ),
            (
                "YV12",
                planar(true),
                image_bytes(
                    60,
                    40,
                    [yp, (second, 1, cs32, 2, 2), (first, 1, cs32, 2, 2)],
                ),
            ),
        ];
        for (expect_name, buf, image) in cases {
            let (layout, name) = layout_from_image_data(&image, None).unwrap();
            assert_eq!(name, expect_name);
            let mut got = Vec::new();
            yuv420_to_rgba(&buf, &layout, &mut got).unwrap();
            assert_eq!(got, want, "{name}");
        }
    }

    #[test]
    fn image_data_crop_is_intersected_with_the_image() {
        let bytes = nv12_image(1920, 1080, 1920, 1088);
        // Codec2 may report the crop-sized image; a crop reaching past it
        // is clipped, as Image.setCropRect does.
        let (l, _) = layout_from_image_data(&bytes, Some((0, 0, 1919, 1087))).unwrap();
        assert_eq!((l.crop_x, l.crop_y, l.crop_w, l.crop_h), (0, 0, 1920, 1080));
        let (l, _) = layout_from_image_data(&bytes, Some((-4, 2, 99, 51))).unwrap();
        assert_eq!((l.crop_x, l.crop_y, l.crop_w, l.crop_h), (0, 2, 100, 50));
        let e = layout_from_image_data(&bytes, Some((1920, 0, 2000, 10))).unwrap_err();
        assert!(e.contains("does not intersect"), "{e}");
    }

    #[test]
    fn image_data_rejects_what_it_cannot_describe() {
        let good = nv12_image(64, 48, 64, 48);
        assert!(layout_from_image_data(&good, None).is_ok());
        let uv = 64 * 48;
        let expect_err = |bytes: &[u8], needle: &str| {
            let e = layout_from_image_data(bytes, None).unwrap_err();
            assert!(e.contains(needle), "expected {needle:?} in {e:?}");
        };
        // Length: only exactly sizeof(MediaImage2).
        for len in [0, 80, 103] {
            expect_err(&good[..len], "not a 104-byte MediaImage2");
        }
        let mut long = good.clone();
        long.push(0);
        expect_err(&long, "105 bytes");
        // Header: type, plane count, bit depth, size.
        expect_err(&with_word(good.clone(), 0, 0), "type 0 is not YUV");
        expect_err(&with_word(good.clone(), 0, 2), "type 2 is not YUV");
        expect_err(&with_word(good.clone(), 1, 4), "4 planes");
        expect_err(&with_word(good.clone(), 4, 10), "10-bit YUV in 8-bit");
        expect_err(&with_word(good.clone(), 5, 16), "8-bit YUV in 16-bit");
        expect_err(&with_word(good.clone(), 2, 0), "size 0x48");
        expect_err(&with_word(good.clone(), 3, 20_000), "out of range");
        // Subsampling: 4:4:4 and 4:2:2 chroma, subsampled luma.
        let chroma_sub = |hs: u32, vs: u32| {
            image_bytes(
                64,
                48,
                [
                    (0, 1, 64, 1, 1),
                    (uv, 2, 64, hs, vs),
                    (uv + 1, 2, 64, hs, vs),
                ],
            )
        };
        expect_err(&chroma_sub(1, 1), "not 4:2:0");
        expect_err(&chroma_sub(2, 1), "not 4:2:0");
        expect_err(&with_word(good.clone(), 9, 2), "not 4:2:0");
        // Luma increments.
        expect_err(&with_word(good.clone(), 7, 2), "Y column increment 2");
        expect_err(
            &with_word(good.clone(), 8, 63),
            "Y row increment 63 < width 64",
        );
        expect_err(
            &with_word(good.clone(), 8, (-64i32) as u32),
            "Y row increment -64",
        );
        // Chroma row increments: unequal, non-positive, too small.
        expect_err(&with_word(good.clone(), 13, 128), "unequal or not positive");
        let zero_rows = with_word(with_word(good.clone(), 13, 0), 18, 0);
        expect_err(&zero_rows, "unequal or not positive");
        let narrow = with_word(with_word(good.clone(), 13, 62), 18, 62);
        expect_err(&narrow, "interleaved chroma row increment 62 < 64");
        // Interleaved planes that are not one byte apart.
        expect_err(&with_word(good.clone(), 16, uv + 2), "not adjacent");
        expect_err(&with_word(good.clone(), 16, uv), "not adjacent");
        // Mixed / unsupported column increments.
        expect_err(&with_word(good.clone(), 12, 1), "U 1 V 2");
        expect_err(&with_word(with_word(good.clone(), 12, 4), 17, 4), "U 4 V 4");
        // Planar chroma that overlaps, or rows narrower than a chroma row.
        let planar = |u_off: u32, v_off: u32, row: i32| {
            image_bytes(
                64,
                48,
                [
                    (0, 1, 64, 1, 1),
                    (u_off, 1, row, 2, 2),
                    (v_off, 1, row, 2, 2),
                ],
            )
        };
        assert!(layout_from_image_data(&planar(uv, uv + 32 * 24, 32), None).is_ok());
        expect_err(&planar(uv, uv + 32 * 24 - 1, 32), "overlap");
        expect_err(&planar(uv, uv, 32), "overlap");
        expect_err(
            &planar(uv, uv + 31 * 24, 31),
            "planar chroma row increment 31 < 32",
        );
    }

    #[test]
    fn color_format_override_parsing() {
        assert_eq!(
            parse_color_format_override("2135033992"),
            Some(COLOR_FORMAT_YUV420_FLEXIBLE)
        );
        assert_eq!(
            parse_color_format_override(" 0x7f420888 "),
            Some(COLOR_FORMAT_YUV420_FLEXIBLE)
        );
        assert_eq!(parse_color_format_override("0X15"), Some(21));
        assert_eq!(parse_color_format_override("19"), Some(19));
        assert_eq!(parse_color_format_override("0"), None);
        assert_eq!(parse_color_format_override("flexible"), None);
        assert_eq!(parse_color_format_override(""), None);
    }

    #[test]
    fn unsupported_backoff_holds_keyframes_for_five_seconds() {
        let t0 = Instant::now();
        let size = (2560, 1600);
        let mut b = UnsupportedBackoff::default();
        assert!(b.may_build(t0, size) && !b.is_blocked());
        assert!(b.on_failure(t0, size), "first failure is reported");
        assert!(b.is_blocked());
        assert!(!b.may_build(t0 + ms(4_999), size));
        // A different stream size is a different codec: try it at once.
        assert!(b.may_build(t0 + ms(1), (1920, 1080)));
        assert!(b.may_build(t0 + ms(5_000), size));
        b.on_built();
        assert!(!b.is_blocked());
        assert!(b.may_build(t0 + ms(5_001), size));
    }

    #[test]
    fn unsupported_backoff_flush_clears_but_reports_stay_rate_limited() {
        let t0 = Instant::now();
        let size = (2560, 1600);
        let mut b = UnsupportedBackoff::default();
        assert!(b.on_failure(t0, size));
        // The pipeline answers the reported error with flush + keyframe
        // request; the flush lets that keyframe retry at once...
        b.on_flush();
        assert!(!b.is_blocked());
        assert!(b.may_build(t0 + ms(50), size));
        b.on_built();
        // ...and when the retry fails too, it is not reported again (so no
        // second flush / keyframe request) and keyframes are held again.
        assert!(!b.on_failure(t0 + ms(60), size));
        assert!(!b.may_build(t0 + ms(2_000), size));
        // A later flush (a reconnect, a network gap) retries again, still
        // silently inside the window.
        b.on_flush();
        assert!(b.may_build(t0 + ms(3_000), size));
        b.on_built();
        assert!(!b.on_failure(t0 + ms(3_010), size));
        // 5 s after the last report, a failure is reported again.
        assert!(!b.may_build(t0 + ms(8_000), size));
        assert!(b.may_build(t0 + ms(8_010), size));
        b.on_built();
        assert!(b.on_failure(t0 + ms(8_020), size));
    }

    #[test]
    fn unsupported_backoff_bounds_codec_builds_and_reports() {
        // Simulate a permanently unconvertible codec under a pipeline that
        // flushes + requests a keyframe on every reported error and a host
        // that sends a keyframe every 100 ms (worst case: every request is
        // answered at once). Over 60 s: about one report per 5 s, and two
        // builds per report (the timed retry + the post-flush one).
        let t0 = Instant::now();
        let size = (2560, 1600);
        let mut b = UnsupportedBackoff::default();
        let (mut builds, mut reports) = (0u32, 0u32);
        for step in 0..600u64 {
            let now = t0 + ms(step * 100);
            if b.may_build(now, size) {
                b.on_built();
                builds += 1;
                if b.on_failure(now, size) {
                    reports += 1;
                    b.on_flush();
                }
            }
        }
        assert!((11..=13).contains(&reports), "reports={reports}");
        assert!(
            builds <= 2 * reports + 1,
            "builds={builds} reports={reports}"
        );
    }

    #[test]
    fn flexible_color_format_constant_matches_the_sdk() {
        // MediaCodecInfo.CodecCapabilities.COLOR_FormatYUV420Flexible
        assert_eq!(COLOR_FORMAT_YUV420_FLEXIBLE, 2_135_033_992);
    }

    #[test]
    fn max_input_size_bounds() {
        assert_eq!(max_input_size(320, 240), 1 << 20);
        assert_eq!(max_input_size(2560, 1600), 2560 * 1600 * 3 / 2);
        assert_eq!(max_input_size(u32::MAX, u32::MAX), i32::MAX);
    }

    #[test]
    fn latency_ladder_degrades_to_plain() {
        assert_eq!(LatencyTier::LADDER[0], LatencyTier::LowLatencyOnly);
        assert!(LatencyTier::LowLatencyOnly
            .keys()
            .iter()
            .any(|(k, _)| *k == "low-latency"));
        assert!(!LatencyTier::LowLatencyOnly
            .keys()
            .iter()
            .any(|(k, _)| *k == "priority" || *k == "operating-rate"));
        assert!(LatencyTier::Plain.keys().is_empty());
    }

    #[test]
    fn stats_summary_once_per_interval() {
        let t0 = Instant::now();
        let mut s = DecodeStats::new(t0, Duration::from_secs(5));
        s.on_input(1);
        s.on_input(3);
        s.on_output(Some(ms(12)));
        s.on_output(Some(ms(9)));
        assert!(s.summary_due(t0 + ms(4_999), 1, 0).is_none());
        let line = s.summary_due(t0 + ms(5_000), 1, 2).unwrap();
        assert!(line.contains("in=2 out=2"), "{line}");
        assert!(line.contains("max_in_flight=3"), "{line}");
        assert!(line.contains("last=9.0 max=12.0"), "{line}");
        assert!(line.contains("dropped=2"), "{line}");
        // New window: nothing due until another interval passes.
        assert!(s.summary_due(t0 + ms(6_000), 0, 2).is_none());
    }
}
