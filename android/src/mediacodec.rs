//! H.264 → RGBA8 through the NDK's `AMediaCodec`, synchronous ByteBuffer
//! mode (no Surface, no AImageReader): each decoded picture is read back from
//! the output buffer and converted on the CPU by `directdesk_client::yuv`.
//!
//! Shape of one [`Decoder::decode`] call:
//! 1. drain output that is already ready (0 timeout);
//! 2. queue the frame (10 ms for an input slot; on a miss drain and retry
//!    once, then fail);
//! 3. wait up to 12 ms for a picture, then drain the rest with 0 timeout.
//!
//! Output that arrives later is returned by the next call. The codec is built
//! lazily from the first keyframe's SPS (size) and SPS/PPS (`csd-0/1`),
//! rebuilt when a keyframe's SPS changes the size, and dropped after
//! [`ERROR_LIMIT`] consecutive failed calls (the next keyframe rebuilds it).
//! Delta frames while no codec exists — and, through [`IdrGate`], after a
//! flush or on a new codec until a keyframe has been queued — decode to
//! nothing; the pipeline's keyframe gate and `RequestKeyframe` handle
//! recovery.
//!
//! An output color format `yuv` cannot convert is reported as an error once
//! and then disables that codec instance (every later frame decodes to
//! nothing, without errors that would make the pipeline flush and request a
//! keyframe per frame); a keyframe with a new SPS size builds a fresh codec
//! that tries again.
//!
//! A panic anywhere inside [`Decoder::decode`] / [`Decoder::flush`] (the ndk
//! crate unwraps on NULL from a few NDK calls) is caught, the codec dropped,
//! and an error returned, so it cannot take the decode thread down.

use std::any::Any;
use std::ffi::c_void;
use std::os::raw::c_char;
use std::panic::AssertUnwindSafe;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use directdesk_client::h264;
use directdesk_client::yuv::{self, PlaneLayout};
use directdesk_shared::error::{Error, Result};
use directdesk_shared::traits::{Decoder, PixelFormat, RawFrame};
use directdesk_shared::video::EncodedFrame;
use ndk::media::media_codec::{
    DequeuedInputBufferResult, DequeuedOutputBufferInfoResult, MediaCodec, MediaCodecDirection,
};
use ndk::media::media_format::MediaFormat;

use crate::codec_state::{
    color_format_supported, max_input_size, normalize_color_format, DecodeStats, ErrorStreak,
    IdrGate, LatencyTier, OutputFormatKeys, PtsMap, COLOR_FORMAT_YUV420_FLEXIBLE, ERROR_LIMIT,
};

const MIME_AVC: &str = "video/avc";
const INPUT_TIMEOUT: Duration = Duration::from_millis(10);
const OUTPUT_WAIT: Duration = Duration::from_millis(12);
const SUMMARY_INTERVAL: Duration = Duration::from_secs(5);
/// Largest picture we will configure a codec for (the host caps at 4K).
const MAX_DIMENSION: u32 = 8192;

/// `BUFFER_FLAG_CODEC_CONFIG` / `BUFFER_FLAG_END_OF_STREAM`: output buffers
/// carrying no picture.
const FLAG_CODEC_CONFIG: u32 = 2;
const FLAG_END_OF_STREAM: u32 = 4;

/// [`directdesk_client::pipeline::NewDecoder`] for Android. Never fails: the
/// codec itself is created on the first keyframe, on the decode thread.
pub fn new_decoder() -> Result<Box<dyn Decoder>> {
    Ok(Box::new(MediaCodecDecoder::new()))
}

pub struct MediaCodecDecoder {
    active: Option<ActiveCodec>,
    errors: ErrorStreak,
    stats: DecodeStats,
    idr: IdrGate,
}

impl MediaCodecDecoder {
    pub fn new() -> Self {
        Self {
            active: None,
            errors: ErrorStreak::default(),
            stats: DecodeStats::new(Instant::now(), SUMMARY_INTERVAL),
            idr: IdrGate::new(),
        }
    }

    fn drop_codec(&mut self, why: &str) {
        self.idr.reset();
        if let Some(active) = self.active.take() {
            tracing::warn!(
                width = active.sps_size.0,
                height = active.sps_size.1,
                "dropping MediaCodec: {why}"
            );
        }
    }

    /// After a caught panic: drop the codec, which may itself be what is
    /// broken (ndk's `Drop` unwraps `AMediaCodec_delete`'s status), so that
    /// is guarded too. `active` is taken before anything can panic, so the
    /// decoder is left codec-less either way.
    fn drop_codec_after_panic(&mut self, what: &str, payload: &(dyn Any + Send)) -> String {
        let msg = format!("MediaCodec {what} panicked: {}", panic_message(payload));
        if std::panic::catch_unwind(AssertUnwindSafe(|| self.drop_codec(&msg))).is_err() {
            tracing::error!("dropping the MediaCodec after a panic panicked as well");
        }
        self.idr.reset();
        msg
    }

    fn decode_inner(&mut self, frame: &EncodedFrame) -> Result<Vec<RawFrame>> {
        if frame.keyframe {
            self.prepare_for_keyframe(&frame.data)?;
        }
        let Some(active) = self.active.as_mut() else {
            return Ok(Vec::new());
        };
        if active.output.unsupported.is_some() {
            // Reported (once) when it was found; see OutputState.
            return Ok(Vec::new());
        }
        if !self.idr.admit(frame.keyframe) {
            return Ok(Vec::new());
        }
        active.decode(frame, &mut self.stats, &mut self.idr)
    }

    /// The whole of [`Decoder::decode`], run under `catch_unwind`.
    fn decode_guarded(&mut self, frame: &EncodedFrame) -> Result<Vec<RawFrame>> {
        let result = self.decode_inner(frame);
        match &result {
            Ok(_) => self.errors.ok(),
            Err(e) => {
                self.stats.errors += 1;
                tracing::debug!(frame_id = frame.frame_id, "MediaCodec decode error: {e}");
                if self.errors.fail() {
                    self.drop_codec(&format!("{ERROR_LIMIT} consecutive errors, last: {e}"));
                }
            }
        }
        let (in_flight, dropped) = self
            .active
            .as_ref()
            .map_or((0, 0), |a| (a.pts.in_flight(), a.pts.dropped()));
        if let Some(line) = self.stats.summary_due(Instant::now(), in_flight, dropped) {
            tracing::info!("{line} skipped_awaiting_idr={}", self.idr.skipped());
        }
        result
    }

    /// The whole of [`Decoder::flush`], run under `catch_unwind`.
    fn flush_guarded(&mut self) {
        // Whatever happens below, the next frame the codec may take is a
        // keyframe.
        self.idr.reset();
        let Some(active) = self.active.as_mut() else {
            return;
        };
        match active.codec.0.flush() {
            Ok(()) => {
                active.pts.clear();
                tracing::debug!("MediaCodec flushed");
            }
            Err(e) => self.drop_codec(&format!("flush failed: {e}")),
        }
    }

    /// Make sure a codec matching this keyframe's SPS exists.
    fn prepare_for_keyframe(&mut self, annexb: &[u8]) -> Result<()> {
        let nals = h264::split_nals(annexb);
        let Some(sps_nal) = nals.iter().find(|n| n.nal_type == 7) else {
            // The host repeats SPS/PPS before every IDR; an existing codec
            // already has its parameters, so only a fresh one needs them.
            if self.active.is_some() {
                return Ok(());
            }
            return Err(Error::Decoder(
                "keyframe without SPS: cannot configure MediaCodec".into(),
            ));
        };
        let sps = h264::parse_sps(sps_nal.data)?;
        let size = (sps.width, sps.height);
        if let Some(active) = &self.active {
            if active.sps_size == size {
                return Ok(());
            }
            tracing::info!(
                "stream size changed {}x{} -> {}x{}; rebuilding MediaCodec",
                active.sps_size.0,
                active.sps_size.1,
                size.0,
                size.1
            );
            self.active = None;
        }
        // Old codec gone (or never there): no references until this
        // keyframe is queued.
        self.idr.reset();
        let csd = h264::extract_csd(annexb);
        if csd.is_none() {
            tracing::warn!(
                "keyframe has no SPS+PPS pair for csd-0/csd-1; relying on in-band parameters"
            );
        }
        let active = ActiveCodec::create(size, csd.as_ref(), sps.profile_idc, sps.level_idc)?;
        self.stats.codecs_built += 1;
        self.active = Some(active);
        Ok(())
    }
}

impl Default for MediaCodecDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for MediaCodecDecoder {
    fn decode(&mut self, frame: &EncodedFrame) -> Result<Vec<RawFrame>> {
        match std::panic::catch_unwind(AssertUnwindSafe(|| self.decode_guarded(frame))) {
            Ok(result) => result,
            Err(payload) => {
                // The panic hook has already logged message and backtrace.
                // The codec is dropped outright, so the error streak that
                // would otherwise drop it starts over.
                self.stats.errors += 1;
                self.errors.ok();
                Err(Error::Decoder(self.drop_codec_after_panic("decode", &*payload)))
            }
        }
    }

    fn flush(&mut self) {
        if let Err(payload) = std::panic::catch_unwind(AssertUnwindSafe(|| self.flush_guarded())) {
            self.drop_codec_after_panic("flush", &*payload);
        }
    }
}

/// The text of a panic payload (`&str` or `String`, as `panic!` makes them).
fn panic_message(payload: &(dyn Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("<non-string panic payload>")
}

/// `ndk::MediaCodec` wraps a raw `AMediaCodec*` and is therefore `!Send`.
struct SendCodec(MediaCodec);

// SAFETY: AMediaCodec has no thread affinity (the NDK documents none, and the
// Java MediaCodec it fronts may be driven from any thread); what it forbids is
// concurrent calls. A `SendCodec` is owned by exactly one `MediaCodecDecoder`,
// which the pipeline moves to its decode thread and only ever touches through
// `&mut self` — moved between threads, never shared, which is precisely the
// `Send`-but-not-`Sync` contract. (`Sync` is deliberately not implemented.)
unsafe impl Send for SendCodec {}

/// A configured, started codec plus everything tied to its lifetime.
struct ActiveCodec {
    codec: SendCodec,
    /// Picture size from the SPS it was configured with.
    sps_size: (u32, u32),
    pts: PtsMap,
    output: OutputState,
}

impl ActiveCodec {
    /// Create, configure and start a decoder, walking down the
    /// [`LatencyTier::LADDER`] until one configuration is accepted.
    fn create(
        size: (u32, u32),
        csd: Option<&(Vec<u8>, Vec<u8>)>,
        profile_idc: u8,
        level_idc: u8,
    ) -> Result<Self> {
        let (width, height) = size;
        if width == 0 || height == 0 || width > MAX_DIMENSION || height > MAX_DIMENSION {
            return Err(Error::Decoder(format!(
                "SPS size {width}x{height} out of range"
            )));
        }
        let mut last_error = String::new();
        for tier in LatencyTier::LADDER {
            let Some(codec) = MediaCodec::from_decoder_type(MIME_AVC) else {
                return Err(Error::Decoder(format!(
                    "no {MIME_AVC} decoder on this device"
                )));
            };
            let format = build_format(width, height, csd, tier);
            if let Err(e) = codec.configure(&format, None, MediaCodecDirection::Decoder) {
                tracing::warn!(?tier, "MediaCodec configure rejected: {e}");
                last_error = format!("configure ({tier:?}): {e}");
                continue;
            }
            if let Err(e) = codec.start() {
                tracing::warn!(?tier, "MediaCodec start failed: {e}");
                last_error = format!("start ({tier:?}): {e}");
                continue;
            }
            tracing::info!(
                width,
                height,
                profile_idc,
                level_idc,
                ?tier,
                csd = csd.is_some(),
                "MediaCodec {MIME_AVC} decoder started"
            );
            let now = Instant::now();
            return Ok(Self {
                codec: SendCodec(codec),
                sps_size: size,
                pts: PtsMap::new(now),
                output: OutputState::new(size),
            });
        }
        Err(Error::Decoder(format!(
            "MediaCodec unusable at every latency tier; last: {last_error}"
        )))
    }

    fn decode(
        &mut self,
        frame: &EncodedFrame,
        stats: &mut DecodeStats,
        idr: &mut IdrGate,
    ) -> Result<Vec<RawFrame>> {
        let codec = &self.codec.0;
        let mut out = Vec::new();

        // (1) Whatever finished since the last call.
        drain(
            codec,
            &mut self.output,
            &mut self.pts,
            stats,
            Duration::ZERO,
            &mut out,
        )?;

        // (2) Queue this frame.
        let mut retried = false;
        loop {
            let slot = codec
                .dequeue_input_buffer(INPUT_TIMEOUT)
                .map_err(|e| media_error("dequeue_input_buffer", e))?;
            match slot {
                DequeuedInputBufferResult::Buffer(mut input) => {
                    let dst = input.buffer_mut();
                    let n = frame.data.len();
                    let capacity = dst.len();
                    let fits = n <= capacity;
                    if fits {
                        // Safe MaybeUninit initialisation, byte by byte
                        // (compiles to a memcpy); no `unsafe` needed.
                        for (d, s) in dst.iter_mut().zip(&frame.data) {
                            d.write(*s);
                        }
                    }
                    let pts = self.pts.push(Instant::now(), frame.timestamp_ms);
                    // A frame that does not fit still returns its slot (empty)
                    // so the codec does not lose an input buffer until flush.
                    let len = if fits { n } else { 0 };
                    codec
                        .queue_input_buffer(input, 0, len, pts, 0)
                        .map_err(|e| media_error("queue_input_buffer", e))?;
                    if !fits {
                        return Err(Error::Decoder(format!(
                            "frame {} is {n} bytes, MediaCodec input buffer holds {capacity}",
                            frame.frame_id
                        )));
                    }
                    idr.on_queued(frame.keyframe);
                    stats.on_input(self.pts.in_flight());
                    break;
                }
                DequeuedInputBufferResult::TryAgainLater => {
                    if retried {
                        return Err(Error::Decoder(format!(
                            "no MediaCodec input buffer within {}ms ({} frames in flight)",
                            2 * INPUT_TIMEOUT.as_millis(),
                            self.pts.in_flight()
                        )));
                    }
                    retried = true;
                    drain(
                        codec,
                        &mut self.output,
                        &mut self.pts,
                        stats,
                        Duration::ZERO,
                        &mut out,
                    )?;
                }
            }
        }

        // (3) Give this frame a short chance to come out now.
        drain(
            codec,
            &mut self.output,
            &mut self.pts,
            stats,
            OUTPUT_WAIT,
            &mut out,
        )?;
        Ok(out)
    }
}

impl Drop for ActiveCodec {
    fn drop(&mut self) {
        // `AMediaCodec_delete` (ndk's Drop) releases it either way; stopping
        // first is the documented order.
        let _ = self.codec.0.stop();
    }
}

/// The current output layout, re-read on every format change.
struct OutputState {
    /// Picture size from the SPS the codec was configured with: the crop
    /// fallback when the output format reports none.
    sps_size: (u32, u32),
    keys: Option<OutputFormatKeys>,
    layout: Option<PlaneLayout>,
    /// The raw output color format, once one turned out to be something
    /// `yuv` cannot convert. Permanent for this codec instance.
    unsupported: Option<i32>,
}

impl OutputState {
    fn new(sps_size: (u32, u32)) -> Self {
        Self {
            sps_size,
            keys: None,
            layout: None,
            unsupported: None,
        }
    }

    fn update(&mut self, format: &MediaFormat) -> Result<PlaneLayout> {
        // Never keep converting with the previous layout if this format
        // turns out unreadable: the next buffer re-reads it instead.
        self.layout = None;
        let keys = OutputFormatKeys::read(|k| format.i32(k), crop_rect(format), self.sps_size)
            .map_err(Error::Decoder)?;
        let color_format = normalize_color_format(keys.color_format);
        if !color_format_supported(color_format) {
            if self.unsupported.is_none() {
                tracing::error!(
                    "MediaCodec output color format {:#x} ({}) is not convertible; this \
                     decoder instance is disabled until the stream size changes",
                    keys.color_format,
                    keys.color_format
                );
            }
            self.unsupported = Some(keys.color_format);
            return Err(Error::Decoder(format!(
                "unsupported MediaCodec output color format {:#x}",
                keys.color_format
            )));
        }
        let layout = yuv::layout_from_format(
            color_format,
            keys.width,
            keys.height,
            keys.stride,
            keys.slice_height,
            keys.crop,
        );
        if self.keys != Some(keys) {
            tracing::info!(
                "MediaCodec output format: color-format={:#x} ({}, as {}) {}x{} stride={} \
                 slice-height={} crop={:?} -> {:?}",
                keys.color_format,
                keys.color_format,
                color_format,
                keys.width,
                keys.height,
                keys.stride,
                keys.slice_height,
                keys.crop,
                layout
            );
            self.keys = Some(keys);
        }
        self.layout = layout.as_ref().ok().copied();
        layout
    }
}

/// Collect decoded pictures. With a non-zero `wait`, blocks up to `wait` for
/// the first picture (only while something is in flight), then takes
/// whatever else is ready without blocking.
fn drain(
    codec: &MediaCodec,
    output: &mut OutputState,
    pts: &mut PtsMap,
    stats: &mut DecodeStats,
    wait: Duration,
    out: &mut Vec<RawFrame>,
) -> Result<()> {
    let deadline = Instant::now() + wait;
    let mut got_picture = false;
    loop {
        let timeout = if got_picture || pts.in_flight() == 0 {
            Duration::ZERO
        } else {
            deadline.saturating_duration_since(Instant::now())
        };
        let next = codec
            .dequeue_output_buffer(timeout)
            .map_err(|e| media_error("dequeue_output_buffer", e))?;
        match next {
            DequeuedOutputBufferInfoResult::Buffer(buffer) => {
                let info = *buffer.info();
                let now = Instant::now();
                if info.size() <= 0 || info.flags() & (FLAG_CODEC_CONFIG | FLAG_END_OF_STREAM) != 0
                {
                    codec
                        .release_output_buffer(buffer, false)
                        .map_err(|e| media_error("release_output_buffer", e))?;
                    continue;
                }
                let pending = u64::try_from(info.presentation_time_us())
                    .ok()
                    .and_then(|p| pts.take(p));
                let timestamp_ms =
                    pending.map_or_else(|| pts.fallback_timestamp_ms(), |p| p.timestamp_ms);

                // Convert, then release the buffer whether or not that
                // worked, then report.
                let layout = match output.layout {
                    Some(l) => Ok(l),
                    // No FORMAT_CHANGED seen yet (some codecs skip it):
                    // the codec's current output format is authoritative.
                    None => output.update(&codec.output_format()),
                };
                let converted = layout.and_then(|layout| {
                    let start = usize::try_from(info.offset()).unwrap_or(usize::MAX);
                    // From the offset to the end of the buffer rather than
                    // `offset + size`: some vendors report a size that omits
                    // the padding after the last chroma row, which the
                    // layout's plane offsets may still span.
                    let src = buffer.buffer().get(start..).ok_or_else(|| {
                        Error::Decoder(format!("output offset {} out of range", info.offset()))
                    })?;
                    let mut rgba = Vec::new();
                    yuv::yuv420_to_rgba(src, &layout, &mut rgba)?;
                    Ok(RawFrame {
                        width: layout.crop_w,
                        height: layout.crop_h,
                        format: PixelFormat::Rgba8,
                        data: rgba,
                        timestamp_ms,
                    })
                });
                codec
                    .release_output_buffer(buffer, false)
                    .map_err(|e| media_error("release_output_buffer", e))?;
                out.push(converted?);
                stats.on_output(pending.map(|p| now.saturating_duration_since(p.queued_at)));
                got_picture = true;
            }
            DequeuedOutputBufferInfoResult::OutputFormatChanged => {
                output.update(&codec.output_format())?;
            }
            DequeuedOutputBufferInfoResult::OutputBuffersChanged => {
                // Buffers are fetched by index on every dequeue, so there is
                // no cached array to refresh.
                tracing::debug!("MediaCodec output buffers changed");
            }
            DequeuedOutputBufferInfoResult::TryAgainLater => return Ok(()),
        }
    }
}

fn build_format(
    width: u32,
    height: u32,
    csd: Option<&(Vec<u8>, Vec<u8>)>,
    tier: LatencyTier,
) -> MediaFormat {
    let mut format = MediaFormat::new();
    format.set_str("mime", MIME_AVC);
    // Both <= MAX_DIMENSION, checked by the caller.
    format.set_i32("width", width as i32);
    format.set_i32("height", height as i32);
    format.set_i32("max-input-size", max_input_size(width, height));
    format.set_i32("color-format", COLOR_FORMAT_YUV420_FLEXIBLE);
    if let Some((sps, pps)) = csd {
        format.set_buffer("csd-0", sps);
        format.set_buffer("csd-1", pps);
    }
    for (key, value) in tier.keys() {
        format.set_i32(key, *value);
    }
    format
}

fn media_error(what: &str, e: ndk::media_error::MediaError) -> Error {
    Error::Decoder(format!("AMediaCodec {what}: {e}"))
}

/// `AMediaFormat_getRect`, API 28+.
type GetRectFn = unsafe extern "C" fn(
    format: *mut c_void,
    name: *const c_char,
    left: *mut i32,
    top: *mut i32,
    right: *mut i32,
    bottom: *mut i32,
) -> bool;

/// Look `AMediaFormat_getRect` up at runtime: linking it directly (ndk's
/// `api-level-28` feature) would make the library fail to load on API 26/27.
fn get_rect_fn() -> Option<GetRectFn> {
    static GET_RECT: OnceLock<Option<GetRectFn>> = OnceLock::new();
    *GET_RECT.get_or_init(|| {
        // SAFETY: valid NUL-terminated names. RTLD_NOLOAD only returns a
        // handle if libmediandk is already mapped (it is: we link it), and
        // the handle is never closed, so the symbol stays valid for the life
        // of the process. The transmute gives the pointer the exact C
        // signature from <media/NdkMediaFormat.h>.
        unsafe {
            let lib = libc::dlopen(
                c"libmediandk.so".as_ptr(),
                libc::RTLD_NOW | libc::RTLD_NOLOAD,
            );
            if lib.is_null() {
                return None;
            }
            let sym = libc::dlsym(lib, c"AMediaFormat_getRect".as_ptr());
            if sym.is_null() {
                None
            } else {
                Some(std::mem::transmute::<*mut c_void, GetRectFn>(sym))
            }
        }
    })
}

/// The output crop as an inclusive (left, top, right, bottom), from the
/// native `"crop"` rect where the platform can read it.
fn crop_rect(format: &MediaFormat) -> Option<(i32, i32, i32, i32)> {
    let get_rect = get_rect_fn()?;
    let (mut l, mut t, mut r, mut b) = (0i32, 0i32, 0i32, 0i32);
    // SAFETY: `format` is a live AMediaFormat for the duration of the call,
    // the key is NUL-terminated, and the four out-pointers are valid i32s.
    let found = unsafe {
        get_rect(
            format.as_ptr().cast::<c_void>(),
            c"crop".as_ptr(),
            &mut l,
            &mut t,
            &mut r,
            &mut b,
        )
    };
    found.then_some((l, t, r, b))
}
