//! Media Foundation H.264 decoder implementing [`Decoder`].
//!
//! Pipeline: annex-B H.264 (`EncodedFrame.data`) → `CLSID_MSH264DecoderMFT`
//! → NV12 CPU sample → RGBA8 [`RawFrame`] (limited-range BT.709).
//!
//! # Latency rule
//!
//! **Every frame is decoded, in order.** P-frames reference their
//! predecessors, so skipping one corrupts everything until the next IDR.
//! Frames are discarded only at *present* time (see [`crate::renderer`]).
//! The single exception is the post-[`Decoder::flush`] state, where we
//! genuinely cannot decode anything until a keyframe arrives.
//!
//! # Threading
//!
//! MF and COM are initialized per thread by [`ensure_mf_initialized`], which
//! runs on construction *and* on every decode call, so the decoder is correct
//! wherever it is used. Initialization is MTA and deliberately never torn down
//! (no `MFShutdown`/`CoUninitialize`): shutting MF down while its worker
//! threads still hold references is a well-known crash source, and the process
//! is exiting anyway.

use std::collections::VecDeque;

use directdesk_shared::error::{Error, Result};
use directdesk_shared::traits::{Decoder, PixelFormat, RawFrame};
use directdesk_shared::video::EncodedFrame;

// ---------------------------------------------------------------------------
// NV12 → RGBA8 (pure, platform independent, unit tested)
// ---------------------------------------------------------------------------

/// Rec.709 limited-range ("studio swing", Y 16..235 / C 16..240) NV12 to RGBA8.
///
/// Fixed-point Q8 of the standard matrix:
/// ```text
/// R = 1.1644(Y-16)                  + 1.7927(V-128)
/// G = 1.1644(Y-16) - 0.2132(U-128)  - 0.5329(V-128)
/// B = 1.1644(Y-16) + 2.1124(U-128)
/// ```
///
/// `stride` is the Y-plane pitch in bytes (the UV plane shares it, as NV12
/// always does). `width`/`height` are the *display* dimensions, which may be
/// smaller than the coded plane — that is how 1088-tall H.264 output gets
/// cropped back to 1080.
///
/// # Chroma upsampling geometry (MPEG-2 / "left-sited")
///
/// H.264 with no `chroma_sample_loc_type` in the VUI — which is what this
/// pipeline produces — means chroma sample `(k, j)` sits **co-sited with the
/// even luma column `2k`** and **midway between luma rows `2j` and `2j+1`**.
/// We reconstruct with bilinear interpolation on exactly that grid:
///
/// * Horizontal: luma column `2k` is the chroma sample `k` itself (weight 1);
///   luma column `2k+1` is halfway between `k` and `k+1` → `0.5 / 0.5`.
/// * Vertical: chroma row `j` lives at luma-row coordinate `2j + 0.5`, so luma
///   row `r` maps to chroma coordinate `r/2 - 0.25`. Luma row `2k` lands at
///   `k - 0.25` → `0.75 * C[k] + 0.25 * C[k-1]`; luma row `2k+1` lands at
///   `k + 0.25` → `0.75 * C[k] + 0.25 * C[k+1]`.
/// * Edges: the out-of-range neighbour is clamped to the nearest existing
///   sample/row, which degenerates the blend to weight 1 on the edge sample.
///
/// The previous implementation replicated chroma nearest-neighbour in both
/// axes, which desaturated 1px coloured glyph stems *and* shifted them half a
/// pixel left of the luma stroke they belong to.
///
/// Interpolation stays in integers: the vertical `0.75/0.25` blend is kept in
/// Q2 (value × 4) per output row, and the horizontal blend promotes it to Q3
/// (value × 8), which the Q8 colour matrix absorbs by shifting 11 instead of 8.
/// For a constant chroma field this is bit-identical to the old code.
pub fn nv12_to_rgba(
    y_plane: &[u8],
    uv_plane: &[u8],
    width: usize,
    height: usize,
    stride: usize,
) -> Result<Vec<u8>> {
    if width == 0 || height == 0 {
        return Err(Error::Decoder("zero-sized frame".into()));
    }
    if stride < width {
        return Err(Error::Decoder(format!("stride {stride} < width {width}")));
    }
    let y_needed = (height - 1) * stride + width;
    let uv_rows = height.div_ceil(2);
    // UV row holds `width` bytes (width/2 interleaved U,V pairs), rounded up.
    let uv_needed = (uv_rows - 1) * stride + width.div_ceil(2) * 2;
    if y_plane.len() < y_needed {
        return Err(Error::Decoder(format!(
            "Y plane {} < {y_needed}",
            y_plane.len()
        )));
    }
    if uv_plane.len() < uv_needed {
        return Err(Error::Decoder(format!(
            "UV plane {} < {uv_needed}",
            uv_plane.len()
        )));
    }

    let cw = width.div_ceil(2); // chroma samples per row
    let uv_row_bytes = cw * 2; // interleaved U,V
    let last_c = cw - 1;
    let last_c_row = uv_rows - 1;

    let mut out = vec![0u8; width * height * 4];
    // Scratch for the vertically-blended chroma row, in Q2 (value * 4).
    // Allocated once and reused for every output row.
    let mut cblend = vec![0i32; uv_row_bytes];

    for row in 0..height {
        let y_row = &y_plane[row * stride..row * stride + width];

        // Vertical 0.75 / 0.25 blend, done once per output row.
        let k = row / 2;
        let far_row = if row % 2 == 0 {
            k.saturating_sub(1) // clamp above the first chroma row
        } else {
            (k + 1).min(last_c_row) // clamp below the last chroma row
        };
        let near = &uv_plane[k * stride..k * stride + uv_row_bytes];
        let far = &uv_plane[far_row * stride..far_row * stride + uv_row_bytes];
        for i in 0..uv_row_bytes {
            cblend[i] = 3 * near[i] as i32 + far[i] as i32;
        }

        let out_row = &mut out[row * width * 4..(row + 1) * width * 4];
        // One chroma sample feeds a pair of output pixels: the even column
        // takes it straight, the odd column averages it with the next one.
        let mut pairs = out_row.chunks_exact_mut(8);
        for (kx, pair) in pairs.by_ref().enumerate() {
            let kx1 = (kx + 1).min(last_c);
            let (u0, v0) = (cblend[kx * 2], cblend[kx * 2 + 1]);
            let (u1, v1) = (cblend[kx1 * 2], cblend[kx1 * 2 + 1]);
            let (even, odd) = pair.split_at_mut(4);
            write_px(even, y_row[kx * 2], u0 * 2, v0 * 2);
            write_px(odd, y_row[kx * 2 + 1], u0 + u1, v0 + v1);
        }
        // Odd display width: the trailing pixel is an even (co-sited) column.
        let rem = pairs.into_remainder();
        if !rem.is_empty() {
            write_px(
                rem,
                y_row[width - 1],
                cblend[last_c * 2] * 2,
                cblend[last_c * 2 + 1] * 2,
            );
        }
    }
    Ok(out)
}

/// Q8 limited-range BT.709 matrix, taking chroma in Q3 (value * 8).
///
/// Identical to `(298*c + 459*e + 128) >> 8` when the chroma is a whole
/// number: everything is scaled by 8 and the shift grows from 8 to 11.
#[inline(always)]
fn write_px(px: &mut [u8], y: u8, u_q3: i32, v_q3: i32) {
    let d = u_q3 - 128 * 8;
    let e = v_q3 - 128 * 8;
    let luma = 298 * 8 * (y as i32 - 16);
    px[0] = clamp_u8((luma + 459 * e + 1024) >> 11);
    px[1] = clamp_u8((luma - 55 * d - 136 * e + 1024) >> 11);
    px[2] = clamp_u8((luma + 541 * d + 1024) >> 11);
    px[3] = 255;
}

#[inline(always)]
fn clamp_u8(v: i32) -> u8 {
    v.clamp(0, 255) as u8
}

// ---------------------------------------------------------------------------
// Media Foundation implementation
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod mf {
    use super::*;

    use std::mem::ManuallyDrop;

    use windows::core::HRESULT;
    use windows::Win32::Media::MediaFoundation::*;
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
    };

    /// Another apartment model was already chosen on this thread — harmless,
    /// COM stays usable.
    const RPC_E_CHANGED_MODE: HRESULT = HRESULT(0x8001_0106_u32 as i32);
    /// The MFT cannot take more input until output is drained.
    const MF_E_NOTACCEPTING_HR: HRESULT = HRESULT(0xC00D_36B5_u32 as i32);

    thread_local! {
        static MF_READY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// Idempotent per-thread COM(MTA) + Media Foundation startup.
    pub fn ensure_mf_initialized() -> Result<()> {
        MF_READY.with(|ready| {
            if ready.get() {
                return Ok(());
            }
            // SAFETY: standard COM/MF process init; both calls are documented
            // as safe to make from any thread.
            unsafe {
                let hr = CoInitializeEx(None, COINIT_MULTITHREADED);
                if hr.is_err() && hr != RPC_E_CHANGED_MODE {
                    return Err(Error::Decoder(format!("CoInitializeEx failed: {hr:?}")));
                }
                MFStartup(MF_VERSION, MFSTARTUP_NOSOCKET)
                    .map_err(|e| Error::Decoder(format!("MFStartup failed: {e}")))?;
            }
            ready.set(true);
            tracing::debug!("Media Foundation initialized on this thread");
            Ok(())
        })
    }

    /// Negotiated output geometry.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct OutputFormat {
        /// Coded (padded) plane size, e.g. 1920x1088.
        pub coded_w: u32,
        pub coded_h: u32,
        /// Display size after `MF_MT_MINIMUM_DISPLAY_APERTURE`, e.g. 1920x1080.
        pub disp_w: u32,
        pub disp_h: u32,
        /// Y-plane pitch in bytes.
        pub stride: u32,
    }

    impl OutputFormat {
        fn nv12_bytes(&self) -> usize {
            self.stride as usize * self.coded_h as usize * 3 / 2
        }
    }

    pub struct MfH264Decoder {
        transform: IMFTransform,
        format: Option<OutputFormat>,
        provides_samples: bool,
        out_sample_bytes: u32,
        out_sample: Option<IMFSample>,
        /// PTS → host timestamp, so latency stats survive MF's own clock.
        pending_ts: VecDeque<(i64, u32)>,
        next_pts: i64,
        last_input_ts_ms: u32,
        needs_keyframe: bool,
        frames_in: u64,
        frames_out: u64,
        skipped_awaiting_key: u64,
    }

    // SAFETY: every MF object here is created and used through this struct
    // only, and `ensure_mf_initialized` runs on entry to `new` and `decode`,
    // so whichever thread owns the decoder has COM initialized as MTA. MTA
    // objects may legally be called from any MTA thread, so transferring
    // ownership (which is all `Send` permits) is sound.
    unsafe impl Send for MfH264Decoder {}

    impl MfH264Decoder {
        pub fn new() -> Result<Self> {
            ensure_mf_initialized()?;

            // SAFETY: all calls below are on freshly created MF objects with
            // correctly typed arguments; failures come back as HRESULTs.
            unsafe {
                let transform: IMFTransform =
                    CoCreateInstance(&CLSID_MSH264DecoderMFT, None, CLSCTX_INPROC_SERVER).map_err(
                        |e| Error::Decoder(format!("CoCreateInstance(H264 decoder): {e}")),
                    )?;

                // Low latency: no lookahead, emit as soon as a picture is done.
                match transform.GetAttributes() {
                    Ok(attrs) => {
                        if let Err(e) = attrs.SetUINT32(&MF_LOW_LATENCY, 1) {
                            tracing::warn!("MF_LOW_LATENCY not accepted: {e}");
                        }
                    }
                    Err(e) => tracing::warn!("decoder exposes no attributes: {e}"),
                }

                let input = MFCreateMediaType()
                    .map_err(|e| Error::Decoder(format!("MFCreateMediaType: {e}")))?;
                input
                    .SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)
                    .map_err(|e| Error::Decoder(format!("set major type: {e}")))?;
                input
                    .SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_H264)
                    .map_err(|e| Error::Decoder(format!("set H264 subtype: {e}")))?;
                let _ =
                    input.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32);
                // No MF_MT_MPEG_SEQUENCE_HEADER: that is what tells the MFT the
                // stream is annex-B with in-band SPS/PPS, which is what the host
                // sends.
                transform
                    .SetInputType(0, &input, 0)
                    .map_err(|e| Error::Decoder(format!("SetInputType(H264): {e}")))?;

                let mut decoder = Self {
                    transform,
                    format: None,
                    provides_samples: false,
                    out_sample_bytes: 0,
                    out_sample: None,
                    pending_ts: VecDeque::new(),
                    next_pts: 0,
                    last_input_ts_ms: 0,
                    needs_keyframe: true,
                    frames_in: 0,
                    frames_out: 0,
                    skipped_awaiting_key: 0,
                };

                // The real geometry only arrives with the first SPS, but many
                // builds already offer NV12 here; failure is expected and fine.
                match decoder.configure_output() {
                    Ok(fmt) => tracing::info!(
                        "H.264 MFT initial output {}x{} (coded {}x{}, stride {})",
                        fmt.disp_w,
                        fmt.disp_h,
                        fmt.coded_w,
                        fmt.coded_h,
                        fmt.stride
                    ),
                    Err(e) => tracing::debug!("output type deferred until first SPS: {e}"),
                }

                decoder
                    .transform
                    .ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)
                    .map_err(|e| Error::Decoder(format!("BEGIN_STREAMING: {e}")))?;
                decoder
                    .transform
                    .ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)
                    .map_err(|e| Error::Decoder(format!("START_OF_STREAM: {e}")))?;

                tracing::info!("Media Foundation H.264 decoder ready");
                Ok(decoder)
            }
        }

        pub fn describe(&self) -> String {
            match self.format {
                Some(f) => format!(
                    "MF H.264 (CLSID_MSH264DecoderMFT), {}x{} NV12→RGBA (coded {}x{}, stride {})",
                    f.disp_w, f.disp_h, f.coded_w, f.coded_h, f.stride
                ),
                None => "MF H.264 (CLSID_MSH264DecoderMFT), awaiting first keyframe".into(),
            }
        }

        pub fn format(&self) -> Option<OutputFormat> {
            self.format
        }

        pub fn frames_decoded(&self) -> u64 {
            self.frames_out
        }

        pub fn frames_skipped_awaiting_key(&self) -> u64 {
            self.skipped_awaiting_key
        }

        /// Pick the NV12 output type and read back the negotiated geometry.
        ///
        /// # Safety
        /// Requires an initialized MF apartment on the calling thread.
        unsafe fn configure_output(&mut self) -> Result<OutputFormat> {
            let transform = self.transform.clone();
            let mut index = 0u32;
            loop {
                // SAFETY: index-based enumeration; ends with an error HRESULT.
                let ty = match unsafe { transform.GetOutputAvailableType(0, index) } {
                    Ok(t) => t,
                    Err(_) => break,
                };
                // SAFETY: `ty` is a valid media type from the MFT.
                let subtype = unsafe { ty.GetGUID(&MF_MT_SUBTYPE) };
                if subtype.map(|g| g == MFVideoFormat_NV12).unwrap_or(false) {
                    // SAFETY: setting a type the MFT itself offered.
                    unsafe { transform.SetOutputType(0, &ty, 0) }
                        .map_err(|e| Error::Decoder(format!("SetOutputType(NV12): {e}")))?;
                    // SAFETY: type is now set, so current type is readable.
                    let fmt = unsafe { read_output_format(&transform) }?;
                    self.format = Some(fmt);
                    self.out_sample = None;
                    // SAFETY: stream info is valid once types are negotiated.
                    unsafe { self.refresh_stream_info(fmt) }?;
                    return Ok(fmt);
                }
                index += 1;
            }
            Err(Error::Decoder("MFT offers no NV12 output type".into()))
        }

        /// # Safety
        /// Requires negotiated types on stream 0.
        unsafe fn refresh_stream_info(&mut self, fmt: OutputFormat) -> Result<()> {
            // SAFETY: stream 0 exists on this MFT.
            let info = unsafe { self.transform.GetOutputStreamInfo(0) }
                .map_err(|e| Error::Decoder(format!("GetOutputStreamInfo: {e}")))?;
            let provides = MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 as u32
                | MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES.0 as u32;
            self.provides_samples = info.dwFlags & provides != 0;
            self.out_sample_bytes = info.cbSize.max(fmt.nv12_bytes() as u32);
            tracing::debug!(
                "MFT output stream: provides_samples={} cbSize={} using={}",
                self.provides_samples,
                info.cbSize,
                self.out_sample_bytes
            );
            Ok(())
        }

        /// A reusable, zero-length output sample.
        ///
        /// # Safety
        /// Requires an initialized MF apartment.
        unsafe fn acquire_out_sample(&mut self) -> Result<IMFSample> {
            if let Some(sample) = self.out_sample.take() {
                // SAFETY: our own sample, always built with exactly one buffer.
                if let Ok(buffer) = unsafe { sample.GetBufferByIndex(0) } {
                    // SAFETY: resetting length on a buffer we own.
                    if unsafe { buffer.SetCurrentLength(0) }.is_ok() {
                        return Ok(sample);
                    }
                }
            }
            let size = self.out_sample_bytes.max(1);
            // SAFETY: plain MF allocation calls.
            unsafe {
                let buffer = MFCreateMemoryBuffer(size)
                    .map_err(|e| Error::Decoder(format!("MFCreateMemoryBuffer({size}): {e}")))?;
                let sample =
                    MFCreateSample().map_err(|e| Error::Decoder(format!("MFCreateSample: {e}")))?;
                sample
                    .AddBuffer(&buffer)
                    .map_err(|e| Error::Decoder(format!("AddBuffer: {e}")))?;
                Ok(sample)
            }
        }

        /// # Safety
        /// Requires an initialized MF apartment.
        unsafe fn make_input_sample(&mut self, data: &[u8], ts_ms: u32) -> Result<IMFSample> {
            // MF wants a strictly increasing clock; `timestamp_ms` wraps, so we
            // feed a synthetic PTS and map it back on the way out.
            let pts = self.next_pts;
            self.next_pts += 10_000; // 1 ms in 100 ns units

            // SAFETY: buffer is sized to `data`, locked, filled, unlocked.
            unsafe {
                let buffer = MFCreateMemoryBuffer(data.len() as u32)
                    .map_err(|e| Error::Decoder(format!("MFCreateMemoryBuffer: {e}")))?;
                let mut ptr: *mut u8 = std::ptr::null_mut();
                buffer
                    .Lock(&mut ptr, None, None)
                    .map_err(|e| Error::Decoder(format!("buffer Lock: {e}")))?;
                std::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
                let _ = buffer.Unlock();
                buffer
                    .SetCurrentLength(data.len() as u32)
                    .map_err(|e| Error::Decoder(format!("SetCurrentLength: {e}")))?;

                let sample =
                    MFCreateSample().map_err(|e| Error::Decoder(format!("MFCreateSample: {e}")))?;
                sample
                    .AddBuffer(&buffer)
                    .map_err(|e| Error::Decoder(format!("AddBuffer: {e}")))?;
                sample
                    .SetSampleTime(pts)
                    .map_err(|e| Error::Decoder(format!("SetSampleTime: {e}")))?;

                self.pending_ts.push_back((pts, ts_ms));
                while self.pending_ts.len() > 64 {
                    self.pending_ts.pop_front();
                }
                Ok(sample)
            }
        }

        /// Match an output PTS back to the host timestamp that produced it.
        fn host_ts_for(&mut self, pts: i64) -> u32 {
            while let Some(&(front, ts)) = self.pending_ts.front() {
                if front < pts {
                    self.pending_ts.pop_front();
                } else if front == pts {
                    self.pending_ts.pop_front();
                    return ts;
                } else {
                    break;
                }
            }
            self.last_input_ts_ms
        }

        /// # Safety
        /// `sample` must be an NV12 output sample matching `self.format`.
        unsafe fn sample_to_frame(&mut self, sample: &IMFSample) -> Result<RawFrame> {
            let fmt = self
                .format
                .ok_or_else(|| Error::Decoder("output sample before format negotiation".into()))?;

            // SAFETY: reading the sample's own timestamp.
            let ts_ms = match unsafe { sample.GetSampleTime() } {
                Ok(pts) => self.host_ts_for(pts),
                Err(_) => self.last_input_ts_ms,
            };

            // SAFETY: contiguous view of the sample's buffers, then locked for
            // the duration of the copy and unlocked on every path below.
            let buffer = unsafe { sample.ConvertToContiguousBuffer() }
                .map_err(|e| Error::Decoder(format!("ConvertToContiguousBuffer: {e}")))?;

            let mut ptr: *mut u8 = std::ptr::null_mut();
            let mut current: u32 = 0;
            // SAFETY: Lock hands back a pointer valid until Unlock.
            unsafe { buffer.Lock(&mut ptr, None, Some(&mut current)) }
                .map_err(|e| Error::Decoder(format!("output Lock: {e}")))?;

            // SAFETY: `ptr`/`current` describe the locked region.
            let bytes = unsafe { std::slice::from_raw_parts(ptr, current as usize) };
            let y_len = fmt.stride as usize * fmt.coded_h as usize;
            let converted = if bytes.len() < y_len {
                Err(Error::Decoder(format!(
                    "output buffer {} < Y plane {y_len} ({}x{} stride {})",
                    bytes.len(),
                    fmt.coded_w,
                    fmt.coded_h,
                    fmt.stride
                )))
            } else {
                nv12_to_rgba(
                    &bytes[..y_len],
                    &bytes[y_len..],
                    fmt.disp_w as usize,
                    fmt.disp_h as usize,
                    fmt.stride as usize,
                )
            };
            // SAFETY: matching Unlock for the Lock above; runs on both paths.
            let _ = unsafe { buffer.Unlock() };

            Ok(RawFrame {
                width: fmt.disp_w,
                height: fmt.disp_h,
                format: PixelFormat::Rgba8,
                data: converted?,
                timestamp_ms: ts_ms,
            })
        }

        /// Pull every ready picture out of the MFT.
        ///
        /// # Safety
        /// Requires an initialized MF apartment.
        unsafe fn drain_outputs(&mut self, out: &mut Vec<RawFrame>) -> Result<()> {
            let transform = self.transform.clone();
            loop {
                let supplied = if self.provides_samples {
                    None
                } else {
                    Some(unsafe { self.acquire_out_sample()? })
                };

                let mut buffers = [MFT_OUTPUT_DATA_BUFFER {
                    dwStreamID: 0,
                    pSample: ManuallyDrop::new(supplied),
                    dwStatus: 0,
                    pEvents: ManuallyDrop::new(None),
                }];
                let mut status = 0u32;
                // SAFETY: one correctly initialized output buffer descriptor.
                let result = unsafe { transform.ProcessOutput(0, &mut buffers, &mut status) };
                // SAFETY: taking ownership back exactly once; `buffers` is not
                // read again afterwards.
                let produced = unsafe { ManuallyDrop::take(&mut buffers[0].pSample) };
                // SAFETY: same, for the (unused) event collection.
                drop(unsafe { ManuallyDrop::take(&mut buffers[0].pEvents) });

                match result {
                    Ok(()) => {
                        if let Some(sample) = produced {
                            // SAFETY: an NV12 sample matching the current type.
                            match unsafe { self.sample_to_frame(&sample) } {
                                Ok(frame) => {
                                    self.frames_out += 1;
                                    out.push(frame);
                                }
                                Err(e) => tracing::warn!("dropping undecodable output: {e}"),
                            }
                            if !self.provides_samples {
                                self.out_sample = Some(sample); // recycle
                            }
                        }
                    }
                    Err(e) if e.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => break,
                    Err(e) if e.code() == MF_E_TRANSFORM_STREAM_CHANGE => {
                        drop(produced);
                        self.out_sample = None;
                        // SAFETY: renegotiating on the same initialized thread.
                        let fmt = unsafe { self.configure_output() }?;
                        tracing::info!(
                            "H.264 stream change → {}x{} (coded {}x{}, stride {})",
                            fmt.disp_w,
                            fmt.disp_h,
                            fmt.coded_w,
                            fmt.coded_h,
                            fmt.stride
                        );
                        continue;
                    }
                    Err(e) => {
                        drop(produced);
                        return Err(Error::Decoder(format!("ProcessOutput: {e}")));
                    }
                }
            }
            Ok(())
        }
    }

    impl Decoder for MfH264Decoder {
        fn decode(&mut self, frame: &EncodedFrame) -> Result<Vec<RawFrame>> {
            ensure_mf_initialized()?;

            if self.needs_keyframe {
                if !frame.keyframe {
                    // Not a latency drop: without an IDR there is nothing the
                    // decoder could legally produce.
                    self.skipped_awaiting_key += 1;
                    return Ok(Vec::new());
                }
                self.needs_keyframe = false;
                tracing::debug!("resuming from keyframe {}", frame.frame_id);
            }
            if frame.data.is_empty() {
                return Err(Error::Decoder("empty encoded frame".into()));
            }

            self.last_input_ts_ms = frame.timestamp_ms;
            self.frames_in += 1;
            let mut out = Vec::new();

            // SAFETY: MF is initialized on this thread (checked above); every
            // call below uses objects owned by this struct.
            unsafe {
                let sample = self.make_input_sample(&frame.data, frame.timestamp_ms)?;
                let transform = self.transform.clone();
                match transform.ProcessInput(0, &sample, 0) {
                    Ok(()) => {}
                    Err(e) if e.code() == MF_E_NOTACCEPTING_HR => {
                        // Backed up: drain, then the input must be accepted.
                        self.drain_outputs(&mut out)?;
                        transform.ProcessInput(0, &sample, 0).map_err(|e| {
                            Error::Decoder(format!("ProcessInput after drain: {e}"))
                        })?;
                    }
                    Err(e) => return Err(Error::Decoder(format!("ProcessInput: {e}"))),
                }
                self.drain_outputs(&mut out)?;
            }
            Ok(out)
        }

        fn flush(&mut self) {
            // SAFETY: flushing our own MFT; failure is non-fatal.
            unsafe {
                if let Err(e) = self.transform.ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0) {
                    tracing::warn!("MFT flush failed: {e}");
                }
            }
            self.pending_ts.clear();
            self.out_sample = None;
            self.needs_keyframe = true;
            tracing::debug!("decoder flushed — waiting for a keyframe");
        }
    }

    /// # Safety
    /// Requires a negotiated output type on stream 0.
    unsafe fn read_output_format(transform: &IMFTransform) -> Result<OutputFormat> {
        // SAFETY: current type exists once SetOutputType succeeded.
        let ty = unsafe { transform.GetOutputCurrentType(0) }
            .map_err(|e| Error::Decoder(format!("GetOutputCurrentType: {e}")))?;

        // SAFETY: reading attributes off a valid media type.
        let frame_size = unsafe { ty.GetUINT64(&MF_MT_FRAME_SIZE) }
            .map_err(|e| Error::Decoder(format!("MF_MT_FRAME_SIZE: {e}")))?;
        let coded_w = (frame_size >> 32) as u32;
        let coded_h = (frame_size & 0xFFFF_FFFF) as u32;
        if coded_w == 0 || coded_h == 0 {
            return Err(Error::Decoder("MFT reported a zero frame size".into()));
        }

        // SAFETY: optional attribute; absence is an error we tolerate.
        let stride = match unsafe { ty.GetUINT32(&MF_MT_DEFAULT_STRIDE) } {
            Ok(s) => (s as i32).unsigned_abs().max(coded_w),
            Err(_) => coded_w,
        };

        // MF_MT_MINIMUM_DISPLAY_APERTURE is how 1088-tall coded output declares
        // that only the top 1080 rows are real picture.
        // SAFETY: optional blob; we size the buffer to the struct exactly.
        let (disp_w, disp_h) = match unsafe { read_aperture(&ty) } {
            Some((w, h)) if w > 0 && h > 0 => (w.min(coded_w), h.min(coded_h)),
            _ => (coded_w, coded_h),
        };

        Ok(OutputFormat {
            coded_w,
            coded_h,
            disp_w,
            disp_h,
            stride,
        })
    }

    /// # Safety
    /// `ty` must be a valid media type.
    unsafe fn read_aperture(ty: &IMFMediaType) -> Option<(u32, u32)> {
        let mut blob = [0u8; std::mem::size_of::<MFVideoArea>()];
        // SAFETY: buffer is exactly the documented blob size.
        unsafe { ty.GetBlob(&MF_MT_MINIMUM_DISPLAY_APERTURE, &mut blob, None) }.ok()?;
        // SAFETY: MFVideoArea is a plain repr(C) POD; the blob is its size.
        let area: MFVideoArea = unsafe { std::ptr::read_unaligned(blob.as_ptr().cast()) };
        Some((
            u32::try_from(area.Area.cx).ok()?,
            u32::try_from(area.Area.cy).ok()?,
        ))
    }

    /// Create a decoder and report what Media Foundation negotiated. Used by
    /// `--decoder-selftest`; proves MFT creation + type negotiation without
    /// claiming anything about end-to-end decoding.
    pub fn self_test() -> String {
        let mut report = String::new();
        match MfH264Decoder::new() {
            Ok(decoder) => {
                report.push_str("MFT created: CLSID_MSH264DecoderMFT\n");
                report.push_str("input type set: MFVideoFormat_H264 (annex-B, in-band SPS/PPS)\n");
                match decoder.format() {
                    Some(f) => report.push_str(&format!(
                        "output type: NV12 coded {}x{}, display {}x{}, stride {}\n",
                        f.coded_w, f.coded_h, f.disp_w, f.disp_h, f.stride
                    )),
                    None => report
                        .push_str("output type: not negotiable before the first SPS (expected)\n"),
                }
                report.push_str(&format!("provides_samples: {}\n", decoder.provides_samples));
                // SAFETY: enumerating types on a live MFT we own.
                unsafe {
                    let mut i = 0;
                    while let Ok(ty) = decoder.transform.GetOutputAvailableType(0, i) {
                        let sub = ty.GetGUID(&MF_MT_SUBTYPE).ok();
                        report.push_str(&format!(
                            "  available output[{i}]: {}\n",
                            match sub {
                                Some(g) if g == MFVideoFormat_NV12 => "NV12".to_string(),
                                Some(g) => format!("{g:?}"),
                                None => "<unknown>".to_string(),
                            }
                        ));
                        i += 1;
                        if i > 16 {
                            break;
                        }
                    }
                }
                report.push_str("STATUS: decoder initializes and negotiates types\n");
            }
            Err(e) => report.push_str(&format!("STATUS: decoder init FAILED: {e}\n")),
        }
        report
    }
}

#[cfg(windows)]
pub use mf::{ensure_mf_initialized, self_test, MfH264Decoder, OutputFormat};

/// Build the platform H.264 decoder.
pub fn new_decoder() -> Result<Box<dyn Decoder>> {
    #[cfg(windows)]
    {
        Ok(Box::new(MfH264Decoder::new()?))
    }
    #[cfg(not(windows))]
    {
        Err(Error::Decoder("no H.264 decoder on this platform".into()))
    }
}

/// End-to-end verification: drive the Media Foundation H.264 **encoder** to
/// produce a real annex-B bitstream, then decode it with [`MfH264Decoder`].
///
/// This is the only way to exercise the decode path without a host, and it
/// covers what unit tests cannot: MFT type negotiation against a real stream,
/// `MF_E_TRANSFORM_STREAM_CHANGE` renegotiation, the coded-vs-display
/// aperture crop, and NV12→RGBA on genuine decoder output.
#[cfg(all(test, windows))]
mod roundtrip {
    use super::mf::{ensure_mf_initialized, MfH264Decoder};
    use super::*;
    use std::mem::ManuallyDrop;
    use windows::Win32::Media::MediaFoundation::*;
    use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_INPROC_SERVER};

    const MF_E_TRANSFORM_NEED_MORE_INPUT_HR: windows::core::HRESULT =
        windows::core::HRESULT(0xC00D_6D72_u32 as i32);

    fn packed_u64(hi: u32, lo: u32) -> u64 {
        ((hi as u64) << 32) | lo as u64
    }

    /// Minimal H.264 encoder wrapper — test scaffolding only.
    struct TestEncoder {
        transform: IMFTransform,
        provides_samples: bool,
        out_bytes: u32,
    }

    impl TestEncoder {
        fn new(width: u32, height: u32, fps: u32, bitrate: u32) -> Result<Self> {
            ensure_mf_initialized()?;
            unsafe {
                let transform: IMFTransform =
                    CoCreateInstance(&CLSID_MSH264EncoderMFT, None, CLSCTX_INPROC_SERVER).map_err(
                        |e| Error::Encoder(format!("CoCreateInstance(H264 encoder): {e}")),
                    )?;

                // The MS encoder requires the OUTPUT type to be set first.
                let out = MFCreateMediaType().map_err(|e| Error::Encoder(e.to_string()))?;
                out.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)
                    .map_err(|e| Error::Encoder(e.to_string()))?;
                out.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_H264)
                    .map_err(|e| Error::Encoder(e.to_string()))?;
                out.SetUINT32(&MF_MT_AVG_BITRATE, bitrate)
                    .map_err(|e| Error::Encoder(e.to_string()))?;
                out.SetUINT64(&MF_MT_FRAME_SIZE, packed_u64(width, height))
                    .map_err(|e| Error::Encoder(e.to_string()))?;
                out.SetUINT64(&MF_MT_FRAME_RATE, packed_u64(fps, 1))
                    .map_err(|e| Error::Encoder(e.to_string()))?;
                out.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)
                    .map_err(|e| Error::Encoder(e.to_string()))?;
                out.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, packed_u64(1, 1))
                    .map_err(|e| Error::Encoder(e.to_string()))?;
                transform
                    .SetOutputType(0, &out, 0)
                    .map_err(|e| Error::Encoder(format!("encoder SetOutputType: {e}")))?;

                let inp = MFCreateMediaType().map_err(|e| Error::Encoder(e.to_string()))?;
                inp.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)
                    .map_err(|e| Error::Encoder(e.to_string()))?;
                inp.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_NV12)
                    .map_err(|e| Error::Encoder(e.to_string()))?;
                inp.SetUINT64(&MF_MT_FRAME_SIZE, packed_u64(width, height))
                    .map_err(|e| Error::Encoder(e.to_string()))?;
                inp.SetUINT64(&MF_MT_FRAME_RATE, packed_u64(fps, 1))
                    .map_err(|e| Error::Encoder(e.to_string()))?;
                inp.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)
                    .map_err(|e| Error::Encoder(e.to_string()))?;
                inp.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, packed_u64(1, 1))
                    .map_err(|e| Error::Encoder(e.to_string()))?;
                transform
                    .SetInputType(0, &inp, 0)
                    .map_err(|e| Error::Encoder(format!("encoder SetInputType: {e}")))?;

                let info = transform
                    .GetOutputStreamInfo(0)
                    .map_err(|e| Error::Encoder(format!("encoder stream info: {e}")))?;
                let provides = MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 as u32
                    | MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES.0 as u32;

                transform
                    .ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)
                    .map_err(|e| Error::Encoder(e.to_string()))?;
                transform
                    .ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)
                    .map_err(|e| Error::Encoder(e.to_string()))?;

                Ok(Self {
                    transform,
                    provides_samples: info.dwFlags & provides != 0,
                    out_bytes: info.cbSize.max(width * height * 2),
                })
            }
        }

        /// Feed one NV12 frame; return any encoded frames it produced.
        fn encode(&mut self, nv12: &[u8], index: u32, fps: u32) -> Result<Vec<EncodedFrame>> {
            let duration = 10_000_000i64 / fps as i64;
            unsafe {
                let buffer = MFCreateMemoryBuffer(nv12.len() as u32)
                    .map_err(|e| Error::Encoder(e.to_string()))?;
                let mut ptr: *mut u8 = std::ptr::null_mut();
                buffer
                    .Lock(&mut ptr, None, None)
                    .map_err(|e| Error::Encoder(e.to_string()))?;
                std::ptr::copy_nonoverlapping(nv12.as_ptr(), ptr, nv12.len());
                let _ = buffer.Unlock();
                buffer
                    .SetCurrentLength(nv12.len() as u32)
                    .map_err(|e| Error::Encoder(e.to_string()))?;

                let sample = MFCreateSample().map_err(|e| Error::Encoder(e.to_string()))?;
                sample
                    .AddBuffer(&buffer)
                    .map_err(|e| Error::Encoder(e.to_string()))?;
                sample
                    .SetSampleTime(index as i64 * duration)
                    .map_err(|e| Error::Encoder(e.to_string()))?;
                sample
                    .SetSampleDuration(duration)
                    .map_err(|e| Error::Encoder(e.to_string()))?;

                self.transform
                    .ProcessInput(0, &sample, 0)
                    .map_err(|e| Error::Encoder(format!("encoder ProcessInput: {e}")))?;
                self.drain(index)
            }
        }

        unsafe fn drain(&mut self, index: u32) -> Result<Vec<EncodedFrame>> {
            let mut out = Vec::new();
            loop {
                let supplied = if self.provides_samples {
                    None
                } else {
                    let buffer = MFCreateMemoryBuffer(self.out_bytes)
                        .map_err(|e| Error::Encoder(e.to_string()))?;
                    let sample = MFCreateSample().map_err(|e| Error::Encoder(e.to_string()))?;
                    sample
                        .AddBuffer(&buffer)
                        .map_err(|e| Error::Encoder(e.to_string()))?;
                    Some(sample)
                };
                let mut buffers = [MFT_OUTPUT_DATA_BUFFER {
                    dwStreamID: 0,
                    pSample: ManuallyDrop::new(supplied),
                    dwStatus: 0,
                    pEvents: ManuallyDrop::new(None),
                }];
                let mut status = 0u32;
                let result = self.transform.ProcessOutput(0, &mut buffers, &mut status);
                let produced = ManuallyDrop::take(&mut buffers[0].pSample);
                drop(ManuallyDrop::take(&mut buffers[0].pEvents));

                match result {
                    Ok(()) => {
                        if let Some(sample) = produced {
                            let buffer = sample
                                .ConvertToContiguousBuffer()
                                .map_err(|e| Error::Encoder(e.to_string()))?;
                            let mut ptr: *mut u8 = std::ptr::null_mut();
                            let mut len = 0u32;
                            buffer
                                .Lock(&mut ptr, None, Some(&mut len))
                                .map_err(|e| Error::Encoder(e.to_string()))?;
                            let data = std::slice::from_raw_parts(ptr, len as usize).to_vec();
                            let _ = buffer.Unlock();
                            if !data.is_empty() {
                                // Annex-B IDR NAL (type 5) or SPS (type 7) marks a keyframe.
                                let keyframe = has_keyframe_nal(&data);
                                out.push(EncodedFrame {
                                    frame_id: index,
                                    keyframe,
                                    timestamp_ms: index * 33,
                                    data,
                                });
                            }
                        }
                    }
                    Err(e) if e.code() == MF_E_TRANSFORM_NEED_MORE_INPUT_HR => break,
                    Err(e) if e.code() == MF_E_TRANSFORM_STREAM_CHANGE => {
                        drop(produced);
                        // Encoder renegotiating its output; accept and retry.
                        let ty = self
                            .transform
                            .GetOutputAvailableType(0, 0)
                            .map_err(|e| Error::Encoder(e.to_string()))?;
                        self.transform
                            .SetOutputType(0, &ty, 0)
                            .map_err(|e| Error::Encoder(e.to_string()))?;
                        continue;
                    }
                    Err(e) => {
                        drop(produced);
                        return Err(Error::Encoder(format!("encoder ProcessOutput: {e}")));
                    }
                }
            }
            Ok(out)
        }
    }

    /// Scan annex-B start codes for an SPS (7) or IDR (5) NAL.
    fn has_keyframe_nal(data: &[u8]) -> bool {
        let mut i = 0;
        while i + 3 < data.len() {
            let start = if data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1 {
                Some(i + 3)
            } else if i + 4 < data.len()
                && data[i] == 0
                && data[i + 1] == 0
                && data[i + 2] == 0
                && data[i + 3] == 1
            {
                Some(i + 4)
            } else {
                None
            };
            if let Some(s) = start {
                let nal_type = data[s] & 0x1F;
                if nal_type == 5 || nal_type == 7 {
                    return true;
                }
                i = s;
            } else {
                i += 1;
            }
        }
        false
    }

    /// Left half Rec.709 red, right half Rec.709 blue.
    fn nv12_split_pattern(width: usize, height: usize) -> Vec<u8> {
        const RED: (u8, u8, u8) = (63, 102, 240);
        const BLUE: (u8, u8, u8) = (32, 240, 118);
        let mut plane = vec![0u8; width * height * 3 / 2];
        let (y_plane, uv_plane) = plane.split_at_mut(width * height);
        for row in 0..height {
            for col in 0..width {
                let (y, _, _) = if col < width / 2 { RED } else { BLUE };
                y_plane[row * width + col] = y;
            }
        }
        for row in 0..height / 2 {
            for pair in 0..width / 2 {
                let col = pair * 2;
                let (_, u, v) = if col < width / 2 { RED } else { BLUE };
                uv_plane[row * width + col] = u;
                uv_plane[row * width + col + 1] = v;
            }
        }
        plane
    }

    fn mean_rgb(
        rgba: &[u8],
        width: usize,
        x0: usize,
        x1: usize,
        y0: usize,
        y1: usize,
    ) -> (f64, f64, f64) {
        let (mut r, mut g, mut b, mut n) = (0f64, 0f64, 0f64, 0f64);
        for y in y0..y1 {
            for x in x0..x1 {
                let i = (y * width + x) * 4;
                r += rgba[i] as f64;
                g += rgba[i + 1] as f64;
                b += rgba[i + 2] as f64;
                n += 1.0;
            }
        }
        (r / n, g / n, b / n)
    }

    /// 640x360 is deliberately NOT a multiple of 16 vertically, so the encoder
    /// codes 368 rows and signals a 360-row display aperture — exercising the
    /// same crop path that turns 1088 into 1080 at 1080p.
    #[test]
    fn encode_then_decode_recovers_the_picture() {
        const W: usize = 640;
        const H: usize = 360;
        const FPS: u32 = 30;

        let mut encoder = match TestEncoder::new(W as u32, H as u32, FPS, 4_000_000) {
            Ok(e) => e,
            Err(e) => {
                // No H.264 encoder on this machine: skip rather than fail.
                eprintln!("SKIP: MF H.264 encoder unavailable: {e}");
                return;
            }
        };
        let mut decoder = MfH264Decoder::new().expect("decoder must initialize");

        let nv12 = nv12_split_pattern(W, H);
        let mut decoded: Vec<RawFrame> = Vec::new();
        for index in 0..30u32 {
            let encoded = encoder.encode(&nv12, index, FPS).expect("encode");
            for frame in encoded {
                decoded.extend(decoder.decode(&frame).expect("decode"));
            }
            if !decoded.is_empty() {
                break;
            }
        }

        let frame = decoded
            .first()
            .expect("decoder produced no frames from a real H.264 stream");

        // Prove the aperture crop actually did something: H.264 codes in 16-row
        // macroblocks, so 360 rows must be carried as 368 coded rows.
        let fmt = decoder.format().expect("output format negotiated");
        eprintln!(
            "round-trip: coded {}x{}, display {}x{}, stride {}",
            fmt.coded_w, fmt.coded_h, fmt.disp_w, fmt.disp_h, fmt.stride
        );
        assert_eq!(
            fmt.disp_h, H as u32,
            "display height must be the real picture height"
        );
        assert!(
            fmt.coded_h > fmt.disp_h,
            "coded {} should exceed display {}",
            fmt.coded_h,
            fmt.disp_h
        );

        // Geometry: display size, not coded size.
        assert_eq!(
            (frame.width, frame.height),
            (W as u32, H as u32),
            "cropped to display aperture"
        );
        assert_eq!(frame.format, PixelFormat::Rgba8);
        assert_eq!(frame.data.len(), W * H * 4);
        assert!(
            frame.data.chunks_exact(4).all(|p| p[3] == 255),
            "alpha must be opaque"
        );

        // Content: left half red, right half blue, sampled away from the edges
        // so codec ringing at the boundary cannot muddy the result.
        let (lr, lg, lb) = mean_rgb(&frame.data, W, 20, W / 2 - 20, 20, H - 20);
        let (rr, rg, rb) = mean_rgb(&frame.data, W, W / 2 + 20, W - 20, 20, H - 20);
        assert!(
            lr > 180.0 && lg < 70.0 && lb < 70.0,
            "left half should be red, got ({lr:.0},{lg:.0},{lb:.0})"
        );
        assert!(
            rb > 180.0 && rr < 70.0 && rg < 70.0,
            "right half should be blue, got ({rr:.0},{rg:.0},{rb:.0})"
        );

        // The last-mile invariant: flush must demand a fresh keyframe.
        decoder.flush();
        let dummy = EncodedFrame {
            frame_id: 999,
            keyframe: false,
            timestamp_ms: 0,
            data: vec![0, 0, 0, 1, 0x41],
        };
        assert!(
            decoder.decode(&dummy).unwrap().is_empty(),
            "must wait for a keyframe after flush"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build NV12 planes from a per-pixel (Y, U, V) function, with padding so
    /// the stride path is exercised (real MF output is always padded).
    fn synth_nv12(
        width: usize,
        height: usize,
        stride: usize,
        f: impl Fn(usize, usize) -> (u8, u8, u8),
    ) -> (Vec<u8>, Vec<u8>) {
        let mut y = vec![0u8; stride * height];
        let mut uv = vec![0u8; stride * height.div_ceil(2)];
        for row in 0..height {
            for col in 0..width {
                let (yy, u, v) = f(col, row);
                y[row * stride + col] = yy;
                if row % 2 == 0 && col % 2 == 0 {
                    uv[(row / 2) * stride + col] = u;
                    uv[(row / 2) * stride + col + 1] = v;
                }
            }
        }
        (y, uv)
    }

    fn px(rgba: &[u8], width: usize, x: usize, y: usize) -> (u8, u8, u8, u8) {
        let i = (y * width + x) * 4;
        (rgba[i], rgba[i + 1], rgba[i + 2], rgba[i + 3])
    }

    #[test]
    fn black_and_white_hit_the_limited_range_endpoints() {
        // Y=16 is studio black, Y=235 is studio white; chroma neutral at 128.
        let (y, uv) = synth_nv12(4, 4, 8, |x, _| {
            if x < 2 {
                (16, 128, 128)
            } else {
                (235, 128, 128)
            }
        });
        let rgba = nv12_to_rgba(&y, &uv, 4, 4, 8).unwrap();
        assert_eq!(px(&rgba, 4, 0, 0), (0, 0, 0, 255), "studio black → 0");
        assert_eq!(
            px(&rgba, 4, 3, 0),
            (255, 255, 255, 255),
            "studio white → 255"
        );
    }

    #[test]
    fn primaries_land_where_bt709_says() {
        /// (Y, U, V) input and the (R, G, B) it must produce.
        type Case = ((u8, u8, u8), (u8, u8, u8));
        // Rec.709 limited-range encodings of pure red / green / blue.
        let cases: [Case; 3] = [
            ((63, 102, 240), (255, 0, 0)),
            ((173, 42, 26), (0, 255, 0)),
            ((32, 240, 118), (0, 0, 255)),
        ];
        for ((yv, u, v), (er, eg, eb)) in cases {
            let (y, uv) = synth_nv12(2, 2, 4, |_, _| (yv, u, v));
            let rgba = nv12_to_rgba(&y, &uv, 2, 2, 4).unwrap();
            let (r, g, b, a) = px(&rgba, 2, 0, 0);
            assert_eq!(a, 255);
            let close = |got: u8, want: u8| got.abs_diff(want) <= 6;
            assert!(
                close(r, er) && close(g, eg) && close(b, eb),
                "Y{yv} U{u} V{v} → ({r},{g},{b}), expected ~({er},{eg},{eb})"
            );
        }
    }

    #[test]
    fn grey_ramp_is_monotonic_and_neutral() {
        let (y, uv) = synth_nv12(16, 2, 32, |x, _| ((16 + x * 13) as u8, 128, 128));
        let rgba = nv12_to_rgba(&y, &uv, 16, 2, 32).unwrap();
        let mut prev = 0u8;
        for x in 0..16 {
            let (r, g, b, _) = px(&rgba, 16, x, 0);
            assert_eq!((r, g), (r, b), "neutral chroma must stay grey at x={x}");
            assert_eq!(r, g, "neutral chroma must stay grey at x={x}");
            assert!(r >= prev, "ramp must be monotonic at x={x}: {r} < {prev}");
            prev = r;
        }
        assert!(prev > 200, "ramp should reach near-white, got {prev}");
    }

    #[test]
    fn stride_padding_is_skipped() {
        // Poison the padding: if the converter reads it, colours change.
        let width = 4;
        let height = 4;
        let stride = 16;
        let (mut y, mut uv) = synth_nv12(width, height, stride, |_, _| (235, 128, 128));
        for row in 0..height {
            for col in width..stride {
                y[row * stride + col] = 0xFF;
            }
        }
        for row in 0..height / 2 {
            for col in width..stride {
                uv[row * stride + col] = 0x00;
            }
        }
        let rgba = nv12_to_rgba(&y, &uv, width, height, stride).unwrap();
        for x in 0..width {
            for row in 0..height {
                assert_eq!(px(&rgba, width, x, row), (255, 255, 255, 255));
            }
        }
    }

    #[test]
    fn crops_1088_coded_height_to_1080_display() {
        // Exactly the 1080p case: coded plane is 1088 tall, we render 1080.
        let stride = 1920;
        let coded_h = 1088;
        let (y, uv) = synth_nv12(1920, coded_h, stride, |_, row| {
            if row < 1080 {
                (235, 128, 128)
            } else {
                (16, 128, 128) // padding rows must never be shown
            }
        });
        let rgba = nv12_to_rgba(&y, &uv, 1920, 1080, stride).unwrap();
        assert_eq!(rgba.len(), 1920 * 1080 * 4);
        assert_eq!(
            px(&rgba, 1920, 0, 1079),
            (255, 255, 255, 255),
            "last visible row"
        );
    }

    /// The Q8 integer matrix as it was before bilinear upsampling — the
    /// reference for "a whole-numbered chroma sample must convert exactly".
    fn ref_rgb(yv: u8, u: i32, v: i32) -> (u8, u8, u8) {
        let luma = 298 * (yv as i32 - 16);
        let (d, e) = (u - 128, v - 128);
        (
            clamp_u8((luma + 459 * e + 128) >> 8),
            clamp_u8((luma - 55 * d - 136 * e + 128) >> 8),
            clamp_u8((luma + 541 * d + 128) >> 8),
        )
    }

    #[test]
    fn uniform_chroma_is_bit_identical_to_the_unfiltered_matrix() {
        // Interpolating a constant field returns the constant, so a flat image
        // must round-trip to exactly the same RGB as the old nearest code.
        for (yv, u, v) in [
            (16u8, 128i32, 128i32),
            (235, 128, 128),
            (63, 102, 240),
            (173, 42, 26),
            (32, 240, 118),
            (128, 200, 60),
        ] {
            let (y, uv) = synth_nv12(6, 6, 16, |_, _| (yv, u as u8, v as u8));
            let rgba = nv12_to_rgba(&y, &uv, 6, 6, 16).unwrap();
            let want = ref_rgb(yv, u, v);
            for row in 0..6 {
                for col in 0..6 {
                    let (r, g, b, a) = px(&rgba, 6, col, row);
                    assert_eq!((r, g, b), want, "({col},{row}) Y{yv} U{u} V{v}");
                    assert_eq!(a, 255);
                }
            }
        }
    }

    #[test]
    fn horizontal_chroma_is_left_sited_and_bilinear() {
        // Chroma columns k = 0..3 cover x = 0,2,4,6. V steps 128 -> 240 at k=2.
        // Expected V per luma column: co-sited on even, midpoint on odd.
        let width = 8;
        let (y, uv) = synth_nv12(width, 2, 16, |x, _| {
            if x < 4 {
                (128, 128, 128)
            } else {
                (128, 128, 240)
            }
        });
        let rgba = nv12_to_rgba(&y, &uv, width, 2, 16).unwrap();
        // k:      0    0/1  1    1/2  2    2/3  3    3/clamp
        let want_v = [128, 128, 128, 184, 240, 240, 240, 240];
        for (col, v) in want_v.into_iter().enumerate() {
            let (r, g, b, _) = px(&rgba, width, col, 0);
            assert_eq!((r, g, b), ref_rgb(128, 128, v), "column {col}");
        }
    }

    #[test]
    fn a_sharp_chroma_edge_gets_an_intermediate_column() {
        // The improvement: the old nearest code produced a hard 2px step with
        // no transitional sample. Column 3 must now sit strictly between its
        // neighbours instead of matching column 2 exactly.
        let (y, uv) = synth_nv12(8, 2, 16, |x, _| {
            if x < 4 {
                (128, 128, 128)
            } else {
                (128, 128, 240)
            }
        });
        let rgba = nv12_to_rgba(&y, &uv, 8, 2, 16).unwrap();
        let r_at = |x| px(&rgba, 8, x, 0).0;
        let (flat, mid, full) = (r_at(2), r_at(3), r_at(4));
        assert!(
            flat < mid && mid < full,
            "expected an intermediate boundary column, got {flat} < {mid} < {full}"
        );
    }

    #[test]
    fn vertical_chroma_uses_quarter_weights_and_clamps_at_the_edges() {
        // Chroma rows j = 0,1 sit midway between luma rows (0,1) and (2,3).
        // V steps 128 -> 240 at j=1.
        let (y, uv) = synth_nv12(2, 4, 8, |_, row| {
            if row < 2 {
                (128, 128, 128)
            } else {
                (128, 128, 240)
            }
        });
        let rgba = nv12_to_rgba(&y, &uv, 2, 4, 8).unwrap();
        // row0: clamped to C0 -> 128        row1: .75*C0 + .25*C1 -> 156
        // row2: .75*C1 + .25*C0 -> 212      row3: clamped to C1 -> 240
        let want_v = [128, 156, 212, 240];
        for (row, v) in want_v.into_iter().enumerate() {
            for col in 0..2 {
                let (r, g, b, _) = px(&rgba, 2, col, row);
                assert_eq!((r, g, b), ref_rgb(128, 128, v), "({col},{row})");
            }
        }
    }

    #[test]
    fn odd_dimensions_clamp_instead_of_reading_out_of_bounds() {
        // 5x3: the trailing luma column/row have no right/bottom chroma
        // neighbour, so the blend must degenerate to the edge sample.
        let (y, uv) = synth_nv12(5, 3, 8, |x, _| {
            if x < 2 {
                (128, 128, 128)
            } else {
                (128, 128, 240)
            }
        });
        let rgba = nv12_to_rgba(&y, &uv, 5, 3, 8).unwrap();
        assert_eq!(rgba.len(), 5 * 3 * 4);
        for row in 0..3 {
            // Column 4 is co-sited with the last chroma sample (k=2).
            let (r, g, b, _) = px(&rgba, 5, 4, row);
            assert_eq!((r, g, b), ref_rgb(128, 128, 240), "row {row}");
        }
    }

    #[test]
    fn rejects_impossible_geometry() {
        let (y, uv) = synth_nv12(4, 4, 4, |_, _| (16, 128, 128));
        assert!(nv12_to_rgba(&y, &uv, 0, 4, 4).is_err(), "zero width");
        assert!(nv12_to_rgba(&y, &uv, 8, 4, 4).is_err(), "stride < width");
        assert!(
            nv12_to_rgba(&y, &uv, 4, 64, 4).is_err(),
            "Y plane too small"
        );
        assert!(
            nv12_to_rgba(&y, &[], 4, 4, 4).is_err(),
            "UV plane too small"
        );
    }

    #[test]
    fn output_is_exactly_display_sized_rgba() {
        let (y, uv) = synth_nv12(6, 4, 8, |_, _| (128, 128, 128));
        let rgba = nv12_to_rgba(&y, &uv, 6, 4, 8).unwrap();
        assert_eq!(rgba.len(), 6 * 4 * 4);
        assert!(
            rgba.chunks_exact(4).all(|p| p[3] == 255),
            "alpha must be opaque"
        );
    }
}
