//! Media Foundation H.264 encoder.
//!
//! Selection order, most to least desirable:
//!
//! 1. Hardware async MFT **on the capture adapter's LUID** (`MFT_ENUM_ADAPTER_LUID`).
//!    On a hybrid laptop the desktop texture lives on whichever GPU drives the
//!    panel; encoding it on the *other* GPU would force a cross-adapter copy or
//!    simply fail, so the LUID match is the whole point.
//! 2. Hardware async MFT on any adapter (cross-adapter copy via CPU NV12).
//! 3. Media Foundation's software H.264 encoder — [`MfH264Encoder::describe`]
//!    says so plainly.
//!
//! Async MFTs are driven the documented way: `METransformNeedInput` grants one
//! `ProcessInput`, `METransformHaveOutput` grants one `ProcessOutput`. Sync
//! (software) MFTs use the classic feed-then-drain loop. Both produce Annex-B
//! output; if a driver hands back length-prefixed NALs we convert, and we splice
//! in SPS/PPS on IDRs that lack them so a decoder can start from any keyframe.

use std::collections::VecDeque;
use std::mem::ManuallyDrop;
use std::time::{Duration, Instant};

use directdesk_shared::traits::{Encoder, PixelFormat, RawFrame};
use directdesk_shared::video::EncodedFrame;
use directdesk_shared::{Error, Result};
use windows::core::{Interface, GUID};
use windows::Win32::Foundation::{VARIANT_BOOL, VARIANT_TRUE};
use windows::Win32::Graphics::Direct3D11::{ID3D11Device, ID3D11Texture2D};
use windows::Win32::Media::MediaFoundation::*;
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::Variant::{VARIANT, VT_BOOL, VT_UI4};

/// What the encoder is actually running on. Reported honestly by `describe()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncoderPath {
    /// Hardware MFT on the same adapter as the capture texture.
    HardwareSameAdapter,
    /// Hardware MFT, but on a different adapter than the capture texture.
    HardwareOtherAdapter,
    /// Media Foundation software encoder.
    Software,
}

impl EncoderPath {
    pub fn label(&self) -> &'static str {
        match self {
            EncoderPath::HardwareSameAdapter => "HW (capture adapter)",
            EncoderPath::HardwareOtherAdapter => "HW (different adapter)",
            EncoderPath::Software => "SOFTWARE (no hardware MFT found)",
        }
    }

    pub fn is_hardware(&self) -> bool {
        !matches!(self, EncoderPath::Software)
    }
}

#[derive(Debug, Clone)]
pub struct EncoderConfig {
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub bitrate_kbps: u32,
    /// Keyframe interval in seconds. Long GOP + on-demand IDR is the low-latency
    /// remote-desktop pattern: keyframes cost bandwidth, so only send them when
    /// the receiver actually needs one.
    pub gop_seconds: u32,
    /// LUID of the adapter the capture texture lives on, if known.
    pub adapter_luid: Option<u64>,
    /// PCI vendor ID of that adapter (0x8086 Intel, 0x10DE NVIDIA, 0x1002 AMD).
    pub adapter_vendor_id: Option<u32>,
    pub adapter_name: String,
}

impl Default for EncoderConfig {
    fn default() -> Self {
        Self {
            width: 1920,
            height: 1080,
            fps: 60,
            bitrate_kbps: 12_000,
            gop_seconds: 4,
            adapter_luid: None,
            adapter_vendor_id: None,
            adapter_name: String::new(),
        }
    }
}

/// One frame of encoder input.
pub enum FrameInput<'a> {
    /// GPU-resident NV12 texture on the encoder's D3D11 device.
    Texture(&'a ID3D11Texture2D),
    /// Tightly-packed CPU NV12 (`w * h` luma then `w * h / 2` interleaved chroma).
    Nv12(&'a [u8]),
}

pub struct MfH264Encoder {
    transform: IMFTransform,
    codec_api: Option<ICodecAPI>,
    events: Option<IMFMediaEventGenerator>,
    /// D3D device manager handed to the MFT. Must outlive the transform's use.
    _dxgi_manager: Option<IMFDXGIDeviceManager>,
    d3d_bound: bool,

    cfg: EncoderConfig,
    path: EncoderPath,
    friendly_name: String,

    /// Async MFT credits. `need_input` is decremented per `ProcessInput`.
    need_input: u32,
    have_output: u32,
    out_provides_samples: bool,
    out_buf_size: u32,

    queue: VecDeque<EncodedFrame>,
    frame_id: u32,
    last_hns: i64,
    force_key: bool,
    seq_header: Vec<u8>,
    warned_format: bool,
    started: bool,
    /// Scratch for the BGRA -> NV12 CPU path used by the `Encoder` trait impl.
    cpu_scratch: Vec<u8>,
    /// Frames refused because the MFT never granted an input credit in time.
    dropped_no_credit: u64,
    /// Total time blocked waiting for an input credit.
    waited_for_credit: Duration,
}

impl MfH264Encoder {
    /// Build an encoder. `device` is the D3D11 device the capture texture lives
    /// on; pass `None` for a pure CPU-input encoder.
    ///
    /// Every candidate MFT is tried in priority order. Vendor encoders can fail
    /// to activate or refuse a media type for reasons entirely outside our
    /// control (GPU asleep, driver session lost, encoder already in use), so a
    /// single failure demotes us to the next candidate rather than the whole
    /// pipeline.
    pub fn new(cfg: EncoderConfig, device: Option<&ID3D11Device>) -> Result<Self> {
        let candidates = candidate_mfts(&cfg)?;
        if candidates.is_empty() {
            return Err(Error::Encoder(
                "no H.264 encoder MFT of any kind is registered".into(),
            ));
        }
        let mut last_err = None;
        for (activate, path) in candidates {
            // SAFETY: `activate` came from MFTEnum2 and is a live IMFActivate.
            let name = unsafe { read_string(&activate, &MFT_FRIENDLY_NAME_Attribute) }
                .unwrap_or_else(|| "<unnamed MFT>".to_string());
            match Self::try_build(&activate, path, name.clone(), cfg.clone(), device) {
                Ok(me) => return Ok(me),
                Err(e) => {
                    tracing::warn!("encoder candidate \"{name}\" ({}) unusable: {e}", path.label());
                    // SAFETY: releases whatever the failed activation created.
                    unsafe {
                        let _ = activate.ShutdownObject();
                    }
                    last_err = Some(e);
                }
            }
        }
        Err(last_err
            .unwrap_or_else(|| Error::Encoder("no usable H.264 encoder MFT".into())))
    }

    fn try_build(
        activate: &IMFActivate,
        path: EncoderPath,
        friendly_name: String,
        cfg: EncoderConfig,
        device: Option<&ID3D11Device>,
    ) -> Result<Self> {
        // SAFETY: live IMFActivate; the transform is retained for our lifetime.
        let transform: IMFTransform = unsafe { activate.ActivateObject() }
            .map_err(|e| Error::Encoder(format!("ActivateObject: {e}")))?;

        let mut me = Self {
            transform,
            codec_api: None,
            events: None,
            _dxgi_manager: None,
            d3d_bound: false,
            cfg,
            path,
            friendly_name,
            need_input: 0,
            have_output: 0,
            out_provides_samples: false,
            out_buf_size: 0,
            queue: VecDeque::new(),
            frame_id: 0,
            last_hns: -1,
            force_key: false,
            seq_header: Vec::new(),
            warned_format: false,
            started: false,
            cpu_scratch: Vec::new(),
            dropped_no_credit: 0,
            waited_for_credit: Duration::ZERO,
        };

        me.unlock_async()?;
        if path.is_hardware() {
            if let Some(dev) = device {
                me.bind_d3d(dev);
            }
        }
        me.negotiate_types()?;
        me.apply_codec_settings();
        me.begin_streaming()?;

        tracing::info!(
            encoder = %me.friendly_name,
            path = me.path.label(),
            d3d = me.d3d_bound,
            "H.264 encoder ready ({}x{} @ {} fps, {} kbps)",
            me.cfg.width, me.cfg.height, me.cfg.fps, me.cfg.bitrate_kbps
        );
        Ok(me)
    }

    pub fn path(&self) -> EncoderPath {
        self.path
    }

    /// True when the MFT accepted a DXGI device manager, i.e. it can take GPU
    /// textures directly.
    pub fn accepts_textures(&self) -> bool {
        self.d3d_bound
    }

    pub fn friendly_name(&self) -> &str {
        &self.friendly_name
    }

    /// Frames the MFT refused because it never granted an input credit, and the
    /// total time spent waiting for one. Both should stay near zero; growth
    /// means the encoder is the pipeline bottleneck.
    pub fn backpressure(&self) -> (u64, Duration) {
        (self.dropped_no_credit, self.waited_for_credit)
    }

    /// Feed one frame and return an encoded frame if one is ready.
    ///
    /// Returns `Ok(None)` when the encoder is not ready for input (frame
    /// dropped, back-pressure) or has not produced output yet.
    pub fn submit(&mut self, input: FrameInput<'_>, timestamp_ms: u32) -> Result<Option<EncodedFrame>> {
        if self.force_key {
            self.set_codec_u32(&CODECAPI_AVEncVideoForceKeyFrame, 1, "ForceKeyFrame");
            self.force_key = false;
        }

        let sample = self.build_sample(input, timestamp_ms)?;

        if self.events.is_some() {
            self.submit_async(sample)?;
        } else {
            self.submit_sync(sample)?;
        }
        Ok(self.queue.pop_front())
    }

    /// Drain any already-produced output without submitting new input.
    pub fn poll_output(&mut self) -> Option<EncodedFrame> {
        if self.events.is_some() {
            self.pump_events();
            while self.have_output > 0 {
                self.have_output -= 1;
                match self.process_output() {
                    Ok(Some(f)) => self.queue.push_back(f),
                    Ok(None) => {}
                    Err(e) => tracing::warn!("ProcessOutput: {e}"),
                }
            }
        }
        self.queue.pop_front()
    }

    // ---- construction helpers -------------------------------------------------

    fn unlock_async(&mut self) -> Result<()> {
        // SAFETY: live transform; attribute store is owned by the MFT.
        let attrs = unsafe { self.transform.GetAttributes() };
        let Ok(attrs) = attrs else {
            // Sync MFTs may not expose attributes at all.
            return Ok(());
        };
        // SAFETY: plain attribute reads/writes with static GUID keys.
        unsafe {
            let is_async = attrs.GetUINT32(&MF_TRANSFORM_ASYNC).unwrap_or(0) == 1;
            if is_async {
                attrs
                    .SetUINT32(&MF_TRANSFORM_ASYNC_UNLOCK, 1)
                    .map_err(|e| Error::Encoder(format!("MF_TRANSFORM_ASYNC_UNLOCK: {e}")))?;
                self.events = Some(
                    self.transform
                        .cast::<IMFMediaEventGenerator>()
                        .map_err(|e| Error::Encoder(format!("async MFT without event generator: {e}")))?,
                );
            }
            let _ = attrs.SetUINT32(&MF_LOW_LATENCY, 1);
        }
        Ok(())
    }

    fn bind_d3d(&mut self, device: &ID3D11Device) {
        // SAFETY: manager and device outlive the transform; failures here are
        // non-fatal and fall back to the CPU-input path.
        unsafe {
            let attrs = self.transform.GetAttributes().ok();
            let aware = attrs
                .as_ref()
                .and_then(|a| a.GetUINT32(&MF_SA_D3D11_AWARE).ok())
                .unwrap_or(0);
            if aware == 0 {
                tracing::info!("MFT is not MF_SA_D3D11_AWARE; using CPU NV12 input");
                return;
            }
            let mut token = 0u32;
            let mut manager: Option<IMFDXGIDeviceManager> = None;
            if let Err(e) = MFCreateDXGIDeviceManager(&mut token, &mut manager) {
                tracing::warn!("MFCreateDXGIDeviceManager failed: {e}");
                return;
            }
            let Some(manager) = manager else { return };
            if let Err(e) = manager.ResetDevice(device, token) {
                tracing::warn!("IMFDXGIDeviceManager::ResetDevice failed: {e}");
                return;
            }
            let param = manager.as_raw() as usize;
            match self
                .transform
                .ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER, param)
            {
                Ok(()) => {
                    self._dxgi_manager = Some(manager);
                    self.d3d_bound = true;
                    tracing::info!("MFT bound to D3D11 device manager (GPU texture input)");
                }
                Err(e) => tracing::warn!("SET_D3D_MANAGER rejected ({e}); using CPU NV12 input"),
            }
        }
    }

    fn negotiate_types(&mut self) -> Result<()> {
        let bps = self.cfg.bitrate_kbps.saturating_mul(1000);
        // SAFETY: media types are freshly created; every setter takes static
        // GUID keys and plain scalars.
        unsafe {
            let out = MFCreateMediaType().map_err(enc_err("MFCreateMediaType(out)"))?;
            out.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video).ok();
            out.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_H264).ok();
            out.SetUINT32(&MF_MT_AVG_BITRATE, bps).ok();
            out.SetUINT64(&MF_MT_FRAME_SIZE, pack_2x32(self.cfg.width, self.cfg.height))
                .ok();
            out.SetUINT64(&MF_MT_FRAME_RATE, pack_2x32(self.cfg.fps, 1)).ok();
            out.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, pack_2x32(1, 1)).ok();
            out.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)
                .ok();
            out.SetUINT32(&MF_MT_MPEG2_PROFILE, eAVEncH264VProfile_Main.0 as u32)
                .ok();
            out.SetUINT32(
                &MF_MT_MAX_KEYFRAME_SPACING,
                self.cfg.fps.max(1) * self.cfg.gop_seconds.max(1),
            )
            .ok();
            out.SetUINT32(&MF_MT_ALL_SAMPLES_INDEPENDENT, 0).ok();

            // H.264 MFTs require the output type before the input type.
            self.transform
                .SetOutputType(0, &out, 0)
                .map_err(enc_err("SetOutputType(H264)"))?;

            let inp = MFCreateMediaType().map_err(enc_err("MFCreateMediaType(in)"))?;
            inp.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video).ok();
            inp.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_NV12).ok();
            inp.SetUINT64(&MF_MT_FRAME_SIZE, pack_2x32(self.cfg.width, self.cfg.height))
                .ok();
            inp.SetUINT64(&MF_MT_FRAME_RATE, pack_2x32(self.cfg.fps, 1)).ok();
            inp.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, pack_2x32(1, 1)).ok();
            inp.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)
                .ok();
            self.transform
                .SetInputType(0, &inp, 0)
                .map_err(enc_err("SetInputType(NV12)"))?;

            let info = self
                .transform
                .GetOutputStreamInfo(0)
                .map_err(enc_err("GetOutputStreamInfo"))?;
            let provides = MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 as u32
                | MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES.0 as u32;
            self.out_provides_samples = info.dwFlags & provides != 0;
            self.out_buf_size = info
                .cbSize
                .max(self.cfg.width * self.cfg.height); // generous floor
        }
        self.codec_api = self.transform.cast::<ICodecAPI>().ok();
        Ok(())
    }

    fn apply_codec_settings(&mut self) {
        self.set_codec_u32(
            &CODECAPI_AVEncCommonRateControlMode,
            eAVEncCommonRateControlMode_CBR.0 as u32,
            "RateControlMode=CBR",
        );
        self.set_codec_u32(
            &CODECAPI_AVEncCommonMeanBitRate,
            self.cfg.bitrate_kbps.saturating_mul(1000),
            "MeanBitRate",
        );
        self.set_codec_bool(&CODECAPI_AVLowLatencyMode, true, "LowLatencyMode");
        self.set_codec_u32(&CODECAPI_AVEncMPVDefaultBPictureCount, 0, "BPictureCount=0");
        self.set_codec_u32(
            &CODECAPI_AVEncMPVGOPSize,
            self.cfg.fps.max(1) * self.cfg.gop_seconds.max(1),
            "GOPSize",
        );
        // 0 = quality-biased, 100 = speed-biased. Remote desktop wants latency.
        self.set_codec_u32(&CODECAPI_AVEncCommonQualityVsSpeed, 33, "QualityVsSpeed");
    }

    fn begin_streaming(&mut self) -> Result<()> {
        // SAFETY: live transform; messages are the documented start sequence.
        unsafe {
            self.transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)
                .map_err(enc_err("NOTIFY_BEGIN_STREAMING"))?;
            self.transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)
                .map_err(enc_err("NOTIFY_START_OF_STREAM"))?;
        }
        self.started = true;
        Ok(())
    }

    // ---- submission -----------------------------------------------------------

    fn submit_async(&mut self, sample: IMFSample) -> Result<()> {
        // Give the MFT a brief window to grant an input credit. Hardware MFTs
        // raise METransformNeedInput within a frame time under normal load; if
        // none arrives the encoder is genuinely saturated and dropping is right.
        let started = Instant::now();
        let deadline = started + Duration::from_millis(12);
        loop {
            self.pump_events();
            // Draining output is what frees the encoder to ask for more input,
            // so do it inside the wait rather than only after.
            self.drain_outputs();
            if self.need_input > 0 || Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_micros(200));
        }
        self.waited_for_credit += started.elapsed();

        if self.need_input == 0 {
            // Encoder is saturated: drop this frame rather than build latency.
            self.dropped_no_credit += 1;
            self.drain_outputs();
            return Ok(());
        }
        self.need_input -= 1;
        // SAFETY: one ProcessInput per METransformNeedInput, as the async MFT
        // contract requires.
        unsafe {
            self.transform
                .ProcessInput(0, &sample, 0)
                .map_err(enc_err("ProcessInput"))?;
        }

        // Deliberately do NOT block waiting for this frame's output. A hardware
        // encoder is a pipeline; stalling until frame N emerges before capturing
        // N+1 throws away most of the throughput and adds latency rather than
        // removing it. Drain whatever is ready and let the caller's queue absorb
        // the one-or-two-frame depth.
        self.pump_events();
        self.drain_outputs();
        Ok(())
    }

    fn submit_sync(&mut self, sample: IMFSample) -> Result<()> {
        // SAFETY: sync MFT contract — feed one sample, then drain until the MFT
        // says it needs more input.
        unsafe {
            match self.transform.ProcessInput(0, &sample, 0) {
                Ok(()) => {}
                Err(e) if e.code() == MF_E_NOTACCEPTING => {}
                Err(e) => return Err(Error::Encoder(format!("ProcessInput: {e}"))),
            }
        }
        loop {
            match self.process_output() {
                Ok(Some(f)) => self.queue.push_back(f),
                Ok(None) => break,
                Err(e) => {
                    tracing::warn!("ProcessOutput: {e}");
                    break;
                }
            }
        }
        Ok(())
    }

    fn drain_outputs(&mut self) {
        while self.have_output > 0 {
            self.have_output -= 1;
            match self.process_output() {
                Ok(Some(f)) => self.queue.push_back(f),
                Ok(None) => {}
                Err(e) => tracing::warn!("ProcessOutput: {e}"),
            }
        }
    }

    fn pump_events(&mut self) {
        let Some(gen) = self.events.clone() else { return };
        loop {
            // SAFETY: NO_WAIT never blocks; errors mean "queue empty".
            let ev = unsafe { gen.GetEvent(MF_EVENT_FLAG_NO_WAIT) };
            let Ok(ev) = ev else { return };
            // SAFETY: live event object.
            let kind = unsafe { ev.GetType() }.unwrap_or(0);
            match kind as i32 {
                x if x == METransformNeedInput.0 => self.need_input += 1,
                x if x == METransformHaveOutput.0 => self.have_output += 1,
                x if x == METransformDrainComplete.0 => {}
                x if x == MEError.0 => {
                    // SAFETY: live event object.
                    let st = unsafe { ev.GetStatus() };
                    tracing::warn!("MFT reported MEError: {st:?}");
                }
                _ => {}
            }
        }
    }

    fn process_output(&mut self) -> Result<Option<EncodedFrame>> {
        let mut bufs = [MFT_OUTPUT_DATA_BUFFER {
            dwStreamID: 0,
            ..Default::default()
        }];

        // SAFETY: when the MFT does not allocate, we supply a sample whose
        // buffer is large enough for `cbSize`; the ManuallyDrop fields are
        // taken exactly once below so refcounts stay balanced.
        unsafe {
            if !self.out_provides_samples {
                let sample = MFCreateSample().map_err(enc_err("MFCreateSample(out)"))?;
                let buf = MFCreateMemoryBuffer(self.out_buf_size.max(4096))
                    .map_err(enc_err("MFCreateMemoryBuffer(out)"))?;
                sample.AddBuffer(&buf).map_err(enc_err("AddBuffer(out)"))?;
                bufs[0].pSample = ManuallyDrop::new(Some(sample));
            }

            let mut status = 0u32;
            let res = self.transform.ProcessOutput(0, &mut bufs, &mut status);
            let sample = ManuallyDrop::take(&mut bufs[0].pSample);
            let events = ManuallyDrop::take(&mut bufs[0].pEvents);
            drop(events);

            match res {
                Ok(()) => {}
                Err(e) if e.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => return Ok(None),
                Err(e) if e.code() == MF_E_TRANSFORM_STREAM_CHANGE => {
                    self.renegotiate_output()?;
                    return Ok(None);
                }
                Err(e) => return Err(Error::Encoder(format!("ProcessOutput: {e}"))),
            }

            let Some(sample) = sample else { return Ok(None) };
            let keyframe = sample.GetUINT32(&MFSampleExtension_CleanPoint).unwrap_or(0) == 1;
            let ts_hns = sample.GetSampleTime().unwrap_or(0);

            let buffer = sample
                .ConvertToContiguousBuffer()
                .map_err(enc_err("ConvertToContiguousBuffer"))?;
            let mut ptr: *mut u8 = std::ptr::null_mut();
            let mut len = 0u32;
            buffer
                .Lock(&mut ptr, None, Some(&mut len))
                .map_err(enc_err("IMFMediaBuffer::Lock"))?;
            let raw = std::slice::from_raw_parts(ptr, len as usize).to_vec();
            let _ = buffer.Unlock();

            if raw.is_empty() {
                return Ok(None);
            }

            if keyframe && self.seq_header.is_empty() {
                self.fetch_sequence_header();
            }
            let data = self.normalize_bitstream(raw, keyframe);
            self.frame_id = self.frame_id.wrapping_add(1);
            Ok(Some(EncodedFrame {
                frame_id: self.frame_id,
                keyframe,
                timestamp_ms: (ts_hns / 10_000) as u32,
                data,
            }))
        }
    }

    fn renegotiate_output(&mut self) -> Result<()> {
        // SAFETY: live transform; we adopt the MFT's own preferred output type.
        unsafe {
            let t = self
                .transform
                .GetOutputAvailableType(0, 0)
                .map_err(enc_err("GetOutputAvailableType"))?;
            self.transform
                .SetOutputType(0, &t, 0)
                .map_err(enc_err("SetOutputType(renegotiate)"))?;
        }
        self.seq_header.clear();
        Ok(())
    }

    fn fetch_sequence_header(&mut self) {
        // SAFETY: live transform; blob size is queried before the read.
        unsafe {
            let Ok(t) = self.transform.GetOutputCurrentType(0) else { return };
            let Ok(size) = t.GetBlobSize(&MF_MT_MPEG_SEQUENCE_HEADER) else { return };
            if size == 0 {
                return;
            }
            let mut buf = vec![0u8; size as usize];
            if t.GetBlob(&MF_MT_MPEG_SEQUENCE_HEADER, &mut buf, None).is_ok() {
                tracing::debug!("captured {} byte H.264 sequence header", buf.len());
                self.seq_header = buf;
            }
        }
    }

    fn normalize_bitstream(&mut self, raw: Vec<u8>, keyframe: bool) -> Vec<u8> {
        let annexb = if starts_with_start_code(&raw) {
            raw
        } else if let Some(converted) = avcc_to_annexb(&raw) {
            if !self.warned_format {
                self.warned_format = true;
                tracing::info!("encoder emits length-prefixed NALs; converting to Annex-B");
            }
            converted
        } else {
            if !self.warned_format {
                self.warned_format = true;
                tracing::warn!("encoder output is neither Annex-B nor AVCC; passing through");
            }
            raw
        };

        if keyframe && !self.seq_header.is_empty() && !contains_nal(&annexb, 7) {
            let mut out = Vec::with_capacity(self.seq_header.len() + annexb.len());
            out.extend_from_slice(&self.seq_header);
            out.extend_from_slice(&annexb);
            return out;
        }
        annexb
    }

    fn build_sample(&mut self, input: FrameInput<'_>, timestamp_ms: u32) -> Result<IMFSample> {
        // SAFETY: all MF object creation with checked results; buffer lengths
        // are set to exactly what we wrote.
        unsafe {
            let sample = MFCreateSample().map_err(enc_err("MFCreateSample(in)"))?;
            match input {
                FrameInput::Texture(tex) => {
                    if !self.d3d_bound {
                        return Err(Error::Encoder(
                            "texture input requested but MFT has no D3D manager".into(),
                        ));
                    }
                    let buf = MFCreateDXGISurfaceBuffer(&ID3D11Texture2D::IID, tex, 0, false)
                        .map_err(enc_err("MFCreateDXGISurfaceBuffer"))?;
                    if let Ok(two_d) = buf.cast::<IMF2DBuffer>() {
                        if let Ok(len) = two_d.GetContiguousLength() {
                            let _ = buf.SetCurrentLength(len);
                        }
                    }
                    sample.AddBuffer(&buf).map_err(enc_err("AddBuffer(dxgi)"))?;
                }
                FrameInput::Nv12(bytes) => {
                    let want = crate::convert::nv12_len(self.cfg.width, self.cfg.height);
                    if bytes.len() < want {
                        return Err(Error::Encoder(format!(
                            "NV12 buffer is {} bytes, need {want}",
                            bytes.len()
                        )));
                    }
                    let buf = MFCreateMemoryBuffer(want as u32)
                        .map_err(enc_err("MFCreateMemoryBuffer(in)"))?;
                    let mut ptr: *mut u8 = std::ptr::null_mut();
                    buf.Lock(&mut ptr, None, None)
                        .map_err(enc_err("Lock(in buffer)"))?;
                    std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, want);
                    let _ = buf.Unlock();
                    buf.SetCurrentLength(want as u32)
                        .map_err(enc_err("SetCurrentLength(in)"))?;
                    sample.AddBuffer(&buf).map_err(enc_err("AddBuffer(cpu)"))?;
                }
            }

            // Sample times must be strictly increasing or rate control misbehaves.
            let mut hns = timestamp_ms as i64 * 10_000;
            if hns <= self.last_hns {
                hns = self.last_hns + 1;
            }
            self.last_hns = hns;
            let _ = sample.SetSampleTime(hns);
            let _ = sample.SetSampleDuration(10_000_000 / self.cfg.fps.max(1) as i64);
            Ok(sample)
        }
    }

    fn set_codec_u32(&self, key: &GUID, value: u32, what: &str) {
        let Some(api) = &self.codec_api else { return };
        let var = variant_u32(value);
        // SAFETY: `var` outlives the call; ICodecAPI copies the value.
        if let Err(e) = unsafe { api.SetValue(key, &var) } {
            tracing::debug!("codec property {what} not settable: {e}");
        }
    }

    fn set_codec_bool(&self, key: &GUID, value: bool, what: &str) {
        let Some(api) = &self.codec_api else { return };
        let var = variant_bool(value);
        // SAFETY: as above.
        if let Err(e) = unsafe { api.SetValue(key, &var) } {
            tracing::debug!("codec property {what} not settable: {e}");
        }
    }
}

impl Drop for MfH264Encoder {
    fn drop(&mut self) {
        if !self.started {
            return;
        }
        // SAFETY: mirror of begin_streaming(); failures at teardown are ignored.
        unsafe {
            let _ = self
                .transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0);
            let _ = self
                .transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0);
            let _ = self.transform.ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0);
        }
    }
}

impl Encoder for MfH264Encoder {
    fn encode(&mut self, frame: &RawFrame) -> Result<Option<EncodedFrame>> {
        match frame.format {
            PixelFormat::Nv12 => {
                let data = std::mem::take(&mut self.cpu_scratch);
                let out = self.submit(FrameInput::Nv12(&frame.data), frame.timestamp_ms);
                self.cpu_scratch = data;
                out
            }
            PixelFormat::Bgra8 => {
                let mut scratch = std::mem::take(&mut self.cpu_scratch);
                let stride = frame.width as usize * 4;
                let res = crate::convert::bgra_to_nv12(
                    &frame.data,
                    stride,
                    frame.width,
                    frame.height,
                    &mut scratch,
                );
                let out = match res {
                    Ok(()) => self.submit(FrameInput::Nv12(&scratch), frame.timestamp_ms),
                    Err(e) => Err(e),
                };
                self.cpu_scratch = scratch;
                out
            }
            PixelFormat::Rgba8 => Err(Error::Encoder(
                "RGBA input is not supported; convert to BGRA or NV12 first".into(),
            )),
        }
    }

    fn request_keyframe(&mut self) {
        self.force_key = true;
    }

    fn set_bitrate(&mut self, kbps: u32) -> Result<()> {
        self.cfg.bitrate_kbps = kbps;
        self.set_codec_u32(
            &CODECAPI_AVEncCommonMeanBitRate,
            kbps.saturating_mul(1000),
            "MeanBitRate",
        );
        Ok(())
    }

    fn describe(&self) -> String {
        let adapter = if self.cfg.adapter_name.is_empty() {
            "unknown adapter".to_string()
        } else {
            self.cfg.adapter_name.clone()
        };
        let io = if self.d3d_bound { "GPU texture in" } else { "CPU NV12 in" };
        format!(
            "MF H.264 \"{}\" — {} on {} ({})",
            self.friendly_name,
            self.path.label(),
            adapter,
            io
        )
    }
}

// SAFETY: the encoder is created on and used from a single pipeline thread; it
// is only ever *moved* across threads, never shared. All COM objects it holds
// are free-threaded (MTA) or thread-affine to that same thread.
unsafe impl Send for MfH264Encoder {}

// ---- MFT selection -----------------------------------------------------------

/// All usable encoder MFTs, best first. Duplicates across passes are fine —
/// activation is attempted in order and the first that works wins.
fn candidate_mfts(cfg: &EncoderConfig) -> Result<Vec<(IMFActivate, EncoderPath)>> {
    let hw = MFT_ENUM_FLAG(
        MFT_ENUM_FLAG_HARDWARE.0 | MFT_ENUM_FLAG_ASYNCMFT.0 | MFT_ENUM_FLAG_SORTANDFILTER.0,
    );
    let mut out: Vec<(IMFActivate, EncoderPath)> = Vec::new();

    if let Some(luid) = cfg.adapter_luid {
        match enumerate(hw, Some(luid)) {
            Ok(mut list) => {
                if list.is_empty() {
                    tracing::warn!("no hardware H.264 MFT on capture adapter LUID {luid:#x}");
                }
                // The LUID filter is advisory: in practice MFTEnum2 still returns
                // other vendors' encoders. Put the ones whose PCI vendor ID
                // matches the capture adapter first, or on a hybrid laptop we
                // would happily bind the discrete GPU's encoder to a texture
                // that lives on the integrated one.
                if let Some(vendor) = cfg.adapter_vendor_id {
                    let want = format!("VEN_{vendor:04X}");
                    list.sort_by_key(|a| !mft_vendor_matches(a, &want));
                }
                log_names("LUID-matched hardware", &list);
                out.extend(list.into_iter().map(|a| (a, EncoderPath::HardwareSameAdapter)));
            }
            Err(e) => tracing::warn!("LUID-scoped MFT enumeration failed: {e}"),
        }
    }

    match enumerate(hw, None) {
        Ok(list) => {
            log_names("any-adapter hardware", &list);
            let path = if cfg.adapter_luid.is_some() {
                EncoderPath::HardwareOtherAdapter
            } else {
                EncoderPath::HardwareSameAdapter
            };
            out.extend(list.into_iter().map(|a| (a, path)));
        }
        Err(e) => tracing::warn!("hardware MFT enumeration failed: {e}"),
    }

    let sw = MFT_ENUM_FLAG(MFT_ENUM_FLAG_SYNCMFT.0 | MFT_ENUM_FLAG_SORTANDFILTER.0);
    match enumerate(sw, None) {
        Ok(list) => {
            log_names("software", &list);
            out.extend(list.into_iter().map(|a| (a, EncoderPath::Software)));
        }
        Err(e) => tracing::warn!("software MFT enumeration failed: {e}"),
    }
    Ok(out)
}

/// Does this MFT advertise the given `VEN_xxxx` hardware vendor ID?
fn mft_vendor_matches(activate: &IMFActivate, want: &str) -> bool {
    // SAFETY: live IMFActivate from MFTEnum2.
    unsafe { read_string(activate, &MFT_ENUM_HARDWARE_VENDOR_ID_Attribute) }
        .map(|v| v.eq_ignore_ascii_case(want))
        .unwrap_or(false)
}

fn log_names(kind: &str, list: &[IMFActivate]) {
    for a in list {
        // SAFETY: live IMFActivate from MFTEnum2.
        let name = unsafe { read_string(a, &MFT_FRIENDLY_NAME_Attribute) }
            .unwrap_or_else(|| "<unnamed>".into());
        tracing::info!("H.264 encoder candidate ({kind}): {name}");
    }
}

fn enumerate(flags: MFT_ENUM_FLAG, luid: Option<u64>) -> Result<Vec<IMFActivate>> {
    let input = MFT_REGISTER_TYPE_INFO {
        guidMajorType: MFMediaType_Video,
        guidSubtype: MFVideoFormat_NV12,
    };
    let output = MFT_REGISTER_TYPE_INFO {
        guidMajorType: MFMediaType_Video,
        guidSubtype: MFVideoFormat_H264,
    };

    // SAFETY: MFTEnum2 writes a CoTaskMem array of IMFActivate*, which we take
    // ownership of element-by-element and then free exactly once.
    unsafe {
        let mut attrs: Option<IMFAttributes> = None;
        MFCreateAttributes(&mut attrs, 1).map_err(enc_err("MFCreateAttributes"))?;
        let attrs = attrs.ok_or_else(|| Error::Encoder("MFCreateAttributes returned null".into()))?;
        if let Some(luid) = luid {
            attrs
                .SetUINT64(&MFT_ENUM_ADAPTER_LUID, luid)
                .map_err(enc_err("SetUINT64(MFT_ENUM_ADAPTER_LUID)"))?;
        }

        let mut arr: *mut Option<IMFActivate> = std::ptr::null_mut();
        let mut count: u32 = 0;
        MFTEnum2(
            MFT_CATEGORY_VIDEO_ENCODER,
            flags,
            Some(&input),
            Some(&output),
            &attrs,
            &mut arr,
            &mut count,
        )
        .map_err(enc_err("MFTEnum2"))?;

        let mut out = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            if let Some(a) = (*arr.add(i)).take() {
                out.push(a);
            }
        }
        if !arr.is_null() {
            CoTaskMemFree(Some(arr as *const std::ffi::c_void));
        }
        Ok(out)
    }
}

/// # Safety
/// `attrs` must be a live attribute store.
unsafe fn read_string(attrs: &IMFActivate, key: &GUID) -> Option<String> {
    unsafe {
        let len = attrs.GetStringLength(key).ok()?;
        let mut buf = vec![0u16; len as usize + 1];
        attrs.GetString(key, &mut buf, None).ok()?;
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        Some(String::from_utf16_lossy(&buf[..end]))
    }
}

// ---- helpers -----------------------------------------------------------------

fn enc_err(what: &'static str) -> impl Fn(windows::core::Error) -> Error {
    move |e| Error::Encoder(format!("{what}: {e}"))
}

const fn pack_2x32(hi: u32, lo: u32) -> u64 {
    ((hi as u64) << 32) | lo as u64
}

fn variant_u32(v: u32) -> VARIANT {
    let mut var = VARIANT::default();
    // SAFETY: VARIANT is a zeroed POD union here; VT_UI4 selects `ulVal`, which
    // owns no resources, so no VariantClear is required.
    unsafe {
        let inner = &mut *var.Anonymous.Anonymous;
        inner.vt = VT_UI4;
        inner.Anonymous.ulVal = v;
    }
    var
}

fn variant_bool(v: bool) -> VARIANT {
    let mut var = VARIANT::default();
    // SAFETY: as above; VT_BOOL selects `boolVal`.
    unsafe {
        let inner = &mut *var.Anonymous.Anonymous;
        inner.vt = VT_BOOL;
        inner.Anonymous.boolVal = if v { VARIANT_TRUE } else { VARIANT_BOOL(0) };
    }
    var
}

/// True if the buffer opens with a 3- or 4-byte Annex-B start code.
pub fn starts_with_start_code(b: &[u8]) -> bool {
    (b.len() >= 4 && b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 1)
        || (b.len() >= 3 && b[0] == 0 && b[1] == 0 && b[2] == 1)
}

/// Convert a 4-byte-length-prefixed (AVCC) bitstream to Annex-B, or `None` if
/// the buffer does not parse as AVCC.
pub fn avcc_to_annexb(b: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(b.len() + 16);
    let mut i = 0usize;
    while i + 4 <= b.len() {
        let n = u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]) as usize;
        if n == 0 || i + 4 + n > b.len() {
            return None;
        }
        out.extend_from_slice(&[0, 0, 0, 1]);
        out.extend_from_slice(&b[i + 4..i + 4 + n]);
        i += 4 + n;
    }
    if i == b.len() && !out.is_empty() {
        Some(out)
    } else {
        None
    }
}

/// Scan an Annex-B buffer for a NAL of the given type (7 = SPS, 5 = IDR slice).
pub fn contains_nal(b: &[u8], nal_type: u8) -> bool {
    let mut i = 0usize;
    while i + 3 < b.len() {
        if b[i] == 0 && b[i + 1] == 0 && b[i + 2] == 1 {
            if (b[i + 3] & 0x1F) == nal_type {
                return true;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_matches_mf_attribute_layout() {
        assert_eq!(pack_2x32(1920, 1080), (1920u64 << 32) | 1080);
    }

    #[test]
    fn detects_start_codes() {
        assert!(starts_with_start_code(&[0, 0, 0, 1, 0x67]));
        assert!(starts_with_start_code(&[0, 0, 1, 0x67]));
        assert!(!starts_with_start_code(&[0, 0, 0, 0x12, 0x67]));
        assert!(!starts_with_start_code(&[0x00, 0x00]));
    }

    #[test]
    fn avcc_roundtrips_to_annexb() {
        // Two NALs: SPS (0x67) of 3 bytes and IDR (0x65) of 2 bytes.
        let avcc = [0, 0, 0, 3, 0x67, 1, 2, 0, 0, 0, 2, 0x65, 9];
        let annexb = avcc_to_annexb(&avcc).expect("valid avcc");
        assert_eq!(annexb, vec![0, 0, 0, 1, 0x67, 1, 2, 0, 0, 0, 1, 0x65, 9]);
        assert!(contains_nal(&annexb, 7));
        assert!(contains_nal(&annexb, 5));
        assert!(!contains_nal(&annexb, 8));
    }

    #[test]
    fn avcc_rejects_garbage() {
        assert!(avcc_to_annexb(&[0, 0, 0, 200, 1, 2, 3]).is_none());
        assert!(avcc_to_annexb(&[0, 0, 0, 1, 0x67, 0xFF]).is_none());
        assert!(avcc_to_annexb(&[]).is_none());
    }

    #[test]
    fn nal_scan_finds_sps_after_leading_slice() {
        let buf = [0, 0, 0, 1, 0x65, 0xAA, 0, 0, 0, 1, 0x67, 0x42];
        assert!(contains_nal(&buf, 7));
        assert!(contains_nal(&buf, 5));
    }

    #[test]
    fn encoder_path_labels_are_honest() {
        assert!(!EncoderPath::Software.is_hardware());
        assert!(EncoderPath::Software.label().contains("SOFTWARE"));
        assert!(EncoderPath::HardwareSameAdapter.is_hardware());
    }
}
