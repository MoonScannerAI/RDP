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

use crate::capture::AdapterInfo;

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

/// H.264 profiles to try on the output type, most to least desirable.
///
/// High buys CABAC and the 8x8 transform over Main. On a desktop — thin,
/// high-contrast text on flat backgrounds — that is a visible sharpness win at
/// a fixed bitrate, which is exactly the content we encode. The client decodes
/// with `CLSID_MSH264DecoderMFT`, which handles High fine, and the profile is
/// signalled in-band in the SPS, so nothing in the wire protocol changes.
///
/// Main is the fallback because it is universally supported: no H.264 decoder
/// or encoder in existence refuses it. Some drivers (old integrated parts,
/// virtualised GPUs) will refuse High on `SetOutputType`, and a refused output
/// type fails the whole candidate MFT — so we walk down rather than die.
const PROFILE_LADDER: [(i32, &str); 2] = [
    (eAVEncH264VProfile_High.0, "High"),
    (eAVEncH264VProfile_Main.0, "Main"),
];

/// Worst quantizer the encoder is allowed to reach — a quality *floor*, since a
/// higher QP means a coarser picture. Small text is the first thing to dissolve
/// when rate control panics on a full-window repaint; capping QP here means the
/// encoder must spend bits (or drop below the mean, which peak-constrained VBR
/// permits) rather than let text turn to mush.
///
/// Only `MaxQP` is set. A `MinQP` would forbid the encoder from spending *more*
/// bits than it thinks necessary on an easy frame, which is exactly the saving
/// VBR already makes on its own — it costs quality and buys nothing.
const TEXT_QUALITY_FLOOR_MAX_QP: u32 = 32;

/// Peak ceiling for a given mean, under peak-constrained VBR.
///
/// 1.5x is headroom for the one frame where the whole window repainted. Higher
/// ratios keep a scroll marginally sharper but let the burst outrun a
/// residential uplink, and a burst that queues in the uplink buffer is felt as
/// input lag — at a ~258 ms RTT the user is already paying for every extra
/// millisecond of queueing.
///
/// This lives in one place because the ceiling must be re-written every time the
/// mean moves (see `apply_rate_control`): a mean cut by the adaptor with a stale
/// ceiling left behind means the encoder keeps bursting into a link that just
/// reported congestion.
fn peak_bitrate_bps(mean_bps: u32) -> u32 {
    ((mean_bps as u64 * 3) / 2).min(u32::MAX as u64) as u32
}

// ---- static refinement: the "MJPEG-like" pass --------------------------------
//
// WHY CQP AND NOT A BITRATE BURST
//
// Hardware KVMs (PiKVM, TinyPilot) look better than us on static text for one
// architectural reason: they ship MJPEG, i.e. every frame is coded at a *fixed
// quality factor* and the bitrate is whatever that quality costs. Our settle
// IDR, by contrast, is coded inside a bitrate-targeted budget, so on a detailed
// 1080p screen the rate controller quantizes it down to fit the mean and the
// "refinement" comes out barely sharper than the frame it replaced.
//
// Two ways to fix that were on the table:
//
//   (b) stay in PeakConstrainedVBR and raise mean+peak to a big "burst" value
//       for the one IDR. Reuses `apply_rate_control` and never changes mode,
//       so it is the gentler thing to do to a vendor MFT — but it asks for the
//       result indirectly. Rate control still owns the decision, still carries
//       its HRD buffer state across the switch, and typically *ramps* toward a
//       new mean rather than granting one enormous frame immediately. It also
//       has no bound worth the name: the only lever is bits/second, the encoder
//       decides how many of them land in this particular frame, and if it
//       decides "all of them" the frame blows past the fragmenter's limit and
//       is dropped outright (see the ceiling in `session.rs`).
//
//   (a) switch rate control to Quality (CQP) with a high `AVEncCommonQuality`
//       for the one IDR, then switch back. This is MJPEG's own semantics —
//       quality is the input, size is the output — so it targets the actual
//       goal instead of a proxy for it. The hardware probe on this class of
//       machine verified by measured output size (not by return codes) that the
//       Intel QuickSync MFT accepts mode switches to Quality=3 and back, and
//       that `AVEncCommonQuality` both takes and reads back.
//
// (a) is chosen. The decisive point is bounding: under CQP the cost is bounded
// *directly* by a QP window (`AVEncVideoMinQP`/`MaxQP`, which the probe found
// settable and honoured on this MFT despite `IsSupported` saying no), and a QP
// floor is a hard, encoder-enforced cap on how many bits one frame may eat.
// Under (b) there is no equivalent — a mean is not a per-frame limit.
//
// The two risks of (a) are handled rather than avoided:
//   * mid-stream mode switch — it is a single property write, applied like
//     `ForceKeyFrame` immediately before the `ProcessInput` it is meant to
//     affect, and undone the same way;
//   * being left in Quality mode, where the adaptor's mean/peak writes are
//     ignored and it can no longer steer — see `end_static_refinement`, which
//     the media loop calls unconditionally at the top of the *next* iteration
//     and which `set_bitrate` also forces.
//
// On the Microsoft software encoder every codec-API write is ignored (the probe
// found CBR and CQP produced byte-identical output); it follows only
// MF_MT_AVG_BITRATE. There the whole feature is inert, which is the correct
// degradation: no refinement, and equally no way to get stuck.

/// Lowest `AVEncCommonQuality` a config may ask the refinement frame for.
/// Below this the frame is not meaningfully better than the stream it
/// interrupts and the extra IDR is not worth its bytes.
pub const MIN_STATIC_REFINE_QUALITY: u32 = 50;
/// Highest `AVEncCommonQuality` a config may ask for. Deliberately not 100:
/// the quality scale runs toward QP 0, and a 1080p intra frame near QP 0 is
/// megabytes — more than the fragmenter will carry, so it would be *dropped*
/// and the user would get no picture at all. The QP window below is the hard
/// bound; this is the first of the two guards.
pub const MAX_STATIC_REFINE_QUALITY: u32 = 96;
/// Default quality for the refinement frame. Near the top of the permitted
/// range: the whole premise is that the screen is static, so we have the idle
/// period and the idle bandwidth to spend on one good frame.
pub const DEFAULT_STATIC_REFINE_QUALITY: u32 = 88;

/// QP the refinement frame may never go below, whatever quality is asked for.
///
/// This is the real cost bound. At 1080p, desktop content (flat backgrounds,
/// thin high-contrast text) codes an intra frame at roughly QP 18 in the low
/// hundreds of KB; each further QP step down multiplies that. `MinQP` is
/// enforced by the encoder itself, so unlike a bitrate target it cannot be
/// "missed" on a hard frame.
const REFINE_QP_FLOOR: u32 = 18;
/// QP at the bottom of the permitted quality range — still a clear step better
/// than the streaming path's `TEXT_QUALITY_FLOOR_MAX_QP` worst case.
const REFINE_QP_CEILING: u32 = 26;
/// Slack allowed above the target QP, so an unusually busy screen can give a
/// little back instead of overshooting the size bound.
const REFINE_QP_WINDOW: u32 = 4;

/// The codec-API settings one refinement frame is encoded with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefineSettings {
    /// `AVEncCommonQuality`, clamped into the permitted range.
    pub quality: u32,
    /// `AVEncVideoMinQP` — the size bound.
    pub min_qp: u32,
    /// `AVEncVideoMaxQP` — how coarse the frame is still allowed to get.
    pub max_qp: u32,
}

/// Map a configured quality level onto a bounded QP window.
///
/// Pure, so the bound can be tested without an MFT. `quality` is clamped into
/// `[MIN_STATIC_REFINE_QUALITY, MAX_STATIC_REFINE_QUALITY]` first, so no config
/// value — hand-edited, zero, or `u32::MAX` — can produce a QP below
/// [`REFINE_QP_FLOOR`].
pub fn refine_settings(quality: u32) -> RefineSettings {
    let quality = quality.clamp(MIN_STATIC_REFINE_QUALITY, MAX_STATIC_REFINE_QUALITY);
    let span = MAX_STATIC_REFINE_QUALITY - MIN_STATIC_REFINE_QUALITY;
    let depth = REFINE_QP_CEILING - REFINE_QP_FLOOR;
    // Linear across the permitted band: MIN quality -> ceiling QP, MAX -> floor.
    let step = (quality - MIN_STATIC_REFINE_QUALITY) * depth / span;
    let min_qp = (REFINE_QP_CEILING - step).max(REFINE_QP_FLOOR);
    let max_qp = (min_qp + REFINE_QP_WINDOW).min(TEXT_QUALITY_FLOOR_MAX_QP);
    RefineSettings {
        quality,
        min_qp,
        max_qp,
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

impl EncoderConfig {
    /// The config for encoding `width`x`height` on the adapter `info`
    /// describes, at `fps`/`bitrate_kbps`/`gop_seconds`.
    ///
    /// Centralizes what used to be three independently hand-copied struct
    /// literals (`session::build_pipeline`, `session::rebuild_encoder`, and
    /// `capture_harness`), all of which populate `adapter_luid`,
    /// `adapter_vendor_id` and `adapter_name` from an [`AdapterInfo`] the same
    /// way. `fps`/`bitrate_kbps`/`gop_seconds` are floored at 1 here — every
    /// call site independently applied the same `.max(1)` before this existed,
    /// since `0` in any of the three is a divide-by-zero or a meaningless
    /// "never" further down the pipeline.
    pub fn for_adapter(
        info: &AdapterInfo,
        width: u32,
        height: u32,
        fps: u32,
        bitrate_kbps: u32,
        gop_seconds: u32,
    ) -> Self {
        Self {
            width,
            height,
            fps: fps.max(1),
            bitrate_kbps: bitrate_kbps.max(1),
            gop_seconds: gop_seconds.max(1),
            adapter_luid: Some(info.luid),
            adapter_vendor_id: Some(info.vendor_id),
            adapter_name: info.short(),
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
    /// H.264 profile the MFT actually accepted, from [`PROFILE_LADDER`].
    /// `"unknown"` until `negotiate_types` settles. Surfaced by `describe()` so
    /// a human can tell High from Main without attaching a debugger.
    negotiated_profile: &'static str,

    /// Async MFT credits. `need_input` is decremented per `ProcessInput`.
    need_input: u32,
    have_output: u32,
    out_provides_samples: bool,
    out_buf_size: u32,

    queue: VecDeque<EncodedFrame>,
    frame_id: u32,
    last_hns: i64,
    force_key: bool,
    /// True while the MFT is parked in Quality/CQP mode for one static
    /// refinement frame. Exists so the restore is idempotent and so
    /// `set_bitrate` can tell that the adaptor is trying to steer an encoder
    /// that is currently deaf to mean/peak writes.
    refine_active: bool,
    /// Cached SPS/PPS blob, spliced in front of keyframes that lack one.
    ///
    /// INVARIANT: this blob must describe the output type *currently installed*
    /// on the MFT. Any code path that calls `SetOutputType` after streaming has
    /// begun MUST clear it — `renegotiate_output` does. A Main-profile SPS
    /// spliced in front of High-profile slices by `normalize_bitstream` is not a
    /// soft failure or a quality regression: `profile_idc` in the SPS gates
    /// CABAC and the 8x8 transform, so the decoder parses the slice data with
    /// the wrong entropy coder and the stream is dead from that keyframe on.
    ///
    /// The profile ladder cannot trip this — `seq_header` is populated lazily at
    /// the first keyframe, strictly after negotiation has settled — but write the
    /// rule down so it is not reintroduced.
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
    ///
    /// That promise is only worth as much as [`try_build`]'s error discipline:
    /// EVERY fallible step from `ActivateObject` up to the moment we return
    /// `Ok` must come back as an `Err` from `try_build`, never propagate past
    /// the ladder. The one deliberate exception is [`bind_d3d`], which is
    /// infallible by construction — see its doc for why a refused device
    /// manager is a degradation rather than a failure.
    ///
    /// This matters most with two pipelines running: a consumer NVIDIA part
    /// grants two or three concurrent NVENC sessions, so the *second* monitor's
    /// encoder is the one that meets "already in use", and a `new()` that
    /// failed instead of demoting would take `HostSession::start` down with it
    /// when the software encoder would have carried the stream.
    ///
    /// [`try_build`]: Self::try_build
    /// [`bind_d3d`]: Self::bind_d3d
    pub fn new(cfg: EncoderConfig, device: Option<&ID3D11Device>) -> Result<Self> {
        let candidates = candidate_mfts(&cfg)?;
        first_usable(
            candidates,
            |activate| {
                // SAFETY: `activate` came from MFTEnum2 and is a live IMFActivate.
                unsafe { read_string(activate, &MFT_FRIENDLY_NAME_Attribute) }
                    .unwrap_or_else(|| "<unnamed MFT>".to_string())
            },
            |activate, path, name| Self::try_build(activate, path, name, cfg.clone(), device),
            |activate| {
                // SAFETY: releases whatever the failed activation created.
                unsafe {
                    let _ = activate.ShutdownObject();
                }
            },
        )
    }

    /// One candidate, from activation to "committed". Every step that can fail
    /// returns `Err` so [`new`] can demote; nothing here aborts the ladder.
    ///
    /// [`new`]: Self::new
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
            negotiated_profile: "unknown",
            need_input: 0,
            have_output: 0,
            out_provides_samples: false,
            out_buf_size: 0,
            queue: VecDeque::new(),
            frame_id: 0,
            last_hns: -1,
            force_key: false,
            refine_active: false,
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
    pub fn submit(
        &mut self,
        input: FrameInput<'_>,
        timestamp_ms: u32,
    ) -> Result<Option<EncodedFrame>> {
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
                self.events = Some(self.transform.cast::<IMFMediaEventGenerator>().map_err(
                    |e| Error::Encoder(format!("async MFT without event generator: {e}")),
                )?);
            }
            let _ = attrs.SetUINT32(&MF_LOW_LATENCY, 1);
        }
        Ok(())
    }

    /// Hand the MFT our D3D11 device manager so it can take GPU textures.
    ///
    /// Infallible ON PURPOSE — the one step inside `try_build` that does not
    /// demote to the next candidate, and the exception is load-bearing rather
    /// than laziness:
    ///
    /// * Selection tier 2 is "hardware MFT on ANY adapter (cross-adapter copy
    ///   via CPU NV12)". Attaching adapter A's device manager to adapter B's
    ///   encoder is *expected* to be refused; that refusal is how the tier is
    ///   supposed to work, so demoting on it would delete tier 2 outright.
    /// * The caller already adapts. `session::build_pipeline` computes
    ///   `gpu_encode_input = converter.is_some() && encoder.accepts_textures()`
    ///   and does a `readback_nv12` when it is false, so an unbound MFT is a
    ///   working encoder that pays for a readback — not a broken one.
    /// * Demoting here would trade a hardware encoder with a CPU-side copy for
    ///   the *software* encoder on any host that has only one hardware MFT.
    ///   That is strictly worse than what it is meant to protect.
    ///
    /// The failure that genuinely means "this device cannot encode right now"
    /// shows up at `SetOutputType`, `SetInputType` or `NOTIFY_BEGIN_STREAMING`,
    /// and all three do demote.
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

    /// Build and install the H.264 output type at `profile`.
    ///
    /// The `MF_MT_MPEG2_PROFILE` setter stays `.ok()`-swallowed on purpose: an
    /// attribute store refusing a `SetUINT32` tells us nothing. `SetOutputType`
    /// is the real gate — that is the call that either accepts the profile or
    /// rejects the whole type, so that is the error we propagate.
    ///
    /// # Safety
    /// The transform must be live and not yet streaming (see `negotiate_types`).
    unsafe fn set_output_type(&self, profile: u32) -> Result<()> {
        let bps = self.cfg.bitrate_kbps.saturating_mul(1000);
        // SAFETY: media types are freshly created; every setter takes static
        // GUID keys and plain scalars.
        unsafe {
            let out = MFCreateMediaType().map_err(enc_err("MFCreateMediaType(out)"))?;
            out.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video).ok();
            out.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_H264).ok();
            out.SetUINT32(&MF_MT_AVG_BITRATE, bps).ok();
            out.SetUINT64(
                &MF_MT_FRAME_SIZE,
                pack_2x32(self.cfg.width, self.cfg.height),
            )
            .ok();
            out.SetUINT64(&MF_MT_FRAME_RATE, pack_2x32(self.cfg.fps, 1))
                .ok();
            out.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, pack_2x32(1, 1))
                .ok();
            out.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)
                .ok();
            out.SetUINT32(&MF_MT_MPEG2_PROFILE, profile).ok();
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
        }
        Ok(())
    }

    fn negotiate_types(&mut self) -> Result<()> {
        // Walk the profile ladder and keep the first profile the MFT installs.
        //
        // Retrying on the *same* transform is safe: `SetOutputType` may be
        // called repeatedly until MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, which
        // `try_build` only sends later, and a rejected call leaves the output
        // type simply unset rather than half-applied. If every profile is
        // refused we return the last error unchanged, so `new()` still demotes
        // to the next candidate MFT and ultimately to the software encoder —
        // never to "media pipeline unavailable" on a machine that had a working
        // Main-profile encoder all along.
        let mut last_err = None;
        for (profile, name) in PROFILE_LADDER {
            // SAFETY: live transform, not yet streaming (see above).
            match unsafe { self.set_output_type(profile as u32) } {
                Ok(()) => {
                    self.negotiated_profile = name;
                    last_err = None;
                    break;
                }
                Err(e) => {
                    tracing::warn!(
                        "H.264 {name} profile refused by \"{}\": {e}",
                        self.friendly_name
                    );
                    last_err = Some(e);
                }
            }
        }
        if let Some(e) = last_err {
            return Err(e);
        }
        if self.negotiated_profile != "High" {
            tracing::warn!(
                profile = self.negotiated_profile,
                "encoder fell back from H.264 High profile; without CABAC and the \
                 8x8 transform, text will be softer at a given bitrate"
            );
        }

        // SAFETY: media types are freshly created; every setter takes static
        // GUID keys and plain scalars.
        unsafe {
            let inp = MFCreateMediaType().map_err(enc_err("MFCreateMediaType(in)"))?;
            inp.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video).ok();
            inp.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_NV12).ok();
            inp.SetUINT64(
                &MF_MT_FRAME_SIZE,
                pack_2x32(self.cfg.width, self.cfg.height),
            )
            .ok();
            inp.SetUINT64(&MF_MT_FRAME_RATE, pack_2x32(self.cfg.fps, 1))
                .ok();
            inp.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, pack_2x32(1, 1))
                .ok();
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
            self.out_buf_size = info.cbSize.max(self.cfg.width * self.cfg.height);
            // generous floor
        }
        self.codec_api = self.transform.cast::<ICodecAPI>().ok();
        Ok(())
    }

    /// Write the mean *and* the peak ceiling together.
    ///
    /// Under peak-constrained VBR the two are a pair: writing one without the
    /// other leaves the encoder bursting to a ceiling that no longer relates to
    /// the rate we asked for. Every site that moves the bitrate goes through
    /// here so the two cannot drift.
    fn apply_rate_control(&self, kbps: u32) {
        let mean = kbps.saturating_mul(1000);
        self.set_codec_u32(&CODECAPI_AVEncCommonMeanBitRate, mean, "MeanBitRate");
        self.set_codec_u32(
            &CODECAPI_AVEncCommonMaxBitRate,
            peak_bitrate_bps(mean),
            "MaxBitRate",
        );
    }

    /// Park the encoder in Quality/CQP for exactly one frame — the static
    /// refinement IDR — and force that IDR.
    ///
    /// See the design note above [`refine_settings`] for why CQP rather than a
    /// bitrate burst. The writes land here, immediately before the
    /// `ProcessInput` they are meant to affect, for the same reason
    /// `ForceKeyFrame` does: that is the point at which an MFT latches
    /// per-frame parameters.
    ///
    /// THE CALLER MUST CALL [`end_static_refinement`] on its next iteration,
    /// unconditionally. While this is active the encoder ignores mean/peak
    /// writes, so the adaptor cannot steer it.
    ///
    /// [`end_static_refinement`]: Self::end_static_refinement
    pub fn begin_static_refinement(&mut self, quality: u32) -> RefineSettings {
        let s = refine_settings(quality);
        self.set_codec_u32(
            &CODECAPI_AVEncCommonRateControlMode,
            eAVEncCommonRateControlMode_Quality.0 as u32,
            "RateControlMode=Quality",
        );
        self.set_codec_u32(&CODECAPI_AVEncCommonQuality, s.quality, "CommonQuality");
        // The bound. Written after the mode so a driver that resets its QP
        // window on a mode change cannot leave us unbounded.
        self.set_codec_u32(&CODECAPI_AVEncVideoMinQP, s.min_qp, "MinQP(refine)");
        self.set_codec_u32(&CODECAPI_AVEncVideoMaxQP, s.max_qp, "MaxQP(refine)");
        self.refine_active = true;
        // Pair the IDR with the mode so the two can never be requested apart.
        self.force_key = true;
        s
    }

    /// Undo [`begin_static_refinement`]: back to peak-constrained VBR at the
    /// bitrate currently in force, and drop the QP floor.
    ///
    /// Idempotent — a no-op when no refinement is armed — so the media loop can
    /// call it every iteration without tracking whether it is needed.
    ///
    /// [`begin_static_refinement`]: Self::begin_static_refinement
    pub fn end_static_refinement(&mut self) {
        if !self.refine_active {
            return;
        }
        self.refine_active = false;
        self.set_codec_u32(
            &CODECAPI_AVEncCommonRateControlMode,
            eAVEncCommonRateControlMode_PeakConstrainedVBR.0 as u32,
            "RateControlMode=PeakConstrainedVBR",
        );
        // `cfg.bitrate_kbps` tracks `set_bitrate`, so this restores the rate the
        // adaptor last chose — never the one the config booted with.
        self.apply_rate_control(self.cfg.bitrate_kbps);
        // 0 = no floor, which is the streaming default: outside a refinement we
        // want the encoder free to spend *fewer* bits on an easy frame.
        self.set_codec_u32(&CODECAPI_AVEncVideoMinQP, 0, "MinQP");
        self.set_codec_u32(
            &CODECAPI_AVEncVideoMaxQP,
            TEXT_QUALITY_FLOOR_MAX_QP,
            "MaxQP",
        );
    }

    /// True while a refinement frame's settings are installed on the MFT.
    pub fn refining(&self) -> bool {
        self.refine_active
    }

    fn apply_codec_settings(&mut self) {
        // Peak-constrained VBR, not CBR. CBR hands every frame the same bit
        // budget whether it is a full-window repaint or an unchanged desktop, so
        // the repaint — the frame that draws the text — is the one that gets
        // starved. VBR lets that frame overspend up to the peak and take the
        // bits back on the idle frames that follow.
        //
        // PeakConstrainedVBR specifically: the probe confirmed the Intel MFT
        // accepts it (as it does Quality/CQP and UnconstrainedVBR, but not
        // LowDelayVBR or GlobalVBR), and a *constrained* peak is what keeps the
        // burst inside the uplink's headroom.
        self.set_codec_u32(
            &CODECAPI_AVEncCommonRateControlMode,
            eAVEncCommonRateControlMode_PeakConstrainedVBR.0 as u32,
            "RateControlMode=PeakConstrainedVBR",
        );
        self.apply_rate_control(self.cfg.bitrate_kbps);
        // Quality floor. Best-effort like its neighbours, and deliberately not
        // gated on `IsSupported`: the probe found the Intel MFT reports NO for
        // MinQP/MaxQP and then accepts and honours the write anyway.
        self.set_codec_u32(
            &CODECAPI_AVEncVideoMaxQP,
            TEXT_QUALITY_FLOOR_MAX_QP,
            "MaxQP",
        );
        self.set_codec_bool(&CODECAPI_AVLowLatencyMode, true, "LowLatencyMode");
        self.set_codec_u32(&CODECAPI_AVEncMPVDefaultBPictureCount, 0, "BPictureCount=0");
        self.set_codec_u32(
            &CODECAPI_AVEncMPVGOPSize,
            self.cfg.fps.max(1) * self.cfg.gop_seconds.max(1),
            "GOPSize",
        );
        // 0 = quality-biased, 100 = speed-biased. 33 was biased toward speed,
        // and on this class of MFT that dial gates the intra-mode search and the
        // 8x8-vs-4x4 transform decision — which is precisely the machinery High
        // profile buys us. A hardware encoder at 1080p has the throughput to
        // spare, so we now pay for High and let the encoder actually use it.
        self.set_codec_u32(&CODECAPI_AVEncCommonQualityVsSpeed, 10, "QualityVsSpeed");
        // High *permits* CABAC but plenty of MFTs still default to CAVLC, and
        // CABAC is where most of High's coding gain actually lives. Best-effort
        // like its neighbours: a driver that ignores this still encodes.
        self.set_codec_bool(&CODECAPI_AVEncH264CABACEnable, true, "CABACEnable");
    }

    fn begin_streaming(&mut self) -> Result<()> {
        // SAFETY: live transform; messages are the documented start sequence.
        unsafe {
            self.transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)
                .map_err(enc_err("NOTIFY_BEGIN_STREAMING"))?;
            // Armed HERE, between the two messages, not after both.
            //
            // BEGIN_STREAMING is the message on which a vendor MFT allocates
            // its encode session — on NVIDIA, one of the two or three NVENC
            // sessions a consumer part will ever grant. If START_OF_STREAM then
            // fails we return `Err` and `new()` demotes to the next candidate;
            // `Drop` is the only thing that ever sends END_STREAMING, and with
            // this flag still `false` it skipped teardown and left the session
            // pinned for the life of the process. On the two-monitor path that
            // is the exact resource the second pipeline is queueing for, so the
            // demotion would poison the fallback it was demoting to.
            //
            // END_OF_STREAM without a matching START_OF_STREAM is harmless:
            // `Drop` ignores every result, and an MFT that never got a start
            // has nothing to end.
            self.started = true;
            self.transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)
                .map_err(enc_err("NOTIFY_START_OF_STREAM"))?;
        }
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
        let Some(gen) = self.events.clone() else {
            return;
        };
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

            let Some(sample) = sample else {
                return Ok(None);
            };
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

    /// Adopt the MFT's preferred output type after MF_E_TRANSFORM_STREAM_CHANGE.
    ///
    /// This path is HOT, not rare: the Intel MFT raises the stream change on the
    /// *first* `ProcessOutput` of every session, so this runs on every single
    /// connection. Treat it as part of startup.
    ///
    /// The MFT's preferred type carries the MFT's attributes, not ours — adopting
    /// it wholesale silently drops `MF_MT_AVG_BITRATE` and everything else we set
    /// in `set_output_type`. That matters twice over: it is what the *software*
    /// encoder follows (it ignores the codec API entirely), and it is the last
    /// word for any MFT that reads the media type rather than the codec API. So
    /// re-stamp our attributes onto the type before installing it, then re-apply
    /// the codec settings at the CURRENT adaptive bitrate — `self.cfg.bitrate_kbps`
    /// tracks `set_bitrate`, so a renegotiation mid-session does not resurrect
    /// the rate the session booted at.
    ///
    /// Frame size, frame rate and profile are deliberately left as the MFT chose
    /// them: the stream change means the MFT is telling us what it will emit, and
    /// arguing with it here just risks a refused `SetOutputType` on the one path
    /// every session must pass through.
    fn renegotiate_output(&mut self) -> Result<()> {
        // SAFETY: live transform; the type came from the MFT itself and every
        // setter takes static GUID keys and plain scalars.
        unsafe {
            let t = self
                .transform
                .GetOutputAvailableType(0, 0)
                .map_err(enc_err("GetOutputAvailableType"))?;
            t.SetUINT32(
                &MF_MT_AVG_BITRATE,
                self.cfg.bitrate_kbps.saturating_mul(1000),
            )
            .ok();
            t.SetUINT32(
                &MF_MT_MAX_KEYFRAME_SPACING,
                self.cfg.fps.max(1) * self.cfg.gop_seconds.max(1),
            )
            .ok();
            t.SetUINT32(&MF_MT_ALL_SAMPLES_INDEPENDENT, 0).ok();
            self.transform
                .SetOutputType(0, &t, 0)
                .map_err(enc_err("SetOutputType(renegotiate)"))?;
        }
        // A new output type resets rate control on some drivers; re-state it.
        self.apply_codec_settings();
        self.seq_header.clear();
        Ok(())
    }

    fn fetch_sequence_header(&mut self) {
        // SAFETY: live transform; blob size is queried before the read.
        unsafe {
            let Ok(t) = self.transform.GetOutputCurrentType(0) else {
                return;
            };
            let Ok(size) = t.GetBlobSize(&MF_MT_MPEG_SEQUENCE_HEADER) else {
                return;
            };
            if size == 0 {
                return;
            }
            let mut buf = vec![0u8; size as usize];
            if t.GetBlob(&MF_MT_MPEG_SEQUENCE_HEADER, &mut buf, None)
                .is_ok()
            {
                // The SPS is the ground truth for the profile we asked for; an
                // MFT can accept MF_MT_MPEG2_PROFILE and still emit Main. Log
                // what is actually on the wire, not what we requested.
                match sps_profile_idc(&buf) {
                    Some(idc) => tracing::info!(
                        requested = self.negotiated_profile,
                        chroma_format_idc = ?sps_chroma_format_idc(&buf),
                        "captured {} byte H.264 sequence header; emitted profile_idc = {idc} \
                         (66=Baseline, 77=Main, 100=High, 244=High 4:4:4), \
                         chroma_format_idc (0=mono, 1=4:2:0, 2=4:2:2, 3=4:4:4)",
                        buf.len()
                    ),
                    None => tracing::debug!(
                        "captured {} byte H.264 sequence header (no SPS found in blob)",
                        buf.len()
                    ),
                }
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

    /// Adopt the frame numbering and timestamp watermark of the encoder being
    /// replaced, so a mid-session rebuild is invisible to the receiver's
    /// reassembler — which would otherwise spend `resync_after` frames adopting
    /// a restart at zero (see shared::transport::reassembly).
    pub(crate) fn resume_numbering_from(&mut self, prev: &Self) {
        self.frame_id = prev.frame_id;
        self.last_hns = prev.last_hns;
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
        // Second line of defence on the refinement restore. In Quality mode the
        // mean/peak writes below are ignored, so an adaptor cutting the rate
        // because the link is losing packets would achieve nothing at all.
        // Steering outranks refinement: leave the mode first, which itself
        // re-applies rate control at the new `cfg.bitrate_kbps`.
        if self.refine_active {
            self.end_static_refinement();
            return Ok(());
        }
        // Mean *and* peak. Writing only the mean under peak-constrained VBR is a
        // congestion-collapse trap: the adaptor cuts to, say, 1.5 Mbps because
        // the link is losing packets, and an untouched ceiling lets the encoder
        // go on bursting to whatever the build-time peak was — straight back
        // into the congestion that caused the cut.
        self.apply_rate_control(kbps);
        Ok(())
    }

    fn describe(&self) -> String {
        let adapter = if self.cfg.adapter_name.is_empty() {
            "unknown adapter".to_string()
        } else {
            self.cfg.adapter_name.clone()
        };
        let io = if self.d3d_bound {
            "GPU texture in"
        } else {
            "CPU NV12 in"
        };
        format!(
            "MF H.264 {} \"{}\" — {} on {} ({})",
            self.negotiated_profile,
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
                out.extend(
                    list.into_iter()
                        .map(|a| (a, EncoderPath::HardwareSameAdapter)),
                );
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

/// Walk `candidates` best-first and return the first one `build` accepts.
///
/// The demotion ladder, lifted out of [`MfH264Encoder::new`] and made generic
/// over the candidate type for one reason: activation is COM and hardware, but
/// the *ordering rules* are not, and those rules are what stands between "this
/// GPU is out of NVENC sessions" and a dead second monitor. With the ladder in
/// a plain function the rules are unit-testable (see `tests::ladder`) without
/// an MFT, a D3D device or a COM apartment anywhere near them.
///
/// The contract, in order:
///
/// * an empty list is its own diagnosis — nothing was registered, which is a
///   different problem from everything having refused;
/// * the first `Ok` wins immediately, and no candidate below it is activated or
///   discarded;
/// * every `Err` is logged with the candidate's name and tier, handed to
///   `discard` (which releases what the failed activation created), and then
///   demoted past — a failure at ANY position continues the walk;
/// * if the list runs out, the last reason is reported along with how many
///   candidates refused, because "the software encoder said no" on its own
///   hides the hardware reason that actually mattered.
fn first_usable<C, T>(
    candidates: Vec<(C, EncoderPath)>,
    name_of: impl Fn(&C) -> String,
    build: impl Fn(&C, EncoderPath, String) -> Result<T>,
    discard: impl Fn(&C),
) -> Result<T> {
    if candidates.is_empty() {
        return Err(Error::Encoder(
            "no H.264 encoder MFT of any kind is registered".into(),
        ));
    }
    let tried = candidates.len();
    let mut last_err = None;
    for (candidate, path) in candidates {
        let name = name_of(&candidate);
        match build(&candidate, path, name.clone()) {
            Ok(built) => return Ok(built),
            Err(e) => {
                tracing::warn!(
                    "encoder candidate \"{name}\" ({}) unusable: {e}",
                    path.label()
                );
                discard(&candidate);
                last_err = Some(e);
            }
        }
    }
    Err(match last_err {
        // Unwrap our own variant so the message does not read
        // "encoder: ... last: encoder: ...".
        Some(Error::Encoder(msg)) => Error::Encoder(format!(
            "all {tried} H.264 encoder candidate(s) refused; last: {msg}"
        )),
        Some(other) => other,
        // Unreachable: the list was non-empty and every iteration either
        // returned or recorded an error. Kept total rather than panicking.
        None => Error::Encoder("no usable H.264 encoder MFT".into()),
    })
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
        let attrs =
            attrs.ok_or_else(|| Error::Encoder("MFCreateAttributes returned null".into()))?;
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

/// `profile_idc` from the first SPS (NAL type 7) in an Annex-B buffer:
/// 66 = Baseline, 77 = Main, 100 = High. `None` if there is no SPS, or if the
/// buffer ends before the byte after the NAL header.
///
/// This is the *only* trustworthy answer to "which profile is the encoder
/// actually emitting". `MF_MT_MPEG2_PROFILE` is a request: an MFT may accept the
/// attribute, accept the output type, and then quietly emit Main anyway. The
/// bitstream cannot lie — `profile_idc` is what the decoder itself reads.
pub fn sps_profile_idc(b: &[u8]) -> Option<u8> {
    let mut i = 0usize;
    while i + 3 < b.len() {
        if b[i] == 0 && b[i + 1] == 0 && b[i + 2] == 1 {
            if (b[i + 3] & 0x1F) == 7 {
                // profile_idc is the byte immediately after the NAL header.
                return b.get(i + 4).copied();
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    None
}

/// `chroma_format_idc` from the first SPS in an Annex-B buffer:
/// 0 = monochrome, 1 = 4:2:0, 2 = 4:2:2, 3 = 4:4:4. `None` if there is no SPS or
/// it is truncated.
///
/// Worth parsing because the profile alone does not answer the question. The
/// probe had the Intel MFT accept profile 244 (High 4:4:4 Predictive), report
/// 244 back on `GetOutputAvailableType` — and then emit `chroma_format_idc = 1`,
/// i.e. plain 4:2:0, which is what makes coloured text fringe. Only the
/// bitstream tells the truth, so log what the bitstream says.
///
/// Profiles below High do not carry the field at all; the standard fixes them at
/// 4:2:0, so `Some(1)` for those is the correct answer, not a guess.
pub fn sps_chroma_format_idc(b: &[u8]) -> Option<u8> {
    /// Profiles whose SPS carries the chroma/bit-depth extension (7.3.2.1.1).
    const EXTENDED_PROFILES: [u8; 13] =
        [100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135];
    let rbsp = first_sps_rbsp(b)?;
    let profile_idc = *rbsp.first()?;
    if !EXTENDED_PROFILES.contains(&profile_idc) {
        return Some(1);
    }
    // Skip profile_idc, the constraint-flag byte and level_idc.
    let mut r = BitReader::new(rbsp.get(3..)?);
    let _seq_parameter_set_id = r.ue()?;
    let chroma = r.ue()?;
    if chroma > 3 {
        return None;
    }
    Some(chroma as u8)
}

/// Payload of the first SPS (NAL type 7) in an Annex-B buffer, with
/// emulation-prevention bytes removed, starting at `profile_idc`.
fn first_sps_rbsp(b: &[u8]) -> Option<Vec<u8>> {
    let mut i = 0usize;
    while i + 3 < b.len() {
        if b[i] == 0 && b[i + 1] == 0 && b[i + 2] == 1 {
            if (b[i + 3] & 0x1F) == 7 {
                let start = i + 4;
                let end = next_start_code(b, start).unwrap_or(b.len());
                return Some(unescape_rbsp(&b[start..end]));
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    None
}

/// Index of the next 3-byte start code at or after `from`.
fn next_start_code(b: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i + 2 < b.len() {
        if b[i] == 0 && b[i + 1] == 0 && b[i + 2] == 1 {
            // Report the 4-byte form's leading zero when there is one, so the
            // NAL payload does not keep a trailing 0x00 that belongs to the
            // *next* start code.
            return Some(if i > from && b[i - 1] == 0 { i - 1 } else { i });
        }
        i += 1;
    }
    None
}

/// Drop the 0x03 of every `00 00 03` sequence — the escape H.264 inserts so a
/// payload can never contain a start code.
fn unescape_rbsp(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    let mut zeros = 0usize;
    for &byte in b {
        if zeros >= 2 && byte == 3 {
            zeros = 0;
            continue;
        }
        if byte == 0 {
            zeros += 1;
        } else {
            zeros = 0;
        }
        out.push(byte);
    }
    out
}

/// Big-endian bit reader over an RBSP, with the Exp-Golomb decode the SPS needs.
struct BitReader<'a> {
    b: &'a [u8],
    bit: usize,
}

impl<'a> BitReader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, bit: 0 }
    }

    fn read_bit(&mut self) -> Option<u32> {
        let byte = *self.b.get(self.bit / 8)?;
        let shift = 7 - (self.bit % 8);
        self.bit += 1;
        Some(((byte >> shift) & 1) as u32)
    }

    fn read_bits(&mut self, n: u32) -> Option<u32> {
        let mut v = 0u32;
        for _ in 0..n {
            v = (v << 1) | self.read_bit()?;
        }
        Some(v)
    }

    /// Unsigned Exp-Golomb, `ue(v)`. `None` on a truncated or absurd code —
    /// never a panic, since this parses attacker-adjacent encoder output.
    fn ue(&mut self) -> Option<u32> {
        let mut leading = 0u32;
        while self.read_bit()? == 0 {
            leading += 1;
            if leading > 31 {
                return None;
            }
        }
        if leading == 0 {
            return Some(0);
        }
        let rest = self.read_bits(leading)?;
        Some((1u32 << leading) - 1 + rest)
    }
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
    fn sps_profile_idc_reads_the_first_sps() {
        // SPS (0x67) first: profile_idc 100 = High.
        assert_eq!(sps_profile_idc(&[0, 0, 0, 1, 0x67, 100, 0xC0]), Some(100));
        // 3-byte start code, Main.
        assert_eq!(sps_profile_idc(&[0, 0, 1, 0x67, 77, 0xC0]), Some(77));
    }

    #[test]
    fn sps_profile_idc_skips_a_leading_slice() {
        let buf = [0, 0, 0, 1, 0x65, 0xAA, 0xBB, 0, 0, 0, 1, 0x67, 66, 0xC0];
        assert_eq!(sps_profile_idc(&buf), Some(66));
    }

    #[test]
    fn sps_profile_idc_without_an_sps_is_none() {
        // PPS (0x68) and an IDR slice (0x65), but no SPS.
        let buf = [0, 0, 0, 1, 0x68, 0xCE, 0, 0, 0, 1, 0x65, 0x88];
        assert_eq!(sps_profile_idc(&buf), None);
        assert_eq!(sps_profile_idc(&[]), None);
    }

    #[test]
    fn sps_profile_idc_truncated_after_nal_header_is_none() {
        // Buffer ends exactly on the NAL header byte: must be None, not a panic.
        assert_eq!(sps_profile_idc(&[0, 0, 0, 1, 0x67]), None);
        assert_eq!(sps_profile_idc(&[0, 0, 1, 0x67]), None);
    }

    #[test]
    fn profile_ladder_prefers_high_then_main() {
        assert_eq!(PROFILE_LADDER[0].1, "High");
        assert_eq!(PROFILE_LADDER[0].0, 100);
        assert_eq!(PROFILE_LADDER[PROFILE_LADDER.len() - 1].1, "Main");
        assert_eq!(PROFILE_LADDER[PROFILE_LADDER.len() - 1].0, 77);
    }

    /// The regression test for "hardcoding High kills the pipeline": whatever
    /// this machine's encoder is, if it builds at all it must have settled on a
    /// real profile rather than failing negotiation outright.
    #[cfg(windows)]
    #[test]
    fn built_encoder_reports_a_negotiated_profile() {
        let Ok(enc) = MfH264Encoder::new(EncoderConfig::default(), None) else {
            // CI may have no usable H.264 MFT and no Media Foundation startup.
            // Nothing to assert; a missing encoder is not this test's subject.
            return;
        };
        let d = enc.describe();
        assert!(
            d.contains("High") || d.contains("Main"),
            "describe() must name the negotiated profile, got: {d}"
        );
    }

    /// Synthetic SPS: `profile_idc`, a constraint byte, `level_idc`, then the
    /// bit-packed `ue(seq_parameter_set_id) ue(chroma_format_idc)`.
    fn synthetic_sps(profile_idc: u8, packed: u8) -> Vec<u8> {
        vec![0, 0, 0, 1, 0x67, profile_idc, 0x00, 0x28, packed, 0x00]
    }

    #[test]
    fn chroma_format_idc_reads_the_extension() {
        // ue(0)="1", then ue(1)="010"  -> 1 010 0000
        let c420 = sps_chroma_format_idc(&synthetic_sps(100, 0b1010_0000));
        assert_eq!(c420, Some(1));
        // ue(0)="1", then ue(0)="1"    -> 11 000000
        let mono = sps_chroma_format_idc(&synthetic_sps(244, 0b1100_0000));
        assert_eq!(mono, Some(0));
        // ue(0)="1", then ue(3)="00100" -> 1 00100 00
        let c444 = sps_chroma_format_idc(&synthetic_sps(244, 0b1001_0000));
        assert_eq!(c444, Some(3));
    }

    /// The point of the whole function: High 4:4:4 in the profile field does not
    /// mean 4:4:4 on the wire.
    #[test]
    fn profile_244_can_still_be_420() {
        let sps = synthetic_sps(244, 0b1010_0000);
        assert_eq!(sps_profile_idc(&sps), Some(244));
        assert_eq!(sps_chroma_format_idc(&sps), Some(1));
    }

    #[test]
    fn chroma_format_idc_is_implied_420_below_high() {
        // Main and Baseline do not carry the field; 4:2:0 is fixed by the spec,
        // so the payload bits after level_idc are irrelevant.
        assert_eq!(sps_chroma_format_idc(&synthetic_sps(77, 0xFF)), Some(1));
        assert_eq!(sps_chroma_format_idc(&synthetic_sps(66, 0x00)), Some(1));
    }

    #[test]
    fn chroma_format_idc_without_an_sps_is_none() {
        assert_eq!(sps_chroma_format_idc(&[0, 0, 0, 1, 0x68, 0xCE]), None);
        assert_eq!(sps_chroma_format_idc(&[]), None);
        // Truncated right after the NAL header, and after level_idc.
        assert_eq!(sps_chroma_format_idc(&[0, 0, 0, 1, 0x67]), None);
        let cut_after_level = sps_chroma_format_idc(&[0, 0, 0, 1, 0x67, 100, 0, 0x28]);
        assert_eq!(cut_after_level, None);
    }

    #[test]
    fn sps_payload_drops_emulation_prevention_bytes() {
        assert_eq!(unescape_rbsp(&[0, 0, 3, 1, 2]), vec![0, 0, 1, 2]);
        // 0x03 not preceded by two zeros is ordinary data.
        assert_eq!(unescape_rbsp(&[0, 3, 1]), vec![0, 3, 1]);
    }

    #[test]
    fn sps_payload_stops_at_the_next_nal() {
        let buf = [0, 0, 0, 1, 0x67, 100, 0, 0x28, 0xA0, 0, 0, 0, 1, 0x68, 0xCE];
        let rbsp = first_sps_rbsp(&buf).expect("sps present");
        assert_eq!(rbsp, vec![100, 0, 0x28, 0xA0]);
    }

    #[test]
    fn exp_golomb_matches_the_spec_table() {
        let mut r = BitReader::new(&[0b1010_0110, 0b0101_0000]);
        assert_eq!(r.ue(), Some(0)); // 1
        assert_eq!(r.ue(), Some(1)); // 010
        assert_eq!(r.ue(), Some(2)); // 011
        assert_eq!(r.ue(), Some(4)); // 00101
                                     // Nothing but zero bits left: truncated, not a panic.
        assert_eq!(r.ue(), None);
    }

    #[test]
    fn peak_is_one_and_a_half_times_the_mean() {
        assert_eq!(peak_bitrate_bps(12_000_000), 18_000_000);
        assert_eq!(peak_bitrate_bps(1_500_000), 2_250_000);
        assert_eq!(peak_bitrate_bps(0), 0);
        // The 3x multiply must not wrap at the top of the u32 range.
        assert_eq!(peak_bitrate_bps(u32::MAX), u32::MAX);
    }

    #[test]
    fn refinement_quality_clamps_into_the_permitted_band() {
        // Nothing a config file can say escapes the band — including 0, which
        // means "disabled" upstream and must never reach here as a QP of 26+.
        assert_eq!(refine_settings(0).quality, MIN_STATIC_REFINE_QUALITY);
        assert_eq!(refine_settings(u32::MAX).quality, MAX_STATIC_REFINE_QUALITY);
        assert_eq!(refine_settings(70).quality, 70);
    }

    #[test]
    fn refinement_qp_is_bounded_at_both_ends() {
        // The floor is the cost bound: no quality level may ask for a finer
        // quantizer, because an intra frame below it stops fitting the
        // fragmenter (see session::STATIC_REFINE_MAX_BYTES).
        for q in 0..=120u32 {
            let s = refine_settings(q);
            assert!(s.min_qp >= REFINE_QP_FLOOR, "q={q} min_qp={}", s.min_qp);
            assert!(s.min_qp <= REFINE_QP_CEILING, "q={q} min_qp={}", s.min_qp);
            assert!(s.max_qp >= s.min_qp, "q={q}");
            assert!(s.max_qp <= TEXT_QUALITY_FLOOR_MAX_QP, "q={q}");
        }
        assert_eq!(
            refine_settings(MAX_STATIC_REFINE_QUALITY).min_qp,
            REFINE_QP_FLOOR
        );
        assert_eq!(
            refine_settings(MIN_STATIC_REFINE_QUALITY).min_qp,
            REFINE_QP_CEILING
        );
    }

    #[test]
    fn refinement_qp_falls_monotonically_with_quality() {
        // Asking for more quality may never produce a coarser frame.
        let mut prev = u32::MAX;
        for q in MIN_STATIC_REFINE_QUALITY..=MAX_STATIC_REFINE_QUALITY {
            let qp = refine_settings(q).min_qp;
            assert!(qp <= prev, "q={q}: {qp} > {prev}");
            prev = qp;
        }
    }

    #[test]
    fn refinement_is_strictly_better_than_the_streaming_floor() {
        // If the refinement window were not below the streaming path's worst
        // allowed QP, the whole feature would be a no-op.
        let s = refine_settings(DEFAULT_STATIC_REFINE_QUALITY);
        assert!(s.min_qp < TEXT_QUALITY_FLOOR_MAX_QP);
        assert!(s.max_qp < TEXT_QUALITY_FLOOR_MAX_QP);
    }

    // The shipped default must itself be expressible; checked at compile time
    // because it is a relation between constants.
    const _: () = assert!(DEFAULT_STATIC_REFINE_QUALITY <= MAX_STATIC_REFINE_QUALITY);
    const _: () = assert!(DEFAULT_STATIC_REFINE_QUALITY >= MIN_STATIC_REFINE_QUALITY);
    const _: () = assert!(MIN_STATIC_REFINE_QUALITY < MAX_STATIC_REFINE_QUALITY);

    // 51 is the H.264 maximum; a floor at or above it would be inert.
    const _: () = assert!(TEXT_QUALITY_FLOOR_MAX_QP < 51);
    const _: () = assert!(TEXT_QUALITY_FLOOR_MAX_QP > 0);

    #[test]
    fn encoder_path_labels_are_honest() {
        assert!(!EncoderPath::Software.is_hardware());
        assert!(EncoderPath::Software.label().contains("SOFTWARE"));
        assert!(EncoderPath::HardwareSameAdapter.is_hardware());
    }

    /// The demotion ladder, without COM.
    ///
    /// Full activation cannot be exercised headlessly — it needs a real MFT, a
    /// D3D device and an apartment — but the ladder's *rules* are ordinary
    /// control flow, and they are the part that kills a stream when they are
    /// wrong. `first_usable` exists as a seam precisely so these can be pinned
    /// down: a fake candidate is a name and a yes/no, and the tests assert what
    /// was attempted, in what order, and what was released afterwards.
    mod ladder {
        use super::super::{first_usable, EncoderPath};
        use directdesk_shared::{Error, Result};
        use std::cell::RefCell;

        /// One fake MFT. `works == false` means "refused activation", which is
        /// what an out-of-NVENC-sessions vendor encoder looks like from here.
        struct Candidate {
            name: &'static str,
            works: bool,
        }

        fn hw(name: &'static str, works: bool) -> (Candidate, EncoderPath) {
            (Candidate { name, works }, EncoderPath::HardwareSameAdapter)
        }

        fn sw(name: &'static str, works: bool) -> (Candidate, EncoderPath) {
            (Candidate { name, works }, EncoderPath::Software)
        }

        type Walk = (
            Result<(&'static str, EncoderPath)>,
            Vec<&'static str>,
            Vec<&'static str>,
        );

        /// Run the ladder and report what it did: the result, the candidates it
        /// attempted in order, and the candidates it discarded in order.
        fn walk(candidates: Vec<(Candidate, EncoderPath)>) -> Walk {
            let attempted = RefCell::new(Vec::new());
            let discarded = RefCell::new(Vec::new());
            let out = first_usable(
                candidates,
                |c: &Candidate| c.name.to_string(),
                |c: &Candidate, path, name| {
                    // The name the ladder logs and the name the builder sees
                    // must be the same string, or a demotion warning points at
                    // the wrong encoder.
                    assert_eq!(name, c.name, "builder got a different name");
                    attempted.borrow_mut().push(c.name);
                    if c.works {
                        Ok((c.name, path))
                    } else {
                        Err(Error::Encoder(format!("{} is already in use", c.name)))
                    }
                },
                |c: &Candidate| discarded.borrow_mut().push(c.name),
            );
            (out, attempted.into_inner(), discarded.into_inner())
        }

        #[test]
        fn the_first_working_candidate_wins_and_nothing_below_it_is_touched() {
            let (out, attempted, discarded) =
                walk(vec![hw("nvenc", true), hw("qsv", true), sw("ms", true)]);
            let (name, path) = out.expect("the first candidate builds");
            assert_eq!(name, "nvenc");
            assert_eq!(path, EncoderPath::HardwareSameAdapter);
            assert_eq!(
                attempted,
                vec!["nvenc"],
                "the ladder must stop dead at the first Ok"
            );
            assert!(
                discarded.is_empty(),
                "a candidate that worked is never shut down"
            );
        }

        /// The T-nvenc case in miniature: the consumer GPU is out of NVENC
        /// sessions, so both hardware entries refuse and the software SYNCMFT
        /// has to carry the second monitor. `new()` must NOT fail here.
        #[test]
        fn exhausted_hardware_demotes_all_the_way_to_software() {
            let (out, attempted, discarded) = walk(vec![
                hw("nvenc (capture adapter)", false),
                hw("nvenc (any adapter)", false),
                sw("ms software", true),
            ]);
            let (name, path) = out.expect("software must catch the fall");
            assert_eq!(name, "ms software");
            assert_eq!(path, EncoderPath::Software);
            assert_eq!(
                attempted,
                vec![
                    "nvenc (capture adapter)",
                    "nvenc (any adapter)",
                    "ms software"
                ]
            );
            assert_eq!(
                discarded,
                vec!["nvenc (capture adapter)", "nvenc (any adapter)"],
                "every failed activation is released, and only those"
            );
        }

        /// Activation can fail at ActivateObject, at media-type negotiation, at
        /// the D3D attach or at BEGIN_STREAMING; from the ladder's side those
        /// are indistinguishable, so what matters is that a refusal at ANY
        /// position keeps walking instead of aborting.
        #[test]
        fn a_refusal_at_any_position_demotes_rather_than_aborting() {
            const NAMES: [&str; 3] = ["first", "second", "third"];
            for good in 0..NAMES.len() {
                let list = NAMES
                    .into_iter()
                    .enumerate()
                    .map(|(i, n)| hw(n, i == good))
                    .collect::<Vec<_>>();
                let (out, attempted, discarded) = walk(list);
                assert_eq!(
                    out.expect("one candidate works").0,
                    NAMES[good],
                    "working candidate at index {good} was not selected"
                );
                assert_eq!(attempted, NAMES[..=good].to_vec(), "good={good}");
                assert_eq!(discarded, NAMES[..good].to_vec(), "good={good}");
            }
        }

        #[test]
        fn an_exhausted_ladder_reports_the_count_and_the_last_reason() {
            let (out, attempted, discarded) = walk(vec![hw("nvenc", false), sw("ms", false)]);
            let msg = out.err().expect("nothing usable").to_string();
            assert!(msg.contains('2'), "must say how many were tried: {msg}");
            assert!(
                msg.contains("ms is already in use"),
                "must carry the last reason: {msg}"
            );
            // A non-Encoder error would be passed through unwrapped; ours is an
            // Encoder error, so the message must not be doubly prefixed.
            assert_eq!(
                msg.matches("encoder: ").count(),
                1,
                "nested Error::Encoder prefixes: {msg}"
            );
            assert_eq!(attempted, vec!["nvenc", "ms"]);
            assert_eq!(discarded, vec!["nvenc", "ms"]);
        }

        #[test]
        fn no_candidates_at_all_is_its_own_diagnosis() {
            let err = first_usable::<Candidate, ()>(
                Vec::new(),
                |c| c.name.to_string(),
                |_, _, _| Ok(()),
                |_| unreachable!("nothing was activated, so nothing can be discarded"),
            )
            .err()
            .expect("an empty list cannot produce an encoder");
            let msg = err.to_string();
            assert!(msg.contains("of any kind is registered"), "{msg}");
            // Distinct from the exhausted-ladder message: "none registered" and
            // "all refused" are different faults with different fixes.
            assert!(!msg.contains("refused"), "{msg}");
        }
    }
}
