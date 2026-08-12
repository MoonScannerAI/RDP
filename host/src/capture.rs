//! Desktop Duplication API screen capture.
//!
//! [`DdaCapture`] duplicates the *primary* monitor and creates its D3D11 device
//! on whichever adapter actually owns that output. On this class of hybrid-GPU
//! laptop the panel is usually wired to the iGPU, so the captured texture lives
//! on the Intel device — never assume the discrete GPU. The adapter LUID we
//! record here is what [`crate::mf_encoder`] uses to pick a matching encoder MFT.
//!
//! Two consumption paths are offered:
//!
//! * [`DdaCapture::acquire`] — GPU-native. Returns a [`GpuFrame`] holding a
//!   BGRA `ID3D11Texture2D` owned by us (the DDA frame is released immediately
//!   after a `CopyResource`, as the API requires).
//! * `impl FrameSource` — contract-conformant. Stages the same texture back to
//!   system memory as tightly-packed BGRA. Slower; used for tests and for the
//!   CPU fallback pipeline.

use std::time::{Duration, Instant};

use directdesk_shared::protocol::{MonitorInfo, MAX_MONITORS};
use directdesk_shared::traits::{FrameSource, PixelFormat, RawFrame};
use directdesk_shared::{Error, Result};
use windows::core::Interface;
use windows::Win32::Foundation::{E_ACCESSDENIED, HMODULE, POINT, RECT};
use windows::Win32::Graphics::Direct3D::{
    D3D_DRIVER_TYPE_UNKNOWN, D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_11_1,
};
use windows::Win32::Graphics::Direct3D11::{
    D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Multithread, ID3D11Texture2D,
    D3D11_BIND_RENDER_TARGET, D3D11_BIND_SHADER_RESOURCE, D3D11_CPU_ACCESS_READ,
    D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_CREATE_DEVICE_VIDEO_SUPPORT, D3D11_MAPPED_SUBRESOURCE,
    D3D11_MAP_READ, D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC, D3D11_USAGE_DEFAULT,
    D3D11_USAGE_STAGING,
};
use windows::Win32::Graphics::Dxgi::Common::{DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_SAMPLE_DESC};
use windows::Win32::Graphics::Dxgi::{
    CreateDXGIFactory1, IDXGIAdapter1, IDXGIFactory1, IDXGIOutput1, IDXGIOutputDuplication,
    IDXGIResource, DXGI_ERROR_ACCESS_LOST, DXGI_ERROR_INVALID_CALL, DXGI_ERROR_MORE_DATA,
    DXGI_ERROR_NOT_FOUND, DXGI_ERROR_SESSION_DISCONNECTED, DXGI_ERROR_UNSUPPORTED,
    DXGI_ERROR_WAIT_TIMEOUT, DXGI_OUTDUPL_FRAME_INFO, DXGI_OUTDUPL_MOVE_RECT, DXGI_OUTPUT_DESC,
};
use windows::Win32::Graphics::Gdi::{MonitorFromPoint, HMONITOR, MONITOR_DEFAULTTOPRIMARY};
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, OpenInputDesktop, DESKTOP_CONTROL_FLAGS, DESKTOP_READOBJECTS,
};
use windows::Win32::UI::HiDpi::{
    SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
};

/// Opt the process into Per-Monitor-V2 DPI awareness.
///
/// This is not cosmetic. A DPI-*unaware* process sees DXGI's virtualized
/// desktop coordinates — a 2560x1600 panel at 150% scaling reports 1707x1067,
/// which is both wrong and *odd*, and NV12 (4:2:0) cannot represent odd
/// dimensions at all. Relying on a linker manifest makes capture geometry
/// depend on how the binary was built, so we assert it in code instead.
///
/// Safe to call repeatedly and from any thread; a failure means awareness was
/// already set (by a manifest or an earlier call), which is fine.
pub fn set_process_dpi_aware() -> bool {
    // SAFETY: plain FFI with a documented constant; no out params.
    unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2).is_ok() }
}

/// Identity of the GPU that owns the duplicated output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterInfo {
    /// Adapter LUID packed as `(HighPart << 32) | LowPart` — the exact form the
    /// `MFT_ENUM_ADAPTER_LUID` attribute wants.
    pub luid: u64,
    pub name: String,
    pub vendor_id: u32,
    pub device_id: u32,
    /// Device name of the duplicated output, e.g. `\\.\DISPLAY1`.
    pub output_name: String,
    /// Top-left of the output in virtual-desktop coordinates.
    pub origin: (i32, i32),
}

impl AdapterInfo {
    pub fn short(&self) -> String {
        format!("{} [{}]", self.name, self.output_name)
    }
}

/// Stable identity for one output within a session (per-boot stable; survives
/// duplication rebuilds and DISPLAYn renumbering via the luid+origin tie-break).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorKey {
    pub adapter_luid: u64,
    /// e.g. `\\.\DISPLAY2` — the primary match key.
    pub device_name: String,
    /// Top-left of the output in virtual-desktop coordinates — tie-breaker.
    pub origin: (i32, i32),
}

/// Which output [`DdaCapture::new`] should duplicate.
#[derive(Debug, Clone)]
pub enum MonitorSelector {
    /// Today's behavior: the output whose `HMONITOR` matches
    /// `MonitorFromPoint(_, MONITOR_DEFAULTTOPRIMARY)`, falling back to the
    /// first desktop-attached output if none matches.
    Primary,
    /// A specific output, addressed by its [`MonitorKey`].
    Key(MonitorKey),
}

/// A captured desktop image still resident on the GPU.
pub struct GpuFrame {
    /// BGRA8 texture owned by [`DdaCapture`]; contents are overwritten on the
    /// next successful [`DdaCapture::acquire`].
    pub texture: ID3D11Texture2D,
    pub width: u32,
    pub height: u32,
    /// Monotonic ms since capture start (wraps, matching the wire contract).
    pub timestamp_ms: u32,
    /// True when this is a re-emission of the previous image because the
    /// desktop did not change within `repeat_after`.
    pub repeated: bool,
    /// Regions changed since the previously emitted frame — **or `None`**.
    ///
    /// `None` and `Some(vec![])` mean opposite things and must never be
    /// collapsed into "no rects":
    ///
    /// * `None` — *we cannot tell.* Either DXGI refused the metadata query, or
    ///   the duplication was just rebuilt and its change history no longer
    ///   describes the image we are handing out. **Treat the entire surface as
    ///   changed.** Anything that caches per-region state — static-region
    ///   refinement, tile hashing, damage-driven encoding — must invalidate
    ///   everything on `None`. Reading `None` as "static" is how stale pixels
    ///   get painted over a screen that really did change, and a transient
    ///   driver hiccup is enough to trigger it.
    /// * `Some(rects)` — DXGI answered, and the answer is complete. An empty
    ///   vec genuinely means *nothing* changed, so a region may safely be
    ///   marked settled.
    ///
    /// A repeat frame (`repeated == true`) carries `Some(vec![])`: it is a
    /// byte-identical re-emission of the image already sent, so the delta
    /// really is empty.
    pub dirty_rects: Option<Vec<RECT>>,
    /// Scroll/blit regions DXGI reported for this frame, under exactly the same
    /// `None`-vs-`Some(vec![])` contract as [`Self::dirty_rects`]. The two lists
    /// come from the same per-frame metadata block and fail together.
    pub move_rects: Option<Vec<DXGI_OUTDUPL_MOVE_RECT>>,
    /// DDA's count of coalesced desktop updates.
    pub accumulated_frames: u32,
}

/// Why capture is currently unavailable, when it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureState {
    Running,
    /// Secure desktop (UAC / lock screen / Ctrl-Alt-Del). Confirmed by
    /// `OpenInputDesktop` failing in addition to DDA returning `E_ACCESSDENIED`.
    SecureDesktop,
    /// Duplication was invalidated (mode change, GPU switch, fullscreen app).
    /// The next `acquire` transparently rebuilds it.
    NeedsRecreate,
}

/// Whether the capture loop should be paused for `state`, and the label to
/// pause it under.
///
/// This is the ONE definition of "does this `CaptureState` mean the session
/// is paused, and what is it paused as." `session.rs` calls it from both the
/// `Ok(None)` arm of `acquire` (where `capture.state()` is read directly) and
/// the `Err(Error::Capture(_))` arm (where it is read the same way — `state`
/// is always assigned before `acquire`/`recreate_duplication` return an
/// error, so it is authoritative there too). Before this existed, the `Err`
/// arm instead string-matched the error text for the literal `"secure
/// desktop"`, which made a purely cosmetic rename of that error message
/// capable of silently breaking pause/resume. Routing both arms through this
/// function removes that trap: nothing outside here inspects error text to
/// decide the pause reason, and the returned label is the one and only
/// `"secure desktop"` constant, which downstream code (the `Paused` state,
/// `ControlMsg::SecureDesktopActive`) still keys off exactly as before.
///
/// The match is written exhaustively, without a wildcard arm, so adding a
/// future `CaptureState` variant forces a conscious decision here instead of
/// silently falling through to "don't pause".
#[must_use]
pub fn pause_reason(state: CaptureState) -> Option<&'static str> {
    match state {
        CaptureState::SecureDesktop => Some("secure desktop"),
        CaptureState::Running | CaptureState::NeedsRecreate => None,
    }
}

pub struct DdaCapture {
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    adapter: IDXGIAdapter1,
    output: IDXGIOutput1,
    dupl: Option<IDXGIOutputDuplication>,
    /// Our private BGRA copy of the most recent desktop image.
    tex: ID3D11Texture2D,
    /// Lazily created readback texture for the `FrameSource` path.
    staging: Option<ID3D11Texture2D>,
    width: u32,
    height: u32,
    info: AdapterInfo,
    state: CaptureState,
    epoch: Instant,
    /// When the next idle re-emission becomes due. Advanced on a fixed cadence
    /// so downstream cost never inflates the repeat interval.
    next_emit: Option<Instant>,
    have_image: bool,
    /// Re-emit the last image if the desktop has been idle this long. Keeps the
    /// encoder and downstream stats alive on a static screen. Default 33 ms.
    repeat_after: Duration,
    /// Reused destination for `GetFrameDirtyRects`. Typed as `RECT` rather than
    /// bytes so the fill call cannot hand DXGI an under-aligned buffer.
    dirty_scratch: Vec<RECT>,
    recreate_backoff: Option<Instant>,
    /// Set every time duplication is (re)built. A fresh `IDXGIOutputDuplication`
    /// has no memory of what the *previous* one had already shown the client, so
    /// its first frame's dirty rects describe a delta against an image nobody
    /// ever saw. The next real frame therefore reports `dirty_rects: None`
    /// ("assume everything changed") instead of DXGI's misleading answer.
    force_full_dirty: bool,
}

impl DdaCapture {
    /// Duplicate the output `selector` picks, creating the D3D11 device on its
    /// adapter.
    ///
    /// With [`MonitorSelector::Primary`] this reproduces the pre-multi-monitor
    /// behavior exactly: same enumeration walk, same `AttachedToDesktop`
    /// filter, same primary-`HMONITOR` match with the same first-attached
    /// fallback. See [`resolve_output`] and [`select_output`].
    pub fn new(selector: &MonitorSelector) -> Result<Self> {
        // Must happen before we ask DXGI for any geometry.
        set_process_dpi_aware();
        let (adapter, output, info) = resolve_output(selector)?;
        let (device, context) = create_device(&adapter)?;

        let desc = unsafe { output.GetDesc() }.map_err(cap_err("IDXGIOutput::GetDesc"))?;
        let width = (desc.DesktopCoordinates.right - desc.DesktopCoordinates.left).unsigned_abs();
        let height = (desc.DesktopCoordinates.bottom - desc.DesktopCoordinates.top).unsigned_abs();
        if width == 0 || height == 0 {
            return Err(Error::Capture("primary output reports zero size".into()));
        }

        let tex = create_bgra_texture(&device, width, height)?;
        tracing::info!(
            luid = format!("{:#x}", info.luid),
            vendor = format!("{:#06x}", info.vendor_id),
            "capturing {} at {width}x{height} on adapter \"{}\" (origin {:?})",
            info.output_name,
            info.name,
            info.origin
        );

        let mut me = Self {
            device,
            context,
            adapter,
            output,
            dupl: None,
            tex,
            staging: None,
            width,
            height,
            info,
            state: CaptureState::NeedsRecreate,
            epoch: Instant::now(),
            next_emit: None,
            have_image: false,
            repeat_after: Duration::from_millis(33),
            dirty_scratch: Vec::new(),
            recreate_backoff: None,
            // No duplication exists yet, so nothing has been shown to anyone:
            // the first frame we ever emit is by definition a full update.
            force_full_dirty: true,
        };
        // Best-effort: a failure here is recoverable and retried in acquire().
        if let Err(e) = me.recreate_duplication() {
            tracing::warn!("initial DuplicateOutput failed, will retry: {e}");
        }
        Ok(me)
    }

    pub fn adapter_info(&self) -> &AdapterInfo {
        &self.info
    }

    pub fn state(&self) -> CaptureState {
        self.state
    }

    pub fn device(&self) -> &ID3D11Device {
        &self.device
    }

    pub fn context(&self) -> &ID3D11DeviceContext {
        &self.context
    }

    /// The DXGI adapter that owns the duplicated output. Held for the lifetime
    /// of the capture so the device and duplication stay valid.
    pub fn adapter(&self) -> &IDXGIAdapter1 {
        &self.adapter
    }

    /// Idle re-emission interval. `Duration::MAX` disables repeats entirely.
    pub fn set_repeat_after(&mut self, d: Duration) {
        self.repeat_after = d;
    }

    /// Acquire the next desktop image.
    ///
    /// * `Ok(Some(frame))` — a new (or deliberately repeated) image.
    /// * `Ok(None)` — nothing to send this interval, or duplication is being
    ///   rebuilt, or we are on the secure desktop (check [`Self::state`]).
    pub fn acquire(&mut self, timeout_ms: u32) -> Result<Option<GpuFrame>> {
        if self.dupl.is_none() {
            if let Some(until) = self.recreate_backoff {
                if Instant::now() < until {
                    return Ok(None);
                }
            }
            match self.recreate_duplication() {
                Ok(()) => {}
                Err(e) => {
                    // Secure desktop is an expected, transient state — not a
                    // hard error. Anything else backs off and retries too, but
                    // is surfaced to the caller.
                    self.recreate_backoff = Some(Instant::now() + Duration::from_millis(200));
                    if self.state == CaptureState::SecureDesktop {
                        return Ok(None);
                    }
                    return Err(e);
                }
            }
        }

        let dupl = self.dupl.clone().expect("duplication present");
        let mut frame_info = DXGI_OUTDUPL_FRAME_INFO::default();
        let mut resource: Option<IDXGIResource> = None;

        // SAFETY: `dupl` is a live duplication for this device; both out params
        // are valid for the call and `resource` is released via RAII below.
        let acquired = unsafe { dupl.AcquireNextFrame(timeout_ms, &mut frame_info, &mut resource) };

        match acquired {
            Ok(()) => {}
            Err(e) if e.code() == DXGI_ERROR_WAIT_TIMEOUT => {
                return Ok(self.maybe_repeat());
            }
            Err(e)
                if e.code() == DXGI_ERROR_ACCESS_LOST
                    || e.code() == DXGI_ERROR_INVALID_CALL
                    || e.code() == DXGI_ERROR_SESSION_DISCONNECTED =>
            {
                tracing::info!("duplication lost ({:?}), recreating", e.code());
                self.drop_duplication(CaptureState::NeedsRecreate);
                return Ok(None);
            }
            Err(e) if e.code() == E_ACCESSDENIED => {
                self.drop_duplication(if secure_desktop_active() {
                    CaptureState::SecureDesktop
                } else {
                    CaptureState::NeedsRecreate
                });
                if self.state == CaptureState::SecureDesktop {
                    // The exact wording here is no longer load-bearing: callers
                    // decide the pause reason from `self.state` (already set
                    // above) via `pause_reason`, not by parsing this string.
                    return Err(Error::Capture(
                        "AcquireNextFrame: access denied on the secure desktop".into(),
                    ));
                }
                return Ok(None);
            }
            Err(e) => {
                self.drop_duplication(CaptureState::NeedsRecreate);
                return Err(Error::Capture(format!("AcquireNextFrame: {e}")));
            }
        }

        // Whatever happens below, the DDA frame must be released before the next
        // AcquireNextFrame. Guard it so early returns cannot leak it.
        let _release = ReleaseGuard(&dupl);

        let new_image = frame_info.LastPresentTime != 0 || frame_info.AccumulatedFrames > 0;
        if !new_image {
            // Pointer-only update. No pixels changed.
            drop(_release);
            return Ok(self.maybe_repeat());
        }

        let resource = match resource {
            Some(r) => r,
            None => {
                drop(_release);
                return Ok(self.maybe_repeat());
            }
        };
        let src: ID3D11Texture2D = resource
            .cast()
            .map_err(cap_err("desktop resource is not an ID3D11Texture2D"))?;

        // SAFETY: same device, identical BGRA descs — a straight full-surface copy.
        unsafe { self.context.CopyResource(&self.tex, &src) };

        // Read the metadata even when we are about to discard it: both queries
        // must be issued before ReleaseFrame, and issuing them keeps the driver
        // on the same code path frame to frame.
        let mut dirty_rects = self.read_dirty_rects(&dupl);
        let mut move_rects = self.read_move_rects(&dupl);
        if self.force_full_dirty {
            // First frame after a (re)build — see `force_full_dirty`.
            dirty_rects = None;
            move_rects = None;
            self.force_full_dirty = false;
        }

        drop(_release);

        self.have_image = true;
        self.state = CaptureState::Running;
        let now = Instant::now();
        // Real content resets the idle clock: no repeat is needed for a while.
        self.next_emit = None;
        self.schedule_next(now);

        Ok(Some(GpuFrame {
            texture: self.tex.clone(),
            width: self.width,
            height: self.height,
            timestamp_ms: self.elapsed_ms(now),
            repeated: false,
            dirty_rects,
            move_rects,
            accumulated_frames: frame_info.AccumulatedFrames,
        }))
    }

    /// Copy the last acquired GPU image into a tightly-packed BGRA buffer.
    pub fn readback_bgra(&mut self, out: &mut Vec<u8>) -> Result<()> {
        let staging = match &self.staging {
            Some(s) => s.clone(),
            None => {
                let s = create_staging_texture(&self.device, self.width, self.height)?;
                self.staging = Some(s.clone());
                s
            }
        };
        // SAFETY: staging has identical dimensions/format and STAGING usage with
        // CPU read access; Map/Unmap are paired below.
        unsafe {
            self.context.CopyResource(&staging, &self.tex);
            let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
            self.context
                .Map(&staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))
                .map_err(cap_err("Map(staging)"))?;
            let row_bytes = self.width as usize * 4;
            out.clear();
            out.reserve(row_bytes * self.height as usize);
            let base = mapped.pData as *const u8;
            for y in 0..self.height as usize {
                let row = base.add(y * mapped.RowPitch as usize);
                out.extend_from_slice(std::slice::from_raw_parts(row, row_bytes));
            }
            self.context.Unmap(&staging, 0);
        }
        Ok(())
    }

    fn maybe_repeat(&mut self) -> Option<GpuFrame> {
        if !self.have_image {
            return None;
        }
        let now = Instant::now();
        if self.next_emit.is_some_and(|t| now < t) {
            return None;
        }
        self.schedule_next(now);
        Some(GpuFrame {
            texture: self.tex.clone(),
            width: self.width,
            height: self.height,
            timestamp_ms: self.elapsed_ms(now),
            repeated: true,
            // A repeat re-sends the exact image already emitted, so "nothing
            // changed" is a fact we know first-hand — not a DXGI answer we
            // failed to get. `Some(vec![])`, never `None`.
            dirty_rects: Some(Vec::new()),
            move_rects: Some(Vec::new()),
            accumulated_frames: 0,
        })
    }

    fn elapsed_ms(&self, now: Instant) -> u32 {
        now.duration_since(self.epoch).as_millis() as u32
    }

    /// Advance the idle-repeat deadline on a fixed cadence.
    ///
    /// Scheduling from a running deadline rather than "now + interval" keeps the
    /// repeat rate at the configured value instead of `interval + however long
    /// convert/encode took`, which otherwise silently drags idle throughput well
    /// below target. Resyncs to `now` if we have fallen a whole interval behind.
    fn schedule_next(&mut self, now: Instant) {
        if self.repeat_after == Duration::MAX {
            self.next_emit = None;
            return;
        }
        let base = self.next_emit.unwrap_or(now);
        let mut next = base + self.repeat_after;
        if next <= now {
            next = now + self.repeat_after;
        }
        self.next_emit = Some(next);
    }

    fn drop_duplication(&mut self, state: CaptureState) {
        self.dupl = None;
        self.state = state;
        self.recreate_backoff = Some(Instant::now() + Duration::from_millis(150));
    }

    fn recreate_duplication(&mut self) -> Result<()> {
        // SAFETY: `output` and `device` outlive the duplication we store.
        let dupl = unsafe { self.output.DuplicateOutput(&self.device) };
        match dupl {
            Ok(d) => {
                self.dupl = Some(d);
                self.state = CaptureState::Running;
                self.recreate_backoff = None;
                // The new duplication's dirty-rect history starts from *its*
                // first frame, not from the last image we emitted. Force the
                // next frame to declare a full update.
                self.force_full_dirty = true;
                Ok(())
            }
            Err(e) if e.code() == E_ACCESSDENIED => {
                self.state = if secure_desktop_active() {
                    CaptureState::SecureDesktop
                } else {
                    CaptureState::NeedsRecreate
                };
                if self.state == CaptureState::SecureDesktop {
                    // Same non-load-bearing wording as the AcquireNextFrame
                    // case above: callers read `self.state` via `pause_reason`,
                    // never this string.
                    Err(Error::Capture(
                        "DuplicateOutput: access denied on the secure desktop".into(),
                    ))
                } else {
                    Err(Error::Capture("DuplicateOutput access denied".into()))
                }
            }
            Err(e) if e.code() == DXGI_ERROR_UNSUPPORTED => {
                self.state = CaptureState::NeedsRecreate;
                Err(Error::Capture(
                    "DuplicateOutput unsupported on this adapter/output".into(),
                ))
            }
            Err(e) => {
                self.state = CaptureState::NeedsRecreate;
                Err(Error::Capture(format!("DuplicateOutput: {e}")))
            }
        }
    }

    /// Read the dirty-rect list for the frame `dupl` currently holds.
    ///
    /// `None` means the query failed and the answer is unknowable; `Some` — even
    /// `Some(vec![])` — means DXGI answered completely. See
    /// [`GpuFrame::dirty_rects`] for why the caller may not merge the two.
    ///
    /// Both DXGI metadata getters take *byte* counts, not rect counts, and use
    /// the standard two-phase "probe then fill" shape. Deciding which probe
    /// outcome is a genuine empty result is the whole point of this function:
    ///
    /// * `Ok` with `needed == 0` — the call succeeded against a zero-byte
    ///   buffer, which it can only do when there was nothing to write.
    ///   Genuinely empty: `Some(vec![])`.
    /// * `DXGI_ERROR_MORE_DATA` — the documented "your buffer is too small"
    ///   reply; `needed` now holds the required size. Not a failure, proceed.
    /// * any other error — the driver would not answer (lost access, invalid
    ///   call, an out-of-contract refusal of the null probe buffer). We have no
    ///   idea what changed, so we must say so.
    ///
    /// The old code returned an empty vec for that last case, which made a
    /// transient driver failure indistinguishable from a static screen.
    fn read_dirty_rects(&mut self, dupl: &IDXGIOutputDuplication) -> Option<Vec<RECT>> {
        let mut needed: u32 = 0;
        // SAFETY: `dupl` holds an acquired frame for the whole of both calls.
        // Phase one passes a null buffer with a matching zero length, which is
        // the documented size-probe form; phase two passes a buffer whose byte
        // length is exactly the `size` argument, correctly aligned for `RECT`
        // because the scratch is a `Vec<RECT>`. `written` is only trusted after
        // the call reports success.
        unsafe {
            match dupl.GetFrameDirtyRects(0, std::ptr::null_mut(), &mut needed) {
                Ok(()) if needed == 0 => return Some(Vec::new()),
                Ok(()) => {}
                // A MORE_DATA that asks for zero bytes is self-contradictory;
                // refuse to guess.
                Err(e) if e.code() == DXGI_ERROR_MORE_DATA && needed > 0 => {}
                Err(e) => {
                    tracing::debug!("GetFrameDirtyRects probe failed ({:?})", e.code());
                    return None;
                }
            }

            // Round up so the buffer we pass is never shorter than `needed`.
            let n = (needed as usize).div_ceil(std::mem::size_of::<RECT>());
            self.dirty_scratch.clear();
            self.dirty_scratch.resize(n, RECT::default());
            let size = (n * std::mem::size_of::<RECT>()) as u32;
            let ptr = self.dirty_scratch.as_mut_ptr();
            let mut written = 0u32;
            if let Err(e) = dupl.GetFrameDirtyRects(size, ptr, &mut written) {
                tracing::debug!("GetFrameDirtyRects fill failed ({:?})", e.code());
                return None;
            }
            let count = (written as usize / std::mem::size_of::<RECT>()).min(n);
            Some(self.dirty_scratch[..count].to_vec())
        }
    }

    /// Move rects for the current frame, under the same `None`-means-unknowable
    /// contract as [`Self::read_dirty_rects`]; see there for the probe reasoning.
    fn read_move_rects(
        &mut self,
        dupl: &IDXGIOutputDuplication,
    ) -> Option<Vec<DXGI_OUTDUPL_MOVE_RECT>> {
        const SZ: usize = std::mem::size_of::<DXGI_OUTDUPL_MOVE_RECT>();
        let mut needed: u32 = 0;
        // SAFETY: identical two-phase query as dirty rects — null buffer with a
        // zero length to probe, then a correctly sized and aligned `Vec`.
        unsafe {
            match dupl.GetFrameMoveRects(0, std::ptr::null_mut(), &mut needed) {
                Ok(()) if needed == 0 => return Some(Vec::new()),
                Ok(()) => {}
                Err(e) if e.code() == DXGI_ERROR_MORE_DATA && needed > 0 => {}
                Err(e) => {
                    tracing::debug!("GetFrameMoveRects probe failed ({:?})", e.code());
                    return None;
                }
            }

            let n = (needed as usize).div_ceil(SZ);
            let mut buf: Vec<DXGI_OUTDUPL_MOVE_RECT> = vec![DXGI_OUTDUPL_MOVE_RECT::default(); n];
            let mut written = 0u32;
            if let Err(e) = dupl.GetFrameMoveRects((n * SZ) as u32, buf.as_mut_ptr(), &mut written)
            {
                tracing::debug!("GetFrameMoveRects fill failed ({:?})", e.code());
                return None;
            }
            buf.truncate((written as usize / SZ).min(n));
            Some(buf)
        }
    }
}

/// Releases a DDA frame on scope exit; DDA requires exactly one `ReleaseFrame`
/// per successful `AcquireNextFrame` before the next acquire.
struct ReleaseGuard<'a>(&'a IDXGIOutputDuplication);

impl Drop for ReleaseGuard<'_> {
    fn drop(&mut self) {
        // SAFETY: paired with a successful AcquireNextFrame on the same object.
        unsafe {
            let _ = self.0.ReleaseFrame();
        }
    }
}

impl FrameSource for DdaCapture {
    fn next_frame(&mut self, timeout_ms: u32) -> Result<Option<RawFrame>> {
        let Some(frame) = self.acquire(timeout_ms)? else {
            return Ok(None);
        };
        let (w, h, ts) = (frame.width, frame.height, frame.timestamp_ms);
        drop(frame);
        let mut data = Vec::new();
        self.readback_bgra(&mut data)?;
        Ok(Some(RawFrame {
            width: w,
            height: h,
            format: PixelFormat::Bgra8,
            data,
            timestamp_ms: ts,
        }))
    }

    fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }
}

// `DdaCapture` owns apartment-threaded-free COM objects created on, and only
// used from, the capture thread. The pipeline moves it to that thread once and
// never shares it.
// SAFETY: no `&self` method is callable concurrently — all methods take `&mut
// self` or return clones of refcounted COM pointers that stay on the thread.
unsafe impl Send for DdaCapture {}

fn secure_desktop_active() -> bool {
    // SAFETY: plain FFI; the returned HDESK is closed on the success path.
    unsafe {
        match OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_READOBJECTS) {
            Ok(h) => {
                let _ = CloseDesktop(h);
                false
            }
            Err(_) => true,
        }
    }
}

fn cap_err(what: &'static str) -> impl Fn(windows::core::Error) -> Error {
    move |e| Error::Capture(format!("{what}: {e}"))
}

fn create_device(adapter: &IDXGIAdapter1) -> Result<(ID3D11Device, ID3D11DeviceContext)> {
    let levels = [D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0];
    let mut device: Option<ID3D11Device> = None;
    let mut context: Option<ID3D11DeviceContext> = None;

    // SAFETY: DRIVER_TYPE_UNKNOWN is mandatory when an explicit adapter is
    // supplied; out params are written only on success.
    unsafe {
        D3D11CreateDevice(
            adapter,
            D3D_DRIVER_TYPE_UNKNOWN,
            HMODULE::default(),
            D3D11_CREATE_DEVICE_BGRA_SUPPORT | D3D11_CREATE_DEVICE_VIDEO_SUPPORT,
            Some(&levels),
            D3D11_SDK_VERSION,
            Some(&mut device),
            None,
            Some(&mut context),
        )
        .map_err(cap_err("D3D11CreateDevice"))?;
    }

    let device = device.ok_or_else(|| Error::Capture("D3D11CreateDevice returned null".into()))?;
    let context =
        context.ok_or_else(|| Error::Capture("D3D11CreateDevice returned null ctx".into()))?;

    // The encoder MFT drives this same device from its own worker threads.
    if let Ok(mt) = device.cast::<ID3D11Multithread>() {
        // SAFETY: plain FFI on a live interface.
        unsafe {
            let _ = mt.SetMultithreadProtected(true);
        }
    }
    Ok((device, context))
}

fn create_bgra_texture(device: &ID3D11Device, w: u32, h: u32) -> Result<ID3D11Texture2D> {
    let desc = D3D11_TEXTURE2D_DESC {
        Width: w,
        Height: h,
        MipLevels: 1,
        ArraySize: 1,
        Format: DXGI_FORMAT_B8G8R8A8_UNORM,
        SampleDesc: DXGI_SAMPLE_DESC {
            Count: 1,
            Quality: 0,
        },
        Usage: D3D11_USAGE_DEFAULT,
        BindFlags: (D3D11_BIND_SHADER_RESOURCE.0 | D3D11_BIND_RENDER_TARGET.0) as u32,
        CPUAccessFlags: 0,
        MiscFlags: 0,
    };
    let mut tex: Option<ID3D11Texture2D> = None;
    // SAFETY: desc is fully initialized; out param written only on success.
    unsafe {
        device
            .CreateTexture2D(&desc, None, Some(&mut tex))
            .map_err(cap_err("CreateTexture2D(bgra)"))?;
    }
    tex.ok_or_else(|| Error::Capture("CreateTexture2D returned null".into()))
}

fn create_staging_texture(device: &ID3D11Device, w: u32, h: u32) -> Result<ID3D11Texture2D> {
    let desc = D3D11_TEXTURE2D_DESC {
        Width: w,
        Height: h,
        MipLevels: 1,
        ArraySize: 1,
        Format: DXGI_FORMAT_B8G8R8A8_UNORM,
        SampleDesc: DXGI_SAMPLE_DESC {
            Count: 1,
            Quality: 0,
        },
        Usage: D3D11_USAGE_STAGING,
        BindFlags: 0,
        CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
        MiscFlags: 0,
    };
    let mut tex: Option<ID3D11Texture2D> = None;
    // SAFETY: as above.
    unsafe {
        device
            .CreateTexture2D(&desc, None, Some(&mut tex))
            .map_err(cap_err("CreateTexture2D(staging)"))?;
    }
    tex.ok_or_else(|| Error::Capture("CreateTexture2D(staging) returned null".into()))
}

/// Plain-data description of one enumerated output — everything
/// [`select_output`] needs to decide between candidates, with no COM types, so
/// the selection policy is constructible and testable without a live DXGI
/// enumeration.
#[derive(Debug, Clone, PartialEq)]
struct CandidateInfo {
    adapter_luid: u64,
    device_name: String,
    origin: (i32, i32),
    width: u32,
    height: u32,
    /// Exact `HMONITOR` match against `MonitorFromPoint(_,
    /// MONITOR_DEFAULTTOPRIMARY)` — the same test `find_primary_output` used
    /// to make pre-refactor.
    is_primary: bool,
}

/// One desktop-attached output discovered by [`enumerate_outputs`], pairing
/// the live COM handles (needed to actually duplicate it) with the plain-data
/// [`CandidateInfo`] (needed to pick it) and the raw [`DXGI_OUTPUT_DESC`]
/// (needed by [`adapter_info`] once a candidate is chosen).
struct EnumeratedOutput {
    adapter: IDXGIAdapter1,
    output: IDXGIOutput1,
    desc: DXGI_OUTPUT_DESC,
    candidate: CandidateInfo,
}

/// Walk every adapter/output pair and collect the desktop-attached ones.
///
/// Same walk and the same `AttachedToDesktop` filter as the pre-refactor
/// `find_primary_output`; the only behavioral difference is that every
/// attached output is collected instead of returning as soon as the primary
/// match is found — selection is now a separate, pure step ([`select_output`]).
fn enumerate_outputs() -> Result<Vec<EnumeratedOutput>> {
    // SAFETY: DXGI enumeration; every call's result is checked before use.
    unsafe {
        let primary: HMONITOR = MonitorFromPoint(POINT { x: 0, y: 0 }, MONITOR_DEFAULTTOPRIMARY);
        let factory: IDXGIFactory1 = CreateDXGIFactory1().map_err(cap_err("CreateDXGIFactory1"))?;

        let mut found = Vec::new();

        let mut ai = 0u32;
        loop {
            let adapter = match factory.EnumAdapters1(ai) {
                Ok(a) => a,
                Err(e) if e.code() == DXGI_ERROR_NOT_FOUND => break,
                Err(e) => return Err(Error::Capture(format!("EnumAdapters1: {e}"))),
            };
            ai += 1;
            let Ok(adapter_desc) = adapter.GetDesc1() else {
                continue;
            };
            let adapter_luid = ((adapter_desc.AdapterLuid.HighPart as u64) << 32)
                | adapter_desc.AdapterLuid.LowPart as u64;

            let mut oi = 0u32;
            loop {
                let output = match adapter.EnumOutputs(oi) {
                    Ok(o) => o,
                    Err(_) => break,
                };
                oi += 1;
                let Ok(out1) = output.cast::<IDXGIOutput1>() else {
                    continue;
                };
                let Ok(desc) = out1.GetDesc() else { continue };
                if !desc.AttachedToDesktop.as_bool() {
                    continue;
                }
                let origin = (desc.DesktopCoordinates.left, desc.DesktopCoordinates.top);
                let width =
                    (desc.DesktopCoordinates.right - desc.DesktopCoordinates.left).unsigned_abs();
                let height =
                    (desc.DesktopCoordinates.bottom - desc.DesktopCoordinates.top).unsigned_abs();
                found.push(EnumeratedOutput {
                    adapter: adapter.clone(),
                    output: out1,
                    desc,
                    candidate: CandidateInfo {
                        adapter_luid,
                        device_name: wide_to_string(&desc.DeviceName),
                        origin,
                        width,
                        height,
                        is_primary: desc.Monitor == primary,
                    },
                });
            }
        }
        Ok(found)
    }
}

/// Pick which of `candidates` should be duplicated. Pure — no COM, no I/O —
/// so it is directly unit-testable.
///
/// * [`MonitorSelector::Primary`] — exactly `find_primary_output`'s old rule:
///   the candidate flagged `is_primary`, else the first candidate in
///   enumeration order (adapter-0/output-0-first, same as the old fallback).
/// * [`MonitorSelector::Key`] — match by `device_name` first (holds across a
///   duplication rebuild that kept the same GDI device name), else by
///   `(adapter_luid, origin)` (holds across a DISPLAYn renumbering that keeps
///   the physical panel on the same adapter at the same desktop position).
///   `None` if neither matches.
fn select_output(candidates: &[CandidateInfo], selector: &MonitorSelector) -> Option<usize> {
    match selector {
        MonitorSelector::Primary => candidates
            .iter()
            .position(|c| c.is_primary)
            .or_else(|| (!candidates.is_empty()).then_some(0)),
        MonitorSelector::Key(key) => candidates
            .iter()
            .position(|c| c.device_name == key.device_name)
            .or_else(|| {
                candidates
                    .iter()
                    .position(|c| c.adapter_luid == key.adapter_luid && c.origin == key.origin)
            }),
    }
}

/// Enumerate outputs, apply `selector`, and build the [`AdapterInfo`] the
/// caller needs to finish constructing the capture. The glue between the pure
/// [`select_output`] and the COM handles [`enumerate_outputs`] collected.
fn resolve_output(selector: &MonitorSelector) -> Result<(IDXGIAdapter1, IDXGIOutput1, AdapterInfo)> {
    let outputs = enumerate_outputs()?;
    if outputs.is_empty() {
        return Err(Error::Capture(
            "no desktop-attached DXGI output found".into(),
        ));
    }
    let candidates: Vec<CandidateInfo> = outputs.iter().map(|o| o.candidate.clone()).collect();
    let idx = select_output(&candidates, selector).ok_or_else(|| {
        Error::Capture("no DXGI output matched the requested monitor selector".into())
    })?;
    if matches!(selector, MonitorSelector::Primary) && !candidates[idx].is_primary {
        tracing::warn!("no output matched the primary HMONITOR; using first attached one");
    }
    let EnumeratedOutput {
        adapter,
        output,
        desc,
        ..
    } = outputs
        .into_iter()
        .nth(idx)
        .expect("idx returned by select_output is in range");
    let info = adapter_info(&adapter, &desc)?;
    Ok((adapter, output, info))
}

/// Enumerate capturable outputs without creating any D3D device or
/// duplication — cheap enough to call for every `MonitorList` refresh.
///
/// Id `0` is always the primary output (session-scoped — see
/// [`MonitorInfo`]'s docs); the rest are sorted `(origin_y, origin_x)`,
/// top-to-bottom then left-to-right, and the list is capped at
/// [`MAX_MONITORS`]. Returns the [`MonitorKey`] alongside each entry, in the
/// same order, so a caller can build the id -> key table `SelectMonitors`
/// needs.
pub fn list_monitors() -> Result<Vec<(MonitorInfo, MonitorKey)>> {
    let outputs = enumerate_outputs()?;
    if outputs.is_empty() {
        return Ok(Vec::new());
    }
    let mut candidates: Vec<CandidateInfo> = outputs.into_iter().map(|o| o.candidate).collect();

    // Same primary rule as `select_output(Primary, ..)`: the flagged
    // candidate, else the first in enumeration order.
    let primary_idx = candidates.iter().position(|c| c.is_primary).unwrap_or(0);
    let primary = candidates.remove(primary_idx);
    candidates.sort_by_key(|c| (c.origin.1, c.origin.0));

    let mut ordered = Vec::with_capacity(candidates.len() + 1);
    ordered.push(primary);
    ordered.extend(candidates);
    ordered.truncate(MAX_MONITORS);

    Ok(ordered
        .into_iter()
        .enumerate()
        .map(|(i, c)| {
            let key = MonitorKey {
                adapter_luid: c.adapter_luid,
                device_name: c.device_name.clone(),
                origin: c.origin,
            };
            let mut name = c.device_name;
            if name.len() > 64 {
                let mut end = 64;
                while !name.is_char_boundary(end) {
                    end -= 1;
                }
                name.truncate(end);
            }
            let info = MonitorInfo {
                id: i as u8,
                width: c.width,
                height: c.height,
                origin_x: c.origin.0,
                origin_y: c.origin.1,
                is_primary: i == 0,
                name,
            };
            (info, key)
        })
        .collect())
}

fn adapter_info(adapter: &IDXGIAdapter1, out: &DXGI_OUTPUT_DESC) -> Result<AdapterInfo> {
    // SAFETY: live adapter interface.
    let d = unsafe { adapter.GetDesc1() }.map_err(cap_err("GetDesc1"))?;
    let name = wide_to_string(&d.Description);
    let output_name = wide_to_string(&out.DeviceName);
    let luid = ((d.AdapterLuid.HighPart as u64) << 32) | d.AdapterLuid.LowPart as u64;
    Ok(AdapterInfo {
        luid,
        name,
        vendor_id: d.VendorId,
        device_id: d.DeviceId,
        output_name,
        origin: (out.DesktopCoordinates.left, out.DesktopCoordinates.top),
    })
}

fn wide_to_string(w: &[u16]) -> String {
    let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_to_string_stops_at_nul() {
        let mut buf = [0u16; 8];
        for (i, c) in "Arc".encode_utf16().enumerate() {
            buf[i] = c;
        }
        assert_eq!(wide_to_string(&buf), "Arc");
    }

    #[test]
    fn luid_packing_is_high_shifted() {
        // Mirrors adapter_info(): MFT_ENUM_ADAPTER_LUID wants (High << 32) | Low.
        let (low, high) = (0x1234_5678u32, 0x0000_0009i32);
        let packed = ((high as u64) << 32) | low as u64;
        assert_eq!(packed, 0x0000_0009_1234_5678);
    }

    // -- pause_reason: the one place that maps CaptureState to a pause label --

    #[test]
    fn pause_reason_secure_desktop_is_the_load_bearing_label() {
        // session.rs's `Paused` state and `ControlMsg::SecureDesktopActive`
        // both key off this exact string; it must never drift.
        assert_eq!(
            pause_reason(CaptureState::SecureDesktop),
            Some("secure desktop")
        );
    }

    #[test]
    fn pause_reason_running_does_not_pause() {
        assert_eq!(pause_reason(CaptureState::Running), None);
    }

    #[test]
    fn pause_reason_needs_recreate_does_not_pause() {
        // A duplication rebuild is transparent to the session; only the
        // secure desktop pauses the loop.
        assert_eq!(pause_reason(CaptureState::NeedsRecreate), None);
    }

    // -- select_output: pure, so exercised without any live DXGI enumeration --

    fn candidate(luid: u64, name: &str, origin: (i32, i32), is_primary: bool) -> CandidateInfo {
        CandidateInfo {
            adapter_luid: luid,
            device_name: name.into(),
            origin,
            width: 1920,
            height: 1080,
            is_primary,
        }
    }

    #[test]
    fn select_primary_picks_the_flagged_candidate_regardless_of_position() {
        let cands = vec![
            candidate(1, r"\\.\DISPLAY1", (0, 0), false),
            candidate(2, r"\\.\DISPLAY2", (1920, 0), true),
            candidate(3, r"\\.\DISPLAY3", (-1920, 0), false),
        ];
        assert_eq!(select_output(&cands, &MonitorSelector::Primary), Some(1));
    }

    #[test]
    fn select_primary_falls_back_to_first_when_none_flagged() {
        // Mirrors the old `find_primary_output` fallback: no HMONITOR match
        // (e.g. between a mode change and the next enumeration) still yields
        // a usable output rather than failing the whole capture.
        let cands = vec![
            candidate(1, r"\\.\DISPLAY1", (0, 0), false),
            candidate(2, r"\\.\DISPLAY2", (1920, 0), false),
        ];
        assert_eq!(select_output(&cands, &MonitorSelector::Primary), Some(0));
    }

    #[test]
    fn select_key_matches_by_device_name() {
        let cands = vec![
            candidate(1, r"\\.\DISPLAY1", (0, 0), true),
            candidate(2, r"\\.\DISPLAY2", (1920, 0), false),
        ];
        let key = MonitorKey {
            adapter_luid: 999, // deliberately stale — name must win first.
            device_name: r"\\.\DISPLAY2".into(),
            origin: (0, 0), // deliberately stale too.
        };
        assert_eq!(
            select_output(&cands, &MonitorSelector::Key(key)),
            Some(1)
        );
    }

    #[test]
    fn select_key_falls_back_to_luid_and_origin_when_names_have_been_renumbered() {
        // Windows renumbered \\.\DISPLAY2 to \\.\DISPLAY3 (e.g. a monitor was
        // unplugged and replugged) but the physical panel is still on the same
        // adapter at the same desktop position.
        let cands = vec![
            candidate(1, r"\\.\DISPLAY1", (0, 0), true),
            candidate(2, r"\\.\DISPLAY3", (1920, 0), false),
        ];
        let key = MonitorKey {
            adapter_luid: 2,
            device_name: r"\\.\DISPLAY2".into(),
            origin: (1920, 0),
        };
        assert_eq!(
            select_output(&cands, &MonitorSelector::Key(key)),
            Some(1)
        );
    }

    #[test]
    fn select_key_matching_nothing_is_none() {
        let cands = vec![candidate(1, r"\\.\DISPLAY1", (0, 0), true)];
        let key = MonitorKey {
            adapter_luid: 404,
            device_name: r"\\.\DISPLAY9".into(),
            origin: (5000, 5000),
        };
        assert_eq!(select_output(&cands, &MonitorSelector::Key(key)), None);
    }

    #[test]
    fn select_output_on_empty_list_is_always_none() {
        assert_eq!(select_output(&[], &MonitorSelector::Primary), None);
        let key = MonitorKey {
            adapter_luid: 1,
            device_name: r"\\.\DISPLAY1".into(),
            origin: (0, 0),
        };
        assert_eq!(select_output(&[], &MonitorSelector::Key(key)), None);
    }

    // -- list_monitors: touches real DXGI enumeration, so only invariants that
    // hold for any topology are asserted; mirrors the "skip gracefully when
    // there's no usable hardware" idiom used for the encoder in mf_encoder.rs.
    #[test]
    #[cfg(windows)]
    fn list_monitors_invariants_hold_for_this_machines_topology() {
        let Ok(monitors) = list_monitors() else {
            // No DXGI adapters/outputs available (e.g. a bare CI runner).
            // Nothing to assert; a missing GPU is not this test's subject.
            return;
        };
        if monitors.is_empty() {
            return;
        }
        assert!(monitors.len() <= MAX_MONITORS);
        // Ids are dense and match position: 0, 1, 2, ...
        for (i, (info, _key)) in monitors.iter().enumerate() {
            assert_eq!(info.id as usize, i);
        }
        // Id 0, and only id 0, is primary.
        assert!(monitors[0].0.is_primary);
        assert!(monitors[1..].iter().all(|(info, _)| !info.is_primary));
        // The rest are sorted (origin_y, origin_x), top-to-bottom then
        // left-to-right.
        for w in monitors[1..].windows(2) {
            let a = (w[0].0.origin_y, w[0].0.origin_x);
            let b = (w[1].0.origin_y, w[1].0.origin_x);
            assert!(a <= b, "not sorted: {a:?} should precede {b:?}");
        }
        // One key per monitor, same order.
        assert_eq!(monitors.len(), monitors.iter().map(|(_, k)| k).count());
    }
}
