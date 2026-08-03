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
use windows::Win32::Graphics::Dxgi::Common::{
    DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_SAMPLE_DESC,
};
use windows::Win32::Graphics::Dxgi::{
    CreateDXGIFactory1, IDXGIAdapter1, IDXGIFactory1, IDXGIOutput1, IDXGIOutputDuplication,
    IDXGIResource, DXGI_ERROR_ACCESS_LOST, DXGI_ERROR_INVALID_CALL, DXGI_ERROR_NOT_FOUND,
    DXGI_ERROR_SESSION_DISCONNECTED, DXGI_ERROR_UNSUPPORTED, DXGI_ERROR_WAIT_TIMEOUT,
    DXGI_OUTDUPL_FRAME_INFO, DXGI_OUTDUPL_MOVE_RECT, DXGI_OUTPUT_DESC,
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
    /// Regions changed since the previous frame. Empty on a repeat frame.
    pub dirty_rects: Vec<RECT>,
    pub move_rects: Vec<DXGI_OUTDUPL_MOVE_RECT>,
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
    dirty_scratch: Vec<u8>,
    recreate_backoff: Option<Instant>,
}

impl DdaCapture {
    /// Duplicate the primary monitor, creating the D3D11 device on its adapter.
    pub fn new() -> Result<Self> {
        // Must happen before we ask DXGI for any geometry.
        set_process_dpi_aware();
        let (adapter, output, info) = find_primary_output()?;
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
                    return Err(Error::Capture("secure desktop".into()));
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

        let dirty_rects = self.read_dirty_rects(&dupl);
        let move_rects = self.read_move_rects(&dupl);

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
            dirty_rects: Vec::new(),
            move_rects: Vec::new(),
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
                Ok(())
            }
            Err(e) if e.code() == E_ACCESSDENIED => {
                self.state = if secure_desktop_active() {
                    CaptureState::SecureDesktop
                } else {
                    CaptureState::NeedsRecreate
                };
                if self.state == CaptureState::SecureDesktop {
                    Err(Error::Capture("secure desktop".into()))
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

    fn read_dirty_rects(&mut self, dupl: &IDXGIOutputDuplication) -> Vec<RECT> {
        let mut needed: u32 = 0;
        // SAFETY: query size first with a zero-length buffer, then fill.
        unsafe {
            if dupl
                .GetFrameDirtyRects(0, std::ptr::null_mut(), &mut needed)
                .is_err()
                && needed == 0
            {
                return Vec::new();
            }
            if needed == 0 {
                return Vec::new();
            }
            self.dirty_scratch.resize(needed as usize, 0);
            let ptr = self.dirty_scratch.as_mut_ptr() as *mut RECT;
            let mut written = 0u32;
            if dupl.GetFrameDirtyRects(needed, ptr, &mut written).is_err() {
                return Vec::new();
            }
            let count = written as usize / std::mem::size_of::<RECT>();
            std::slice::from_raw_parts(ptr as *const RECT, count).to_vec()
        }
    }

    fn read_move_rects(&mut self, dupl: &IDXGIOutputDuplication) -> Vec<DXGI_OUTDUPL_MOVE_RECT> {
        let mut needed: u32 = 0;
        // SAFETY: identical two-phase query as dirty rects.
        unsafe {
            if dupl
                .GetFrameMoveRects(0, std::ptr::null_mut(), &mut needed)
                .is_err()
                && needed == 0
            {
                return Vec::new();
            }
            if needed == 0 {
                return Vec::new();
            }
            let n = needed as usize / std::mem::size_of::<DXGI_OUTDUPL_MOVE_RECT>();
            let mut buf: Vec<DXGI_OUTDUPL_MOVE_RECT> = vec![DXGI_OUTDUPL_MOVE_RECT::default(); n];
            let mut written = 0u32;
            if dupl
                .GetFrameMoveRects(needed, buf.as_mut_ptr(), &mut written)
                .is_err()
            {
                return Vec::new();
            }
            buf.truncate(written as usize / std::mem::size_of::<DXGI_OUTDUPL_MOVE_RECT>());
            buf
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
        SampleDesc: DXGI_SAMPLE_DESC { Count: 1, Quality: 0 },
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
        SampleDesc: DXGI_SAMPLE_DESC { Count: 1, Quality: 0 },
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

/// Walk every adapter/output pair and return the one whose `HMONITOR` matches
/// the primary monitor. Falls back to adapter 0 / output 0.
fn find_primary_output() -> Result<(IDXGIAdapter1, IDXGIOutput1, AdapterInfo)> {
    // SAFETY: DXGI enumeration; every call's result is checked before use.
    unsafe {
        let primary: HMONITOR = MonitorFromPoint(POINT { x: 0, y: 0 }, MONITOR_DEFAULTTOPRIMARY);
        let factory: IDXGIFactory1 =
            CreateDXGIFactory1().map_err(cap_err("CreateDXGIFactory1"))?;

        let mut fallback: Option<(IDXGIAdapter1, IDXGIOutput1, DXGI_OUTPUT_DESC)> = None;

        let mut ai = 0u32;
        loop {
            let adapter = match factory.EnumAdapters1(ai) {
                Ok(a) => a,
                Err(e) if e.code() == DXGI_ERROR_NOT_FOUND => break,
                Err(e) => return Err(Error::Capture(format!("EnumAdapters1: {e}"))),
            };
            ai += 1;

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
                if desc.Monitor == primary {
                    let info = adapter_info(&adapter, &desc)?;
                    return Ok((adapter, out1, info));
                }
                if fallback.is_none() {
                    fallback = Some((adapter.clone(), out1, desc));
                }
            }
        }

        match fallback {
            Some((adapter, out1, desc)) => {
                tracing::warn!("no output matched the primary HMONITOR; using first attached one");
                let info = adapter_info(&adapter, &desc)?;
                Ok((adapter, out1, info))
            }
            None => Err(Error::Capture("no desktop-attached DXGI output found".into())),
        }
    }
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
}
