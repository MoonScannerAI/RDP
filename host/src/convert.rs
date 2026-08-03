//! BGRA to NV12 colour conversion.
//!
//! Primary path is [`GpuConverter`]: a D3D11 VideoProcessor blit that stays
//! entirely on the GPU, producing an NV12 `ID3D11Texture2D` the Media
//! Foundation encoder can consume through `MFCreateDXGISurfaceBuffer`.
//!
//! [`bgra_to_nv12`] is the CPU fallback, used when the video processor is
//! unavailable or fails at runtime (some hybrid-graphics driver combinations
//! refuse RGB->NV12 on the iGPU). It emits limited-range BT.709, which is what
//! the H.264 encoder and every sane decoder assume by default.

use std::ffi::c_void;
use std::mem::ManuallyDrop;

use directdesk_shared::{Error, Result};
use windows::core::Interface;
use windows::Win32::Graphics::Direct3D11::{
    ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D, ID3D11VideoContext, ID3D11VideoDevice,
    ID3D11VideoProcessor, ID3D11VideoProcessorEnumerator, ID3D11VideoProcessorInputView,
    ID3D11VideoProcessorOutputView, D3D11_BIND_RENDER_TARGET, D3D11_BIND_SHADER_RESOURCE,
    D3D11_CPU_ACCESS_READ, D3D11_FORMAT_SUPPORT_RENDER_TARGET, D3D11_FORMAT_SUPPORT_SHADER_SAMPLE,
    D3D11_FORMAT_SUPPORT_TEXTURE2D, D3D11_MAPPED_SUBRESOURCE, D3D11_MAP_READ, D3D11_TEXTURE2D_DESC,
    D3D11_USAGE_DEFAULT, D3D11_USAGE_STAGING, D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE,
    D3D11_VIDEO_PROCESSOR_COLOR_SPACE, D3D11_VIDEO_PROCESSOR_CONTENT_DESC,
    D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC, D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC,
    D3D11_VIDEO_PROCESSOR_STREAM, D3D11_VIDEO_USAGE_PLAYBACK_NORMAL,
    D3D11_VPIV_DIMENSION_TEXTURE2D, D3D11_VPOV_DIMENSION_TEXTURE2D,
};
use windows::Win32::Graphics::Dxgi::Common::{DXGI_FORMAT_NV12, DXGI_RATIONAL, DXGI_SAMPLE_DESC};

/// How many NV12 textures to rotate through. The encoder MFT may still hold a
/// reference to the previous frame when we blit the next one, so a single
/// output texture would race.
const RING: usize = 4;

/// GPU BGRA -> NV12 converter backed by the D3D11 video processor.
pub struct GpuConverter {
    video_device: ID3D11VideoDevice,
    video_ctx: ID3D11VideoContext,
    enumerator: ID3D11VideoProcessorEnumerator,
    processor: ID3D11VideoProcessor,
    ring: Vec<(ID3D11Texture2D, ID3D11VideoProcessorOutputView)>,
    next: usize,
    /// Cached input view, keyed by the source texture's identity — the capture
    /// side reuses one texture, so this is created once.
    src_view: Option<(*mut c_void, ID3D11VideoProcessorInputView)>,
    width: u32,
    height: u32,
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    nv12_staging: Option<ID3D11Texture2D>,
}

impl GpuConverter {
    pub fn new(
        device: &ID3D11Device,
        context: &ID3D11DeviceContext,
        w: u32,
        h: u32,
    ) -> Result<Self> {
        if w == 0 || h == 0 {
            return Err(Error::Encoder("converter needs non-zero dimensions".into()));
        }
        // SAFETY: plain FFI query on a live device; failure is only informational.
        let fmt_support = unsafe { device.CheckFormatSupport(DXGI_FORMAT_NV12) }.unwrap_or(0);
        tracing::info!(
            "D3D11 NV12 format support {:#x} (texture2d={}, render_target={}, shader_resource={})",
            fmt_support,
            fmt_support & D3D11_FORMAT_SUPPORT_TEXTURE2D.0 as u32 != 0,
            fmt_support & D3D11_FORMAT_SUPPORT_RENDER_TARGET.0 as u32 != 0,
            fmt_support & D3D11_FORMAT_SUPPORT_SHADER_SAMPLE.0 as u32 != 0,
        );

        let video_device: ID3D11VideoDevice = device
            .cast()
            .map_err(|e| Error::Encoder(format!("ID3D11VideoDevice unavailable: {e}")))?;
        let video_ctx: ID3D11VideoContext = context
            .cast()
            .map_err(|e| Error::Encoder(format!("ID3D11VideoContext unavailable: {e}")))?;

        let content = D3D11_VIDEO_PROCESSOR_CONTENT_DESC {
            InputFrameFormat: D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE,
            InputFrameRate: DXGI_RATIONAL {
                Numerator: 60,
                Denominator: 1,
            },
            InputWidth: w,
            InputHeight: h,
            OutputFrameRate: DXGI_RATIONAL {
                Numerator: 60,
                Denominator: 1,
            },
            OutputWidth: w,
            OutputHeight: h,
            Usage: D3D11_VIDEO_USAGE_PLAYBACK_NORMAL,
        };

        // SAFETY: `content` is fully initialized; every returned interface is
        // checked before use and kept alive in `self`.
        let (enumerator, processor) = unsafe {
            let enumerator = video_device
                .CreateVideoProcessorEnumerator(&content)
                .map_err(|e| Error::Encoder(format!("CreateVideoProcessorEnumerator: {e}")))?;
            // Confirm the driver can actually write NV12 before we commit.
            let support = enumerator
                .CheckVideoProcessorFormat(DXGI_FORMAT_NV12)
                .map_err(|e| Error::Encoder(format!("CheckVideoProcessorFormat(NV12): {e}")))?;
            if support == 0 {
                return Err(Error::Encoder(
                    "video processor reports no NV12 support".into(),
                ));
            }
            let processor = video_device
                .CreateVideoProcessor(&enumerator, 0)
                .map_err(|e| Error::Encoder(format!("CreateVideoProcessor: {e}")))?;
            (enumerator, processor)
        };

        let mut me = Self {
            video_device,
            video_ctx,
            enumerator,
            processor,
            ring: Vec::with_capacity(RING),
            next: 0,
            src_view: None,
            width: w,
            height: h,
            device: device.clone(),
            context: context.clone(),
            nv12_staging: None,
        };
        me.build_ring()?;
        me.configure_colour_space();
        Ok(me)
    }

    pub fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    /// Convert one BGRA texture, returning the NV12 texture that now holds it.
    /// The returned texture is valid until it comes around the ring again.
    pub fn convert(&mut self, src: &ID3D11Texture2D) -> Result<ID3D11Texture2D> {
        let in_view = self.input_view(src)?;
        let idx = self.next;
        self.next = (self.next + 1) % self.ring.len();
        let (tex, out_view) = self.ring[idx].clone();

        // SAFETY: `stream` is zero-initialized then partially filled; the only
        // owning field we set (`pInputSurface`) is explicitly dropped after the
        // call so the clone's refcount is balanced.
        unsafe {
            let mut stream = D3D11_VIDEO_PROCESSOR_STREAM {
                Enable: true.into(),
                pInputSurface: ManuallyDrop::new(Some(in_view)),
                ..Default::default()
            };
            let res = self.video_ctx.VideoProcessorBlt(
                &self.processor,
                &out_view,
                0,
                std::slice::from_ref(&stream),
            );
            ManuallyDrop::drop(&mut stream.pInputSurface);
            res.map_err(|e| Error::Encoder(format!("VideoProcessorBlt: {e}")))?;
        }
        Ok(tex)
    }

    /// Read an NV12 GPU texture back into a tightly-packed CPU NV12 buffer.
    /// Only used by diagnostics and by the CPU-input encoder fallback.
    pub fn readback_nv12(&mut self, tex: &ID3D11Texture2D, out: &mut Vec<u8>) -> Result<()> {
        let staging = match &self.nv12_staging {
            Some(s) => s.clone(),
            None => {
                let s = create_nv12_texture(&self.device, self.width, self.height, true)?;
                self.nv12_staging = Some(s.clone());
                s
            }
        };
        // SAFETY: identical desc apart from usage; Map/Unmap are paired.
        unsafe {
            self.context.CopyResource(&staging, tex);
            let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
            self.context
                .Map(&staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))
                .map_err(|e| Error::Encoder(format!("Map(nv12 staging): {e}")))?;
            let w = self.width as usize;
            let h = self.height as usize;
            out.clear();
            out.reserve(w * h * 3 / 2);
            let base = mapped.pData as *const u8;
            for y in 0..h {
                let row = base.add(y * mapped.RowPitch as usize);
                out.extend_from_slice(std::slice::from_raw_parts(row, w));
            }
            // The UV plane starts immediately after `h` rows of pitch.
            for y in 0..h / 2 {
                let row = base.add((h + y) * mapped.RowPitch as usize);
                out.extend_from_slice(std::slice::from_raw_parts(row, w));
            }
            self.context.Unmap(&staging, 0);
        }
        Ok(())
    }

    fn build_ring(&mut self) -> Result<()> {
        for _ in 0..RING {
            let tex = create_nv12_texture(&self.device, self.width, self.height, false)?;
            let desc = D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC {
                ViewDimension: D3D11_VPOV_DIMENSION_TEXTURE2D,
                ..Default::default()
            };
            let mut view: Option<ID3D11VideoProcessorOutputView> = None;
            // SAFETY: desc fully initialized (MipSlice defaults to 0).
            unsafe {
                self.video_device
                    .CreateVideoProcessorOutputView(&tex, &self.enumerator, &desc, Some(&mut view))
                    .map_err(|e| Error::Encoder(format!("CreateVideoProcessorOutputView: {e}")))?;
            }
            let view =
                view.ok_or_else(|| Error::Encoder("null video processor output view".into()))?;
            self.ring.push((tex, view));
        }
        Ok(())
    }

    fn configure_colour_space(&self) {
        // Input: full-range RGB from the desktop. bitfield 0 == Usage(playback),
        // RGB_Range(full), matrix/nominal-range unused for RGB.
        let rgb = D3D11_VIDEO_PROCESSOR_COLOR_SPACE { _bitfield: 0 };
        // Output: YCbCr_Matrix = BT.709 (bit 2), Nominal_Range = 16-235 (bits 4-5 == 1).
        let ycbcr = D3D11_VIDEO_PROCESSOR_COLOR_SPACE {
            _bitfield: (1 << 2) | (1 << 4),
        };
        // SAFETY: plain FFI on live interfaces; all setters are infallible.
        unsafe {
            self.video_ctx
                .VideoProcessorSetStreamColorSpace(&self.processor, 0, &rgb);
            self.video_ctx
                .VideoProcessorSetOutputColorSpace(&self.processor, &ycbcr);
            self.video_ctx.VideoProcessorSetStreamFrameFormat(
                &self.processor,
                0,
                D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE,
            );
            self.video_ctx
                .VideoProcessorSetStreamSourceRect(&self.processor, 0, false, None);
            self.video_ctx
                .VideoProcessorSetStreamDestRect(&self.processor, 0, false, None);
        }
    }

    fn input_view(&mut self, src: &ID3D11Texture2D) -> Result<ID3D11VideoProcessorInputView> {
        let key = src.as_raw();
        if let Some((cached_key, view)) = &self.src_view {
            if *cached_key == key {
                return Ok(view.clone());
            }
        }
        let desc = D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC {
            FourCC: 0,
            ViewDimension: D3D11_VPIV_DIMENSION_TEXTURE2D,
            ..Default::default()
        };
        let mut view: Option<ID3D11VideoProcessorInputView> = None;
        // SAFETY: desc fully initialized (MipSlice/ArraySlice default to 0).
        unsafe {
            self.video_device
                .CreateVideoProcessorInputView(src, &self.enumerator, &desc, Some(&mut view))
                .map_err(|e| Error::Encoder(format!("CreateVideoProcessorInputView: {e}")))?;
        }
        let view = view.ok_or_else(|| Error::Encoder("null video processor input view".into()))?;
        self.src_view = Some((key, view.clone()));
        Ok(view)
    }
}

// SAFETY: the converter is created on, and used exclusively from, the single
// pipeline thread. The raw pointer in `src_view` is only an identity token and
// is never dereferenced.
unsafe impl Send for GpuConverter {}

/// Create an NV12 texture, walking a ladder of bind-flag combinations.
///
/// NV12 render-target support is genuinely optional in D3D11 and several
/// drivers (notably some NVIDIA ones) reject `BIND_RENDER_TARGET |
/// BIND_SHADER_RESOURCE` with `E_INVALIDARG`. Rather than assume, try the most
/// capable combination first and degrade. A texture without RENDER_TARGET
/// cannot back a video-processor output view, so the caller will end up on the
/// CPU path — which is the honest outcome, not a crash.
fn create_nv12_texture(
    device: &ID3D11Device,
    w: u32,
    h: u32,
    staging: bool,
) -> Result<ID3D11Texture2D> {
    // NV12 is 4:2:0 — odd dimensions have no valid chroma plane.
    if !w.is_multiple_of(2) || !h.is_multiple_of(2) {
        return Err(Error::Encoder(format!(
            "NV12 needs even dimensions, got {w}x{h}"
        )));
    }

    let binds: &[u32] = if staging {
        &[0]
    } else {
        &[
            (D3D11_BIND_RENDER_TARGET.0 | D3D11_BIND_SHADER_RESOURCE.0) as u32,
            D3D11_BIND_RENDER_TARGET.0 as u32,
            D3D11_BIND_SHADER_RESOURCE.0 as u32,
            0,
        ]
    };

    let mut last = String::new();
    for &bind in binds {
        let desc = D3D11_TEXTURE2D_DESC {
            Width: w,
            Height: h,
            MipLevels: 1,
            ArraySize: 1,
            Format: DXGI_FORMAT_NV12,
            SampleDesc: DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            Usage: if staging {
                D3D11_USAGE_STAGING
            } else {
                D3D11_USAGE_DEFAULT
            },
            BindFlags: bind,
            CPUAccessFlags: if staging {
                D3D11_CPU_ACCESS_READ.0 as u32
            } else {
                0
            },
            MiscFlags: 0,
        };
        let mut tex: Option<ID3D11Texture2D> = None;
        // SAFETY: desc fully initialized; out param written only on success.
        let res = unsafe { device.CreateTexture2D(&desc, None, Some(&mut tex)) };
        match res {
            Ok(()) => {
                if let Some(tex) = tex {
                    if bind != binds[0] {
                        tracing::info!("NV12 texture created with reduced bind flags {bind:#x}");
                    }
                    return Ok(tex);
                }
                last = "CreateTexture2D returned null".into();
            }
            Err(e) => last = format!("bind {bind:#x}: {e}"),
        }
    }
    Err(Error::Encoder(format!(
        "CreateTexture2D(NV12) {w}x{h}: {last}"
    )))
}

/// Size in bytes of a tightly-packed NV12 image.
pub const fn nv12_len(w: u32, h: u32) -> usize {
    (w as usize) * (h as usize) * 3 / 2
}

/// CPU BGRA -> NV12, limited-range BT.709.
///
/// `src` is BGRA8 with `src_stride` bytes per row (>= `w * 4`). `dst` is
/// overwritten with a tightly-packed NV12 image: a `w * h` luma plane followed
/// by a `w * (h / 2)` interleaved Cb/Cr plane. Odd `w`/`h` are handled by
/// clamping the 2x2 chroma sample to the last valid pixel.
pub fn bgra_to_nv12(
    src: &[u8],
    src_stride: usize,
    w: u32,
    h: u32,
    dst: &mut Vec<u8>,
) -> Result<()> {
    let (wu, hu) = (w as usize, h as usize);
    if wu == 0 || hu == 0 {
        return Err(Error::Encoder("nv12 conversion needs non-zero size".into()));
    }
    if src_stride < wu * 4 || src.len() < src_stride * (hu - 1) + wu * 4 {
        return Err(Error::Encoder(format!(
            "bgra buffer too small: {} bytes, stride {src_stride}, {w}x{h}",
            src.len()
        )));
    }

    dst.clear();
    dst.resize(nv12_len(w, h), 0);
    let (y_plane, uv_plane) = dst.split_at_mut(wu * hu);

    for y in 0..hu {
        let row = &src[y * src_stride..y * src_stride + wu * 4];
        let out = &mut y_plane[y * wu..(y + 1) * wu];
        for x in 0..wu {
            let p = &row[x * 4..x * 4 + 4];
            out[x] = luma709(p[2] as i32, p[1] as i32, p[0] as i32);
        }
    }

    let ch = hu / 2;
    let cw = wu / 2;
    for cy in 0..ch {
        let out = &mut uv_plane[cy * wu..cy * wu + cw * 2];
        let y0 = cy * 2;
        let y1 = (y0 + 1).min(hu - 1);
        let r0 = &src[y0 * src_stride..y0 * src_stride + wu * 4];
        let r1 = &src[y1 * src_stride..y1 * src_stride + wu * 4];
        for cx in 0..cw {
            let x0 = cx * 2;
            let x1 = (x0 + 1).min(wu - 1);
            let mut b = 0i32;
            let mut g = 0i32;
            let mut r = 0i32;
            for (row, x) in [(r0, x0), (r0, x1), (r1, x0), (r1, x1)] {
                let p = &row[x * 4..x * 4 + 4];
                b += p[0] as i32;
                g += p[1] as i32;
                r += p[2] as i32;
            }
            let (b, g, r) = ((b + 2) / 4, (g + 2) / 4, (r + 2) / 4);
            out[cx * 2] = chroma_cb709(r, g, b);
            out[cx * 2 + 1] = chroma_cr709(r, g, b);
        }
    }
    Ok(())
}

#[inline]
fn luma709(r: i32, g: i32, b: i32) -> u8 {
    (((47 * r + 157 * g + 16 * b + 128) >> 8) + 16).clamp(16, 235) as u8
}

#[inline]
fn chroma_cb709(r: i32, g: i32, b: i32) -> u8 {
    (((-26 * r - 87 * g + 112 * b + 128) >> 8) + 128).clamp(16, 240) as u8
}

#[inline]
fn chroma_cr709(r: i32, g: i32, b: i32) -> u8 {
    (((112 * r - 102 * g - 10 * b + 128) >> 8) + 128).clamp(16, 240) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    fn solid(w: u32, h: u32, b: u8, g: u8, r: u8) -> Vec<u8> {
        let mut v = Vec::with_capacity((w * h * 4) as usize);
        for _ in 0..w * h {
            v.extend_from_slice(&[b, g, r, 255]);
        }
        v
    }

    #[test]
    fn nv12_sizes() {
        assert_eq!(nv12_len(1920, 1080), 1920 * 1080 * 3 / 2);
        let mut dst = Vec::new();
        bgra_to_nv12(&solid(64, 32, 0, 0, 0), 64 * 4, 64, 32, &mut dst).unwrap();
        assert_eq!(dst.len(), nv12_len(64, 32));
    }

    #[test]
    fn black_and_white_hit_limited_range_endpoints() {
        let mut dst = Vec::new();
        bgra_to_nv12(&solid(16, 16, 0, 0, 0), 16 * 4, 16, 16, &mut dst).unwrap();
        assert_eq!(dst[0], 16, "black luma must be 16 (limited range)");
        assert_eq!(dst[16 * 16], 128, "black Cb neutral");
        assert_eq!(dst[16 * 16 + 1], 128, "black Cr neutral");

        bgra_to_nv12(&solid(16, 16, 255, 255, 255), 16 * 4, 16, 16, &mut dst).unwrap();
        assert_eq!(dst[0], 235, "white luma must be 235 (limited range)");
        assert!((dst[16 * 16] as i32 - 128).abs() <= 1, "white Cb neutral");
        assert!(
            (dst[16 * 16 + 1] as i32 - 128).abs() <= 1,
            "white Cr neutral"
        );
    }

    #[test]
    fn primaries_land_where_bt709_says() {
        let mut dst = Vec::new();
        // Pure green is the brightest primary under BT.709 (0.7152 weight).
        bgra_to_nv12(&solid(8, 8, 0, 255, 0), 8 * 4, 8, 8, &mut dst).unwrap();
        let g_luma = dst[0];
        bgra_to_nv12(&solid(8, 8, 255, 0, 0), 8 * 4, 8, 8, &mut dst).unwrap();
        let b_luma = dst[0];
        let b_cb = dst[64];
        bgra_to_nv12(&solid(8, 8, 0, 0, 255), 8 * 4, 8, 8, &mut dst).unwrap();
        let r_luma = dst[0];
        let r_cr = dst[65];

        assert!(g_luma > r_luma && r_luma > b_luma, "709 weights G > R > B");
        assert!(b_cb > 200, "pure blue must max out Cb, got {b_cb}");
        assert!(r_cr > 200, "pure red must max out Cr, got {r_cr}");
    }

    #[test]
    fn gradient_luma_is_monotonic() {
        // A horizontal ramp must produce a non-decreasing luma row.
        let (w, h) = (32u32, 4u32);
        let mut src = Vec::new();
        for _ in 0..h {
            for x in 0..w {
                let v = (x * 255 / (w - 1)) as u8;
                src.extend_from_slice(&[v, v, v, 255]);
            }
        }
        let mut dst = Vec::new();
        bgra_to_nv12(&src, (w * 4) as usize, w, h, &mut dst).unwrap();
        for x in 1..w as usize {
            assert!(dst[x] >= dst[x - 1], "luma ramp regressed at x={x}");
        }
    }

    #[test]
    fn respects_padded_stride() {
        let (w, h) = (8u32, 8u32);
        let stride = (w * 4 + 64) as usize;
        let mut src = vec![0u8; stride * h as usize];
        for y in 0..h as usize {
            for x in 0..w as usize {
                let p = y * stride + x * 4;
                src[p] = 255; // blue
                src[p + 3] = 255;
            }
        }
        let mut dst = Vec::new();
        bgra_to_nv12(&src, stride, w, h, &mut dst).unwrap();
        // Every luma sample should equal pure-blue luma, proving the padding
        // bytes were skipped rather than read as pixels.
        let expect = luma709(0, 0, 255);
        assert!(dst[..(w * h) as usize].iter().all(|&v| v == expect));
    }

    #[test]
    fn rejects_undersized_input() {
        let mut dst = Vec::new();
        assert!(bgra_to_nv12(&[0u8; 8], 64, 16, 16, &mut dst).is_err());
        assert!(bgra_to_nv12(&[0u8; 64], 4, 16, 16, &mut dst).is_err());
    }
}
