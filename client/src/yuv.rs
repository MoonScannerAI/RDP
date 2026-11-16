//! Stride- and crop-aware YUV 4:2:0 → RGBA8 conversion for decoders that hand
//! back CPU planes with arbitrary layout (Android MediaCodec output buffers).
//!
//! The Windows path keeps using [`crate::decoder::nv12_to_rgba`]; this module
//! produces **byte-identical** pixels for a tightly packed NV12 frame (same
//! limited-range BT.709 matrix, same bilinear chroma reconstruction, same
//! rounding), which the tests pin.
//!
//! # Chroma geometry with a crop
//!
//! The crop rectangle is treated as *the picture*: chroma phase comes from the
//! absolute luma coordinate (chroma sample `k` is co-sited with even luma
//! column `2k` and sits between luma rows `2k`/`2k+1`), but neighbours outside
//! the crop are clamped to the nearest sample inside it, exactly as
//! `nv12_to_rgba` clamps at the frame edge. For an even-aligned crop the result
//! equals `nv12_to_rgba` run on the cropped sub-picture. Odd crop offsets keep
//! the phase of the underlying picture.
//!
//! # Performance
//!
//! Per output row: one vertical chroma blend into a small `u16` scratch, one
//! expansion to per-pixel chroma (Q3), then a branch-free integer loop over
//! `zip`ped slices that LLVM auto-vectorizes. No per-pixel bounds checks.

use directdesk_shared::error::{Error, Result};

/// Chroma arrangement of a 4:2:0 frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chroma {
    /// One interleaved U,V plane (NV12).
    InterleavedUv,
    /// One interleaved V,U plane (NV21): NV12 with each chroma pair swapped.
    InterleavedVu,
    /// Separate U and V planes (I420, or YV12 when `v_offset < u_offset`).
    Planar,
}

/// Where each plane lives inside one contiguous output buffer, and which part
/// of the decoded picture is visible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlaneLayout {
    pub chroma: Chroma,
    /// Byte offset of row 0 of the Y plane.
    pub y_offset: usize,
    pub y_stride: usize,
    /// Byte offset of row 0 of the interleaved chroma plane — its first byte
    /// is U for NV12, V for NV21 — or of the U plane (planar).
    pub u_offset: usize,
    /// Byte offset of row 0 of the V plane (planar only; unused when
    /// interleaved).
    pub v_offset: usize,
    /// Row stride of the chroma plane(s).
    pub uv_stride: usize,
    /// Visible rectangle in luma pixels: left, top, width, height. The output
    /// RGBA image is `crop_w x crop_h`.
    pub crop_x: u32,
    pub crop_y: u32,
    pub crop_w: u32,
    pub crop_h: u32,
}

const COLOR_FORMAT_YUV420_PLANAR: i32 = 19;
const COLOR_FORMAT_YUV420_SEMIPLANAR: i32 = 21;
/// `OMX_QCOM_COLOR_FormatYUV420PackedSemiPlanar64x32Tile2m8ka`-family values
/// Qualcomm decoders report; both are plain NV12 for our purposes.
const COLOR_FORMAT_QCOM_SEMIPLANAR: i32 = 0x7FA3_0C00;
/// `QOMX_COLOR_FormatYUV420SemiPlanar32m`-style: Y stride aligned to 128 and
/// Y scanlines to 32 when the codec does not say.
const COLOR_FORMAT_QCOM_SEMIPLANAR_32M: i32 = 0x7FA3_0C04;

/// Sanity bound on picture dimensions; keeps every offset computation far from
/// overflow even on 32-bit targets.
const MAX_DIM: i32 = 16384;

fn align_up(v: usize, a: usize) -> usize {
    v.div_ceil(a) * a
}

/// Derive a [`PlaneLayout`] from MediaCodec's output-format keys.
///
/// `color_format`: 19 (I420), 21 (NV12), 0x7FA30C00 / 0x7FA30C04 (Qualcomm
/// NV12 variants). Anything else is an error naming the value in hex.
/// `stride`/`slice_height` fall back to `width`/`height` when the codec does
/// not report them (<= 0, or smaller than the picture, which no valid layout
/// can be). For 0x7FA30C04 the fallback is instead `width` aligned up to 128
/// and `height` aligned up to 32. `crop` is MediaCodec's inclusive
/// (left, top, right, bottom), when present; the default is the full frame.
pub fn layout_from_format(
    color_format: i32,
    width: i32,
    height: i32,
    stride: i32,
    slice_height: i32,
    crop: Option<(i32, i32, i32, i32)>,
) -> Result<PlaneLayout> {
    let chroma = match color_format {
        COLOR_FORMAT_YUV420_PLANAR => Chroma::Planar,
        COLOR_FORMAT_YUV420_SEMIPLANAR
        | COLOR_FORMAT_QCOM_SEMIPLANAR
        | COLOR_FORMAT_QCOM_SEMIPLANAR_32M => Chroma::InterleavedUv,
        other => {
            return Err(Error::Decoder(format!(
                "unsupported MediaCodec color format 0x{:X}",
                other as u32
            )))
        }
    };
    if !(1..=MAX_DIM).contains(&width) || !(1..=MAX_DIM).contains(&height) {
        return Err(Error::Decoder(format!("bad picture size {width}x{height}")));
    }
    let (w, h) = (width as usize, height as usize);

    let aligned = color_format == COLOR_FORMAT_QCOM_SEMIPLANAR_32M;
    let y_stride = if stride >= width && stride <= 4 * MAX_DIM {
        stride as usize
    } else if aligned {
        align_up(w, 128)
    } else {
        w
    };
    let slice = if slice_height >= height && slice_height <= 4 * MAX_DIM {
        slice_height as usize
    } else if aligned {
        align_up(h, 32)
    } else {
        h
    };

    let (cl, ct, cr, cb) = crop.unwrap_or((0, 0, width - 1, height - 1));
    if cl < 0 || ct < 0 || cr < cl || cb < ct || cr >= width || cb >= height {
        return Err(Error::Decoder(format!(
            "crop ({cl},{ct},{cr},{cb}) outside {width}x{height} picture"
        )));
    }

    let u_offset = y_stride * slice;
    let (uv_stride, v_offset) = match chroma {
        Chroma::InterleavedUv | Chroma::InterleavedVu => (y_stride, 0),
        Chroma::Planar => {
            let uvs = y_stride.div_ceil(2);
            (uvs, u_offset + uvs * slice.div_ceil(2))
        }
    };
    Ok(PlaneLayout {
        chroma,
        y_offset: 0,
        y_stride,
        u_offset,
        v_offset,
        uv_stride,
        crop_x: cl as u32,
        crop_y: ct as u32,
        crop_w: (cr - cl + 1) as u32,
        crop_h: (cb - ct + 1) as u32,
    })
}

/// Everything derived from a validated layout.
struct Geometry {
    x0: usize,
    y0: usize,
    w: usize,
    h: usize,
    /// First / last chroma column and row touched by the crop.
    cx0: usize,
    cx1: usize,
    cy0: usize,
    cy1: usize,
}

fn validate(src_len: usize, l: &PlaneLayout) -> Result<Geometry> {
    let err = |m: String| Err(Error::Decoder(m));
    let (x0, y0, w, h) = (
        l.crop_x as usize,
        l.crop_y as usize,
        l.crop_w as usize,
        l.crop_h as usize,
    );
    if w == 0 || h == 0 {
        return err("zero-sized crop".into());
    }
    if w > MAX_DIM as usize * 2 || h > MAX_DIM as usize * 2 || x0 > 1 << 20 || y0 > 1 << 20 {
        return err(format!("crop {x0},{y0} {w}x{h} out of range"));
    }
    let (cx0, cx1) = (x0 / 2, (x0 + w - 1) / 2);
    let (cy0, cy1) = (y0 / 2, (y0 + h - 1) / 2);
    if l.y_stride < x0 + w {
        return err(format!(
            "Y stride {} < crop right edge {}",
            l.y_stride,
            x0 + w
        ));
    }
    // Plane end offsets, checked.
    let end = |off: usize, stride: usize, last_row: usize, row_bytes: usize| {
        last_row
            .checked_mul(stride)
            .and_then(|v| v.checked_add(off))
            .and_then(|v| v.checked_add(row_bytes))
    };
    let y_end = end(l.y_offset, l.y_stride, y0 + h - 1, x0 + w);
    let (uv_row_end, planes): (usize, &[usize]) = match l.chroma {
        Chroma::InterleavedUv | Chroma::InterleavedVu => ((cx1 + 1) * 2, &[l.u_offset]),
        Chroma::Planar => (cx1 + 1, &[l.u_offset, l.v_offset]),
    };
    if l.uv_stride < uv_row_end {
        return err(format!("chroma stride {} < {uv_row_end}", l.uv_stride));
    }
    let mut needed = y_end;
    for &p in planes {
        needed = match (needed, end(p, l.uv_stride, cy1, uv_row_end)) {
            (Some(a), Some(b)) => Some(a.max(b)),
            _ => None,
        };
    }
    match needed {
        Some(n) if n <= src_len => Ok(Geometry {
            x0,
            y0,
            w,
            h,
            cx0,
            cx1,
            cy0,
            cy1,
        }),
        Some(n) => err(format!(
            "frame buffer {src_len} bytes < {n} needed by layout"
        )),
        None => err("layout offsets overflow".into()),
    }
}

/// Convert the visible rectangle of `src` (laid out per `layout`) to tightly
/// packed RGBA8, limited-range BT.709, alpha 255. `out` is resized to
/// `crop_w * crop_h * 4`. Errors if `src` is too short for `layout`.
///
/// Every output byte is written, so `out` may be a reused buffer with stale
/// contents: when its length is already `crop_w * crop_h * 4` it is neither
/// reallocated nor cleared first (only a length change zero-fills, and only
/// the added tail). The result never depends on what `out` held.
pub fn yuv420_to_rgba(src: &[u8], layout: &PlaneLayout, out: &mut Vec<u8>) -> Result<()> {
    let g = validate(src.len(), layout)?;
    // A no-op at the right length: no memset on a recycled buffer.
    out.resize(g.w * g.h * 4, 0);

    convert_rows(src, layout, &g, 0, g.h, out);
    Ok(())
}

/// Convert output rows `first..first + count` into `out` (which holds exactly
/// those rows).
fn convert_rows(
    src: &[u8],
    l: &PlaneLayout,
    g: &Geometry,
    first: usize,
    count: usize,
    out: &mut [u8],
) {
    let w = g.w;
    let cw = g.cx1 - g.cx0 + 1;
    let mut cu = vec![0u16; cw];
    let mut cv = vec![0u16; cw];
    let mut uq = vec![0i16; w];
    let mut vq = vec![0i16; w];
    let mut rr = vec![0u8; w];
    let mut gg = vec![0u8; w];
    let mut bb = vec![0u8; w];

    for (r, out_row) in out.chunks_exact_mut(w * 4).take(count).enumerate() {
        let row = first + r;
        let ay = g.y0 + row; // absolute luma row
        let k = ay / 2;
        let far = if ay.is_multiple_of(2) {
            k.saturating_sub(1).max(g.cy0)
        } else {
            (k + 1).min(g.cy1)
        };

        // Vertical 0.75 / 0.25 blend into Q2.
        match l.chroma {
            Chroma::InterleavedUv | Chroma::InterleavedVu => {
                let near = &src[l.u_offset + k * l.uv_stride + g.cx0 * 2..][..cw * 2];
                let farr = &src[l.u_offset + far * l.uv_stride + g.cx0 * 2..][..cw * 2];
                if l.chroma == Chroma::InterleavedUv {
                    blend_interleaved::<0, 1>(near, farr, &mut cu, &mut cv);
                } else {
                    blend_interleaved::<1, 0>(near, farr, &mut cu, &mut cv);
                }
            }
            Chroma::Planar => {
                let un = &src[l.u_offset + k * l.uv_stride + g.cx0..][..cw];
                let uf = &src[l.u_offset + far * l.uv_stride + g.cx0..][..cw];
                let vn = &src[l.v_offset + k * l.uv_stride + g.cx0..][..cw];
                let vf = &src[l.v_offset + far * l.uv_stride + g.cx0..][..cw];
                for ((u, &a), &b) in cu.iter_mut().zip(un).zip(uf) {
                    *u = 3 * a as u16 + b as u16;
                }
                for ((v, &a), &b) in cv.iter_mut().zip(vn).zip(vf) {
                    *v = 3 * a as u16 + b as u16;
                }
            }
        }

        expand_chroma(&cu, g.x0, &mut uq);
        expand_chroma(&cv, g.x0, &mut vq);

        let y_row = &src[l.y_offset + ay * l.y_stride + g.x0..][..w];
        // Planar passes: each is a simple zip over slices with no stores
        // other than one byte per lane, which LLVM vectorizes; the final pass
        // only interleaves.
        for ((r, &y), &v) in rr.iter_mut().zip(y_row).zip(vq.iter()) {
            let luma = 298 * 8 * (y as i32 - 16);
            let e = v as i32 - 128 * 8;
            *r = ((luma + 459 * e + 1024) >> 11).clamp(0, 255) as u8;
        }
        for (((gc, &y), &u), &v) in gg.iter_mut().zip(y_row).zip(uq.iter()).zip(vq.iter()) {
            let luma = 298 * 8 * (y as i32 - 16);
            let d = u as i32 - 128 * 8;
            let e = v as i32 - 128 * 8;
            *gc = ((luma - 55 * d - 136 * e + 1024) >> 11).clamp(0, 255) as u8;
        }
        for ((b, &y), &u) in bb.iter_mut().zip(y_row).zip(uq.iter()) {
            let luma = 298 * 8 * (y as i32 - 16);
            let d = u as i32 - 128 * 8;
            *b = ((luma + 541 * d + 1024) >> 11).clamp(0, 255) as u8;
        }
        for (((px, &r), &gc), &b) in out_row
            .chunks_exact_mut(4)
            .zip(rr.iter())
            .zip(gg.iter())
            .zip(bb.iter())
        {
            px.copy_from_slice(&[r, gc, b, 255]);
        }
    }
}

/// Vertical 0.75 / 0.25 blend of one interleaved chroma row pair into Q2
/// `cu`/`cv`. `U`/`V` are the byte positions of U and V inside each pair:
/// `<0, 1>` for NV12, `<1, 0>` for NV21. Constant indices keep each variant
/// the same branch-free, bounds-check-free loop.
fn blend_interleaved<const U: usize, const V: usize>(
    near: &[u8],
    far: &[u8],
    cu: &mut [u16],
    cv: &mut [u16],
) {
    for (((n, f), u), v) in near
        .chunks_exact(2)
        .zip(far.chunks_exact(2))
        .zip(cu.iter_mut())
        .zip(cv.iter_mut())
    {
        *u = 3 * n[U] as u16 + f[U] as u16;
        *v = 3 * n[V] as u16 + f[V] as u16;
    }
}

/// Expand one vertically blended chroma row (Q2, `c[0]` = chroma column
/// `x0 / 2`) to per-pixel Q3 values: an even luma column takes its co-sited
/// sample `2c[k]`, an odd one averages it with the next, `c[k] + c[k+1]`, the
/// last neighbour clamped to the row's final sample.
fn expand_chroma(c: &[u16], x0: usize, out: &mut [i16]) {
    let last = c.len() - 1;
    let w = out.len();
    let (mut x, mut ci) = (0usize, 0usize);
    if x0 & 1 == 1 {
        // First visible pixel is an odd column.
        out[0] = (c[0] + c[1.min(last)]) as i16;
        x = 1;
        ci = 1;
    }
    // Interior pairs, where the right neighbour exists: branch-free zip.
    let pairs_left = (w - x) / 2;
    let interior = pairs_left.min(last.saturating_sub(ci));
    for ((o, &a), &b) in out[x..x + interior * 2]
        .chunks_exact_mut(2)
        .zip(c.get(ci..).unwrap_or(&[]))
        .zip(c.get(ci + 1..).unwrap_or(&[]))
    {
        o[0] = (2 * a) as i16;
        o[1] = (a + b) as i16;
    }
    x += interior * 2;
    ci += interior;
    // Edge pair (clamped neighbour) and a possible trailing even column.
    if x + 1 < w {
        let a = c[ci.min(last)];
        out[x] = (2 * a) as i16;
        out[x + 1] = (a + c[(ci + 1).min(last)]) as i16;
        x += 2;
        ci += 1;
    }
    if x < w {
        out[x] = (2 * c[ci.min(last)]) as i16;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoder::nv12_to_rgba;

    struct Rng(u64);
    impl Rng {
        fn byte(&mut self) -> u8 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 >> 24) as u8
        }
        fn fill(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.byte()).collect()
        }
    }

    fn nv12_layout(w: usize, h: usize, stride: usize, slice: usize) -> PlaneLayout {
        PlaneLayout {
            chroma: Chroma::InterleavedUv,
            y_offset: 0,
            y_stride: stride,
            u_offset: stride * slice,
            v_offset: 0,
            uv_stride: stride,
            crop_x: 0,
            crop_y: 0,
            crop_w: w as u32,
            crop_h: h as u32,
        }
    }

    const SIZES: [(usize, usize); 10] = [
        (2, 2),
        (4, 2),
        (16, 16),
        (3, 5),
        (1, 1),
        (33, 17),
        (130, 66),
        (64, 1),
        (1, 64),
        (1920, 1080),
    ];

    #[test]
    fn nv12_matches_reference_byte_for_byte() {
        let mut rng = Rng(0x1234_5678_9abc_def1);
        for (w, h) in SIZES {
            let stride = w.next_multiple_of(2);
            let rows_uv = h.div_ceil(2);
            let y = rng.fill(stride * h);
            let uv = rng.fill(stride * rows_uv);
            let want = nv12_to_rgba(&y, &uv, w, h, stride).unwrap();
            let mut buf = y.clone();
            buf.extend_from_slice(&uv);
            let l = nv12_layout(w, h, stride, h);
            let mut out = Vec::new();
            yuv420_to_rgba(&buf, &l, &mut out).unwrap();
            assert_eq!(out, want, "{w}x{h}");
        }
    }

    #[test]
    fn i420_matches_nv12() {
        let mut rng = Rng(77);
        for (w, h) in SIZES {
            let cw = w.div_ceil(2);
            let ch = h.div_ceil(2);
            let y = rng.fill(w * h);
            let u = rng.fill(cw * ch);
            let v = rng.fill(cw * ch);
            let mut uv = Vec::new();
            for i in 0..cw * ch {
                uv.push(u[i]);
                uv.push(v[i]);
            }
            // nv12_to_rgba wants stride >= width and 2*cw bytes per UV row.
            let stride = (cw * 2).max(w);
            let mut yp = vec![0u8; stride * h];
            for r in 0..h {
                yp[r * stride..r * stride + w].copy_from_slice(&y[r * w..(r + 1) * w]);
            }
            let mut uvp = vec![0u8; stride * ch];
            for r in 0..ch {
                uvp[r * stride..r * stride + cw * 2]
                    .copy_from_slice(&uv[r * cw * 2..(r + 1) * cw * 2]);
            }
            let want = nv12_to_rgba(&yp, &uvp, w, h, stride).unwrap();

            let mut buf = y.clone();
            buf.extend_from_slice(&u);
            buf.extend_from_slice(&v);
            let l = PlaneLayout {
                chroma: Chroma::Planar,
                y_offset: 0,
                y_stride: w,
                u_offset: w * h,
                v_offset: w * h + cw * ch,
                uv_stride: cw,
                crop_x: 0,
                crop_y: 0,
                crop_w: w as u32,
                crop_h: h as u32,
            };
            let mut out = Vec::new();
            yuv420_to_rgba(&buf, &l, &mut out).unwrap();
            assert_eq!(out, want, "{w}x{h}");
        }
    }

    #[test]
    fn padded_strides_and_even_crop_match_subpicture() {
        let mut rng = Rng(4242);
        let (pw, ph) = (96usize, 80usize);
        let (stride, slice) = (128usize, 96usize);
        let buf = rng.fill(stride * slice * 3 / 2);
        let l0 = nv12_layout(pw, ph, stride, slice);
        // Full picture with padding vs tight copy.
        let mut y = vec![0u8; pw * ph];
        for r in 0..ph {
            y[r * pw..(r + 1) * pw].copy_from_slice(&buf[r * stride..r * stride + pw]);
        }
        let mut uv = vec![0u8; pw * ph / 2];
        for r in 0..ph / 2 {
            let o = stride * slice + r * stride;
            uv[r * pw..(r + 1) * pw].copy_from_slice(&buf[o..o + pw]);
        }
        let mut out = Vec::new();
        yuv420_to_rgba(&buf, &l0, &mut out).unwrap();
        assert_eq!(out, nv12_to_rgba(&y, &uv, pw, ph, pw).unwrap());

        // Even-aligned crop == nv12_to_rgba of the sub-picture.
        let (cx, cy, cw, chh) = (10usize, 6usize, 50usize, 40usize);
        let mut sy = vec![0u8; cw * chh];
        for r in 0..chh {
            sy[r * cw..(r + 1) * cw]
                .copy_from_slice(&y[(cy + r) * pw + cx..(cy + r) * pw + cx + cw]);
        }
        let mut suv = vec![0u8; cw * chh / 2];
        for r in 0..chh / 2 {
            let s = (cy / 2 + r) * pw + cx;
            suv[r * cw..(r + 1) * cw].copy_from_slice(&uv[s..s + cw]);
        }
        let want = nv12_to_rgba(&sy, &suv, cw, chh, cw).unwrap();
        let l = PlaneLayout {
            crop_x: cx as u32,
            crop_y: cy as u32,
            crop_w: cw as u32,
            crop_h: chh as u32,
            ..l0
        };
        yuv420_to_rgba(&buf, &l, &mut out).unwrap();
        assert_eq!(out, want);
    }

    #[test]
    fn odd_crops_stay_in_bounds_on_a_tight_buffer() {
        // Buffer is exactly as large as the layout needs: any over-read panics.
        let mut rng = Rng(9);
        for (x, y, w, h) in [
            (1, 1, 7, 5),
            (3, 0, 9, 2),
            (0, 3, 1, 1),
            (5, 5, 1, 3),
            (1, 0, 2, 2),
        ] {
            let (pw, ph) = (x + w + 1usize, y + h + 1usize);
            let stride = pw.next_multiple_of(2);
            let slice = ph.next_multiple_of(2);
            let mut l = nv12_layout(pw, ph, stride, slice);
            l.crop_x = x as u32;
            l.crop_y = y as u32;
            l.crop_w = w as u32;
            l.crop_h = h as u32;
            // Trim the buffer to the exact need.
            let need = validate(usize::MAX, &l).map(|_| ()).is_ok();
            assert!(need);
            let full = rng.fill(stride * slice * 3 / 2);
            let mut out = Vec::new();
            yuv420_to_rgba(&full, &l, &mut out).unwrap();
            assert_eq!(out.len(), w * h * 4);
            // Shrink to exactly what the geometry needs and retry.
            let cx1 = (x + w - 1) / 2;
            let cy1 = (y + h - 1) / 2;
            let exact =
                (stride * slice + cy1 * stride + (cx1 + 1) * 2).max((y + h - 1) * stride + x + w);
            let mut out2 = Vec::new();
            yuv420_to_rgba(&full[..exact], &l, &mut out2).unwrap();
            assert_eq!(out, out2);
        }
    }

    #[test]
    fn a_reused_buffer_converts_identically_without_reallocating() {
        let mut rng = Rng(0xbeef);
        for (w, h) in SIZES {
            let stride = w.next_multiple_of(2);
            let buf = rng.fill(stride * h + stride * h.div_ceil(2));
            let l = nv12_layout(w, h, stride, h);
            let mut fresh = Vec::new();
            yuv420_to_rgba(&buf, &l, &mut fresh).unwrap();

            // Right length, garbage contents: overwritten in place.
            let mut reused = rng.fill(w * h * 4);
            let ptr = reused.as_ptr();
            yuv420_to_rgba(&buf, &l, &mut reused).unwrap();
            assert_eq!(reused, fresh, "{w}x{h}");
            assert_eq!(reused.as_ptr(), ptr, "{w}x{h}: must not reallocate");

            // Wrong lengths (a size change) still come out exact.
            for len in [w * h * 4 + 7, (w * h * 4) / 2] {
                let mut other = rng.fill(len);
                yuv420_to_rgba(&buf, &l, &mut other).unwrap();
                assert_eq!(other, fresh, "{w}x{h} from len {len}");
            }
        }
    }

    #[test]
    fn short_buffers_error_instead_of_panicking() {
        let l = nv12_layout(64, 32, 64, 32);
        let mut out = Vec::new();
        let full = 64 * 32 * 3 / 2;
        let src = vec![128u8; full];
        assert!(yuv420_to_rgba(&src, &l, &mut out).is_ok());
        assert!(yuv420_to_rgba(&src[..full - 1], &l, &mut out).is_err());
        assert!(yuv420_to_rgba(&[], &l, &mut out).is_err());
        let mut bad = l;
        bad.crop_w = 0;
        assert!(yuv420_to_rgba(&src, &bad, &mut out).is_err());
        let mut bad = l;
        bad.y_stride = 10;
        assert!(yuv420_to_rgba(&src, &bad, &mut out).is_err());
        let mut bad = l;
        bad.u_offset = usize::MAX - 3;
        assert!(yuv420_to_rgba(&src, &bad, &mut out).is_err());
    }

    #[test]
    fn layout_nv12_and_i420() {
        let l = layout_from_format(21, 1920, 1080, 1920, 1088, Some((0, 0, 1919, 1079))).unwrap();
        assert_eq!(l.chroma, Chroma::InterleavedUv);
        assert_eq!(
            (l.y_stride, l.u_offset, l.uv_stride),
            (1920, 1920 * 1088, 1920)
        );
        assert_eq!((l.crop_x, l.crop_y, l.crop_w, l.crop_h), (0, 0, 1920, 1080));

        let l = layout_from_format(19, 64, 48, 80, 64, None).unwrap();
        assert_eq!(l.chroma, Chroma::Planar);
        assert_eq!(l.u_offset, 80 * 64);
        assert_eq!(l.uv_stride, 40);
        assert_eq!(l.v_offset, 80 * 64 + 40 * 32);
        assert_eq!((l.crop_w, l.crop_h), (64, 48));

        // Unreported stride/slice fall back to the picture size.
        let l = layout_from_format(21, 100, 60, 0, -1, None).unwrap();
        assert_eq!((l.y_stride, l.u_offset), (100, 100 * 60));
        let l = layout_from_format(0x7FA3_0C00, 100, 60, 0, 0, None).unwrap();
        assert_eq!((l.y_stride, l.u_offset), (100, 100 * 60));
    }

    #[test]
    fn layout_qcom_32m_alignment() {
        let l = layout_from_format(0x7FA3_0C04, 1080, 1920, 0, 0, None).unwrap();
        assert_eq!(l.y_stride, 1152);
        assert_eq!(l.u_offset, 1152 * 1920);
        assert_eq!(l.uv_stride, 1152);
        let l = layout_from_format(0x7FA3_0C04, 1920, 1080, 5, 3, None).unwrap();
        assert_eq!((l.y_stride, l.u_offset), (1920, 1920 * 1088));
        // A sane reported value wins.
        let l = layout_from_format(0x7FA3_0C04, 1920, 1080, 2048, 1088, None).unwrap();
        assert_eq!((l.y_stride, l.u_offset), (2048, 2048 * 1088));
    }

    #[test]
    fn layout_rejects_bad_input() {
        let e = layout_from_format(0x7F000789, 64, 64, 64, 64, None).unwrap_err();
        assert!(e.to_string().contains("0x7F000789"), "{e}");
        assert!(layout_from_format(21, 0, 64, 64, 64, None).is_err());
        assert!(layout_from_format(21, 64, 64, 64, 64, Some((0, 0, 64, 63))).is_err());
        assert!(layout_from_format(21, 64, 64, 64, 64, Some((-1, 0, 10, 10))).is_err());
        assert!(layout_from_format(21, 64, 64, 64, 64, Some((10, 0, 9, 10))).is_err());
        assert!(layout_from_format(21, 64, 64, 64, 64, Some((0, 0, 63, 64))).is_err());
        // Odd crop sizes are fine.
        let l = layout_from_format(21, 64, 64, 64, 64, Some((1, 1, 7, 5))).unwrap();
        assert_eq!((l.crop_w, l.crop_h), (7, 5));
    }

    /// The NV21 twin of an NV12 buffer: every chroma pair swapped in place,
    /// luma and padding untouched.
    fn swap_chroma_pairs(nv12: &[u8], l: &PlaneLayout, chroma_rows: usize) -> Vec<u8> {
        let mut nv21 = nv12.to_vec();
        for r in 0..chroma_rows {
            let row = l.u_offset + r * l.uv_stride;
            if row >= nv21.len() {
                break;
            }
            let end = (row + l.uv_stride).min(nv21.len());
            for pair in nv21[row..end].chunks_exact_mut(2) {
                pair.swap(0, 1);
            }
        }
        nv21
    }

    #[test]
    fn nv21_matches_nv12_from_the_same_planes() {
        let mut rng = Rng(0x0021_0012);
        // Tight frames of every test size.
        for (w, h) in SIZES {
            let stride = w.next_multiple_of(2);
            let rows_uv = h.div_ceil(2);
            let buf = rng.fill(stride * h + stride * rows_uv);
            let l12 = nv12_layout(w, h, stride, h);
            let l21 = PlaneLayout {
                chroma: Chroma::InterleavedVu,
                ..l12
            };
            let nv21 = swap_chroma_pairs(&buf, &l12, rows_uv);
            let (mut want, mut got) = (Vec::new(), Vec::new());
            yuv420_to_rgba(&buf, &l12, &mut want).unwrap();
            yuv420_to_rgba(&nv21, &l21, &mut got).unwrap();
            assert_eq!(got, want, "{w}x{h}");
        }
        // Padded strides, a nonzero Y offset and odd crops, on a buffer
        // trimmed to exactly what the layout needs (an over-read panics).
        let (pw, ph, stride, slice, y_off) = (37usize, 29usize, 48usize, 32usize, 64usize);
        let full = rng.fill(y_off + stride * slice + stride * slice / 2);
        for (x, y, w, h) in [(0, 0, 37, 29), (1, 1, 7, 5), (3, 2, 33, 26), (36, 28, 1, 1)] {
            let l12 = PlaneLayout {
                chroma: Chroma::InterleavedUv,
                y_offset: y_off,
                y_stride: stride,
                u_offset: y_off + stride * slice,
                v_offset: 0,
                uv_stride: stride,
                crop_x: x,
                crop_y: y,
                crop_w: w,
                crop_h: h,
            };
            let l21 = PlaneLayout {
                chroma: Chroma::InterleavedVu,
                ..l12
            };
            let (cx1, cy1) = ((x + w - 1) as usize / 2, (y + h - 1) as usize / 2);
            let exact = (l12.u_offset + cy1 * stride + (cx1 + 1) * 2)
                .max(y_off + (y + h - 1) as usize * stride + (x + w) as usize);
            let nv12 = &full[..exact];
            let nv21 = swap_chroma_pairs(nv12, &l12, ph.div_ceil(2));
            let (mut want, mut got) = (Vec::new(), Vec::new());
            yuv420_to_rgba(nv12, &l12, &mut want).unwrap();
            yuv420_to_rgba(&nv21, &l21, &mut got).unwrap();
            assert_eq!(got, want, "crop {x},{y} {w}x{h} of {pw}x{ph}");
            assert!(yuv420_to_rgba(&nv21[..exact - 1], &l21, &mut got).is_err());
        }
    }

    #[test]
    fn nv21_is_not_nv12_unless_chroma_is_symmetric() {
        // Guards against InterleavedVu silently reading U,V: a frame whose U
        // and V differ must convert differently under the two layouts.
        let (w, h) = (4usize, 2usize);
        let mut buf = vec![128u8; w * h];
        buf.extend_from_slice(&[60, 200, 60, 200]);
        let l12 = nv12_layout(w, h, w, h);
        let l21 = PlaneLayout {
            chroma: Chroma::InterleavedVu,
            ..l12
        };
        let (mut a, mut b) = (Vec::new(), Vec::new());
        yuv420_to_rgba(&buf, &l12, &mut a).unwrap();
        yuv420_to_rgba(&buf, &l21, &mut b).unwrap();
        assert_ne!(a, b);
        // U=60, V=200 read as NV12 is reddish (R > B); as NV21 the roles swap.
        assert!(a[0] > a[2] && b[2] > b[0], "{:?} {:?}", &a[..4], &b[..4]);
    }

    /// `cargo test -p directdesk-client --release yuv -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn bench_1080p() {
        use std::time::Instant;
        let mut rng = Rng(5);
        for (w, h, slice) in [(1920usize, 1080usize, 1088usize), (2560, 1600, 1600)] {
            let buf = rng.fill(w * slice * 3 / 2);
            let l = nv12_layout(w, h, w, slice);
            let mut out = Vec::new();
            yuv420_to_rgba(&buf, &l, &mut out).unwrap();
            let n = 60;
            let t = Instant::now();
            for _ in 0..n {
                yuv420_to_rgba(&buf, &l, &mut out).unwrap();
            }
            let ms = t.elapsed().as_secs_f64() * 1000.0 / n as f64;
            println!("{w}x{h}: {ms:.2} ms/frame (single-threaded)");
        }
    }
}
