//! Stride- and crop-aware YUV 4:2:0 → RGBA8 conversion for decoders that hand
//! back CPU planes with arbitrary layout (Android MediaCodec output buffers).
//!
//! The Windows path keeps using [`crate::decoder::nv12_to_rgba`]; this module
//! must produce identical pixels for a tightly packed NV12 frame (same
//! limited-range BT.709 matrix), which the tests pin.
//!
//! CONTRACT (Phase 1.0 scaffold): signatures fixed; bodies filled in by W3.

use directdesk_shared::error::Result;

/// Chroma arrangement of a 4:2:0 frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chroma {
    /// One interleaved U,V plane (NV12).
    InterleavedUv,
    /// Separate U then V planes (I420).
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
    /// Byte offset of row 0 of the UV plane (NV12) or the U plane (I420).
    pub u_offset: usize,
    /// Byte offset of row 0 of the V plane (I420 only; unused for NV12).
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

/// Derive a [`PlaneLayout`] from MediaCodec's output-format keys.
///
/// `color_format`: 19 (I420), 21 (NV12), 0x7FA30C00 / 0x7FA30C04 (Qualcomm
/// NV12 variants). Anything else is an error naming the value in hex.
/// `stride`/`slice_height` fall back to `width`/`height` when the codec does
/// not report them (<= 0). `crop` is MediaCodec's inclusive
/// (left, top, right, bottom), when present.
pub fn layout_from_format(
    color_format: i32,
    width: i32,
    height: i32,
    stride: i32,
    slice_height: i32,
    crop: Option<(i32, i32, i32, i32)>,
) -> Result<PlaneLayout> {
    let _ = (color_format, width, height, stride, slice_height, crop);
    todo!("W3")
}

/// Convert the visible rectangle of `src` (laid out per `layout`) to tightly
/// packed RGBA8, limited-range BT.709, alpha 255. `out` is resized to
/// `crop_w * crop_h * 4`. Errors if `src` is too short for `layout`.
pub fn yuv420_to_rgba(src: &[u8], layout: &PlaneLayout, out: &mut Vec<u8>) -> Result<()> {
    let _ = (src, layout, out);
    todo!("W3")
}
