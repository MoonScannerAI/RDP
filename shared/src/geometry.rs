//! Coordinate mapping between normalized wire coordinates (0..=u16::MAX over
//! the video frame) and physical pixels on either end.

/// Map a physical pixel in a `dim`-sized frame to normalized 0..=u16::MAX.
pub fn to_norm(px: u32, dim: u32) -> u16 {
    if dim <= 1 {
        return 0;
    }
    let clamped = px.min(dim - 1) as u64;
    ((clamped * u16::MAX as u64) / (dim as u64 - 1)) as u16
}

/// Map a normalized coordinate back to a physical pixel in a `dim`-sized frame.
pub fn from_norm(norm: u16, dim: u32) -> u32 {
    if dim <= 1 {
        return 0;
    }
    ((norm as u64 * (dim as u64 - 1) + u16::MAX as u64 / 2) / u16::MAX as u64) as u32
}

/// Compute the letterboxed destination rect for rendering a `src` aspect frame
/// inside a `dst` viewport. Returns (x, y, w, h).
pub fn fit_rect(src_w: u32, src_h: u32, dst_w: u32, dst_h: u32) -> (u32, u32, u32, u32) {
    if src_w == 0 || src_h == 0 || dst_w == 0 || dst_h == 0 {
        return (0, 0, 0, 0);
    }
    let scale = f64::min(dst_w as f64 / src_w as f64, dst_h as f64 / src_h as f64);
    let w = (src_w as f64 * scale).round() as u32;
    let h = (src_h as f64 * scale).round() as u32;
    ((dst_w - w) / 2, (dst_h - h) / 2, w.max(1), h.max(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn norm_roundtrip_corners() {
        for dim in [2u32, 1080, 1920, 3840] {
            assert_eq!(from_norm(to_norm(0, dim), dim), 0);
            assert_eq!(from_norm(to_norm(dim - 1, dim), dim), dim - 1);
        }
    }

    #[test]
    fn norm_roundtrip_error_bounded() {
        let dim = 1920u32;
        for px in (0..dim).step_by(7) {
            let back = from_norm(to_norm(px, dim), dim);
            assert!((back as i64 - px as i64).abs() <= 1, "px={px} back={back}");
        }
    }

    #[test]
    fn fit_rect_letterboxes() {
        // 16:9 into a square viewport → horizontal bars
        let (x, y, w, h) = fit_rect(1920, 1080, 1000, 1000);
        assert_eq!((x, w), (0, 1000));
        assert!(y > 0 && h < 1000);
    }
}
