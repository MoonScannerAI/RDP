//! Minimal H.264 Annex-B helpers for decoders that need stream parameters up
//! front (Android MediaCodec is configured with the frame size and the
//! SPS/PPS as `csd-0`/`csd-1`).
//!
//! The SPS parser is ported from the host's (`host/src/mf_encoder.rs`) so both
//! ends agree on what the stream says: same emulation-prevention stripping and
//! Exp-Golomb reader, extended here to walk the whole SPS up to the frame
//! cropping fields.

use directdesk_shared::error::{Error, Result};

/// One NAL unit inside an Annex-B buffer, without its start code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nal<'a> {
    /// `nal_unit_type` (low 5 bits of the header byte): 7 = SPS, 8 = PPS,
    /// 5 = IDR slice, 1 = non-IDR slice, 9 = access-unit delimiter.
    pub nal_type: u8,
    /// Header byte included.
    pub data: &'a [u8],
}

/// Split an Annex-B buffer on 3- and 4-byte start codes.
///
/// Zero-copy: every [`Nal::data`] borrows from `annexb`. Bytes before the first
/// start code are ignored, trailing zero bytes (the leading zero of a 4-byte
/// start code, or `trailing_zero_8bits`) are not part of the NAL, and empty
/// NALs (back-to-back start codes) are skipped.
pub fn split_nals(annexb: &[u8]) -> Vec<Nal<'_>> {
    let mut out = Vec::new();
    // Payload start of the NAL currently being collected.
    let mut start: Option<usize> = None;
    let mut i = 0usize;
    while i + 2 < annexb.len() {
        if annexb[i + 2] > 1 {
            // Neither of these three bytes can start or be inside `00 00 01`.
            i += 3;
        } else if annexb[i] == 0 && annexb[i + 1] == 0 && annexb[i + 2] == 1 {
            if let Some(s) = start {
                push_nal(&mut out, &annexb[s..i]);
            }
            start = Some(i + 3);
            i += 3;
        } else {
            i += 1;
        }
    }
    if let Some(s) = start {
        push_nal(&mut out, &annexb[s..]);
    }
    out
}

fn push_nal<'a>(out: &mut Vec<Nal<'a>>, raw: &'a [u8]) {
    // A NAL never ends in 0x00 (RBSP trailing bits), so these zeros belong to
    // the next start code or to trailing padding.
    let end = raw.iter().rposition(|&b| b != 0).map_or(0, |p| p + 1);
    let data = &raw[..end];
    if let Some(&hdr) = data.first() {
        out.push(Nal {
            nal_type: hdr & 0x1F,
            data,
        });
    }
}

/// Frame parameters read from an SPS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpsInfo {
    pub profile_idc: u8,
    pub level_idc: u8,
    /// Display size after frame cropping, in pixels.
    pub width: u32,
    pub height: u32,
}

/// Profiles whose SPS carries the chroma/bit-depth extension (7.3.2.1.1).
const EXTENDED_PROFILES: [u8; 13] = [100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135];

/// Parse an SPS NAL (header byte included, emulation-prevention bytes still
/// present — the parser strips them).
pub fn parse_sps(sps_nal: &[u8]) -> Result<SpsInfo> {
    fn bad(what: &str) -> Error {
        Error::Decoder(format!("bad SPS: {what}"))
    }
    let trunc = || bad("truncated");

    let (&hdr, payload) = sps_nal.split_first().ok_or_else(|| bad("empty"))?;
    if hdr & 0x1F != 7 {
        return Err(bad("not an SPS NAL"));
    }
    let rbsp = unescape_rbsp(payload);
    let profile_idc = *rbsp.first().ok_or_else(trunc)?;
    let level_idc = *rbsp.get(2).ok_or_else(trunc)?;
    let mut r = BitReader::new(&rbsp[3..]);

    let _sps_id = r.ue().ok_or_else(trunc)?;
    let mut chroma_format_idc = 1u32;
    let mut separate_colour_plane = false;
    if EXTENDED_PROFILES.contains(&profile_idc) {
        chroma_format_idc = r.ue().ok_or_else(trunc)?;
        if chroma_format_idc > 3 {
            return Err(bad("chroma_format_idc"));
        }
        if chroma_format_idc == 3 {
            separate_colour_plane = r.bit().ok_or_else(trunc)? == 1;
        }
        let _bit_depth_luma = r.ue().ok_or_else(trunc)?;
        let _bit_depth_chroma = r.ue().ok_or_else(trunc)?;
        let _qpprime_bypass = r.bit().ok_or_else(trunc)?;
        if r.bit().ok_or_else(trunc)? == 1 {
            let lists = if chroma_format_idc != 3 { 8 } else { 12 };
            for i in 0..lists {
                if r.bit().ok_or_else(trunc)? == 1 {
                    r.skip_scaling_list(if i < 6 { 16 } else { 64 })
                        .ok_or_else(trunc)?;
                }
            }
        }
    }
    let _log2_max_frame_num = r.ue().ok_or_else(trunc)?;
    match r.ue().ok_or_else(trunc)? {
        0 => {
            let _log2_max_poc_lsb = r.ue().ok_or_else(trunc)?;
        }
        1 => {
            let _delta_pic_order_always_zero = r.bit().ok_or_else(trunc)?;
            let _offset_for_non_ref_pic = r.se().ok_or_else(trunc)?;
            let _offset_for_top_to_bottom = r.se().ok_or_else(trunc)?;
            let n = r.ue().ok_or_else(trunc)?;
            if n > 255 {
                return Err(bad("num_ref_frames_in_pic_order_cnt_cycle"));
            }
            for _ in 0..n {
                r.se().ok_or_else(trunc)?;
            }
        }
        _ => {}
    }
    let _max_num_ref_frames = r.ue().ok_or_else(trunc)?;
    let _gaps = r.bit().ok_or_else(trunc)?;
    let w_mbs = r.ue().ok_or_else(trunc)? as u64 + 1;
    let h_map_units = r.ue().ok_or_else(trunc)? as u64 + 1;
    let frame_mbs_only = r.bit().ok_or_else(trunc)? == 1;
    if !frame_mbs_only {
        let _mb_adaptive = r.bit().ok_or_else(trunc)?;
    }
    let _direct_8x8 = r.bit().ok_or_else(trunc)?;

    let (mut cl, mut cr, mut ct, mut cb) = (0u64, 0u64, 0u64, 0u64);
    if r.bit().ok_or_else(trunc)? == 1 {
        cl = r.ue().ok_or_else(trunc)? as u64;
        cr = r.ue().ok_or_else(trunc)? as u64;
        ct = r.ue().ok_or_else(trunc)? as u64;
        cb = r.ue().ok_or_else(trunc)? as u64;
    }

    let chroma_array_type = if separate_colour_plane {
        0
    } else {
        chroma_format_idc
    };
    let (sub_w, sub_h) = match chroma_array_type {
        1 => (2, 2),
        2 => (2, 1),
        _ => (1, 1), // monochrome / 4:4:4
    };
    let crop_unit_x = sub_w;
    let crop_unit_y = sub_h * if frame_mbs_only { 1 } else { 2 };

    let full_w = w_mbs * 16;
    let full_h = h_map_units * 16 * if frame_mbs_only { 1 } else { 2 };
    let crop_w = (cl + cr) * crop_unit_x;
    let crop_h = (ct + cb) * crop_unit_y;
    if crop_w >= full_w || crop_h >= full_h {
        return Err(bad("cropping exceeds picture"));
    }
    Ok(SpsInfo {
        profile_idc,
        level_idc,
        width: (full_w - crop_w) as u32,
        height: (full_h - crop_h) as u32,
    })
}

/// The codec-specific data a keyframe carries: its SPS and PPS NALs, each
/// returned *with* a 4-byte Annex-B start code prepended (the form MediaCodec
/// expects in `csd-0`/`csd-1`). `None` if either is missing.
pub fn extract_csd(annexb: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let (mut sps, mut pps) = (None, None);
    for nal in split_nals(annexb) {
        let slot = match nal.nal_type {
            7 => &mut sps,
            8 => &mut pps,
            _ => continue,
        };
        if slot.is_none() {
            let mut v = Vec::with_capacity(nal.data.len() + 4);
            v.extend_from_slice(&[0, 0, 0, 1]);
            v.extend_from_slice(nal.data);
            *slot = Some(v);
        }
    }
    Some((sps?, pps?))
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
        zeros = if byte == 0 { zeros + 1 } else { 0 };
        out.push(byte);
    }
    out
}

/// Big-endian bit reader with Exp-Golomb decode (same shape as the host's).
struct BitReader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> BitReader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }

    fn bit(&mut self) -> Option<u32> {
        let byte = *self.b.get(self.pos / 8)?;
        let v = (byte >> (7 - self.pos % 8)) & 1;
        self.pos += 1;
        Some(v as u32)
    }

    fn bits(&mut self, n: u32) -> Option<u32> {
        let mut v = 0u32;
        for _ in 0..n {
            v = (v << 1) | self.bit()?;
        }
        Some(v)
    }

    /// Unsigned Exp-Golomb. `None` on truncation or an absurd code.
    fn ue(&mut self) -> Option<u32> {
        let mut leading = 0u32;
        while self.bit()? == 0 {
            leading += 1;
            if leading > 31 {
                return None;
            }
        }
        if leading == 0 {
            return Some(0);
        }
        let rest = self.bits(leading)?;
        Some(((1u64 << leading) - 1 + rest as u64).min(u32::MAX as u64) as u32)
    }

    /// Signed Exp-Golomb.
    fn se(&mut self) -> Option<i32> {
        let k = self.ue()? as i64;
        let v = if k & 1 == 1 { (k + 1) / 2 } else { -(k / 2) };
        Some(v as i32)
    }

    /// `scaling_list()` (7.3.2.1.1.1): only the syntax is consumed.
    fn skip_scaling_list(&mut self, size: usize) -> Option<()> {
        let (mut last, mut next) = (8i32, 8i32);
        for _ in 0..size {
            if next != 0 {
                let delta = self.se()?;
                next = (last + delta + 256).rem_euclid(256);
            }
            if next != 0 {
                last = next;
            }
        }
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MSB-first bit writer producing an RBSP.
    struct BitWriter {
        bytes: Vec<u8>,
        nbits: usize,
    }

    impl BitWriter {
        fn new() -> Self {
            Self {
                bytes: Vec::new(),
                nbits: 0,
            }
        }
        fn bit(&mut self, b: u32) {
            if self.nbits.is_multiple_of(8) {
                self.bytes.push(0);
            }
            if b != 0 {
                *self.bytes.last_mut().unwrap() |= 0x80 >> (self.nbits % 8);
            }
            self.nbits += 1;
        }
        fn bits(&mut self, v: u32, n: u32) {
            for i in (0..n).rev() {
                self.bit((v >> i) & 1);
            }
        }
        fn ue(&mut self, v: u32) {
            let x = v as u64 + 1;
            let len = 64 - x.leading_zeros();
            self.bits(0, len - 1);
            for i in (0..len).rev() {
                self.bit(((x >> i) & 1) as u32);
            }
        }
        fn se(&mut self, v: i32) {
            self.ue(if v > 0 {
                (2 * v - 1) as u32
            } else {
                (-2 * v) as u32
            });
        }
    }

    /// Insert emulation-prevention bytes.
    fn escape(rbsp: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut zeros = 0;
        for &b in rbsp {
            if zeros >= 2 && b <= 3 {
                out.push(3);
                zeros = 0;
            }
            zeros = if b == 0 { zeros + 1 } else { 0 };
            out.push(b);
        }
        out
    }

    struct Spec {
        profile: u8,
        chroma_format_idc: u32,
        scaling: bool,
        mbs_w: u32,
        map_h: u32,
        frame_mbs_only: bool,
        /// left, right, top, bottom (in crop units)
        crop: [u32; 4],
        poc_type: u32,
    }

    fn base(profile: u8, w: u32, h: u32, crop_bottom: u32) -> Spec {
        Spec {
            profile,
            chroma_format_idc: 1,
            scaling: false,
            mbs_w: w.div_ceil(16),
            map_h: h.div_ceil(16),
            frame_mbs_only: true,
            crop: [0, 0, 0, crop_bottom],
            poc_type: 0,
        }
    }

    fn build_sps(s: &Spec) -> Vec<u8> {
        let mut w = BitWriter::new();
        w.bits(s.profile as u32, 8);
        w.bits(0, 8);
        w.bits(40, 8);
        w.ue(0);
        if EXTENDED_PROFILES.contains(&s.profile) {
            w.ue(s.chroma_format_idc);
            if s.chroma_format_idc == 3 {
                w.bit(0);
            }
            w.ue(0);
            w.ue(0);
            w.bit(0);
            w.bit(s.scaling as u32);
            if s.scaling {
                let lists = if s.chroma_format_idc != 3 { 8 } else { 12 };
                for i in 0..lists {
                    match i % 3 {
                        0 => w.bit(0), // not present
                        1 => {
                            // present, "use default": delta makes next == 0
                            w.bit(1);
                            w.se(-8);
                        }
                        _ => {
                            w.bit(1);
                            let size = if i < 6 { 16 } else { 64 };
                            let mut last = 8;
                            for j in 0..size {
                                if j == size / 2 && i % 2 == 0 {
                                    w.se(-last); // next = 0: the rest repeats
                                    break;
                                }
                                w.se(1 + (j % 3));
                                last += 1 + (j % 3);
                            }
                        }
                    }
                }
            }
        }
        w.ue(4); // log2_max_frame_num_minus4
        w.ue(s.poc_type);
        match s.poc_type {
            0 => w.ue(2),
            1 => {
                w.bit(0);
                w.se(-3);
                w.se(5);
                w.ue(3);
                for k in 0..3 {
                    w.se(k - 1);
                }
            }
            _ => {}
        }
        w.ue(4);
        w.bit(0);
        w.ue(s.mbs_w - 1);
        w.ue(s.map_h - 1);
        w.bit(s.frame_mbs_only as u32);
        if !s.frame_mbs_only {
            w.bit(0);
        }
        w.bit(1);
        let cropped = s.crop.iter().any(|&c| c != 0);
        w.bit(cropped as u32);
        if cropped {
            for c in s.crop {
                w.ue(c);
            }
        }
        w.bit(0); // no VUI
        w.bit(1); // rbsp stop bit
        let mut nal = vec![0x67];
        nal.extend(escape(&w.bytes));
        nal
    }

    fn dims(s: &Spec) -> (u32, u32) {
        let i = parse_sps(&build_sps(s)).unwrap();
        (i.width, i.height)
    }

    #[test]
    fn sps_1080p_cropped_from_1088() {
        let s = base(100, 1920, 1088, 4); // 4 * CropUnitY(2) = 8 rows
        let info = parse_sps(&build_sps(&s)).unwrap();
        assert_eq!((info.width, info.height), (1920, 1080));
        assert_eq!((info.profile_idc, info.level_idc), (100, 40));
    }

    #[test]
    fn sps_2560x1600_and_720p() {
        assert_eq!(dims(&base(100, 2560, 1600, 0)), (2560, 1600));
        assert_eq!(dims(&base(66, 1280, 720, 0)), (1280, 720));
        assert_eq!(dims(&base(77, 1280, 736, 8)), (1280, 720));
    }

    #[test]
    fn sps_high_profile_with_scaling_lists() {
        for chroma in [1, 2, 3] {
            let mut s = base(100, 1920, 1088, 0);
            s.chroma_format_idc = chroma;
            s.scaling = true;
            // CropUnitY is 2 for 4:2:0 and 1 otherwise.
            s.crop = [0, 0, 0, if chroma == 1 { 4 } else { 8 }];
            assert_eq!(dims(&s), (1920, 1080), "chroma {chroma}");
        }
        let mut s = base(244, 640, 480, 0);
        s.scaling = true;
        assert_eq!(dims(&s), (640, 480));
    }

    #[test]
    fn sps_poc_types_interlaced_and_horizontal_crop() {
        let mut s = base(77, 1920, 1088, 0);
        s.poc_type = 1;
        assert_eq!(dims(&s), (1920, 1088));
        s.poc_type = 2;
        assert_eq!(dims(&s), (1920, 1088));
        // Field coded: map units are 32 rows tall, CropUnitY is 4 for 4:2:0.
        let mut s = base(77, 1920, 1088, 0);
        s.frame_mbs_only = false;
        s.map_h = 34;
        s.crop = [0, 0, 0, 4]; // 4 * 4 = 16 rows
        assert_eq!(dims(&s), (1920, 34 * 32 - 16));
        // Horizontal crop: CropUnitX is 2 for 4:2:0.
        let mut s = base(100, 1920, 1088, 0);
        s.crop = [1, 2, 0, 0];
        assert_eq!(dims(&s), (1920 - 6, 1088));
    }

    #[test]
    fn sps_with_emulation_prevention_bytes() {
        // A 24-bit-long Exp-Golomb prefix guarantees two whole zero bytes in
        // the RBSP, so the writer must escape them as 00 00 03.
        let mut s = base(66, 16, 16, 0);
        s.mbs_w = (1 << 24) + 1;
        let nal = build_sps(&s);
        assert!(
            nal.windows(3).any(|x| x == [0, 0, 3]),
            "vector has no escape"
        );
        assert_eq!(parse_sps(&nal).unwrap().width, ((1 << 24) + 1) * 16);
    }

    #[test]
    fn sps_real_x264_2560x1600() {
        // From libx264 (High profile); contains 00 00 03 escapes.
        let sps = [
            0x67u8, 0x64, 0x00, 0x32, 0xac, 0xb4, 0x01, 0x40, 0x06, 0x4d, 0x80, 0x88, 0x00, 0x00,
            0x03, 0x00, 0x08, 0x00, 0x00, 0x03, 0x01, 0xe4, 0x78, 0xc1, 0x95,
        ];
        let info = parse_sps(&sps).unwrap();
        assert_eq!((info.width, info.height), (2560, 1600));
        assert_eq!((info.profile_idc, info.level_idc), (100, 50));
    }

    #[test]
    fn sps_errors_never_panic() {
        assert!(parse_sps(&[]).is_err());
        assert!(parse_sps(&[0x68, 1, 2, 3]).is_err());
        assert!(parse_sps(&[0x67, 100]).is_err());
        let nal = build_sps(&base(100, 1920, 1088, 0));
        for n in 1..nal.len() {
            let _ = parse_sps(&nal[..n]);
        }
        assert!(parse_sps(&nal[..8]).is_err());
    }

    #[test]
    fn split_basic_and_edge_cases() {
        let b = [
            0, 0, 0, 1, 0x67, 1, 2, // 4-byte start code
            0, 0, 1, 0x68, 3, // 3-byte
            0, 0, 1, 0, 0, 1, // empty NAL between start codes
            0, 0, 0, 1, 0x65, 9, 9, 0, 0, // trailing zeros
        ];
        let n = split_nals(&b);
        assert_eq!(n.len(), 3);
        assert_eq!((n[0].nal_type, n[0].data), (7, &[0x67, 1, 2][..]));
        assert_eq!((n[1].nal_type, n[1].data), (8, &[0x68, 3][..]));
        assert_eq!((n[2].nal_type, n[2].data), (5, &[0x65, 9, 9][..]));
        // Zero-copy.
        let p = n[0].data.as_ptr() as usize;
        assert!(p >= b.as_ptr() as usize && p < b.as_ptr() as usize + b.len());
    }

    #[test]
    fn split_degenerate_inputs() {
        assert!(split_nals(&[]).is_empty());
        assert!(split_nals(&[0, 0]).is_empty());
        assert!(split_nals(&[1, 2, 3, 4]).is_empty());
        assert!(split_nals(&[0, 0, 1]).is_empty());
        assert!(split_nals(&[0, 0, 0, 1, 0, 0, 0, 1]).is_empty());
        let n = split_nals(&[9, 9, 0, 0, 1, 0x41, 7]);
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].nal_type, 1);
        let n = split_nals(&[0, 0, 1, 0x61, 5, 0, 0, 1, 0x61, 6]);
        assert_eq!(n.len(), 2);
        // Start code immediately after a non-zero run the skip-ahead steps over.
        let n = split_nals(&[0, 0, 1, 0x65, 7, 7, 0, 0, 1, 0x41, 1]);
        assert_eq!(n.len(), 2);
        assert_eq!(n[1].data, &[0x41, 1]);
    }

    #[test]
    fn extract_csd_from_keyframe() {
        let mut b = vec![0, 0, 0, 1, 0x09, 0x10];
        b.extend([0, 0, 0, 1, 0x67, 0x64, 0, 0x32]);
        b.extend([0, 0, 0, 1, 0x68, 0xef, 0x3c, 0xb0]);
        b.extend([0, 0, 1, 0x65, 0x88, 0x84, 0, 0, 0]);
        let (sps, pps) = extract_csd(&b).unwrap();
        assert_eq!(sps, [0, 0, 0, 1, 0x67, 0x64, 0, 0x32]);
        assert_eq!(pps, [0, 0, 0, 1, 0x68, 0xef, 0x3c, 0xb0]);
        // Missing PPS / SPS.
        assert!(extract_csd(&b[..14]).is_none());
        assert!(extract_csd(&[0, 0, 0, 1, 0x65, 1]).is_none());
        assert!(extract_csd(&[]).is_none());
    }
}
