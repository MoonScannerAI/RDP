//! Minimal H.264 Annex-B helpers for decoders that need stream parameters up
//! front (Android MediaCodec is configured with the frame size and the
//! SPS/PPS as `csd-0`/`csd-1`).
//!
//! The SPS parser is ported from the host's (`host/src/mf_encoder.rs`) so both
//! ends agree on what the stream says.
//!
//! CONTRACT (Phase 1.0 scaffold): signatures fixed; bodies filled in by W3.

use directdesk_shared::error::Result;

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
pub fn split_nals(annexb: &[u8]) -> Vec<Nal<'_>> {
    let _ = annexb;
    todo!("W3")
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

/// Parse an SPS NAL (header byte included, emulation-prevention bytes still
/// present — the parser strips them).
pub fn parse_sps(sps_nal: &[u8]) -> Result<SpsInfo> {
    let _ = sps_nal;
    todo!("W3")
}

/// The codec-specific data a keyframe carries: its SPS and PPS NALs, each
/// returned *with* a 4-byte Annex-B start code prepended (the form MediaCodec
/// expects in `csd-0`/`csd-1`). `None` if either is missing.
pub fn extract_csd(annexb: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let _ = annexb;
    todo!("W3")
}
