//! Lossless static-region refinement: wire format and codec.
//!
//! H.264 carries motion. When a region of the desktop stops changing, the host
//! re-sends it **losslessly** over a reliable QUIC stream and the client
//! composites it over the decoded video. Small text then converges to
//! pixel-exact instead of sitting at whatever the encoder's quantiser left.
//!
//! This module is deliberately pure: no I/O, no Windows, no async. It is shared
//! so host and client cannot disagree about the format, and so the codec's
//! round-trip can be property-tested on any machine.
//!
//! # Colour contract (read this before touching the codec)
//!
//! The host captures **BGRA**. The client's decoded frames are **RGBA**. The
//! wire carries **BGR**, in capture order, with alpha discarded.
//!
//! - [`compress_strip`] takes BGRA and emits BGR.
//! - [`decompress_strip`] takes BGR and emits RGBA with alpha forced to `255`.
//!
//! The channel swap and the alpha fill happen once, here, at admission — not in
//! the compositor's blit, which stays a `copy_from_slice` per row. Dropping
//! alpha is not a loss: the desktop is opaque, and it makes the `Sub` filter's
//! residual exactly zero across runs of identical pixels, which is most of a
//! text page.
//!
//! "Lossless" therefore means: every colour byte survives bit-exact. Alpha is
//! defined to be opaque rather than transmitted.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Tile edge in pixels.
///
/// 64 matches RDP's tile size and DXGI's dirty-rect granularity, and 64 rows of
/// BGR is enough context for deflate to find real matches.
pub const TILE_EDGE: u32 = 64;

/// Maximum tiles coalesced into one horizontal strip.
///
/// Compressing a 256x64 block rather than four 64x64 blocks gives deflate a
/// much longer match window across a line of text, and amortises the per-message
/// envelope. Strips never cross a tile row.
pub const MAX_STRIP_TILES: u32 = 4;

/// Maximum strip width in pixels.
pub const MAX_STRIP_W: u32 = TILE_EDGE * MAX_STRIP_TILES;

/// Bytes per pixel on the wire (BGR, alpha dropped).
const WIRE_BPP: usize = 3;

/// Bytes per pixel in host capture buffers and client frame buffers (BGRA/RGBA).
const FRAME_BPP: usize = 4;

/// Deflate's stored-block overhead: 5 bytes of header per 65535-byte block, and
/// incompressible input is stored rather than expanded.
const DEFLATE_STORED_OVERHEAD: usize = 5 * 2;

/// Slack for the postcard envelope around the payload (discriminant, varint
/// coordinates, timestamps, the data length prefix).
const ENVELOPE_SLACK: usize = 64;

/// Worst-case encoded size of one strip: every row incompressible, every row
/// carrying its filter byte.
pub const MAX_STRIP_ENCODED: usize = (MAX_STRIP_W as usize * WIRE_BPP + 1) * TILE_EDGE as usize
    + DEFLATE_STORED_OVERHEAD
    + ENVELOPE_SLACK;

// The whole reason strips are capped at 4 tiles: a strip must fit inside one
// control message, so `encode_framed` and its 64 KiB pre-allocation cap need no
// change at all. If this ever fails, shrink MAX_STRIP_TILES — do not raise
// MAX_CONTROL_MSG, which is a wire-visible constant on a shipped protocol.
const _: () = assert!(MAX_STRIP_ENCODED < crate::protocol::MAX_CONTROL_MSG);

/// How a strip's pixels are encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TileCodec {
    /// The whole strip is one colour. Payload is exactly 3 bytes, `[b, g, r]`.
    ///
    /// Worth a variant of its own: `blank_wallpaper_during_session` defaults
    /// true, so a large share of a session's screen is literally solid black and
    /// costs 3 bytes here instead of a deflate stream.
    Solid,
    /// PNG-style adaptive per-row filter over BGR, then raw deflate.
    FilteredDeflateBgr,
}

/// Messages on the host-to-client unidirectional tile stream.
///
/// Ordering matters and is guaranteed by the stream: a [`TileMsg::Revoke`]
/// issued after a [`TileMsg::Strip`] for the same tile always applies after it.
/// That is what makes per-tile generation counters unnecessary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TileMsg {
    /// Drop everything and re-arm for a grid of this size. Sent when the stream
    /// opens, on resolution change, and on reconnect.
    Reset {
        width: u32,
        height: u32,
        /// Tile edge in force. Sent rather than assumed so a future host can
        /// change it without a protocol version bump.
        edge: u32,
    },
    /// Lossless pixels for a horizontal run of up to [`MAX_STRIP_TILES`] tiles.
    ///
    /// `valid_from_ms` and `lease_ms` are on the **host capture clock** — the
    /// same `u32` the decoder recovers into `RawFrame::timestamp_ms`. The client
    /// paints this strip only while the frame it is painting onto falls inside
    /// the lease. Delay can only shorten a tile's life, never extend it.
    Strip {
        x: u32,
        y: u32,
        w: u32,
        h: u32,
        codec: TileCodec,
        valid_from_ms: u32,
        lease_ms: u32,
        data: Vec<u8>,
    },
    /// These tiles are stale — stop painting them. Never dropped, never
    /// reordered relative to strips.
    Revoke { ids: Vec<u32> },
    /// Extend the lease on tiles that are still exact, so a long-static screen
    /// does not have to re-send pixels merely to stay alive.
    Renew {
        ids: Vec<u32>,
        valid_through_ms: u32,
    },
}

/// Identity of a tile within the grid: `row * cols + col`.
///
/// Both sides derive this from the [`TileMsg::Reset`] dimensions, so a stale id
/// from a previous resolution cannot alias a live one — the store is cleared and
/// disarmed until the next `Reset`.
#[must_use]
pub fn tile_id(col: u32, row: u32, cols: u32) -> u32 {
    row * cols + col
}

/// Number of tile columns covering `width` pixels.
#[must_use]
pub fn tile_cols(width: u32, edge: u32) -> u32 {
    width.div_ceil(edge)
}

/// Number of tile rows covering `height` pixels.
#[must_use]
pub fn tile_rows(height: u32, edge: u32) -> u32 {
    height.div_ceil(edge)
}

// ---------------------------------------------------------------------------
// Row filters
// ---------------------------------------------------------------------------

/// PNG filter type codes. `Average` is deliberately omitted: it buys little on
/// screen content and every extra candidate costs a full pass over the row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Filter {
    None = 0,
    Sub = 1,
    Up = 2,
    Paeth = 4,
}

impl Filter {
    const CANDIDATES: [Filter; 4] = [Filter::None, Filter::Sub, Filter::Up, Filter::Paeth];

    fn from_code(code: u8) -> Result<Filter> {
        match code {
            0 => Ok(Filter::None),
            1 => Ok(Filter::Sub),
            2 => Ok(Filter::Up),
            4 => Ok(Filter::Paeth),
            other => Err(Error::Invalid(format!("unknown tile row filter {other}"))),
        }
    }
}

/// The PNG Paeth predictor: pick whichever neighbour the gradient points at.
#[inline]
fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let p = a as i16 + b as i16 - c as i16;
    let pa = (p - a as i16).abs();
    let pb = (p - b as i16).abs();
    let pc = (p - c as i16).abs();
    if pa <= pb && pa <= pc {
        a
    } else if pb <= pc {
        b
    } else {
        c
    }
}

/// Apply `filter` to `row`, writing residuals into `out`.
///
/// `prior` is the *unfiltered* previous row, or an all-zero slice for row 0.
fn filter_row(filter: Filter, row: &[u8], prior: &[u8], out: &mut Vec<u8>) {
    let bpp = WIRE_BPP;
    match filter {
        Filter::None => out.extend_from_slice(row),
        Filter::Sub => {
            for i in 0..row.len() {
                let left = if i >= bpp { row[i - bpp] } else { 0 };
                out.push(row[i].wrapping_sub(left));
            }
        }
        Filter::Up => {
            for i in 0..row.len() {
                out.push(row[i].wrapping_sub(prior[i]));
            }
        }
        Filter::Paeth => {
            for i in 0..row.len() {
                let left = if i >= bpp { row[i - bpp] } else { 0 };
                let up = prior[i];
                let up_left = if i >= bpp { prior[i - bpp] } else { 0 };
                out.push(row[i].wrapping_sub(paeth(left, up, up_left)));
            }
        }
    }
}

/// Reverse `filter` in place over `row`, given the already-reconstructed `prior`.
fn unfilter_row(filter: Filter, row: &mut [u8], prior: &[u8]) {
    let bpp = WIRE_BPP;
    match filter {
        Filter::None => {}
        Filter::Sub => {
            for i in bpp..row.len() {
                row[i] = row[i].wrapping_add(row[i - bpp]);
            }
        }
        Filter::Up => {
            for i in 0..row.len() {
                row[i] = row[i].wrapping_add(prior[i]);
            }
        }
        Filter::Paeth => {
            for i in 0..row.len() {
                let left = if i >= bpp { row[i - bpp] } else { 0 };
                let up = prior[i];
                let up_left = if i >= bpp { prior[i - bpp] } else { 0 };
                row[i] = row[i].wrapping_add(paeth(left, up, up_left));
            }
        }
    }
}

/// Sum of absolute signed residuals — the standard PNG heuristic for picking a
/// filter without actually compressing each candidate.
fn residual_cost(buf: &[u8]) -> u64 {
    buf.iter().map(|&b| (b as i8).unsigned_abs() as u64).sum()
}

// ---------------------------------------------------------------------------
// Codec
// ---------------------------------------------------------------------------

/// Compress a `w * h` rectangle at `(x, y)` out of a full-frame **BGRA** buffer.
///
/// `stride` is the source buffer's row stride in bytes. Returns the codec that
/// was chosen and the payload for [`TileMsg::Strip::data`].
pub fn compress_strip(
    bgra: &[u8],
    stride: usize,
    x: u32,
    y: u32,
    w: u32,
    h: u32,
    level: u8,
) -> Result<(TileCodec, Vec<u8>)> {
    if w == 0 || h == 0 || w > MAX_STRIP_W || h > TILE_EDGE {
        return Err(Error::Invalid(format!("bad strip extent {w}x{h}")));
    }
    let (xs, ys, ws, hs) = (x as usize, y as usize, w as usize, h as usize);
    // The last row we touch must be fully inside the buffer.
    let last = ys
        .checked_add(hs - 1)
        .and_then(|r| r.checked_mul(stride))
        .and_then(|o| o.checked_add((xs + ws) * FRAME_BPP))
        .ok_or_else(|| Error::Invalid("strip extent overflows".into()))?;
    if last > bgra.len() || (xs + ws) * FRAME_BPP > stride {
        return Err(Error::Invalid("strip extends past source buffer".into()));
    }

    // Pass 1: pull BGRA down to packed BGR, and notice a uniform strip while we
    // are already touching every pixel.
    let mut raw = Vec::with_capacity(ws * hs * WIRE_BPP);
    let mut solid = true;
    let first = {
        let o = ys * stride + xs * FRAME_BPP;
        [bgra[o], bgra[o + 1], bgra[o + 2]]
    };
    for row in 0..hs {
        let base = (ys + row) * stride + xs * FRAME_BPP;
        for col in 0..ws {
            let o = base + col * FRAME_BPP;
            let px = [bgra[o], bgra[o + 1], bgra[o + 2]];
            solid &= px == first;
            raw.extend_from_slice(&px);
        }
    }
    if solid {
        return Ok((TileCodec::Solid, first.to_vec()));
    }

    // Pass 2: adaptive per-row filter.
    let row_bytes = ws * WIRE_BPP;
    let mut filtered = Vec::with_capacity(hs * (row_bytes + 1));
    let mut candidate = Vec::with_capacity(row_bytes);
    let zero = vec![0u8; row_bytes];
    for row in 0..hs {
        let cur = &raw[row * row_bytes..(row + 1) * row_bytes];
        let prior = if row == 0 {
            &zero[..]
        } else {
            &raw[(row - 1) * row_bytes..row * row_bytes]
        };
        let mut best = (Filter::None, u64::MAX, Vec::new());
        for &f in &Filter::CANDIDATES {
            candidate.clear();
            filter_row(f, cur, prior, &mut candidate);
            let cost = residual_cost(&candidate);
            if cost < best.1 {
                best = (f, cost, candidate.clone());
            }
        }
        filtered.push(best.0 as u8);
        filtered.extend_from_slice(&best.2);
    }

    // Pass 3: raw deflate (no zlib wrapper — the length is already framed).
    use std::io::Write;
    let mut enc = flate2::write::DeflateEncoder::new(
        Vec::with_capacity(filtered.len() / 4),
        flate2::Compression::new(u32::from(level.min(9))),
    );
    enc.write_all(&filtered)
        .map_err(|e| Error::Invalid(format!("tile deflate failed: {e}")))?;
    let data = enc
        .finish()
        .map_err(|e| Error::Invalid(format!("tile deflate finish failed: {e}")))?;
    Ok((TileCodec::FilteredDeflateBgr, data))
}

/// Decode a strip payload into tightly-packed **RGBA** (`w * h * 4` bytes,
/// alpha `255`), replacing `out`.
///
/// This runs on untrusted input, so the inflated size is bounded to exactly what
/// a `w * h` strip can legally produce rather than growing on demand.
pub fn decompress_strip(
    codec: TileCodec,
    data: &[u8],
    w: u32,
    h: u32,
    out: &mut Vec<u8>,
) -> Result<()> {
    if w == 0 || h == 0 || w > MAX_STRIP_W || h > TILE_EDGE {
        return Err(Error::Invalid(format!("bad strip extent {w}x{h}")));
    }
    let (ws, hs) = (w as usize, h as usize);
    let row_bytes = ws * WIRE_BPP;

    out.clear();
    out.resize(ws * hs * FRAME_BPP, 0);

    match codec {
        TileCodec::Solid => {
            if data.len() != WIRE_BPP {
                return Err(Error::Invalid(format!(
                    "solid strip payload is {} bytes, want {WIRE_BPP}",
                    data.len()
                )));
            }
            // Wire is BGR; frame is RGBA.
            for px in out.chunks_exact_mut(FRAME_BPP) {
                px[0] = data[2];
                px[1] = data[1];
                px[2] = data[0];
                px[3] = 255;
            }
            Ok(())
        }
        TileCodec::FilteredDeflateBgr => {
            let want = hs * (row_bytes + 1);
            let mut filtered = vec![0u8; want];
            let mut inflate = flate2::Decompress::new(false);
            let status = inflate
                .decompress(data, &mut filtered, flate2::FlushDecompress::Finish)
                .map_err(|e| Error::Invalid(format!("tile inflate failed: {e}")))?;
            // Both a short and a long stream are corruption: the strip's
            // dimensions fix the byte count exactly.
            if inflate.total_out() as usize != want || status == flate2::Status::BufError {
                return Err(Error::Invalid(format!(
                    "tile inflated to {} bytes, want {want}",
                    inflate.total_out()
                )));
            }

            // Unfilter into a BGR scratch, then expand to RGBA.
            //
            // Row 0 has no predecessor and the filters treat it as all-zero, so
            // it reads a zero row that is allocated **once** here rather than
            // per row — the same shape `compress_strip`'s filter pass uses. Only
            // row 0 ever looks at it; at 64 rows a strip this was 63 allocations
            // per strip that nothing read.
            let zero = vec![0u8; row_bytes];
            let mut bgr = vec![0u8; hs * row_bytes];
            for row in 0..hs {
                let code = filtered[row * (row_bytes + 1)];
                let filter = Filter::from_code(code)?;
                let src = &filtered[row * (row_bytes + 1) + 1..(row + 1) * (row_bytes + 1)];
                let (done, rest) = bgr.split_at_mut(row * row_bytes);
                let cur = &mut rest[..row_bytes];
                cur.copy_from_slice(src);
                let prior: &[u8] = if row == 0 {
                    &zero
                } else {
                    &done[(row - 1) * row_bytes..]
                };
                unfilter_row(filter, cur, prior);
            }

            for (dst, src) in out.chunks_exact_mut(FRAME_BPP).zip(bgr.chunks_exact(WIRE_BPP)) {
                dst[0] = src[2];
                dst[1] = src[1];
                dst[2] = src[0];
                dst[3] = 255;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Build a BGRA frame buffer and round-trip a strip out of it, returning the
    /// decoded RGBA.
    fn roundtrip(bgra: &[u8], stride: usize, x: u32, y: u32, w: u32, h: u32) -> Vec<u8> {
        let (codec, data) = compress_strip(bgra, stride, x, y, w, h, 6).expect("compress");
        let mut out = Vec::new();
        decompress_strip(codec, &data, w, h, &mut out).expect("decompress");
        out
    }

    /// Assert the decoded RGBA equals the source BGRA rect, channel-swapped and
    /// alpha-filled. This is the premise of the entire feature.
    fn assert_exact(bgra: &[u8], stride: usize, x: u32, y: u32, w: u32, h: u32, got: &[u8]) {
        assert_eq!(got.len(), (w * h * 4) as usize);
        for row in 0..h as usize {
            for col in 0..w as usize {
                let s = (y as usize + row) * stride + (x as usize + col) * FRAME_BPP;
                let d = (row * w as usize + col) * FRAME_BPP;
                assert_eq!(got[d], bgra[s + 2], "R at {col},{row}");
                assert_eq!(got[d + 1], bgra[s + 1], "G at {col},{row}");
                assert_eq!(got[d + 2], bgra[s], "B at {col},{row}");
                assert_eq!(got[d + 3], 255, "A at {col},{row}");
            }
        }
    }

    #[test]
    fn solid_strip_costs_three_bytes() {
        let (w, h) = (256u32, 64u32);
        let stride = (w * 4) as usize;
        let bgra = vec![0u8; stride * h as usize];
        let (codec, data) = compress_strip(&bgra, stride, 0, 0, w, h, 6).unwrap();
        assert_eq!(codec, TileCodec::Solid);
        assert_eq!(data.len(), 3);
        let got = roundtrip(&bgra, stride, 0, 0, w, h);
        assert_exact(&bgra, stride, 0, 0, w, h, &got);
    }

    #[test]
    fn synthetic_text_compresses_hard_and_exactly() {
        // Monochrome glyph-ish content: the case the whole feature exists for.
        let (w, h) = (256u32, 64u32);
        let stride = (w * 4) as usize;
        let mut bgra = vec![255u8; stride * h as usize];
        for row in 0..h as usize {
            for col in 0..w as usize {
                if (col / 3 + row / 5) % 7 == 0 {
                    let o = row * stride + col * 4;
                    bgra[o..o + 4].copy_from_slice(&[0, 0, 0, 255]);
                }
            }
        }
        let (codec, data) = compress_strip(&bgra, stride, 0, 0, w, h, 6).unwrap();
        assert_eq!(codec, TileCodec::FilteredDeflateBgr);
        let ratio = data.len() as f64 / (w * h * 3) as f64;
        assert!(ratio < 0.3, "text should compress hard, got ratio {ratio}");
        let got = roundtrip(&bgra, stride, 0, 0, w, h);
        assert_exact(&bgra, stride, 0, 0, w, h, &got);
    }

    #[test]
    fn partial_edge_strip_roundtrips() {
        // Edge tiles are partial; nothing may assume a multiple of 64.
        let stride = 1920 * 4;
        let mut bgra = vec![0u8; stride * 1080];
        for (i, b) in bgra.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let (x, y, w, h) = (1792u32, 1024u32, 128u32, 56u32);
        let got = roundtrip(&bgra, stride, x, y, w, h);
        assert_exact(&bgra, stride, x, y, w, h, &got);
    }

    #[test]
    fn rejects_extent_past_buffer() {
        let stride = 256 * 4;
        let bgra = vec![0u8; stride * 64];
        assert!(compress_strip(&bgra, stride, 0, 60, 256, 64, 6).is_err());
        assert!(compress_strip(&bgra, stride, 200, 0, 256, 64, 6).is_err());
        assert!(compress_strip(&bgra, stride, 0, 0, 0, 64, 6).is_err());
        assert!(compress_strip(&bgra, stride, 0, 0, 512, 64, 6).is_err());
    }

    #[test]
    fn rejects_malformed_payloads() {
        let mut out = Vec::new();
        assert!(decompress_strip(TileCodec::Solid, &[1, 2], 64, 64, &mut out).is_err());
        assert!(decompress_strip(TileCodec::FilteredDeflateBgr, &[], 64, 64, &mut out).is_err());
        assert!(
            decompress_strip(TileCodec::FilteredDeflateBgr, &[0xff; 32], 64, 64, &mut out).is_err()
        );
        // A valid stream decoded at the wrong dimensions must be rejected, not
        // silently reinterpreted.
        let stride = 256 * 4;
        let mut bgra = vec![0u8; stride * 64];
        for (i, b) in bgra.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let (codec, data) = compress_strip(&bgra, stride, 0, 0, 256, 64, 6).unwrap();
        assert!(decompress_strip(codec, &data, 128, 64, &mut out).is_err());
    }

    #[test]
    fn grid_geometry_covers_partial_edges() {
        assert_eq!(tile_cols(1920, 64), 30);
        assert_eq!(tile_rows(1080, 64), 17); // 16 full rows + a 56px remainder
        assert_eq!(tile_cols(1, 64), 1);
        assert_eq!(tile_id(3, 2, 30), 63);
    }

    proptest! {
        /// The single most important test in the feature: compress then
        /// decompress is bit-exact, over random, solid, gradient and
        /// structured inputs.
        #[test]
        fn compress_decompress_is_byte_identical(
            w in 1u32..=MAX_STRIP_W,
            h in 1u32..=TILE_EDGE,
            kind in 0u8..4,
            seed in any::<u64>(),
        ) {
            let stride = (MAX_STRIP_W * 4) as usize;
            let mut bgra = vec![0u8; stride * TILE_EDGE as usize];
            let mut s = seed | 1;
            for (i, b) in bgra.iter_mut().enumerate() {
                *b = match kind {
                    0 => { s ^= s << 13; s ^= s >> 7; s ^= s << 17; (s & 0xff) as u8 }
                    1 => 0x20,
                    2 => ((i / 4) % 256) as u8,
                    _ => if (i / 4 / 3) % 5 == 0 { 0 } else { 255 },
                };
            }
            let (codec, data) = compress_strip(&bgra, stride, 0, 0, w, h, 6).unwrap();
            let mut out = Vec::new();
            decompress_strip(codec, &data, w, h, &mut out).unwrap();

            prop_assert_eq!(out.len(), (w * h * 4) as usize);
            for row in 0..h as usize {
                for col in 0..w as usize {
                    let src = row * stride + col * FRAME_BPP;
                    let d = (row * w as usize + col) * FRAME_BPP;
                    prop_assert_eq!(out[d], bgra[src + 2]);
                    prop_assert_eq!(out[d + 1], bgra[src + 1]);
                    prop_assert_eq!(out[d + 2], bgra[src]);
                    prop_assert_eq!(out[d + 3], 255);
                }
            }
        }
    }
}
