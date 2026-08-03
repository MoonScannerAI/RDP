//! Deterministic synthetic frame content with a self-describing content hash.
//!
//! The host's frame source produces, for frame `id`, a payload laid out as
//! `fnv1a64(body).to_le_bytes() || body`, where `body` is a pure function of
//! `id`. That makes every presented frame checkable twice over:
//!
//! * the embedded hash proves the fragments were concatenated in the right
//!   order and none were silently truncated or swapped, and
//! * regenerating `body` from the delivered `frame_id` proves the frame that
//!   arrived is the frame the host captured under that id — a mis-ordered or
//!   mis-labelled frame cannot pass.
//!
//! Nothing here reads a clock or an RNG: the same id always yields the same
//! bytes, in this process and in any other.

/// Width of the content hash prefix, in bytes.
pub const HASH_LEN: usize = 8;

/// FNV-1a over 64 bits. Written out rather than pulled from a crate so the
/// expected bytes never change as a side effect of a dependency update.
#[must_use]
pub fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// The body bytes a frame with this id must carry.
#[must_use]
pub fn synth_body(frame_id: u32, body_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(body_len);
    // An LCG rather than the netsim RNG: this is content, not scheduling, and
    // it must stay independent of how many packets the simulator has drawn for.
    let mut state = u64::from(frame_id).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x5DEE_CE66_D1CE_1234;
    for i in 0..body_len {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        out.push(((state >> 33) as u8) ^ (i as u8));
    }
    out
}

/// Full frame payload for `frame_id`: hash prefix followed by the body.
///
/// `total_len` includes the [`HASH_LEN`] prefix and is clamped so at least one
/// body byte is always produced (`fragment_frame` rejects empty frames).
#[must_use]
pub fn synth_payload(frame_id: u32, total_len: usize) -> Vec<u8> {
    let body_len = total_len.saturating_sub(HASH_LEN).max(1);
    let body = synth_body(frame_id, body_len);
    let mut out = Vec::with_capacity(HASH_LEN + body_len);
    out.extend_from_slice(&fnv1a64(&body).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// Whether `data` is exactly the payload frame `frame_id` should carry.
///
/// Checks the embedded hash first (cheap, catches reassembly corruption) and
/// then the full regenerated content (catches a frame delivered under the wrong
/// id).
#[must_use]
pub fn verify_payload(frame_id: u32, data: &[u8]) -> bool {
    if data.len() <= HASH_LEN {
        return false;
    }
    let (prefix, body) = data.split_at(HASH_LEN);
    let stored = u64::from_le_bytes(prefix.try_into().expect("split_at guarantees 8 bytes"));
    if stored != fnv1a64(body) {
        return false;
    }
    body == synth_body(frame_id, body.len()).as_slice()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_round_trips() {
        for id in [1u32, 2, 1000, u32::MAX] {
            let p = synth_payload(id, 4000);
            assert_eq!(p.len(), 4000);
            assert!(verify_payload(id, &p));
        }
    }

    #[test]
    fn wrong_id_or_corruption_is_caught() {
        let p = synth_payload(7, 512);
        assert!(!verify_payload(8, &p), "content is bound to the frame id");

        let mut corrupt = p.clone();
        corrupt[HASH_LEN + 3] ^= 0xFF;
        assert!(!verify_payload(7, &corrupt), "body corruption must fail the hash");

        // Fragments concatenated out of order: swap two halves of the body.
        let mut swapped = p.clone();
        let body = &p[HASH_LEN..];
        let half = body.len() / 2;
        swapped[HASH_LEN..HASH_LEN + half].copy_from_slice(&body[half..half * 2]);
        swapped[HASH_LEN + half..HASH_LEN + half * 2].copy_from_slice(&body[..half]);
        assert!(!verify_payload(7, &swapped));
    }

    #[test]
    fn payload_is_stable_and_never_empty() {
        assert_eq!(synth_payload(3, 4000), synth_payload(3, 4000));
        assert_eq!(synth_payload(3, 0).len(), HASH_LEN + 1);
    }
}
