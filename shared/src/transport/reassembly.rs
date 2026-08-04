//! Datagram fragment reassembly for the video path.
//!
//! # Slot model
//!
//! Every in-flight frame owns a *slot*: the header metadata declared by its
//! first fragment plus a `Vec<Option<Vec<u8>>>` sized `frag_count`, indexed by
//! `frag_index`. Fragments may arrive in any order, may be duplicated, and may
//! never arrive at all. A slot completes when every index is filled; the
//! payloads are then concatenated **by index**, so fragments of unequal size
//! (the last one always is) reassemble correctly. Slot count is bounded by
//! [`ReassemblyConfig::max_slots`]; slots die by completion, timeout, staleness
//! or overflow eviction, so a lossy link can never grow this structure without
//! bound.
//!
//! # Wrapping serial arithmetic
//!
//! `frame_id` is a `u32` that wraps. Plain `<` is therefore wrong: after the
//! wrap, `0` is *newer* than `0xFFFF_FFFF`. All ordering goes through
//! [`is_newer`], an RFC 1982 style serial-number comparison
//! (`a.wrapping_sub(b) != 0 && a.wrapping_sub(b) < 0x8000_0000`), and all
//! distance checks go through `wrapping_sub`.
//!
//! # Latest wins
//!
//! Completed frames land in a small ready queue. A live screen-share wants the
//! *newest* picture, not a faithful replay of a stalled one, so with
//! [`ReassemblyConfig::latest_wins`] set (the default) [`Reassembler::pop_frame`]
//! returns the newest queued frame and discards the older ones, counting them in
//! [`ReassemblyStats::frames_skipped_latest_wins`]. Turning it off yields frames
//! in completion order instead.
//!
//! # Injected clock
//!
//! Nothing here reads the system clock. Every method that ages state takes
//! `now_ms`, so ageing, timeouts and the keyframe-request rate limiter are
//! exactly reproducible in tests.
//!
//! No monotonic floor is kept. An earlier version clamped every injected
//! timestamp to the highest ever seen, which defended against a clock stepping
//! backwards but made the opposite mistake permanent: one absurd `now_ms` — a
//! microsecond/millisecond slip, a wall-clock/monotonic mix-up — pinned the
//! floor forever, disabling slot expiry and starving the keyframe limiter for
//! the life of the session. Instead each timestamp is taken at face value and
//! both consumers are individually self-healing: a slot dated in the future is
//! expired on sight, and a rate limiter whose recorded instant is in the future
//! re-arms rather than starving.
//!
//! # Frame-id window
//!
//! `newest_seen` is what staleness is measured against, so letting a single
//! datagram move it arbitrarily far forward is a denial-of-service: one
//! well-formed datagram claiming a frame id 2^30 ahead would evict every live
//! slot and make every subsequent legitimate fragment look ancient, wedging the
//! video path for the life of the session. A forward jump beyond
//! [`ReassemblyConfig::max_forward_jump`] is therefore refused outright.
//!
//! Refusing outright would in turn strand a *legitimate* renumbering — an
//! encoder restart resets `frame_id` to 0 — so out-of-window ids are also
//! counted. Once [`ReassemblyConfig::resync_after`] consecutive out-of-window
//! datagrams agree with each other, the reassembler adopts the new numbering
//! and demands a keyframe. Any in-window datagram resets that counter, so on a
//! live stream an attacker cannot accumulate the run.
//!
//! # Error handling
//!
//! [`Reassembler::push`] returns `Err` for malformed or contradictory
//! datagrams and keeps working afterwards. A hostile or corrupt datagram must
//! never kill the session: the caller logs the error, counts it, and carries on.

use std::collections::VecDeque;

use crate::error::{Error, Result};
use crate::video::{EncodedFrame, FragHeader, MAX_FRAME_BYTES};

/// Upper bound on completed-but-not-yet-popped frames. Overflow drops the
/// oldest, which is the same policy `latest_wins` applies on the way out.
const MAX_READY_FRAMES: usize = 8;

/// Serial-number comparison for wrapping `u32` frame ids.
///
/// Returns `true` when `a` is strictly newer than `b`, treating the id space as
/// a circle: the half-space `1..=0x7FFF_FFFF` ahead of `b` counts as newer, so
/// `is_newer(0, 0xFFFF_FFFF)` is `true`. Never use plain `<` on frame ids.
#[inline]
#[must_use]
pub fn is_newer(a: u32, b: u32) -> bool {
    let delta = a.wrapping_sub(b);
    delta != 0 && delta < 0x8000_0000
}

/// True when `id` sits more than `distance` frames behind `newest` in serial
/// order. Ids at or ahead of `newest` are never stale.
#[inline]
fn is_stale(newest: u32, id: u32, distance: u32) -> bool {
    let behind = newest.wrapping_sub(id);
    behind != 0 && behind < 0x8000_0000 && behind > distance
}

/// Tuning knobs for [`Reassembler`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReassemblyConfig {
    /// Max number of concurrently tracked incomplete frames. Default 8.
    ///
    /// A value of `0` is treated as `1`; the reassembler always keeps at least
    /// one slot so that forward progress is possible.
    pub max_slots: usize,
    /// Discard an incomplete frame once a frame this many ids newer has been
    /// seen. Default 4.
    pub stale_frame_distance: u32,
    /// Discard an incomplete frame after this many ms with no new fragment.
    /// Default 500. `0` disables the timeout entirely (slots are then reclaimed
    /// only by staleness, overflow or completion).
    pub slot_timeout_ms: u64,
    /// Minimum interval between `need_keyframe` signals. Default 500.
    pub keyframe_request_min_interval_ms: u64,
    /// If true, [`Reassembler::pop_frame`] skips older completed frames when a
    /// newer complete frame is already available (latest-wins). Default true.
    pub latest_wins: bool,
    /// Largest forward jump in `frame_id` a single datagram may cause. Default
    /// 64 — generous next to `stale_frame_distance`, but far short of the
    /// half-id-space a serial comparison would otherwise accept. See the module
    /// docs for why this bound exists.
    pub max_forward_jump: u32,
    /// How many consecutive out-of-window datagrams must agree before the
    /// reassembler adopts a new numbering. Default 8. `0` is treated as 1.
    pub resync_after: u32,
}

impl Default for ReassemblyConfig {
    fn default() -> Self {
        Self {
            max_slots: 8,
            stale_frame_distance: 4,
            slot_timeout_ms: 500,
            keyframe_request_min_interval_ms: 500,
            latest_wins: true,
            max_forward_jump: 64,
            resync_after: 8,
        }
    }
}

impl ReassemblyConfig {
    /// Reject settings that would silently prevent reassembly.
    ///
    /// `max_slots == 0` and `resync_after == 0` are tolerated (both are clamped
    /// to 1), but a `max_forward_jump` of zero would refuse every frame after
    /// the first, and `stale_frame_distance` at half the id space would make
    /// staleness meaningless.
    pub fn validate(&self) -> Result<()> {
        if self.max_forward_jump == 0 {
            return Err(Error::Invalid("max_forward_jump must be non-zero".into()));
        }
        if self.stale_frame_distance >= 0x8000_0000 {
            return Err(Error::Invalid(
                "stale_frame_distance must be under 2^31".into(),
            ));
        }
        if self.max_forward_jump >= 0x8000_0000 {
            return Err(Error::Invalid("max_forward_jump must be under 2^31".into()));
        }
        Ok(())
    }
}

/// Cumulative counters describing what the reassembler has seen.
///
/// The fragment counters partition every [`Reassembler::push`] call exactly
/// once: `fragments_received + fragments_duplicate + fragments_rejected +
/// fec_parity_received` equals the number of pushes, where `fragments_rejected`
/// equals the number of `Err` returns. FEC recovery is *not* a push — it bumps
/// `fec_recovered` (and a slot's internal received count) without touching any
/// of the partition categories.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReassemblyStats {
    /// Frames fully reassembled and handed to the ready queue.
    pub frames_completed: u64,
    /// Incomplete frames abandoned on timeout, slot overflow or byte cap.
    pub frames_dropped_incomplete: u64,
    /// Incomplete frames abandoned because newer frames left them behind.
    pub frames_dropped_stale: u64,
    /// Completed frames discarded without being popped (latest-wins or ready
    /// queue overflow).
    pub frames_skipped_latest_wins: u64,
    /// Completed frames dropped at `pop_frame` because they were not newer than
    /// a frame already delivered — a straggler slot that finished after being
    /// overtaken. On a healthy link this stays zero; a rising count is direct
    /// evidence the network is delivering frames out of order.
    pub frames_dropped_reorder: u64,
    /// Fragments accepted into a slot.
    pub fragments_received: u64,
    /// Fragments ignored as duplicates or as late arrivals for a frame that is
    /// already finished or already aged out.
    pub fragments_duplicate: u64,
    /// Fragments refused with an error: malformed header, metadata that
    /// contradicts an existing slot, or a frame exceeding the byte cap.
    pub fragments_rejected: u64,
    /// Parity fragments accepted into a slot (its own push category).
    pub fec_parity_received: u64,
    /// Data fragments reconstructed from a block's parity, never received on the
    /// wire. Recovery bumps a slot's `received` count but is not a push.
    pub fec_recovered: u64,
    /// Number of times [`Reassembler::take_keyframe_request`] returned true.
    pub keyframe_requests: u64,
}

/// One partially received frame.
#[derive(Debug)]
struct Slot {
    frame_id: u32,
    frag_count: u16,
    keyframe: bool,
    timestamp_ms: u32,
    /// One entry per `frag_index`; `None` until that fragment arrives.
    parts: Vec<Option<Vec<u8>>>,
    /// Number of `Some` entries in `parts` (including FEC-recovered ones).
    received: u16,
    /// Sum of the stored payload lengths.
    bytes: usize,
    /// Injected clock value of the most recent accepted fragment.
    last_update_ms: u64,
    /// FEC block size K (0 = no FEC). Read from the fragment header.
    fec_k: u16,
    /// One entry per FEC block; `None` until that block's parity arrives.
    /// Empty when `fec_k == 0`.
    parity: Vec<Option<Vec<u8>>>,
    /// Byte length of the frame's final (short) data fragment, learned from a
    /// parity fragment; needed to trim a recovered last fragment.
    last_frag_len: u16,
    /// Whether `timestamp_ms` is authoritative. A slot first opened by a parity
    /// fragment has no real timestamp (parity repurposes that field), so the
    /// first data fragment adopts one rather than colliding with it.
    timestamp_known: bool,
}

impl Slot {
    fn new(header: &FragHeader, now_ms: u64) -> Self {
        // `frag_count` is validated to be 1..=MAX_FRAGS_PER_FRAME by
        // `FragHeader::decode`, so this allocation is bounded by 512 entries.
        let fec_k = header.block_size as u16;
        let parity = if fec_k > 0 {
            vec![None; header.frag_count.div_ceil(fec_k) as usize]
        } else {
            Vec::new()
        };
        Self {
            frame_id: header.frame_id,
            frag_count: header.frag_count,
            keyframe: header.keyframe,
            // A parity fragment carries no real timestamp (0); the first data
            // fragment fills it in. `timestamp_known` tracks which is which.
            timestamp_ms: header.timestamp_ms,
            parts: vec![None; header.frag_count as usize],
            received: 0,
            bytes: 0,
            last_update_ms: now_ms,
            fec_k,
            parity,
            last_frag_len: 0,
            timestamp_known: !header.parity,
        }
    }

    fn into_frame(self) -> EncodedFrame {
        let mut data = Vec::with_capacity(self.bytes);
        for part in self.parts.into_iter().flatten() {
            data.extend_from_slice(&part);
        }
        EncodedFrame {
            frame_id: self.frame_id,
            keyframe: self.keyframe,
            timestamp_ms: self.timestamp_ms,
            data,
        }
    }
}

/// Reassembles datagram fragments into [`EncodedFrame`]s.
///
/// Completed frames are **only** available through [`Reassembler::pop_frame`];
/// [`Reassembler::push`] reports completion as a `bool` and enqueues the frame.
/// This single-exit design keeps the latest-wins policy in one place.
#[derive(Debug)]
pub struct Reassembler {
    config: ReassemblyConfig,
    /// Bounded by `config.max_slots`; a `Vec` is faster and inherently
    /// deterministic at this size, unlike `HashMap` iteration.
    slots: Vec<Slot>,
    ready: VecDeque<EncodedFrame>,
    /// Newest frame id seen in any accepted or considered fragment.
    newest_seen: Option<u32>,
    /// Newest frame id that has completed, for gap detection.
    last_completed: Option<u32>,
    /// Newest frame id actually handed out by [`Reassembler::pop_frame`].
    /// Keyframe demand is tracked against *delivery*, not completion, because a
    /// keyframe discarded by latest-wins never reached the decoder.
    last_delivered: Option<u32>,
    /// `(base_id, run_length)` of consecutive out-of-window datagrams that agree
    /// with each other — a candidate sender renumbering.
    resync: Option<(u32, u32)>,
    /// Value of `frames_skipped_latest_wins` at the previous delivery, so
    /// `pop_frame` can tell whether anything was discarded since.
    skipped_mark: u64,
    need_keyframe: bool,
    /// `None` means "no request has been made yet", so the first request after
    /// construction or [`Reassembler::reset`] is always allowed, including at
    /// `now_ms == 0`.
    last_keyframe_request_ms: Option<u64>,
    stats: ReassemblyStats,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new(ReassemblyConfig::default())
    }
}

impl Reassembler {
    /// Create a reassembler with the given configuration.
    ///
    /// A fresh reassembler does not itself ask for a keyframe: the session
    /// driver requests the initial keyframe as part of stream setup. The flag
    /// is raised only by a drop, a gap, or [`Reassembler::reset`].
    #[must_use]
    pub fn new(config: ReassemblyConfig) -> Self {
        Self {
            config,
            slots: Vec::new(),
            ready: VecDeque::new(),
            newest_seen: None,
            last_completed: None,
            last_delivered: None,
            resync: None,
            skipped_mark: 0,
            need_keyframe: false,
            last_keyframe_request_ms: None,
            stats: ReassemblyStats::default(),
        }
    }

    /// Feed one raw datagram (header + payload).
    ///
    /// Returns `Ok(true)` when this datagram completed a frame; the frame is
    /// pushed onto the ready queue and must be collected with
    /// [`Reassembler::pop_frame`]. Returns `Ok(false)` when the fragment was
    /// stored, was a duplicate, or was a late arrival for a frame that is
    /// already finished or aged out.
    ///
    /// # Errors
    ///
    /// - [`Error::Invalid`] if the header is malformed (see
    ///   [`FragHeader::decode`]) or contradicts the `frag_count`, `keyframe`
    ///   flag or `timestamp_ms` already recorded for that frame's slot. The
    ///   slot is left untouched, so the frame can still complete from correct
    ///   fragments.
    /// - [`Error::Oversized`] if the frame's payload bytes would exceed
    ///   [`MAX_FRAME_BYTES`]; the slot is dropped and a keyframe is requested.
    /// - [`Error::Invalid`] if the frame id lies outside the accepted window
    ///   (see the module docs); no state is disturbed.
    ///
    /// Every error increments `fragments_rejected`. The reassembler stays
    /// usable: callers should log and continue.
    pub fn push(&mut self, datagram: &[u8], now_ms: u64) -> Result<bool> {
        self.expire_timed_out(now_ms);

        let (header, payload) = match FragHeader::decode(datagram) {
            Ok(parts) => parts,
            Err(e) => {
                self.stats.fragments_rejected += 1;
                return Err(e);
            }
        };

        // Window check FIRST: nothing may touch `newest_seen` or evict a slot
        // until we have decided the id is plausible. An earlier version bumped
        // `newest_seen` before the metadata-contradiction check below, which
        // let a datagram that was ultimately rejected still poison the window.
        if !self.accept_frame_id(header.frame_id) {
            self.stats.fragments_rejected += 1;
            return Err(Error::Invalid(format!(
                "frame id {} is outside the accepted window (newest seen {:?})",
                header.frame_id, self.newest_seen
            )));
        }

        let bump_newest = match self.newest_seen {
            None => true,
            Some(newest) => is_newer(header.frame_id, newest),
        };
        if bump_newest {
            self.newest_seen = Some(header.frame_id);
        }
        self.evict_stale();

        let slot_pos = match self.slot_index(header.frame_id) {
            Some(pos) => {
                let (frag_count, keyframe, timestamp_ms, timestamp_known) = {
                    let slot = &self.slots[pos];
                    (
                        slot.frag_count,
                        slot.keyframe,
                        slot.timestamp_ms,
                        slot.timestamp_known,
                    )
                };
                // Parity fragments repurpose the timestamp field, so only frame
                // geometry and the keyframe flag are comparable for them. Data
                // fragments additionally pin the capture timestamp — but only
                // once one has been recorded, since a slot opened by a parity
                // fragment carries no authoritative timestamp yet.
                let contradiction = frag_count != header.frag_count
                    || keyframe != header.keyframe
                    || (!header.parity && timestamp_known && timestamp_ms != header.timestamp_ms);
                if contradiction {
                    self.stats.fragments_rejected += 1;
                    return Err(Error::Invalid(format!(
                        "fragment {}/{} of frame {} contradicts its slot",
                        header.frag_index, header.frag_count, header.frame_id
                    )));
                }
                // First data fragment for a parity-opened slot adopts the real
                // timestamp.
                if !header.parity && !timestamp_known {
                    let slot = &mut self.slots[pos];
                    slot.timestamp_ms = header.timestamp_ms;
                    slot.timestamp_known = true;
                }
                pos
            }
            None => {
                if self.is_late(header.frame_id) {
                    self.stats.fragments_duplicate += 1;
                    return Ok(false);
                }
                self.slots.push(Slot::new(&header, now_ms));
                self.evict_overflow();
                // Overflow eviction may have removed the slot just created, if
                // this fragment is the oldest thing we are tracking.
                match self.slot_index(header.frame_id) {
                    Some(pos) => pos,
                    None => {
                        // Still count the push, or the documented partition
                        // `received + duplicate + rejected == pushes` breaks.
                        self.stats.fragments_duplicate += 1;
                        return Ok(false);
                    }
                }
            }
        };

        // Parity fragment: it never occupies a data slot. It records its block's
        // parity, may enable an immediate single-loss recovery, and can itself
        // complete a frame whose last missing data fragment it reconstructs.
        if header.parity {
            let block = header.frag_index as usize;
            {
                let slot = &mut self.slots[slot_pos];
                if block >= slot.parity.len() {
                    // Decode already bounds the block index against the block
                    // count; a mismatch here means a slot opened with a
                    // different K, which we do not trust.
                    self.stats.fragments_rejected += 1;
                    return Err(Error::Invalid(format!(
                        "parity block {} out of range for frame {}",
                        block, header.frame_id
                    )));
                }
                if slot.parity[block].is_some() {
                    self.stats.fragments_duplicate += 1;
                    return Ok(false);
                }
                slot.parity[block] = Some(payload.to_vec());
                slot.last_frag_len = header.last_frag_len;
                slot.last_update_ms = now_ms;
            }
            self.stats.fec_parity_received += 1;
            self.try_recover(slot_pos);
            if self.slots[slot_pos].received < self.slots[slot_pos].frag_count {
                return Ok(false);
            }
            let frame = self.slots.remove(slot_pos).into_frame();
            self.complete(frame);
            return Ok(true);
        }

        let index = header.frag_index as usize;
        if self.slots[slot_pos].parts[index].is_some() {
            // Keep the first copy: a retransmission can differ byte for byte
            // only if something upstream is broken, and overwriting could
            // corrupt an otherwise good frame.
            self.stats.fragments_duplicate += 1;
            return Ok(false);
        }

        let total = self.slots[slot_pos].bytes.saturating_add(payload.len());
        if total > MAX_FRAME_BYTES {
            self.slots.remove(slot_pos);
            self.stats.fragments_rejected += 1;
            self.stats.frames_dropped_incomplete += 1;
            self.need_keyframe = true;
            return Err(Error::Oversized {
                got: total,
                limit: MAX_FRAME_BYTES,
            });
        }

        {
            let slot = &mut self.slots[slot_pos];
            slot.parts[index] = Some(payload.to_vec());
            slot.bytes = total;
            slot.received += 1;
            slot.last_update_ms = now_ms;
        }
        self.stats.fragments_received += 1;

        // A newly arrived data fragment can drop a block from two-missing to
        // one-missing, so parity recovery is retried on every data arrival.
        self.try_recover(slot_pos);

        if self.slots[slot_pos].received < self.slots[slot_pos].frag_count {
            return Ok(false);
        }

        let frame = self.slots.remove(slot_pos).into_frame();
        self.complete(frame);
        Ok(true)
    }

    /// XOR-recover a single missing data fragment per parity block.
    ///
    /// For each block whose parity fragment has arrived, if exactly one of the
    /// block's data fragments is still missing it is reconstructed as the XOR of
    /// the parity payload with every present data fragment in the block. A block
    /// missing two or more fragments is beyond single-parity FEC and is left to
    /// the normal timeout/keyframe path. Recovery bumps the slot's `received`
    /// count and `fec_recovered`; it is never a push and never a duplicate.
    fn try_recover(&mut self, slot_pos: usize) {
        let slot = &mut self.slots[slot_pos];
        if slot.fec_k == 0 {
            return;
        }
        let k = slot.fec_k as usize;
        let frag_count = slot.frag_count as usize;
        let num_blocks = slot.parity.len();
        for b in 0..num_blocks {
            let Some(par) = slot.parity[b].as_ref() else {
                continue;
            };
            let lo = b * k;
            let hi = ((b + 1) * k).min(frag_count);
            // Recoverable only when exactly one data index in the block is
            // still missing.
            let mut missing: Option<usize> = None;
            let mut recoverable = true;
            for i in lo..hi {
                if slot.parts[i].is_none() {
                    if missing.is_some() {
                        recoverable = false;
                        break;
                    }
                    missing = Some(i);
                }
            }
            let (Some(m), true) = (missing, recoverable) else {
                continue;
            };
            // Reconstruct: parity XOR every present data fragment in the block.
            let mut recon = par.clone();
            for i in lo..hi {
                if i == m {
                    continue;
                }
                if let Some(part) = slot.parts[i].as_ref() {
                    for (j, &byte) in part.iter().enumerate() {
                        recon[j] ^= byte;
                    }
                }
            }
            // Only the final data fragment is short; the parity header carries
            // its true length. Every other recovered fragment is the full
            // parity width.
            let true_len = if m == frag_count - 1 {
                slot.last_frag_len as usize
            } else {
                recon.len()
            };
            if true_len > recon.len() {
                // Contradictory geometry: refuse to fabricate bytes.
                continue;
            }
            recon.truncate(true_len);
            slot.bytes = slot.bytes.saturating_add(recon.len());
            slot.parts[m] = Some(recon);
            slot.received += 1;
            self.stats.fec_recovered += 1;
        }
    }

    /// Pop the next completed frame, honouring
    /// [`ReassemblyConfig::latest_wins`].
    ///
    /// With latest-wins enabled this returns the newest queued frame in serial
    /// order and discards every older queued frame, counting them in
    /// `frames_skipped_latest_wins`. Otherwise frames come out in completion
    /// order. Returns `None` when nothing is ready.
    ///
    /// Keyframe demand is settled here rather than at completion, because this
    /// is the only point at which a frame actually reaches the decoder. A
    /// keyframe that completed but was then discarded by latest-wins must not
    /// count as having satisfied the demand, and frames dropped on the way out
    /// open exactly the same reference-frame hole a lost frame does.
    pub fn pop_frame(&mut self) -> Option<EncodedFrame> {
        loop {
            let frame = if self.config.latest_wins {
                let mut best = 0usize;
                let mut best_id = self.ready.front()?.frame_id;
                for (i, f) in self.ready.iter().enumerate() {
                    if is_newer(f.frame_id, best_id) {
                        best = i;
                        best_id = f.frame_id;
                    }
                }
                let frame = self.ready.remove(best)?;
                self.stats.frames_skipped_latest_wins += self.ready.len() as u64;
                self.ready.clear();
                frame
            } else {
                self.ready.pop_front()?
            };
            // Monotonic delivery. A slot opened before a newer frame overtook it
            // can still complete and land in the ready queue *after* that newer
            // frame was already handed out; delivering it would step the decoder
            // backwards. Drop any frame that is not strictly newer than the last
            // one delivered. Legitimate renumbering (encoder restart / resync)
            // clears `last_delivered`, so this never blocks a real new stream.
            if let Some(prev) = self.last_delivered {
                if !is_newer(frame.frame_id, prev) {
                    self.stats.frames_dropped_reorder += 1;
                    continue;
                }
            }
            self.note_delivered(&frame);
            return Some(frame);
        }
    }

    /// Delivery-time bookkeeping for [`Reassembler::pop_frame`].
    fn note_delivered(&mut self, frame: &EncodedFrame) {
        let skipped_on_the_way_out = self.skipped_since_last_pop();
        let gap = match self.last_delivered {
            // The decoder cannot start on a delta frame.
            None => !frame.keyframe,
            Some(prev) => frame.frame_id != prev.wrapping_add(1),
        };
        if frame.keyframe {
            self.need_keyframe = false;
        } else if gap || skipped_on_the_way_out {
            self.need_keyframe = true;
        }
        self.last_delivered = Some(frame.frame_id);
        self.skipped_mark = self.stats.frames_skipped_latest_wins;
    }

    /// Whether any frame was discarded (latest-wins or ready-queue overflow)
    /// since the previous delivery.
    fn skipped_since_last_pop(&self) -> bool {
        self.stats.frames_skipped_latest_wins > self.skipped_mark
    }

    /// True if the reassembler wants a keyframe *and* the rate limiter allows
    /// asking now.
    ///
    /// Returning `true` consumes the permit: `now_ms` is recorded as the last
    /// request time and `keyframe_requests` is incremented. The demand itself
    /// persists across requests and is cleared only by a completed keyframe or
    /// by [`Reassembler::reset`], so a caller that keeps polling gets one
    /// `true` per [`ReassemblyConfig::keyframe_request_min_interval_ms`] until
    /// the keyframe actually shows up.
    pub fn take_keyframe_request(&mut self, now_ms: u64) -> bool {
        if !self.need_keyframe {
            return false;
        }
        let allowed = match self.last_keyframe_request_ms {
            None => true,
            // Our recorded instant is in the future, so it is meaningless —
            // the caller's clock jumped or slipped units. Re-arm rather than
            // starve the request forever.
            Some(last) if now_ms < last => true,
            Some(last) => now_ms - last >= self.config.keyframe_request_min_interval_ms,
        };
        if !allowed {
            return false;
        }
        self.last_keyframe_request_ms = Some(now_ms);
        self.stats.keyframe_requests += 1;
        true
    }

    /// Drop all slots and queued frames; the next frame must be a keyframe.
    ///
    /// The rate limiter is re-armed, so the next
    /// [`Reassembler::take_keyframe_request`] is allowed immediately.
    /// Statistics are cumulative and survive the reset.
    pub fn reset(&mut self, _now_ms: u64) {
        let abandoned = self.slots.len() as u64;
        self.slots.clear();
        self.stats.frames_dropped_incomplete += abandoned;
        self.stats.frames_skipped_latest_wins += self.ready.len() as u64;
        self.ready.clear();
        self.newest_seen = None;
        self.last_completed = None;
        self.last_delivered = None;
        self.resync = None;
        self.skipped_mark = self.stats.frames_skipped_latest_wins;
        self.need_keyframe = true;
        self.last_keyframe_request_ms = None;
    }

    /// Snapshot of the cumulative counters.
    #[must_use]
    pub fn stats(&self) -> ReassemblyStats {
        self.stats
    }

    /// Expire slots that timed out.
    ///
    /// Called internally by [`Reassembler::push`], but exposed so an idle
    /// receiver can still age out state while no datagrams arrive.
    pub fn tick(&mut self, now_ms: u64) {
        self.expire_timed_out(now_ms);
    }

    /// Decide whether `frame_id` is close enough to what we have seen to act
    /// on, adopting a new numbering when the peer has clearly renumbered.
    ///
    /// Returns `false` when the caller must reject the datagram outright.
    fn accept_frame_id(&mut self, frame_id: u32) -> bool {
        let Some(newest) = self.newest_seen else {
            self.resync = None;
            return true;
        };
        let jump = self.config.max_forward_jump;
        let forward = frame_id.wrapping_sub(newest);
        let backward = newest.wrapping_sub(frame_id);

        // Ahead by a plausible amount, or behind by a plausible amount (late
        // and stale fragments are handled downstream by `is_late`).
        if forward <= jump || backward <= jump {
            self.resync = None;
            return true;
        }

        // Out of window. Treat it as a possible renumbering only if it forms a
        // consistent run; any in-window datagram above clears the run, so on a
        // live stream an injected id can never accumulate one.
        let run = match self.resync {
            Some((base, n)) if frame_id.wrapping_sub(base) <= jump => {
                self.resync = Some((base, n.saturating_add(1)));
                n.saturating_add(1)
            }
            _ => {
                self.resync = Some((frame_id, 1));
                1
            }
        };
        if run >= self.config.resync_after.max(1) {
            return self.adopt_numbering(frame_id);
        }
        false
    }

    /// Abandon all state and restart numbering at `frame_id`, demanding a
    /// keyframe. Always returns `true` so callers can tail-call it.
    fn adopt_numbering(&mut self, frame_id: u32) -> bool {
        self.stats.frames_dropped_incomplete += self.slots.len() as u64;
        self.slots.clear();
        self.stats.frames_skipped_latest_wins += self.ready.len() as u64;
        self.ready.clear();
        self.skipped_mark = self.stats.frames_skipped_latest_wins;
        self.newest_seen = Some(frame_id);
        self.last_completed = None;
        self.last_delivered = None;
        self.resync = None;
        self.need_keyframe = true;
        true
    }

    fn slot_index(&self, frame_id: u32) -> Option<usize> {
        self.slots.iter().position(|slot| slot.frame_id == frame_id)
    }

    /// True when a fragment for `frame_id` can no longer be useful: its frame
    /// already completed, or it fell behind the stale window.
    fn is_late(&self, frame_id: u32) -> bool {
        let distance = self.config.stale_frame_distance;
        let finished = matches!(self.last_completed, Some(done) if !is_newer(frame_id, done));
        let behind = matches!(self.newest_seen, Some(seen) if is_stale(seen, frame_id, distance));
        finished || behind
    }

    /// Record a completed frame: gap detection, then enqueue.
    fn complete(&mut self, frame: EncodedFrame) {
        self.stats.frames_completed += 1;
        // A hole in the delivered sequence: the decoder needs a fresh anchor
        // rather than a frame that references something we never got.
        let gap = match self.last_completed {
            None => false,
            Some(prev) => frame.frame_id != prev.wrapping_add(1),
        };
        if gap {
            self.need_keyframe = true;
        }
        let bump = match self.last_completed {
            None => true,
            Some(prev) => is_newer(frame.frame_id, prev),
        };
        if bump {
            self.last_completed = Some(frame.frame_id);
        }
        // Deliberately NOT clearing `need_keyframe` here. A keyframe that
        // completes but is then discarded by latest-wins or by ready-queue
        // overflow never reaches the decoder, so the demand is only settled in
        // `note_delivered`.
        while self.ready.len() >= MAX_READY_FRAMES {
            self.ready.pop_front();
            self.stats.frames_skipped_latest_wins += 1;
        }
        self.ready.push_back(frame);
    }

    /// Drop slots whose last fragment is older than the slot timeout.
    fn expire_timed_out(&mut self, now_ms: u64) {
        let timeout = self.config.slot_timeout_ms;
        if timeout == 0 {
            // Documented: 0 disables the timeout. Without this guard the
            // comparison below would expire every slot on the very next push,
            // silently making multi-fragment reassembly impossible.
            return;
        }
        let mut dropped = 0u64;
        self.slots.retain(|slot| {
            // A slot dated in the future can only come from a caller clock
            // glitch. Expire it on sight rather than let it live forever.
            let alive = slot.last_update_ms <= now_ms
                && slot.last_update_ms.saturating_add(timeout) > now_ms;
            if !alive {
                dropped += 1;
            }
            alive
        });
        if dropped > 0 {
            self.stats.frames_dropped_incomplete += dropped;
            self.need_keyframe = true;
        }
    }

    /// Drop slots left too far behind the newest frame id seen.
    fn evict_stale(&mut self) {
        let Some(newest) = self.newest_seen else {
            return;
        };
        let distance = self.config.stale_frame_distance;
        let mut dropped = 0u64;
        self.slots.retain(|slot| {
            let stale = is_stale(newest, slot.frame_id, distance);
            if stale {
                dropped += 1;
            }
            !stale
        });
        if dropped > 0 {
            self.stats.frames_dropped_stale += dropped;
            self.need_keyframe = true;
        }
    }

    /// Enforce `max_slots` by evicting the oldest slot in serial order.
    fn evict_overflow(&mut self) {
        let cap = self.config.max_slots.max(1);
        while self.slots.len() > cap {
            let Some(oldest) = self.oldest_slot_index() else {
                break;
            };
            self.slots.remove(oldest);
            self.stats.frames_dropped_incomplete += 1;
            self.need_keyframe = true;
        }
    }

    /// Index of the slot with the oldest frame id in serial order.
    fn oldest_slot_index(&self) -> Option<usize> {
        let mut best: Option<(usize, u32)> = None;
        for (i, slot) in self.slots.iter().enumerate() {
            let take = match best {
                None => true,
                Some((_, id)) => is_newer(id, slot.frame_id),
            };
            if take {
                best = Some((i, slot.frame_id));
            }
        }
        best.map(|(i, _)| i)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::video::{
        fragment_frame, fragment_frame_fec, FRAG_HEADER_LEN, MAX_FRAGS_PER_FRAME,
    };

    /// Deterministic payload of `len` bytes.
    fn payload(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    /// Fragments for one synthetic frame, via the real `fragment_frame`.
    fn frags(id: u32, keyframe: bool, ts: u32, len: usize, mtu: usize) -> Vec<Vec<u8>> {
        let frame = EncodedFrame {
            frame_id: id,
            keyframe,
            timestamp_ms: ts,
            data: payload(len),
        };
        fragment_frame(&frame, mtu).expect("fragment_frame")
    }

    /// Hand-built datagram, for cases `fragment_frame` cannot produce.
    fn forge(
        id: u32,
        frag_index: u16,
        frag_count: u16,
        keyframe: bool,
        ts: u32,
        payload_len: usize,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(FRAG_HEADER_LEN + payload_len);
        FragHeader {
            frame_id: id,
            frag_index,
            frag_count,
            keyframe,
            parity: false,
            block_size: 0,
            last_frag_len: 0,
            timestamp_ms: ts,
        }
        .encode(&mut out);
        out.resize(FRAG_HEADER_LEN + payload_len, 0x5A);
        out
    }

    /// Fragments for one synthetic frame *with* FEC parity, via the real
    /// `fragment_frame_fec`.
    fn frags_fec(
        id: u32,
        keyframe: bool,
        ts: u32,
        len: usize,
        mtu: usize,
        k: u8,
    ) -> Vec<Vec<u8>> {
        let frame = EncodedFrame {
            frame_id: id,
            keyframe,
            timestamp_ms: ts,
            data: payload(len),
        };
        fragment_frame_fec(&frame, mtu, k).expect("fragment_frame_fec")
    }

    /// Push `order` (fragment indices) at a fixed instant; returns how many
    /// pushes reported a completed frame.
    fn push_order(r: &mut Reassembler, frags: &[Vec<u8>], order: &[usize], now_ms: u64) -> usize {
        let mut completed = 0;
        for &i in order {
            if r.push(&frags[i], now_ms).expect("push") {
                completed += 1;
            }
        }
        completed
    }

    fn cfg() -> ReassemblyConfig {
        ReassemblyConfig::default()
    }

    #[test]
    fn is_newer_uses_serial_order() {
        assert!(is_newer(1, 0));
        assert!(!is_newer(0, 1));
        assert!(!is_newer(5, 5));
        // Across the wrap.
        assert!(is_newer(0, 0xFFFF_FFFF));
        assert!(is_newer(1, 0xFFFF_FFFE));
        assert!(!is_newer(0xFFFF_FFFF, 0));
        // Half-space boundary.
        assert!(is_newer(0x7FFF_FFFF, 0));
        assert!(!is_newer(0x8000_0000, 0));
        assert!(is_stale(10, 5, 4));
        assert!(!is_stale(10, 6, 4));
        assert!(!is_stale(10, 11, 4));
        assert!(is_stale(1, 0xFFFF_FFFE, 2));
    }

    #[test]
    fn in_order_reassembles_exact_bytes() {
        let mut r = Reassembler::new(cfg());
        let f = frags(1, true, 4242, 5000, 300);
        assert!(f.len() > 1);
        let order: Vec<usize> = (0..f.len()).collect();
        assert_eq!(push_order(&mut r, &f, &order, 100), 1);
        let frame = r.pop_frame().expect("frame");
        assert_eq!(frame.frame_id, 1);
        assert!(frame.keyframe);
        assert_eq!(frame.timestamp_ms, 4242);
        assert_eq!(frame.data, payload(5000));
        assert!(r.pop_frame().is_none());
        assert_eq!(r.stats().frames_completed, 1);
        assert_eq!(r.stats().fragments_received, f.len() as u64);
    }

    #[test]
    fn reversed_order_reassembles() {
        let mut r = Reassembler::new(cfg());
        let f = frags(9, false, 7, 4096, 512);
        let order: Vec<usize> = (0..f.len()).rev().collect();
        assert_eq!(push_order(&mut r, &f, &order, 0), 1);
        let frame = r.pop_frame().expect("frame");
        assert_eq!(frame.data, payload(4096));
        assert!(!frame.keyframe);
    }

    #[test]
    fn shuffled_order_reassembles() {
        let mut r = Reassembler::new(cfg());
        // 5 fragments: 4 * 1186 = 4744 < 5000 <= 5 * 1186.
        let f = frags(3, false, 11, 5000, 1200);
        assert_eq!(f.len(), 5);
        // Fixed permutation, no randomness.
        assert_eq!(push_order(&mut r, &f, &[3, 0, 4, 1, 2], 50), 1);
        let frame = r.pop_frame().expect("frame");
        assert_eq!(frame.data, payload(5000));
    }

    #[test]
    fn single_fragment_frame_completes_immediately() {
        let mut r = Reassembler::new(cfg());
        let f = frags(42, true, 1, 100, 1200);
        assert_eq!(f.len(), 1);
        assert!(r.push(&f[0], 0).expect("push"));
        let frame = r.pop_frame().expect("frame");
        assert_eq!(frame.frame_id, 42);
        assert_eq!(frame.data, payload(100));
    }

    #[test]
    fn duplicate_fragments_keep_first_copy() {
        let mut r = Reassembler::new(cfg());
        let f = frags(6, false, 3, 2000, 1024);
        assert_eq!(f.len(), 2);
        assert!(!r.push(&f[0], 0).expect("push"));
        // Same header, different payload bytes: must be ignored, not merged.
        let mut poisoned = f[0].clone();
        for byte in poisoned.iter_mut().skip(FRAG_HEADER_LEN) {
            *byte ^= 0xFF;
        }
        assert!(!r.push(&poisoned, 0).expect("push"));
        assert!(!r.push(&f[0], 0).expect("push"));
        assert!(r.push(&f[1], 0).expect("push"));
        let frame = r.pop_frame().expect("frame");
        assert_eq!(frame.data, payload(2000));
        assert_eq!(r.stats().fragments_duplicate, 2);
        assert_eq!(r.stats().fragments_received, 2);
    }

    #[test]
    fn interleaved_frames_both_complete() {
        let mut r = Reassembler::new(cfg());
        let a = frags(1, true, 10, 2000, 1024);
        let b = frags(2, false, 20, 2000, 1024);
        assert!(!r.push(&a[0], 0).expect("push"));
        assert!(!r.push(&b[0], 0).expect("push"));
        assert!(r.push(&a[1], 0).expect("push"));
        assert!(r.push(&b[1], 0).expect("push"));
        assert_eq!(r.stats().frames_completed, 2);
        // Contiguous ids: no gap, so no keyframe demand.
        assert!(!r.take_keyframe_request(0));
        let mut r2 = Reassembler::new(ReassemblyConfig {
            latest_wins: false,
            ..cfg()
        });
        for d in a.iter().chain(b.iter()) {
            let _ = r2.push(d, 0).expect("push");
        }
        assert_eq!(r2.pop_frame().expect("a").frame_id, 1);
        assert_eq!(r2.pop_frame().expect("b").frame_id, 2);
    }

    #[test]
    fn lost_fragment_times_out_and_requests_keyframe() {
        let mut r = Reassembler::new(ReassemblyConfig {
            slot_timeout_ms: 500,
            ..cfg()
        });
        let f = frags(1, false, 0, 3000, 1024);
        assert_eq!(f.len(), 3);
        assert!(!r.push(&f[0], 1000).expect("push"));
        assert!(!r.push(&f[2], 1100).expect("push"));
        // Not yet: 1100 + 500 > 1500.
        r.tick(1500);
        assert_eq!(r.stats().frames_dropped_incomplete, 0);
        assert!(!r.take_keyframe_request(1500));
        r.tick(1600);
        assert_eq!(r.stats().frames_dropped_incomplete, 1);
        assert_eq!(r.stats().frames_completed, 0);
        assert!(r.take_keyframe_request(1600));
        assert_eq!(r.stats().keyframe_requests, 1);
        // The missing fragment now arrives far too late: no zombie completion.
        assert!(!r.push(&f[1], 1700).expect("push"));
    }

    #[test]
    fn stale_distance_drops_incomplete_frames() {
        let mut r = Reassembler::new(ReassemblyConfig {
            stale_frame_distance: 4,
            slot_timeout_ms: 100_000,
            ..cfg()
        });
        let stuck = frags(100, false, 0, 3000, 1024);
        assert!(!r.push(&stuck[0], 0).expect("push"));
        // Frames 101..=104 are within the window; 105 pushes 100 out.
        for id in 101..=104u32 {
            let one = frags(id, false, id, 64, 1200);
            assert!(r.push(&one[0], 0).expect("push"));
        }
        assert_eq!(r.stats().frames_dropped_stale, 0);
        let one = frags(105, false, 105, 64, 1200);
        assert!(r.push(&one[0], 0).expect("push"));
        assert_eq!(r.stats().frames_dropped_stale, 1);
        assert!(r.take_keyframe_request(0));
        // A late fragment for the aged-out frame is counted, not resurrected.
        let before = r.stats().fragments_duplicate;
        assert!(!r.push(&stuck[1], 0).expect("push"));
        assert_eq!(r.stats().fragments_duplicate, before + 1);
        assert_eq!(r.stats().frames_completed, 5);
    }

    #[test]
    fn max_slots_evicts_oldest_by_serial_order() {
        let mut r = Reassembler::new(ReassemblyConfig {
            max_slots: 2,
            slot_timeout_ms: 100_000,
            ..cfg()
        });
        let a = frags(10, false, 10, 2000, 1024);
        let b = frags(11, false, 11, 2000, 1024);
        let c = frags(12, false, 12, 2000, 1024);
        // Deliberately not in id order: eviction must use serial order, not
        // insertion order.
        assert!(!r.push(&b[0], 0).expect("push"));
        assert!(!r.push(&c[0], 0).expect("push"));
        assert!(!r.push(&a[0], 0).expect("push"));
        assert_eq!(r.stats().frames_dropped_incomplete, 1);
        // 11 and 12 survived; 10 was the oldest and is gone.
        assert!(r.push(&b[1], 0).expect("push"));
        assert!(r.push(&c[1], 0).expect("push"));
        assert_eq!(r.stats().frames_completed, 2);
        assert!(!r.push(&a[1], 0).expect("push"));
        assert_eq!(r.stats().frames_completed, 2);
    }

    #[test]
    fn frame_id_wrap_is_ordered_correctly() {
        let ids = [0xFFFF_FFFEu32, 0xFFFF_FFFF, 0x0000_0000, 0x0000_0001];
        // latest-wins must pick 1, not 0xFFFF_FFFF.
        let mut r = Reassembler::new(cfg());
        for &id in &ids {
            let one = frags(id, false, 1, 64, 1200);
            assert!(r.push(&one[0], 0).expect("push"));
        }
        // Contiguous across the wrap: no gap detected.
        assert!(!r.take_keyframe_request(0));
        let frame = r.pop_frame().expect("frame");
        assert_eq!(frame.frame_id, 0x0000_0001);
        assert_eq!(r.stats().frames_skipped_latest_wins, 3);

        // Staleness must also wrap: 0xFFFF_FFFE is 3 behind 0x0000_0001.
        let mut r2 = Reassembler::new(ReassemblyConfig {
            stale_frame_distance: 2,
            slot_timeout_ms: 100_000,
            ..cfg()
        });
        let stuck = frags(0xFFFF_FFFE, false, 0, 3000, 1024);
        assert!(!r2.push(&stuck[0], 0).expect("push"));
        let mid = frags(0x0000_0000, false, 1, 64, 1200);
        assert!(r2.push(&mid[0], 0).expect("push"));
        assert_eq!(r2.stats().frames_dropped_stale, 0);
        let last = frags(0x0000_0001, false, 1, 64, 1200);
        assert!(r2.push(&last[0], 0).expect("push"));
        assert_eq!(r2.stats().frames_dropped_stale, 1);
    }

    #[test]
    fn latest_wins_returns_newest_and_counts_skips() {
        let mut r = Reassembler::new(cfg());
        for id in 1..=3u32 {
            let one = frags(id, false, id, 64, 1200);
            assert!(r.push(&one[0], 0).expect("push"));
        }
        let frame = r.pop_frame().expect("frame");
        assert_eq!(frame.frame_id, 3);
        assert_eq!(r.stats().frames_skipped_latest_wins, 2);
        assert!(r.pop_frame().is_none());
        assert_eq!(r.stats().frames_completed, 3);
    }

    #[test]
    fn arrival_order_when_latest_wins_disabled() {
        let mut r = Reassembler::new(ReassemblyConfig {
            latest_wins: false,
            ..cfg()
        });
        for id in 1..=3u32 {
            let one = frags(id, false, id, 64, 1200);
            assert!(r.push(&one[0], 0).expect("push"));
        }
        assert_eq!(r.pop_frame().expect("1").frame_id, 1);
        assert_eq!(r.pop_frame().expect("2").frame_id, 2);
        assert_eq!(r.pop_frame().expect("3").frame_id, 3);
        assert!(r.pop_frame().is_none());
        assert_eq!(r.stats().frames_skipped_latest_wins, 0);
    }

    #[test]
    fn ready_queue_cap_drops_oldest() {
        let mut r = Reassembler::new(ReassemblyConfig {
            latest_wins: false,
            ..cfg()
        });
        let total = MAX_READY_FRAMES as u32 + 3;
        for id in 1..=total {
            let one = frags(id, false, id, 64, 1200);
            assert!(r.push(&one[0], 0).expect("push"));
        }
        assert_eq!(r.stats().frames_completed, u64::from(total));
        assert_eq!(r.stats().frames_skipped_latest_wins, 3);
        // The oldest survivor is frame 4.
        assert_eq!(r.pop_frame().expect("oldest").frame_id, 4);
    }

    #[test]
    fn malformed_datagrams_are_rejected_and_recoverable() {
        let mut r = Reassembler::new(cfg());
        // Truncated header.
        assert!(r.push(&[0u8; 5], 0).is_err());
        // Header with no payload.
        let empty = forge(1, 0, 1, false, 0, 0);
        assert!(r.push(&empty, 0).is_err());
        // Offset 9 is now `block_size`, no longer a must-be-zero reserved byte;
        // a non-zero value is a valid FEC K, so it must NOT be rejected here.
        // Unknown flag bits (bit 2 and up are undefined) are still rejected.
        let mut flags = forge(1, 0, 1, false, 0, 8);
        flags[8] = 0b1000_0000;
        assert!(r.push(&flags, 0).is_err());
        assert_eq!(r.stats().fragments_rejected, 3);
        assert_eq!(r.stats().fragments_received, 0);
        // Still usable.
        let f = frags(1, true, 5, 2000, 1024);
        assert!(!r.push(&f[0], 0).expect("push"));
        assert!(r.push(&f[1], 0).expect("push"));
        assert_eq!(r.pop_frame().expect("frame").data, payload(2000));
    }

    #[test]
    fn inconsistent_slot_metadata_is_rejected() {
        let mut r = Reassembler::new(cfg());
        let f = frags(5, false, 77, 3000, 1024);
        assert_eq!(f.len(), 3);
        assert!(!r.push(&f[0], 0).expect("push"));
        // Wrong frag_count, wrong keyframe flag, wrong timestamp.
        for bad in [
            forge(5, 1, 4, false, 77, 16),
            forge(5, 1, 3, true, 77, 16),
            forge(5, 1, 3, false, 78, 16),
        ] {
            let err = r.push(&bad, 0).expect_err("must reject");
            assert!(matches!(err, Error::Invalid(_)), "unexpected error: {err}");
        }
        assert_eq!(r.stats().fragments_rejected, 3);
        // Slot survived intact and still completes from good fragments.
        assert!(!r.push(&f[1], 0).expect("push"));
        assert!(r.push(&f[2], 0).expect("push"));
        assert_eq!(r.pop_frame().expect("frame").data, payload(3000));
    }

    #[test]
    fn per_frame_byte_cap_is_enforced() {
        let mut r = Reassembler::new(cfg());
        let count = MAX_FRAGS_PER_FRAME;
        let chunk = 8192usize;
        let mut oversized = None;
        for index in 0..count {
            let dgram = forge(77, index, count, false, 0, chunk);
            match r.push(&dgram, 0) {
                Ok(completed) => assert!(!completed),
                Err(e) => {
                    oversized = Some(e);
                    break;
                }
            }
        }
        let err = oversized.expect("byte cap must trip");
        match err {
            Error::Oversized { got, limit } => {
                assert_eq!(limit, MAX_FRAME_BYTES);
                assert!(got > MAX_FRAME_BYTES, "got {got}");
            }
            other => panic!("expected Oversized, got {other}"),
        }
        assert_eq!(r.stats().fragments_rejected, 1);
        assert_eq!(r.stats().frames_dropped_incomplete, 1);
        assert_eq!(r.stats().frames_completed, 0);
        assert!(r.take_keyframe_request(0));
        // Slot is gone: further fragments for that frame cannot complete it.
        let dgram = forge(77, count - 1, count, false, 0, 16);
        assert!(!r.push(&dgram, 0).expect("push"));
    }

    #[test]
    fn keyframe_requests_are_rate_limited() {
        let mut r = Reassembler::new(ReassemblyConfig {
            slot_timeout_ms: 500,
            keyframe_request_min_interval_ms: 500,
            ..cfg()
        });
        assert!(
            !r.take_keyframe_request(0),
            "fresh reassembler wants nothing"
        );
        let f = frags(1, false, 0, 3000, 1024);
        assert!(!r.push(&f[0], 1000).expect("push"));
        r.tick(1600);
        assert_eq!(r.stats().frames_dropped_incomplete, 1);
        // First request after the need arises is immediate.
        assert!(r.take_keyframe_request(1600));
        assert!(!r.take_keyframe_request(1700));
        assert!(!r.take_keyframe_request(2099));
        assert!(r.take_keyframe_request(2100));
        assert_eq!(r.stats().keyframe_requests, 2);
        // Completing a keyframe is NOT enough — it has to reach the decoder.
        let kf = frags(9, true, 9, 64, 1200);
        assert!(r.push(&kf[0], 2100).expect("push"));
        assert!(
            r.take_keyframe_request(2700),
            "still unsatisfied until delivered"
        );
        assert_eq!(r.stats().keyframe_requests, 3);

        // Delivering it settles the demand.
        let frame = r.pop_frame().expect("keyframe ready");
        assert!(frame.keyframe);
        assert!(!r.take_keyframe_request(9999));
        assert_eq!(r.stats().keyframe_requests, 3);
    }

    /// A single well-formed datagram claiming a wildly future frame id must not
    /// be able to wedge the receiver. Before the window check existed, this
    /// bumped `newest_seen` by 2^30, evicted every slot, and made every later
    /// legitimate fragment look ancient — permanently.
    #[test]
    fn far_future_frame_id_cannot_wedge_the_receiver() {
        let mut r = Reassembler::new(cfg());

        // Establish normal numbering and deliver a frame.
        let f1 = frags(1000, true, 0, 64, 1200);
        assert!(r.push(&f1[0], 0).expect("push"));
        assert!(r.pop_frame().is_some());

        // Hostile datagram, structurally valid, absurd id.
        let evil = forge(0x4000_03E8, 0, 2, false, 0, 16);
        let err = r.push(&evil, 10).unwrap_err();
        assert!(matches!(err, Error::Invalid(_)), "got {err:?}");
        assert_eq!(r.stats().fragments_rejected, 1);

        // The legitimate stream keeps working, frame after frame.
        for (n, id) in (1001u32..1010).enumerate() {
            let f = frags(id, false, id, 64, 1200);
            assert!(
                r.push(&f[0], 20 + n as u64).expect("push"),
                "frame {id} must complete"
            );
            let got = r.pop_frame().expect("frame must be delivered");
            assert_eq!(got.frame_id, id);
        }
    }

    /// Repeated hostile ids that do NOT agree with each other never accumulate
    /// a resync run, and interleaved legitimate traffic clears it too.
    #[test]
    fn scattered_hostile_ids_never_trigger_resync() {
        let mut r = Reassembler::new(cfg());
        let f = frags(500, true, 0, 64, 1200);
        assert!(r.push(&f[0], 0).expect("push"));

        for i in 0..40u32 {
            // Each hostile id is far from the previous one, so the run resets.
            let evil = forge(
                0x1000_0000u32.wrapping_mul(i.wrapping_add(1)),
                0,
                2,
                false,
                0,
                16,
            );
            let _ = r.push(&evil, 1);
            // A legitimate fragment in between also clears the run.
            let good = frags(500 + i + 1, false, 0, 64, 1200);
            assert!(r.push(&good[0], 1).expect("push"));
            assert!(r.pop_frame().is_some());
        }
        assert_eq!(r.stats().frames_completed, 41);
    }

    /// A sender that restarts its encoder renumbers from 0. After a consistent
    /// run the receiver adopts the new numbering and demands a keyframe.
    #[test]
    fn consistent_renumbering_run_triggers_resync() {
        let mut r = Reassembler::new(ReassemblyConfig {
            resync_after: 4,
            ..cfg()
        });
        let f = frags(100_000, true, 0, 64, 1200);
        assert!(r.push(&f[0], 0).expect("push"));
        assert!(r.pop_frame().is_some());

        // Sender restarts at 0. The first few are refused...
        for id in 0u32..3 {
            let f = frags(id, false, id, 64, 1200);
            assert!(
                r.push(&f[0], 1).is_err(),
                "id {id} should still be out of window"
            );
        }
        // ...then the run is long enough and the numbering is adopted.
        let f = frags(3, true, 3, 64, 1200);
        assert!(
            r.push(&f[0], 1).expect("push"),
            "resync should accept and complete"
        );
        let got = r.pop_frame().expect("frame after resync");
        assert_eq!(got.frame_id, 3);

        // And the stream continues in the new numbering.
        let f = frags(4, false, 4, 64, 1200);
        assert!(r.push(&f[0], 2).expect("push"));
        assert_eq!(r.pop_frame().unwrap().frame_id, 4);
    }

    /// Latest-wins must not silently strand the decoder: a keyframe discarded
    /// on the way out has not satisfied the keyframe demand, and skipping
    /// frames raises a new demand.
    #[test]
    fn latest_wins_skip_keeps_keyframe_demand_honest() {
        let mut r = Reassembler::new(ReassemblyConfig {
            latest_wins: true,
            keyframe_request_min_interval_ms: 0,
            ..cfg()
        });
        // Deliver an anchor keyframe so the demand starts satisfied.
        let kf = frags(10, true, 10, 64, 1200);
        assert!(r.push(&kf[0], 0).expect("push"));
        assert!(r.pop_frame().is_some());
        assert!(
            !r.take_keyframe_request(0),
            "anchor delivered, nothing wanted"
        );

        // Now a keyframe and a newer delta both complete before the consumer
        // pops. Latest-wins hands over the delta and throws the keyframe away.
        let kf2 = frags(11, true, 11, 64, 1200);
        assert!(r.push(&kf2[0], 1).expect("push"));
        let delta = frags(12, false, 12, 64, 1200);
        assert!(r.push(&delta[0], 1).expect("push"));

        let got = r.pop_frame().expect("frame");
        assert_eq!(got.frame_id, 12);
        assert!(!got.keyframe);
        assert!(r.stats().frames_skipped_latest_wins >= 1);
        assert!(
            r.take_keyframe_request(1),
            "the discarded keyframe never reached the decoder, so ask again"
        );
    }

    /// A straggler slot that finishes *after* a newer frame was already
    /// delivered must never be handed over — that would step the decoder
    /// backwards. (Regression: the netsim matrix saw frame 151 delivered after
    /// 152 because the latest-wins pick only considered the current ready queue.)
    #[test]
    fn straggler_completing_after_a_newer_delivery_is_dropped() {
        // Two-fragment frames so a slot can stay open across another delivery.
        let older = frags(151, false, 151, 2000, 1024);
        let newer = frags(152, false, 152, 2000, 1024);
        assert_eq!(older.len(), 2);
        assert_eq!(newer.len(), 2);

        let mut r = Reassembler::new(ReassemblyConfig {
            slot_timeout_ms: 100_000,
            stale_frame_distance: 64,
            ..cfg()
        });

        // Frame 151 opens its slot but only one fragment arrives.
        assert!(!r.push(&older[0], 0).expect("push"));
        // Frame 152 arrives complete and is delivered.
        assert!(!r.push(&newer[0], 0).expect("push"));
        assert!(r.push(&newer[1], 0).expect("push"));
        assert_eq!(r.pop_frame().expect("152").frame_id, 152);

        // Now 151's missing fragment finally arrives and completes the frame.
        assert!(r.push(&older[1], 0).expect("push"));
        // It must NOT come out: it is older than what we already delivered.
        assert!(
            r.pop_frame().is_none(),
            "stale straggler must be dropped, not delivered"
        );
        assert_eq!(r.stats().frames_dropped_reorder, 1);
    }

    /// The first frame ever delivered must be a keyframe; a delta first means
    /// the decoder has no anchor.
    #[test]
    fn first_delivered_delta_demands_a_keyframe() {
        let mut r = Reassembler::new(cfg());
        let delta = frags(5, false, 5, 64, 1200);
        assert!(r.push(&delta[0], 0).expect("push"));
        assert!(r.pop_frame().is_some());
        assert!(r.take_keyframe_request(0));
    }

    /// A caller clock glitch must not disable expiry or starve the limiter
    /// forever; both recover once the clock is sane again.
    #[test]
    fn absurd_clock_value_is_self_healing() {
        let mut r = Reassembler::new(ReassemblyConfig {
            slot_timeout_ms: 500,
            keyframe_request_min_interval_ms: 500,
            ..cfg()
        });
        // A slot created with a wildly future timestamp (µs mistaken for ms).
        let f = frags(1, false, 0, 3000, 1024);
        assert!(!r.push(&f[0], 5_000_000_000).expect("push"));
        // Back on a sane clock, the future-dated slot is expired on sight.
        r.tick(1_000);
        assert_eq!(r.stats().frames_dropped_incomplete, 1);
        assert!(r.take_keyframe_request(1_000));

        // A limiter instant recorded in the future re-arms rather than starving.
        assert!(!r.take_keyframe_request(1_100));
        let mut r2 = Reassembler::new(ReassemblyConfig {
            keyframe_request_min_interval_ms: 500,
            ..cfg()
        });
        r2.reset(0);
        assert!(r2.take_keyframe_request(9_000_000));
        assert!(
            r2.take_keyframe_request(10),
            "clock went backwards: re-arm, do not starve"
        );
    }

    /// `slot_timeout_ms == 0` means "no timeout", not "expire everything".
    #[test]
    fn zero_slot_timeout_disables_expiry() {
        let mut r = Reassembler::new(ReassemblyConfig {
            slot_timeout_ms: 0,
            ..cfg()
        });
        let f = frags(1, false, 0, 3000, 1024);
        for (i, d) in f.iter().enumerate() {
            let last = i + 1 == f.len();
            assert_eq!(r.push(d, i as u64 * 10_000).expect("push"), last);
        }
        assert_eq!(r.stats().frames_dropped_incomplete, 0);
        assert_eq!(r.pop_frame().expect("frame").data.len(), 3000);
    }

    #[test]
    fn config_validation() {
        assert!(ReassemblyConfig::default().validate().is_ok());
        assert!(ReassemblyConfig {
            max_forward_jump: 0,
            ..Default::default()
        }
        .validate()
        .is_err());
        assert!(ReassemblyConfig {
            stale_frame_distance: 0x8000_0000,
            ..Default::default()
        }
        .validate()
        .is_err());
    }

    /// The counter partition must hold even when a newly created slot is itself
    /// the one evicted by overflow.
    #[test]
    fn stats_partition_holds_on_overflow_eviction() {
        let mut r = Reassembler::new(ReassemblyConfig {
            max_slots: 2,
            stale_frame_distance: 64,
            ..cfg()
        });
        let mut pushes = 0u64;
        for id in [11u32, 12, 10] {
            let f = frags(id, false, id, 3000, 1024);
            let _ = r.push(&f[0], 0);
            pushes += 1;
        }
        let s = r.stats();
        assert_eq!(
            s.fragments_received + s.fragments_duplicate + s.fragments_rejected,
            pushes,
            "counters must partition every push"
        );
    }

    #[test]
    fn reset_clears_state_and_demands_keyframe() {
        let mut r = Reassembler::new(cfg());
        let f = frags(1, false, 0, 3000, 1024);
        assert!(!r.push(&f[0], 100).expect("push"));
        let done = frags(2, false, 2, 64, 1200);
        assert!(r.push(&done[0], 100).expect("push"));
        r.reset(200);
        assert!(r.pop_frame().is_none(), "ready queue cleared");
        assert!(
            r.take_keyframe_request(200),
            "first request allowed at once"
        );
        assert_eq!(r.stats().frames_dropped_incomplete, 1);
        // The half-built frame cannot resume: its remaining fragments start a
        // fresh slot instead.
        assert!(!r.push(&f[1], 200).expect("push"));
        assert!(!r.push(&f[2], 200).expect("push"));
        assert!(r.push(&f[0], 200).expect("push"));
        assert_eq!(r.pop_frame().expect("frame").data, payload(3000));
    }

    #[test]
    fn stats_arithmetic_is_consistent() {
        let mut r = Reassembler::new(ReassemblyConfig {
            slot_timeout_ms: 500,
            ..cfg()
        });
        let mut pushes = 0u64;
        fn counted_push(r: &mut Reassembler, d: &[u8], t: u64, pushes: &mut u64) -> Result<bool> {
            *pushes += 1;
            r.push(d, t)
        }

        let a = frags(1, true, 1, 3000, 1024);
        let b = frags(2, false, 2, 2000, 1024);
        let lost = frags(3, false, 3, 3000, 1024);

        // Frame 1: complete, with one duplicate and one malformed datagram.
        for i in [0usize, 0, 1, 2] {
            let _ = counted_push(&mut r, &a[i], 0, &mut pushes).expect("push");
        }
        assert!(counted_push(&mut r, &[0u8; 3], 0, &mut pushes).is_err());
        // Frame 2: complete.
        for d in &b {
            let _ = counted_push(&mut r, d, 0, &mut pushes).expect("push");
        }
        // Frame 3: one fragment only, then aged out.
        let _ = counted_push(&mut r, &lost[0], 0, &mut pushes).expect("push");
        r.tick(1000);

        let s = r.stats();
        assert_eq!(
            s.fragments_received + s.fragments_duplicate + s.fragments_rejected,
            pushes
        );
        assert_eq!(s.fragments_received, 6);
        assert_eq!(s.fragments_duplicate, 1);
        assert_eq!(s.fragments_rejected, 1);
        assert_eq!(s.frames_completed, 2);
        assert_eq!(s.frames_dropped_incomplete, 1);
        assert_eq!(s.frames_dropped_stale, 0);
        assert_eq!(s.keyframe_requests, 0);

        let frame = r.pop_frame().expect("frame");
        assert_eq!(frame.frame_id, 2);
        assert_eq!(r.stats().frames_skipped_latest_wins, 1);
        assert!(r.take_keyframe_request(1000));
        assert_eq!(r.stats().keyframe_requests, 1);
    }

    #[test]
    fn default_reassembler_matches_default_config() {
        let mut r = Reassembler::default();
        assert_eq!(r.stats(), ReassemblyStats::default());
        let f = frags(0, true, 0, 64, 1200);
        assert!(r.push(&f[0], 0).expect("push"));
        assert_eq!(r.pop_frame().expect("frame").frame_id, 0);
    }

    /// FEC reconstructs a single lost data fragment per block with no stall:
    /// dropping one data fragment in *every* block still completes the frame,
    /// and the recovered keyframe satisfies the keyframe demand.
    #[test]
    fn fec_recovers_one_loss_per_block_without_keyframe() {
        let mut r = Reassembler::new(ReassemblyConfig {
            slot_timeout_ms: 100_000,
            stale_frame_distance: 64,
            ..cfg()
        });
        let k = 4u8;
        let f = frags_fec(1, true, 42, 10_000, 1200, k);
        let chunk = 1200 - FRAG_HEADER_LEN;
        let n = 10_000usize.div_ceil(chunk);
        let num_blocks = n.div_ceil(k as usize);
        assert!(num_blocks >= 2, "want a multi-block frame");
        assert_eq!(f.len(), n + num_blocks);

        // The first data fragment of every block is lost. Data fragments are at
        // [0, n); parity fragments at [n, f.len()).
        let dropped: Vec<usize> = (0..num_blocks).map(|b| b * k as usize).collect();

        // Push all parity first — this exercises the parity-before-data path,
        // where the slot is first opened by a parity fragment.
        let mut completed = 0;
        for p in n..f.len() {
            if r.push(&f[p], 0).expect("push parity") {
                completed += 1;
            }
        }
        for i in 0..n {
            if dropped.contains(&i) {
                continue;
            }
            if r.push(&f[i], 0).expect("push data") {
                completed += 1;
            }
        }
        assert_eq!(completed, 1, "frame completes via recovery");

        let frame = r.pop_frame().expect("frame");
        assert_eq!(frame.frame_id, 1);
        assert!(frame.keyframe);
        assert_eq!(frame.timestamp_ms, 42, "real timestamp adopted from data");
        assert_eq!(frame.data, payload(10_000));
        assert!(r.stats().fec_recovered >= num_blocks as u64);
        assert_eq!(r.stats().fec_parity_received, num_blocks as u64);
        // The keyframe reached the decoder, recovered and all: no demand.
        assert!(!r.take_keyframe_request(0));
    }

    /// Two losses in one block are beyond single-parity FEC: the frame cannot
    /// complete, and the slot eventually ages out and demands a keyframe.
    #[test]
    fn fec_cannot_recover_two_losses_in_a_block() {
        let mut r = Reassembler::new(ReassemblyConfig {
            slot_timeout_ms: 500,
            stale_frame_distance: 64,
            ..cfg()
        });
        let k = 4u8;
        let f = frags_fec(7, false, 7, 10_000, 1200, k);

        // Drop two data fragments from block 0 (indices 0 and 1).
        let mut completed = 0;
        for (idx, d) in f.iter().enumerate() {
            if idx == 0 || idx == 1 {
                continue;
            }
            if r.push(d, 1000).expect("push") {
                completed += 1;
            }
        }
        assert_eq!(completed, 0, "two losses in one block is unrecoverable");
        assert!(r.pop_frame().is_none());

        // No completion, so the slot times out and a keyframe is demanded.
        r.tick(2000);
        assert_eq!(r.stats().frames_dropped_incomplete, 1);
        assert!(r.take_keyframe_request(2000));
    }

    /// A parity fragment for a frame that already completed must be ignored as a
    /// late duplicate — no panic, no new push category, invariant intact.
    #[test]
    fn parity_for_completed_frame_is_ignored() {
        let mut r = Reassembler::new(cfg());
        let k = 4u8;
        let f = frags_fec(3, true, 3, 10_000, 1200, k);
        let n = 10_000usize.div_ceil(1200 - FRAG_HEADER_LEN);

        // Every data fragment arrives: the frame completes without parity.
        let mut completed = 0;
        for i in 0..n {
            if r.push(&f[i], 0).expect("push") {
                completed += 1;
            }
        }
        assert_eq!(completed, 1);

        // A straggling parity fragment for that finished frame now arrives.
        let before = r.stats();
        let done = r.push(&f[n], 0).expect("push parity");
        assert!(!done, "parity for a completed frame does nothing");
        assert_eq!(r.stats().fec_parity_received, before.fec_parity_received);
        assert_eq!(r.stats().fragments_duplicate, before.fragments_duplicate + 1);
    }

    /// The push partition must still hold with parity fragments, recovery,
    /// duplicates and a malformed datagram all mixed together.
    #[test]
    fn stats_partition_holds_with_fec_fragments() {
        let mut r = Reassembler::new(ReassemblyConfig {
            slot_timeout_ms: 100_000,
            stale_frame_distance: 64,
            ..cfg()
        });
        let k = 4u8;
        let f = frags_fec(20, true, 20, 10_000, 1200, k);
        let n = 10_000usize.div_ceil(1200 - FRAG_HEADER_LEN);
        let mut pushes = 0u64;

        // Parity first (accepted into `fec_parity_received`), then data with
        // index 1 dropped so a block genuinely recovers from its parity.
        for p in n..f.len() {
            let _ = r.push(&f[p], 0);
            pushes += 1;
        }
        for i in 0..n {
            if i == 1 {
                continue;
            }
            let _ = r.push(&f[i], 0);
            pushes += 1;
        }
        // One of each remaining category: duplicate parity, duplicate/late data,
        // malformed datagram.
        let _ = r.push(&f[n], 0);
        pushes += 1;
        let _ = r.push(&f[0], 0);
        pushes += 1;
        assert!(r.push(&[0u8; 3], 0).is_err());
        pushes += 1;

        let s = r.stats();
        assert!(s.fec_parity_received >= 1, "parity was accepted");
        assert!(s.fec_recovered >= 1, "a fragment was recovered");
        assert_eq!(
            s.fragments_received
                + s.fragments_duplicate
                + s.fragments_rejected
                + s.fec_parity_received,
            pushes,
            "every push falls into exactly one partition category"
        );
    }
}
