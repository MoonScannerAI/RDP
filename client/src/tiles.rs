//! Client-side tile store and compositor for lossless static-region refinement.
//!
//! The host re-sends regions of the desktop that have stopped changing as
//! *lossless* tiles on a reliable stream (see [`directdesk_shared::tiles`] for
//! the wire format and codec). This module owns the client half: it accumulates
//! those tiles, and it paints them over each decoded H.264 frame just before
//! presentation, so small text converges to pixel-exact instead of sitting at
//! whatever the encoder's quantiser left behind.
//!
//! # Why this module has no egui, no sockets and no async
//!
//! Everything here is a pure function of (messages seen so far, the frame being
//! painted). That is deliberate: compositing bugs are *visual* bugs, and visual
//! bugs are miserable to chase through a render loop. Keeping the store and the
//! blit pure means every clipping, lease and capacity rule below is pinned down
//! by a unit test that runs on any machine in milliseconds.
//!
//! # Why the blit is a bare `copy_from_slice`
//!
//! [`directdesk_shared::tiles::decompress_strip`] already emits tightly-packed
//! RGBA with alpha forced to `255`. The channel swap and the alpha fill happen
//! once, at admission, in shared code. This module must **not** redo either.
//!
//! Alpha in particular is load-bearing: the presenter builds its texture with
//! `egui::ColorImage::from_rgba_unmultiplied`, so a single pixel left at `A < 255`
//! punches a translucent hole straight through to the black background. Any code
//! path here that touches pixels leaves byte 3 alone — including the
//! `highlight` tint.
//!
//! # Why tiles are refused rather than evicted
//!
//! Refinement is a *bonus* layer over a picture that is already correct. If the
//! store is full, dropping the incoming tile costs nothing but a little
//! sharpness in one region. Evicting a resident tile to make room would instead
//! produce a patchwork of freshly-refined and suddenly-unrefined regions that
//! shimmer against each other — strictly worse than not refining at all.
//!
//! # Why leases are wrapping u32 comparisons
//!
//! `valid_from_ms` / `lease_ms` live on the host's **capture clock**: the same
//! wrapping `u32` counter the decoder recovers into `RawFrame::timestamp_ms`.
//! It is not wall time and it is not monotonic in the `u64` sense — it wraps
//! roughly every 49.7 days, and a host that has been up that long must not
//! suddenly stop refining. Every comparison therefore goes through
//! [`lease_covers`], which measures *distance* with wrapping arithmetic rather
//! than comparing absolute values.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use directdesk_shared::tiles::{
    decompress_strip, tile_cols, tile_id, TileCodec, TileMsg, MAX_STRIP_W, TILE_EDGE,
};
use parking_lot::Mutex;

/// Bytes per pixel in decoded frames and in tile payloads (RGBA).
const FRAME_BPP: usize = 4;

/// Hard ceiling on resident tile bytes, whatever the frame size implies.
///
/// 64 MiB is far more than any sane grid needs (a 4K frame's worth of tiles is
/// ~33 MiB) — it exists so a malformed or hostile `Reset` claiming an absurd
/// resolution cannot talk us into an unbounded footprint.
pub const MAX_STORE_BYTES: usize = 64 * 1024 * 1024;

/// Smallest tile edge the store will arm a grid for.
///
/// [`MAX_STORE_BYTES`] counts pixel bytes only, but every resident tile also
/// costs an `Arc` header, a `Vec` header and a `BTreeMap` node — call it 120
/// bytes that the budget cannot see. That overhead is negligible at a 64-pixel
/// edge (16 KiB of pixels per tile) and catastrophic at a 1-pixel edge, where
/// the budget would admit millions of 4-byte tiles. Flooring the edge bounds
/// the unaccounted overhead to a small fraction of the accounted bytes.
pub const MIN_TILE_EDGE: u32 = 16;

const _: () = assert!(MIN_TILE_EDGE <= TILE_EDGE);

/// Widest lease window the store will honour, in capture-clock milliseconds.
///
/// The wrapping comparator in [`lease_covers`] is unambiguous only while the
/// window is shorter than half the clock's range: at exactly half, "just before
/// the start" and "just after the end" become indistinguishable. Clamping to
/// `u32::MAX / 2` (~24.9 days) keeps the comparator honest while being far
/// longer than any lease a real host would issue.
const MAX_LEASE_WINDOW_MS: u32 = u32::MAX / 2;

/// Identity of a tile within the grid, as defined by
/// [`directdesk_shared::tiles::tile_id`]: `row * cols + col`.
///
/// Ordering is `row`-major by construction, so a [`BTreeMap`] keyed on this
/// iterates top-left to bottom-right. That is both cache-friendly for the blit
/// and — more importantly — *deterministic*, which is what makes overlapping
/// tiles composite the same way on every machine and every run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TileKey(pub u32);

/// One resident tile: where it goes, how long it is valid, and its pixels.
///
/// `rgba` is tightly packed (`w * h * 4`, no stride padding) with alpha already
/// `255`, exactly as [`decompress_strip`] produced it.
///
/// The lease is an atomic rather than a plain field so that
/// [`TileMsg::Renew`] can extend it in place. A renewal must not have to clone
/// the pixel buffer, and it must be visible to a compositor that already holds
/// an [`Arc`] to this tile — a renewal is a statement that the pixels are
/// *still exact*, so honouring it immediately is correct.
///
/// Both halves live in one `u64` so a reader can never observe a new
/// `valid_from` against an old `valid_through` (which, in the clamp path below,
/// could invert the window and paint a tile that should be dead).
#[derive(Debug)]
pub struct Tile {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
    pub rgba: Vec<u8>,
    lease: AtomicU64,
}

impl Tile {
    /// Build a tile. `rgba` must be `w * h * 4` bytes; a payload of any other
    /// length is not a panic here — [`composite_tiles`] refuses it at paint
    /// time, because this constructor is also the seam tests poke malformed
    /// input through.
    #[must_use]
    pub fn new(
        x: u32,
        y: u32,
        w: u32,
        h: u32,
        valid_from_ms: u32,
        valid_through_ms: u32,
        rgba: Vec<u8>,
    ) -> Self {
        Self {
            x,
            y,
            w,
            h,
            rgba,
            lease: AtomicU64::new(pack_lease(valid_from_ms, valid_through_ms)),
        }
    }

    /// `(valid_from_ms, valid_through_ms)` on the host capture clock.
    #[must_use]
    pub fn lease(&self) -> (u32, u32) {
        unpack_lease(self.lease.load(Ordering::Relaxed))
    }

    /// Bytes of pixel payload this tile holds — the unit of the capacity budget.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.rgba.len()
    }

    /// Pixels this tile covers, ignoring any clipping at the frame edge.
    #[must_use]
    pub fn pixels(&self) -> u64 {
        u64::from(self.w) * u64::from(self.h)
    }

    fn set_lease(&self, valid_from_ms: u32, valid_through_ms: u32) {
        self.lease.store(
            pack_lease(valid_from_ms, valid_through_ms),
            Ordering::Relaxed,
        );
    }
}

fn pack_lease(from: u32, through: u32) -> u64 {
    (u64::from(from) << 32) | u64::from(through)
}

fn unpack_lease(v: u64) -> (u32, u32) {
    ((v >> 32) as u32, v as u32)
}

/// Wrapping-safe lease test: is `frame_ts_ms` inside `[from, through]`?
///
/// Both endpoints and the probe are points on a wrapping `u32` capture clock,
/// so `from <= now && now <= through` is simply wrong near the wrap: a lease
/// issued at `u32::MAX - 10` and running 100 ms covers timestamp `50`, and a
/// naive comparison would refuse it for ~49 days.
///
/// Instead measure the *distance* from the start of the window in wrapping
/// arithmetic and compare it against the window's length. Both endpoints are
/// inclusive.
#[must_use]
pub fn lease_covers(frame_ts_ms: u32, valid_from_ms: u32, valid_through_ms: u32) -> bool {
    frame_ts_ms.wrapping_sub(valid_from_ms) <= valid_through_ms.wrapping_sub(valid_from_ms)
}

/// Has a lease's end passed, as of `frame_ts_ms`?
///
/// **Deliberately one-sided, and [`lease_covers`] must not be substituted for
/// it.** "Not yet valid" and "no longer valid" are entirely different states,
/// and only the second one justifies destroying a tile.
///
/// A freshly arrived tile is *routinely* not yet valid: the host stamps
/// `valid_from_ms` with the capture timestamp of the frame the refinement pass
/// ran on, while the client is still compositing an **earlier** frame — the
/// encoder's pipeline depth, the outbound frame queue, pacing and the decoder's
/// own latency all sit between them. So a brand-new tile normally arrives with
/// its window starting slightly in the future. Evicting on the two-sided test
/// would therefore delete almost every tile before it was ever painted, while
/// the host — which has already recorded it as delivered and keeps renewing it
/// — would never re-send it. The feature would spend bandwidth and refine
/// nothing. Waiting is free; deleting is not.
///
/// Uses the signed-difference trick so it is correct across the `u32` wrap for
/// any interval shorter than ~24.8 days.
#[must_use]
pub fn lease_ended(frame_ts_ms: u32, valid_through_ms: u32) -> bool {
    (frame_ts_ms.wrapping_sub(valid_through_ms) as i32) > 0
}

/// Capacity budget derived from the frame size: one full frame of tiles plus
/// 25% headroom, capped at [`MAX_STORE_BYTES`].
///
/// A full grid of `edge`-aligned tiles is very slightly larger than the frame
/// (partial edge columns round up to whole cells), and a refresh wave can
/// transiently hold a shrunken partial-height tile alongside its replacement.
/// The 25% covers both without ever being large enough to matter. An absurd
/// resolution whose byte count overflows `usize` falls back to the ceiling
/// rather than panicking.
#[must_use]
pub fn capacity_for_frame(width: u32, height: u32) -> usize {
    (width as usize)
        .checked_mul(height as usize)
        .and_then(|px| px.checked_mul(FRAME_BPP))
        .and_then(|bytes| bytes.checked_mul(5))
        .map_or(MAX_STORE_BYTES, |scaled| scaled / 4)
        .min(MAX_STORE_BYTES)
}

/// What one [`TileStore::apply`] call did.
///
/// Returned rather than merely counted so the caller (and the tests) can assert
/// on a single message's effect without diffing cumulative gauges.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ApplyOutcome {
    /// Tiles inserted, revoked or renewed.
    pub admitted: u32,
    /// Tiles refused because admitting them would exceed the capacity budget.
    pub dropped_capacity: u32,
    /// Messages refused outright: malformed geometry, corrupt payload, or a
    /// message arriving while the store is disarmed.
    pub rejected: u32,
}

/// What one [`composite_tiles`] call did, for the diagnostics overlay.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CompositeStats {
    /// Tiles blitted (possibly clipped) onto the frame.
    pub painted: u32,
    /// Tiles whose lease does not cover this frame's timestamp.
    pub skipped_expired: u32,
    /// Tiles that do not belong on this frame at all: the store was sized for a
    /// different resolution, the tile lies wholly off the frame, or its payload
    /// length disagrees with its declared extent.
    pub skipped_mismatched: u32,
    /// Frame pixels actually covered, after clipping.
    pub covered_px: u64,
}

/// The `TileMsg::Strip` payload, destructured.
///
/// A struct rather than eight positional parameters purely so the handler reads
/// as prose at the call site.
struct StripIn<'a> {
    x: u32,
    y: u32,
    w: u32,
    h: u32,
    codec: TileCodec,
    valid_from_ms: u32,
    lease_ms: u32,
    data: &'a [u8],
}

/// Everything guarded by the store's mutex.
struct Inner {
    tiles: BTreeMap<TileKey, Arc<Tile>>,
    /// Running total of `tiles`' payload bytes. Maintained incrementally: the
    /// capacity check runs on every admitted tile and must not be `O(n)`.
    bytes: usize,
    /// Running total of pixels covered by resident tiles.
    covered: u64,
    /// False until the host's next `Reset`. See [`TileStore::clear`].
    armed: bool,
    /// Capture timestamp of the most recent frame swept against, or `None`
    /// before any frame has been composited. Lets [`TileStore::renew`] refuse
    /// to resurrect a lapsed tile even when no frame has arrived to sweep it.
    last_frame_ts: Option<u32>,
    size: (u32, u32),
    edge: u32,
    cols: u32,
    capacity: usize,
    /// Bumped on every `Reset` and `clear`. A strip decompressed against one
    /// generation may not be inserted into another.
    generation: u64,
}

/// Accumulates lossless tiles from the host and hands snapshots to the
/// compositor.
///
/// Cheap to share: the pixel payloads live behind [`Arc`], so taking a snapshot
/// for a frame clones pointers, not megabytes, and the lock is held only for
/// the length of that pointer copy.
pub struct TileStore {
    inner: Mutex<Inner>,
    /// Upper bound applied on top of the size-derived capacity.
    capacity_ceiling: usize,

    // Diagnostics. Gauges are republished from `Inner` under the lock; counters
    // are monotonic. All `Relaxed`: they are read by a UI panel that only needs
    // to be approximately right.
    resident_tiles: AtomicUsize,
    resident_bytes: AtomicUsize,
    covered_pixels: AtomicU64,
    tiles_admitted: AtomicU64,
    tiles_dropped_capacity: AtomicU64,
    msgs_rejected: AtomicU64,
}

impl Default for TileStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TileStore {
    /// A disarmed, empty store. Nothing is painted until the host's first
    /// `Reset` establishes the grid.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity_ceiling(MAX_STORE_BYTES)
    }

    /// As [`TileStore::new`], but clamps the size-derived capacity to at most
    /// `ceiling` bytes.
    ///
    /// A real grid always fits inside the derived budget by construction, so
    /// this is the only way to exercise the drop-on-overflow path — and it is
    /// the hook a future memory-pressure signal would use to shrink the store
    /// without touching the wire protocol.
    #[must_use]
    pub fn with_capacity_ceiling(ceiling: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                tiles: BTreeMap::new(),
                bytes: 0,
                covered: 0,
                armed: false,
                last_frame_ts: None,
                size: (0, 0),
                edge: 0,
                cols: 0,
                capacity: 0,
                generation: 0,
            }),
            capacity_ceiling: ceiling,
            resident_tiles: AtomicUsize::new(0),
            resident_bytes: AtomicUsize::new(0),
            covered_pixels: AtomicU64::new(0),
            tiles_admitted: AtomicU64::new(0),
            tiles_dropped_capacity: AtomicU64::new(0),
            msgs_rejected: AtomicU64::new(0),
        }
    }

    /// Apply one message from the host's tile stream.
    ///
    /// The stream guarantees ordering, which is what makes per-tile generation
    /// counters unnecessary: a `Revoke` issued after a `Strip` for the same tile
    /// always lands after it.
    pub fn apply(&self, msg: TileMsg) -> ApplyOutcome {
        match msg {
            TileMsg::Reset {
                width,
                height,
                edge,
            } => self.reset(width, height, edge),
            TileMsg::Strip {
                x,
                y,
                w,
                h,
                codec,
                valid_from_ms,
                lease_ms,
                data,
            } => self.strip(StripIn {
                x,
                y,
                w,
                h,
                codec,
                valid_from_ms,
                lease_ms,
                data: &data,
            }),
            TileMsg::Revoke { ids } => self.revoke(&ids),
            TileMsg::Renew {
                ids,
                valid_through_ms,
            } => self.renew(&ids, valid_through_ms),
        }
    }

    /// Drop every tile and **disarm** until the host's next `Reset`.
    ///
    /// Disarming is the whole point. On a resolution change the old tiles are
    /// garbage, but so is anything already in flight from the old grid — a
    /// strip that left the host before the change can land microseconds after
    /// this call and would otherwise be admitted at coordinates that now mean
    /// something else. Staying disarmed until the host says `Reset` closes that
    /// race without needing a sequence number on the wire.
    pub fn clear(&self) {
        let mut inner = self.inner.lock();
        inner.tiles.clear();
        inner.bytes = 0;
        inner.covered = 0;
        inner.armed = false;
        // The host capture clock restarts from a fresh epoch whenever DDA is
        // rebuilt, so a timestamp learned under the old grid must not be used
        // to judge leases issued under the new one.
        inner.last_frame_ts = None;
        inner.size = (0, 0);
        inner.edge = 0;
        inner.cols = 0;
        inner.capacity = 0;
        inner.generation = inner.generation.wrapping_add(1);
        self.publish_gauges(&inner);
    }

    /// True once a `Reset` has established a usable grid.
    #[must_use]
    pub fn is_armed(&self) -> bool {
        self.inner.lock().armed
    }

    /// Frame size the resident tiles were sized for, or `(0, 0)` while disarmed.
    #[must_use]
    pub fn store_size(&self) -> (u32, u32) {
        self.inner.lock().size
    }

    /// Tile edge in force, or `0` while disarmed.
    #[must_use]
    pub fn edge(&self) -> u32 {
        self.inner.lock().edge
    }

    /// Current byte budget.
    #[must_use]
    pub fn capacity_bytes(&self) -> usize {
        self.inner.lock().capacity
    }

    /// Number of resident tiles.
    #[must_use]
    pub fn resident_tiles(&self) -> usize {
        self.resident_tiles.load(Ordering::Relaxed)
    }

    /// Pixel bytes held by resident tiles.
    #[must_use]
    pub fn resident_bytes(&self) -> usize {
        self.resident_bytes.load(Ordering::Relaxed)
    }

    /// Pixels covered by resident tiles, ignoring frame-edge clipping.
    #[must_use]
    pub fn covered_pixels(&self) -> u64 {
        self.covered_pixels.load(Ordering::Relaxed)
    }

    /// Lifetime count of tiles stored.
    #[must_use]
    pub fn tiles_admitted(&self) -> u64 {
        self.tiles_admitted.load(Ordering::Relaxed)
    }

    /// Lifetime count of tiles refused for want of capacity. Persistently
    /// non-zero means the budget is wrong, not that the host is misbehaving.
    #[must_use]
    pub fn tiles_dropped_capacity(&self) -> u64 {
        self.tiles_dropped_capacity.load(Ordering::Relaxed)
    }

    /// Lifetime count of refused messages. Non-zero in a healthy session means
    /// host and client disagree about the grid — worth a look.
    #[must_use]
    pub fn msgs_rejected(&self) -> u64 {
        self.msgs_rejected.load(Ordering::Relaxed)
    }

    /// Snapshot the resident tiles into `out` for one frame's compositing, and
    /// return the size the store is armed for.
    ///
    /// `None` means disarmed: paint nothing. `out` is reused across frames so
    /// the per-frame cost is a memcpy of `Arc` pointers under a briefly-held
    /// lock — never a pixel copy, never an allocation in the steady state.
    pub fn snapshot_into(&self, out: &mut Vec<Arc<Tile>>) -> Option<(u32, u32)> {
        out.clear();
        let inner = self.inner.lock();
        if !inner.armed {
            return None;
        }
        out.extend(inner.tiles.values().cloned());
        Some(inner.size)
    }

    /// Evict every tile whose lease has run out, as of `frame_ts_ms`.
    ///
    /// # Why eviction, and not merely "skip painting it"
    ///
    /// The host **relies** on this. When a lease lapses, `host::tiles`'
    /// `begin_pass` drops the tile from `Refined` back to `Moving` and
    /// deliberately queues **no** revocation — its comment reads "there is
    /// nothing to retract", because the client is supposed to have dropped it
    /// already. From then on the host also stops revoking that tile when its
    /// pixels change, since it only revokes tiles it believes are resident.
    ///
    /// If the client keeps a lapsed tile merely *unpainted*, that assumption is
    /// false, and a later `Renew` — which the host will send once the region
    /// settles again and re-hashes identically — hands it a fresh lease and the
    /// stale pixels are painted over live content, with no bound at all. That
    /// is precisely the failure the lease exists to prevent, so expiry has to
    /// mean *gone*, not *dormant*.
    ///
    /// Returns how many tiles were dropped. Cheap: one pass over a map bounded
    /// by the grid (~500 entries at 1080p) under an uncontended lock.
    pub fn sweep_expired(&self, frame_ts_ms: u32) -> u32 {
        let mut inner = self.inner.lock();
        if !inner.armed {
            return 0;
        }
        // Remembered so `renew` can refuse to resurrect a tile even in the
        // absence of a decoded frame to sweep against.
        inner.last_frame_ts = Some(frame_ts_ms);

        let mut dropped = 0;
        let mut freed_bytes = 0usize;
        let mut freed_px = 0u64;
        inner.tiles.retain(|_, tile| {
            let (_from, through) = tile.lease();
            // `lease_ended`, NOT `lease_covers` — a tile whose window has not
            // opened yet is the normal state of a freshly arrived one, and
            // destroying it there would delete nearly every tile before it
            // could be painted. See `lease_ended`.
            if !lease_ended(frame_ts_ms, through) {
                return true;
            }
            dropped += 1;
            freed_bytes += tile.bytes();
            freed_px += tile.pixels();
            false
        });
        if dropped > 0 {
            inner.bytes = inner.bytes.saturating_sub(freed_bytes);
            inner.covered = inner.covered.saturating_sub(freed_px);
            self.publish_gauges(&inner);
        }
        dropped
    }

    // -----------------------------------------------------------------------
    // Message handlers
    // -----------------------------------------------------------------------

    fn reset(&self, width: u32, height: u32, edge: u32) -> ApplyOutcome {
        let mut inner = self.inner.lock();
        inner.tiles.clear();
        inner.bytes = 0;
        inner.covered = 0;
        inner.generation = inner.generation.wrapping_add(1);

        // `edge` is on the wire so a future host can change it without a
        // version bump — but the shared codec refuses any strip taller than
        // `TILE_EDGE`, so an edge above it could never decode. Refusing to arm
        // is the honest response: we paint nothing rather than half a grid.
        //
        // The *lower* bound matters just as much, and for a different reason:
        // the capacity budget counts pixel bytes, while a resident tile also
        // costs an `Arc` allocation, a `Vec` header and a `BTreeMap` entry —
        // roughly 120 bytes that nothing accounts for. At `edge = 1` a tile
        // holds 4 pixel bytes, so the 64 MiB budget would admit ~16.7M tiles
        // and about 2 GB of real memory, from a wire message a few bytes long.
        // A floor of `MIN_TILE_EDGE` keeps the unaccounted overhead a small
        // fraction of the budget it rides on.
        if width == 0 || height == 0 || !(MIN_TILE_EDGE..=TILE_EDGE).contains(&edge) {
            inner.armed = false;
            inner.size = (0, 0);
            inner.edge = 0;
            inner.cols = 0;
            inner.capacity = 0;
            self.publish_gauges(&inner);
            drop(inner);
            return self.reject("unusable Reset geometry");
        }

        inner.armed = true;
        // Forget the old clock. A `Reset` follows a capture rebuild, and the
        // host's capture clock restarts from a fresh epoch there — judging a
        // new-generation lease against a timestamp from the old one would
        // delete healthy tiles.
        inner.last_frame_ts = None;
        inner.size = (width, height);
        inner.edge = edge;
        inner.cols = tile_cols(width, edge);
        inner.capacity = capacity_for_frame(width, height).min(self.capacity_ceiling);
        self.publish_gauges(&inner);
        ApplyOutcome::default()
    }

    fn strip(&self, s: StripIn<'_>) -> ApplyOutcome {
        // Phase 1: read the grid config, then release the lock. Inflating a
        // strip takes tens of microseconds and must not stall the compositor's
        // per-frame snapshot.
        let (armed, size, edge, cols, capacity, generation) = {
            let inner = self.inner.lock();
            (
                inner.armed,
                inner.size,
                inner.edge,
                inner.cols,
                inner.capacity,
                inner.generation,
            )
        };
        if !armed {
            return self.reject("strip while disarmed");
        }
        if s.w == 0 || s.h == 0 || s.w > MAX_STRIP_W || s.h > edge {
            return self.reject("strip extent out of range");
        }
        // Tile ids are grid coordinates: `x / edge` and `y / edge`. An unaligned
        // strip would therefore be filed under a neighbour's id, and a later
        // `Revoke` for that id would erase pixels the host never meant to touch
        // — stale content ghosting over live video. Refuse instead of guessing.
        if !s.x.is_multiple_of(edge) || !s.y.is_multiple_of(edge) {
            return self.reject("strip not aligned to the tile grid");
        }
        let (Some(right), Some(bottom)) = (s.x.checked_add(s.w), s.y.checked_add(s.h)) else {
            return self.reject("strip extent overflows");
        };
        if right > size.0 || bottom > size.1 {
            return self.reject("strip extends past the grid");
        }

        // `decompress_strip` bounds its own output to exactly `w * h * 4`, so a
        // hostile payload cannot inflate into an unbounded allocation here.
        // A fresh scratch buffer per strip costs one allocation against the
        // per-tile allocations we are about to make anyway, and buys us not
        // having to reason about a second lock's ordering against `inner`.
        let mut rgba = Vec::new();
        if decompress_strip(s.codec, s.data, s.w, s.h, &mut rgba).is_err() {
            return self.reject("strip payload failed to decode");
        }
        debug_assert_eq!(rgba.len(), s.w as usize * s.h as usize * FRAME_BPP);

        let valid_through_ms =
            clamp_lease_end(s.valid_from_ms, s.valid_from_ms.wrapping_add(s.lease_ms));
        let col0 = s.x / edge;
        let row = s.y / edge;
        let strip_stride = s.w as usize * FRAME_BPP;

        // Phase 2: insert. If a `Reset` or `clear` slipped in while we were
        // inflating, these pixels describe a grid that no longer exists.
        let mut inner = self.inner.lock();
        if inner.generation != generation || !inner.armed {
            drop(inner);
            return self.reject("grid changed while the strip was decoding");
        }

        let mut out = ApplyOutcome::default();
        for i in 0..s.w.div_ceil(edge) {
            let tx = s.x + i * edge;
            let tw = edge.min(right - tx);
            let th = s.h;
            let key = TileKey(tile_id(col0 + i, row, cols));

            let bytes = tw as usize * th as usize * FRAME_BPP;
            // Replacing a resident tile frees its bytes, so account for that
            // before deciding there is no room.
            let freed = inner.tiles.get(&key).map_or(0, |t| t.bytes());
            if inner.bytes - freed + bytes > capacity {
                out.dropped_capacity += 1;
                self.tiles_dropped_capacity.fetch_add(1, Ordering::Relaxed);
                continue;
            }

            let mut px = Vec::with_capacity(bytes);
            let x_off = (tx - s.x) as usize * FRAME_BPP;
            let row_bytes = tw as usize * FRAME_BPP;
            for r in 0..th as usize {
                let o = r * strip_stride + x_off;
                px.extend_from_slice(&rgba[o..o + row_bytes]);
            }

            let tile = Arc::new(Tile::new(
                tx,
                s.y,
                tw,
                th,
                s.valid_from_ms,
                valid_through_ms,
                px,
            ));
            inner.covered += tile.pixels();
            inner.bytes += tile.bytes();
            let replaced = inner.tiles.insert(key, tile);
            if let Some(old) = replaced {
                inner.bytes -= old.bytes();
                inner.covered -= old.pixels();
            }
            out.admitted += 1;
        }
        self.publish_gauges(&inner);
        drop(inner);
        self.tiles_admitted
            .fetch_add(u64::from(out.admitted), Ordering::Relaxed);
        out
    }

    fn revoke(&self, ids: &[u32]) -> ApplyOutcome {
        let mut inner = self.inner.lock();
        if !inner.armed {
            drop(inner);
            return self.reject("revoke while disarmed");
        }
        let mut out = ApplyOutcome::default();
        for &id in ids {
            let removed = inner.tiles.remove(&TileKey(id));
            if let Some(tile) = removed {
                inner.bytes -= tile.bytes();
                inner.covered -= tile.pixels();
                out.admitted += 1;
            }
        }
        self.publish_gauges(&inner);
        out
    }

    fn renew(&self, ids: &[u32], valid_through_ms: u32) -> ApplyOutcome {
        let inner = self.inner.lock();
        if !inner.armed {
            drop(inner);
            return self.reject("renew while disarmed");
        }
        let mut out = ApplyOutcome::default();
        let last_seen = inner.last_frame_ts;
        let mut lapsed: Vec<TileKey> = Vec::new();
        for &id in ids {
            if let Some(tile) = inner.tiles.get(&TileKey(id)) {
                let (from, through) = tile.lease();
                // Never resurrect. Once a lease has run out the host has
                // already written this tile off — `begin_pass` returned it to
                // `Moving` without a revocation, and it will no longer revoke
                // it when the pixels change. Extending the lease here would
                // paint content the host abandoned, unbounded. Drop it instead
                // and wait for a real strip.
                let _ = from;
                if last_seen.is_some_and(|now| lease_ended(now, through)) {
                    lapsed.push(TileKey(id));
                    continue;
                }
                // Renewals accumulate. Slide the window's start forward rather
                // than let it grow past the point where the wrapping comparator
                // stops being able to tell "before" from "after".
                let from = if valid_through_ms.wrapping_sub(from) > MAX_LEASE_WINDOW_MS {
                    valid_through_ms.wrapping_sub(MAX_LEASE_WINDOW_MS)
                } else {
                    from
                };
                tile.set_lease(from, valid_through_ms);
                out.admitted += 1;
            }
        }
        if !lapsed.is_empty() {
            let mut inner = inner;
            for key in lapsed {
                if let Some(tile) = inner.tiles.remove(&key) {
                    inner.bytes = inner.bytes.saturating_sub(tile.bytes());
                    inner.covered = inner.covered.saturating_sub(tile.pixels());
                    out.rejected += 1;
                }
            }
            self.publish_gauges(&inner);
        }
        out
    }

    fn reject(&self, why: &str) -> ApplyOutcome {
        self.msgs_rejected.fetch_add(1, Ordering::Relaxed);
        tracing::debug!("tile message rejected: {why}");
        ApplyOutcome {
            rejected: 1,
            ..ApplyOutcome::default()
        }
    }

    /// Republish the gauges from the authoritative values in `Inner`.
    fn publish_gauges(&self, inner: &Inner) {
        self.resident_tiles
            .store(inner.tiles.len(), Ordering::Relaxed);
        self.resident_bytes.store(inner.bytes, Ordering::Relaxed);
        self.covered_pixels.store(inner.covered, Ordering::Relaxed);
    }
}

/// Clamp a lease's end so the window stays inside [`MAX_LEASE_WINDOW_MS`].
fn clamp_lease_end(from: u32, through: u32) -> u32 {
    if through.wrapping_sub(from) > MAX_LEASE_WINDOW_MS {
        from.wrapping_add(MAX_LEASE_WINDOW_MS)
    } else {
        through
    }
}

/// Blit `tiles` over a decoded RGBA frame in `dst`.
///
/// A free function, not a method: the whole point is that the paint is a pure
/// function of its arguments, so every clipping and lease rule below is
/// testable without standing up a store.
///
/// `dst` is `w * h` RGBA, tightly packed. `frame_ts_ms` is the decoded frame's
/// host-capture timestamp. `store_size` is what the store is armed for.
///
/// A tile is painted iff **all** of:
///
/// * `store_size == (w, h)` — a store armed for another resolution has tiles at
///   coordinates that now mean something else, so nothing at all is painted.
/// * [`lease_covers`] accepts `frame_ts_ms` against the tile's lease. Network
///   delay can only shorten a tile's effective life, never extend it.
/// * The tile's payload length matches its declared extent, and its origin is
///   on the frame.
///
/// Nothing here panics and nothing here allocates, whatever the inputs. Tiles
/// clipped at the right or bottom edge are painted partially; tiles wholly off
/// the frame are skipped.
///
/// `highlight` tints painted pixels toward green so tile coverage is visible at
/// a glance during bring-up. It never touches alpha.
pub fn composite_tiles(
    dst: &mut [u8],
    w: u32,
    h: u32,
    frame_ts_ms: u32,
    store_size: (u32, u32),
    tiles: &[Arc<Tile>],
    highlight: bool,
) -> CompositeStats {
    let mut stats = CompositeStats::default();
    let all = tiles.len() as u32;

    if store_size != (w, h) || w == 0 || h == 0 {
        stats.skipped_mismatched = all;
        return stats;
    }
    // The frame buffer must be at least as large as its dimensions claim.
    // `checked_mul` rather than a bare product: `w` and `h` come off the wire,
    // and on a 32-bit target `w * h * 4` overflows long before the frame is
    // implausible.
    let Some(need) = (w as usize)
        .checked_mul(h as usize)
        .and_then(|px| px.checked_mul(FRAME_BPP))
    else {
        stats.skipped_mismatched = all;
        return stats;
    };
    if dst.len() < need {
        stats.skipped_mismatched = all;
        return stats;
    }
    let dst_stride = w as usize * FRAME_BPP;

    for tile in tiles {
        let (from, through) = tile.lease();
        if !lease_covers(frame_ts_ms, from, through) {
            stats.skipped_expired += 1;
            continue;
        }

        let want = (tile.w as usize)
            .checked_mul(tile.h as usize)
            .and_then(|px| px.checked_mul(FRAME_BPP));
        // A payload that disagrees with its declared extent is corruption, and
        // the only safe response is to leave the decoded frame alone.
        if tile.w == 0 || tile.h == 0 || want != Some(tile.rgba.len()) {
            stats.skipped_mismatched += 1;
            continue;
        }
        if tile.x >= w || tile.y >= h {
            stats.skipped_mismatched += 1;
            continue;
        }

        // Clip at the right and bottom edges. `tile.x < w` and `tile.w > 0`, so
        // both extents are at least 1 and every index below is in bounds:
        //   dst: (tile.y + copy_h - 1) * dst_stride + (tile.x + copy_w) * 4 <= need
        //   src: (copy_h - 1) * src_stride + copy_w * 4 <= rgba.len()
        let copy_w = tile.w.min(w - tile.x) as usize;
        let copy_h = tile.h.min(h - tile.y) as usize;
        let src_stride = tile.w as usize * FRAME_BPP;
        let row_bytes = copy_w * FRAME_BPP;
        let x_off = tile.x as usize * FRAME_BPP;

        for r in 0..copy_h {
            let s = r * src_stride;
            let d = (tile.y as usize + r) * dst_stride + x_off;
            let row = &mut dst[d..d + row_bytes];
            row.copy_from_slice(&tile.rgba[s..s + row_bytes]);
            if highlight {
                // Halve red and blue to push the region green. Byte 3 is left
                // alone: `from_rgba_unmultiplied` would turn any A < 255 into a
                // translucent hole onto the black background.
                for px in row.chunks_exact_mut(FRAME_BPP) {
                    px[0] /= 2;
                    px[2] /= 2;
                }
            }
        }

        stats.painted += 1;
        stats.covered_px += (copy_w * copy_h) as u64;
    }

    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use directdesk_shared::tiles::compress_strip;

    /// A frame filled with a recognisable, position-dependent pattern, so any
    /// stray write shows up as a byte that is no longer its own function of
    /// `(x, y)`.
    fn sentinel_frame(w: u32, h: u32) -> Vec<u8> {
        let mut f = vec![0u8; w as usize * h as usize * FRAME_BPP];
        for (i, b) in f.iter_mut().enumerate() {
            *b = if i % 4 == 3 { 255 } else { (i % 251) as u8 };
        }
        f
    }

    /// A tile of one flat colour, valid for all time.
    fn solid_tile(x: u32, y: u32, w: u32, h: u32, rgb: [u8; 3]) -> Arc<Tile> {
        let mut px = Vec::with_capacity(w as usize * h as usize * FRAME_BPP);
        for _ in 0..(w as usize * h as usize) {
            px.extend_from_slice(&[rgb[0], rgb[1], rgb[2], 255]);
        }
        Arc::new(Tile::new(x, y, w, h, 0, u32::MAX / 4, px))
    }

    fn px_at(buf: &[u8], w: u32, x: u32, y: u32) -> [u8; 4] {
        let o = (y as usize * w as usize + x as usize) * FRAME_BPP;
        [buf[o], buf[o + 1], buf[o + 2], buf[o + 3]]
    }

    /// A BGRA source frame with a position-dependent pattern, for round-tripping
    /// through the real codec.
    fn bgra_source(w: u32, h: u32) -> Vec<u8> {
        let mut src = vec![0u8; w as usize * h as usize * FRAME_BPP];
        for (i, b) in src.iter_mut().enumerate() {
            *b = if i % 4 == 3 {
                255
            } else {
                ((i * 37) % 251) as u8
            };
        }
        src
    }

    fn armed_store(w: u32, h: u32) -> TileStore {
        let store = TileStore::new();
        assert_eq!(
            store.apply(TileMsg::Reset {
                width: w,
                height: h,
                edge: TILE_EDGE,
            }),
            ApplyOutcome::default()
        );
        store
    }

    // -----------------------------------------------------------------------
    // composite_tiles: clipping
    // -----------------------------------------------------------------------

    #[test]
    fn right_edge_tile_is_clipped_not_wrapped() {
        let (w, h) = (100u32, 40u32);
        let mut dst = sentinel_frame(w, h);
        let before = dst.clone();
        // 64 wide starting at x=80: only 20 columns are on the frame.
        let tiles = [solid_tile(80, 0, 64, 8, [10, 20, 30])];
        let stats = composite_tiles(&mut dst, w, h, 0, (w, h), &tiles, false);

        assert_eq!(stats.painted, 1);
        assert_eq!(stats.covered_px, 20 * 8);
        assert_eq!(px_at(&dst, w, 99, 7), [10, 20, 30, 255]);
        // The row below the tile, and the wrapped-around column 0, are untouched.
        assert_eq!(px_at(&dst, w, 0, 1), px_at(&before, w, 0, 1));
        assert_eq!(px_at(&dst, w, 80, 8), px_at(&before, w, 80, 8));
    }

    #[test]
    fn bottom_edge_tile_is_clipped() {
        let (w, h) = (64u32, 40u32);
        let mut dst = sentinel_frame(w, h);
        let before = dst.clone();
        // 64 tall starting at y=32: only 8 rows are on the frame.
        let tiles = [solid_tile(0, 32, 64, 64, [1, 2, 3])];
        let stats = composite_tiles(&mut dst, w, h, 0, (w, h), &tiles, false);

        assert_eq!(stats.painted, 1);
        assert_eq!(stats.covered_px, 64 * 8);
        assert_eq!(px_at(&dst, w, 63, 39), [1, 2, 3, 255]);
        assert_eq!(px_at(&dst, w, 0, 31), px_at(&before, w, 0, 31));
    }

    #[test]
    fn both_edges_clip_at_once() {
        let (w, h) = (70u32, 70u32);
        let mut dst = sentinel_frame(w, h);
        let tiles = [solid_tile(64, 64, 64, 64, [9, 9, 9])];
        let stats = composite_tiles(&mut dst, w, h, 0, (w, h), &tiles, false);
        assert_eq!(stats.painted, 1);
        assert_eq!(stats.covered_px, 6 * 6);
        assert_eq!(px_at(&dst, w, 69, 69), [9, 9, 9, 255]);
    }

    #[test]
    fn offsets_need_not_be_multiples_of_the_tile_edge() {
        // The compositor is pure geometry; nothing in the blit may assume the
        // grid. (The store does enforce alignment — see the store tests.)
        let (w, h) = (128u32, 96u32);
        let mut dst = sentinel_frame(w, h);
        let before = dst.clone();
        let tiles = [solid_tile(37, 13, 11, 7, [200, 100, 50])];
        let stats = composite_tiles(&mut dst, w, h, 0, (w, h), &tiles, false);

        assert_eq!(stats.painted, 1);
        assert_eq!(stats.covered_px, 11 * 7);
        assert_eq!(px_at(&dst, w, 37, 13), [200, 100, 50, 255]);
        assert_eq!(px_at(&dst, w, 47, 19), [200, 100, 50, 255]);
        assert_eq!(px_at(&dst, w, 36, 13), px_at(&before, w, 36, 13));
        assert_eq!(px_at(&dst, w, 48, 19), px_at(&before, w, 48, 19));
        assert_eq!(px_at(&dst, w, 37, 20), px_at(&before, w, 37, 20));
    }

    #[test]
    fn fully_offscreen_tile_is_a_noop() {
        let (w, h) = (64u32, 64u32);
        let mut dst = sentinel_frame(w, h);
        let before = dst.clone();
        let tiles = [
            solid_tile(64, 0, 8, 8, [1, 1, 1]), // just past the right
            solid_tile(0, 64, 8, 8, [2, 2, 2]), // just past the bottom
            solid_tile(u32::MAX, u32::MAX, 8, 8, [3; 3]), // absurdly past both
        ];
        let stats = composite_tiles(&mut dst, w, h, 0, (w, h), &tiles, false);

        assert_eq!(stats.painted, 0);
        assert_eq!(stats.skipped_mismatched, 3);
        assert_eq!(stats.covered_px, 0);
        assert_eq!(dst, before);
    }

    // -----------------------------------------------------------------------
    // composite_tiles: hostile input
    // -----------------------------------------------------------------------

    #[test]
    fn short_or_long_tile_payload_is_rejected_without_panicking() {
        let (w, h) = (64u32, 64u32);
        let mut dst = sentinel_frame(w, h);
        let before = dst.clone();
        let tiles = [
            Arc::new(Tile::new(0, 0, 8, 8, 0, u32::MAX, vec![0u8; 8 * 8 * 4 - 1])),
            Arc::new(Tile::new(0, 0, 8, 8, 0, u32::MAX, vec![0u8; 8 * 8 * 4 + 1])),
            Arc::new(Tile::new(0, 0, 8, 8, 0, u32::MAX, Vec::new())),
            Arc::new(Tile::new(0, 0, 0, 8, 0, u32::MAX, Vec::new())),
            Arc::new(Tile::new(0, 0, 8, 0, 0, u32::MAX, Vec::new())),
        ];
        let stats = composite_tiles(&mut dst, w, h, 0, (w, h), &tiles, false);

        assert_eq!(stats.painted, 0);
        assert_eq!(stats.skipped_mismatched, 5);
        assert_eq!(dst, before);
    }

    #[test]
    fn absurd_dimensions_neither_panic_nor_allocate() {
        // A tiny buffer described as a gigantic frame: the byte count either
        // overflows or exceeds the buffer, and both paths must bail cleanly.
        let mut dst = vec![7u8; 64];
        let before = dst.clone();
        let tiles = [solid_tile(0, 0, 2, 2, [1, 2, 3])];

        for (w, h) in [
            (u32::MAX, u32::MAX),
            (u32::MAX, 1),
            (1, u32::MAX),
            (100_000, 100_000),
        ] {
            let stats = composite_tiles(&mut dst, w, h, 0, (w, h), &tiles, false);
            assert_eq!(stats.painted, 0, "{w}x{h}");
            assert_eq!(stats.skipped_mismatched, 1, "{w}x{h}");
            assert_eq!(dst, before, "{w}x{h}");
        }

        // A tile claiming an extent whose byte count overflows `usize`.
        let (w, h) = (4u32, 4u32);
        let mut small = sentinel_frame(w, h);
        let snapshot = small.clone();
        let huge = [Arc::new(Tile::new(
            0,
            0,
            u32::MAX,
            u32::MAX,
            0,
            u32::MAX,
            vec![0u8; 4],
        ))];
        let stats = composite_tiles(&mut small, w, h, 0, (w, h), &huge, false);
        assert_eq!(stats.skipped_mismatched, 1);
        assert_eq!(small, snapshot);
    }

    #[test]
    fn resolution_mismatch_paints_nothing() {
        let (w, h) = (64u32, 64u32);
        let mut dst = sentinel_frame(w, h);
        let before = dst.clone();
        let tiles = [solid_tile(0, 0, 64, 64, [255, 0, 0])];

        for store_size in [(128u32, 64u32), (64, 128), (0, 0), (65, 64)] {
            let stats = composite_tiles(&mut dst, w, h, 0, store_size, &tiles, false);
            assert_eq!(stats.painted, 0, "{store_size:?}");
            assert_eq!(stats.skipped_mismatched, 1, "{store_size:?}");
            assert_eq!(stats.covered_px, 0, "{store_size:?}");
            assert_eq!(dst, before, "{store_size:?}");
        }
    }

    #[test]
    fn zero_sized_frame_paints_nothing() {
        let mut dst: Vec<u8> = Vec::new();
        let tiles = [solid_tile(0, 0, 2, 2, [1, 1, 1])];
        let stats = composite_tiles(&mut dst, 0, 0, 0, (0, 0), &tiles, false);
        assert_eq!(stats.painted, 0);
        assert!(dst.is_empty());
    }

    // -----------------------------------------------------------------------
    // composite_tiles: ordering, bounds, highlight
    // -----------------------------------------------------------------------

    #[test]
    fn overlapping_tiles_composite_deterministically_in_slice_order() {
        let (w, h) = (32u32, 32u32);
        let tiles = [
            solid_tile(0, 0, 16, 16, [10, 10, 10]),
            solid_tile(8, 8, 16, 16, [20, 20, 20]),
        ];

        let mut a = sentinel_frame(w, h);
        let stats = composite_tiles(&mut a, w, h, 0, (w, h), &tiles, false);
        assert_eq!(stats.painted, 2);
        // Last writer wins in the overlap; the non-overlapping parts keep theirs.
        assert_eq!(px_at(&a, w, 0, 0), [10, 10, 10, 255]);
        assert_eq!(px_at(&a, w, 12, 12), [20, 20, 20, 255]);
        assert_eq!(px_at(&a, w, 20, 20), [20, 20, 20, 255]);

        // Same inputs, same bytes, every time.
        let mut b = sentinel_frame(w, h);
        composite_tiles(&mut b, w, h, 0, (w, h), &tiles, false);
        assert_eq!(a, b);

        // Reversed order is a different — but equally deterministic — picture,
        // which is exactly why the store iterates a BTreeMap.
        let flipped = [tiles[1].clone(), tiles[0].clone()];
        let mut c = sentinel_frame(w, h);
        composite_tiles(&mut c, w, h, 0, (w, h), &flipped, false);
        assert_eq!(px_at(&c, w, 12, 12), [10, 10, 10, 255]);
    }

    #[test]
    fn every_byte_outside_the_clipped_union_is_unchanged() {
        let (w, h) = (200u32, 120u32);
        let before = sentinel_frame(w, h);
        let mut dst = before.clone();

        let tiles = [
            solid_tile(0, 0, 64, 64, [1, 2, 3]),      // fully inside
            solid_tile(180, 100, 64, 64, [4, 5, 6]),  // clipped on both edges
            solid_tile(37, 91, 13, 29, [7, 8, 9]),    // unaligned, clipped bottom
            solid_tile(200, 0, 8, 8, [11, 12, 13]),   // wholly offscreen
            solid_tile(196, 116, 8, 8, [14, 15, 16]), // single-pixel-ish corner
            // Expired: must not contribute to the union.
            Arc::new(Tile::new(
                0,
                0,
                32,
                32,
                1_000,
                2_000,
                vec![9u8; 32 * 32 * 4],
            )),
            // Malformed: must not contribute either.
            Arc::new(Tile::new(100, 0, 8, 8, 0, u32::MAX, vec![0u8; 3])),
        ];

        let stats = composite_tiles(&mut dst, w, h, 5_000, (w, h), &tiles, false);
        assert_eq!(stats.painted, 4);
        assert_eq!(stats.skipped_expired, 1);
        assert_eq!(stats.skipped_mismatched, 2);

        // Independently recompute the union with plain min() clipping.
        let mut inside = vec![false; (w * h) as usize];
        let mut union_px = 0u64;
        for t in &tiles {
            let (from, through) = t.lease();
            if !lease_covers(5_000, from, through) {
                continue;
            }
            if t.rgba.len() != (t.w as usize * t.h as usize * FRAME_BPP) || t.w == 0 || t.h == 0 {
                continue;
            }
            if t.x >= w || t.y >= h {
                continue;
            }
            let cw = t.w.min(w - t.x);
            let ch = t.h.min(h - t.y);
            union_px += u64::from(cw) * u64::from(ch);
            for yy in t.y..t.y + ch {
                for xx in t.x..t.x + cw {
                    inside[(yy * w + xx) as usize] = true;
                }
            }
        }
        // Overlap makes covered_px >= distinct pixels; here the rects are
        // disjoint, so they agree and the stat is pinned exactly.
        assert_eq!(stats.covered_px, union_px);

        for (i, covered) in inside.iter().enumerate().take((w * h) as usize) {
            if *covered {
                continue;
            }
            let o = i * FRAME_BPP;
            assert_eq!(
                &dst[o..o + FRAME_BPP],
                &before[o..o + FRAME_BPP],
                "wrote outside the clipped union at pixel {i}"
            );
        }
    }

    #[test]
    fn highlight_tints_only_painted_pixels_and_never_alpha() {
        let (w, h) = (16u32, 16u32);
        let mut dst = sentinel_frame(w, h);
        let before = dst.clone();
        let tiles = [solid_tile(4, 4, 4, 4, [200, 100, 60])];
        composite_tiles(&mut dst, w, h, 0, (w, h), &tiles, true);

        assert_eq!(px_at(&dst, w, 4, 4), [100, 100, 30, 255]);
        assert_eq!(px_at(&dst, w, 7, 7), [100, 100, 30, 255]);
        assert_eq!(px_at(&dst, w, 3, 4), px_at(&before, w, 3, 4));
        assert!(
            dst.chunks_exact(FRAME_BPP).all(|p| p[3] == 255),
            "a translucent pixel would punch a hole through to black"
        );
    }

    // -----------------------------------------------------------------------
    // Leases
    // -----------------------------------------------------------------------

    #[test]
    fn lease_comparator_is_inclusive_at_both_ends() {
        assert!(lease_covers(100, 100, 200));
        assert!(lease_covers(150, 100, 200));
        assert!(lease_covers(200, 100, 200));
        assert!(!lease_covers(99, 100, 200));
        assert!(!lease_covers(201, 100, 200));
        // A zero-length lease covers exactly one instant.
        assert!(lease_covers(100, 100, 100));
        assert!(!lease_covers(101, 100, 100));
    }

    #[test]
    fn lease_window_wraps_across_u32_max() {
        // Issued 10 ms before the clock wraps, running 100 ms.
        let from = u32::MAX - 9;
        let through = from.wrapping_add(100); // == 90
        assert!(lease_covers(from, from, through));
        assert!(lease_covers(u32::MAX, from, through));
        assert!(lease_covers(0, from, through)); // the wrap itself
        assert!(lease_covers(50, from, through));
        assert!(lease_covers(90, from, through));
        assert!(!lease_covers(91, from, through));
        // A frame from *before* the lease started, on the other side of the wrap.
        assert!(!lease_covers(from - 1, from, through));
    }

    #[test]
    fn expired_tile_is_skipped_not_painted() {
        let (w, h) = (32u32, 32u32);
        let mut dst = sentinel_frame(w, h);
        let before = dst.clone();
        let tiles = [Arc::new(Tile::new(
            0,
            0,
            8,
            8,
            1_000,
            1_500,
            vec![0u8; 8 * 8 * 4],
        ))];

        let stats = composite_tiles(&mut dst, w, h, 1_501, (w, h), &tiles, false);
        assert_eq!(stats.skipped_expired, 1);
        assert_eq!(stats.painted, 0);
        assert_eq!(dst, before);

        // Too early is refused too: delay may shorten a lease, never extend it.
        let stats = composite_tiles(&mut dst, w, h, 999, (w, h), &tiles, false);
        assert_eq!(stats.skipped_expired, 1);
        assert_eq!(dst, before);

        // In window: painted.
        let stats = composite_tiles(&mut dst, w, h, 1_200, (w, h), &tiles, false);
        assert_eq!(stats.painted, 1);
        assert_ne!(dst, before);
    }

    #[test]
    fn store_composites_across_the_clock_wrap() {
        let store = armed_store(64, 64);
        let src = bgra_source(64, 64);
        let (codec, data) = compress_strip(&src, 64 * 4, 0, 0, 64, 64, 6).unwrap();
        let from = u32::MAX - 20;
        let out = store.apply(TileMsg::Strip {
            x: 0,
            y: 0,
            w: 64,
            h: 64,
            codec,
            valid_from_ms: from,
            lease_ms: 200,
            data,
        });
        assert_eq!(out.admitted, 1);

        let mut tiles = Vec::new();
        let size = store.snapshot_into(&mut tiles).unwrap();

        // Timestamp 30 is 51 ms after `from` once the wrap is accounted for.
        let mut dst = sentinel_frame(64, 64);
        let stats = composite_tiles(&mut dst, 64, 64, 30, size, &tiles, false);
        assert_eq!(stats.painted, 1);
        // ...and 200 ms after `from` is timestamp 179; 180 is one past the end.
        let mut dst2 = sentinel_frame(64, 64);
        let stats = composite_tiles(&mut dst2, 64, 64, 180, size, &tiles, false);
        assert_eq!(stats.skipped_expired, 1);
    }

    #[test]
    fn absurd_lease_is_clamped_to_half_the_clock() {
        // A lease longer than half the clock's range makes "before the start"
        // and "after the end" indistinguishable, so it is clamped at admission.
        assert_eq!(clamp_lease_end(0, u32::MAX), MAX_LEASE_WINDOW_MS);
        assert_eq!(clamp_lease_end(10, 20), 20);
        assert_eq!(clamp_lease_end(u32::MAX, 9), 9); // wraps, window == 10
    }

    // -----------------------------------------------------------------------
    // TileStore
    // -----------------------------------------------------------------------

    #[test]
    fn reset_arms_and_sizes_the_grid() {
        let store = TileStore::new();
        assert!(!store.is_armed());
        assert_eq!(store.snapshot_into(&mut Vec::new()), None);

        store.apply(TileMsg::Reset {
            width: 1920,
            height: 1080,
            edge: TILE_EDGE,
        });
        assert!(store.is_armed());
        assert_eq!(store.store_size(), (1920, 1080));
        assert_eq!(store.edge(), TILE_EDGE);
        assert_eq!(store.capacity_bytes(), 1920 * 1080 * 4 * 5 / 4);
    }

    #[test]
    fn unusable_reset_geometry_leaves_the_store_disarmed() {
        for (w, h, edge) in [
            (0u32, 1080u32, 64u32),
            (1920, 0, 64),
            (1920, 1080, 0),
            (1920, 1080, TILE_EDGE + 1),
        ] {
            let store = TileStore::new();
            let out = store.apply(TileMsg::Reset {
                width: w,
                height: h,
                edge,
            });
            assert_eq!(out.rejected, 1, "{w}x{h} edge {edge}");
            assert!(!store.is_armed(), "{w}x{h} edge {edge}");
        }
    }

    #[test]
    fn absurd_reset_falls_back_to_the_hard_ceiling() {
        let store = armed_store(u32::MAX, u32::MAX);
        assert_eq!(store.capacity_bytes(), MAX_STORE_BYTES);
        assert_eq!(store.resident_bytes(), 0);
        assert_eq!(capacity_for_frame(u32::MAX, u32::MAX), MAX_STORE_BYTES);
        assert_eq!(capacity_for_frame(3840, 2160), 3840 * 2160 * 4 * 5 / 4);
    }

    #[test]
    fn strip_splits_into_grid_tiles_and_round_trips_exactly() {
        let (w, h) = (256u32, 128u32);
        let store = armed_store(w, h);
        let src = bgra_source(w, h);
        let (codec, data) = compress_strip(&src, w as usize * 4, 0, 64, 256, 64, 6).unwrap();

        let out = store.apply(TileMsg::Strip {
            x: 0,
            y: 64,
            w: 256,
            h: 64,
            codec,
            valid_from_ms: 0,
            lease_ms: 10_000,
            data,
        });
        assert_eq!(out.admitted, 4, "a 256px strip is four grid tiles");
        assert_eq!(store.resident_tiles(), 4);
        assert_eq!(store.resident_bytes(), 256 * 64 * 4);
        assert_eq!(store.covered_pixels(), 256 * 64);
        assert_eq!(store.tiles_admitted(), 4);

        let mut tiles = Vec::new();
        let size = store.snapshot_into(&mut tiles).unwrap();
        // Row 1 of a 4-column grid: ids 4..8, in ascending order.
        assert_eq!(tiles.len(), 4);
        for (i, t) in tiles.iter().enumerate() {
            assert_eq!(t.x, i as u32 * 64);
            assert_eq!(t.y, 64);
            assert_eq!((t.w, t.h), (64, 64));
        }

        let mut dst = sentinel_frame(w, h);
        let stats = composite_tiles(&mut dst, w, h, 500, size, &tiles, false);
        assert_eq!(stats.painted, 4);
        assert_eq!(stats.covered_px, 256 * 64);

        // The painted region must be the source, BGRA -> RGBA, alpha forced.
        for y in 64..128u32 {
            for x in 0..w {
                let s = (y as usize * w as usize + x as usize) * 4;
                assert_eq!(
                    px_at(&dst, w, x, y),
                    [src[s + 2], src[s + 1], src[s], 255],
                    "at {x},{y}"
                );
            }
        }
    }

    #[test]
    fn partial_edge_strip_lands_on_the_right_tile_id() {
        // 200x100 with edge 64 is a 4x2 grid whose last column is 8px wide and
        // whose last row is 36px tall.
        let (w, h) = (200u32, 100u32);
        let store = armed_store(w, h);
        let src = bgra_source(w, h);
        let (codec, data) = compress_strip(&src, w as usize * 4, 192, 64, 8, 36, 6).unwrap();

        let out = store.apply(TileMsg::Strip {
            x: 192,
            y: 64,
            w: 8,
            h: 36,
            codec,
            valid_from_ms: 0,
            lease_ms: 1_000,
            data,
        });
        assert_eq!(out.admitted, 1);
        assert_eq!(store.resident_bytes(), 8 * 36 * 4);

        let mut tiles = Vec::new();
        let size = store.snapshot_into(&mut tiles).unwrap();
        assert_eq!(
            (tiles[0].x, tiles[0].y, tiles[0].w, tiles[0].h),
            (192, 64, 8, 36)
        );

        let mut dst = sentinel_frame(w, h);
        let stats = composite_tiles(&mut dst, w, h, 10, size, &tiles, false);
        assert_eq!(stats.covered_px, 8 * 36);
        assert_eq!(px_at(&dst, w, 199, 99)[3], 255);
    }

    #[test]
    fn misaligned_or_oversized_strips_are_rejected() {
        let store = armed_store(256, 128);
        let src = bgra_source(256, 128);
        let (codec, data) = compress_strip(&src, 256 * 4, 0, 0, 64, 64, 6).unwrap();

        let bad = [
            (1u32, 0u32, 64u32, 64u32),  // x not on the grid
            (0, 1, 64, 64),              // y not on the grid
            (0, 0, 0, 64),               // empty
            (0, 0, 64, 0),               // empty
            (0, 0, MAX_STRIP_W + 1, 64), // wider than a strip may be
            (0, 0, 64, TILE_EDGE + 1),   // taller than a tile
            (192, 0, 128, 64),           // runs off the right edge
            (0, 64, 64, 128),            // runs off the bottom edge
            (u32::MAX, 0, 64, 64),       // extent overflows
        ];
        for (x, y, w, h) in bad {
            let out = store.apply(TileMsg::Strip {
                x,
                y,
                w,
                h,
                codec,
                valid_from_ms: 0,
                lease_ms: 100,
                data: data.clone(),
            });
            assert_eq!(
                out,
                ApplyOutcome {
                    rejected: 1,
                    ..Default::default()
                },
                "{x},{y} {w}x{h}"
            );
        }
        assert_eq!(store.resident_tiles(), 0);
        assert_eq!(store.msgs_rejected(), bad.len() as u64);
    }

    #[test]
    fn corrupt_strip_payload_is_rejected_without_panicking() {
        let store = armed_store(128, 128);
        for data in [
            Vec::new(),
            vec![0xffu8; 32],
            vec![0x00u8; 4096],
            vec![1, 2], // a Solid payload must be exactly 3 bytes
        ] {
            let out = store.apply(TileMsg::Strip {
                x: 0,
                y: 0,
                w: 64,
                h: 64,
                codec: TileCodec::FilteredDeflateBgr,
                valid_from_ms: 0,
                lease_ms: 100,
                data,
            });
            assert_eq!(out.rejected, 1);
        }
        let out = store.apply(TileMsg::Strip {
            x: 0,
            y: 0,
            w: 64,
            h: 64,
            codec: TileCodec::Solid,
            valid_from_ms: 0,
            lease_ms: 100,
            data: vec![1, 2],
        });
        assert_eq!(out.rejected, 1);
        assert_eq!(store.resident_tiles(), 0);
    }

    #[test]
    fn revoke_removes_tiles_and_frees_their_budget() {
        let store = armed_store(256, 64);
        let src = bgra_source(256, 64);
        let (codec, data) = compress_strip(&src, 256 * 4, 0, 0, 256, 64, 6).unwrap();
        store.apply(TileMsg::Strip {
            x: 0,
            y: 0,
            w: 256,
            h: 64,
            codec,
            valid_from_ms: 0,
            lease_ms: 1_000,
            data,
        });
        assert_eq!(store.resident_tiles(), 4);

        // Ids 1 and 2 exist; 99 does not and is silently ignored.
        let out = store.apply(TileMsg::Revoke {
            ids: vec![1, 2, 99],
        });
        assert_eq!(out.admitted, 2);
        assert_eq!(store.resident_tiles(), 2);
        assert_eq!(store.resident_bytes(), 2 * 64 * 64 * 4);
        assert_eq!(store.covered_pixels(), 2 * 64 * 64);

        let mut tiles = Vec::new();
        store.snapshot_into(&mut tiles);
        assert_eq!(tiles.iter().map(|t| t.x).collect::<Vec<_>>(), vec![0, 192]);
    }

    #[test]
    fn renew_extends_the_lease_in_place() {
        let store = armed_store(64, 64);
        let src = bgra_source(64, 64);
        let (codec, data) = compress_strip(&src, 64 * 4, 0, 0, 64, 64, 6).unwrap();
        store.apply(TileMsg::Strip {
            x: 0,
            y: 0,
            w: 64,
            h: 64,
            codec,
            valid_from_ms: 100,
            lease_ms: 200,
            data,
        });

        let mut tiles = Vec::new();
        let size = store.snapshot_into(&mut tiles).unwrap();
        let mut dst = sentinel_frame(64, 64);
        // Renewed WHILE STILL LIVE (frame 200 is inside [100, 300]).
        assert_eq!(
            composite_tiles(&mut dst, 64, 64, 200, size, &tiles, false).painted,
            1
        );

        let out = store.apply(TileMsg::Renew {
            ids: vec![0, 7],
            valid_through_ms: 5_000,
        });
        assert_eq!(out.admitted, 1, "id 7 does not exist");

        // The renewal is visible through the Arc we already hold — no pixel
        // copy, no re-snapshot needed.
        assert_eq!(tiles[0].lease(), (100, 5_000));
        assert_eq!(
            composite_tiles(&mut dst, 64, 64, 400, size, &tiles, false).painted,
            1
        );
    }

    #[test]
    fn a_tiny_edge_is_refused_because_the_budget_cannot_see_per_tile_overhead() {
        // `edge = 1` would let a handful of wire bytes create millions of
        // 4-byte tiles, each costing ~120 bytes of allocator and map overhead
        // that MAX_STORE_BYTES does not count — roughly 2 GB of RSS.
        let store = TileStore::new();
        store.apply(TileMsg::Reset {
            width: 1920,
            height: 1080,
            edge: 1,
        });
        assert!(!store.is_armed(), "a 1-pixel edge must not arm the grid");

        for edge in [MIN_TILE_EDGE, 32, TILE_EDGE] {
            let store = TileStore::new();
            store.apply(TileMsg::Reset {
                width: 1920,
                height: 1080,
                edge,
            });
            assert!(store.is_armed(), "edge {edge} is legitimate");
        }
    }

    #[test]
    fn a_tile_that_is_not_valid_yet_is_never_evicted() {
        // THE regression test for this module. A freshly arrived tile is
        // normally not yet valid: the host stamps `valid_from_ms` with the
        // capture ts of the frame its refinement pass ran on, while the client
        // is still compositing an earlier frame — encoder pipeline depth, the
        // frame queue, pacing and decoder latency all sit in between. So the
        // margin is zero by construction and routinely negative.
        //
        // Evicting on the two-sided `lease_covers` deleted essentially every
        // tile before it could be painted, and because the host had already
        // recorded delivery and kept renewing it, it was never re-sent: the
        // feature spent bandwidth and refined nothing, silently.
        let store = armed_store(64, 64);
        let src = bgra_source(64, 64);
        let (codec, data) = compress_strip(&src, 64 * 4, 0, 0, 64, 64, 6).unwrap();
        store.apply(TileMsg::Strip {
            x: 0,
            y: 0,
            w: 64,
            h: 64,
            codec,
            valid_from_ms: 130,
            lease_ms: 4_000,
            data,
        });
        assert_eq!(store.resident_tiles(), 1);

        // The client is compositing a frame captured 30 ms BEFORE this tile's
        // window opens. It must survive, unpainted, and then be painted.
        assert_eq!(store.sweep_expired(100), 0, "a not-yet-valid tile must live");
        assert_eq!(store.resident_tiles(), 1);

        let mut tiles = Vec::new();
        let size = store.snapshot_into(&mut tiles).unwrap();
        let mut dst = sentinel_frame(64, 64);
        assert_eq!(
            composite_tiles(&mut dst, 64, 64, 100, size, &tiles, false).painted,
            0,
            "still too early to paint"
        );
        assert_eq!(
            composite_tiles(&mut dst, 64, 64, 200, size, &tiles, false).painted,
            1,
            "and then it paints, because it was not destroyed"
        );
    }

    #[test]
    fn lease_ended_is_one_sided_and_wraps() {
        // Before the window opens is NOT ended.
        assert!(!lease_ended(100, 300));
        assert!(!lease_ended(299, 300));
        assert!(!lease_ended(300, 300), "inclusive at the end");
        assert!(lease_ended(301, 300));
        // Across the u32 wrap, in both directions.
        assert!(!lease_ended(u32::MAX - 10, u32::MAX));
        assert!(lease_ended(10, u32::MAX));
        assert!(!lease_ended(u32::MAX, 10), "10 is 'after' only by wrapping");
    }

    #[test]
    fn a_reset_forgets_the_previous_clock() {
        // The host capture clock restarts from a fresh epoch on a DDA rebuild,
        // which is exactly when a `Reset` arrives. A stale `last_frame_ts` from
        // the old (much larger) clock would make `renew` judge new-generation
        // leases as long expired and delete healthy tiles.
        let store = armed_store(64, 64);
        store.sweep_expired(5_000_000);
        store.apply(TileMsg::Reset {
            width: 64,
            height: 64,
            edge: 64,
        });

        let src = bgra_source(64, 64);
        let (codec, data) = compress_strip(&src, 64 * 4, 0, 0, 64, 64, 6).unwrap();
        store.apply(TileMsg::Strip {
            x: 0,
            y: 0,
            w: 64,
            h: 64,
            codec,
            valid_from_ms: 0,
            lease_ms: 4_000,
            data,
        });
        let out = store.apply(TileMsg::Renew {
            ids: vec![0],
            valid_through_ms: 9_000,
        });
        assert_eq!(out.admitted, 1, "the new grid's tile must survive renewal");
        assert_eq!(store.resident_tiles(), 1);
    }

    #[test]
    fn an_expired_tile_is_evicted_not_merely_left_unpainted() {
        // The host stops revoking a tile once its lease lapses — `begin_pass`
        // returns it to `Moving` with no revocation because it assumes we have
        // dropped it. Keeping it resident makes that assumption false.
        let store = armed_store(64, 64);
        let src = bgra_source(64, 64);
        let (codec, data) = compress_strip(&src, 64 * 4, 0, 0, 64, 64, 6).unwrap();
        store.apply(TileMsg::Strip {
            x: 0,
            y: 0,
            w: 64,
            h: 64,
            codec,
            valid_from_ms: 100,
            lease_ms: 200,
            data,
        });
        assert_eq!(store.resident_tiles(), 1);
        assert!(store.resident_bytes() > 0);

        assert_eq!(store.sweep_expired(250), 0, "still inside its lease");
        assert_eq!(store.resident_tiles(), 1);

        assert_eq!(store.sweep_expired(400), 1, "lease ran out at 300");
        assert_eq!(store.resident_tiles(), 0);
        assert_eq!(store.resident_bytes(), 0, "capacity must be reclaimed too");
        assert_eq!(store.covered_pixels(), 0);
    }

    #[test]
    fn renew_never_resurrects_a_lapsed_tile() {
        // The exact reported failure, in order:
        //  1. a long scroll means no refinement passes, so the lease lapses;
        //  2. the host drops the tile to `Moving` WITHOUT revoking it, and from
        //     then on will not revoke it when the pixels change either;
        //  3. the replacement strip is lost (seam overflow / capacity drop);
        //  4. the host re-hashes, sees its own pixels unchanged, and renews.
        // If step 4 could revive the tile, the client would paint pre-scroll
        // pixels over live content on every renewal, forever.
        let store = armed_store(64, 64);
        let src = bgra_source(64, 64);
        let (codec, data) = compress_strip(&src, 64 * 4, 0, 0, 64, 64, 6).unwrap();
        store.apply(TileMsg::Strip {
            x: 0,
            y: 0,
            w: 64,
            h: 64,
            codec,
            valid_from_ms: 100,
            lease_ms: 200,
            data,
        });

        // A frame arrives past the lease. Even without an explicit sweep call
        // the store must not later hand this tile a fresh life.
        assert_eq!(store.sweep_expired(400), 1);

        let out = store.apply(TileMsg::Renew {
            ids: vec![0],
            valid_through_ms: 99_000,
        });
        assert_eq!(out.admitted, 0, "a dead tile must not be renewable");
        assert_eq!(store.resident_tiles(), 0);

        let mut tiles = Vec::new();
        let size = store.snapshot_into(&mut tiles).unwrap();
        let mut dst = sentinel_frame(64, 64);
        let before = dst.clone();
        let stats = composite_tiles(&mut dst, 64, 64, 500, size, &tiles, false);
        assert_eq!(stats.painted, 0);
        assert_eq!(dst, before, "stale pixels were painted over live content");
    }

    #[test]
    fn renew_is_refused_for_a_tile_that_lapsed_without_being_swept() {
        // Belt and braces: if the decoder stalls, no frame arrives to sweep
        // against, but the store still remembers the last timestamp it saw and
        // must use it to refuse the renewal.
        let store = armed_store(64, 64);
        let src = bgra_source(64, 64);
        let (codec, data) = compress_strip(&src, 64 * 4, 0, 0, 64, 64, 6).unwrap();
        store.apply(TileMsg::Strip {
            x: 0,
            y: 0,
            w: 64,
            h: 64,
            codec,
            valid_from_ms: 100,
            lease_ms: 200,
            data,
        });
        // A frame at 250 keeps it alive and teaches the store "now".
        assert_eq!(store.sweep_expired(250), 0);
        assert_eq!(store.resident_tiles(), 1);

        // Host renews late, after the lease would have run out at 300, but no
        // frame has arrived in between to sweep it.
        let out = store.apply(TileMsg::Renew {
            ids: vec![0],
            valid_through_ms: 99_000,
        });
        // Still live as of the last frame we saw (250 < 300), so this renewal
        // is legitimate and must be honoured — refusing it would make a
        // perfectly healthy tile flicker.
        assert_eq!(out.admitted, 1);
        assert_eq!(store.resident_tiles(), 1);
    }

    #[test]
    fn renew_slides_the_window_start_when_it_would_grow_too_wide() {
        let store = armed_store(64, 64);
        let src = bgra_source(64, 64);
        let (codec, data) = compress_strip(&src, 64 * 4, 0, 0, 64, 64, 6).unwrap();
        store.apply(TileMsg::Strip {
            x: 0,
            y: 0,
            w: 64,
            h: 64,
            codec,
            valid_from_ms: 0,
            lease_ms: 100,
            data,
        });
        store.apply(TileMsg::Renew {
            ids: vec![0],
            valid_through_ms: u32::MAX,
        });
        let mut tiles = Vec::new();
        store.snapshot_into(&mut tiles);
        let (from, through) = tiles[0].lease();
        assert_eq!(through, u32::MAX);
        assert_eq!(through.wrapping_sub(from), MAX_LEASE_WINDOW_MS);
    }

    #[test]
    fn clear_disarms_until_the_next_reset() {
        let store = armed_store(128, 64);
        let src = bgra_source(128, 64);
        let (codec, data) = compress_strip(&src, 128 * 4, 0, 0, 128, 64, 6).unwrap();
        let strip = TileMsg::Strip {
            x: 0,
            y: 0,
            w: 128,
            h: 64,
            codec,
            valid_from_ms: 0,
            lease_ms: 10_000,
            data,
        };
        assert_eq!(store.apply(strip.clone()).admitted, 2);

        store.clear();
        assert!(!store.is_armed());
        assert_eq!(store.resident_tiles(), 0);
        assert_eq!(store.resident_bytes(), 0);
        assert_eq!(store.store_size(), (0, 0));
        assert_eq!(store.snapshot_into(&mut Vec::new()), None);

        // The race this exists for: a strip already in flight from the old
        // resolution lands right after the clear. It must not be admitted.
        assert_eq!(store.apply(strip.clone()).rejected, 1);
        assert_eq!(store.apply(TileMsg::Revoke { ids: vec![0] }).rejected, 1);
        assert_eq!(
            store
                .apply(TileMsg::Renew {
                    ids: vec![0],
                    valid_through_ms: 9_999,
                })
                .rejected,
            1
        );
        assert_eq!(store.resident_tiles(), 0);

        // The host's next Reset re-arms it.
        store.apply(TileMsg::Reset {
            width: 128,
            height: 64,
            edge: TILE_EDGE,
        });
        assert!(store.is_armed());
        assert_eq!(store.apply(strip).admitted, 2);
        assert_eq!(store.resident_tiles(), 2);
    }

    #[test]
    fn reset_drops_the_previous_grid() {
        let store = armed_store(128, 64);
        let src = bgra_source(128, 64);
        let (codec, data) = compress_strip(&src, 128 * 4, 0, 0, 128, 64, 6).unwrap();
        store.apply(TileMsg::Strip {
            x: 0,
            y: 0,
            w: 128,
            h: 64,
            codec,
            valid_from_ms: 0,
            lease_ms: 10_000,
            data,
        });
        assert_eq!(store.resident_tiles(), 2);

        store.apply(TileMsg::Reset {
            width: 1920,
            height: 1080,
            edge: TILE_EDGE,
        });
        assert_eq!(store.resident_tiles(), 0);
        assert_eq!(store.resident_bytes(), 0);
        assert_eq!(store.covered_pixels(), 0);
        assert_eq!(store.store_size(), (1920, 1080));
    }

    #[test]
    fn capacity_overflow_drops_the_incoming_tile_and_keeps_residents() {
        // Room for exactly one 64x64 tile (16 KiB) plus change.
        let store = TileStore::with_capacity_ceiling(20_000);
        store.apply(TileMsg::Reset {
            width: 256,
            height: 64,
            edge: TILE_EDGE,
        });
        assert_eq!(store.capacity_bytes(), 20_000);

        let src = bgra_source(256, 64);
        let strip = |x: u32| {
            let (codec, data) = compress_strip(&src, 256 * 4, x, 0, 64, 64, 6).unwrap();
            TileMsg::Strip {
                x,
                y: 0,
                w: 64,
                h: 64,
                codec,
                valid_from_ms: 0,
                lease_ms: 10_000,
                data,
            }
        };

        assert_eq!(store.apply(strip(0)).admitted, 1);
        assert_eq!(store.resident_bytes(), 64 * 64 * 4);

        // Everything after this must be refused — and the resident tile must
        // survive untouched, because a patchwork of fresh and evicted regions
        // looks far worse than simply not refining.
        for x in [64u32, 128, 192] {
            let out = store.apply(strip(x));
            assert_eq!(
                out,
                ApplyOutcome {
                    dropped_capacity: 1,
                    ..Default::default()
                },
                "x={x}"
            );
        }
        assert_eq!(store.resident_tiles(), 1);
        assert_eq!(store.resident_bytes(), 64 * 64 * 4);
        assert_eq!(store.tiles_dropped_capacity(), 3);

        let mut tiles = Vec::new();
        store.snapshot_into(&mut tiles);
        assert_eq!(tiles.len(), 1);
        assert_eq!(tiles[0].x, 0);

        // Re-sending the *same* tile is fine: replacement frees before it adds.
        assert_eq!(store.apply(strip(0)).admitted, 1);
        assert_eq!(store.resident_tiles(), 1);
        assert_eq!(store.resident_bytes(), 64 * 64 * 4);

        // Freeing a resident makes room again.
        store.apply(TileMsg::Revoke { ids: vec![0] });
        assert_eq!(store.resident_bytes(), 0);
        assert_eq!(store.apply(strip(128)).admitted, 1);
        assert_eq!(store.resident_tiles(), 1);
    }

    #[test]
    fn a_multi_tile_strip_admits_what_fits_and_drops_the_rest() {
        // Two 64x64 tiles fit; the third and fourth of the same strip do not.
        let store = TileStore::with_capacity_ceiling(2 * 64 * 64 * 4);
        store.apply(TileMsg::Reset {
            width: 256,
            height: 64,
            edge: TILE_EDGE,
        });
        let src = bgra_source(256, 64);
        let (codec, data) = compress_strip(&src, 256 * 4, 0, 0, 256, 64, 6).unwrap();
        let out = store.apply(TileMsg::Strip {
            x: 0,
            y: 0,
            w: 256,
            h: 64,
            codec,
            valid_from_ms: 0,
            lease_ms: 10_000,
            data,
        });
        assert_eq!(
            out,
            ApplyOutcome {
                admitted: 2,
                dropped_capacity: 2,
                rejected: 0
            }
        );
        assert_eq!(store.resident_tiles(), 2);
    }

    #[test]
    fn messages_before_the_first_reset_are_refused() {
        let store = TileStore::new();
        assert_eq!(
            store
                .apply(TileMsg::Strip {
                    x: 0,
                    y: 0,
                    w: 64,
                    h: 64,
                    codec: TileCodec::Solid,
                    valid_from_ms: 0,
                    lease_ms: 100,
                    data: vec![0, 0, 0],
                })
                .rejected,
            1
        );
        assert_eq!(store.apply(TileMsg::Revoke { ids: vec![0] }).rejected, 1);
        assert_eq!(store.resident_tiles(), 0);
    }

    #[test]
    fn snapshot_reuses_its_buffer_and_yields_ascending_ids() {
        let store = armed_store(256, 128);
        let src = bgra_source(256, 128);
        for y in [64u32, 0] {
            let (codec, data) = compress_strip(&src, 256 * 4, 0, y, 256, 64, 6).unwrap();
            store.apply(TileMsg::Strip {
                x: 0,
                y,
                w: 256,
                h: 64,
                codec,
                valid_from_ms: 0,
                lease_ms: 10_000,
                data,
            });
        }

        let mut tiles = vec![solid_tile(0, 0, 1, 1, [0; 3])];
        let size = store.snapshot_into(&mut tiles).unwrap();
        assert_eq!(size, (256, 128));
        assert_eq!(tiles.len(), 8, "stale contents must be cleared first");
        // BTreeMap order is id order, which is row-major regardless of the
        // order the strips arrived in.
        let coords: Vec<(u32, u32)> = tiles.iter().map(|t| (t.x, t.y)).collect();
        assert_eq!(
            coords,
            vec![
                (0, 0),
                (64, 0),
                (128, 0),
                (192, 0),
                (0, 64),
                (64, 64),
                (128, 64),
                (192, 64)
            ]
        );
    }
}
