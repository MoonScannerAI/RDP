//! The lossless-refinement tile grid: which parts of the desktop have stopped
//! moving, and therefore which parts are worth re-sending pixel-exact.
//!
//! H.264 carries motion; this grid decides where H.264 has finished and a
//! lossless overlay may take over. It is the whole state machine for the
//! feature and it is deliberately **pure** — no Direct3D, no sockets, no async,
//! no Windows types. Everything here runs and is tested on any machine, which
//! matters because this is where the feature's complexity lives.
//!
//! The wire format and the codec are in [`directdesk_shared::tiles`]; this
//! module only decides *what* to send and *when*. `host::session` owns the
//! pixels and the transport and drives this type.
//!
//! # GOVERNING INVARIANT — every ambiguity resolves to revoke
//!
//! Revoking a tile that had not actually changed merely drops the client back
//! to the H.264 image for that square: correct, slightly softer, and
//! self-correcting on the next refinement pass. **Failing** to revoke a tile
//! that *did* change leaves the client compositing pixels that no longer exist
//! on the host — wrong pixels, indefinitely, over live video. Those two
//! outcomes are not comparable, so every branch below that could go either way
//! goes the revoke way:
//!
//! * a dirty-rect query the driver could not answer marks the **entire** grid;
//! * a malformed or inverted rect is normalised into the region it plausibly
//!   describes rather than discarded;
//! * a tile whose strip was planned but whose fate the caller never reported is
//!   revoked, not assumed delivered;
//! * a hash comparison that cannot be made (missing hash, wrong length, tile no
//!   longer resident) answers "different", which forces a re-send;
//! * a revoke list covering more than half the grid collapses into a `Reset`,
//!   which is the maximal revoke.
//!
//! # Clock
//!
//! Every `*_ms` value here is on the **host capture clock**: a `u32` count of
//! milliseconds that wraps roughly every 49.7 days, the same one
//! `capture::GpuFrame::timestamp_ms` carries and the client recovers into
//! `RawFrame::timestamp_ms`. It is *not* wall time and it is *not* monotonic in
//! the `u32` ordering sense. A naive `now - then` underflows across the wrap and
//! produces a ~4-billion-millisecond "elapsed", which would make every tile
//! instantly due and every lease instantly expired. All comparisons therefore go
//! through [`reached`], which is correct across the wrap.
//!
//! # Pass structure
//!
//! One refinement pass, driven from the media thread on an idle frame:
//!
//! ```text
//! grid.mark_frame(dirty, moves, now)      // top of the capture loop, every frame
//! ...
//! let plans = grid.plan_strips(now, settle_ms, budget);
//! for plan in &plans {
//!     let hashes = hash_plan_tiles(bgra, stride, plan)?;   // settled tiles only
//!     let (codec, data) = compress_strip(...)?;
//!     // send TileMsg::Strip
//!     grid.commit_sent(plan, &hashes, now, lease_ms);      // or grid.abandon(plan)
//! }
//! for plan in grid.plan_reverify(now, renew_before_ms, budget) {
//!     let hashes = hash_plan_tiles(bgra, stride, &plan)?;
//!     if grid.strip_matches_sent(&plan, &hashes) {
//!         // send TileMsg::Renew — no pixels
//!         grid.commit_renewed(plan.ids(), now.wrapping_add(lease_ms));
//!     } else {
//!         grid.mark_tiles_dirty(plan.ids(), now);          // driver missed a change
//!     }
//! }
//! if let Some(msg) = grid.take_revocations(now) { /* send — never droppable */ }
//! ```

use directdesk_shared::tiles::{
    tile_cols, tile_id, tile_rows, TileMsg, MAX_STRIP_TILES, TILE_EDGE,
};

/// Bytes per pixel in a host capture buffer (BGRA).
const FRAME_BPP: usize = 4;

/// Maximum tiles in a strip, as a `usize` for array sizing.
const STRIP_CAP: usize = MAX_STRIP_TILES as usize;

// ---------------------------------------------------------------------------
// Wrapping clock
// ---------------------------------------------------------------------------

/// Has the wrapping-`u32` capture clock reached `deadline_ms` by `now_ms`?
///
/// The signed cast is the whole trick: `now - deadline` is computed modulo 2^32
/// and reinterpreted as a signed offset, so "16 ms after the wrap" and "16 ms
/// before the wrap" come out as `+16` and `-16` rather than as `16` and
/// `4294967280`. Correct for any real interval up to 2^31 ms (~24.8 days) in
/// either direction, which is far longer than any settle window or lease this
/// module deals in.
///
/// Every time comparison in this module goes through here. There is deliberately
/// no `elapsed = now - then` helper, because the subtraction is exactly the bug.
#[must_use]
#[inline]
pub fn reached(deadline_ms: u32, now_ms: u32) -> bool {
    (now_ms.wrapping_sub(deadline_ms) as i32) >= 0
}

// ---------------------------------------------------------------------------
// Input geometry
// ---------------------------------------------------------------------------

/// A changed region in capture pixels, in the left/top/right/bottom form DXGI
/// reports.
///
/// Signed, and half-open on the right and bottom, because that is what `RECT`
/// is. Keeping the driver's own shape means `host::session` converts with four
/// field copies and no arithmetic — arithmetic at the boundary is where sign and
/// off-by-one bugs get in. All clipping, clamping and normalising happens here,
/// once, in [`TileGrid::mark_dirty_rect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DirtyRect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

impl DirtyRect {
    /// From DXGI's left/top/right/bottom.
    #[must_use]
    pub const fn ltrb(left: i32, top: i32, right: i32, bottom: i32) -> Self {
        Self {
            left,
            top,
            right,
            bottom,
        }
    }

    /// From an origin and an extent, for callers that think in pixels.
    #[must_use]
    pub fn xywh(x: u32, y: u32, w: u32, h: u32) -> Self {
        let (x, y) = (i64::from(x), i64::from(y));
        Self {
            left: clamp_i32(x),
            top: clamp_i32(y),
            right: clamp_i32(x + i64::from(w)),
            bottom: clamp_i32(y + i64::from(h)),
        }
    }

    /// True when the rect describes no pixels at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.right == self.left || self.bottom == self.top
    }
}

/// A blit the desktop compositor performed on our behalf, as DXGI reports it:
/// a destination rect plus the point the content came from. The source region is
/// the same size as the destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MoveRect {
    pub src_x: i32,
    pub src_y: i32,
    pub dst: DirtyRect,
}

impl MoveRect {
    /// Directly from `DXGI_OUTDUPL_MOVE_RECT`'s `SourcePoint` and
    /// `DestinationRect`.
    #[must_use]
    pub const fn new(src_x: i32, src_y: i32, dst: DirtyRect) -> Self {
        Self { src_x, src_y, dst }
    }

    /// The region the content was copied *out of*.
    #[must_use]
    pub fn source(&self) -> DirtyRect {
        let w = i64::from(self.dst.right) - i64::from(self.dst.left);
        let h = i64::from(self.dst.bottom) - i64::from(self.dst.top);
        DirtyRect {
            left: self.src_x,
            top: self.src_y,
            right: clamp_i32(i64::from(self.src_x) + w),
            bottom: clamp_i32(i64::from(self.src_y) + h),
        }
    }
}

fn clamp_i32(v: i64) -> i32 {
    v.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
}

// ---------------------------------------------------------------------------
// Tiles
// ---------------------------------------------------------------------------

/// Where a tile is in its journey from "moving" to "pixel-exact on the client".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum TileState {
    /// Changed recently (or never sent). The client holds nothing from us for
    /// this square and is showing plain H.264. This is the only safe resting
    /// state, so it is also the default and what every failure path falls back
    /// to.
    #[default]
    Moving,
    /// Settled, planned into a strip, and handed to the caller. Nothing is known
    /// to be on the client yet. Resolved by [`TileGrid::commit_sent`] or
    /// [`TileGrid::abandon`]; a tile still here at the start of the next pass is
    /// assumed to have escaped and is revoked.
    Settling,
    /// A strip carrying this tile went on the wire. The client is believed to be
    /// compositing it until `lease_expires_ms`.
    Refined,
}

/// Per-tile state.
///
/// Deliberately packed into 24 bytes: a 4K grid is 60 x 34 = 2040 tiles, so the
/// whole grid is ~48 KB and stays resident in L2 across a pass. `sent_hash` is
/// a bare `u64` plus a flag rather than an `Option<u64>` for exactly that
/// reason — `u64` has no niche, so the `Option` would cost a full extra word.
#[derive(Debug, Clone, Copy)]
struct Tile {
    /// Hash of the BGR bytes last put on the wire for this tile. Meaningful only
    /// when `has_hash`.
    sent_hash: u64,
    /// Capture-clock stamp of the most recent change. Drives the settle timer.
    changed_ms: u32,
    /// Capture-clock instant the client stops painting this tile by itself.
    /// Meaningful only in [`TileState::Refined`].
    lease_expires_ms: u32,
    state: TileState,
    has_hash: bool,
    /// This tile's id is already in the pending revoke list. Dedupes the list
    /// without a set, and keeps its length bounded by the grid size.
    revoke_pending: bool,
}

impl Tile {
    const fn new(now_ms: u32) -> Self {
        Self {
            sent_hash: 0,
            changed_ms: now_ms,
            lease_expires_ms: now_ms,
            state: TileState::Moving,
            has_hash: false,
            revoke_pending: false,
        }
    }
}

// The memory budget is a design constraint, not an accident: the grid is walked
// end-to-end several times per refinement pass on the media thread, which is the
// same thread that must not miss a capture deadline.
const _: () = assert!(std::mem::size_of::<Tile>() <= 24);
const _: () = assert!(std::mem::size_of::<Tile>() * 1000 <= 28 * 1024);

/// Is this tile ready to be re-sent losslessly?
///
/// The one predicate the whole cadence rests on, kept free-standing and pure so
/// its boundaries can be pinned by test rather than inferred from grid state.
///
/// Only [`TileState::Moving`] is ever due:
/// * [`TileState::Settling`] already has work in flight — planning it twice
///   would put the same pixels on the wire twice;
/// * [`TileState::Refined`] is already exact on the client. Its lease is renewed
///   through [`TileGrid::plan_reverify`], not through this.
///
/// The comparison is `reached(changed_ms + settle_ms, now_ms)`, so `settle_ms`
/// of `0` makes a tile due the instant it is marked, and the boundary is
/// inclusive: due at exactly `changed_ms + settle_ms`. Note that a `now_ms`
/// slightly *behind* `changed_ms` (out-of-order frames) answers "not due", which
/// is the safe direction — a not-due tile is simply showing H.264.
#[must_use]
pub fn tile_due(state: TileState, changed_ms: u32, now_ms: u32, settle_ms: u32) -> bool {
    matches!(state, TileState::Moving) && reached(changed_ms.wrapping_add(settle_ms), now_ms)
}

// ---------------------------------------------------------------------------
// Strips
// ---------------------------------------------------------------------------

/// A horizontal run of up to [`MAX_STRIP_TILES`] tiles in one grid row, ready to
/// be compressed as a single unit.
///
/// `x`/`y`/`w`/`h` are the pixel rect, already clipped to the frame, so the
/// right-hand and bottom strips are narrower/shorter than a full tile and the
/// caller never has to think about it. `w` is always a whole number of tiles
/// wide except where the frame's right edge cuts the last one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StripPlan {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
    /// Grid column of the leftmost tile.
    pub col: u32,
    /// Grid row. A strip never spans rows.
    pub row: u32,
    ids: [u32; STRIP_CAP],
    len: u8,
}

impl StripPlan {
    /// Tile ids, left to right. Same order as the hashes
    /// [`hash_plan_tiles`] produces.
    #[must_use]
    pub fn ids(&self) -> &[u32] {
        &self.ids[..self.len as usize]
    }

    /// How many tiles this strip covers.
    #[must_use]
    pub fn tiles(&self) -> u32 {
        u32::from(self.len)
    }
}

// ---------------------------------------------------------------------------
// Revocation policy
// ---------------------------------------------------------------------------

/// What the caller must put on the wire to retract stale tiles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevokeAction {
    /// Nothing is stale.
    Nothing,
    /// Send `TileMsg::Revoke` with these ids, sorted into raster order.
    Revoke(Vec<u32>),
    /// So much is stale that a `TileMsg::Reset` is both smaller on the wire and
    /// stronger in effect.
    Reset,
}

/// Decide between a revoke list and a wholesale reset.
///
/// A `Reset` is the maximal revoke: it retracts everything and re-arms the
/// client, so collapsing into it is always *safe* — it only ever costs
/// refinement that has to be re-earned. Past half the grid it is also cheaper:
/// several hundred varint ids versus three integers, and it spares the client a
/// large id set to apply. Under half, an id list is worth it because the tiles
/// it does not name keep their refinement.
///
/// The list is sorted and deduplicated **before** the size test, so a caller
/// that names the same tile repeatedly cannot accidentally trigger a full-screen
/// reset. "Exceeds half" is strict: a list covering exactly half stays a revoke.
#[must_use]
pub fn revoke_or_reset(mut ids: Vec<u32>, grid_len: usize) -> RevokeAction {
    ids.sort_unstable();
    ids.dedup();
    if ids.is_empty() {
        return RevokeAction::Nothing;
    }
    // A revoke against a grid we do not have geometry for cannot be expressed;
    // reset instead of guessing.
    if grid_len == 0 || ids.len() * 2 > grid_len {
        return RevokeAction::Reset;
    }
    RevokeAction::Revoke(ids)
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// FNV-1a over one tile's **BGR** bytes out of a full-frame BGRA buffer.
///
/// Returns `None` when the extent does not fit the buffer — a caller that cannot
/// hash must treat the strip as "must send" rather than substitute a value that
/// might collide with a real one.
///
/// Two deliberate choices:
///
/// * **Alpha is skipped.** The wire drops alpha, so two tiles that differ only
///   in alpha compress to identical bytes; hashing alpha would force pointless
///   re-sends of a strip the client already has verbatim.
/// * **The extent is folded in first**, so a 64x56 bottom-edge tile can never
///   collide with the 64x64 tile whose first 56 rows are the same.
///
/// 64 bits, not 32: a collision here shows *wrong pixels* under a renewed lease,
/// and 2^-64 across a few thousand tiles a second is a risk worth zero thought,
/// where 2^-32 is not.
#[must_use]
pub fn hash_tile(bgra: &[u8], stride: usize, x: u32, y: u32, w: u32, h: u32) -> Option<u64> {
    if w == 0 || h == 0 {
        return None;
    }
    let (xs, ys, ws, hs) = (x as usize, y as usize, w as usize, h as usize);
    let row_end = xs.checked_add(ws)?.checked_mul(FRAME_BPP)?;
    if row_end > stride {
        return None;
    }
    let last = ys
        .checked_add(hs - 1)?
        .checked_mul(stride)?
        .checked_add(row_end)?;
    if last > bgra.len() {
        return None;
    }

    let mut hash = FNV_OFFSET;
    for b in w.to_le_bytes().into_iter().chain(h.to_le_bytes()) {
        hash = (hash ^ u64::from(b)).wrapping_mul(FNV_PRIME);
    }
    for row in 0..hs {
        let base = (ys + row) * stride + xs * FRAME_BPP;
        for px in bgra[base..base + ws * FRAME_BPP].chunks_exact(FRAME_BPP) {
            hash = (hash ^ u64::from(px[0])).wrapping_mul(FNV_PRIME);
            hash = (hash ^ u64::from(px[1])).wrapping_mul(FNV_PRIME);
            hash = (hash ^ u64::from(px[2])).wrapping_mul(FNV_PRIME);
        }
    }
    Some(hash)
}

/// Hash every tile in `plan`, left to right, out of a full-frame BGRA buffer.
///
/// This is the *only* place pixels are hashed, and it runs on tiles that have
/// already settled and are about to be compressed anyway — the bytes are in L1
/// from the extraction. There is deliberately no per-frame hashing: hashing a
/// 1080p frame every frame would cost more than the H.264 encode it is meant to
/// assist, and the dirty rects already tell us what moved.
///
/// `None` if any tile's extent does not fit; see [`hash_tile`].
#[must_use]
pub fn hash_plan_tiles(bgra: &[u8], stride: usize, plan: &StripPlan) -> Option<Vec<u64>> {
    let n = plan.ids().len();
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let tx = plan.x + i as u32 * TILE_EDGE;
        // Only the last tile of a grid row can be partial, and a strip is
        // contiguous, so the remaining width of the strip is the bound.
        let tw = TILE_EDGE.min(plan.x + plan.w - tx);
        out.push(hash_tile(bgra, stride, tx, plan.y, tw, plan.h)?);
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// The grid
// ---------------------------------------------------------------------------

/// Aggregate tile counts, for logging and for tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GridStats {
    pub moving: u32,
    pub settling: u32,
    pub refined: u32,
    pub pending_revokes: u32,
}

/// The tile grid over one captured output.
///
/// Tiles are a fixed [`TILE_EDGE`] square. **Edge tiles are partial** — a
/// 1920x1080 grid is 30 columns by 17 rows whose bottom row is 56 pixels tall —
/// and nothing in this module or downstream of it may assume a multiple of 64.
/// The edge is nevertheless carried in `TileMsg::Reset` rather than assumed by
/// the client, so a future host can change it without a protocol bump.
pub struct TileGrid {
    width: u32,
    height: u32,
    cols: u32,
    rows: u32,
    tiles: Vec<Tile>,
    /// Ids awaiting a `Revoke`, deduplicated by `Tile::revoke_pending` and
    /// therefore never longer than the grid.
    pending_revoke: Vec<u32>,
}

impl TileGrid {
    /// Build a grid for a `width` x `height` capture.
    ///
    /// Every tile starts [`TileState::Moving`] stamped at `now_ms`, so the whole
    /// screen becomes due one settle period after the grid is armed rather than
    /// immediately. That matters: the frames right after a connection or a
    /// resolution change are the most motion-heavy of the session, and refining
    /// into them would spend the tile budget on pixels that are about to change.
    #[must_use]
    pub fn new(width: u32, height: u32, now_ms: u32) -> Self {
        let cols = tile_cols(width, TILE_EDGE);
        let rows = tile_rows(height, TILE_EDGE);
        let n = (cols as usize).saturating_mul(rows as usize);
        Self {
            width,
            height,
            cols,
            rows,
            tiles: vec![Tile::new(now_ms); n],
            pending_revoke: Vec::new(),
        }
    }

    #[must_use]
    pub fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    #[must_use]
    pub fn cols(&self) -> u32 {
        self.cols
    }

    #[must_use]
    pub fn rows(&self) -> u32 {
        self.rows
    }

    /// Number of tiles in the grid.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tiles.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tiles.is_empty()
    }

    /// Current state of one tile, for diagnostics. `None` for an unknown id.
    #[must_use]
    pub fn state_of(&self, id: u32) -> Option<TileState> {
        self.tiles.get(id as usize).map(|t| t.state)
    }

    /// The pixel rect one tile covers, already clipped to the frame.
    #[must_use]
    pub fn tile_rect(&self, id: u32) -> Option<(u32, u32, u32, u32)> {
        if self.cols == 0 || id as usize >= self.tiles.len() {
            return None;
        }
        let (col, row) = (id % self.cols, id / self.cols);
        let (x, y) = (col * TILE_EDGE, row * TILE_EDGE);
        Some((
            x,
            y,
            ((col + 1) * TILE_EDGE).min(self.width) - x,
            ((row + 1) * TILE_EDGE).min(self.height) - y,
        ))
    }

    #[must_use]
    pub fn stats(&self) -> GridStats {
        let mut s = GridStats {
            pending_revokes: self.pending_revoke.len() as u32,
            ..GridStats::default()
        };
        for t in &self.tiles {
            match t.state {
                TileState::Moving => s.moving += 1,
                TileState::Settling => s.settling += 1,
                TileState::Refined => s.refined += 1,
            }
        }
        s
    }

    /// The `Reset` describing this grid's current geometry.
    #[must_use]
    pub fn reset_msg(&self) -> TileMsg {
        TileMsg::Reset {
            width: self.width,
            height: self.height,
            edge: TILE_EDGE,
        }
    }

    /// Re-arm from scratch: every tile back to [`TileState::Moving`], every
    /// recorded hash forgotten, every pending revoke superseded.
    ///
    /// Forgetting the hashes is the load-bearing part. `HostSession` outlives a
    /// client connection, so a reconnecting client holds **zero** tiles while the
    /// grid would still say `Refined`; if the hashes survived, the re-send
    /// suppression would fire on every tile and the screen would stay soft
    /// forever. Symptom of getting this wrong: perfect on the first connection,
    /// permanently blurry on every reconnect. Call this on stream open, on
    /// reconnect, on resolution change, and on secure-desktop resume.
    #[must_use = "the client is only re-armed when this Reset is actually sent"]
    pub fn reset(&mut self, now_ms: u32) -> TileMsg {
        for t in &mut self.tiles {
            *t = Tile::new(now_ms);
        }
        self.pending_revoke.clear();
        self.reset_msg()
    }

    /// Rebuild the grid for a new capture size.
    ///
    /// `Some(Reset)` when the geometry actually changed — tile ids are derived
    /// from the grid width on both sides, so a stale id from the old resolution
    /// would alias a live one, and the client must be re-armed before any strip
    /// for the new geometry arrives. `None` when the dimensions are unchanged,
    /// which keeps this safe to call unconditionally every frame.
    #[must_use = "a resize is only safe once the client has been re-armed"]
    pub fn resize(&mut self, width: u32, height: u32, now_ms: u32) -> Option<TileMsg> {
        if width == self.width && height == self.height {
            return None;
        }
        *self = Self::new(width, height, now_ms);
        Some(self.reset_msg())
    }

    // -- marking ------------------------------------------------------------

    /// Fold one captured frame's change report into the grid.
    ///
    /// `None` for either list means **the driver could not tell us** — not "no
    /// changes". That distinction is the single most important input to this
    /// module: treating an unanswerable query as a static screen would refine
    /// stale pixels, which is the worst bug the feature can have. Either query
    /// failing therefore marks the entire grid. `Some(&[])` genuinely means
    /// nothing changed and is a no-op.
    ///
    /// Returns the number of tile marks applied (tiles may be counted twice if
    /// several rects overlap); useful for logging, not a tile count.
    pub fn mark_frame(
        &mut self,
        dirty: Option<&[DirtyRect]>,
        moves: Option<&[MoveRect]>,
        now_ms: u32,
    ) -> u32 {
        let (Some(dirty), Some(moves)) = (dirty, moves) else {
            return self.mark_all_dirty(now_ms);
        };
        let mut n = 0;
        for m in moves {
            n += self.mark_move_rect(*m, now_ms);
        }
        for d in dirty {
            n += self.mark_dirty_rect(*d, now_ms);
        }
        n
    }

    /// Mark every tile changed. The safety path for an unanswerable dirty-rect
    /// query, a duplication rebuild, or a secure-desktop resume.
    pub fn mark_all_dirty(&mut self, now_ms: u32) -> u32 {
        for idx in 0..self.tiles.len() {
            self.touch(idx, now_ms);
        }
        self.tiles.len() as u32
    }

    /// Map a pixel rect to the tiles it overlaps and drive them to
    /// [`TileState::Moving`].
    ///
    /// Every degenerate input is handled here so no caller has to: coordinates
    /// are clipped to the grid, negative origins clamp to zero, a rect larger
    /// than the frame marks the whole frame, a zero-area rect marks nothing, and
    /// an inverted rect (`right < left`) is normalised into the region it
    /// plausibly describes rather than dropped — dropping it would be the one
    /// choice that risks stale pixels.
    ///
    /// Partial overlap counts: a rect touching a single pixel of a tile marks the
    /// whole tile, because a tile is the smallest thing that can be revoked.
    pub fn mark_dirty_rect(&mut self, rect: DirtyRect, now_ms: u32) -> u32 {
        let Some((c0, c1, r0, r1)) = self.clip_to_tiles(rect) else {
            return 0;
        };
        let mut n = 0;
        for row in r0..=r1 {
            for col in c0..=c1 {
                let idx = (row * self.cols + col) as usize;
                self.touch(idx, now_ms);
                n += 1;
            }
        }
        n
    }

    /// Mark **both** ends of a compositor blit.
    ///
    /// The destination obviously changed. The source is marked too because the
    /// desktop only guarantees the destination: whatever was revealed behind the
    /// moved content is supposed to arrive as an ordinary dirty rect, and betting
    /// the picture on every driver getting that right is exactly the bet this
    /// module refuses to make. Marking the source costs one extra strip on a
    /// window drag and removes a whole class of "ghost of the old window"
    /// artifact.
    pub fn mark_move_rect(&mut self, mv: MoveRect, now_ms: u32) -> u32 {
        self.mark_dirty_rect(mv.dst, now_ms) + self.mark_dirty_rect(mv.source(), now_ms)
    }

    /// Drive specific tiles back to [`TileState::Moving`], revoking any the
    /// client is still painting.
    ///
    /// Used when a re-verification finds pixels that changed without the driver
    /// reporting them — the case leases exist to bound.
    pub fn mark_tiles_dirty(&mut self, ids: &[u32], now_ms: u32) {
        for &id in ids {
            if (id as usize) < self.tiles.len() {
                self.touch(id as usize, now_ms);
            }
        }
    }

    // -- planning -----------------------------------------------------------

    /// Housekeeping run at the start of every refinement pass. Idempotent.
    ///
    /// Two sweeps, both of which resolve an ambiguity toward revoke:
    ///
    /// * a tile still [`TileState::Settling`] was planned in an earlier pass and
    ///   the caller never reported its fate. We cannot know whether its strip
    ///   reached the wire, so we assume it did and revoke it;
    /// * a [`TileState::Refined`] tile whose lease has run out is no longer being
    ///   painted by the client — the client drops it on its own — so it goes back
    ///   to `Moving` for a fresh send. No revoke: there is nothing to retract.
    ///
    /// [`Self::plan_strips`] calls this itself, so a caller that only ever plans
    /// strips need not think about it.
    pub fn begin_pass(&mut self, now_ms: u32) {
        let mut abandoned: Vec<u32> = Vec::new();
        for (i, t) in self.tiles.iter_mut().enumerate() {
            match t.state {
                TileState::Settling => {
                    t.state = TileState::Moving;
                    abandoned.push(i as u32);
                }
                TileState::Refined if reached(t.lease_expires_ms, now_ms) => {
                    t.state = TileState::Moving;
                    // Date the change at the expiry rather than at `now`, so the
                    // tile is due one settle period after it went stale instead
                    // of one settle period after we happened to notice.
                    t.changed_ms = t.lease_expires_ms;
                }
                _ => {}
            }
        }
        for id in abandoned {
            self.queue_revoke(id as usize);
        }
    }

    /// Coalesce due tiles into horizontal strips, in raster order.
    ///
    /// A strip **never crosses a tile row** and never exceeds
    /// [`MAX_STRIP_TILES`], both of which the codec depends on: `compress_strip`
    /// rejects anything wider than `MAX_STRIP_W` or taller than `TILE_EDGE`, and
    /// the worst-case encoded size that keeps a strip inside one control message
    /// is derived from exactly those bounds.
    ///
    /// Raster order is a *visual* requirement, not an implementation detail. A
    /// refinement that sweeps top-to-bottom reads as the picture deliberately
    /// sharpening; the same tiles delivered in scattered order read as
    /// compression artifacts appearing at random. `max_strips` bounds the work
    /// (and the bandwidth) of one pass; the remainder is picked up next pass,
    /// still in raster order, because the sweep restarts from the top.
    ///
    /// The returned tiles are claimed into [`TileState::Settling`]. The caller
    /// **must** resolve each plan with [`Self::commit_sent`] or
    /// [`Self::abandon`]; anything left unresolved is revoked at the start of the
    /// next pass.
    #[must_use = "planned tiles are claimed and must be sent or abandoned"]
    pub fn plan_strips(
        &mut self,
        now_ms: u32,
        settle_ms: u32,
        max_strips: usize,
    ) -> Vec<StripPlan> {
        self.begin_pass(now_ms);
        let this: &Self = self;
        let plans = this.build_strips(max_strips, |g, col, row| {
            let t = &g.tiles[(row * g.cols + col) as usize];
            tile_due(t.state, t.changed_ms, now_ms, settle_ms)
        });
        for plan in &plans {
            for &id in plan.ids() {
                if let Some(t) = self.tiles.get_mut(id as usize) {
                    t.state = TileState::Settling;
                }
            }
        }
        plans
    }

    /// Strips of [`TileState::Refined`] tiles whose lease is within
    /// `renew_before_ms` of expiring.
    ///
    /// The caller re-hashes these and, if [`Self::strip_matches_sent`] agrees,
    /// extends the lease with a `TileMsg::Renew` — ids only, no pixels. That is
    /// what keeps a long-static screen from re-sending the entire desktop
    /// losslessly once per lease period.
    ///
    /// Why re-hash instead of renewing blindly: a blind renew extends the life of
    /// pixels nobody re-checked, *forever*. One dirty rect the driver failed to
    /// report would then become permanently wrong pixels, which is precisely the
    /// outcome the governing invariant exists to prevent. Verifying bounds that
    /// failure to a single renew interval. Unlike [`Self::plan_strips`] this does
    /// not claim the tiles — they stay `Refined`, and the client keeps painting
    /// them, until the caller says otherwise.
    #[must_use]
    pub fn plan_reverify(
        &self,
        now_ms: u32,
        renew_before_ms: u32,
        max_strips: usize,
    ) -> Vec<StripPlan> {
        self.build_strips(max_strips, |g, col, row| {
            let t = &g.tiles[(row * g.cols + col) as usize];
            t.state == TileState::Refined
                && reached(t.lease_expires_ms.wrapping_sub(renew_before_ms), now_ms)
        })
    }

    /// Do these freshly computed hashes match what was last transmitted for
    /// every tile in `plan`?
    ///
    /// `false` — meaning "send the pixels" — whenever the question cannot be
    /// answered: a length mismatch, an empty plan, a tile with no recorded hash,
    /// or a tile the client is no longer painting. In particular a tile that was
    /// revoked is not `Refined`, so a hash match on it can never suppress the
    /// re-send it needs.
    #[must_use]
    pub fn strip_matches_sent(&self, plan: &StripPlan, hashes: &[u64]) -> bool {
        if hashes.is_empty() || hashes.len() != plan.ids().len() {
            return false;
        }
        plan.ids().iter().zip(hashes).all(|(&id, &h)| {
            self.tiles
                .get(id as usize)
                .is_some_and(|t| t.state == TileState::Refined && t.has_hash && t.sent_hash == h)
        })
    }

    // -- committing ---------------------------------------------------------

    /// Record that a strip's pixels went on the wire.
    ///
    /// Only tiles still [`TileState::Settling`] are promoted: a tile that was
    /// re-marked dirty between planning and sending describes pixels that are
    /// already stale, and calling it `Refined` would suppress the very re-send it
    /// needs. Such a tile stays `Moving` (and already carries a queued revoke).
    ///
    /// A `hashes` length that does not match the plan is ignored entirely,
    /// leaving the tiles `Settling` so the next pass revokes them.
    pub fn commit_sent(&mut self, plan: &StripPlan, hashes: &[u64], now_ms: u32, lease_ms: u32) {
        if hashes.len() != plan.ids().len() {
            return;
        }
        let expires = now_ms.wrapping_add(lease_ms);
        for (&id, &h) in plan.ids().iter().zip(hashes) {
            let Some(t) = self.tiles.get_mut(id as usize) else {
                continue;
            };
            if t.state != TileState::Settling {
                continue;
            }
            t.state = TileState::Refined;
            t.sent_hash = h;
            t.has_hash = true;
            t.lease_expires_ms = expires;
        }
    }

    /// The caller decided not to send this strip — nothing reached the wire.
    ///
    /// No revoke, because the client was never told anything. This is the
    /// throttle's path, and it must stay cheap: a budget-limited pass abandons
    /// most of what it planned.
    pub fn abandon(&mut self, plan: &StripPlan) {
        for &id in plan.ids() {
            if let Some(t) = self.tiles.get_mut(id as usize) {
                if t.state == TileState::Settling {
                    t.state = TileState::Moving;
                }
            }
        }
    }

    /// Record a `TileMsg::Renew` for tiles verified still exact.
    ///
    /// Mirrors the client exactly rather than clamping: `valid_through_ms` is the
    /// absolute capture-clock instant sent on the wire, and both sides holding
    /// the same number is what makes the lease reasoning simple.
    pub fn commit_renewed(&mut self, ids: &[u32], valid_through_ms: u32) {
        for &id in ids {
            if let Some(t) = self.tiles.get_mut(id as usize) {
                if t.state == TileState::Refined {
                    t.lease_expires_ms = valid_through_ms;
                }
            }
        }
    }

    /// Take everything the client must stop painting.
    ///
    /// Collapses to a `Reset` past half the grid — see [`revoke_or_reset`] — and
    /// in that case re-arms this grid to match, so host and client agree that
    /// nothing is resident.
    ///
    /// The returned message is **not droppable**. `Strip`s may be dropped by the
    /// throttle before they are queued; a dropped `Revoke` is stale pixels on
    /// screen until the lease runs out, which is the one failure this design
    /// works hardest to avoid.
    #[must_use = "a dropped revoke leaves stale pixels on the client until the lease expires"]
    pub fn take_revocations(&mut self, now_ms: u32) -> Option<TileMsg> {
        let ids = std::mem::take(&mut self.pending_revoke);
        for &id in &ids {
            if let Some(t) = self.tiles.get_mut(id as usize) {
                t.revoke_pending = false;
            }
        }
        match revoke_or_reset(ids, self.tiles.len()) {
            RevokeAction::Nothing => None,
            RevokeAction::Revoke(ids) => Some(TileMsg::Revoke { ids }),
            RevokeAction::Reset => Some(self.reset(now_ms)),
        }
    }

    // -- internals ----------------------------------------------------------

    /// Drive one tile to `Moving`, revoking it if the client might be painting
    /// it.
    ///
    /// `Settling` counts as "might be painting": the caller may already have put
    /// that strip on the wire and simply not reported back yet. Revoking a tile
    /// the client never received is free — it ignores unknown ids — so the
    /// asymmetry is entirely in our favour.
    fn touch(&mut self, idx: usize, now_ms: u32) {
        let live = {
            let t = &mut self.tiles[idx];
            let live = matches!(t.state, TileState::Refined | TileState::Settling);
            t.state = TileState::Moving;
            t.changed_ms = now_ms;
            live
        };
        if live {
            self.queue_revoke(idx);
        }
    }

    fn queue_revoke(&mut self, idx: usize) {
        let t = &mut self.tiles[idx];
        if t.revoke_pending {
            return;
        }
        t.revoke_pending = true;
        self.pending_revoke.push(idx as u32);
    }

    /// Clip a rect to the grid and return the inclusive tile range it covers.
    fn clip_to_tiles(&self, rect: DirtyRect) -> Option<(u32, u32, u32, u32)> {
        if self.cols == 0 || self.rows == 0 {
            return None;
        }
        // Normalise before clipping: an inverted rect still names a region.
        let (l, r) = if rect.right < rect.left {
            (rect.right, rect.left)
        } else {
            (rect.left, rect.right)
        };
        let (t, b) = if rect.bottom < rect.top {
            (rect.bottom, rect.top)
        } else {
            (rect.top, rect.bottom)
        };
        // i64 throughout: an i32::MAX right edge must clamp, not overflow.
        let l = i64::from(l).max(0);
        let t = i64::from(t).max(0);
        let r = i64::from(r).min(i64::from(self.width));
        let b = i64::from(b).min(i64::from(self.height));
        if r <= l || b <= t {
            return None;
        }
        let e = i64::from(TILE_EDGE);
        Some((
            (l / e) as u32,
            ((r - 1) / e) as u32,
            (t / e) as u32,
            ((b - 1) / e) as u32,
        ))
    }

    /// Walk the grid in raster order, coalescing runs of tiles `pick` accepts
    /// into strips. Shared by [`Self::plan_strips`] and [`Self::plan_reverify`]
    /// so the row and width bounds cannot drift apart between them.
    fn build_strips(
        &self,
        max_strips: usize,
        pick: impl Fn(&Self, u32, u32) -> bool,
    ) -> Vec<StripPlan> {
        let mut out: Vec<StripPlan> = Vec::new();
        if max_strips == 0 {
            return out;
        }
        'rows: for row in 0..self.rows {
            let mut col = 0u32;
            while col < self.cols {
                if !pick(self, col, row) {
                    col += 1;
                    continue;
                }
                let start = col;
                let mut n = 0u32;
                // Three independent stops, and all three matter: the row's end
                // (a strip never spans rows), the codec's tile cap, and the first
                // tile that is not a candidate.
                while col < self.cols && n < MAX_STRIP_TILES && pick(self, col, row) {
                    col += 1;
                    n += 1;
                }
                out.push(self.make_plan(start, row, n));
                if out.len() >= max_strips {
                    break 'rows;
                }
            }
        }
        out
    }

    fn make_plan(&self, col: u32, row: u32, n: u32) -> StripPlan {
        let x = col * TILE_EDGE;
        let y = row * TILE_EDGE;
        let x_end = col
            .saturating_add(n)
            .saturating_mul(TILE_EDGE)
            .min(self.width);
        let y_end = row
            .saturating_add(1)
            .saturating_mul(TILE_EDGE)
            .min(self.height);
        let mut ids = [0u32; STRIP_CAP];
        for (i, slot) in ids.iter_mut().enumerate().take(n as usize) {
            *slot = tile_id(col + i as u32, row, self.cols);
        }
        StripPlan {
            x,
            y,
            w: x_end - x,
            h: y_end - y,
            col,
            row,
            ids,
            len: n as u8,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use directdesk_shared::tiles::MAX_STRIP_W;

    const SETTLE: u32 = 900;
    const LEASE: u32 = 4_000;

    /// A 1920x1080 grid: 30 x 17 tiles, bottom row 56 px tall. The canonical
    /// shape, and the one that proves nothing assumes a multiple of 64.
    fn grid_1080p(now: u32) -> TileGrid {
        TileGrid::new(1920, 1080, now)
    }

    /// A grid whose initial whole-screen refinement has already been delivered.
    ///
    /// A fresh grid arms *every* tile, because the client starts holding nothing
    /// — correct in production, but it means a test that marks one rect would see
    /// the entire screen come due. Draining that first pass first is what lets a
    /// test observe the tiles it actually marked. The lease is set far beyond any
    /// time these tests use, so nothing expires underneath them.
    fn settled_grid(w: u32, h: u32) -> TileGrid {
        let mut g = TileGrid::new(w, h, 0);
        let plans = g.plan_strips(0, 0, usize::MAX);
        for p in &plans {
            g.commit_sent(p, &vec![0u64; p.ids().len()], 0, u32::MAX / 4);
        }
        assert_eq!(g.stats().moving, 0, "the whole screen should be refined");
        g
    }

    /// A frame buffer whose pixels are a deterministic function of position.
    fn frame(w: u32, h: u32, salt: u8) -> (Vec<u8>, usize) {
        let stride = (w * 4) as usize;
        let mut buf = vec![0u8; stride * h as usize];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = ((i / 4 + i % 251) as u8) ^ salt;
        }
        (buf, stride)
    }

    // -- geometry -----------------------------------------------------------

    #[test]
    fn grid_covers_partial_edge_tiles() {
        let g = grid_1080p(0);
        assert_eq!((g.cols(), g.rows()), (30, 17));
        assert_eq!(g.len(), 510);
        // Interior tile is a full square.
        assert_eq!(g.tile_rect(0), Some((0, 0, 64, 64)));
        // Bottom-left tile: row 16 starts at y=1024, so it is 56 px tall.
        assert_eq!(g.tile_rect(16 * 30), Some((0, 1024, 64, 56)));
        // Bottom-right corner tile: 1920 is an exact multiple of 64, so only the
        // height is partial.
        assert_eq!(g.tile_rect(509), Some((1856, 1024, 64, 56)));
        assert_eq!(g.tile_rect(510), None);
    }

    #[test]
    fn grid_handles_non_multiple_width() {
        // 1366x768: 22 columns whose last is 22 px wide, 12 rows exactly.
        let g = TileGrid::new(1366, 768, 0);
        assert_eq!((g.cols(), g.rows()), (22, 12));
        assert_eq!(g.tile_rect(21), Some((1344, 0, 22, 64)));
        assert_eq!(g.tile_rect(11 * 22), Some((0, 704, 64, 64)));
    }

    #[test]
    fn zero_sized_grid_is_inert() {
        let mut g = TileGrid::new(0, 0, 0);
        assert!(g.is_empty());
        assert_eq!(g.mark_dirty_rect(DirtyRect::xywh(0, 0, 100, 100), 0), 0);
        assert_eq!(g.mark_all_dirty(0), 0);
        assert!(g.plan_strips(10_000, SETTLE, 32).is_empty());
        assert!(g.take_revocations(0).is_none());
    }

    // -- tile_due boundaries ------------------------------------------------

    #[test]
    fn tile_due_boundary_is_inclusive_and_exact() {
        // One millisecond short: not due. Exactly at the deadline: due.
        assert!(!tile_due(
            TileState::Moving,
            1_000,
            1_000 + SETTLE - 1,
            SETTLE
        ));
        assert!(tile_due(TileState::Moving, 1_000, 1_000 + SETTLE, SETTLE));
        assert!(tile_due(
            TileState::Moving,
            1_000,
            1_000 + SETTLE + 1,
            SETTLE
        ));
        // A zero settle makes a tile due the instant it is marked.
        assert!(tile_due(TileState::Moving, 1_000, 1_000, 0));
        // A clock that went backwards answers "not due" — the safe direction.
        assert!(!tile_due(TileState::Moving, 1_000, 999, 0));
    }

    #[test]
    fn tile_due_only_ever_fires_on_moving() {
        for state in [TileState::Settling, TileState::Refined] {
            assert!(
                !tile_due(state, 0, 10_000_000, SETTLE),
                "{state:?} must never be due: work is in flight or already exact"
            );
        }
    }

    #[test]
    fn reached_is_correct_across_u32_max() {
        // Deadline 10 ms before the wrap, now 6 ms after it: 16 ms elapsed.
        let deadline = u32::MAX - 10;
        assert!(reached(deadline, 5));
        assert!(reached(deadline, deadline));
        assert!(!reached(deadline, deadline - 1));
        // The naive comparison would say `5 < deadline` and stall forever.
        assert!(5 < deadline);
    }

    #[test]
    fn tile_due_crosses_u32_max() {
        // Changed 100 ms before the counter wraps; the settle deadline lands on
        // the far side of the wrap.
        let changed = u32::MAX - 100;
        let due_at = changed.wrapping_add(SETTLE); // = 799
        assert!(due_at < changed, "the deadline must have wrapped");
        assert!(!tile_due(
            TileState::Moving,
            changed,
            due_at.wrapping_sub(1),
            SETTLE
        ));
        assert!(tile_due(TileState::Moving, changed, due_at, SETTLE));
        assert!(tile_due(
            TileState::Moving,
            changed,
            due_at.wrapping_add(50),
            SETTLE
        ));
        // And the whole cycle works on a live grid across the wrap.
        let mut g = TileGrid::new(256, 128, changed);
        assert!(g
            .plan_strips(changed.wrapping_add(SETTLE - 1), SETTLE, 32)
            .is_empty());
        assert!(!g.plan_strips(due_at, SETTLE, 32).is_empty());
    }

    #[test]
    fn leases_expire_across_u32_max() {
        let start = u32::MAX - 500;
        let mut g = TileGrid::new(128, 64, start);
        let now = start.wrapping_add(SETTLE);
        let plans = g.plan_strips(now, SETTLE, 32);
        for p in &plans {
            g.commit_sent(p, &vec![7u64; p.ids().len()], now, LEASE);
        }
        assert_eq!(g.stats().refined, 2);
        // Just before expiry, still refined; just after, back to moving.
        let expiry = now.wrapping_add(LEASE);
        g.begin_pass(expiry.wrapping_sub(1));
        assert_eq!(g.stats().refined, 2);
        g.begin_pass(expiry);
        assert_eq!(g.stats().moving, 2);
        // Expiry is silent on the wire: the client drops the tile itself.
        assert!(g.take_revocations(expiry).is_none());
    }

    // -- mark_dirty_rect ----------------------------------------------------

    #[test]
    fn dirty_rect_partially_overlapping_marks_whole_tiles() {
        let mut g = grid_1080p(0);
        // A single pixel at (65, 1) sits in column 1, row 0.
        assert_eq!(g.mark_dirty_rect(DirtyRect::xywh(65, 1, 1, 1), 10), 1);
        // A rect straddling the 64-px boundary marks both columns.
        let mut g = grid_1080p(0);
        assert_eq!(g.mark_dirty_rect(DirtyRect::ltrb(63, 0, 65, 1), 10), 2);
        // 2x2 tiles when it straddles both axes.
        let mut g = grid_1080p(0);
        assert_eq!(g.mark_dirty_rect(DirtyRect::ltrb(63, 63, 65, 65), 10), 4);
    }

    #[test]
    fn dirty_rect_edges_map_exactly() {
        let mut g = grid_1080p(0);
        // Exactly one tile: [0,64) x [0,64).
        assert_eq!(g.mark_dirty_rect(DirtyRect::ltrb(0, 0, 64, 64), 10), 1);
        // One pixel further right spills into the next column.
        let mut g = grid_1080p(0);
        assert_eq!(g.mark_dirty_rect(DirtyRect::ltrb(0, 0, 65, 64), 10), 2);
    }

    #[test]
    fn dirty_rect_zero_area_marks_nothing() {
        let mut g = grid_1080p(0);
        assert_eq!(
            g.mark_dirty_rect(DirtyRect::ltrb(100, 100, 100, 200), 10),
            0
        );
        assert_eq!(
            g.mark_dirty_rect(DirtyRect::ltrb(100, 100, 200, 100), 10),
            0
        );
        assert_eq!(g.mark_dirty_rect(DirtyRect::xywh(0, 0, 0, 0), 10), 0);
        assert_eq!(g.stats().moving, 510); // untouched, still at their epoch
                                           // A zero-area rect against an already-refined grid changes nothing.
        let mut g = settled_grid(256, 64);
        assert_eq!(g.mark_dirty_rect(DirtyRect::ltrb(64, 0, 64, 64), 5_000), 0);
        assert_eq!(g.stats().refined, 4);
        assert!(g.take_revocations(5_000).is_none());
    }

    #[test]
    fn dirty_rect_is_clipped_to_the_grid() {
        // Larger than the frame in every direction: marks everything, no panic.
        let mut g = grid_1080p(0);
        assert_eq!(
            g.mark_dirty_rect(DirtyRect::ltrb(-5_000, -5_000, 5_000, 5_000), 10),
            510
        );
        // Entirely off the right/bottom: marks nothing.
        let mut g = grid_1080p(0);
        assert_eq!(
            g.mark_dirty_rect(DirtyRect::ltrb(1_920, 0, 2_000, 10), 10),
            0
        );
        assert_eq!(
            g.mark_dirty_rect(DirtyRect::ltrb(0, 1_080, 10, 2_000), 10),
            0
        );
        // Entirely off the left/top: marks nothing.
        assert_eq!(
            g.mark_dirty_rect(DirtyRect::ltrb(-100, -100, -1, -1), 10),
            0
        );
        // Straddling the origin: clamps and marks the one tile it reaches.
        assert_eq!(g.mark_dirty_rect(DirtyRect::ltrb(-100, -100, 1, 1), 10), 1);
    }

    #[test]
    fn dirty_rect_extremes_do_not_overflow() {
        let mut g = grid_1080p(0);
        assert_eq!(
            g.mark_dirty_rect(DirtyRect::ltrb(i32::MIN, i32::MIN, i32::MAX, i32::MAX), 10),
            510
        );
    }

    #[test]
    fn inverted_dirty_rect_is_normalised_not_dropped() {
        // Dropping it would risk stale pixels; normalising marks the region it
        // plausibly describes.
        let mut g = grid_1080p(0);
        assert_eq!(g.mark_dirty_rect(DirtyRect::ltrb(65, 65, 63, 63), 10), 4);
    }

    #[test]
    fn dirty_rect_revokes_only_tiles_the_client_holds() {
        // One row of 10 refined tiles.
        let mut g = settled_grid(640, 64);
        assert_eq!(g.stats().refined, 10);
        assert!(g.take_revocations(0).is_none(), "nothing stale yet");

        // Dirtying three of them revokes exactly those three.
        g.mark_dirty_rect(DirtyRect::ltrb(60, 0, 130, 10), 5_000);
        let msg = g.take_revocations(5_000).expect("stale tiles");
        assert_eq!(msg, TileMsg::Revoke { ids: vec![0, 1, 2] });
        // Draining twice does not repeat them.
        assert!(g.take_revocations(5_000).is_none());
    }

    // -- move rects ---------------------------------------------------------

    #[test]
    fn move_rect_marks_source_and_destination() {
        let mut g = settled_grid(1920, 1080);
        // Move a 64x64 block from (0,0) to (640,640) — two distinct tiles.
        let mv = MoveRect::new(0, 0, DirtyRect::ltrb(640, 640, 704, 704));
        assert_eq!(g.mark_move_rect(mv, 5_000), 2);
        let now = 5_000 + SETTLE;
        let plans = g.plan_strips(now, SETTLE, 32);
        let ids: Vec<u32> = plans.iter().flat_map(|p| p.ids().to_vec()).collect();
        assert_eq!(ids, vec![tile_id(0, 0, 30), tile_id(10, 10, 30)]);
    }

    #[test]
    fn move_rect_source_derives_extent_from_destination() {
        let mv = MoveRect::new(100, 200, DirtyRect::ltrb(300, 400, 364, 432));
        assert_eq!(mv.source(), DirtyRect::ltrb(100, 200, 164, 232));
    }

    #[test]
    fn move_rect_off_screen_source_is_clipped_not_panicking() {
        let mut g = TileGrid::new(256, 128, 0);
        let mv = MoveRect::new(-200, -200, DirtyRect::ltrb(0, 0, 64, 64));
        // Destination only; the source is entirely off-screen.
        assert_eq!(g.mark_move_rect(mv, 10), 1);
    }

    // -- the "cannot tell" safety path -------------------------------------

    #[test]
    fn unanswerable_dirty_query_marks_the_entire_grid() {
        // This is the critical safety path: `None` means the driver could not
        // tell us what changed, which is emphatically not "nothing changed".
        let mut g = grid_1080p(0);
        assert_eq!(g.mark_frame(None, Some(&[]), 10), 510);
        let mut g = grid_1080p(0);
        assert_eq!(g.mark_frame(Some(&[]), None, 10), 510);
        let mut g = grid_1080p(0);
        assert_eq!(g.mark_frame(None, None, 10), 510);
    }

    #[test]
    fn empty_dirty_list_means_nothing_changed() {
        let mut g = grid_1080p(0);
        assert_eq!(g.mark_frame(Some(&[]), Some(&[]), 10), 0);
    }

    #[test]
    fn mark_all_dirty_revokes_everything_via_reset() {
        let mut g = TileGrid::new(256, 64, 0);
        let now = SETTLE;
        let plans = g.plan_strips(now, SETTLE, 32);
        g.commit_sent(&plans[0], &[1, 2, 3, 4], now, LEASE);
        g.mark_all_dirty(now + 1);
        // 4 of 4 tiles stale: past half the grid, so one Reset, not a list.
        assert_eq!(
            g.take_revocations(now + 1),
            Some(TileMsg::Reset {
                width: 256,
                height: 64,
                edge: TILE_EDGE
            })
        );
        // And the host's own view is re-armed to match.
        assert_eq!(g.stats().refined, 0);
        assert_eq!(g.stats().moving, 4);
    }

    // -- plan_strips --------------------------------------------------------

    #[test]
    fn strips_never_cross_a_row_or_exceed_the_tile_cap() {
        let mut g = grid_1080p(0);
        g.mark_all_dirty(0);
        let plans = g.plan_strips(SETTLE, SETTLE, usize::MAX);
        assert!(!plans.is_empty());
        for p in &plans {
            assert!(p.tiles() <= MAX_STRIP_TILES, "strip of {} tiles", p.tiles());
            assert!(p.w <= MAX_STRIP_W, "strip {} px wide", p.w);
            assert!(p.h <= TILE_EDGE);
            // Every id in the strip is in the same grid row.
            for &id in p.ids() {
                assert_eq!(id / g.cols(), p.row, "strip {p:?} crosses a row");
            }
            // The pixel rect never leaves the frame.
            assert!(p.x + p.w <= 1920 && p.y + p.h <= 1080);
        }
        // 30 columns per row = 7 full strips of 4 + one of 2, times 17 rows.
        assert_eq!(plans.len(), 8 * 17);
        assert_eq!(g.stats().settling, 510);
    }

    #[test]
    fn strips_are_emitted_in_raster_order() {
        let mut g = grid_1080p(0);
        g.mark_all_dirty(0);
        let plans = g.plan_strips(SETTLE, SETTLE, usize::MAX);
        let mut prev = (0u32, 0u32);
        for p in &plans {
            assert!(
                (p.row, p.col) >= prev,
                "strip at {:?} came after {:?} — a sweep must read top-to-bottom",
                (p.row, p.col),
                prev
            );
            prev = (p.row, p.col);
        }
    }

    #[test]
    fn strips_cover_partial_edge_tiles_exactly() {
        let mut g = grid_1080p(0);
        g.mark_all_dirty(0);
        let plans = g.plan_strips(SETTLE, SETTLE, usize::MAX);
        // Bottom row is 56 px tall, and the last strip of each row is 2 tiles.
        let bottom: Vec<&StripPlan> = plans.iter().filter(|p| p.row == 16).collect();
        assert_eq!(bottom.len(), 8);
        assert!(bottom.iter().all(|p| p.h == 56 && p.y == 1024));
        assert_eq!(bottom.last().unwrap().w, 128);
        assert_eq!(bottom.last().unwrap().x, 1792);
    }

    #[test]
    fn strips_break_at_gaps() {
        let mut g = settled_grid(640, 64); // one row of 10 tiles
                                           // Dirty columns 0,1 and 4,5,6,7,8 — leaving a gap at 2,3 and 9.
        g.mark_dirty_rect(DirtyRect::ltrb(0, 0, 128, 64), 5_000);
        g.mark_dirty_rect(DirtyRect::ltrb(256, 0, 576, 64), 5_000);
        let plans = g.plan_strips(5_000 + SETTLE, SETTLE, usize::MAX);
        let shape: Vec<(u32, u32)> = plans.iter().map(|p| (p.col, p.tiles())).collect();
        // The gap breaks the run; the second run is split by the 4-tile cap.
        assert_eq!(shape, vec![(0, 2), (4, 4), (8, 1)]);
    }

    #[test]
    fn strips_only_pick_settled_tiles() {
        let mut g = settled_grid(256, 64);
        g.mark_dirty_rect(DirtyRect::ltrb(0, 0, 64, 64), 1_000);
        g.mark_dirty_rect(DirtyRect::ltrb(64, 0, 128, 64), 1_200);
        // At 1000+SETTLE only the first tile has settled.
        let plans = g.plan_strips(1_000 + SETTLE, SETTLE, usize::MAX);
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].ids(), &[0]);
        g.abandon(&plans[0]);
        // By 1200+SETTLE both have, and they coalesce.
        let plans = g.plan_strips(1_200 + SETTLE, SETTLE, usize::MAX);
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].ids(), &[0, 1]);
    }

    #[test]
    fn max_strips_bounds_the_pass_and_the_rest_follows_next_pass() {
        let mut g = grid_1080p(0);
        g.mark_all_dirty(0);
        let first = g.plan_strips(SETTLE, SETTLE, 32);
        assert_eq!(first.len(), 32);
        // A 30-column row is 8 strips (seven of 4, one of 2), so a 32-strip
        // budget is exactly four rows — 120 tiles, not 32 x 4.
        assert_eq!(g.stats().settling, 120);
        assert_eq!(first.last().unwrap().row, 3);
        // Abandon them (as a throttled pass would) and the next pass restarts
        // from the top, still in raster order.
        for p in &first {
            g.abandon(p);
        }
        let second = g.plan_strips(SETTLE + 1, SETTLE, 32);
        assert_eq!(second.len(), 32);
        assert_eq!(second[0].row, 0);
        assert_eq!(second[0].col, 0);
        // A zero budget plans nothing at all.
        assert!(g.plan_strips(SETTLE + 2, SETTLE, 0).is_empty());
    }

    // -- commit / abandon / settling sweep ----------------------------------

    #[test]
    fn commit_sent_promotes_only_still_settling_tiles() {
        let mut g = TileGrid::new(256, 64, 0);
        let now = SETTLE;
        let plans = g.plan_strips(now, SETTLE, 32);
        // Tile 1 is re-dirtied between planning and sending: its pixels are
        // already stale, so it must not be recorded as exact.
        g.mark_dirty_rect(DirtyRect::ltrb(64, 0, 128, 64), now);
        g.commit_sent(&plans[0], &[10, 20, 30, 40], now, LEASE);
        assert_eq!(g.state_of(0), Some(TileState::Refined));
        assert_eq!(g.state_of(1), Some(TileState::Moving));
        assert_eq!(g.state_of(2), Some(TileState::Refined));
        // ...and it was revoked, because its strip may already be on the wire.
        assert_eq!(
            g.take_revocations(now),
            Some(TileMsg::Revoke { ids: vec![1] })
        );
    }

    #[test]
    fn commit_sent_with_mismatched_hashes_is_ignored() {
        let mut g = TileGrid::new(256, 64, 0);
        let now = SETTLE;
        let plans = g.plan_strips(now, SETTLE, 32);
        g.commit_sent(&plans[0], &[1, 2], now, LEASE);
        assert_eq!(
            g.stats().settling,
            4,
            "nothing promoted on a length mismatch"
        );
    }

    #[test]
    fn abandoned_strips_are_not_revoked() {
        let mut g = TileGrid::new(256, 64, 0);
        let plans = g.plan_strips(SETTLE, SETTLE, 32);
        g.abandon(&plans[0]);
        assert_eq!(g.stats().moving, 4);
        assert!(
            g.take_revocations(SETTLE).is_none(),
            "the client was never told anything"
        );
    }

    #[test]
    fn unresolved_settling_tiles_are_revoked_next_pass() {
        // The caller planned a strip and never reported back. We cannot know
        // whether it reached the wire, so we assume it did.
        let mut g = TileGrid::new(256, 64, 0);
        let plans = g.plan_strips(SETTLE, SETTLE, 32);
        assert_eq!(plans.len(), 1);
        let _ = g.plan_strips(SETTLE + 1, SETTLE, 32);
        let msg = g.take_revocations(SETTLE + 1);
        // 4 of 4 tiles: collapses to a Reset.
        assert!(matches!(msg, Some(TileMsg::Reset { .. })), "got {msg:?}");
    }

    // -- revoke_or_reset ----------------------------------------------------

    #[test]
    fn revoke_or_reset_boundaries() {
        assert_eq!(revoke_or_reset(vec![], 510), RevokeAction::Nothing);
        assert_eq!(
            revoke_or_reset(vec![3, 1], 510),
            RevokeAction::Revoke(vec![1, 3])
        );
        // Exactly half stays a revoke; one more collapses.
        let half: Vec<u32> = (0..255).collect();
        assert_eq!(
            revoke_or_reset(half.clone(), 510),
            RevokeAction::Revoke(half)
        );
        let past_half: Vec<u32> = (0..256).collect();
        assert_eq!(revoke_or_reset(past_half, 510), RevokeAction::Reset);
        // A grid we have no geometry for cannot express a revoke.
        assert_eq!(revoke_or_reset(vec![0], 0), RevokeAction::Reset);
    }

    #[test]
    fn revoke_or_reset_dedupes_before_measuring() {
        // 600 ids naming 3 tiles must not be mistaken for a full-screen change.
        let ids: Vec<u32> = (0..600).map(|i| i % 3).collect();
        assert_eq!(
            revoke_or_reset(ids, 510),
            RevokeAction::Revoke(vec![0, 1, 2])
        );
    }

    #[test]
    fn pending_revokes_are_deduplicated_by_the_grid() {
        let mut g = TileGrid::new(256, 64, 0);
        let now = SETTLE;
        let plans = g.plan_strips(now, SETTLE, 32);
        g.commit_sent(&plans[0], &[1, 2, 3, 4], now, LEASE);
        // Dirty the same tile from ten overlapping rects.
        for i in 0..10 {
            g.mark_dirty_rect(DirtyRect::ltrb(0, 0, 10 + i, 10), now + 1);
        }
        assert_eq!(g.stats().pending_revokes, 1);
        assert_eq!(
            g.take_revocations(now + 1),
            Some(TileMsg::Revoke { ids: vec![0] })
        );
    }

    // -- hashing and re-send suppression ------------------------------------

    #[test]
    fn hash_is_stable_and_position_sensitive() {
        let (buf, stride) = frame(256, 64, 0);
        let a = hash_tile(&buf, stride, 0, 0, 64, 64).unwrap();
        assert_eq!(a, hash_tile(&buf, stride, 0, 0, 64, 64).unwrap());
        assert_ne!(a, hash_tile(&buf, stride, 64, 0, 64, 64).unwrap());
        // A one-byte colour change is caught.
        let mut changed = buf.clone();
        changed[4 * 33 + 1] ^= 0xff;
        assert_ne!(a, hash_tile(&changed, stride, 0, 0, 64, 64).unwrap());
    }

    #[test]
    fn hash_ignores_alpha_because_the_wire_does() {
        let (buf, stride) = frame(64, 64, 0);
        let mut alpha_only = buf.clone();
        for px in alpha_only.chunks_exact_mut(4) {
            px[3] = px[3].wrapping_add(97);
        }
        assert_eq!(
            hash_tile(&buf, stride, 0, 0, 64, 64),
            hash_tile(&alpha_only, stride, 0, 0, 64, 64)
        );
    }

    #[test]
    fn hash_folds_in_the_extent() {
        // A 64x56 edge tile must not collide with the 64x64 tile it prefixes.
        let (buf, stride) = frame(64, 64, 0);
        assert_ne!(
            hash_tile(&buf, stride, 0, 0, 64, 56),
            hash_tile(&buf, stride, 0, 0, 64, 64)
        );
    }

    #[test]
    fn hash_rejects_extents_it_cannot_read() {
        let (buf, stride) = frame(64, 64, 0);
        assert_eq!(hash_tile(&buf, stride, 0, 0, 0, 64), None);
        assert_eq!(hash_tile(&buf, stride, 0, 0, 64, 0), None);
        assert_eq!(hash_tile(&buf, stride, 1, 0, 64, 64), None); // past the stride
        assert_eq!(hash_tile(&buf, stride, 0, 1, 64, 64), None); // past the buffer
        assert_eq!(hash_tile(&buf, stride, 0, 0, u32::MAX, 64), None);
    }

    #[test]
    fn hash_plan_tiles_walks_the_strip_left_to_right() {
        let mut g = TileGrid::new(256, 64, 0);
        g.mark_all_dirty(0);
        let plans = g.plan_strips(SETTLE, SETTLE, 32);
        let (buf, stride) = frame(256, 64, 0);
        let hashes = hash_plan_tiles(&buf, stride, &plans[0]).unwrap();
        assert_eq!(hashes.len(), 4);
        for (i, h) in hashes.iter().enumerate() {
            assert_eq!(
                *h,
                hash_tile(&buf, stride, i as u32 * 64, 0, 64, 64).unwrap()
            );
        }
        // All four tiles differ, so the strip is not uniform by accident.
        let mut sorted = hashes.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 4);
    }

    #[test]
    fn hash_plan_tiles_handles_a_partial_right_edge() {
        let mut g = TileGrid::new(160, 64, 0); // 3 columns, last is 32 px wide
        g.mark_all_dirty(0);
        let plans = g.plan_strips(SETTLE, SETTLE, 32);
        assert_eq!(plans[0].w, 160);
        let (buf, stride) = frame(160, 64, 0);
        let hashes = hash_plan_tiles(&buf, stride, &plans[0]).unwrap();
        assert_eq!(hashes.len(), 3);
        assert_eq!(hashes[2], hash_tile(&buf, stride, 128, 0, 32, 64).unwrap());
    }

    #[test]
    fn identical_repaint_of_a_resident_tile_is_renewed_not_resent() {
        // The caret case: a region the driver reported as changed which in fact
        // repainted identically. Verified renewal replaces a full re-send.
        let mut g = TileGrid::new(256, 64, 0);
        let (buf, stride) = frame(256, 64, 0);
        let now = SETTLE;
        let plans = g.plan_strips(now, SETTLE, 32);
        let hashes = hash_plan_tiles(&buf, stride, &plans[0]).unwrap();
        g.commit_sent(&plans[0], &hashes, now, LEASE);

        // Late in the lease the tiles come up for re-verification.
        let renew_at = now + LEASE - 500;
        let due = g.plan_reverify(renew_at, 1_000, 32);
        assert_eq!(due.len(), 1);
        let again = hash_plan_tiles(&buf, stride, &due[0]).unwrap();
        assert!(g.strip_matches_sent(&due[0], &again));
        g.commit_renewed(due[0].ids(), renew_at + LEASE);
        // Still refined, and no longer near expiry.
        assert_eq!(g.stats().refined, 4);
        assert!(g.plan_reverify(renew_at, 1_000, 32).is_empty());
    }

    #[test]
    fn reverify_that_finds_different_pixels_revokes() {
        // A change the driver never reported. Leases exist to bound exactly this,
        // and re-verification is what turns "wrong pixels forever" into "wrong
        // pixels for at most one renew interval".
        let mut g = TileGrid::new(256, 64, 0);
        let (buf, stride) = frame(256, 64, 0);
        let now = SETTLE;
        let plans = g.plan_strips(now, SETTLE, 32);
        g.commit_sent(
            &plans[0],
            &hash_plan_tiles(&buf, stride, &plans[0]).unwrap(),
            now,
            LEASE,
        );

        let (other, _) = frame(256, 64, 0x5a);
        let renew_at = now + LEASE - 500;
        let due = g.plan_reverify(renew_at, 1_000, 32);
        let again = hash_plan_tiles(&other, stride, &due[0]).unwrap();
        assert!(!g.strip_matches_sent(&due[0], &again));
        g.mark_tiles_dirty(due[0].ids(), renew_at);
        assert!(matches!(
            g.take_revocations(renew_at),
            Some(TileMsg::Reset { .. })
        ));
    }

    #[test]
    fn suppression_never_fires_on_a_tile_the_client_no_longer_holds() {
        // The trap this guard exists to avoid: a tile that was revoked must be
        // re-sent even though its pixels are byte-identical to the last send.
        let mut g = TileGrid::new(256, 64, 0);
        let (buf, stride) = frame(256, 64, 0);
        let now = SETTLE;
        let plans = g.plan_strips(now, SETTLE, 32);
        let hashes = hash_plan_tiles(&buf, stride, &plans[0]).unwrap();
        g.commit_sent(&plans[0], &hashes, now, LEASE);
        assert!(g.strip_matches_sent(&plans[0], &hashes));

        g.mark_all_dirty(now + 1);
        let _ = g.take_revocations(now + 1);
        assert!(
            !g.strip_matches_sent(&plans[0], &hashes),
            "a revoked tile must be re-sent even when its pixels are unchanged"
        );
    }

    #[test]
    fn strip_matches_sent_fails_closed() {
        let mut g = TileGrid::new(256, 64, 0);
        let now = SETTLE;
        let plans = g.plan_strips(now, SETTLE, 32);
        // Never sent: no recorded hash.
        assert!(!g.strip_matches_sent(&plans[0], &[1, 2, 3, 4]));
        g.commit_sent(&plans[0], &[1, 2, 3, 4], now, LEASE);
        assert!(g.strip_matches_sent(&plans[0], &[1, 2, 3, 4]));
        // Wrong length, empty, and one differing hash all answer "send it".
        assert!(!g.strip_matches_sent(&plans[0], &[1, 2, 3]));
        assert!(!g.strip_matches_sent(&plans[0], &[]));
        assert!(!g.strip_matches_sent(&plans[0], &[1, 2, 3, 5]));
    }

    // -- reset / resize -----------------------------------------------------

    #[test]
    fn reset_forgets_hashes_so_a_reconnect_resends_everything() {
        // The reconnect bug: HostSession outlives a connection, so a fresh client
        // holds nothing. If the hashes survived, suppression would fire on every
        // tile and the screen would stay soft forever.
        let mut g = TileGrid::new(256, 64, 0);
        let (buf, stride) = frame(256, 64, 0);
        let now = SETTLE;
        let plans = g.plan_strips(now, SETTLE, 32);
        let hashes = hash_plan_tiles(&buf, stride, &plans[0]).unwrap();
        g.commit_sent(&plans[0], &hashes, now, LEASE);

        let msg = g.reset(now + 10);
        assert_eq!(
            msg,
            TileMsg::Reset {
                width: 256,
                height: 64,
                edge: TILE_EDGE
            }
        );
        assert_eq!(
            g.stats(),
            GridStats {
                moving: 4,
                ..GridStats::default()
            }
        );
        assert!(!g.strip_matches_sent(&plans[0], &hashes));
        // And everything is planned again one settle later.
        let after = g.plan_strips(now + 10 + SETTLE, SETTLE, 32);
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].ids(), &[0, 1, 2, 3]);
    }

    #[test]
    fn resize_rebuilds_the_grid_and_demands_a_reset() {
        let mut g = grid_1080p(0);
        assert_eq!(g.resize(1920, 1080, 10), None, "no change, no reset");
        let msg = g.resize(1280, 720, 10).expect("geometry changed");
        assert_eq!(
            msg,
            TileMsg::Reset {
                width: 1280,
                height: 720,
                edge: TILE_EDGE
            }
        );
        assert_eq!((g.cols(), g.rows()), (20, 12));
        assert_eq!(g.len(), 240);
        assert_eq!(g.stats().moving, 240);
        assert!(
            g.take_revocations(10).is_none(),
            "the Reset supersedes them"
        );
        assert_eq!(g.dimensions(), (1280, 720));
    }

    #[test]
    fn full_cycle_on_a_1080p_grid() {
        // End to end: arm, settle, plan every strip, send, and confirm the whole
        // screen ends up refined with nothing outstanding.
        let mut g = grid_1080p(0);
        let (buf, stride) = frame(1920, 1080, 0);
        let mut now = SETTLE;
        let mut sent = 0usize;
        for _ in 0..80 {
            let plans = g.plan_strips(now, SETTLE, 32);
            if plans.is_empty() {
                break;
            }
            for p in &plans {
                let h = hash_plan_tiles(&buf, stride, p).expect("in bounds");
                g.commit_sent(p, &h, now, LEASE);
                sent += 1;
            }
            assert!(g.take_revocations(now).is_none(), "nothing should be stale");
            now += 10;
        }
        assert_eq!(sent, 8 * 17);
        assert_eq!(g.stats().refined, 510);
    }
}
