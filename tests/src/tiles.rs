//! Refinement tiles and the one congestion window they share with video.
//!
//! # The hazard this models
//!
//! Lossless static-region refinement ("tiles") rides a host-opened
//! unidirectional QUIC **stream** while H.264 video rides unreliable
//! **datagrams**. The two never contend for the same send buffer — but they
//! share one congestion window. Unthrottled tiles therefore inflate the host's
//! `backpressured` counter → `pressure` → [`congestion_signal`] → and the
//! adaptive bitrate controller quietly cuts **video**, with no packet loss and
//! no obvious cause. QUIC stream priority does not help: it orders streams
//! against each other, not against datagrams.
//!
//! The only defence is application-level throttling, which is
//! [`TileThrottle`] — [`tile_budget_kbps`]'s raw headroom gap, clamped by a
//! ceiling the throttle *learns* by experiment: multiplicative decrease
//! anchored to what was actually spent, and an additive increase taken only on
//! evidence (the ceiling was the binding constraint *and* refinement spent at
//! least half its grant). This module exists so that throttle can be put under
//! load against a real bitrate adaptor and a real video path.
//!
//! [`TilePolicy::RawGap`] runs the same harness with the learned ceiling
//! removed, so what the ceiling is buying can be measured rather than assumed.
//!
//! # Why the netsim needs help here
//!
//! [`directdesk_shared::netsim`] models loss, latency, jitter, reordering and
//! outages — but it has **no bandwidth model and no congestion window at all**.
//! Its datagrams and its streams are completely independent: a stream byte can
//! never displace a datagram. Sending tile bytes through it would therefore
//! have *exactly zero* effect on video, and a tiles-ON/tiles-OFF comparison
//! would pass for the same reason an empty test passes.
//!
//! So the shared window is modelled here, in the harness, by [`SharedLink`]:
//! one token bucket that both classes draw from, in front of the netsim. Video
//! datagrams that survive it go on to the real netsim and through the real
//! fragmenter, reassembler and adaptor; only the capacity contention is
//! synthetic.
//!
//! # The two asymmetries that make the model honest
//!
//! Everything the hazard depends on comes from two properties of QUIC, and both
//! are reproduced literally:
//!
//! * **Datagrams are dropped, stream bytes are retained.** A video frame that
//!   does not fit the window right now is gone — the host counts it
//!   `backpressured` and skips it whole (mirroring `host/src/net.rs`, which
//!   refuses to offer a frame `datagram_send_buffer_space()` cannot take,
//!   because a frame missing one fragment is as useless as one never sent).
//!   Tile bytes that do not fit stay queued and are sent later.
//! * **Retained bytes are ahead in the queue.** A tick drains the carried-over
//!   tile backlog *before* video is offered, because those bytes were already
//!   handed to the congestion controller on an earlier tick. New tile bytes
//!   produced this tick queue *behind* this tick's video.
//!
//! That ordering is the whole game, so it is worth being explicit about why it
//! is not rigged in either direction. Draining tiles unconditionally first
//! would let them starve video even when correctly budgeted, and the test would
//! "catch" a hazard that a correct throttle should survive. Offering video first
//! every tick would mean tile bytes could only ever use genuine leftovers, no
//! throttle would be needed, and the test could never fail. Carried-backlog
//! first is the real behaviour and leaves the outcome entirely up to whether
//! [`TileThrottle`] estimated the spare capacity correctly.
//!
//! # Tile bytes are not put on the netsim wire
//!
//! Deliberately. [`NetSim::send_stream`] draws from the seeded RNG, so tile
//! traffic would shift the loss and jitter schedule of every video datagram
//! sent after it — the tiles-ON run and the tiles-OFF run would no longer be
//! the same simulated network, and the matched-seed comparison this module
//! exists to support would be meaningless. Since the netsim gives streams no
//! influence over datagrams anyway, putting them there would buy nothing and
//! cost the comparison. Tile bytes are accounted as congestion-window
//! consumption and logged; the RNG stream is left untouched.
//!
//! # Window-limited and application-limited
//!
//! By default refinement produces exactly its budget every tick, i.e. it always
//! has more work than it is allowed to do. That is the *window-limited* case and
//! it is the one the hazard lives in, but it is not the only one refinement
//! runs in — a static desktop eventually runs out of tiles to send. Set
//! [`TileSim::tile_supply_kbps`] to model that; it caps what the source can
//! produce independently of the budget, which is the only way the harness can
//! reach the branches of [`TileThrottle`] that a spend *below* the grant
//! selects.
//!
//! [`NetSim::send_stream`]: directdesk_shared::netsim::NetSim::send_stream
//! [`tile_budget_kbps`]: directdesk_host::net::tile_budget_kbps

use directdesk_host::net::{congestion_signal, tile_budget_kbps, TileThrottle, WindowDelivery};
use directdesk_shared::adapt::BitrateAdaptor;

use crate::event::SimEvent;
use crate::pump::PumpCtx;

/// Status-window length, mirroring the host's `STATUS_INTERVAL_MS`. Every
/// congestion measurement and every tile-budget refill happens on this cadence,
/// exactly as `host::net::status_loop` does it.
pub const STATUS_INTERVAL_MS: u64 = 1_000;

/// Who decides how much bandwidth refinement tiles may spend this window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TilePolicy {
    /// The production throttle, [`TileThrottle`], fed the same inputs
    /// `status_loop` feeds it — including the tile bandwidth actually spent
    /// over the window just closed, which is the evidence its learned ceiling
    /// is built from.
    Production,
    /// The raw headroom policy: [`tile_budget_kbps`] alone, with no learned
    /// ceiling over the top. This is what the host granted before
    /// [`TileThrottle`] existed, and it is the baseline the throttle has to
    /// beat — a throttle that merely matches it is buying nothing.
    ///
    /// It calls the production function directly rather than reimplementing it,
    /// so this control cannot drift away from what it is a control for.
    RawGap,
    /// A negative control: tiles spend this many kbps unconditionally, with no
    /// regard for pressure, loss or headroom. This is what the feature would do
    /// with the throttle removed, and a row that asserts the throttle works is
    /// only meaningful if the same row fails under this policy.
    Unthrottled(u32),
}

/// Refinement-tile and shared-link parameters for one scenario.
///
/// Present on [`SimConfig::tiles`](crate::SimConfig::tiles) only for rows that
/// are about this; `None` leaves the host on the pre-existing code path, byte
/// for byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TileSim {
    /// Capacity of the one congestion window both classes share, in kbps.
    pub link_kbps: u32,
    /// Whether refinement tiles run at all. This is the ON/OFF switch the
    /// matched-seed comparison flips; everything else stays identical, so the
    /// two runs differ only by the presence of tile traffic.
    pub tiles_enabled: bool,
    /// Which policy governs the tile budget.
    pub policy: TilePolicy,
    /// The operator's standing ceiling on tile bandwidth, mirroring
    /// `HostConfig::lossless_tile_max_kbps`. `0` means "no explicit ceiling".
    pub tile_max_kbps: u32,
    /// How much of the link the bucket may bank while idle, in milliseconds of
    /// capacity. Must exceed one frame interval or a single frame could never
    /// fit in the window and every frame would backpressure regardless of load.
    pub link_burst_ms: u64,
    /// How much refinement work the *screen* actually has, in kbps. `0` means
    /// "always more than any budget", which is the default and what every row
    /// above assumes.
    ///
    /// # Why this exists
    ///
    /// Without it [`TileEngine::end_tick`] produces exactly `budget_kbps` of
    /// tile bytes every single tick, so `spent_kbps` always equals the grant and
    /// [`TileThrottle`]'s `used_its_grant` test is *always* satisfied. That
    /// makes the whole application-limited half of the throttle's logic
    /// unreachable — and application-limited is not an exotic case, it is the
    /// normal one: refinement exists for a static screen, and a static screen
    /// runs out of tiles to send.
    ///
    /// The distinction matters because the two halves of the throttle read a
    /// low `spent_kbps` in opposite directions. The growth gate treats it as
    /// "no evidence the link would carry more" and correctly declines to probe.
    /// The *backoff* anchors to it, so a strain event that lands while the
    /// screen is quiet sets `safe_kbps` from a spend that reflects the screen
    /// rather than the link — and everything above that level is creep-only
    /// from then on. This field is what lets that be measured instead of
    /// argued about.
    ///
    /// [`TileThrottle`]: directdesk_host::net::TileThrottle
    pub tile_supply_kbps: u32,
}

impl TileSim {
    /// A link of `link_kbps` with tiles off — the control run.
    #[must_use]
    pub fn off(link_kbps: u32) -> Self {
        Self {
            link_kbps,
            tiles_enabled: false,
            policy: TilePolicy::Production,
            tile_max_kbps: DEFAULT_TILE_MAX_KBPS,
            link_burst_ms: DEFAULT_LINK_BURST_MS,
            tile_supply_kbps: 0,
        }
    }

    /// The same link with tiles on under the production throttle.
    #[must_use]
    pub fn on(link_kbps: u32) -> Self {
        Self {
            tiles_enabled: true,
            ..Self::off(link_kbps)
        }
    }

    /// The same link with tiles on under the raw headroom policy, with no
    /// learned ceiling — the pre-[`TileThrottle`] baseline.
    #[must_use]
    pub fn raw_gap(link_kbps: u32) -> Self {
        Self {
            policy: TilePolicy::RawGap,
            ..Self::on(link_kbps)
        }
    }

    /// The same link with tiles on and the throttle removed.
    #[must_use]
    pub fn unthrottled(link_kbps: u32, tile_kbps: u32) -> Self {
        Self {
            policy: TilePolicy::Unthrottled(tile_kbps),
            ..Self::on(link_kbps)
        }
    }

    /// The production throttle on a screen that only has `supply_kbps` of
    /// refinement work to do — the static-desktop case, where refinement is
    /// limited by content rather than by its budget.
    #[must_use]
    pub fn app_limited(link_kbps: u32, supply_kbps: u32) -> Self {
        Self {
            tile_supply_kbps: supply_kbps,
            ..Self::on(link_kbps)
        }
    }
}

/// Mirrors `HostConfig::lossless_tile_max_kbps`'s default, so a row that does
/// not deliberately set a ceiling gets the shipped one.
pub const DEFAULT_TILE_MAX_KBPS: u32 = 8_000;

/// Default bucket depth. Longer than the 33 ms frame interval so a whole frame
/// can always be banked for, short enough that sustained overload shows up as
/// backpressure within a status window rather than being absorbed.
pub const DEFAULT_LINK_BURST_MS: u64 = 40;

/// What the engine observed over a run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TileStats {
    /// Tile bytes the shared window actually carried.
    pub tile_bytes_sent: u64,
    /// Tile bytes discarded because the backlog was already at its cap — the
    /// link could not keep up with the budget it was handed.
    pub tile_bytes_dropped: u64,
    /// Video frames that fitted the window and went to the netsim.
    pub video_frames_sent: u64,
    /// Video frames the window had no room for, skipped whole.
    pub video_frames_backpressured: u64,
    /// Status windows closed.
    pub windows_closed: u64,
    /// Status windows that measured any backpressure at all. On a correctly
    /// throttled run this is the number the hazard would inflate.
    pub windows_with_pressure: u64,
}

/// One status window's measurements, kept for assertions and diffing.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TileWindowRecord {
    /// Virtual millisecond the window closed.
    pub at_ms: u64,
    /// Backpressure ratio the window measured.
    pub pressure: f32,
    /// Client-reported loss fraction in force when it closed.
    pub loss: f32,
    /// Encoder output over the window, kbps.
    pub media_kbps: u32,
    /// The adaptor's target after observing this window.
    pub adaptor_kbps: u32,
    /// The tile budget granted for the *next* window.
    pub budget_kbps: u32,
    /// Tile bandwidth actually spent over *this* window — the evidence
    /// [`TileThrottle`] learns its ceiling from.
    pub spent_kbps: u32,
    /// The throttle's learned ceiling after observing this window. Under
    /// [`TilePolicy::Unthrottled`] the throttle is never driven, so this stays
    /// at its initial value and means nothing.
    pub ceiling_kbps: u32,
}

/// The shared congestion window plus the host-side status loop that governs it.
///
/// Owned by [`SimHost`](crate::SimHost) and driven once per tick:
/// [`TileEngine::begin_tick`] → [`TileEngine::offer_video`] →
/// [`TileEngine::end_tick`].
#[derive(Debug)]
pub struct TileEngine {
    cfg: TileSim,
    tick_ms: u64,

    /// Bytes of congestion window available right now.
    bucket_bytes: u64,
    /// Sub-byte remainder of the link's per-tick refill, so the modelled
    /// capacity is exact over a run rather than losing a few bits per tick.
    link_bits_carry: u64,
    /// Tile bytes handed to the congestion controller on an earlier tick and
    /// not yet on the wire. Retained, unlike a datagram.
    tile_backlog_bytes: u64,
    /// Sub-byte remainder of the tile budget's per-tick production.
    tile_bits_carry: u64,

    /// Bandwidth tiles may spend, refilled at each window close.
    budget_kbps: u32,
    /// The real production throttle, carried across windows because its whole
    /// job is to *learn* — a fresh one per window would have no memory and
    /// would be indistinguishable from the raw headroom gap. Driven only under
    /// [`TilePolicy::Production`]; [`TilePolicy::Unthrottled`] never touches it.
    throttle: TileThrottle,
    /// `stats.tile_bytes_sent` as of the last window close, so the throttle can
    /// be fed a *matched* per-window delta rather than a lifetime total. Same
    /// idiom as the `win_*` counters below and as `status_loop`'s
    /// `prev_tile_bytes`: a lifetime figure would make every window look more
    /// expensive than the last and the ceiling would collapse for no reason.
    prev_tile_bytes: u64,

    // -- status window accounting, mirroring `status_loop` -------------------
    win_start_ms: u64,
    win_sent: u64,
    win_backpressured: u64,
    win_bytes: u64,
    win_encoded_bytes: u64,
    /// Latest client-reported loss and RTT, standing in for `ConnStats`.
    peer_loss: f32,
    peer_rtt_ms: f32,

    stats: TileStats,
    windows: Vec<TileWindowRecord>,
}

impl TileEngine {
    /// An engine for `cfg` on a `tick_ms` clock, with an empty window and a
    /// zero tile budget.
    ///
    /// The budget starts at zero on purpose: the production host only calls
    /// `set_tile_budget_kbps` once a status window has closed, so refinement
    /// cannot spend anything before a single congestion measurement exists.
    #[must_use]
    pub fn new(cfg: TileSim, tick_ms: u64) -> Self {
        // The window starts full. A session opens on an idle connection, so
        // nothing has consumed it yet — and starting it empty would make the
        // opening keyframe, which is larger than one tick of any modest link,
        // backpressure in *every* run for reasons that have nothing to do with
        // tiles. Symmetric across a pair, but a confound worth removing.
        let bucket_bytes = bits_to_bytes(u64::from(cfg.link_kbps) * cfg.link_burst_ms);
        Self {
            cfg,
            tick_ms,
            bucket_bytes,
            link_bits_carry: 0,
            tile_backlog_bytes: 0,
            tile_bits_carry: 0,
            budget_kbps: 0,
            throttle: TileThrottle::new(),
            prev_tile_bytes: 0,
            win_start_ms: 0,
            win_sent: 0,
            win_backpressured: 0,
            win_bytes: 0,
            win_encoded_bytes: 0,
            peer_loss: 0.0,
            peer_rtt_ms: 0.0,
            stats: TileStats::default(),
            windows: Vec::new(),
        }
    }

    /// The parameters in force.
    #[must_use]
    pub fn config(&self) -> &TileSim {
        &self.cfg
    }

    /// Counters for the whole run.
    #[must_use]
    pub fn stats(&self) -> TileStats {
        self.stats
    }

    /// Every closed status window, in order.
    #[must_use]
    pub fn windows(&self) -> &[TileWindowRecord] {
        &self.windows
    }

    /// The tile budget currently in force.
    #[must_use]
    pub fn budget_kbps(&self) -> u32 {
        self.budget_kbps
    }

    /// Depth of the shared bucket in bytes.
    fn bucket_depth(&self) -> u64 {
        bits_to_bytes(u64::from(self.cfg.link_kbps) * self.cfg.link_burst_ms)
    }

    /// Record the newest client feedback. Replaces the direct
    /// `adaptor.observe` the host does when tiles are not configured: with an
    /// engine present the adaptor is driven once per status window from the
    /// full [`congestion_signal`], exactly as `status_loop` does, rather than
    /// from raw loss on every report.
    pub fn observe_peer_stats(&mut self, loss: f32, rtt_ms: f32) {
        self.peer_loss = loss.clamp(0.0, 1.0);
        self.peer_rtt_ms = rtt_ms;
    }

    /// Note that the encoder produced `bytes`, whether or not they reach the
    /// wire. This is the `media.bitrate_kbps` half of the headroom estimate.
    pub fn record_encoded(&mut self, bytes: usize) {
        self.win_encoded_bytes = self.win_encoded_bytes.saturating_add(bytes as u64);
    }

    /// Start of tick: close the status window if it is due, refill the shared
    /// bucket, then let the carried-over tile backlog drain into it.
    pub fn begin_tick(&mut self, ctx: &mut PumpCtx<'_>, adaptor: &mut BitrateAdaptor) {
        if ctx.now_ms.saturating_sub(self.win_start_ms) >= STATUS_INTERVAL_MS {
            self.close_window(ctx, adaptor);
        }

        // Exact refill: accumulate bits, spend whole bytes, keep the remainder.
        self.link_bits_carry += u64::from(self.cfg.link_kbps) * self.tick_ms;
        let refill = self.link_bits_carry / 8;
        self.link_bits_carry %= 8;
        self.bucket_bytes = (self.bucket_bytes + refill).min(self.bucket_depth());

        // Bytes already given to the congestion controller go first: they are
        // ahead of anything offered this tick, and unlike a datagram they were
        // never at risk of being dropped for not fitting.
        let drained = self.tile_backlog_bytes.min(self.bucket_bytes);
        self.tile_backlog_bytes -= drained;
        self.bucket_bytes -= drained;
        self.stats.tile_bytes_sent += drained;
    }

    /// Offer one whole video frame of `wire_bytes` to the shared window.
    ///
    /// Returns whether it fitted. A frame that does not fit is **not** sent at
    /// all, mirroring `host/src/net.rs`: quinn's datagram buffer, when full,
    /// evicts the *oldest* queued datagrams, so offering a frame that does not
    /// fit shreds the one already in flight and costs two frames instead of
    /// one. Skipping whole costs exactly one and keeps every sent frame
    /// decodable.
    pub fn offer_video(&mut self, wire_bytes: usize) -> bool {
        let need = wire_bytes as u64;
        if self.bucket_bytes >= need {
            self.bucket_bytes -= need;
            self.win_sent += 1;
            self.win_bytes += need;
            self.stats.video_frames_sent += 1;
            true
        } else {
            self.win_backpressured += 1;
            self.stats.video_frames_backpressured += 1;
            false
        }
    }

    /// End of tick: produce this tick's tile bytes and let them take whatever
    /// window is left over, queueing the rest behind this tick's video.
    ///
    /// Refinement produces the smaller of its budget and what the screen
    /// actually has to refine — see [`TileSim::tile_supply_kbps`]. With the
    /// default supply of "unlimited" this is exactly the budget, so every row
    /// that does not opt in is byte-for-byte unchanged.
    pub fn end_tick(&mut self) {
        let rate_kbps = if self.cfg.tile_supply_kbps == 0 {
            self.budget_kbps
        } else {
            self.budget_kbps.min(self.cfg.tile_supply_kbps)
        };
        if !self.cfg.tiles_enabled || rate_kbps == 0 {
            // Nothing produced. Any carried remainder is stale once the budget
            // is revoked, so drop it rather than let a burst leak out later.
            self.tile_bits_carry = 0;
            return;
        }
        self.tile_bits_carry += u64::from(rate_kbps) * self.tick_ms;
        let produced = self.tile_bits_carry / 8;
        self.tile_bits_carry %= 8;

        // Whatever window is left after video takes it immediately; the rest
        // queues, bounded by the same depth as the bucket so a link that cannot
        // keep up sheds work instead of banking an unbounded burst.
        let immediate = produced.min(self.bucket_bytes);
        self.bucket_bytes -= immediate;
        self.stats.tile_bytes_sent += immediate;

        let queued = produced - immediate;
        let room = self.bucket_depth().saturating_sub(self.tile_backlog_bytes);
        let accepted = queued.min(room);
        self.tile_backlog_bytes += accepted;
        self.stats.tile_bytes_dropped += queued - accepted;
    }

    /// Close a status window: measure it, drive the adaptor from the same
    /// [`congestion_signal`] the host uses, and refill the tile budget from the
    /// same [`TileThrottle::observe`] call `status_loop` makes.
    fn close_window(&mut self, ctx: &mut PumpCtx<'_>, adaptor: &mut BitrateAdaptor) {
        let dt_ms = ctx.now_ms.saturating_sub(self.win_start_ms);
        let delivery = WindowDelivery {
            sent: self.win_sent,
            offered: self.win_sent + self.win_backpressured,
            bytes: self.win_bytes,
            dt_ms,
        };
        let pressure = delivery.backpressure_ratio();
        // Bits over milliseconds is kbps directly. A zero-length window (only
        // reachable if the clock never moved) reports nothing rather than
        // dividing by zero.
        let media_kbps = (self.win_encoded_bytes * 8)
            .checked_div(dt_ms)
            .unwrap_or(0)
            .min(u64::from(u32::MAX)) as u32;

        // `overrun` is the encoder-vs-carried diagnostic, which needs a
        // transport bandwidth estimate the netsim does not have. It is gated off
        // in production until warm anyway, so passing `warm = false` reproduces
        // the shipped behaviour for the window lengths this harness runs.
        let congestion = congestion_signal(self.peer_loss, pressure, 0.0, false);
        if let Some(next) = adaptor.observe(ctx.now_ms, congestion, self.peer_rtt_ms) {
            ctx.log.push(SimEvent::BitrateChanged {
                at_ms: ctx.now_ms,
                kbps: next,
            });
        }

        // What refinement actually spent over the window just closed, as a
        // matched delta over the *same* window `delivery` measures — exactly
        // how `status_loop` derives `tile_spent_kbps`. `dt_ms` is floored at 1
        // so a zero-length window reports nothing rather than dividing by zero.
        let tile_bytes_now = self.stats.tile_bytes_sent;
        let spent_kbps =
            ((tile_bytes_now.saturating_sub(self.prev_tile_bytes) * 8) / dt_ms.max(1)) as u32;
        self.prev_tile_bytes = tile_bytes_now;

        let budget = match self.cfg.policy {
            TilePolicy::Production => self.throttle.observe(
                spent_kbps,
                adaptor.current(),
                media_kbps,
                pressure,
                self.peer_loss,
                false,
                true,
                self.cfg.tile_max_kbps,
            ),
            TilePolicy::RawGap => tile_budget_kbps(
                adaptor.current(),
                media_kbps,
                pressure,
                self.peer_loss,
                false,
                true,
                self.cfg.tile_max_kbps,
            ),
            TilePolicy::Unthrottled(kbps) => kbps,
        };
        self.budget_kbps = if self.cfg.tiles_enabled { budget } else { 0 };

        self.stats.windows_closed += 1;
        if pressure > 0.0 {
            self.stats.windows_with_pressure += 1;
        }
        let record = TileWindowRecord {
            at_ms: ctx.now_ms,
            pressure,
            loss: self.peer_loss,
            media_kbps,
            adaptor_kbps: adaptor.current(),
            budget_kbps: self.budget_kbps,
            spent_kbps,
            ceiling_kbps: self.throttle.ceiling(),
        };
        self.windows.push(record);
        ctx.log.push(SimEvent::TileWindow {
            at_ms: ctx.now_ms,
            pressure,
            budget_kbps: self.budget_kbps,
            adaptor_kbps: adaptor.current(),
            video_sent: self.win_sent,
            video_backpressured: self.win_backpressured,
        });

        self.win_start_ms = ctx.now_ms;
        self.win_sent = 0;
        self.win_backpressured = 0;
        self.win_bytes = 0;
        self.win_encoded_bytes = 0;
    }
}

/// Whole bytes in `bits`, rounding down.
fn bits_to_bytes(bits: u64) -> u64 {
    bits / 8
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventLog;
    use directdesk_shared::adapt::AdaptConfig;
    use directdesk_shared::netsim::{NetParams, NetSim};
    use directdesk_shared::protocol::QualityMode;

    /// A bucket that refills at the configured rate and never banks more than
    /// its depth.
    #[test]
    fn bucket_refills_at_the_link_rate_and_is_capped() {
        let mut net = NetSim::new(NetParams::perfect(), 0).expect("valid");
        let mut log = EventLog::new();
        let mut adaptor = BitrateAdaptor::new(AdaptConfig::for_mode(QualityMode::Balanced));
        let cfg = TileSim::off(8_000);
        let mut engine = TileEngine::new(cfg, 5);

        // 8000 kbps over a 5 ms tick is exactly 5000 bytes.
        // Depth is 40 ms of link: 8000 kbps * 40 ms / 8 = 40_000 bytes, and the
        // window opens full.
        assert_eq!(engine.bucket_bytes, 40_000);
        engine.bucket_bytes = 0;

        // 8000 kbps over a 5 ms tick is exactly 5000 bytes.
        let mut ctx = PumpCtx {
            net: &mut net,
            now_ms: 0,
            log: &mut log,
        };
        engine.begin_tick(&mut ctx, &mut adaptor);
        assert_eq!(engine.bucket_bytes, 5_000);

        // Even after far more than eight idle ticks it may not exceed the depth.
        for t in 1..64u64 {
            let mut ctx = PumpCtx {
                net: &mut net,
                now_ms: t * 5,
                log: &mut log,
            };
            engine.begin_tick(&mut ctx, &mut adaptor);
            engine.end_tick();
        }
        assert_eq!(engine.bucket_bytes, 40_000);
    }

    /// A frame larger than the remaining window is skipped whole and counted,
    /// never partially sent.
    #[test]
    fn oversized_offer_is_refused_whole() {
        let mut engine = TileEngine::new(TileSim::off(8_000), 5);
        engine.bucket_bytes = 1_000;
        assert!(!engine.offer_video(1_001), "must not fit");
        assert_eq!(engine.bucket_bytes, 1_000, "a refused frame spends nothing");
        assert_eq!(engine.stats().video_frames_backpressured, 1);
        assert!(engine.offer_video(1_000), "exactly the remainder fits");
        assert_eq!(engine.bucket_bytes, 0);
        assert_eq!(engine.stats().video_frames_sent, 1);
    }

    /// With tiles off nothing is ever produced, whatever the budget field says.
    #[test]
    fn disabled_tiles_produce_nothing() {
        let mut engine = TileEngine::new(TileSim::off(8_000), 5);
        engine.budget_kbps = 4_000;
        engine.bucket_bytes = 10_000;
        engine.end_tick();
        assert_eq!(engine.stats().tile_bytes_sent, 0);
        assert_eq!(engine.tile_backlog_bytes, 0);
    }

    /// An application-limited source produces its supply, not its budget, and
    /// the default of `0` still means "always exactly the budget".
    #[test]
    fn a_quiet_screen_produces_its_supply_not_its_budget() {
        // 4 000 kbps of budget against a screen with only 1 000 kbps to send.
        let mut engine = TileEngine::new(TileSim::app_limited(8_000, 1_000), 5);
        engine.budget_kbps = 4_000;
        for _ in 0..200 {
            engine.bucket_bytes = engine.bucket_depth();
            engine.end_tick();
        }
        // 1 000 kbps over 200 ticks of 5 ms is 1 second, i.e. 125 000 bytes.
        assert_eq!(engine.stats().tile_bytes_sent, 125_000);

        // The same engine with no supply cap produces the whole budget.
        let mut engine = TileEngine::new(TileSim::on(8_000), 5);
        engine.budget_kbps = 4_000;
        for _ in 0..200 {
            engine.bucket_bytes = engine.bucket_depth();
            engine.end_tick();
        }
        assert_eq!(engine.stats().tile_bytes_sent, 500_000);
    }

    /// The backlog is bounded: a link that cannot carry the budget sheds the
    /// excess rather than banking an unbounded burst.
    #[test]
    fn tile_backlog_is_bounded_and_sheds() {
        let mut engine = TileEngine::new(TileSim::unthrottled(1_000, 100_000), 5);
        engine.budget_kbps = 100_000;
        for _ in 0..200 {
            engine.end_tick();
        }
        assert!(engine.tile_backlog_bytes <= engine.bucket_depth());
        assert!(
            engine.stats().tile_bytes_dropped > 0,
            "a 1 Mbps link cannot carry a 100 Mbps budget"
        );
    }
}
