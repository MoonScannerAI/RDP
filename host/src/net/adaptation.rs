//! The control loop's numbers: rate limiting, matched-window delivery, the
//! congestion signal the bitrate adaptor observes, and the tile budget.
//!
//! Everything here is pure arithmetic over a single status window, with the
//! clock injected as a `now_ms` argument. Nothing in this module opens a
//! socket, takes a lock, touches a pipeline or reads a clock of its own —
//! which is exactly what lets the whole adaptation policy be pinned by tests
//! that never establish a connection.
//!
//! That is also the rule for what belongs here. A number that decides *how
//! much* to send over the next window belongs in this module; the code that
//! measures the window, holds the adaptor behind a mutex and actually sends
//! belongs in [`crate::net`].

/// Period of the host's `Stats` / `RouteReport` broadcast.
pub const STATUS_INTERVAL_MS: u64 = 1_000;
/// Status windows a stream must run before the encoder-vs-carried `overrun`
/// diagnostic is trusted to move the adaptor. The first windows measure the
/// encoder over a full interval while the transport has barely begun carrying
/// the stream, so their ratio is a window artifact — not congestion. Gating on
/// it is what stops the spurious start-up downshift.
pub const OVERRUN_WARMUP_INTERVALS: u32 = 3;
/// Frames that must actually have gone out in a window for that window's
/// `overrun` ratio to mean anything. A window where we barely sent (idle, or a
/// stream that just stopped) cannot report meaningful carried bitrate.
pub const OVERRUN_MIN_FRAMES: u64 = 5;

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

/// "At most once per interval", with the clock injected.
#[derive(Debug, Clone, Copy)]
pub struct RateLimiter {
    min_interval_ms: u64,
    last_ms: Option<u64>,
}

impl RateLimiter {
    pub fn new(min_interval_ms: u64) -> Self {
        Self {
            min_interval_ms,
            last_ms: None,
        }
    }

    /// Whether the action may run now; records the time when it may.
    pub fn allow(&mut self, now_ms: u64) -> bool {
        match self.last_ms {
            Some(last) if now_ms.saturating_sub(last) < self.min_interval_ms => false,
            _ => {
                self.last_ms = Some(now_ms);
                true
            }
        }
    }
}

/// How far the encoder is outrunning what the connection actually carries,
/// expressed as the 0..1 congestion signal [`BitrateAdaptor`] expects.
///
/// This is the signal that packet loss cannot provide. QUIC datagrams are
/// unreliable by design: when the congestion controller cannot place them,
/// quinn discards them itself, without an error, without filling its send
/// buffer, and — because nothing was ever put on the wire — without a single
/// lost *packet*. A host watching only `loss` therefore sees a perfectly clean
/// link while half its video evaporates. Comparing what the encoder produced
/// against what the transport moved is what makes that visible.
///
/// The 15% slack keeps normal measurement noise and protocol overhead from
/// being mistaken for congestion.
///
/// [`BitrateAdaptor`]: directdesk_shared::adapt::BitrateAdaptor
pub fn overrun_signal(encoder_kbps: u32, carried_kbps: u32) -> f32 {
    if encoder_kbps == 0 || carried_kbps == 0 {
        return 0.0;
    }
    let produced = encoder_kbps as f32;
    let carried = carried_kbps as f32;
    if produced <= carried * 1.15 {
        return 0.0;
    }
    ((produced - carried) / produced).clamp(0.0, 1.0)
}

/// Host-side delivery over a **single matched status window**.
///
/// Every field is a delta measured across the *same* interval — never a
/// lifetime total. The old diagnostic compared a session-lifetime send count
/// against a one-second client report, so a link that had been up for a minute
/// looked ~50% "lossy" the instant the client's window began. Deltas over one
/// shared window cannot drift like that.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct WindowDelivery {
    /// Frames actually put on the wire this window.
    pub sent: u64,
    /// Frames offered to the link this window: sent plus those the link had no
    /// room for. Frames merely coalesced (a newer one superseded them) are not
    /// offered and so are not counted here.
    pub offered: u64,
    /// Bytes put on the wire this window.
    pub bytes: u64,
    /// Length of the window, milliseconds.
    pub dt_ms: u64,
}

impl WindowDelivery {
    /// Fraction of offered frames that actually reached the wire, `0.0..=1.0`.
    /// An idle window (`offered == 0`) delivered everything it was asked to, so
    /// it reads `1.0` rather than dividing by zero into a false shortfall.
    pub fn delivery_ratio(&self) -> f32 {
        if self.offered == 0 {
            1.0
        } else {
            (self.sent as f32 / self.offered as f32).clamp(0.0, 1.0)
        }
    }

    /// Fraction of offered frames the link had no room for, `0.0..=1.0`. This is
    /// congestion quinn's packet-loss counter cannot see (the frame was never
    /// sent) and the receiver's reassembler cannot see either (nothing to
    /// reassemble), so it is a genuine, matched-window congestion signal.
    pub fn backpressure_ratio(&self) -> f32 {
        if self.offered == 0 {
            0.0
        } else {
            (self.offered.saturating_sub(self.sent) as f32 / self.offered as f32).clamp(0.0, 1.0)
        }
    }

    /// Throughput actually carried this window, kbps. Bytes over the real
    /// elapsed window, not a nominal tick length.
    pub fn throughput_kbps(&self) -> u32 {
        if self.dt_ms == 0 {
            0
        } else {
            ((self.bytes as f64 * 8.0) / self.dt_ms as f64).min(u32::MAX as f64) as u32
        }
    }
}

/// Turns the session's raw, monotonically-increasing counters into one
/// [`WindowDelivery`] per status tick, and tracks how many ticks have run so
/// the overrun diagnostic knows when it can be trusted (see
/// [`OVERRUN_WARMUP_INTERVALS`] / [`OVERRUN_MIN_FRAMES`]).
///
/// Holds nothing but the previous tick's raw counters and a tick count — no
/// clock of its own, no socket, no lock. `close` is the only way to move it
/// forward, and there is no way to read the current window without also
/// consuming it, which is exactly what `status_loop` does once per tick.
#[derive(Debug, Clone)]
pub(crate) struct StatusWindow {
    prev_sent: u64,
    prev_bytes: u64,
    prev_backpressured: u64,
    prev_now: u64,
    intervals: u32,
}

impl StatusWindow {
    /// `now` seeds the first window's `dt_ms` against the moment the session
    /// actually started, not zero.
    pub(crate) fn new(now: u64) -> Self {
        Self {
            prev_sent: 0,
            prev_bytes: 0,
            prev_backpressured: 0,
            prev_now: now,
            intervals: 0,
        }
    }

    /// Close out one status window: fold this tick's raw lifetime counters
    /// into a matched delta against the previous tick, and report whether the
    /// stream is warm enough for the overrun ratio to mean anything.
    pub(crate) fn close(
        &mut self,
        now: u64,
        sent: u64,
        bytes: u64,
        backpressured: u64,
    ) -> (WindowDelivery, bool) {
        let win_sent = sent.saturating_sub(self.prev_sent);
        let win_backpressured = backpressured.saturating_sub(self.prev_backpressured);
        let delivery = WindowDelivery {
            sent: win_sent,
            offered: win_sent + win_backpressured,
            bytes: bytes.saturating_sub(self.prev_bytes),
            dt_ms: now.saturating_sub(self.prev_now),
        };
        self.prev_sent = sent;
        self.prev_bytes = bytes;
        self.prev_backpressured = backpressured;
        self.prev_now = now;
        self.intervals = self.intervals.saturating_add(1);

        // The encoder-vs-carried "overrun" is only a trustworthy congestion
        // signal once the stream has run a few windows AND actually sent a
        // meaningful number of frames this window. Before that (start-up, or a
        // window where the stream just stopped) the encoder bitrate is
        // measured over a full interval while the link carried almost
        // nothing, and their ratio is a window artifact that would drive the
        // adaptor down for no reason.
        let warm = self.intervals > OVERRUN_WARMUP_INTERVALS && win_sent >= OVERRUN_MIN_FRAMES;
        (delivery, warm)
    }
}

/// The single congestion number the [`BitrateAdaptor`] observes for one window.
///
/// `loss` is the transport's real, matched-window application-level loss — the
/// [`ConnStats::loss`] that already folds in the receiver's silent-datagram
/// accounting *and* quinn's packet loss upstream. `backpressure` is host frames
/// the link had no room for this window. `overrun` is the encoder-vs-carried
/// *diagnostic*, and is only folded in once `warm`: before warm-up its two
/// inputs are measured over mismatched, half-empty windows and their ratio is
/// meaningless, so feeding it to the adaptor is exactly the spurious-downshift
/// bug. The adaptor is therefore *driven by the real loss*, with the diagnostic
/// gated out until it can be trusted.
///
/// [`BitrateAdaptor`]: directdesk_shared::adapt::BitrateAdaptor
/// [`ConnStats::loss`]: directdesk_shared::stats::ConnStats::loss
pub fn congestion_signal(loss: f32, backpressure: f32, overrun: f32, warm: bool) -> f32 {
    let overrun = if warm { overrun } else { 0.0 };
    loss.max(backpressure).max(overrun).clamp(0.0, 1.0)
}

/// The congestion number for one status window: [`congestion_signal`], with a
/// keyframe the fragmenter refused overriding every measured signal outright.
///
/// Nothing of a refused keyframe reached the wire, and the next IDR would be
/// the same size unless the bitrate comes down — that outranks a `loss` or
/// `backpressure` reading that has not caught up to the stall yet.
pub(crate) fn window_congestion(
    loss: f32,
    delivery: WindowDelivery,
    overrun: f32,
    warm: bool,
    oversized_keyframe: bool,
) -> f32 {
    if oversized_keyframe {
        return 1.0;
    }
    congestion_signal(loss, delivery.backpressure_ratio(), overrun, warm)
}

/// Loss above this fraction means the link is already hurting; refinement
/// tiles are a luxury and must stop entirely until it clears.
const TILE_LOSS_CUTOFF: f32 = 0.02;

/// Share of the measured spare headroom that tiles may claim. A quarter is
/// deliberately timid: the headroom figure is an estimate, and being wrong in
/// the generous direction degrades the video this feature exists to improve.
const TILE_HEADROOM_SHARE: u32 = 4;

/// Whether the link is currently too strained for tiles to spend any budget.
///
/// The one predicate [`tile_budget_kbps`] and [`TileThrottle::observe`] must
/// agree on. `observe` checks this itself before it ever calls
/// `tile_budget_kbps`, so the two are on the same path today — but they are
/// two separate copies of the same judgment call, and if they were ever edited
/// out of step a window one function calls strained could still be granted
/// budget by the other: exactly the class of bug this design exists to
/// prevent, just moved from the network to the code that decides whether to
/// use it.
#[must_use]
pub fn tiles_strained(pressure: f32, loss: f32, oversized_keyframe: bool, streaming: bool) -> bool {
    !streaming || oversized_keyframe || pressure > 0.0 || loss > TILE_LOSS_CUTOFF
}

/// Bandwidth (kbps) refinement tiles may use over the next window.
///
/// **This is the one hazard the design cannot structurally remove.** Tiles ride
/// a QUIC stream and video rides datagrams, so they never contend for the same
/// send buffer — but they share one congestion window. Unthrottled tiles
/// therefore inflate `backpressured` → `pressure` → [`congestion_signal`] and
/// the adaptor quietly cuts **video** bitrate, with no loss and no obvious
/// cause. Stream priority does not help: it orders streams against each other,
/// not against datagrams.
///
/// So the budget is spent only out of *demonstrated* spare capacity: the gap
/// between what the adaptor has allocated and what the encoder is actually
/// producing. On a static screen — exactly when tiles want to run — capture
/// suppresses frames so `media_kbps` collapses while the adaptor's allocation
/// stays high, which is precisely the headroom being measured.
///
/// Any sign of strain zeroes it outright rather than scaling it down: a
/// half-speed refinement of a struggling link is still a struggling link.
#[allow(clippy::too_many_arguments)]
pub fn tile_budget_kbps(
    adaptor_target: u32,
    media_kbps: u32,
    pressure: f32,
    loss: f32,
    oversized_keyframe: bool,
    streaming: bool,
    cap_kbps: u32,
) -> u32 {
    // Any backpressure at all: quinn already had to drop something we offered.
    if tiles_strained(pressure, loss, oversized_keyframe, streaming) {
        return 0;
    }
    let headroom = adaptor_target.saturating_sub(media_kbps) / TILE_HEADROOM_SHARE;
    // `0` on the cap means "no explicit ceiling"; the headroom is the limit.
    if cap_kbps == 0 {
        headroom
    } else {
        headroom.min(cap_kbps)
    }
}

/// Lowest tile ceiling the throttle will learn down to, and the level it starts
/// from. Conservative on purpose: refinement ramping up over a few seconds is
/// invisible, refinement overshooting is not.
pub const TILE_CEILING_MIN_KBPS: u32 = 500;
/// Ramp step while the ceiling is still below a level known to be safe.
pub const TILE_CEILING_STEP_KBPS: u32 = 500;

/// Step used when probing *above* the last known-safe level.
///
/// Deliberately tiny. Overshooting is not symmetric with under-using: an
/// overshoot costs the **video** bitrate a 30% multiplicative cut that takes
/// many seconds of additive recovery to undo, while under-using costs only some
/// refinement latency on a picture that is already correct. So above the safe
/// level this creeps rather than steps.
///
/// A flat step cannot converge at all below a certain link speed: the cycle
/// settles wherever `spare > STEP / (1 - BACKOFF)`, which for a 500 kbps step is
/// 1667 kbps. Measured on a link with ~1550 kbps spare, `0.7 * 1664 + 500` is an
/// exact fixed point, so the same damaging level recurred on schedule forever.
/// 64 kbps puts that floor at ~213 kbps instead.
pub const TILE_CEILING_CREEP_KBPS: u32 = 64;
/// Multiplicative decrease on strain. Matches the video adaptor's
/// `decrease_factor` so the two react to congestion at the same rate.
pub const TILE_CEILING_BACKOFF: f32 = 0.7;

/// Learns how much bandwidth refinement may actually use, by experiment.
///
/// # Why the gap alone is not enough
///
/// [`tile_budget_kbps`] offers a quarter of `adaptor_target - media_kbps`, and
/// that gap is only *demonstrated* spare capacity when the encoder has actually
/// been filling the link. On a low-motion screen it has not: the encoder is
/// **content** limited, so video alone never congests anything, so the adaptor's
/// AIMD ratchets its target all the way to the quality mode's ceiling (28 Mbps
/// on `TextDesktop`) without ever testing what the link can carry. A quarter of
/// that un-validated gap can exceed the real spare capacity — and it does so
/// precisely on a still screen, which is exactly when refinement runs.
///
/// The failure is invisible in the obvious places: the link drops nothing, so
/// packet loss stays at zero. What happens instead is that tile bytes fill the
/// shared congestion window, the *video* pump's datagrams no longer fit, and the
/// adaptor reads that backpressure as congestion and cuts the **video** bitrate
/// 30%. Measured on a 2500 kbps link, that held the video target at ~42% of
/// where the same link sat with refinement switched off.
///
/// So the ceiling is learned the same way the video bitrate is: additive
/// increase while clean, multiplicative decrease on strain — and the decrease is
/// anchored to what was **actually spent**, not to the previous ceiling, because
/// the ceiling may sit far above the level that did the damage.
#[derive(Debug, Clone)]
pub struct TileThrottle {
    ceiling_kbps: u32,
    /// Highest level not yet known to hurt — TCP's `ssthresh` in all but name.
    /// Below it the ceiling ramps; above it it creeps.
    safe_kbps: u32,
    /// Whether the window just closed was strained, and so granted nothing.
    ///
    /// Distinguishes "refinement declined its grant" from "refinement was never
    /// given one" — `spent_kbps` is zero in both cases and cannot tell them
    /// apart. A recovery window is allowed to grow the ceiling without spend
    /// evidence, because it had no opportunity to produce any; otherwise a link
    /// that strains every other window could never climb out of the floor.
    ///
    /// That concession does let a chronically lossy link ratchet the ceiling up
    /// without evidence, so the growth it permits is a *creep*, not a step. The
    /// ratchet is bounded three ways: by `gap`, by `ceiling_was_binding`, and —
    /// decisively — by the fact that the moment it actually causes backpressure
    /// the backoff fires, pins `safe_kbps`, and everything above that creeps
    /// anyway. Refusing the concession outright was measured to cost a third of
    /// all refinement on lossy links that had zero backpressure, i.e. links
    /// refinement was demonstrably not harming.
    last_window_strained: bool,
}

impl Default for TileThrottle {
    fn default() -> Self {
        Self::new()
    }
}

impl TileThrottle {
    pub fn new() -> Self {
        Self {
            ceiling_kbps: TILE_CEILING_MIN_KBPS,
            // Nothing is known to hurt yet, so the initial ramp is the fast one.
            safe_kbps: u32::MAX,
            last_window_strained: false,
        }
    }

    /// The learned ceiling, for diagnostics.
    pub fn ceiling(&self) -> u32 {
        self.ceiling_kbps
    }

    /// Fold in one status window and return the budget for the next.
    ///
    /// `spent_kbps` is the tile bandwidth actually used over the window just
    /// closed — the evidence the ceiling is learned from.
    #[allow(clippy::too_many_arguments)]
    pub fn observe(
        &mut self,
        spent_kbps: u32,
        adaptor_target: u32,
        media_kbps: u32,
        pressure: f32,
        loss: f32,
        oversized_keyframe: bool,
        streaming: bool,
        cap_kbps: u32,
    ) -> u32 {
        let strained = tiles_strained(pressure, loss, oversized_keyframe, streaming);
        if strained {
            // Only learn from strain refinement could plausibly have caused,
            // and `pressure` is the signal that actually implicates it: it means
            // our own sending outran the congestion window. Packet loss with no
            // backpressure is the link being lossy on its own — video was going
            // to lose those packets regardless — so lowering the tile ceiling
            // for it is a false attribution that throttles refinement on
            // precisely the links where it was never the problem.
            if spent_kbps > 0 && pressure > 0.0 {
                let backed_off =
                    ((spent_kbps as f32 * TILE_CEILING_BACKOFF) as u32).max(TILE_CEILING_MIN_KBPS);
                self.safe_kbps = backed_off;
                self.ceiling_kbps = backed_off;
            }
            self.last_window_strained = true;
            return 0;
        }
        let gap = tile_budget_kbps(
            adaptor_target,
            media_kbps,
            pressure,
            loss,
            oversized_keyframe,
            streaming,
            cap_kbps,
        );

        // Grow the ceiling ONLY on evidence, which means two things had to be
        // true of the window just closed: the ceiling is what held refinement
        // back (rather than the gap), and refinement actually used most of what
        // it was granted.
        //
        // Without this the learned value is thrown away. The ceiling climbs a
        // flat step per clean window while the gap it is meant to bound grows
        // only a quarter of the adaptor's own step, so within about two windows
        // the ceiling overtakes the gap and stops binding — the backoff keeps
        // correctly landing it near the safe level, and the very next window
        // discards that answer and reverts to the raw gap. Measured on a
        // constrained link, the ceiling bound the budget in 2 of 29 windows.
        //
        // This is the rule TCP applies when it is application-limited rather
        // than window-limited: a grant you did not spend is no evidence the
        // link would have carried more.
        let ceiling_was_binding = self.ceiling_kbps <= gap;
        // A window that was granted nothing is not a refusal, and must not be
        // read as one. `spent_kbps` is zero both when refinement declined its
        // grant and when it never had one; without this distinction a link that
        // strains every other window can never climb out of the floor, because
        // every recovery window follows a zeroed one.
        let judgeable = !self.last_window_strained;
        let used_its_grant = spent_kbps.saturating_mul(2) >= self.ceiling_kbps;
        if ceiling_was_binding && (!judgeable || used_its_grant) {
            // A window that produced no evidence buys only a creep, never a
            // step: it is a concession to "you had no chance to prove
            // yourself", not proof of anything.
            let step = if !judgeable || self.ceiling_kbps >= self.safe_kbps {
                TILE_CEILING_CREEP_KBPS
            } else {
                TILE_CEILING_STEP_KBPS
            };
            self.ceiling_kbps = self
                .ceiling_kbps
                .saturating_add(step)
                .min(crate::config::MAX_TILE_KBPS);
        }
        self.last_window_strained = false;
        gap.min(self.ceiling_kbps)
    }
}

/// Combine the host's standing cap with a client's `BitrateLimit`. A client can
/// only narrow the cap, never widen it.
pub fn effective_cap(host_cap: Option<u32>, client_limit: Option<u32>) -> Option<u32> {
    match (host_cap, client_limit) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, b) => b,
    }
}

/// Combine the host's frame rate with a client's `preferred_fps`. Same idiom as
/// [`effective_cap`]: the client can only narrow, never widen.
///
/// `client_pref == 0` is "no preference" (the field is not optional on the
/// wire), and yields the host's own value.
pub fn effective_fps(host_fps: u32, client_pref: u32) -> u32 {
    use crate::config::{MAX_TARGET_FPS, MIN_TARGET_FPS};
    let host = host_fps.clamp(MIN_TARGET_FPS, MAX_TARGET_FPS);
    if client_pref == 0 {
        host
    } else {
        host.min(client_pref.clamp(MIN_TARGET_FPS, MAX_TARGET_FPS))
    }
}

/// Clamp a bitrate target to a hard cap, if one is set.
pub fn clamp_to_cap(kbps: u32, cap: Option<u32>) -> u32 {
    match cap {
        Some(c) => kbps.min(c),
        None => kbps,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use directdesk_shared::adapt::{AdaptConfig, BitrateAdaptor};
    use directdesk_shared::protocol::QualityMode;

    // -- rate limiter ------------------------------------------------------

    #[test]
    fn rate_limiter_allows_then_blocks() {
        let mut r = RateLimiter::new(500);
        assert!(r.allow(0));
        assert!(!r.allow(1));
        assert!(!r.allow(499));
        assert!(r.allow(500));
        assert!(!r.allow(999));
        assert!(r.allow(1_000));
    }

    #[test]
    fn rate_limiter_first_call_always_passes() {
        let mut r = RateLimiter::new(500);
        assert!(r.allow(9_999_999));
    }

    #[test]
    fn overrun_is_silent_when_the_link_keeps_up() {
        assert_eq!(overrun_signal(8_000, 8_000), 0.0);
        assert_eq!(
            overrun_signal(8_000, 9_000),
            0.0,
            "headroom is not congestion"
        );
        assert_eq!(overrun_signal(8_000, 7_500), 0.0, "within the 15% slack");
    }

    #[test]
    fn overrun_reports_the_shortfall_when_the_encoder_outruns_the_link() {
        // The measured case: a 13 Mbps encoder on a link carrying 7.3 Mbps.
        let s = overrun_signal(13_000, 7_313);
        assert!(s > 0.4 && s < 0.5, "got {s}");
        // Well past the adaptor's 2% congestion threshold, so it will back off.
        assert!(s > 0.02);
    }

    #[test]
    fn overrun_needs_both_numbers_to_mean_anything() {
        assert_eq!(overrun_signal(0, 5_000), 0.0);
        assert_eq!(
            overrun_signal(5_000, 0),
            0.0,
            "an unmeasured link is not a congested one"
        );
    }

    #[test]
    fn overrun_stays_in_the_unit_range() {
        for (e, c) in [(1u32, 1u32), (u32::MAX, 1), (1, u32::MAX), (12_000, 300)] {
            let s = overrun_signal(e, c);
            assert!((0.0..=1.0).contains(&s), "{e}/{c} gave {s}");
        }
    }

    #[test]
    fn overrun_drives_the_adaptor_downward() {
        // The whole point: this signal must actually move the bitrate.
        let mut a = BitrateAdaptor::new(AdaptConfig::for_mode(QualityMode::Balanced));
        let start = a.current();
        assert_eq!(a.observe(0, 0.0, 1.0), None, "establish a baseline");
        let signal = overrun_signal(13_000, 7_313);
        let next = a
            .observe(1_500, signal, 1.0)
            .expect("an overrun must lower the bitrate");
        assert!(next < start, "{next} should be below {start}");
    }

    #[test]
    fn tiles_never_spend_a_link_that_is_already_strained() {
        // Every strain signal must zero the budget outright, not scale it.
        // These are the exact inputs that would otherwise make the adaptor cut
        // video bitrate and leave no trace of why.
        assert_eq!(
            tile_budget_kbps(20_000, 2_000, 0.01, 0.0, false, true, 0),
            0
        );
        assert_eq!(
            tile_budget_kbps(20_000, 2_000, 0.0, 0.05, false, true, 0),
            0
        );
        assert_eq!(tile_budget_kbps(20_000, 2_000, 0.0, 0.0, true, true, 0), 0);
        assert_eq!(
            tile_budget_kbps(20_000, 2_000, 0.0, 0.0, false, false, 0),
            0
        );
    }

    #[test]
    fn tile_budget_kbps_and_tile_throttle_agree_on_strain() {
        // `tile_budget_kbps` and `TileThrottle::observe` each decide, on their
        // own, whether a window is too strained to spend anything. Both now
        // delegate that call to `tiles_strained`, but they are still two call
        // sites and could be edited out of step in the future — a window one
        // judged strained getting a grant from the other is precisely the
        // hazard the doc comment on `tiles_strained` warns about. Sweep every
        // combination of the four strain inputs and check both functions
        // against the shared predicate, which pins them to each other.
        //
        // `adaptor_target` / `media_kbps` are fixed so the measured headroom
        // (4_500 kbps) is always positive: that isolates "zero because
        // strained" from "zero because there was no headroom to begin with",
        // which is a different, already-covered case.
        const ADAPTOR_TARGET: u32 = 20_000;
        const MEDIA_KBPS: u32 = 2_000;
        const CAP_KBPS: u32 = 0;

        for &pressure in &[0.0_f32, 0.3] {
            for &loss in &[0.0_f32, 0.05] {
                for &oversized_keyframe in &[false, true] {
                    for &streaming in &[true, false] {
                        let strained =
                            tiles_strained(pressure, loss, oversized_keyframe, streaming);

                        let budget = tile_budget_kbps(
                            ADAPTOR_TARGET,
                            MEDIA_KBPS,
                            pressure,
                            loss,
                            oversized_keyframe,
                            streaming,
                            CAP_KBPS,
                        );
                        assert_eq!(
                            budget == 0,
                            strained,
                            "tile_budget_kbps vs tiles_strained mismatch: \
                             pressure={pressure}, loss={loss}, \
                             oversized_keyframe={oversized_keyframe}, streaming={streaming}"
                        );

                        // Fresh throttle per case: only the strain branch is
                        // under test, not the ceiling's cross-window learning.
                        let mut throttle = TileThrottle::new();
                        let throttled = throttle.observe(
                            0,
                            ADAPTOR_TARGET,
                            MEDIA_KBPS,
                            pressure,
                            loss,
                            oversized_keyframe,
                            streaming,
                            CAP_KBPS,
                        );
                        assert_eq!(
                            throttled == 0,
                            strained,
                            "TileThrottle::observe vs tiles_strained mismatch: \
                             pressure={pressure}, loss={loss}, \
                             oversized_keyframe={oversized_keyframe}, streaming={streaming}"
                        );

                        // And therefore, transitively, the two public
                        // functions agree with each other on every strain
                        // combination in the grid.
                        assert_eq!(
                            budget == 0,
                            throttled == 0,
                            "tile_budget_kbps and TileThrottle::observe disagree: \
                             pressure={pressure}, loss={loss}, \
                             oversized_keyframe={oversized_keyframe}, streaming={streaming}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn tiles_claim_only_a_quarter_of_demonstrated_headroom() {
        // The static-screen case the feature exists for: the adaptor still has
        // 20 Mbps allocated while a suppressed capture emits almost nothing.
        assert_eq!(
            tile_budget_kbps(20_000, 0, 0.0, 0.0, false, true, 0),
            5_000,
            "a quarter of the measured gap, not the whole gap"
        );
        // No headroom means no tiles, never a negative or wrapped value.
        assert_eq!(tile_budget_kbps(4_000, 8_000, 0.0, 0.0, false, true, 0), 0);
        assert_eq!(tile_budget_kbps(0, 0, 0.0, 0.0, false, true, 0), 0);
    }

    #[test]
    fn the_configured_ceiling_narrows_but_never_widens() {
        // Same idiom as `effective_cap`: a cap may only lower the figure.
        assert_eq!(
            tile_budget_kbps(20_000, 0, 0.0, 0.0, false, true, 1_000),
            1_000
        );
        assert_eq!(
            tile_budget_kbps(20_000, 0, 0.0, 0.0, false, true, 99_000),
            5_000
        );
        // 0 means "no explicit ceiling" — it must not mean "no bandwidth".
        assert_eq!(tile_budget_kbps(20_000, 0, 0.0, 0.0, false, true, 0), 5_000);
    }

    #[test]
    fn the_tile_ceiling_starts_conservative_and_climbs_additively() {
        let mut t = TileThrottle::new();
        assert_eq!(t.ceiling(), TILE_CEILING_MIN_KBPS);
        // A huge gap must NOT be taken on trust: the ceiling is what binds
        // until the link has actually carried that much without complaint.
        let first = t.observe(0, 28_000, 0, 0.0, 0.0, false, true, 0);
        assert_eq!(first, TILE_CEILING_MIN_KBPS);
        // Spending the whole grant on a clean link is the evidence that earns
        // the next step up.
        let mut budget = first;
        for _ in 0..8 {
            budget = t.observe(budget, 28_000, 0, 0.0, 0.0, false, true, 0);
        }
        assert!(budget > first, "a clean link must let refinement grow");
    }

    #[test]
    fn a_grant_that_was_not_spent_is_no_evidence_the_link_would_carry_more() {
        // Application-limited, not ceiling-limited: refinement had nothing to
        // send. Raising the ceiling here would be inventing capacity from
        // silence — and it is exactly how the learned value gets discarded.
        let mut t = TileThrottle::new();
        let before = t.ceiling();
        for _ in 0..20 {
            t.observe(0, 28_000, 0, 0.0, 0.0, false, true, 0);
        }
        assert_eq!(t.ceiling(), before, "silence must not raise the ceiling");
    }

    #[test]
    fn link_loss_without_backpressure_is_not_blamed_on_refinement() {
        // A lossy link drops packets whether or not tiles are running. Reading
        // that as "refinement overfilled the window" throttles it hardest on
        // exactly the links where it was never the cause — measured as a third
        // less refinement on a 3% link whose backpressure count was zero.
        // The budget is still zeroed (loss means spend nothing), but the
        // *learned* ceiling must survive.
        let mut t = TileThrottle::new();
        let mut budget = 0;
        for _ in 0..10 {
            budget = t.observe(budget, 28_000, 0, 0.0, 0.0, false, true, 0);
        }
        let learned = t.ceiling();
        assert!(learned > TILE_CEILING_MIN_KBPS);

        // Pure packet loss, no backpressure at all.
        assert_eq!(t.observe(budget, 28_000, 0, 0.0, 0.05, false, true, 0), 0);
        assert_eq!(t.ceiling(), learned, "link loss must not lower the ceiling");

        // Backpressure, on the other hand, does implicate refinement.
        assert_eq!(t.observe(budget, 28_000, 0, 0.2, 0.0, false, true, 0), 0);
        assert!(t.ceiling() < learned, "backpressure must lower it");
    }

    #[test]
    fn a_window_that_was_granted_nothing_is_not_counted_as_a_refusal() {
        // The recovery window after any strain is granted 0, so it necessarily
        // spends 0. Treating that as "refinement declined its grant" would mean
        // a link that strains every other window could never climb out of the
        // floor, because every recovery window follows a zeroed one.
        let mut t = TileThrottle::new();
        // Strain immediately, so the ceiling is floored and the next window is
        // a recovery one.
        t.observe(2_000, 28_000, 0, 0.2, 0.0, false, true, 0);
        let floored = t.ceiling();

        // Clean window, but spent is 0 because the previous grant was 0.
        let grant = t.observe(0, 28_000, 0, 0.0, 0.0, false, true, 0);
        assert!(
            t.ceiling() > floored,
            "recovery stalled: ceiling stuck at {floored}"
        );
        assert!(grant > 0);
    }

    #[test]
    fn probing_above_a_known_safe_level_creeps_rather_than_steps() {
        // Overshoot is not symmetric with under-use: it costs the VIDEO a 30%
        // multiplicative cut that takes seconds to recover, while under-use
        // costs only refinement latency. A flat step also cannot converge below
        // `STEP / (1 - BACKOFF)` of spare capacity — 1667 kbps at a 500 step,
        // which is why a link with ~1550 spare sat on an exact fixed point.
        let mut t = TileThrottle::new();
        let mut budget = 0;
        for _ in 0..12 {
            budget = t.observe(budget, 28_000, 0, 0.0, 0.0, false, true, 0);
        }
        // Establish a safe level by hurting it once.
        t.observe(budget, 28_000, 0, 0.2, 0.0, false, true, 0);
        let safe = t.ceiling();

        // Climbing back through the safe level must switch from step to creep.
        let mut prev = safe;
        let mut budget = t.observe(0, 28_000, 0, 0.0, 0.0, false, true, 0);
        for _ in 0..6 {
            let before = t.ceiling();
            budget = t.observe(budget, 28_000, 0, 0.0, 0.0, false, true, 0);
            let grew = t.ceiling().saturating_sub(before);
            assert!(
                grew <= TILE_CEILING_STEP_KBPS,
                "grew {grew} in one window from {before}"
            );
            prev = t.ceiling();
        }
        assert!(
            prev < safe.saturating_add(TILE_CEILING_STEP_KBPS * 3),
            "creeping above the safe level should be slow, reached {prev} from {safe}"
        );
    }

    /// One window of an application-limited link: refinement can only spend
    /// what it has work for, however much it is granted.
    fn spend(grant: u32, work_available: u32) -> u32 {
        grant.min(work_available)
    }

    #[test]
    fn a_floored_ceiling_recovers_as_soon_as_there_is_work_to_prove_it() {
        // The application-limited worry: growth requires refinement to spend
        // its grant, but on a quiet screen there is nothing to send. If a
        // strain event floors the ceiling, what lifts it again?
        //
        // Answer: work does — and the ceiling only *matters* when there is
        // work, so it recovers exactly when it needs to.
        let mut t = TileThrottle::new();
        // Spending only 500 when strain hits backs off to 350, which clamps to
        // the floor — the worst case for recovery.
        t.observe(500, 28_000, 0, 0.2, 0.0, false, true, 0);
        let floored = t.ceiling();
        assert_eq!(floored, TILE_CEILING_MIN_KBPS);

        // A quiet screen: almost nothing to refine. The ceiling does not climb
        // — correctly, there is no evidence — and that costs nothing, because
        // the trickle is nowhere near the grant anyway.
        let mut grant = t.observe(0, 28_000, 0, 0.0, 0.0, false, true, 0);
        for _ in 0..20 {
            grant = t.observe(spend(grant, 40), 28_000, 0, 0.0, 0.0, false, true, 0);
        }
        assert!(
            grant >= 40,
            "a quiet screen is never actually limited by the ceiling"
        );

        // Now the screen gets busy — a scroll, a window opening. Refinement has
        // real work, spends its grant, and the ceiling climbs back out.
        let before_busy = t.ceiling();
        for _ in 0..12 {
            grant = t.observe(spend(grant, 100_000), 28_000, 0, 0.0, 0.0, false, true, 0);
        }
        assert!(
            t.ceiling() > before_busy,
            "a busy screen must lift a floored ceiling; stuck at {before_busy}"
        );

        // Recovery is deliberately at the CREEP rate, not the step rate: the
        // backoff set `safe` to this level, so climbing past it is probing
        // territory already known to hurt. ~64 kbps per second is slow — a few
        // seconds of softer text — and that is the correct trade against
        // re-triggering a 30% cut to the video bitrate, which costs far longer
        // to undo. Pinned so nobody "optimises" it into a step.
        let grew = t.ceiling() - before_busy;
        assert!(
            grew <= 12 * TILE_CEILING_CREEP_KBPS,
            "recovery above the safe level must creep, grew {grew} in 12 windows"
        );
    }

    #[test]
    fn repeated_loss_without_backpressure_drifts_only_at_the_creep_rate() {
        // A recovery window is allowed to grow the ceiling without spend
        // evidence, because it had no chance to produce any. On a chronically
        // lossy link that concession does let the ceiling drift upward — and
        // that is a deliberate trade, not an oversight.
        //
        // Refusing it outright was measured to cost a third of all refinement
        // on lossy links whose backpressure count was *zero*, i.e. links
        // refinement was demonstrably not harming. Allowing it at the full step
        // rate is the ratchet that reverts the budget to the raw unvalidated
        // gap. So it is allowed, at the creep rate: 8x slower, bounded by the
        // gap, and self-correcting — the first window it actually causes
        // backpressure, the backoff fires and pins `safe`.
        let mut t = TileThrottle::new();
        let start = t.ceiling();
        for _ in 0..30 {
            // Lossy, but never any backpressure.
            t.observe(0, 28_000, 0, 0.0, 0.05, false, true, 0);
            t.observe(0, 28_000, 0, 0.0, 0.0, false, true, 0);
        }
        let drift = t.ceiling() - start;
        assert!(
            drift <= 30 * TILE_CEILING_CREEP_KBPS,
            "drifted {drift} over 30 lossy cycles — that is step-rate, not creep-rate"
        );

        // And it self-corrects the moment it actually costs anything.
        let raised = t.ceiling();
        t.observe(raised, 28_000, 0, 0.3, 0.0, false, true, 0);
        assert!(
            t.ceiling() < raised,
            "backpressure must claw back the drift; {} vs {raised}",
            t.ceiling()
        );
    }

    #[test]
    fn a_genuine_backoff_still_grants_its_recovery_window() {
        // The other half: a window whose strain DID lower the ceiling must be
        // allowed to grow again without spend evidence, or a link that strains
        // every other window can never climb out.
        let mut t = TileThrottle::new();
        t.observe(2_000, 28_000, 0, 0.3, 0.0, false, true, 0);
        let floored = t.ceiling();
        t.observe(0, 28_000, 0, 0.0, 0.0, false, true, 0);
        assert!(
            t.ceiling() > floored,
            "recovery stalled at {floored} after a real backoff"
        );
    }

    #[test]
    fn a_link_that_never_strains_is_still_bounded_by_the_gap() {
        // `safe_kbps` starts at `u32::MAX`, so a link that never strains stays
        // in fast-ramp mode forever. That must not run away — the gap is the
        // backstop, and the configured cap narrows it further.
        let mut t = TileThrottle::new();
        let mut grant = 0;
        for _ in 0..200 {
            grant = t.observe(spend(grant, 100_000), 8_000, 0, 0.0, 0.0, false, true, 0);
        }
        // gap = (8000 - 0) / 4 = 2000, and nothing may exceed it.
        assert_eq!(grant, 2_000);

        let mut t = TileThrottle::new();
        let mut grant = 0;
        for _ in 0..200 {
            grant = t.observe(
                spend(grant, 100_000),
                28_000,
                0,
                0.0,
                0.0,
                false,
                true,
                1_500,
            );
        }
        assert_eq!(grant, 1_500, "the configured cap must still bind");
    }

    #[test]
    fn the_ceiling_stops_climbing_once_it_outruns_the_gap() {
        // The bug this rule fixes: the ceiling used to climb a flat step every
        // clean window regardless, overtake the gap within ~2 windows, and stop
        // binding — so the backoff's correct answer was thrown away and the
        // budget reverted to the raw, unvalidated gap.
        let mut t = TileThrottle::new();
        // Small gap: a nearly-saturated link, so the gap binds, not the ceiling.
        let small_target = 1_200; // gap = 1200/4 = 300 kbps
        let mut budget = 0;
        for _ in 0..40 {
            budget = t.observe(budget, small_target, 0, 0.0, 0.0, false, true, 0);
        }
        assert_eq!(budget, 300, "the gap should bind here");
        assert_eq!(
            t.ceiling(),
            TILE_CEILING_MIN_KBPS,
            "the ceiling must not drift upward while the gap is what binds"
        );
    }

    #[test]
    fn strain_backs_the_ceiling_off_from_what_was_actually_spent() {
        let mut t = TileThrottle::new();
        for _ in 0..20 {
            t.observe(3_000, 28_000, 0, 0.0, 0.0, false, true, 0);
        }
        let before = t.ceiling();
        assert!(before > 5_000, "should have climbed, got {before}");

        // Backpressure while spending 2000 kbps: the ceiling must anchor to the
        // level that did the damage, NOT to its own (much higher) value —
        // otherwise it backs off 30% of a number the link never saw and keeps
        // overshooting for many more windows.
        assert_eq!(t.observe(2_000, 28_000, 0, 0.05, 0.0, false, true, 0), 0);
        assert_eq!(t.ceiling(), 1_400);
    }

    #[test]
    fn strain_with_no_tile_traffic_does_not_blame_refinement() {
        // Video congested the link entirely on its own. That window says
        // nothing about how much refinement the link would tolerate, so the
        // learned ceiling must be left alone.
        let mut t = TileThrottle::new();
        for _ in 0..10 {
            t.observe(1_000, 28_000, 0, 0.0, 0.0, false, true, 0);
        }
        let before = t.ceiling();
        assert_eq!(t.observe(0, 28_000, 12_000, 0.4, 0.0, false, true, 0), 0);
        assert_eq!(t.ceiling(), before);
    }

    #[test]
    fn the_ceiling_converges_instead_of_sawtoothing() {
        // The bug this class of test exists for: with a free-running gap the
        // budget jumped straight back to a quarter of an un-validated 28 Mbps
        // every time strain cleared, so it re-overshot forever. Model a link
        // whose true spare is 2000 kbps and check the offered budget settles
        // at or below it rather than oscillating over it.
        // AIMD probes above the limit periodically — that is how it finds the
        // limit at all, and the video adaptor does exactly the same. So the
        // property is not "never overshoots", it is "never overshoots by
        // much": the old free-running gap offered a quarter of an unvalidated
        // 28 Mbps (7000 kbps against 2000 of real spare, a 3.5x overshoot),
        // which is what cut the video bitrate. One additive step is not.
        const TRUE_SPARE: u32 = 2_000;
        let unvalidated = tile_budget_kbps(28_000, 0, 0.0, 0.0, false, true, 0);
        assert!(
            unvalidated > TRUE_SPARE * 3,
            "precondition: the raw gap really is wildly optimistic here ({unvalidated})"
        );

        let mut t = TileThrottle::new();
        let mut last = 0;
        let mut worst = 0;
        let mut best = 0;
        for window in 0..80 {
            let strained = last > TRUE_SPARE;
            last = t.observe(
                last,
                28_000, // the adaptor's aspiration, never tested by a content-limited encoder
                0,
                if strained { 0.1 } else { 0.0 },
                0.0,
                false,
                true,
                0,
            );
            // Ignore the ramp; judge the steady state.
            if window >= 20 {
                worst = worst.max(last);
                best = best.max(last.min(TRUE_SPARE));
            }
        }
        assert!(
            worst <= TRUE_SPARE + TILE_CEILING_STEP_KBPS,
            "overshoot of {worst} exceeds one additive step above real spare"
        );
        // And it must still do useful work — a throttle that converges to zero
        // would pass the assertion above while disabling the whole feature.
        assert!(
            best >= TRUE_SPARE / 2,
            "throttle strangled refinement: best steady-state budget was {best}"
        );
    }

    // -- M5: windowed delivery reporting -----------------------------------

    #[test]
    fn window_delivery_is_matched_window_math() {
        let d = WindowDelivery {
            sent: 45,
            offered: 60,
            bytes: 1_000_000,
            dt_ms: 1_000,
        };
        assert!((d.delivery_ratio() - 0.75).abs() < 1e-6);
        assert!((d.backpressure_ratio() - 0.25).abs() < 1e-6);
        // 1,000,000 bytes in 1 s = 8,000 kbps.
        assert_eq!(d.throughput_kbps(), 8_000);
    }

    #[test]
    fn idle_window_reports_full_delivery_not_loss() {
        // The old bug read a lifetime send count against a fresh client window
        // and called a healthy link ~50% lossy. A matched window with nothing
        // offered delivered everything it was asked to.
        let idle = WindowDelivery {
            sent: 0,
            offered: 0,
            bytes: 0,
            dt_ms: 1_000,
        };
        assert_eq!(idle.delivery_ratio(), 1.0);
        assert_eq!(idle.backpressure_ratio(), 0.0);
        assert_eq!(idle.throughput_kbps(), 0);
    }

    #[test]
    fn window_delivery_cannot_divide_by_a_zero_length_window() {
        let z = WindowDelivery {
            sent: 10,
            offered: 10,
            bytes: 500,
            dt_ms: 0,
        };
        assert_eq!(z.throughput_kbps(), 0);
    }

    // -- M5: congestion signal + overrun gating ----------------------------

    #[test]
    fn congestion_ignores_overrun_until_warm() {
        // Cold: a big overrun ratio is discarded; only real loss/backpressure
        // count. This is what stops the spurious start-up downshift.
        assert_eq!(congestion_signal(0.0, 0.0, 0.9, false), 0.0);
        assert!((congestion_signal(0.05, 0.0, 0.9, false) - 0.05).abs() < 1e-6);
        assert!((congestion_signal(0.0, 0.2, 0.9, false) - 0.2).abs() < 1e-6);
        // Warm: the overrun is folded in.
        assert!((congestion_signal(0.0, 0.0, 0.9, true) - 0.9).abs() < 1e-6);
        // Real loss wins whenever it is larger, warm or not.
        assert!((congestion_signal(0.5, 0.1, 0.2, true) - 0.5).abs() < 1e-6);
    }

    // -- StatusWindow --------------------------------------------------------

    #[test]
    fn status_window_first_tick_has_no_previous_sample() {
        // Nothing came before, so `saturating_sub` against a zero baseline
        // makes the whole lifetime counter this window's delta rather than
        // underflowing.
        let mut w = StatusWindow::new(0);
        let (delivery, warm) = w.close(1_000, 60, 120_000, 0);
        assert_eq!(delivery.sent, 60);
        assert_eq!(delivery.offered, 60, "nothing was backpressured yet");
        assert_eq!(delivery.bytes, 120_000);
        assert_eq!(
            delivery.dt_ms, 1_000,
            "measured against the seed passed to new()"
        );
        assert!(!warm, "a single interval can never be warm");
    }

    #[test]
    fn status_window_warm_gate_needs_both_intervals_and_frames() {
        let mut w = StatusWindow::new(0);
        let mut now = 0u64;
        let mut sent = 0u64;

        // Below OVERRUN_WARMUP_INTERVALS closes: never warm, even though every
        // window here sends plenty of frames.
        for i in 1..=OVERRUN_WARMUP_INTERVALS {
            now += 1_000;
            sent += 100;
            let (_, warm) = w.close(now, sent, 0, 0);
            assert!(
                !warm,
                "interval {i} of {OVERRUN_WARMUP_INTERVALS} must not be warm"
            );
        }

        // Past the interval count now, but this window sent too few frames to
        // trust the overrun ratio.
        now += 1_000;
        sent += OVERRUN_MIN_FRAMES - 1;
        let (_, warm) = w.close(now, sent, 0, 0);
        assert!(!warm, "win_sent below OVERRUN_MIN_FRAMES must not be warm");

        // Enough intervals AND enough frames sent this window: now it's warm.
        now += 1_000;
        sent += OVERRUN_MIN_FRAMES;
        let (_, warm) = w.close(now, sent, 0, 0);
        assert!(warm, "past warm-up with enough frames sent must be warm");
    }

    #[test]
    fn status_window_delta_matches_a_normal_tick() {
        let mut w = StatusWindow::new(0);
        w.close(1_000, 100, 1_000_000, 5); // seed a previous sample
        let (delivery, _) = w.close(2_000, 160, 1_500_000, 10);
        assert_eq!(
            delivery,
            WindowDelivery {
                sent: 60,
                offered: 65,
                bytes: 500_000,
                dt_ms: 1_000,
            }
        );
    }

    // -- window_congestion ---------------------------------------------------

    #[test]
    fn window_congestion_lets_an_oversized_keyframe_override_everything() {
        // Even an otherwise pristine window must read as full congestion:
        // nothing of the refused keyframe reached the wire.
        let clean = WindowDelivery {
            sent: 60,
            offered: 60,
            bytes: 1_000_000,
            dt_ms: 1_000,
        };
        assert_eq!(window_congestion(0.0, clean, 0.0, true, true), 1.0);
    }

    #[test]
    fn window_congestion_matches_congestion_signal_when_not_oversized() {
        let d = WindowDelivery {
            sent: 45,
            offered: 60,
            bytes: 1_000_000,
            dt_ms: 1_000,
        };
        let expected = congestion_signal(0.02, d.backpressure_ratio(), 0.3, true);
        assert_eq!(window_congestion(0.02, d, 0.3, true, false), expected);
    }

    // -- M5: bitrate caps --------------------------------------------------

    #[test]
    fn caps_narrow_but_never_widen() {
        assert_eq!(effective_cap(None, None), None);
        assert_eq!(effective_cap(Some(5_000), None), Some(5_000));
        assert_eq!(effective_cap(None, Some(3_000)), Some(3_000));
        assert_eq!(
            effective_cap(Some(5_000), Some(3_000)),
            Some(3_000),
            "client narrows"
        );
        assert_eq!(
            effective_cap(Some(2_000), Some(9_000)),
            Some(2_000),
            "client cannot widen"
        );
        assert_eq!(clamp_to_cap(8_000, Some(3_000)), 3_000);
        assert_eq!(clamp_to_cap(2_000, Some(3_000)), 2_000);
        assert_eq!(clamp_to_cap(8_000, None), 8_000);
    }

    #[test]
    fn client_fps_narrows_but_never_widens() {
        assert_eq!(effective_fps(60, 0), 60, "0 is 'no preference'");
        assert_eq!(effective_fps(60, 30), 30, "client narrows");
        assert_eq!(effective_fps(30, 60), 30, "client cannot widen");
        assert_eq!(effective_fps(60, 1), 1);
        assert_eq!(
            effective_fps(60, 99_999),
            60,
            "an absurd preference is clamped, then still cannot widen"
        );
    }

    #[test]
    fn bitrate_limit_clamps_the_adaptor_output() {
        // The adaptor free-runs in Balanced (start 8000). A 3000 kbps client
        // limit must be a hard ceiling on what the encoder is actually asked for.
        let a = BitrateAdaptor::new(AdaptConfig::for_mode(QualityMode::Balanced));
        let cap = effective_cap(None, Some(3_000));
        assert_eq!(clamp_to_cap(a.current(), cap), 3_000);
    }

    // -- M5: adaptor drive (synthetic status windows) ----------------------

    /// One synthetic `status_loop` window.
    struct Window {
        loss: f32,
        sent: u64,
        backpressured: u64,
        encoder_kbps: u32,
        carried_kbps: u32,
    }

    /// Reproduce the adaptor drive from `status_loop` without a live
    /// connection: build the exact congestion number the loop would and observe
    /// the adaptor. Returns (current target, Some(new) when it changed).
    fn drive(a: &mut BitrateAdaptor, w: &Window, now_ms: u64, interval: u32) -> (u32, Option<u32>) {
        let delivery = WindowDelivery {
            sent: w.sent,
            offered: w.sent + w.backpressured,
            bytes: 0,
            dt_ms: STATUS_INTERVAL_MS,
        };
        let warm = interval > OVERRUN_WARMUP_INTERVALS && w.sent >= OVERRUN_MIN_FRAMES;
        let overrun = overrun_signal(w.encoder_kbps, w.carried_kbps);
        let congestion = congestion_signal(w.loss, delivery.backpressure_ratio(), overrun, warm);
        let changed = a.observe(now_ms, congestion, 50.0);
        (a.current(), changed)
    }

    #[test]
    fn adaptor_backs_off_on_real_loss_then_recovers() {
        let mut a = BitrateAdaptor::new(AdaptConfig::for_mode(QualityMode::Balanced));
        let start = a.current();
        let clean = Window {
            loss: 0.0,
            sent: 60,
            backpressured: 0,
            encoder_kbps: 8_000,
            carried_kbps: 8_000,
        };
        drive(&mut a, &clean, 0, 1);
        // A window of real transport loss backs the target off.
        let lossy = Window {
            loss: 0.08,
            sent: 60,
            backpressured: 0,
            encoder_kbps: 8_000,
            carried_kbps: 8_000,
        };
        let (after, changed) = drive(&mut a, &lossy, 1_100, 2);
        assert!(
            changed.is_some() && after < start,
            "loss must lower the target ({after} < {start})"
        );
        // Clean windows then raise it back up.
        let mut t = 2_000;
        let mut raised = None;
        for i in 3..40 {
            t += 1_000;
            if let (_, Some(v)) = drive(&mut a, &clean, t, i) {
                raised = Some(v);
                break;
            }
        }
        assert!(
            raised.unwrap() > after,
            "clean windows raise the target back up"
        );
    }

    #[test]
    fn startup_overrun_does_not_spuriously_downshift() {
        let mut a = BitrateAdaptor::new(AdaptConfig::for_mode(QualityMode::Balanced));
        let start = a.current();
        // Encoder 12 Mbps but the link "carried" only 2 Mbps because the stream
        // just began — a pure window artifact, with no real loss.
        let w = Window {
            loss: 0.0,
            sent: 60,
            backpressured: 0,
            encoder_kbps: 12_000,
            carried_kbps: 2_000,
        };
        let mut t = 0;
        for i in 1..=OVERRUN_WARMUP_INTERVALS {
            t += 500;
            let (cur, changed) = drive(&mut a, &w, t, i);
            assert_eq!(
                cur, start,
                "a gated overrun must not move the adaptor during warm-up"
            );
            assert!(changed.is_none());
        }
        // Once warm, the same sustained overrun IS treated as congestion.
        t += 1_100;
        let (cur, changed) = drive(&mut a, &w, t, OVERRUN_WARMUP_INTERVALS + 1);
        assert!(
            changed.is_some() && cur < start,
            "a warm, sustained overrun backs off"
        );
    }

    #[test]
    fn quality_mode_switch_applies_ceiling_and_floor() {
        // Ramp to the Motion ceiling, then switch to LowBandwidth: the current
        // target clamps down into the new, lower range.
        let mut a = BitrateAdaptor::new(AdaptConfig::for_mode(QualityMode::Motion));
        let clean = Window {
            loss: 0.0,
            sent: 60,
            backpressured: 0,
            encoder_kbps: 1,
            carried_kbps: 1,
        };
        let mut t = 0;
        for i in 1..200 {
            t += 2_100;
            drive(&mut a, &clean, t, i);
        }
        assert_eq!(
            a.current(),
            AdaptConfig::for_mode(QualityMode::Motion).ceiling_kbps
        );
        a.set_mode(QualityMode::LowBandwidth, t);
        assert_eq!(
            a.current(),
            AdaptConfig::for_mode(QualityMode::LowBandwidth).ceiling_kbps,
            "clamped down to the new ceiling",
        );

        // A mode with a higher floor lifts a floored-out target up to it.
        let mut b = BitrateAdaptor::new(AdaptConfig::for_mode(QualityMode::LowBandwidth));
        let heavy = Window {
            loss: 0.9,
            sent: 10,
            backpressured: 0,
            encoder_kbps: 1,
            carried_kbps: 1,
        };
        for i in 1..200u32 {
            drive(&mut b, &heavy, i as u64 * 1_100, i);
        }
        assert_eq!(
            b.current(),
            AdaptConfig::for_mode(QualityMode::LowBandwidth).floor_kbps
        );
        b.set_mode(QualityMode::Motion, 999_999);
        assert_eq!(
            b.current(),
            AdaptConfig::for_mode(QualityMode::Motion).floor_kbps,
            "lifted up to the new floor",
        );
    }
}
