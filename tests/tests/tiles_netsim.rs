//! Refinement tiles versus video: the direct proof against the shared
//! congestion-window coupling hazard.
//!
//! Lossless static-region refinement rides a host-opened unidirectional QUIC
//! stream while H.264 video rides datagrams. They never contend for the same
//! send buffer, but they share one congestion window — so unthrottled tiles
//! inflate the host's `backpressured` counter, that becomes `pressure`,
//! `pressure` becomes the `congestion_signal` the [`BitrateAdaptor`] observes,
//! and the adaptor quietly cuts **video** with no packet loss and no obvious
//! cause. QUIC stream priority does not help: it orders streams against each
//! other, not against datagrams.
//!
//! Every row here is a matched pair: the same seed, the same link, the same
//! configuration, run once with tiles off and once with tiles on. Two
//! statements are made about the pair.
//!
//! 1. Refinement does not cost video frames —
//!    [`refinement_costs_no_video_frames`].
//! 2. Refinement does not leave the adaptor's video target lower than it would
//!    have been — [`refinement_does_not_lower_the_video_target`]. This is the
//!    assertion that actually catches the hazard.
//!
//! Both are *relative* statements about a matched pair, never absolute
//! throughput numbers, so nothing here depends on how busy the machine running
//! it is. The whole matrix runs in well under a second of virtual-clock work.
//!
//! The throttle under test is the real one: [`TileThrottle`], fed the same
//! inputs `host::net::status_loop` gives it — including the matched-window
//! `spent_kbps` its learned ceiling is built from — driving the real
//! [`BitrateAdaptor`] through the real [`congestion_signal`]. The shared window
//! itself is modelled by the harness (see [`directdesk_tests::tiles`]) because
//! the netsim has no bandwidth model at all — without it, stream bytes cannot
//! influence datagrams and both assertions above would pass vacuously.
//!
//! # Why these assertions are not vacuous
//!
//! [`unthrottled_tiles_steal_the_window`] is a negative control: the same rows,
//! the same seeds, with the throttle replaced by a fixed allowance. It asserts
//! that the hazard *does* fire — video frames lost by the hundred, the adaptor
//! driven to its floor — which is what gives the positive rows their meaning.
//! If a change made the throttle a no-op the positive rows fail; if a change
//! made tile traffic weightless in the harness the control fails.
//!
//! [`TileThrottle`]: directdesk_host::net::TileThrottle

use directdesk_host::net::{
    congestion_signal, tile_budget_kbps, TileThrottle, TILE_CEILING_BACKOFF,
    TILE_CEILING_CREEP_KBPS, TILE_CEILING_MIN_KBPS, TILE_CEILING_STEP_KBPS,
};
use directdesk_shared::adapt::{AdaptConfig, BitrateAdaptor};
use directdesk_shared::error::Result;
use directdesk_shared::netsim::NetParams;
use directdesk_shared::protocol::QualityMode;
use directdesk_tests::assertions::{assert_all_hashes_ok, assert_strictly_increasing};
use directdesk_tests::{assert_logs_match, Sim, SimConfig, TileSim, STATUS_INTERVAL_MS};

// ---------------------------------------------------------------------------
// Scaffolding
// ---------------------------------------------------------------------------

/// Thirty status windows against a `raise_after_ms` of 3 000, so a run that
/// suffers a multiplicative cut has room to show whether it climbs back.
const DURATION_MS: u64 = 30_000;

/// One link condition, with the seed pinned so the row is diffable.
struct Condition {
    /// Name used in assertion messages.
    label: &'static str,
    /// Netsim seed. Distinct per condition so no two share a loss schedule.
    seed: u64,
    /// Capacity of the shared congestion window, kbps.
    link_kbps: u32,
    /// Loss on the link itself, applied to datagrams by the netsim.
    loss_pct: f32,
}

/// The matrix: a clean link, a lossy link, and a constrained-bandwidth link.
///
/// The encoder here produces a steady ~930 kbps (4 000-byte frames at 30 fps)
/// regardless of its target. That is deliberate and it is the case refinement
/// exists for: a *low-motion* desktop, where a small live region keeps video
/// flowing while most of the screen is static enough to be worth refining. It
/// also means the two runs of a pair do the same amount of encoding work, so
/// their frame counts are directly comparable with no encoder feedback loop in
/// between.
const CONDITIONS: &[Condition] = &[
    Condition {
        label: "clean",
        seed: 0x711E_0001,
        link_kbps: 6_000,
        loss_pct: 0.0,
    },
    Condition {
        label: "lossy",
        seed: 0x711E_0002,
        link_kbps: 6_000,
        loss_pct: 3.0,
    },
    Condition {
        label: "constrained",
        seed: 0x711E_0003,
        link_kbps: 2_500,
        loss_pct: 0.0,
    },
];

/// Index into [`CONDITIONS`] of the constrained row, which several tests treat
/// separately — see [`constrained_link_headroom_estimate_overshoots`].
const CONSTRAINED: usize = 2;

/// How far below the tiles-OFF frame count a tiles-ON run may land, in
/// hundredths. Refinement must not cost video frames; two percent is the
/// "small epsilon" that allows for a frame straddling the end of the run.
///
/// **This is currently a tripwire with zero margin.** The constrained row
/// presents 839 frames against a control's 856, and the floor is exactly 839. The
/// number has eroded steadily as the throttle got better at tracking the link's
/// real capacity — 9 refused frames under the raw policy, then 10, 13, 16 — since
/// a ceiling that sits close to the damage threshold lands on it harder when it
/// finally crosses. Modelling whole strips took it to 17.
///
/// Two things follow, and they point in opposite directions:
///
/// * Do **not** widen this constant to make room. The next revision of the
///   throttle needs to attack the overshoot *count*, and this is the assertion
///   that will say whether it did.
/// * Do not read a one-frame movement here as signal either. Swept across the
///   realistic 1-4 KiB strip band the same configuration presents 840 / 839 /
///   844 — the count is now sensitive to when a strip happens to land relative
///   to a frame, at about the same magnitude as the effect being measured. It is
///   a bound worth keeping and a poor instrument for comparing policies; the mean
///   adaptor target is the instrument for that.
const FRAME_EPSILON_PCT: usize = 2;

/// 60 ms one way, no jitter, `loss_pct` datagram loss.
///
/// Jitter is deliberately zero. The netsim draws jitter per send, so any
/// difference in *how many* sends a run makes shifts the schedule of everything
/// after it. With zero jitter that draw has no observable effect, and the two
/// runs of a pair therefore see a bit-identical link right up until the moment
/// the hazard actually costs a frame — which is exactly the moment we want to
/// be measuring.
fn link(loss_pct: f32) -> NetParams {
    NetParams {
        latency_ms: 60,
        jitter_ms: 0,
        loss_pct,
        ..NetParams::perfect()
    }
}

/// Run one side of a pair to completion.
fn run(cond: &Condition, tiles: TileSim) -> Result<Sim> {
    let mut cfg = SimConfig::new(link(cond.loss_pct), cond.seed);
    cfg.tiles = Some(tiles);
    let mut sim = Sim::new(cfg)?;
    sim.run_to(DURATION_MS)?;
    Ok(sim)
}

/// The matched pair for a condition: `(tiles off, tiles on)`.
///
/// Both sides carry the shared-window model and the production status loop; the
/// *only* difference between them is whether refinement traffic exists.
fn pair(cond: &Condition) -> Result<(Sim, Sim)> {
    Ok((
        run(cond, TileSim::off(cond.link_kbps))?,
        run(cond, TileSim::on(cond.link_kbps))?,
    ))
}

/// The negative control for a condition: tiles on, throttle removed, spending
/// the whole nominal link. Video needs about a sixth of that on top, so this
/// always oversubscribes — which is precisely what an unthrottled refinement
/// pass would do on a static screen.
fn unthrottled(cond: &Condition) -> Result<Sim> {
    run(cond, TileSim::unthrottled(cond.link_kbps, cond.link_kbps))
}

/// Frames that reached the screen, having first checked every one of them was
/// intact and in order. A count is only worth comparing if the frames behind it
/// were real.
fn presented(sim: &Sim, label: &str) -> usize {
    let frames = sim.log().presented();
    assert_all_hashes_ok(&frames, label);
    assert_strictly_increasing(&frames, label);
    frames.len()
}

/// Mean adaptor target over every closed status window.
///
/// This, not the final target, is the statistic to compare policies on. The
/// target on a link that overshoots is a sawtooth, so its value at the end of
/// the run mostly reports *phase* — which window of the cycle the clock happened
/// to stop in — and can move hundreds of kbps between two policies that behave
/// identically. The mean over all ~29 windows is what the user actually watched.
fn mean_adaptor(sim: &Sim) -> u32 {
    let w = sim.host().tile_windows();
    (w.iter().map(|x| u64::from(x.adaptor_kbps)).sum::<u64>() / w.len().max(1) as u64) as u32
}

/// A one-line summary of a run, so an assertion message explains itself.
fn summary(sim: &Sim) -> String {
    let stats = sim.host().tile_stats();
    format!(
        "presented={} mean_kbps={} final_kbps={} tile_kb={} backpressured={} \
         pressure_windows={}/{}",
        sim.log().presented().len(),
        mean_adaptor(sim),
        sim.host().bitrate_kbps(),
        stats.tile_bytes_sent / 1_024,
        stats.video_frames_backpressured,
        stats.windows_with_pressure,
        stats.windows_closed,
    )
}

/// A quarter of adaptor-minus-encoder: what [`tile_budget_kbps`] would grant
/// with no ceiling over the top. Reproduced here so a window record can be asked
/// which of the two constraints — gap or ceiling — actually bound its grant.
fn gap_of(w: &directdesk_tests::TileWindowRecord) -> u32 {
    w.adaptor_kbps.saturating_sub(w.media_kbps) / 4
}

/// Whether `TileThrottle::observe` would classify this window as strained, and
/// so revoke the budget and mark the next window unjudgeable.
///
/// Reproduces the production condition for the inputs this harness supplies:
/// `streaming` is always true and `oversized_keyframe` always false here, which
/// leaves backpressure or loss over the 2% cutoff. (The cutoff itself is private
/// to `host::net`, so the literal is repeated — deliberately, so that changing it
/// there shows up as a failure here rather than being silently tracked.)
fn strained(w: &directdesk_tests::TileWindowRecord) -> bool {
    w.pressure > 0.0 || w.loss > 0.02
}

/// Reconstruct the throttle's private `safe_kbps` from a window trace.
///
/// `TileThrottle` exposes only `ceiling()`, but `safe` is fully determined by
/// what is already recorded: it is set, together with the ceiling, to the
/// backed-off spend on every damaging window and never moves otherwise. So the
/// safe level in force at window `i` is the ceiling recorded at the most recent
/// damaging window before it, and `None` (conceptually `u32::MAX`, "nothing is
/// known to hurt yet") before the first one.
fn safe_before(windows: &[directdesk_tests::TileWindowRecord], i: usize) -> Option<u32> {
    windows[..i]
        .iter()
        .rev()
        .find(|w| w.pressure > 0.0 && w.spent_kbps > 0)
        .map(|w| w.ceiling_kbps)
}

// ---------------------------------------------------------------------------
// Assertion 1 — refinement must not cost video frames
// ---------------------------------------------------------------------------

#[test]
fn refinement_costs_no_video_frames() -> Result<()> {
    for cond in CONDITIONS {
        let (off, on) = pair(cond)?;
        let base = presented(&off, cond.label);
        let with_tiles = presented(&on, cond.label);
        let floor = base - base * FRAME_EPSILON_PCT / 100;

        assert!(
            base > 700,
            "{}: the control run only presented {base} frames, so this row \
             compares nothing",
            cond.label
        );
        assert!(
            with_tiles >= floor,
            "{}: refinement cost {} of {base} frames (floor {floor})\n  off: {}\n  on : {}",
            cond.label,
            base - with_tiles,
            summary(&off),
            summary(&on),
        );
        // Refinement cannot *add* frames either; a run that presents more than
        // its own control would mean the pair is not actually matched.
        assert!(
            with_tiles <= base,
            "{}: tiles-on presented {with_tiles} frames, more than the {base} \
             of its own control — the pair is not matched",
            cond.label
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Assertion 2 — refinement must not depress the video bitrate target
// ---------------------------------------------------------------------------

/// The hazard assertion. If tiles steal the congestion window, `pressure`
/// climbs, the adaptor reads it as congestion, and the tiles-ON run ends below
/// its own control.
///
/// The constrained row is excluded and handled by
/// [`constrained_link_headroom_estimate_overshoots`], which documents exactly
/// why: on a link whose real capacity is below what the adaptor has allocated,
/// the throttle's headroom estimate overshoots and this property does *not*
/// currently hold.
#[test]
fn refinement_does_not_lower_the_video_target() -> Result<()> {
    for (i, cond) in CONDITIONS.iter().enumerate() {
        if i == CONSTRAINED {
            continue;
        }
        let (off, on) = pair(cond)?;
        let base = off.host().bitrate_kbps();
        let with_tiles = on.host().bitrate_kbps();

        assert!(
            with_tiles >= base,
            "{}: refinement pulled the video target from {base} down to \
             {with_tiles} kbps — tiles are stealing the congestion window\n  \
             off: {}\n  on : {}",
            cond.label,
            summary(&off),
            summary(&on),
        );
        // The adaptor must actually have been exercised, or "not lower" is a
        // statement about a number that never moved.
        assert!(
            !off.log().bitrate_changes().is_empty(),
            "{}: the adaptor never made a decision, so this row proves nothing",
            cond.label
        );
        // And the shared window must have stayed clean: no backpressure at all
        // is the positive form of the same claim.
        assert_eq!(
            on.host().tile_stats().video_frames_backpressured,
            off.host().tile_stats().video_frames_backpressured,
            "{}: refinement changed how many frames the window refused",
            cond.label
        );
    }
    Ok(())
}

/// Refinement has to have actually happened, or every row above is vacuous.
#[test]
fn refinement_actually_ran() -> Result<()> {
    for cond in CONDITIONS {
        let (off, on) = pair(cond)?;
        assert_eq!(
            off.host().tile_stats().tile_bytes_sent,
            0,
            "{}: the control run sent tile bytes",
            cond.label
        );
        assert!(
            on.host().tile_stats().tile_bytes_sent > 256 * 1_024,
            "{}: refinement only moved {} bytes, so the ON run is barely \
             distinguishable from the OFF run",
            cond.label,
            on.host().tile_stats().tile_bytes_sent
        );
        assert!(
            on.host()
                .tile_windows()
                .iter()
                .any(|w| w.budget_kbps > 0),
            "{}: the throttle never granted a budget at all",
            cond.label
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The loss cutoff
// ---------------------------------------------------------------------------

/// A link that is already losing packets gets no refinement worth the name.
///
/// `tile_budget_kbps` zeroes outright above a 2% loss cutoff rather than
/// scaling down, on the grounds that a half-speed refinement of a struggling
/// link is still a struggling link. This states that positively: on the 3% row
/// most windows grant nothing, and the total refinement traffic is an order of
/// magnitude below the clean row's.
///
/// # What the learned ceiling costs on top, and where it goes
///
/// This row is the one where the throttle can only lose: the link's loss is
/// nothing to do with refinement (zero backpressure, and a video path
/// bit-identical to tiles being switched off), so every kbps the ceiling
/// withholds is work not done for no benefit. The measured deficit against the
/// unbounded policy is 1 452 of 4 428 kbps-windows — a third — and the whole of
/// it lands in **two** windows:
///
/// | window | raw gap | learned | deficit | why |
/// |--------|---------|---------|---------|-----|
/// | 0 | 1 768 | 500 | 1 268 (87%) | cold start: nothing measured yet |
/// | 3 | 748 | 564 | 184 (13%) | creep-rate growth after a revoked window |
/// | 4.. | equal | equal | 0 | the gap collapses below the ceiling |
///
/// Neither is the ceiling being wrong. Window 0 is the throttle declining to
/// spend 1 768 kbps on a luxury before a single congestion measurement exists,
/// which is the entire point of a floor. Window 3 is the price of the rule that
/// a window which was granted nothing may grow the ceiling by a *creep* and not
/// a *step* — the concession keeps a chronically strained link from being pinned
/// at the floor forever, while refusing to let it ratchet at full speed on no
/// evidence back to the unvalidated raw gap. 184 kbps-windows, or 23 KB of 540,
/// is a cheap price for that and this test pins it there.
///
/// Parity arrives at window 4 and holds for the remaining 25 — and note *why*:
/// not because the ceiling caught up (it stops at 564) but because loss drives
/// the adaptor down to its floor, which collapses the headroom gap to ~143 kbps,
/// well under the ceiling. On this row the throttle stops being the binding
/// constraint almost immediately, which is the correct outcome.
#[test]
fn a_lossy_link_gets_almost_no_refinement() -> Result<()> {
    let lossy = run(&CONDITIONS[1], TileSim::on(CONDITIONS[1].link_kbps))?;
    let clean = run(&CONDITIONS[0], TileSim::on(CONDITIONS[0].link_kbps))?;

    let windows = lossy.host().tile_windows();
    let revoked = windows.iter().filter(|w| w.budget_kbps == 0).count();
    assert!(
        revoked * 2 > windows.len(),
        "only {revoked} of {} windows revoked the budget on a 3% link",
        windows.len()
    );
    // Every revoked window must have a reason the production function accepts:
    // loss over its cutoff, or backpressure.
    for w in windows.iter().filter(|w| w.budget_kbps == 0) {
        assert!(
            w.loss > 0.02 || w.pressure > 0.0,
            "budget revoked at {} ms with loss {:.3} and pressure {:.3}, \
             which is neither reason `tile_budget_kbps` recognises",
            w.at_ms,
            w.loss,
            w.pressure
        );
    }
    assert!(
        lossy.host().tile_stats().tile_bytes_sent * 8
            < clean.host().tile_stats().tile_bytes_sent,
        "a 3% link refined {} bytes against the clean link's {}",
        lossy.host().tile_stats().tile_bytes_sent,
        clean.host().tile_stats().tile_bytes_sent
    );

    // What the *learned ceiling* must not do on this row is add to that, and it
    // used to. The ceiling is lowered only when refinement is implicated, and on
    // a link that is simply lossy it never is — so the ceiling leaves the floor
    // and stops being the constraint at all, exactly as it should on a link
    // where the budget was never what limited refinement.
    //
    // Before the attribution fix, every lossy window read as a refusal, the
    // ceiling never left TILE_CEILING_MIN_KBPS for the whole run and this row
    // moved 355 KB against the raw policy's 540. It now reaches 564 and moves
    // 362 KB — see the deficit analysis below for why that is nearly all cold
    // start rather than throttling.
    let raw = run(&CONDITIONS[1], TileSim::raw_gap(CONDITIONS[1].link_kbps))?;
    let peak = windows.iter().map(|w| w.ceiling_kbps).max().unwrap_or(0);
    assert!(
        peak > TILE_CEILING_MIN_KBPS,
        "the ceiling never left its {TILE_CEILING_MIN_KBPS} kbps floor on a link \
         whose loss refinement did not cause"
    );

    // The residual is a bounded *prefix*, not a permanent tax. Walk both runs
    // window by window and find the point from which the learned policy grants
    // exactly what the unbounded one does, for the whole rest of the run.
    let raw_windows = raw.host().tile_windows();
    assert_eq!(windows.len(), raw_windows.len());
    let mut deficits: Vec<i64> = Vec::with_capacity(windows.len());
    let mut granted: i64 = 0;
    for (learned, unbounded) in windows.iter().zip(raw_windows) {
        granted += i64::from(unbounded.budget_kbps);
        deficits.push(i64::from(unbounded.budget_kbps) - i64::from(learned.budget_kbps));
        assert!(
            learned.budget_kbps <= unbounded.budget_kbps,
            "at {} ms the ceiling granted {} where the raw gap granted {} — a \
             ceiling may only ever narrow",
            learned.at_ms,
            learned.budget_kbps,
            unbounded.budget_kbps
        );
    }
    let parity_from = deficits
        .iter()
        .rposition(|&d| d != 0)
        .map_or(0, |last| last + 1);
    assert!(
        parity_from <= 4,
        "the learned policy did not reach parity with the raw gap until window \
         {parity_from} of {}; the ramp is supposed to be a short prefix, not a \
         standing cost",
        windows.len()
    );
    // Two windows carry the whole of it, and they are two different things.
    assert_eq!(
        deficits.iter().filter(|&&d| d != 0).count(),
        2,
        "the deficit is spread over {:?}; it should be the opening slow start \
         plus exactly one creep-rate recovery window",
        deficits
            .iter()
            .enumerate()
            .filter(|(_, &d)| d != 0)
            .collect::<Vec<_>>()
    );
    let total: i64 = deficits.iter().sum();
    let opening = deficits[0];
    let ramp = total - opening;

    // 1. The opening slow start: 1 768 kbps of raw gap against a 500 kbps floor,
    //    because nothing has been measured yet. That is the design and it is
    //    ~87% of the whole deficit.
    assert!(
        opening * 100 >= total * 80,
        "the opening slow start is only {opening} of a {total} kbps-window \
         deficit; something other than the cold start has become the cost"
    );
    // 2. The creep-rate recovery. A strained window grants nothing and so spends
    //    nothing, and the throttle concedes growth on the window after it rather
    //    than pinning the ceiling forever — but that concession is evidence-free,
    //    so it buys a 64 kbps creep and not a 500 kbps step. On this row that
    //    costs exactly one window: window 3 grants 564 where the raw gap grants
    //    748. Under step-rate growth the ceiling would have been 1 000 there and
    //    the two would have matched.
    //
    //    So the price of refusing to ratchet on no evidence is 184 kbps-windows
    //    out of 4 428, or 23 KB of the 540 KB the raw policy moves. It is a good
    //    trade: the alternative is that a link which strains every other window
    //    climbs at the full step with nothing supporting it, and arrives back at
    //    the unvalidated raw gap the ceiling exists to bound.
    assert!(
        ramp * 100 < granted * 10,
        "the creep-rate ramp cost {ramp} of {granted} kbps-windows granted, over \
         10% — at that price the concession should buy a step rather than a \
         creep, or be refused outright"
    );
    // And the total, so the headline number cannot drift unnoticed. It is a
    // third of the raw policy's work, but that third is overwhelmingly the cold
    // start, not the learned ceiling being wrong.
    assert!(
        total * 100 <= granted * 35,
        "the learned ceiling cost {total} of {granted} kbps-windows granted"
    );

    // None of this may turn on the strip size, which is a property of the screen
    // rather than of the throttle. Sweep the realistic 1-4 KiB band.
    let mut volumes = Vec::new();
    for bytes in [1_024u64, 2_048, 4_096] {
        let mut tiles = TileSim::on(CONDITIONS[1].link_kbps);
        tiles.tile_strip_bytes = bytes;
        volumes.push(run(&CONDITIONS[1], tiles)?.host().tile_stats().tile_bytes_sent);
    }
    let (lo, hi) = (
        *volumes.iter().min().expect("swept"),
        *volumes.iter().max().expect("swept"),
    );
    assert!(
        (hi - lo) * 100 < hi * 2,
        "refinement volume swung {lo}..{hi} bytes across a 1-4 KiB strip size; \
         this row's conclusions depend on a modelling constant"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// The static screen — refinement's actual reason for existing
// ---------------------------------------------------------------------------

/// A screen with only so much to refine neither strains the link nor gets pinned
/// by the throttle.
///
/// This is the case refinement is *for* and until [`TileSim::tile_supply_kbps`]
/// existed the harness could not reach it: [`TileEngine::end_tick`] produced
/// exactly `budget_kbps` every tick, so `spent_kbps` always equalled the grant,
/// `used_its_grant` was always satisfied, and every branch of the throttle that a
/// spend *below* the grant selects was unreachable.
///
/// The specific fear was that a ceiling knocked down by a strain event on a quiet
/// screen would stay down, because a quiet screen never spends enough to satisfy
/// the growth gate. The measurement says that cannot happen, and the reason is
/// structural rather than lucky: a screen whose demand is below the link's spare
/// capacity cannot *cause* a strain event in the first place, so there is nothing
/// to recover from. Below the threshold every supply level here runs the video
/// path bit-identically to tiles being switched off entirely.
///
/// What the ceiling does instead is park at roughly twice the supply — the level
/// at which `spent * 2 >= ceiling` stops holding — and stay there. That is the
/// correct answer: it is not evidence about the link, it is evidence about the
/// screen, and the throttle declines to probe on it. The ceiling is left with
/// headroom for demand to return into, and the moment it does the ramp resumes
/// (which is what [`a_revoked_window_does_not_stall_the_ceiling`] pins).
///
/// The genuine residual risk that remains is a strain event caused by something
/// *other* than refinement landing while refinement is quiet — see
/// [`a_cheap_strain_event_makes_recovery_creep_only`], which measures it directly
/// because this harness cannot produce it (a quiet screen cannot strain the
/// link, which is the whole finding above).
///
/// [`TileEngine::end_tick`]: directdesk_tests::TileEngine::end_tick
#[test]
fn a_quiet_screen_is_free_and_parks_the_ceiling_above_its_own_demand() -> Result<()> {
    let cond = &CONDITIONS[CONSTRAINED];
    let off = run(cond, TileSim::off(cond.link_kbps))?;

    // This link carries ~930 kbps of video and has roughly 1 550 kbps spare,
    // bracketed at 1 625..1 664 by `constrained_link_headroom_estimate_overshoots`.
    // Every supply below that is a screen the link can comfortably refine.
    for supply in [300u32, 600, 1_200] {
        let quiet = run(cond, TileSim::app_limited(cond.link_kbps, supply))?;
        let stats = quiet.host().tile_stats();

        // Free: the video path is indistinguishable from tiles being off.
        assert_eq!(
            presented(&quiet, "quiet"),
            presented(&off, "quiet/off"),
            "supply {supply}: refinement cost frames on a screen the link can \
             carry\n  off  : {}\n  quiet: {}",
            summary(&off),
            summary(&quiet),
        );
        assert_eq!(
            mean_adaptor(&quiet),
            mean_adaptor(&off),
            "supply {supply}: refinement moved the video target"
        );
        assert_eq!(
            stats.windows_with_pressure, 0,
            "supply {supply}: a screen below the link's spare capacity strained it"
        );
        assert_eq!(stats.video_frames_backpressured, 0, "supply {supply}");

        // And refinement actually happened, or "free" is a statement about
        // nothing.
        assert!(
            stats.tile_bytes_sent > 256 * 1_024,
            "supply {supply}: only {} tile bytes moved",
            stats.tile_bytes_sent
        );

        // The ceiling parks above the demand and stops. It must not stay at the
        // floor (that would throttle a screen that is not the problem) and it
        // must not run away (that would be the un-gated increase back again).
        let windows = quiet.host().tile_windows();
        let peak = windows.iter().map(|w| w.ceiling_kbps).max().unwrap_or(0);
        let settled = windows.last().map_or(0, |w| w.ceiling_kbps);
        assert_eq!(
            peak, settled,
            "supply {supply}: the ceiling peaked at {peak} and ended at \
             {settled}, so something knocked it down"
        );
        assert!(
            settled >= supply && settled <= supply * 2 + TILE_CEILING_STEP_KBPS,
            "supply {supply}: the ceiling settled at {settled}, which is not \
             'just above what the screen asked for'"
        );
        // Nothing was ever learned *about the link* here, so the fast ramp is
        // the only one that ever ran: a run with no strain has no safe level.
        assert!(
            windows.iter().all(|w| w.pressure == 0.0),
            "supply {supply}: this row is supposed to be strain-free"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The constrained link — where the headroom estimate overshoots
// ---------------------------------------------------------------------------

/// On a link whose real capacity is below what the adaptor has allocated,
/// refinement *does* cost video bitrate, and this row records exactly how.
///
/// # The original diagnosis, which was right
///
/// [`tile_budget_kbps`] spends a quarter of `adaptor_target - media_kbps`. That
/// is only spare *link* capacity if the adaptor's target is a measured property
/// of the link — and on a low-motion screen it is not. The encoder is content
/// limited, so it never fills its allocation, so video alone never congests
/// anything, so AIMD ratchets the target up to the mode ceiling without ever
/// testing it. A quarter of that unvalidated gap can exceed what the link
/// actually has spare, and when it does the backpressure lands on **video**.
///
/// The loop is self-limiting — the budget is revoked the very next window — but
/// it is not free: the adaptor loses 30% multiplicatively and regains
/// `step_kbps` only every `raise_after_ms`, so the target sawtooths well below
/// where the same link would have put it with refinement off.
///
/// # Why [`TileThrottle`] does not yet close it
///
/// [`TileThrottle`] bounds that gap by a ceiling learned from experiment. Three
/// versions of that learning have now been measured on this row, all on the same
/// seed, and the mean adaptor target is the statistic to read them by — the final
/// target is one sample of a sawtooth and mostly reports which phase of the cycle
/// the run happened to stop in.
///
/// | policy                              | mean  | final | tile KB | refused | pressure |
/// |-------------------------------------|-------|-------|---------|---------|----------|
/// | raw `tile_budget_kbps` (no ceiling) | 6 278 | 6 171 | 4 325   | 9       | 3/29     |
/// | v1 `TileThrottle`, ungated step     | 6 404 | 5 421 | 4 310   | 10      | 3/29     |
/// | v2 + evidence gate on the increase  | 6 433 | 6 060 | 4 171   | 13      | 3/29     |
/// | v3 + ssthresh and attribution       | 6 698 | 5 310 | 4 334   | 16      | 3/29     |
/// | v4 + creep on the concession        | 6 698 | 5 310 | 4 334   | 17      | 3/29     |
///
/// Against a tiles-OFF control that means 11 258. So v3 holds 59% of the control
/// where raw holds 56% — real, measurable, and nowhere near closed.
///
/// v4 is bit-identical to v3 on this row and that is expected: the creep-on-a
/// -concession rule only fires on a window that was granted nothing, and the only
/// such windows here are the three recovery windows after an overshoot — where
/// the ceiling already sits *at* `safe` and was creeping anyway. The rule bites
/// on the 3% lossy row instead; see [`a_lossy_link_gets_almost_no_refinement`].
/// The refused-frame count moves 16 → 17 purely because refinement now emits
/// whole 2 KiB strips rather than a divisible byte stream, which is burstier.
///
/// The three fixes and what each bought:
///
/// * **v1 → v2, the evidence gate.** The increase used to be applied on *every*
///   clean window, so the ceiling climbed a flat 500 kbps while the gap it bounds
///   grew only ~180, overtook it within two windows and never bound again — the
///   learned value was computed and then discarded. Gating growth on "the ceiling
///   was the binding constraint *and* refinement spent at least half its grant"
///   fixed the mechanism (peak ceiling 2 000 instead of 6 243) without moving the
///   outcome much, because the step size took over as the limiting factor.
/// * **v2 → v3, ssthresh.** A flat step cannot converge at all below
///   `STEP / (1 - BACKOFF)` = 1 667 kbps of spare. This link has ~1 550, so
///   `floor(0.7 x 1664) + 500 = 1664` was an exact fixed point and the same
///   damaging level recurred on schedule forever. Splitting the ramp — 500 kbps
///   below the last known-safe level, [`TILE_CEILING_CREEP_KBPS`] of 64 above it
///   — drops that floor to ~213 and the fixed point is gone. Measured below.
/// * **v2 → v3, attribution.** The ceiling is now lowered only when
///   `pressure > 0`; loss with no backpressure is the link being lossy on its own.
///   That is the 3% row, not this one — see
///   [`a_lossy_link_gets_almost_no_refinement`].
///
/// # What the ssthresh split actually bought here
///
/// The probe is now fine enough to find the edge instead of vaulting it. Bracket
/// the link's real tile capacity by what happened: the largest budget followed by
/// a clean window, and the smallest followed by a pressure window.
///
/// | version | bracket        | width | cycle period |
/// |---------|----------------|-------|--------------|
/// | v2      | 1 500 .. 1 664 | 164   | ~10 windows  |
/// | v3      | 1 625 .. 1 664 | 39    | ~13 windows  |
///
/// so the uncertainty about this link's safe tile rate is down four-fold, and the
/// interval between overshoots is up by a third. Both assertions below pin that.
///
/// # What is left
///
/// AIMD always re-probes, so it always eventually oversteps: the count of
/// damaging windows over a 29-window run is still exactly 3, unchanged across all
/// four policies. What changed is *when* — the third event moved from window 25 to
/// window 28 — and that, not the count, is the whole of the improvement.
///
/// The deeper residual is that the backoff target is wrong, not the step. It
/// anchors to `0.7 x spend`, which lands `safe` at 1 177 against a true threshold
/// near 1 660: a 30% multiplicative cut is calibrated for a *shared* link where
/// the competing flow also backs off, and here the competitor is our own video on
/// a fixed pipe. Every event therefore throws away ~480 kbps of correctly learned
/// headroom and spends the next eight windows creeping back through capacity it
/// already knew was safe. A gentler backoff *above* a known-safe floor — or
/// seeding `safe` from the largest clean spend rather than from the damaging one —
/// is what would actually reduce the event count.
///
/// This test asserts the mechanism and bounds the damage, so it fails if the
/// behaviour gets worse. The property that *should* hold is asserted by
/// [`constrained_link_should_not_lower_the_video_target`], which is ignored
/// because it still does not.
///
/// [`TileThrottle`]: directdesk_host::net::TileThrottle
/// [`TILE_CEILING_CREEP_KBPS`]: directdesk_host::net::TILE_CEILING_CREEP_KBPS
#[test]
fn constrained_link_headroom_estimate_overshoots() -> Result<()> {
    let cond = &CONDITIONS[CONSTRAINED];
    let (off, on) = pair(cond)?;

    // The link itself lost nothing. Every frame missing from the screen is one
    // the host declined to send, which is the whole point: this congestion is
    // invisible to any packet-loss counter.
    assert_eq!(on.net_stats().datagrams_dropped_loss, 0);
    assert_eq!(off.net_stats().datagrams_dropped_loss, 0);
    assert_eq!(
        off.host().tile_stats().video_frames_backpressured,
        0,
        "without refinement this link carries the video comfortably"
    );

    let stats = on.host().tile_stats();
    assert!(
        stats.video_frames_backpressured > 0,
        "refinement did not stress the window at all, so this row records nothing"
    );
    assert!(
        stats.windows_with_pressure > 0 && stats.windows_with_pressure * 4 < stats.windows_closed,
        "{} of {} windows saw pressure; the loop should be occasional, not constant",
        stats.windows_with_pressure,
        stats.windows_closed
    );

    // Self-limiting: every window that measured pressure revokes the budget,
    // and the window after it is clean again.
    let windows = on.host().tile_windows();
    for (i, w) in windows.iter().enumerate() {
        if w.pressure > 0.0 {
            assert_eq!(
                w.budget_kbps, 0,
                "pressure at {} ms did not revoke the tile budget",
                w.at_ms
            );
            if let Some(next) = windows.get(i + 1) {
                assert_eq!(
                    next.pressure, 0.0,
                    "pressure persisted into the window after the budget was revoked"
                );
            }
        }
    }

    // Half one of the throttle's story: it learns the right number. Every
    // window that overshot backs the ceiling off below the spend that caused
    // the overshoot, because the decrease is anchored to what was actually
    // spent rather than to the ceiling it came from.
    let overshoots: Vec<_> = windows.iter().filter(|w| w.pressure > 0.0).collect();
    assert!(!overshoots.is_empty(), "no window to learn from");
    for w in &overshoots {
        assert!(
            w.spent_kbps > 0 && w.ceiling_kbps < w.spent_kbps,
            "at {} ms the ceiling backed off to {} against a spend of {}, which \
             is not a decrease anchored to what was spent",
            w.at_ms,
            w.ceiling_kbps,
            w.spent_kbps
        );
    }

    // Half two: the learned number is now *kept*, and the ramp back to it has
    // two speeds. Reproduce the whole growth rule and check it against every
    // clean window in the run — `gap` is `tile_budget_kbps`, a quarter of
    // adaptor-minus-encoder (the operator ceiling of 8 000 kbps is far above
    // everything here and never participates), and `safe` is reconstructed from
    // the trace by `safe_before`.
    //
    // A window's record carries the ceiling *after* its own `observe`, so the
    // ceiling entering window `i` is `windows[i - 1].ceiling_kbps`.
    let mut stepped = 0usize;
    let mut crept = 0usize;
    let mut held = 0usize;
    for i in 1..windows.len() {
        let (prev, next) = (&windows[i - 1], &windows[i]);
        if strained(next) {
            continue; // the backoff branch, asserted above.
        }
        let entering = prev.ceiling_kbps;
        let safe = safe_before(windows, i).unwrap_or(u32::MAX);
        let was_binding = entering <= gap_of(next);
        // A window that was granted nothing is not a refusal: the throttle only
        // asks "did you use your grant?" of a window that had one.
        let judgeable = !strained(prev);
        let used_its_grant = next.spent_kbps * 2 >= entering;
        let expected = if was_binding && (!judgeable || used_its_grant) {
            if entering < safe {
                stepped += 1;
                entering + TILE_CEILING_STEP_KBPS
            } else {
                crept += 1;
                entering + TILE_CEILING_CREEP_KBPS
            }
        } else {
            held += 1;
            entering
        };
        assert_eq!(
            next.ceiling_kbps, expected,
            "at {} ms the ceiling moved {entering} → {} over a clean window \
             (binding={was_binding}, judgeable={judgeable}, \
             used_its_grant={used_its_grant}, safe={safe}, gap={}, spent={})",
            next.at_ms,
            next.ceiling_kbps,
            gap_of(next),
            next.spent_kbps,
        );
    }
    // Every branch of that rule has to be exercised or it is only part tested.
    assert!(
        stepped > 0 && crept > 0 && held > 0,
        "the growth rule did not go every way: {stepped} stepped, {crept} crept, \
         {held} held"
    );
    // And the shape of it: the fast ramp is the opening slow start only, so once
    // the link has said "no" once, almost all of the run is spent creeping.
    assert!(
        crept > stepped * 3,
        "only {crept} of the {} growth windows crept; the ceiling is spending \
         its time in the fast ramp, which means `safe` is not being learned",
        crept + stepped
    );

    // The consequence: the ceiling stays near what it learned instead of running
    // away. Under the original unconditional increase it reached 6 243 kbps on
    // this row; it now peaks at 2 000 — the level reached before the link said
    // "no" for the first time — and never exceeds it again.
    let peak_ceiling = windows.iter().map(|w| w.ceiling_kbps).max().unwrap_or(0);
    assert!(
        peak_ceiling <= 2_500,
        "the ceiling climbed to {peak_ceiling} kbps on a link with ~1 550 spare; \
         it is running away again"
    );

    // Bracket the link's real safe tile rate by what actually happened: the
    // largest budget followed by a clean window, and the smallest followed by a
    // pressure window.
    let mut safe = 0u32;
    let mut damaging = u32::MAX;
    for (i, w) in windows.iter().enumerate() {
        if w.budget_kbps == 0 {
            continue;
        }
        match windows.get(i + 1) {
            Some(n) if n.pressure > 0.0 => damaging = damaging.min(w.budget_kbps),
            Some(_) => safe = safe.max(w.budget_kbps),
            None => {}
        }
    }
    assert!(
        safe > 0 && damaging < u32::MAX && safe < damaging,
        "no coherent safe/damaging bracket: safe {safe}, damaging {damaging}"
    );
    // The improvement, stated as a measurement rather than a claim. A flat
    // 500 kbps step left this bracket 164 kbps wide (1 500 .. 1 664); the creep
    // closes it to one creep step, because the last clean probe before the
    // overshoot is now only TILE_CEILING_CREEP_KBPS below the one that overshot.
    assert!(
        damaging - safe <= TILE_CEILING_CREEP_KBPS,
        "the bracket on this link's safe tile rate is {safe}..{damaging}, \
         {} kbps wide — wider than one {TILE_CEILING_CREEP_KBPS} kbps creep, so \
         the ceiling is still vaulting the threshold rather than finding it",
        damaging - safe
    );
    // Which means the old fixed point is gone: backing off from the damaging
    // spend and taking one probe no longer returns to the damaging spend, it
    // lands far below and has to creep back.
    let after_backoff = (damaging as f32 * TILE_CEILING_BACKOFF) as u32;
    assert!(
        after_backoff + TILE_CEILING_CREEP_KBPS < safe,
        "one probe still carries the ceiling from {after_backoff} across the \
         {safe}..{damaging} threshold; the AIMD cycle is a fixed point again"
    );
    // The general form: a cycle can only settle above STEP / (1 - BACKOFF). At
    // 500 kbps that floor is 1 667 and this link (~1 550 spare) was under it,
    // which is exactly why the overshoot used to recur on schedule. At 64 it is
    // 213 and this link is comfortably clear.
    let step_floor = (TILE_CEILING_STEP_KBPS as f32 / (1.0 - TILE_CEILING_BACKOFF)) as u32;
    let creep_floor = (TILE_CEILING_CREEP_KBPS as f32 / (1.0 - TILE_CEILING_BACKOFF)) as u32;
    assert!(
        damaging <= step_floor && damaging > creep_floor,
        "this link's damage threshold ({damaging}) no longer sits between the \
         creep's settling floor ({creep_floor}) and the step's ({step_floor}), \
         so it is no longer the row that distinguishes them"
    );
    // But settling is not converging, and this is the honest residual: AIMD
    // always re-probes, so the ceiling always eventually re-crosses the
    // threshold. The backoff throws away ~480 kbps of correctly learned headroom
    // every time (0.7 x 1 664 = 1 164 against a real threshold near 1 660), and
    // the creep spends eight windows walking back through capacity it already
    // knew was safe. That is the whole cost that remains.
    let damaging_windows = windows.iter().filter(|w| strained(w)).count();
    assert_eq!(
        damaging_windows, 3,
        "the number of overshoots over a {DURATION_MS} ms run changed; it has \
         been exactly 3 under the raw policy and under all three versions of the \
         throttle, and only the spacing between them has moved"
    );
    // The spacing is where the gain is. The creep stretched the interval between
    // the second overshoot and the third from ~10 windows to 13.
    let events: Vec<u64> = windows
        .iter()
        .filter(|w| strained(w))
        .map(|w| w.at_ms)
        .collect();
    let last_gap = (events[2] - events[1]) / STATUS_INTERVAL_MS;
    assert!(
        last_gap >= 12,
        "the interval between the last two overshoots is {last_gap} windows; a \
         flat step gave 10 and the creep is supposed to stretch it"
    );

    // The ceiling now binds late into the run, which is the point: with a flat
    // step it was overtaken by the gap within the first few windows and the
    // throttle stopped participating. With the creep it is the smaller of the
    // two constraints for most of the run.
    let binding_windows = windows
        .iter()
        .filter(|w| w.budget_kbps > 0 && w.budget_kbps == w.ceiling_kbps)
        .count();
    let last_binding = windows
        .iter()
        .filter(|w| w.budget_kbps > 0 && w.budget_kbps == w.ceiling_kbps)
        .map(|w| w.at_ms)
        .max()
        .unwrap_or(0);
    assert!(
        binding_windows >= 8 && last_binding >= 20 * STATUS_INTERVAL_MS,
        "the ceiling bound the grant in {binding_windows} windows, last at \
         {last_binding} ms — it has stopped being the constraint that matters \
         and the throttle is back to granting the raw gap"
    );

    // But not free. Bound the damage in both directions so this test fails if
    // the overshoot grows *or* if someone fixes it (at which point the ignored
    // test below is the one to promote).
    let base = off.host().bitrate_kbps();
    let with_tiles = on.host().bitrate_kbps();
    assert!(
        mean_adaptor(&on) < mean_adaptor(&off),
        "refinement no longer depresses the target on a constrained link \
         (mean {} vs {}) — the headroom estimate appears to have been fixed; \
         promote `constrained_link_should_not_lower_the_video_target`",
        mean_adaptor(&on),
        mean_adaptor(&off),
    );
    // Recorded behaviour is a sawtooth: peaks 8 750 → 7 625 → 7 587, troughs
    // 6 125 → 5 337 → 5 310, against a control that climbs freely to 14 750. The
    // run now ends *in* the third trough at 5 310 rather than recovering from it,
    // because the creep pushed that trough from window 25 out to window 28 —
    // which is why `final` reads worse than v2's 6 060 while the mean, the
    // statistic that is not a phase artefact, reads 4% better.
    //
    // A third is the line: below it the loop is no longer an occasional
    // transient and this stops being a bounded cost.
    assert!(
        with_tiles * 3 > base && mean_adaptor(&on) * 3 > mean_adaptor(&off),
        "refinement cost more than two thirds of the video target \
         ({with_tiles} vs {base}), which is worse than the recorded \
         behaviour\n  off: {}\n  on : {}",
        summary(&off),
        summary(&on)
    );
    // The frame cost stays a rounding error on the run, but it is the one number
    // that has got monotonically worse across all three throttle versions:
    // 9 refused under the raw gap, then 10, 13, and now 16. The cause is the same
    // thing that makes the throttle work — the ceiling holds a value close to the
    // threshold going into the overshoot instead of having been overtaken by the
    // gap long before, so each event is a slightly harder landing.
    assert!(
        stats.video_frames_backpressured < 25,
        "{} frames were refused; the transient is no longer a transient",
        stats.video_frames_backpressured
    );
    Ok(())
}

/// The property a constrained link *should* have, and does not.
///
/// Ignored, not deleted: it is a correct statement of the contract
/// [`tile_budget_kbps`] documents ("the budget is spent only out of demonstrated
/// spare capacity"), and it fails today because the demonstrated-spare-capacity
/// figure is not demonstrated — it is `adaptor_target - media_kbps`, and on a
/// content-limited encoder `adaptor_target` is an aspiration the link has never
/// been asked to honour.
///
/// [`TileThrottle`] is the intended fix and is what this harness drives. Three
/// things have now been tried on it. All three worked as designed. None of them
/// makes this test pass, and the reason is the same each time — they change how
/// *often* the ceiling oversteps, not whether it does.
///
/// * The **backoff** anchors to what was actually spent rather than to the
///   ceiling it came from, so it lands below the level that did the damage. It
///   always did this correctly.
/// * The **increase** is gated on evidence — the ceiling grows only when it was
///   the binding constraint and refinement spent at least half its grant. That
///   stopped the ceiling running away (peak 2 000 kbps here, down from 6 243).
///   Mean video target 6 433, up 0.5% on the ungated version.
/// * The ramp is **split at a known-safe level**: 500 kbps below it, 64 above.
///   That removed the fixed point (see
///   [`constrained_link_headroom_estimate_overshoots`] for the algebra), narrowed
///   the bracket on this link's true tile capacity from 164 kbps to 39, and
///   stretched the interval between overshoots from ~10 windows to 13. Mean video
///   target 6 698, up 4.1%.
///
/// So the trend is real and in the right direction — 6 278 (no ceiling at all) →
/// 6 404 → 6 433 → 6 698 — but the target with refinement on is still 59% of the
/// 11 258 the same link reaches with it off, and the run still takes exactly 3
/// overshoots. Making that count zero is a different problem from making the
/// probe finer.
///
/// What blocks it now is the **backoff target**, not the step size. On strain the
/// ceiling drops to `0.7 x spend` = 1 164 kbps against a threshold this run
/// brackets at 1 625..1 664 — it throws away roughly 480 kbps of headroom it had
/// already proved safe, then creeps back through it over eight windows, and the
/// eventual re-crossing costs the video adaptor another 30% multiplicative cut.
/// A 30% cut is the right response on a link shared with a competitor that also
/// backs off; here the competitor is our own video on a fixed pipe, and there is
/// nobody to yield to.
///
/// The candidate fix is therefore to stop discarding the learned floor: back off
/// toward the largest *clean* spend rather than a fixed fraction of the damaging
/// one, so `safe` converges on the bracket instead of resetting below it. That
/// would attack the event count, which is the number that has not moved.
///
/// Run this with `cargo test -p directdesk-tests -- --ignored`.
///
/// [`TileThrottle`]: directdesk_host::net::TileThrottle
#[test]
#[ignore = "the ssthresh split removed the fixed point and stretched the \
            overshoot interval, but the backoff still discards ~480 kbps of \
            proven-safe headroom per event and the event count is unchanged at \
            3; see constrained_link_headroom_estimate_overshoots"]
fn constrained_link_should_not_lower_the_video_target() -> Result<()> {
    let cond = &CONDITIONS[CONSTRAINED];
    let (off, on) = pair(cond)?;
    assert!(
        mean_adaptor(&on) >= mean_adaptor(&off),
        "refinement pulled the mean video target from {} down to {} kbps\n  \
         off: {}\n  on : {}",
        mean_adaptor(&off),
        mean_adaptor(&on),
        summary(&off),
        summary(&on)
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// What the learned ceiling is actually buying, against the policy it replaced
// ---------------------------------------------------------------------------

/// [`TileThrottle`] against the raw headroom policy it wraps, on the row where
/// the difference is supposed to show.
///
/// This is the comparison that says whether the learned ceiling is earning its
/// place. It spent two revisions recording parity — the mean video target moved
/// 6 278 → 6 404 → 6 433 kbps, inside the noise — with a note saying that when a
/// finer increase landed this test should start failing and be promoted. It has,
/// and it is: the ssthresh split puts the throttle at 6 698 kbps, **6.7% above**
/// the raw policy, so the assertion is now superiority rather than parity.
///
/// The win is bought in a specific way and it is worth being precise about it,
/// because two of the three headline numbers still favour the raw policy:
///
/// | | raw gap | learned ceiling |
/// |---|---------|-----------------|
/// | mean video target | 6 278 | **6 698** |
/// | final video target | **6 171** | 5 310 |
/// | tile KB moved | 4 325 | **4 334** |
/// | video frames refused | **9** | 16 |
/// | pressure windows | 3/29 | 3/29 |
///
/// * The **mean** is the real result and it is what a viewer experiences: the
///   throttle holds a higher video bitrate across the run because it delays the
///   third overshoot from window 25 to window 28.
/// * The **final** figure is worse purely because of that delay — the run stops
///   inside the third trough instead of eight windows into the recovery from it.
///   It is phase, not quality, which is why this test asserts on the mean.
/// * The **frame cost** is genuinely worse and is not phase. A ceiling that
///   tracks the threshold closely is a ceiling that is near the threshold when it
///   finally crosses, so the landing is harder: 16 refused frames against 9. On
///   an 856-frame run that is 0.8%, and it buys 420 kbps of mean video, which is
///   the trade this test now locks in. It is also the number to watch — see the
///   frame-cost assertion at the end.
///
/// [`TileThrottle`]: directdesk_host::net::TileThrottle
#[test]
fn the_learned_ceiling_beats_the_raw_policy_on_a_constrained_link() -> Result<()> {
    let cond = &CONDITIONS[CONSTRAINED];
    let raw = run(cond, TileSim::raw_gap(cond.link_kbps))?;
    let learned = run(cond, TileSim::on(cond.link_kbps))?;

    // The raw policy has no ceiling to learn, so its budget is the gap every
    // window. That is the thing the throttle is supposed to improve on.
    assert!(
        raw.host()
            .tile_windows()
            .iter()
            .filter(|w| w.budget_kbps > 0)
            .all(|w| w.budget_kbps == gap_of(w)),
        "the raw control is not granting the raw gap, so it is not a control"
    );

    // The result: a clear win on the statistic that is not a phase artefact.
    assert!(
        mean_adaptor(&learned) * 100 > mean_adaptor(&raw) * 105,
        "the learned ceiling left the mean video target at {} against the raw \
         policy's {} — under 5% ahead, which is where it sat for two revisions \
         while it was doing no real work\n  raw    : {}\n  learned: {}",
        mean_adaptor(&learned),
        mean_adaptor(&raw),
        summary(&raw),
        summary(&learned),
    );
    // And it is not bought by refining less: the ceiling moves at least as many
    // tile bytes as the unbounded policy does.
    assert!(
        learned.host().tile_stats().tile_bytes_sent >= raw.host().tile_stats().tile_bytes_sent,
        "the learned ceiling won the video target by doing less refinement \
         ({} bytes vs {})",
        learned.host().tile_stats().tile_bytes_sent,
        raw.host().tile_stats().tile_bytes_sent,
    );

    // What it has *not* bought, recorded so that it is not mistaken for a full
    // fix: the number of overshoots is identical. The throttle spaces them out;
    // it does not prevent them. When that changes, this assertion is the one that
    // will say so.
    assert_eq!(
        learned.host().tile_stats().windows_with_pressure,
        raw.host().tile_stats().windows_with_pressure,
        "the learned ceiling changed how many windows overshot — if it went \
         *down* this is the fix landing and \
         `constrained_link_should_not_lower_the_video_target` is the test to \
         promote\n  raw    : {}\n  learned: {}",
        summary(&raw),
        summary(&learned),
    );
    // And the price. Tracking the threshold closely means landing on it harder,
    // so the throttle refuses more video frames than the raw gap does. Bounded
    // at twice the raw policy's cost: beyond that the trade stops being worth
    // 420 kbps of mean video.
    let (learned_refused, raw_refused) = (
        learned.host().tile_stats().video_frames_backpressured,
        raw.host().tile_stats().video_frames_backpressured,
    );
    assert!(
        learned_refused <= raw_refused * 2,
        "the learned ceiling refused {learned_refused} video frames against the \
         raw policy's {raw_refused}; the closer tracking is costing more than it \
         returns"
    );
    Ok(())
}

/// A window whose budget was *revoked* must not be read as a window that
/// declined its budget.
///
/// `used_its_grant` is derived from `spent_kbps` alone, and `spent_kbps` is zero
/// both when refinement declined to use its allowance and when it was never
/// given one. The throttle used to conflate those, so the first clean window
/// after any revocation could never grow the ceiling however much headroom had
/// appeared — the ramp stalled for exactly one window per revocation. On a link
/// that strains every other window that was not a one-window cost but a
/// permanent pin: the ceiling was knocked back by the backoff and then held,
/// because no window ever both bound and spent. Measured on the 3% lossy row,
/// the ceiling never left [`TILE_CEILING_MIN_KBPS`] for the entire run.
///
/// `last_window_strained` records the distinction explicitly, and this test is
/// the fix stated as a property: a recovery window may grow the ceiling.
#[test]
fn a_revoked_window_does_not_stall_the_ceiling() {
    const TARGET: u32 = 8_000;
    const MEDIA: u32 = 1_000;
    let mut t = TileThrottle::new();
    assert_eq!(t.ceiling(), TILE_CEILING_MIN_KBPS);

    // A clean window that spent its grant grows the ceiling by one step, because
    // nothing is known to hurt yet and the ramp is therefore the fast one.
    let granted = t.observe(TILE_CEILING_MIN_KBPS, TARGET, MEDIA, 0.0, 0.0, false, true, 0);
    let grown = TILE_CEILING_MIN_KBPS + TILE_CEILING_STEP_KBPS;
    assert_eq!(t.ceiling(), grown, "a spent grant is evidence");
    assert_eq!(granted, grown);

    // Backpressure revokes the budget and backs the ceiling off from the spend.
    // That level is now `safe`, so everything above it is creep territory.
    let revoked = t.observe(grown, TARGET, MEDIA, 0.5, 0.0, false, true, 0);
    assert_eq!(revoked, 0, "backpressure must revoke the budget");
    let backed_off = t.ceiling();
    assert_eq!(
        backed_off,
        (grown as f32 * TILE_CEILING_BACKOFF) as u32,
        "the decrease must be anchored to what was spent"
    );

    // The next window is clean and the ceiling is well under the headroom gap,
    // so it is the binding constraint and there is every reason to probe. The
    // window before it granted nothing, so `spent_kbps` is zero — but that is
    // not a refusal and must not be read as one.
    let gap = (TARGET - MEDIA) / 4;
    assert!(backed_off < gap, "the ceiling is the binding constraint here");
    let after = t.observe(0, TARGET, MEDIA, 0.0, 0.0, false, true, 0);
    assert_eq!(
        t.ceiling(),
        backed_off + TILE_CEILING_CREEP_KBPS,
        "the recovery window after a revocation did not grow the ceiling"
    );
    assert_eq!(after, t.ceiling(), "the budget is the ceiling");

    // And it keeps creeping: above the known-safe level the probe is the small
    // one, every window, for as long as the ceiling is what binds.
    t.observe(after, TARGET, MEDIA, 0.0, 0.0, false, true, 0);
    assert_eq!(
        t.ceiling(),
        backed_off + 2 * TILE_CEILING_CREEP_KBPS,
        "the ramp did not continue"
    );
}

/// The concession to a window that was granted nothing buys a *creep*, never a
/// *step*.
///
/// This is the narrow case the rule turns on, and it is the 3% lossy row's
/// window 3 exactly. A loss-only strained window revokes the budget and marks
/// the next window unjudgeable — but, because refinement is not implicated in
/// plain loss, it leaves `safe_kbps` alone. So the recovery window arrives with
/// the ceiling still *below* the known-safe level, where the fast ramp would
/// normally apply, and with no evidence whatsoever that the link would carry
/// more.
///
/// Granting a full step there is how a chronically lossy link ratchets its
/// ceiling back up to the raw unvalidated gap the ceiling exists to bound: every
/// other window is strained, so every other window is unjudgeable, so every
/// other window grows for free. A creep keeps the concession — the link is not
/// pinned at the floor — while making it cost twelve times as long to reach a
/// level nothing has justified.
#[test]
fn a_recovery_window_buys_a_creep_not_a_step() {
    const TARGET: u32 = 8_000;
    const MEDIA: u32 = 1_000;
    let mut t = TileThrottle::new();

    // A lossy window: strained, so the budget goes — but with no backpressure
    // the ceiling is untouched and `safe` is never set, so the ceiling is still
    // in nominal fast-ramp territory.
    assert_eq!(
        t.observe(TILE_CEILING_MIN_KBPS, TARGET, MEDIA, 0.0, 0.05, false, true, 0),
        0
    );
    assert_eq!(t.ceiling(), TILE_CEILING_MIN_KBPS, "loss alone must not learn");

    // The recovery window. It binds, and it is unjudgeable, so it grows — by a
    // creep, because "you had no chance to prove yourself" is a concession and
    // not proof.
    let granted = t.observe(0, TARGET, MEDIA, 0.0, 0.0, false, true, 0);
    assert_eq!(
        t.ceiling(),
        TILE_CEILING_MIN_KBPS + TILE_CEILING_CREEP_KBPS,
        "a window with no evidence behind it took the full step"
    );
    assert_eq!(granted, t.ceiling());

    // Whereas a window that did spend its grant, on the same untouched `safe`,
    // takes the step: the fast ramp is still available, it just has to be earned.
    let mut u = TileThrottle::new();
    u.observe(TILE_CEILING_MIN_KBPS, TARGET, MEDIA, 0.0, 0.0, false, true, 0);
    assert_eq!(
        u.ceiling(),
        TILE_CEILING_MIN_KBPS + TILE_CEILING_STEP_KBPS,
        "evidence must still buy the fast ramp, or this is a blanket slowdown"
    );
}

/// Packet loss with no backpressure must not lower the learned ceiling.
///
/// The two signals mean different things and only one of them implicates
/// refinement. `pressure` is our own sending outrunning the congestion window —
/// tile bytes could have caused that, and the ceiling is the right thing to
/// move. Plain loss is the link dropping packets on its own; video was going to
/// lose those regardless, and cutting the tile ceiling for it is a false
/// attribution that throttles refinement hardest on exactly the links where it
/// was never the problem.
///
/// The budget is still revoked for the window either way — a link that is losing
/// packets is not a link to send luxuries over — but the *learning* is
/// conditional on the signal that actually implicates the learner.
#[test]
fn loss_without_backpressure_does_not_lower_the_ceiling() {
    const TARGET: u32 = 8_000;
    const MEDIA: u32 = 1_000;
    let mut t = TileThrottle::new();

    // Ramp the ceiling up over a few clean windows.
    let mut grant = t.observe(TILE_CEILING_MIN_KBPS, TARGET, MEDIA, 0.0, 0.0, false, true, 0);
    for _ in 0..2 {
        grant = t.observe(grant, TARGET, MEDIA, 0.0, 0.0, false, true, 0);
    }
    let learned = t.ceiling();
    assert!(learned > TILE_CEILING_MIN_KBPS, "nothing was learned to keep");

    // 5% loss, zero backpressure: the budget goes, the ceiling stays.
    let revoked = t.observe(grant, TARGET, MEDIA, 0.0, 0.05, false, true, 0);
    assert_eq!(revoked, 0, "a lossy link must not be granted refinement");
    assert_eq!(
        t.ceiling(),
        learned,
        "loss with no backpressure lowered the ceiling; refinement is being \
         blamed for the link's own drops"
    );

    // The same spend with backpressure instead does lower it, so the assertion
    // above is about the signal and not about the throttle having gone inert.
    let mut u = TileThrottle::new();
    let mut grant = u.observe(TILE_CEILING_MIN_KBPS, TARGET, MEDIA, 0.0, 0.0, false, true, 0);
    for _ in 0..2 {
        grant = u.observe(grant, TARGET, MEDIA, 0.0, 0.0, false, true, 0);
    }
    assert_eq!(u.ceiling(), learned, "the two throttles must start level");
    assert_eq!(u.observe(grant, TARGET, MEDIA, 0.4, 0.0, false, true, 0), 0);
    assert!(
        u.ceiling() < learned,
        "backpressure must still lower the ceiling"
    );
}

/// The cost of the ssthresh structure, stated plainly: a strain event that
/// lands while refinement is spending very little pins `safe_kbps` at the floor,
/// and every probe from then on is a 64 kbps creep.
///
/// The backoff clamps to [`TILE_CEILING_MIN_KBPS`], so `safe` cannot land below
/// 500 kbps however small the spend was — but it also cannot land *above* it,
/// which means one backpressure event at a low spend converts the whole of the
/// range above 500 kbps from a 500 kbps ramp into a 64 kbps creep. Recovering to
/// 4 750 kbps of available headroom then takes 67 windows instead of 9, i.e.
/// over a minute of wall clock on the production 1 s status cadence.
///
/// This is the price of not overshooting and it is charged whether or not
/// refinement caused the event. The attribution fix means plain loss no longer
/// triggers it (see [`loss_without_backpressure_does_not_lower_the_ceiling`]),
/// so it takes real backpressure — but real backpressure can come from video
/// alone, and refinement pays for it either way. If that recovery time ever
/// becomes the complaint, the fix is to floor `safe` at the largest clean spend
/// rather than at [`TILE_CEILING_MIN_KBPS`].
#[test]
fn a_cheap_strain_event_makes_recovery_creep_only() {
    const TARGET: u32 = 20_000;
    const MEDIA: u32 = 1_000;
    let gap = (TARGET - MEDIA) / 4;
    let mut t = TileThrottle::new();

    // One backpressure event while refinement was barely spending. The backoff
    // would land at 0.7 x 200 = 140, so the floor clamp is what sets `safe`.
    assert_eq!(t.observe(200, TARGET, MEDIA, 0.5, 0.0, false, true, 0), 0);
    assert_eq!(
        t.ceiling(),
        TILE_CEILING_MIN_KBPS,
        "the backoff must clamp at the floor rather than go below it"
    );

    // From here every window creeps, because `safe` is the floor and the ceiling
    // is never below it again.
    let mut grant = t.observe(0, TARGET, MEDIA, 0.0, 0.0, false, true, 0);
    let mut windows = 1usize;
    while t.ceiling() < gap && windows < 500 {
        let before = t.ceiling();
        grant = t.observe(grant, TARGET, MEDIA, 0.0, 0.0, false, true, 0);
        assert_eq!(
            t.ceiling() - before,
            TILE_CEILING_CREEP_KBPS,
            "window {windows} grew by more than a creep, so `safe` moved"
        );
        windows += 1;
    }
    // 500 → 4 750 at 64 kbps a window. A flat 500 kbps ramp would have taken 9.
    let flat = (gap - TILE_CEILING_MIN_KBPS).div_ceil(TILE_CEILING_STEP_KBPS) as usize;
    assert_eq!(windows, 67, "the creep-only recovery time changed");
    assert!(
        windows > flat * 7,
        "recovery took {windows} windows against the {flat} a flat ramp would \
         take; the creep is no longer the dominant cost of a strain event"
    );
}

// ---------------------------------------------------------------------------
// Negative control — the hazard is real and the assertions can see it
// ---------------------------------------------------------------------------

/// With the throttle removed, refinement wrecks video. Every row above is only
/// meaningful because this one fails in the way it does.
#[test]
fn unthrottled_tiles_steal_the_window() -> Result<()> {
    // The constrained link is where an unthrottled pass is unambiguous: the
    // budget is larger than everything the link has, so video is squeezed out.
    let cond = &CONDITIONS[CONSTRAINED];
    let (off, _) = pair(cond)?;
    let wild = unthrottled(cond)?;

    let base = presented(&off, "constrained/off");
    let wrecked = presented(&wild, "constrained/unthrottled");
    assert!(
        wrecked * 4 < base,
        "an unthrottled refinement pass still presented {wrecked} of {base} \
         frames, so the harness is not modelling a shared window and every \
         other row in this file is vacuous\n  off : {}\n  wild: {}",
        summary(&off),
        summary(&wild)
    );

    // The signature the hazard doc describes: backpressure climbs, the adaptor
    // is driven down, and the link itself never dropped a thing.
    assert_eq!(wild.net_stats().datagrams_dropped_loss, 0);
    let stats = wild.host().tile_stats();
    assert!(
        stats.video_frames_backpressured > 100,
        "only {} frames were refused",
        stats.video_frames_backpressured
    );
    assert!(
        stats.windows_with_pressure * 2 > stats.windows_closed,
        "pressure was not sustained: {} of {} windows",
        stats.windows_with_pressure,
        stats.windows_closed
    );
    assert_eq!(
        wild.host().bitrate_kbps(),
        AdaptConfig::for_mode(QualityMode::Balanced).floor_kbps,
        "unthrottled refinement should drive the video target to the mode floor"
    );
    assert!(
        wild.host().bitrate_kbps() < off.host().bitrate_kbps(),
        "the control ended no lower than its own tiles-off run"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// The budget policy on its own — no transport, no netsim, never flaky
// ---------------------------------------------------------------------------

/// [`tile_budget_kbps`] and [`BitrateAdaptor`] driven together over a scripted
/// sequence of status windows.
///
/// This is the policy in isolation: no link, no frames, no simulator, so it
/// cannot be slow and cannot be flaky. The sequence walks the three states that
/// matter — clean, backpressured with *zero* loss (the hazard's exact
/// signature), and lossy — and pins what the pair of them does.
///
/// The asymmetry it exists to record is in the last group of assertions: the
/// budget re-arms in the very first clean window, but the video target the
/// backpressure cost does not come back for another `raise_after_ms` per
/// `step_kbps`. The throttle recovers in one second; video takes twenty.
#[test]
fn tile_budget_collapses_on_backpressure_and_rearms_only_when_clean() {
    /// Encoder output held constant, as on a content-limited screen.
    const MEDIA_KBPS: u32 = 1_000;
    /// A flat RTT: this test is about loss and backpressure, not RTT inflation.
    const RTT_MS: f32 = 120.0;
    /// Window indices that measure backpressure, with no loss whatsoever.
    const BACKPRESSURE: std::ops::RangeInclusive<usize> = 4..=7;
    /// Window indices that measure loss above the cutoff, with no backpressure.
    const LOSSY: std::ops::RangeInclusive<usize> = 12..=15;

    let adapt = AdaptConfig::for_mode(QualityMode::Balanced);
    let mut adaptor = BitrateAdaptor::new(adapt);
    let mut budgets: Vec<u32> = Vec::new();
    let mut targets: Vec<u32> = Vec::new();

    for i in 0..24usize {
        let now_ms = i as u64 * 1_000;
        let (pressure, loss) = if BACKPRESSURE.contains(&i) {
            (0.4, 0.0)
        } else if LOSSY.contains(&i) {
            (0.0, 0.05)
        } else {
            (0.0, 0.0)
        };
        // Exactly what `status_loop` does, in the same order.
        let congestion = congestion_signal(loss, pressure, 0.0, false);
        adaptor.observe(now_ms, congestion, RTT_MS);
        let budget = tile_budget_kbps(
            adaptor.current(),
            MEDIA_KBPS,
            pressure,
            loss,
            false,
            true,
            0,
        );
        budgets.push(budget);
        targets.push(adaptor.current());
    }

    // The exact transcript, so this is a test of the policy rather than of the
    // word "changed". Read it as: four clean windows granting a budget, four
    // backpressured windows granting nothing while the target is cut in half
    // twice over, recovery, then the same again driven by loss instead.
    assert_eq!(
        targets,
        vec![
            8_000, 8_000, 8_000, 8_750, 6_125, 4_287, 3_000, 2_100, 2_100, 2_100, 2_100, 2_850,
            1_995, 1_500, 1_500, 1_500, 1_500, 1_500, 1_500, 2_250, 2_250, 2_250, 3_000, 3_000,
        ],
        "adaptor target sequence changed"
    );
    assert_eq!(
        budgets,
        vec![
            1_750, 1_750, 1_750, 1_937, 0, 0, 0, 0, 275, 275, 275, 462, 0, 0, 0, 0, 125, 125, 125,
            312, 312, 312, 500, 500,
        ],
        "tile budget sequence changed"
    );

    // 1. Backpressure with no loss at all still zeroes the budget outright.
    //    This is the hazard signature and the single most important line here.
    for i in BACKPRESSURE {
        assert_eq!(budgets[i], 0, "window {i} granted a budget under backpressure");
    }
    // 2. So does loss over the cutoff, with no backpressure at all.
    for i in LOSSY {
        assert_eq!(budgets[i], 0, "window {i} granted a budget on a lossy link");
    }
    // 3. Before any strain, the budget is exactly a quarter of the headroom.
    for i in 0..*BACKPRESSURE.start() {
        assert_eq!(budgets[i], (targets[i] - MEDIA_KBPS) / 4);
        assert!(budgets[i] > 0);
    }
    // 4. The throttle is a gate, not a latch: the first clean window after the
    //    strain grants a budget again.
    let after = *BACKPRESSURE.end() + 1;
    assert!(
        budgets[after] > 0,
        "the budget stayed revoked after the link came back"
    );
    // 5. And the asymmetry. The budget is back in one window; the video target
    //    the tile traffic cost is not, and is still far below where it was.
    let before = *BACKPRESSURE.start() - 1;
    assert!(
        targets[after] * 3 < targets[before],
        "target recovered from {} to {} in one window, which AIMD cannot do",
        targets[before],
        targets[after]
    );
    let regained = targets[23];
    assert!(
        regained < targets[before],
        "after twenty-four windows the target is {regained}, back at the {} it \
         started from — the ramp is not being exercised",
        targets[before]
    );

    // The operator's ceiling narrows the grant and can never widen it.
    let headroom = (targets[0] - MEDIA_KBPS) / 4;
    assert_eq!(
        tile_budget_kbps(targets[0], MEDIA_KBPS, 0.0, 0.0, false, true, 100),
        100
    );
    assert_eq!(
        tile_budget_kbps(targets[0], MEDIA_KBPS, 0.0, 0.0, false, true, 999_999),
        headroom
    );
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

/// Every row, run twice, must produce the same transcript event for event.
#[test]
fn every_row_is_bit_repeatable() -> Result<()> {
    for cond in CONDITIONS {
        for (name, tiles) in [
            ("off", TileSim::off(cond.link_kbps)),
            ("on", TileSim::on(cond.link_kbps)),
            (
                "unthrottled",
                TileSim::unthrottled(cond.link_kbps, cond.link_kbps),
            ),
        ] {
            let label = format!("{}/{name}", cond.label);
            let first = run(cond, tiles)?;
            let second = run(cond, tiles)?;
            assert_logs_match(first.log(), second.log(), &label);
            assert_eq!(
                first.net_stats(),
                second.net_stats(),
                "{label}: link counters diverge"
            );
            assert_eq!(
                first.host().tile_stats(),
                second.host().tile_stats(),
                "{label}: tile counters diverge"
            );
            assert_eq!(
                first.host().bitrate_kbps(),
                second.host().bitrate_kbps(),
                "{label}: final bitrate diverges"
            );
            assert!(!first.log().is_empty(), "{label}: produced no events");
        }
    }
    Ok(())
}

/// A tiles-OFF run must be identical to what the same configuration produced
/// before refinement existed, up to the shared-window model itself: no tile
/// events, no tile bytes, no budget.
#[test]
fn tiles_off_is_inert() -> Result<()> {
    for cond in CONDITIONS {
        let off = run(cond, TileSim::off(cond.link_kbps))?;
        let stats = off.host().tile_stats();
        assert_eq!(stats.tile_bytes_sent, 0, "{}", cond.label);
        assert_eq!(stats.tile_bytes_dropped, 0, "{}", cond.label);
        assert_eq!(off.host().tile_budget_kbps(), 0, "{}", cond.label);
        assert!(
            off.host().tile_windows().iter().all(|w| w.budget_kbps == 0),
            "{}: a tiles-off run granted a budget",
            cond.label
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

/// Print the whole matrix. Not an assertion — run it with `--nocapture` when a
/// row fails and it shows which half moved and in which window.
#[test]
fn matrix_summary() -> Result<()> {
    for cond in CONDITIONS {
        let (off, on) = pair(cond)?;
        let raw = run(cond, TileSim::raw_gap(cond.link_kbps))?;
        let div = run(cond, TileSim::on(cond.link_kbps).divisible())?;
        let wild = unthrottled(cond)?;
        eprintln!("--- {} (link {} kbps) ---", cond.label, cond.link_kbps);
        eprintln!("  off : {}", summary(&off));
        eprintln!("  raw : {}", summary(&raw));
        eprintln!("  on  : {}", summary(&on));
        eprintln!("  div : {}", summary(&div));
        eprintln!("  wild: {}", summary(&wild));

        let windows = on.host().tile_windows();
        let bound = windows
            .iter()
            .filter(|w| w.budget_kbps > 0 && w.budget_kbps == w.ceiling_kbps)
            .count();
        let damaging = windows
            .iter()
            .filter(|w| w.pressure > 0.0 && w.spent_kbps > 0)
            .count();
        eprintln!(
            "  ceiling bound the grant in {bound}/{} windows; {damaging} damaging \
             (pressure with a spend), {} pressure windows total",
            windows.len(),
            windows.iter().filter(|w| w.pressure > 0.0).count(),
        );
        for (i, w) in windows.iter().enumerate() {
            let safe = safe_before(windows, i)
                .map_or_else(|| "  none".to_string(), |s| format!("{s:>6}"));
            eprintln!(
                "    t={:>5} pressure={:.3} loss={:.3} media={:>5} adaptor={:>6} \
                 spent={:>5} gap={:>6} safe={safe} ceiling={:>6} budget={:>5}",
                w.at_ms,
                w.pressure,
                w.loss,
                w.media_kbps,
                w.adaptor_kbps,
                w.spent_kbps,
                gap_of(w),
                w.ceiling_kbps,
                w.budget_kbps
            );
        }
    }
    Ok(())
}
