//! The DirectDesk integration matrix.
//!
//! Each row is one `#[test]`, each row owns all of its state, and each row uses
//! a distinct seed — so no two rows share a loss or jitter schedule and the
//! suite is safe to run in parallel. Every assertion is made against the
//! harness's event log: presented frame ids, content-hash verdicts,
//! capture-to-present ages, keyframe requests and honourings, input send and
//! injection instants, bitrate decisions, mux delivery order. Nothing here
//! passes merely because it did not panic.
//!
//! Latency bounds are computed from the scenario, never guessed; see
//! [`SimConfig::present_age_bound_ms`] for the derivation, and the fallback row
//! below for the queueing-delay version of the same argument.

use directdesk_shared::adapt::AdaptConfig;
use directdesk_shared::error::Result;
use directdesk_shared::netsim::{NetParams, Outage};
use directdesk_shared::protocol::QualityMode;
use directdesk_tests::assertions::{
    assert_all_hashes_ok, assert_contiguous, assert_strictly_increasing, max_age_ms, mean_age_ms,
};
use directdesk_tests::{
    assert_logs_match, MuxClass, Route, Sim, SimConfig, FRAME_RECORD_HEADER_LEN, MUX_HEADER_LEN,
};

// ---------------------------------------------------------------------------
// Shared scaffolding
// ---------------------------------------------------------------------------

/// A link with the given one-way latency, jitter and datagram loss.
fn link(latency_ms: u64, jitter_ms: u64, loss_pct: f32) -> NetParams {
    NetParams {
        latency_ms,
        jitter_ms,
        loss_pct,
        ..NetParams::perfect()
    }
}

/// Frames the final fifth of a run must still be presenting for the stream to
/// count as live: half of the nominal frame rate. Anything at or above this is
/// a stream that is still moving; zero is a permanent stall.
fn min_tail_presents(sim: &Sim) -> usize {
    let window_ms = sim.now_ms() / 5;
    ((window_ms / sim.config().frame_interval_ms) / 2) as usize
}

/// Assert the stream was still delivering frames in the final fifth of the run.
fn assert_still_live(sim: &Sim, label: &str) {
    let end = sim.now_ms();
    let tail = sim.log().presented_between(end - end / 5, end);
    let need = min_tail_presents(sim);
    assert!(
        tail.len() >= need,
        "{label}: only {} frames presented in the final {} ms; expected at least {need} \
         (a permanent stall)",
        tail.len(),
        end / 5
    );
    assert_all_hashes_ok(&tail, label);
}

/// Assert every injected input arrived in send order with no gaps, and that
/// essentially everything sent was delivered.
///
/// The reliable stream never drops and never reorders, so a gap or an inversion
/// here is a harness or transport defect, not a network condition. A handful of
/// events may still be in flight when the clock stops, hence the tolerance.
fn assert_input_stream_intact(sim: &Sim, label: &str) {
    let log = sim.log();
    let sent = log.inputs_sent();
    let injected = log.inputs_injected();
    let seqs: Vec<u32> = injected.iter().map(|(seq, _)| *seq).collect();
    for (i, seq) in seqs.iter().enumerate() {
        assert_eq!(
            *seq, i as u32,
            "{label}: input {seq} injected out of order at position {i}"
        );
    }
    assert!(
        injected.len() + 3 >= sent.len(),
        "{label}: {} inputs sent but only {} injected",
        sent.len(),
        injected.len()
    );
    assert!(
        !injected.is_empty(),
        "{label}: no input was delivered at all"
    );
}

// ---------------------------------------------------------------------------
// Row builders
//
// Each returns a fully run session. They are separate from the `#[test]`s so
// the repeatability row can replay every one of them, including the rows that
// change link conditions part-way through.
// ---------------------------------------------------------------------------

const DURATION_CLEAN: u64 = 6_000;
const DURATION_LOSSY: u64 = 8_000;
const DURATION_OUTAGE: u64 = 14_000;
const DURATION_ADAPT: u64 = 22_000;
const DURATION_FALLBACK: u64 = 12_000;

/// 200 ms one-way, no loss.
fn row_clean() -> Result<Sim> {
    let mut sim = Sim::new(SimConfig::new(link(200, 0, 0.0), 0xD1CE_0001))?;
    sim.run_to(DURATION_CLEAN)?;
    Ok(sim)
}

/// 200 ms one-way, 1% datagram loss.
fn row_loss_1pct() -> Result<Sim> {
    let mut sim = Sim::new(SimConfig::new(link(200, 0, 1.0), 0xD1CE_0002))?;
    sim.run_to(DURATION_LOSSY)?;
    Ok(sim)
}

/// 200 ms one-way, 3% datagram loss.
fn row_loss_3pct() -> Result<Sim> {
    let mut sim = Sim::new(SimConfig::new(link(200, 0, 3.0), 0xD1CE_0003))?;
    sim.run_to(DURATION_LOSSY)?;
    Ok(sim)
}

/// 250 ms one-way, 30 ms jitter, 5% datagram loss.
fn row_hostile() -> Result<Sim> {
    let mut sim = Sim::new(SimConfig::new(link(250, 30, 5.0), 0xD1CE_0004))?;
    sim.run_to(DURATION_LOSSY)?;
    Ok(sim)
}

/// The link is down entirely from 4 s to 9 s.
fn row_outage() -> Result<Sim> {
    let mut params = link(200, 0, 0.0);
    params.outages = vec![Outage::new(OUTAGE_START_MS, OUTAGE_LEN_MS)];
    let mut sim = Sim::new(SimConfig::new(params, 0xD1CE_0005))?;
    sim.run_to(DURATION_OUTAGE)?;
    Ok(sim)
}

const OUTAGE_START_MS: u64 = 4_000;
const OUTAGE_LEN_MS: u64 = 5_000;
const OUTAGE_END_MS: u64 = OUTAGE_START_MS + OUTAGE_LEN_MS;

/// A 700 ms window of 70% loss part-way through an otherwise clean run. High
/// enough to shred frames, low enough that fragments keep arriving — so the
/// reassembler accumulates *partial* frames it must throw away rather than
/// display.
fn row_loss_spike() -> Result<Sim> {
    let clean = link(100, 0, 0.0);
    let mut sim = Sim::new(SimConfig::new(clean.clone(), 0xD1CE_0006))?;
    sim.run_to(SPIKE_START_MS)?;
    sim.set_params(link(100, 0, 70.0))?;
    sim.run_to(SPIKE_END_MS)?;
    sim.set_params(clean)?;
    sim.run_to(DURATION_LOSSY)?;
    Ok(sim)
}

const SPIKE_START_MS: u64 = 2_000;
const SPIKE_END_MS: u64 = 2_700;

/// Sustained 5% loss, then a clean link for long enough to climb back.
fn row_adaptation() -> Result<Sim> {
    let mut sim = Sim::new(SimConfig::new(link(50, 0, 5.0), 0xD1CE_0007))?;
    sim.run_to(ADAPT_PHASE_MS)?;
    sim.set_params(link(50, 0, 0.0))?;
    sim.run_to(DURATION_ADAPT)?;
    Ok(sim)
}

const ADAPT_PHASE_MS: u64 = 8_000;

/// 200 ms one-way with 10 ms jitter and no loss — the latency-ceiling row.
fn row_latency_ceiling() -> Result<Sim> {
    let mut sim = Sim::new(SimConfig::new(link(200, 10, 0.0), 0xD1CE_0008))?;
    sim.run_to(DURATION_LOSSY)?;
    Ok(sim)
}

/// Every datagram is dropped from the first millisecond — what a network that
/// blocks UDP looks like from inside the session. Streams still work.
fn row_udp_blocked() -> Result<Sim> {
    let mut cfg = SimConfig::new(link(30, 0, 100.0), 0xD1CE_0009);
    cfg.fallback_enabled = true;
    let mut sim = Sim::new(cfg)?;
    sim.run_to(DURATION_FALLBACK)?;
    Ok(sim)
}

/// A named row: its label and the builder that runs it end to end.
type Row = (&'static str, fn() -> Result<Sim>);

/// Every row, for the repeatability check.
fn all_rows() -> Vec<Row> {
    vec![
        ("clean", row_clean as fn() -> Result<Sim>),
        ("loss_1pct", row_loss_1pct),
        ("loss_3pct", row_loss_3pct),
        ("hostile", row_hostile),
        ("outage", row_outage),
        ("loss_spike", row_loss_spike),
        ("adaptation", row_adaptation),
        ("latency_ceiling", row_latency_ceiling),
        ("udp_blocked", row_udp_blocked),
    ]
}

// ---------------------------------------------------------------------------
// Row 1 — 200 ms RTT, 0% loss
// ---------------------------------------------------------------------------

#[test]
fn clean_link_presents_every_frame_in_order() -> Result<()> {
    let sim = row_clean()?;
    let log = sim.log();
    let presented = log.presented();

    // Roughly `duration / frame_interval` frames, less the ~200 ms still in
    // flight when the clock stops.
    assert!(
        presented.len() >= 150,
        "expected ~166 frames in {DURATION_CLEAN} ms, got {}",
        presented.len()
    );
    assert_eq!(
        presented[0].frame_id, 1,
        "numbering starts at the first frame"
    );
    assert!(presented[0].keyframe, "a session opens on a keyframe");
    assert_contiguous(&presented, "clean");
    assert_all_hashes_ok(&presented, "clean");
    assert!(presented.iter().all(|p| p.route == Route::Datagram));

    // Hash continuity is 100%: every frame that was captured and had time to
    // arrive was presented, exactly once, with the right content.
    let captured = log.captured_ids();
    assert_eq!(captured[0], 1);
    assert!(captured.len() > presented.len());
    assert_eq!(
        presented.last().expect("presented").frame_id as usize,
        presented.len(),
        "no id was skipped"
    );

    // A lossless link opens with one keyframe and never needs another.
    assert_eq!(presented.iter().filter(|p| p.keyframe).count(), 1);
    assert!(
        log.keyframe_requests().is_empty(),
        "nothing was lost, so nothing should have been asked for: {:?}",
        log.keyframe_requests()
    );
    assert_eq!(sim.net_stats().datagrams_dropped_loss, 0);
    assert!(log.datagram_rejections().is_empty());
    assert!(log.control_rejections().is_empty());

    // Age is exactly the one-way latency: no jitter to add, and the client
    // observes the arrival on the same tick the host sent it plus 200 ms.
    let bound = sim.config().present_age_bound_ms();
    assert_eq!(bound, 205, "200 latency + 0 jitter + 5 tick");
    assert_eq!(max_age_ms(&presented), 200);
    assert!(max_age_ms(&presented) <= bound);

    // Input round trip: one-way latency, no jitter, no quantisation loss.
    assert_input_stream_intact(&sim, "clean");
    let latencies = log.input_latencies();
    for (seq, latency) in &latencies {
        assert_eq!(
            *latency, 200,
            "input {seq} took {latency} ms on a 200 ms jitter-free link"
        );
    }
    // Ping/pong sees the same link in both directions.
    assert!(log.rtt_samples().iter().all(|(_, rtt)| *rtt == 400));
    Ok(())
}

// ---------------------------------------------------------------------------
// Rows 2 and 3 — 1% and 3% loss
// ---------------------------------------------------------------------------

/// Shared body for the two mild-loss rows: the stream must keep flowing, ask
/// for keyframes when it loses its reference, get them, and never show a frame
/// that failed its content hash.
fn assert_recovers_under_loss(sim: &Sim, label: &str, min_presented: usize) {
    let log = sim.log();
    let presented = log.presented();

    assert!(
        presented.len() >= min_presented,
        "{label}: only {} frames presented",
        presented.len()
    );
    assert_all_hashes_ok(&presented, label);
    assert_strictly_increasing(&presented, label);
    assert!(presented.iter().all(|p| p.route == Route::Datagram));

    // Loss actually happened, and it actually cost frames.
    assert!(
        sim.net_stats().datagrams_dropped_loss > 0,
        "{label}: the link dropped nothing, so this row proves nothing"
    );
    let stats = sim.client().reassembly_stats();
    assert!(
        stats.frames_dropped_stale + stats.frames_dropped_incomplete > 0,
        "{label}: no incomplete frame was ever abandoned"
    );

    // The client noticed and asked; the host heard and armed the encoder.
    let requests = log.keyframe_requests();
    let honored = log.keyframes_honored();
    assert!(
        !requests.is_empty(),
        "{label}: frames were lost but no keyframe was requested"
    );
    assert!(
        honored.len() + 1 >= requests.len(),
        "{label}: {} requests but only {} honoured",
        requests.len(),
        honored.len()
    );
    for (request, honor) in requests.iter().zip(&honored) {
        assert!(
            honor > request,
            "{label}: a keyframe was honoured at {honor} before it was requested at {request}"
        );
    }
    assert!(
        presented.iter().filter(|p| p.keyframe).count() >= 2,
        "{label}: recovery keyframes never reached the decoder"
    );

    assert_still_live(sim, label);
    assert_input_stream_intact(sim, label);
}

#[test]
fn one_percent_loss_recovers_without_stalling() -> Result<()> {
    let sim = row_loss_1pct()?;
    assert_recovers_under_loss(&sim, "1% loss", 180);
    // A lossless stream would present every frame; 1% costs a few and no more.
    assert!(sim.log().presented().len() >= sim.log().captured_ids().len() * 8 / 10);
    Ok(())
}

#[test]
fn three_percent_loss_recovers_without_stalling() -> Result<()> {
    let sim = row_loss_3pct()?;
    // Same liveness and correctness statements, more tolerance on the count.
    assert_recovers_under_loss(&sim, "3% loss", 160);
    assert!(
        sim.log().keyframe_requests().len() > 3,
        "3% loss should provoke more keyframe demand than 1% did"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Row 4 — 250 ms, 5% loss, 30 ms jitter
// ---------------------------------------------------------------------------

#[test]
fn hostile_link_stays_live_and_correct() -> Result<()> {
    let sim = row_hostile()?;
    let log = sim.log();
    let presented = log.presented();
    let params = &sim.config().params;

    assert!(presented.len() >= 140, "got {}", presented.len());
    assert_all_hashes_ok(&presented, "hostile");
    assert_strictly_increasing(&presented, "hostile");
    assert_still_live(&sim, "hostile");
    assert!(!log.keyframe_requests().is_empty());

    // 30 ms of jitter is enough for a frame to be overtaken while its slot is
    // still open, so a straggler slot finishes *after* a newer frame was already
    // delivered. The reassembler refuses to hand that straggler over — that
    // refusal is what keeps the sequence above strictly increasing, and it must
    // actually be happening rather than being vacuously true. The evidence is
    // the reassembler's dedicated reorder-drop counter (the client's present
    // slot is now only a defense-in-depth backstop and no longer fires).
    let reorder_drops = sim.client().reassembly_stats().frames_dropped_reorder;
    assert!(
        reorder_drops > 0,
        "jitter this high should strand at least one late frame in the reassembler"
    );

    // Jitter cannot push a frame past latency + jitter, even at 5% loss: a lost
    // frame costs the *frame*, never extra age on the ones that do arrive.
    let bound = sim.config().present_age_bound_ms();
    assert_eq!(bound, 285, "250 latency + 30 jitter + 5 tick");
    assert!(
        max_age_ms(&presented) <= bound,
        "worst presented age {} exceeded the bound {bound}",
        max_age_ms(&presented)
    );

    // Streams are lossless in the netsim, so input must be perfect: in order,
    // complete, and inside the same latency envelope.
    assert_input_stream_intact(&sim, "hostile");
    let floor = params.latency_ms - params.jitter_ms;
    let ceiling = sim.config().input_latency_bound_ms();
    for (seq, latency) in log.input_latencies() {
        assert!(
            latency >= floor && latency <= ceiling,
            "input {seq} took {latency} ms, outside {floor}..={ceiling}"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Row 5 — a five-second total outage mid-run
// ---------------------------------------------------------------------------

#[test]
fn total_outage_stalls_then_recovers() -> Result<()> {
    let sim = row_outage()?;
    let log = sim.log();
    let params = &sim.config().params;

    // Before: a healthy stream.
    let before = log.presented_between(0, OUTAGE_START_MS);
    assert!(
        before.len() > 90,
        "got {} frames before the outage",
        before.len()
    );
    assert_all_hashes_ok(&before, "outage/before");

    // During: nothing. A datagram is lost if it is sent into the window *or*
    // would land in it, so presentation stops at the outage and stays stopped
    // until one full latency after it lifts.
    let dark_until = OUTAGE_END_MS + params.latency_ms;
    assert!(
        log.presented_between(OUTAGE_START_MS, dark_until)
            .is_empty(),
        "frames were presented while the link was down: {:?}",
        log.presented_between(OUTAGE_START_MS, dark_until)
    );

    // After: it comes back, promptly, and correctly.
    let after = log.presented_between(OUTAGE_END_MS, DURATION_OUTAGE);
    assert!(!after.is_empty(), "the stream never resumed");
    assert!(
        after[0].at_ms <= OUTAGE_END_MS + 1_000,
        "first frame after the outage arrived at {} ms",
        after[0].at_ms
    );
    assert_all_hashes_ok(&after, "outage/after");
    assert_strictly_increasing(&presented_all(&sim), "outage");

    // Five seconds at ~30 fps is ~150 frame ids, far beyond the reassembler's
    // forward-jump window — so the first datagrams back are *refused*, and the
    // resync run is what re-adopts the numbering. Both halves must show up.
    assert!(
        !log.datagram_rejections().is_empty(),
        "the forward-jump guard should have refused the post-outage jump"
    );
    assert!(
        sim.client().reassembly_stats().fragments_rejected > 0
            && sim.client().reassembly_stats().frames_completed > before.len() as u64,
        "the reassembler refused the jump but never resynced"
    );

    // Keyframe recovery kicks in and a keyframe actually reaches the decoder.
    assert!(
        log.keyframe_requests()
            .iter()
            .any(|t| *t > OUTAGE_END_MS && *t < OUTAGE_END_MS + 1_000),
        "no keyframe was requested after the link came back: {:?}",
        log.keyframe_requests()
    );
    assert!(
        after.iter().any(|p| p.keyframe),
        "recovery never delivered a keyframe"
    );

    // Input is reliable, so it is *queued*, not lost: nothing is delivered
    // during the outage and everything sent through it arrives afterwards, in
    // order.
    let sent_during = log
        .inputs_sent()
        .iter()
        .filter(|(_, at)| *at >= OUTAGE_START_MS && *at < OUTAGE_END_MS)
        .count();
    assert!(
        sent_during >= 40,
        "only {sent_during} inputs were written during the outage"
    );
    let injected_during = log
        .inputs_injected()
        .iter()
        .filter(|(_, at)| *at > OUTAGE_START_MS && *at < dark_until)
        .count();
    assert_eq!(
        injected_during, 0,
        "input was injected while the link was down"
    );
    assert_input_stream_intact(&sim, "outage");

    // No wedge: the reassembler is healthy and the stream is still moving.
    assert_still_live(&sim, "outage");
    assert!(log.control_rejections().is_empty());
    assert_eq!(
        sim.host().route(),
        Route::Datagram,
        "no fallback in this row"
    );
    Ok(())
}

fn presented_all(sim: &Sim) -> Vec<directdesk_tests::Presented> {
    sim.log().presented()
}

// ---------------------------------------------------------------------------
// Row 6 — forced keyframe recovery after a loss spike
// ---------------------------------------------------------------------------

#[test]
fn loss_spike_forces_keyframe_recovery() -> Result<()> {
    let sim = row_loss_spike()?;
    let log = sim.log();
    let presented = log.presented();

    // The spike really did shred frames, and it left *partial* ones behind.
    assert!(sim.net_stats().datagrams_dropped_loss > 20);
    let stats = sim.client().reassembly_stats();
    assert!(
        stats.frames_dropped_stale + stats.frames_dropped_incomplete > 0,
        "70% loss should strand partially received frames: {stats:?}"
    );

    // Those partials were discarded, never displayed. Every frame that reached
    // the present slot verified byte for byte against its id.
    assert_all_hashes_ok(&presented, "loss spike");
    assert_strictly_increasing(&presented, "loss spike");

    // Demand fires, the host honours it, and a keyframe reaches the decoder.
    let request = log
        .keyframe_requests()
        .into_iter()
        .find(|t| *t >= SPIKE_START_MS)
        .expect("the spike must provoke a keyframe request");
    assert!(
        request < SPIKE_END_MS + 500,
        "the client took until {request} ms to notice"
    );
    let honor = log
        .keyframes_honored()
        .into_iter()
        .find(|t| *t > request)
        .expect("the host must honour the request");
    assert!(honor >= request + sim.config().params.latency_ms);

    // How long recovery may take once the link is clean again. The encoder
    // arms exactly one keyframe per request, so a keyframe lost to the spike
    // costs a full retry: one rate-limit interval before the client may ask
    // again, one one-way trip for the request, up to a frame interval before
    // the encoder next runs, one one-way trip back, and a tick of quantisation
    // at each end.
    let cfg = sim.config();
    let recovery_bound = cfg.reassembly.keyframe_request_min_interval_ms
        + 2 * cfg.params.latency_ms
        + cfg.frame_interval_ms
        + 2 * cfg.tick_ms;
    assert_eq!(recovery_bound, 743);

    let keyframe = presented
        .iter()
        .find(|p| p.keyframe && p.at_ms > SPIKE_START_MS)
        .expect("presentation must resume with a keyframe");
    assert!(
        keyframe.at_ms <= SPIKE_END_MS + recovery_bound,
        "keyframe arrived at {} ms, past the {} ms recovery bound",
        keyframe.at_ms,
        SPIKE_END_MS + recovery_bound
    );
    assert!(
        keyframe.at_ms > honor,
        "the keyframe must follow the request"
    );
    assert!(keyframe.hash_ok);

    // And the stream continues past it.
    let resumed = log.presented_between(keyframe.at_ms, sim.now_ms());
    assert!(
        resumed.len() > 100,
        "only {} frames after recovery",
        resumed.len()
    );
    assert_still_live(&sim, "loss spike");
    Ok(())
}

// ---------------------------------------------------------------------------
// Row 7 — bitrate adaptation down, then back up
// ---------------------------------------------------------------------------

#[test]
fn bitrate_falls_under_loss_and_recovers_when_clean() -> Result<()> {
    let sim = row_adaptation()?;
    let log = sim.log();
    let adapt = AdaptConfig::for_mode(QualityMode::Balanced);
    let changes = log.bitrate_changes();
    let sequence: Vec<u32> = changes.iter().map(|(_, kbps)| *kbps).collect();

    // The exact output sequence, which is what makes this a test of the
    // adaptor's policy rather than of the word "changed": multiplicative
    // decrease at most once a second down to the mode floor, then additive
    // `step_kbps` increases once conditions have been clean for `raise_after_ms`.
    assert_eq!(
        sequence,
        vec![5_600, 3_920, 2_744, 1_920, 1_500, 2_250, 3_000, 3_750, 4_500],
        "adaptor output sequence changed"
    );

    let trough = sequence
        .iter()
        .position(|k| *k == adapt.floor_kbps)
        .expect("loss should drive the target to the mode floor");
    let (down, up) = sequence.split_at(trough + 1);
    assert!(down.len() >= 5 && down.windows(2).all(|w| w[1] < w[0]));
    assert!(up.len() >= 4 && up.windows(2).all(|w| w[1] > w[0]));
    assert!(
        down[0] < adapt.start_kbps,
        "the first move must be downward"
    );
    for step in up.windows(2) {
        assert_eq!(
            step[1] - step[0],
            adapt.step_kbps,
            "increase must be additive"
        );
    }

    // Every decrease belongs to the lossy phase, every increase to the clean one.
    for (at_ms, kbps) in &changes[..=trough] {
        assert!(
            *at_ms <= ADAPT_PHASE_MS,
            "bitrate dropped to {kbps} at {at_ms} ms, after the loss ended"
        );
    }
    for (at_ms, kbps) in &changes[trough + 1..] {
        assert!(
            *at_ms > ADAPT_PHASE_MS,
            "bitrate rose to {kbps} at {at_ms} ms, while the link was still lossy"
        );
    }
    assert_eq!(
        sim.host().bitrate_kbps(),
        *sequence.last().expect("changes")
    );

    // The feedback that drove it: real measurements, above the adaptor's 2%
    // congestion threshold while lossy and exactly zero once clean.
    let reports = log.loss_reports();
    let lossy: Vec<f32> = reports
        .iter()
        .filter(|(t, _)| *t < ADAPT_PHASE_MS)
        .map(|(_, l)| *l)
        .collect();
    assert!(lossy.len() >= 10);
    let mean = lossy.iter().sum::<f32>() / lossy.len() as f32;
    assert!(
        (0.02..0.12).contains(&mean),
        "measured loss averaged {mean}, not the 5% the link was configured for"
    );
    // A settled clean link reports no loss at all.
    for (at_ms, loss) in reports.iter().filter(|(t, _)| *t > ADAPT_PHASE_MS + 1_000) {
        assert_eq!(
            *loss, 0.0,
            "loss {loss} reported at {at_ms} on a clean link"
        );
    }

    assert_all_hashes_ok(&log.presented(), "adaptation");
    assert_still_live(&sim, "adaptation");
    Ok(())
}

// ---------------------------------------------------------------------------
// Row 8 — the latency ceiling
// ---------------------------------------------------------------------------

#[test]
fn presented_frame_age_stays_under_the_computed_ceiling() -> Result<()> {
    let sim = row_latency_ceiling()?;
    let log = sim.log();
    let presented = log.presented();
    let params = &sim.config().params;

    // Bound = one-way latency + worst jitter draw + one tick of client polling
    // quantisation. Reassembly contributes nothing: all four fragments are sent
    // in the same virtual millisecond, the frame completes in the pump that
    // receives the slowest of them, and it is presented in that same pump.
    let bound = sim.config().present_age_bound_ms();
    assert_eq!(bound, 215, "200 latency + 10 jitter + 5 tick");

    let worst = max_age_ms(&presented);
    assert!(
        worst <= bound,
        "worst presented age {worst} ms exceeded the computed ceiling {bound} ms"
    );
    assert!(
        worst >= params.latency_ms,
        "age {worst} ms is below the one-way latency, which is impossible"
    );
    // In practice the jitter draw is a multiple of the tick here, so the tick
    // term is absorbed and the worst case lands exactly on latency + jitter.
    assert_eq!(worst, 210);
    let mean = mean_age_ms(&presented);
    assert!(
        mean > params.latency_ms as f64 && mean < bound as f64,
        "mean age {mean} ms outside {}..{bound}",
        params.latency_ms
    );

    // Nothing was lost, so nothing may be skipped and nothing may be asked for.
    assert_contiguous(&presented, "ceiling");
    assert_all_hashes_ok(&presented, "ceiling");
    assert!(log.keyframe_requests().is_empty());
    assert_eq!(sim.net_stats().datagrams_dropped_loss, 0);
    assert_eq!(
        sim.client().reassembly_stats().frames_skipped_latest_wins,
        0,
        "frames 33 ms apart with +/-10 ms jitter cannot overlap"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Row 9 — UDP blocked, reliable-stream fallback
// ---------------------------------------------------------------------------

#[test]
fn blocked_datagrams_fall_back_to_the_reliable_path() -> Result<()> {
    let sim = row_udp_blocked()?;
    let log = sim.log();
    let cfg = sim.config();
    let params = &cfg.params;

    // Nothing ever got through on datagrams.
    let net = sim.net_stats();
    assert_eq!(net.datagrams_delivered, 0);
    assert!(net.datagrams_dropped_loss > 0);
    assert_eq!(sim.client().reassembly_stats().frames_completed, 0);

    // The client noticed the silence and the host moved video to the stream.
    let requested = log
        .fallback_requested_at()
        .expect("the client must detect a dead datagram path");
    let engaged = log
        .fallback_engaged_at()
        .expect("the host must engage the fallback");
    assert_eq!(
        requested, cfg.fallback_probe_ms,
        "detected on the probe window"
    );
    assert!(engaged >= requested + params.latency_ms && engaged <= requested + 100);
    assert_eq!(sim.host().route(), Route::Fallback);
    assert_eq!(sim.client().route(), Route::Fallback);

    // Video flows again, over the reliable path, intact and in order.
    let presented = log.presented();
    assert!(
        presented.len() > 150,
        "only {} frames presented",
        presented.len()
    );
    assert!(presented.iter().all(|p| p.route == Route::Fallback));
    assert_all_hashes_ok(&presented, "fallback");
    assert_strictly_increasing(&presented, "fallback");
    assert!(
        presented[0].keyframe,
        "a path change must re-anchor the decoder"
    );
    assert_still_live(&sim, "fallback");
    assert!(log.control_rejections().is_empty());

    // Derived queueing bounds. One record is
    // `MUX_HEADER_LEN + FRAME_RECORD_HEADER_LEN + frame_bytes` on the wire, and
    // the sender writes `mux_bytes_per_tick` per tick.
    let record_bytes = MUX_HEADER_LEN + FRAME_RECORD_HEADER_LEN + cfg.frame_bytes;
    let ticks_for = |bytes: usize| (bytes.div_ceil(cfg.mux_bytes_per_tick) as u64) * cfg.tick_ms;
    let net_ms = params.latency_ms + params.jitter_ms + cfg.tick_ms;
    // Worst case for a small record: the whole of one video record is already
    // on the wire and cannot be interrupted. It waits for that remainder, and
    // for nothing else in the queue.
    let inflight_ms = ticks_for(record_bytes);
    let control_bound = inflight_ms + net_ms;
    // Input additionally yields to any control record queued ahead of it; those
    // are tens of bytes, so one tick covers them.
    let input_bound = control_bound + cfg.tick_ms;
    // A video record waits for everything the backlog cap allows plus the record
    // on the wire, and for the control and input records that overtake it — a
    // few tens of bytes each, generously four ticks.
    let video_bound =
        ticks_for((cfg.mux_max_video_backlog + 1) * record_bytes) + 4 * cfg.tick_ms + net_ms;
    assert_eq!((control_bound, input_bound, video_bound), (90, 95, 260));

    let deliveries = log.mux_deliveries();
    assert!(deliveries.len() > 200);
    for delivery in &deliveries {
        let bound = match delivery.class {
            MuxClass::Control => control_bound,
            MuxClass::Input => input_bound,
            MuxClass::Video => video_bound,
        };
        assert!(
            delivery.queue_delay_ms() <= bound,
            "{:?} record {} waited {} ms, over its {bound} ms bound",
            delivery.class,
            delivery.seq,
            delivery.queue_delay_ms()
        );
    }

    // The point of the row: latency-sensitive traffic is *not* delayed behind
    // queued video. Both classes overtake video records that were enqueued
    // before them — impossible on a FIFO sender — and both stay inside a bound
    // far below what video experiences.
    let worst = |class: MuxClass| {
        deliveries
            .iter()
            .filter(|d| d.class == class)
            .map(|d| d.queue_delay_ms())
            .max()
            .unwrap_or(0)
    };
    assert!(
        log.priority_bypasses(MuxClass::Input) > 10,
        "input never overtook queued video, so priority is not being exercised"
    );
    assert!(log.priority_bypasses(MuxClass::Control) > 10);
    assert!(
        worst(MuxClass::Input) < worst(MuxClass::Video),
        "input waited as long as video: {} vs {}",
        worst(MuxClass::Input),
        worst(MuxClass::Video)
    );
    assert!(worst(MuxClass::Control) < worst(MuxClass::Video));

    // Drop-stale keeps the backlog — and therefore the age of what is on screen
    // — bounded, instead of retransmitting frames nobody will ever look at.
    assert!(
        !log.mux_video_drops().is_empty(),
        "the offered bitrate exceeds the link, so stale video must be shed"
    );
    assert_eq!(
        sim.host().mux_stats().video_dropped_stale as usize,
        log.mux_video_drops().len()
    );
    assert!(max_age_ms(&presented) <= video_bound);
    // The backlog is shed, not accumulated: the tail is no staler than the head.
    let end = sim.now_ms();
    assert!(
        max_age_ms(&log.presented_between(end - end / 5, end)) <= max_age_ms(&presented),
        "presented age grew over the run, so the backlog is not being bounded"
    );

    // Input on its own client-to-host stream is untouched by any of this.
    assert_input_stream_intact(&sim, "fallback");
    for (seq, latency) in log.input_latencies() {
        assert!(
            latency <= cfg.input_latency_bound_ms(),
            "input {seq} took {latency} ms"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn every_row_is_bit_repeatable() -> Result<()> {
    for (name, build) in all_rows() {
        let first = build()?;
        let second = build()?;
        assert_logs_match(first.log(), second.log(), name);
        assert_eq!(
            first.net_stats(),
            second.net_stats(),
            "{name}: link counters diverge"
        );
        assert_eq!(
            first.client().reassembly_stats(),
            second.client().reassembly_stats(),
            "{name}: reassembler counters diverge"
        );
        assert!(!first.log().is_empty(), "{name}: produced no events");
    }
    Ok(())
}

#[test]
fn rows_use_distinct_seeds_and_therefore_distinct_schedules() -> Result<()> {
    // Two lossy rows differing only in seed and loss rate must not coincide.
    let a = row_loss_1pct()?;
    let b = row_loss_3pct()?;
    assert_ne!(a.log(), b.log());
    assert_ne!(
        a.net_stats().datagrams_dropped_loss,
        b.net_stats().datagrams_dropped_loss
    );
    Ok(())
}
