//! The live session: everything an authenticated client gets, from the media
//! pipeline coming up to the last held key being released.
//!
//! [`run_session`] is the orchestrator. It brings the pipeline up, arms the
//! guards that have to fire on *every* exit path, spawns the four loops below
//! alongside the two pumps in [`super::egress`], and then does nothing at all
//! until the connection closes. The loops are deliberately small and
//! single-purpose: `input_loop` injects, `control_loop` answers the client,
//! `status_loop` measures one window and hands the result to the adaptor, and
//! `event_loop` relays driver events.
//!
//! The order of the local bindings in [`run_session`] is load-bearing, and the
//! reasons are written at the bindings themselves. Rust drops locals in reverse
//! declaration order, so moving one line silently changes what happens at
//! session end — and binding a guard to a bare `_` drops it immediately instead
//! of at scope end, which for [`ReleaseGuard`] would mean client-held input is
//! never released.
//!
//! What belongs here: session-scoped orchestration, and the loops that live for
//! exactly one client.
//!
//! What does not: how bytes reach the wire is [`super::egress`], *how much* to
//! send is decided in [`super::adaptation`], the UAC click-through is
//! [`super::elevation`], and getting as far as `AuthOk` is
//! [`super::handshake`]. The counters these loops read and reset stay in
//! [`crate::net`], because the pumps in [`super::egress`] write them.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use quinn::Connection;
use tokio::sync::mpsc;

use directdesk_shared::adapt::{AdaptConfig, BitrateAdaptor};
use directdesk_shared::input::validate_event;
use directdesk_shared::protocol::{Codec, ControlMsg, InputMsg};
use directdesk_shared::stats::ConnStats;
use directdesk_shared::transport::quic::SessionStreams;
use directdesk_shared::transport::session::{
    QuicSession, Session, SessionConfig as DriverConfig, SessionEvent,
};

use crate::session::{HostSession, SessionState};

use super::adaptation::{
    clamp_to_cap, effective_cap, effective_fps, overrun_signal, window_congestion, RateLimiter,
    StatusWindow, TileThrottle, WindowDelivery, STATUS_INTERVAL_MS,
};
use super::egress::{tile_pump, video_pump};
use super::elevation::elevation_loop;
use super::{Inner, NetEvent, TileCounters, VideoCounters, CLOSE_CODE_REJECTED, HOST_ROUTE};

/// Floor on how often a *client's* `RequestKeyframe` is honoured. The client
/// only asks when its own decoder is stuck (a frame-id gap), and it rate-limits
/// itself; gating that a second time at 500 ms is what made recovery from a
/// scene-change stall take up to 1.5 s on a high-RTT link.
pub const CLIENT_KEYFRAME_MIN_INTERVAL_MS: u64 = 200;

/// Releases every held key and button when a session ends, on every path.
struct ReleaseGuard(Arc<HostSession>);

impl Drop for ReleaseGuard {
    fn drop(&mut self) {
        self.0.release_all_input();
        // Stop refinement dead when the client goes away. The media pipeline is
        // a singleton that outlives every connection, and `status_loop` — the
        // only thing that ever lowers this — has just been aborted, so without
        // this the media thread would carry on compressing and queueing strips
        // at the departed client's measured budget, for a desktop nobody is
        // watching. Those stale bytes would then be the first thing the *next*
        // client's stream carried, ahead of its own `Reset`, competing with its
        // connect keyframe.
        self.0.set_tile_budget_kbps(0);
        tracing::info!("released all client-held input");
    }
}

/// Drive one authenticated client until the connection ends.
///
/// Returns the reason the session finished, for the log and the UI.
pub(super) async fn run_session(
    inner: &Arc<Inner>,
    conn: Connection,
    streams: SessionStreams,
    negotiated_features: u64,
) -> String {
    let pipeline = match inner.ensure_pipeline().await {
        Ok(p) => p,
        Err(e) => {
            let detail = format!("media pipeline unavailable: {e}");
            tracing::error!("{detail}");
            inner.status_mut(|s| s.last_error = Some(detail.clone()));
            conn.close(CLOSE_CODE_REJECTED.into(), b"host pipeline unavailable");
            return detail;
        }
    };
    // Nothing below may return without this guard being dropped.
    let _release = ReleaseGuard(pipeline.clone());
    // The pipeline is a singleton that outlives any one connection, so a
    // reconnecting client inherits a grid that still believes the *previous*
    // client's tiles are resident. This client's store is empty. Reset
    // unconditionally — it costs one full refinement sweep on a screen we are
    // about to send a keyframe for anyway, and skipping it means a permanently
    // soft picture on every connection after the first.
    pipeline.reset_tiles();
    // Bandwidth saver: blank the desktop to black for the life of this
    // session and restore it on every exit path (this function's `String`
    // return covers all of them — success, error, timeout, disconnect). A
    // no-op guard when the config flag is off. Scoped to the session rather
    // than the pipeline because the pipeline outlives a single client.
    let _wallpaper =
        crate::wallpaper::WallpaperGuard::new(inner.cfg.blank_wallpaper_during_session);

    let driver_cfg = DriverConfig {
        heartbeat_ms: 2_000,
        stats_interval_ms: STATUS_INTERVAL_MS,
        control_capacity: 64,
        input_capacity: 512,
        // The host only ever *sends* video (`video_pump` below). Running the
        // driver's receive path here would keep a reassembler alive for
        // datagrams no client sends, and give the client a second, unlimited
        // route into `request_keyframe` — the `ControlMsg::RequestKeyframe`
        // path in `control_loop` is rate-limited, `SessionEvent::KeyframeNeeded`
        // is not.
        receive_video: false,
        ..DriverConfig::default()
    };
    let (session, receivers) =
        match QuicSession::start(conn.clone(), streams, HOST_ROUTE, driver_cfg) {
            Ok(v) => v,
            Err(e) => {
                let detail = format!("session driver failed to start: {e}");
                tracing::error!("{detail}");
                conn.close(CLOSE_CODE_REJECTED.into(), b"session start failed");
                return detail;
            }
        };
    let session = Arc::new(session);

    let streaming = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let counters = Arc::new(VideoCounters::default());
    let adaptor = Arc::new(Mutex::new(BitrateAdaptor::new(AdaptConfig::for_mode(
        *inner.quality.lock(),
    ))));

    let video = {
        let conn = conn.clone();
        let frames = pipeline.frames();
        let pipeline = pipeline.clone();
        let streaming = streaming.clone();
        let stop = stop.clone();
        let counters = counters.clone();
        std::thread::Builder::new()
            .name("dd-video-tx".into())
            .spawn(move || video_pump(conn, frames, pipeline, streaming, stop, counters))
            .ok()
    };
    if video.is_none() {
        tracing::error!("could not spawn the video sender thread");
    }

    // Elevation click-through: the control loop forwards `ArmElevation` here;
    // `elevation_loop` owns the state machine, the detector poll, and the SYSTEM
    // worker's lifecycle. It is NOT in `tasks` (which are hard-aborted): it is
    // stopped cooperatively via `stop` and awaited so it can tear the worker and
    // the input route down cleanly before the next client connects.
    let (arm_tx, arm_rx) = mpsc::unbounded_channel::<(bool, u32)>();
    let elevation = tokio::spawn(elevation_loop(
        inner.clone(),
        session.clone(),
        pipeline.clone(),
        arm_rx,
        stop.clone(),
    ));

    // Lossless refinement, only when BOTH ends asked for it. `negotiated_features`
    // is already the intersection, so this is a single bit test — and a client
    // that predates the feature never gets a stream opened at it.
    let tile_counters = Arc::new(TileCounters::default());
    let mut tasks = vec![
        tokio::spawn(input_loop(receivers.input, pipeline.clone())),
        tokio::spawn(control_loop(
            inner.clone(),
            receivers.control,
            session.clone(),
            pipeline.clone(),
            streaming.clone(),
            adaptor.clone(),
            arm_tx,
        )),
        tokio::spawn(status_loop(
            inner.clone(),
            session.clone(),
            pipeline.clone(),
            adaptor,
            counters.clone(),
            streaming.clone(),
            tile_counters.clone(),
        )),
        tokio::spawn(event_loop(
            inner.clone(),
            receivers.events,
            pipeline.clone(),
        )),
    ];

    if negotiated_features & directdesk_shared::protocol::features::LOSSLESS_TILES != 0 {
        tasks.push(tokio::spawn(tile_pump(
            conn.clone(),
            pipeline.tiles(),
            stop.clone(),
            tile_counters,
        )));
    }

    let reason = conn.closed().await.to_string();

    stop.store(true, Ordering::SeqCst);
    streaming.store(false, Ordering::SeqCst);
    for t in tasks {
        t.abort();
    }
    // Await (do not abort) the elevation loop so it tears down any live SYSTEM
    // worker and clears the input route before the next client connects.
    let _ = elevation.await;
    if let Some(v) = video {
        let _ = v.join();
    }
    // Explicit, not just the guard: input must be released before the next
    // client can possibly connect.
    pipeline.release_all_input();

    inner.status_mut(|s| {
        s.frames_sent = counters.frames_sent.load(Ordering::Relaxed);
        s.bytes_sent = counters.bytes_sent.load(Ordering::Relaxed);
        s.frames_coalesced = counters.coalesced.load(Ordering::Relaxed);
        s.frames_backpressured = counters.backpressured.load(Ordering::Relaxed);
        s.pace_deadline_bursts = counters.pace_deadline_bursts.load(Ordering::Relaxed);
        s.frames_unfragmentable = counters.frames_unfragmentable.load(Ordering::Relaxed);
        // A per-window gauge, like `delivery`: with no session there is no
        // window, so it reads zero rather than freezing at the last value.
        s.emit_ms_max = 0;
        s.transport = ConnStats::default();
        s.delivery = WindowDelivery::default();
        s.quality_mode = None;
    });
    reason
}

/// Inbound input. The driver has already decoded and validated; validating
/// again is cheap and keeps this the last line of defence before injection.
async fn input_loop(mut rx: mpsc::Receiver<InputMsg>, pipeline: Arc<HostSession>) {
    let tx = pipeline.input_sender();
    while let Some(msg) = rx.recv().await {
        match msg {
            InputMsg::Event(ev) => match validate_event(&ev) {
                Ok(()) => {
                    if tx.send(ev).is_err() {
                        tracing::warn!("input pipeline closed; stopping input forwarding");
                        return;
                    }
                }
                Err(e) => tracing::warn!("rejected input event: {e}"),
            },
            InputMsg::ReleaseAll => {
                tracing::info!("client asked for a full input release");
                pipeline.release_all_input();
            }
        }
    }
}

/// Session control from the client.
#[allow(clippy::too_many_arguments)]
async fn control_loop(
    inner: Arc<Inner>,
    mut rx: mpsc::Receiver<ControlMsg>,
    session: Arc<QuicSession>,
    pipeline: Arc<HostSession>,
    streaming: Arc<AtomicBool>,
    adaptor: Arc<Mutex<BitrateAdaptor>>,
    arm_tx: mpsc::UnboundedSender<(bool, u32)>,
) {
    let mut keyframes = RateLimiter::new(CLIENT_KEYFRAME_MIN_INTERVAL_MS);

    while let Some(msg) = rx.recv().await {
        let now = inner.now_ms();
        match msg {
            ControlMsg::StartStream {
                max_width,
                max_height,
                preferred_fps,
                quality_mode,
            } => {
                let (w, h) = pipeline.dimensions();
                tracing::info!(
                    "stream requested: client canvas {max_width}x{max_height} @ {preferred_fps} \
                     fps, {quality_mode:?}; host sends {w}x{h}"
                );
                *inner.quality.lock() = quality_mode;
                // The client's preference narrows the host's frame rate, never
                // widens it — same contract as `BitrateLimit` (`effective_cap`).
                // The host side of that is the LIVE value, not `cfg.pipeline`:
                // an operator who lowered the rate mid-session must not have it
                // undone by the next StartStream.
                let host_fps = *inner.fps.lock();
                let fps = effective_fps(host_fps, preferred_fps);
                *inner.fps.lock() = fps;
                pipeline.set_fps(fps);
                {
                    let mut a = adaptor.lock();
                    a.set_mode(quality_mode, now);
                    apply_bitrate(&inner, &pipeline, a.current());
                }
                pipeline.request_keyframe();
                streaming.store(true, Ordering::SeqCst);

                let cfg = ControlMsg::VideoConfig {
                    width: w,
                    height: h,
                    // The intended rate, not `pipeline.active_fps()`: `set_fps`
                    // lands on the media thread on its next pass (up to one
                    // frame away), so reading it back here would still report
                    // the old value. `active_fps()` is for the status path,
                    // where observed truth is what is wanted.
                    fps,
                    bitrate_kbps: adaptor.lock().current(),
                    codec: Codec::H264,
                };
                if let Err(e) = session.send_control(cfg) {
                    tracing::warn!("could not send VideoConfig: {e}");
                }
            }
            ControlMsg::StopStream => {
                tracing::info!("client stopped the stream");
                streaming.store(false, Ordering::SeqCst);
            }
            ControlMsg::RequestKeyframe => {
                if keyframes.allow(now) {
                    pipeline.request_keyframe();
                } else {
                    tracing::trace!("keyframe request rate-limited");
                }
            }
            ControlMsg::QualityChange(mode) => {
                tracing::info!("quality mode changed to {mode:?}");
                *inner.quality.lock() = mode;
                let mut a = adaptor.lock();
                a.set_mode(mode, now);
                apply_bitrate(&inner, &pipeline, a.current());
            }
            ControlMsg::BitrateLimit { max_kbps } => {
                tracing::info!("client asked for a bitrate limit of {max_kbps:?} kbps");
                // The client's request narrows, never widens, the host's cap.
                let effective = effective_cap(*inner.bitrate_cap.lock(), max_kbps);
                *inner.bitrate_cap.lock() = effective;
                apply_bitrate(&inner, &pipeline, adaptor.lock().current());
            }
            ControlMsg::ClipboardText(text) => {
                // Clipboard is a later milestone. Say so rather than pretending.
                tracing::info!(
                    "ignoring {} bytes of clipboard text (not implemented)",
                    text.len()
                );
            }
            ControlMsg::Stats(peer) => {
                inner.status_mut(|s| {
                    s.transport.fps_decode = peer.fps_decode;
                    s.transport.fps_present = peer.fps_present;
                });
            }
            ControlMsg::ArmElevation { one_shot, ttl_secs } => {
                if !inner.cfg.uac_clickthrough {
                    tracing::warn!("client armed elevation but uac_clickthrough is off; ignoring");
                } else {
                    tracing::info!("client armed elevation (one_shot={one_shot}, ttl={ttl_secs}s)");
                    // Hand it to the elevation loop; if that task is gone the
                    // session is ending anyway.
                    let _ = arm_tx.send((one_shot, ttl_secs));
                }
            }
            other => tracing::debug!("ignoring control message from client: {other:?}"),
        }
    }
}

fn apply_bitrate(inner: &Arc<Inner>, pipeline: &Arc<HostSession>, kbps: u32) {
    // A `BitrateLimit`/host cap is a hard ceiling on what the encoder is ever
    // asked for, applied on top of whatever the adaptor picked within its mode
    // range. The encoder never sees a value above the cap.
    let capped = clamp_to_cap(kbps, *inner.bitrate_cap.lock());
    pipeline.set_bitrate(capped);
    inner.status_mut(|s| s.target_kbps = capped);
}

/// Periodic host → client status, and the adaptive bitrate loop.
async fn status_loop(
    inner: Arc<Inner>,
    session: Arc<QuicSession>,
    pipeline: Arc<HostSession>,
    adaptor: Arc<Mutex<BitrateAdaptor>>,
    counters: Arc<VideoCounters>,
    streaming: Arc<AtomicBool>,
    tile_counters: Arc<TileCounters>,
) {
    let mut ticker = tokio::time::interval(Duration::from_millis(STATUS_INTERVAL_MS));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_paused: Option<bool> = None;
    let mut window = StatusWindow::new(inner.now_ms());
    let mut tile_throttle = TileThrottle::new();
    let mut prev_tile_bytes = 0u64;

    loop {
        ticker.tick().await;
        if session.is_closed() {
            return;
        }
        let now = inner.now_ms();
        let transport = session.stats();
        let media = pipeline.stats();
        let state = pipeline.state();
        let paused = matches!(state, SessionState::Paused(_));

        // Merge: the transport owns RTT/loss/bandwidth, the pipeline owns the
        // capture and encode numbers. Neither invents the other's.
        let merged = ConnStats {
            rtt_ms: transport.rtt_ms,
            jitter_ms: transport.jitter_ms,
            loss: transport.loss,
            bandwidth_kbps: transport.bandwidth_kbps,
            fps_capture: media.fps_capture,
            fps_encode: media.fps_encode,
            fps_decode: 0.0,
            fps_present: 0.0,
            bitrate_kbps: media.bitrate_kbps,
            frames_dropped: media.frames_dropped,
            keyframes_requested: media.keyframes_requested,
            pipeline_ms: media.pipeline_ms,
            // End-to-end input confirmation: report how many client keystrokes
            // this host has actually injected, so the client can see whether the
            // keys it sent are landing here.
            input_injected: pipeline.input_events_injected(),
        };

        // Everything below is a delta over THIS window (a matched sliding
        // window, never a lifetime total), measured against the real elapsed
        // time so the throughput figure is honest even if a tick was skipped.
        // `StatusWindow` owns the previous tick's raw counters and folds them
        // into that delta, plus whether the stream is warm enough for the
        // overrun ratio (see its doc comment) to be trusted.
        let sent = counters.frames_sent.load(Ordering::Relaxed);
        let bytes = counters.bytes_sent.load(Ordering::Relaxed);
        let backpressured = counters.backpressured.load(Ordering::Relaxed);
        let pace_deadline_bursts = counters.pace_deadline_bursts.load(Ordering::Relaxed);
        // A gauge over this window only: take it and leave the counter at zero
        // so the next window measures itself rather than inheriting a spike.
        let emit_ms_max = counters.emit_ms_max.swap(0, Ordering::Relaxed);
        let (delivery, warm) = window.close(now, sent, bytes, backpressured);

        // Backpressure is congestion the packet-level loss counter cannot see:
        // quinn accepted every datagram we offered and then dropped some itself.
        // It is a matched-window ratio, so it does not skew like the old
        // lifetime comparison did.
        let pressure = delivery.backpressure_ratio();

        let overrun = overrun_signal(media.bitrate_kbps, transport.bandwidth_kbps);
        // A keyframe the fragmenter refused outranks every measured signal:
        // nothing of it reached the wire, and the next IDR would be the same
        // size unless the bitrate comes down. Read-and-clear, then hand the
        // adaptor a full congestion event.
        let oversized_keyframe = counters.oversized_keyframe.swap(false, Ordering::Relaxed);
        if oversized_keyframe {
            tracing::error!("a keyframe was too big to fragment; forcing a bitrate cut");
        }
        let congestion =
            window_congestion(transport.loss, delivery, overrun, warm, oversized_keyframe);
        if let Some(next) = adaptor.lock().observe(now, congestion, transport.rtt_ms) {
            tracing::info!(
                "adaptive bitrate → {next} kbps (loss {:.1}%, send pressure {:.1}%, \
                 overrun {:.1}%{}: encoder {} kbps vs link {} kbps)",
                transport.loss * 100.0,
                pressure * 100.0,
                overrun * 100.0,
                if warm { "" } else { " [gated]" },
                media.bitrate_kbps,
                transport.bandwidth_kbps
            );
            apply_bitrate(&inner, &pipeline, next);
        }
        let quality_mode = *inner.quality.lock();

        let _ = session.send_control(ControlMsg::Stats(merged));
        let _ = session.send_control(ControlMsg::RouteReport(HOST_ROUTE));
        if last_paused != Some(paused) {
            last_paused = Some(paused);
            tracing::info!(
                "secure desktop {}",
                if paused { "active" } else { "cleared" }
            );
            let _ = session.send_control(ControlMsg::SecureDesktopActive(paused));
            if !paused {
                // The desktop we came back to may look nothing like the one we
                // left; the client needs a fresh IDR to resync.
                pipeline.request_keyframe();
            }
        }

        let injected = pipeline.input_events_injected();
        // Observed, not requested: a rebuild that failed must not be reported as
        // if it had taken.
        let active_fps = pipeline.active_fps();
        inner.status_mut(|s| {
            s.transport = transport;
            s.pipeline = merged;
            s.pipeline_state = Some(format!("{state:?}"));
            s.secure_desktop = paused;
            s.quality_mode = Some(quality_mode);
            s.target_fps = active_fps;
            s.delivery = delivery;
            s.frames_sent = sent;
            s.bytes_sent = bytes;
            s.frames_coalesced = counters.coalesced.load(Ordering::Relaxed);
            s.frames_backpressured = backpressured;
            s.pace_deadline_bursts = pace_deadline_bursts;
            s.frames_unfragmentable = counters.frames_unfragmentable.load(Ordering::Relaxed);
            s.emit_ms_max = emit_ms_max;
            s.input_injected = injected;
        });
        // Cumulative injected count beside the send rate: under full video load
        // this should keep climbing as the client types (proving input is not
        // starved by encode). It stalling while frames_sent races is the
        // signature of the input-priority bug.
        tracing::info!(
            input_injected = injected,
            frames_sent = sent,
            "host input diag"
        );

        // Refill the refinement allowance from this window's measurements. Done
        // here because every input is already computed once per second and
        // agrees with what the adaptor just decided — recomputing any of it
        // elsewhere would risk the two disagreeing.
        // What refinement actually spent over the window just closed. This is
        // the evidence the ceiling is learned from, so it must be a matched
        // delta over the same window as `delivery`, not a lifetime total.
        let tile_bytes_now = tile_counters.bytes_sent.load(Ordering::Relaxed);
        let tile_spent_kbps = {
            // `delivery.dt_ms`, not a fresh `now`-based diff: `window.close()`
            // already advanced its own previous-tick clock above, so measuring
            // elapsed time again here would always give zero.
            let dt_ms = delivery.dt_ms.max(1);
            let delta = tile_bytes_now.saturating_sub(prev_tile_bytes);
            ((delta * 8) / dt_ms) as u32
        };
        prev_tile_bytes = tile_bytes_now;

        let budget = tile_throttle.observe(
            tile_spent_kbps,
            adaptor.lock().current(),
            media.bitrate_kbps,
            pressure,
            transport.loss,
            oversized_keyframe,
            streaming.load(Ordering::Relaxed),
            inner.cfg.tile_max_kbps,
        );
        // Published to the media thread, which is the only place a strip can be
        // dropped safely — it owns the grid, so it can decline to *plan* work
        // rather than discard work it has already recorded as delivered.
        pipeline.set_tile_budget_kbps(budget);

        let tile_strips = tile_counters.strips_sent.load(Ordering::Relaxed);
        if tile_strips > 0 {
            // Hazard 6's observable signature, logged together on purpose: if
            // `backpressured` climbs while tile traffic flows and loss stays at
            // zero, tiles are stealing the congestion window from video and the
            // budget above is too generous.
            tracing::info!(
                tile_strips,
                tile_kbytes = tile_counters.bytes_sent.load(Ordering::Relaxed) / 1024,
                tile_spent_kbps,
                tile_budget_kbps = budget,
                tile_ceiling_kbps = tile_throttle.ceiling(),
                backpressured,
                loss = transport.loss,
                "tile diag"
            );
        }
    }
}

/// Driver-level events: warnings, peer `Bye`, keyframe requests from loss.
async fn event_loop(
    inner: Arc<Inner>,
    mut rx: mpsc::Receiver<SessionEvent>,
    pipeline: Arc<HostSession>,
) {
    while let Some(ev) = rx.recv().await {
        match ev {
            SessionEvent::KeyframeNeeded => pipeline.request_keyframe(),
            SessionEvent::PeerClosed { reason } => {
                tracing::info!("client said goodbye: {reason}");
            }
            SessionEvent::Warning { detail } => {
                tracing::warn!("session warning: {detail}");
                inner.emit(NetEvent::Warning { detail });
            }
            SessionEvent::Closed { reason } => {
                tracing::debug!("session closed: {reason}");
                return;
            }
            SessionEvent::Stats(_) => {}
        }
    }
}
