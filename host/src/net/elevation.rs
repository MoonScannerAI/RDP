//! The UAC click-through: watch for a consent prompt, offer it to the client,
//! and — once the operator arms — route input to a transient SYSTEM-integrity
//! worker for as long as the elevation lasts.
//!
//! This is the highest-privilege surface the host has, which is exactly why it
//! is one small file. Three properties have to hold, and all three are enforced
//! here:
//!
//! - Nothing is detected, offered or spawned unless the operator opted in
//!   (`NetConfig::uac_clickthrough`); the loop returns immediately otherwise.
//! - The client may arm the route but cannot outlast the operator: the TTL it
//!   asks for is clamped to the configured ceiling.
//! - The route is torn down on every exit path, including a session that ends
//!   mid-elevation. That is why `run_session` *awaits* this task instead of
//!   aborting it with the others: an aborted loop would leave a SYSTEM worker
//!   holding the input route while the next client connects.
//!
//! What belongs here: the poll, the state machine's effects, the worker's
//! lifecycle, and the forwarder thread that feeds it.
//!
//! What does not: the decision logic is the pure [`ElevationMachine`] in
//! [`crate::uac_client`], prompt detection is [`crate::elevation`], and the
//! ordinary input path — which must keep working while all of this sits idle —
//! stays in [`crate::net`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use directdesk_shared::input::InputEvent;
use directdesk_shared::protocol::{ControlMsg, InputMsg};
use directdesk_shared::svc_ipc::SvcResponse;
use directdesk_shared::transport::session::{QuicSession, Session};
use directdesk_shared::{Error, Result};

use crate::elevation::detect_consent_prompt;
use crate::session::{HostSession, SessionDescription};
use crate::uac_client::{ElevEffect, ElevationMachine, SvcControlClient, UacDataClient};

use super::Inner;

// ---------------------------------------------------------------------------
// UAC click-through orchestration
// ---------------------------------------------------------------------------

/// How often the elevation loop polls for a consent prompt.
const ELEVATION_POLL_MS: u64 = 200;

/// A live SYSTEM-worker route: the forwarder thread draining the input route
/// sink into the worker's data pipe.
struct ActiveRoute {
    forwarder: std::thread::JoinHandle<()>,
}

/// Detect a consent prompt, offer the client the click-through, and — once the
/// operator arms — route input to a transient SYSTEM worker for the duration of
/// the elevation. All Windows/pipe work is done off the runtime via
/// `spawn_blocking`; the decision logic is the pure [`ElevationMachine`].
pub(super) async fn elevation_loop(
    inner: Arc<Inner>,
    session: Arc<QuicSession>,
    pipeline: Arc<HostSession>,
    mut arm_rx: mpsc::UnboundedReceiver<(bool, u32)>,
    stop: Arc<AtomicBool>,
) {
    if !inner.cfg.uac_clickthrough {
        // Opt-out: never detect, never offer, never spawn a SYSTEM worker.
        return;
    }
    tracing::info!("UAC click-through enabled; watching for consent prompts");

    let mut machine = ElevationMachine::new();
    let mut active: Option<ActiveRoute> = None;
    let mut ticker = tokio::time::interval(Duration::from_millis(ELEVATION_POLL_MS));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if stop.load(Ordering::SeqCst) || session.is_closed() {
                    break;
                }
                let prompt = detect_consent_prompt();
                let effect = machine.observe(prompt.is_some(), Instant::now());
                match effect {
                    ElevEffect::None => {}
                    ElevEffect::Notify => {
                        let title = prompt.map(|p| p.title).unwrap_or_default();
                        tracing::info!("consent prompt detected; offering click-through");
                        let _ = session.send_control(ControlMsg::ElevationPrompt { title });
                    }
                    ElevEffect::BeginRoute => {
                        let desc = pipeline.describe();
                        let pl = pipeline.clone();
                        match tokio::task::spawn_blocking(move || start_route(pl, desc)).await {
                            Ok(Ok(route)) => {
                                active = Some(route);
                                tracing::info!("SYSTEM injector routing input for elevation");
                            }
                            Ok(Err(e)) => {
                                tracing::error!("could not start SYSTEM injector: {e}");
                                let _ = machine.cancel();
                                let _ = session.send_control(ControlMsg::ElevationEnded);
                            }
                            Err(e) => {
                                tracing::error!("start-route task failed: {e}");
                                let _ = machine.cancel();
                                let _ = session.send_control(ControlMsg::ElevationEnded);
                            }
                        }
                    }
                    ElevEffect::EndRoute => {
                        if let Some(route) = active.take() {
                            let pl = pipeline.clone();
                            let _ = tokio::task::spawn_blocking(move || end_route(pl, route)).await;
                        } else {
                            pipeline.end_elevation_route();
                        }
                        tracing::info!("elevation ended; input back on the local injector");
                        let _ = session.send_control(ControlMsg::ElevationEnded);
                    }
                    ElevEffect::Cleared => {
                        let _ = session.send_control(ControlMsg::ElevationEnded);
                    }
                }
            }
            armed = arm_rx.recv() => {
                match armed {
                    Some((one_shot, ttl_secs)) => {
                        // The host's config TTL is the ceiling; the client cannot
                        // ask for longer than the operator configured.
                        let ttl_secs = ttl_secs
                            .clamp(crate::config::MIN_UAC_ARM_TTL_SECS, inner.cfg.uac_arm_ttl_secs);
                        let accepted = machine.arm(one_shot, Duration::from_secs(ttl_secs as u64), Instant::now());
                        if accepted {
                            tracing::info!("elevation armed (one_shot={one_shot}, ttl={ttl_secs}s)");
                        } else {
                            tracing::warn!("arm ignored: no consent prompt currently on screen");
                            let _ = session.send_control(ControlMsg::ElevationEnded);
                        }
                    }
                    None => break,
                }
            }
        }
    }

    // Cleanup: tear down any live worker and clear the input route.
    if let Some(route) = active.take() {
        let pl = pipeline.clone();
        let _ = tokio::task::spawn_blocking(move || end_route(pl, route)).await;
        let _ = session.send_control(ControlMsg::ElevationEnded);
    }
    tracing::debug!("elevation loop finished");
}

/// Start the SYSTEM worker, connect its data pipe, flip the session's input
/// route to it, and spawn the forwarder that drains the route into the pipe.
/// Blocking: runs on a `spawn_blocking` thread.
fn start_route(pipeline: Arc<HostSession>, desc: SessionDescription) -> Result<ActiveRoute> {
    let resp = SvcControlClient::start_uac_injector()?;
    let (pipe_name, cap_token) = match resp {
        SvcResponse::UacInjectorReady {
            pipe_name,
            cap_token,
        } => (pipe_name, cap_token),
        SvcResponse::Denied { reason } => {
            return Err(Error::Other(format!(
                "service denied UAC injector: {reason}"
            )));
        }
        other => {
            return Err(Error::Other(format!(
                "unexpected service response to StartUacInjector: {other:?}"
            )));
        }
    };

    let client = UacDataClient::connect(&pipe_name, &cap_token)?;
    client.send_geometry(desc.width, desc.height, desc.monitor_origin)?;

    // The input thread owns the Sender; when the route ends it drops it, which
    // disconnects this Receiver and unblocks the forwarder below.
    let (tx, rx) = crossbeam_channel::unbounded::<InputEvent>();
    pipeline.begin_elevation_route(tx);

    let forwarder = std::thread::Builder::new()
        .name("dd-uac-fwd".into())
        .spawn(move || {
            for ev in rx.iter() {
                if let Err(e) = client.send_input(InputMsg::Event(ev)) {
                    tracing::warn!("UAC forward failed; stopping forwarder: {e}");
                    break;
                }
            }
            // Dropping `client` here closes the pipe, so the worker sees the
            // disconnect and self-exits (after releasing all held input).
            tracing::debug!("UAC forwarder finished");
        })
        .map_err(|e| Error::Other(format!("spawn UAC forwarder: {e}")))?;

    Ok(ActiveRoute { forwarder })
}

/// Leave the route: clear the session's elevation route (which drops the input
/// thread's Sender and unblocks the forwarder), join the forwarder, then ask the
/// service to stop the worker. Blocking.
fn end_route(pipeline: Arc<HostSession>, route: ActiveRoute) {
    pipeline.end_elevation_route();
    let _ = route.forwarder.join();
    if let Err(e) = SvcControlClient::stop_uac_injector() {
        tracing::debug!("stop_uac_injector: {e}");
    }
}
