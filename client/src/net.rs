//! Client transport driver: connect, authenticate, stream.
//!
//! This is the seam between [`crate::session::TransportEndpoints`] (the UI-facing
//! channels) and the real network. [`run_client`] owns the whole lifecycle:
//!
//! 1. **Connect** — QUIC route racing (IPv4 → IPv6). The TCP/TLS fallback and
//!    the staggered racer both exist and are unit-tested in
//!    `directdesk_shared::transport::{tcp, race}`; they are simply not selected
//!    by any binary. This client is QUIC-only *by decision*, behind the
//!    [`connect_race`] seam that `race::connect` slots into once the
//!    `transport-race` cargo feature is enabled. See the `TODO(race)` marker.
//! 2. **Handshake** — a `Hello` exchange, then either SPAKE2 pairing (when a
//!    code is supplied) or steady-state mutual authentication against the pinned
//!    host identity. On a pin/signature mismatch the connection is refused: that
//!    is the anti-MITM gate and it is never weakened.
//! 3. **Stream** — hand the two reliable streams to the transport-agnostic
//!    [`QuicSession`] driver (which already owns the control/input/video pumps,
//!    the heartbeat and the stats sampler) and bridge its typed receivers onto
//!    the UI channels.
//! 4. **Reconnect** — on an unexpected drop, back off (capped) and retry using
//!    the *stored* host identity (never re-pairing — the code is single-use),
//!    until the UI cancels.
//!
//! ## Canonical application handshake (the wire contract)
//!
//! After the QUIC handshake and the two tagged reliable streams are open, on the
//! **control** stream, framed with `u32-le length || postcard`. The host issues
//! **one** `ServerChallenge` immediately after the Hello exchange — *before* it
//! knows which branch we want — and in **both** branches the client proves its
//! Ed25519 key by signing that fresh per-connection `nonce_s`. Which branch runs
//! is chosen by the client from "did the user supply a pairing code?"; the host
//! branches on the message type it reads next.
//!
//! ```text
//! Phase 0 — Hello (client writes first)
//!   C -> H : Hello { version, features, agent = <client display name> }
//!   H -> C : Hello { .. }                              (both validate_hello)
//!
//! Phase 1 — the host always challenges first
//!   H -> C : AuthMsg::ServerChallenge { nonce_s }      (read in both branches)
//!
//! Phase 1a — PAIRING  (user supplied a code)
//!   C -> H : AuthMsg::PairStart    { spake A }
//!   H -> C : AuthMsg::PairResponse { spake B }
//!   C -> H : AuthMsg::PairConfirm  { client mac }
//!   H -> C : AuthMsg::PairConfirm  { host mac }        (client verifies)
//!   H -> C : AuthMsg::PairComplete { host identity }   (client pins host; anti-MITM)
//!   C -> H : AuthMsg::ClientAuth      { client_pub, sig_c over nonce_s }
//!   C -> H : AuthMsg::ClientChallenge { nonce_c }
//!   H -> C : AuthMsg::ServerAuth      { sig_s }        (client verifies pinned host key)
//!   H -> C : AuthMsg::AuthOk                           (client persists host only now)
//!
//! Phase 1b — AUTH  (no code: reconnect of a known host)
//!   C -> H : AuthMsg::ClientAuth      { client_pub, sig_c over nonce_s }
//!   C -> H : AuthMsg::ClientChallenge { nonce_c }
//!   H -> C : AuthMsg::ServerAuth      { sig_s }        (client verifies pinned host key)
//!   H -> C : AuthMsg::AuthOk
//!
//! Phase 1c — MONITORS (only when `features::MULTI_MONITOR` came back mutual)
//!   H -> C : ControlMsg::MonitorList   { monitors }   (guaranteed FIRST post-AuthOk
//!                                                      host message; still raw framed)
//!   C -> H : ControlMsg::SelectMonitors { ids }       (ALWAYS, even for `[0]`)
//!
//! Phase 2 — Stream start (still raw framed, before the session driver attaches)
//!   C -> H : ControlMsg::StartStream { caps, quality }
//! ```
//!
//! The host's answer to `StartStream` — the legacy `VideoConfig` for stream 0,
//! and a `StreamConfig { id: 1, .. }` after it when a second stream is live —
//! arrives on the same control stream but is read by the session driver, not
//! here, so it needs no special handling in the handshake: `StreamConfig` may
//! trail `VideoConfig` by any amount and both simply reach the UI.
//!
//! Phase 1c is skipped entirely when the bit did not come back, and that is the
//! whole compatibility story: against a host that predates multi-monitor the
//! client reads nothing extra and writes nothing extra, so the sequence above
//! is byte-identical to the one every deployed peer already speaks.
//!
//! Both ends then call [`QuicSession::start`] on the same streams and the driver
//! takes over. This is the exact sequence the real `directdesk_host` listener
//! implements (`host::net::{authenticate,pair}`); the `interop.rs` test drives
//! the real client against the real host to prove it.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use directdesk_shared::audio::AudioFrame;
use directdesk_shared::crypto::auth::{
    ClientAuthenticator, TrustedPeer, TrustedPeers, TRUSTED_HOSTS_KEY,
};
use directdesk_shared::crypto::identity::ClientIdentity;
use directdesk_shared::crypto::pairing::{PairingClient, PairingCode};
use directdesk_shared::crypto::storage::SecretStore;
use directdesk_shared::crypto::tls::{ObservedPin, ServerPinning};
use directdesk_shared::crypto::Ed25519Pub;
use directdesk_shared::error::{Error, Result};
use directdesk_shared::input::validate_event;
use directdesk_shared::protocol::{
    self, AuthMsg, ControlMsg, Hello, InputMsg, MonitorInfo, QualityMode, MAX_AUTH_MSG,
    MAX_CONTROL_MSG,
};
use directdesk_shared::stats::{ConnStats, TransportRoute};
use directdesk_shared::tiles::TileMsg;
use directdesk_shared::transport::quic::{self, QuicParams, SessionStreams};
use directdesk_shared::transport::reassembly::ReassemblyConfig;
use directdesk_shared::transport::session::{QuicSession, Session, SessionConfig, SessionEvent};
use quinn::{Connection, Endpoint};
use tokio::sync::watch;

use crate::monitors::{self, MonitorChoice};
use crate::session::{ConnectionState, TransportEndpoints};

/// `Hello.features` bit the client sets to *hint* it intends to pair rather
/// than reconnect. It is only a hint: the real `directdesk_host` branches on the
/// message type it reads after its `ServerChallenge` (`PairStart` vs
/// `ClientAuth`), and the client's own branch is driven by whether the user
/// supplied a pairing code. Occupies a high bit so it never collides with the
/// wire feature flags in [`protocol::features`].
pub const FEATURE_PAIRING_REQUEST: u64 = 1 << 32;

/// Per-attempt QUIC connect timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
/// Per-message read timeout during the handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// First reconnect backoff.
const BACKOFF_MIN: Duration = Duration::from_millis(500);
/// Capped reconnect backoff.
const BACKOFF_MAX: Duration = Duration::from_secs(10);

/// Everything the driver needs to reach and greet a host.
#[derive(Debug, Clone)]
pub struct ConnectParams {
    /// Host name or IP (no port).
    pub host: String,
    pub udp_port: u16,
    /// `Some(code)` selects pairing mode for the first connection.
    pub pairing_code: Option<String>,
    /// This client's friendly name, shown on the host after pairing.
    pub display_name: String,
    pub quality: QualityMode,
    pub max_width: u32,
    pub max_height: u32,
    pub preferred_fps: u32,
    /// Ask the host for lossless refinement of settled regions.
    ///
    /// Only a request: the feature is on solely if the host echoes the bit
    /// back, so leaving this true costs nothing against a host that does not
    /// support it or has it switched off.
    pub lossless_tiles: bool,
    /// Ask the host to stream its system audio.
    ///
    /// Only a request, exactly like [`ConnectParams::lossless_tiles`]: the
    /// feature is on solely if the host echoes `features::SYSTEM_AUDIO` back.
    /// See [`crate::connect::StreamCaps::system_audio`] for why the client's
    /// default is `true` while the host's is `false`.
    pub system_audio: bool,
    /// Which outputs to ask the host for once `features::MULTI_MONITOR`
    /// comes back mutual.
    ///
    /// Unlike [`lossless_tiles`](Self::lossless_tiles) and
    /// [`system_audio`](Self::system_audio) this does **not** decide what the
    /// `Hello` offers — the bit is offered unconditionally (see
    /// [`ConnectParams::hello_features`]) — only what the client does with the
    /// host's `MonitorList` once it has one. `Primary` is today's behaviour
    /// exactly: one stream, one window, and a `SelectMonitors { ids: [0] }`
    /// that tells the host so explicitly.
    pub monitor_choice: MonitorChoice,
}

impl ConnectParams {
    fn start_stream(&self) -> ControlMsg {
        ControlMsg::StartStream {
            max_width: self.max_width,
            max_height: self.max_height,
            preferred_fps: self.preferred_fps,
            quality_mode: self.quality,
        }
    }

    /// The feature bits this client puts in its `Hello`.
    ///
    /// The client asks blind — it advertises before it has seen the host's
    /// reply — and the host answers with the intersection, so everything here
    /// is a request that is off unless it comes back.
    ///
    /// `MULTI_MONITOR` is offered **unconditionally**, including for
    /// [`MonitorChoice::Primary`], and that is deliberate rather than sloppy.
    /// Offering it costs one bit and buys two things a conditional offer could
    /// not: the host sends its `MonitorList`, which is the only way the connect
    /// screen ever learns what outputs exist (a user cannot pick "second
    /// monitor" before anything has told them there is one), and the client
    /// sends an explicit `SelectMonitors { ids: [0] }` instead of leaving the
    /// host to infer the selection. Neither costs a second encoder: the host
    /// starts a second stream only when a selection asks for one.
    fn hello_features(&self, want_pairing: bool) -> u64 {
        let mut features = if want_pairing {
            FEATURE_PAIRING_REQUEST
        } else {
            0
        };
        if self.lossless_tiles {
            features |= protocol::features::LOSSLESS_TILES;
        }
        if self.system_audio {
            features |= protocol::features::SYSTEM_AUDIO;
        }
        features |= protocol::features::MULTI_MONITOR;
        features
    }
}

/// Drive a client session for the lifetime of the connection, reconnecting on
/// drops until `shutdown` flips to `true` or the UI closes its outbound
/// channels.
///
/// Must run inside a tokio runtime. `store` is the persistent secret store used
/// for the client identity and the trusted-host list (inject a `MemoryStore`
/// under test).
pub async fn run_client(
    endpoints: TransportEndpoints,
    params: ConnectParams,
    store: Arc<dyn SecretStore>,
    mut shutdown: watch::Receiver<bool>,
) {
    let TransportEndpoints {
        video_tx,
        stats_tx,
        route_tx,
        state_tx,
        control_tx,
        mut input_rx,
        tiles_tx,
        audio_tx,
        video2_tx,
        mut control_rx,
    } = endpoints;

    // Load-or-create the long-term client identity once.
    let client_id = match ClientIdentity::load_or_create(store.as_ref(), &params.display_name) {
        Ok(id) => id,
        Err(e) => {
            let _ = state_tx.try_send(ConnectionState::Failed(format!("identity: {e}")));
            return;
        }
    };

    // In-memory record of the host we trust. Set by a successful pairing, or
    // loaded when reconnecting in auth mode.
    let mut known_host: Option<TrustedPeer> = if params.pairing_code.is_some() {
        None
    } else {
        sole_trusted_host(store.as_ref())
    };
    let mut want_pairing = params.pairing_code.is_some();
    let mut backoff = BACKOFF_MIN;

    loop {
        if *shutdown.borrow() {
            let _ = state_tx.try_send(ConnectionState::Disconnected);
            return;
        }

        let _ = state_tx.try_send(ConnectionState::Connecting);
        let _ = route_tx.try_send(None);

        let established = connect_and_auth(
            &params,
            &client_id,
            store.as_ref(),
            want_pairing,
            known_host.as_ref(),
            &state_tx,
        )
        .await;

        let Established {
            _endpoint,
            conn,
            streams,
            route,
            paired_host,
            lossless_tiles,
            system_audio,
            multi_monitor,
            monitors,
            selected,
        } = match established {
            Ok(e) => e,
            Err(HandshakeError {
                message,
                recoverable,
            }) => {
                let _ = state_tx.try_send(ConnectionState::Failed(message.clone()));
                if !recoverable {
                    tracing::error!("unrecoverable connect failure: {message}");
                    return;
                }
                tracing::warn!("connect failed: {message}; retrying in {:?}", backoff);
                if wait_or_shutdown(&mut shutdown, backoff).await {
                    let _ = state_tx.try_send(ConnectionState::Disconnected);
                    return;
                }
                backoff = (backoff * 2).min(BACKOFF_MAX);
                continue;
            }
        };

        // A pairing that just succeeded becomes the identity used for every
        // later (re)connect — never pair twice with a single-use code.
        if let Some(peer) = paired_host {
            known_host = Some(peer);
            want_pairing = false;
        }
        backoff = BACKOFF_MIN;

        let _ = state_tx.try_send(ConnectionState::Connected);
        let _ = route_tx.try_send(Some(route));

        // Whether this connection carries a second monitor. Computed once and
        // used for *both* the driver's demux and the bridge below: if those two
        // could disagree, stream-1 datagrams would either be reassembled into a
        // channel nobody reads or dropped before a live bridge.
        let second_stream = second_stream_armed(multi_monitor, &selected);

        // Hand the host's monitor list to the UI on the ordinary inbound
        // control lane, which is where a mid-session `MonitorList` (topology
        // change) already arrives via `forward_control`. The handshake consumed
        // *this* one before the driver existed, so without this re-publish the
        // UI would learn the topology only if the host happened to change it.
        //
        // Sent whenever the feature was mutual, including for a one-entry list
        // and a `Primary` choice: its absence is exactly how the UI recognises
        // a host that cannot do this at all, so an empty-handed connection must
        // stay silent here rather than publish an invented list.
        //
        // This lane is also how the picker's persisted label cache
        // (`ClientConfig::cached_monitors`) gets filled: the UI writes it from
        // this message, because config belongs to the UI thread and nothing on
        // the transport side may reach into it.
        if multi_monitor {
            tracing::info!(
                monitors = monitors.len(),
                selected = ?selected,
                "host accepted monitor selection"
            );
            let _ = control_tx.try_send(ControlMsg::MonitorList { monitors });
        }

        // Attach the session driver; it owns the pumps, heartbeat and stats.
        let cfg = SessionConfig {
            heartbeat_ms: 2_000,
            stats_interval_ms: 1_000,
            control_capacity: 64,
            input_capacity: 256,
            // Generous: the decode thread drains eagerly and does latest-wins,
            // so we must not throw inbound video away at the transport seam.
            video_capacity: 256,
            // Roughly half a second of AAC-LC access units. Deliberately not
            // scaled up the way `video_capacity` was: a deep audio queue is a
            // growing lip-sync offset, never a smoother stream.
            audio_capacity: 32,
            // Tighter than the shared 500ms default: paired with the client's
            // KeyframeGate (pipeline.rs), a gap should get a fresh IDR request
            // on the wire sooner. Leave the shared default alone — sim
            // baselines depend on it.
            reassembly: ReassemblyConfig {
                keyframe_request_min_interval_ms: 250,
                ..ReassemblyConfig::default()
            },
            // The client is the receiving end of a one-directional video path.
            receive_video: true,
            // The second monitor's stream. Armed only when this session
            // actually selected two outputs: an unarmed slot makes the demux
            // drop stream-1 datagrams before any parse, which is what keeps a
            // single-monitor session paying nothing for the feature.
            receive_video_1: second_stream,
            // And of the audio path, which is one-directional the same way.
            // Left unconditionally on rather than gated on `system_audio`: a
            // host that did not echo the bit sends no audio datagrams at all,
            // so the flag costs an idle queue and nothing else, while gating it
            // would add a second place the feature can be off. The demux that
            // keeps these datagrams away from the video reassembler runs
            // regardless of this flag either way.
            receive_audio: true,
        };
        let (session, receivers) = match QuicSession::start(conn, streams, route, cfg) {
            Ok(pair) => pair,
            Err(e) => {
                let _ = state_tx.try_send(ConnectionState::Failed(format!("session: {e}")));
                if wait_or_shutdown(&mut shutdown, backoff).await {
                    return;
                }
                continue;
            }
        };
        let session = Arc::new(session);

        // Bridge the driver's inbound receivers onto the UI's crossbeam senders.
        let closed = Arc::new(tokio::sync::Notify::new());
        let mut fwd = vec![
            tokio::spawn(forward_video(receivers.video, video_tx.clone())),
            tokio::spawn(forward_control(
                receivers.control,
                stats_tx.clone(),
                route_tx.clone(),
                control_tx.clone(),
            )),
            tokio::spawn(forward_events(
                receivers.events,
                stats_tx.clone(),
                closed.clone(),
            )),
        ];

        // Refinement tiles, only when the host agreed to send them. Spawned
        // alongside the other bridges so it is aborted with them below; it is
        // deliberately *not* given the `closed` notifier, because nothing that
        // happens on the tile stream may end the session.
        if lossless_tiles {
            tracing::info!("host accepted lossless tile refinement");
            fwd.push(tokio::spawn(forward_tiles(
                session.connection().clone(),
                tiles_tx.clone(),
            )));
        }

        // System audio, only when the host agreed to send it. Same treatment as
        // the tile bridge and for the same reason: aborted with the rest of the
        // session's bridges, and deliberately *not* given the `closed`
        // notifier, because nothing that happens on the audio path may end the
        // session. When the bit did not come back, `receivers.audio` is simply
        // dropped here and the driver's audio queue closes with it.
        if system_audio {
            tracing::info!("host accepted system audio");
            fwd.push(tokio::spawn(forward_audio(
                receivers.audio,
                audio_tx.clone(),
            )));
        }

        // The second monitor's frames, only when this session selected two
        // outputs. Same treatment as the tile and audio bridges: aborted with
        // the rest below, and deliberately not given the `closed` notifier,
        // because losing the second picture must cost a window and never the
        // session. When the stream was not selected, `receivers.video1` is
        // dropped here and the driver's (already unarmed) queue closes with it.
        //
        // `forward_video` verbatim, including its drop-on-overflow: the second
        // stream is a second encoder with its own frame_id space, and its
        // backlog must not become back-pressure on the shared QUIC connection
        // that the *primary* picture also rides.
        if second_stream {
            fwd.push(tokio::spawn(forward_video(
                receivers.video1,
                video2_tx.clone(),
            )));
        }

        // Outbound + lifecycle loop. Owns input_rx / control_rx across
        // reconnects (they cannot be cloned), so it lives here, not in a task.
        let user_quit = run_session_loop(
            &session,
            &mut input_rx,
            &mut control_rx,
            &closed,
            &mut shutdown,
        )
        .await;

        for t in fwd {
            t.abort();
        }
        drop(session);

        if user_quit {
            let _ = state_tx.try_send(ConnectionState::Disconnected);
            return;
        }

        // Unexpected drop: report and reconnect (auth mode from here on).
        let _ = route_tx.try_send(None);
        let _ = state_tx.try_send(ConnectionState::Failed("connection lost".into()));
        if wait_or_shutdown(&mut shutdown, backoff).await {
            let _ = state_tx.try_send(ConnectionState::Disconnected);
            return;
        }
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
}

/// Outcome of the per-session outbound loop: `true` means the user/UI asked to
/// stop (do not reconnect); `false` means the session ended and we should retry.
async fn run_session_loop(
    session: &Arc<QuicSession>,
    input_rx: &mut tokio::sync::mpsc::Receiver<InputMsg>,
    control_rx: &mut tokio::sync::mpsc::Receiver<ControlMsg>,
    closed: &Arc<tokio::sync::Notify>,
    shutdown: &mut watch::Receiver<bool>,
) -> bool {
    // Every 2s, log the hook's enqueue count next to what the input write_loop
    // has actually put on the wire. If `enqueued` climbs while `written` stalls
    // (window open, video decoding hard), the client's own send path is starved
    // — distinct from the host starving on injection. Cheap; diagnosis only.
    let mut diag = tokio::time::interval(Duration::from_secs(2));
    diag.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        if session.is_closed() {
            return false;
        }
        tokio::select! {
            _ = diag.tick() => {
                // `tx_dgrams` is the QUIC engine's real count of UDP datagrams
                // actually sent. If `written` (handed to QUIC) climbs while
                // `tx_dgrams` barely moves with the window open, the client's
                // driver is buffering keystrokes and not transmitting them until
                // the render loop quiets (minimize) — a client-side stall. If
                // `tx_dgrams` keeps climbing while typing does nothing on the
                // host, the bytes are leaving and the stall is downstream (host).
                let tx_dgrams = session.connection().stats().udp_tx.datagrams;
                tracing::info!(
                    enqueued = crate::input_capture::keys_forwarded_total(),
                    written = session.input_events_written(),
                    tx_dgrams = tx_dgrams,
                    "input tx diag",
                );
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    session.close_graceful("client shutdown", Duration::from_secs(2)).await;
                    return true;
                }
            }
            _ = closed.notified() => {
                return false;
            }
            msg = input_rx.recv() => {
                match msg {
                    Some(m) => {
                        if let InputMsg::Event(ev) = &m {
                            if let Err(e) = validate_event(ev) {
                                tracing::warn!("dropping invalid input event: {e}");
                                continue;
                            }
                        }
                        if let Err(e) = session.send_input(m) {
                            tracing::warn!("input send failed: {e}");
                        }
                    }
                    // UI dropped its outbound half: the app is closing.
                    None => {
                        session.close_graceful("client closed", Duration::from_secs(1)).await;
                        return true;
                    }
                }
            }
            msg = control_rx.recv() => {
                match msg {
                    Some(m) => {
                        if let Err(e) = session.send_control(m) {
                            tracing::warn!("control send failed: {e}");
                        }
                    }
                    None => {
                        session.close_graceful("client closed", Duration::from_secs(1)).await;
                        return true;
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Inbound bridges (driver receivers -> UI crossbeam senders)
// ---------------------------------------------------------------------------

async fn forward_video(
    mut rx: tokio::sync::mpsc::Receiver<directdesk_shared::video::EncodedFrame>,
    tx: crossbeam_channel::Sender<directdesk_shared::video::EncodedFrame>,
) {
    while let Some(frame) = rx.recv().await {
        // The decode/present path does latest-wins; if even the 256-deep queue
        // is full the consumer has stalled hard — drop rather than block.
        if tx.try_send(frame).is_err() {
            tracing::trace!("video queue full at UI seam; frame dropped");
        }
    }
}

async fn forward_control(
    mut rx: tokio::sync::mpsc::Receiver<ControlMsg>,
    stats_tx: crossbeam_channel::Sender<ConnStats>,
    route_tx: crossbeam_channel::Sender<Option<TransportRoute>>,
    control_tx: crossbeam_channel::Sender<ControlMsg>,
) {
    while let Some(msg) = rx.recv().await {
        match msg {
            // Stats and route have dedicated UI channels; everything else goes
            // to the general control channel the UI drains. "Everything else"
            // now includes the mid-session multi-monitor traffic —
            // `MonitorList` (topology changed), `StreamConfig { id: 1, .. }`
            // and `StreamStopped` — which needs no arm of its own here: the UI
            // is the only thing that reacts to any of them, and it reads them
            // off exactly this lane. See `multi_monitor_control_reaches_the_ui`.
            ControlMsg::Stats(s) => {
                let _ = stats_tx.try_send(s);
            }
            ControlMsg::RouteReport(r) => {
                let _ = route_tx.try_send(Some(r));
            }
            other => {
                let _ = control_tx.try_send(other);
            }
        }
    }
}

async fn forward_events(
    mut rx: tokio::sync::mpsc::Receiver<SessionEvent>,
    stats_tx: crossbeam_channel::Sender<ConnStats>,
    closed: Arc<tokio::sync::Notify>,
) {
    while let Some(ev) = rx.recv().await {
        match ev {
            SessionEvent::Stats(s) => {
                let _ = stats_tx.try_send(s);
            }
            SessionEvent::PeerClosed { reason } => {
                tracing::info!("host closed the session: {reason}");
                closed.notify_waiters();
                return;
            }
            SessionEvent::Closed { reason } => {
                tracing::info!("session closed: {reason}");
                closed.notify_waiters();
                return;
            }
            // Intentional no-op: the reassembler already emitted the wire-level
            // keyframe request (rate-limited by `keyframe_request_min_interval_ms`
            // above) when it detected the gap. That path is authoritative —
            // do NOT add a second `ControlMsg::RequestKeyframe` send here, or
            // gaps end up double-requested.
            SessionEvent::KeyframeNeeded => {}
            SessionEvent::Warning { detail } => tracing::debug!("session warning: {detail}"),
        }
    }
    closed.notify_waiters();
}

// ---------------------------------------------------------------------------
// Lossless refinement tiles (host -> client, bulk uni stream)
// ---------------------------------------------------------------------------

/// Read the host's bulk stream of refinement tiles for as long as it lasts.
///
/// # This loop must never end the session
///
/// Every other stream loop in this file treats a decode or read error as fatal,
/// and for control and input that is exactly right — losing them means losing
/// the session's meaning. **Tiles are the opposite.** They are a bonus layer
/// painted over a picture that is already correct, so a malformed message, a
/// reset stream, or a host that never opens the stream at all must cost nothing
/// beyond the refinement itself. This function therefore never touches
/// `mark_closed`, never notifies `closed`, and never reports a `ConnectionState`
/// — on any error it logs and returns, leaving the session fully alive with
/// tiles simply off. Do not "fix" it to match the loops above it.
///
/// Overflow is dropped rather than awaited, exactly like [`forward_video`]:
/// blocking here would back-pressure QUIC's receive window on a stream whose
/// whole point is that it yields to everything else. Dropping is safe because
/// tiles carry leases — a `Revoke` that never arrives expires on its own.
async fn forward_tiles(conn: Connection, tx: crossbeam_channel::Sender<TileMsg>) {
    // The host opens this only after the handshake, and only to a client that
    // asked for it. If it never opens one, this simply stays pending until the
    // task is aborted with the rest of the session's bridges.
    let mut stream = match quic::accept_bulk(&conn).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("no tile stream from host: {e}; refinement disabled");
            return;
        }
    };
    let mut received: u64 = 0;
    loop {
        match quic::read_framed::<TileMsg>(&mut stream, MAX_CONTROL_MSG).await {
            Ok(msg) => {
                received += 1;
                if tx.try_send(msg).is_err() {
                    tracing::trace!("tile queue full at UI seam; message dropped");
                }
            }
            Err(e) => {
                tracing::warn!(received, "tile stream ended: {e}; refinement disabled");
                return;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// System audio (host -> client, unreliable datagrams)
// ---------------------------------------------------------------------------

/// Move the driver's decoded audio packets onto the UI's crossbeam channel for
/// as long as the session lasts.
///
/// # This loop must never end the session
///
/// The same discipline [`forward_tiles`] documents, restated because it is just
/// as load-bearing here and just as easy to "fix" away. Audio is a bonus layer
/// over a session that is already correct: a client with no endpoint, no AAC
/// decoder, or a host that never sends a datagram must lose exactly the audio
/// and nothing else. So this function never touches `mark_closed`, never
/// notifies `closed` — it is deliberately not given the notifier — and never
/// reports a [`ConnectionState`]. When the driver's audio channel closes, it
/// logs and returns, leaving the session fully alive with audio simply off.
///
/// Contrast [`forward_control`] and [`forward_events`], which sit on the other
/// side of that line: control carries the session's *meaning* (stats, route,
/// clipboard, `VideoConfig`), and `forward_events` holds the `closed` notifier
/// precisely because a `PeerClosed`/`Closed` event is the session ending. A
/// return from this function means "no more audio", never "no more session";
/// `run_session_loop` is not watching it and cannot be woken by it.
///
/// Overflow is dropped rather than awaited, exactly like [`forward_video`] and
/// [`forward_tiles`]: blocking here would back-pressure QUIC's receive window
/// on behalf of a layer whose whole point is that it yields to everything else.
/// A dropped access unit is one ~21 ms click, which the jitter buffer
/// downstream already conceals as ordinary loss.
async fn forward_audio(
    mut rx: tokio::sync::mpsc::Receiver<AudioFrame>,
    tx: crossbeam_channel::Sender<AudioFrame>,
) {
    let mut received: u64 = 0;
    while let Some(frame) = rx.recv().await {
        received += 1;
        if tx.try_send(frame).is_err() {
            tracing::trace!("audio queue full at UI seam; packet dropped");
        }
    }
    tracing::info!(received, "audio stream ended; playback stops");
}

// ---------------------------------------------------------------------------
// Connect + handshake
// ---------------------------------------------------------------------------

struct Established {
    /// The quinn endpoint must outlive the connection (it drives the socket).
    _endpoint: Endpoint,
    conn: Connection,
    streams: SessionStreams,
    route: TransportRoute,
    /// `Some` only when this attempt completed a fresh pairing.
    paired_host: Option<TrustedPeer>,
    /// The host echoed `features::LOSSLESS_TILES`, so it intends to open the
    /// bulk tile stream on this connection.
    lossless_tiles: bool,
    /// The host echoed `features::SYSTEM_AUDIO`, so it intends to send audio
    /// datagrams on this connection.
    system_audio: bool,
    /// The host echoed `features::MULTI_MONITOR`, so the monitor exchange in
    /// Phase 1c ran and the host understands `SelectMonitors` / `EventOn`.
    /// When this is false the two fields below are the "assume one primary"
    /// fallback rather than anything the host said.
    multi_monitor: bool,
    /// Every output the host advertised, verbatim. Empty when the feature was
    /// not mutual — the client must not invent a list it was never told.
    monitors: Vec<MonitorInfo>,
    /// What the client actually asked to be streamed, in slot order:
    /// `selected[0]` rides video stream 0 and `selected[1]` (when present)
    /// rides stream 1. Never longer than `protocol::MAX_VIDEO_STREAMS`.
    selected: Vec<u8>,
}

/// The client's post-`AuthOk` monitor decision, as data.
///
/// Split out from [`connect_and_auth`] so the part with judgement in it — what
/// to send, what to arm, and what is a protocol violation — is a pure function
/// over one message, testable without a socket. The IO around it is then only
/// "read one frame if the bit is set" and "write what the plan says".
#[derive(Debug, PartialEq, Eq)]
struct MonitorPlan {
    /// The host's list, verbatim; empty when there was nothing to read.
    monitors: Vec<MonitorInfo>,
    /// Stream ids to select, in slot order.
    selected: Vec<u8>,
    /// The choice could not be honoured as asked. Not an error — the session
    /// runs, showing the primary — but the operator asked for something they
    /// are not getting, so it must be visible somewhere.
    degraded: bool,
    /// Whether to write `SelectMonitors { ids: selected }` before
    /// `StartStream`. True for every negotiated session — a `Primary`
    /// selection is still stated out loud — and false *only* when the feature
    /// was not mutual, where the send would kill an old host's control stream.
    ///
    /// A flag rather than the built message because `ControlMsg` has no
    /// `PartialEq`: keeping the decision comparable is what makes this
    /// function's whole contract assertable in one line per case.
    send_selection: bool,
}

/// Decide what to do with the first post-`AuthOk` message.
///
/// `first` is `None` when `features::MULTI_MONITOR` did not come back mutual —
/// meaning **no read was attempted at all**, which is the only reason it is
/// safe to carry on: an old host is mid-`StartStream`-wait, not mid-frame.
/// `Some(msg)` is the frame that was read, which the contract says is always a
/// `MonitorList`.
///
/// Anything else is a host contract violation and comes back as `Err`, which
/// the caller turns into a recoverable [`HandshakeError`] that tears the
/// attempt down. That is deliberately harsher than "ignore and continue":
/// having read one frame we cannot know whether the *next* one is the reply we
/// think it is, and guessing on a control stream desyncs every later framed
/// read. Reconnecting is cheap; a desynced control stream is not diagnosable.
fn plan_monitors(
    choice: MonitorChoice,
    first: Option<ControlMsg>,
) -> std::result::Result<MonitorPlan, String> {
    let Some(msg) = first else {
        // Old host: no list, no send, and the operator's choice cannot be
        // honoured beyond the primary. `Primary` is not a degrade — it is
        // exactly what they asked for and exactly what they get.
        return Ok(MonitorPlan {
            monitors: Vec::new(),
            selected: vec![0],
            degraded: choice != MonitorChoice::Primary,
            send_selection: false,
        });
    };
    let ControlMsg::MonitorList { monitors } = msg else {
        return Err(format!(
            "host sent {} instead of the MonitorList its MULTI_MONITOR bit promised",
            control_kind(&msg)
        ));
    };
    let resolved = monitors::resolve_selection(choice, &monitors);
    Ok(MonitorPlan {
        monitors,
        selected: resolved.ids,
        degraded: resolved.degraded,
        send_selection: true,
    })
}

/// Whether this session runs a second video stream.
///
/// One expression with two consumers — `SessionConfig::receive_video_1` (the
/// driver's datagram demux) and the stream-1 bridge — because they must never
/// disagree: an armed demux with no bridge reassembles frames into a channel
/// nobody drains, and a bridge with an unarmed demux waits on datagrams that
/// were dropped before parsing. The `multi_monitor` term is redundant today
/// (a session that never negotiated cannot have selected two ids) and is kept
/// anyway: it states the safety rule locally instead of relying on a caller
/// three functions away having got the selection right.
fn second_stream_armed(multi_monitor: bool, selected: &[u8]) -> bool {
    multi_monitor && selected.len() > 1
}

/// A short name for a control message, for one error string. Deliberately not
/// `{msg:?}`: a `ClipboardText` or a `Stats` would put peer-controlled bytes
/// into a log line and a UI status string.
fn control_kind(msg: &ControlMsg) -> &'static str {
    match msg {
        ControlMsg::VideoConfig { .. } => "VideoConfig",
        ControlMsg::StreamConfig { .. } => "StreamConfig",
        ControlMsg::StreamStopped { .. } => "StreamStopped",
        ControlMsg::Stats(_) => "Stats",
        ControlMsg::Bye { .. } => "Bye",
        ControlMsg::ClipboardText(_) => "ClipboardText",
        ControlMsg::SelectMonitors { .. } => "SelectMonitors",
        _ => "an unexpected control message",
    }
}

struct HandshakeError {
    message: String,
    /// Whether a reconnect could plausibly succeed. A missing pairing or an
    /// anti-MITM rejection is not recoverable by retrying.
    recoverable: bool,
}

impl HandshakeError {
    fn recoverable(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            recoverable: true,
        }
    }
    fn fatal(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            recoverable: false,
        }
    }
}

async fn connect_and_auth(
    params: &ConnectParams,
    client_id: &ClientIdentity,
    store: &dyn SecretStore,
    want_pairing: bool,
    known_host: Option<&TrustedPeer>,
    state_tx: &crossbeam_channel::Sender<ConnectionState>,
) -> std::result::Result<Established, HandshakeError> {
    let qp = QuicParams::default();

    // Build the pinning policy.
    let observed = ObservedPin::new();
    let pinning = if want_pairing {
        ServerPinning::TrustOnPair(observed.clone())
    } else {
        match known_host {
            Some(h) => ServerPinning::Pinned(h.spki_sha256),
            None => {
                return Err(HandshakeError::fatal(
                    "no paired host on record — pair with a code first",
                ));
            }
        }
    };

    // Resolve + race candidate routes (QUIC-only by decision, not by absence —
    // see `connect_race`).
    let candidates = resolve_candidates(&params.host, params.udp_port).await;
    if candidates.is_empty() {
        return Err(HandshakeError::recoverable(format!(
            "cannot resolve host '{}'",
            params.host
        )));
    }
    let (endpoint, conn, route) = match connect_race(&candidates, &pinning, &qp).await {
        Ok(v) => v,
        Err(e) => return Err(HandshakeError::recoverable(format!("connect: {e}"))),
    };

    let exporter = match quic::channel_binding(&conn) {
        Ok(e) => e,
        Err(e) => return Err(HandshakeError::recoverable(format!("channel binding: {e}"))),
    };
    let observed_spki = match quic::peer_spki_pin(&conn) {
        Ok(p) => p,
        Err(e) => return Err(HandshakeError::recoverable(format!("peer pin: {e}"))),
    };

    let mut streams = match quic::open_streams(&conn).await {
        Ok(s) => s,
        Err(e) => return Err(HandshakeError::recoverable(format!("open streams: {e}"))),
    };

    let _ = state_tx.try_send(ConnectionState::Authenticating);

    // Phase 0 — Hello (client writes first). See `ConnectParams::hello_features`
    // for what is offered and why.
    let hello = Hello {
        version: protocol::PROTOCOL_VERSION,
        features: params.hello_features(want_pairing),
        agent: params.display_name.clone(),
    };
    if let Err(e) = quic::write_framed(&mut streams.control.0, &hello).await {
        return Err(HandshakeError::recoverable(format!("send hello: {e}")));
    }
    let peer_hello: Hello = match read_hello(&mut streams.control.1).await {
        Ok(h) => h,
        Err(e) => return Err(HandshakeError::recoverable(format!("recv hello: {e}"))),
    };
    if let Err(e) = protocol::validate_hello(&peer_hello) {
        return Err(HandshakeError::fatal(format!("host hello rejected: {e}")));
    }
    // The host's reply *is* the intersection (`hello.features & offered`), so
    // one bit test settles it: no need to re-check what we asked for.
    let lossless_tiles = peer_hello.features & protocol::features::LOSSLESS_TILES != 0;
    let system_audio = peer_hello.features & protocol::features::SYSTEM_AUDIO != 0;
    // The same one-bit test, and it decides more than the others do: it is the
    // gate on reading an extra frame after `AuthOk` and on ever writing a
    // `SelectMonitors`. Both are fatal to a host that predates the feature —
    // the read would consume its `VideoConfig`, and the write would fail its
    // `decode_strict` — so nothing below may consult the operator's *choice*
    // in place of this bit.
    let multi_monitor = peer_hello.features & protocol::features::MULTI_MONITOR != 0;

    // Phase 1 — the host always issues its ServerChallenge immediately after the
    // Hello exchange, before it knows which branch we want. Read it now; in both
    // branches the client signs this exact per-connection nonce.
    let challenge = recv_auth(&mut streams).await?;

    let paired_host = if want_pairing {
        // SPAKE2 first-contact, then pin the host identity (anti-MITM gate),
        // then prove our key over `nonce_s` through the just-pinned host key.
        let peer = do_pairing(&mut streams, params, &exporter, &observed_spki).await?;
        finish_auth(
            &mut streams,
            client_id,
            &peer.ed25519_pub,
            &exporter,
            &challenge,
        )
        .await?;
        // Persist the freshly trusted host only after AuthOk (anti-MITM anchor).
        if let Err(e) = persist_trusted_host(store, &peer) {
            tracing::warn!("could not persist trusted host: {e}");
        }
        Some(peer)
    } else {
        let host = known_host.expect("auth mode requires a known host");
        finish_auth(
            &mut streams,
            client_id,
            &host.ed25519_pub,
            &exporter,
            &challenge,
        )
        .await?;
        None
    };

    // Phase 1c — MonitorList / SelectMonitors, between `AuthOk` and
    // `StartStream`, and *only* when the feature came back mutual.
    //
    // The read is bounded by the same budget as every other handshake read,
    // and a timeout here is a torn-down attempt rather than a shrug for the
    // reason `recv_control` documents. Ordering is not a preference either:
    // the host promises this list is its first post-`AuthOk` message, so
    // asking for the stream first would mean choosing outputs after the encode
    // had already started.
    let first_control = if multi_monitor {
        Some(recv_control(&mut streams).await?)
    } else {
        None
    };
    let plan =
        plan_monitors(params.monitor_choice, first_control).map_err(HandshakeError::recoverable)?;
    if plan.send_selection {
        let select = ControlMsg::SelectMonitors {
            ids: plan.selected.clone(),
        };
        if let Err(e) = quic::write_framed(&mut streams.control.0, &select).await {
            return Err(HandshakeError::recoverable(format!(
                "send SelectMonitors: {e}"
            )));
        }
    }
    if plan.degraded {
        // Logged, not reported as a failure: the session is about to run
        // perfectly well, just showing one screen. The operator-visible note is
        // the UI's, computed from the same list — which is why the list is
        // re-published to it below rather than summarised here.
        tracing::warn!(
            choice = ?params.monitor_choice,
            monitors = plan.monitors.len(),
            multi_monitor,
            "host cannot honour the monitor choice; showing the primary only"
        );
    }

    // Phase 2 — StartStream (raw, before the driver attaches).
    if let Err(e) = quic::write_framed(&mut streams.control.0, &params.start_stream()).await {
        return Err(HandshakeError::recoverable(format!(
            "send StartStream: {e}"
        )));
    }

    Ok(Established {
        _endpoint: endpoint,
        conn,
        streams,
        route,
        paired_host,
        lossless_tiles,
        system_audio,
        multi_monitor,
        monitors: plan.monitors,
        selected: plan.selected,
    })
}

/// SPAKE2 first-contact bound to the channel binding, ending at `PairComplete`.
///
/// Returns the host identity the client has just pinned (SPKI + Ed25519),
/// cross-checked against the certificate the TLS layer actually saw — the
/// anti-MITM gate. The caller then runs [`finish_auth`] to prove the client's
/// own key over `nonce_s` through this pinned key, exactly as the steady-state
/// branch does; the host verifies that proof against the just-paired key.
async fn do_pairing(
    streams: &mut SessionStreams,
    params: &ConnectParams,
    exporter: &[u8; 32],
    observed_spki: &[u8; 32],
) -> std::result::Result<TrustedPeer, HandshakeError> {
    let code = PairingCode::parse(params.pairing_code.as_deref().unwrap_or_default())
        .map_err(|e| HandshakeError::fatal(format!("pairing code: {e}")))?;

    let now = now_ms();
    let (mut pc, start) = PairingClient::start(&code, exporter, now)
        .map_err(|e| HandshakeError::fatal(format!("pairing start: {e}")))?;

    send_auth(streams, &start).await?;
    let response = recv_auth(streams).await?;
    let confirm = pc
        .on_pair_response(&response, now_ms())
        .map_err(pairing_fatal)?;
    send_auth(streams, &confirm).await?;

    let host_confirm = recv_auth(streams).await?;
    pc.on_pair_confirm(&host_confirm, now_ms())
        .map_err(pairing_fatal)?;

    // PairComplete carries the host identity. Pin it against the pin the TLS
    // layer actually observed — a relay that terminated its own TLS session
    // cannot make these agree, which is what makes trust-on-pair safe.
    let complete = recv_auth(streams).await?;
    pc.accept_pair_complete(&complete, observed_spki, now_ms())
        .map_err(pairing_fatal)
}

/// The mutual-auth tail shared by both branches.
///
/// Answers the host's already-read `ServerChallenge` by signing `nonce_s`
/// through `host_pub` (the pinned/known host key), challenges the host back,
/// verifies the host's signature over our nonce against that pinned key — the
/// anti-MITM gate — and consumes `AuthOk`.
async fn finish_auth(
    streams: &mut SessionStreams,
    client_id: &ClientIdentity,
    host_pub: &Ed25519Pub,
    exporter: &[u8; 32],
    challenge: &AuthMsg,
) -> std::result::Result<(), HandshakeError> {
    let mut ca = ClientAuthenticator::start(exporter, host_pub)
        .map_err(|e| HandshakeError::fatal(format!("auth start: {e}")))?;

    // C -> H : ClientAuth (sig over nonce_s) + ClientChallenge (our nonce_c).
    let (client_auth, client_challenge) = ca
        .on_server_challenge(challenge, client_id.signing_key())
        .map_err(auth_fatal)?;
    send_auth(streams, &client_auth).await?;
    send_auth(streams, &client_challenge).await?;

    // H -> C : ServerAuth (verified against the pinned host key — the gate).
    let server_auth = recv_auth(streams).await?;
    ca.on_server_auth(&server_auth).map_err(auth_fatal)?;

    // H -> C : AuthOk
    let ok = recv_auth(streams).await?;
    ca.on_auth_ok(&ok).map_err(auth_fatal)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn pairing_fatal(e: Error) -> HandshakeError {
    // A pairing failure is almost always a wrong/expired code or a relay — not
    // something a blind retry fixes.
    HandshakeError::fatal(format!("pairing failed: {e}"))
}

fn auth_fatal(e: Error) -> HandshakeError {
    HandshakeError::fatal(format!("authentication failed: {e}"))
}

async fn send_auth(
    streams: &mut SessionStreams,
    msg: &AuthMsg,
) -> std::result::Result<(), HandshakeError> {
    quic::write_framed(&mut streams.control.0, msg)
        .await
        .map_err(|e| HandshakeError::recoverable(format!("send auth: {e}")))
}

async fn recv_auth(streams: &mut SessionStreams) -> std::result::Result<AuthMsg, HandshakeError> {
    match tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        quic::read_auth::<AuthMsg>(&mut streams.control.1),
    )
    .await
    {
        Ok(Ok(m)) => Ok(m),
        Ok(Err(e)) => Err(HandshakeError::recoverable(format!("recv auth: {e}"))),
        Err(_) => Err(HandshakeError::recoverable(
            "handshake timed out".to_string(),
        )),
    }
}

/// Read one raw-framed [`ControlMsg`] during the handshake, before the session
/// driver owns the control stream.
///
/// Every failure is a *recoverable* error that tears the attempt down, and the
/// timeout case is the one that matters. A `tokio::time::timeout` firing
/// mid-`read_framed` abandons the bytes already taken off the stream, so every
/// later framed read on that connection is misaligned — the auth reads get away
/// with it only because a timeout there ends the connection too. Continuing
/// past a timeout here (say, "no list, assume primary") would leave a live
/// session reading a `VideoConfig` as if it were the middle of a length prefix.
/// So: no partial-read path survives, by construction.
async fn recv_control(
    streams: &mut SessionStreams,
) -> std::result::Result<ControlMsg, HandshakeError> {
    match tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        quic::read_framed::<ControlMsg>(&mut streams.control.1, MAX_CONTROL_MSG),
    )
    .await
    {
        Ok(Ok(m)) => Ok(m),
        Ok(Err(e)) => Err(HandshakeError::recoverable(format!(
            "recv MonitorList: {e}"
        ))),
        Err(_) => Err(HandshakeError::recoverable(
            "timed out waiting for the host's monitor list".to_string(),
        )),
    }
}

async fn read_hello(stream: &mut quinn::RecvStream) -> Result<Hello> {
    match tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        quic::read_framed::<Hello>(stream, MAX_AUTH_MSG),
    )
    .await
    {
        Ok(r) => r,
        Err(_) => Err(Error::Transport("hello read timed out".into())),
    }
}

fn persist_trusted_host(store: &dyn SecretStore, peer: &TrustedPeer) -> Result<()> {
    let mut hosts = TrustedPeers::load(store, TRUSTED_HOSTS_KEY)?;
    hosts.upsert(peer.clone())?;
    hosts.save(store, TRUSTED_HOSTS_KEY)
}

/// If exactly one host is trusted, return it. With none or several we cannot
/// pick by address (the record has no address), so we decline — auth mode then
/// reports "no paired host". (Multi-host address disambiguation is a follow-up.)
fn sole_trusted_host(store: &dyn SecretStore) -> Option<TrustedPeer> {
    let hosts = TrustedPeers::load(store, TRUSTED_HOSTS_KEY).ok()?;
    match hosts.peers() {
        [only] => Some(only.clone()),
        many => {
            if many.len() > 1 {
                tracing::warn!(
                    "{} trusted hosts on record; cannot disambiguate by address without pairing",
                    many.len()
                );
            }
            None
        }
    }
}

/// Resolve the host to ordered candidate addresses: IPv4 first (DirectUdp),
/// then IPv6 (DirectIpv6). DNS resolution runs on a blocking thread.
async fn resolve_candidates(host: &str, port: u16) -> Vec<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return vec![SocketAddr::new(ip, port)];
    }
    let host = host.to_string();
    let resolved = tokio::task::spawn_blocking(move || {
        (host.as_str(), port)
            .to_socket_addrs()
            .map(|it| it.collect::<Vec<_>>())
            .unwrap_or_default()
    })
    .await
    .unwrap_or_default();

    let mut v4: Vec<SocketAddr> = resolved.iter().copied().filter(|a| a.is_ipv4()).collect();
    let v6: Vec<SocketAddr> = resolved.iter().copied().filter(|a| a.is_ipv6()).collect();
    v4.extend(v6);
    v4
}

/// The QUIC-only route race. Tries each candidate in order with a per-attempt
/// timeout; the first to complete the QUIC handshake wins.
///
/// TODO(race): `directdesk_shared::transport::race` and `::tcp` are written and
/// unit-tested — what is missing is the wiring, not the dependency. Delegating
/// here would stage the TCP/TLS fallback in parallel with the QUIC attempts.
/// That is a deliberate decision to leave off until the `transport-race` cargo
/// feature is enabled, so this stays QUIC-only and never labels a TCP route as
/// UDP.
async fn connect_race(
    candidates: &[SocketAddr],
    pinning: &ServerPinning,
    qp: &QuicParams,
) -> Result<(Endpoint, Connection, TransportRoute)> {
    let mut last_err = Error::Transport("no candidate addresses".into());
    for addr in candidates {
        let bind: SocketAddr = if addr.is_ipv6() {
            "[::]:0".parse().expect("literal")
        } else {
            "0.0.0.0:0".parse().expect("literal")
        };
        let endpoint = match quic::client_endpoint(bind, pinning.clone(), qp) {
            Ok(e) => e,
            Err(e) => {
                last_err = e;
                continue;
            }
        };
        match tokio::time::timeout(CONNECT_TIMEOUT, quic::connect(&endpoint, *addr)).await {
            Ok(Ok(conn)) => {
                let route = if addr.is_ipv6() {
                    TransportRoute::DirectIpv6
                } else {
                    TransportRoute::DirectUdp
                };
                tracing::info!("connected to {addr} via {}", route.label());
                return Ok((endpoint, conn, route));
            }
            Ok(Err(e)) => {
                tracing::debug!("connect to {addr} failed: {e}");
                last_err = e;
            }
            Err(_) => {
                tracing::debug!("connect to {addr} timed out");
                last_err = Error::Transport(format!("connect to {addr} timed out"));
            }
        }
    }
    Err(last_err)
}

/// Wait `dur`, or return early with `true` if shutdown is signalled meanwhile.
async fn wait_or_shutdown(shutdown: &mut watch::Receiver<bool>, dur: Duration) -> bool {
    if *shutdown.borrow() {
        return true;
    }
    tokio::select! {
        _ = tokio::time::sleep(dur) => *shutdown.borrow(),
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}

/// Milliseconds since the Unix epoch, for the pairing state machines' TTL
/// checks. (The pairing modules take an injected clock precisely so this is the
/// only place a wall clock is read on the client transport path.)
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_feature_bit_does_not_collide_with_wire_flags() {
        // The wire flags live in the low bits; our handshake-only signal must
        // not overlap any of them.
        let wire = protocol::features::CLIPBOARD_TEXT
            | protocol::features::CURSOR_METADATA
            | protocol::features::ADAPTIVE_BITRATE;
        assert_eq!(FEATURE_PAIRING_REQUEST & wire, 0);
    }

    /// The tile stream is armed purely by the bit the *host* echoed back — the
    /// intersection it computed — so a client that asked and was refused, and a
    /// client that never asked, both end up with tiles off.
    #[test]
    fn tiles_are_armed_only_by_the_hosts_echoed_bit() {
        let armed = |features: u64| features & protocol::features::LOSSLESS_TILES != 0;
        assert!(armed(protocol::features::LOSSLESS_TILES));
        assert!(armed(
            protocol::features::LOSSLESS_TILES | protocol::features::CLIPBOARD_TEXT
        ));
        assert!(!armed(0));
        assert!(!armed(protocol::features::CLIPBOARD_TEXT));
        // A host that never learned the flag cannot accidentally arm us via the
        // handshake-only pairing hint, which lives well clear of the wire bits.
        assert!(!armed(FEATURE_PAIRING_REQUEST));
    }

    /// The audio sibling of the test above. Same rule, same single bit test:
    /// the host's reply *is* the intersection, so a client that asked and was
    /// refused, a client that never asked, and a host that predates the flag
    /// all end up with audio off — and the audio bridge is never spawned.
    #[test]
    fn audio_is_armed_only_by_the_hosts_echoed_bit() {
        let armed = |features: u64| features & protocol::features::SYSTEM_AUDIO != 0;
        assert!(armed(protocol::features::SYSTEM_AUDIO));
        assert!(armed(
            protocol::features::SYSTEM_AUDIO | protocol::features::LOSSLESS_TILES
        ));
        assert!(!armed(0), "a host that echoed nothing sends no audio");
        assert!(!armed(protocol::features::CLIPBOARD_TEXT));
        assert!(!armed(FEATURE_PAIRING_REQUEST));

        // The two optional layers are independent: one being on must never arm
        // the other. They ride different transports (a bulk stream vs
        // datagrams) and a host may well support only one.
        assert!(!armed(protocol::features::LOSSLESS_TILES));
        let tiles = |f: u64| f & protocol::features::LOSSLESS_TILES != 0;
        assert!(!tiles(protocol::features::SYSTEM_AUDIO));
    }

    /// What the client *offers* is driven by `params`, not by a constant, so a
    /// client that declines audio cannot have it turned on by the host echoing
    /// a bit we never sent (the host answers with an intersection, and a bit
    /// absent from our offer cannot be in it).
    #[test]
    fn the_hello_offer_carries_exactly_what_the_params_asked_for() {
        let offer = |lossless: bool, audio: bool| {
            let mut features = 0u64;
            if lossless {
                features |= protocol::features::LOSSLESS_TILES;
            }
            if audio {
                features |= protocol::features::SYSTEM_AUDIO;
            }
            features
        };
        assert_eq!(offer(false, false), 0);
        assert_eq!(offer(false, true), protocol::features::SYSTEM_AUDIO);
        assert_eq!(offer(true, false), protocol::features::LOSSLESS_TILES);
        assert_eq!(
            offer(true, true),
            protocol::features::LOSSLESS_TILES | protocol::features::SYSTEM_AUDIO
        );
        // And neither collides with the handshake-only pairing hint.
        assert_eq!(offer(true, true) & FEATURE_PAIRING_REQUEST, 0);
    }

    /// The multi-monitor sibling of the two tests above. Same rule, same single
    /// bit test — and here the rule is not just "the feature is off": an
    /// unechoed bit means the client must not read the extra frame and must not
    /// write `SelectMonitors`, either of which breaks a host that predates the
    /// feature.
    #[test]
    fn multi_monitor_is_armed_only_by_the_hosts_echoed_bit() {
        let armed = |features: u64| features & protocol::features::MULTI_MONITOR != 0;
        assert!(armed(protocol::features::MULTI_MONITOR));
        assert!(armed(
            protocol::features::MULTI_MONITOR | protocol::features::SYSTEM_AUDIO
        ));
        assert!(!armed(0), "a host that echoed nothing has one monitor");
        assert!(!armed(protocol::features::CLIPBOARD_TEXT));
        assert!(!armed(FEATURE_PAIRING_REQUEST));
        // Independent of the other optional layers in both directions.
        assert!(!armed(protocol::features::LOSSLESS_TILES));
        let tiles = |f: u64| f & protocol::features::LOSSLESS_TILES != 0;
        let audio = |f: u64| f & protocol::features::SYSTEM_AUDIO != 0;
        assert!(!tiles(protocol::features::MULTI_MONITOR));
        assert!(!audio(protocol::features::MULTI_MONITOR));
    }

    fn params(choice: MonitorChoice) -> ConnectParams {
        ConnectParams {
            host: "h".into(),
            udp_port: 1,
            pairing_code: None,
            display_name: "n".into(),
            quality: QualityMode::Balanced,
            max_width: 1920,
            max_height: 1080,
            preferred_fps: 60,
            lossless_tiles: true,
            system_audio: true,
            monitor_choice: choice,
        }
    }

    /// The offer is assembled by the real function, not a test's copy of it.
    /// `MULTI_MONITOR` is in every `Hello` — even a `Primary` one, which is the
    /// point: the host's `MonitorList` is the only way the picker ever learns a
    /// second screen exists.
    #[test]
    fn the_hello_offer_always_includes_multi_monitor() {
        for choice in [
            MonitorChoice::Primary,
            MonitorChoice::Second,
            MonitorChoice::Both,
        ] {
            let f = params(choice).hello_features(false);
            assert!(
                f & protocol::features::MULTI_MONITOR != 0,
                "{choice:?} must still offer the bit"
            );
        }

        // The other bits stay driven by params, and pairing stays orthogonal.
        let quiet = ConnectParams {
            lossless_tiles: false,
            system_audio: false,
            ..params(MonitorChoice::Primary)
        };
        assert_eq!(
            quiet.hello_features(false),
            protocol::features::MULTI_MONITOR,
            "a client that declined the optional layers still offers monitors"
        );
        assert_eq!(
            quiet.hello_features(true),
            protocol::features::MULTI_MONITOR | FEATURE_PAIRING_REQUEST
        );
        assert_eq!(
            params(MonitorChoice::Both).hello_features(false),
            protocol::features::MULTI_MONITOR
                | protocol::features::LOSSLESS_TILES
                | protocol::features::SYSTEM_AUDIO
        );
    }

    fn monitor(id: u8) -> MonitorInfo {
        MonitorInfo {
            id,
            width: 1920,
            height: 1080,
            origin_x: 0,
            origin_y: 0,
            is_primary: id == 0,
            name: format!("\\\\.\\DISPLAY{}", id + 1),
        }
    }

    fn list(n: u8) -> ControlMsg {
        ControlMsg::MonitorList {
            monitors: (0..n).map(monitor).collect(),
        }
    }

    /// Old host: the bit did not come back, so no frame was read (`None`) and
    /// nothing may be written. This is the one path where carrying on is safe,
    /// precisely because no read was attempted.
    #[test]
    fn without_the_echoed_bit_nothing_is_read_or_sent() {
        let plan = plan_monitors(MonitorChoice::Primary, None).unwrap();
        assert_eq!(
            plan,
            MonitorPlan {
                monitors: vec![],
                selected: vec![0],
                degraded: false,
                send_selection: false,
            },
            "a Primary choice against an old host is not a degrade"
        );

        for choice in [MonitorChoice::Second, MonitorChoice::Both] {
            let plan = plan_monitors(choice, None).unwrap();
            assert!(!plan.send_selection, "{choice:?} must send nothing");
            assert_eq!(plan.selected, vec![0]);
            assert!(plan.degraded, "{choice:?} could not be honoured; say so");
            assert!(plan.monitors.is_empty(), "never invent a list");
        }
    }

    /// Feature mutual: the list resolves, and `SelectMonitors` goes out for
    /// *every* choice — including `Primary`, whose selection is stated rather
    /// than left for the host to infer.
    #[test]
    fn an_echoed_bit_always_answers_the_list_with_a_selection() {
        let plan = plan_monitors(MonitorChoice::Both, Some(list(2))).unwrap();
        assert_eq!(plan.selected, vec![0, 1]);
        assert!(!plan.degraded);
        assert!(plan.send_selection);
        assert_eq!(plan.monitors.len(), 2, "the host's list is kept verbatim");

        let plan = plan_monitors(MonitorChoice::Primary, Some(list(2))).unwrap();
        assert_eq!(plan.selected, vec![0]);
        assert!(!plan.degraded);
        assert!(
            plan.send_selection,
            "Primary states its selection out loud too"
        );

        let plan = plan_monitors(MonitorChoice::Second, Some(list(2))).unwrap();
        assert_eq!(plan.selected, vec![1]);
        assert!(plan.send_selection);
    }

    /// A host with one screen is a *graceful* degrade, not a protocol error:
    /// the selection falls back to the primary, the session runs, and the
    /// operator gets a note. Distinct from the error case below.
    #[test]
    fn a_single_monitor_list_degrades_instead_of_failing() {
        for choice in [MonitorChoice::Second, MonitorChoice::Both] {
            let plan = plan_monitors(choice, Some(list(1))).unwrap();
            assert_eq!(plan.selected, vec![0], "{choice:?} falls back to primary");
            assert!(plan.degraded);
            assert!(
                plan.send_selection,
                "the fallback is still stated on the wire"
            );
            assert_eq!(plan.monitors.len(), 1);
        }
        // An empty list is the same shape of answer, never a panic.
        let plan = plan_monitors(MonitorChoice::Both, Some(list(0))).unwrap();
        assert_eq!(plan.selected, vec![0]);
        assert!(plan.degraded);
    }

    /// A host that echoed the bit and then sent something else has violated the
    /// contract. That is an error and must stay one: having consumed a frame we
    /// cannot know what the next one is, so continuing would desync every later
    /// framed read on the control stream. The caller turns this into a
    /// *recoverable* handshake error — reconnect, do not limp on.
    #[test]
    fn a_wrong_first_message_is_an_error_not_a_degrade() {
        let wrong = ControlMsg::VideoConfig {
            width: 1920,
            height: 1080,
            fps: 60,
            bitrate_kbps: 8000,
            codec: protocol::Codec::H264,
        };
        let err = plan_monitors(MonitorChoice::Both, Some(wrong)).unwrap_err();
        assert!(
            err.contains("VideoConfig"),
            "the log must name what came: {err}"
        );

        // Including for a Primary choice: the desync risk is about the stream,
        // not about what the operator asked for.
        assert!(plan_monitors(
            MonitorChoice::Primary,
            Some(ControlMsg::Bye { reason: "x".into() })
        )
        .is_err());

        // And the message never interpolates peer-controlled text.
        let err = plan_monitors(
            MonitorChoice::Primary,
            Some(ControlMsg::ClipboardText("secret\nvalue".into())),
        )
        .unwrap_err();
        assert!(
            !err.contains("secret"),
            "peer bytes must not reach the log: {err}"
        );
    }

    /// The demux flag and the bridge are one decision, so they cannot drift.
    #[test]
    fn the_second_stream_is_armed_only_for_a_two_id_selection() {
        assert!(second_stream_armed(true, &[0, 1]));
        assert!(!second_stream_armed(true, &[0]));
        assert!(!second_stream_armed(true, &[1]), "one output is one stream");
        assert!(!second_stream_armed(true, &[]));
        assert!(
            !second_stream_armed(false, &[0, 1]),
            "never arm a stream the host did not negotiate"
        );
    }

    /// The multi-monitor control traffic the UI reacts to reaches it on the
    /// ordinary inbound lane, with no arm of its own — the property the C3
    /// window lifecycle is built on.
    #[tokio::test]
    async fn multi_monitor_control_reaches_the_ui() {
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let (stats_tx, _stats_rx) = crossbeam_channel::bounded(8);
        let (route_tx, _route_rx) = crossbeam_channel::bounded(8);
        let (control_tx, control_rx) = crossbeam_channel::bounded(8);

        tx.send(list(2)).await.unwrap();
        tx.send(ControlMsg::StreamConfig {
            id: 1,
            monitor: 1,
            width: 2560,
            height: 1600,
            fps: 60,
            bitrate_kbps: 8000,
            codec: protocol::Codec::H264,
        })
        .await
        .unwrap();
        tx.send(ControlMsg::StreamStopped {
            id: 1,
            reason: "monitor unplugged".into(),
        })
        .await
        .unwrap();
        drop(tx);

        forward_control(rx, stats_tx, route_tx, control_tx).await;

        assert!(matches!(
            control_rx.try_recv().unwrap(),
            ControlMsg::MonitorList { monitors } if monitors.len() == 2
        ));
        assert!(matches!(
            control_rx.try_recv().unwrap(),
            ControlMsg::StreamConfig {
                id: 1,
                monitor: 1,
                ..
            }
        ));
        assert!(matches!(
            control_rx.try_recv().unwrap(),
            ControlMsg::StreamStopped { id: 1, .. }
        ));
    }

    #[tokio::test]
    async fn literal_ip_resolves_without_dns() {
        let c = resolve_candidates("127.0.0.1", 47990).await;
        assert_eq!(c, vec!["127.0.0.1:47990".parse().unwrap()]);
    }

    #[test]
    fn start_stream_carries_caps() {
        let p = params(MonitorChoice::default());
        match p.start_stream() {
            ControlMsg::StartStream {
                max_width,
                max_height,
                preferred_fps,
                quality_mode,
            } => {
                assert_eq!((max_width, max_height, preferred_fps), (1920, 1080, 60));
                assert_eq!(quality_mode, QualityMode::Balanced);
            }
            _ => panic!("wrong message"),
        }
    }
}
