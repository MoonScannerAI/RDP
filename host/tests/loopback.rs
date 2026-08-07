//! The M1 gate: a real client, over a real QUIC connection, on this machine.
//!
//! Nothing is mocked below the [`directdesk_host::net`] API. The test starts
//! the actual listener, pairs over SPAKE2 with a code it reads from the pairing
//! slot the UI would show, authenticates with a freshly generated client
//! identity, receives real H.264 datagrams off the real capture pipeline,
//! reassembles them, and injects real input events — then checks the host's own
//! injector counter to prove they arrived.
//!
//! Requirements: an interactive desktop session (Desktop Duplication cannot run
//! on a session-0 service) and UDP 47990 free on loopback. Run it with
//!
//! ```text
//! cargo test -p directdesk-host --test loopback -- --nocapture
//! ```
//!
//! The input events are deliberately the least intrusive ones that still prove
//! the path: scan code 0x76 (F24), which does nothing on a normal desktop, held
//! down and then released through `ReleaseAll` — which also exercises the
//! held-key tracking the disconnect path depends on.

#![cfg(windows)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use directdesk_shared::crypto::pairing::{PairingClient, PairingCode};
use directdesk_shared::crypto::storage::MemoryStore;
use directdesk_shared::crypto::tls::{ObservedPin, ServerPinning};
use directdesk_shared::crypto::{auth::ClientAuthenticator, ClientIdentity, HostIdentity};
use directdesk_shared::input::{InputEvent, KeyAction};
use directdesk_shared::protocol::{
    validate_hello, AuthMsg, ControlMsg, Hello, InputMsg, QualityMode, MAX_AUTH_MSG,
    PROTOCOL_VERSION,
};
use directdesk_shared::stats::TransportRoute;
use directdesk_shared::transport::quic::{self, QuicParams, SessionStreams};
use directdesk_shared::transport::session::{QuicSession, Session, SessionConfig as DriverConfig};
use directdesk_shared::video::EncodedFrame;
use directdesk_shared::Result;
use parking_lot::Mutex;

use directdesk_host::config::HostConfig;
use directdesk_host::net::{
    NetCommand, NetConfig, NetEvent, NetService, PairingSlot, StatusSnapshot,
};

/// Loopback only: the test must never expose a listener to the network.
const HOST_ADDR: &str = "127.0.0.1:47990";
/// How long to stream for. The contract asks for at least three seconds.
const STREAM_SECONDS: u64 = 4;
/// Minimum frames that must arrive in that window.
const MIN_FRAMES: usize = 60;
/// F24. Injecting it is observable to the host and invisible to the user.
const HARMLESS_SCAN_CODE: u16 = 0x76;

#[test]
fn loopback_pair_authenticate_stream_and_inject() {
    // Serialize with other real-capture tests: one GPU capture/encode session
    // per machine (see directdesk_host::testsupport).
    let _capture = directdesk_host::testsupport::CaptureLock::acquire();
    // The host logs why it dropped anything; with `--nocapture` that is the
    // difference between a number and a diagnosis.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("DIRECTDESK_LOG").unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new("warn,directdesk_host=info")
            }),
        )
        .try_init();

    // Two runtimes, not one. In production the client is a different process on
    // a different machine; sharing a thread pool with the host — whose media
    // thread is busy encoding 2560×1600 — starves the client's QUIC poller and
    // measures the test harness rather than the product.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_name("host-rt")
        .enable_all()
        .build()
        .expect("host runtime");
    let client_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_name("client-rt")
        .enable_all()
        .build()
        .expect("client runtime");

    let bind: SocketAddr = HOST_ADDR.parse().expect("literal address");
    let store = Arc::new(MemoryStore::new());
    let identity =
        Arc::new(HostIdentity::generate("loopback-host").expect("generate host identity"));
    let status = Arc::new(Mutex::new(StatusSnapshot::default()));
    let pairing = Arc::new(PairingSlot::new());

    let host_cfg = HostConfig {
        udp_port: bind.port(),
        target_fps: 60,
        ..HostConfig::default()
    };
    let mut net_cfg = NetConfig::from_host_config(&host_cfg);
    net_cfg.bind = bind;

    let host = NetService::start(
        net_cfg,
        runtime.handle(),
        identity.clone(),
        store.clone(),
        status.clone(),
        pairing.clone(),
    );

    // 1. The listener must actually bind before a client can be honest about
    //    what it is testing.
    let bound = wait_for_listening(&host).expect("the host never reported a bound socket");
    println!("host bound   : {bound}");
    assert!(status.lock().listening, "status must agree with the event");

    // 2. Arm pairing exactly as the UI's "Pair new device" button does, and
    //    read the code out of the same slot the window would render.
    host.command(NetCommand::ArmPairing);
    let code = wait_for(Duration::from_secs(5), || {
        pairing.snapshot(host.now_ms()).map(|p| p.digits)
    })
    .expect("no pairing code was armed");
    assert_eq!(code.len(), 8, "the code must be eight digits");
    println!("pairing code : {} digits armed", code.len());

    // Sampled while video is flowing: `run_session` clears the transport stats
    // when the client goes away, so reading them afterwards would report zeroes
    // and call it a measurement.
    let mid: Arc<Mutex<Option<StatusSnapshot>>> = Arc::new(Mutex::new(None));
    {
        let (status, mid) = (status.clone(), mid.clone());
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(3_500));
            *mid.lock() = Some(status.lock().clone());
        });
    }

    let outcome = client_rt.block_on(async { client_session(bind, &code).await });
    let outcome = match outcome {
        Ok(o) => o,
        Err(e) => {
            drain_events(&host);
            panic!("client session failed: {e}");
        }
    };

    // 3. Give the host's one-second status tick a chance to publish the
    //    injector count before we assert on it.
    let injected = wait_for(Duration::from_secs(4), || {
        let n = status.lock().input_injected;
        (n > 0).then_some(n)
    })
    .unwrap_or(0);

    let snapshot = status.lock().clone();
    println!("--- loopback results ---");
    println!("frames rx    : {}", outcome.frames);
    println!("keyframes rx : {}", outcome.keyframes);
    println!("bytes rx     : {}", outcome.bytes);
    println!("elapsed      : {:.2} s", outcome.elapsed.as_secs_f32());
    println!("fps          : {:.1}", outcome.fps());
    println!("largest frame: {} bytes", outcome.largest);
    println!("first NAL    : {:02x?}", outcome.first_head);
    println!(
        "host sent    : {} frames, {} bytes",
        snapshot.frames_sent, snapshot.bytes_sent
    );
    println!("host skipped : {} stale frames", snapshot.frames_coalesced);
    println!(
        "host held    : {} frames (no room)",
        snapshot.frames_backpressured
    );
    println!("input inject : {injected} events");
    if let Some(live) = mid.lock().as_ref() {
        println!(
            "host link    : rtt {:.2} ms, loss {:.2} %, {} kbps (sampled mid-stream)",
            live.transport.rtt_ms,
            live.transport.loss * 100.0,
            live.transport.bandwidth_kbps
        );
        println!(
            "host mid     : {} frames sent, {} skipped, {} held",
            live.frames_sent, live.frames_coalesced, live.frames_backpressured
        );
    }
    println!("capture fps  : {:.1}", snapshot.pipeline.fps_capture);
    println!("encode fps   : {:.1}", snapshot.pipeline.fps_encode);
    println!(
        "encoder      : {}",
        snapshot.encoder.clone().unwrap_or_default()
    );
    println!("route        : {}", outcome.route.label());
    drain_events(&host);

    // 4. The assertions the milestone is actually gated on.
    assert!(
        outcome.frames >= MIN_FRAMES,
        "expected at least {MIN_FRAMES} frames, got {}",
        outcome.frames
    );
    assert!(
        outcome.elapsed >= Duration::from_secs(3),
        "the sample window must be at least 3 s, was {:?}",
        outcome.elapsed
    );
    assert!(outcome.bytes > 0, "no video bytes arrived");
    assert!(
        outcome.keyframes > 0,
        "no keyframe arrived; the client could never decode"
    );
    assert!(
        outcome.first_head.starts_with(&[0, 0, 0, 1]) || outcome.first_head.starts_with(&[0, 0, 1]),
        "the first keyframe is not Annex-B: {:02x?}",
        outcome.first_head
    );
    assert_eq!(
        outcome.route,
        TransportRoute::DirectUdp,
        "the host must report its real route"
    );
    assert!(injected > 0, "no client input reached the host's injector");
    assert!(
        snapshot.frames_sent > 0 && snapshot.bytes_sent > 0,
        "the host's own counters disagree with what the client received"
    );

    // 5. The pairing code is single-use and the client is now trusted.
    assert!(
        pairing.snapshot(host.now_ms()).is_none(),
        "the pairing code must be burned after use"
    );
    assert!(
        snapshot.trusted_clients >= 1,
        "the paired client was not persisted"
    );

    host.shutdown();
    let _ = wait_for(Duration::from_secs(10), || host.is_stopped().then_some(()));
    client_rt.shutdown_timeout(Duration::from_secs(5));
    runtime.shutdown_timeout(Duration::from_secs(5));
}

/// What the client observed.
struct Outcome {
    frames: usize,
    keyframes: usize,
    bytes: u64,
    largest: usize,
    elapsed: Duration,
    first_head: Vec<u8>,
    route: TransportRoute,
}

impl Outcome {
    fn fps(&self) -> f32 {
        self.frames as f32 / self.elapsed.as_secs_f32().max(f32::EPSILON)
    }
}

/// A minimal but complete DirectDesk client: pair, authenticate, stream, type.
async fn client_session(addr: SocketAddr, code: &str) -> Result<Outcome> {
    let recorder = ObservedPin::new();
    let endpoint = quic::client_endpoint(
        "0.0.0.0:0".parse().expect("literal address"),
        ServerPinning::TrustOnPair(recorder.clone()),
        &QuicParams::default(),
    )?;
    let conn = quic::connect(&endpoint, addr).await?;
    let mut streams = quic::open_streams(&conn).await?;

    // -- hello ------------------------------------------------------------
    let hello = Hello {
        version: PROTOCOL_VERSION,
        features: 0,
        agent: "loopback-test-client".to_string(),
    };
    quic::write_framed(&mut streams.control.0, &hello).await?;
    let host_hello: Hello = quic::read_framed(&mut streams.control.1, MAX_AUTH_MSG).await?;
    validate_hello(&host_hello)?;
    assert!(
        host_hello.agent.starts_with("directdesk-host"),
        "{}",
        host_hello.agent
    );

    let exporter = quic::channel_binding(&conn)?;

    // The host always challenges first; which message we answer with picks the
    // pairing branch or the steady-state branch.
    let challenge: AuthMsg = quic::read_auth(&mut streams.control.1).await?;
    assert!(
        matches!(challenge, AuthMsg::ServerChallenge { .. }),
        "{challenge:?}"
    );

    // -- pairing ----------------------------------------------------------
    let host_key = pair(&mut streams, &conn, &exporter, code, &recorder).await?;

    // -- steady-state mutual authentication over the same challenge --------
    let client_id = ClientIdentity::generate("loopback-client")?;
    let mut authenticator = ClientAuthenticator::start(&exporter, &host_key)?;
    let (client_auth, client_challenge) =
        authenticator.on_server_challenge(&challenge, client_id.signing_key())?;
    quic::write_framed(&mut streams.control.0, &client_auth).await?;
    quic::write_framed(&mut streams.control.0, &client_challenge).await?;

    let server_auth: AuthMsg = quic::read_auth(&mut streams.control.1).await?;
    authenticator.on_server_auth(&server_auth)?;
    let ok: AuthMsg = quic::read_auth(&mut streams.control.1).await?;
    authenticator.on_auth_ok(&ok)?;
    assert!(
        authenticator.is_complete(),
        "mutual authentication did not complete"
    );
    println!("authenticated: mutual, channel-bound");

    // -- session ----------------------------------------------------------
    let (session, mut rx) = QuicSession::start(
        conn.clone(),
        streams,
        TransportRoute::DirectUdp,
        DriverConfig {
            heartbeat_ms: 500,
            stats_interval_ms: 500,
            // Deep enough that the *test* is never the reason a frame is lost.
            video_capacity: 256,
            ..DriverConfig::default()
        },
    )?;

    session.send_control(ControlMsg::StartStream {
        max_width: 1920,
        max_height: 1080,
        preferred_fps: 60,
        quality_mode: QualityMode::Balanced,
    })?;

    // -- collect video -----------------------------------------------------
    let started = Instant::now();
    let window = Duration::from_secs(STREAM_SECONDS);
    let mut frames: Vec<EncodedFrame> = Vec::new();
    let mut route = TransportRoute::Relayed;
    let mut video_config = None;

    while started.elapsed() < window {
        tokio::select! {
            frame = rx.video.recv() => match frame {
                Some(f) => frames.push(f),
                None => break,
            },
            msg = rx.control.recv() => match msg {
                Some(ControlMsg::RouteReport(r)) => route = r,
                Some(ControlMsg::VideoConfig { width, height, codec, .. }) => {
                    video_config = Some((width, height, codec));
                }
                Some(_) => {}
                None => break,
            },
            _ = tokio::time::sleep(Duration::from_millis(250)) => {}
        }
    }
    let elapsed = started.elapsed();
    println!("video config : {video_config:?}");

    // Where any missing frame actually went. `udp_rx.datagrams` counts what the
    // socket delivered, so a gap between it and the host's fragment count is
    // network loss, while a gap between reassembled and received frames is the
    // reassembler's latest-wins policy discarding stale work.
    let quic = conn.stats();
    println!(
        "quic rx      : {} datagrams, {} bytes",
        quic.udp_rx.datagrams, quic.udp_rx.bytes
    );
    println!(
        "quic lost    : {} of {} sent",
        quic.path.lost_packets, quic.path.sent_packets
    );
    println!("keyframe reqs: {}", session.keyframes_requested());

    // -- input -------------------------------------------------------------
    // Hold a key the desktop ignores, then let the host's release path put it
    // back up. Both halves of the input contract in four messages.
    for _ in 0..3 {
        session.send_input(InputMsg::Event(InputEvent::Key {
            scan_code: HARMLESS_SCAN_CODE,
            extended: false,
            action: KeyAction::Down,
        }))?;
        session.send_input(InputMsg::Event(InputEvent::Key {
            scan_code: HARMLESS_SCAN_CODE,
            extended: false,
            action: KeyAction::Up,
        }))?;
    }
    session.send_input(InputMsg::Event(InputEvent::Key {
        scan_code: HARMLESS_SCAN_CODE,
        extended: false,
        action: KeyAction::Down,
    }))?;
    session.send_input(InputMsg::ReleaseAll)?;
    // The input stream is reliable, but delivery and injection are not
    // instantaneous; give the host's input thread room before we close.
    tokio::time::sleep(Duration::from_millis(600)).await;

    let first_head: Vec<u8> = frames
        .iter()
        .find(|f| f.keyframe)
        .map(|f| f.data.iter().take(8).copied().collect())
        .unwrap_or_default();

    let outcome = Outcome {
        frames: frames.len(),
        keyframes: frames.iter().filter(|f| f.keyframe).count(),
        bytes: frames.iter().map(|f| f.data.len() as u64).sum(),
        largest: frames.iter().map(|f| f.data.len()).max().unwrap_or(0),
        elapsed,
        first_head,
        route,
    };

    // -- goodbye -----------------------------------------------------------
    session
        .close_graceful("loopback test finished", Duration::from_secs(3))
        .await;
    endpoint.wait_idle().await;
    Ok(outcome)
}

/// The SPAKE2 half of first contact.
async fn pair(
    streams: &mut SessionStreams,
    conn: &quinn::Connection,
    exporter: &directdesk_shared::crypto::Exporter,
    code: &str,
    recorder: &Arc<ObservedPin>,
) -> Result<[u8; 32]> {
    let (mut client, start) = PairingClient::start(&PairingCode::parse(code)?, exporter, 0)?;
    quic::write_framed(&mut streams.control.0, &start).await?;

    let response: AuthMsg = quic::read_auth(&mut streams.control.1).await?;
    let confirm = client.on_pair_response(&response, 50)?;
    quic::write_framed(&mut streams.control.0, &confirm).await?;

    let host_confirm: AuthMsg = quic::read_auth(&mut streams.control.1).await?;
    client.on_pair_confirm(&host_confirm, 100)?;
    assert!(client.is_complete(), "pairing did not complete");

    let complete: AuthMsg = quic::read_auth(&mut streams.control.1).await?;
    // The pin the TLS layer saw must match the one the host claims — that
    // cross-check is what makes trust-on-pair safe.
    let observed = quic::peer_spki_pin(conn)?;
    assert_eq!(
        recorder.get(),
        Some(observed),
        "the recorder and the connection disagree"
    );
    let host_peer = client.accept_pair_complete(&complete, &observed, 0)?;
    println!(
        "paired with  : {} ({})",
        host_peer.name,
        host_peer.fingerprint_short()
    );
    Ok(host_peer.ed25519_pub)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn wait_for_listening(host: &directdesk_host::net::NetHandle) -> Option<SocketAddr> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        while let Some(ev) = host.try_event() {
            match ev {
                NetEvent::Listening { bound, addresses } => {
                    println!("advertising  : {addresses:?}");
                    return Some(bound);
                }
                NetEvent::ListenFailed { detail } => {
                    panic!("the host could not bind {HOST_ADDR}: {detail}");
                }
                other => println!("host event   : {other:?}"),
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

fn wait_for<T>(limit: Duration, mut probe: impl FnMut() -> Option<T>) -> Option<T> {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(v) = probe() {
            return Some(v);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn drain_events(host: &directdesk_host::net::NetHandle) {
    while let Some(ev) = host.try_event() {
        println!("host event   : {ev:?}");
    }
}
