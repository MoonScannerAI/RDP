//! End-to-end loopback: the real client transport driver ([`net::run_client`])
//! against a real QUIC host endpoint over `127.0.0.1`.
//!
//! There is no networked host yet (the host crate is media-only), so this test
//! owns the host side of the wire contract — but it builds it entirely from the
//! *production* primitives: real quinn QUIC, real TLS SPKI pinning, real SPAKE2
//! pairing, real Ed25519 mutual auth, real datagram fragmentation/reassembly via
//! [`QuicSession`]. When the Desktop Duplication + Media Foundation stack is
//! available the video is real H.264 straight from `directdesk_host`; otherwise
//! it falls back to synthetic Annex-B so the transport/auth gate still runs. The
//! path taken is printed.
//!
//! It asserts the whole keystone:
//!  * pairing succeeds and the client reaches `Connected`;
//!  * >= 60 `EncodedFrame`s arrive over the client's video channel within 3 s;
//!  * the first keyframe is Annex-B (start-code prefixed);
//!  * an injected `InputMsg` is observed on the host's input sink;
//!  * a wrong pairing code fails cleanly (no `Connected`);
//!  * a mismatched SPKI pin is rejected before the session is established.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use directdesk_client::net::{run_client, ConnectParams, FEATURE_PAIRING_REQUEST};
use directdesk_client::session::{ClientSession, ConnectionState};
use directdesk_shared::crypto::auth::{
    HostAuthenticator, TrustedPeer, TrustedPeers, TRUSTED_HOSTS_KEY,
};
use directdesk_shared::crypto::pairing::{PairingCode, PairingHost};
use directdesk_shared::crypto::storage::{MemoryStore, SecretStore};
use directdesk_shared::crypto::HostIdentity;
use directdesk_shared::input::{InputEvent, KeyAction};
use directdesk_shared::protocol::{
    self, AuthMsg, ControlMsg, Hello, InputMsg, MAX_AUTH_MSG, PROTOCOL_VERSION,
};
use directdesk_shared::stats::TransportRoute;
use directdesk_shared::transport::quic::{self, QuicParams, SessionStreams};
use directdesk_shared::transport::session::{QuicSession, Session, SessionConfig};
use directdesk_shared::video::EncodedFrame;
use quinn::Connection;
use tokio::sync::watch;

const CODE: &str = "12345678";

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Shared observation of what the host received — the "injector hook".
#[derive(Default)]
struct HostObservations {
    inputs: Mutex<Vec<InputMsg>>,
    got_start_stream: AtomicBool,
    real_frames: AtomicBool,
    /// Set only when [`spawn_frame_producer`]'s real-capture attempt actually
    /// failed and it fell back to the synthetic Annex-B generator. Distinct
    /// from "neither flag is set yet", which means the producer thread is
    /// still inside `HostSession::start` and hasn't sent a frame at all.
    synthetic_fallback: AtomicBool,
}

/// A running loopback host. Dropping / setting `stop` tears it down.
struct HostHandle {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    obs: Arc<HostObservations>,
    task: tokio::task::JoinHandle<()>,
}

impl HostHandle {
    async fn shutdown(self) {
        self.stop.store(true, Ordering::SeqCst);
        self.task.abort();
        let _ = self.task.await;
    }
}

/// Stand up a host endpoint serving `serve_id`, expecting `expect_code` for
/// pairing (`None` = steady-state auth against `trusted_client`).
fn spawn_host(
    serve_id: Arc<HostIdentity>,
    expect_code: Option<String>,
    trusted_client: Option<TrustedPeer>,
    produce_frames: bool,
) -> HostHandle {
    let params = QuicParams::default();
    let endpoint = quic::server_endpoint("127.0.0.1:0".parse().unwrap(), serve_id.tls(), &params)
        .expect("host endpoint");
    let addr = endpoint.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let obs = Arc::new(HostObservations::default());

    let task = {
        let stop = stop.clone();
        let obs = obs.clone();
        tokio::spawn(async move {
            // Accept connections until told to stop (each retry re-accepts).
            while !stop.load(Ordering::SeqCst) {
                let incoming = match endpoint.accept().await {
                    Some(i) => i,
                    None => break,
                };
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(_) => continue, // e.g. a client that pinned the wrong key
                };
                let obs = obs.clone();
                let serve_id = serve_id.clone();
                let expect_code = expect_code.clone();
                let trusted_client = trusted_client.clone();
                let stop = stop.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_conn(
                        conn,
                        serve_id,
                        expect_code,
                        trusted_client,
                        obs,
                        stop,
                        produce_frames,
                    )
                    .await
                    {
                        eprintln!("[host] connection ended: {e}");
                    }
                });
            }
        })
    };

    HostHandle {
        addr,
        stop,
        obs,
        task,
    }
}

async fn serve_conn(
    conn: Connection,
    serve_id: Arc<HostIdentity>,
    expect_code: Option<String>,
    trusted_client: Option<TrustedPeer>,
    obs: Arc<HostObservations>,
    stop: Arc<AtomicBool>,
    produce_frames: bool,
) -> Result<(), String> {
    let exporter = quic::channel_binding(&conn).map_err(|e| e.to_string())?;
    let mut streams = quic::accept_streams(&conn)
        .await
        .map_err(|e| e.to_string())?;

    // Phase 0 — Hello.
    let hello: Hello = quic::read_framed(&mut streams.control.1, MAX_AUTH_MSG)
        .await
        .map_err(|e| e.to_string())?;
    protocol::validate_hello(&hello).map_err(|e| e.to_string())?;
    let client_name = if hello.agent.is_empty() {
        "client".to_string()
    } else {
        hello.agent.clone()
    };
    let wants_pairing = hello.features & FEATURE_PAIRING_REQUEST != 0;
    quic::write_framed(
        &mut streams.control.0,
        &Hello {
            version: PROTOCOL_VERSION,
            features: 0,
            agent: "DirectDeskHost-e2e".into(),
        },
    )
    .await
    .map_err(|e| e.to_string())?;

    // Phase 1 — the host always issues ServerChallenge first, then branches on
    // the message type it reads next. Both branches sign this nonce.
    let (mut ha, challenge) = HostAuthenticator::start(&exporter).map_err(|e| e.to_string())?;
    write_auth(&mut streams, &challenge).await?;

    if wants_pairing {
        let code = expect_code.clone().ok_or("host not armed for pairing")?;
        host_pairing(
            &mut streams,
            &serve_id,
            &exporter,
            &code,
            &client_name,
            &mut ha,
        )
        .await?;
    } else {
        let client = trusted_client.clone().ok_or("host has no trusted client")?;
        host_auth(&mut streams, &serve_id, &client, &mut ha).await?;
    }

    // Phase 2 — StartStream (raw), then the driver attaches.
    let start: ControlMsg = quic::read_framed(&mut streams.control.1, protocol::MAX_CONTROL_MSG)
        .await
        .map_err(|e| e.to_string())?;
    if !matches!(start, ControlMsg::StartStream { .. }) {
        return Err(format!("expected StartStream, got {start:?}"));
    }
    obs.got_start_stream.store(true, Ordering::SeqCst);

    let (session, mut receivers) = QuicSession::start(
        conn,
        streams,
        TransportRoute::DirectUdp,
        SessionConfig::default(),
    )
    .map_err(|e| e.to_string())?;
    let session = Arc::new(session);

    // Observe inbound input — this is the host's injector hook.
    let input_obs = obs.clone();
    let input_task = tokio::spawn(async move {
        while let Some(msg) = receivers.input.recv().await {
            input_obs.inputs.lock().unwrap().push(msg);
        }
    });

    if produce_frames {
        spawn_frame_producer(session.clone(), stop.clone(), obs.clone());
    }

    // Keep the connection alive until torn down.
    while !stop.load(Ordering::SeqCst) && !session.is_closed() {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    input_task.abort();
    session.close("host done");
    Ok(())
}

async fn host_pairing(
    streams: &mut SessionStreams,
    serve_id: &HostIdentity,
    exporter: &[u8; 32],
    code: &str,
    client_name: &str,
    ha: &mut HostAuthenticator,
) -> Result<(), String> {
    let mut ph = PairingHost::with_code(
        PairingCode::parse(code).map_err(|e| e.to_string())?,
        now_ms(),
        directdesk_shared::crypto::pairing::PAIRING_TTL_MS,
    );

    let start = read_auth(streams).await?;
    let response = ph
        .on_pair_start(&start, exporter, now_ms())
        .map_err(|e| e.to_string())?;
    write_auth(streams, &response).await?;

    let client_confirm = read_auth(streams).await?;
    let host_confirm = ph
        .on_pair_confirm(&client_confirm, now_ms())
        .map_err(|e| e.to_string())?;
    write_auth(streams, &host_confirm).await?;
    write_auth(streams, &serve_id.pair_complete()).await?;

    // The client now proves possession of its long-term key over the fresh
    // ServerChallenge nonce, verified against the just-paired key.
    let client_auth = read_auth(streams).await?;
    let AuthMsg::ClientAuth {
        client_ed25519_pub, ..
    } = &client_auth
    else {
        return Err(format!("expected ClientAuth, got {client_auth:?}"));
    };
    let candidate = ph
        .accept_client(client_ed25519_pub, client_name, now_ms())
        .map_err(|e| e.to_string())?;
    let mut provisional = TrustedPeers::new();
    provisional.upsert(candidate).map_err(|e| e.to_string())?;
    ha.on_client_auth(&client_auth, &provisional)
        .map_err(|e| e.to_string())?;

    finish_host_auth(streams, serve_id, ha).await
}

async fn host_auth(
    streams: &mut SessionStreams,
    serve_id: &HostIdentity,
    client: &TrustedPeer,
    ha: &mut HostAuthenticator,
) -> Result<(), String> {
    let mut trusted = TrustedPeers::new();
    trusted.upsert(client.clone()).map_err(|e| e.to_string())?;

    let client_auth = read_auth(streams).await?;
    ha.on_client_auth(&client_auth, &trusted)
        .map_err(|e| e.to_string())?;

    finish_host_auth(streams, serve_id, ha).await
}

/// The mutual-auth tail shared by both host branches: read the client's
/// challenge, answer it, and send `AuthOk`.
async fn finish_host_auth(
    streams: &mut SessionStreams,
    serve_id: &HostIdentity,
    ha: &mut HostAuthenticator,
) -> Result<(), String> {
    let client_challenge = read_auth(streams).await?;
    let (server_auth, ok) = ha
        .on_client_challenge(&client_challenge, serve_id.signing_key())
        .map_err(|e| e.to_string())?;
    write_auth(streams, &server_auth).await?;
    write_auth(streams, &ok).await?;
    Ok(())
}

async fn read_auth(streams: &mut SessionStreams) -> Result<AuthMsg, String> {
    quic::read_auth::<AuthMsg>(&mut streams.control.1)
        .await
        .map_err(|e| e.to_string())
}

async fn write_auth(streams: &mut SessionStreams, msg: &AuthMsg) -> Result<(), String> {
    quic::write_framed(&mut streams.control.0, msg)
        .await
        .map_err(|e| e.to_string())
}

/// Feed the session with frames: real H.264 from the host pipeline if the
/// capture stack is up, else synthetic Annex-B. Runs on its own OS thread since
/// [`Session`] methods are synchronous.
fn spawn_frame_producer(
    session: Arc<QuicSession>,
    stop: Arc<AtomicBool>,
    obs: Arc<HostObservations>,
) {
    std::thread::spawn(move || {
        #[cfg(windows)]
        directdesk_host::capture::set_process_dpi_aware();

        let real =
            directdesk_host::session::HostSession::start(directdesk_host::session::SessionConfig {
                target_fps: 60,
                bitrate_kbps: 8_000,
                idle_repeat_ms: 16,
                ..Default::default()
            });

        match real {
            Ok(host) => {
                obs.real_frames.store(true, Ordering::SeqCst);
                eprintln!(
                    "[host] frame source: REAL Media Foundation H.264 ({}x{})",
                    host.dimensions().0,
                    host.dimensions().1
                );
                let frames = host.frames();
                while !stop.load(Ordering::SeqCst) {
                    match frames.recv_timeout(Duration::from_millis(200)) {
                        Ok(f) => {
                            let _ = session.send_video(f);
                        }
                        Err(_) => {
                            if session.is_closed() {
                                break;
                            }
                        }
                    }
                }
                host.shutdown();
            }
            Err(e) => {
                obs.synthetic_fallback.store(true, Ordering::SeqCst);
                eprintln!("[host] real capture unavailable ({e}); frame source: SYNTHETIC Annex-B");
                let interval = Duration::from_millis(1000 / 60);
                let mut id: u32 = 0;
                let start = Instant::now();
                while !stop.load(Ordering::SeqCst) && !session.is_closed() {
                    let keyframe = id.is_multiple_of(60);
                    let ts = start.elapsed().as_millis() as u32;
                    let _ = session.send_video(synth_annexb(id, keyframe, ts));
                    id = id.wrapping_add(1);
                    std::thread::sleep(interval);
                }
            }
        }
    });
}

/// A well-formed Annex-B frame: real start codes + NAL headers, junk payload.
/// Never decoded in this test (assertions are at the transport seam), so the
/// payload only needs valid framing.
fn synth_annexb(frame_id: u32, keyframe: bool, ts: u32) -> EncodedFrame {
    let mut data = Vec::new();
    if keyframe {
        data.extend_from_slice(&[0, 0, 0, 1, 0x67, 0x42, 0x00, 0x0a, 0x0f]); // SPS
        data.extend_from_slice(&[0, 0, 0, 1, 0x68, 0xce, 0x38, 0x80]); // PPS
        data.extend_from_slice(&[0, 0, 0, 1, 0x65]); // IDR NAL header
        data.extend(std::iter::repeat_n(0xAB, 3000));
    } else {
        data.extend_from_slice(&[0, 0, 0, 1, 0x41]); // non-IDR NAL header
        data.extend(std::iter::repeat_n(0xCD, 1500));
    }
    EncodedFrame {
        frame_id,
        keyframe,
        timestamp_ms: ts,
        data,
    }
}

/// Spawn the client transport driver and hand back the UI-side channels.
fn spawn_client(
    params: ConnectParams,
    store: Arc<dyn SecretStore>,
) -> (
    ClientSession,
    watch::Sender<bool>,
    tokio::task::JoinHandle<()>,
) {
    let (session, transport) = ClientSession::new();
    let (sd_tx, sd_rx) = watch::channel(false);
    let task = tokio::spawn(run_client(transport, params, store, sd_rx));
    (session, sd_tx, task)
}

fn pair_params(addr: SocketAddr, code: &str) -> ConnectParams {
    ConnectParams {
        host: addr.ip().to_string(),
        udp_port: addr.port(),
        tcp_port: 0,
        pairing_code: Some(code.to_string()),
        display_name: "e2e-client".into(),
        quality: protocol::QualityMode::Balanced,
        max_width: 1920,
        max_height: 1080,
        preferred_fps: 60,
        lossless_tiles: true,
    }
}

/// Drain the state channel; return the latest state seen (if any changed).
fn latest_state(session: &ClientSession, sink: &mut Vec<ConnectionState>) {
    while let Ok(s) = session.state_rx.try_recv() {
        sink.push(s);
    }
}

// ---------------------------------------------------------------------------
// The keystone: pair, stream, inject input.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pair_stream_and_input_end_to_end() {
    let _capture = directdesk_host::testsupport::CaptureLock::acquire();
    let host_id = Arc::new(HostIdentity::generate("e2e-host").unwrap());
    let host = spawn_host(host_id.clone(), Some(CODE.to_string()), None, true);
    let addr = host.addr;
    eprintln!("[test] host listening on {addr}");

    let store: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
    let (client, shutdown, client_task) = spawn_client(pair_params(addr, CODE), store);

    // Wait for Connected (pairing + auth).
    let mut states = Vec::new();
    let connect_deadline = Instant::now() + Duration::from_secs(15);
    let mut connected = false;
    while Instant::now() < connect_deadline {
        latest_state(&client, &mut states);
        if states
            .iter()
            .any(|s| matches!(s, ConnectionState::Connected))
        {
            connected = true;
            break;
        }
        if let Some(ConnectionState::Failed(r)) = states.last() {
            panic!("connect failed before pairing completed: {r}");
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        connected,
        "client never reached Connected; states={states:?}"
    );
    eprintln!("[test] PAIRING + AUTH OK — client Connected");

    // Inject an input event and confirm the host observes it.
    let key = InputMsg::Event(InputEvent::Key {
        scan_code: 0x1E,
        extended: false,
        action: KeyAction::Down,
    });
    client
        .input_tx
        .send(key.clone())
        .await
        .expect("queue input");

    // Count frames arriving over the client's video channel.
    //
    // The 3s throughput window opens at the *first received frame*, not at
    // Connected: spawn_frame_producer's real-capture path blocks inside
    // HostSession::start (Media Foundation + DDA capture init — observed
    // 1.0-3.5s) before it ever calls send_video for the first time. Starting
    // the clock at Connected races that init and undercounts (or zeroes)
    // frames through no fault of the streaming path itself. Waiting for the
    // first frame first, with a generous separate deadline, isolates "the
    // producer never started" from "the producer started but throughput is
    // low" as two distinct failures.
    let mut frames = 0u64;
    let mut bytes = 0u64;
    let mut first_keyframe: Option<Vec<u8>> = None;

    // Phase A — wait (up to 15s) for the first frame. This frame counts
    // toward the throughput total below.
    let init_deadline = Instant::now() + Duration::from_secs(15);
    let mut got_first = false;
    while Instant::now() < init_deadline {
        if let Ok(f) = client.video_rx.try_recv() {
            frames += 1;
            bytes += f.data.len() as u64;
            if f.keyframe && first_keyframe.is_none() {
                first_keyframe = Some(f.data.clone());
            }
            got_first = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // Phase B — with the window now anchored to real producer activity,
    // measure sustained throughput for 3s.
    if got_first {
        let window = Instant::now() + Duration::from_secs(3);
        while Instant::now() < window {
            while let Ok(f) = client.video_rx.try_recv() {
                frames += 1;
                bytes += f.data.len() as u64;
                if f.keyframe && first_keyframe.is_none() {
                    first_keyframe = Some(f.data.clone());
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    // Give the injected input a moment to traverse the wire.
    let input_deadline = Instant::now() + Duration::from_secs(2);
    let mut input_seen = false;
    while Instant::now() < input_deadline {
        if host.obs.inputs.lock().unwrap().iter().any(|m| {
            matches!(
                m,
                InputMsg::Event(InputEvent::Key {
                    scan_code: 0x1E,
                    ..
                })
            )
        }) {
            input_seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Three distinct producer states, not two: `real` and `synthetic_fallback`
    // are only set once the corresponding branch of spawn_frame_producer
    // actually ran; if neither is set, the producer thread is still (or was
    // still, when the test gave up) blocked inside HostSession::start and
    // never sent a single frame. Previously the diagnostics conflated
    // "not started yet" with "genuine synthetic fallback" by printing
    // "synthetic Annex-B" whenever `real_frames` was false.
    let real = host.obs.real_frames.load(Ordering::SeqCst);
    let synthetic = host.obs.synthetic_fallback.load(Ordering::SeqCst);
    let source = if real {
        "REAL MF H.264"
    } else if synthetic {
        "synthetic Annex-B (fallback)"
    } else {
        "producer never started (no frame observed)"
    };
    let head: Vec<u8> = first_keyframe
        .as_ref()
        .map(|d| d.iter().take(8).copied().collect())
        .unwrap_or_default();
    let annexb = first_keyframe
        .as_ref()
        .map(|d| d.starts_with(&[0, 0, 0, 1]) || d.starts_with(&[0, 0, 1]))
        .unwrap_or(false);

    eprintln!("=== e2e loopback results ===");
    eprintln!("frame source     : {source}");
    eprintln!("frames in 3s     : {frames}");
    eprintln!("bytes received   : {bytes}");
    eprintln!(
        "first keyframe   : {} (head {head:02x?})",
        if annexb { "Annex-B" } else { "NOT Annex-B" }
    );
    eprintln!(
        "host got StartStream: {}",
        host.obs.got_start_stream.load(Ordering::SeqCst)
    );
    eprintln!("input observed   : {input_seen}");

    let _ = shutdown.send(true);
    client_task.abort();
    host.shutdown().await;

    assert!(
        got_first,
        "producer never delivered a frame within 15s; frame source: {source}"
    );
    assert!(
        frames >= 60,
        "expected >= 60 frames in the 3s window starting at the first received \
         frame, got {frames}; frame source: {source}"
    );
    assert!(bytes > 0, "no video bytes received");
    assert!(first_keyframe.is_some(), "no keyframe arrived");
    assert!(annexb, "first keyframe is not Annex-B: head {head:02x?}");
    assert!(input_seen, "host never observed the injected input event");
}

// ---------------------------------------------------------------------------
// A wrong pairing code must fail cleanly.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_pairing_code_fails_cleanly() {
    let _capture = directdesk_host::testsupport::CaptureLock::acquire();
    let host_id = Arc::new(HostIdentity::generate("e2e-host-2").unwrap());
    let host = spawn_host(host_id.clone(), Some(CODE.to_string()), None, false);
    let addr = host.addr;

    let store: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
    // Client supplies the WRONG code.
    let (client, shutdown, client_task) = spawn_client(pair_params(addr, "87654321"), store);

    let mut states = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut failed = false;
    while Instant::now() < deadline {
        latest_state(&client, &mut states);
        assert!(
            !states
                .iter()
                .any(|s| matches!(s, ConnectionState::Connected)),
            "wrong code must never reach Connected"
        );
        if states
            .iter()
            .any(|s| matches!(s, ConnectionState::Failed(_)))
        {
            failed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    eprintln!("[test] wrong-code states: {states:?}");
    let _ = shutdown.send(true);
    client_task.abort();
    host.shutdown().await;

    assert!(
        failed,
        "wrong pairing code should have surfaced a Failed state; states={states:?}"
    );
}

// ---------------------------------------------------------------------------
// A mismatched SPKI pin must be rejected before a session is established.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mismatched_spki_pin_is_rejected() {
    let _capture = directdesk_host::testsupport::CaptureLock::acquire();
    // The client trusts host A (its pin), but the server on the wire is host B.
    let host_a = HostIdentity::generate("host-A").unwrap();
    let host_b = Arc::new(HostIdentity::generate("host-B-impostor").unwrap());

    // A client identity that host A would trust (irrelevant: TLS rejects first).
    let client_id = directdesk_shared::crypto::ClientIdentity::generate("e2e-client").unwrap();

    // Preload the client store: trust host A's pin, in auth (non-pairing) mode.
    let store = Arc::new(MemoryStore::new());
    client_id.save(store.as_ref()).unwrap();
    let mut hosts = TrustedPeers::new();
    hosts
        .upsert(TrustedPeer {
            name: "host-A".into(),
            ed25519_pub: host_a.ed25519_pub(),
            spki_sha256: *host_a.spki_sha256(),
            added_at_ms: 1,
        })
        .unwrap();
    hosts.save(store.as_ref(), TRUSTED_HOSTS_KEY).unwrap();
    let store: Arc<dyn SecretStore> = store;

    // The impostor (host B) answers on the wire.
    let client_peer = TrustedPeer {
        name: "e2e-client".into(),
        ed25519_pub: client_id.ed25519_pub(),
        spki_sha256: [0u8; 32],
        added_at_ms: 1,
    };
    let host = spawn_host(host_b.clone(), None, Some(client_peer), false);
    let addr = host.addr;

    // Auth mode (no pairing code): the driver pins host A and dials host B.
    let params = ConnectParams {
        host: addr.ip().to_string(),
        udp_port: addr.port(),
        tcp_port: 0,
        pairing_code: None,
        display_name: "e2e-client".into(),
        quality: protocol::QualityMode::Balanced,
        max_width: 1920,
        max_height: 1080,
        preferred_fps: 60,
        lossless_tiles: true,
    };
    let (client, shutdown, client_task) = spawn_client(params, store);

    let mut states = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut rejected = false;
    while Instant::now() < deadline {
        latest_state(&client, &mut states);
        assert!(
            !states
                .iter()
                .any(|s| matches!(s, ConnectionState::Connected)),
            "a pin mismatch must never reach Connected"
        );
        if states
            .iter()
            .any(|s| matches!(s, ConnectionState::Failed(_)))
        {
            rejected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    eprintln!("[test] pin-mismatch states: {states:?}");
    let _ = shutdown.send(true);
    client_task.abort();
    host.shutdown().await;

    assert!(
        rejected,
        "mismatched SPKI pin must be rejected (Failed); states={states:?}"
    );
}
