//! Real cross-binary pairing interop: the REAL `directdesk_client` transport
//! driver ([`run_client`]) against the REAL `directdesk_host` listener
//! ([`directdesk_host::net::NetService`]) over loopback QUIC.
//!
//! Unlike `e2e_loopback.rs` (which stands up a *client-built* host mirror), this
//! test boots the actual host server used by `host/tests/loopback.rs` — the same
//! `authenticate`/`pair` state machine — and proves the two binaries now agree
//! on the canonical handshake:
//!
//!  * (a) fresh PAIRING with the correct code reaches `Connected` and streams
//!    real `EncodedFrame`s;
//!  * (b) a SECOND connection with NO code (steady-state AUTH against the
//!    now-trusted host) reaches `Connected`;
//!  * (c) a WRONG pairing code fails cleanly (never `Connected`) and the host
//!    burns the single-use code;
//!  * (d) a host presenting a DIFFERENT SPKI is rejected at pinning (the client
//!    never reaches `Connected`);
//!  * (e) `StreamCaps::touch_device()` (the Android preset), through the real
//!    `ConnectSupervisor`, negotiates one plain stream against a host that
//!    offers every optional layer, and still receives video.
//!
//! Requires an interactive desktop session for the host capture pipeline (real
//! frames); the auth/pairing assertions do not depend on it. Run with:
//!
//! ```text
//! cargo test -p directdesk-client --test interop -- --nocapture
//! ```

#![cfg(windows)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use directdesk_client::connect::{ConnectRequest, ConnectSupervisor, StreamCaps};
use directdesk_client::monitors::MonitorChoice;
use directdesk_client::net::{run_client, ConnectParams};
use directdesk_client::session::{ClientSession, ConnectionState};
use directdesk_shared::crypto::auth::{TrustedPeer, TrustedPeers, TRUSTED_HOSTS_KEY};
use directdesk_shared::crypto::storage::{MemoryStore, SecretStore};
use directdesk_shared::crypto::{ClientIdentity, HostIdentity};
use directdesk_shared::protocol::{ControlMsg, QualityMode};
use parking_lot::Mutex;
use tokio::sync::watch;

use directdesk_host::config::HostConfig;
use directdesk_host::net::{
    NetCommand, NetConfig, NetEvent, NetHandle, NetService, PairingSlot, StatusSnapshot,
};

/// Frames the pairing case must receive to prove the media path is live.
const MIN_FRAMES: u64 = 30;

// ---------------------------------------------------------------------------
// Host harness (the REAL directdesk_host listener)
// ---------------------------------------------------------------------------

/// A booted real host and everything the test needs to observe it.
struct Host {
    handle: NetHandle,
    addr: SocketAddr,
    pairing: Arc<PairingSlot>,
    status: Arc<Mutex<StatusSnapshot>>,
}

/// Boot the real `NetService` on an ephemeral loopback port and wait until it
/// reports a bound socket.
fn boot_host(
    rt: &tokio::runtime::Handle,
    identity: Arc<HostIdentity>,
    store: Arc<dyn SecretStore>,
) -> Host {
    let host_cfg = HostConfig {
        udp_port: 0,
        target_fps: 60,
        ..HostConfig::default()
    };
    boot_host_with(rt, identity, store, host_cfg)
}

/// [`boot_host`] with an explicit host configuration (the bind address is
/// still forced to an ephemeral loopback port).
fn boot_host_with(
    rt: &tokio::runtime::Handle,
    identity: Arc<HostIdentity>,
    store: Arc<dyn SecretStore>,
    host_cfg: HostConfig,
) -> Host {
    let status = Arc::new(Mutex::new(StatusSnapshot::default()));
    let pairing = Arc::new(PairingSlot::new());

    let mut net_cfg = NetConfig::from_host_config(&host_cfg);
    net_cfg.bind = "127.0.0.1:0".parse().expect("literal address");

    let handle = NetService::start(
        net_cfg,
        rt,
        identity,
        store,
        status.clone(),
        pairing.clone(),
    );
    let addr = wait_for_listening(&handle).expect("host never reported a bound socket");
    Host {
        handle,
        addr,
        pairing,
        status,
    }
}

fn wait_for_listening(host: &NetHandle) -> Option<SocketAddr> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        while let Some(ev) = host.try_event() {
            match ev {
                NetEvent::Listening { bound, .. } => return Some(bound),
                NetEvent::ListenFailed { detail } => panic!("host could not bind: {detail}"),
                _ => {}
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

/// Arm a pairing window and return the eight-digit code the UI would show.
fn arm_pairing(host: &Host) -> String {
    host.handle.command(NetCommand::ArmPairing);
    wait_for(Duration::from_secs(5), || {
        host.pairing
            .snapshot(host.handle.now_ms())
            .map(|p| p.digits)
    })
    .expect("no pairing code was armed")
}

// ---------------------------------------------------------------------------
// Client harness (the REAL run_client driver)
// ---------------------------------------------------------------------------

/// A running client transport driver plus its UI-side channels.
struct Client {
    session: ClientSession,
    shutdown: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl Client {
    fn spawn(
        rt: &tokio::runtime::Handle,
        params: ConnectParams,
        store: Arc<dyn SecretStore>,
    ) -> Self {
        let (session, transport) = ClientSession::new();
        let (shutdown, sd_rx) = watch::channel(false);
        let task = rt.spawn(run_client(transport, params, store, sd_rx));
        Client {
            session,
            shutdown,
            task,
        }
    }

    /// Ask the driver to stop and let it settle.
    fn stop(self, rt: &tokio::runtime::Runtime) {
        let _ = self.shutdown.send(true);
        rt.block_on(async {
            let _ = tokio::time::timeout(Duration::from_secs(5), self.task).await;
        });
    }
}

fn pair_params(addr: SocketAddr, code: Option<&str>) -> ConnectParams {
    ConnectParams {
        host: addr.ip().to_string(),
        udp_port: addr.port(),
        pairing_code: code.map(|c| c.to_string()),
        display_name: "interop-client".into(),
        quality: QualityMode::Balanced,
        max_width: 1920,
        max_height: 1080,
        preferred_fps: 60,
        // Advertise the bit: against a host with tiles switched off (the
        // default, and what this test builds) the negotiated intersection is
        // empty and no stream is ever opened — which is exactly the property
        // the interop test should be exercising.
        lossless_tiles: true,
        // Same reasoning for audio: the host defaults it off, so advertising it
        // here exercises the "asked and refused" path — the client must connect
        // and stream normally with no audio bridge spawned.
        system_audio: true,
        monitor_choice: MonitorChoice::default(),
        multi_monitor: true,
    }
}

/// Poll the state channel until `Connected` is seen (returns true) or `limit`
/// elapses. Accumulates every state observed into `seen`.
fn wait_for_connected(
    session: &ClientSession,
    seen: &mut Vec<ConnectionState>,
    limit: Duration,
) -> bool {
    let deadline = Instant::now() + limit;
    loop {
        while let Ok(s) = session.state_rx.try_recv() {
            seen.push(s);
        }
        if seen.iter().any(|s| matches!(s, ConnectionState::Connected)) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Poll until a `Failed` state is seen, asserting `Connected` never appears.
/// Returns whether a `Failed` was observed.
fn wait_for_clean_failure(
    session: &ClientSession,
    seen: &mut Vec<ConnectionState>,
    limit: Duration,
) -> bool {
    let deadline = Instant::now() + limit;
    loop {
        while let Ok(s) = session.state_rx.try_recv() {
            seen.push(s);
        }
        assert!(
            !seen.iter().any(|s| matches!(s, ConnectionState::Connected)),
            "must never reach Connected; states={seen:?}"
        );
        if seen.iter().any(|s| matches!(s, ConnectionState::Failed(_))) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Drain the client's video channel for `window`, returning (frames, bytes).
fn collect_frames(session: &ClientSession, window: Duration) -> (u64, u64) {
    let end = Instant::now() + window;
    let (mut frames, mut bytes) = (0u64, 0u64);
    while Instant::now() < end {
        while let Ok(f) = session.video_rx.try_recv() {
            frames += 1;
            bytes += f.data.len() as u64;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    (frames, bytes)
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

fn runtimes() -> (tokio::runtime::Runtime, tokio::runtime::Runtime) {
    // Two runtimes: the host's media thread must not starve the client's QUIC
    // poller (see host/tests/loopback.rs for the rationale).
    let host_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_name("interop-host-rt")
        .enable_all()
        .build()
        .expect("host runtime");
    let client_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_name("interop-client-rt")
        .enable_all()
        .build()
        .expect("client runtime");
    (host_rt, client_rt)
}

// ---------------------------------------------------------------------------
// (a) + (b): pair with the real host, then reconnect with no code.
// ---------------------------------------------------------------------------

#[test]
fn pairing_then_reconnect_against_real_host() {
    let _capture = directdesk_host::testsupport::CaptureLock::acquire();
    let (host_rt, client_rt) = runtimes();

    // The client store persists across the pairing and the reconnect.
    let client_store: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
    let host_store: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
    let identity = Arc::new(HostIdentity::generate("interop-host").expect("host identity"));

    let host = boot_host(host_rt.handle(), identity, host_store);
    println!("[a] host bound   : {}", host.addr);

    // --- (a) fresh pairing --------------------------------------------------
    let code = arm_pairing(&host);
    println!("[a] pairing code : {} digits armed", code.len());

    let client = Client::spawn(
        client_rt.handle(),
        pair_params(host.addr, Some(&code)),
        client_store.clone(),
    );
    let mut states = Vec::new();
    let connected = wait_for_connected(&client.session, &mut states, Duration::from_secs(20));
    assert!(
        connected,
        "[a] client never reached Connected; states={states:?}"
    );
    println!("[a] PAIRING OK   : client Connected");

    let (frames, bytes) = collect_frames(&client.session, Duration::from_secs(5));
    println!("[a] frames rx    : {frames} ({bytes} bytes)");

    // Single-use code must be burned, and the client must be persisted host-side.
    assert!(
        host.pairing.snapshot(host.handle.now_ms()).is_none(),
        "[a] the pairing code must be burned after use"
    );
    let trusted_clients = host.status.lock().trusted_clients;
    println!("[a] host trusted : {trusted_clients} client(s)");
    assert!(
        trusted_clients >= 1,
        "[a] the paired client was not persisted host-side"
    );
    assert!(
        frames >= MIN_FRAMES,
        "[a] expected >= {MIN_FRAMES} real frames, got {frames}"
    );

    // Tear the first client down before reconnecting (host serves one at a time).
    client.stop(&client_rt);
    std::thread::sleep(Duration::from_millis(500));

    // --- (b) reconnect in steady-state AUTH (no code) -----------------------
    let client2 = Client::spawn(
        client_rt.handle(),
        pair_params(host.addr, None),
        client_store.clone(),
    );
    let mut states2 = Vec::new();
    let reconnected = wait_for_connected(&client2.session, &mut states2, Duration::from_secs(20));
    println!("[b] reconnect states: {states2:?}");
    assert!(
        reconnected,
        "[b] steady-state reconnect never reached Connected; states={states2:?}"
    );
    println!("[b] RECONNECT OK : trusted-host auth Connected");

    client2.stop(&client_rt);
    host.handle.shutdown();
    let _ = wait_for(Duration::from_secs(10), || {
        host.handle.is_stopped().then_some(())
    });
    client_rt.shutdown_timeout(Duration::from_secs(5));
    host_rt.shutdown_timeout(Duration::from_secs(5));
}

// ---------------------------------------------------------------------------
// (e): the touch-device caps negotiate one plain stream.
// ---------------------------------------------------------------------------

/// Stream-0 frames the touch case must receive. Lower than [`MIN_FRAMES`]
/// because the touch preset caps the host at 30 fps: on an idle desktop the
/// host's 250 ms keepalive alone yields ~20 in the 5 s window.
const MIN_TOUCH_FRAMES: u64 = 10;

/// What arrived on each inbound lane during a collection window.
#[derive(Debug, Default)]
struct LaneCounts {
    frames: u64,
    frames2: u64,
    tiles: u64,
    audio: u64,
    monitor_lists: u64,
    stream1_configs: u64,
}

fn collect_lanes(session: &ClientSession, window: Duration) -> LaneCounts {
    let end = Instant::now() + window;
    let mut c = LaneCounts::default();
    while Instant::now() < end {
        while session.video_rx.try_recv().is_ok() {
            c.frames += 1;
        }
        while session.video2_rx.try_recv().is_ok() {
            c.frames2 += 1;
        }
        while session.tiles_rx.try_recv().is_ok() {
            c.tiles += 1;
        }
        while session.audio_rx.try_recv().is_ok() {
            c.audio += 1;
        }
        while let Ok(msg) = session.control_rx.try_recv() {
            match msg {
                ControlMsg::MonitorList { .. } => c.monitor_lists += 1,
                ControlMsg::StreamConfig { id, .. } if id != 0 => c.stream1_configs += 1,
                _ => {}
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    c
}

/// `StreamCaps::touch_device()` through the production path `app::run` uses —
/// a [`ConnectSupervisor`] built with those caps — against a real host that
/// *offers* multi-monitor, system audio and lossless tiles. The touch client
/// asks for none of them, so the session must come up as one plain stream: no
/// `MonitorList`, nothing on the second-stream, tile or audio lanes, and real
/// video on stream 0.
///
/// A second connection with the desktop default caps against the same host is
/// the positive control: it does get a `MonitorList`, so the first half's
/// silence is the client's doing rather than a host that never offered.
#[test]
fn touch_device_caps_negotiate_one_plain_stream() {
    let _capture = directdesk_host::testsupport::CaptureLock::acquire();
    let (host_rt, client_rt) = runtimes();
    let client_store: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
    let host_store: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
    let identity = Arc::new(HostIdentity::generate("interop-host-e").expect("host identity"));

    let host = boot_host_with(
        host_rt.handle(),
        identity,
        host_store,
        HostConfig {
            udp_port: 0,
            target_fps: 60,
            multi_monitor_enabled: true,
            system_audio_enabled: true,
            lossless_tiles_enabled: true,
            ..HostConfig::default()
        },
    );
    println!(
        "[e] host bound   : {} (offers monitors, audio, tiles)",
        host.addr
    );
    let code = arm_pairing(&host);

    let request = |pairing_code: Option<String>| ConnectRequest {
        host: host.addr.ip().to_string(),
        udp_port: host.addr.port(),
        display_name: "interop-touch-client".into(),
        pairing_code,
        quality: QualityMode::Balanced,
    };

    // --- touch caps: pair and stream ----------------------------------------
    let (session, transport) = ClientSession::new();
    let mut touch = ConnectSupervisor::new(
        client_rt.handle().clone(),
        client_store.clone(),
        transport,
        StreamCaps::touch_device(),
    );
    touch.connect(request(Some(code)));
    let mut states = Vec::new();
    assert!(
        wait_for_connected(&session, &mut states, Duration::from_secs(20)),
        "[e] touch client never reached Connected; states={states:?}"
    );
    let lanes = collect_lanes(&session, Duration::from_secs(5));
    println!("[e] touch lanes  : {lanes:?}");
    assert_eq!(
        lanes.monitor_lists, 0,
        "[e] MULTI_MONITOR must not be negotiated"
    );
    assert_eq!(
        lanes.stream1_configs, 0,
        "[e] no secondary stream may be configured"
    );
    assert_eq!(lanes.frames2, 0, "[e] nothing on the second-stream lane");
    assert_eq!(lanes.tiles, 0, "[e] LOSSLESS_TILES must not be negotiated");
    assert_eq!(lanes.audio, 0, "[e] SYSTEM_AUDIO must not be negotiated");
    assert!(
        lanes.frames >= MIN_TOUCH_FRAMES,
        "[e] expected >= {MIN_TOUCH_FRAMES} real frames on stream 0, got {}",
        lanes.frames
    );
    touch.disconnect();
    drop(touch);
    std::thread::sleep(Duration::from_millis(500));

    // --- positive control: desktop caps, same (now trusted) host -------------
    let (session2, transport2) = ClientSession::new();
    let mut desktop = ConnectSupervisor::new(
        client_rt.handle().clone(),
        client_store,
        transport2,
        StreamCaps::default(),
    );
    desktop.connect(request(None));
    let mut states2 = Vec::new();
    assert!(
        wait_for_connected(&session2, &mut states2, Duration::from_secs(20)),
        "[e] desktop control never reached Connected; states={states2:?}"
    );
    let control = collect_lanes(&session2, Duration::from_secs(2));
    println!("[e] desktop lanes: {control:?}");
    assert!(
        control.monitor_lists >= 1,
        "[e] control: the host offers MULTI_MONITOR, so default caps must get a MonitorList"
    );
    desktop.disconnect();
    drop(desktop);

    host.handle.shutdown();
    let _ = wait_for(Duration::from_secs(10), || {
        host.handle.is_stopped().then_some(())
    });
    client_rt.shutdown_timeout(Duration::from_secs(5));
    host_rt.shutdown_timeout(Duration::from_secs(5));
}

// ---------------------------------------------------------------------------
// (c): a wrong pairing code fails cleanly and burns the host code.
// ---------------------------------------------------------------------------

#[test]
fn wrong_pairing_code_fails_and_burns_code() {
    let _capture = directdesk_host::testsupport::CaptureLock::acquire();
    let (host_rt, client_rt) = runtimes();
    let client_store: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
    let host_store: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
    let identity = Arc::new(HostIdentity::generate("interop-host-c").expect("host identity"));

    let host = boot_host(host_rt.handle(), identity, host_store);
    let real_code = arm_pairing(&host);
    // Supply a code guaranteed to differ from the armed one.
    let wrong: String = real_code
        .chars()
        .map(|c| if c == '0' { '1' } else { '0' })
        .collect();
    println!("[c] armed a real code; client will present a wrong one");

    let client = Client::spawn(
        client_rt.handle(),
        pair_params(host.addr, Some(&wrong)),
        client_store,
    );
    let mut states = Vec::new();
    let failed = wait_for_clean_failure(&client.session, &mut states, Duration::from_secs(20));
    println!("[c] states       : {states:?}");
    assert!(
        failed,
        "[c] wrong code should have surfaced a Failed state; states={states:?}"
    );

    // The host burns the code on any pairing attempt, right or wrong.
    assert!(
        host.pairing.snapshot(host.handle.now_ms()).is_none(),
        "[c] the wrong-code attempt must still burn the single-use code"
    );
    println!("[c] WRONG CODE OK: clean failure, host code burned");

    client.stop(&client_rt);
    host.handle.shutdown();
    let _ = wait_for(Duration::from_secs(10), || {
        host.handle.is_stopped().then_some(())
    });
    client_rt.shutdown_timeout(Duration::from_secs(5));
    host_rt.shutdown_timeout(Duration::from_secs(5));
}

// ---------------------------------------------------------------------------
// (d): a host presenting a different SPKI is rejected at pinning.
// ---------------------------------------------------------------------------

#[test]
fn mismatched_host_spki_is_rejected() {
    let _capture = directdesk_host::testsupport::CaptureLock::acquire();
    let (host_rt, client_rt) = runtimes();

    // The client trusts host A's pin, but host B answers on the wire.
    let host_a = HostIdentity::generate("interop-host-A").expect("host A");
    let host_b = Arc::new(HostIdentity::generate("interop-host-B-impostor").expect("host B"));

    // Preload the client store: a valid client identity plus trust in host A's
    // pin, in auth (non-pairing) mode.
    let store = Arc::new(MemoryStore::new());
    let client_id = ClientIdentity::generate("interop-client").expect("client identity");
    client_id.save(store.as_ref()).expect("save client id");
    let mut hosts = TrustedPeers::new();
    hosts
        .upsert(TrustedPeer {
            name: "interop-host-A".into(),
            ed25519_pub: host_a.ed25519_pub(),
            spki_sha256: *host_a.spki_sha256(),
            added_at_ms: 1,
        })
        .expect("trust host A");
    hosts
        .save(store.as_ref(), TRUSTED_HOSTS_KEY)
        .expect("persist trusted host");
    let client_store: Arc<dyn SecretStore> = store;

    // The impostor (host B) is the real listener the client will dial.
    let host_store: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
    let host = boot_host(host_rt.handle(), host_b, host_store);
    println!("[d] impostor host bound: {}", host.addr);

    // Auth mode (no code): the driver pins host A and dials host B.
    let client = Client::spawn(
        client_rt.handle(),
        pair_params(host.addr, None),
        client_store,
    );
    let mut states = Vec::new();
    let rejected = wait_for_clean_failure(&client.session, &mut states, Duration::from_secs(20));
    println!("[d] states       : {states:?}");
    assert!(
        rejected,
        "[d] a pin mismatch must surface Failed; states={states:?}"
    );
    println!("[d] MITM OK      : mismatched SPKI rejected before Connected");

    client.stop(&client_rt);
    host.handle.shutdown();
    let _ = wait_for(Duration::from_secs(10), || {
        host.handle.is_stopped().then_some(())
    });
    client_rt.shutdown_timeout(Duration::from_secs(5));
    host_rt.shutdown_timeout(Duration::from_secs(5));
}
