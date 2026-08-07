//! Backward-compatibility gate for lossless static-region refinement ("tiles").
//!
//! The host this feature ships to is remote and hard to reach, so a handshake
//! regression is close to unrecoverable: a host that mishandles an old client's
//! `Hello` is a host nobody can connect to in order to fix it. These tests exist
//! to prove the new code **cannot** change what an already-deployed peer sees.
//!
//! Like [`loopback`](../loopback.rs), nothing below the [`directdesk_host::net`]
//! API is mocked: a real listener, a real SPAKE2 pairing, real mutual
//! authentication over real QUIC on loopback, and a real capture/encode
//! pipeline behind it. What differs is the *subject*: every assertion here is
//! about **protocol behaviour** — which feature bits come back, whether a
//! unidirectional stream is ever opened, and whether the session survives — and
//! never about throughput. Nothing in this file may depend on achieving a frame
//! rate.
//!
//! ```text
//! cargo test -p directdesk-host --test tiles_interop -- --nocapture
//! ```
//!
//! The four scenarios, in rollout order:
//!
//! 1. [`legacy_client_gets_no_tile_stream_from_a_tiles_enabled_host`] — the
//!    already-deployed client (`features: 0`) against a host with the feature
//!    fully switched on.
//! 2. [`new_client_and_disabled_host_are_wire_identical_to_the_old_build`] —
//!    rollout step 1: the new binary with `lossless_tiles_enabled: false`, which
//!    is the shipped default.
//! 3. [`both_ends_enabled_opens_the_stream_and_delivers_a_reset`] — rollout
//!    step 2: the feature actually works.
//! 4. [`a_dead_tile_stream_degrades_the_picture_not_the_session`] — the design
//!    rule the whole feature rests on.
//!
//! Requirements: an interactive desktop session (Desktop Duplication cannot run
//! on a session-0 service) and UDP 47995-47998 free on loopback.

#![cfg(windows)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use directdesk_shared::crypto::pairing::{PairingClient, PairingCode};
use directdesk_shared::crypto::storage::MemoryStore;
use directdesk_shared::crypto::tls::{ObservedPin, ServerPinning};
use directdesk_shared::crypto::{auth::ClientAuthenticator, ClientIdentity, HostIdentity};
use directdesk_shared::protocol::features::LOSSLESS_TILES;
use directdesk_shared::protocol::{
    decode_strict, encode_framed, validate_hello, AuthMsg, ControlMsg, Hello, QualityMode,
    MAX_AUTH_MSG, MAX_CONTROL_MSG, PROTOCOL_VERSION,
};
use directdesk_shared::stats::TransportRoute;
use directdesk_shared::tiles::{decompress_strip, TileCodec, TileMsg, TILE_EDGE};
use directdesk_shared::transport::quic::{self, QuicParams, SessionStreams};
use directdesk_shared::transport::session::{
    QuicSession, Session, SessionConfig as DriverConfig, SessionEvent, SessionReceivers,
};
use directdesk_shared::Result;
use parking_lot::Mutex;

use directdesk_host::config::HostConfig;
use directdesk_host::net::{
    NetCommand, NetConfig, NetEvent, NetHandle, NetService, PairingSlot, StatusSnapshot,
};

/// Loopback only: these tests must never expose a listener to the network.
/// One port per scenario so a lingering socket from the previous test can never
/// be mistaken for this one's.
const LEGACY_PORT: u16 = 47_995;
const DISABLED_PORT: u16 = 47_996;
const ENABLED_PORT: u16 = 47_997;
const DEGRADE_PORT: u16 = 47_998;

/// Client heartbeat interval. Deliberately short so a few-second observation
/// window really does span *several* heartbeats.
const HEARTBEAT_MS: u64 = 400;

/// How long a "the session behaves completely normally" observation runs.
/// Ten heartbeats at [`HEARTBEAT_MS`].
const OBSERVE: Duration = Duration::from_secs(4);

/// How long a negotiated tile stream gets to open and deliver its first
/// message. Very generous on purpose: a real Desktop Duplication + Media
/// Foundation pipeline is starting up behind it, and this is a protocol test —
/// it must fail because the message never comes, not because the machine was
/// busy.
const TILE_TIMEOUT: Duration = Duration::from_secs(20);

/// Host status ticks are one second apart (`directdesk_host::net`'s
/// `STATUS_INTERVAL_MS`), so a 4 s window carries about four `Stats` messages.
/// Two is the "the host's control plane is still talking to us" floor that no
/// amount of load can plausibly breach.
const MIN_HOST_STATS: u64 = 2;

// ---------------------------------------------------------------------------
// 1. Legacy client, new host
// ---------------------------------------------------------------------------

/// An already-deployed client — one whose `Hello.features` is `0` because it
/// was built before the feature existed — against a host with
/// `lossless_tiles_enabled: true`.
///
/// This is the strongest form of the compatibility question: the host is not
/// merely capable of tiles, it is *configured for them*, and it still must not
/// let a byte of the new protocol reach a peer that never asked. The negative
/// is asserted directly — `accept_uni` is raced against the whole observation
/// window and must stay pending.
#[test]
fn legacy_client_gets_no_tile_stream_from_a_tiles_enabled_host() {
    let h = Harness::start(LEGACY_PORT, true);
    h.client_rt.block_on(async {
        let Handshake {
            endpoint,
            conn,
            streams,
            host_features,
        } = connect_and_pair(h.bind, &h.code, 0)
            .await
            .expect("legacy client handshake");

        // The intersection of "nothing requested" and "everything offered" is
        // nothing — and the host must say so rather than advertise its own
        // capability set.
        assert_eq!(
            host_features & LOSSLESS_TILES,
            0,
            "the host echoed the tile bit to a client that never set it"
        );
        assert_eq!(
            host_features, 0,
            "the host must reply with the intersection, not its offer"
        );

        let (session, rx) = QuicSession::start(
            conn.clone(),
            streams,
            TransportRoute::DirectUdp,
            driver_config(),
        )
        .expect("session driver");
        session.send_control(start_stream()).expect("StartStream");
        let tally = spawn_pump(rx);

        // The negative, proved rather than assumed: any resolution of
        // `accept_uni` inside the window is a failure. A pending future is what
        // "an old peer sees nothing" actually looks like on the wire.
        match tokio::time::timeout(OBSERVE, quic::accept_bulk(&conn)).await {
            Err(_elapsed) => {}
            Ok(Ok(_)) => panic!("the host opened a unidirectional stream to a legacy client"),
            Ok(Err(e)) => panic!("the connection died while proving no tile stream opens: {e}"),
        }

        report("legacy client", &tally, &session);
        assert_healthy("legacy client", &tally, &session, &conn);

        session
            .close_graceful("tiles interop test finished", Duration::from_secs(3))
            .await;
        endpoint.wait_idle().await;
    });
    assert!(
        h.status.lock().frames_sent > 0,
        "the host's own counters say it never sent a frame to the legacy client"
    );
    h.finish();
}

// ---------------------------------------------------------------------------
// 2. New client, host with the feature off (the shipped default)
// ---------------------------------------------------------------------------

/// Rollout step 1: the new binary, deployed with `lossless_tiles_enabled` at its
/// default `false`, talking to a client that *does* set the bit.
///
/// The property under test is not "tiles are off" but something stronger: this
/// build is **byte-identical on the wire** to the one already deployed. The
/// host's `Hello` carries no bits, no unidirectional stream is opened, and the
/// session is indistinguishable from a pre-feature one. That is what makes
/// shipping the code and enabling it later two separately reversible steps.
#[test]
fn new_client_and_disabled_host_are_wire_identical_to_the_old_build() {
    let h = Harness::start(DISABLED_PORT, false);
    h.client_rt.block_on(async {
        let Handshake {
            endpoint,
            conn,
            streams,
            host_features,
        } = connect_and_pair(h.bind, &h.code, LOSSLESS_TILES)
            .await
            .expect("new client handshake");

        // The client asked; the host, unconfigured, offers nothing. An operator
        // turning the feature off must be indistinguishable from a host that
        // never had it.
        assert_eq!(
            host_features & LOSSLESS_TILES,
            0,
            "a host with lossless_tiles_enabled=false accepted the tile bit"
        );
        assert_eq!(
            host_features, 0,
            "the negotiated intersection must be empty on the default config"
        );

        let (session, rx) = QuicSession::start(
            conn.clone(),
            streams,
            TransportRoute::DirectUdp,
            driver_config(),
        )
        .expect("session driver");
        session.send_control(start_stream()).expect("StartStream");
        let tally = spawn_pump(rx);

        match tokio::time::timeout(OBSERVE, quic::accept_bulk(&conn)).await {
            Err(_elapsed) => {}
            Ok(Ok(_)) => panic!(
                "the host opened a tile stream despite lossless_tiles_enabled=false; \
                 the shipped default is not wire-identical to the deployed build"
            ),
            Ok(Err(e)) => panic!("the connection died while proving no tile stream opens: {e}"),
        }

        report("tiles disabled", &tally, &session);
        assert_healthy("tiles disabled", &tally, &session, &conn);

        session
            .close_graceful("tiles interop test finished", Duration::from_secs(3))
            .await;
        endpoint.wait_idle().await;
    });
    h.finish();
}

// ---------------------------------------------------------------------------
// 3. Both ends enabled
// ---------------------------------------------------------------------------

/// Rollout step 2: with the bit mutual, the host really does open the stream and
/// really does speak the format.
///
/// # Why this stops at `Reset`
///
/// A `Strip` is only produced once a region of the *real* desktop has held still
/// for `lossless_tile_settle_ms` and the refinement pass has budget for it. An
/// integration test cannot control what is on the screen of the machine it runs
/// on — a screensaver, a blinking caret, another test's window, or a busy CI
/// desktop all legitimately suppress strips — so any assertion on strip counts
/// would be a coin flip dressed up as a gate. `Reset` is different: the grid is
/// armed from `tiles_reset_req` on the very first captured frame, unconditionally
/// and independent of desktop content, so it is the strongest claim this layer
/// can make deterministically. The codec itself (compress/decompress bit-exactness,
/// malformed payloads, clipping, leases) is covered exhaustively by the unit and
/// property tests in `shared/src/tiles.rs` and `client/src/tiles.rs`, which need
/// no desktop at all.
#[test]
fn both_ends_enabled_opens_the_stream_and_delivers_a_reset() {
    let h = Harness::start(ENABLED_PORT, true);
    h.client_rt.block_on(async {
        let Handshake {
            endpoint,
            conn,
            streams,
            host_features,
        } = connect_and_pair(h.bind, &h.code, LOSSLESS_TILES)
            .await
            .expect("new client handshake");

        assert_eq!(
            host_features & LOSSLESS_TILES,
            LOSSLESS_TILES,
            "both ends asked for tiles but the host did not echo the bit"
        );

        let (session, rx) = QuicSession::start(
            conn.clone(),
            streams,
            TransportRoute::DirectUdp,
            driver_config(),
        )
        .expect("session driver");
        session.send_control(start_stream()).expect("StartStream");
        let tally = spawn_pump(rx);
        let started = Instant::now();

        // A QUIC stream only becomes visible to the peer once bytes are on it,
        // so this single await proves both halves at once: the host opened the
        // unidirectional stream, and it wrote something we can frame.
        let mut stream = tokio::time::timeout(TILE_TIMEOUT, quic::accept_bulk(&conn))
            .await
            .expect("the host never opened the negotiated tile stream")
            .expect("accept_uni failed on a negotiated tile stream");
        println!(
            "tile stream  : open after {:.2} s",
            started.elapsed().as_secs_f32()
        );

        let first: TileMsg = tokio::time::timeout(
            TILE_TIMEOUT,
            quic::read_framed(&mut stream, MAX_CONTROL_MSG),
        )
        .await
        .expect("no tile message arrived on the open stream")
        .expect("the first tile message did not decode");

        match first {
            TileMsg::Reset {
                width,
                height,
                edge,
            } => {
                println!("tile reset   : {width}x{height}, edge {edge}");
                assert!(width > 0 && height > 0, "Reset carried an empty grid");
                // `edge` is on the wire so a future host can change it, but the
                // shared codec refuses any strip taller than TILE_EDGE, so an
                // edge above it could never decode.
                assert!(
                    edge > 0 && edge <= TILE_EDGE,
                    "Reset edge {edge} is outside what the codec can decode"
                );
            }
            other => panic!("the first tile message must be a Reset, got {other:?}"),
        }

        finish_window(started).await;
        report("tiles enabled", &tally, &session);
        assert_healthy("tiles enabled", &tally, &session, &conn);

        session
            .close_graceful("tiles interop test finished", Duration::from_secs(3))
            .await;
        endpoint.wait_idle().await;
    });
    h.finish();
}

// ---------------------------------------------------------------------------
// 4. The tile path may degrade the picture, never the session
// ---------------------------------------------------------------------------

/// A tile stream that dies must cost nothing but sharpness.
///
/// # What this test can and cannot reach
///
/// The production client's reaction to a malformed tile message lives in
/// `client::net::forward_tiles` (log, return, leave the session alone) and
/// `client::tiles::TileStore::apply` (reject the message, count it, keep every
/// resident tile). Neither is reachable from a *host* integration test:
/// `directdesk-host` has no dependency on `directdesk-client`, and adding one
/// to assert on it would be inventing coupling that does not exist in the
/// product. Those two are already covered by unit tests inside the client crate.
///
/// What *is* reachable here — and is the half that a host regression could
/// actually break — is the mirror image of that policy on the host side. So this
/// test asserts both parts of the rule at the layer each one lives at:
///
/// * **Decode is total.** The exact shared functions the client feeds untrusted
///   bytes into ([`decode_strict`] for the framing, [`decompress_strip`] for the
///   payload) return `Err` on garbage rather than panicking. A panic here would
///   take the client's whole tile task down with it.
/// * **The host survives the client giving up.** When the client's tile reader
///   returns after a bad message, its `RecvStream` is dropped, which sends
///   `STOP_SENDING` and makes the host's next tile write fail. That is simulated
///   exactly, with `RecvStream::stop`, and the session must carry on: video
///   still flowing, the host's control stream still ticking, nothing closed.
#[test]
fn a_dead_tile_stream_degrades_the_picture_not_the_session() {
    // Pure, no I/O: the decode seam the client hands hostile bytes to.
    assert_malformed_tile_bytes_are_refused();

    let h = Harness::start(DEGRADE_PORT, true);
    h.client_rt.block_on(async {
        let Handshake {
            endpoint,
            conn,
            streams,
            host_features,
        } = connect_and_pair(h.bind, &h.code, LOSSLESS_TILES)
            .await
            .expect("new client handshake");
        assert_eq!(host_features & LOSSLESS_TILES, LOSSLESS_TILES);

        let (session, rx) = QuicSession::start(
            conn.clone(),
            streams,
            TransportRoute::DirectUdp,
            driver_config(),
        )
        .expect("session driver");
        session.send_control(start_stream()).expect("StartStream");
        let tally = spawn_pump(rx);

        let mut stream = tokio::time::timeout(TILE_TIMEOUT, quic::accept_bulk(&conn))
            .await
            .expect("the host never opened the negotiated tile stream")
            .expect("accept_uni failed on a negotiated tile stream");
        let first: TileMsg = tokio::time::timeout(
            TILE_TIMEOUT,
            quic::read_framed(&mut stream, MAX_CONTROL_MSG),
        )
        .await
        .expect("no tile message arrived on the open stream")
        .expect("the first tile message did not decode");
        assert!(matches!(first, TileMsg::Reset { .. }), "{first:?}");

        // Exactly what a client whose tile decoder gave up leaves behind: the
        // reader is gone and the stream is reset from the receiving end.
        //
        // Whether the host's pump *notices* is deliberately not asserted: it
        // only finds out when it next has a message to write, and a test cannot
        // make the real desktop settle on cue. Both outcomes are the same
        // requirement — the host either fails that write and quietly stops
        // refining, or never writes again and quietly stops refining. What must
        // not happen, in either case, is the session noticing.
        let _ = stream.stop(0u32.into());
        drop(stream);
        println!("tile stream  : reset by the client (simulating a malformed message)");

        let frames_at_reset = tally.frames();
        let stats_at_reset = tally.host_stats();

        // Long enough for several heartbeats, several host status ticks, and
        // any number of tile writes to fail behind the scenes.
        tokio::time::sleep(Duration::from_secs(3)).await;

        report("tile stream reset", &tally, &session);
        assert!(
            tally.frames() > frames_at_reset,
            "video stopped after the tile stream was reset: {} frames before, {} after",
            frames_at_reset,
            tally.frames()
        );
        assert!(
            tally.host_stats() > stats_at_reset,
            "the host's control stream went quiet after the tile stream was reset"
        );
        assert_healthy("tile stream reset", &tally, &session, &conn);

        session
            .close_graceful("tiles interop test finished", Duration::from_secs(3))
            .await;
        endpoint.wait_idle().await;
    });
    h.finish();
}

/// The client's decode seam, fed the things a corrupt or hostile stream would
/// put on it. Every case must be an `Err`, and none may panic.
///
/// The cases are chosen to be unambiguously invalid rather than "random":
/// postcard is a compact format, so a handful of arbitrary bytes can easily
/// *happen* to be a valid `Revoke { ids: [] }`. Each input below fails for a
/// stated structural reason.
fn assert_malformed_tile_bytes_are_refused() {
    let reset = TileMsg::Reset {
        width: 1920,
        height: 1080,
        edge: TILE_EDGE,
    };
    let framed = encode_framed(&reset).expect("encode");
    let body = &framed[4..];
    // Sanity: the well-formed message decodes, so a failure below is really
    // about the corruption and not about the fixture.
    assert_eq!(
        decode_strict::<TileMsg>(body).expect("the fixture must decode"),
        reset
    );

    // An empty frame: nothing to read a discriminant from.
    assert!(
        decode_strict::<TileMsg>(&[]).is_err(),
        "empty frame accepted"
    );
    // A varint that never terminates, so the discriminant is unreadable.
    assert!(
        decode_strict::<TileMsg>(&[0xff; 12]).is_err(),
        "unterminated varint accepted"
    );
    // A real message cut short mid-body — the truncated-frame case.
    assert!(
        decode_strict::<TileMsg>(&body[..body.len() - 1]).is_err(),
        "truncated message accepted"
    );
    // A real message with a stray byte glued on. Trailing data means the sender
    // and receiver disagree about the format; decoding the prefix and shrugging
    // is how a desync becomes silent corruption.
    let mut trailing = body.to_vec();
    trailing.push(0);
    assert!(
        decode_strict::<TileMsg>(&trailing).is_err(),
        "trailing bytes accepted"
    );

    // A structurally valid `Strip` whose *payload* is garbage: the message
    // frames and decodes, and the corruption only surfaces in the codec. This
    // is the case that matters most, because it is the one that reaches pixels.
    let mut out = Vec::new();
    assert!(
        decompress_strip(TileCodec::FilteredDeflateBgr, &[0xab; 64], 64, 64, &mut out).is_err(),
        "garbage deflate payload accepted"
    );
    assert!(
        decompress_strip(TileCodec::FilteredDeflateBgr, &[], 64, 64, &mut out).is_err(),
        "empty deflate payload accepted"
    );
    assert!(
        decompress_strip(TileCodec::Solid, &[1, 2], 64, 64, &mut out).is_err(),
        "short solid payload accepted"
    );
    // Extents the codec must refuse before it allocates anything.
    assert!(
        decompress_strip(TileCodec::Solid, &[1, 2, 3], 0, 64, &mut out).is_err(),
        "zero-width strip accepted"
    );
    assert!(
        decompress_strip(TileCodec::Solid, &[1, 2, 3], 64, TILE_EDGE + 1, &mut out).is_err(),
        "over-tall strip accepted"
    );
}

// ---------------------------------------------------------------------------
// Harness: a real host on loopback, paired and ready
// ---------------------------------------------------------------------------

/// A running host plus the two runtimes and the pairing code needed to talk to
/// it. Call [`Harness::finish`] at the end of the test rather than relying on
/// drop order.
struct Harness {
    host: NetHandle,
    runtime: tokio::runtime::Runtime,
    client_rt: tokio::runtime::Runtime,
    bind: SocketAddr,
    code: String,
    status: Arc<Mutex<StatusSnapshot>>,
    /// Serializes with every other real-capture test on this machine.
    _capture: directdesk_host::testsupport::CaptureLock,
}

impl Harness {
    fn start(port: u16, lossless_tiles_enabled: bool) -> Harness {
        // First line, before any thread or socket exists: one GPU
        // capture/encode session per machine.
        let _capture = directdesk_host::testsupport::CaptureLock::acquire();
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_env("DIRECTDESK_LOG").unwrap_or_else(
                    |_| tracing_subscriber::EnvFilter::new("warn,directdesk_host=info"),
                ),
            )
            .try_init();

        // Two runtimes, not one: in production the client is a different
        // process on a different machine, and sharing a thread pool with a host
        // that is busy encoding would measure the harness rather than the
        // product.
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

        let bind = SocketAddr::from(([127, 0, 0, 1], port));
        let store = Arc::new(MemoryStore::new());
        let identity =
            Arc::new(HostIdentity::generate("tiles-interop-host").expect("generate host identity"));
        let status = Arc::new(Mutex::new(StatusSnapshot::default()));
        let pairing = Arc::new(PairingSlot::new());

        // Straight through `HostConfig`, not by poking `NetConfig`: the config
        // knob reaching the wire is part of what is being tested.
        let host_cfg = HostConfig {
            udp_port: port,
            target_fps: 60,
            lossless_tiles_enabled,
            ..HostConfig::default()
        };
        let mut net_cfg = NetConfig::from_host_config(&host_cfg);
        net_cfg.bind = bind;
        assert_eq!(
            net_cfg.pipeline.lossless_tiles_enabled, lossless_tiles_enabled,
            "the config knob did not reach the pipeline"
        );

        let host = NetService::start(
            net_cfg,
            runtime.handle(),
            identity,
            store,
            status.clone(),
            pairing.clone(),
        );

        let bound =
            wait_for_listening(&host, bind).expect("the host never reported a bound socket");
        println!("host bound   : {bound} (tiles {lossless_tiles_enabled})");
        assert!(status.lock().listening, "status must agree with the event");

        host.command(NetCommand::ArmPairing);
        let code = wait_for(Duration::from_secs(5), || {
            pairing.snapshot(host.now_ms()).map(|p| p.digits)
        })
        .expect("no pairing code was armed");
        assert_eq!(code.len(), 8, "the code must be eight digits");

        Harness {
            host,
            runtime,
            client_rt,
            bind,
            code,
            status,
            _capture,
        }
    }

    fn finish(self) {
        while let Some(ev) = self.host.try_event() {
            println!("host event   : {ev:?}");
        }
        self.host.shutdown();
        let _ = wait_for(Duration::from_secs(10), || {
            self.host.is_stopped().then_some(())
        });
        self.client_rt.shutdown_timeout(Duration::from_secs(5));
        self.runtime.shutdown_timeout(Duration::from_secs(5));
    }
}

// ---------------------------------------------------------------------------
// Client: pair, authenticate, and report what was negotiated
// ---------------------------------------------------------------------------

/// An authenticated connection, before the session driver takes the streams.
struct Handshake {
    /// The endpoint drives the socket and must outlive the connection.
    endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    streams: SessionStreams,
    /// `Hello.features` as the host replied — the negotiated intersection.
    host_features: u64,
}

/// Pair over SPAKE2 and authenticate mutually, advertising exactly
/// `client_features`.
///
/// The ordering the whole tile feature rests on is exercised here as-is: the
/// client writes its `Hello` blind, the host reads it before replying, and the
/// client reads the reply before doing anything else. Both ends know the
/// intersection before either acts on it.
async fn connect_and_pair(addr: SocketAddr, code: &str, client_features: u64) -> Result<Handshake> {
    let recorder = ObservedPin::new();
    let endpoint = quic::client_endpoint(
        "0.0.0.0:0".parse().expect("literal address"),
        ServerPinning::TrustOnPair(recorder.clone()),
        &QuicParams::default(),
    )?;
    let conn = quic::connect(&endpoint, addr).await?;
    let mut streams = quic::open_streams(&conn).await?;

    let hello = Hello {
        version: PROTOCOL_VERSION,
        features: client_features,
        agent: "tiles-interop-test-client".to_string(),
    };
    quic::write_framed(&mut streams.control.0, &hello).await?;
    let host_hello: Hello = quic::read_framed(&mut streams.control.1, MAX_AUTH_MSG).await?;
    validate_hello(&host_hello)?;
    assert!(
        host_hello.agent.starts_with("directdesk-host"),
        "{}",
        host_hello.agent
    );
    println!(
        "hello        : client {client_features:#x} -> host {:#x}",
        host_hello.features
    );
    // Whatever else the host offers, it can never hand back a bit the client did
    // not ask for; that is the invariant an old peer's safety rests on.
    assert_eq!(
        host_hello.features & !client_features,
        0,
        "the host echoed a feature the client never requested"
    );

    let exporter = quic::channel_binding(&conn)?;

    let challenge: AuthMsg = quic::read_auth(&mut streams.control.1).await?;
    assert!(
        matches!(challenge, AuthMsg::ServerChallenge { .. }),
        "{challenge:?}"
    );

    let host_key = pair(&mut streams, &conn, &exporter, code, &recorder).await?;

    let client_id = ClientIdentity::generate("tiles-interop-client")?;
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

    Ok(Handshake {
        endpoint,
        conn,
        streams,
        host_features: host_hello.features,
    })
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
    let observed = quic::peer_spki_pin(conn)?;
    assert_eq!(
        recorder.get(),
        Some(observed),
        "the recorder and the connection disagree"
    );
    let host_peer = client.accept_pair_complete(&complete, &observed, 0)?;
    Ok(host_peer.ed25519_pub)
}

// ---------------------------------------------------------------------------
// Session plumbing shared by every scenario
// ---------------------------------------------------------------------------

fn driver_config() -> DriverConfig {
    DriverConfig {
        heartbeat_ms: HEARTBEAT_MS,
        stats_interval_ms: 500,
        // Deep enough that the *test* is never the reason a frame is lost.
        video_capacity: 256,
        ..DriverConfig::default()
    }
}

fn start_stream() -> ControlMsg {
    ControlMsg::StartStream {
        max_width: 1920,
        max_height: 1080,
        preferred_fps: 60,
        quality_mode: QualityMode::Balanced,
    }
}

/// What the client observed, accumulated by a background task so a test can ask
/// at any moment — including "did this keep growing after I broke the tile
/// stream?".
#[derive(Default)]
struct Tally {
    frames: AtomicU64,
    keyframes: AtomicU64,
    /// `ControlMsg::Stats` from the host: its status loop ticks once a second,
    /// so these are the host's own proof of life on the control stream.
    host_stats: AtomicU64,
    closed: AtomicBool,
    reason: Mutex<Option<String>>,
}

impl Tally {
    fn frames(&self) -> u64 {
        self.frames.load(Ordering::Relaxed)
    }
    fn keyframes(&self) -> u64 {
        self.keyframes.load(Ordering::Relaxed)
    }
    fn host_stats(&self) -> u64 {
        self.host_stats.load(Ordering::Relaxed)
    }
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
    fn reason(&self) -> Option<String> {
        self.reason.lock().clone()
    }
    fn note_closed(&self, reason: String) {
        self.closed.store(true, Ordering::SeqCst);
        let mut slot = self.reason.lock();
        if slot.is_none() {
            *slot = Some(reason);
        }
    }
}

/// Drain the session's receivers into a [`Tally`] until the session ends.
///
/// A background task rather than an inline loop: every test needs to be doing
/// something else (racing `accept_uni`, reading the tile stream) while the
/// session runs, and leaving the receivers unread would let their queues fill
/// and turn a protocol assertion into a plumbing artefact.
fn spawn_pump(mut rx: SessionReceivers) -> Arc<Tally> {
    let tally = Arc::new(Tally::default());
    let out = tally.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                frame = rx.video.recv() => match frame {
                    Some(f) => {
                        tally.frames.fetch_add(1, Ordering::Relaxed);
                        if f.keyframe {
                            tally.keyframes.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    None => break,
                },
                msg = rx.control.recv() => match msg {
                    Some(ControlMsg::Stats(_)) => {
                        tally.host_stats.fetch_add(1, Ordering::Relaxed);
                    }
                    Some(ControlMsg::Bye { reason }) => tally.note_closed(reason),
                    Some(_) => {}
                    None => break,
                },
                ev = rx.events.recv() => match ev {
                    Some(SessionEvent::PeerClosed { reason }) => tally.note_closed(reason),
                    Some(SessionEvent::Closed { reason }) => tally.note_closed(reason),
                    Some(_) => {}
                    None => break,
                },
            }
        }
    });
    out
}

/// Sleep out whatever is left of the standard observation window.
async fn finish_window(started: Instant) {
    let left = OBSERVE.saturating_sub(started.elapsed());
    if !left.is_zero() {
        tokio::time::sleep(left).await;
    }
}

fn report(what: &str, tally: &Tally, session: &QuicSession) {
    let stats = session.stats();
    println!(
        "{what:<18}: {} frames ({} keyframes), {} host Stats, rtt {:.2} ms",
        tally.frames(),
        tally.keyframes(),
        tally.host_stats(),
        stats.rtt_ms
    );
}

/// The properties every scenario in this file expects of a healthy session.
///
/// Note what is deliberately *not* here: any assertion about frame rate. These
/// tests run behind a real capture and encode pipeline whose throughput depends
/// on the machine's load, and a protocol test that fails when the box is busy is
/// worse than no test at all. "A frame arrived" and "the host is still talking"
/// are what matter.
fn assert_healthy(what: &str, tally: &Tally, session: &QuicSession, conn: &quinn::Connection) {
    assert!(
        !tally.is_closed(),
        "{what}: the session ended early: {:?}",
        tally.reason()
    );
    assert!(
        !session.is_closed(),
        "{what}: the driver considers the session closed"
    );
    assert!(
        conn.close_reason().is_none(),
        "{what}: the connection closed: {:?}",
        conn.close_reason()
    );
    assert!(tally.frames() > 0, "{what}: no video frames arrived");
    assert!(
        tally.keyframes() > 0,
        "{what}: no keyframe arrived; the client could never decode"
    );
    // The observation window is many heartbeat intervals long, so a host that
    // had stopped answering would have been noticed by now; these are the host's
    // own periodic messages, which only flow while its status loop and control
    // writer are both alive.
    assert!(
        tally.host_stats() >= MIN_HOST_STATS,
        "{what}: the host's control stream went quiet ({} Stats messages, wanted {MIN_HOST_STATS})",
        tally.host_stats()
    );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn wait_for_listening(host: &NetHandle, bind: SocketAddr) -> Option<SocketAddr> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        while let Some(ev) = host.try_event() {
            match ev {
                NetEvent::Listening { bound, .. } => return Some(bound),
                NetEvent::ListenFailed { detail } => {
                    panic!("the host could not bind {bind}: {detail}");
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
