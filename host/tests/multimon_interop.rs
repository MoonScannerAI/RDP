//! Backward-compatibility gate for multi-monitor.
//!
//! The host this feature ships to is remote and hard to reach, so a handshake
//! regression is close to unrecoverable: a host that mishandles an old client's
//! `Hello` is a host nobody can connect to in order to fix it. These tests exist
//! to prove the new code **cannot** change what an already-deployed peer sees.
//!
//! # Why this feature needs its own gate, and why the bar is higher
//!
//! [`tiles_interop`](../tiles_interop.rs) guards a feature that gets a stream of
//! its own; [`audio_interop`](../audio_interop.rs) guards one that shares the
//! media datagram path. Multi-monitor is the first feature that leaks into
//! **three** places at once, and each has a different blast radius:
//!
//! * **New `ControlMsg` variants.** `MonitorList`, `SelectMonitors`,
//!   `StreamConfig` and `StreamStopped` are *appended* discriminants. The
//!   control stream is read with `decode_strict`, which does not skip an unknown
//!   variant — it errors, and the error kills the control stream. One of these
//!   sent to an old peer ends the session.
//! * **New `InputMsg::EventOn`.** The same appended-variant problem on the
//!   *input* stream, where it is worse: the operator's keyboard and mouse stop
//!   working against a host whose video is still perfectly healthy, which reads
//!   as a hung remote machine rather than a protocol mismatch.
//! * **Stream-tagged datagrams.** `FLAG_STREAM1` at
//!   [`FRAG_FLAGS_OFFSET`] is the gentle case — an old peer's
//!   `FragHeader::decode` rejects the flag and drops the datagram — but it costs
//!   a second window, and it costs it silently.
//!
//! "Never sent unless the bit came back mutual" is what keeps all three
//! theoretical, and it is the single property this file exists to hold down.
//!
//! # The lesson this suite is built from
//!
//! Commit `a5a928f` renumbered the `ControlMsg` enum and broke every peer built
//! before it — silently, because both ends still parsed *something*, just not
//! the message that was sent. Nothing in that change looked like a wire change.
//! The defence that actually works is not "read the diff carefully": it is a
//! test that connects a peer whose `Hello` is pinned to the pre-feature encoding
//! and asserts, message by message and datagram by datagram, that the new host
//! says nothing the old peer cannot parse. That is scenario 1, and the reason
//! [`connect_and_pair`] is hand-rolled rather than reusing the client crate is
//! that only a hand-rolled client can send `features: 0` — a value no shipping
//! client will ever send again, and the only one that reproduces a deployed
//! peer.
//!
//! Like [`loopback`](../loopback.rs), `tiles_interop` and `audio_interop`,
//! nothing below the [`directdesk_host::net`] API is mocked: a real listener, a
//! real SPAKE2 pairing, real mutual authentication over real QUIC on loopback,
//! and a real capture/encode pipeline behind it. Every assertion is about
//! **protocol behaviour** and never about throughput.
//!
//! ```text
//! cargo test -p directdesk-host --test multimon_interop -- --nocapture
//! ```
//!
//! The four scenarios, in rollout order:
//!
//! 1. [`legacy_client_gets_no_multimon_from_an_enabled_host`] — the
//!    already-deployed client (`features: 0`) against a host with
//!    `multi_monitor_enabled: true`.
//! 2. [`new_client_and_disabled_host_are_wire_identical`] — rollout step 1: the
//!    new binary with the knob at its shipped default `false`, against a client
//!    that *does* set the bit.
//! 3. [`both_new_single_monitor`] — rollout step 2 on the topology this
//!    repository's machines actually have: the bit is mutual, the list arrives,
//!    and one selected output is still byte-for-byte the legacy stream.
//! 4. [`both_new_dual_monitor`] — the feature doing its job, on a box with two
//!    outputs. Skips with a printed reason where it cannot run.
//!
//! # Why new-client/old-host needs no scenario of its own
//!
//! The fourth cell of the compatibility matrix — a *new* client against an
//! *old* host — is covered by scenario 2 plus the pinning in
//! [`connect_and_pair`], and covering it that way is stronger than a fifth
//! scenario would be.
//!
//! An old host is, on the wire, exactly a feature-off host. Feature negotiation
//! is an intersection computed by the host over a `u64` whose unknown bits it
//! ignores, so an old host handed `features: MULTI_MONITOR` does the same thing
//! a new host with the knob off does: it masks the bit away and echoes an
//! intersection without it. There is nothing else in the client's `Hello` for it
//! to trip over, because [`connect_and_pair`] writes the *pinned* pre-feature
//! `Hello` encoding — `version`, `features`, `agent`, in that order and no more
//! — which is the same struct an old host's `decode_strict` was built against.
//! `PROTOCOL_VERSION` is unchanged by this feature by design; the whole point of
//! spending a feature bit is to avoid the version bump that would brick a host
//! reachable only through the session this protocol carries.
//!
//! So scenario 2 *is* the new-client/old-host test, with the host's behaviour
//! supplied by the branch an old host would take anyway — and it is a better
//! one, because it also proves the operator's off switch is indistinguishable
//! from the absence of the feature. If those two ever diverge, this file fails
//! rather than a deployment.
//!
//! # How the datagram sniffing works
//!
//! `transport::session`'s `datagram_recv_loop` is the only `read_datagram`
//! caller in the workspace, and quinn hands each datagram to exactly one
//! reader — so a test cannot both run that loop and watch the wire. These tests
//! therefore start the session driver with `receive_video: false` and
//! `receive_audio: false`, which is precisely the flag pair that stops the
//! driver spawning that loop at all, and [`spawn_sniffer`] takes its place.
//!
//! The sniffer is a faithful copy of the client's own demux — classify with
//! `is_audio_datagram` before anything parses or allocates, then split the video
//! population by [`datagram_stream_id`] into two independent [`Reassembler`]s,
//! one pinned to `expected_stream: 0` and one to `expected_stream: 1` — with one
//! deliberate omission: it never asks for a keyframe. An observer must not
//! perturb what it is observing.
//!
//! The one place the sniffer does **not** use a shared helper is the negative
//! this whole file rests on. `tagged`/`untagged` are counted by loading byte
//! [`FRAG_FLAGS_OFFSET`] and masking [`FLAG_STREAM1`] by hand, because "no
//! datagram on this wire has bit 3 set" is a claim about the *bytes*, and
//! asserting it through the very helper that would also have to be correct is
//! how a demux bug hides a wire bug. [`Tally::tag_disagreements`] then checks
//! the raw read and `datagram_stream_id` against each other, so the two
//! readings can never quietly drift apart.
//!
//! # Scenario 3's ordering assertion, and where it is read
//!
//! `MonitorList` is specified as the **first** post-`AuthOk` host message, and
//! the host implements that by writing it raw into `streams.control.0` in the
//! one window where the guarantee is expressible: after `handshake::authenticate`
//! wrote `AuthOk` and before `QuicSession::start` takes ownership of the stream.
//! The test reads it the same way — one `quic::read_control` off
//! `streams.control.1` **before** starting the driver and before sending
//! anything at all. Reading it through the driver's control channel could not
//! test the ordering it claims to: by then the status tick's `Stats` and
//! `RouteReport` are racing it.
//!
//! # This box may be locked, and the suite says so rather than lying
//!
//! Desktop Duplication is denied on the secure desktop, so on a locked machine
//! the pipeline pauses and **no video datagram is ever sent**. That is an
//! environment fact, not a regression, and it must not be allowed to do either
//! of the two things it naturally would:
//!
//! * **hang** — nothing here waits unboundedly for a frame; every datagram-level
//!   wait is a bounded poll whose expiry is a *reported* outcome, not a panic;
//!   and
//! * **pass silently** — "none of the datagrams was tagged" is trivially true of
//!   zero datagrams, so [`Tally::video_coverage`] prints, per scenario, whether
//!   the negative was witnessed against real traffic or held only vacuously.
//!
//! The split is deliberate and it is where the value of this file lives: the
//! **control plane is asserted strictly and unconditionally** — feature bits,
//! message ordering, and the total absence of the four new `ControlMsg`
//! variants all hold on a locked box exactly as they do on an unlocked one,
//! because none of them depends on capture. Only the datagram-level halves
//! degrade, and they degrade loudly.
//!
//! # What the harness pins, and why
//!
//! Multi-monitor has to be the only variable on the connection, so the harness
//! fixes every other feature that shares the wire with it rather than inheriting
//! the shipped defaults: tiles off (a second feature's stream), audio off (a
//! second feature's datagrams — and `FLAG_AUDIO` sits one bit away from
//! `FLAG_STREAM1` in the same byte this file makes its central claim about).
//!
//! The encoder is pinned to [`HARNESS_KBPS`] with a matching hard cap and the
//! constant-quality static-refinement pass is switched off, for the reason
//! `audio_interop` spells out at length on its own `HARNESS_KBPS`: at this
//! machine's display size the stock configuration emits keyframes the fragmenter
//! refuses to carry, and a refused keyframe is a lost frame that would be
//! charged to the second stream in [`both_new_dual_monitor`]'s
//! "stream 0 abandons nothing" assertion.
//!
//! [`Harness`] tears the host down in `Drop`, not only in `Harness::finish`, so
//! that a scenario which fails still releases Desktop Duplication before the
//! next one acquires the capture lock.
//!
//! Requirements: an interactive desktop session for the *datagram* halves (see
//! above — the control-plane halves need nothing) and UDP 48005-48008 free on
//! loopback. 47990 belongs to `loopback`, 47995-47998 to `tiles_interop` and
//! 48001-48004 to `audio_interop`, so the suites can run in sequence without a
//! lingering socket from one being mistaken for another's.
//!
//! [`FRAG_FLAGS_OFFSET`]: directdesk_shared::video::FRAG_FLAGS_OFFSET
//! [`FLAG_STREAM1`]: directdesk_shared::video::FLAG_STREAM1
//! [`datagram_stream_id`]: directdesk_shared::video::datagram_stream_id

#![cfg(windows)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use directdesk_shared::audio::is_audio_datagram;
use directdesk_shared::crypto::pairing::{PairingClient, PairingCode};
use directdesk_shared::crypto::storage::MemoryStore;
use directdesk_shared::crypto::tls::{ObservedPin, ServerPinning};
use directdesk_shared::crypto::{auth::ClientAuthenticator, ClientIdentity, HostIdentity};
use directdesk_shared::protocol::features::MULTI_MONITOR;
use directdesk_shared::protocol::{
    validate_hello, AuthMsg, ControlMsg, Hello, MonitorInfo, QualityMode, MAX_AUTH_MSG,
    MAX_VIDEO_STREAMS, PROTOCOL_VERSION,
};
use directdesk_shared::stats::TransportRoute;
use directdesk_shared::transport::quic::{self, QuicParams, SessionStreams};
use directdesk_shared::transport::reassembly::{Reassembler, ReassemblyConfig, ReassemblyStats};
use directdesk_shared::transport::session::{
    QuicSession, Session, SessionConfig as DriverConfig, SessionEvent, SessionReceivers,
};
use directdesk_shared::video::{datagram_stream_id, FragHeader, FLAG_STREAM1, FRAG_FLAGS_OFFSET};
use directdesk_shared::Result;
use parking_lot::Mutex;

use directdesk_host::config::HostConfig;
use directdesk_host::net::{
    NetCommand, NetConfig, NetEvent, NetHandle, NetService, PairingSlot, StatusSnapshot,
};

/// Loopback only: these tests must never expose a listener to the network.
/// One port per scenario so a lingering socket from the previous test can never
/// be mistaken for this one's. (47990 is `loopback`, 47995-47998 belong to
/// `tiles_interop`, 48001-48004 to `audio_interop`.)
const LEGACY_PORT: u16 = 48_005;
const DISABLED_PORT: u16 = 48_006;
const SINGLE_PORT: u16 = 48_007;
const DUAL_PORT: u16 = 48_008;

/// Client heartbeat interval. Deliberately short so a few-second observation
/// window really does span *several* heartbeats.
const HEARTBEAT_MS: u64 = 400;

/// How long a "the session behaves completely normally" observation runs.
/// Ten heartbeats at [`HEARTBEAT_MS`].
const OBSERVE: Duration = Duration::from_secs(4);

/// Bound on the one framed read this file does by hand — `MonitorList`, ahead of
/// the session driver. Generous, because `list_monitors` is a synchronous DXGI
/// factory-and-output walk that talks to the display driver, and mean nothing
/// like a frame deadline: it must fail because the message never came, not
/// because the box was busy.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a control message the client asked for gets to come back — a
/// `VideoConfig` after `StartStream`, a `StreamConfig` after `SelectMonitors`.
/// These are pure control-plane round trips with no capture behind them, so
/// this is bounded well inside a scenario's budget.
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a *datagram*-level condition is given before the run is reported as
/// having observed nothing. Expiring is never a panic in this file; see the
/// module docs on the locked desktop.
const DATAGRAM_TIMEOUT: Duration = Duration::from_secs(12);

/// How long a stream that has been told to stop is given to actually go quiet
/// before "the tagged datagrams ceased" is measured.
const CEASE_SETTLE: Duration = Duration::from_secs(2);

/// Host status ticks are one second apart (`directdesk_host::net`'s
/// `STATUS_INTERVAL_MS`), so a 4 s window carries about four `Stats` messages.
/// Two is the "the host's control plane is still talking to us" floor that no
/// amount of load can plausibly breach — and, unlike anything about frames, it
/// holds on a locked desktop, because the status loop does not depend on
/// capture succeeding.
const MIN_HOST_STATS: u64 = 2;

/// Encoder bitrate this harness pins the host to — as the starting rate *and* as
/// a hard cap the adaptive controller may never climb back above, together with
/// `static_refine_quality: 0`.
///
/// The full argument is on `audio_interop`'s constant of the same name and is
/// not repeated here. In one line: at this repository's display sizes the stock
/// host emits keyframes larger than `fragment_frame_fec` will carry (512
/// fragments), a refused keyframe never reaches the datagram path at all, and it
/// lands in the reassembler's counters looking exactly like a frame something
/// else shredded. [`both_new_dual_monitor`] asserts stream 0 abandons nothing
/// while stream 1 flows, and that assertion means "stream 1 did not cost stream
/// 0" only if the fragmenter is not independently losing frames underneath it.
const HARNESS_KBPS: u32 = 4_000;

/// How long the host's media thread is given to release Desktop Duplication
/// after the listener reports stopped, before the capture lock is handed to the
/// next scenario. See the note on [`Harness`].
const CAPTURE_RELEASE: Duration = Duration::from_millis(750);

// ---------------------------------------------------------------------------
// 1. Legacy client, new host with the feature switched on
// ---------------------------------------------------------------------------

/// An already-deployed client — one whose `Hello.features` is `0` because it was
/// built before the feature existed — against a host with
/// `multi_monitor_enabled: true`.
///
/// This is the strongest form of the compatibility question: the host is not
/// merely capable of multi-monitor, it is *configured for it*, and it has
/// enumerated its outputs and built a `MonitorList` it is entirely ready to
/// send. It still must not let one byte of the new vocabulary reach a peer that
/// never asked — because on the control stream "a message the peer never asked
/// for" means a `decode_strict` failure, and a `decode_strict` failure on the
/// control stream means the session is over.
///
/// The negative is asserted on both planes at the level each one matters:
///
/// * **Control (strict, and unaffected by a locked desktop).** Every control
///   message of the whole observation window is inspected, and not one may be
///   `MonitorList`, `StreamConfig` or `StreamStopped`. The host's `Hello` must
///   carry the empty intersection rather than its own offer.
/// * **Datagrams (strict about what arrived, honest about how much did).**
///   Every datagram is classified, and each one must be a well-formed video
///   fragment with bit 3 of byte [`FRAG_FLAGS_OFFSET`] clear — read raw, not
///   through the demux helper.
///
/// [`FRAG_FLAGS_OFFSET`]: directdesk_shared::video::FRAG_FLAGS_OFFSET
#[test]
fn legacy_client_gets_no_multimon_from_an_enabled_host() {
    let h = Harness::start(LEGACY_PORT, MultiMonitor::On);
    h.block_on(async {
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
            host_features & MULTI_MONITOR,
            0,
            "the host echoed the multi-monitor bit to a client that never set it"
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
        let tally = spawn_pump(rx);
        // Before `StartStream`, so not one media datagram of this session can
        // reach the socket unobserved.
        spawn_sniffer(conn.clone(), tally.clone());
        session.send_control(start_stream()).expect("StartStream");

        tokio::time::sleep(OBSERVE).await;

        report("legacy client", &tally, &session);
        assert_no_multimon_control("legacy client", &tally);
        assert_no_tagged_datagrams("legacy client", &tally);
        assert_control_plane_healthy("legacy client", &tally, &session, &conn);
        // A legacy session is a working session, not merely a quiet one: the
        // host must still have answered `StartStream` with the `VideoConfig`
        // it has always answered it with.
        assert!(
            tally.video_configs() > 0,
            "legacy client: no VideoConfig arrived, so the session the host was \
             supposed to leave untouched is not actually working"
        );

        session
            .close_graceful("multimon interop test finished", Duration::from_secs(3))
            .await;
        endpoint.wait_idle().await;
    });
    h.finish();
}

// ---------------------------------------------------------------------------
// 2. New client, host with the feature off (the shipped default)
// ---------------------------------------------------------------------------

/// Rollout step 1: the new binary, deployed with `multi_monitor_enabled` at its
/// default `false`, talking to a client that *does* set the bit.
///
/// The property under test is not "multi-monitor is off" but something stronger:
/// this build is **indistinguishable on the wire** from the one already
/// deployed. That is what makes shipping the code and enabling it later two
/// separately reversible steps — and, as the module docs argue, it is also what
/// makes this the new-client/old-host test, since an old host and a feature-off
/// host take the same branch.
///
/// So the assertion is not merely "no multi-monitor traffic". It is that the
/// negotiated intersection equals what a pre-feature host would have negotiated
/// — `0` — for a client that asked for the feature and nothing else. A host that
/// echoed the bit while declining to act on it would pass a "no `MonitorList`
/// arrived" test and still be a host whose clients open a second window that
/// never receives a frame.
#[test]
fn new_client_and_disabled_host_are_wire_identical() {
    let h = Harness::start(DISABLED_PORT, MultiMonitor::Off);
    h.block_on(async {
        let Handshake {
            endpoint,
            conn,
            streams,
            host_features,
        } = connect_and_pair(h.bind, &h.code, MULTI_MONITOR)
            .await
            .expect("new client handshake");

        // The client asked; the host, unconfigured, offers nothing. An operator
        // turning the feature off must be indistinguishable from a host that
        // never had it — which is the same thing as saying: from an old host.
        assert_eq!(
            host_features & MULTI_MONITOR,
            0,
            "a host with multi_monitor_enabled=false accepted the multi-monitor bit"
        );
        assert_eq!(
            host_features, 0,
            "the negotiated intersection must be empty on the shipped default \
             config; this is the value a pre-feature host would have replied \
             with, and the two must not be tellable apart"
        );

        let (session, rx) = QuicSession::start(
            conn.clone(),
            streams,
            TransportRoute::DirectUdp,
            driver_config(),
        )
        .expect("session driver");
        let tally = spawn_pump(rx);
        spawn_sniffer(conn.clone(), tally.clone());
        session.send_control(start_stream()).expect("StartStream");

        tokio::time::sleep(OBSERVE).await;

        report("multimon off", &tally, &session);
        // Identical negatives to scenario 1: the shipped default must offer
        // nothing, and "nothing" is spelled out message by message and byte by
        // byte rather than assumed from the empty `Hello`.
        assert_no_multimon_control("multimon off", &tally);
        assert_no_tagged_datagrams("multimon off", &tally);
        assert_control_plane_healthy("multimon off", &tally, &session, &conn);
        assert!(
            tally.video_configs() > 0,
            "multimon off: no VideoConfig arrived, so the session that is \
             supposed to be identical to a pre-feature one is not working"
        );

        session
            .close_graceful("multimon interop test finished", Duration::from_secs(3))
            .await;
        endpoint.wait_idle().await;
    });
    h.finish();
}

// ---------------------------------------------------------------------------
// 3. Both ends new, one monitor selected
// ---------------------------------------------------------------------------

/// Rollout step 2, on the topology this repository's machines actually have: the
/// bit is mutual, the host really does enumerate and announce its outputs, and a
/// client that selects one output still gets byte-for-byte the legacy stream.
///
/// # The ordering assertion, and why it is the first thing that happens
///
/// `MonitorList` is specified as the **first** post-`AuthOk` host control
/// message, and the client's whole handshake is built on it: one framed read
/// after `AuthOk` and it knows the topology, so its `SelectMonitors` and
/// `StartStream` are one decision rather than a start-then-correct flicker.
///
/// That guarantee is only expressible in the window before `QuicSession::start`
/// takes ownership of the control stream — after that, `send_control` races the
/// status tick's `Stats` and `RouteReport` and "first message" stops meaning
/// anything. So this test reads it in exactly that window: one
/// `quic::read_control` before the driver exists and before the client has sent
/// a single byte of its own. Asserting the ordering from inside the driver's
/// control channel would be asserting something weaker while looking identical.
///
/// # And what stays legacy
///
/// One selected output is the single-monitor path every deployed peer runs, so
/// with `SelectMonitors { ids: [0] }` the wire below the handshake must be
/// unchanged: the legacy `VideoConfig` describes stream 0 with today's
/// semantics, no `StreamConfig` is sent (that message is for `id != 0` only, and
/// `StreamConfig { id: 0, .. }` is a bug rather than a synonym), no
/// `StreamStopped` is sent, and not one datagram carries the stream tag.
#[test]
fn both_new_single_monitor() {
    let h = Harness::start(SINGLE_PORT, MultiMonitor::On);
    h.block_on(async {
        let Handshake {
            endpoint,
            conn,
            mut streams,
            host_features,
        } = connect_and_pair(h.bind, &h.code, MULTI_MONITOR)
            .await
            .expect("new client handshake");

        assert_eq!(
            host_features & MULTI_MONITOR,
            MULTI_MONITOR,
            "both ends asked for multi-monitor but the host did not echo the bit"
        );

        // --- the ordering assertion -------------------------------------
        // Read before anything is sent and before the driver exists. See the
        // doc comment: this is the only window in which "first" is a property
        // rather than a race.
        let first = tokio::time::timeout(
            CONTROL_TIMEOUT,
            quic::read_control::<ControlMsg>(&mut streams.control.1),
        )
        .await
        .unwrap_or_else(|_| {
            panic!(
                "no host control message arrived within {CONTROL_TIMEOUT:?} of \
                 AuthOk on a session that negotiated MULTI_MONITOR; MonitorList \
                 is supposed to be written before the session driver starts"
            )
        })
        .expect("the first post-AuthOk control message did not decode");

        let ControlMsg::MonitorList { monitors } = first else {
            panic!(
                "the first post-AuthOk host control message was {first:?}, not \
                 MonitorList. The client does one framed read here and treats \
                 whatever it gets as the topology, so anything else ahead of it \
                 breaks the handshake this feature is built on"
            );
        };
        describe_monitors(&monitors);
        assert!(
            !monitors.is_empty(),
            "the host sent an empty MonitorList; a client with no monitors in \
             its list cannot select even the primary"
        );
        assert_eq!(
            monitors[0].id, 0,
            "the first entry of MonitorList must be id 0: ids are positional and \
             SelectMonitors addresses them by number"
        );
        assert!(
            monitors[0].is_primary,
            "id 0 is specified as always the primary output, and the client's \
             picker preselects it on that basis; got {:?}",
            monitors[0]
        );
        // Positional ids, asserted across the whole list rather than only at 0,
        // because `SelectMonitors` is resolved by index on the host side and a
        // gap would silently address the wrong output.
        for (i, m) in monitors.iter().enumerate() {
            assert_eq!(
                m.id, i as u8,
                "MonitorList ids must be positional: entry {i} says id {}",
                m.id
            );
        }
        assert_eq!(
            monitors.iter().filter(|m| m.is_primary).count(),
            1,
            "exactly one monitor may be flagged primary"
        );

        // --- the session, now that the topology is known -----------------
        let (session, rx) = QuicSession::start(
            conn.clone(),
            streams,
            TransportRoute::DirectUdp,
            driver_config(),
        )
        .expect("session driver");
        let tally = spawn_pump(rx);
        spawn_sniffer(conn.clone(), tally.clone());

        // The real client's order: select first, then start. Selecting after
        // starting is the flicker the ordering guarantee above exists to avoid.
        session
            .send_control(ControlMsg::SelectMonitors { ids: vec![0] })
            .expect("SelectMonitors");
        session.send_control(start_stream()).expect("StartStream");

        assert!(
            poll_until(REPLY_TIMEOUT, || tally.video_configs() > 0).await,
            "no legacy VideoConfig arrived within {REPLY_TIMEOUT:?} of StartStream; \
             stream 0 is supposed to keep being described by the message it has \
             always been described by"
        );
        let (w, hgt) = tally
            .last_video_config()
            .expect("a VideoConfig was counted");
        println!("videoconfig  : {w}x{hgt} (legacy, stream 0)");
        assert!(
            w > 0 && hgt > 0,
            "the legacy VideoConfig carried a degenerate {w}x{hgt}"
        );
        assert_eq!(
            (w, hgt),
            (monitors[0].width, monitors[0].height),
            "stream 0's legacy VideoConfig must describe the monitor the client \
             selected (id 0); MonitorList said {}x{}",
            monitors[0].width,
            monitors[0].height
        );

        tokio::time::sleep(OBSERVE).await;

        report("both new, 1 mon", &tally, &session);

        // With one output selected the wire below the handshake is the legacy
        // wire, and every part of that is asserted rather than inferred.
        assert_eq!(
            tally.stream_configs(),
            0,
            "a StreamConfig arrived for a single-monitor selection; that message \
             is for id != 0 only, and StreamConfig {{ id: 0 }} is a bug rather \
             than a synonym for VideoConfig"
        );
        assert_eq!(
            tally.stream_stoppeds(),
            0,
            "a StreamStopped arrived on a session that never had a second stream"
        );
        // Re-sends are *reported*, not asserted against. `watch_topology` fires
        // on the status tick and re-sends whenever the enumeration differs from
        // its cached copy on the full `MonitorInfo`, and there is a legitimate
        // way for that to happen on a perfectly static desktop: if
        // `list_monitors` fails or comes back empty in `run_session`, the host
        // sends a synthesized one-entry list built from the pipeline's own
        // description, and the first successful tick then corrects it. Asserting
        // "exactly one MonitorList per session" would make this suite fail for a
        // transient DXGI enumeration hiccup, which is not what it is for.
        if tally.monitor_lists() > 0 {
            println!(
                "both new, 1 mon: NOTE — the host re-sent MonitorList {} time(s) \
                 on a static desktop. Legal (the run_session fallback list being \
                 corrected by the first watch_topology tick looks exactly like \
                 this), but worth knowing: a re-send renumbers outputs the client \
                 is already watching.",
                tally.monitor_lists()
            );
        }
        assert_no_tagged_datagrams("both new, 1 mon", &tally);
        assert_control_plane_healthy("both new, 1 mon", &tally, &session, &conn);

        session
            .close_graceful("multimon interop test finished", Duration::from_secs(3))
            .await;
        endpoint.wait_idle().await;
    });
    h.finish();
}

// ---------------------------------------------------------------------------
// 4. Both ends new, two monitors
// ---------------------------------------------------------------------------

/// The feature actually doing its job: two outputs, two independent video
/// streams sharing one datagram path, demuxed by one bit.
///
/// # Why this skips rather than fails
///
/// It needs a second physical output, which is a property of the machine and not
/// of the code — the same reason `loopback` gates on an interactive desktop.
/// A hardware requirement asserted as a failure is a red test that everyone
/// learns to ignore, and a test everyone ignores is worse than one that says
/// out loud what it did not check. The skip message names the requirement so a
/// run on a one-monitor box reports honestly-reduced coverage.
///
/// # What it asserts when it can run
///
/// * `SelectMonitors { ids: [0, 1] }` produces `StreamConfig { id: 1, monitor:
///   1, .. }` — and stream 0 is still described by the legacy `VideoConfig`.
/// * The two lanes really are independent: tagged and untagged datagrams go to
///   two [`Reassembler`]s with **separate frame-id spaces**, and both complete
///   frames. One shared reassembler would reject half the traffic outright,
///   which is exactly why `expected_stream` exists.
/// * Stream 1 does not cost stream 0: reassembler 0 abandons nothing while
///   stream 1 flows. Both lanes compete for one `send_datagram` buffer, and when
///   it fills quinn evicts the *oldest* queued datagrams — so an unbudgeted
///   second stream does not drop itself, it shreds the frame already in flight.
/// * One `RequestKeyframe` produces a keyframe on **both** streams. The host
///   fans it to every slot behind a single session-wide rate limiter, which is
///   the behaviour a client with two stuck decoders needs.
/// * Re-selecting `[0]` produces `StreamStopped { id: 1 }` and the tagged
///   datagrams **cease** — the teardown half of the same guarantee scenario 1
///   asserts about a peer that never asked.
/// * `StopStream` stops both.
#[test]
fn both_new_dual_monitor() {
    let outputs = match directdesk_host::capture::list_monitors() {
        Ok(l) => l.len(),
        Err(e) => {
            println!(
                "SKIP both_new_dual_monitor: could not enumerate this machine's \
                 outputs ({e}). This scenario requires >= 2 capturable monitors."
            );
            return;
        }
    };
    if outputs < 2 {
        println!(
            "SKIP both_new_dual_monitor: this machine reports {outputs} capturable \
             monitor(s); the scenario requires >= 2 so there is a second output to \
             put on video stream 1. Everything below the two-output requirement is \
             covered by both_new_single_monitor; what is NOT covered on this box is \
             the tagged datagram lane, its independent reassembly, the \
             StreamConfig/StreamStopped round trip and the two-stream keyframe fan-out."
        );
        return;
    }
    println!("dual monitor : {outputs} outputs reported; running the full scenario");

    let h = Harness::start(DUAL_PORT, MultiMonitor::On);
    h.block_on(async {
        let Handshake {
            endpoint,
            conn,
            mut streams,
            host_features,
        } = connect_and_pair(h.bind, &h.code, MULTI_MONITOR)
            .await
            .expect("new client handshake");
        assert_eq!(host_features & MULTI_MONITOR, MULTI_MONITOR);

        let first = tokio::time::timeout(
            CONTROL_TIMEOUT,
            quic::read_control::<ControlMsg>(&mut streams.control.1),
        )
        .await
        .expect("no MonitorList before the driver started")
        .expect("MonitorList did not decode");
        let ControlMsg::MonitorList { monitors } = first else {
            panic!("the first post-AuthOk host message was {first:?}, not MonitorList");
        };
        describe_monitors(&monitors);
        assert!(
            monitors.len() >= 2,
            "this machine enumerates {outputs} outputs but the host announced \
             {} monitor(s); the host's list is what the client selects against",
            monitors.len()
        );

        let (session, rx) = QuicSession::start(
            conn.clone(),
            streams,
            TransportRoute::DirectUdp,
            driver_config(),
        )
        .expect("session driver");
        let tally = spawn_pump(rx);
        spawn_sniffer(conn.clone(), tally.clone());

        // --- both outputs ------------------------------------------------
        session
            .send_control(ControlMsg::SelectMonitors { ids: vec![0, 1] })
            .expect("SelectMonitors [0, 1]");
        session.send_control(start_stream()).expect("StartStream");

        assert!(
            poll_until(REPLY_TIMEOUT, || tally.stream_configs() > 0).await,
            "no StreamConfig arrived within {REPLY_TIMEOUT:?} of \
             SelectMonitors {{ ids: [0, 1] }}"
        );
        let sc = tally
            .last_stream_config()
            .expect("a StreamConfig was counted");
        println!(
            "streamconfig : id {} monitor {} {}x{}",
            sc.id, sc.monitor, sc.width, sc.height
        );
        assert_eq!(sc.id, 1, "the secondary stream must be slot 1");
        assert_eq!(
            sc.monitor, 1,
            "slot 1 must carry the monitor the client put at index 1 of its \
             SelectMonitors list; SelectMonitors is ordered, not a set"
        );
        assert!(sc.width > 0 && sc.height > 0);
        assert!(
            poll_until(REPLY_TIMEOUT, || tally.video_configs() > 0).await,
            "stream 0 got no legacy VideoConfig while a second stream was live"
        );

        // --- the two lanes ------------------------------------------------
        let saw_traffic = poll_until(DATAGRAM_TIMEOUT, || {
            tally.reassembly0().frames_completed > 0 && tally.reassembly1().frames_completed > 0
        })
        .await;
        report("both new, 2 mon", &tally, &session);
        tally.video_coverage("both new, 2 mon");

        if !saw_traffic {
            println!(
                "both new, 2 mon: NOT VERIFIED at the datagram level — no complete \
                 frame arrived on one or both lanes within {DATAGRAM_TIMEOUT:?}. The \
                 control-plane half of this scenario (StreamConfig/StreamStopped, \
                 ordering, feature bits) was asserted strictly; the tagged-lane \
                 half was not exercised. On a locked desktop this is expected: \
                 Desktop Duplication is denied on the secure desktop."
            );
        } else {
            assert!(
                tally.tagged() > 0,
                "both lanes completed frames but no datagram carried FLAG_STREAM1; \
                 stream 1 cannot have been the tagged one"
            );
            assert!(
                tally.untagged() > 0,
                "no untagged datagram arrived; stream 0 must stay legacy"
            );
            assert_eq!(
                tally.tag_disagreements(),
                0,
                "the raw byte-{FRAG_FLAGS_OFFSET} read and datagram_stream_id \
                 disagreed about {} datagram(s)",
                tally.tag_disagreements()
            );
            // Independent frame-id spaces: two reassemblers, each refusing the
            // other's stream, and both completing frames anyway. If the ids
            // shared a space one of them would be rejecting or abandoning.
            assert_eq!(
                tally.reassembly0().fragments_rejected,
                0,
                "reassembler 0 rejected {} fragment(s): a tagged datagram reached \
                 the untagged lane",
                tally.reassembly0().fragments_rejected
            );
            assert_eq!(
                tally.reassembly1().fragments_rejected,
                0,
                "reassembler 1 rejected {} fragment(s): an untagged datagram \
                 reached the tagged lane",
                tally.reassembly1().fragments_rejected
            );

            // Stream 1 must not cost stream 0.
            let base0 = tally.reassembly0();
            tokio::time::sleep(OBSERVE).await;
            let after0 = tally.reassembly0();
            assert!(
                after0.frames_completed > base0.frames_completed,
                "stream 0 stopped completing frames while stream 1 flowed"
            );
            assert_eq!(
                abandoned(&after0),
                abandoned(&base0),
                "stream 0 abandoned a frame while stream 1 flowed — the signature \
                 of the second stream spending send-buffer room the first had \
                 already counted on ({base0:?} -> {after0:?})"
            );

            // One request, both decoders served.
            let k0 = tally.keyframes0();
            let k1 = tally.keyframes1();
            session
                .send_control(ControlMsg::RequestKeyframe)
                .expect("RequestKeyframe");
            assert!(
                poll_until(DATAGRAM_TIMEOUT, || tally.keyframes0() > k0
                    && tally.keyframes1() > k1)
                .await,
                "one RequestKeyframe did not produce a keyframe on both streams \
                 within {DATAGRAM_TIMEOUT:?} (stream 0: {} -> {}, stream 1: {} -> \
                 {}); the host fans the request to every slot behind one \
                 session-wide limiter",
                k0,
                tally.keyframes0(),
                k1,
                tally.keyframes1()
            );
        }

        // --- back to one output -------------------------------------------
        // Asserted whether or not datagrams flowed: this half is control plane.
        session
            .send_control(ControlMsg::SelectMonitors { ids: vec![0] })
            .expect("SelectMonitors [0]");
        assert!(
            poll_until(REPLY_TIMEOUT, || tally.stream_stoppeds() > 0).await,
            "no StreamStopped arrived within {REPLY_TIMEOUT:?} of deselecting \
             monitor 1"
        );
        assert_eq!(
            tally.stopped_ids(),
            vec![1],
            "StreamStopped must name stream 1 and only stream 1; stream 0 ends \
             with StopStream or Bye, exactly as it does today"
        );

        if saw_traffic {
            // The teardown half of scenario 1's guarantee: not merely "the
            // client was told", but "the bytes stopped".
            tokio::time::sleep(CEASE_SETTLE).await;
            let tagged_at_mark = tally.tagged();
            tokio::time::sleep(CEASE_SETTLE).await;
            assert_eq!(
                tally.tagged(),
                tagged_at_mark,
                "{} tagged datagram(s) arrived after StreamStopped {{ id: 1 }}",
                tally.tagged() - tagged_at_mark
            );
            let untagged_at_mark = tally.untagged();
            tokio::time::sleep(CEASE_SETTLE).await;
            assert!(
                tally.untagged() > untagged_at_mark,
                "stream 0 stopped when stream 1 was deselected"
            );
        }

        // --- and StopStream stops what is left ----------------------------
        session
            .send_control(ControlMsg::StopStream)
            .expect("StopStream");
        if saw_traffic {
            tokio::time::sleep(CEASE_SETTLE).await;
            let all_at_mark = tally.video();
            tokio::time::sleep(CEASE_SETTLE).await;
            assert_eq!(
                tally.video(),
                all_at_mark,
                "{} video datagram(s) arrived after StopStream",
                tally.video() - all_at_mark
            );
        }

        report("both new, 2 mon", &tally, &session);
        assert_control_plane_healthy("both new, 2 mon", &tally, &session, &conn);

        session
            .close_graceful("multimon interop test finished", Duration::from_secs(3))
            .await;
        endpoint.wait_idle().await;
    });
    h.finish();
}

// ---------------------------------------------------------------------------
// Harness: a real host on loopback, paired and ready
// ---------------------------------------------------------------------------

/// The host's multi-monitor configuration for one scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MultiMonitor {
    /// The shipped default.
    Off,
    On,
}

impl MultiMonitor {
    const fn enabled(self) -> bool {
        matches!(self, MultiMonitor::On)
    }
}

/// A running host plus the two runtimes and the pairing code needed to talk to
/// it.
///
/// # Why the teardown is a `Drop` and not only [`Harness::finish`]
///
/// Every scenario here boots a real Desktop Duplication session, and
/// `testsupport::CaptureLock` exists to guarantee only one of those is alive at a
/// time. But a lock is only as good as the moment it is released, and
/// `CaptureLock` releases on drop — so with the teardown living only in
/// `finish()`, a *failing* scenario unwinds straight past it and hands the lock
/// to the next scenario while its own `dd-media` thread is still holding
/// `IDXGIOutputDuplication`. The next `DuplicateOutput` then fails with
/// `E_INVALIDARG` (0x80070057), which is why it does not read as a lock problem:
/// a contended output reports a bad *parameter*, not access denied. One genuine
/// failure becomes three, and multi-monitor makes that worse rather than better,
/// because a two-slot scenario holds two duplications.
///
/// Putting the teardown in `Drop` fixes the ordering by construction: Rust runs
/// `Drop::drop` before it drops the struct's fields, and `_capture` is a field,
/// so the host is stopped and its media threads given time to let go of DXGI
/// before the lock is handed on — whether the test passed or panicked.
struct Harness {
    host: NetHandle,
    /// `Option` only so [`Harness::teardown`] can take them by value out of
    /// `&mut self` — `Runtime::shutdown_timeout` consumes the runtime.
    runtime: Option<tokio::runtime::Runtime>,
    client_rt: Option<tokio::runtime::Runtime>,
    bind: SocketAddr,
    code: String,
    #[allow(dead_code)]
    status: Arc<Mutex<StatusSnapshot>>,
    /// Serializes with every other real-capture test on this machine. Declared
    /// last on purpose: fields drop in declaration order and after
    /// `Drop::drop`, so this is released once the host is down.
    _capture: directdesk_host::testsupport::CaptureLock,
}

impl Harness {
    fn start(port: u16, multimon: MultiMonitor) -> Harness {
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

        // Two runtimes, not one: in production the client is a different process
        // on a different machine, and sharing a thread pool with a host that is
        // busy encoding two outputs would measure the harness rather than the
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
        let identity = Arc::new(
            HostIdentity::generate("multimon-interop-host").expect("generate host identity"),
        );
        let status = Arc::new(Mutex::new(StatusSnapshot::default()));
        let pairing = Arc::new(PairingSlot::new());

        // Straight through `HostConfig`, not by poking `NetConfig`: the config
        // knob reaching the wire is part of what is being tested.
        let host_cfg = HostConfig {
            udp_port: port,
            target_fps: 60,
            // --- multi-monitor: the subject ------------------------------
            multi_monitor_enabled: multimon.enabled(),
            // --- the two features that share this wire, both held off ----
            // Audio matters more than it looks: `FLAG_AUDIO` is bit 2 of the
            // same flags byte this file makes its central claim about at bit 3,
            // and an audio datagram in the population would be classified out
            // before the raw tag read ever saw it.
            system_audio_enabled: false,
            // --- video: the knobs that keep multi-monitor the only subject -
            // Pinned rather than defaulted; the long "why" is on
            // [`HARNESS_KBPS`].
            bitrate_kbps: HARNESS_KBPS,
            bitrate_cap_kbps: Some(HARNESS_KBPS),
            static_refine_quality: 0,
            ..HostConfig::default()
        };
        let mut net_cfg = NetConfig::from_host_config(&host_cfg);
        net_cfg.bind = bind;
        assert_eq!(
            net_cfg.multi_monitor_enabled,
            multimon.enabled(),
            "the multi-monitor knob did not reach the listener"
        );
        assert!(
            !net_cfg.system_audio_enabled,
            "audio must stay off: it shares the datagram path and its flag bit \
             sits next to the one this file asserts on"
        );
        assert!(
            !net_cfg.pipeline.lossless_tiles_enabled,
            "tiles must stay at their default off here: multi-monitor is the \
             only variable in this file, and a tile stream would put a second \
             feature's traffic on the connection"
        );
        assert_eq!(
            net_cfg.pipeline.bitrate_kbps, HARNESS_KBPS,
            "the starting bitrate did not reach the pipeline"
        );
        assert_eq!(
            net_cfg.bitrate_cap_kbps,
            Some(HARNESS_KBPS),
            "the bitrate cap did not reach the listener; without it the adaptor \
             climbs back to its mode ceiling and the fragmenter starts refusing \
             keyframes again"
        );
        assert_eq!(
            net_cfg.pipeline.static_refine_quality, 0,
            "the constant-quality static-refinement pass must stay off here; it \
             emits keyframes no bitrate cut can shrink"
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
        println!(
            "host bound   : {bound} (multi-monitor {})",
            multimon.enabled()
        );
        assert!(status.lock().listening, "status must agree with the event");

        host.command(NetCommand::ArmPairing);
        let code = wait_for(Duration::from_secs(5), || {
            pairing.snapshot(host.now_ms()).map(|p| p.digits)
        })
        .expect("no pairing code was armed");
        assert_eq!(code.len(), 8, "the code must be eight digits");

        Harness {
            host,
            runtime: Some(runtime),
            client_rt: Some(client_rt),
            bind,
            code,
            status,
            _capture,
        }
    }

    /// Run `fut` on the client runtime.
    fn block_on<F: std::future::Future>(&self, fut: F) -> F::Output {
        self.client_rt
            .as_ref()
            .expect("the client runtime is gone; finish() ran early")
            .block_on(fut)
    }

    /// Stop the host and both runtimes. Idempotent, and called by `Drop`, so a
    /// scenario that panics tears down in the same order a scenario that passes
    /// does. See the note on [`Harness`] for why that order matters.
    fn finish(mut self) {
        self.teardown();
    }

    /// The teardown itself. Must not panic: it runs during unwinding.
    fn teardown(&mut self) {
        let Some(runtime) = self.runtime.take() else {
            return;
        };

        while let Some(ev) = self.host.try_event() {
            println!("host event   : {ev:?}");
        }
        self.host.shutdown();
        if wait_for(Duration::from_secs(10), || {
            self.host.is_stopped().then_some(())
        })
        .is_none()
        {
            // Reported rather than asserted: this runs during unwinding, where a
            // second panic aborts the process and destroys the first one's
            // message — which is the message that says why the run failed.
            println!("host          : did not report stopped within 10 s");
        }

        // Client first: its tasks hold the connection whose close the host's
        // session loop is waiting on.
        if let Some(client_rt) = self.client_rt.take() {
            client_rt.shutdown_timeout(Duration::from_secs(5));
        }
        runtime.shutdown_timeout(Duration::from_secs(5));

        // And the last gap: `HostSession`'s drop joins `dd-media`, but the
        // `IDXGIOutputDuplication` that thread owns is released by COM as the
        // thread's stack unwinds, which `shutdown_timeout` does not wait for.
        std::thread::sleep(CAPTURE_RELEASE);
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.teardown();
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
/// Hand-rolled rather than reusing the client crate's connect path precisely so
/// that `client_features` is exactly controllable — including `0`, which is the
/// value no shipping client will ever send again and the only one that
/// reproduces an already-deployed peer.
///
/// The `Hello` written here is also the **pinned pre-feature encoding**: three
/// fields, in the declared order, and nothing this feature added. That pinning
/// is what lets the module docs claim scenario 2 covers new-client/old-host — an
/// old host's `decode_strict` was built against exactly this shape, and a
/// `features` `u64` with an unknown bit set is a value it already knows how to
/// intersect away. If this feature ever grows the handshake, this function stops
/// compiling, which is the point.
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
        agent: "multimon-interop-test-client".to_string(),
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

    let client_id = ClientIdentity::generate("multimon-interop-client")?;
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

/// The driver, configured to leave the datagram path alone.
///
/// `receive_video: false` and `receive_audio: false` together are exactly what
/// stops `QuicSession::start` spawning `datagram_recv_loop` — and that loop is
/// the workspace's only `read_datagram` caller. Turning it off is what lets
/// [`spawn_sniffer`] see the raw wire; leaving it on would mean two readers
/// racing for datagrams quinn hands to exactly one of them, and neither the
/// driver's view nor the test's would be complete.
fn driver_config() -> DriverConfig {
    DriverConfig {
        heartbeat_ms: HEARTBEAT_MS,
        stats_interval_ms: 500,
        receive_video: false,
        receive_audio: false,
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

/// A `StreamConfig` as the client saw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SeenStreamConfig {
    id: u8,
    monitor: u8,
    width: u32,
    height: u32,
}

/// What the client observed, accumulated by background tasks so a test can ask
/// at any moment.
#[derive(Default)]
struct Tally {
    // ---- control plane, from the session driver -------------------------
    /// `ControlMsg::Stats` from the host: its status loop ticks once a second,
    /// so these are the host's own proof of life on the control stream — and
    /// they keep ticking on a locked desktop, which is what makes
    /// [`assert_control_plane_healthy`] strict everywhere.
    host_stats: AtomicU64,
    video_configs: AtomicU64,
    last_video_config: Mutex<Option<(u32, u32)>>,
    /// The four messages that must never reach a peer which did not negotiate
    /// the feature. `monitor_lists` counts only what arrived *through the
    /// driver*: the initial one is read by hand before the driver starts, so a
    /// non-zero count here means a re-send.
    monitor_lists: AtomicU64,
    stream_configs: AtomicU64,
    stream_stoppeds: AtomicU64,
    last_stream_config: Mutex<Option<SeenStreamConfig>>,
    stopped_ids: Mutex<Vec<u8>>,
    /// The first new-vocabulary message seen, verbatim, so a compatibility
    /// failure names the message rather than only counting it.
    multimon_complaint: Mutex<Option<String>>,
    closed: AtomicBool,
    reason: Mutex<Option<String>>,

    // ---- datagram plane, from the sniffer -------------------------------
    datagrams: AtomicU64,
    /// Must stay 0 in this file: audio is configured off, and a datagram
    /// classified as audio would be one the raw tag read never inspected.
    audio: AtomicU64,
    video: AtomicU64,
    /// Counted from a **raw** load of byte `FRAG_FLAGS_OFFSET` masked with
    /// `FLAG_STREAM1`. Deliberately not `datagram_stream_id`: see the module
    /// docs.
    tagged: AtomicU64,
    untagged: AtomicU64,
    /// Datagrams where the raw read and `datagram_stream_id` disagreed.
    tag_disagreements: AtomicU64,
    /// Non-audio datagrams that would not parse as a video fragment.
    video_decode_errors: AtomicU64,
    frames0: AtomicU64,
    keyframes0: AtomicU64,
    frames1: AtomicU64,
    keyframes1: AtomicU64,
    complaint: Mutex<Option<String>>,
    reassembly0: Mutex<ReassemblyStats>,
    reassembly1: Mutex<ReassemblyStats>,
}

impl Tally {
    fn host_stats(&self) -> u64 {
        self.host_stats.load(Ordering::Relaxed)
    }
    fn video_configs(&self) -> u64 {
        self.video_configs.load(Ordering::Relaxed)
    }
    fn last_video_config(&self) -> Option<(u32, u32)> {
        *self.last_video_config.lock()
    }
    fn monitor_lists(&self) -> u64 {
        self.monitor_lists.load(Ordering::Relaxed)
    }
    fn stream_configs(&self) -> u64 {
        self.stream_configs.load(Ordering::Relaxed)
    }
    fn stream_stoppeds(&self) -> u64 {
        self.stream_stoppeds.load(Ordering::Relaxed)
    }
    fn last_stream_config(&self) -> Option<SeenStreamConfig> {
        *self.last_stream_config.lock()
    }
    fn stopped_ids(&self) -> Vec<u8> {
        self.stopped_ids.lock().clone()
    }
    fn multimon_complaint(&self) -> Option<String> {
        self.multimon_complaint.lock().clone()
    }
    fn datagrams(&self) -> u64 {
        self.datagrams.load(Ordering::Relaxed)
    }
    fn audio(&self) -> u64 {
        self.audio.load(Ordering::Relaxed)
    }
    fn video(&self) -> u64 {
        self.video.load(Ordering::Relaxed)
    }
    fn tagged(&self) -> u64 {
        self.tagged.load(Ordering::Relaxed)
    }
    fn untagged(&self) -> u64 {
        self.untagged.load(Ordering::Relaxed)
    }
    fn tag_disagreements(&self) -> u64 {
        self.tag_disagreements.load(Ordering::Relaxed)
    }
    fn video_decode_errors(&self) -> u64 {
        self.video_decode_errors.load(Ordering::Relaxed)
    }
    fn frames0(&self) -> u64 {
        self.frames0.load(Ordering::Relaxed)
    }
    fn keyframes0(&self) -> u64 {
        self.keyframes0.load(Ordering::Relaxed)
    }
    fn frames1(&self) -> u64 {
        self.frames1.load(Ordering::Relaxed)
    }
    fn keyframes1(&self) -> u64 {
        self.keyframes1.load(Ordering::Relaxed)
    }
    fn reassembly0(&self) -> ReassemblyStats {
        *self.reassembly0.lock()
    }
    fn reassembly1(&self) -> ReassemblyStats {
        *self.reassembly1.lock()
    }
    fn first_complaint(&self) -> Option<String> {
        self.complaint.lock().clone()
    }
    fn complain(&self, detail: String) {
        let mut slot = self.complaint.lock();
        if slot.is_none() {
            *slot = Some(detail);
        }
    }
    fn note_multimon(&self, detail: String) {
        let mut slot = self.multimon_complaint.lock();
        if slot.is_none() {
            *slot = Some(detail);
        }
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

    /// Say, in one line, whether this run's datagram-level negatives were
    /// witnessed against real traffic or held only vacuously.
    ///
    /// A locked desktop denies Desktop Duplication, so the pipeline pauses and
    /// no video datagram is ever sent. "None of them was tagged" is then true
    /// and worthless, and the honest thing for a test to do is say so rather
    /// than report a pass that means less than it looks like. The control-plane
    /// assertions around it are unaffected and stay strict.
    fn video_coverage(&self, what: &str) -> bool {
        let n = self.video();
        if n == 0 {
            println!(
                "{what:<15}: WEAKER COVERAGE — zero video datagrams arrived, so \
                 every datagram-level negative in this scenario held vacuously. \
                 That is the expected shape of a run on a LOCKED desktop (Desktop \
                 Duplication is denied on the secure desktop, so the pipeline \
                 pauses). The control-plane assertions — feature bits, message \
                 ordering, and the absence of MonitorList/StreamConfig/\
                 StreamStopped — were asserted strictly and are unaffected."
            );
            false
        } else {
            println!(
                "{what:<15}: datagram negatives witnessed against {n} real video \
                 datagram(s)"
            );
            true
        }
    }
}

/// Drain the session's control plane into a [`Tally`] until the session ends.
///
/// A background task rather than an inline loop: every test needs to be doing
/// something else while the session runs, and leaving the receivers unread would
/// let their queues fill and turn a protocol assertion into a plumbing artefact.
///
/// The `_ => {}` arm of `audio_interop`'s pump is deliberately *not* reproduced.
/// Every message this feature added is matched by name, because the whole
/// question in scenarios 1 and 2 is whether one of them arrived, and a catch-all
/// would swallow exactly the evidence.
fn spawn_pump(rx: SessionReceivers) -> Arc<Tally> {
    let SessionReceivers {
        mut control,
        mut events,
        ..
    } = rx;
    let tally = Arc::new(Tally::default());
    let out = tally.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                msg = control.recv() => match msg {
                    Some(ControlMsg::Stats(_)) => {
                        tally.host_stats.fetch_add(1, Ordering::Relaxed);
                    }
                    Some(ControlMsg::VideoConfig { width, height, .. }) => {
                        tally.video_configs.fetch_add(1, Ordering::Relaxed);
                        *tally.last_video_config.lock() = Some((width, height));
                    }
                    // --- the four this file is about ------------------------
                    Some(ControlMsg::MonitorList { monitors }) => {
                        tally.monitor_lists.fetch_add(1, Ordering::Relaxed);
                        tally.note_multimon(format!(
                            "MonitorList with {} monitor(s)",
                            monitors.len()
                        ));
                    }
                    Some(ControlMsg::StreamConfig {
                        id, monitor, width, height, ..
                    }) => {
                        tally.stream_configs.fetch_add(1, Ordering::Relaxed);
                        *tally.last_stream_config.lock() = Some(SeenStreamConfig {
                            id, monitor, width, height,
                        });
                        tally.note_multimon(format!(
                            "StreamConfig {{ id: {id}, monitor: {monitor}, \
                             {width}x{height} }}"
                        ));
                    }
                    Some(ControlMsg::StreamStopped { id, ref reason }) => {
                        tally.stream_stoppeds.fetch_add(1, Ordering::Relaxed);
                        tally.stopped_ids.lock().push(id);
                        tally.note_multimon(format!(
                            "StreamStopped {{ id: {id}, reason: {reason:?} }}"
                        ));
                    }
                    // `SelectMonitors` is client -> host and can never appear
                    // here; it is named anyway so that a host which ever echoed
                    // one is caught rather than falling into the catch-all.
                    Some(ControlMsg::SelectMonitors { ref ids }) => {
                        tally.note_multimon(format!(
                            "the host sent SelectMonitors {ids:?}, which is a \
                             client -> host message"
                        ));
                    }
                    Some(ControlMsg::Bye { reason }) => tally.note_closed(reason),
                    Some(_) => {}
                    None => break,
                },
                ev = events.recv() => match ev {
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

/// Read every media datagram this connection delivers and record what it was.
///
/// This is the client's `datagram_recv_loop` for the purposes of these tests —
/// same demux, same order of operations — with two deliberate differences:
///
/// * it records instead of delivering, so a test can assert on the *whole*
///   datagram population rather than on what survived a channel;
/// * it never calls `take_keyframe_request`, and so never sends
///   `RequestKeyframe` of its own. An observer that asked the host to re-encode
///   would be changing the traffic it is measuring — and scenario 4 asserts on
///   exactly one explicit `RequestKeyframe`, which a chatty sniffer would drown.
///
/// # Two reassemblers, and why they cannot be one
///
/// The two lanes have **independent frame-id spaces**: stream 1's frame 7 has
/// nothing to do with stream 0's frame 7, and a single reassembler would treat
/// the interleaving as a storm of out-of-order fragments, abandon frames on both
/// lanes and reject the rest. `ReassemblyConfig::expected_stream` is the
/// mechanism the client uses to keep them apart, and mirroring it here is what
/// makes "both lanes completed frames" a statement about the product rather than
/// about the test's own bookkeeping.
///
/// Both run with `latest_wins` off so that every completed frame is counted in
/// completion order; the production policy of skipping stale frames is right for
/// a decoder and wrong for a census.
fn spawn_sniffer(conn: quinn::Connection, tally: Arc<Tally>) {
    tokio::spawn(async move {
        let started = Instant::now();
        let mut lanes: Vec<Reassembler> = (0..MAX_VIDEO_STREAMS)
            .map(|s| {
                Reassembler::new(ReassemblyConfig {
                    latest_wins: false,
                    expected_stream: s,
                    ..ReassemblyConfig::default()
                })
            })
            .collect();
        loop {
            let datagram = match conn.read_datagram().await {
                Ok(d) => d,
                // The session ended. Not this task's business to say so; the
                // pump above is watching the control plane for that.
                Err(_) => return,
            };
            tally.datagrams.fetch_add(1, Ordering::Relaxed);

            // The demux, ahead of every parser and every allocation, exactly as
            // the driver does it: one bounds-checked byte load and a mask on a
            // slice of entirely unknown provenance. Audio is configured off in
            // this file, so this arm is a tripwire rather than a route.
            if is_audio_datagram(&datagram) {
                tally.audio.fetch_add(1, Ordering::Relaxed);
                tally.complain(format!(
                    "a datagram of {} bytes classified as AUDIO on a host with \
                     system_audio_enabled=false",
                    datagram.len()
                ));
                continue;
            }

            tally.video.fetch_add(1, Ordering::Relaxed);

            // --- the raw read, and why it is raw --------------------------
            // "No datagram on this wire has bit 3 of byte 8 set" is a claim
            // about the bytes. Reading it through `datagram_stream_id` would
            // make the claim depend on that helper also being right, and a
            // demux bug would then hide the wire bug this file exists to catch.
            // A datagram too short to hold the flags byte cannot be tagged and
            // is not one: `.get()` keeps this total over a slice of any length,
            // including the zero-length datagram QUIC permits.
            let raw_tagged = datagram
                .get(FRAG_FLAGS_OFFSET)
                .is_some_and(|f| f & FLAG_STREAM1 != 0);
            if raw_tagged {
                tally.tagged.fetch_add(1, Ordering::Relaxed);
            } else {
                tally.untagged.fetch_add(1, Ordering::Relaxed);
            }
            // Cross-check, so the raw read and the shipped helper can never
            // quietly drift apart about what a tag is.
            let via_helper = datagram_stream_id(&datagram);
            if via_helper != u8::from(raw_tagged) {
                tally.tag_disagreements.fetch_add(1, Ordering::Relaxed);
                tally.complain(format!(
                    "datagram_stream_id said {via_helper} but byte \
                     {FRAG_FLAGS_OFFSET} & {FLAG_STREAM1:#b} said {}",
                    u8::from(raw_tagged)
                ));
            }

            // Asserted separately from the reassembler's own decode: this is the
            // claim the compatibility scenarios make about *every* datagram on
            // the wire — that it is a video fragment and nothing else.
            if let Err(e) = FragHeader::decode(&datagram) {
                tally.video_decode_errors.fetch_add(1, Ordering::Relaxed);
                tally.complain(format!(
                    "datagram of {} bytes is neither audio nor a video fragment: {e}",
                    datagram.len()
                ));
                continue;
            }

            let lane = via_helper as usize;
            let now_ms = started.elapsed().as_millis() as u64;
            let Some(reassembler) = lanes.get_mut(lane) else {
                tally.complain(format!("datagram routed to unknown lane {lane}"));
                continue;
            };
            if let Err(e) = reassembler.push(&datagram, now_ms) {
                tally.complain(format!("reassembler {lane} refused a datagram: {e}"));
            }
            while let Some(frame) = reassembler.pop_frame() {
                let (frames, keyframes) = if lane == 0 {
                    (&tally.frames0, &tally.keyframes0)
                } else {
                    (&tally.frames1, &tally.keyframes1)
                };
                frames.fetch_add(1, Ordering::Relaxed);
                if frame.keyframe {
                    keyframes.fetch_add(1, Ordering::Relaxed);
                }
            }
            let stats = reassembler.stats();
            if lane == 0 {
                *tally.reassembly0.lock() = stats;
            } else {
                *tally.reassembly1.lock() = stats;
            }
        }
    });
}

fn report(what: &str, tally: &Tally, session: &QuicSession) {
    let stats = session.stats();
    println!(
        "{what:<15}: {} datagrams ({} video: {} untagged / {} tagged, {} audio), \
         stream0 {} frames ({} kf), stream1 {} frames ({} kf), {} host Stats, \
         rtt {:.2} ms",
        tally.datagrams(),
        tally.video(),
        tally.untagged(),
        tally.tagged(),
        tally.audio(),
        tally.frames0(),
        tally.keyframes0(),
        tally.frames1(),
        tally.keyframes1(),
        tally.host_stats(),
        stats.rtt_ms
    );
    println!(
        "{what:<15}: control — {} VideoConfig, {} MonitorList (re-sends), {} \
         StreamConfig, {} StreamStopped",
        tally.video_configs(),
        tally.monitor_lists(),
        tally.stream_configs(),
        tally.stream_stoppeds()
    );
    println!(
        "{what:<15}: reassembly0 {:?} / reassembly1 {:?}",
        tally.reassembly0(),
        tally.reassembly1()
    );
}

fn describe_monitors(monitors: &[MonitorInfo]) {
    println!("monitorlist  : {} output(s)", monitors.len());
    for m in monitors {
        println!(
            "  id {} {}x{} @ ({}, {}) primary={} {:?}",
            m.id, m.width, m.height, m.origin_x, m.origin_y, m.is_primary, m.name
        );
    }
}

// ---------------------------------------------------------------------------
// The two negatives, and the one health check that survives a locked desktop
// ---------------------------------------------------------------------------

/// The control-plane negative both compatibility scenarios rest on: not one
/// message of the new vocabulary reached a peer that did not negotiate it.
///
/// Strict and unconditional. Nothing here depends on capture succeeding, so a
/// locked desktop weakens it not at all — which is precisely why the four
/// `ControlMsg` variants, the ones whose blast radius is the whole session, are
/// checked on this plane rather than inferred from an absence of datagrams.
fn assert_no_multimon_control(what: &str, tally: &Tally) {
    // Without this the assertions below could be satisfied by a control stream
    // that never carried anything at all.
    assert!(
        tally.host_stats() > 0,
        "{what}: no host control message of any kind arrived, so 'none of them \
         was MonitorList' proves nothing"
    );
    assert_eq!(
        tally.monitor_lists(),
        0,
        "{what}: the host sent MonitorList to a peer that did not negotiate \
         MULTI_MONITOR. The control stream is read with decode_strict, so on a \
         real deployed client this is not a stray message — it is the end of the \
         session. First: {:?}",
        tally.multimon_complaint()
    );
    assert_eq!(
        tally.stream_configs(),
        0,
        "{what}: the host sent StreamConfig to a peer that did not negotiate \
         MULTI_MONITOR; first: {:?}",
        tally.multimon_complaint()
    );
    assert_eq!(
        tally.stream_stoppeds(),
        0,
        "{what}: the host sent StreamStopped to a peer that did not negotiate \
         MULTI_MONITOR; first: {:?}",
        tally.multimon_complaint()
    );
    // Belt and braces: nothing else in the new vocabulary either.
    assert_eq!(
        tally.multimon_complaint(),
        None,
        "{what}: a multi-monitor control message reached a peer that did not \
         negotiate the feature"
    );
}

/// The datagram-plane negative: no fragment on this wire carried the stream tag.
///
/// # Strict about what arrived, honest about how much did
///
/// The assertion itself is unconditional — if a tagged datagram arrived, this
/// fails, whatever the desktop was doing. What is *conditional* is the strength
/// of the conclusion: on a locked box no video datagram is sent at all, so the
/// negative holds vacuously, and [`Tally::video_coverage`] prints that rather
/// than letting a vacuous pass read like a witnessed one.
///
/// This is deliberately not written as `assert!(datagrams > 0)` the way
/// `audio_interop` writes its equivalent. That suite runs on an interactive
/// desktop by requirement; this one must also be runnable on a locked host,
/// where a hard requirement of traffic would turn an environment fact into a red
/// test and a hang.
fn assert_no_tagged_datagrams(what: &str, tally: &Tally) {
    tally.video_coverage(what);
    assert_eq!(
        tally.tagged(),
        0,
        "{what}: {} of {} video datagram(s) had bit 3 set at byte \
         {FRAG_FLAGS_OFFSET} at a peer that never negotiated MULTI_MONITOR. An \
         already-deployed peer's FragHeader::decode rejects that flag and drops \
         the datagram, so this costs a second window silently. First: {:?}",
        tally.tagged(),
        tally.video(),
        tally.first_complaint()
    );
    assert_eq!(
        tally.audio(),
        0,
        "{what}: {} datagram(s) classified as audio on a host configured without \
         it; they never reached the stream-tag check at all",
        tally.audio()
    );
    assert_eq!(
        tally.video_decode_errors(),
        0,
        "{what}: {} datagram(s) did not decode as a video fragment; first: {:?}",
        tally.video_decode_errors(),
        tally.first_complaint()
    );
    assert_eq!(
        tally.tag_disagreements(),
        0,
        "{what}: the raw flags-byte read and datagram_stream_id disagreed about \
         {} datagram(s); first: {:?}",
        tally.tag_disagreements(),
        tally.first_complaint()
    );
    assert_eq!(
        tally.frames1(),
        0,
        "{what}: the stream-1 reassembler completed {} frame(s) on a session that \
         never negotiated a second stream",
        tally.frames1()
    );
}

/// The properties every scenario in this file expects of a healthy session,
/// restricted to the ones that hold on a **locked** desktop.
///
/// Note what is deliberately not here. `audio_interop`'s equivalent asserts
/// `frames > 0` and `keyframes > 0`; this one cannot, because Desktop
/// Duplication is denied on the secure desktop and a host with no picture to
/// send is still a host whose protocol behaviour this file is about. The
/// picture, where it exists, is reported by [`Tally::video_coverage`] and
/// asserted by [`both_new_dual_monitor`] behind its own traffic guard.
///
/// What remains is strict and is the part that matters: the session is open, the
/// driver agrees, the connection is not closing, and the host's own periodic
/// `Stats` — which flow from its status loop and not from its encoder — are
/// still arriving. Also deliberately absent: any assertion about frame rate or
/// packet rate. A protocol test that fails when the box is busy is worse than no
/// test at all.
fn assert_control_plane_healthy(
    what: &str,
    tally: &Tally,
    session: &QuicSession,
    conn: &quinn::Connection,
) {
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
    assert!(
        tally.host_stats() >= MIN_HOST_STATS,
        "{what}: the host's control stream went quiet ({} Stats messages, wanted \
         {MIN_HOST_STATS}). This one does not depend on capture, so a locked \
         desktop is no excuse for it",
        tally.host_stats()
    );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Await a condition, polling. Bounded, and never a bare sleep-then-assert: the
/// thing being waited for has a real pipeline starting up behind it.
///
/// Every caller in this file treats the `false` return as a *result*, not as a
/// reason to keep waiting — which is what keeps the suite from hanging a locked
/// box.
async fn poll_until(limit: Duration, mut probe: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + limit;
    loop {
        if probe() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// The three counters that together mean "the reassembler gave up on something".
fn abandoned(s: &ReassemblyStats) -> (u64, u64, u64) {
    (
        s.frames_dropped_incomplete,
        s.frames_dropped_stale,
        s.fragments_rejected,
    )
}

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
