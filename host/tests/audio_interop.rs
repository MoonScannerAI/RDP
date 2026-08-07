//! Backward-compatibility gate for system audio.
//!
//! The host this feature ships to is remote and hard to reach, so a handshake
//! regression is close to unrecoverable: a host that mishandles an old client's
//! `Hello` is a host nobody can connect to in order to fix it. These tests exist
//! to prove the new code **cannot** change what an already-deployed peer sees.
//!
//! Audio raises the stakes above what [`tiles_interop`](../tiles_interop.rs)
//! covers, because audio does not get a stream of its own: it shares the
//! unreliable **media datagram path** with video, demuxed by one byte
//! ([`directdesk_shared::audio::is_audio_datagram`]). A tile stream leaking to
//! an old peer would be a stream it never accepts. An audio datagram leaking to
//! an old peer goes straight into that peer's video reassembler, which is a
//! different and much worse kind of wrong. So the negative here is asserted at
//! the level it matters: **every datagram** that reaches the client is
//! classified and parsed, and in the two compatibility scenarios not one of them
//! may be audio.
//!
//! Like [`loopback`](../loopback.rs) and `tiles_interop`, nothing below the
//! [`directdesk_host::net`] API is mocked: a real listener, a real SPAKE2
//! pairing, real mutual authentication over real QUIC on loopback, and a real
//! capture/encode pipeline behind it. Every assertion is about **protocol
//! behaviour** — which feature bits come back, what appears on the datagram
//! path, whether the session survives — and never about throughput. Nothing in
//! this file may depend on achieving a frame rate or an audio packet rate.
//!
//! ```text
//! cargo test -p directdesk-host --test audio_interop -- --nocapture
//! ```
//!
//! # How the datagram sniffing works
//!
//! `transport::session`'s `datagram_recv_loop` is the only `read_datagram`
//! caller in the workspace, and quinn hands each datagram to exactly one
//! reader — so a test cannot both run that loop and watch the wire. These tests
//! therefore start the session driver with `receive_video` and `receive_audio`
//! **off**, which is precisely the flag pair that stops the driver spawning that
//! loop at all, and [`spawn_sniffer`] takes its place. The sniffer is a faithful
//! copy of the driver's own demux — classify with `is_audio_datagram` before
//! anything parses or allocates, route audio to `decode_packet` and everything
//! else to a real [`Reassembler`] — with one deliberate omission: it never asks
//! for a keyframe. An observer must not perturb what it is observing.
//!
//! Everything else about the session is real and unchanged: the control stream,
//! the heartbeat, the host's `Stats` ticks and the `StartStream` that makes the
//! host encode at all all go through the ordinary driver.
//!
//! The four scenarios, in rollout order:
//!
//! 1. [`legacy_client_gets_no_audio_from_an_audio_enabled_host`] — the
//!    already-deployed client (`features: 0`) against a host with the feature
//!    fully switched on and a source that is guaranteed to have something to
//!    send.
//! 2. [`new_client_and_disabled_host_are_wire_identical_to_the_old_build`] —
//!    rollout step 1: the new binary with `system_audio_enabled: false`, which
//!    is the shipped default.
//! 3. [`both_ends_enabled_deliver_decodable_audio`] — rollout step 2: the
//!    feature actually works, and does not cost the picture anything.
//! 4. [`a_broken_audio_path_degrades_the_sound_not_the_session`] — the design
//!    rule the whole feature rests on.
//!
//! # What the harness pins, and why
//!
//! Audio has to be the only variable on the connection, so the harness fixes
//! every other feature that shares the wire with it rather than inheriting the
//! shipped defaults. Tiles stay off (a second feature's stream). The encoder is
//! pinned to [`HARNESS_KBPS`] with a matching hard cap, and the host's
//! constant-quality static-refinement pass is switched off — both because at
//! this machine's display size they emit keyframes the fragmenter refuses to
//! carry, which is a *lost frame* that looks exactly like the one scenario 3
//! blames on audio. The full argument, and why this sharpens the assertion
//! rather than relaxing it, is on [`HARNESS_KBPS`].
//!
//! [`Harness`] tears the host down in `Drop`, not only in `Harness::finish`, so
//! that a scenario which fails still releases Desktop Duplication before the
//! next one acquires the capture lock. The note on [`Harness`] explains what
//! goes wrong when it does not.
//!
//! Requirements: an interactive desktop session (Desktop Duplication cannot run
//! on a session-0 service, and a locked desktop mutes audio by design) and UDP
//! 48001-48004 free on loopback. No audio *hardware* is needed by scenarios
//! 1-3: they run the host's `AudioSource::TestTone`, which exists for exactly
//! this reason.

#![cfg(windows)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use directdesk_shared::audio::{
    decode_packet, encode_packet, is_audio_datagram, AudioFormat, AudioPacket, AUDIO_FLAGS_MASK,
    AUDIO_FLAGS_OFFSET, AUDIO_FORMAT_OFFSET, AUDIO_HEADER_LEN, FLAG_AUDIO, MAX_AUDIO_PAYLOAD,
};
use directdesk_shared::crypto::pairing::{PairingClient, PairingCode};
use directdesk_shared::crypto::storage::MemoryStore;
use directdesk_shared::crypto::tls::{ObservedPin, ServerPinning};
use directdesk_shared::crypto::{auth::ClientAuthenticator, ClientIdentity, HostIdentity};
use directdesk_shared::protocol::features::SYSTEM_AUDIO;
use directdesk_shared::protocol::{
    validate_hello, AuthMsg, ControlMsg, Hello, QualityMode, MAX_AUTH_MSG, PROTOCOL_VERSION,
};
use directdesk_shared::stats::TransportRoute;
use directdesk_shared::transport::quic::{self, QuicParams, SessionStreams};
use directdesk_shared::transport::reassembly::{
    is_newer, Reassembler, ReassemblyConfig, ReassemblyStats,
};
use directdesk_shared::transport::session::{
    QuicSession, Session, SessionConfig as DriverConfig, SessionEvent, SessionReceivers,
};
use directdesk_shared::video::FragHeader;
use directdesk_shared::Result;
use parking_lot::Mutex;

use directdesk_host::config::{AudioSource, HostConfig};
use directdesk_host::net::{
    AudioStatus, NetCommand, NetConfig, NetEvent, NetHandle, NetService, PairingSlot,
    StatusSnapshot,
};
use directdesk_host::session::FRAGMENTER_FRAME_LIMIT_BYTES;

/// Loopback only: these tests must never expose a listener to the network.
/// One port per scenario so a lingering socket from the previous test can never
/// be mistaken for this one's. (47995-47998 belong to `tiles_interop`.)
const LEGACY_PORT: u16 = 48_001;
const DISABLED_PORT: u16 = 48_002;
const ENABLED_PORT: u16 = 48_003;
const DEGRADE_PORT: u16 = 48_004;

/// Client heartbeat interval. Deliberately short so a few-second observation
/// window really does span *several* heartbeats.
const HEARTBEAT_MS: u64 = 400;

/// How long a "the session behaves completely normally" observation runs.
/// Ten heartbeats at [`HEARTBEAT_MS`].
const OBSERVE: Duration = Duration::from_secs(4);

/// How long the first audio datagram gets to appear once both ends have agreed
/// on it. Very generous on purpose: a COM apartment, `MFStartup`, a capture
/// source and an AAC MFT are all being built behind it, and this is a protocol
/// test — it must fail because audio never comes, not because the machine was
/// busy.
const AUDIO_TIMEOUT: Duration = Duration::from_secs(20);

/// How long audio is watched once it has started. AAC-LC codes 1024 samples at
/// a time, so 48 kHz audio is ~47 access units a second and two seconds is
/// ~94 packets — four times [`MIN_AUDIO_PACKETS`], which is the slack that
/// keeps this a count assertion rather than a rate one.
const AUDIO_WINDOW: Duration = Duration::from_secs(2);

/// Floor on audio datagrams seen inside [`AUDIO_WINDOW`]. Low enough that a
/// heavily loaded machine still clears it, high enough that it cannot be met by
/// a stray packet or two.
const MIN_AUDIO_PACKETS: u64 = 20;

/// Host status ticks are one second apart (`directdesk_host::net`'s
/// `STATUS_INTERVAL_MS`), so a 4 s window carries about four `Stats` messages.
/// Two is the "the host's control plane is still talking to us" floor that no
/// amount of load can plausibly breach.
const MIN_HOST_STATS: u64 = 2;

/// Encoder bitrate this harness pins the host to — as the starting rate *and*
/// as a hard cap the adaptive controller may never climb back above.
///
/// # Why a test about audio configures the video encoder
///
/// [`both_ends_enabled_deliver_decodable_audio`] asserts that no video frame is
/// abandoned while audio is on the wire. On a large display the stock host
/// configuration breaks that assertion by itself, with no audio anywhere near
/// it, and it does so in two ways that have to be closed together:
///
/// * **The streaming IDR.** The host encodes at the *desktop's* resolution —
///   `StartStream`'s `max_width`/`max_height` are advisory, logged by
///   `net::serve`'s control loop and never applied — and `AdaptConfig`'s
///   Balanced mode starts at 8 Mbps and climbs toward a 15 Mbps ceiling. On a
///   2560x1600 screen that yields IDRs of several hundred KB, and
///   `fragment_frame_fec` refuses outright any frame needing more than
///   `MAX_FRAGS_PER_FRAME` (512) datagrams — [`FRAGMENTER_FRAME_LIMIT_BYTES`],
///   593 KiB at the QUIC minimum MTU. A refused keyframe is a lost frame.
/// * **The static-refinement IDR**, which is worse, because no bitrate cut can
///   shrink it. Once the desktop has held still for `static_settle_ms` the host
///   buys that idle period's one keyframe in constant-*quality* mode (CQP,
///   `AVEncCommonQuality` 88) rather than inside the rate controller's budget.
///   `directdesk_host::session::STATIC_REFINE_MAX_BYTES` holds it to 243 KB — a
///   ceiling derived for 1080p — and a still 2560x1600 desktop sails through
///   both that and the fragmenter's own limit. The host then walks the quality
///   down eight points per overshoot (88 -> 80 -> ... -> off), and **every rung
///   of that ladder is a frame the client never completes**. A test desktop is
///   still by definition, so this fires for the whole run and no amount of
///   waiting outlasts it.
///
/// Both are pre-existing consequences of this machine's screen size rather than
/// audio defects, and neither is something this file may make a claim about. So
/// the harness configures them out, for exactly the reason it already refuses
/// to let tiles run here: audio must be the only variable on the connection.
/// `HARNESS_KBPS` keeps every IDR an order of magnitude inside the fragmenter's
/// limit, and `static_refine_quality: 0` is the documented off switch for the
/// CQP pass — the settle keyframe is still requested and still sent, it is
/// simply coded inside the ordinary budget like every other frame.
///
/// What is deliberately *not* done is weakening the assertion. The frames audio
/// must not cost are still counted one for one; and the host's own
/// `StatusSnapshot::frames_unfragmentable` is now asserted flat across the
/// measured window, so that if this condition ever returns it is *named* rather
/// than silently blamed on audio.
const HARNESS_KBPS: u32 = 4_000;

/// How long the picture is given to stop losing frames before the audio window
/// starts. Generous: the encoder, the adaptor and QUIC's path-MTU discovery are
/// all still converging when the first audio datagram lands.
const VIDEO_SETTLE_TIMEOUT: Duration = Duration::from_secs(15);

/// How long the reassembler must abandon nothing for the stream to count as
/// settled. Longer than a GOP would be ideal but is not affordable inside the
/// test's budget; 1.5 s spans several `idle_repeat_ms` keepalives and any
/// startup burst, which is what this is for.
const VIDEO_QUIET: Duration = Duration::from_millis(1_500);

/// One host status interval (`STATUS_INTERVAL_MS`, 1 s) plus slack. The host's
/// lifetime counters are only republished on that tick, so a delta measured
/// across the audio window has to wait this long to be sure it has seen the
/// whole window.
const STATUS_LAG: Duration = Duration::from_millis(1_500);

/// How long the host's media thread is given to release Desktop Duplication
/// after the listener reports stopped, before the capture lock is handed to the
/// next scenario. See the note on [`Harness`].
const CAPTURE_RELEASE: Duration = Duration::from_millis(750);

// ---------------------------------------------------------------------------
// 1. Legacy client, new host
// ---------------------------------------------------------------------------

/// An already-deployed client — one whose `Hello.features` is `0` because it
/// was built before the feature existed — against a host with
/// `system_audio_enabled: true`.
///
/// This is the strongest form of the compatibility question: the host is not
/// merely capable of audio, it is *configured for it*, and its source is
/// [`AudioSource::TestTone`] rather than loopback, so there is unquestionably a
/// stream of audio it could send. (With loopback and a quiet desktop the host
/// would emit nothing anyway and this test would pass while proving nothing.)
/// It still must not let a byte of the new format reach a peer that never
/// asked — because on this path "a byte the peer never asked for" means a
/// datagram handed to that peer's *video reassembler*.
///
/// The negative is asserted directly: every datagram of the whole observation
/// window is classified, and each one must be a well-formed video fragment.
#[test]
fn legacy_client_gets_no_audio_from_an_audio_enabled_host() {
    let h = Harness::start(LEGACY_PORT, Audio::tone());
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
            host_features & SYSTEM_AUDIO,
            0,
            "the host echoed the audio bit to a client that never set it"
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
        assert_no_audio_reached_the_client("legacy client", &tally);
        assert_healthy("legacy client", &tally, &session, &conn);

        // The host side of the same negative, read *live*: the sender thread is
        // spawned from the negotiated bit, so for a legacy client it never
        // starts at all — which is why nothing downstream of it ever has to
        // filter anything. Read here rather than after the session because
        // `run_session` forces this field back to `Disabled` on its way out, so
        // a post-session read would pass no matter what had happened.
        assert_eq!(
            h.status.lock().audio_status,
            AudioStatus::Disabled,
            "the audio sender thread ran for a client that never asked for audio"
        );

        session
            .close_graceful("audio interop test finished", Duration::from_secs(3))
            .await;
        endpoint.wait_idle().await;
    });
    // Both of these are session *totals*, which `run_session` publishes rather
    // than clears, so they are still meaningful once the client has gone.
    let status = h.status.lock().clone();
    assert!(
        status.frames_sent > 0,
        "the host's own counters say it never sent a frame to the legacy client"
    );
    assert_eq!(
        status.audio_packets_sent, 0,
        "the host's own counters say it sent audio to a legacy client"
    );
    h.finish();
}

// ---------------------------------------------------------------------------
// 2. New client, host with the feature off (the shipped default)
// ---------------------------------------------------------------------------

/// Rollout step 1: the new binary, deployed with `system_audio_enabled` at its
/// default `false`, talking to a client that *does* set the bit.
///
/// The property under test is not "audio is off" but something stronger: this
/// build is **byte-identical on the wire** to the one already deployed. The
/// host's `Hello` carries no bits, the media path carries nothing but video, and
/// the session is indistinguishable from a pre-feature one. That is what makes
/// shipping the code and enabling it later two separately reversible steps — and
/// it is the step this repository's rollout notes already record as taken.
///
/// The source is still the test tone, so that the *only* thing standing between
/// a live audio stream and the wire is the operator's flag.
#[test]
fn new_client_and_disabled_host_are_wire_identical_to_the_old_build() {
    let h = Harness::start(DISABLED_PORT, Audio::off());
    h.block_on(async {
        let Handshake {
            endpoint,
            conn,
            streams,
            host_features,
        } = connect_and_pair(h.bind, &h.code, SYSTEM_AUDIO)
            .await
            .expect("new client handshake");

        // The client asked; the host, unconfigured, offers nothing. An operator
        // turning the feature off must be indistinguishable from a host that
        // never had it.
        assert_eq!(
            host_features & SYSTEM_AUDIO,
            0,
            "a host with system_audio_enabled=false accepted the audio bit"
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
        let tally = spawn_pump(rx);
        spawn_sniffer(conn.clone(), tally.clone());
        session.send_control(start_stream()).expect("StartStream");

        tokio::time::sleep(OBSERVE).await;

        report("audio disabled", &tally, &session);
        assert_no_audio_reached_the_client("audio disabled", &tally);
        assert_healthy("audio disabled", &tally, &session, &conn);

        // Live, for the reason given in scenario 1: after the session this
        // field reads `Disabled` unconditionally.
        assert_eq!(
            h.status.lock().audio_status,
            AudioStatus::Disabled,
            "the audio sender thread ran on a host with system_audio_enabled=false"
        );

        session
            .close_graceful("audio interop test finished", Duration::from_secs(3))
            .await;
        endpoint.wait_idle().await;
    });
    assert_eq!(
        h.status.lock().audio_packets_sent,
        0,
        "the host's own counters say it sent audio with system_audio_enabled=false"
    );
    h.finish();
}

// ---------------------------------------------------------------------------
// 3. Both ends enabled
// ---------------------------------------------------------------------------

/// Rollout step 2: with the bit mutual, the host really does send audio and
/// really does speak the format.
///
/// # Why the test tone
///
/// `system_audio_source: TestTone` is what makes this deterministic and
/// hardware-free. Loopback capture would make the assertions depend on the
/// machine having a playback endpoint *and* on something audible playing
/// through it at the moment the test runs — a silent desktop is deliberately
/// suppressed by the sender, so "no audio arrived" would be correct behaviour
/// and a failing test at the same time. The tone is a fixed 440 Hz at 48 kHz
/// stereo, produced without touching a device, which is precisely why the
/// product ships it.
///
/// # What is asserted, and what is deliberately not
///
/// Counts, decodability and ordering: at least [`MIN_AUDIO_PACKETS`] datagrams
/// classify as audio, every one of them decodes, and `seq` advances in
/// wrapping-serial order. Never a rate — a machine busy encoding 1080p is
/// allowed to deliver audio unevenly, and a protocol test that fails when the
/// box is busy is worse than no test.
///
/// The last assertion is the one the feature's design rests on: **audio must
/// not cost video**. Audio and video compete for one `send_datagram` buffer,
/// and when it fills quinn evicts the *oldest* queued datagrams — so an audio
/// packet sent without the reserve `net::audio::has_room` holds back does not
/// drop itself, it shreds fragments of the frame already in flight. That
/// failure is invisible as bandwidth and unmistakable as an incomplete frame,
/// so it is asserted where it would land: the reassembler must abandon nothing
/// while audio is flowing.
///
/// # Making that last assertion mean what it says
///
/// "The reassembler abandoned a frame" only implicates *audio* if audio is the
/// only thing that could have caused it, and two other things can:
///
/// * the host refusing to fragment a frame at all, which is a loss that never
///   reaches the datagram path — configured out of existence by
///   [`HARNESS_KBPS`], and then asserted against directly, because a confound
///   that is merely unlikely is a confound that eventually returns as a
///   mysterious audio failure;
/// * the stream's own startup, where the encoder, the bitrate adaptor and
///   QUIC's path-MTU discovery are all still converging. So the window does not
///   open when audio does: [`settle_video`] first waits for the picture to go
///   quiet, and *fails* rather than proceeding if it never does. A stream that
///   cannot settle while audio flows is precisely the regression this test is
///   for, and it is reported as that rather than skipped past.
#[test]
fn both_ends_enabled_deliver_decodable_audio() {
    let h = Harness::start(ENABLED_PORT, Audio::tone());
    h.block_on(async {
        let Handshake {
            endpoint,
            conn,
            streams,
            host_features,
        } = connect_and_pair(h.bind, &h.code, SYSTEM_AUDIO)
            .await
            .expect("new client handshake");

        assert_eq!(
            host_features & SYSTEM_AUDIO,
            SYSTEM_AUDIO,
            "both ends asked for audio but the host did not echo the bit"
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
        let started = Instant::now();

        assert!(
            poll_until(AUDIO_TIMEOUT, || tally.audio() > 0).await,
            "no audio datagram arrived within {AUDIO_TIMEOUT:?} of a session that \
             negotiated the bit ({} datagrams seen, all video)",
            tally.datagrams()
        );
        println!(
            "first audio  : after {:.2} s",
            started.elapsed().as_secs_f32()
        );

        // Audio is already flowing; now let the *picture* reach steady state
        // before anything is measured against it. Everything below is therefore
        // "what happened while audio was on the wire and video had settled",
        // which is the only span in which an abandoned frame can be read as
        // audio's doing.
        let settled = settle_video(VIDEO_SETTLE_TIMEOUT, VIDEO_QUIET, &tally)
            .await
            .unwrap_or_else(|| {
                panic!(
                    "the video stream never went {VIDEO_QUIET:?} without abandoning a \
                     frame, in {VIDEO_SETTLE_TIMEOUT:?} of audio flowing. Either audio \
                     is shredding video — which is this test's subject — or the host is \
                     emitting frames the fragmenter cannot carry, which \
                     `frames_unfragmentable` below will say. reassembly {:?}, host \
                     unfragmentable {}",
                    tally.reassembly(),
                    h.status.lock().frames_unfragmentable
                )
            });
        println!(
            "video settled: after {:.2} s, {settled:?}",
            started.elapsed().as_secs_f32()
        );

        // Every baseline is taken one host status interval *after* the settle,
        // not at it. `frames_unfragmentable` is a lifetime counter the host
        // republishes only on its 1 s tick, so a baseline read the instant the
        // settle finished would not yet include the settle's own last tick, and
        // that difference would be charged to audio. The reassembler's
        // baselines are re-taken at the same moment so that every delta below
        // bounds exactly the same span.
        tokio::time::sleep(STATUS_LAG).await;
        let unfragmentable_at_start = h.status.lock().frames_unfragmentable;
        let audio_at_start = tally.audio();
        let video_at_start = tally.reassembly();

        tokio::time::sleep(AUDIO_WINDOW).await;
        let video_after = tally.reassembly();

        report("audio enabled", &tally, &session);

        // --- the audio itself -------------------------------------------
        let in_window = tally.audio() - audio_at_start;
        assert!(
            in_window >= MIN_AUDIO_PACKETS,
            "only {in_window} audio datagrams arrived in {AUDIO_WINDOW:?}, wanted \
             at least {MIN_AUDIO_PACKETS}"
        );
        assert_eq!(
            tally.audio_decode_errors(),
            0,
            "{} audio datagram(s) did not decode; first: {:?}",
            tally.audio_decode_errors(),
            tally.first_complaint()
        );
        assert_eq!(
            tally.seq_regressions(),
            0,
            "audio `seq` went backwards {} time(s) in wrapping-serial order; \
             first: {:?}",
            tally.seq_regressions(),
            tally.first_complaint()
        );
        assert_eq!(
            tally.wrong_format(),
            0,
            "{} audio datagram(s) carried a format other than the tone's 48 kHz \
             stereo, which `Stream::open` fixes for this source",
            tally.wrong_format()
        );

        // --- and the picture it must not have cost ----------------------
        // First the loss that would NOT be audio's: a frame the host could not
        // fragment never reaches the datagram path at all, so it cannot have
        // been shredded by an audio packet — but it lands in the reassembler's
        // counters looking exactly like one that was. Checked before them so
        // that when this fires the failure names itself instead of libelling
        // audio. `HARNESS_KBPS` is what keeps it at zero; this is the tripwire
        // that says so out loud if that ever stops being true.
        //
        // Read after a status interval because these are the host's lifetime
        // counters, republished on its 1 s tick — sampling immediately would
        // read a figure that predates the end of the window.
        tokio::time::sleep(STATUS_LAG).await;
        let unfragmentable_after = h.status.lock().frames_unfragmentable;
        assert_eq!(
            unfragmentable_after,
            unfragmentable_at_start,
            "the host refused to fragment {} frame(s) during the audio window, so \
             the reassembler's losses below are the fragmenter's and not audio's. \
             A frame over {FRAGMENTER_FRAME_LIMIT_BYTES} bytes cannot be carried at \
             the QUIC minimum MTU; the harness pins the encoder to \
             {HARNESS_KBPS} kbps and turns the constant-quality refinement pass off \
             precisely so this stays zero. If this machine's display has grown, \
             lower HARNESS_KBPS — do not relax the assertions below",
            unfragmentable_after - unfragmentable_at_start
        );

        assert!(
            video_after.frames_completed > video_at_start.frames_completed,
            "video stopped while audio flowed: {} frames completed before, {} after",
            video_at_start.frames_completed,
            video_after.frames_completed
        );
        assert_eq!(
            video_after.frames_dropped_incomplete, video_at_start.frames_dropped_incomplete,
            "a video frame was abandoned incomplete while audio flowed — the \
             signature of audio spending send-buffer room the video pump had \
             already counted on ({video_at_start:?} -> {video_after:?})"
        );
        assert_eq!(
            video_after.frames_dropped_stale, video_at_start.frames_dropped_stale,
            "a video frame was left behind incomplete while audio flowed \
             ({video_at_start:?} -> {video_after:?})"
        );
        assert_eq!(
            video_after.fragments_rejected, video_at_start.fragments_rejected,
            "the reassembler refused a datagram while audio flowed, so something \
             that was not a video fragment reached it ({video_at_start:?} -> \
             {video_after:?})"
        );

        assert_healthy("audio enabled", &tally, &session, &conn);

        session
            .close_graceful("audio interop test finished", Duration::from_secs(3))
            .await;
        endpoint.wait_idle().await;
    });
    let status = h.status.lock().clone();
    println!(
        "host audio   : {:?}, {} packets, {} KiB, {} backpressured, {} suppressed",
        status.audio_status,
        status.audio_packets_sent,
        status.audio_bytes_sent / 1024,
        status.audio_backpressured,
        status.audio_silent_suppressed
    );
    assert!(
        status.audio_packets_sent > 0,
        "the client received audio the host's own counters say it never sent"
    );
    h.finish();
}

// ---------------------------------------------------------------------------
// 4. The audio path may degrade the sound, never the session
// ---------------------------------------------------------------------------

/// An audio path that cannot produce anything must cost nothing but sound.
///
/// # The two halves
///
/// * **Decode is total.** The exact shared function the client feeds untrusted
///   datagram bytes into ([`decode_packet`]) returns `Err` on every malformed
///   shape rather than panicking, and the classifier in front of it
///   ([`is_audio_datagram`]) is total over a slice of *any* length. This matters
///   more here than on the tile stream: datagrams are unauthenticated at the
///   application layer in the sense that anyone on the path can inject one, and
///   this decoder runs inside the client's single datagram task — a panic there
///   takes video down with it, silently, because nothing joins that task.
/// * **The host survives its own audio path failing.** The live half runs the
///   host with `AudioSource::Loopback`, the one source that can fail, and
///   asserts the session is untouched: video still arriving, the host's control
///   stream still ticking, the connection still open.
///
/// # What "broken" means here, honestly
///
/// The failure is environmental rather than injected, because the implementation
/// offers no lever to inject one (see the note on [`Audio::loopback`]). Both
/// branches it can take are the failure this test is about, and both are covered
/// by the same assertions:
///
/// * no usable playback endpoint (a session-0 runner, a machine with no audio
///   device, an endpoint whose mix format `classify_mix_format` refuses):
///   `Stream::open` fails, the sender publishes [`AudioStatus::NoEndpoint`] and
///   retries with backoff for the life of the session;
/// * a working but idle endpoint: every captured packet is silent, so every
///   access unit is deliberately suppressed and nothing reaches the wire.
///
/// From the client's chair those are the same event — audio that produces
/// nothing — and in neither case may the session notice. What is asserted about
/// the sender is the part that is invariant across both: it is still running and
/// still reporting a live status, rather than having taken anything down with
/// it.
#[test]
fn a_broken_audio_path_degrades_the_sound_not_the_session() {
    // Pure, no I/O: the decode seam the client hands hostile bytes to.
    assert_malformed_audio_bytes_are_refused();

    let h = Harness::start(DEGRADE_PORT, Audio::loopback());
    h.block_on(async {
        let Handshake {
            endpoint,
            conn,
            streams,
            host_features,
        } = connect_and_pair(h.bind, &h.code, SYSTEM_AUDIO)
            .await
            .expect("new client handshake");
        // The feature is fully negotiated: only the *source* is in trouble.
        assert_eq!(host_features & SYSTEM_AUDIO, SYSTEM_AUDIO);

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

        // Long enough for the capture open to fail (or succeed and find
        // silence), for the backoff to retry at least once, and for several
        // host status ticks either way.
        tokio::time::sleep(OBSERVE).await;

        let frames_at_mark = tally.frames();
        let stats_at_mark = tally.host_stats();
        tokio::time::sleep(Duration::from_secs(3)).await;

        report("audio degraded", &tally, &session);
        assert!(
            tally.frames() > frames_at_mark,
            "video stopped while the audio path was failing: {} frames before, \
             {} after",
            frames_at_mark,
            tally.frames()
        );
        assert!(
            tally.host_stats() > stats_at_mark,
            "the host's control stream went quiet while the audio path was failing"
        );
        assert!(
            conn.close_reason().is_none(),
            "the connection closed because of the audio path: {:?}",
            conn.close_reason()
        );
        assert_healthy("audio degraded", &tally, &session, &conn);

        // Whatever the audio path managed to emit — nothing, silence
        // suppression, or a real stream if the machine happened to be playing
        // something — every datagram on the media path is still well formed and
        // still routed to the right parser.
        assert_eq!(
            tally.audio_decode_errors() + tally.video_decode_errors(),
            0,
            "a malformed datagram reached the client; first: {:?}",
            tally.first_complaint()
        );

        // The sender is still alive and still reporting, in whichever of the two
        // branches this machine took. `Disabled` is the one status it may not
        // have: the thread only publishes that on its way out.
        let status = poll_for_audio_status(&h.status, Duration::from_secs(10)).await;
        println!("host audio   : {status:?}");
        assert_ne!(
            status,
            AudioStatus::Disabled,
            "the audio sender thread exited during a live session that negotiated \
             audio; it is supposed to warn, back off and retry, not give up"
        );

        session
            .close_graceful("audio interop test finished", Duration::from_secs(3))
            .await;
        endpoint.wait_idle().await;
    });
    h.finish();
}

/// The client's audio decode seam, fed the things a corrupt or hostile datagram
/// would put on it. Every case must be an `Err`, and none may panic — a panic
/// here would take the client's whole datagram task down, and with it video.
///
/// The cases are the header's own rules, one at a time, each failing for a
/// stated structural reason rather than by being random bytes.
fn assert_malformed_audio_bytes_are_refused() {
    let payload = [0xA5u8; 64];
    let good = AudioPacket {
        seq: 7,
        capture_ms: 1_234,
        discontinuity: false,
        format: AudioFormat::Stereo48k,
        payload: &payload,
    };
    let bytes = encode_packet(&good).expect("encode");
    // Sanity: the well-formed packet decodes, so every failure below is really
    // about the corruption and not about the fixture.
    assert_eq!(
        decode_packet(&bytes).expect("the fixture must decode"),
        good,
        "the fixture does not round-trip"
    );

    // --- truncation: every length that cannot hold the fixed header ------
    for len in 0..AUDIO_HEADER_LEN {
        let mut short = vec![0u8; len];
        if len > AUDIO_FLAGS_OFFSET {
            short[AUDIO_FLAGS_OFFSET] = FLAG_AUDIO;
        }
        assert!(
            decode_packet(&short).is_err(),
            "a {len}-byte datagram decoded as an audio packet"
        );
    }
    // Header complete, payload absent: long enough to parse, still not a packet.
    // There is no fragmentation on this path, so "one access unit" means at
    // least one byte of one.
    let mut header_only = bytes.clone();
    header_only.truncate(AUDIO_HEADER_LEN);
    assert!(
        decode_packet(&header_only).is_err(),
        "a header with no access unit behind it decoded"
    );

    // --- an over-long payload -------------------------------------------
    // Built by hand: `encode_packet` refuses to produce one, which is itself the
    // property that keeps a host bug from becoming a one-way audio outage.
    let mut oversized = bytes.clone();
    oversized.resize(AUDIO_HEADER_LEN + MAX_AUDIO_PAYLOAD + 1, 0);
    assert!(
        decode_packet(&oversized).is_err(),
        "a payload one byte over MAX_AUDIO_PAYLOAD decoded"
    );
    // One byte less is the largest legal packet, so the refusal above is the
    // length and not something else about the fixture.
    oversized.truncate(AUDIO_HEADER_LEN + MAX_AUDIO_PAYLOAD);
    assert!(
        decode_packet(&oversized).is_ok(),
        "the largest legal payload was refused"
    );

    // --- FLAG_AUDIO clear ------------------------------------------------
    // A datagram that reached the audio parser without the marker was
    // misrouted; parsing it anyway would turn a routing bug into silently wrong
    // audio.
    let mut unmarked = bytes.clone();
    unmarked[AUDIO_FLAGS_OFFSET] &= !FLAG_AUDIO;
    assert!(
        decode_packet(&unmarked).is_err(),
        "a datagram without FLAG_AUDIO decoded as audio"
    );

    // --- reserved flag bits ----------------------------------------------
    // Rejected so they stay spendable later: a receiver that ignored them would
    // already have decided they mean "nothing".
    for bit in 0..8u8 {
        let reserved = 1u8 << bit;
        if reserved & AUDIO_FLAGS_MASK != 0 {
            continue;
        }
        let mut with_reserved = bytes.clone();
        with_reserved[AUDIO_FLAGS_OFFSET] |= reserved;
        assert!(
            decode_packet(&with_reserved).is_err(),
            "reserved flag bit {reserved:#x} was accepted, and is now spent"
        );
    }

    // --- unknown format codes --------------------------------------------
    // Dropped, never guessed at: guessing means playing noise at the wrong rate
    // instead of losing one 20 ms frame.
    for code in [4u8, 17, 255] {
        let mut wrong_format = bytes.clone();
        wrong_format[AUDIO_FORMAT_OFFSET] = code;
        assert!(
            decode_packet(&wrong_format).is_err(),
            "unassigned format code {code} decoded"
        );
    }

    // --- the classifier is total -----------------------------------------
    // QUIC permits a zero-length datagram and anyone on the path can inject
    // one, so this must be a `false`, not an index panic.
    assert!(!is_audio_datagram(&[]), "an empty datagram classified");
    assert!(
        !is_audio_datagram(&[0xFF; 8]),
        "8 bytes is too short to hold the flags byte at all"
    );
    // Nine bytes: the flags byte exists, so this classifies as audio even
    // though it is far too short to *be* a packet. Classification and
    // validation are separate on purpose — the alternative is a malformed audio
    // packet being retried as a video fragment.
    let mut nine = [0u8; 9];
    nine[AUDIO_FLAGS_OFFSET] = FLAG_AUDIO;
    assert!(
        is_audio_datagram(&nine),
        "9 bytes is enough to classify, never enough to decode"
    );
    assert!(
        decode_packet(&nine).is_err(),
        "classification must not imply validity"
    );
}

// ---------------------------------------------------------------------------
// Harness: a real host on loopback, paired and ready
// ---------------------------------------------------------------------------

/// The host's audio configuration for one scenario.
#[derive(Debug, Clone, Copy)]
struct Audio {
    enabled: bool,
    source: AudioSource,
}

impl Audio {
    /// The shipped default: the feature off. The source is still the tone, so
    /// that the operator's flag is the *only* thing keeping audio off the wire.
    const fn off() -> Self {
        Self {
            enabled: false,
            source: AudioSource::TestTone,
        }
    }

    /// On, with the synthetic 440 Hz source: deterministic, needs no audio
    /// hardware, and guaranteed to have something to send. See
    /// [`both_ends_enabled_deliver_decodable_audio`] on why that matters in the
    /// negative scenarios too.
    const fn tone() -> Self {
        Self {
            enabled: true,
            source: AudioSource::TestTone,
        }
    }

    /// On, pointed at the real WASAPI render endpoint.
    ///
    /// This is the closest the implementation gets to a broken audio path that a
    /// black-box test can ask for. There is no fault injection anywhere in the
    /// audio sender, and nothing else in the config surface can break it:
    /// `system_audio_kbps` is deliberately *tolerant* (`choose_output_type`
    /// falls back to the highest offered rate rather than failing, so no value
    /// refuses), and `TestTone` cannot fail by construction. `Loopback` is the
    /// one source whose `Stream::open` has a real failure path.
    const fn loopback() -> Self {
        Self {
            enabled: true,
            source: AudioSource::Loopback,
        }
    }
}

/// A running host plus the two runtimes and the pairing code needed to talk to
/// it.
///
/// # Why the teardown is a `Drop` and not only [`Harness::finish`]
///
/// Every scenario here boots a real Desktop Duplication session, and
/// `testsupport::CaptureLock` exists to guarantee only one of those is alive at
/// a time. But a lock is only as good as the moment it is released, and
/// `CaptureLock` releases on drop — so with the teardown living only in
/// `finish()`, a *failing* scenario unwinds straight past it and hands the lock
/// to the next scenario while its own `dd-media` thread is still holding
/// `IDXGIOutputDuplication`. The next `DuplicateOutput` then fails with
/// `E_INVALIDARG` (0x80070057), which is why it does not read as a lock problem:
/// a contended output reports a bad *parameter*, not access denied. The host
/// retries on a 200 ms backoff for the rest of that scenario, no frame ever
/// arrives, and a test that was about `Hello` bits fails claiming no datagrams
/// were seen. One genuine failure becomes three.
///
/// Putting the teardown in `Drop` fixes the ordering by construction: Rust runs
/// `Drop::drop` before it drops the struct's fields, and `_capture` is a field,
/// so the host is stopped and its media thread given time to let go of DXGI
/// before the lock is handed on — whether the test passed or panicked.
/// [`Harness::finish`] is kept because it makes the end of a scenario readable
/// and puts the shutdown before the test's final assertions; it is idempotent,
/// so the `Drop` that follows it does nothing.
struct Harness {
    host: NetHandle,
    /// `Option` only so [`Harness::teardown`] can take them by value out of
    /// `&mut self` — `Runtime::shutdown_timeout` consumes the runtime. Both are
    /// `Some` for the whole life of a scenario.
    runtime: Option<tokio::runtime::Runtime>,
    client_rt: Option<tokio::runtime::Runtime>,
    bind: SocketAddr,
    code: String,
    status: Arc<Mutex<StatusSnapshot>>,
    /// Serializes with every other real-capture test on this machine. Declared
    /// last on purpose: fields drop in declaration order and after
    /// `Drop::drop`, so this is released once the host is down.
    _capture: directdesk_host::testsupport::CaptureLock,
}

impl Harness {
    fn start(port: u16, audio: Audio) -> Harness {
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
            Arc::new(HostIdentity::generate("audio-interop-host").expect("generate host identity"));
        let status = Arc::new(Mutex::new(StatusSnapshot::default()));
        let pairing = Arc::new(PairingSlot::new());

        // Straight through `HostConfig`, not by poking `NetConfig`: the config
        // knob reaching the wire is part of what is being tested.
        let host_cfg = HostConfig {
            udp_port: port,
            target_fps: 60,
            // --- audio: the subject ------------------------------------------
            system_audio_enabled: audio.enabled,
            system_audio_source: audio.source,
            // Off, and load-bearing for scenario 3: the redundant re-send puts
            // the *previous* packet on the wire behind the current one, so
            // received `seq` would legitimately step backwards and the ordering
            // assertion would be testing the wrong thing.
            system_audio_redundancy: false,
            // --- video: the two knobs that keep audio the *only* subject -----
            // Both are pinned rather than defaulted, and the long "why" is on
            // [`HARNESS_KBPS`]. In one line: at this repository's display sizes
            // the stock encoder emits keyframes the fragmenter refuses, and a
            // refused keyframe is a lost frame — which would defeat scenario
            // 3's "audio does not cost video" assertion before audio was ever
            // involved.
            bitrate_kbps: HARNESS_KBPS,
            bitrate_cap_kbps: Some(HARNESS_KBPS),
            static_refine_quality: 0,
            ..HostConfig::default()
        };
        let mut net_cfg = NetConfig::from_host_config(&host_cfg);
        net_cfg.bind = bind;
        assert_eq!(
            net_cfg.system_audio_enabled, audio.enabled,
            "the config knob did not reach the listener"
        );
        assert_eq!(
            net_cfg.system_audio_source, audio.source,
            "the source knob did not reach the listener"
        );
        assert!(
            !net_cfg.system_audio_redundancy,
            "redundancy must stay off; see the comment above"
        );
        assert!(
            !net_cfg.pipeline.lossless_tiles_enabled,
            "tiles must stay at their default off here: audio is the only \
             variable in this file, and a tile stream would put a second \
             feature's traffic on the connection"
        );
        // The same rule, applied to the two video knobs. Asserted rather than
        // trusted because each one travels through a different path into the
        // running host — `pipeline` for the encoder's starting rate, the
        // listener's own field for the cap the adaptor is clamped to — and a
        // knob that quietly stopped arriving would put the confound described
        // on [`HARNESS_KBPS`] straight back into scenario 3.
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
            "host bound   : {bound} (audio {} / {:?})",
            audio.enabled, audio.source
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
    ///
    /// Exists only because the runtime became an `Option`; it is the same
    /// `block_on` the scenarios always used.
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
        // The runtimes are the idempotence marker — once they are gone this has
        // already run.
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
            // Reported rather than asserted: this runs during unwinding, where
            // a second panic aborts the process and destroys the first one's
            // message — which is the message that says why the run failed.
            println!("host          : did not report stopped within 10 s");
        }

        // Client first: its tasks hold the connection whose close the host's
        // session loop is waiting on.
        if let Some(client_rt) = self.client_rt.take() {
            client_rt.shutdown_timeout(Duration::from_secs(5));
        }
        // Then the host's, which is what actually drops the per-session tokio
        // tasks. `net::serve`'s session loop *aborts* four of them rather than
        // awaiting them, and each holds an `Arc<HostSession>`; the media thread
        // is joined by the last of those `Arc`s to drop, so `is_stopped()`
        // above is a statement about the accept loop, not about DXGI.
        runtime.shutdown_timeout(Duration::from_secs(5));

        // And the last gap: `HostSession`'s drop joins `dd-media`, but the
        // `IDXGIOutputDuplication` that thread owns is released by COM as the
        // thread's stack unwinds, which `shutdown_timeout` does not wait for.
        // There is nothing observable to poll from here — the pipeline is not
        // exposed and the status snapshot describes the listener — so this is
        // a bounded, documented settle rather than a pretend condition. It is
        // the difference between "the next scenario starts clean" and "the next
        // scenario spends its whole window retrying DuplicateOutput".
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
/// The ordering the whole feature rests on is exercised here as-is: the client
/// writes its `Hello` blind, the host reads it before replying, and the client
/// reads the reply before doing anything else. Both ends know the intersection
/// before either acts on it, which is what makes "the host sends its first audio
/// datagram only when the bit is mutual" implementable at all.
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
        agent: "audio-interop-test-client".to_string(),
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

    let client_id = ClientIdentity::generate("audio-interop-client")?;
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

/// What the client observed, accumulated by background tasks so a test can ask
/// at any moment — including "did this keep growing while the audio path was
/// failing?".
#[derive(Default)]
struct Tally {
    // ---- control plane, from the session driver -------------------------
    /// `ControlMsg::Stats` from the host: its status loop ticks once a second,
    /// so these are the host's own proof of life on the control stream.
    host_stats: AtomicU64,
    closed: AtomicBool,
    reason: Mutex<Option<String>>,

    // ---- datagram plane, from the sniffer -------------------------------
    datagrams: AtomicU64,
    audio: AtomicU64,
    video: AtomicU64,
    /// Audio datagrams that classified but would not parse.
    audio_decode_errors: AtomicU64,
    /// Non-audio datagrams that would not parse as a video fragment.
    video_decode_errors: AtomicU64,
    /// Audio datagrams whose `seq` was not strictly newer than its predecessor
    /// in wrapping-serial order.
    seq_regressions: AtomicU64,
    /// Audio datagrams carrying a format other than the one the source is fixed
    /// at.
    wrong_format: AtomicU64,
    /// Frames the sniffer's reassembler handed out.
    frames: AtomicU64,
    keyframes: AtomicU64,
    /// The first thing the sniffer objected to, verbatim, so a failure names the
    /// datagram rather than only counting it.
    complaint: Mutex<Option<String>>,
    /// The reassembler's cumulative counters, republished after every datagram.
    reassembly: Mutex<ReassemblyStats>,
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
    fn datagrams(&self) -> u64 {
        self.datagrams.load(Ordering::Relaxed)
    }
    fn audio(&self) -> u64 {
        self.audio.load(Ordering::Relaxed)
    }
    fn video(&self) -> u64 {
        self.video.load(Ordering::Relaxed)
    }
    fn audio_decode_errors(&self) -> u64 {
        self.audio_decode_errors.load(Ordering::Relaxed)
    }
    fn video_decode_errors(&self) -> u64 {
        self.video_decode_errors.load(Ordering::Relaxed)
    }
    fn seq_regressions(&self) -> u64 {
        self.seq_regressions.load(Ordering::Relaxed)
    }
    fn wrong_format(&self) -> u64 {
        self.wrong_format.load(Ordering::Relaxed)
    }
    fn reassembly(&self) -> ReassemblyStats {
        *self.reassembly.lock()
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

/// Drain the session's control plane into a [`Tally`] until the session ends.
///
/// A background task rather than an inline loop: every test needs to be doing
/// something else while the session runs, and leaving the receivers unread would
/// let their queues fill and turn a protocol assertion into a plumbing artefact.
///
/// `rx.video` and `rx.audio` are dropped unread on purpose. Both are closed from
/// the start by [`driver_config`], and the datagram traffic they would have
/// carried is [`spawn_sniffer`]'s subject instead.
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
///   `RequestKeyframe`. An observer that asked the host to re-encode would be
///   changing the traffic it is measuring.
///
/// The reassembler runs with `latest_wins` off so that every completed frame is
/// counted in completion order; the production policy of skipping stale frames
/// is right for a decoder and wrong for a census.
fn spawn_sniffer(conn: quinn::Connection, tally: Arc<Tally>) {
    tokio::spawn(async move {
        let started = Instant::now();
        let mut reassembler = Reassembler::new(ReassemblyConfig {
            latest_wins: false,
            ..ReassemblyConfig::default()
        });
        let mut last_seq: Option<u32> = None;
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
            // slice of entirely unknown provenance.
            if is_audio_datagram(&datagram) {
                tally.audio.fetch_add(1, Ordering::Relaxed);
                match decode_packet(&datagram) {
                    Ok(packet) => {
                        // Gaps are legal — this is the unreliable path and a
                        // lost packet is a click. Going *backwards* is not:
                        // wrapping-serial order is what the receiver's reorder
                        // window and concealment both rest on.
                        if let Some(prev) = last_seq {
                            if !is_newer(packet.seq, prev) {
                                tally.seq_regressions.fetch_add(1, Ordering::Relaxed);
                                tally.complain(format!(
                                    "audio seq {} is not newer than {prev}",
                                    packet.seq
                                ));
                            }
                        }
                        last_seq = Some(packet.seq);
                        if packet.format != AudioFormat::Stereo48k {
                            tally.wrong_format.fetch_add(1, Ordering::Relaxed);
                            tally.complain(format!(
                                "audio packet in {:?}, not the source's 48 kHz stereo",
                                packet.format
                            ));
                        }
                    }
                    Err(e) => {
                        tally.audio_decode_errors.fetch_add(1, Ordering::Relaxed);
                        tally.complain(format!(
                            "audio datagram of {} bytes did not decode: {e}",
                            datagram.len()
                        ));
                    }
                }
                continue;
            }

            tally.video.fetch_add(1, Ordering::Relaxed);
            // Asserted separately from the reassembler's own decode: this is the
            // claim the compatibility scenarios make about *every* datagram on
            // the wire — that it is a video fragment and nothing else.
            if let Err(e) = FragHeader::decode(&datagram) {
                tally.video_decode_errors.fetch_add(1, Ordering::Relaxed);
                tally.complain(format!(
                    "datagram of {} bytes is neither audio nor a video fragment: {e}",
                    datagram.len()
                ));
            }

            let now_ms = started.elapsed().as_millis() as u64;
            if let Err(e) = reassembler.push(&datagram, now_ms) {
                tally.complain(format!("reassembler refused a datagram: {e}"));
            }
            while let Some(frame) = reassembler.pop_frame() {
                tally.frames.fetch_add(1, Ordering::Relaxed);
                if frame.keyframe {
                    tally.keyframes.fetch_add(1, Ordering::Relaxed);
                }
            }
            *tally.reassembly.lock() = reassembler.stats();
        }
    });
}

fn report(what: &str, tally: &Tally, session: &QuicSession) {
    let stats = session.stats();
    println!(
        "{what:<15}: {} datagrams ({} video, {} audio), {} frames ({} keyframes), \
         {} host Stats, rtt {:.2} ms",
        tally.datagrams(),
        tally.video(),
        tally.audio(),
        tally.frames(),
        tally.keyframes(),
        tally.host_stats(),
        stats.rtt_ms
    );
    println!("{what:<15}: reassembly {:?}", tally.reassembly());
}

/// The negative both compatibility scenarios rest on: the media path carried
/// video and only video.
fn assert_no_audio_reached_the_client(what: &str, tally: &Tally) {
    // Without this the two assertions below are vacuous: a connection that
    // delivered nothing at all also delivered no audio.
    assert!(
        tally.datagrams() > 0,
        "{what}: no datagrams arrived at all, so 'none of them was audio' proves \
         nothing"
    );
    assert_eq!(
        tally.audio(),
        0,
        "{what}: {} of {} datagrams classified as audio at a peer that never \
         negotiated it — on this path that means they were handed to a video \
         reassembler. First: {:?}",
        tally.audio(),
        tally.datagrams(),
        tally.first_complaint()
    );
    assert_eq!(
        tally.video_decode_errors(),
        0,
        "{what}: {} datagram(s) did not decode as a video fragment; first: {:?}",
        tally.video_decode_errors(),
        tally.first_complaint()
    );
}

/// The properties every scenario in this file expects of a healthy session.
///
/// Note what is deliberately *not* here: any assertion about frame rate or
/// packet rate. These tests run behind a real capture and encode pipeline whose
/// throughput depends on the machine's load, and a protocol test that fails when
/// the box is busy is worse than no test at all. "A frame arrived" and "the host
/// is still talking" are what matter.
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

/// Await a condition, polling. Bounded, and never a bare sleep-then-assert: the
/// thing being waited for has a real pipeline starting up behind it.
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

/// The three counters that together mean "the reassembler gave up on
/// something". Kept as one function so the settle below and the assertions in
/// [`both_ends_enabled_deliver_decodable_audio`] can never drift apart about
/// what counts as a loss.
fn abandoned(s: &ReassemblyStats) -> (u64, u64, u64) {
    (
        s.frames_dropped_incomplete,
        s.frames_dropped_stale,
        s.fragments_rejected,
    )
}

/// Wait until the video stream has gone `quiet` without abandoning anything
/// *and* is still completing frames, and return the reassembler's counters at
/// that moment. `None` if it never does inside `limit`.
///
/// # Why a settle and not a sleep
///
/// The first seconds of a session are not steady state: the encoder is emitting
/// its opening IDRs, the bitrate adaptor has not observed a window yet, and
/// QUIC's path-MTU discovery is still raising the datagram size the fragmenter
/// sizes frames against. Sampling a baseline there and comparing it two seconds
/// later measures that convergence, not the thing under test.
///
/// This is deliberately *not* a fixed delay. A fixed delay makes the test
/// slower on a fast machine and still wrong on a slow one, and — worse — it
/// passes silently on a stream that never settles at all. Requiring the stream
/// to *demonstrate* quiet, and failing when it cannot, keeps the property this
/// file cares about intact: the caller treats `None` as a failure, because a
/// video stream that cannot go quiet while audio is flowing is exactly the
/// regression [`both_ends_enabled_deliver_decodable_audio`] exists to catch.
///
/// `frames_completed` must still be advancing at the end, so a stream that went
/// quiet by *stopping* can never be mistaken for one that went quiet by
/// working.
async fn settle_video(limit: Duration, quiet: Duration, tally: &Tally) -> Option<ReassemblyStats> {
    let deadline = Instant::now() + limit;
    let mut last_loss = abandoned(&tally.reassembly());
    let mut quiet_since = Instant::now();
    let mut frames_at_quiet = tally.reassembly().frames_completed;
    loop {
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        let now = tally.reassembly();
        let loss = abandoned(&now);
        if loss != last_loss {
            // Something was abandoned: the clock restarts, and so does the
            // frame mark, so the "still delivering" test below always spans the
            // quiet period rather than the whole wait.
            last_loss = loss;
            quiet_since = Instant::now();
            frames_at_quiet = now.frames_completed;
            continue;
        }
        if quiet_since.elapsed() >= quiet && now.frames_completed > frames_at_quiet {
            return Some(now);
        }
    }
}

/// Wait for the host's status loop to publish a status the audio sender itself
/// set, rather than the `Disabled` a fresh snapshot starts at.
///
/// Polled rather than read once so that a slow WASAPI device open cannot turn a
/// statement about the sender into a race against the first status tick. Returns
/// whatever the snapshot says when the wait ends, so the caller still asserts.
async fn poll_for_audio_status(status: &Mutex<StatusSnapshot>, limit: Duration) -> AudioStatus {
    let _ = poll_until(limit, || {
        status.lock().audio_status != AudioStatus::Disabled
    })
    .await;
    status.lock().audio_status
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
