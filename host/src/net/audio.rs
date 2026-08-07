//! The system-audio send path: one thread that captures what the host is
//! playing, encodes it as AAC-LC, and puts each access unit on the wire as a
//! single QUIC datagram.
//!
//! # Shape
//!
//! One named OS thread (`dd-audio-tx`), spawned by [`super::serve::run_session`]
//! only when [`features::SYSTEM_AUDIO`] is mutual, and **joined** at session end
//! exactly as `dd-video-tx` is. It owns its capture endpoint, its encoder and
//! `send_datagram` outright.
//!
//! What is deliberately absent is the entire apparatus the video path needs:
//! **no queue, no pump task, no channel, no [`HostSession`] involvement.** All
//! of that exists for video because a frame is 20–600 datagrams that have to be
//! paced across a frame interval, and because the encoder runs on a thread that
//! must not block on the network. An audio packet is *one* datagram of a few
//! hundred bytes with nothing to pace and nothing to fragment, produced by a
//! source this thread is already polling. A queue between the two would add a
//! hand-off, a drop policy and a shutdown race, and buy nothing.
//!
//! [`HostSession`]: crate::session::HostSession
//! [`features::SYSTEM_AUDIO`]: directdesk_shared::protocol::features::SYSTEM_AUDIO
//!
//! # Failure policy
//!
//! Read [`super::egress::tile_pump`]'s doc comment and apply it here: **this
//! thread may cost you sound, never the session and never the picture.** Every
//! failure — no playback endpoint, an unsupported mix format, the AAC MFT
//! refusing to start, `AUDCLNT_E_DEVICE_INVALIDATED` when a headset is plugged
//! in, a full datagram buffer — is a `tracing::warn!` followed by either a
//! backed-off retry or a plain return. Nothing here calls `mark_closed`, nothing
//! calls `conn.close()`, and nothing publishes a `ConnectionState`. A host whose
//! remote session died because someone unplugged their speakers would be a far
//! worse product than one that goes quiet.
//!
//! # Three types are called `AudioFormat`
//!
//! [`crate::audio_capture::AudioFormat`] is a **struct** (a validated rate +
//! channel-count pair), [`directdesk_shared::audio::AudioFormat`] is a
//! four-variant **enum** (the wire code), and [`crate::config::AudioSource`] is
//! neither but sits next to both. Everything below uses qualified or aliased
//! paths — `CaptureFormat` and `WireFormat` — and [`wire_format`] is the one
//! place the two are converted.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use quinn::Connection;
use windows::Win32::Media::MediaFoundation::{MFShutdown, MFStartup, MFSTARTUP_LITE, MF_VERSION};

use directdesk_shared::audio::{
    encode_packet, AudioFormat as WireFormat, AudioPacket as WirePacket,
};
use directdesk_shared::{Error, Result};

use crate::audio_capture::{
    AudioFormat as CaptureFormat, AudioSource as CaptureSource, ComMta, LoopbackCapture, TestTone,
};
use crate::audio_encoder::AacEncoder;
use crate::config::AudioSource;

use super::egress::max_frame_wire_size;
use super::{AudioCounters, AudioStatus};

/// How long the thread sleeps when the source has nothing ready.
///
/// Comfortably under the 40 ms engine buffer `audio_capture` asks WASAPI for,
/// so an ordinary (non-realtime) thread that misses a couple of wakeups still
/// loses no samples. See that module's `BUFFER_DURATION_HNS`.
const POLL_MS: u64 = 10;

/// First retry delay after the capture endpoint or the encoder fails to open.
const REBUILD_BACKOFF_MIN: Duration = Duration::from_millis(500);
/// Ceiling on that backoff. A machine with no playback device at all must not
/// spend the session retrying in a tight loop, but a headset that appears two
/// minutes in should still start working without a reconnect.
const REBUILD_BACKOFF_MAX: Duration = Duration::from_secs(15);

/// Longest single sleep while waiting out a backoff, so `stop` is observed
/// promptly and the session's `join` never waits on a sleeping thread.
const STOP_POLL: Duration = Duration::from_millis(50);

/// Samples one AAC-LC access unit covers, per channel.
///
/// Not a guess about the encoder: `audio_encoder::audio_specific_config` writes
/// `frameLengthFlag = 0` into the two bytes the client's decoder is configured
/// from, and its tests pin that bit. 1024 is therefore what this host's own
/// configuration mandates, which is what makes it safe to derive timestamps
/// from an access-unit count.
const AAC_FRAME_SAMPLES: u64 = 1_024;

/// What the sender needs from [`crate::config::HostConfig`]. Copied at session
/// start rather than read live: an operator toggling a knob mid-session has no
/// path to this thread anyway, and a value that cannot change is one fewer
/// thing to reason about across a rebuild.
#[derive(Debug, Clone, Copy)]
pub(super) struct AudioTxConfig {
    pub source: AudioSource,
    pub kbps: u32,
    pub redundancy: bool,
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/// Map the capture side's validated (rate, channels) pair onto the wire enum.
///
/// Looked up **by value** rather than by position, even though
/// [`CaptureFormat::SUPPORTED`] and [`WireFormat::ALL`] happen to be
/// index-for-index identical today (a test below pins that they still are). A
/// positional mapping would keep compiling after either list was reordered, and
/// the failure would not be an error anywhere: the client would configure its
/// output device for the wrong rate or channel count and play the stream at the
/// wrong pitch, or as noise.
///
/// `Err` is unreachable from a `CaptureFormat`, which cannot be constructed
/// outside the supported set — but it is returned rather than asserted so that
/// adding a fifth capture format fails as a logged refusal instead of a panic
/// on the sender thread.
fn wire_format(format: CaptureFormat) -> Result<WireFormat> {
    WireFormat::ALL
        .iter()
        .copied()
        .find(|w| w.sample_rate() == format.sample_rate && w.channels() as u16 == format.channels)
        .ok_or_else(|| {
            Error::Capture(format!(
                "{} has no audio wire format code; system audio cannot be described \
                 to the client and is off for this session",
                format.label()
            ))
        })
}

/// kbps from the config to the bytes-per-second the AAC MFT negotiates in.
///
/// Integer maths throughout: every rate in play is a multiple of 8, so nothing
/// is lost, and `audio_encoder::choose_output_type` rounds whatever comes out
/// of here up to the cheapest type the local encoder actually offers.
fn target_bytes_per_second(kbps: u32) -> u32 {
    kbps.saturating_mul(1_000) / 8
}

/// Capture timestamp of the block of samples starting at absolute frame
/// `frame`, in milliseconds.
///
/// Derived from the running sample count, never from a wall clock, for the same
/// reason `AacEncoder::hns_at` is: the timeline the receiver reconstructs must
/// equal the number of samples that were actually captured, or a scheduling
/// hiccup on this thread turns into drift a listener can hear. Computed from
/// the absolute frame index rather than by accumulating per-packet durations,
/// so the rounding error stays bounded at one millisecond instead of growing
/// with the length of the session — which is what makes 44.1 kHz (where a
/// millisecond is not a whole number of samples) safe.
///
/// Truncating to `u32` is the documented wrap of the wire field, reached after
/// ~49 days of continuous audio.
fn capture_ms(frame: u64, sample_rate: u32) -> u32 {
    (frame.saturating_mul(1_000) / sample_rate.max(1) as u64) as u32
}

/// Capture timestamp of the `n`th access unit of the stream.
///
/// The access-unit index, not the number of samples handed to the encoder: AAC
/// buffers up to one frame internally, so those two differ by a lag that varies
/// with how the capture packets happened to land. What the receiver needs is
/// the presentation time of the audio *inside this packet*, and for a codec
/// with a fixed frame length that is exactly `n * 1024` samples from the start
/// of the stream. Deriving it from the submit that produced the unit instead
/// would stamp two units emitted by one submit with the same timestamp, which
/// is wrong by a whole 21 ms frame.
fn access_unit_ms(index: u64, sample_rate: u32) -> u32 {
    capture_ms(index.saturating_mul(AAC_FRAME_SAMPLES), sample_rate)
}

/// **The most important two lines in this module.**
///
/// Whether an audio datagram of `packet_len` bytes may be offered to a
/// connection with `space` bytes free in its datagram send buffer, while
/// holding `reserve` bytes back for the video pump.
///
/// `send_datagram` never blocks and never refuses. When its buffer is full
/// quinn silently evicts the **oldest** queued datagrams to make room — which
/// means offering more than fits does not drop the packet being offered, it
/// shreds fragments of the frame already in flight, and a frame missing one
/// fragment is as useless as one that never arrived.
///
/// Video's own precheck in [`super::egress::video_pump`] guards that for a
/// single producer, but it is check-then-act: between the check and the last
/// fragment of that frame reaching the wire lie the pacing sleeps, which at
/// 15 fps run to ~133 ms. A second producer sending inside that window spends
/// headroom the pump has already counted, and the eviction lands on the frame
/// being paced out. Without the reserve, turning audio on would intermittently
/// freeze the picture on constrained links, with nothing logged anywhere to say
/// why — the sender would see `Ok(())` from every send.
///
/// So audio yields. `reserve` is one worst-case frame ([`max_frame_wire_size`]),
/// because this thread cannot know how big the frame currently being paced out
/// is, and an under-estimate is exactly the failure being prevented.
fn has_room(space: usize, packet_len: usize, reserve: usize) -> bool {
    space >= packet_len.saturating_add(reserve)
}

/// Is this failure news, or the same one again?
///
/// Records `text` as the most recent failure and reports whether it differs
/// from the previous one. The caller logs a `true` at `warn` and a `false` at
/// `debug`.
///
/// Both failure paths in [`audio_pump`] need this, and for the same reason: a
/// machine with no playback device, or an endpoint that opens and then faults
/// on its first read, retries forever by design. Without the dedup that is one
/// `warn!` every backoff period for the entire length of the session, which
/// buries everything else in the host log. A *changed* message — the user
/// switched devices and now it is an unsupported format rather than no device
/// at all — is the one thing actually worth seeing, and that still gets
/// through.
///
/// One slot rather than one per path on purpose: the interesting repetition is
/// the same failure recurring, and a loop that genuinely alternates between two
/// distinct messages is one where no audio ever flowed, so the backoff has
/// already escalated to [`REBUILD_BACKOFF_MAX`] and the pair costs two lines
/// every 15 seconds.
fn is_new_failure(last: &mut Option<String>, text: &str) -> bool {
    if last.as_deref() == Some(text) {
        false
    } else {
        *last = Some(text.to_string());
        true
    }
}

// ---------------------------------------------------------------------------
// Media Foundation platform guard
// ---------------------------------------------------------------------------

/// RAII `MFStartup`/`MFShutdown` for this thread.
///
/// [`AacEncoder`] needs the MF platform up: `MFCreateSample` and
/// `MFCreateMediaType` live in mfplat and fail without it. Deliberately **not**
/// [`crate::mfinit::MfThread`], for two reasons:
///
/// * that guard starts MF with `MFSTARTUP_FULL`, which exists because some
///   vendor *hardware video* MFTs (NVENC) will not activate under a lite
///   startup. The AAC encoder is the one software MFT on Windows and has no
///   such quirk, so `MFSTARTUP_LITE` — which skips the network media source —
///   is what this thread should ask for;
/// * its `Drop` calls `CoUninitialize` unconditionally at depth 1, including on
///   a thread whose apartment it merely inherited rather than created. The
///   apartment here belongs to [`ComMta`], which tracks that ownership
///   correctly, so this guard must not touch COM at all.
struct MfPlatform;

impl MfPlatform {
    fn start() -> Result<Self> {
        // SAFETY: plain per-thread FFI, balanced by MFShutdown in Drop. COM is
        // already initialized on this thread by the ComMta guard held above it.
        unsafe { MFStartup(MF_VERSION, MFSTARTUP_LITE) }
            .map_err(|e| Error::Other(format!("MFStartup(LITE) for system audio failed: {e}")))?;
        Ok(MfPlatform)
    }
}

impl Drop for MfPlatform {
    fn drop(&mut self) {
        // SAFETY: balanced against the successful MFStartup above. Nothing here
        // touches COM — that is ComMta's job and only ComMta's.
        unsafe {
            let _ = MFShutdown();
        }
    }
}

// ---------------------------------------------------------------------------
// One capture endpoint plus its encoder
// ---------------------------------------------------------------------------

/// A live capture source and the encoder configured for its exact format.
///
/// The two are built and thrown away together on purpose. The encoder's input
/// type, its `AudioSpecificConfig` and the wire format code are all derived
/// from the source's format, so a source whose format changed (the default
/// playback device moved to a Bluetooth headset) cannot be reused with the
/// encoder that was built for the old one.
///
/// # Field order is load-bearing: `encoder` before `source`
///
/// Rust drops struct fields in **declaration** order, so this order means the
/// encoder is torn down first, and it must be. `AacEncoder::drop` is live COM
/// work — three `ProcessMessage` calls on an `IMFTransform`, then the release
/// of that interface — while the last field of a [`LoopbackCapture`] is a
/// [`ComMta`] whose own `Drop` calls `CoUninitialize`. Declared the other way
/// round, the apartment's reference count is decremented while the encoder
/// still has COM calls to make on it.
///
/// Today that ordering happens to be survivable only because [`audio_pump`]
/// holds a [`ComMta`] of its own for the whole thread, pinning the count at one
/// or more — an outer guard that reads as redundant *precisely because* a wrong
/// field order here would be hidden by it. It is not redundant, and this order
/// does not rely on it.
///
/// Construction runs the opposite way (the encoder cannot be built until the
/// source has reported its format), which is why [`Stream::open`] still binds
/// `source` first. Only the declaration order decides teardown.
struct Stream {
    encoder: AacEncoder,
    source: Box<dyn CaptureSource>,
    format: CaptureFormat,
    wire: WireFormat,
}

impl Stream {
    fn open(cfg: &AudioTxConfig) -> Result<Self> {
        let source: Box<dyn CaptureSource> = match cfg.source {
            AudioSource::Loopback => Box::new(LoopbackCapture::new()?),
            AudioSource::TestTone => Box::new(TestTone::new(CaptureFormat::DEFAULT)),
        };
        let format = source.format();
        let wire = wire_format(format)?;
        let encoder = AacEncoder::new(format, target_bytes_per_second(cfg.kbps))?;
        Ok(Self {
            encoder,
            source,
            format,
            wire,
        })
    }
}

/// Everything the inner loop needs that does not change across a rebuild.
struct Tx<'a> {
    conn: &'a Connection,
    counters: &'a AudioCounters,
    /// The secure-desktop signal. See [`audio_pump`] on muting.
    muted: &'a AtomicBool,
    stop: &'a AtomicBool,
    redundancy: bool,
}

// ---------------------------------------------------------------------------
// The thread
// ---------------------------------------------------------------------------

/// Capture, encode and send system audio until the session ends.
///
/// # Thread priority: deliberately left at NORMAL
///
/// Neither `session::lower_video_thread_priority` nor
/// `session::raise_input_thread_priority` is called here, and neither should
/// be. The established ordering in this product is **input > audio > video**,
/// and it is enforced by the video sender lowering itself rather than by
/// anything raising audio. Audio's deadline is hard — a late packet is a click
/// — but its cost is tiny: a few hundred bytes every ~21 ms and one AAC frame
/// to encode, which is nothing next to a 1080p60 encode. A normal-priority
/// thread with a 40 ms capture buffer under it meets that deadline comfortably
/// while already sitting above the video sender.
///
/// MMCSS ("Pro Audio"/"Audio" task) would be the reflex here and would be
/// wrong: it puts this thread *above* the input thread that
/// `raise_input_thread_priority` deliberately lifted, inverting the one
/// scheduling invariant this product actually cares about. A remote desktop
/// where the mouse stutters so a notification chime is sample-accurate is the
/// wrong trade.
pub(super) fn audio_pump(
    conn: Connection,
    cfg: AudioTxConfig,
    muted: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    counters: Arc<AudioCounters>,
) {
    // Declaration order is drop order in reverse: `_mf` shuts the MF platform
    // down before `_com` leaves the apartment, and every `Stream` built below
    // is scoped inside the loop so its COM interfaces are released before
    // either. Do not reorder these two lines.
    let _com = match ComMta::enter() {
        Ok(g) => g,
        Err(e) => {
            tracing::warn!("system audio off for this session: {e}");
            counters.set_status(AudioStatus::NoEndpoint);
            return;
        }
    };
    let _mf = match MfPlatform::start() {
        Ok(g) => g,
        Err(e) => {
            tracing::warn!("system audio off for this session: {e}");
            counters.set_status(AudioStatus::NoEndpoint);
            return;
        }
    };

    let tx = Tx {
        conn: &conn,
        counters: &counters,
        muted: &muted,
        stop: &stop,
        redundancy: cfg.redundancy,
    };

    // Sequence numbers and the access-unit clock both span rebuilds. A gap the
    // client sees across an endpoint switch is exactly what it should see:
    // samples really were lost, and the first packet after the switch carries
    // FLAG_DISCONTINUITY to say so. Restarting either counter at zero would
    // instead look like a brand-new stream arriving with timestamps *behind*
    // the ones already played.
    let mut seq: u32 = 0;
    let mut units_emitted: u64 = 0;
    let mut backoff = REBUILD_BACKOFF_MIN;
    let mut last_failure: Option<String> = None;

    while !stop.load(Ordering::Relaxed) {
        match Stream::open(&cfg) {
            Ok(mut stream) => {
                counters.set_status(AudioStatus::Idle);
                tracing::info!(
                    audio_format = %stream.format.label(),
                    redundancy = cfg.redundancy,
                    "system audio streaming: {} / {}",
                    stream.source.describe(),
                    stream.encoder.describe()
                );

                // THE BACKOFF IS RESET BY AUDIO HAVING FLOWED, NEVER BY THE
                // ENDPOINT HAVING OPENED.
                //
                // `Stream::open` succeeding says nothing whatever about whether
                // a single sample follows it. An endpoint that activates and
                // then faults on its first read — a device being torn down
                // underneath us, an exclusive-mode application taking it the
                // instant we got it — would otherwise loop
                // open → fail → 500 ms → open for the entire session, never
                // escalating: two `IAudioClient` activations plus a full AAC MFT
                // negotiation twice a second, forever, on a machine that has
                // already told us twice that it cannot do this.
                //
                // `units_emitted` is the exact witness, and it costs nothing
                // extra because `pump` already maintains it: it advances once
                // per access unit the encoder produced, whether that unit went
                // out, was suppressed as silence or was dropped by
                // backpressure. So a muted or silent desktop still counts as
                // flowing — it is a working stream and it should keep its fast
                // retry — while a stream that only ever returned `Ok(None)`
                // does not.
                let units_before = units_emitted;
                let outcome = pump(&tx, &mut stream, &mut seq, &mut units_emitted);
                if units_emitted > units_before {
                    backoff = REBUILD_BACKOFF_MIN;
                    last_failure = None;
                }
                if let Err(e) = outcome {
                    // Endpoint invalidated, MFT refusal, anything. Never fatal
                    // to the session; the outer loop rebuilds after a backoff.
                    // Deduped for the same reason the open path is — see
                    // `is_new_failure`. A stream that flowed and *then* broke
                    // cleared `last_failure` just above, so that case is always
                    // reported loudly.
                    let text = e.to_string();
                    if is_new_failure(&mut last_failure, &text) {
                        tracing::warn!("system audio interrupted ({text}); rebuilding capture");
                    } else {
                        tracing::debug!("system audio still failing ({text}); rebuilding capture");
                    }
                }
            }
            Err(e) => {
                counters.set_status(AudioStatus::NoEndpoint);
                let text = e.to_string();
                if is_new_failure(&mut last_failure, &text) {
                    tracing::warn!("system audio unavailable: {text}");
                } else {
                    tracing::debug!("system audio still unavailable: {text}");
                }
            }
        }

        if stop.load(Ordering::Relaxed) {
            break;
        }
        sleep_watching_stop(&stop, backoff);
        backoff = (backoff * 2).min(REBUILD_BACKOFF_MAX);
    }

    counters.set_status(AudioStatus::Disabled);
    tracing::debug!("audio sender finished");
}

/// Pump one live [`Stream`] until it fails or the session stops.
///
/// `Ok(())` means "stop, without a complaint" — the session is ending, or the
/// peer stopped accepting datagrams. `Err` means this stream is finished and
/// the caller should build another.
fn pump(tx: &Tx<'_>, stream: &mut Stream, seq: &mut u32, units_emitted: &mut u64) -> Result<()> {
    let rate = stream.format.sample_rate;
    // The immediately preceding datagram, for the redundant re-send. `Bytes`
    // rather than `Vec<u8>` so the duplicate is a refcount bump, not a copy.
    let mut prev: Option<Bytes> = None;
    // The first packet of any stream is by definition the first after a gap.
    //
    // What sets this again, and what deliberately does not, is the subtle part.
    // FLAG_DISCONTINUITY tells the receiver to *reset* its jitter buffer rather
    // than conceal, so it belongs on holes of unknown or unbounded length:
    // suppressed silence (which can last hours), a mute, an endpoint switch.
    // A single packet lost to backpressure is the opposite case — one 21 ms
    // hole that the receiver's reorder window exists to bridge — and flagging
    // it would trade a concealed frame for a full buffer reset. The sequence
    // gap already tells the receiver that packet is missing.
    let mut discontinuity = true;

    while !tx.stop.load(Ordering::Relaxed) {
        let captured = match stream.source.next_packet() {
            Ok(Some(p)) => p,
            Ok(None) => {
                std::thread::sleep(Duration::from_millis(POLL_MS));
                continue;
            }
            Err(e) => return Err(e),
        };
        if captured.discontinuity {
            discontinuity = true;
        }

        // The encoder is fed unconditionally, including silence and including
        // while muted. AAC is an MDCT codec with a 50%-overlapped window, so
        // every frame it emits depends on the samples before it: skipping the
        // submit to save CPU would leave the encoder's state describing audio
        // from before the gap, and the first frame after would decode with an
        // audible artefact. Feeding it and discarding the output costs a
        // fraction of a millisecond and keeps the state coherent.
        let units = stream.encoder.submit(&captured.pcm)?;
        if units.is_empty() {
            // Normal: AAC codes 1024 frames at a time, so most 10 ms packets
            // produce nothing at all. Not backpressure.
            continue;
        }

        // ONE atomic read, and the only thing muting costs in the hot path.
        //
        // This is the same fact the host publishes to the client as
        // `ControlMsg::SecureDesktopActive` and the same one that parks the
        // media pipeline in `SessionState::Paused` — `serve::status_loop`
        // computes it once and stores it here, so "the picture is frozen" and
        // "audio is muted" cannot disagree by construction. A host owner who
        // locks their machine, or whom Windows has just dropped onto the UAC
        // secure desktop, reasonably expects that nothing further leaves it;
        // continuing to stream the room's audio out of a machine whose screen
        // has deliberately gone dark is not a defensible default.
        //
        // The cost of sourcing it from the status loop is that muting lands
        // within one status interval (1 s) rather than instantly. That is the
        // right trade: the alternative is this thread taking the pipeline's
        // state lock tens of times a second to shave a second off a boundary
        // that is itself approximate.
        let muted = tx.muted.load(Ordering::Relaxed);
        let hold = muted || captured.silent;

        // Four realities that all sound identical from the client's chair.
        // `Streaming` means "there is audio to send" — whether it is landing is
        // what `audio_backpressured` is for.
        tx.counters.set_status(if muted {
            AudioStatus::Muted
        } else if captured.silent {
            AudioStatus::Idle
        } else {
            AudioStatus::Streaming
        });

        for unit in units {
            // `seq` and the access-unit clock both advance for every unit the
            // encoder produced, whether or not it goes out. The receiver reads
            // sequence gaps as loss and conceals them, which is exactly right
            // for suppressed silence: the audio really is missing, it just was
            // not worth sending — and the timeline must not compress to hide
            // that, or everything after a quiet stretch would play early.
            let unit_ms = access_unit_ms(*units_emitted, rate);
            *units_emitted += 1;
            *seq = seq.wrapping_add(1);

            if hold {
                tx.counters
                    .silent_suppressed
                    .fetch_add(1, Ordering::Relaxed);
                // A silent desktop costs zero bandwidth, and the next real
                // packet tells the receiver to reset rather than try to bridge
                // the hole it just skipped over.
                discontinuity = true;
                prev = None;
                continue;
            }

            let wire = WirePacket {
                seq: *seq,
                capture_ms: unit_ms,
                discontinuity,
                format: stream.wire,
                payload: unit.as_slice(),
            };
            let packet = match encode_packet(&wire) {
                Ok(p) => p,
                Err(e) => {
                    // An access unit over MAX_AUDIO_PAYLOAD. One frame of sound
                    // at any bitrate this host negotiates is a few hundred
                    // bytes, so this should never fire; if it does, dropping
                    // the frame is the whole cost.
                    tracing::warn!("audio packet not encodable ({e}); dropping one frame");
                    prev = None;
                    continue;
                }
            };

            let Some(mtu) = tx.conn.max_datagram_size() else {
                // The peer withdrew datagram support mid-session. Video is
                // already dead in this case; audio simply stops, quietly.
                tracing::warn!("peer stopped accepting datagrams; system audio stops");
                return Ok(());
            };
            // The reserve: one worst-case frame's wire size at this
            // connection's current MTU. A local and not a constant, because
            // path-MTU discovery can move the answer mid-session; recomputed
            // per packet because it is a handful of integer operations. At the
            // 1200-byte initial MTU it is 676,800 bytes.
            let audio_reserve = max_frame_wire_size(mtu);

            if !has_room(
                tx.conn.datagram_send_buffer_space(),
                packet.len(),
                audio_reserve,
            ) {
                // Drop this packet; video keeps its window. See `has_room`.
                tx.counters.backpressured.fetch_add(1, Ordering::Relaxed);
                prev = None;
                continue;
            }

            let len = packet.len() as u64;
            let bytes = Bytes::from(packet);
            match tx.conn.send_datagram(bytes.clone()) {
                Ok(()) => {
                    tx.counters.packets_sent.fetch_add(1, Ordering::Relaxed);
                    tx.counters.bytes_sent.fetch_add(len, Ordering::Relaxed);
                    discontinuity = false;
                }
                Err(quinn::SendDatagramError::ConnectionLost(_)) => {
                    // The session is over. Not this thread's business to say so.
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!("audio datagram dropped: {e}");
                    prev = None;
                    continue;
                }
            }

            // Redundancy: having sent packet N, send N-1 again behind it.
            //
            // Zero client code. The receiver's reorder window already discards
            // duplicates and fills holes, so a second copy of the previous
            // packet is either ignored or is the packet that was lost. Costs
            // exactly double the audio bitrate, which is why it is opt-in.
            //
            // The duplicate obeys the same reserve as everything else: it is
            // still audio, and it still must not displace video.
            let duplicate = if tx.redundancy { prev.take() } else { None };
            if let Some(dup) = duplicate {
                let dup_len = dup.len();
                if has_room(tx.conn.datagram_send_buffer_space(), dup_len, audio_reserve) {
                    if tx.conn.send_datagram(dup).is_ok() {
                        // Counted in bytes (it is real cost on the link) but not
                        // in packets: it carries nothing new.
                        tx.counters
                            .bytes_sent
                            .fetch_add(dup_len as u64, Ordering::Relaxed);
                    }
                } else {
                    tx.counters.backpressured.fetch_add(1, Ordering::Relaxed);
                }
            }
            // Whether or not redundancy is on, `prev` is always the packet
            // immediately preceding the next one — every path that skips a
            // packet clears it, so a duplicate is never a stale one.
            prev = Some(bytes);
        }
    }
    Ok(())
}

/// Sleep for `total`, waking often enough that `stop` is honoured promptly.
///
/// The session `join`s this thread, so a plain `sleep(15s)` inside a backoff
/// would make every disconnect wait out the remainder of it.
fn sleep_watching_stop(stop: &AtomicBool, total: Duration) {
    let mut left = total;
    while !left.is_zero() && !stop.load(Ordering::Relaxed) {
        let slice = left.min(STOP_POLL);
        std::thread::sleep(slice);
        left -= slice;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- format mapping ----------------------------------------------------

    #[test]
    fn every_capture_format_maps_to_a_wire_format() {
        for f in CaptureFormat::SUPPORTED {
            let w = wire_format(f).unwrap_or_else(|e| panic!("{}: {e}", f.label()));
            assert_eq!(w.sample_rate(), f.sample_rate, "{}", f.label());
            assert_eq!(w.channels() as u16, f.channels, "{}", f.label());
        }
    }

    #[test]
    fn the_mapping_is_injective() {
        // Two capture formats collapsing onto one wire code would mean one of
        // them decoding at the other's rate or channel count — a pitch shift or
        // a noise burst, with no error raised anywhere along the way.
        let mut seen: Vec<u8> = Vec::new();
        for f in CaptureFormat::SUPPORTED {
            let code = wire_format(f).unwrap().code();
            assert!(
                !seen.contains(&code),
                "{} collides on code {code}",
                f.label()
            );
            seen.push(code);
        }
        assert_eq!(seen.len(), 4);
    }

    #[test]
    fn the_two_supported_lists_are_still_index_for_index_identical() {
        // `wire_format` looks up by value precisely so it does not depend on
        // this — but the claim is made in several doc comments, and a reader
        // who relies on it deserves to be told when it stops being true.
        assert_eq!(CaptureFormat::SUPPORTED.len(), WireFormat::ALL.len());
        for (i, (c, w)) in CaptureFormat::SUPPORTED
            .iter()
            .zip(WireFormat::ALL.iter())
            .enumerate()
        {
            assert_eq!(wire_format(*c).unwrap(), *w, "index {i} diverged");
        }
        // And the pipeline's default is the ordinary Windows endpoint.
        assert_eq!(wire_format(CaptureFormat::DEFAULT).unwrap().code(), 0);
    }

    // -- bitrate -----------------------------------------------------------

    #[test]
    fn kbps_converts_to_the_encoders_bytes_per_second() {
        use crate::audio_encoder::{DEFAULT_BYTES_PER_SECOND, DOCUMENTED_BYTES_PER_SECOND};

        // The four rates the Windows AAC MFT documents, expressed the way the
        // config expresses them.
        assert_eq!(target_bytes_per_second(96), 12_000);
        assert_eq!(target_bytes_per_second(128), 16_000);
        assert_eq!(target_bytes_per_second(160), 20_000);
        assert_eq!(target_bytes_per_second(192), 24_000);
        assert_eq!(target_bytes_per_second(128), DEFAULT_BYTES_PER_SECOND);
        assert!(DOCUMENTED_BYTES_PER_SECOND.contains(&target_bytes_per_second(96)));

        // The config default reaches a rate the encoder documents, so the
        // shipped setting never lands on `choose_output_type`'s fallback path.
        let shipped = crate::config::HostConfig::default()
            .sanitized()
            .system_audio_kbps;
        assert!(DOCUMENTED_BYTES_PER_SECOND.contains(&target_bytes_per_second(shipped)));

        // And the clamped extremes cannot overflow or reach zero.
        assert!(target_bytes_per_second(crate::config::MIN_SYSTEM_AUDIO_KBPS) > 0);
        assert!(target_bytes_per_second(u32::MAX) > 0);
    }

    // -- timestamps --------------------------------------------------------

    #[test]
    fn capture_ms_is_a_sample_clock_not_a_wall_clock() {
        assert_eq!(capture_ms(0, 48_000), 0);
        assert_eq!(capture_ms(48_000, 48_000), 1_000);
        assert_eq!(capture_ms(1_024, 48_000), 21, "one AAC frame at 48 kHz");
        assert_eq!(capture_ms(44_100, 44_100), 1_000);
        assert_eq!(capture_ms(1_024, 44_100), 23, "one AAC frame at 44.1 kHz");
    }

    #[test]
    fn capture_ms_does_not_drift_across_a_long_session() {
        // Computed from the absolute frame index, so an hour of 44.1 kHz audio
        // — the rate whose millisecond is not an integer number of samples —
        // is still exact rather than having accumulated a per-packet rounding
        // error. Accumulating 1024-frame durations would be ~0.03 ms out per
        // frame, which is over 3 seconds an hour.
        let one_hour_frames = 44_100u64 * 3_600;
        assert_eq!(capture_ms(one_hour_frames, 44_100), 3_600_000);
        let ten_hours = 48_000u64 * 36_000;
        assert_eq!(capture_ms(ten_hours, 48_000), 36_000_000);
    }

    #[test]
    fn capture_ms_wraps_rather_than_panicking() {
        // The wire field is documented as a wrapping u32; reached after ~49
        // days of continuous audio, which a long-lived host will do.
        let just_over = (u32::MAX as u64 + 1) * 48; // frames for 2^32 ms at 48 kHz
        assert_eq!(capture_ms(just_over, 48_000), 0);
        assert_eq!(
            capture_ms(just_over + 48_000, 48_000),
            1_000,
            "wraps, cleanly"
        );
        // An absurd frame index saturates rather than overflowing the multiply.
        let _ = capture_ms(u64::MAX, 48_000);
        // A nonsense rate must not divide by zero.
        assert_eq!(capture_ms(1_000, 0), 1_000_000);
        // Same saturation through the access-unit multiply.
        let _ = access_unit_ms(u64::MAX, 48_000);
    }

    #[test]
    fn access_units_advance_one_aac_frame_at_a_time() {
        // The bug this pins: stamping every unit produced by one `submit` with
        // the submit's own timestamp. AAC emits 0, 1 or 2 units per call, so
        // that would silently collapse two units 21 ms apart onto one instant.
        assert_eq!(access_unit_ms(0, 48_000), 0);
        assert_eq!(access_unit_ms(1, 48_000), 21);
        assert_eq!(access_unit_ms(2, 48_000), 42);
        assert_eq!(access_unit_ms(1, 44_100), 23);

        // Over a long run the units must track real time to the millisecond,
        // which they only do because each is computed from its absolute index.
        // 1024 units at 48 kHz is 1,048,576 samples = 21845.33 ms.
        assert_eq!(access_unit_ms(1_024, 48_000), 21_845);
        // A minute's worth of units really is about a minute, at both rates —
        // the property that matters, stated as a bound rather than as a
        // memorised quotient. Within one frame (21-23 ms) by construction,
        // since the unit count is itself a truncating division.
        for rate in [48_000u32, 44_100] {
            let units = (rate as u64 * 60) / AAC_FRAME_SAMPLES;
            let ms = access_unit_ms(units, rate);
            assert!(
                (59_950..=60_000).contains(&ms),
                "{rate} Hz: {units} access units read as {ms} ms, not ~60 s"
            );
        }

        // Strictly increasing: a receiver ordering by timestamp must never see
        // two units claim the same instant.
        for n in 0..2_000u64 {
            assert!(
                access_unit_ms(n + 1, 48_000) > access_unit_ms(n, 48_000),
                "unit {n} and {} share a timestamp",
                n + 1
            );
        }
    }

    // -- the backpressure guard -------------------------------------------

    #[test]
    fn audio_yields_the_whole_reserve_to_video() {
        let reserve = max_frame_wire_size(1_200);
        let packet = 350usize; // a realistic AAC-LC access unit plus its header

        // Exactly enough is enough; one byte short is not.
        assert!(has_room(packet + reserve, packet, reserve));
        assert!(!has_room(packet + reserve - 1, packet, reserve));

        // An empty buffer sends; a buffer with only the packet's own size free
        // does not, which is the whole point — that room belongs to the frame
        // the video pump is part-way through pacing out.
        assert!(has_room(2 * 1024 * 1024, packet, reserve));
        assert!(
            !has_room(packet, packet, reserve),
            "audio must not take the last of the buffer even when its own \
             packet would fit — that is the eviction that shreds a keyframe"
        );
        assert!(!has_room(0, packet, reserve));
    }

    #[test]
    fn the_room_check_cannot_overflow_into_permission() {
        // A saturating add, so an absurd reserve or packet length refuses
        // rather than wrapping to a small number and letting the send through.
        assert!(!has_room(usize::MAX - 1, usize::MAX, usize::MAX));
        assert!(!has_room(1_000, usize::MAX, 10));
        assert!(!has_room(1_000, 10, usize::MAX));
    }

    // -- failure logging ---------------------------------------------------

    #[test]
    fn the_first_of_each_distinct_failure_is_loud_and_repeats_are_quiet() {
        let mut last: Option<String> = None;

        // First sighting is news.
        assert!(is_new_failure(&mut last, "no playback endpoint"));
        // The same machine saying the same thing 30 times an hour is not, and
        // this is the whole point: without it the retry loop prints one warn
        // per backoff period for the life of the session.
        for _ in 0..1_000 {
            assert!(!is_new_failure(&mut last, "no playback endpoint"));
        }

        // A *changed* failure is news again — the user plugged something in and
        // the reason moved from "no device" to "unsupported format", which is
        // exactly the transition an operator needs to see.
        assert!(is_new_failure(&mut last, "5.1 endpoint is unsupported"));
        assert!(!is_new_failure(&mut last, "5.1 endpoint is unsupported"));

        // And going back to the original message is news too: it is a change.
        assert!(is_new_failure(&mut last, "no playback endpoint"));
    }

    #[test]
    fn clearing_the_slot_makes_the_next_failure_loud_again() {
        // `audio_pump` clears it whenever audio actually flowed. A stream that
        // worked for ten minutes and then broke must not be silenced just
        // because it happens to break with the same message it used before.
        let mut last: Option<String> = None;
        assert!(is_new_failure(&mut last, "endpoint invalidated"));
        assert!(!is_new_failure(&mut last, "endpoint invalidated"));
        last = None;
        assert!(is_new_failure(&mut last, "endpoint invalidated"));
    }

    // -- retry backoff -----------------------------------------------------

    #[test]
    fn the_backoff_escalates_to_its_ceiling_in_a_handful_of_attempts() {
        // The property the "reset only when audio flowed" rule exists to
        // preserve: an endpoint that opens and immediately faults must stop
        // costing two `IAudioClient` activations and an AAC MFT negotiation
        // twice a second. Resetting on a successful *open* pinned this
        // sequence at its first element forever.
        let mut backoff = REBUILD_BACKOFF_MIN;
        let mut attempts = 0;
        while backoff < REBUILD_BACKOFF_MAX {
            backoff = (backoff * 2).min(REBUILD_BACKOFF_MAX);
            attempts += 1;
            assert!(attempts < 100, "backoff never reached its ceiling");
        }
        assert_eq!(backoff, REBUILD_BACKOFF_MAX);
        assert!(
            attempts <= 6,
            "a hopeless endpoint should reach the {REBUILD_BACKOFF_MAX:?} \
             ceiling within seconds, not minutes; took {attempts} retries"
        );
        // The floor is still fast enough that a headset appearing mid-session
        // starts working without a reconnect.
        assert!(REBUILD_BACKOFF_MIN <= Duration::from_secs(1));
        assert!(REBUILD_BACKOFF_MIN < REBUILD_BACKOFF_MAX);
    }

    // -- config plumbing ---------------------------------------------------

    #[test]
    fn the_tx_config_carries_what_the_thread_needs() {
        let cfg = AudioTxConfig {
            source: AudioSource::TestTone,
            kbps: 96,
            redundancy: true,
        };
        assert_eq!(cfg.source, AudioSource::TestTone);
        assert_eq!(target_bytes_per_second(cfg.kbps), 12_000);
        assert!(cfg.redundancy);
    }
}
