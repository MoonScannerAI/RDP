//! Control-plane wire protocol: framing, message types, strict validation.
//!
//! Encoding: postcard (compact, rejects unknown enum variants = strict).
//! Every control message travels on a QUIC stream (or the TCP fallback's
//! length-prefixed channel) as: `u32-le length || postcard bytes`.
//! Length caps are enforced BEFORE allocation.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::input::InputEvent;
use crate::stats::{ConnStats, TransportRoute};

/// Bump on ANY wire-visible change.
pub const PROTOCOL_VERSION: u16 = 1;

/// Hard cap for any single control message (pre-allocation check).
pub const MAX_CONTROL_MSG: usize = 64 * 1024;
/// Clipboard text cap (spec: text-only clipboard for MVP).
pub const MAX_CLIPBOARD_BYTES: usize = 1024 * 1024;
/// Cap on pairing/auth messages — they are small; anything bigger is hostile.
pub const MAX_AUTH_MSG: usize = 4 * 1024;

/// Default ports (configurable in settings).
pub const DEFAULT_UDP_PORT: u16 = 47990;
pub const DEFAULT_TCP_PORT: u16 = 47991;

/// Lowest frame rate a *stored or wire* value may express. Deliberately 1, and
/// deliberately **not** the UI's user-facing floor of [`UI_MIN_TARGET_FPS`]:
/// this bound exists only to keep a hand-edited `0` — in a config file, or in a
/// peer's `ControlMsg::StartStream { preferred_fps }` — from reaching a divisor.
/// The floor a person can actually pick is a separate, product-level question;
/// see [`UI_MIN_TARGET_FPS`].
pub const MIN_TARGET_FPS: u32 = 1;
/// Highest frame rate the encoder is ever asked for. Both tiers share this
/// ceiling; only the floor is split.
pub const MAX_TARGET_FPS: u32 = 240;
/// Lowest frame rate a *person* may choose in a settings panel.
///
/// The gap between this and [`MIN_TARGET_FPS`] is intentional and must not be
/// collapsed into a single constant: `MIN_TARGET_FPS` is a sanitizer's floor
/// that only has to keep arithmetic safe, whereas this is a judgement about
/// what is worth offering a user. Widgets and pickers clamp to this; config
/// sanitizing and wire-side validation clamp to `MIN_TARGET_FPS`, so a file or
/// peer that already says `3` keeps working while the UI never offers it.
pub const UI_MIN_TARGET_FPS: u32 = 10;

/// ALPN for the QUIC/TLS handshake.
pub const ALPN: &[u8] = b"directdesk/1";

/// Channel identifiers used for stream typing and priority policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Channel {
    /// Reliable, highest priority: auth, pairing, session control.
    Control,
    /// Reliable, priority above video: key/button events, clipboard, IDR requests.
    Input,
    /// Unreliable datagrams: video fragments, mouse-move, transient stats.
    Media,
}

/// First message on the control stream, both directions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    pub version: u16,
    /// Feature bits for forward-compat negotiation.
    pub features: u64,
    /// Free-form software version, e.g. "directdesk 0.1.0". Never trusted.
    pub agent: String,
}

pub mod features {
    pub const CLIPBOARD_TEXT: u64 = 1 << 0;
    pub const CURSOR_METADATA: u64 = 1 << 1;
    pub const ADAPTIVE_BITRATE: u64 = 1 << 2;
    /// Lossless static-region tile refinement on a host-opened unidirectional
    /// stream (see [`crate::tiles`]).
    ///
    /// Negotiated as an intersection: the client sets the bit in its `Hello`,
    /// and the host echoes it only if it too supports and is configured for the
    /// feature. The host opens the stream **only** when the bit is mutual, so a
    /// peer that predates this feature never sees a byte of it — which is the
    /// whole reason this is a feature bit rather than a `PROTOCOL_VERSION` bump
    /// or a new `ControlMsg` variant. See the wire-stability tests below.
    pub const LOSSLESS_TILES: u64 = 1 << 3;
    /// System audio capture on the host, streamed host→client as AAC-LC in
    /// QUIC datagrams (see [`crate::audio`]).
    ///
    /// Negotiated as an intersection, exactly like [`LOSSLESS_TILES`]: the
    /// client sets the bit in its `Hello` to say it can decode and play the
    /// stream, and the host echoes it only if it too supports and is configured
    /// for capture. The host sends its first audio datagram **only** when the
    /// bit is mutual, so a peer that predates this feature never sees one —
    /// which matters more here than for tiles, because audio shares the media
    /// datagram path with video rather than getting a stream of its own. An old
    /// client handed an audio datagram would route it into the video
    /// reassembler; [`crate::video::FLAG_AUDIO`] documents why that is
    /// survivable, but "never sent" is the guarantee we actually rely on.
    ///
    /// This is a feature bit rather than a `PROTOCOL_VERSION` bump or a new
    /// `ControlMsg` variant for the reason the wire-stability tests below spell
    /// out: both of those brick an already-deployed remote host.
    pub const SYSTEM_AUDIO: u64 = 1 << 4;
    /// Multi-monitor streaming: the host enumerates its outputs
    /// ([`super::ControlMsg::MonitorList`]), the client picks which ones it
    /// wants ([`super::ControlMsg::SelectMonitors`]), and a second video stream
    /// — tagged with [`crate::video::FLAG_STREAM1`] in the datagram flags byte —
    /// carries the extra output alongside the existing one.
    ///
    /// Negotiated as an intersection, exactly like [`LOSSLESS_TILES`] and
    /// [`SYSTEM_AUDIO`]: the client sets the bit in its `Hello` to say it can
    /// render more than one output, and the host echoes it only if it too
    /// supports the feature **and** is configured for it. The host sends no
    /// `MonitorList`, no `StreamConfig`, and no stream-1 datagram unless the bit
    /// came back mutual, and the client sends no `SelectMonitors` and no
    /// `InputMsg::EventOn` — so a peer that predates this feature sees a session
    /// byte-for-byte identical to today's single-monitor one.
    ///
    /// That gate is load-bearing in both directions, and more so here than for
    /// tiles or audio. The new `ControlMsg` and `InputMsg` variants are appended
    /// discriminants, which an old peer's `decode_strict` rejects as an unknown
    /// variant — fatal on the control stream, and fatal on the *input* stream,
    /// where it would kill the operator's keyboard and mouse. Stream-1 video
    /// datagrams are the gentler case: an old peer's `FragHeader::decode`
    /// rejects the flag and drops the datagram with a warning, which costs a
    /// second window rather than the session. "Never sent unless mutual" is what
    /// keeps all of that theoretical.
    ///
    /// This is a feature bit rather than a `PROTOCOL_VERSION` bump for the
    /// reason the wire-stability tests below spell out: a bump bricks an
    /// already-deployed remote host, and the host is reachable only through the
    /// session this protocol carries.
    pub const MULTI_MONITOR: u64 = 1 << 5;
}

/// Pairing + steady-state authentication messages.
/// SPAKE2 pairing is bound to the TLS channel via exporter keying material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthMsg {
    /// Client → host: begin pairing with a fresh SPAKE2 first message.
    PairStart {
        spake_msg: Vec<u8>,
    },
    /// Host → client: SPAKE2 response.
    PairResponse {
        spake_msg: Vec<u8>,
    },
    /// Both directions: HMAC(confirm_key, transcript || tls_exporter || role).
    PairConfirm {
        mac: [u8; 32],
    },
    /// Host → client after pairing: host's long-term identity.
    PairComplete {
        host_ed25519_pub: [u8; 32],
        host_spki_sha256: [u8; 32],
        host_name: String,
    },
    /// Client → host: prove possession of a paired client identity.
    ClientAuth {
        client_ed25519_pub: [u8; 32],
        /// Signature over (tls_exporter || server_nonce).
        sig: Vec<u8>,
    },
    /// Host → client: fresh nonce the client must sign.
    ServerChallenge {
        nonce: [u8; 32],
    },
    /// Host → client: signature over (tls_exporter || client_nonce) with host key.
    ServerAuth {
        sig: Vec<u8>,
    },
    /// Client → host: nonce for the host to sign.
    ClientChallenge {
        nonce: [u8; 32],
    },
    AuthOk,
    AuthFail {
        reason: String,
    },
}

/// Hard cap on how many monitors a `MonitorList` may describe.
///
/// A receiver-side sanity bound, not a statement about hardware: it exists so
/// that a `Vec<MonitorInfo>` arriving from the network is never sized from a
/// count the peer chose. Sixteen outputs is far past any real desk and still
/// trivially cheap to hold. Pair it with [`MAX_VIDEO_STREAMS`]: **never
/// allocate from a wire-declared count beyond these two.** The
/// [`MAX_CONTROL_MSG`] frame cap already bounds the bytes, but a decoder that
/// pre-sizes from a length field is a distinct mistake, and postcard's own
/// length prefix is peer-controlled.
pub const MAX_MONITORS: usize = 16;
/// Hard cap on concurrent video streams in one session: stream 0 (the legacy,
/// always-present one) plus at most one tagged second stream.
///
/// Two is the number the datagram wire can actually express — the fragment
/// flags byte spends exactly one bit on the stream tag
/// ([`crate::video::FLAG_STREAM1`]), so a third stream is not a config change
/// but a wire change. The host truncates `SelectMonitors` to this length rather
/// than erroring, and the client allocates at most this many decoders; neither
/// side sizes anything from a peer-declared count.
pub const MAX_VIDEO_STREAMS: u8 = 2;

/// One capturable output on the host, as advertised in
/// [`ControlMsg::MonitorList`].
///
/// **`id` is SESSION-scoped and is not stable across reconnects.** It is an
/// index the host assigns when it enumerates, not a Windows display id, an
/// adapter id, or anything the operating system would recognise: id `0` is
/// ALWAYS the primary output — the one today's single stream already shows —
/// and `1..N` are the remaining outputs sorted by `(origin_y, origin_x)`, i.e.
/// top-to-bottom then left-to-right in virtual-desktop coordinates. That
/// ordering is a stable *function of the topology*, which is the most a client
/// may assume: unplug a monitor, dock a laptop, or simply reconnect, and the
/// same physical panel can come back under a different id. A client that wants
/// to remember "the operator was watching the right-hand screen" must key that
/// memory off [`name`](Self::name) or the geometry, never off `id`.
///
/// `origin_x` / `origin_y` are signed because the Windows virtual desktop puts
/// the primary monitor's top-left at `(0, 0)`, so anything above or to the left
/// of it has negative coordinates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorInfo {
    /// Session-scoped index; `0` is always the primary output. See the type
    /// docs — this is not stable across reconnects.
    pub id: u8,
    pub width: u32,
    pub height: u32,
    pub origin_x: i32,
    pub origin_y: i32,
    pub is_primary: bool,
    /// GDI device name (e.g. `\\.\DISPLAY1`). **Display only** — never parsed,
    /// never used to address a monitor, and never trusted: it comes off the
    /// wire and lands in a UI label. The host caps it at 64 bytes when it
    /// enumerates, so a client rendering it is not sizing a widget from
    /// peer-controlled length.
    pub name: String,
}

/// Session control messages (Control channel, after auth).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlMsg {
    /// Client requests stream start with its display capabilities.
    StartStream {
        max_width: u32,
        max_height: u32,
        preferred_fps: u32,
        quality_mode: QualityMode,
    },
    StopStream,
    /// Either side may request a fresh IDR frame (rate-limited by host).
    RequestKeyframe,
    /// Video format changed (host → client): expect a new SPS/PPS + IDR.
    VideoConfig {
        width: u32,
        height: u32,
        fps: u32,
        bitrate_kbps: u32,
        codec: Codec,
    },
    QualityChange(QualityMode),
    BitrateLimit {
        max_kbps: Option<u32>,
    },
    ClipboardText(String),
    /// Periodic stats exchange for diagnostics UI.
    Stats(ConnStats),
    /// Host → client: which route the host believes is active.
    RouteReport(TransportRoute),
    /// Host is on the secure desktop (UAC/lock) — capture unavailable.
    SecureDesktopActive(bool),
    /// Host → client: a UAC/elevation consent prompt is on screen that the
    /// normal-integrity host cannot click through UIPI. Offers the operator a
    /// one-shot opt-in to have a SYSTEM worker perform the click. `title` is the
    /// consent window caption for the operator to eyeball what they're approving.
    ElevationPrompt {
        title: String,
    },
    /// Client → host: operator opts in to respond to the *current* prompt. The
    /// host arms the SYSTEM injector for one elevation (or a short TTL) only.
    ArmElevation {
        one_shot: bool,
        ttl_secs: u32,
    },
    /// Host → client: elevation handling ended (prompt gone / TTL expired /
    /// stopped). The client clears any "arm?" affordance.
    ElevationEnded,
    /// Graceful disconnect with a human-readable reason.
    Bye {
        reason: String,
    },
    /// Liveness. Echoed with the same token.
    Ping {
        token: u64,
    },
    Pong {
        token: u64,
    },
    // -- Appended for MULTI_MONITOR. Sent only when the feature bit came back
    // -- mutual; see `features::MULTI_MONITOR` for why that gate is load-bearing.
    /// Host → client: every output the host can capture.
    ///
    /// Written raw-framed onto the control stream immediately after `AuthOk`,
    /// which makes it the **guaranteed first post-`AuthOk` host message** when
    /// the feature is mutual. The client therefore knows the topology before it
    /// asks for a stream, so its `StartStream` and any `SelectMonitors` can be
    /// one decision rather than a start-then-correct flicker.
    ///
    /// Re-sent whenever the topology changes (a monitor plugged, unplugged,
    /// re-arranged, or a resolution change): a `MonitorList` always describes
    /// the *whole* current set and replaces the client's previous copy outright.
    /// Because ids are session-scoped and re-derived on every enumeration (see
    /// [`MonitorInfo`]), a re-send may renumber outputs the client is already
    /// watching — the host reconciles by re-sending the affected
    /// [`StreamConfig`](Self::StreamConfig) or
    /// [`StreamStopped`](Self::StreamStopped), never by expecting the client to
    /// guess.
    MonitorList {
        monitors: Vec<MonitorInfo>,
    },
    /// Client → host: which outputs to stream, and in which slot.
    ///
    /// **Ordered, not a set**: `ids[0]` rides video stream 0 and `ids[1]` rides
    /// stream 1. That is the whole reason it is a `Vec` rather than a bitmask —
    /// the operator's choice of *which* screen is the main one is exactly the
    /// order of this list.
    ///
    /// Idempotent and re-sendable mid-session: the client may send it at any
    /// time to add, drop, or swap outputs, and sending the same list twice is a
    /// no-op. The host is forgiving by construction rather than by erroring,
    /// because a client's view of the topology can legitimately be one
    /// `MonitorList` out of date: it filters out ids it does not recognise,
    /// de-duplicates, and truncates to [`MAX_VIDEO_STREAMS`]. If nothing
    /// survives that filtering the host **keeps its current selection** — a
    /// stale request must never black out a working session.
    SelectMonitors {
        ids: Vec<u8>,
    },
    /// Host → client: the video format of a *secondary* stream.
    ///
    /// Sent for `id != 0` ONLY. Stream 0 stays described by the legacy
    /// [`VideoConfig`](Self::VideoConfig), with byte-identical old semantics, so
    /// that the single-monitor path — the one every deployed peer runs — is not
    /// touched by this feature at all. A `StreamConfig { id: 0, .. }` is a bug,
    /// not a synonym.
    ///
    /// Like `VideoConfig`, it implies a **discontinuity**: the receiver resets
    /// that stream's fragment reassembly and its decoder, and expects fresh
    /// SPS/PPS followed by an IDR. Anything still in flight for the old format
    /// is undecodable by definition, so dropping it is the correct handling
    /// rather than a lost-frame event worth reporting.
    StreamConfig {
        id: u8,
        monitor: u8,
        width: u32,
        height: u32,
        fps: u32,
        bitrate_kbps: u32,
        codec: Codec,
    },
    /// Host → client: a secondary stream has ended. `id` is never 0.
    ///
    /// Covers every way a second stream can stop — the client deselected it,
    /// the monitor was unplugged or disabled, or the capture/encode pipeline
    /// for it failed — because from the client's side the correct response is
    /// the same in all three: close that window. `reason` is human-readable
    /// text for the log and the UI, never a code to branch on.
    ///
    /// Stream 0 does not have an equivalent: it ends with the session (`Bye`)
    /// or with `StopStream`, exactly as it does today.
    StreamStopped {
        id: u8,
        reason: String,
    },
}

/// Input events ride their own reliable stream (except mouse-move → datagram).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InputMsg {
    Event(InputEvent),
    /// Client explicitly released input (chord or focus loss) — host must
    /// release any held keys/buttons NOW.
    ReleaseAll,
    /// Client → host: an input event aimed at a specific video stream.
    ///
    /// Sent **only** when [`features::MULTI_MONITOR`] came back mutual, and the
    /// gate matters more on this enum than on any other. The input stream is
    /// decoded with `decode_strict`, so an old host handed an unknown variant
    /// does not skip the message — it errors, and the error kills the input
    /// stream. The operator's keyboard and mouse stop working against a host
    /// that is otherwise perfectly healthy, on a session whose video keeps
    /// running, which reads as a hung remote machine rather than a protocol
    /// mismatch. One unguarded send is enough to produce that.
    ///
    /// Legacy [`Event`](Self::Event) remains exactly "stream 0" and stays the
    /// only thing a single-monitor client sends. The host treats
    /// `EventOn { id: 0, event: e }` as identical to `Event(e)`, so the two
    /// spellings never disagree about the primary output; `id` exists to say
    /// *which* window's coordinate space a click was normalized against, which
    /// is unanswerable once a second monitor is on screen.
    EventOn {
        id: u8,
        event: InputEvent,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Codec {
    H264,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QualityMode {
    TextDesktop,
    Balanced,
    Motion,
    LowBandwidth,
}

impl QualityMode {
    /// The one user-facing wording for each mode.
    ///
    /// Host and client both render this, so the two ends of a session can never
    /// show the operator two different names for the same setting — a mismatch
    /// that reads as two unrelated features. Editing a string here changes both
    /// UIs at once, which is the whole point of it living on the shared type.
    pub const fn label(self) -> &'static str {
        match self {
            QualityMode::TextDesktop => "Text / desktop",
            QualityMode::Balanced => "Balanced",
            QualityMode::Motion => "Motion",
            QualityMode::LowBandwidth => "Low bandwidth",
        }
    }
}

/// Serialize a control-plane message with the length prefix.
pub fn encode_framed<T: Serialize>(msg: &T) -> Result<Vec<u8>> {
    encode_framed_capped(msg, MAX_CONTROL_MSG)
}

/// Serialize any message as `u32-le length || postcard body`, capped at
/// `limit`.
///
/// The cap is checked *before* the prefix is written, so an oversize message is
/// an error rather than a frame a peer would reject after reading it. Callers
/// that are not on the control plane (the local UAC pipe, the service IPC pipe)
/// pass their own, smaller cap; [`encode_framed`] is this function with
/// [`MAX_CONTROL_MSG`].
pub fn encode_framed_capped<T: Serialize>(msg: &T, limit: usize) -> Result<Vec<u8>> {
    let body = postcard::to_stdvec(msg)?;
    if body.len() > limit {
        return Err(Error::Oversized {
            got: body.len(),
            limit,
        });
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Parse a length prefix; returns the body length if the cap allows it.
pub fn parse_frame_len(prefix: [u8; 4], limit: usize) -> Result<usize> {
    let len = u32::from_le_bytes(prefix) as usize;
    if len == 0 {
        return Err(Error::Invalid("zero-length frame".into()));
    }
    if len > limit {
        return Err(Error::Oversized { got: len, limit });
    }
    Ok(len)
}

/// Strict decode: rejects trailing bytes (postcard already rejects unknown
/// variants / out-of-range values).
pub fn decode_strict<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T> {
    let (value, rest) = postcard::take_from_bytes::<T>(bytes)?;
    if !rest.is_empty() {
        return Err(Error::Invalid(format!("{} trailing bytes", rest.len())));
    }
    Ok(value)
}

/// Decode one complete, already-buffered frame (`u32-le length || postcard
/// body`, prefix included) under an explicit `limit`.
///
/// Rejects, in this order:
/// * a frame shorter than the 4-byte length prefix,
/// * a zero-length body (via [`parse_frame_len`]),
/// * a declared length over `limit`, checked before anything is read,
/// * a prefix that disagrees with the actual body length,
/// * unknown enum variants and out-of-range values (postcard is strict),
/// * trailing bytes after the message (via [`decode_strict`]).
///
/// **This must remain the only implementation of that list.** The local UAC
/// control pipe and the service IPC pipe deliberately reuse the control plane's
/// framing so that a single strict decoder guards all three paths. That is not
/// tidiness: the UAC pipe drives SYSTEM-integrity input injection and the
/// service pipe drives the install/elevation verbs, so a second copy of this
/// function that drifted — a missing length-disagreement check, a forgiving
/// trailing-byte rule — would be a local privilege-escalation surface that the
/// network path's own tests could never observe. `limit` is the only knob a
/// caller is meant to vary.
///
/// Use it for whole frames held in memory (a message-mode pipe read). A
/// streaming transport that reads the prefix and then exactly that many bytes
/// should keep using [`parse_frame_len`] + [`decode_strict`] directly; the two
/// enforce the same rules, and the length-disagreement check is vacuous there.
pub fn decode_framed<T: serde::de::DeserializeOwned>(frame: &[u8], limit: usize) -> Result<T> {
    if frame.len() < 4 {
        return Err(Error::Invalid(format!(
            "short frame: {} bytes",
            frame.len()
        )));
    }
    let prefix: [u8; 4] = frame[..4].try_into().expect("checked length");
    let declared = parse_frame_len(prefix, limit)?;
    let body = &frame[4..];
    if body.len() != declared {
        return Err(Error::Invalid(format!(
            "frame length mismatch: prefix says {declared}, body is {}",
            body.len()
        )));
    }
    decode_strict::<T>(body)
}

/// Validate a Hello — version must match exactly for MVP.
pub fn validate_hello(h: &Hello) -> Result<()> {
    if h.version != PROTOCOL_VERSION {
        return Err(Error::Version(h.version));
    }
    if h.agent.len() > 128 {
        return Err(Error::Invalid("agent string too long".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framed_roundtrip() {
        let msg = ControlMsg::Ping { token: 42 };
        let framed = encode_framed(&msg).unwrap();
        let len = parse_frame_len(framed[..4].try_into().unwrap(), MAX_CONTROL_MSG).unwrap();
        assert_eq!(len, framed.len() - 4);
        let back: ControlMsg = decode_strict(&framed[4..]).unwrap();
        matches!(back, ControlMsg::Ping { token: 42 });
    }

    #[test]
    fn rejects_trailing_bytes() {
        let msg = ControlMsg::StopStream;
        let mut body = postcard::to_stdvec(&msg).unwrap();
        body.push(0xAA);
        assert!(decode_strict::<ControlMsg>(&body).is_err());
    }

    #[test]
    fn rejects_oversized_prefix() {
        let prefix = (MAX_CONTROL_MSG as u32 + 1).to_le_bytes();
        assert!(parse_frame_len(prefix, MAX_CONTROL_MSG).is_err());
    }

    #[test]
    fn rejects_wrong_version() {
        let h = Hello {
            version: 999,
            features: 0,
            agent: "x".into(),
        };
        assert!(validate_hello(&h).is_err());
    }

    // -----------------------------------------------------------------------
    // Wire stability — the anti-brick suite.
    //
    // These tests exist to be READ by the next person adding a feature. The
    // host is remote (Ohio) and is reached through the very session this
    // protocol carries, so a wire change that breaks the handshake does not
    // merely fail — it removes the means of shipping the fix.
    //
    // Every assertion below guards a specific, verified path to that outcome.
    // If one fails, do not update the expected value: change your feature to
    // negotiate via `Hello.features` instead, the way `LOSSLESS_TILES` does.
    // -----------------------------------------------------------------------

    /// Bumping `PROTOCOL_VERSION` bricks a remote host.
    ///
    /// `validate_hello` is exact-equality, so a mismatched version returns
    /// `Error::Version`. That lands in the host's auth-failure path, which
    /// calls `record_failure`; three failures inside 60 s trigger a 30 s IP
    /// lockout — while the client's reconnect `BACKOFF_MAX` is only 10 s. The
    /// client therefore retries *faster* than the lockout clears and the two
    /// never converge: a permanent lockout loop, unrecoverable without
    /// physical access to the host.
    #[test]
    fn protocol_version_is_pinned() {
        assert_eq!(
            PROTOCOL_VERSION, 1,
            "bumping PROTOCOL_VERSION causes a permanent auth-lockout loop \
             against every already-deployed peer — negotiate with a \
             Hello.features bit instead"
        );
    }

    /// `Hello`'s postcard encoding must not move.
    ///
    /// postcard is positional and has no field names: inserting, reordering or
    /// retyping a field silently changes how an old peer parses the bytes. A
    /// new *value* in the existing `features` u64 is safe; a new *field* is not.
    #[test]
    fn hello_encoding_is_stable() {
        let h = Hello {
            version: 1,
            features: 0,
            agent: "d".into(),
        };
        // version(u16 varint)=01, features(u64 varint)=00, agent len=01 'd'=64
        assert_eq!(
            postcard::to_stdvec(&h).unwrap(),
            vec![0x01, 0x00, 0x01, 0x64]
        );

        // Setting a feature bit must change only the features byte(s) — proof
        // that negotiation costs no structural change.
        let h2 = Hello {
            features: features::LOSSLESS_TILES,
            ..h
        };
        assert_eq!(
            postcard::to_stdvec(&h2).unwrap(),
            vec![0x01, 0x08, 0x01, 0x64]
        );

        // Same again for the audio bit, added when system audio landed. Each
        // new feature bit gets a line here on purpose: it costs one assertion
        // to prove that the bit is still just a *value* in the existing u64 —
        // 16 fits in a single postcard varint byte, so the frame stays four
        // bytes long and an old peer parses it unchanged. The day this
        // assertion needs a fifth byte or a shifted `agent` field, the change
        // in front of it is a structural one and must not ship.
        let h3 = Hello {
            features: features::SYSTEM_AUDIO,
            ..h2
        };
        assert_eq!(
            postcard::to_stdvec(&h3).unwrap(),
            vec![0x01, 0x10, 0x01, 0x64]
        );

        // And for the multi-monitor bit. 32 is still one varint byte — the
        // frame stays four bytes long, `agent` has not moved, and an old peer
        // parses it as a Hello carrying a feature it does not recognise and
        // therefore does not echo. `1 << 6` is the last bit that fits in a
        // single varint byte; `1 << 7` will make this frame five bytes. That is
        // a *length* change, not a structural one — postcard reads the varint
        // rather than a fixed width, so an old peer still finds `agent` — but
        // the assertion here will need its own new line, and that is the point:
        // each bit costs one line to prove it is still only a value in the
        // existing u64.
        let h4 = Hello {
            features: features::MULTI_MONITOR,
            ..h3
        };
        assert_eq!(
            postcard::to_stdvec(&h4).unwrap(),
            vec![0x01, 0x20, 0x01, 0x64]
        );
    }

    /// `MonitorInfo`'s postcard encoding must not move, for the same reason
    /// `ConnStats`' must not.
    ///
    /// It rides inside `ControlMsg::MonitorList` and is decoded with
    /// `decode_strict`, so it is positional with no field names: adding,
    /// removing, reordering or retyping a field makes a peer built from another
    /// commit read every following field out of the wrong bytes — and then fail
    /// on trailing bytes, which closes the control stream. Unlike `ConnStats`
    /// this message arrives once, right after `AuthOk`, so the failure is not
    /// "the session dies a second in" but "the session never starts".
    ///
    /// Distinctive values on purpose: an all-default struct encodes every
    /// integer as a 1-byte varint and would not notice a `u32` widening to
    /// `u64`, nor the signed `origin_*` fields losing their zigzag encoding.
    /// The negative origins are the ones that matter — they are what a monitor
    /// placed above or to the left of the primary produces.
    #[test]
    fn monitor_info_encoding_is_pinned() {
        let m = MonitorInfo {
            id: 1,
            width: 2560,
            height: 1600,
            origin_x: -1920,
            origin_y: -120,
            is_primary: false,
            name: "D2".into(),
        };
        let got = postcard::to_stdvec(&m).unwrap();
        assert_eq!(
            got,
            vec![
                0x01, // id             u8 1
                0x80, 0x14, // width    u32 varint 2560
                0xc0, 0x0c, // height   u32 varint 1600
                0xff, 0x1d, // origin_x i32 zigzag varint -1920
                0xef, 0x01, // origin_y i32 zigzag varint -120
                0x00, // is_primary     bool false
                0x02, 0x44, 0x32, // name len=2 "D2"
            ],
            "MonitorInfo's encoding moved: it is positional, so adding, \
             removing, reordering or retyping a field makes a peer built from \
             another commit misparse the MonitorList that arrives immediately \
             after AuthOk — the session never starts"
        );
    }

    /// Adding a `ConnStats` field breaks every already-deployed peer.
    ///
    /// `ConnStats` rides inside `ControlMsg::Stats` and is decoded with
    /// `decode_strict`, which rejects trailing bytes. A new field appends
    /// bytes an old peer cannot account for → "trailing bytes" → the control
    /// stream errors → `mark_closed`. The session dies on the first stats tick,
    /// i.e. within a second of connecting.
    #[test]
    fn conn_stats_encoding_is_pinned() {
        // Distinctive non-zero values on purpose: an all-default struct encodes
        // every integer as a 1-byte varint, so it would not notice a u32 field
        // widening to u64. These values make each field's width visible.
        let s = crate::stats::ConnStats {
            rtt_ms: 1.0,
            jitter_ms: 2.0,
            loss: 0.5,
            bandwidth_kbps: 300,
            fps_capture: 3.0,
            fps_encode: 4.0,
            fps_decode: 5.0,
            fps_present: 6.0,
            bitrate_kbps: 400,
            frames_dropped: 500,
            keyframes_requested: 600,
            pipeline_ms: 7.0,
            input_injected: 700,
        };
        let got = postcard::to_stdvec(&s).unwrap();
        assert_eq!(
            got,
            vec![
                0x00, 0x00, 0x80, 0x3f, // rtt_ms      f32 1.0
                0x00, 0x00, 0x00, 0x40, // jitter_ms   f32 2.0
                0x00, 0x00, 0x00, 0x3f, // loss        f32 0.5
                0xac, 0x02, // bandwidth_kbps       u32 varint 300
                0x00, 0x00, 0x40, 0x40, // fps_capture f32 3.0
                0x00, 0x00, 0x80, 0x40, // fps_encode  f32 4.0
                0x00, 0x00, 0xa0, 0x40, // fps_decode  f32 5.0
                0x00, 0x00, 0xc0, 0x40, // fps_present f32 6.0
                0x90, 0x03, // bitrate_kbps         u32 varint 400
                0xf4, 0x03, // frames_dropped       u32 varint 500
                0xd8, 0x04, // keyframes_requested  u32 varint 600
                0x00, 0x00, 0xe0, 0x40, // pipeline_ms f32 7.0
                0xbc, 0x05, // input_injected       u64 varint 700
            ],
            "ConnStats' encoding moved: it is positional, so adding, removing, \
             reordering or retyping a field makes every already-deployed peer \
             fail decode_strict with 'trailing bytes' and drop the session on \
             the first stats tick"
        );
    }

    /// `ControlMsg` discriminants are positional in postcard, so *inserting* a
    /// variant renumbers every variant after it. An old peer would then read a
    /// `Bye` as something else entirely — and an unknown discriminant fails
    /// `decode_strict`, which is treated as fatal and closes the session.
    ///
    /// New variants may only be APPENDED, and only once both ends are known to
    /// support them. This test pins the existing order.
    ///
    /// The tail past `Pong` (15) is the multi-monitor block, 16..=19, appended
    /// under `features::MULTI_MONITOR` and sent only when that bit is mutual.
    /// Those four are pinned here for the same reason as the rest: the next
    /// feature must append at 20, not tidy itself into the middle.
    #[test]
    fn control_msg_discriminants_are_pinned() {
        let cases: [(ControlMsg, u8); 10] = [
            (ControlMsg::StopStream, 1),
            (ControlMsg::RequestKeyframe, 2),
            (
                ControlMsg::Bye {
                    reason: String::new(),
                },
                13,
            ),
            (ControlMsg::Ping { token: 0 }, 14),
            (ControlMsg::Pong { token: 0 }, 15),
            (ControlMsg::ElevationEnded, 12),
            (ControlMsg::MonitorList { monitors: vec![] }, 16),
            (ControlMsg::SelectMonitors { ids: vec![] }, 17),
            (
                ControlMsg::StreamConfig {
                    id: 1,
                    monitor: 1,
                    width: 0,
                    height: 0,
                    fps: 0,
                    bitrate_kbps: 0,
                    codec: Codec::H264,
                },
                18,
            ),
            (
                ControlMsg::StreamStopped {
                    id: 1,
                    reason: String::new(),
                },
                19,
            ),
        ];
        for (msg, want) in cases {
            let got = postcard::to_stdvec(&msg).unwrap()[0];
            assert_eq!(
                got, want,
                "discriminant moved for {msg:?} — a variant was \
                 inserted rather than appended; old peers will misparse every \
                 later variant"
            );
        }
    }

    /// `InputMsg`'s discriminants are pinned for the same positional reason as
    /// `ControlMsg`'s, with a worse failure mode.
    ///
    /// This enum is small enough to look safe to reorganise, and it is the one
    /// place where a renumbering costs the operator their keyboard: the input
    /// stream is decoded with `decode_strict`, so a `ReleaseAll` read as an
    /// `Event`, or an unknown discriminant on an old host, errors out and takes
    /// the input stream with it. Video keeps flowing, so the symptom is a
    /// remote machine that appears alive and ignores every key.
    ///
    /// `EventOn` is appended at 2 under `features::MULTI_MONITOR` and is sent
    /// only when that bit is mutual — an old host has no variant 2 at all.
    #[test]
    fn input_msg_discriminants_are_pinned() {
        let cases: [(InputMsg, u8); 3] = [
            (InputMsg::Event(InputEvent::MouseMove { x: 0, y: 0 }), 0),
            (InputMsg::ReleaseAll, 1),
            (
                InputMsg::EventOn {
                    id: 0,
                    event: InputEvent::MouseMove { x: 0, y: 0 },
                },
                2,
            ),
        ];
        for (msg, want) in cases {
            let got = postcard::to_stdvec(&msg).unwrap()[0];
            assert_eq!(
                got, want,
                "discriminant moved for {msg:?} — a variant was \
                 inserted rather than appended; old peers will misparse every \
                 later variant and drop the input stream"
            );
        }
    }

    /// The tile feature must be negotiable, i.e. actually distinguishable from
    /// the bits already in use. Cheap, but it catches a copy-paste collision.
    #[test]
    fn feature_bits_are_distinct() {
        let bits = [
            features::CLIPBOARD_TEXT,
            features::CURSOR_METADATA,
            features::ADAPTIVE_BITRATE,
            features::LOSSLESS_TILES,
            features::SYSTEM_AUDIO,
            features::MULTI_MONITOR,
        ];
        for (i, a) in bits.iter().enumerate() {
            assert!(a.count_ones() == 1, "feature bits must be single bits");
            for b in &bits[i + 1..] {
                assert_eq!(a & b, 0, "feature bit collision");
            }
        }
        // The client reserves the high half for local hints
        // (`FEATURE_PAIRING_REQUEST = 1 << 32`); protocol bits stay low.
        assert!(bits.iter().all(|b| *b < (1u64 << 32)));
    }
}
