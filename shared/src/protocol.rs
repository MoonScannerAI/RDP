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
}

/// Input events ride their own reliable stream (except mouse-move → datagram).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InputMsg {
    Event(InputEvent),
    /// Client explicitly released input (chord or focus loss) — host must
    /// release any held keys/buttons NOW.
    ReleaseAll,
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

/// Serialize a control-plane message with the length prefix.
pub fn encode_framed<T: Serialize>(msg: &T) -> Result<Vec<u8>> {
    let body = postcard::to_stdvec(msg)?;
    if body.len() > MAX_CONTROL_MSG {
        return Err(Error::Oversized {
            got: body.len(),
            limit: MAX_CONTROL_MSG,
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
    #[test]
    fn control_msg_discriminants_are_pinned() {
        let cases: [(ControlMsg, u8); 6] = [
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

    /// The tile feature must be negotiable, i.e. actually distinguishable from
    /// the bits already in use. Cheap, but it catches a copy-paste collision.
    #[test]
    fn feature_bits_are_distinct() {
        let bits = [
            features::CLIPBOARD_TEXT,
            features::CURSOR_METADATA,
            features::ADAPTIVE_BITRATE,
            features::LOSSLESS_TILES,
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
