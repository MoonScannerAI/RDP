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
}

/// Pairing + steady-state authentication messages.
/// SPAKE2 pairing is bound to the TLS channel via exporter keying material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthMsg {
    /// Client → host: begin pairing with a fresh SPAKE2 first message.
    PairStart { spake_msg: Vec<u8> },
    /// Host → client: SPAKE2 response.
    PairResponse { spake_msg: Vec<u8> },
    /// Both directions: HMAC(confirm_key, transcript || tls_exporter || role).
    PairConfirm { mac: [u8; 32] },
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
    ServerChallenge { nonce: [u8; 32] },
    /// Host → client: signature over (tls_exporter || client_nonce) with host key.
    ServerAuth { sig: Vec<u8> },
    /// Client → host: nonce for the host to sign.
    ClientChallenge { nonce: [u8; 32] },
    AuthOk,
    AuthFail { reason: String },
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
    BitrateLimit { max_kbps: Option<u32> },
    ClipboardText(String),
    /// Periodic stats exchange for diagnostics UI.
    Stats(ConnStats),
    /// Host → client: which route the host believes is active.
    RouteReport(TransportRoute),
    /// Host is on the secure desktop (UAC/lock) — capture unavailable.
    SecureDesktopActive(bool),
    /// Graceful disconnect with a human-readable reason.
    Bye { reason: String },
    /// Liveness. Echoed with the same token.
    Ping { token: u64 },
    Pong { token: u64 },
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
        return Err(Error::Oversized { got: body.len(), limit: MAX_CONTROL_MSG });
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
        let h = Hello { version: 999, features: 0, agent: "x".into() };
        assert!(validate_hello(&h).is_err());
    }
}
