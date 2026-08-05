//! Wire protocol between the medium-integrity host and the transient
//! SYSTEM-integrity UAC injector worker (`DirectDeskUacInjector.exe`).
//!
//! The two processes talk over a message-mode named pipe whose DACL grants only
//! SYSTEM and the console user. Framing reuses the control-plane's
//! `u32-le length || postcard body`, so the same strict decoder that guards the
//! network path guards this local one.
//!
//! SECURITY: the very first frame the host sends is [`UacWireMsg::Hello`]
//! carrying the one-time capability token the service minted. The worker
//! compares it to `DIRECTDESK_UAC_CAP` in **constant time** ([`tokens_match`])
//! and disconnects on any mismatch, so the pipe cannot be driven by a process
//! that merely guessed the (already ACL-restricted) pipe name.

use directdesk_shared::protocol::{
    decode_strict, encode_framed, parse_frame_len, InputMsg, MAX_CONTROL_MSG,
};
use directdesk_shared::{Error, Result};
use serde::{Deserialize, Serialize};

/// Hard cap on a single UAC wire frame. Every message here is tiny (an auth
/// token, a geometry tuple, or one input event), so the control-plane cap is
/// already generous; sharing it keeps one number to reason about.
pub const MAX_UAC_MSG: usize = MAX_CONTROL_MSG;

/// The capability token is exactly 32 hex characters (see the service contract).
/// Anything else is rejected before the constant-time compare even runs.
pub const CAP_TOKEN_LEN: usize = 32;

/// Messages the host streams to the SYSTEM worker. One-way (host → worker); the
/// worker never replies on the wire, it only acts (or exits).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UacWireMsg {
    /// First frame. Must equal `DIRECTDESK_UAC_CAP` or the worker disconnects.
    Hello { cap_token: String },
    /// Frame geometry so the worker's [`crate::input_inject::WinInjector`] maps
    /// normalized coordinates to the same virtual-desktop pixels the host would.
    /// Sent once, before any input.
    Geometry {
        width: u32,
        height: u32,
        origin_x: i32,
        origin_y: i32,
    },
    /// A single input event (or an explicit release-all) to inject as SYSTEM,
    /// subject to the worker's consent-window guardrail.
    Input(InputMsg),
}

/// Serialize a [`UacWireMsg`] as a length-prefixed frame.
pub fn encode(msg: &UacWireMsg) -> Result<Vec<u8>> {
    encode_framed(msg)
}

/// Decode one complete frame (prefix included) into a [`UacWireMsg`].
///
/// Rejects short frames, zero-length / oversize bodies, a prefix that disagrees
/// with the body length, unknown variants, and trailing bytes — the same strict
/// contract the network decoder enforces.
pub fn decode_frame(frame: &[u8]) -> Result<UacWireMsg> {
    if frame.len() < 4 {
        return Err(Error::Invalid(format!("short UAC frame: {} bytes", frame.len())));
    }
    let prefix: [u8; 4] = frame[..4].try_into().expect("checked length");
    let declared = parse_frame_len(prefix, MAX_UAC_MSG)?;
    let body = &frame[4..];
    if body.len() != declared {
        return Err(Error::Invalid(format!(
            "UAC frame length mismatch: prefix says {declared}, body is {}",
            body.len()
        )));
    }
    decode_strict::<UacWireMsg>(body)
}

/// A window rectangle in virtual-desktop pixels, as `GetWindowRect` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PixelRect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

/// Clamp a normalized frame point so it lands inside `rect`.
///
/// This is the coordinate half of the worker's guardrail: even if a mouse event
/// arrives targeting somewhere outside the consent dialog, the SYSTEM worker
/// rewrites it to the nearest point *inside* the dialog before injecting, so the
/// worker can never click arbitrary UI while it is alive.
///
/// `frame` is the video frame size, `origin` the captured monitor's top-left in
/// virtual-desktop pixels (both from the `Geometry` frame). Pure and tested.
pub fn clamp_norm_to_rect(
    nx: u16,
    ny: u16,
    frame: (u32, u32),
    origin: (i32, i32),
    rect: PixelRect,
) -> (u16, u16) {
    use directdesk_shared::geometry::{from_norm, to_norm};
    let vx = origin.0 + from_norm(nx, frame.0) as i32;
    let vy = origin.1 + from_norm(ny, frame.1) as i32;
    // A degenerate/empty rect collapses to its top-left rather than inverting.
    let cx = vx.clamp(rect.left, (rect.right - 1).max(rect.left));
    let cy = vy.clamp(rect.top, (rect.bottom - 1).max(rect.top));
    let px = (cx - origin.0).max(0) as u32;
    let py = (cy - origin.1).max(0) as u32;
    (to_norm(px, frame.0), to_norm(py, frame.1))
}

/// Constant-time comparison of two capability tokens.
///
/// Both must be the fixed [`CAP_TOKEN_LEN`]; a length mismatch short-circuits
/// (the length of a 32-char token is not secret, its value is). Uses `subtle`
/// so a timing side-channel cannot leak how many leading characters matched.
pub fn tokens_match(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != CAP_TOKEN_LEN || b.len() != CAP_TOKEN_LEN {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use directdesk_shared::input::{InputEvent, KeyAction, MouseButton};

    fn tok(c: char) -> String {
        std::iter::repeat_n(c, CAP_TOKEN_LEN).collect()
    }

    #[test]
    fn hello_roundtrips() {
        let msg = UacWireMsg::Hello {
            cap_token: tok('a'),
        };
        let framed = encode(&msg).unwrap();
        match decode_frame(&framed).unwrap() {
            UacWireMsg::Hello { cap_token } => assert_eq!(cap_token, tok('a')),
            other => panic!("expected Hello, got {other:?}"),
        }
    }

    #[test]
    fn geometry_roundtrips() {
        let msg = UacWireMsg::Geometry {
            width: 1920,
            height: 1080,
            origin_x: -1920,
            origin_y: 0,
        };
        let framed = encode(&msg).unwrap();
        match decode_frame(&framed).unwrap() {
            UacWireMsg::Geometry {
                width,
                height,
                origin_x,
                origin_y,
            } => {
                assert_eq!((width, height, origin_x, origin_y), (1920, 1080, -1920, 0));
            }
            other => panic!("expected Geometry, got {other:?}"),
        }
    }

    #[test]
    fn input_event_roundtrips() {
        let ev = InputEvent::MouseButton {
            button: MouseButton::Left,
            action: KeyAction::Down,
            x: 30_000,
            y: 20_000,
        };
        let msg = UacWireMsg::Input(InputMsg::Event(ev));
        let framed = encode(&msg).unwrap();
        match decode_frame(&framed).unwrap() {
            UacWireMsg::Input(InputMsg::Event(InputEvent::MouseButton {
                button,
                action,
                x,
                y,
            })) => {
                assert!(matches!(button, MouseButton::Left));
                assert!(matches!(action, KeyAction::Down));
                assert_eq!((x, y), (30_000, 20_000));
            }
            other => panic!("expected Input(MouseButton), got {other:?}"),
        }
        // The frame is stable: re-encoding the decoded message reproduces bytes.
        assert_eq!(encode(&msg).unwrap(), framed);
    }

    #[test]
    fn release_all_roundtrips() {
        let msg = UacWireMsg::Input(InputMsg::ReleaseAll);
        let framed = encode(&msg).unwrap();
        assert!(matches!(
            decode_frame(&framed).unwrap(),
            UacWireMsg::Input(InputMsg::ReleaseAll)
        ));
    }

    #[test]
    fn decode_rejects_short_and_mismatched_frames() {
        assert!(decode_frame(&[]).is_err());
        assert!(decode_frame(&[0, 0, 0]).is_err());
        // Prefix claims a zero-length body.
        assert!(decode_frame(&[0, 0, 0, 0]).is_err());
        // Length mismatch: body longer than the prefix claims.
        let mut framed = encode(&UacWireMsg::Input(InputMsg::ReleaseAll)).unwrap();
        framed.push(0xAA);
        assert!(decode_frame(&framed).is_err());
    }

    #[test]
    fn tokens_match_is_true_only_for_identical_full_length_tokens() {
        assert!(tokens_match(&tok('a'), &tok('a')));
        assert!(!tokens_match(&tok('a'), &tok('b')));
    }

    #[test]
    fn tokens_match_rejects_wrong_length() {
        assert!(!tokens_match("short", "short"));
        assert!(!tokens_match(&tok('a'), "a"));
        assert!(!tokens_match("", ""));
        // One char too long.
        let long = "a".repeat(CAP_TOKEN_LEN + 1);
        assert!(!tokens_match(&long, &long));
    }

    #[test]
    fn clamp_leaves_points_already_inside_the_rect_effectively_unchanged() {
        // A point in the middle of the consent window maps back to ~itself
        // (within the 1px normalization rounding).
        let frame = (1920u32, 1080u32);
        let origin = (0i32, 0i32);
        let rect = PixelRect {
            left: 800,
            top: 400,
            right: 1120,
            bottom: 680,
        };
        use directdesk_shared::geometry::{from_norm, to_norm};
        let (nx, ny) = (to_norm(960, frame.0), to_norm(540, frame.1));
        let (cx, cy) = clamp_norm_to_rect(nx, ny, frame, origin, rect);
        let (px, py) = (from_norm(cx, frame.0) as i32, from_norm(cy, frame.1) as i32);
        assert!((px - 960).abs() <= 1 && (py - 540).abs() <= 1, "{px},{py}");
    }

    #[test]
    fn clamp_pulls_outside_points_into_the_rect() {
        let frame = (1920u32, 1080u32);
        let origin = (0i32, 0i32);
        let rect = PixelRect {
            left: 800,
            top: 400,
            right: 1120,
            bottom: 680,
        };
        use directdesk_shared::geometry::{from_norm, to_norm};
        // Top-left corner of the frame is far outside the dialog.
        let (cx, cy) = clamp_norm_to_rect(to_norm(0, frame.0), to_norm(0, frame.1), frame, origin, rect);
        let px = from_norm(cx, frame.0) as i32;
        let py = from_norm(cy, frame.1) as i32;
        assert!((rect.left..rect.right).contains(&px), "x {px} not in rect");
        assert!((rect.top..rect.bottom).contains(&py), "y {py} not in rect");
    }

    #[test]
    fn clamp_respects_a_monitor_origin_offset() {
        // Consent dialog on a second monitor whose origin is x=1920.
        let frame = (1920u32, 1080u32);
        let origin = (1920i32, 0i32);
        let rect = PixelRect {
            left: 2720,
            top: 400,
            right: 3040,
            bottom: 680,
        };
        use directdesk_shared::geometry::{from_norm, to_norm};
        let (cx, cy) = clamp_norm_to_rect(to_norm(0, frame.0), to_norm(0, frame.1), frame, origin, rect);
        let vx = origin.0 + from_norm(cx, frame.0) as i32;
        let vy = origin.1 + from_norm(cy, frame.1) as i32;
        assert!((rect.left..rect.right).contains(&vx), "vx {vx}");
        assert!((rect.top..rect.bottom).contains(&vy), "vy {vy}");
    }

    #[test]
    fn tokens_match_differs_in_last_char() {
        let mut b = tok('a');
        b.pop();
        b.push('b');
        assert!(!tokens_match(&tok('a'), &b));
    }
}
