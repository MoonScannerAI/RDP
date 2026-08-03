//! Input event definitions. Coordinates are normalized to the HOST's video
//! frame (0..=u16::MAX maps to 0..frame_dim) so DPI/scaling differences never
//! corrupt positioning; the host converts to physical pixels.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyAction {
    Down,
    Up,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
    X1,
    X2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InputEvent {
    Key {
        /// Windows scan code (hardware, layout-independent).
        scan_code: u16,
        /// Extended-key flag (arrows, right-ctrl, etc.).
        extended: bool,
        action: KeyAction,
    },
    MouseButton {
        button: MouseButton,
        action: KeyAction,
        x: u16,
        y: u16,
    },
    /// Absolute position normalized to 0..=u16::MAX over the video frame.
    MouseMove { x: u16, y: u16 },
    MouseWheel {
        /// Positive = away from user. In WHEEL_DELTA units (120 per notch).
        delta: i16,
        horizontal: bool,
        x: u16,
        y: u16,
    },
}

/// Validate an event against the current video frame dimensions.
/// Normalized coords are always in range by construction (u16), but scan
/// codes and wheel deltas get sanity caps.
pub fn validate_event(ev: &InputEvent) -> Result<()> {
    match ev {
        InputEvent::Key { scan_code, .. } => {
            // Scan codes are 7-bit + extended flag; 0 is invalid.
            if *scan_code == 0 || *scan_code > 0xFF {
                return Err(Error::Invalid(format!(
                    "scan code {scan_code:#x} out of range"
                )));
            }
        }
        InputEvent::MouseWheel { delta, .. } => {
            if delta.unsigned_abs() > 120 * 32 {
                return Err(Error::Invalid("wheel delta implausible".into()));
            }
        }
        InputEvent::MouseButton { .. } | InputEvent::MouseMove { .. } => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero_scan_code() {
        let ev = InputEvent::Key {
            scan_code: 0,
            extended: false,
            action: KeyAction::Down,
        };
        assert!(validate_event(&ev).is_err());
    }

    #[test]
    fn accepts_normal_events() {
        assert!(validate_event(&InputEvent::MouseMove { x: 100, y: 200 }).is_ok());
        assert!(validate_event(&InputEvent::Key {
            scan_code: 0x1E,
            extended: false,
            action: KeyAction::Up
        })
        .is_ok());
    }
}
