//! Stuck-key tracking: the host records every key/button it has pressed on
//! behalf of the remote client so that on disconnect, release-chord, focus
//! loss, or secure-desktop transition, everything held gets released.

use std::collections::HashSet;

use crate::input::{InputEvent, KeyAction, MouseButton};

#[derive(Debug, Default)]
pub struct HeldInput {
    keys: HashSet<(u16, bool)>, // (scan_code, extended)
    buttons: HashSet<MouseButton>,
}

impl HeldInput {
    pub fn new() -> Self {
        Self::default()
    }

    /// Track the effect of an event about to be injected.
    pub fn observe(&mut self, ev: &InputEvent) {
        match ev {
            InputEvent::Key {
                scan_code,
                extended,
                action,
            } => match action {
                KeyAction::Down => {
                    self.keys.insert((*scan_code, *extended));
                }
                KeyAction::Up => {
                    self.keys.remove(&(*scan_code, *extended));
                }
            },
            InputEvent::MouseButton { button, action, .. } => match action {
                KeyAction::Down => {
                    self.buttons.insert(*button);
                }
                KeyAction::Up => {
                    self.buttons.remove(button);
                }
            },
            _ => {}
        }
    }

    /// Produce the release events for everything currently held, clearing state.
    /// Order: buttons first (avoids drag artifacts), then keys.
    pub fn drain_releases(&mut self) -> Vec<InputEvent> {
        let mut out = Vec::with_capacity(self.keys.len() + self.buttons.len());
        for b in self.buttons.drain() {
            out.push(InputEvent::MouseButton {
                button: b,
                action: KeyAction::Up,
                x: 0,
                y: 0,
            });
        }
        for (scan_code, extended) in self.keys.drain() {
            out.push(InputEvent::Key {
                scan_code,
                extended,
                action: KeyAction::Up,
            });
        }
        out
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty() && self.buttons.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn releases_everything_held() {
        let mut h = HeldInput::new();
        h.observe(&InputEvent::Key {
            scan_code: 0x1E,
            extended: false,
            action: KeyAction::Down,
        });
        h.observe(&InputEvent::Key {
            scan_code: 0x2A,
            extended: false,
            action: KeyAction::Down,
        });
        h.observe(&InputEvent::Key {
            scan_code: 0x1E,
            extended: false,
            action: KeyAction::Up,
        });
        h.observe(&InputEvent::MouseButton {
            button: MouseButton::Left,
            action: KeyAction::Down,
            x: 1,
            y: 1,
        });
        let rel = h.drain_releases();
        assert_eq!(rel.len(), 2); // shift key + left button
        assert!(h.is_empty());
    }
}
