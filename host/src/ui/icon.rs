//! The tray icon bitmap, drawn in code.
//!
//! Shipping a `.ico` would mean a build-script and a binary blob in the repo
//! for four flat-coloured 32×32 images. Drawing them is a dozen lines, keeps
//! the colour and the meaning in the same place, and makes the "the icon must
//! tell the truth about the state" rule testable.

use super::TrayState;

/// Icon edge length in pixels. 32 is what the Windows notification area asks
/// for at 100–150% scaling.
pub const SIZE: u32 = 32;

impl TrayState {
    /// The accent colour for this state. Chosen to be distinguishable in
    /// greyscale too: off is dark, listening is mid, connected is bright.
    fn accent(self) -> [u8; 3] {
        match self {
            TrayState::Disabled => [110, 116, 124], // grey: not serving
            TrayState::Starting => [140, 160, 186], // pale: on its way up
            TrayState::Listening => [64, 148, 236], // blue: ready
            TrayState::Connected => [58, 196, 118], // green: someone is here
            TrayState::Problem => [226, 106, 62],   // orange: enabled, broken
        }
    }
}

/// RGBA8 pixels for the tray icon in a given state.
///
/// The shape is a small monitor: a filled bezel in the accent colour, a dark
/// screen, and a stand. The state is carried by colour, and by whether the
/// screen has a "live" dot in it.
pub fn rgba(state: TrayState) -> Vec<u8> {
    let [ar, ag, ab] = state.accent();
    let screen = [22u8, 26, 32];
    let mut px = vec![0u8; (SIZE * SIZE * 4) as usize];

    let set = |px: &mut Vec<u8>, x: u32, y: u32, c: [u8; 3], a: u8| {
        if x >= SIZE || y >= SIZE {
            return;
        }
        let i = ((y * SIZE + x) * 4) as usize;
        px[i] = c[0];
        px[i + 1] = c[1];
        px[i + 2] = c[2];
        px[i + 3] = a;
    };

    // Bezel: rows 3..24, columns 2..30, with the corners knocked off.
    for y in 3..24u32 {
        for x in 2..30u32 {
            let corner = (x == 2 || x == 29) && (y == 3 || y == 23);
            if corner {
                continue;
            }
            set(&mut px, x, y, [ar, ag, ab], 255);
        }
    }
    // Screen.
    for y in 6..21u32 {
        for x in 5..27u32 {
            set(&mut px, x, y, screen, 255);
        }
    }
    // Connected gets a filled indicator inside the screen; every other state
    // leaves it dark. Colour alone is not the only signal.
    if state == TrayState::Connected {
        for y in 11..16u32 {
            for x in 13..19u32 {
                set(&mut px, x, y, [ar, ag, ab], 255);
            }
        }
    }
    // Neck and base of the stand.
    for y in 24..27u32 {
        for x in 13..19u32 {
            set(&mut px, x, y, [ar, ag, ab], 255);
        }
    }
    for y in 27..30u32 {
        for x in 8..24u32 {
            set(&mut px, x, y, [ar, ag, ab], 255);
        }
    }
    px
}

/// The icon in the form `tray-icon` wants.
pub fn tray_icon(state: TrayState) -> Result<tray_icon::Icon, tray_icon::BadIcon> {
    tray_icon::Icon::from_rgba(rgba(state), SIZE, SIZE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icon_has_the_right_shape() {
        let px = rgba(TrayState::Listening);
        assert_eq!(px.len(), (SIZE * SIZE * 4) as usize);
        assert!(tray_icon(TrayState::Listening).is_ok());
    }

    #[test]
    fn every_state_produces_a_valid_icon() {
        for s in [
            TrayState::Disabled,
            TrayState::Starting,
            TrayState::Listening,
            TrayState::Connected,
            TrayState::Problem,
        ] {
            assert!(tray_icon(s).is_ok(), "{s:?}");
        }
    }

    #[test]
    fn states_are_visually_distinct() {
        // A user must be able to tell "listening" from "someone is watching my
        // screen" at a glance, so the pixels really have to differ.
        let listening = rgba(TrayState::Listening);
        let connected = rgba(TrayState::Connected);
        let disabled = rgba(TrayState::Disabled);
        assert_ne!(listening, connected);
        assert_ne!(listening, disabled);
        assert_ne!(connected, disabled);
        assert_ne!(rgba(TrayState::Problem), disabled);
    }

    #[test]
    fn connected_lights_the_screen_indicator() {
        let connected = rgba(TrayState::Connected);
        let idx = |x: u32, y: u32| ((y * SIZE + x) * 4) as usize;
        let centre = &connected[idx(15, 13)..idx(15, 13) + 3];
        assert_eq!(centre, TrayState::Connected.accent());
        let listening = rgba(TrayState::Listening);
        assert_ne!(
            &listening[idx(15, 13)..idx(15, 13) + 3],
            TrayState::Listening.accent()
        );
    }

    #[test]
    fn the_icon_is_not_fully_transparent() {
        let px = rgba(TrayState::Listening);
        let opaque = px.chunks(4).filter(|p| p[3] > 0).count();
        assert!(opaque > 200, "only {opaque} opaque pixels");
    }
}
