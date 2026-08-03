//! `SendInput` injection.
//!
//! Keys travel as hardware scan codes (`KEYEVENTF_SCANCODE`) so the host's
//! keyboard layout is irrelevant — the client sends what the physical key *is*,
//! not what it means. Mouse positions arrive normalized to the video frame and
//! are mapped frame-pixel -> monitor-pixel -> virtual-desktop-absolute, which is
//! the only mapping that survives multi-monitor and mixed-DPI setups.
//!
//! Everything injected is tracked in [`HeldInput`] so a disconnect, focus loss
//! or secure-desktop transition can release it all instead of leaving the host
//! with a stuck Ctrl key.

use directdesk_shared::geometry::from_norm;
use directdesk_shared::input::{InputEvent, KeyAction, MouseButton};
use directdesk_shared::input_state::HeldInput;
use directdesk_shared::traits::InputInjector;
use directdesk_shared::{Error, Result};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYEVENTF_EXTENDEDKEY,
    KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE, MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_HWHEEL,
    MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP,
    MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_VIRTUALDESK,
    MOUSEEVENTF_WHEEL, MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP, MOUSEINPUT, MOUSE_EVENT_FLAGS,
    VIRTUAL_KEY,
};
use windows::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
    XBUTTON1, XBUTTON2,
};

/// Bounding box of all monitors, in physical pixels: `(left, top, width, height)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtualScreen {
    pub left: i32,
    pub top: i32,
    pub width: i32,
    pub height: i32,
}

impl VirtualScreen {
    pub fn query() -> Self {
        // SAFETY: plain FFI returning scalars.
        unsafe {
            Self {
                left: GetSystemMetrics(SM_XVIRTUALSCREEN),
                top: GetSystemMetrics(SM_YVIRTUALSCREEN),
                width: GetSystemMetrics(SM_CXVIRTUALSCREEN).max(1),
                height: GetSystemMetrics(SM_CYVIRTUALSCREEN).max(1),
            }
        }
    }
}

pub struct WinInjector {
    held: HeldInput,
    /// Dimensions of the video frame the client is looking at.
    frame: (u32, u32),
    /// Top-left of the captured monitor in virtual-desktop coordinates.
    origin: (i32, i32),
    screen: VirtualScreen,
    injected: u64,
}

impl WinInjector {
    pub fn new(frame_w: u32, frame_h: u32, origin: (i32, i32)) -> Self {
        Self {
            held: HeldInput::new(),
            frame: (frame_w.max(1), frame_h.max(1)),
            origin,
            screen: VirtualScreen::query(),
            injected: 0,
        }
    }

    /// Update after a resolution change; also re-reads the virtual screen box.
    pub fn set_frame(&mut self, w: u32, h: u32, origin: (i32, i32)) {
        self.frame = (w.max(1), h.max(1));
        self.origin = origin;
        self.screen = VirtualScreen::query();
    }

    pub fn refresh_metrics(&mut self) {
        self.screen = VirtualScreen::query();
    }

    pub fn injected_count(&self) -> u64 {
        self.injected
    }

    pub fn anything_held(&self) -> bool {
        !self.held.is_empty()
    }

    /// Release every key and button we are currently holding down on behalf of
    /// the remote client. Safe to call repeatedly.
    pub fn release_all(&mut self) -> Result<()> {
        let releases = self.held.drain_releases();
        if releases.is_empty() {
            return Ok(());
        }
        tracing::info!("releasing {} stuck input(s)", releases.len());
        let mut inputs = Vec::with_capacity(releases.len());
        for ev in &releases {
            // Release events carry no position; suppress the move component.
            if let Some(i) = self.build(ev, false) {
                inputs.push(i);
            }
        }
        self.send(&inputs)
    }

    fn send(&mut self, inputs: &[INPUT]) -> Result<()> {
        if inputs.is_empty() {
            return Ok(());
        }
        // SAFETY: `inputs` is a valid slice of fully-initialized INPUT records
        // and cbSize matches the struct we built.
        let sent = unsafe { SendInput(inputs, std::mem::size_of::<INPUT>() as i32) };
        if sent as usize != inputs.len() {
            return Err(Error::Input(format!(
                "SendInput injected {sent}/{} events (blocked by UIPI or a higher-integrity window?)",
                inputs.len()
            )));
        }
        self.injected += sent as u64;
        Ok(())
    }

    /// Map a normalized wire coordinate to `SendInput`'s 0..=65535 absolute
    /// virtual-desktop space.
    pub fn to_virtual_abs(&self, nx: u16, ny: u16) -> (i32, i32) {
        norm_to_virtual_abs(nx, ny, self.frame, self.origin, self.screen)
    }

    fn build(&self, ev: &InputEvent, with_move: bool) -> Option<INPUT> {
        match ev {
            InputEvent::Key { scan_code, extended, action } => {
                let mut flags = KEYEVENTF_SCANCODE;
                // Some clients send the full 0xE0xx scan code; normalize to the
                // low byte plus the extended flag, which is what Windows wants.
                let extended = *extended || (*scan_code & 0xFF00) == 0xE000;
                if extended {
                    flags |= KEYEVENTF_EXTENDEDKEY;
                }
                if matches!(action, KeyAction::Up) {
                    flags |= KEYEVENTF_KEYUP;
                }
                Some(INPUT {
                    r#type: INPUT_KEYBOARD,
                    Anonymous: INPUT_0 {
                        ki: KEYBDINPUT {
                            wVk: VIRTUAL_KEY(0),
                            wScan: *scan_code & 0xFF,
                            dwFlags: flags,
                            time: 0,
                            dwExtraInfo: 0,
                        },
                    },
                })
            }
            InputEvent::MouseMove { x, y } => {
                let (ax, ay) = self.to_virtual_abs(*x, *y);
                Some(mouse_input(
                    MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
                    0,
                    ax,
                    ay,
                ))
            }
            InputEvent::MouseButton { button, action, x, y } => {
                let down = matches!(action, KeyAction::Down);
                let (flag, data) = match (button, down) {
                    (MouseButton::Left, true) => (MOUSEEVENTF_LEFTDOWN, 0),
                    (MouseButton::Left, false) => (MOUSEEVENTF_LEFTUP, 0),
                    (MouseButton::Right, true) => (MOUSEEVENTF_RIGHTDOWN, 0),
                    (MouseButton::Right, false) => (MOUSEEVENTF_RIGHTUP, 0),
                    (MouseButton::Middle, true) => (MOUSEEVENTF_MIDDLEDOWN, 0),
                    (MouseButton::Middle, false) => (MOUSEEVENTF_MIDDLEUP, 0),
                    (MouseButton::X1, true) => (MOUSEEVENTF_XDOWN, XBUTTON1 as u32),
                    (MouseButton::X1, false) => (MOUSEEVENTF_XUP, XBUTTON1 as u32),
                    (MouseButton::X2, true) => (MOUSEEVENTF_XDOWN, XBUTTON2 as u32),
                    (MouseButton::X2, false) => (MOUSEEVENTF_XUP, XBUTTON2 as u32),
                };
                if with_move {
                    let (ax, ay) = self.to_virtual_abs(*x, *y);
                    Some(mouse_input(
                        flag | MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
                        data,
                        ax,
                        ay,
                    ))
                } else {
                    Some(mouse_input(flag, data, 0, 0))
                }
            }
            InputEvent::MouseWheel { delta, horizontal, x, y } => {
                let flag = if *horizontal { MOUSEEVENTF_HWHEEL } else { MOUSEEVENTF_WHEEL };
                let data = *delta as i32 as u32;
                if with_move {
                    let (ax, ay) = self.to_virtual_abs(*x, *y);
                    Some(mouse_input(
                        flag | MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
                        data,
                        ax,
                        ay,
                    ))
                } else {
                    Some(mouse_input(flag, data, 0, 0))
                }
            }
        }
    }
}

impl InputInjector for WinInjector {
    fn inject(&mut self, ev: &InputEvent) -> Result<()> {
        directdesk_shared::input::validate_event(ev)?;
        let Some(input) = self.build(ev, true) else {
            return Ok(());
        };
        // Track before sending: if SendInput partially succeeds we would rather
        // over-release later than leave a key held forever.
        self.held.observe(ev);
        self.send(&[input])
    }
}

impl Drop for WinInjector {
    fn drop(&mut self) {
        let _ = self.release_all();
    }
}

fn mouse_input(flags: MOUSE_EVENT_FLAGS, data: u32, dx: i32, dy: i32) -> INPUT {
    INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx,
                dy,
                mouseData: data,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

/// Pure coordinate math, extracted so it can be tested without a desktop.
///
/// `frame` is the video frame size, `origin` the captured monitor's top-left in
/// virtual-desktop coordinates, `screen` the virtual desktop bounding box.
/// Result is `SendInput`'s absolute 0..=65535 space.
pub fn norm_to_virtual_abs(
    nx: u16,
    ny: u16,
    frame: (u32, u32),
    origin: (i32, i32),
    screen: VirtualScreen,
) -> (i32, i32) {
    let px = from_norm(nx, frame.0) as i32;
    let py = from_norm(ny, frame.1) as i32;
    let vx = origin.0 + px;
    let vy = origin.1 + py;

    let span_x = (screen.width - 1).max(1) as i64;
    let span_y = (screen.height - 1).max(1) as i64;
    let ax = ((vx - screen.left) as i64 * 65535 + span_x / 2) / span_x;
    let ay = ((vy - screen.top) as i64 * 65535 + span_y / 2) / span_y;
    (ax.clamp(0, 65535) as i32, ay.clamp(0, 65535) as i32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use directdesk_shared::geometry::to_norm;

    const SINGLE: VirtualScreen = VirtualScreen { left: 0, top: 0, width: 1920, height: 1080 };

    #[test]
    fn single_monitor_corners_map_to_extremes() {
        let frame = (1920, 1080);
        assert_eq!(norm_to_virtual_abs(0, 0, frame, (0, 0), SINGLE), (0, 0));
        assert_eq!(
            norm_to_virtual_abs(u16::MAX, u16::MAX, frame, (0, 0), SINGLE),
            (65535, 65535)
        );
    }

    #[test]
    fn centre_stays_centred() {
        // The wire coordinate is quantized to a frame pixel first, so the
        // result is only accurate to one pixel — 65535/1919 ≈ 34 units across,
        // 65535/1079 ≈ 61 down. Assert in pixels, which is what actually matters.
        let frame = (1920u32, 1080u32);
        let (x, y) = norm_to_virtual_abs(u16::MAX / 2, u16::MAX / 2, frame, (0, 0), SINGLE);
        let px = (x as i64 * 1919 + 32767) / 65535;
        let py = (y as i64 * 1079 + 32767) / 65535;
        assert!((px - 959).abs() <= 1, "x={x} -> px={px}");
        assert!((py - 539).abs() <= 1, "y={y} -> py={py}");
    }

    #[test]
    fn secondary_monitor_offsets_into_its_own_half() {
        // Two 1920x1080 monitors side by side; we capture the RIGHT one, whose
        // origin is x=1920 in a 3840-wide virtual desktop.
        let screen = VirtualScreen { left: 0, top: 0, width: 3840, height: 1080 };
        let frame = (1920, 1080);
        let (x0, _) = norm_to_virtual_abs(0, 0, frame, (1920, 0), screen);
        let (x1, _) = norm_to_virtual_abs(u16::MAX, 0, frame, (1920, 0), screen);
        assert!(x0 > 32000 && x0 < 33500, "left edge of right monitor: {x0}");
        assert_eq!(x1, 65535, "right edge must saturate");
    }

    #[test]
    fn negative_origin_monitor_maps_into_range() {
        // Left-hand monitor at x=-1920 in a 3840-wide desktop starting at -1920.
        let screen = VirtualScreen { left: -1920, top: 0, width: 3840, height: 1080 };
        let frame = (1920, 1080);
        let (x0, _) = norm_to_virtual_abs(0, 0, frame, (-1920, 0), screen);
        let (x1, _) = norm_to_virtual_abs(u16::MAX, 0, frame, (-1920, 0), screen);
        assert_eq!(x0, 0);
        assert!(x1 > 32000 && x1 < 33500, "{x1}");
    }

    #[test]
    fn roundtrip_pixel_to_abs_is_within_one_pixel() {
        let frame = (2560u32, 1440u32);
        let screen = VirtualScreen { left: 0, top: 0, width: 2560, height: 1440 };
        for px in (0..2560u32).step_by(97) {
            let n = to_norm(px, frame.0);
            let (ax, _) = norm_to_virtual_abs(n, 0, frame, (0, 0), screen);
            // Windows maps abs back as round(ax * (w-1) / 65535).
            let back = (ax as i64 * 2559 + 32767) / 65535;
            assert!((back - px as i64).abs() <= 1, "px={px} back={back}");
        }
    }

    #[test]
    fn degenerate_screen_does_not_divide_by_zero() {
        let screen = VirtualScreen { left: 0, top: 0, width: 1, height: 1 };
        let (x, y) = norm_to_virtual_abs(30000, 30000, (1, 1), (0, 0), screen);
        assert!((0..=65535).contains(&x) && (0..=65535).contains(&y));
    }

    #[test]
    fn held_input_tracks_and_releases() {
        // Integration with the shared stuck-key tracker, without touching the
        // real desktop: exercise HeldInput exactly as inject() does.
        let mut held = HeldInput::new();
        let evs = [
            InputEvent::Key { scan_code: 0x2A, extended: false, action: KeyAction::Down },
            InputEvent::Key { scan_code: 0x1D, extended: true, action: KeyAction::Down },
            InputEvent::MouseButton {
                button: MouseButton::Left,
                action: KeyAction::Down,
                x: 1,
                y: 1,
            },
            InputEvent::Key { scan_code: 0x2A, extended: false, action: KeyAction::Up },
        ];
        for e in &evs {
            assert!(directdesk_shared::input::validate_event(e).is_ok());
            held.observe(e);
        }
        let rel = held.drain_releases();
        assert_eq!(rel.len(), 2, "ctrl (extended) + left button remain held");
        assert!(held.is_empty());
        assert!(rel.iter().all(|e| matches!(
            e,
            InputEvent::Key { action: KeyAction::Up, .. }
                | InputEvent::MouseButton { action: KeyAction::Up, .. }
        )));
    }

    #[test]
    fn extended_scan_codes_are_masked_to_low_byte() {
        let inj = WinInjector {
            held: HeldInput::new(),
            frame: (1920, 1080),
            origin: (0, 0),
            screen: SINGLE,
            injected: 0,
        };
        let ev = InputEvent::Key { scan_code: 0xE04D, extended: false, action: KeyAction::Down };
        let input = inj.build(&ev, false).unwrap();
        // SAFETY: we just built this as a keyboard INPUT.
        let ki = unsafe { input.Anonymous.ki };
        assert_eq!(ki.wScan, 0x4D);
        assert!(ki.dwFlags.0 & KEYEVENTF_EXTENDEDKEY.0 != 0);
        assert!(ki.dwFlags.0 & KEYEVENTF_SCANCODE.0 != 0);
        assert!(ki.dwFlags.0 & KEYEVENTF_KEYUP.0 == 0);
    }

    #[test]
    fn wheel_delta_survives_sign() {
        let inj = WinInjector {
            held: HeldInput::new(),
            frame: (1920, 1080),
            origin: (0, 0),
            screen: SINGLE,
            injected: 0,
        };
        let ev = InputEvent::MouseWheel { delta: -120, horizontal: false, x: 0, y: 0 };
        let input = inj.build(&ev, false).unwrap();
        // SAFETY: we just built this as a mouse INPUT.
        let mi = unsafe { input.Anonymous.mi };
        assert_eq!(mi.mouseData as i32, -120);
        assert!(mi.dwFlags.0 & MOUSEEVENTF_WHEEL.0 != 0);
    }

    #[test]
    fn x_buttons_carry_the_right_mousedata() {
        let inj = WinInjector {
            held: HeldInput::new(),
            frame: (1920, 1080),
            origin: (0, 0),
            screen: SINGLE,
            injected: 0,
        };
        for (btn, want) in [(MouseButton::X1, XBUTTON1 as u32), (MouseButton::X2, XBUTTON2 as u32)] {
            let ev = InputEvent::MouseButton { button: btn, action: KeyAction::Down, x: 0, y: 0 };
            let input = inj.build(&ev, false).unwrap();
            // SAFETY: we just built this as a mouse INPUT.
            let mi = unsafe { input.Anonymous.mi };
            assert_eq!(mi.mouseData, want);
            assert!(mi.dwFlags.0 & MOUSEEVENTF_XDOWN.0 != 0);
        }
    }
}
