//! Local input capture and forwarding.
//!
//! Two independent paths, deliberately:
//!
//! * **Keyboard** — a global `WH_KEYBOARD_LL` hook, active only while capture
//!   is on. It swallows keys locally and forwards raw scan codes, so Win, and
//!   Alt+Tab act on the REMOTE machine. The release chord
//!   [`RELEASE_CHORD`] is checked *first* and always wins.
//! * **Mouse** — egui pointer events over the video rect. No global mouse hook:
//!   the pointer must stay usable for the local toolbar, and normalizing from
//!   the drawn rect is the only way the math can agree with the pixels.
//!
//! Coordinates are normalized with [`directdesk_shared::geometry::to_norm`]
//! against the CURRENT remote frame dimensions, never the local window size.
//!
//! The hook lives on its own thread with a dedicated `GetMessage` pump.
//! Windows dispatches `WH_KEYBOARD_LL` callbacks on the installing thread, and
//! silently removes any hook that fails to answer within
//! `LowLevelHooksTimeout` (300 ms) — so it must never share a thread with
//! rendering. Teardown is RAII all the way down, meaning focus loss, minimize,
//! window close, and unwinding panics all release capture.
//!
//! KNOWN GAP: on the development machine the hook installs successfully but is
//! never invoked, even for input this process injects into itself, so the
//! keyboard forwarding path is unverified end to end. See `hook_calls` in the
//! diagnostics counters — it stays at 0 there.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use directdesk_shared::geometry::to_norm;
use directdesk_shared::input::{InputEvent, KeyAction, MouseButton};
use directdesk_shared::protocol::InputMsg;
use parking_lot::Mutex;
use tokio::sync::mpsc;

use crate::renderer::VideoView;
use crate::session::send_input;

/// Human-readable chord shown on the capture toggle.
pub const RELEASE_CHORD: &str = "Ctrl+Alt+Shift+F12";

/// Mouse-move send rate cap. Moves ride unreliable datagrams, so sending more
/// than this is pure waste — a newer position always supersedes an older one.
pub const MOUSE_MOVE_HZ: u32 = 250;

// ---------------------------------------------------------------------------
// Scan codes (hardware, layout-independent — the wire format uses these)
// ---------------------------------------------------------------------------

const SC_CTRL: u16 = 0x1D; // extended flag distinguishes right ctrl
const SC_LSHIFT: u16 = 0x2A;
const SC_RSHIFT: u16 = 0x36;
const SC_ALT: u16 = 0x38; // extended flag distinguishes right alt / AltGr
const SC_F12: u16 = 0x58;

// ---------------------------------------------------------------------------
// Release chord state machine (pure logic — unit tested)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChordOutcome {
    /// Forward to the host and swallow locally (normal captured key).
    Forward,
    /// Swallow locally, forward nothing (chord residue).
    Swallow,
    /// Chord completed: drop capture now.
    Release,
}

/// Tracks modifier state purely from the hook's own event stream, so it can
/// never disagree with what we forwarded to the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ChordState {
    ctrl: bool,
    alt: bool,
    shift: bool,
    /// Chord fired; swallow the matching key-up so it cannot leak locally.
    armed: bool,
}

impl ChordState {
    pub const fn new() -> Self {
        Self {
            ctrl: false,
            alt: false,
            shift: false,
            armed: false,
        }
    }

    /// Called on capture start/stop — physical modifier state is unknown then.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    pub fn modifiers(&self) -> (bool, bool, bool) {
        (self.ctrl, self.alt, self.shift)
    }

    /// Feed one hook event. Modifier keys are tracked *and* forwarded, because
    /// the remote needs them; only the chord's trigger key is withheld.
    pub fn on_key(&mut self, scan_code: u16, extended: bool, down: bool) -> ChordOutcome {
        match (scan_code, extended) {
            (SC_CTRL, _) => self.ctrl = down,
            (SC_ALT, _) => self.alt = down,
            (SC_LSHIFT, _) | (SC_RSHIFT, _) => self.shift = down,
            (SC_F12, false) => {
                if down {
                    if self.ctrl && self.alt && self.shift {
                        self.armed = true;
                        return ChordOutcome::Release;
                    }
                } else if self.armed {
                    self.armed = false;
                    return ChordOutcome::Swallow;
                }
            }
            _ => {}
        }
        ChordOutcome::Forward
    }
}

// ---------------------------------------------------------------------------
// Mouse-move coalescing slot (pure logic — unit tested)
// ---------------------------------------------------------------------------

/// Latest-wins slot for mouse moves with a send-rate cap.
///
/// Semantics: `push` always overwrites; a position withheld by the rate cap
/// stays pending and is emitted at the next opportunity, so the host always
/// converges on the true cursor position.
#[derive(Debug)]
pub struct MoveCoalescer {
    pending: Option<(u16, u16)>,
    last_emit: Option<Instant>,
    min_interval: Duration,
    coalesced: u64,
    emitted: u64,
}

impl MoveCoalescer {
    pub fn new(max_hz: u32) -> Self {
        let hz = max_hz.max(1);
        Self {
            pending: None,
            last_emit: None,
            min_interval: Duration::from_nanos(1_000_000_000 / hz as u64),
            coalesced: 0,
            emitted: 0,
        }
    }

    pub fn push(&mut self, x: u16, y: u16) {
        if self.pending.replace((x, y)).is_some() {
            self.coalesced += 1;
        }
    }

    /// Emit the pending position if the rate cap allows it.
    pub fn take_due(&mut self, now: Instant) -> Option<(u16, u16)> {
        let due = match self.last_emit {
            None => true,
            Some(prev) => now.saturating_duration_since(prev) >= self.min_interval,
        };
        if !due {
            return None;
        }
        let value = self.pending.take()?;
        self.last_emit = Some(now);
        self.emitted += 1;
        Some(value)
    }

    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// Positions superseded before they were ever sent.
    pub fn coalesced_count(&self) -> u64 {
        self.coalesced
    }

    pub fn emitted_count(&self) -> u64 {
        self.emitted
    }

    pub fn clear(&mut self) {
        self.pending = None;
    }
}

// ---------------------------------------------------------------------------
// Pointer mapping (pure logic — unit tested)
// ---------------------------------------------------------------------------

fn pixel_of(pos: egui::Pos2, view: &VideoView) -> Option<(i64, i64)> {
    if view.rect.width() <= 0.0
        || view.rect.height() <= 0.0
        || view.remote_w == 0
        || view.remote_h == 0
        || !pos.x.is_finite()
        || !pos.y.is_finite()
    {
        return None;
    }
    let fx = (pos.x - view.rect.min.x) / view.rect.width();
    let fy = (pos.y - view.rect.min.y) / view.rect.height();
    Some((
        (fx * view.remote_w as f32).floor() as i64,
        (fy * view.remote_h as f32).floor() as i64,
    ))
}

/// Strict mapping: `None` when the point is in the letterbox margin (or off the
/// view entirely). Used to gate button-DOWN and wheel — a click on the black
/// bar is not a click on the remote desktop.
pub fn map_pointer(pos: egui::Pos2, view: &VideoView) -> Option<(u16, u16)> {
    let (px, py) = pixel_of(pos, view)?;
    if px < 0 || py < 0 || px >= view.remote_w as i64 || py >= view.remote_h as i64 {
        return None;
    }
    Some((
        to_norm(px as u32, view.remote_w),
        to_norm(py as u32, view.remote_h),
    ))
}

/// Clamped mapping: pins to the nearest edge pixel. Used for moves and for
/// button-UP, so a drag that wanders into the margin still tracks and always
/// releases instead of leaving a stuck button on the host.
pub fn map_pointer_clamped(pos: egui::Pos2, view: &VideoView) -> Option<(u16, u16)> {
    let (px, py) = pixel_of(pos, view)?;
    let px = px.clamp(0, view.remote_w as i64 - 1) as u32;
    let py = py.clamp(0, view.remote_h as i64 - 1) as u32;
    Some((to_norm(px, view.remote_w), to_norm(py, view.remote_h)))
}

pub fn map_button(button: egui::PointerButton) -> Option<MouseButton> {
    Some(match button {
        egui::PointerButton::Primary => MouseButton::Left,
        egui::PointerButton::Secondary => MouseButton::Right,
        egui::PointerButton::Middle => MouseButton::Middle,
        egui::PointerButton::Extra1 => MouseButton::X1,
        egui::PointerButton::Extra2 => MouseButton::X2,
    })
}

/// Convert an egui scroll amount to Windows WHEEL_DELTA units (120 = one
/// notch), clamped to what `validate_event` accepts.
pub fn wheel_delta(unit: egui::MouseWheelUnit, amount: f32) -> i16 {
    if !amount.is_finite() {
        return 0;
    }
    let raw = match unit {
        egui::MouseWheelUnit::Line => amount * 120.0,
        // Pixel scrolling (precision touchpads): ~40 px per notch.
        egui::MouseWheelUnit::Point => amount * 3.0,
        egui::MouseWheelUnit::Page => amount * 360.0,
    };
    raw.clamp(-3840.0, 3840.0) as i16
}

/// Map an egui logical/physical key to a US Set-1 hardware scan code and its
/// extended flag — the wire format the host injects with `KEYEVENTF_SCANCODE`.
/// Returns `None` for keys egui does not model (skipped). The nav cluster and
/// arrows are `extended` (E0-prefixed). Layout note: we send the physical key's
/// scan code and synthesize modifiers, so the host reproduces the same glyph.
pub fn egui_key_to_scancode(key: egui::Key) -> Option<(u16, bool)> {
    use egui::Key::*;
    let sc: (u16, bool) = match key {
        // Letters
        A => (0x1E, false), B => (0x30, false), C => (0x2E, false), D => (0x20, false),
        E => (0x12, false), F => (0x21, false), G => (0x22, false), H => (0x23, false),
        I => (0x17, false), J => (0x24, false), K => (0x25, false), L => (0x26, false),
        M => (0x32, false), N => (0x31, false), O => (0x18, false), P => (0x19, false),
        Q => (0x10, false), R => (0x13, false), S => (0x1F, false), T => (0x14, false),
        U => (0x16, false), V => (0x2F, false), W => (0x11, false), X => (0x2D, false),
        Y => (0x15, false), Z => (0x2C, false),
        // Number row
        Num1 => (0x02, false), Num2 => (0x03, false), Num3 => (0x04, false),
        Num4 => (0x05, false), Num5 => (0x06, false), Num6 => (0x07, false),
        Num7 => (0x08, false), Num8 => (0x09, false), Num9 => (0x0A, false),
        Num0 => (0x0B, false),
        // Editing / whitespace
        Enter => (0x1C, false), Escape => (0x01, false), Backspace => (0x0E, false),
        Tab => (0x0F, false), Space => (0x39, false),
        // Punctuation
        Minus => (0x0C, false), Equals => (0x0D, false),
        OpenBracket => (0x1A, false), CloseBracket => (0x1B, false),
        Backslash => (0x2B, false), Semicolon => (0x27, false), Quote => (0x28, false),
        Backtick => (0x29, false), Comma => (0x33, false), Period => (0x34, false),
        Slash => (0x35, false),
        // Nav cluster + arrows (extended)
        Insert => (0x52, true), Delete => (0x53, true), Home => (0x47, true),
        End => (0x4F, true), PageUp => (0x49, true), PageDown => (0x51, true),
        ArrowUp => (0x48, true), ArrowLeft => (0x4B, true),
        ArrowRight => (0x4D, true), ArrowDown => (0x50, true),
        // Function keys
        F1 => (0x3B, false), F2 => (0x3C, false), F3 => (0x3D, false), F4 => (0x3E, false),
        F5 => (0x3F, false), F6 => (0x40, false), F7 => (0x41, false), F8 => (0x42, false),
        F9 => (0x43, false), F10 => (0x44, false), F11 => (0x57, false), F12 => (0x58, false),
        _ => return None,
    };
    Some(sc)
}

// ---------------------------------------------------------------------------
// Global hook state
// ---------------------------------------------------------------------------

struct HookState {
    tx: Option<mpsc::Sender<InputMsg>>,
    chord: ChordState,
}

static HOOK_STATE: Mutex<HookState> = Mutex::new(HookState {
    tx: None,
    chord: ChordState::new(),
});
static CAPTURING: AtomicBool = AtomicBool::new(false);
static RELEASE_REQUESTED: AtomicBool = AtomicBool::new(false);
static KEYS_FORWARDED: AtomicU64 = AtomicU64::new(0);
static KEYS_SWALLOWED: AtomicU64 = AtomicU64::new(0);
/// Every HC_ACTION the hook saw. Distinguishes "hook never fired" from
/// "hook fired but the event was filtered" when diagnosing capture.
static HOOK_CALLS: AtomicU64 = AtomicU64::new(0);
/// Set by the hook thread when `SetWindowsHookExW` fails, since installation
/// happens asynchronously on that thread.
static HOOK_INSTALL_ERROR: Mutex<Option<String>> = Mutex::new(None);

/// True while the DirectDesk window is the foreground/focused window. When set,
/// the low-level hook stops forwarding+swallowing and passes keys through, so
/// egui receives them and the focused-window path ([`InputCapture::on_key_event`])
/// handles capture instead. This routes around Windows withholding low-level-hook
/// delivery from our own GPU-heavy foreground window (observed as `hook_calls`
/// frozen at 0 while focused). Background capture still uses the hook.
static WINDOW_FOREGROUND: AtomicBool = AtomicBool::new(false);

/// Process-wide enqueue count (keys placed on the outbound channel by the hook),
/// readable without the capture handle so the net supervisor can log it beside
/// the transmit-side count for starvation diagnosis.
pub fn keys_forwarded_total() -> u64 {
    KEYS_FORWARDED.load(Ordering::Relaxed)
}

#[cfg(windows)]
mod hook {
    use super::*;
    use windows::Win32::Foundation::{HINSTANCE, LPARAM, LRESULT, WPARAM};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::System::Threading::GetCurrentThreadId;
    use windows::Win32::UI::WindowsAndMessaging::{
        CallNextHookEx, GetMessageW, PeekMessageW, PostThreadMessageW, SetWindowsHookExW,
        UnhookWindowsHookEx, HC_ACTION, HHOOK, KBDLLHOOKSTRUCT, LLKHF_EXTENDED, MSG, PM_NOREMOVE,
        WH_KEYBOARD_LL, WM_APP, WM_KEYDOWN, WM_QUIT, WM_SYSKEYDOWN, WM_USER,
    };

    /// RAII owner of the installed hook. Dropping it always releases capture —
    /// including while unwinding from a panic.
    pub struct HookHandle(HHOOK);

    impl Drop for HookHandle {
        fn drop(&mut self) {
            CAPTURING.store(false, Ordering::SeqCst);
            // SAFETY: `self.0` came from a successful SetWindowsHookExW on this
            // thread and is unhooked exactly once (Drop runs once).
            if let Err(e) = unsafe { UnhookWindowsHookEx(self.0) } {
                tracing::warn!("UnhookWindowsHookEx failed: {e}");
            } else {
                tracing::info!("keyboard hook removed");
            }
            HOOK_STATE.lock().chord.reset();
        }
    }

    /// Install the low-level keyboard hook on the CURRENT thread.
    ///
    /// The caller MUST be a thread running a `GetMessage` pump: Windows
    /// delivers `WH_KEYBOARD_LL` callbacks by waking the installing thread's
    /// message queue. See [`HookThread`] — the winit/eframe thread is not
    /// suitable, both because its pump is not guaranteed to service the hook
    /// and because a render stall longer than `LowLevelHooksTimeout` makes
    /// Windows silently drop the hook.
    fn install_on_this_thread() -> anyhow::Result<HookHandle> {
        // SAFETY: standard Win32 hook installation. `keyboard_proc` is a
        // `'static` fn; the module handle is the running exe.
        // hMod: MSDN says it must be NULL when the hook procedure lives in the
        // calling process. Some environments reject a non-NULL EXE handle here
        // by installing the hook but never invoking it, so try NULL first and
        // fall back to the module handle.
        let hook = unsafe {
            match SetWindowsHookExW(WH_KEYBOARD_LL, Some(keyboard_proc), None, 0) {
                Ok(h) => {
                    tracing::debug!("keyboard hook installed via NULL module handle");
                    h
                }
                Err(e) => {
                    tracing::warn!(
                        "SetWindowsHookExW(hMod=NULL) failed ({e}); retrying with module handle"
                    );
                    let hmod = GetModuleHandleW(None)?;
                    SetWindowsHookExW(
                        WH_KEYBOARD_LL,
                        Some(keyboard_proc),
                        Some(HINSTANCE(hmod.0)),
                        0,
                    )?
                }
            }
        };
        HOOK_STATE.lock().chord.reset();
        RELEASE_REQUESTED.store(false, Ordering::SeqCst);
        CAPTURING.store(true, Ordering::SeqCst);
        tracing::info!("keyboard hook installed — release with {RELEASE_CHORD}");
        Ok(HookHandle(hook))
    }

    /// A dedicated thread whose only job is to own the keyboard hook and pump
    /// its messages.
    ///
    /// This exists for two reasons, both of which bit us in testing:
    ///
    /// 1. `WH_KEYBOARD_LL` callbacks are dispatched on the installing thread
    ///    during message retrieval. winit's event loop did not service them.
    /// 2. If a low-level hook does not return within `LowLevelHooksTimeout`
    ///    (300 ms by default), Windows removes it **silently**. Tying the hook
    ///    to the render thread would mean one long GPU stall kills capture.
    ///
    /// A tight `GetMessage` loop that does nothing else cannot be starved.
    pub struct HookThread {
        thread_id: u32,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    const MSG_INSTALL: u32 = WM_APP + 1;
    const MSG_UNINSTALL: u32 = WM_APP + 2;

    impl HookThread {
        pub fn start() -> anyhow::Result<Self> {
            let (ready_tx, ready_rx) = std::sync::mpsc::channel::<u32>();
            let handle = std::thread::Builder::new()
                .name("directdesk-hook".into())
                .spawn(move || {
                    // WH_KEYBOARD_LL callbacks are dispatched on this thread
                    // during message retrieval; if it is not serviced within
                    // LowLevelHooksTimeout (300 ms) Windows silently stops
                    // delivering keys (seen as hook_calls frozen at 0 while the
                    // client renders video hard). Top priority keeps the pump
                    // ahead of decode/render so key delivery never lapses.
                    // SAFETY: GetCurrentThread is a pseudo-handle to this thread;
                    // setting priority is a side-effect-free scheduler hint.
                    unsafe {
                        use windows::Win32::System::Threading::{
                            GetCurrentThread, SetThreadPriority, THREAD_PRIORITY_TIME_CRITICAL,
                        };
                        if let Err(e) =
                            SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL)
                        {
                            tracing::warn!("could not raise hook-thread priority: {e}");
                        }
                    }
                    // Force the OS to create this thread's message queue before
                    // anyone posts to it, otherwise the first post is lost.
                    // SAFETY: PeekMessage on our own (empty) queue.
                    unsafe {
                        let mut msg = MSG::default();
                        let _ = PeekMessageW(&mut msg, None, WM_USER, WM_USER, PM_NOREMOVE);
                    }
                    // SAFETY: no preconditions.
                    let id = unsafe { GetCurrentThreadId() };
                    if ready_tx.send(id).is_err() {
                        return;
                    }
                    pump();
                })
                .map_err(|e| anyhow::anyhow!("spawn hook thread: {e}"))?;

            let thread_id = ready_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .map_err(|e| anyhow::anyhow!("hook thread did not start: {e}"))?;
            Ok(Self {
                thread_id,
                handle: Some(handle),
            })
        }

        pub fn install(&self) {
            self.post(MSG_INSTALL);
        }

        pub fn uninstall(&self) {
            self.post(MSG_UNINSTALL);
        }

        fn post(&self, message: u32) {
            // SAFETY: posting to a thread id we own; the thread has a queue.
            if let Err(e) =
                unsafe { PostThreadMessageW(self.thread_id, message, WPARAM(0), LPARAM(0)) }
            {
                tracing::error!("PostThreadMessage({message}) to hook thread failed: {e}");
            }
        }
    }

    impl Drop for HookThread {
        fn drop(&mut self) {
            // WM_QUIT ends the pump, whose own cleanup unhooks. Even if that
            // failed, Windows removes hooks owned by an exiting thread.
            self.post(WM_QUIT);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
            CAPTURING.store(false, Ordering::SeqCst);
        }
    }

    /// Inject one keystroke into this process's own input stream.
    ///
    /// Test aid only: it lets `--capture-on-start` prove the hook is live
    /// without depending on another process being allowed to inject.
    pub fn inject_test_key(scan_code: u16) {
        use windows::Win32::UI::Input::KeyboardAndMouse::{
            SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_KEYUP,
            KEYEVENTF_SCANCODE,
        };
        let mk = |up: bool| INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: Default::default(),
                    wScan: scan_code,
                    dwFlags: if up {
                        KEYEVENTF_SCANCODE | KEYEVENTF_KEYUP
                    } else {
                        KEYEVENTF_SCANCODE
                    },
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        let events = [mk(false), mk(true)];
        // SAFETY: a correctly sized, fully initialized INPUT array.
        let sent = unsafe { SendInput(&events, std::mem::size_of::<INPUT>() as i32) };
        tracing::info!(scan_code, sent, "self-injected test keystroke");
    }

    /// The hook thread's message loop. Owns the `HookHandle` for its lifetime.
    fn pump() {
        let mut installed: Option<HookHandle> = None;
        let mut msg = MSG::default();
        loop {
            // SAFETY: standard blocking message retrieval on our own thread.
            let got = unsafe { GetMessageW(&mut msg, None, 0, 0) };
            if got.0 <= 0 {
                // 0 = WM_QUIT, -1 = error. Either way we are done.
                if got.0 < 0 {
                    tracing::error!("hook thread GetMessage failed");
                }
                break;
            }
            match msg.message {
                // Already installed: installing twice would leak a hook.
                MSG_INSTALL if installed.is_none() => match install_on_this_thread() {
                    Ok(h) => installed = Some(h),
                    Err(e) => {
                        tracing::error!("could not install keyboard hook: {e}");
                        *HOOK_INSTALL_ERROR.lock() = Some(e.to_string());
                        CAPTURING.store(false, Ordering::SeqCst);
                    }
                },
                MSG_UNINSTALL => {
                    CAPTURING.store(false, Ordering::SeqCst);
                    installed = None; // Drop unhooks
                }
                _ => {}
            }
        }
        drop(installed);
        CAPTURING.store(false, Ordering::SeqCst);
        tracing::debug!("hook thread exiting");
    }

    unsafe extern "system" fn keyboard_proc(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
        // Counted before any filtering so "hook never called" and "hook called
        // but event ignored" are distinguishable in the logs.
        HOOK_CALLS.fetch_add(1, Ordering::Relaxed);
        // When our window is foreground, the egui `on_key_event` path owns
        // capture; pass keys through so egui sees them and we never double-send.
        if code == HC_ACTION as i32
            && CAPTURING.load(Ordering::Relaxed)
            && !WINDOW_FOREGROUND.load(Ordering::Relaxed)
        {
            // A panic here would unwind across an FFI boundary (UB / abort), so
            // it is contained. On panic we fall through to CallNextHookEx,
            // which is the fail-open, never-lock-the-keyboard behaviour.
            let handled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                // SAFETY: for HC_ACTION the OS guarantees lparam points at a
                // valid KBDLLHOOKSTRUCT for the duration of this call.
                let kb = unsafe { &*(lparam.0 as *const KBDLLHOOKSTRUCT) };
                handle_key(
                    kb.scanCode as u16,
                    kb.flags.contains(LLKHF_EXTENDED),
                    matches!(wparam.0 as u32, WM_KEYDOWN | WM_SYSKEYDOWN),
                )
            }));
            if matches!(handled, Ok(true)) {
                return LRESULT(1); // swallow locally: this key is the host's
            }
        }
        // SAFETY: forwarding to the next hook in the chain with our own args.
        unsafe { CallNextHookEx(None, code, wparam, lparam) }
    }

    /// Returns true if the key must be swallowed locally.
    fn handle_key(scan_code: u16, extended: bool, down: bool) -> bool {
        let mut state = HOOK_STATE.lock();
        if state.tx.is_none() {
            tracing::error!("keyboard hook fired with no input channel — key dropped");
        }
        match state.chord.on_key(scan_code, extended, down) {
            ChordOutcome::Release => {
                // Stop forwarding immediately; the app tears the hook down on
                // its next frame (Drop cannot run from inside the hook proc).
                CAPTURING.store(false, Ordering::SeqCst);
                RELEASE_REQUESTED.store(true, Ordering::SeqCst);
                if let Some(tx) = state.tx.as_ref() {
                    let _ = tx.try_send(InputMsg::ReleaseAll);
                }
                true
            }
            ChordOutcome::Swallow => true,
            ChordOutcome::Forward => {
                // `validate_event` rejects 0 and >0xFF; filter here so we never
                // put an invalid event on the wire.
                if scan_code != 0 && scan_code <= 0xFF {
                    let ev = InputEvent::Key {
                        scan_code,
                        extended,
                        action: if down { KeyAction::Down } else { KeyAction::Up },
                    };
                    if let Some(tx) = state.tx.as_ref() {
                        if tx.try_send(InputMsg::Event(ev)).is_ok() {
                            KEYS_FORWARDED.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                } else {
                    KEYS_SWALLOWED.fetch_add(1, Ordering::Relaxed);
                }
                true
            }
        }
    }
}

#[cfg(not(windows))]
mod hook {
    use super::*;

    pub struct HookThread;

    impl HookThread {
        pub fn start() -> anyhow::Result<Self> {
            anyhow::bail!("keyboard capture requires Windows")
        }
        pub fn install(&self) {}
        pub fn uninstall(&self) {}
    }

    impl Drop for HookThread {
        fn drop(&mut self) {
            CAPTURING.store(false, Ordering::SeqCst);
        }
    }
}

/// Test aid: inject a keystroke into this process. Windows only.
#[cfg(windows)]
pub use hook::inject_test_key;

// ---------------------------------------------------------------------------
// Facade used by the UI
// ---------------------------------------------------------------------------

/// Owns capture state for the app.
///
/// The hook itself lives on its own thread (see `hook::HookThread`), so this
/// type can be used from the UI thread without constraining it.
pub struct InputCapture {
    tx: mpsc::Sender<InputMsg>,
    hook: Option<hook::HookThread>,
    /// What the user asked for. Drives the UI, and is authoritative for
    /// toggling, because hook installation is asynchronous.
    capture_requested: bool,
    moves: MoveCoalescer,
    buttons_held: u32,
    last_error: Option<String>,
    /// Modifier state last mirrored to the host from the egui key path. egui
    /// reports modifier *state* (not Shift/Ctrl/Alt key events), so we diff
    /// against this and synthesize modifier scan codes on transitions.
    tracked_shift: bool,
    tracked_ctrl: bool,
    tracked_alt: bool,
}

impl InputCapture {
    pub fn new(tx: mpsc::Sender<InputMsg>) -> Self {
        HOOK_STATE.lock().tx = Some(tx.clone());
        Self {
            tx,
            hook: None,
            capture_requested: false,
            moves: MoveCoalescer::new(MOUSE_MOVE_HZ),
            buttons_held: 0,
            last_error: None,
            tracked_shift: false,
            tracked_ctrl: false,
            tracked_alt: false,
        }
    }

    /// Track the window's foreground state. When focused, the egui key path
    /// owns capture and the low-level hook passes through (see
    /// [`WINDOW_FOREGROUND`]). On losing focus, release any modifier we
    /// synthesized so nothing sticks down on the host.
    pub fn set_window_foreground(&mut self, focused: bool) {
        let was = WINDOW_FOREGROUND.swap(focused, Ordering::SeqCst);
        if was && !focused {
            self.release_synth_mods();
        }
    }

    /// Focused-window keyboard capture (mirrors the mouse egui path). Maps the
    /// key to a scan code, synthesizes modifier scan codes from egui's modifier
    /// state, and forwards `InputEvent::Key`. Only used while the window is the
    /// foreground window, where the global hook is unreliable.
    pub fn on_key_event(
        &mut self,
        physical_key: Option<egui::Key>,
        logical_key: egui::Key,
        pressed: bool,
        modifiers: egui::Modifiers,
    ) {
        let key = physical_key.unwrap_or(logical_key);

        // Release chord parity (the hook path is inactive while focused).
        if pressed
            && modifiers.ctrl
            && modifiers.alt
            && modifiers.shift
            && matches!(key, egui::Key::F12)
        {
            RELEASE_REQUESTED.store(true, Ordering::SeqCst);
            return;
        }

        // Mirror modifier transitions to the host before the key so capitals
        // and Ctrl/Alt combos reproduce. A lone modifier release (no egui key
        // event) is corrected on the next key press, and on focus loss.
        if modifiers.shift != self.tracked_shift {
            self.tracked_shift = modifiers.shift;
            self.send_scan(SC_LSHIFT, false, modifiers.shift);
        }
        if modifiers.ctrl != self.tracked_ctrl {
            self.tracked_ctrl = modifiers.ctrl;
            self.send_scan(SC_CTRL, false, modifiers.ctrl);
        }
        if modifiers.alt != self.tracked_alt {
            self.tracked_alt = modifiers.alt;
            self.send_scan(SC_ALT, false, modifiers.alt);
        }

        if let Some((scan, extended)) = egui_key_to_scancode(key) {
            self.send_scan(scan, extended, pressed);
        }
    }

    /// Send one raw scan-code key event and count it like the hook path does.
    fn send_scan(&self, scan_code: u16, extended: bool, down: bool) {
        if scan_code == 0 || scan_code > 0xFF {
            return;
        }
        let ok = send_input(
            &self.tx,
            InputMsg::Event(InputEvent::Key {
                scan_code,
                extended,
                action: if down { KeyAction::Down } else { KeyAction::Up },
            }),
        );
        if ok {
            KEYS_FORWARDED.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Release any modifier the egui path is holding down on the host.
    fn release_synth_mods(&mut self) {
        if self.tracked_shift {
            self.tracked_shift = false;
            self.send_scan(SC_LSHIFT, false, false);
        }
        if self.tracked_ctrl {
            self.tracked_ctrl = false;
            self.send_scan(SC_CTRL, false, false);
        }
        if self.tracked_alt {
            self.tracked_alt = false;
            self.send_scan(SC_ALT, false, false);
        }
    }

    pub fn is_capturing(&self) -> bool {
        self.capture_requested
    }

    /// True once the OS has actually installed the hook (a few ms after
    /// [`Self::start_capture`]).
    pub fn hook_active(&self) -> bool {
        CAPTURING.load(Ordering::Relaxed)
    }

    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    /// Ask the hook thread to install the keyboard hook. Idempotent.
    pub fn start_capture(&mut self) {
        if self.capture_requested {
            return;
        }
        if self.hook.is_none() {
            match hook::HookThread::start() {
                Ok(thread) => self.hook = Some(thread),
                Err(e) => {
                    tracing::error!("could not start hook thread: {e}");
                    self.last_error = Some(e.to_string());
                    return;
                }
            }
        }
        *HOOK_INSTALL_ERROR.lock() = None;
        self.last_error = None;
        RELEASE_REQUESTED.store(false, Ordering::SeqCst);
        HOOK_STATE.lock().chord.reset();
        self.capture_requested = true;
        if let Some(thread) = &self.hook {
            thread.install();
        }
    }

    /// Remove the hook and tell the host to drop everything held. Idempotent.
    pub fn stop_capture(&mut self) {
        RELEASE_REQUESTED.store(false, Ordering::SeqCst);
        if !self.capture_requested {
            return;
        }
        self.capture_requested = false;
        CAPTURING.store(false, Ordering::SeqCst);
        if let Some(thread) = &self.hook {
            thread.uninstall();
        }
        self.release_all();
    }

    pub fn toggle_capture(&mut self) {
        if self.is_capturing() {
            self.stop_capture();
        } else {
            self.start_capture();
        }
    }

    /// Emit `ReleaseAll` and clear local pointer/coalescer state.
    pub fn release_all(&mut self) {
        self.moves.clear();
        self.buttons_held = 0;
        // The host's ReleaseAll drops every held key, so just forget our
        // synthesized-modifier state (don't send individual ups after it).
        self.tracked_shift = false;
        self.tracked_ctrl = false;
        self.tracked_alt = false;
        send_input(&self.tx, InputMsg::ReleaseAll);
        tracing::debug!("sent ReleaseAll");
    }

    /// Poll for asynchronous capture-loss: the release chord firing inside the
    /// hook, or the hook thread failing to install. Returns true once per event.
    pub fn poll_chord_release(&mut self) -> bool {
        if RELEASE_REQUESTED.swap(false, Ordering::SeqCst) {
            tracing::info!("{RELEASE_CHORD} pressed — capture released");
            self.capture_requested = false;
            if let Some(thread) = &self.hook {
                thread.uninstall();
            }
            // The hook already emitted ReleaseAll; just clear local state.
            self.moves.clear();
            self.buttons_held = 0;
            return true;
        }
        if self.capture_requested {
            if let Some(err) = HOOK_INSTALL_ERROR.lock().take() {
                tracing::error!("keyboard hook install failed: {err}");
                self.last_error = Some(err);
                self.capture_requested = false;
                return true;
            }
        }
        false
    }

    /// Queue a pointer position (coalesced, rate-capped).
    pub fn on_pointer_moved(&mut self, pos: egui::Pos2, view: &VideoView) {
        if let Some((x, y)) = map_pointer_clamped(pos, view) {
            self.moves.push(x, y);
        }
    }

    /// Forward a button press/release. Presses in the letterbox margin are
    /// ignored; releases are always delivered (clamped) so nothing sticks.
    pub fn on_pointer_button(
        &mut self,
        pos: egui::Pos2,
        view: &VideoView,
        button: egui::PointerButton,
        pressed: bool,
    ) {
        let Some(button) = map_button(button) else {
            return;
        };
        let mapped = if pressed {
            map_pointer(pos, view)
        } else {
            map_pointer_clamped(pos, view)
        };
        let Some((x, y)) = mapped else { return };

        // A button event carries its own position; flush any pending move first
        // so the host never sees the click land at a stale coordinate.
        self.flush_move_now(x, y);

        if pressed {
            self.buttons_held += 1;
        } else {
            self.buttons_held = self.buttons_held.saturating_sub(1);
        }
        send_input(
            &self.tx,
            InputMsg::Event(InputEvent::MouseButton {
                button,
                action: if pressed {
                    KeyAction::Down
                } else {
                    KeyAction::Up
                },
                x,
                y,
            }),
        );
    }

    pub fn on_wheel(&mut self, pos: egui::Pos2, view: &VideoView, delta: i16, horizontal: bool) {
        if delta == 0 {
            return;
        }
        let Some((x, y)) = map_pointer(pos, view) else {
            return;
        };
        send_input(
            &self.tx,
            InputMsg::Event(InputEvent::MouseWheel {
                delta,
                horizontal,
                x,
                y,
            }),
        );
    }

    /// Send `(x, y)` immediately, bypassing the rate cap.
    ///
    /// The cap exists to thin out continuous motion; a click must never land
    /// at a stale coordinate on the host. Any coalesced move still pending is
    /// dropped, because this position supersedes it.
    fn flush_move_now(&mut self, x: u16, y: u16) {
        self.moves.clear();
        send_input(&self.tx, InputMsg::Event(InputEvent::MouseMove { x, y }));
    }

    /// Drain the coalescing slot. Call once per UI frame.
    pub fn pump(&mut self) {
        if let Some((x, y)) = self.moves.take_due(Instant::now()) {
            send_input(&self.tx, InputMsg::Event(InputEvent::MouseMove { x, y }));
        }
    }

    pub fn keys_forwarded(&self) -> u64 {
        KEYS_FORWARDED.load(Ordering::Relaxed)
    }

    /// Hook invocations seen. Zero while capturing means the hook is installed
    /// but the OS is not delivering events to it.
    pub fn hook_calls(&self) -> u64 {
        HOOK_CALLS.load(Ordering::Relaxed)
    }

    pub fn moves_sent(&self) -> u64 {
        self.moves.emitted_count()
    }

    pub fn moves_coalesced(&self) -> u64 {
        self.moves.coalesced_count()
    }

    pub fn has_pending_move(&self) -> bool {
        self.moves.has_pending()
    }
}

impl Drop for InputCapture {
    fn drop(&mut self) {
        // Guarantees the hook is gone even on an unwinding shutdown: dropping
        // the thread posts WM_QUIT and joins, and the pump unhooks on the way
        // out. Windows would also drop hooks owned by an exiting thread.
        self.capture_requested = false;
        self.hook = None;
        HOOK_STATE.lock().tx = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use directdesk_shared::geometry::fit_rect;

    // -- chord ------------------------------------------------------------

    fn press(c: &mut ChordState, scan: u16, ext: bool) -> ChordOutcome {
        c.on_key(scan, ext, true)
    }
    fn release(c: &mut ChordState, scan: u16, ext: bool) -> ChordOutcome {
        c.on_key(scan, ext, false)
    }

    #[test]
    fn chord_fires_on_full_combination() {
        let mut c = ChordState::new();
        assert_eq!(press(&mut c, SC_CTRL, false), ChordOutcome::Forward);
        assert_eq!(press(&mut c, SC_ALT, false), ChordOutcome::Forward);
        assert_eq!(press(&mut c, SC_LSHIFT, false), ChordOutcome::Forward);
        assert_eq!(press(&mut c, SC_F12, false), ChordOutcome::Release);
        // The trailing key-up must be swallowed, not leaked locally.
        assert_eq!(release(&mut c, SC_F12, false), ChordOutcome::Swallow);
        // ...and only once.
        assert_eq!(release(&mut c, SC_F12, false), ChordOutcome::Forward);
    }

    #[test]
    fn chord_needs_all_three_modifiers() {
        let mut c = ChordState::new();
        press(&mut c, SC_CTRL, false);
        press(&mut c, SC_LSHIFT, false);
        assert_eq!(
            press(&mut c, SC_F12, false),
            ChordOutcome::Forward,
            "no Alt held"
        );

        let mut c = ChordState::new();
        press(&mut c, SC_ALT, false);
        press(&mut c, SC_LSHIFT, false);
        assert_eq!(
            press(&mut c, SC_F12, false),
            ChordOutcome::Forward,
            "no Ctrl held"
        );

        let mut c = ChordState::new();
        press(&mut c, SC_CTRL, false);
        press(&mut c, SC_ALT, false);
        assert_eq!(
            press(&mut c, SC_F12, false),
            ChordOutcome::Forward,
            "no Shift held"
        );
    }

    #[test]
    fn chord_accepts_right_hand_modifiers() {
        let mut c = ChordState::new();
        press(&mut c, SC_CTRL, true); // right ctrl
        press(&mut c, SC_ALT, true); // right alt
        press(&mut c, SC_RSHIFT, false); // right shift
        assert_eq!(press(&mut c, SC_F12, false), ChordOutcome::Release);
    }

    #[test]
    fn releasing_a_modifier_disarms_the_chord() {
        let mut c = ChordState::new();
        press(&mut c, SC_CTRL, false);
        press(&mut c, SC_ALT, false);
        press(&mut c, SC_LSHIFT, false);
        release(&mut c, SC_CTRL, false);
        assert_eq!(c.modifiers(), (false, true, true));
        assert_eq!(press(&mut c, SC_F12, false), ChordOutcome::Forward);
    }

    #[test]
    fn modifier_keys_are_still_forwarded_to_the_host() {
        // Ctrl/Alt/Shift must reach the remote machine — only F12 is withheld.
        let mut c = ChordState::new();
        assert_eq!(press(&mut c, SC_CTRL, false), ChordOutcome::Forward);
        assert_eq!(release(&mut c, SC_CTRL, false), ChordOutcome::Forward);
    }

    #[test]
    fn reset_clears_modifier_and_armed_state() {
        let mut c = ChordState::new();
        press(&mut c, SC_CTRL, false);
        press(&mut c, SC_ALT, false);
        press(&mut c, SC_LSHIFT, false);
        c.reset();
        assert_eq!(c.modifiers(), (false, false, false));
        assert_eq!(press(&mut c, SC_F12, false), ChordOutcome::Forward);
    }

    #[test]
    fn ordinary_keys_pass_through() {
        let mut c = ChordState::new();
        assert_eq!(press(&mut c, 0x1E, false), ChordOutcome::Forward); // 'A'
        assert_eq!(press(&mut c, 0x0F, false), ChordOutcome::Forward); // Tab
        assert_eq!(press(&mut c, 0x5B, true), ChordOutcome::Forward); // Left Win
    }

    // -- coalescer --------------------------------------------------------

    #[test]
    fn coalescer_is_latest_wins() {
        let t0 = Instant::now();
        let mut c = MoveCoalescer::new(250);
        c.push(1, 1);
        c.push(2, 2);
        c.push(3, 3);
        assert_eq!(
            c.take_due(t0),
            Some((3, 3)),
            "only the newest position survives"
        );
        assert_eq!(c.coalesced_count(), 2);
        assert!(!c.has_pending());
        assert_eq!(
            c.take_due(t0 + Duration::from_secs(1)),
            None,
            "slot is empty"
        );
    }

    #[test]
    fn coalescer_enforces_the_rate_cap() {
        let t0 = Instant::now();
        let mut c = MoveCoalescer::new(250); // 4 ms
        c.push(1, 1);
        assert_eq!(c.take_due(t0), Some((1, 1)));
        c.push(2, 2);
        assert_eq!(c.take_due(t0 + Duration::from_millis(1)), None, "too soon");
        // Withheld values are NOT lost.
        assert!(c.has_pending());
        assert_eq!(c.take_due(t0 + Duration::from_millis(4)), Some((2, 2)));
        assert_eq!(c.emitted_count(), 2);
    }

    #[test]
    fn coalescer_withheld_value_is_superseded_not_queued() {
        let t0 = Instant::now();
        let mut c = MoveCoalescer::new(250);
        c.push(1, 1);
        c.take_due(t0);
        c.push(2, 2);
        assert_eq!(c.take_due(t0 + Duration::from_millis(1)), None);
        c.push(9, 9); // arrives while (2,2) is still withheld
        assert_eq!(c.take_due(t0 + Duration::from_millis(5)), Some((9, 9)));
    }

    #[test]
    fn coalescer_clear_drops_pending() {
        let t0 = Instant::now();
        let mut c = MoveCoalescer::new(250);
        c.push(5, 5);
        c.clear();
        assert_eq!(c.take_due(t0), None);
    }

    // -- pointer mapping --------------------------------------------------

    /// 1920x1080 video inside a 1000x1000 viewport => horizontal letterbox.
    fn letterboxed_view() -> VideoView {
        let (x, y, w, h) = fit_rect(1920, 1080, 1000, 1000);
        assert!(y > 0, "test needs a real letterbox margin");
        VideoView {
            rect: egui::Rect::from_min_size(
                egui::pos2(x as f32, y as f32),
                egui::vec2(w as f32, h as f32),
            ),
            remote_w: 1920,
            remote_h: 1080,
        }
    }

    #[test]
    fn mapping_matches_fit_rect_corners() {
        let v = letterboxed_view();
        assert_eq!(map_pointer(v.rect.min, &v), Some((0, 0)));
        let inside_max = egui::pos2(v.rect.max.x - 0.5, v.rect.max.y - 0.5);
        assert_eq!(map_pointer(inside_max, &v), Some((u16::MAX, u16::MAX)));
    }

    #[test]
    fn mapping_centre_is_centre() {
        let v = letterboxed_view();
        let (x, y) = map_pointer(v.rect.center(), &v).unwrap();
        let mid = u16::MAX / 2;
        assert!(x.abs_diff(mid) < 60, "x={x}");
        assert!(y.abs_diff(mid) < 60, "y={y}");
    }

    #[test]
    fn clicks_in_the_letterbox_margin_are_ignored() {
        let v = letterboxed_view();
        // Directly above the video rect — inside the window, on the black bar.
        let above = egui::pos2(v.rect.center().x, v.rect.min.y - 1.0);
        let below = egui::pos2(v.rect.center().x, v.rect.max.y + 1.0);
        assert_eq!(map_pointer(above, &v), None);
        assert_eq!(map_pointer(below, &v), None);
    }

    #[test]
    fn moves_in_the_letterbox_margin_clamp_to_the_edge() {
        let v = letterboxed_view();
        let above = egui::pos2(v.rect.center().x, v.rect.min.y - 50.0);
        let below = egui::pos2(v.rect.center().x, v.rect.max.y + 50.0);
        assert_eq!(
            map_pointer_clamped(above, &v).unwrap().1,
            0,
            "clamps to top row"
        );
        assert_eq!(
            map_pointer_clamped(below, &v).unwrap().1,
            u16::MAX,
            "clamps to bottom row"
        );
    }

    #[test]
    fn pillarboxed_view_ignores_side_margins() {
        // 4:3 remote inside a 16:9 window => vertical bars on the left/right.
        let (x, y, w, h) = fit_rect(1024, 768, 1600, 900);
        assert!(x > 0);
        let v = VideoView {
            rect: egui::Rect::from_min_size(
                egui::pos2(x as f32, y as f32),
                egui::vec2(w as f32, h as f32),
            ),
            remote_w: 1024,
            remote_h: 768,
        };
        let left = egui::pos2(v.rect.min.x - 2.0, v.rect.center().y);
        assert_eq!(map_pointer(left, &v), None);
        assert_eq!(map_pointer_clamped(left, &v).unwrap().0, 0);
    }

    #[test]
    fn degenerate_view_maps_to_nothing() {
        let v = VideoView {
            rect: egui::Rect::from_min_size(egui::pos2(0.0, 0.0), egui::vec2(0.0, 0.0)),
            remote_w: 1920,
            remote_h: 1080,
        };
        assert_eq!(map_pointer(egui::pos2(0.0, 0.0), &v), None);
        assert_eq!(map_pointer_clamped(egui::pos2(0.0, 0.0), &v), None);
    }

    #[test]
    fn mapping_is_independent_of_window_size() {
        // Same relative point, two very different viewports => same wire coords.
        let mk = |dst_w: u32, dst_h: u32| {
            let (x, y, w, h) = fit_rect(1920, 1080, dst_w, dst_h);
            VideoView {
                rect: egui::Rect::from_min_size(
                    egui::pos2(x as f32, y as f32),
                    egui::vec2(w as f32, h as f32),
                ),
                remote_w: 1920,
                remote_h: 1080,
            }
        };
        let small = mk(640, 480);
        let big = mk(2560, 1440);
        let a = map_pointer(small.rect.center(), &small).unwrap();
        let b = map_pointer(big.rect.center(), &big).unwrap();
        assert!(
            a.0.abs_diff(b.0) < 200 && a.1.abs_diff(b.1) < 200,
            "{a:?} vs {b:?}"
        );
    }

    #[test]
    fn wheel_conversion_is_sane_and_valid() {
        use directdesk_shared::input::validate_event;
        assert_eq!(wheel_delta(egui::MouseWheelUnit::Line, 1.0), 120);
        assert_eq!(wheel_delta(egui::MouseWheelUnit::Line, -1.0), -120);
        assert_eq!(wheel_delta(egui::MouseWheelUnit::Line, 0.0), 0);
        assert_eq!(wheel_delta(egui::MouseWheelUnit::Line, f32::NAN), 0);
        // Absurd input must stay inside what the contract accepts.
        let big = wheel_delta(egui::MouseWheelUnit::Line, 1.0e6);
        assert!(validate_event(&InputEvent::MouseWheel {
            delta: big,
            horizontal: false,
            x: 0,
            y: 0
        })
        .is_ok());
    }

    #[test]
    fn buttons_map_onto_the_contract() {
        assert_eq!(
            map_button(egui::PointerButton::Primary),
            Some(MouseButton::Left)
        );
        assert_eq!(
            map_button(egui::PointerButton::Secondary),
            Some(MouseButton::Right)
        );
        assert_eq!(
            map_button(egui::PointerButton::Middle),
            Some(MouseButton::Middle)
        );
        assert_eq!(
            map_button(egui::PointerButton::Extra1),
            Some(MouseButton::X1)
        );
        assert_eq!(
            map_button(egui::PointerButton::Extra2),
            Some(MouseButton::X2)
        );
    }
}
