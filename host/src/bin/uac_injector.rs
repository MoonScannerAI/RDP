//! `DirectDeskUacInjector.exe` — a transient SYSTEM-integrity input worker.
//!
//! The medium-integrity host cannot click the Windows UAC consent dialog
//! (`consent.exe`, System integrity): UIPI blocks its `SendInput`. The
//! LocalSystem service spawns this worker on the console desktop as SYSTEM; it
//! injects the click as SYSTEM on the host's behalf and then goes away.
//!
//! # Contract with the service (must match exactly)
//! The service starts us with:
//! ```text
//! DirectDeskUacInjector.exe --data-pipe <pipe_name> --session <id> --user-sid <sid_string>
//! ```
//! and sets `DIRECTDESK_UAC_CAP=<32-hex>` in the environment (NOT on the command
//! line). We create the data pipe as SERVER, and the host connects to it and
//! presents that same token as the first frame.
//!
//! # Why this is safe to run as SYSTEM
//! Several independent limits keep this worker from being a general-purpose
//! SYSTEM input primitive:
//! * **Capability token** — the first frame must equal `DIRECTDESK_UAC_CAP`,
//!   compared in constant time. The pipe DACL already restricts who can connect
//!   (SYSTEM + the console user); the token proves it is *our* host.
//! * **Mouse-only** — the worker injects **mouse** events exclusively. Keyboard
//!   events are dropped. UAC approval is a mouse click on "Yes"; keyboard
//!   delivery into `consent.exe` (Enter / Alt+Y) could activate the default
//!   button, and — importantly — **remote entry of credentials into a password /
//!   "over-the-shoulder" elevation prompt is explicitly unsupported**. There is
//!   no path by which this worker types into a secure prompt.
//! * **Consent-window guardrail** — before EVERY injection we verify the
//!   foreground window's *full image path* is the real
//!   `%SystemRoot%\System32\consent.exe` (or the credential broker), not merely
//!   a process named `consent.exe`, and clamp mouse coordinates into that
//!   window's rect. Immediately before injecting we re-verify the same consent
//!   PID still owns the foreground (a narrowed TOCTOU window). A SYSTEM worker
//!   that is somehow still alive can therefore only ever click the consent
//!   dialog.
//! * **Self-expiry** — it exits (releasing all held input) on client
//!   disconnect, 30 s of input idle, or the consent window being gone for 5 s.

use std::time::{Duration, Instant};

use directdesk_host::elevation::foreground_consent_rect;
use directdesk_host::input_inject::WinInjector;
use directdesk_host::uac_proto::{
    clamp_norm_to_rect, decode_frame, tokens_match, UacWireMsg, MAX_UAC_MSG,
};
use directdesk_host::winpipe::{pcwstr, wide, Event, OwnedHandle};
use directdesk_shared::input::InputEvent;
use directdesk_shared::protocol::InputMsg;
use directdesk_shared::traits::InputInjector as _;

use windows::Win32::Foundation::{
    GetLastError, LocalFree, ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_MORE_DATA,
    ERROR_PIPE_CONNECTED, HANDLE, HLOCAL, WAIT_OBJECT_0,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TokenIntegrityLevel,
    PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
};
use windows::Win32::Storage::FileSystem::{
    ReadFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_MESSAGE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE, PIPE_WAIT,
};
use windows::Win32::System::StationsAndDesktops::{
    GetThreadDesktop, GetUserObjectInformationW, UOI_NAME,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThreadId, OpenProcessToken, WaitForSingleObject,
};
use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

/// Largest wire frame: 4-byte prefix plus the capped body.
const MAX_FRAME: usize = 4 + MAX_UAC_MSG;
/// No input for this long → the worker exits.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// The consent window gone this long → the worker exits.
const CONSENT_GONE_TIMEOUT: Duration = Duration::from_secs(5);
/// How long to wait for the host to connect after we create the pipe.
const ACCEPT_TIMEOUT_MS: u32 = 30_000;
/// How long to wait for the `Hello` frame once connected.
const HELLO_TIMEOUT_MS: u32 = 5_000;
/// Read poll slice: short enough to service the consent-gone timer.
const READ_SLICE_MS: u32 = 500;

// Exit codes (also the integration-test's contract).
const EXIT_OK: i32 = 0;
const EXIT_BAD_ARGS: i32 = 2;
const EXIT_PIPE_FAILED: i32 = 3;
const EXIT_NO_CLIENT: i32 = 4;
const EXIT_BAD_TOKEN: i32 = 5;

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    let _log = directdesk_shared::logging::init("uac_injector", None);

    let args = match Args::parse() {
        Some(a) => a,
        None => {
            tracing::error!(
                "usage: DirectDeskUacInjector --data-pipe <name> --session <id> --user-sid <sid>"
            );
            return EXIT_BAD_ARGS;
        }
    };
    let cap_token = std::env::var("DIRECTDESK_UAC_CAP").unwrap_or_default();
    if cap_token.is_empty() {
        tracing::error!("DIRECTDESK_UAC_CAP is not set; refusing to run");
        return EXIT_BAD_ARGS;
    }

    // --- self-report (the integration test reads these three facts) ----------
    let integrity = verified_integrity_label();
    let desktop = current_desktop_name();
    tracing::info!(
        integrity = %integrity,
        session = args.session,
        desktop = %desktop,
        data_pipe = %args.data_pipe,
        "UAC injector starting"
    );
    if integrity != "System" && integrity != "High" {
        tracing::warn!(
            "running at integrity {integrity}, NOT System/High — SendInput will be \
             blocked by UIPI against the consent dialog; continuing anyway"
        );
    }

    // --- pipe server ---------------------------------------------------------
    let _sd; // keep the security descriptor alive across CreateNamedPipeW
    let pipe = match build_pipe(&args.data_pipe, &args.user_sid) {
        Ok((p, sd)) => {
            _sd = sd;
            p
        }
        Err(code) => return code,
    };

    match accept(&pipe, ACCEPT_TIMEOUT_MS) {
        Ok(true) => {}
        Ok(false) => {
            tracing::error!("no host connected within {ACCEPT_TIMEOUT_MS} ms");
            return EXIT_NO_CLIENT;
        }
        Err(e) => {
            tracing::error!("accept failed: {e}");
            return EXIT_PIPE_FAILED;
        }
    }

    let mut buf = vec![0u8; MAX_FRAME];

    // First frame must be a Hello carrying the capability token.
    match read_message(&pipe, &mut buf, HELLO_TIMEOUT_MS) {
        ReadOutcome::Message(n) => match decode_frame(&buf[..n]) {
            Ok(UacWireMsg::Hello { cap_token: got }) => {
                if !tokens_match(&got, &cap_token) {
                    tracing::error!("capability token mismatch; disconnecting");
                    disconnect(&pipe);
                    return EXIT_BAD_TOKEN;
                }
                tracing::info!("host authenticated with the capability token");
            }
            Ok(_) => {
                tracing::error!("first frame was not Hello; disconnecting");
                disconnect(&pipe);
                return EXIT_BAD_TOKEN;
            }
            Err(e) => {
                tracing::error!("first frame did not decode: {e}");
                disconnect(&pipe);
                return EXIT_BAD_TOKEN;
            }
        },
        _ => {
            tracing::error!("no Hello frame arrived; disconnecting");
            disconnect(&pipe);
            return EXIT_BAD_TOKEN;
        }
    }

    let code = serve(&pipe, &mut buf);
    disconnect(&pipe);
    code
}

/// The main injection loop. Returns the process exit code.
fn serve(pipe: &OwnedHandle, buf: &mut [u8]) -> i32 {
    let mut injector: Option<WinInjector> = None;
    let mut geom: Option<(u32, u32, i32, i32)> = None;
    let mut last_input = Instant::now();
    let mut consent_last_seen = Instant::now();

    loop {
        // Consent-window liveness: if the dialog has been gone too long, stop.
        if foreground_consent_rect().is_some() {
            consent_last_seen = Instant::now();
        } else if consent_last_seen.elapsed() > CONSENT_GONE_TIMEOUT {
            tracing::info!(
                "consent window gone for >{:?}; exiting",
                CONSENT_GONE_TIMEOUT
            );
            break;
        }

        match read_message(pipe, buf, READ_SLICE_MS) {
            ReadOutcome::Message(n) => {
                let msg = match decode_frame(&buf[..n]) {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::warn!("dropping malformed frame: {e}");
                        continue;
                    }
                };
                match msg {
                    UacWireMsg::Hello { .. } => {
                        tracing::warn!("unexpected second Hello; ignoring");
                    }
                    UacWireMsg::Geometry {
                        width,
                        height,
                        origin_x,
                        origin_y,
                    } => {
                        geom = Some((width, height, origin_x, origin_y));
                        match injector.as_mut() {
                            Some(inj) => inj.set_frame(width, height, (origin_x, origin_y)),
                            None => {
                                injector =
                                    Some(WinInjector::new(width, height, (origin_x, origin_y)))
                            }
                        }
                        tracing::info!(
                            "geometry set to {width}x{height} @ ({origin_x},{origin_y})"
                        );
                    }
                    UacWireMsg::Input(input) => {
                        last_input = Instant::now();
                        let Some(inj) = injector.as_mut() else {
                            tracing::warn!("input before geometry; dropping");
                            continue;
                        };
                        handle_input(inj, geom, input);
                    }
                }
            }
            ReadOutcome::Timeout => {
                if last_input.elapsed() > IDLE_TIMEOUT {
                    tracing::info!("no input for >{:?}; exiting", IDLE_TIMEOUT);
                    break;
                }
            }
            ReadOutcome::Closed => {
                tracing::info!("host disconnected; exiting");
                break;
            }
        }
    }

    // Never leave a key or button stuck down as SYSTEM.
    if let Some(mut inj) = injector {
        if let Err(e) = inj.release_all() {
            tracing::warn!("release_all on exit failed: {e}");
        }
    }
    EXIT_OK
}

/// Apply the guardrails, then inject.
fn handle_input(inj: &mut WinInjector, geom: Option<(u32, u32, i32, i32)>, input: InputMsg) {
    let ev = match input {
        InputMsg::ReleaseAll => {
            if let Err(e) = inj.release_all() {
                tracing::warn!("release_all failed: {e}");
            }
            return;
        }
        InputMsg::Event(ev) => ev,
        // Appended alongside `features::MULTI_MONITOR`, which nothing
        // negotiates yet, so nothing can put this on the UAC pipe. Dropped
        // rather than unwrapped to its inner event: this process injects as
        // SYSTEM against the consent dialog, and it must not widen what it
        // will inject on the strength of a variant no code path produces.
        InputMsg::EventOn { .. } => {
            tracing::debug!(
                "EventOn on the UAC pipe before multi-monitor input is wired; dropping"
            );
            return;
        }
    };

    // GUARDRAIL 1: only inject while the real consent dialog owns the foreground.
    // Capture its PID so we can re-verify it right before injecting (TOCTOU).
    let Some((consent_pid, rect)) = foreground_consent_rect() else {
        tracing::debug!("no consent window in front; dropping event");
        return;
    };

    // GUARDRAIL 2 (mouse-only): keyboard events are dropped; mouse events are
    // clamped into the consent rect. `None` here means "do not inject".
    let Some(ev) = prepare_injection(ev, geom, rect) else {
        tracing::debug!("dropping keyboard event; the UAC worker is mouse-only");
        return;
    };

    // GUARDRAIL 3 (TOCTOU): between the guard check above and SendInput, focus
    // could move. Re-verify the SAME consent process still owns the foreground
    // immediately before injecting; on any change, drop the event and release
    // anything held. This narrows — but, being user-mode, cannot fully close —
    // the race, so a click can never leak to a window that stole focus.
    match foreground_consent_rect() {
        Some((pid_now, _)) if pid_now == consent_pid => {
            if let Err(e) = inj.inject(&ev) {
                tracing::warn!("injection failed: {e}");
            }
        }
        _ => {
            tracing::debug!("foreground changed before inject; dropping event + release_all");
            if let Err(e) = inj.release_all() {
                tracing::warn!("release_all after foreground change failed: {e}");
            }
        }
    }
}

/// The worker's pure per-event policy, free of any live-window call so it can be
/// unit-tested: **keyboard events are dropped** (the worker is mouse-only) and
/// **mouse events are clamped** into the consent `rect`. Returns `None` when the
/// event must not be injected.
fn prepare_injection(
    ev: InputEvent,
    geom: Option<(u32, u32, i32, i32)>,
    rect: directdesk_host::uac_proto::PixelRect,
) -> Option<InputEvent> {
    if matches!(ev, InputEvent::Key { .. }) {
        return None;
    }
    Some(match geom {
        Some((w, h, ox, oy)) => clamp_mouse_event(ev, (w, h), (ox, oy), rect),
        None => ev,
    })
}

/// Rewrite a mouse event's normalized position so it lands inside `rect`.
/// Non-mouse events pass through unchanged.
fn clamp_mouse_event(
    ev: InputEvent,
    frame: (u32, u32),
    origin: (i32, i32),
    rect: directdesk_host::uac_proto::PixelRect,
) -> InputEvent {
    match ev {
        InputEvent::MouseMove { x, y } => {
            let (x, y) = clamp_norm_to_rect(x, y, frame, origin, rect);
            InputEvent::MouseMove { x, y }
        }
        InputEvent::MouseButton {
            button,
            action,
            x,
            y,
        } => {
            let (x, y) = clamp_norm_to_rect(x, y, frame, origin, rect);
            InputEvent::MouseButton {
                button,
                action,
                x,
                y,
            }
        }
        InputEvent::MouseWheel {
            delta,
            horizontal,
            x,
            y,
        } => {
            let (x, y) = clamp_norm_to_rect(x, y, frame, origin, rect);
            InputEvent::MouseWheel {
                delta,
                horizontal,
                x,
                y,
            }
        }
        // Non-mouse events carry no position. In practice keyboard events are
        // already dropped upstream (the worker is mouse-only), so this arm only
        // ever sees mouse variants; it passes anything else through untouched.
        other => other,
    }
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

struct Args {
    data_pipe: String,
    session: u32,
    user_sid: String,
}

impl Args {
    fn parse() -> Option<Self> {
        let argv: Vec<String> = std::env::args().skip(1).collect();
        let mut data_pipe = None;
        let mut session = None;
        let mut user_sid = None;
        let mut i = 0;
        while i + 1 < argv.len() {
            match argv[i].as_str() {
                "--data-pipe" => data_pipe = Some(argv[i + 1].clone()),
                "--session" => session = argv[i + 1].parse::<u32>().ok(),
                "--user-sid" => user_sid = Some(argv[i + 1].clone()),
                _ => {}
            }
            i += 1;
        }
        Some(Self {
            data_pipe: data_pipe?,
            session: session?,
            user_sid: user_sid?,
        })
    }
}

// ---------------------------------------------------------------------------
// Named-pipe server (single instance, overlapped, message mode)
// ---------------------------------------------------------------------------

/// A security descriptor built from SDDL; frees itself with `LocalFree`.
struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: the buffer came from ConvertStringSecurityDescriptor... (LocalAlloc).
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0 .0)));
            }
        }
    }
}

/// Create the single-instance data pipe with a DACL granting SYSTEM full
/// control and the console user read/write only.
fn build_pipe(name: &str, user_sid: &str) -> Result<(OwnedHandle, SecurityDescriptor), i32> {
    // D:P — protected DACL; SYSTEM full; the console user RW; nobody else.
    let sddl = format!("D:P(A;;GA;;;SY)(A;;GRGW;;;{user_sid})");
    let sddl_w = wide(&sddl);
    let mut psd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: sddl_w outlives the call; psd receives a LocalAlloc'd buffer.
    if let Err(e) = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            pcwstr(&sddl_w),
            SDDL_REVISION_1,
            &mut psd,
            None,
        )
    } {
        tracing::error!("bad user SID {user_sid:?} for pipe DACL ({sddl:?}): {e}");
        return Err(EXIT_PIPE_FAILED);
    }
    let sd = SecurityDescriptor(psd);

    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0 .0,
        bInheritHandle: false.into(),
    };
    let name_w = wide(name);
    let open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE;
    let pipe_mode =
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;

    // SAFETY: name_w is NUL-terminated; sa (and the SD it points at) outlive the call.
    let handle = unsafe {
        CreateNamedPipeW(
            pcwstr(&name_w),
            open_mode,
            pipe_mode,
            1, // single instance
            MAX_FRAME as u32,
            MAX_FRAME as u32,
            0,
            Some(&sa as *const SECURITY_ATTRIBUTES),
        )
    };
    if handle.is_invalid() {
        tracing::error!(
            "CreateNamedPipeW({name}) failed: {}",
            windows::core::Error::from_thread()
        );
        return Err(EXIT_PIPE_FAILED);
    }
    // SAFETY: valid handle, exclusively owned by the returned wrapper.
    Ok((unsafe { OwnedHandle::new(handle) }, sd))
}

/// Wait for the host to connect. `Ok(true)` = connected, `Ok(false)` = timeout.
fn accept(pipe: &OwnedHandle, timeout_ms: u32) -> Result<bool, windows::core::Error> {
    let ev = Event::manual_reset()?;
    let mut ov = OVERLAPPED {
        hEvent: ev.raw(),
        ..Default::default()
    };
    // SAFETY: ov and its event outlive the operation (we always wait or cancel).
    let r = unsafe { ConnectNamedPipe(pipe.raw(), Some(&mut ov)) };
    match r {
        Ok(()) => Ok(true),
        Err(e) if e.code() == ERROR_PIPE_CONNECTED.to_hresult() => Ok(true),
        Err(e) if e.code() == ERROR_IO_PENDING.to_hresult() => {
            // SAFETY: the event is alive for the wait.
            let w = unsafe { WaitForSingleObject(ev.raw(), timeout_ms) };
            if w == WAIT_OBJECT_0 {
                let mut transferred = 0u32;
                // SAFETY: the operation completed; ov is still valid.
                unsafe { GetOverlappedResult(pipe.raw(), &ov, &mut transferred, true) }?;
                Ok(true)
            } else {
                cancel(pipe, &ov);
                Ok(false)
            }
        }
        Err(e) => Err(e),
    }
}

enum ReadOutcome {
    Message(usize),
    /// No message within the slice.
    Timeout,
    /// The pipe is broken / the host went away.
    Closed,
}

/// Read one whole message, waiting at most `timeout_ms`.
fn read_message(pipe: &OwnedHandle, buf: &mut [u8], timeout_ms: u32) -> ReadOutcome {
    let ev = match Event::manual_reset() {
        Ok(e) => e,
        Err(_) => return ReadOutcome::Closed,
    };
    let mut ov = OVERLAPPED {
        hEvent: ev.raw(),
        ..Default::default()
    };
    let mut read = 0u32;
    // SAFETY: buf, ov and the event outlive the operation.
    let started = unsafe { ReadFile(pipe.raw(), Some(buf), Some(&mut read), Some(&mut ov)) };
    match started {
        Ok(()) => ReadOutcome::Message(read as usize),
        Err(e) if e.code() == ERROR_MORE_DATA.to_hresult() => {
            // A message larger than our buffer/cap: drop it and keep the pipe.
            tracing::warn!("oversize message discarded");
            ReadOutcome::Message(0)
        }
        Err(e) if e.code() == ERROR_BROKEN_PIPE.to_hresult() => ReadOutcome::Closed,
        Err(e) if e.code() == ERROR_IO_PENDING.to_hresult() => {
            // SAFETY: the event is alive for the wait.
            let w = unsafe { WaitForSingleObject(ev.raw(), timeout_ms) };
            if w == WAIT_OBJECT_0 {
                let mut transferred = 0u32;
                // SAFETY: the operation completed; ov is still valid.
                match unsafe { GetOverlappedResult(pipe.raw(), &ov, &mut transferred, true) } {
                    Ok(()) => ReadOutcome::Message(transferred as usize),
                    Err(e) if e.code() == ERROR_MORE_DATA.to_hresult() => {
                        tracing::warn!("oversize message discarded");
                        ReadOutcome::Message(0)
                    }
                    Err(e) if e.code() == ERROR_BROKEN_PIPE.to_hresult() => ReadOutcome::Closed,
                    Err(e) => {
                        tracing::warn!("read failed: {e}");
                        ReadOutcome::Closed
                    }
                }
            } else {
                cancel(pipe, &ov);
                ReadOutcome::Timeout
            }
        }
        Err(e) => {
            tracing::warn!("ReadFile failed: {e}");
            ReadOutcome::Closed
        }
    }
}

fn cancel(pipe: &OwnedHandle, ov: &OVERLAPPED) {
    // SAFETY: cancelling our own pending operation, then draining its result so
    // `ov` is no longer referenced by the kernel before it is dropped.
    unsafe {
        let _ = CancelIoEx(pipe.raw(), Some(ov));
        let mut n = 0u32;
        let _ = GetOverlappedResult(pipe.raw(), ov, &mut n, true);
    }
}

fn disconnect(pipe: &OwnedHandle) {
    // SAFETY: our own pipe instance.
    unsafe {
        let _ = DisconnectNamedPipe(pipe.raw());
    }
}

// ---------------------------------------------------------------------------
// Self-report helpers
// ---------------------------------------------------------------------------

/// Query our own token's integrity level and map it to a label.
fn verified_integrity_label() -> String {
    // SAFETY: we open our own process token for query only and free everything.
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return "unknown".into();
        }
        let token = OwnedHandle::new(token);

        let mut needed = 0u32;
        let _ = GetTokenInformation(token.raw(), TokenIntegrityLevel, None, 0, &mut needed);
        if needed == 0 {
            return "unknown".into();
        }
        let mut buf = vec![0u8; needed as usize];
        if GetTokenInformation(
            token.raw(),
            TokenIntegrityLevel,
            Some(buf.as_mut_ptr().cast()),
            needed,
            &mut needed,
        )
        .is_err()
        {
            return "unknown".into();
        }
        let label = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
        let sid = label.Label.Sid;
        let count_ptr = GetSidSubAuthorityCount(sid);
        if count_ptr.is_null() {
            return "unknown".into();
        }
        let count = *count_ptr;
        if count == 0 {
            return "unknown".into();
        }
        let rid = *GetSidSubAuthority(sid, (count - 1) as u32);
        match rid {
            r if r >= 0x4000 => "System".into(),
            r if r >= 0x3000 => "High".into(),
            r if r >= 0x2000 => "Medium".into(),
            r if r >= 0x1000 => "Low".into(),
            other => format!("Untrusted(0x{other:x})"),
        }
    }
}

/// The name of the desktop this thread is attached to (e.g. `Default`).
fn current_desktop_name() -> String {
    // SAFETY: query-only calls; the returned HDESK is not owned by us.
    unsafe {
        let desk = match GetThreadDesktop(GetCurrentThreadId()) {
            Ok(d) => d,
            Err(_) => return "unknown".into(),
        };
        if desk.0.is_null() {
            return "unknown".into();
        }
        let mut buf = [0u16; 256];
        let mut needed = 0u32;
        let ok = GetUserObjectInformationW(
            HANDLE(desk.0),
            UOI_NAME,
            Some(buf.as_mut_ptr().cast()),
            (buf.len() * 2) as u32,
            Some(&mut needed),
        );
        if ok.is_err() {
            let _ = GetLastError();
            return "unknown".into();
        }
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..len])
    }
}

// ---------------------------------------------------------------------------
// Tests (the injection policy is pure and window-free)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use directdesk_host::uac_proto::PixelRect;
    use directdesk_shared::geometry::from_norm;
    use directdesk_shared::input::{KeyAction, MouseButton};

    const FRAME_W: u32 = 1920;
    const FRAME_H: u32 = 1080;

    fn consent_rect() -> PixelRect {
        PixelRect {
            left: 800,
            top: 400,
            right: 1120,
            bottom: 680,
        }
    }

    #[test]
    fn keyboard_events_are_dropped_by_the_mouse_only_worker() {
        let rect = consent_rect();
        let geom = Some((FRAME_W, FRAME_H, 0i32, 0i32));
        // An Enter/"Yes"-style keypress must never be injected.
        let key = InputEvent::Key {
            scan_code: 0x1C,
            extended: false,
            action: KeyAction::Down,
        };
        assert!(
            prepare_injection(key, geom, rect).is_none(),
            "keyboard input must be dropped"
        );
        // Key-up is dropped too.
        let key_up = InputEvent::Key {
            scan_code: 0x1C,
            extended: false,
            action: KeyAction::Up,
        };
        assert!(prepare_injection(key_up, geom, rect).is_none());
    }

    #[test]
    fn a_mouse_click_is_passed_and_clamped_into_the_consent_rect() {
        let rect = consent_rect();
        let geom = Some((FRAME_W, FRAME_H, 0i32, 0i32));
        // A left-click aimed at the top-left corner (far outside the dialog) is
        // passed through but clamped to land inside the consent rectangle.
        let click = InputEvent::MouseButton {
            button: MouseButton::Left,
            action: KeyAction::Down,
            x: 0,
            y: 0,
        };
        let out = prepare_injection(click, geom, rect).expect("mouse event must pass");
        match out {
            InputEvent::MouseButton { x, y, .. } => {
                let px = from_norm(x, FRAME_W) as i32;
                let py = from_norm(y, FRAME_H) as i32;
                assert!((rect.left..rect.right).contains(&px), "x {px} not in rect");
                assert!((rect.top..rect.bottom).contains(&py), "y {py} not in rect");
            }
            other => panic!("expected MouseButton, got {other:?}"),
        }
    }
}
