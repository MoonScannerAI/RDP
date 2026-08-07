//! Host-agent supervisor.
//!
//! The service runs as LocalSystem, but the *host agent must not*. It captures
//! the interactive desktop and injects input, so it belongs in the logged-on
//! user's session, running with the logged-on user's token and the logged-on
//! user's privileges — not elevated, not SYSTEM. That is what this module does:
//!
//! 1. `WTSGetActiveConsoleSessionId` — find the physical console session.
//! 2. `WTSQueryUserToken` — obtain that user's token (needs SYSTEM; that is the
//!    only reason the service exists as a service).
//! 3. `CreateEnvironmentBlock` — give the child the user's real environment.
//! 4. `CreateProcessAsUserW` — launch `DirectDeskHost.exe --minimized` on
//!    `winsta0\default` in that session.
//!
//! The executable path is always a sibling of the *service* executable. It is
//! never read from config, from the registry, or from an IPC message.
//!
//! Restart policy:
//! * crash / non-zero exit → exponential backoff 1s, 2s, 4s … capped at 60s,
//!   with the counter reset once a launch has stayed healthy for 5 minutes;
//! * clean exit (code 0) → the user quit deliberately, so the service does
//!   **not** resurrect it; it waits for an explicit `RestartHostRequested`;
//! * no interactive session → poll every few seconds, no backoff escalation;
//! * `autostart_host: false` in the config → nothing is launched at all until
//!   the user explicitly asks via IPC.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{ERROR_NO_TOKEN, HANDLE, LPARAM, WAIT_OBJECT_0};
use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows::Win32::System::RemoteDesktop::{WTSGetActiveConsoleSessionId, WTSQueryUserToken};
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, GetExitCodeProcess, WaitForMultipleObjects, WaitForSingleObject,
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTUPINFOW,
};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowThreadProcessId, PostMessageW, WM_CLOSE,
};

use crate::dispatch::SupervisorOps;
use crate::paths::quote;
use crate::winutil::{pcwstr, wide, Child, Event, OwnedHandle};

/// First restart delay after a crash.
pub const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
/// Ceiling for the restart delay.
pub const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// A launch that survives this long is considered healthy; the backoff resets.
pub const HEALTHY_RUNTIME: Duration = Duration::from_secs(5 * 60);
/// How often to re-check for an interactive session when there isn't one.
pub const SESSION_POLL: Duration = Duration::from_secs(5);
/// Grace period for a WM_CLOSE before the host is terminated.
pub const GRACEFUL_STOP: Duration = Duration::from_secs(5);
/// Argument the host is launched with.
pub const HOST_ARG: &str = "--minimized";

// ---------------------------------------------------------------------------
// Backoff (pure arithmetic — unit-tested directly)
// ---------------------------------------------------------------------------

/// Delay before restart attempt `consecutive_failures` (1-based):
/// 1s, 2s, 4s, 8s, 16s, 32s, then capped at 60s.
pub fn backoff_delay(consecutive_failures: u32) -> Duration {
    let exponent = consecutive_failures.max(1) - 1;
    let secs = 1u64.checked_shl(exponent.min(63)).unwrap_or(u64::MAX);
    Duration::from_secs(secs.min(BACKOFF_MAX.as_secs())).max(BACKOFF_INITIAL)
}

/// Consecutive-failure counter with the "healthy run resets it" rule.
#[derive(Debug, Default, Clone, Copy)]
pub struct BackoffState {
    consecutive: u32,
}

impl BackoffState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a failed run that lasted `ran`; returns how long to wait next.
    pub fn on_failure(&mut self, ran: Duration) -> Duration {
        if ran >= HEALTHY_RUNTIME {
            // It was up long enough to count as healthy — treat this as the
            // first failure of a fresh series, not a continuing crash loop.
            self.consecutive = 0;
        }
        self.consecutive = self.consecutive.saturating_add(1);
        backoff_delay(self.consecutive)
    }

    pub fn reset(&mut self) {
        self.consecutive = 0;
    }

    pub fn consecutive(&self) -> u32 {
        self.consecutive
    }
}

// ---------------------------------------------------------------------------
// Launch errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum LaunchError {
    #[error("no interactive user session is available")]
    NoSession,
    #[error("host executable not found at {0}")]
    MissingExe(PathBuf),
    #[error("obtaining the console user's token requires the service to run as LocalSystem: {0}")]
    NeedsSystem(windows::core::Error),
    #[error("{0}")]
    Win(#[from] windows::core::Error),
}

impl LaunchError {
    /// Transient "nobody is logged on yet" conditions are polled, not backed off.
    fn is_no_session(&self) -> bool {
        matches!(self, LaunchError::NoSession)
    }
}

// ---------------------------------------------------------------------------
// Session / process primitives
// ---------------------------------------------------------------------------

/// Token of the user owning the active console session.
///
/// Requires the caller to be LocalSystem (`SE_TCB_NAME`), so this fails by
/// design when the CLI or a test runs as a normal user.
pub fn console_user_token() -> Result<OwnedHandle, LaunchError> {
    // SAFETY: no arguments, no output buffers.
    let session = unsafe { WTSGetActiveConsoleSessionId() };
    if session == u32::MAX {
        return Err(LaunchError::NoSession);
    }
    let mut token = HANDLE::default();
    // SAFETY: `token` is a valid out-parameter; ownership transfers to us.
    match unsafe { WTSQueryUserToken(session, &mut token) } {
        // SAFETY: WTSQueryUserToken succeeded, so `token` must be closed by us.
        Ok(()) => Ok(unsafe { OwnedHandle::new(token) }),
        Err(e) if e.code() == ERROR_NO_TOKEN.to_hresult() => Err(LaunchError::NoSession),
        Err(e) => Err(LaunchError::NeedsSystem(e)),
    }
}

/// Launch the host agent in the interactive session as the console user.
fn launch_host(host_exe: &std::path::Path) -> Result<Child, LaunchError> {
    if !host_exe.exists() {
        return Err(LaunchError::MissingExe(host_exe.to_path_buf()));
    }
    let token = console_user_token()?;

    // SAFETY: every buffer below outlives the CreateProcessAsUserW call, and
    // the environment block is destroyed on every path.
    unsafe {
        let mut env: *mut std::ffi::c_void = std::ptr::null_mut();
        CreateEnvironmentBlock(&mut env, Some(token.raw()), false)?;

        let mut desktop = wide(r"winsta0\default");
        let mut cmdline = wide(&format!("{} {HOST_ARG}", quote(host_exe)));
        let workdir = wide(&host_exe.parent().unwrap_or(host_exe).to_string_lossy());

        let si = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            lpDesktop: windows::core::PWSTR(desktop.as_mut_ptr()),
            ..Default::default()
        };
        let mut pi = PROCESS_INFORMATION::default();

        let result = CreateProcessAsUserW(
            Some(token.raw()),
            None,
            Some(windows::core::PWSTR(cmdline.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            Some(env),
            pcwstr(&workdir),
            &si,
            &mut pi,
        );

        let _ = DestroyEnvironmentBlock(env);
        result?;

        // The primary thread handle is not needed; close it immediately.
        if !pi.hThread.is_invalid() {
            let _ = windows::Win32::Foundation::CloseHandle(pi.hThread);
        }
        Ok(Child {
            // SAFETY: CreateProcessAsUserW handed us an owned process handle.
            process: OwnedHandle::new(pi.hProcess),
            pid: pi.dwProcessId,
        })
    }
}

/// Ask a process to close its windows, then terminate it if it does not.
fn stop_child(child: &Child) {
    post_close_to_windows(child.pid);
    // SAFETY: our own process handle.
    let waited =
        unsafe { WaitForSingleObject(child.process.raw(), GRACEFUL_STOP.as_millis() as u32) };
    if waited == WAIT_OBJECT_0 {
        tracing::info!(pid = child.pid, "host agent closed gracefully");
        return;
    }
    tracing::warn!(
        pid = child.pid,
        "host agent did not close in time; terminating"
    );
    child.terminate();
    // SAFETY: our own process handle.
    unsafe {
        let _ = WaitForSingleObject(child.process.raw(), 2_000);
    }
}

struct CloseTarget {
    pid: u32,
    posted: u32,
}

/// `PostMessageW(WM_CLOSE)` to every top-level window owned by `pid`.
fn post_close_to_windows(pid: u32) {
    let mut target = CloseTarget { pid, posted: 0 };
    // SAFETY: the callback only touches the `CloseTarget` we pass in, which
    // outlives the (synchronous) enumeration.
    unsafe {
        let _ = EnumWindows(
            Some(enum_windows_proc),
            LPARAM(&mut target as *mut _ as isize),
        );
    }
    tracing::debug!(pid, windows = target.posted, "posted WM_CLOSE");
}

unsafe extern "system" fn enum_windows_proc(
    hwnd: windows::Win32::Foundation::HWND,
    lparam: LPARAM,
) -> windows::core::BOOL {
    // SAFETY: `lparam` is the &mut CloseTarget handed to EnumWindows above.
    let target = unsafe { &mut *(lparam.0 as *mut CloseTarget) };
    let mut pid = 0u32;
    // SAFETY: `hwnd` comes from the enumerator; `pid` is a valid out-parameter.
    unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
    if pid == target.pid {
        // SAFETY: posting a standard message to a window we just identified.
        unsafe {
            let _ = PostMessageW(Some(hwnd), WM_CLOSE, Default::default(), Default::default());
        }
        target.posted += 1;
    }
    true.into()
}

// ---------------------------------------------------------------------------
// Supervisor
// ---------------------------------------------------------------------------

/// Shared supervisor state. This is what the IPC dispatcher talks to.
pub struct Shared {
    host_exe: PathBuf,
    /// Should a host be running? Seeded from config, latched on by an explicit
    /// restart request, latched off when the user closes the host cleanly.
    wanted: AtomicBool,
    running: AtomicBool,
    stop: Event,
    restart: Event,
}

impl Shared {
    fn new(host_exe: PathBuf, autostart: bool) -> anyhow::Result<Self> {
        Ok(Self {
            host_exe,
            wanted: AtomicBool::new(autostart),
            running: AtomicBool::new(false),
            stop: Event::manual_reset()?,
            restart: Event::manual_reset()?,
        })
    }

    /// Is the supervisor currently trying to keep a host alive?
    pub fn wanted(&self) -> bool {
        self.wanted.load(Ordering::SeqCst)
    }

    fn wake(&self) -> Wake {
        if self.stop.is_signaled() {
            Wake::Stop
        } else if self.restart.is_signaled() {
            Wake::Restart
        } else {
            Wake::Timeout
        }
    }

    /// Wait up to `d`, waking early for stop or restart.
    fn wait(&self, d: Duration) -> Wake {
        let handles = [self.stop.raw(), self.restart.raw()];
        let ms = d.as_millis().min(u32::MAX as u128) as u32;
        // SAFETY: both events are owned by `self` and outlive the wait.
        let w = unsafe { WaitForMultipleObjects(&handles, false, ms) };
        match w {
            WAIT_OBJECT_0 => Wake::Stop,
            w if w.0 == WAIT_OBJECT_0.0 + 1 => Wake::Restart,
            _ => self.wake(),
        }
    }
}

impl SupervisorOps for Shared {
    fn host_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn request_restart(&self) -> anyhow::Result<()> {
        self.wanted.store(true, Ordering::SeqCst);
        self.restart.signal();
        tracing::info!("host restart requested");
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Wake {
    Stop,
    Restart,
    Timeout,
}

/// Owns the supervision thread; stops and joins it on drop.
pub struct Supervisor {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}

impl Supervisor {
    /// Start supervising. `autostart` comes from `service.json`; when false the
    /// host is not launched until an explicit `RestartHostRequested` arrives.
    pub fn start(host_exe: PathBuf, autostart: bool) -> anyhow::Result<Self> {
        let shared = Arc::new(Shared::new(host_exe, autostart)?);
        let worker = shared.clone();
        let thread = std::thread::Builder::new()
            .name("dd-supervisor".into())
            .spawn(move || supervise(worker))?;
        Ok(Self {
            shared,
            thread: Some(thread),
        })
    }

    /// Handle for the IPC dispatcher.
    pub fn shared(&self) -> Arc<Shared> {
        self.shared.clone()
    }

    pub fn shutdown(&mut self) {
        if let Some(thread) = self.thread.take() {
            tracing::info!("stopping host supervisor");
            self.shared.stop.signal();
            let _ = thread.join();
            tracing::info!("host supervisor stopped");
        }
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn supervise(shared: Arc<Shared>) {
    let mut backoff = BackoffState::new();
    tracing::info!(
        exe = %shared.host_exe.display(),
        autostart = shared.wanted(),
        "host supervisor started"
    );

    while !shared.stop.is_signaled() {
        if !shared.wanted() {
            // Idle: nothing to supervise until the user asks.
            match shared.wait(SESSION_POLL) {
                Wake::Stop => break,
                Wake::Restart => shared.restart.reset(),
                Wake::Timeout => {}
            }
            continue;
        }
        shared.restart.reset();

        let started = Instant::now();
        let child = match launch_host(&shared.host_exe) {
            Ok(child) => {
                tracing::info!(pid = child.pid, exe = %shared.host_exe.display(), "host agent launched");
                child
            }
            Err(e) => {
                let delay = if e.is_no_session() {
                    tracing::debug!("waiting for an interactive session: {e}");
                    SESSION_POLL
                } else {
                    let d = backoff.on_failure(Duration::ZERO);
                    tracing::warn!("could not launch host agent ({e}); retrying in {d:?}");
                    d
                };
                if shared.wait(delay) == Wake::Stop {
                    break;
                }
                continue;
            }
        };

        shared.running.store(true, Ordering::SeqCst);
        let outcome = wait_for_child(&shared, &child);
        shared.running.store(false, Ordering::SeqCst);

        match outcome {
            ChildOutcome::Stop => {
                stop_child(&child);
                break;
            }
            ChildOutcome::Restart => {
                tracing::info!(pid = child.pid, "cycling host agent on request");
                stop_child(&child);
                backoff.reset();
                shared.restart.reset();
            }
            ChildOutcome::Exited(0) => {
                tracing::info!(
                    pid = child.pid,
                    "host agent exited cleanly; leaving it stopped until requested"
                );
                shared.wanted.store(false, Ordering::SeqCst);
                backoff.reset();
            }
            ChildOutcome::Exited(code) => {
                let ran = started.elapsed();
                let delay = backoff.on_failure(ran);
                tracing::warn!(
                    pid = child.pid,
                    exit_code = code,
                    ran_secs = ran.as_secs(),
                    attempt = backoff.consecutive(),
                    "host agent exited abnormally; restarting in {delay:?}"
                );
                if shared.wait(delay) == Wake::Stop {
                    break;
                }
            }
        }
    }

    shared.running.store(false, Ordering::SeqCst);
}

enum ChildOutcome {
    Exited(u32),
    Restart,
    Stop,
}

fn wait_for_child(shared: &Shared, child: &Child) -> ChildOutcome {
    let handles = [child.process.raw(), shared.stop.raw(), shared.restart.raw()];
    // SAFETY: all three handles are alive for the duration of the wait.
    let w = unsafe { WaitForMultipleObjects(&handles, false, u32::MAX) };
    if w == WAIT_OBJECT_0 {
        let mut code = 0u32;
        // SAFETY: the process has exited; the handle is still ours.
        let _ = unsafe { GetExitCodeProcess(child.process.raw(), &mut code) };
        ChildOutcome::Exited(code)
    } else if w.0 == WAIT_OBJECT_0.0 + 1 {
        ChildOutcome::Stop
    } else if w.0 == WAIT_OBJECT_0.0 + 2 {
        ChildOutcome::Restart
    } else {
        // Wait failed: treat as a crash so the backoff path handles it.
        tracing::warn!("wait on host process failed ({w:?})");
        ChildOutcome::Exited(u32::MAX)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_sequence_is_1_2_4_capped_at_60() {
        let expected = [1u64, 2, 4, 8, 16, 32, 60, 60, 60, 60];
        for (i, want) in expected.iter().enumerate() {
            let n = i as u32 + 1;
            assert_eq!(
                backoff_delay(n),
                Duration::from_secs(*want),
                "attempt {n} should wait {want}s"
            );
        }
    }

    #[test]
    fn backoff_never_exceeds_the_cap_or_overflows() {
        for n in [0u32, 1, 7, 63, 64, 1_000, u32::MAX] {
            let d = backoff_delay(n);
            assert!(d <= BACKOFF_MAX, "attempt {n} produced {d:?}");
            assert!(d >= BACKOFF_INITIAL, "attempt {n} produced {d:?}");
        }
    }

    #[test]
    fn backoff_state_escalates_then_resets_after_a_healthy_run() {
        let mut s = BackoffState::new();
        assert_eq!(s.on_failure(Duration::from_secs(1)), Duration::from_secs(1));
        assert_eq!(s.on_failure(Duration::from_secs(1)), Duration::from_secs(2));
        assert_eq!(s.on_failure(Duration::from_secs(1)), Duration::from_secs(4));
        assert_eq!(s.consecutive(), 3);

        // A run that lasted longer than HEALTHY_RUNTIME clears the history.
        assert_eq!(s.on_failure(HEALTHY_RUNTIME), Duration::from_secs(1));
        assert_eq!(s.consecutive(), 1);

        // Just under the threshold does not.
        assert_eq!(
            s.on_failure(HEALTHY_RUNTIME - Duration::from_secs(1)),
            Duration::from_secs(2)
        );
    }

    #[test]
    fn backoff_state_explicit_reset() {
        let mut s = BackoffState::new();
        for _ in 0..5 {
            s.on_failure(Duration::ZERO);
        }
        assert_eq!(s.consecutive(), 5);
        s.reset();
        assert_eq!(s.consecutive(), 0);
        assert_eq!(s.on_failure(Duration::ZERO), BACKOFF_INITIAL);
    }

    #[test]
    fn shared_state_reports_and_latches_restart_requests() {
        let shared = Shared::new(PathBuf::from(r"C:\nope\DirectDeskHost.exe"), false).unwrap();
        assert!(!shared.wanted());
        assert!(!shared.host_running());

        shared.request_restart().unwrap();
        assert!(
            shared.wanted(),
            "an explicit request must arm the supervisor"
        );
        assert_eq!(shared.wake(), Wake::Restart);

        shared.restart.reset();
        assert_eq!(shared.wake(), Wake::Timeout);

        shared.stop.signal();
        assert_eq!(shared.wake(), Wake::Stop);
    }

    #[test]
    fn wait_returns_promptly_on_stop() {
        let shared = Shared::new(PathBuf::from("x"), false).unwrap();
        shared.stop.signal();
        let t0 = Instant::now();
        assert_eq!(shared.wait(Duration::from_secs(30)), Wake::Stop);
        assert!(t0.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn idle_supervisor_starts_and_stops_cleanly() {
        let mut sup =
            Supervisor::start(PathBuf::from(r"C:\nonexistent\DirectDeskHost.exe"), false).unwrap();
        let shared = sup.shared();
        assert!(!shared.host_running());
        let t0 = Instant::now();
        sup.shutdown();
        sup.shutdown(); // idempotent
        assert!(
            t0.elapsed() < Duration::from_secs(3),
            "shutdown took {:?}",
            t0.elapsed()
        );
    }

    #[test]
    fn armed_supervisor_with_a_missing_exe_backs_off_without_dying() {
        let mut sup =
            Supervisor::start(PathBuf::from(r"C:\nonexistent\DirectDeskHost.exe"), true).unwrap();
        let shared = sup.shared();
        std::thread::sleep(Duration::from_millis(300));
        // It cannot launch, so nothing is running, but the thread is alive and
        // still answering.
        assert!(!shared.host_running());
        assert!(shared.wanted());
        shared.request_restart().unwrap();
        let t0 = Instant::now();
        sup.shutdown();
        assert!(
            t0.elapsed() < Duration::from_secs(3),
            "shutdown took {:?}",
            t0.elapsed()
        );
    }

    #[test]
    fn console_user_token_fails_cleanly_without_system_rights() {
        // Unelevated / non-SYSTEM this must be a tidy error, never a panic.
        match console_user_token() {
            Ok(_) => eprintln!("[supervisor] console user token obtained (running as SYSTEM)"),
            Err(e) => eprintln!("[supervisor] console user token unavailable as expected: {e}"),
        }
    }

    #[test]
    fn launch_host_rejects_a_missing_executable_before_touching_the_session() {
        let err =
            launch_host(std::path::Path::new(r"C:\nonexistent\DirectDeskHost.exe")).unwrap_err();
        assert!(matches!(err, LaunchError::MissingExe(_)), "got {err:?}");
    }

    #[test]
    fn posting_wm_close_to_an_unknown_pid_is_harmless() {
        // PID 0 owns no windows; this must simply do nothing.
        post_close_to_windows(0);
    }

    #[test]
    fn host_is_launched_with_the_minimized_argument_and_a_quoted_path() {
        let exe = std::path::Path::new(r"C:\Program Files\DirectDesk\DirectDeskHost.exe");
        let cmdline = format!("{} {HOST_ARG}", quote(exe));
        assert!(cmdline.starts_with('"'));
        assert!(cmdline.ends_with("--minimized"));
        assert!(cmdline.contains(r"\DirectDeskHost.exe"));
    }
}
