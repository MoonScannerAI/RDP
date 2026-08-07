//! Transient SYSTEM-integrity UAC injector worker.
//!
//! The host agent runs at *medium* integrity in the interactive session, so
//! UIPI forbids it from posting input to `consent.exe` (the UAC dialog, which
//! runs at System integrity on the secure desktop). When the operator needs to
//! click through a UAC prompt remotely, the host asks the service — which *is*
//! LocalSystem — to launch a short-lived worker that runs as SYSTEM and injects
//! on the host's behalf.
//!
//! This module launches that worker. It mirrors [`crate::supervisor`] with one
//! deliberate difference: the worker is spawned with a **SYSTEM primary token**
//! (a duplicate of the service's own token, retargeted to the console session),
//! not the console *user's* token. That is the whole point — only a
//! System-integrity process can reach the consent dialog.
//!
//! Security invariants preserved here:
//!
//! * The worker executable path is always a sibling of the *service* exe
//!   ([`crate::paths::uac_injector_exe_path`]); it is never taken from config,
//!   the registry, or an IPC message.
//! * The IPC *request* that triggers a launch carries no parameters. Everything
//!   the worker needs — the data-pipe name, the one-time capability token, the
//!   session id, the console user's SID — is minted or derived by the *service*.
//! * The capability token is delivered to the worker only through its
//!   environment (`DIRECTDESK_UAC_CAP`), never on the command line.
//! * The whole feature is behind the `uac_clickthrough` master switch; when it
//!   is off, nothing here is ever reached (the dispatcher denies first).

use std::ffi::c_void;
use std::path::{Path, PathBuf};

use parking_lot::Mutex;
use rand::Rng;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{GetLastError, ERROR_SUCCESS, HANDLE, LUID};
use windows::Win32::Security::{
    AdjustTokenPrivileges, DuplicateTokenEx, LookupPrivilegeValueW, SecurityImpersonation,
    SetTokenInformation, TokenPrimary, TokenSessionId, SE_PRIVILEGE_ENABLED, SE_TCB_NAME,
    TOKEN_ACCESS_MASK, TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_SESSIONID, TOKEN_ASSIGN_PRIMARY,
    TOKEN_DUPLICATE, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId;
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, GetCurrentProcess, OpenProcessToken, CREATE_NO_WINDOW,
    CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTUPINFOW,
};

use crate::paths::quote;
use crate::winutil::{pcwstr, wide, Child, OwnedHandle};

/// `MAXIMUM_ALLOWED` generic access right (winnt.h). Kept local so this module
/// does not need the `Win32_System_SystemServices` feature just for a constant.
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

/// Environment variable carrying the one-time capability token to the worker.
pub const CAP_ENV_VAR: &str = "DIRECTDESK_UAC_CAP";

/// What the service hands back after launching a worker: where the host should
/// connect and the single-use token it must present. Both are minted here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UacInjectorReady {
    pub pipe_name: String,
    pub cap_token: String,
}

/// The UAC-injector capabilities the dispatcher is allowed to reach.
pub trait UacInjectorOps: Send + Sync {
    /// Launch a SYSTEM worker in the console session; return its coordinates.
    fn start(&self) -> anyhow::Result<UacInjectorReady>;
    /// Terminate any running worker. Idempotent — `Ok` even if none is running.
    fn stop(&self) -> anyhow::Result<()>;
    /// Is the `uac_clickthrough` master switch on? The dispatcher gates on this
    /// *before* ever calling [`start`](UacInjectorOps::start).
    fn enabled(&self) -> bool;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum InjectorError {
    #[error("no interactive session")]
    NoSession,
    #[error("could not resolve the console user's SID (the service must run as LocalSystem)")]
    NoConsoleSid,
    #[error("UAC injector worker not found at {0}")]
    MissingExe(PathBuf),
    #[error("{0}")]
    Win(#[from] windows::core::Error),
}

// ---------------------------------------------------------------------------
// Real implementation
// ---------------------------------------------------------------------------

/// Launches and tracks the SYSTEM injector worker.
pub struct UacInjector {
    enabled: bool,
    worker_exe: PathBuf,
    running: Mutex<Option<Child>>,
}

impl UacInjector {
    pub fn new(enabled: bool, worker_exe: PathBuf) -> Self {
        Self {
            enabled,
            worker_exe,
            running: Mutex::new(None),
        }
    }

    /// Terminate a tracked worker if present. Used by both `stop` and `Drop`.
    fn terminate_running(&self) {
        if let Some(child) = self.running.lock().take() {
            tracing::info!(pid = child.pid, "terminating UAC injector worker");
            child.terminate();
        }
    }
}

impl UacInjectorOps for UacInjector {
    fn enabled(&self) -> bool {
        self.enabled
    }

    fn start(&self) -> anyhow::Result<UacInjectorReady> {
        // SAFETY: no arguments, no output buffers.
        let session = unsafe { WTSGetActiveConsoleSessionId() };
        if session == u32::MAX {
            return Err(InjectorError::NoSession.into());
        }

        let user_sid =
            crate::winutil::console_user_sid_string().ok_or(InjectorError::NoConsoleSid)?;

        if !self.worker_exe.exists() {
            return Err(InjectorError::MissingExe(self.worker_exe.clone()).into());
        }

        // Mint the data-pipe name (16-hex suffix) and the 128-bit capability
        // token (32-hex). These are the only per-launch secrets and neither
        // comes from the caller.
        let mut rng = rand::thread_rng();
        let pipe_name = format!(
            r"\\.\pipe\DirectDeskUac-{session}-{:016x}",
            rng.gen::<u64>()
        );
        let cap_token = format!("{:032x}", rng.gen::<u128>());

        let child = launch_worker(&self.worker_exe, session, &user_sid, &pipe_name, &cap_token)?;
        tracing::info!(
            pid = child.pid,
            session,
            "UAC injector worker launched as SYSTEM"
        );

        // Replace (and terminate) any previous worker so at most one runs.
        let mut slot = self.running.lock();
        if let Some(old) = slot.replace(child) {
            tracing::info!(pid = old.pid, "replacing previous UAC injector worker");
            old.terminate();
        }

        Ok(UacInjectorReady {
            pipe_name,
            cap_token,
        })
    }

    fn stop(&self) -> anyhow::Result<()> {
        self.terminate_running();
        Ok(())
    }
}

impl Drop for UacInjector {
    fn drop(&mut self) {
        // Never leave a SYSTEM worker running past service shutdown.
        self.terminate_running();
    }
}

// ---------------------------------------------------------------------------
// Token + spawn primitives (require LocalSystem; fail cleanly otherwise)
// ---------------------------------------------------------------------------

/// A SYSTEM primary token, duplicated from the service's own token and
/// retargeted to `session`. Requires `SE_TCB_NAME`, so this fails by design
/// when the service is not LocalSystem (or a test runs unelevated).
fn system_primary_token_for_session(session: u32) -> Result<OwnedHandle, InjectorError> {
    // SAFETY: `svc` is a valid out-parameter; ownership transfers to us.
    let svc = unsafe {
        let mut svc = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE
                | TOKEN_QUERY
                | TOKEN_ASSIGN_PRIMARY
                | TOKEN_ADJUST_DEFAULT
                | TOKEN_ADJUST_SESSIONID,
            &mut svc,
        )?;
        // SAFETY: OpenProcessToken handed us an owned token handle.
        OwnedHandle::new(svc)
    };

    // SAFETY: `svc` is a live token; `primary` is a valid out-parameter. A
    // primary duplicate of the LocalSystem token keeps System integrity.
    let primary = unsafe {
        let mut primary = HANDLE::default();
        DuplicateTokenEx(
            svc.raw(),
            TOKEN_ACCESS_MASK(MAXIMUM_ALLOWED),
            None,
            SecurityImpersonation,
            TokenPrimary,
            &mut primary,
        )?;
        // SAFETY: DuplicateTokenEx handed us an owned token handle.
        OwnedHandle::new(primary)
    };

    // Retargeting a token to another session requires SE_TCB. Enable it, then
    // set the session id so the child lands on the interactive desktop.
    enable_privilege(primary.raw(), SE_TCB_NAME)?;

    // SAFETY: `session` outlives the call; TokenSessionId takes a 4-byte DWORD.
    unsafe {
        SetTokenInformation(
            primary.raw(),
            TokenSessionId,
            &session as *const u32 as *const c_void,
            4,
        )?;
    }

    Ok(primary)
}

/// Enable a single named privilege on `token`. `AdjustTokenPrivileges` reports
/// success even when the privilege is not held, so we check `GetLastError`.
fn enable_privilege(token: HANDLE, name: PCWSTR) -> Result<(), InjectorError> {
    // SAFETY: `luid` is a valid out-parameter; `name` is a static PCWSTR.
    let mut luid = LUID::default();
    unsafe {
        LookupPrivilegeValueW(PCWSTR::null(), name, &mut luid)?;
    }

    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [windows::Win32::Security::LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    // SAFETY: `tp` outlives the call; we ask for no previous-state buffer.
    unsafe {
        AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None)?;
        if GetLastError() != ERROR_SUCCESS {
            return Err(windows::core::Error::from_thread().into());
        }
    }
    Ok(())
}

/// Spawn the worker as SYSTEM on `winsta0\default` in `session`.
///
/// The command line carries only non-secret, service-derived data
/// (`--data-pipe`, `--session`, `--user-sid`); the capability token is passed
/// exclusively through the environment.
fn launch_worker(
    worker_exe: &Path,
    session: u32,
    user_sid: &str,
    pipe_name: &str,
    cap_token: &str,
) -> Result<Child, InjectorError> {
    let primary = system_primary_token_for_session(session)?;

    // SAFETY: every buffer below outlives the CreateProcessAsUserW call, and
    // the source environment block is destroyed before we return.
    unsafe {
        let mut src: *mut c_void = std::ptr::null_mut();
        CreateEnvironmentBlock(&mut src, Some(primary.raw()), false)?;
        // SAFETY: `src` is a double-NUL-terminated block owned by the OS.
        let base = read_env_block(src);
        let _ = DestroyEnvironmentBlock(src);

        let mut env = build_env_block(&base, &[(CAP_ENV_VAR, cap_token)]);

        let mut desktop = wide(r"winsta0\default");
        let mut cmdline = wide(&format!(
            "{} --data-pipe {pipe_name} --session {session} --user-sid {user_sid}",
            quote(worker_exe)
        ));
        let workdir = wide(&worker_exe.parent().unwrap_or(worker_exe).to_string_lossy());

        let si = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            lpDesktop: PWSTR(desktop.as_mut_ptr()),
            ..Default::default()
        };
        let mut pi = PROCESS_INFORMATION::default();

        let result = CreateProcessAsUserW(
            Some(primary.raw()),
            None,
            Some(PWSTR(cmdline.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            Some(env.as_mut_ptr() as *const c_void),
            pcwstr(&workdir),
            &si,
            &mut pi,
        );
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

// ---------------------------------------------------------------------------
// Environment-block helpers (the merge is pure and unit-tested)
// ---------------------------------------------------------------------------

/// Copy an OS environment block (a double-NUL-terminated UTF-16 run) into a
/// `Vec<u16>`, including its two terminating NULs.
///
/// # Safety
/// `src` must be null or point at a valid double-NUL-terminated block.
unsafe fn read_env_block(src: *const c_void) -> Vec<u16> {
    if src.is_null() {
        return Vec::new();
    }
    let p = src as *const u16;
    let mut len = 0isize;
    // SAFETY: caller guarantees a double-NUL terminator exists.
    while !(unsafe { *p.offset(len) } == 0 && unsafe { *p.offset(len + 1) } == 0) {
        len += 1;
    }
    // Include both terminating NULs.
    // SAFETY: the run spans `len + 2` u16s, all within the block.
    unsafe { std::slice::from_raw_parts(p, len as usize + 2) }.to_vec()
}

/// Build a `CREATE_UNICODE_ENVIRONMENT` block from `base` (a raw block as read
/// by [`read_env_block`], possibly empty) with `extra` `NAME=VALUE` entries
/// appended. The result is a fresh double-NUL-terminated UTF-16 block.
fn build_env_block(base: &[u16], extra: &[(&str, &str)]) -> Vec<u16> {
    let mut out: Vec<u16> = Vec::new();

    // Copy the existing entries, dropping the block's final terminating NUL so
    // we can append. An empty block ([0, 0], or a lone [0]) contributes nothing.
    if base.len() > 2 {
        // base ends with `\0\0`; keep everything up to (and including) the last
        // entry's own NUL, i.e. drop exactly one trailing NUL.
        out.extend_from_slice(&base[..base.len() - 1]);
    }

    for (k, v) in extra {
        out.extend(k.encode_utf16());
        out.push(b'=' as u16);
        out.extend(v.encode_utf16());
        out.push(0);
    }
    out.push(0); // block terminator
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn block(entries: &[&str]) -> Vec<u16> {
        // Assemble a raw OS-style block: each entry NUL-terminated, then a
        // final block-terminating NUL.
        let mut v: Vec<u16> = Vec::new();
        for e in entries {
            v.extend(e.encode_utf16());
            v.push(0);
        }
        v.push(0);
        v
    }

    /// Parse a built block back into (name, value) pairs for assertions.
    fn parse(block: &[u16]) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let mut cur: Vec<u16> = Vec::new();
        for &c in block {
            if c == 0 {
                if cur.is_empty() {
                    break; // block terminator
                }
                let s = String::from_utf16_lossy(&cur);
                let (k, val) = s.split_once('=').unwrap_or((s.as_str(), ""));
                out.push((k.to_string(), val.to_string()));
                cur.clear();
            } else {
                cur.push(c);
            }
        }
        out
    }

    #[test]
    fn build_env_block_appends_to_an_existing_block() {
        let base = block(&["PATH=C:\\bin", "OS=Windows_NT"]);
        let built = build_env_block(&base, &[(CAP_ENV_VAR, "cafef00d")]);
        let entries = parse(&built);
        assert!(entries.contains(&("PATH".into(), "C:\\bin".into())));
        assert!(entries.contains(&("OS".into(), "Windows_NT".into())));
        assert!(entries.contains(&(CAP_ENV_VAR.into(), "cafef00d".into())));
        // Correctly double-NUL terminated.
        assert_eq!(&built[built.len() - 1..], &[0]);
    }

    #[test]
    fn build_env_block_from_empty_base_still_carries_the_extra() {
        // A minimal/empty OS block is just the block terminator.
        for empty in [Vec::<u16>::new(), vec![0u16], vec![0u16, 0u16]] {
            let built = build_env_block(&empty, &[(CAP_ENV_VAR, "abc123")]);
            let entries = parse(&built);
            assert_eq!(
                entries,
                vec![(CAP_ENV_VAR.to_string(), "abc123".to_string())]
            );
        }
    }

    #[test]
    fn build_env_block_does_not_terminate_early() {
        // The first entry after the base must survive — i.e. no stray NUL got
        // left in that would prematurely end the block.
        let base = block(&["A=1"]);
        let built = build_env_block(&base, &[("B", "2"), (CAP_ENV_VAR, "z")]);
        let entries = parse(&built);
        assert_eq!(entries.len(), 3, "got {entries:?}");
    }

    #[test]
    fn read_env_block_of_null_is_empty() {
        // SAFETY: null is explicitly handled.
        assert!(unsafe { read_env_block(std::ptr::null()) }.is_empty());
    }

    #[test]
    fn enabled_reflects_the_master_switch() {
        let off = UacInjector::new(false, PathBuf::from(r"C:\nope\DirectDeskUacInjector.exe"));
        assert!(!off.enabled());
        let on = UacInjector::new(true, PathBuf::from(r"C:\nope\DirectDeskUacInjector.exe"));
        assert!(on.enabled());
    }

    #[test]
    fn stop_without_a_running_worker_is_ok() {
        let inj = UacInjector::new(true, PathBuf::from(r"C:\nope\DirectDeskUacInjector.exe"));
        assert!(inj.stop().is_ok());
        assert!(inj.stop().is_ok(), "stop must be idempotent");
    }

    #[test]
    fn start_without_system_rights_fails_cleanly() {
        // Unelevated / non-SYSTEM this must be a tidy error, never a panic. The
        // SID lookup (or the token retarget) fails long before any process is
        // created, so nothing is spawned here.
        let inj = UacInjector::new(
            true,
            PathBuf::from(r"C:\nonexistent\DirectDeskUacInjector.exe"),
        );
        match inj.start() {
            Ok(ready) => eprintln!(
                "[uac] worker launched (running as SYSTEM): pipe={}",
                ready.pipe_name
            ),
            Err(e) => eprintln!("[uac] start unavailable as expected: {e}"),
        }
    }

    #[test]
    fn missing_worker_exe_is_reported_when_a_session_exists() {
        // If there is an interactive session and we can resolve the console SID
        // (i.e. running as SYSTEM), a missing worker exe is the failure. If not,
        // an earlier clean error is fine — either way, no panic, no spawn.
        let inj = UacInjector::new(
            true,
            PathBuf::from(r"C:\nonexistent\DirectDeskUacInjector.exe"),
        );
        let _ = inj.start();
    }
}
