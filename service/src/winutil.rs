//! Small Win32 helpers: owned handles, wide strings, an event, COM apartment
//! guard, a launched-child tracker, and the best-effort "is the console
//! user's autostart entry present" query.
//!
//! `OwnedHandle`, `wide`, `pcwstr`, `from_wide_ptr`, `Event`, and
//! `cancel_overlapped` used to be defined here directly; they now live in
//! `directdesk_shared::winutil` (the host needs the identical definitions)
//! and are just re-exported below. Everything else here is service-specific.

pub use directdesk_shared::winutil::{
    cancel_overlapped, from_wide_ptr, pcwstr, wide, Event, OwnedHandle,
};

use windows::Win32::System::Threading::TerminateProcess;

/// A process launched via `CreateProcessAsUserW`: the host agent
/// ([`crate::supervisor`]) and the SYSTEM UAC-injector worker
/// ([`crate::uac_injector`]) each track one of these. The two call sites used
/// to declare identical copies of this struct; same crate, so there is no
/// reason not to share it.
#[derive(Debug)]
pub(crate) struct Child {
    pub(crate) process: OwnedHandle,
    pub(crate) pid: u32,
}

impl Child {
    /// Forcibly kill the process. The UAC-injector worker has no graceful
    /// shutdown (it is short-lived and SYSTEM-integrity); the supervisor uses
    /// this only as the last resort after a `WM_CLOSE` grace period expires.
    pub(crate) fn terminate(&self) {
        // SAFETY: our own process handle, obtained from CreateProcessAsUserW.
        unsafe {
            let _ = TerminateProcess(self.process.raw(), 1);
        }
    }
}

/// RAII COM apartment guard (MTA). Uninitializes only if *we* initialized.
pub struct ComGuard {
    owned: bool,
}

impl ComGuard {
    /// Enter the multithreaded apartment on the current thread.
    pub fn mta() -> anyhow::Result<Self> {
        use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};
        // SAFETY: plain COM init on the calling thread.
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if hr.is_ok() {
            Ok(Self { owned: true })
        } else if hr == windows::Win32::Foundation::RPC_E_CHANGED_MODE {
            // Another apartment already exists on this thread; use it, don't own it.
            Ok(Self { owned: false })
        } else {
            Err(anyhow::anyhow!("CoInitializeEx failed: {hr:?}"))
        }
    }
}

impl Drop for ComGuard {
    fn drop(&mut self) {
        if self.owned {
            // SAFETY: balanced against our successful CoInitializeEx.
            unsafe { windows::Win32::System::Com::CoUninitialize() };
        }
    }
}

/// Registry subkey holding per-user autostart entries.
pub const RUN_SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
/// Value name DirectDesk uses under the Run key.
pub const RUN_VALUE_NAME: &str = "DirectDesk";

/// Best-effort: does the interactive (console) user have the DirectDesk
/// autostart entry under HKCU\...\Run?
///
/// When running as SYSTEM we resolve the console user's SID and read their hive
/// under `HKEY_USERS`. When running as a normal user (CLI, tests) there is no
/// console token to query, so we read our own `HKEY_CURRENT_USER`. Any failure
/// at any step reports `false` — this is a status hint, never a security
/// decision.
pub fn console_user_autostart_enabled() -> bool {
    match console_user_sid_string() {
        Some(sid) => {
            let subkey = format!("{sid}\\{RUN_SUBKEY}");
            reg_value_exists(HkeyRoot::Users, &subkey, RUN_VALUE_NAME)
        }
        None => reg_value_exists(HkeyRoot::CurrentUser, RUN_SUBKEY, RUN_VALUE_NAME),
    }
}

#[derive(Clone, Copy)]
pub enum HkeyRoot {
    Users,
    CurrentUser,
}

/// Does `root\subkey\value` exist? False on any error (including access denied).
pub fn reg_value_exists(root: HkeyRoot, subkey: &str, value: &str) -> bool {
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_CURRENT_USER, HKEY_USERS,
        KEY_QUERY_VALUE,
    };

    let root = match root {
        HkeyRoot::Users => HKEY_USERS,
        HkeyRoot::CurrentUser => HKEY_CURRENT_USER,
    };
    let subkey_w = wide(subkey);
    let value_w = wide(value);
    let mut hkey = HKEY::default();

    // SAFETY: pointers are valid for the duration of the calls; hkey is closed below.
    unsafe {
        if RegOpenKeyExW(root, pcwstr(&subkey_w), None, KEY_QUERY_VALUE, &mut hkey) != ERROR_SUCCESS
        {
            return false;
        }
        let mut size: u32 = 0;
        let status = RegQueryValueExW(hkey, pcwstr(&value_w), None, None, None, Some(&mut size));
        let _ = RegCloseKey(hkey);
        status == ERROR_SUCCESS
    }
}

/// SID (as a string) of the user owning the active console session.
/// `None` unless we are SYSTEM with an interactive session present.
pub fn console_user_sid_string() -> Option<String> {
    use windows::Win32::Foundation::LocalFree;
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_USER};

    let token = crate::supervisor::console_user_token().ok()?;

    // SAFETY: token is a valid token handle; we size the buffer via the first call.
    unsafe {
        let mut needed: u32 = 0;
        let _ = GetTokenInformation(token.raw(), TokenUser, None, 0, &mut needed);
        if needed == 0 {
            return None;
        }
        let mut buf = vec![0u8; needed as usize];
        GetTokenInformation(
            token.raw(),
            TokenUser,
            Some(buf.as_mut_ptr().cast()),
            needed,
            &mut needed,
        )
        .ok()?;
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut sid_str = windows::core::PWSTR::null();
        ConvertSidToStringSidW(user.User.Sid, &mut sid_str).ok()?;
        let s = from_wide_ptr(sid_str.0);
        let _ = LocalFree(Some(windows::Win32::Foundation::HLOCAL(sid_str.0.cast())));
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn com_mta_guard_initializes_and_releases() {
        let g = ComGuard::mta().expect("MTA init should succeed for a normal user");
        drop(g);
        // Re-entering after release must also work.
        let g = ComGuard::mta().expect("second MTA init should succeed");
        drop(g);
    }

    #[test]
    fn reg_query_missing_value_is_false() {
        assert!(!reg_value_exists(
            HkeyRoot::CurrentUser,
            RUN_SUBKEY,
            "DirectDeskDefinitelyNotPresent_ZZZ"
        ));
        assert!(!reg_value_exists(
            HkeyRoot::CurrentUser,
            r"Software\DirectDeskNoSuchKey_ZZZ",
            "whatever"
        ));
    }

    #[test]
    fn autostart_query_never_panics() {
        // Unelevated this exercises the HKCU fallback path.
        let _ = console_user_autostart_enabled();
    }
}
