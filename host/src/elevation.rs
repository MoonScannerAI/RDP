//! Detecting a UAC / elevation **consent** prompt on the *normal* desktop.
//!
//! With `PromptOnSecureDesktop=0` the consent dialog (`consent.exe`, running at
//! System integrity) is drawn on the interactive desktop, so
//! [`crate::capture::secure_desktop_active`] returns `false` and the host keeps
//! capturing — but the medium-integrity host still cannot *click* the dialog
//! because UIPI blocks its `SendInput`. This module spots that specific window
//! so the host can offer the operator the SYSTEM click-through.
//!
//! It is intentionally cheap (one `GetForegroundWindow` + one process-image
//! query) so the caller can poll it at a few hertz with a debounce.

/// A consent prompt currently in the foreground.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentPrompt {
    /// PID of the foreground `consent.exe` (or credential-broker) process.
    pub pid: u32,
    /// The window caption, shown to the operator so they see what they approve.
    pub title: String,
}

/// Executable base names whose foreground window we treat as an elevation
/// consent prompt. `consent.exe` is the classic UAC dialog; the credential UI
/// broker hosts the modern XAML credential prompt.
pub const CONSENT_IMAGES: [&str; 2] = ["consent.exe", "credentialuibroker.exe"];

/// Is `image_path`'s base name one of [`CONSENT_IMAGES`]? Case-insensitive.
///
/// Pure and unit-tested. This is the **lenient** check: it trusts the base name
/// only, so it is used *only* by [`detect_consent_prompt`], which merely decides
/// whether to OFFER the operator the click-through banner. The SYSTEM worker's
/// injection guardrail uses the stricter [`is_consent_path`] instead.
pub fn is_consent_image(image_path: &str) -> bool {
    let base = image_path
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(image_path)
        .trim();
    CONSENT_IMAGES
        .iter()
        .any(|name| base.eq_ignore_ascii_case(name))
}

/// Does `full_path` name the *real* consent binary — i.e. one of
/// [`CONSENT_IMAGES`] located directly under `%SystemRoot%\System32`?
///
/// Unlike [`is_consent_image`] this rejects any `consent.exe`/`credentialuibroker.exe`
/// that lives outside System32 (a look-alike an attacker dropped elsewhere and
/// pushed to the foreground). Case-insensitive; forward and back slashes are
/// treated alike. Pure and unit-tested — the SYSTEM worker resolves the actual
/// `%SystemRoot%` at runtime and feeds it here before every injection.
pub fn is_consent_path(full_path: &str, system_root: &str) -> bool {
    let normalize = |s: &str| s.trim().replace('/', "\\").to_ascii_lowercase();
    let root = normalize(system_root);
    let root = root.trim_end_matches('\\');
    let actual = normalize(full_path);
    CONSENT_IMAGES.iter().any(|name| {
        // CONSENT_IMAGES entries are already lowercase base names.
        let want = format!(r"{root}\system32\{name}");
        actual == want
    })
}

#[cfg(windows)]
mod imp {
    use super::ConsentPrompt;
    use crate::winpipe::OwnedHandle;
    use windows::Win32::Foundation::RECT;
    use windows::Win32::Foundation::{HWND, MAX_PATH};
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        GetForegroundWindow, GetWindowRect, GetWindowTextLengthW, GetWindowTextW,
        GetWindowThreadProcessId,
    };

    use crate::uac_proto::PixelRect;

    /// The foreground process's full image path, or `None`.
    pub(super) fn foreground_process_image(hwnd: HWND) -> Option<(u32, String)> {
        let mut pid: u32 = 0;
        // SAFETY: hwnd is the foreground window handle; pid is written by the call.
        let _tid = unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
        if pid == 0 {
            return None;
        }
        // SAFETY: LIMITED_INFORMATION is enough for the image path and is grantable
        // even for a higher-integrity process; the handle is closed by OwnedHandle.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
        // SAFETY: valid handle, exclusively owned by the wrapper.
        let handle = unsafe { OwnedHandle::new(handle) };

        let mut buf = [0u16; MAX_PATH as usize];
        let mut len = buf.len() as u32;
        // SAFETY: buf/len are valid for the call; len is updated to the written size.
        let ok = unsafe {
            QueryFullProcessImageNameW(
                handle.raw(),
                PROCESS_NAME_FORMAT(0),
                windows::core::PWSTR(buf.as_mut_ptr()),
                &mut len,
            )
        };
        if ok.is_err() {
            return None;
        }
        Some((pid, String::from_utf16_lossy(&buf[..len as usize])))
    }

    /// Read a window's caption text.
    pub(super) fn window_title(hwnd: HWND) -> String {
        // SAFETY: hwnd is a valid window handle for the length query.
        let len = unsafe { GetWindowTextLengthW(hwnd) };
        if len <= 0 {
            return String::new();
        }
        let mut buf = vec![0u16; len as usize + 1];
        // SAFETY: buf has room for len+NUL; the call returns the copied length.
        let copied = unsafe { GetWindowTextW(hwnd, &mut buf) };
        String::from_utf16_lossy(&buf[..copied as usize])
    }

    pub(super) fn detect() -> Option<ConsentPrompt> {
        // SAFETY: returns the foreground HWND or a null handle we then reject.
        let hwnd = unsafe { GetForegroundWindow() };
        if hwnd.0.is_null() {
            return None;
        }
        let (pid, image) = foreground_process_image(hwnd)?;
        if !super::is_consent_image(&image) {
            return None;
        }
        Some(ConsentPrompt {
            pid,
            title: window_title(hwnd),
        })
    }

    /// `%SystemRoot%` (e.g. `C:\Windows`), or the conventional default if the
    /// environment does not carry it.
    fn system_root() -> String {
        std::env::var("SystemRoot")
            .or_else(|_| std::env::var("windir"))
            .unwrap_or_else(|_| r"C:\Windows".to_string())
    }

    /// If (and only if) a consent process owns the foreground window, its PID
    /// and screen rectangle. This is the SYSTEM worker's per-injection guardrail
    /// primitive: no consent window in front → `None` → drop the event.
    ///
    /// The guardrail requires the foreground process's *full image path* to be
    /// the real `%SystemRoot%\System32\consent.exe` (or the credential broker),
    /// not merely a process named `consent.exe` from some other directory.
    pub(super) fn foreground_consent_rect() -> Option<(u32, PixelRect)> {
        // SAFETY: foreground HWND or a null handle we reject.
        let hwnd = unsafe { GetForegroundWindow() };
        if hwnd.0.is_null() {
            return None;
        }
        let (pid, image) = foreground_process_image(hwnd)?;
        if !super::is_consent_path(&image, &system_root()) {
            return None;
        }
        let mut r = RECT::default();
        // SAFETY: hwnd is a valid window; r is written on success.
        unsafe { GetWindowRect(hwnd, &mut r) }.ok()?;
        Some((
            pid,
            PixelRect {
                left: r.left,
                top: r.top,
                right: r.right,
                bottom: r.bottom,
            },
        ))
    }
}

/// Return the consent prompt in the foreground, or `None`.
///
/// Cheap enough to poll at ~4-8 Hz. The caller is expected to debounce so a
/// single missed poll (e.g. the user briefly focusing another window) does not
/// tear the arming down.
#[cfg(windows)]
pub fn detect_consent_prompt() -> Option<ConsentPrompt> {
    imp::detect()
}

/// Non-Windows stub so the pure logic and its tests build anywhere.
#[cfg(not(windows))]
pub fn detect_consent_prompt() -> Option<ConsentPrompt> {
    None
}

/// The foreground consent window's PID and screen rectangle, if one is present.
///
/// Used by the SYSTEM worker before every injection: `None` means there is no
/// consent dialog in front, so the event must be dropped rather than injected.
#[cfg(windows)]
pub fn foreground_consent_rect() -> Option<(u32, crate::uac_proto::PixelRect)> {
    imp::foreground_consent_rect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_consent_exe_regardless_of_path_or_case() {
        assert!(is_consent_image(r"C:\Windows\System32\consent.exe"));
        assert!(is_consent_image(r"C:\Windows\System32\Consent.EXE"));
        assert!(is_consent_image("consent.exe"));
        assert!(is_consent_image(
            r"C:\Windows\System32\CredentialUIBroker.exe"
        ));
    }

    #[test]
    fn rejects_lookalikes_and_unrelated_processes() {
        assert!(!is_consent_image(r"C:\evil\notconsent.exe"));
        assert!(!is_consent_image(r"C:\Windows\explorer.exe"));
        assert!(!is_consent_image(r"C:\x\consent.exe.evil.exe"));
        assert!(!is_consent_image("consent"));
        assert!(!is_consent_image(""));
    }

    #[test]
    fn is_consent_path_accepts_only_the_real_system32_binary() {
        let root = r"C:\Windows";
        assert!(is_consent_path(r"C:\Windows\System32\consent.exe", root));
        // Case-insensitive on both the path and the root; slashes normalized.
        assert!(is_consent_path(r"c:\windows\system32\CONSENT.EXE", root));
        assert!(is_consent_path("C:/Windows/System32/consent.exe", root));
        assert!(is_consent_path(
            r"C:\Windows\System32\CredentialUIBroker.exe",
            root
        ));
        // A trailing separator on the root must not break the match.
        assert!(is_consent_path(
            r"C:\Windows\System32\consent.exe",
            r"C:\Windows\"
        ));
        // A non-default SystemRoot is honored.
        assert!(is_consent_path(
            r"D:\WinDir\System32\consent.exe",
            r"D:\WinDir"
        ));
    }

    #[test]
    fn is_consent_path_rejects_lookalikes_outside_system32() {
        let root = r"C:\Windows";
        // Right name, wrong directory — the classic planted look-alike.
        assert!(!is_consent_path(r"C:\Temp\consent.exe", root));
        assert!(!is_consent_path(r"C:\Windows\consent.exe", root));
        assert!(!is_consent_path(
            r"C:\Windows\System32\drivers\consent.exe",
            root
        ));
        // Right directory, wrong (unrelated) binary.
        assert!(!is_consent_path(r"C:\Windows\System32\cmd.exe", root));
        // A different SystemRoot must not accept the C:\Windows copy.
        assert!(!is_consent_path(
            r"C:\Windows\System32\consent.exe",
            r"D:\WinDir"
        ));
        assert!(!is_consent_path("", root));
    }

    #[test]
    fn detect_never_panics() {
        // Whatever is in the foreground on the test box, this must be a clean
        // Option, never a crash.
        let _ = detect_consent_prompt();
    }
}
