//! Enforcement for the opt-in "keep UAC's secure desktop disabled" policy
//! (`config::ServiceConfig::disable_uac_secure_desktop`).
//!
//! Windows periodically reasserts its own defaults for this policy (Windows
//! Update and some GPO refreshes flip `PromptOnSecureDesktop` back to `1`), so
//! a one-time write at startup is not enough: [`Reasserter`] re-writes the
//! value once immediately and then on a fixed timer for as long as the
//! service runs, exactly the way [`crate::supervisor::Supervisor`] runs its
//! own background loop.
//!
//! LocalSystem always has write access to `HKEY_LOCAL_MACHINE`, so this is
//! plain registry I/O — no elevation dance, no impersonation. A registry
//! failure is logged and never allowed to crash the service.

use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Registry::{RegSetKeyValueW, HKEY_LOCAL_MACHINE, REG_DWORD};

use crate::winutil::{pcwstr, wide, Event};

/// Registry key (under `HKEY_LOCAL_MACHINE`) holding the system UAC policy.
const POLICY_SUBKEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
/// Value that gates the secure desktop; `0` disables it.
const VALUE_NAME: &str = "PromptOnSecureDesktop";

/// How often the value is re-asserted while the feature is enabled.
pub const REASSERT_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// Write `PromptOnSecureDesktop = 0` (REG_DWORD) under
/// `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
/// creating the key if it does not already exist.
pub fn assert_secure_desktop_disabled() -> anyhow::Result<()> {
    let subkey = wide(POLICY_SUBKEY);
    let value_name = wide(VALUE_NAME);
    let data: u32 = 0;

    // SAFETY: `subkey` and `value_name` are NUL-terminated UTF-16 buffers kept
    // alive for the whole call; `data` is a valid 4-byte REG_DWORD payload
    // whose pointer is only read for the duration of the call.
    let status = unsafe {
        RegSetKeyValueW(
            HKEY_LOCAL_MACHINE,
            pcwstr(&subkey),
            pcwstr(&value_name),
            REG_DWORD.0,
            Some(&data as *const u32 as *const _),
            std::mem::size_of::<u32>() as u32,
        )
    };

    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "RegSetKeyValueW(HKLM\\{POLICY_SUBKEY}\\{VALUE_NAME}) failed: {status:?}"
        ))
    }
}

/// Re-assert the policy once, logging the outcome. Never panics — a registry
/// failure here must not take the service down.
fn reassert_once() {
    match assert_secure_desktop_disabled() {
        Ok(()) => tracing::info!("re-asserted PromptOnSecureDesktop=0"),
        Err(e) => tracing::warn!("could not re-assert PromptOnSecureDesktop=0: {e:#}"),
    }
}

/// Owns the periodic-reassert thread; stops and joins it on drop, the same
/// shutdown shape as [`crate::supervisor::Supervisor`].
pub struct Reasserter {
    stop: Arc<Event>,
    thread: Option<JoinHandle<()>>,
}

impl Reasserter {
    /// Start the background loop: assert once immediately, then again every
    /// [`REASSERT_INTERVAL`] until [`Reasserter::shutdown`] runs.
    pub fn start() -> anyhow::Result<Self> {
        let stop = Arc::new(Event::manual_reset()?);
        let worker_stop = stop.clone();
        let thread = std::thread::Builder::new()
            .name("dd-secure-desktop".into())
            .spawn(move || run(&worker_stop))?;
        tracing::info!("secure-desktop reasserter started");
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }

    pub fn shutdown(&mut self) {
        if let Some(thread) = self.thread.take() {
            tracing::info!("stopping secure-desktop reasserter");
            self.stop.signal();
            let _ = thread.join();
            tracing::info!("secure-desktop reasserter stopped");
        }
    }
}

impl Drop for Reasserter {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn run(stop: &Event) {
    reassert_once();
    while !wait(stop, REASSERT_INTERVAL) {
        reassert_once();
    }
}

/// Wait up to `d`, waking early on stop. Returns `true` if stop fired.
fn wait(stop: &Event, d: Duration) -> bool {
    use windows::Win32::Foundation::WAIT_OBJECT_0;
    use windows::Win32::System::Threading::WaitForSingleObject;
    let ms = d.as_millis().min(u32::MAX as u128) as u32;
    // SAFETY: `stop` is a valid event handle, owned by the `Reasserter` for
    // the whole lifetime of this thread.
    unsafe { WaitForSingleObject(stop.raw(), ms) == WAIT_OBJECT_0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reassert_once_never_panics() {
        // Unelevated (or elevated) this must complete without panicking,
        // whether or not the write actually succeeds — see module docs for
        // why the real registry write is left to manual verification.
        reassert_once();
    }

    #[test]
    fn reasserter_starts_and_stops_cleanly() {
        let mut r = Reasserter::start().unwrap();
        std::thread::sleep(Duration::from_millis(50));
        let t0 = std::time::Instant::now();
        r.shutdown();
        r.shutdown(); // idempotent
        assert!(
            t0.elapsed() < Duration::from_secs(3),
            "shutdown took {:?}",
            t0.elapsed()
        );
    }

    #[test]
    fn wait_returns_promptly_on_stop() {
        let stop = Event::manual_reset().unwrap();
        stop.signal();
        let t0 = std::time::Instant::now();
        assert!(wait(&stop, Duration::from_secs(30)));
        assert!(t0.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn wait_times_out_without_stop() {
        let stop = Event::manual_reset().unwrap();
        assert!(!wait(&stop, Duration::from_millis(50)));
    }
}
