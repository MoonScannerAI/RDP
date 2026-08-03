//! Cross-process serialization for tests that drive the real Desktop
//! Duplication + Media Foundation capture pipeline.
//!
//! Only one such test can run at a time on a single machine: there is one GPU
//! capture/encode path, and two concurrent Desktop Duplication + hardware MFT
//! sessions contend and fail. `cargo test --workspace` runs each crate's test
//! *binary* in parallel (the `--test-threads` flag only bounds threads *within*
//! a binary), so the host's loopback test and the client's interop/e2e tests
//! would otherwise race for the encoder. [`CaptureLock`] makes them queue.
//!
//! This is test-only infrastructure exposed as public API so the `directdesk`
//! crates' integration tests (host, and client via its dev-dependency on this
//! crate) can share one implementation.

use std::fs::{self, OpenOptions};
use std::path::PathBuf;
use std::thread::sleep;
use std::time::{Duration, SystemTime};

/// A held cross-process lock. Drop releases it. Acquire it as the first line of
/// any test that boots a real capture/encode host.
pub struct CaptureLock {
    path: PathBuf,
}

impl CaptureLock {
    /// Block until the machine-wide capture lock is held by this process.
    ///
    /// A lock left behind by a crashed test is stolen after 180 s so a single
    /// failure cannot wedge every later run.
    #[must_use]
    pub fn acquire() -> Self {
        let path = std::env::temp_dir().join("directdesk-capture-test.lock");
        loop {
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(_) => return CaptureLock { path },
                Err(_) => {
                    if stale(&path) {
                        let _ = fs::remove_file(&path);
                        continue;
                    }
                    sleep(Duration::from_millis(100));
                }
            }
        }
    }
}

fn stale(path: &PathBuf) -> bool {
    fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .map(|age| age > Duration::from_secs(180))
        .unwrap_or(false)
}

impl Drop for CaptureLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
