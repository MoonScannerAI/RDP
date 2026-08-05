//! Minimal Win32 named-pipe helpers for the UAC click-through path.
//!
//! The host crate already links the `windows` crate for capture and injection;
//! this module adds just enough to (a) act as a one-instance message-mode pipe
//! **server** (the SYSTEM worker) and (b) act as a synchronous message-mode
//! **client** (the host driving the worker, and the host's control-pipe client
//! to the service). It deliberately mirrors `service/src/pipe.rs` and
//! `service/src/winutil.rs` rather than depending on them: the service crate is
//! off-limits and its helpers are private.

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};

/// A `HANDLE` that closes itself exactly once.
#[derive(Debug)]
pub struct OwnedHandle(HANDLE);

// SAFETY: Win32 kernel handles are process-wide and thread-agnostic; moving one
// between threads is sound, and we close it exactly once in Drop.
unsafe impl Send for OwnedHandle {}
unsafe impl Sync for OwnedHandle {}

impl OwnedHandle {
    /// # Safety
    /// `handle` must be a valid handle this object may exclusively close.
    pub unsafe fn new(handle: HANDLE) -> Self {
        Self(handle)
    }

    pub fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: we own this handle and only close it once.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// NUL-terminated UTF-16 buffer suitable for [`PCWSTR`].
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Borrow a [`wide`] buffer as a [`PCWSTR`].
pub fn pcwstr(buf: &[u16]) -> PCWSTR {
    PCWSTR(buf.as_ptr())
}

/// A manual-reset Win32 event, used to drive overlapped pipe I/O with a
/// timeout (the worker waits on this alongside `WaitForSingleObject`).
pub struct Event(OwnedHandle);

impl Event {
    pub fn manual_reset() -> windows::core::Result<Self> {
        use windows::Win32::System::Threading::CreateEventW;
        // SAFETY: unnamed manual-reset event, initially unsignaled.
        let h = unsafe { CreateEventW(None, true, false, None)? };
        // SAFETY: CreateEventW returned a valid, exclusively owned handle.
        Ok(Self(unsafe { OwnedHandle::new(h) }))
    }

    pub fn raw(&self) -> HANDLE {
        self.0.raw()
    }
}

/// Read a NUL-terminated wide string from a raw pointer.
///
/// # Safety
/// `ptr` must be null or point at a NUL-terminated UTF-16 string.
pub unsafe fn from_wide_ptr(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    // SAFETY: caller guarantees NUL termination.
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: len is the length up to (not including) the NUL.
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(ptr, len) })
}
