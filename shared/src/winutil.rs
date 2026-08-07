//! Win32 handle, string, and event primitives shared by the host and service
//! executables.
//!
//! This lives in the contract crate — not duplicated in `host` and `service`
//! — for one reason: the host (medium integrity, in the logged-on user's
//! session) and the service (LocalSystem) hand raw kernel `HANDLE`s to each
//! other and to short-lived worker processes across that privilege boundary
//! (named-pipe instances, process handles from `CreateProcessAsUserW`, wait
//! events). Their ownership, `Send`/`Sync`, and error semantics for those
//! handles must be *identical*, not merely similar.
//!
//! They used to be two hand-kept copies — `host/src/winpipe.rs` and
//! `service/src/winutil.rs` — and had already diverged: `Event::manual_reset`
//! returned `windows::core::Result` in one and `anyhow::Result` in the other.
//! A single definition here makes that kind of drift structurally impossible;
//! `host/src/winpipe.rs` and `service/src/winutil.rs` now just re-export it.
//!
//! Entirely Windows-only, hence the inner `#![cfg(windows)]` below rather
//! than a `#[cfg(windows)]` on the `pub mod winutil;` declaration in `lib.rs`
//! (compare the `#[cfg(windows)] mod dpapi` block in
//! [`crate::crypto::storage`]).

#![cfg(windows)]

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

/// A `HANDLE` that closes itself exactly once.
///
/// `HANDLE` is a raw pointer, so it is not `Send`/`Sync` by default. Win32
/// kernel handles are process-wide and thread-agnostic, so moving or sharing
/// one between threads is sound — which is what the impls below rely on —
/// as long as it is closed exactly once, which `Drop` guarantees.
#[derive(Debug)]
pub struct OwnedHandle(HANDLE);

// SAFETY: see the type doc above.
unsafe impl Send for OwnedHandle {}
unsafe impl Sync for OwnedHandle {}

impl OwnedHandle {
    /// # Safety
    /// `handle` must be a valid handle that this object may exclusively close.
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

/// A manual-reset Win32 event. Used to drive overlapped pipe I/O with a
/// timeout (a worker thread waits on this alongside `WaitForSingleObject`),
/// to wake blocked threads at shutdown, and to deliver one-shot nudges (e.g.
/// "restart the host") without polling.
pub struct Event(OwnedHandle);

impl Event {
    pub fn manual_reset() -> windows::core::Result<Self> {
        use windows::Win32::System::Threading::CreateEventW;
        // SAFETY: unnamed manual-reset event, initially unsignaled.
        let h = unsafe { CreateEventW(None, true, false, None)? };
        // SAFETY: CreateEventW returned a valid, exclusively owned handle.
        Ok(Self(unsafe { OwnedHandle::new(h) }))
    }

    pub fn signal(&self) {
        // SAFETY: our own event handle.
        unsafe {
            let _ = windows::Win32::System::Threading::SetEvent(self.0.raw());
        }
    }

    pub fn reset(&self) {
        // SAFETY: our own event handle.
        unsafe {
            let _ = windows::Win32::System::Threading::ResetEvent(self.0.raw());
        }
    }

    pub fn is_signaled(&self) -> bool {
        use windows::Win32::Foundation::WAIT_OBJECT_0;
        use windows::Win32::System::Threading::WaitForSingleObject;
        // SAFETY: zero-timeout poll on our own event handle.
        unsafe { WaitForSingleObject(self.0.raw(), 0) == WAIT_OBJECT_0 }
    }

    pub fn raw(&self) -> HANDLE {
        self.0.raw()
    }
}

/// Cancel a pending overlapped I/O operation on `pipe` and drain its result,
/// so the kernel no longer references `ov` before it is dropped.
///
/// Used to be hand-kept identically in `service/src/pipe.rs` and
/// `host/src/bin/uac_injector.rs`.
pub fn cancel_overlapped(pipe: &OwnedHandle, ov: &OVERLAPPED) {
    // SAFETY: cancelling our own pending operation, then draining its result
    // so `ov` is no longer referenced by the kernel before it is dropped.
    unsafe {
        let _ = CancelIoEx(pipe.raw(), Some(ov));
        let mut n = 0u32;
        let _ = GetOverlappedResult(pipe.raw(), ov, &mut n, true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_is_nul_terminated() {
        let w = wide("abc");
        assert_eq!(w, vec![b'a' as u16, b'b' as u16, b'c' as u16, 0]);
    }

    #[test]
    fn wide_roundtrips_through_pointer() {
        let w = wide("DirectDesk Service");
        // SAFETY: `w` is NUL-terminated and alive for the call.
        let back = unsafe { from_wide_ptr(w.as_ptr()) };
        assert_eq!(back, "DirectDesk Service");
    }

    #[test]
    fn from_wide_ptr_handles_null() {
        // SAFETY: null is explicitly handled.
        assert_eq!(unsafe { from_wide_ptr(std::ptr::null()) }, "");
    }
}
