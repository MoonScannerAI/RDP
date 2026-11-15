//! The few raw Android C APIs this crate calls directly: liblog's
//! `__android_log_write` and bionic's `__system_property_get`. All `unsafe`
//! for them lives here.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};

use crate::log_chunks;

/// `android_LogPriority` values from `<android/log.h>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Priority {
    Debug = 3,
    Info = 4,
    Warn = 5,
    Error = 6,
    Fatal = 7,
}

#[link(name = "log")]
extern "C" {
    fn __android_log_write(prio: c_int, tag: *const c_char, text: *const c_char) -> c_int;
}

/// Write `msg` to logcat under `tag`, split into several entries if it is
/// longer than one entry can hold. Interior NULs become `?` rather than
/// truncating the message. Never panics.
pub fn log_write(prio: Priority, tag: &CStr, msg: &str) {
    for piece in log_chunks::split(msg, log_chunks::MAX_ENTRY_BYTES) {
        let text = match CString::new(piece) {
            Ok(c) => c,
            Err(_) => match CString::new(piece.replace('\0', "?")) {
                Ok(c) => c,
                Err(_) => continue,
            },
        };
        // SAFETY: both pointers are valid NUL-terminated strings that outlive
        // the call; liblog copies them and keeps no reference.
        unsafe {
            __android_log_write(prio as c_int, tag.as_ptr(), text.as_ptr());
        }
    }
}

/// Read a system property (`getprop`). `None` when unset or empty.
pub fn system_property(name: &str) -> Option<String> {
    let name = CString::new(name).ok()?;
    // PROP_VALUE_MAX includes the terminating NUL.
    let mut buf: [c_char; libc::PROP_VALUE_MAX as usize] = [0; libc::PROP_VALUE_MAX as usize];
    // SAFETY: `name` is NUL-terminated; `buf` is PROP_VALUE_MAX bytes, the
    // documented maximum the call writes (value + NUL).
    let len = unsafe { libc::__system_property_get(name.as_ptr(), buf.as_mut_ptr()) };
    if len <= 0 {
        return None;
    }
    // Bounded read: never trusts the terminator to be inside the buffer.
    // (`c_char` is i8 on x86_64 but u8 on aarch64; `to_ne_bytes` is a bit
    // copy that compiles cast-free on both.)
    let bytes: Vec<u8> = buf.iter().map(|c| c.to_ne_bytes()[0]).collect();
    let value = CStr::from_bytes_until_nul(&bytes).ok()?;
    let value = value.to_string_lossy().trim().to_string();
    (!value.is_empty()).then_some(value)
}
