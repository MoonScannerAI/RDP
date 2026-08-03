//! Per-thread COM (MTA) + Media Foundation lifetime management.
//!
//! Every thread that touches D3D11/MF must be COM-initialized. MF additionally
//! needs `MFStartup`/`MFShutdown` balanced per thread that starts it. We track
//! nesting depth in a thread-local so nested guards are cheap and correct.

use std::cell::Cell;
use std::marker::PhantomData;

use directdesk_shared::{Error, Result};
use windows::Win32::Media::MediaFoundation::{MFShutdown, MFStartup, MFSTARTUP_FULL, MF_VERSION};
use windows::Win32::System::Com::{
    CoInitializeEx, CoUninitialize, COINIT_DISABLE_OLE1DDE, COINIT_MULTITHREADED,
};

thread_local! {
    static DEPTH: Cell<u32> = const { Cell::new(0) };
}

/// RAII guard: COM apartment (MTA) + Media Foundation are live for this thread
/// while the guard exists. `!Send`/`!Sync` by construction — a guard must be
/// dropped on the same thread that created it.
pub struct MfThread {
    _not_send: PhantomData<*const ()>,
}

impl MfThread {
    /// Initialize COM (MTA) and Media Foundation for the calling thread.
    ///
    /// # Safety invariants
    /// The returned guard must be dropped on the same thread. `RPC_E_CHANGED_MODE`
    /// (the thread is already an STA — eframe/winit does this on the UI thread) is
    /// tolerated: we simply do not own the apartment and skip `CoUninitialize`.
    pub fn enter() -> Result<Self> {
        let depth = DEPTH.with(|d| d.get());
        if depth == 0 {
            // SAFETY: plain FFI; both calls are per-thread and balanced in Drop.
            unsafe {
                let hr = CoInitializeEx(None, COINIT_MULTITHREADED | COINIT_DISABLE_OLE1DDE);
                // S_FALSE = already initialized (still needs a matching uninit).
                // RPC_E_CHANGED_MODE = thread is an STA; usable, but not ours.
                if hr.is_err() && hr.0 != RPC_E_CHANGED_MODE {
                    return Err(Error::Other(format!("CoInitializeEx failed: {hr:?}")));
                }
                // FULL rather than LITE: some vendor hardware MFTs (NVENC in
                // particular) fail to activate under a lite startup.
                MFStartup(MF_VERSION, MFSTARTUP_FULL)
                    .map_err(|e| Error::Other(format!("MFStartup failed: {e}")))?;
            }
        }
        DEPTH.with(|d| d.set(depth + 1));
        Ok(Self {
            _not_send: PhantomData,
        })
    }
}

impl Drop for MfThread {
    fn drop(&mut self) {
        let depth = DEPTH.with(|d| d.get());
        if depth == 1 {
            // SAFETY: balanced against the successful init above on this thread.
            unsafe {
                let _ = MFShutdown();
                CoUninitialize();
            }
        }
        DEPTH.with(|d| d.set(depth.saturating_sub(1)));
    }
}

const RPC_E_CHANGED_MODE: i32 = 0x8001_0106_u32 as i32;
