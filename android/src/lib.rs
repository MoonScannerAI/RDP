//! DirectDesk for Android: NativeActivity entry point, MediaCodec decoder,
//! logcat logging. Android-only; an empty library elsewhere.
//!
//! Module map:
//!
//! * `app_main`    — `android_main`: builds the `PlatformConfig`, runs the
//!   shared client app; when it returns, finishes the Activity and ends the
//!   process; ends the process when Android destroys the Activity on its
//!   own (a destroy watchdog: winit ignores `Destroy`, which would hang the
//!   Java main thread) and when Android reuses it for a second Activity
//!   (winit allows one event loop per process; see its docs).
//! * `mediacodec`  — `Decoder` over AMediaCodec (sync ByteBuffer mode).
//! * `logcat`      — tracing/log → logcat (tag `DirectDesk`), panic hook.
//! * `sys`         — the raw liblog / system-property FFI.
//! * `codec_state`, `log_chunks`, `store_dir` — platform-neutral helpers.
//!   They are also compiled under `cfg(test)` so their unit tests run on
//!   Windows with `cargo test --workspace`; a normal Windows build of this
//!   crate is still empty.
//!
//! Every module is gated individually rather than with a crate-level
//! `#![cfg(target_os = "android")]`, solely so the helper modules can be
//! tested off-device.

#[cfg(any(target_os = "android", test))]
mod codec_state;
#[cfg(any(target_os = "android", test))]
mod log_chunks;
#[cfg(any(target_os = "android", test))]
mod store_dir;

#[cfg(target_os = "android")]
mod app_main;
#[cfg(target_os = "android")]
mod logcat;
#[cfg(target_os = "android")]
mod mediacodec;
#[cfg(target_os = "android")]
mod sys;
