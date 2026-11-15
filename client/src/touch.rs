//! Touch-to-mouse gesture recognition for the touch UI profile (trackpad
//! mode). A pure state machine: touch events plus a clock in, pointer actions
//! (in remote-normalized coordinates) out. No egui painting, no channels — so
//! every gesture is unit tested on Windows.
//!
//! Owned by W4 (Phase 1).
