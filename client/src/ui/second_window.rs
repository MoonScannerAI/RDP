//! The second monitor's OS window: a chrome-less, video-only **deferred**
//! viewport driven by the stream-1 decode path.
//!
//! # Why deferred rather than immediate
//!
//! egui offers both. `show_viewport_immediate`'s own documentation says it
//! "requires both parent and child to repaint if any one of them needs
//! repainting — double work for two viewports". Both of these windows show
//! 30-60 fps video, so immediate mode would double every frame's work
//! permanently and weld the two decode threads' repaint cadences together: a
//! stalled second monitor would drag the primary picture down with it, which is
//! the one failure mode a second window must never be able to cause. Deferred
//! also keeps painting while the parent sleeps — exactly what a video window
//! wants.
//!
//! The price is that the callback must be `Fn + Send + Sync + 'static`, so
//! everything it touches lives behind an `Arc<Mutex<…>>` ([`SecondaryShared`]).
//! That is cheap here because the secondary window's state is small and
//! self-contained, and the lock is only ever held *inside* the callback or
//! briefly in the parent's logic pass — never across the parent's paint.
//!
//! # Lifetime
//!
//! A deferred viewport exists only while it is re-declared. [`show`] must
//! therefore be called on **every** parent pass while the window should be up,
//! and simply not calling it is what closes the OS window. `ClientApp` owns that
//! decision (`stream1_window_open`); this module owns nothing but the pixels.

use std::sync::Arc;

use parking_lot::Mutex;

use crate::renderer::{FrameSlot, Presenter, SECOND_VIDEO_TEXTURE};

/// Stable `ViewportId` for the second monitor's window.
///
/// A function rather than a `const` because `ViewportId::from_hash_of` is not
/// const-constructible. Every producer and consumer must route through this one
/// call — `Context::request_repaint_of`, `Context::input_for` and
/// `show_viewport_deferred` all key on it, and an id computed from a different
/// string in any one of them would silently mean "some other window".
pub fn stream1_viewport_id() -> egui::ViewportId {
    egui::ViewportId::from_hash_of("directdesk-stream1")
}

/// Default size of the second window when it first opens. Deliberately modest:
/// the operator can resize it, and `Presenter::draw` letterboxes whatever it
/// gets, so guessing the host's aspect ratio here would buy nothing.
const DEFAULT_INNER_SIZE: [f32; 2] = [960.0, 540.0];

/// Everything the second window's paint callback touches, plus the flags it
/// reports back to `ClientApp`'s logic pass.
///
/// Shared behind an `Arc<Mutex<…>>` because `show_viewport_deferred` demands a
/// `Send + Sync + 'static` callback (see the module docs).
pub struct SecondaryShared {
    /// Uploads into [`SECOND_VIDEO_TEXTURE`] — never the main window's texture.
    presenter: Presenter,
    /// The stream-1 frame slot, written by the second decode thread.
    slot: Arc<FrameSlot>,

    /// Whether the child window held focus on its last pass.
    ///
    /// **C4 seam.** Milestone C4 makes "is a DirectDesk window in the
    /// foreground" mean *either* window, so the low-level hook's pass-through
    /// gate stops treating a focused second window as "we are in the
    /// background". Written here from the child's own `InputState`, which is
    /// the only place the child's focus is observable.
    pub focused: bool,

    /// The child window's title bar close button was clicked.
    ///
    /// Set inside the child pass and consumed (and cleared) by `ClientApp`,
    /// which owns the teardown: closing this window also tells the host to stop
    /// encoding that monitor.
    pub close_requested: bool,

    /// The release chord was typed while the child window had focus.
    ///
    /// **C4 seam.** The chord is serviced from the *parent's* input today
    /// (`ClientApp::reconcile_capture`), which cannot see keys delivered to the
    /// child viewport. C4 detects it inside the child pass, swallows it from
    /// forwarding, and latches it here as a one-shot for the parent to consume
    /// exactly like its own detection — one flag, so no double-toggle.
    pub chord_fired: bool,

    /// Last pointer position seen in the child window.
    ///
    /// **C4 seam.** `MouseWheel` events carry no position, so the wheel
    /// forwarder needs the most recent one — the same reason `ClientApp` caches
    /// `pointer` for the main window.
    pub last_pointer: Option<egui::Pos2>,

    /// Mirror of `InputCapture::is_capturing()`, refreshed by the parent each
    /// logic pass.
    ///
    /// **C4 seam.** The child pass runs inside a `Fn` callback that cannot
    /// reach `ClientApp`, so the capture gate has to be pushed in rather than
    /// pulled. Until C4 wires the forwarders this is written and never read,
    /// which is why it is set from exactly one place.
    pub capturing: bool,
}

impl SecondaryShared {
    pub fn new(slot: Arc<FrameSlot>) -> Self {
        Self {
            presenter: Presenter::new(SECOND_VIDEO_TEXTURE),
            slot,
            focused: false,
            close_requested: false,
            chord_fired: false,
            last_pointer: None,
            capturing: false,
        }
    }

    /// Drop the picture and every latched flag.
    ///
    /// Called from each of `ClientApp`'s teardown sites. `clear_slot` mirrors
    /// the stream-0 asymmetry those sites already have: the `Bye` path
    /// deliberately leaves the pending frame alone while the others clear it.
    pub fn reset(&mut self, clear_slot: bool) {
        self.presenter.reset();
        if clear_slot {
            self.slot.clear();
        }
        self.focused = false;
        self.close_requested = false;
        self.chord_fired = false;
        self.last_pointer = None;
    }

    /// Rate the second stream is decoding at, for the metrics dump.
    pub fn fps_decode(&self) -> f32 {
        self.presenter.fps_decode()
    }

    /// One paint of the child viewport.
    ///
    /// Runs *inside* the child's own viewport, so `ui.ctx().input(…)` here is
    /// the child window's `InputState`, not the parent's — that is precisely
    /// why focus and the close request are read here and nowhere else.
    fn pass(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();

        // Texture upload on the child's cadence: the second decode thread wakes
        // this viewport directly via `request_repaint_of`, so the picture
        // advances whether or not the parent window is awake.
        self.presenter.update(&ctx, &self.slot);

        let (focused, close_requested, pointer) = ctx.input(|i| {
            (
                i.focused,
                i.viewport().close_requested(),
                i.pointer.latest_pos(),
            )
        });
        self.focused = focused;
        // Latched, never cleared here: the parent consumes it. A close request
        // is reported for one pass only, so sampling it anywhere else would
        // mean losing it.
        self.close_requested |= close_requested;
        if let Some(pos) = pointer {
            self.last_pointer = Some(pos);
        }

        // Chrome-less and video-only by construction: no toolbar panel exists
        // here, so there is no chrome to measure and none of the main window's
        // `chrome_points` / auto-snap / integer-scale machinery applies. The
        // letterboxing is `Presenter::draw`'s own fit.
        let presenter = &self.presenter;
        egui::CentralPanel::no_frame()
            .frame(egui::Frame::NONE.fill(egui::Color32::BLACK))
            .show(ui, |ui| {
                let (viewport, view) = presenter.draw(ui);
                if view.is_none() {
                    ui.painter_at(viewport).text(
                        viewport.center(),
                        egui::Align2::CENTER_CENTER,
                        "Waiting for the second monitor…",
                        egui::FontId::proportional(16.0),
                        egui::Color32::GRAY,
                    );
                }
                // C4 seam: pointer, wheel and key forwarding for stream 1 land
                // here, reading `ui.ctx().input(…)` (the child's events, which
                // must be consumed in this pass — reading them from the parent
                // would double- or mis-count them) and mapping through `view`
                // with `chrome_points = 0`, since the whole panel is video.
                let _ = view;
            });
    }
}

/// Declare the second window for this pass.
///
/// Must be called on every parent pass while the window should exist; see the
/// module docs. `title` is applied to the OS window each pass, so it tracks the
/// monitor's name and dimensions as they are learned.
pub fn show(ctx: &egui::Context, shared: &Arc<Mutex<SecondaryShared>>, title: &str) {
    let shared = shared.clone();
    ctx.show_viewport_deferred(
        stream1_viewport_id(),
        egui::ViewportBuilder::default()
            .with_title(title)
            .with_inner_size(DEFAULT_INNER_SIZE),
        move |ui, _class| shared.lock().pass(ui),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_viewport_id_is_stable_and_is_not_the_root() {
        // Every producer and consumer keys on this one value; if it were
        // derived per call the decode thread's `request_repaint_of` would wake
        // a window nobody is showing.
        assert_eq!(stream1_viewport_id(), stream1_viewport_id());
        assert_ne!(stream1_viewport_id(), egui::ViewportId::ROOT);
    }

    #[test]
    fn the_secondary_presenter_never_uploads_into_the_main_texture() {
        let shared = SecondaryShared::new(Arc::new(FrameSlot::new()));
        assert_eq!(shared.presenter.texture_name(), SECOND_VIDEO_TEXTURE);
    }

    #[test]
    fn reset_clears_every_latched_flag() {
        // Stale flags outlive the session they were latched in: a
        // `close_requested` left set would slam the window shut the instant the
        // next connection opened it.
        let slot = Arc::new(FrameSlot::new());
        let mut shared = SecondaryShared::new(slot.clone());
        shared.focused = true;
        shared.close_requested = true;
        shared.chord_fired = true;
        shared.last_pointer = Some(egui::pos2(1.0, 2.0));

        shared.reset(false);
        assert!(!shared.focused);
        assert!(!shared.close_requested);
        assert!(!shared.chord_fired);
        assert_eq!(shared.last_pointer, None);
    }

    #[test]
    fn reset_honours_the_slot_asymmetry_of_its_call_sites() {
        use directdesk_shared::traits::{PixelFormat, RawFrame};
        let frame = || RawFrame {
            width: 1,
            height: 1,
            format: PixelFormat::Rgba8,
            data: vec![0; 4],
            timestamp_ms: 0,
        };

        // `Bye` resets the picture but deliberately leaves the pending frame,
        // matching what the stream-0 path at that site already does.
        let slot = Arc::new(FrameSlot::new());
        let mut shared = SecondaryShared::new(slot.clone());
        slot.publish(frame());
        shared.reset(false);
        assert!(slot.take_newer_than(0).is_some());

        // Every other teardown site drops it.
        let slot = Arc::new(FrameSlot::new());
        let mut shared = SecondaryShared::new(slot.clone());
        slot.publish(frame());
        shared.reset(true);
        assert!(slot.take_newer_than(0).is_none());
    }
}
