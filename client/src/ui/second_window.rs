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

use directdesk_shared::protocol::InputMsg;
use parking_lot::Mutex;
use tokio::sync::mpsc;

use crate::input_capture::{chord_pressed, EguiKeyForwarder, PointerForwarder};
use crate::renderer::{FrameSlot, Presenter, SECOND_VIDEO_TEXTURE};

/// The stream id the second window's pointer events are tagged with.
///
/// Slot 1 by construction: the client only ever asks for two streams, and
/// `SelectMonitors` gives the second entry slot 1. Keyboard is *not* tagged —
/// see [`EguiKeyForwarder`].
pub const SECOND_STREAM_ID: u8 = 1;

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

    /// This window's pointer path. Tagged `EventOn { id: 1 }`, with its **own**
    /// [`crate::input_capture::MoveCoalescer`] so neither window's motion can
    /// starve the other's rate cap. Starts disarmed; `ClientApp` arms it only on
    /// a session that negotiated multi-monitor.
    pointer: PointerForwarder,
    /// This window's egui key path. Its output rides legacy `InputMsg::Event`
    /// exactly like the main window's — keys are global on the host — but the
    /// synthesized-modifier bookkeeping is per-window, so this forwarder
    /// releases what *it* synthesized when *this* window loses focus.
    keys: EguiKeyForwarder,

    /// Whether the child window held focus on its last pass.
    ///
    /// Read by `ClientApp` so "is a DirectDesk window in the foreground" means
    /// *either* window, and the low-level hook's pass-through gate stops
    /// treating a focused second window as "we are in the background". Written
    /// here from the child's own `InputState`, which is the only place the
    /// child's focus is observable.
    pub focused: bool,

    /// The child window's title bar close button was clicked.
    ///
    /// Set inside the child pass and consumed (and cleared) by `ClientApp`,
    /// which owns the teardown: closing this window also tells the host to stop
    /// encoding that monitor.
    pub close_requested: bool,

    /// The release chord was typed while the child window had focus.
    ///
    /// The chord is serviced from the *parent's* input (`reconcile_capture`),
    /// which cannot see keys delivered to the child viewport — each window has
    /// its own `InputState`. The child pass detects it with the same pure
    /// [`chord_pressed`] the parent uses, swallows it from forwarding, and
    /// latches it here as a one-shot the parent consumes exactly like its own
    /// detection. One flag, so the chord can never toggle capture twice.
    pub chord_fired: bool,

    /// Last pointer position seen in the child window.
    ///
    /// `MouseWheel` events carry no position, so the wheel forwarder needs the
    /// most recent one — the same reason `ClientApp` caches `pointer` for the
    /// main window.
    pub last_pointer: Option<egui::Pos2>,

    /// Mirror of `InputCapture::is_capturing()`, refreshed by the parent each
    /// logic pass through [`SecondaryShared::set_capturing`].
    ///
    /// The child pass runs inside a `Fn` callback that cannot reach
    /// `ClientApp`, so the capture gate has to be pushed in rather than pulled.
    capturing: bool,
}

impl SecondaryShared {
    pub fn new(slot: Arc<FrameSlot>, tx: mpsc::Sender<InputMsg>) -> Self {
        Self {
            presenter: Presenter::new(SECOND_VIDEO_TEXTURE),
            slot,
            pointer: PointerForwarder::on_stream(tx.clone(), SECOND_STREAM_ID),
            keys: EguiKeyForwarder::new(tx),
            focused: false,
            close_requested: false,
            chord_fired: false,
            last_pointer: None,
            capturing: false,
        }
    }

    /// Let this window's pointer events onto the wire.
    ///
    /// `armed` is `monitors.is_some()` — the arrival of a `MonitorList` is the
    /// only proof `MULTI_MONITOR` came back mutual, and the UI is the only
    /// place that knows it. An `EventOn` sent to a host that never echoed the
    /// bit does not get skipped by its `decode_strict` reader: it errors, and
    /// the error kills the whole input stream.
    pub fn set_armed(&mut self, armed: bool) {
        self.pointer.set_armed(armed);
    }

    /// Push the capture gate down from `ClientApp`.
    ///
    /// On the falling edge this window forgets its synthesized modifiers
    /// *without* sending ups: `InputCapture::release_all` has already put a
    /// global `ReleaseAll` on the wire, which drops everything the host holds.
    pub fn set_capturing(&mut self, capturing: bool) {
        if self.capturing && !capturing {
            self.keys.forget_synth_mods();
            self.pointer.clear_gesture();
        }
        self.capturing = capturing;
    }

    /// Take the release chord this window saw, if any. One-shot.
    pub fn take_chord_fired(&mut self) -> bool {
        std::mem::take(&mut self.chord_fired)
    }

    /// Is this window holding a mouse button down on the host? Its window is
    /// about to go away, so somebody has to lift it.
    pub fn has_buttons_held(&self) -> bool {
        self.pointer.is_dragging()
    }

    /// Drop the picture and every latched flag.
    ///
    /// Called from each of `ClientApp`'s teardown sites. `clear_slot` mirrors
    /// the stream-0 asymmetry those sites already have: the `Bye` path
    /// deliberately leaves the pending frame alone while the others clear it.
    ///
    /// Input state is *forgotten*, never released from here: this runs at
    /// teardown, where the caller owns the decision of whether a `ReleaseAll`
    /// is owed (see `ClientApp::close_second_window`) — and a `ReleaseAll` is
    /// global, so emitting one unasked would drop the main window's held keys
    /// too. Disarming is the important half: a new session must re-prove it
    /// negotiated multi-monitor before this window's events reach the wire.
    pub fn reset(&mut self, clear_slot: bool) {
        self.presenter.reset();
        if clear_slot {
            self.slot.clear();
        }
        self.focused = false;
        self.close_requested = false;
        self.chord_fired = false;
        self.last_pointer = None;
        self.capturing = false;
        // Forget before dropping focus, so the falling edge inside
        // `set_focused` has nothing left to send.
        self.keys.forget_synth_mods();
        self.keys.set_focused(false);
        self.pointer.clear_gesture();
        self.pointer.set_armed(false);
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

        // Read once, here: inside this callback `ctx.input` IS the child
        // viewport's own `InputState`. The events in particular must be
        // consumed in this pass — sampling them from the parent's logic would
        // read them twice, or miss them entirely.
        let (focused, close_requested, pointer, events) = ctx.input(|i| {
            (
                i.focused,
                i.viewport().close_requested(),
                i.pointer.latest_pos(),
                i.events.clone(),
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
        // Per-window, so tabbing between the two DirectDesk windows releases
        // the modifiers *this* one synthesized even though the process stays in
        // the foreground throughout.
        self.keys.set_focused(focused);

        // The chord is the escape hatch and is detected whether or not capture
        // is currently on — it toggles. Latched for the parent, which owns the
        // toggle; swallowed from forwarding below so no half of it reaches the
        // remote machine.
        if chord_pressed(&events) {
            self.chord_fired = true;
        }

        // Chrome-less and video-only by construction: no toolbar panel exists
        // here, so there is no chrome to measure and none of the main window's
        // `chrome_points` / auto-snap / integer-scale machinery applies. The
        // letterboxing is `Presenter::draw`'s own fit, and the whole panel is
        // the video viewport (the main window's `chrome_points` equivalent is 0
        // here by construction).
        let presenter = &self.presenter;
        let (viewport, view) = egui::CentralPanel::no_frame()
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
                (viewport, view)
            })
            .inner;

        // Forwarding happens outside the panel closure purely so the mutable
        // borrows of the forwarders don't collide with the presenter's.
        if focused {
            if let Some(view) = view.as_ref() {
                self.pointer
                    .handle_events(&events, viewport, view, self.last_pointer);
            }
            // Keys need no view: they are not spatial, and they ride stream 0
            // whichever window they were typed into.
            if self.capturing {
                self.keys.forward_events(&events);
            }
        }

        self.pointer.pump();
        if self.pointer.has_pending_move() {
            // A move the rate cap withheld is only sent on the next pass, and
            // nothing else is guaranteed to schedule one — the main window's
            // equivalent is `ClientApp::logic`'s `request_repaint`.
            ctx.request_repaint_of(stream1_viewport_id());
        }
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

    /// A `SecondaryShared` plus the receiving end of its input channel, so a
    /// test can read exactly what this window put on the wire.
    fn shared_with_wire(slot: Arc<FrameSlot>) -> (SecondaryShared, mpsc::Receiver<InputMsg>) {
        let (tx, rx) = mpsc::channel(64);
        (SecondaryShared::new(slot, tx), rx)
    }

    fn secondary(slot: Arc<FrameSlot>) -> SecondaryShared {
        shared_with_wire(slot).0
    }

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
        let shared = secondary(Arc::new(FrameSlot::new()));
        assert_eq!(shared.presenter.texture_name(), SECOND_VIDEO_TEXTURE);
    }

    #[test]
    fn reset_clears_every_latched_flag() {
        // Stale flags outlive the session they were latched in: a
        // `close_requested` left set would slam the window shut the instant the
        // next connection opened it.
        let slot = Arc::new(FrameSlot::new());
        let mut shared = secondary(slot.clone());
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

    /// The child's video fills its whole (chrome-less) window.
    fn child_view() -> crate::renderer::VideoView {
        crate::renderer::VideoView {
            rect: egui::Rect::from_min_size(egui::pos2(0.0, 0.0), egui::vec2(960.0, 540.0)),
            remote_w: 1920,
            remote_h: 1080,
        }
    }

    fn press(x: f32, y: f32, pressed: bool) -> egui::Event {
        egui::Event::PointerButton {
            pos: egui::pos2(x, y),
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::default(),
        }
    }

    #[test]
    fn the_chord_this_window_saw_is_handed_over_exactly_once() {
        // The parent consumes it as a toggle. Reporting it twice would release
        // capture and immediately take it back, so the escape hatch would look
        // like it did nothing — the exact bug the one-shot exists to prevent.
        let mut shared = secondary(Arc::new(FrameSlot::new()));
        shared.chord_fired = true;
        assert!(shared.take_chord_fired());
        assert!(!shared.take_chord_fired());
    }

    #[test]
    fn this_windows_events_stay_off_the_wire_until_the_session_negotiated_them() {
        // An `EventOn` reaching a host that never echoed MULTI_MONITOR errors
        // its `decode_strict` reader and kills input for the whole session.
        // `ClientApp` arms this from `monitors.is_some()` every pass.
        let (mut shared, mut rx) = shared_with_wire(Arc::new(FrameSlot::new()));
        let view = child_view();
        let centre = view.rect.center();

        shared
            .pointer
            .handle_events(&[press(centre.x, centre.y, true)], view.rect, &view, None);
        assert!(rx.try_recv().is_err(), "disarmed by construction");

        shared.set_armed(true);
        shared
            .pointer
            .handle_events(&[press(centre.x, centre.y, true)], view.rect, &view, None);
        assert!(matches!(
            rx.try_recv(),
            Ok(InputMsg::EventOn {
                id: SECOND_STREAM_ID,
                ..
            })
        ));

        // And a teardown puts it back: the next session has to prove itself.
        while rx.try_recv().is_ok() {}
        shared.reset(true);
        shared
            .pointer
            .handle_events(&[press(centre.x, centre.y, true)], view.rect, &view, None);
        if let Ok(msg) = rx.try_recv() {
            panic!("a reset window must be silent again: {msg:?}");
        }
    }

    #[test]
    fn a_live_drag_in_this_window_is_visible_to_the_teardown_that_has_to_lift_it() {
        // Once this window is gone no further events can ever come from it, so
        // `ClientApp` needs to know a button is still down in order to send the
        // `ReleaseAll` that lifts it.
        let (mut shared, _rx) = shared_with_wire(Arc::new(FrameSlot::new()));
        shared.set_armed(true);
        let view = child_view();
        let centre = view.rect.center();

        assert!(!shared.has_buttons_held());
        shared
            .pointer
            .handle_events(&[press(centre.x, centre.y, true)], view.rect, &view, None);
        assert!(shared.has_buttons_held());
        shared
            .pointer
            .handle_events(&[press(centre.x, centre.y, false)], view.rect, &view, None);
        assert!(!shared.has_buttons_held());
    }

    #[test]
    fn dropping_capture_forgets_this_windows_modifiers_instead_of_lifting_them() {
        // `InputCapture::release_all` has already put a global `ReleaseAll` on
        // the wire — it drops every held key on the host's one injector — so
        // individual ups after it would be noise about state that is gone.
        let (mut shared, mut rx) = shared_with_wire(Arc::new(FrameSlot::new()));
        shared.set_capturing(true);
        shared.keys.set_focused(true);
        shared.keys.on_key_event(
            Some(egui::Key::A),
            egui::Key::A,
            true,
            egui::Modifiers {
                shift: true,
                ..Default::default()
            },
        );
        while rx.try_recv().is_ok() {}
        assert_eq!(shared.keys.tracked_modifiers(), (false, false, true));

        shared.set_capturing(false);
        assert_eq!(shared.keys.tracked_modifiers(), (false, false, false));
        assert!(
            rx.try_recv().is_err(),
            "nothing should follow the global ReleaseAll"
        );
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
        let mut shared = secondary(slot.clone());
        slot.publish(frame());
        shared.reset(false);
        assert!(slot.take_newer_than(0).is_some());

        // Every other teardown site drops it.
        let slot = Arc::new(FrameSlot::new());
        let mut shared = secondary(slot.clone());
        slot.publish(frame());
        shared.reset(true);
        assert!(slot.take_newer_than(0).is_none());
    }
}
