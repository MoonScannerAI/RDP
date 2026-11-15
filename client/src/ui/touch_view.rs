//! The streaming view for the touch UI profile: applies [`crate::touch`]
//! actions to the main window's `PointerForwarder`, handles pinch zoom, and
//! draws the local cursor sprite (the host does not draw one into the video).
//!
//! Owned by W4 (Phase 1).
//!
//! # Integration (drop-in for `forward_pointer_events` in `streaming_view`)
//!
//! ```ignore
//! // field on ClientApp:  touch: TouchView            (TouchView::new())
//!
//! fn streaming_view(&mut self, ui: &mut egui::Ui) {
//!     // 1. Draw with the zoom/pan the touch layer wants (zoom 1.0 == draw()).
//!     let (zoom, focus) = (self.touch.zoom(), self.touch.focus());
//!     let (viewport, view) = self.presenter.draw_zoomed(ui, zoom, focus);
//!     ...                                   // same chrome_points / "waiting" code
//!     let Some(view) = view else { self.touch.reset(self.input.pointer_mut()); return };
//!
//!     let (events, focused) = ui.ctx().input(|i| (i.events.clone(), i.focused));
//!     if focused {
//!         // Replaces `self.input.forward_pointer_events(..)` in Touch mode.
//!         // Consumes only `Event::Touch`; paints the cursor sprite; asks for
//!         // repaints while a finger is down (long-press timer) or the pan moved.
//!         self.touch.frame(ui, &events, viewport, &view, self.input.pointer_mut());
//!         // forward_key_events / keyboard-focus surrender unchanged.
//!     } else {
//!         self.touch.reset(self.input.pointer_mut());      // focus loss
//!     }
//!     self.input.pump();                                    // as today
//! }
//! ```
//!
//! Also call `self.touch.reset(self.input.pointer_mut())` on disconnect, when
//! the soft keyboard opens, and when the profile changes away from Touch;
//! `self.touch.reset_view()` (zoom back to 1.0) on a new session / stream
//! change. All three are idempotent and release any held button.
//!
//! Signatures:
//! * `TouchView::new() -> Self`
//! * `zoom(&self) -> f32`, `focus(&self) -> (f32, f32)` — feed `draw_zoomed`
//! * `frame(&mut self, ui, events: &[egui::Event], viewport: Rect, view: &VideoView, fwd: &mut PointerForwarder)`
//! * `process(.., now: Instant) -> bool` — `frame` minus painting (testable)
//! * `paint_cursor(&self, painter: &egui::Painter, view: &VideoView)`
//! * `reset(&mut self, fwd: &mut PointerForwarder)`, `reset_view(&mut self)`
//! * `cursor(&self) -> (f32, f32)` — remote-normalized, for status UIs

use std::time::{Duration, Instant};

use egui::{Color32, Pos2, Rect, Vec2};

use crate::input_capture::PointerForwarder;
use crate::renderer::VideoView;
use crate::touch::{TouchAction, TouchButton, TouchEvent, TouchGeometry, TouchState};

/// Keep the cursor at least this far (points) inside the viewport edge when
/// panning a zoomed view to follow it.
pub const FOLLOW_MARGIN_PTS: f32 = 56.0;
/// Cursor sprite scale: 1.0 is a 12x20 pt arrow.
pub const CURSOR_SPRITE_SCALE: f32 = 1.2;
/// Repaint cadence while a finger is down, so timers fire without input.
const ACTIVE_REPAINT: Duration = Duration::from_millis(50);

pub struct TouchView {
    state: TouchState,
    /// Remote-normalized point shown at the viewport centre when zoomed.
    focus: (f32, f32),
    /// Last view seen, so `reset` can release buttons at the right place.
    last_view: Option<VideoView>,
}

impl Default for TouchView {
    fn default() -> Self {
        Self::new()
    }
}

impl TouchView {
    pub fn new() -> Self {
        Self {
            state: TouchState::new(),
            focus: (0.5, 0.5),
            last_view: None,
        }
    }

    pub fn zoom(&self) -> f32 {
        self.state.zoom()
    }

    pub fn focus(&self) -> (f32, f32) {
        self.focus
    }

    pub fn cursor(&self) -> (f32, f32) {
        self.state.cursor()
    }

    /// Back to the whole video, centred. Does not touch held buttons.
    pub fn reset_view(&mut self) {
        self.state.set_zoom(1.0);
        self.focus = (0.5, 0.5);
    }

    /// Release everything: any held button goes up on the host, every finger
    /// is forgotten. Safe to call every frame while unfocused.
    pub fn reset(&mut self, fwd: &mut PointerForwarder) {
        let actions = self.state.reset();
        if let Some(view) = self.last_view {
            apply_actions(&actions, &view, fwd);
        }
        debug_assert!(!self.state.button_held());
    }

    /// One frame: process touches, paint the cursor, schedule repaints.
    pub fn frame(
        &mut self,
        ui: &mut egui::Ui,
        events: &[egui::Event],
        viewport: Rect,
        view: &VideoView,
        fwd: &mut PointerForwarder,
    ) {
        let view_changed = self.process(events, viewport, view, fwd, Instant::now());
        self.paint_cursor(&ui.painter_at(viewport), view);
        if view_changed {
            ui.ctx().request_repaint();
        } else if self.state.is_active() {
            ui.ctx().request_repaint_after(ACTIVE_REPAINT);
        }
    }

    /// The testable core of [`Self::frame`]. Returns true when the zoom/pan
    /// changed (the frame just drawn is stale, so repaint).
    pub fn process(
        &mut self,
        events: &[egui::Event],
        viewport: Rect,
        view: &VideoView,
        fwd: &mut PointerForwarder,
        now: Instant,
    ) -> bool {
        self.last_view = Some(*view);
        let geo = TouchGeometry {
            viewport,
            video: view.rect,
            // `draw_zoomed` ran this frame with the zoom the state holds now.
            drawn_zoom: self.state.zoom(),
        };
        let zoom_before = self.state.zoom();
        let focus_before = self.focus;
        let mut zoomed_by_gesture = false;

        let mut actions = Vec::new();
        for ev in events.iter().filter_map(TouchEvent::from_egui) {
            actions.extend(self.state.handle(ev, &geo, now));
        }
        actions.extend(self.state.tick(now));

        for a in &actions {
            if let TouchAction::ZoomTo {
                focus_x, focus_y, ..
            } = a
            {
                self.focus = (*focus_x, *focus_y);
                zoomed_by_gesture = true;
            }
        }
        apply_actions(&actions, view, fwd);

        // Keep the cursor on screen. After a gesture zoom the drawn rect is
        // stale (one frame), so let the next frame's real rect drive the pan.
        if !zoomed_by_gesture && self.state.zoom() > 1.0 {
            self.focus = match follow_focus(view.rect, viewport, self.state.cursor()) {
                Some(f) => f,
                None => actual_focus(view.rect, viewport),
            };
        }
        self.state.zoom() != zoom_before || self.focus != focus_before && self.state.zoom() > 1.0
    }

    /// Draw the cursor sprite at the cursor, if it is inside the viewport.
    pub fn paint_cursor(&self, painter: &egui::Painter, view: &VideoView) {
        let (x, y) = self.state.cursor();
        let tip = view.rect.min + Vec2::new(x * view.rect.width(), y * view.rect.height());
        if !painter.clip_rect().expand(1.0).contains(tip) {
            return;
        }
        let pts = cursor_sprite(tip, CURSOR_SPRITE_SCALE);
        let mut mesh = egui::Mesh::default();
        for p in pts {
            mesh.colored_vertex(p, Color32::WHITE);
        }
        // Fan from the tip; the arrow is star-shaped from there.
        for i in 1..pts.len() - 1 {
            mesh.add_triangle(0, i as u32, i as u32 + 1);
        }
        painter.add(egui::Shape::mesh(mesh));
        painter.add(egui::Shape::closed_line(
            pts.to_vec(),
            egui::Stroke::new(1.5, Color32::BLACK),
        ));
    }
}

/// Seven-point arrow outline, tip first, clockwise.
pub fn cursor_sprite(tip: Pos2, scale: f32) -> [Pos2; 7] {
    const P: [(f32, f32); 7] = [
        (0.0, 0.0),
        (0.0, 17.0),
        (4.3, 13.2),
        (7.2, 19.5),
        (9.8, 18.4),
        (7.0, 12.2),
        (12.3, 12.2),
    ];
    P.map(|(x, y)| tip + Vec2::new(x, y) * scale)
}

/// Where the forwarder should see the cursor: the *centre* of the remote
/// pixel the normalized position lands on, so 1.0 maps to the last pixel
/// rather than one past it (which `map_pointer` rejects for a button-down).
pub fn cursor_input_pos(view: &VideoView, x: f32, y: f32) -> Pos2 {
    let axis = |n: f32, dim: u32, min: f32, len: f32| -> f32 {
        let dim = dim.max(1) as f32;
        let px = (n.clamp(0.0, 1.0) * (dim - 1.0)).round();
        min + (px + 0.5) / dim * len
    };
    Pos2::new(
        axis(x, view.remote_w, view.rect.min.x, view.rect.width()),
        axis(y, view.remote_h, view.rect.min.y, view.rect.height()),
    )
}

/// Translate gesture output into forwarder calls, in order.
pub fn apply_actions(actions: &[TouchAction], view: &VideoView, fwd: &mut PointerForwarder) {
    for a in actions {
        match *a {
            TouchAction::MoveTo { x, y } => {
                fwd.on_pointer_moved(cursor_input_pos(view, x, y), view);
            }
            TouchAction::Button {
                button,
                pressed,
                x,
                y,
            } => {
                let b = match button {
                    TouchButton::Left => egui::PointerButton::Primary,
                    TouchButton::Right => egui::PointerButton::Secondary,
                };
                fwd.on_pointer_button(cursor_input_pos(view, x, y), view, b, pressed);
            }
            TouchAction::Wheel {
                delta,
                horizontal,
                x,
                y,
            } => {
                fwd.on_wheel(cursor_input_pos(view, x, y), view, delta, horizontal);
            }
            // Handled by `process` (it owns the focus).
            TouchAction::ZoomTo { .. } => {}
        }
    }
}

/// The remote-normalized point currently at the viewport centre.
pub fn actual_focus(rect: Rect, viewport: Rect) -> (f32, f32) {
    let c = viewport.center();
    (
        ((c.x - rect.min.x) / rect.width().max(1.0)).clamp(0.0, 1.0),
        ((c.y - rect.min.y) / rect.height().max(1.0)).clamp(0.0, 1.0),
    )
}

/// If the cursor is outside the viewport (inset by [`FOLLOW_MARGIN_PTS`]),
/// the focus that pans just enough to bring it back; `None` if it is fine.
pub fn follow_focus(rect: Rect, viewport: Rect, cursor: (f32, f32)) -> Option<(f32, f32)> {
    if rect.width() <= 0.0 || rect.height() <= 0.0 {
        return None;
    }
    let p = rect.min + Vec2::new(cursor.0 * rect.width(), cursor.1 * rect.height());
    let m = FOLLOW_MARGIN_PTS
        .min(viewport.width() / 4.0)
        .min(viewport.height() / 4.0)
        .max(0.0);
    let inner = viewport.shrink(m);
    let axis = |p: f32, lo: f32, hi: f32| {
        if p < lo {
            lo - p
        } else if p > hi {
            hi - p
        } else {
            0.0
        }
    };
    let shift = Vec2::new(
        axis(p.x, inner.min.x, inner.max.x),
        axis(p.y, inner.min.y, inner.max.y),
    );
    if shift == Vec2::ZERO {
        return None;
    }
    Some(actual_focus(rect.translate(shift), viewport))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::renderer::zoomed_rect;
    use directdesk_shared::input::{InputEvent, KeyAction, MouseButton};
    use directdesk_shared::protocol::InputMsg;
    use egui::pos2;
    use tokio::sync::mpsc;

    fn viewport() -> Rect {
        Rect::from_min_max(pos2(100.0, 50.0), pos2(900.0, 500.0))
    }

    fn view(zoom: f32, focus: (f32, f32)) -> VideoView {
        VideoView {
            rect: zoomed_rect(viewport(), viewport(), zoom, focus),
            remote_w: 1920,
            remote_h: 1080,
        }
    }

    fn fwd() -> (PointerForwarder, mpsc::Receiver<InputMsg>) {
        let (tx, rx) = mpsc::channel(1024);
        (PointerForwarder::legacy(tx), rx)
    }

    fn drain(rx: &mut mpsc::Receiver<InputMsg>) -> Vec<InputEvent> {
        let mut v = Vec::new();
        while let Ok(m) = rx.try_recv() {
            if let InputMsg::Event(e) = m {
                v.push(e);
            }
        }
        v
    }

    fn touch(id: u64, phase: egui::TouchPhase, x: f32, y: f32) -> egui::Event {
        egui::Event::Touch {
            device_id: egui::TouchDeviceId(0),
            id: egui::TouchId(id),
            phase,
            pos: pos2(x, y),
            force: None,
        }
    }

    fn net_down(evs: &[InputEvent]) -> i32 {
        evs.iter()
            .map(|e| match e {
                InputEvent::MouseButton {
                    action: KeyAction::Down,
                    ..
                } => 1,
                InputEvent::MouseButton {
                    action: KeyAction::Up,
                    ..
                } => -1,
                _ => 0,
            })
            .sum()
    }

    struct Rig {
        v: TouchView,
        f: PointerForwarder,
        rx: mpsc::Receiver<InputMsg>,
        t0: Instant,
        ms: u64,
        view: VideoView,
    }

    impl Rig {
        fn new() -> Self {
            let (f, rx) = fwd();
            Self {
                v: TouchView::new(),
                f,
                rx,
                t0: Instant::now(),
                ms: 0,
                view: view(1.0, (0.5, 0.5)),
            }
        }
        fn step(&mut self, dt: u64, evs: &[egui::Event]) -> bool {
            self.ms += dt;
            let now = self.t0 + Duration::from_millis(self.ms);
            let changed = self
                .v
                .process(evs, viewport(), &self.view, &mut self.f, now);
            self.f.pump();
            changed
        }
    }

    #[test]
    fn tap_reaches_the_forwarder_as_a_click_at_the_remote_centre() {
        let mut r = Rig::new();
        r.step(0, &[touch(1, egui::TouchPhase::Start, 300.0, 200.0)]);
        r.step(80, &[touch(1, egui::TouchPhase::End, 300.0, 200.0)]);
        let evs = drain(&mut r.rx);
        let clicks: Vec<_> = evs
            .iter()
            .filter_map(|e| match e {
                InputEvent::MouseButton {
                    button,
                    action,
                    x,
                    y,
                } => Some((*button, *action, *x, *y)),
                _ => None,
            })
            .collect();
        assert_eq!(clicks.len(), 2);
        assert_eq!(
            (clicks[0].0, clicks[0].1),
            (MouseButton::Left, KeyAction::Down)
        );
        assert_eq!(
            (clicks[1].0, clicks[1].1),
            (MouseButton::Left, KeyAction::Up)
        );
        // Centre of the remote screen.
        assert!((clicks[0].2 as i32 - 32768).abs() < 40, "{}", clicks[0].2);
        assert!((clicks[0].3 as i32 - 32768).abs() < 70, "{}", clicks[0].3);
    }

    #[test]
    fn pointer_events_are_not_consumed_only_touch_is() {
        let mut r = Rig::new();
        let evs = [
            egui::Event::PointerMoved(pos2(300.0, 200.0)),
            egui::Event::PointerButton {
                pos: pos2(300.0, 200.0),
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: Default::default(),
            },
        ];
        r.step(0, &evs);
        assert!(drain(&mut r.rx).is_empty());
    }

    #[test]
    fn cursor_at_the_far_corner_still_accepts_a_button_down() {
        let mut r = Rig::new();
        r.v.state.set_cursor(1.0, 1.0);
        let acts = [TouchAction::Button {
            button: TouchButton::Left,
            pressed: true,
            x: 1.0,
            y: 1.0,
        }];
        apply_actions(&acts, &r.view, &mut r.f);
        assert_eq!(net_down(&drain(&mut r.rx)), 1);
        // And the origin.
        let acts = [TouchAction::Button {
            button: TouchButton::Left,
            pressed: true,
            x: 0.0,
            y: 0.0,
        }];
        apply_actions(&acts, &r.view, &mut r.f);
        assert_eq!(net_down(&drain(&mut r.rx)), 1);
    }

    #[test]
    fn wheel_goes_out_with_its_axis() {
        let mut r = Rig::new();
        let mut evs = vec![
            touch(1, egui::TouchPhase::Start, 300.0, 200.0),
            touch(2, egui::TouchPhase::Start, 360.0, 200.0),
        ];
        r.step(0, &evs);
        evs.clear();
        for i in 1..=6 {
            evs.push(touch(
                1,
                egui::TouchPhase::Move,
                300.0,
                200.0 + 10.0 * i as f32,
            ));
            evs.push(touch(
                2,
                egui::TouchPhase::Move,
                360.0,
                200.0 + 10.0 * i as f32,
            ));
        }
        r.step(16, &evs);
        let wheel: Vec<_> = drain(&mut r.rx)
            .into_iter()
            .filter_map(|e| match e {
                InputEvent::MouseWheel {
                    delta, horizontal, ..
                } => Some((delta, horizontal)),
                _ => None,
            })
            .collect();
        assert!(!wheel.is_empty());
        assert!(wheel.iter().all(|(d, h)| *d > 0 && !*h));
    }

    #[test]
    fn pinch_changes_zoom_and_asks_for_a_repaint() {
        let mut r = Rig::new();
        r.step(
            0,
            &[
                touch(1, egui::TouchPhase::Start, 450.0, 275.0),
                touch(2, egui::TouchPhase::Start, 550.0, 275.0),
            ],
        );
        let mut changed = false;
        for i in 1..=10 {
            changed |= r.step(
                16,
                &[
                    touch(1, egui::TouchPhase::Move, 450.0 - 5.0 * i as f32, 275.0),
                    touch(2, egui::TouchPhase::Move, 550.0 + 5.0 * i as f32, 275.0),
                ],
            );
        }
        assert!(changed);
        assert!(r.v.zoom() > 1.5);
        // Pinching over the middle keeps the middle in the middle.
        let (fx, fy) = r.v.focus();
        assert!((fx - 0.5).abs() < 0.02 && (fy - 0.5).abs() < 0.02);
    }

    #[test]
    fn reset_releases_a_held_drag_on_the_wire() {
        let mut r = Rig::new();
        let s = egui::TouchPhase::Start;
        r.step(0, &[touch(1, s, 300.0, 200.0)]);
        r.step(60, &[touch(1, egui::TouchPhase::End, 300.0, 200.0)]);
        r.step(100, &[touch(1, s, 300.0, 200.0)]);
        r.step(300, &[]); // tick: hold presses left
        assert!(r.f.is_dragging());
        let before = net_down(&drain(&mut r.rx));
        assert_eq!(before, 1); // tap pair nets 0, the hold nets +1
        r.v.reset(&mut r.f);
        let after = net_down(&drain(&mut r.rx));
        assert_eq!(after, -1);
        assert!(!r.f.is_dragging());
    }

    #[test]
    fn nothing_sticks_through_a_whole_session_of_gestures() {
        let mut r = Rig::new();
        let (s, m, e) = (
            egui::TouchPhase::Start,
            egui::TouchPhase::Move,
            egui::TouchPhase::End,
        );
        let mut net = 0;
        // tap, tap-hold-drag cut by a second finger, long-press, cancel.
        r.step(0, &[touch(1, s, 300.0, 200.0)]);
        r.step(60, &[touch(1, e, 300.0, 200.0)]);
        r.step(100, &[touch(1, s, 300.0, 200.0)]);
        r.step(20, &[touch(1, m, 340.0, 200.0)]);
        r.step(20, &[touch(2, s, 500.0, 300.0)]);
        r.step(20, &[touch(2, e, 500.0, 300.0), touch(1, e, 340.0, 200.0)]);
        r.step(100, &[touch(3, s, 300.0, 200.0)]);
        r.step(700, &[]);
        r.step(10, &[touch(3, egui::TouchPhase::Cancel, 300.0, 200.0)]);
        r.v.reset(&mut r.f);
        net += net_down(&drain(&mut r.rx));
        assert_eq!(net, 0);
        assert!(!r.f.is_dragging());
    }

    #[test]
    fn follow_pans_the_cursor_back_into_view() {
        let vp = viewport();
        let rect = zoomed_rect(vp, vp, 2.0, (0.5, 0.5));
        // Cursor toward the right of the remote screen is off-screen at 2x.
        let f = follow_focus(rect, vp, (0.9, 0.5)).expect("must pan");
        let panned = zoomed_rect(vp, vp, 2.0, f);
        let p = panned.min + Vec2::new(0.9 * panned.width(), 0.5 * panned.height());
        assert!(vp.shrink(FOLLOW_MARGIN_PTS - 1.0).contains(p), "p={p:?}");
        // A cursor already comfortably visible needs no pan.
        assert!(follow_focus(rect, vp, (0.5, 0.5)).is_none());
    }

    #[test]
    fn follow_is_stable_when_the_cursor_is_unreachable_margin_wise() {
        // Cursor at the very corner: the picture edge meets the viewport edge,
        // so the cursor sits in the margin and no further pan is possible.
        let vp = viewport();
        let f = follow_focus(zoomed_rect(vp, vp, 2.0, (0.5, 0.5)), vp, (1.0, 1.0)).unwrap();
        let rect = zoomed_rect(vp, vp, 2.0, f);
        assert_eq!(rect.max, vp.max);
        // Re-running on the clamped rect settles (no oscillation).
        let again = follow_focus(rect, vp, (1.0, 1.0));
        if let Some(a) = again {
            assert!((a.0 - f.0).abs() < 1e-3 && (a.1 - f.1).abs() < 1e-3);
        }
    }

    #[test]
    fn input_pos_maps_back_to_the_requested_remote_pixel() {
        let v = view(2.0, (0.3, 0.6));
        for (x, y) in [(0.0, 0.0), (1.0, 1.0), (0.25, 0.75), (0.5, 0.5)] {
            let p = cursor_input_pos(&v, x, y);
            let (nx, ny) = crate::input_capture::map_pointer(p, &v).expect("inside");
            assert!((nx as f32 / 65535.0 - x).abs() < 0.001, "{x}: {nx}");
            assert!((ny as f32 / 65535.0 - y).abs() < 0.001, "{y}: {ny}");
        }
    }

    #[test]
    fn sprite_is_anchored_at_its_tip() {
        let pts = cursor_sprite(pos2(10.0, 20.0), 2.0);
        assert_eq!(pts[0], pos2(10.0, 20.0));
        assert!(pts.iter().all(|p| p.x >= 10.0 && p.y >= 20.0));
    }
}
