//! Touch-to-mouse gesture recognition for the touch UI profile (trackpad
//! mode). A pure state machine: touch events plus a clock in, pointer actions
//! (in remote-normalized coordinates) out. No egui painting, no channels — so
//! every gesture is unit tested on Windows.
//!
//! Owned by W4 (Phase 1).
//!
//! # Gestures
//!
//! | gesture                                   | result                                  |
//! |-------------------------------------------|-----------------------------------------|
//! | 1-finger drag (> [`TAP_SLOP_PTS`])        | relative cursor move                    |
//! | tap (lift before [`LONG_PRESS`], no slop) | left click at the cursor                |
//! | two taps in [`DOUBLE_TAP_WINDOW`]         | two left clicks (host sees a dbl-click) |
//! | tap, touch again, move past slop          | left button DOWN, drag, UP on release   |
//! | tap, touch again, hold [`LONG_PRESS`]     | left button DOWN (hold), UP on release  |
//! | hold >= [`LONG_PRESS`], little movement   | right click                             |
//! | 2-finger tap (lift before [`LONG_PRESS`]) | right click                             |
//! | 2-finger drag (centroid moves)            | wheel, vertical and horizontal          |
//! | 2-finger pinch (distance changes)         | zoom `1.0..=`[`MAX_ZOOM`]               |
//!
//! # Frame timing
//!
//! egui touch events carry no event time, so `now` is the clock of the frame
//! that delivered them. When the UI presents slowly (a few fps) a quick tap's
//! Start and End are a whole frame or more apart. Classification therefore
//! never asks "was this touch short?"; it asks "did anything decisive happen
//! first?". A touch that lifts within slop before the long-press fired is a
//! tap, however long it measured. Only [`LONG_PRESS`] (500 ms, two frames at
//! 4 fps) and [`DOUBLE_TAP_WINDOW`] depend on the clock.
//! # Why no button can stick
//!
//! Every `Button` down is emitted through [`TouchState::press`] and recorded in
//! `held`. Clicks (tap, long-press, two-finger tap) emit down+up in the same
//! batch, so they are never "held" across a call. The only gesture that holds a
//! button across calls is tap-hold-drag, and every way out of the gesture
//! (finger End, Cancel, a second finger arriving, [`TouchState::reset`]) goes
//! through [`TouchState::release_all`], which emits an up for everything in
//! `held`. `no_button_sticks_for_any_gesture_cut_anywhere` replays every
//! scenario, cuts it after every event, and ends it each possible way.

use std::time::{Duration, Instant};

use egui::{Pos2, Rect, Vec2};

pub use crate::renderer::MAX_ZOOM;

/// Smallest zoom: the whole letterboxed video.
pub const MIN_ZOOM: f32 = 1.0;
/// A finger may wander this far (egui points) and still be a tap / long-press.
pub const TAP_SLOP_PTS: f32 = 10.0;
/// Hold time for the long-press right click, and for the tap-hold left press.
/// A touch released before this (without slop) is a tap, however long it
/// measured; see the module docs on frame timing.
pub const LONG_PRESS: Duration = Duration::from_millis(500);
/// A touch starting within this long of a tap's lift is the second half of a
/// double-tap / tap-hold-drag. Wider than a typical 300 ms so one coarse
/// frame (up to ~300 ms between the lift and the next touch's frame) still
/// counts.
pub const DOUBLE_TAP_WINDOW: Duration = Duration::from_millis(400);
/// ...and within this distance (points) of that tap.
pub const DOUBLE_TAP_SLOP_PTS: f32 = 40.0;
/// Centroid / spread change (points) before two fingers become scroll or pinch.
pub const TWO_FINGER_SLOP_PTS: f32 = 12.0;
/// Cursor gain at slow speed (1.0 = cursor tracks the finger 1:1 on screen).
pub const CURSOR_GAIN_BASE: f32 = 1.0;
/// Cursor gain at/above [`ACCEL_FULL_PTS_PER_S`].
pub const CURSOR_GAIN_MAX: f32 = 2.0;
/// Below this finger speed the gain is [`CURSOR_GAIN_BASE`].
pub const ACCEL_START_PTS_PER_S: f32 = 150.0;
/// At/above this finger speed the gain is [`CURSOR_GAIN_MAX`].
pub const ACCEL_FULL_PTS_PER_S: f32 = 1500.0;
/// Wheel units per point of two-finger travel (120 per notch => 40 pt/notch).
pub const WHEEL_UNITS_PER_POINT: f32 = 3.0;
/// Windows `WHEEL_DELTA`: one notch.
pub const WHEEL_DELTA: f32 = 120.0;
/// Largest wheel delta in a single action (three notches).
pub const MAX_WHEEL_PER_EVENT: i16 = 360;

/// Which mouse button an action is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchButton {
    Left,
    Right,
}

impl TouchButton {
    fn index(self) -> usize {
        match self {
            TouchButton::Left => 0,
            TouchButton::Right => 1,
        }
    }
}

/// What the gesture layer wants done. Positions are remote-normalized 0..=1
/// and are carried on every action so a batch replays correctly even when the
/// cursor moves again later in the same batch.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TouchAction {
    MoveTo {
        x: f32,
        y: f32,
    },
    Button {
        button: TouchButton,
        pressed: bool,
        x: f32,
        y: f32,
    },
    /// Windows wheel units (120 = one notch). Vertical: positive scrolls up.
    /// Horizontal: positive scrolls right. Natural (content follows fingers).
    Wheel {
        delta: i16,
        horizontal: bool,
        x: f32,
        y: f32,
    },
    /// New zoom, and the remote-normalized point that should sit at the centre
    /// of the viewport (the pinch anchor). Presenter clamps the pan.
    ZoomTo {
        zoom: f32,
        focus_x: f32,
        focus_y: f32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchPhase {
    Start,
    Move,
    End,
    Cancel,
}

/// One finger event, positions in egui points (window-relative).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TouchEvent {
    pub id: u64,
    pub phase: TouchPhase,
    pub pos: Pos2,
}

impl TouchEvent {
    /// Only `egui::Event::Touch` is consumed; the pointer events egui-winit
    /// synthesizes for the first finger are not this layer's business.
    pub fn from_egui(event: &egui::Event) -> Option<Self> {
        let egui::Event::Touch { id, phase, pos, .. } = event else {
            return None;
        };
        Some(Self {
            id: id.0,
            phase: match phase {
                egui::TouchPhase::Start => TouchPhase::Start,
                egui::TouchPhase::Move => TouchPhase::Move,
                egui::TouchPhase::End => TouchPhase::End,
                egui::TouchPhase::Cancel => TouchPhase::Cancel,
            },
            pos: *pos,
        })
    }
}

/// Where things are on screen this frame.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TouchGeometry {
    /// The whole video area; touches starting outside belong to other widgets.
    pub viewport: Rect,
    /// The video rect as drawn (enlarged and possibly off-screen when zoomed).
    pub video: Rect,
    /// The zoom `video` was drawn at.
    pub drawn_zoom: f32,
}

impl TouchGeometry {
    fn usable(&self) -> bool {
        self.video.width() > 0.0 && self.video.height() > 0.0 && self.viewport.is_positive()
    }
}

#[derive(Debug, Clone, Copy)]
struct Finger {
    id: u64,
    start: Pos2,
    pos: Pos2,
}

#[derive(Debug, Clone, Copy)]
struct One {
    f: Finger,
    start_time: Instant,
    /// Position the cursor delta has been applied up to.
    applied: Pos2,
    last_time: Instant,
    moved: bool,
    long_pressed: bool,
    /// Second touch of a tap-then-touch: holding or dragging presses left.
    follow_up: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum TwoKind {
    Undecided,
    Scroll,
    Pinch,
}

#[derive(Debug, Clone, Copy)]
struct Two {
    a: Finger,
    b: Finger,
    start_time: Instant,
    start_dist: f32,
    start_centroid: Pos2,
    last_dist: f32,
    last_centroid: Pos2,
    kind: TwoKind,
    moved: bool,
    /// False if the first finger had already dragged before the second landed.
    tap_ok: bool,
    acc_x: f32,
    acc_y: f32,
}

impl Two {
    fn dist(&self) -> f32 {
        (self.a.pos - self.b.pos).length().max(1.0)
    }
    fn centroid(&self) -> Pos2 {
        self.a.pos + (self.b.pos - self.a.pos) * 0.5
    }
}

#[derive(Debug, Clone, Copy)]
enum Gesture {
    Idle,
    One(One),
    Two(Two),
}

/// The gesture state machine. See the module docs.
pub struct TouchState {
    gesture: Gesture,
    /// Fingers to disregard until they lift: started outside the viewport, a
    /// third finger, or what is left of a gesture after it ended/cancelled.
    ignored: Vec<u64>,
    cursor: (f32, f32),
    zoom: f32,
    /// Buttons currently down on the host, indexed by [`TouchButton::index`].
    held: [bool; 2],
    last_tap: Option<(Instant, Pos2)>,
}

impl Default for TouchState {
    fn default() -> Self {
        Self::new()
    }
}

impl TouchState {
    pub fn new() -> Self {
        Self {
            gesture: Gesture::Idle,
            ignored: Vec::new(),
            cursor: (0.5, 0.5),
            zoom: MIN_ZOOM,
            held: [false; 2],
            last_tap: None,
        }
    }

    /// Cursor position, remote-normalized 0..=1.
    pub fn cursor(&self) -> (f32, f32) {
        self.cursor
    }

    pub fn set_cursor(&mut self, x: f32, y: f32) {
        self.cursor = (x.clamp(0.0, 1.0), y.clamp(0.0, 1.0));
    }

    pub fn zoom(&self) -> f32 {
        self.zoom
    }

    pub fn set_zoom(&mut self, zoom: f32) {
        self.zoom = crate::renderer::sanitize_zoom(zoom);
    }

    /// A finger is in a gesture right now (the UI should keep repainting so
    /// the long-press timer can fire without further input).
    pub fn is_active(&self) -> bool {
        !matches!(self.gesture, Gesture::Idle)
    }

    /// Some button is down on the host because of this layer.
    pub fn button_held(&self) -> bool {
        self.held.iter().any(|h| *h)
    }

    /// Feed one finger event.
    pub fn handle(
        &mut self,
        ev: TouchEvent,
        geo: &TouchGeometry,
        now: Instant,
    ) -> Vec<TouchAction> {
        let mut out = Vec::new();
        match ev.phase {
            TouchPhase::Start => self.on_start(ev, geo, now, &mut out),
            TouchPhase::Move => self.on_move(ev, geo, now, &mut out),
            TouchPhase::End => self.on_end(ev, now, &mut out),
            TouchPhase::Cancel => self.on_cancel(ev.id, &mut out),
        }
        out
    }

    /// Advance timers with no new input (the long-press right click, the
    /// tap-hold press). Call once per frame.
    pub fn tick(&mut self, now: Instant) -> Vec<TouchAction> {
        let mut out = Vec::new();
        if let Gesture::One(mut o) = self.gesture {
            self.timers(&mut o, now, &mut out);
            self.gesture = Gesture::One(o);
        }
        out
    }

    /// Drop every gesture and release anything held. Call on disconnect,
    /// window focus loss, keyboard open — anything that may eat a finger's End.
    pub fn reset(&mut self) -> Vec<TouchAction> {
        let mut out = Vec::new();
        self.release_all(&mut out);
        self.gesture = Gesture::Idle;
        self.ignored.clear();
        self.last_tap = None;
        out
    }

    // ---- emission helpers ------------------------------------------------

    fn press(&mut self, button: TouchButton, out: &mut Vec<TouchAction>) {
        self.held[button.index()] = true;
        out.push(TouchAction::Button {
            button,
            pressed: true,
            x: self.cursor.0,
            y: self.cursor.1,
        });
    }

    fn release(&mut self, button: TouchButton, out: &mut Vec<TouchAction>) {
        self.held[button.index()] = false;
        out.push(TouchAction::Button {
            button,
            pressed: false,
            x: self.cursor.0,
            y: self.cursor.1,
        });
    }

    fn click(&mut self, button: TouchButton, out: &mut Vec<TouchAction>) {
        self.press(button, out);
        self.release(button, out);
    }

    /// The single exit hatch every path that abandons a gesture goes through.
    fn release_all(&mut self, out: &mut Vec<TouchAction>) {
        for b in [TouchButton::Left, TouchButton::Right] {
            if self.held[b.index()] {
                self.release(b, out);
            }
        }
    }

    fn move_cursor(&mut self, d: Vec2, geo: &TouchGeometry, out: &mut Vec<TouchAction>) {
        let size = geo.video.size();
        if size.x <= 0.0 || size.y <= 0.0 {
            return;
        }
        let x = (self.cursor.0 + d.x / size.x).clamp(0.0, 1.0);
        let y = (self.cursor.1 + d.y / size.y).clamp(0.0, 1.0);
        if (x, y) != self.cursor {
            self.cursor = (x, y);
            out.push(TouchAction::MoveTo { x, y });
        }
    }

    fn is_ignored(&self, id: u64) -> bool {
        self.ignored.contains(&id)
    }

    fn ignore(&mut self, id: u64) {
        if !self.ignored.contains(&id) {
            self.ignored.push(id);
        }
    }

    fn in_gesture(&self, id: u64) -> bool {
        match &self.gesture {
            Gesture::Idle => false,
            Gesture::One(o) => o.f.id == id,
            Gesture::Two(t) => t.a.id == id || t.b.id == id,
        }
    }

    // ---- phases ----------------------------------------------------------

    fn on_start(
        &mut self,
        ev: TouchEvent,
        geo: &TouchGeometry,
        now: Instant,
        out: &mut Vec<TouchAction>,
    ) {
        if self.is_ignored(ev.id) || self.in_gesture(ev.id) {
            return;
        }
        if !geo.usable() || !geo.viewport.contains(ev.pos) {
            // Belongs to a toolbar widget (egui's synthesized pointer drives
            // it); stay out of the way until this finger lifts.
            self.ignore(ev.id);
            return;
        }
        let finger = Finger {
            id: ev.id,
            start: ev.pos,
            pos: ev.pos,
        };
        match self.gesture {
            Gesture::Idle => {
                let follow_up = match self.last_tap.take() {
                    Some((at, pos)) => {
                        now.saturating_duration_since(at) <= DOUBLE_TAP_WINDOW
                            && (pos - ev.pos).length() <= DOUBLE_TAP_SLOP_PTS
                    }
                    None => false,
                };
                self.gesture = Gesture::One(One {
                    f: finger,
                    start_time: now,
                    applied: ev.pos,
                    last_time: now,
                    moved: false,
                    long_pressed: false,
                    follow_up,
                });
            }
            Gesture::One(o) => {
                if o.long_pressed {
                    // That finger is spent; a second one does not revive it.
                    self.ignore(ev.id);
                    return;
                }
                // Finger count changed mid-gesture: let go of anything held.
                self.release_all(out);
                self.last_tap = None;
                let mut two = Two {
                    a: o.f,
                    b: finger,
                    // Measured from the second finger landing: the first may
                    // have waited a coarse frame for its partner.
                    start_time: now,
                    start_dist: 1.0,
                    start_centroid: ev.pos,
                    last_dist: 1.0,
                    last_centroid: ev.pos,
                    kind: TwoKind::Undecided,
                    moved: false,
                    tap_ok: !o.moved,
                    acc_x: 0.0,
                    acc_y: 0.0,
                };
                two.start_dist = two.dist();
                two.last_dist = two.start_dist;
                two.start_centroid = two.centroid();
                two.last_centroid = two.start_centroid;
                self.gesture = Gesture::Two(two);
            }
            Gesture::Two(_) => self.ignore(ev.id),
        }
    }

    fn on_move(
        &mut self,
        ev: TouchEvent,
        geo: &TouchGeometry,
        now: Instant,
        out: &mut Vec<TouchAction>,
    ) {
        if self.is_ignored(ev.id) || !geo.usable() {
            return;
        }
        match self.gesture {
            Gesture::One(mut o) if o.f.id == ev.id => {
                o.f.pos = ev.pos;
                self.one_move(&mut o, geo, now, out);
                self.gesture = Gesture::One(o);
            }
            Gesture::Two(mut t) if t.a.id == ev.id || t.b.id == ev.id => {
                if t.a.id == ev.id {
                    t.a.pos = ev.pos;
                } else {
                    t.b.pos = ev.pos;
                }
                self.two_move(&mut t, geo, out);
                self.gesture = Gesture::Two(t);
            }
            _ => {}
        }
    }

    fn on_end(&mut self, ev: TouchEvent, now: Instant, out: &mut Vec<TouchAction>) {
        if let Some(i) = self.ignored.iter().position(|i| *i == ev.id) {
            self.ignored.swap_remove(i);
            return;
        }
        match self.gesture {
            Gesture::One(mut o) if o.f.id == ev.id => {
                self.gesture = Gesture::Idle;
                // Timers first so the outcome does not depend on tick cadence.
                self.timers(&mut o, now, out);
                if self.held[TouchButton::Left.index()] {
                    self.release(TouchButton::Left, out);
                } else if !o.long_pressed && !o.moved {
                    // Duration is deliberately not checked: the long-press
                    // timer above already claimed anything held long enough.
                    self.click(TouchButton::Left, out);
                    self.last_tap = Some((now, o.f.pos));
                }
                // Whatever else was in `held` (nothing, by construction).
                self.release_all(out);
            }
            Gesture::Two(t) if t.a.id == ev.id || t.b.id == ev.id => {
                self.gesture = Gesture::Idle;
                self.release_all(out);
                if t.tap_ok && !t.moved && now.saturating_duration_since(t.start_time) < LONG_PRESS
                {
                    self.click(TouchButton::Right, out);
                }
                // The finger left standing must not start a cursor drag.
                let other = if t.a.id == ev.id { t.b.id } else { t.a.id };
                self.ignore(other);
            }
            _ => {}
        }
    }

    fn on_cancel(&mut self, id: u64, out: &mut Vec<TouchAction>) {
        self.release_all(out);
        self.last_tap = None;
        let survivors: Vec<u64> = match self.gesture {
            Gesture::Idle => vec![],
            Gesture::One(o) => vec![o.f.id],
            Gesture::Two(t) => vec![t.a.id, t.b.id],
        };
        self.gesture = Gesture::Idle;
        if let Some(i) = self.ignored.iter().position(|i| *i == id) {
            self.ignored.swap_remove(i);
        }
        // A cancel is the system taking the touch stream away; fingers still
        // down must lift before they mean anything again.
        for s in survivors {
            if s != id {
                self.ignore(s);
            }
        }
    }

    // ---- one finger ------------------------------------------------------

    fn timers(&mut self, o: &mut One, now: Instant, out: &mut Vec<TouchAction>) {
        if o.moved || o.long_pressed {
            return;
        }
        let held_for = now.saturating_duration_since(o.start_time);
        if o.follow_up {
            if held_for >= LONG_PRESS && !self.held[TouchButton::Left.index()] {
                self.press(TouchButton::Left, out);
            }
        } else if held_for >= LONG_PRESS {
            self.click(TouchButton::Right, out);
            o.long_pressed = true;
        }
    }

    fn one_move(
        &mut self,
        o: &mut One,
        geo: &TouchGeometry,
        now: Instant,
        out: &mut Vec<TouchAction>,
    ) {
        if o.long_pressed {
            return;
        }
        if !o.moved && (o.f.pos - o.f.start).length() > TAP_SLOP_PTS {
            o.moved = true;
            o.applied = o.f.start;
            if o.follow_up && !self.held[TouchButton::Left.index()] {
                self.press(TouchButton::Left, out);
            }
        }
        if !o.moved {
            self.timers(o, now, out);
            return;
        }
        let delta = o.f.pos - o.applied;
        let dt = now
            .saturating_duration_since(o.last_time)
            .as_secs_f32()
            .max(0.008);
        let gain = cursor_gain(delta.length() / dt);
        self.move_cursor(delta * gain, geo, out);
        o.applied = o.f.pos;
        o.last_time = now;
    }

    // ---- two fingers -----------------------------------------------------

    fn two_move(&mut self, t: &mut Two, geo: &TouchGeometry, out: &mut Vec<TouchAction>) {
        let dist = t.dist();
        let c = t.centroid();
        if t.kind == TwoKind::Undecided {
            let centroid_move = (c - t.start_centroid).length();
            let spread = (dist - t.start_dist).abs();
            if centroid_move > TWO_FINGER_SLOP_PTS || spread > TWO_FINGER_SLOP_PTS {
                t.moved = true;
                t.kind = if spread > centroid_move {
                    TwoKind::Pinch
                } else {
                    TwoKind::Scroll
                };
                t.last_dist = t.start_dist;
                t.last_centroid = t.start_centroid;
            }
        }
        match t.kind {
            TwoKind::Undecided => {}
            TwoKind::Scroll => {
                let mut d = c - t.last_centroid;
                t.last_centroid = c;
                if d.y.abs() > 2.0 * d.x.abs() {
                    d.x = 0.0;
                } else if d.x.abs() > 2.0 * d.y.abs() {
                    d.y = 0.0;
                }
                // Content follows the fingers: fingers down => scroll up (+).
                t.acc_y += d.y * WHEEL_UNITS_PER_POINT;
                // Fingers left => view moves right (+).
                t.acc_x += -d.x * WHEEL_UNITS_PER_POINT;
                let (x, y) = self.cursor;
                for (acc, horizontal) in [(&mut t.acc_y, false), (&mut t.acc_x, true)] {
                    let v = acc
                        .trunc()
                        .clamp(-(MAX_WHEEL_PER_EVENT as f32), MAX_WHEEL_PER_EVENT as f32);
                    if v != 0.0 {
                        out.push(TouchAction::Wheel {
                            delta: v as i16,
                            horizontal,
                            x,
                            y,
                        });
                        *acc -= v;
                    }
                    *acc = acc.clamp(-(MAX_WHEEL_PER_EVENT as f32), MAX_WHEEL_PER_EVENT as f32);
                }
            }
            TwoKind::Pinch => {
                let ratio = dist / t.last_dist.max(1.0);
                t.last_dist = dist;
                let new_zoom = (self.zoom * ratio).clamp(MIN_ZOOM, MAX_ZOOM);
                if new_zoom != self.zoom || new_zoom > MIN_ZOOM {
                    self.zoom = new_zoom;
                    let (fx, fy) = pinch_focus(geo, c, new_zoom);
                    out.push(TouchAction::ZoomTo {
                        zoom: new_zoom,
                        focus_x: fx,
                        focus_y: fy,
                    });
                }
            }
        }
    }
}

/// Mild pointer acceleration: linear in finger speed between the two knees.
pub fn cursor_gain(speed_pts_per_s: f32) -> f32 {
    let t = ((speed_pts_per_s - ACCEL_START_PTS_PER_S)
        / (ACCEL_FULL_PTS_PER_S - ACCEL_START_PTS_PER_S))
        .clamp(0.0, 1.0);
    CURSOR_GAIN_BASE + (CURSOR_GAIN_MAX - CURSOR_GAIN_BASE) * t
}

/// Remote-normalized point to put at the viewport centre so the remote point
/// currently under `anchor` (screen) stays under it after zooming to
/// `new_zoom`. `geo.video` was drawn at `geo.drawn_zoom`.
pub fn pinch_focus(geo: &TouchGeometry, anchor: Pos2, new_zoom: f32) -> (f32, f32) {
    let size = geo.video.size();
    if size.x <= 0.0 || size.y <= 0.0 || geo.drawn_zoom <= 0.0 {
        return (0.5, 0.5);
    }
    let n = Vec2::new(
        ((anchor.x - geo.video.min.x) / size.x).clamp(0.0, 1.0),
        ((anchor.y - geo.video.min.y) / size.y).clamp(0.0, 1.0),
    );
    let new_size = size * (new_zoom / geo.drawn_zoom);
    let new_min = anchor - Vec2::new(n.x * new_size.x, n.y * new_size.y);
    let c = geo.viewport.center();
    (
        ((c.x - new_min.x) / new_size.x).clamp(0.0, 1.0),
        ((c.y - new_min.y) / new_size.y).clamp(0.0, 1.0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use egui::pos2;

    fn geo() -> TouchGeometry {
        let r = Rect::from_min_max(pos2(100.0, 50.0), pos2(900.0, 500.0));
        TouchGeometry {
            viewport: r,
            video: r,
            drawn_zoom: 1.0,
        }
    }

    /// Scripted clock + state machine.
    struct H {
        s: TouchState,
        t0: Instant,
        ms: u64,
        geo: TouchGeometry,
        log: Vec<TouchAction>,
    }

    impl H {
        fn new() -> Self {
            Self {
                s: TouchState::new(),
                t0: Instant::now(),
                ms: 0,
                geo: geo(),
                log: Vec::new(),
            }
        }
        fn at(&self) -> Instant {
            self.t0 + Duration::from_millis(self.ms)
        }
        fn ev(&mut self, dt: u64, id: u64, phase: TouchPhase, x: f32, y: f32) -> Vec<TouchAction> {
            self.ms += dt;
            let a = self.s.handle(
                TouchEvent {
                    id,
                    phase,
                    pos: pos2(x, y),
                },
                &self.geo,
                self.at(),
            );
            self.log.extend(a.iter().copied());
            a
        }
        fn down(&mut self, dt: u64, id: u64, x: f32, y: f32) -> Vec<TouchAction> {
            self.ev(dt, id, TouchPhase::Start, x, y)
        }
        fn mv(&mut self, dt: u64, id: u64, x: f32, y: f32) -> Vec<TouchAction> {
            self.ev(dt, id, TouchPhase::Move, x, y)
        }
        fn up(&mut self, dt: u64, id: u64, x: f32, y: f32) -> Vec<TouchAction> {
            self.ev(dt, id, TouchPhase::End, x, y)
        }
        fn tick(&mut self, dt: u64) -> Vec<TouchAction> {
            self.ms += dt;
            let a = self.s.tick(self.at());
            self.log.extend(a.iter().copied());
            a
        }
    }

    fn buttons(a: &[TouchAction]) -> Vec<(TouchButton, bool)> {
        a.iter()
            .filter_map(|a| match a {
                TouchAction::Button {
                    button, pressed, ..
                } => Some((*button, *pressed)),
                _ => None,
            })
            .collect()
    }

    const L: TouchButton = TouchButton::Left;
    const R: TouchButton = TouchButton::Right;

    #[test]
    fn tap_is_one_left_click_at_the_cursor() {
        let mut h = H::new();
        h.down(0, 1, 300.0, 200.0);
        let a = h.up(100, 1, 300.0, 200.0);
        assert_eq!(buttons(&a), vec![(L, true), (L, false)]);
        // Click lands where the cursor is (centre), not where the finger was.
        assert!(matches!(a[0], TouchAction::Button { x, y, .. } if x == 0.5 && y == 0.5));
    }

    #[test]
    fn slow_touch_without_movement_is_still_a_tap_until_long_press() {
        let mut h = H::new();
        h.down(0, 1, 300.0, 200.0);
        let a = h.up(400, 1, 300.0, 200.0);
        assert_eq!(buttons(&a), vec![(L, true), (L, false)]);
        // Past the long-press with no tick in between: right click, no tap.
        let mut h = H::new();
        h.down(0, 1, 300.0, 200.0);
        let a = h.up(700, 1, 300.0, 200.0);
        assert_eq!(buttons(&a), vec![(R, true), (R, false)]);
    }

    #[test]
    fn double_tap_is_two_clicks() {
        let mut h = H::new();
        h.down(0, 1, 300.0, 200.0);
        h.up(80, 1, 300.0, 200.0);
        h.down(100, 1, 302.0, 201.0);
        h.up(80, 1, 302.0, 201.0);
        assert_eq!(
            buttons(&h.log),
            vec![(L, true), (L, false), (L, true), (L, false)]
        );
    }

    #[test]
    fn drag_moves_the_cursor_relatively_and_clamps() {
        let mut h = H::new();
        h.down(0, 1, 300.0, 200.0);
        // Slow: 20 pt in 1 s => base gain.
        h.mv(1000, 1, 320.0, 200.0);
        let (x, y) = h.s.cursor();
        assert!((x - (0.5 + 20.0 / 800.0)).abs() < 1e-4, "x={x}");
        assert_eq!(y, 0.5);
        // Huge drag pins at the edge.
        h.mv(1000, 1, 5000.0, 5000.0);
        assert_eq!(h.s.cursor(), (1.0, 1.0));
        h.mv(1000, 1, -5000.0, -5000.0);
        assert_eq!(h.s.cursor(), (0.0, 0.0));
        let a = h.up(10, 1, 0.0, 0.0);
        assert!(buttons(&a).is_empty(), "a drag is not a tap");
    }

    #[test]
    fn acceleration_is_mild_and_monotonic() {
        assert_eq!(cursor_gain(0.0), CURSOR_GAIN_BASE);
        assert_eq!(cursor_gain(ACCEL_START_PTS_PER_S), CURSOR_GAIN_BASE);
        assert_eq!(cursor_gain(1e6), CURSOR_GAIN_MAX);
        assert!(cursor_gain(600.0) > cursor_gain(300.0));
        let mut slow = H::new();
        slow.down(0, 1, 300.0, 200.0);
        slow.mv(1000, 1, 360.0, 200.0);
        let mut fast = H::new();
        fast.down(0, 1, 300.0, 200.0);
        fast.mv(16, 1, 360.0, 200.0);
        assert!(fast.s.cursor().0 > slow.s.cursor().0);
    }

    #[test]
    fn cursor_scale_follows_the_visible_video_rect() {
        let mut h = H::new();
        // Zoomed 2x: the enlarged rect is twice as wide, so the same finger
        // travel moves the normalized cursor half as far.
        h.geo.video = Rect::from_min_size(pos2(-300.0, -200.0), egui::vec2(1600.0, 900.0));
        h.geo.drawn_zoom = 2.0;
        h.down(0, 1, 300.0, 200.0);
        h.mv(1000, 1, 340.0, 200.0);
        assert!((h.s.cursor().0 - (0.5 + 40.0 / 1600.0)).abs() < 1e-4);
    }

    #[test]
    fn tap_then_hold_and_drag_holds_left_and_releases() {
        let mut h = H::new();
        h.down(0, 1, 300.0, 200.0);
        h.up(60, 1, 300.0, 200.0);
        h.down(100, 1, 300.0, 200.0);
        // Held to the long-press time with no movement: left goes down on tick.
        assert!(h.tick(300).is_empty());
        let a = h.tick(200);
        assert_eq!(buttons(&a), vec![(L, true)]);
        assert!(h.s.button_held());
        h.mv(16, 1, 330.0, 200.0);
        assert!(h.s.cursor().0 > 0.5);
        let a = h.up(16, 1, 330.0, 200.0);
        assert_eq!(buttons(&a), vec![(L, false)]);
        assert!(!h.s.button_held());
    }

    #[test]
    fn tap_then_immediate_drag_presses_before_moving() {
        let mut h = H::new();
        h.down(0, 1, 300.0, 200.0);
        h.up(60, 1, 300.0, 200.0);
        let n = h.log.len();
        h.down(100, 1, 300.0, 200.0);
        h.mv(16, 1, 330.0, 200.0);
        let tail = &h.log[n..];
        assert!(matches!(tail[0], TouchAction::Button { pressed: true, .. }));
        assert!(matches!(tail[1], TouchAction::MoveTo { .. }));
        h.up(16, 1, 330.0, 200.0);
        assert!(!h.s.button_held());
    }

    #[test]
    fn second_touch_outside_the_window_or_far_away_is_a_fresh_gesture() {
        let mut h = H::new();
        h.down(0, 1, 300.0, 200.0);
        h.up(60, 1, 300.0, 200.0);
        // Too late. A fresh hold ends in a right click; a follow-up would
        // have pressed left instead.
        h.down(450, 1, 300.0, 200.0);
        assert_eq!(buttons(&h.tick(500)), vec![(R, true), (R, false)]);
        h.up(10, 1, 300.0, 200.0);
        // Too far.
        let mut h = H::new();
        h.down(0, 1, 300.0, 200.0);
        h.up(60, 1, 300.0, 200.0);
        h.down(100, 1, 600.0, 400.0);
        assert_eq!(buttons(&h.tick(500)), vec![(R, true), (R, false)]);
    }

    #[test]
    fn long_press_is_one_right_click_even_with_jittery_moves() {
        let mut h = H::new();
        h.down(0, 1, 300.0, 200.0);
        // Observed shape: ~50 zero-distance Moves over 800 ms.
        let mut right = 0;
        for _ in 0..50 {
            let a = h.mv(16, 1, 300.0, 200.0);
            right += buttons(&a).iter().filter(|b| b.0 == R && b.1).count();
        }
        assert_eq!(right, 1);
        let a = h.up(16, 1, 300.0, 200.0);
        assert!(a.is_empty(), "release after long-press adds nothing");
        assert_eq!(h.s.cursor(), (0.5, 0.5));
    }

    #[test]
    fn long_press_fires_from_tick_without_any_moves() {
        let mut h = H::new();
        h.down(0, 1, 300.0, 200.0);
        assert!(h.tick(400).is_empty());
        assert_eq!(buttons(&h.tick(150)), vec![(R, true), (R, false)]);
        assert!(h.tick(500).is_empty(), "fires once");
    }

    #[test]
    fn long_press_does_not_fire_after_real_movement() {
        let mut h = H::new();
        h.down(0, 1, 300.0, 200.0);
        h.mv(100, 1, 340.0, 200.0);
        assert!(h.tick(800).is_empty());
        h.up(10, 1, 340.0, 200.0);
        assert!(buttons(&h.log).is_empty());
    }

    #[test]
    fn two_finger_tap_is_a_right_click() {
        let mut h = H::new();
        h.down(0, 1, 300.0, 200.0);
        h.down(20, 2, 400.0, 200.0);
        let a = h.up(80, 1, 300.0, 200.0);
        assert_eq!(buttons(&a), vec![(R, true), (R, false)]);
        // The leftover finger is inert until it lifts.
        assert!(h.mv(16, 2, 450.0, 260.0).is_empty());
        assert!(h.up(16, 2, 450.0, 260.0).is_empty());
        assert_eq!(h.s.cursor(), (0.5, 0.5));
    }

    #[test]
    fn slow_two_finger_touch_is_not_a_right_click() {
        let mut h = H::new();
        h.down(0, 1, 300.0, 200.0);
        h.down(20, 2, 400.0, 200.0);
        let a = h.up(600, 1, 300.0, 200.0);
        assert!(buttons(&a).is_empty());
    }

    // ---- coarse / jittery frame timing -----------------------------------

    /// One raw gesture event: (time ms, finger id, phase, x, y).
    type Raw = (u64, u64, TouchPhase, f32, f32);

    /// Replay `events` as a UI presenting a frame every `q` ms: each event is
    /// delivered in the first frame at or after its time, then the frame
    /// `tick`s, as the app does. Runs well past the last event.
    fn replay_quantized(events: &[Raw], q: u64) -> H {
        let mut h = H::new();
        let end = events.iter().map(|e| e.0).max().unwrap_or(0) + 1500;
        let mut frame = 0;
        while frame <= end + q {
            h.ms = frame;
            for (t, id, phase, x, y) in events {
                if t.div_ceil(q) * q == frame {
                    let ev = TouchEvent {
                        id: *id,
                        phase: *phase,
                        pos: pos2(*x, *y),
                    };
                    let a = h.s.handle(ev, &h.geo, h.at());
                    h.log.extend(a);
                }
            }
            let a = h.s.tick(h.at());
            h.log.extend(a);
            frame += q;
        }
        h
    }

    /// Frame intervals: fast, 60 fps, slow, and the observed ~4 fps / worse.
    const FRAMES: [u64; 5] = [8, 16, 100, 250, 300];

    #[test]
    fn tap_is_a_click_at_any_frame_rate() {
        use TouchPhase::*;
        for q in FRAMES {
            let h = replay_quantized(&[(0, 1, Start, 300., 200.), (60, 1, End, 300., 200.)], q);
            assert_eq!(buttons(&h.log), vec![(L, true), (L, false)], "q={q}");
        }
    }

    #[test]
    fn double_tap_is_two_clicks_at_any_frame_rate() {
        use TouchPhase::*;
        for q in FRAMES {
            let h = replay_quantized(
                &[
                    (0, 1, Start, 300., 200.),
                    (60, 1, End, 300., 200.),
                    (160, 1, Start, 302., 201.),
                    (220, 1, End, 302., 201.),
                ],
                q,
            );
            assert_eq!(
                buttons(&h.log),
                vec![(L, true), (L, false), (L, true), (L, false)],
                "q={q}"
            );
        }
    }

    #[test]
    fn tap_drag_holds_left_and_releases_at_any_frame_rate() {
        use TouchPhase::*;
        for q in FRAMES {
            let h = replay_quantized(
                &[
                    (0, 1, Start, 300., 200.),
                    (60, 1, End, 300., 200.),
                    (160, 1, Start, 300., 200.),
                    (200, 1, Move, 330., 200.),
                    (260, 1, Move, 380., 200.),
                    (300, 1, End, 380., 200.),
                ],
                q,
            );
            // The tap's click, then press + release around the drag.
            assert_eq!(
                buttons(&h.log),
                vec![(L, true), (L, false), (L, true), (L, false)],
                "q={q}"
            );
            assert!(h.s.cursor().0 > 0.5, "q={q}: cursor did not move");
            assert!(!h.s.button_held(), "q={q}");
            let press = h
                .log
                .iter()
                .rposition(|a| matches!(a, TouchAction::Button { pressed: true, .. }))
                .unwrap();
            let mv = h
                .log
                .iter()
                .position(|a| matches!(a, TouchAction::MoveTo { .. }))
                .unwrap();
            assert!(press < mv, "q={q}: press must precede the first move");
        }
    }

    #[test]
    fn tap_then_hold_still_presses_left_at_any_frame_rate() {
        use TouchPhase::*;
        for q in FRAMES {
            let h = replay_quantized(
                &[
                    (0, 1, Start, 300., 200.),
                    (60, 1, End, 300., 200.),
                    (160, 1, Start, 300., 200.),
                    (1000, 1, End, 300., 200.),
                ],
                q,
            );
            assert_eq!(
                buttons(&h.log),
                vec![(L, true), (L, false), (L, true), (L, false)],
                "q={q}"
            );
            assert_eq!(h.s.cursor(), (0.5, 0.5), "q={q}");
        }
    }

    #[test]
    fn long_press_is_one_right_click_at_any_frame_rate() {
        use TouchPhase::*;
        for q in FRAMES {
            let h = replay_quantized(&[(0, 1, Start, 300., 200.), (900, 1, End, 300., 200.)], q);
            assert_eq!(buttons(&h.log), vec![(R, true), (R, false)], "q={q}");
        }
    }

    #[test]
    fn two_finger_tap_is_a_right_click_at_any_frame_rate() {
        use TouchPhase::*;
        for q in FRAMES {
            let h = replay_quantized(
                &[
                    (0, 1, Start, 300., 200.),
                    (10, 2, Start, 400., 200.),
                    (80, 2, End, 400., 200.),
                    (90, 1, End, 300., 200.),
                ],
                q,
            );
            assert_eq!(buttons(&h.log), vec![(R, true), (R, false)], "q={q}");
            assert_eq!(h.s.cursor(), (0.5, 0.5), "q={q}");
        }
    }

    fn wheel_total(a: &[TouchAction], horizontal: bool) -> i32 {
        a.iter()
            .filter_map(|a| match a {
                TouchAction::Wheel {
                    delta,
                    horizontal: h,
                    ..
                } if *h == horizontal => Some(*delta as i32),
                _ => None,
            })
            .sum()
    }

    #[test]
    fn two_finger_vertical_drag_scrolls_naturally() {
        let mut h = H::new();
        h.down(0, 1, 300.0, 200.0);
        h.down(5, 2, 360.0, 200.0);
        // Fingers move DOWN 90 pt together => content scrolls up => positive.
        for i in 1..=9 {
            h.mv(16, 1, 300.0, 200.0 + 10.0 * i as f32);
            h.mv(0, 2, 360.0, 200.0 + 10.0 * i as f32);
        }
        let v = wheel_total(&h.log, false);
        assert!(v > 0, "v={v}");
        assert_eq!(wheel_total(&h.log, true), 0);
        // 90 pt of travel at 3 units/pt: just under the first 12 pt of slop
        // being "free" is not applied — the full distance is accumulated.
        assert!((v - 270).abs() <= 1, "v={v}");
        // Fingers back up => negative.
        let before = wheel_total(&h.log, false);
        for i in 1..=9 {
            h.mv(16, 1, 300.0, 290.0 - 10.0 * i as f32);
            h.mv(0, 2, 360.0, 290.0 - 10.0 * i as f32);
        }
        assert!(wheel_total(&h.log, false) < before);
        assert!(buttons(&h.log).is_empty());
        h.up(5, 1, 300.0, 200.0);
        h.up(5, 2, 360.0, 200.0);
        assert!(!h.s.button_held());
    }

    #[test]
    fn two_finger_horizontal_drag_scrolls_horizontally() {
        let mut h = H::new();
        h.down(0, 1, 300.0, 200.0);
        h.down(5, 2, 360.0, 200.0);
        // Fingers move LEFT => view scrolls right => positive.
        for i in 1..=10 {
            h.mv(16, 1, 300.0 - 10.0 * i as f32, 200.0);
            h.mv(0, 2, 360.0 - 10.0 * i as f32, 200.0);
        }
        assert!(wheel_total(&h.log, true) > 0);
        assert_eq!(wheel_total(&h.log, false), 0);
    }

    #[test]
    fn wheel_accumulates_fractions_and_caps_per_event() {
        let mut h = H::new();
        h.down(0, 1, 300.0, 200.0);
        h.down(5, 2, 360.0, 200.0);
        // Decide scroll, then creep 0.2 pt per event: 0.6 unit each, so every
        // other-ish event emits a whole unit rather than rounding to nothing.
        h.mv(16, 1, 300.0, 215.0);
        h.mv(0, 2, 360.0, 215.0);
        let base = wheel_total(&h.log, false);
        for i in 0..50 {
            h.mv(16, 1, 300.0, 215.0 + 0.2 * (i + 1) as f32);
            h.mv(0, 2, 360.0, 215.0 + 0.2 * (i + 1) as f32);
        }
        let creep = wheel_total(&h.log, false) - base;
        assert!((creep - 30).abs() <= 1, "creep={creep}");
        // One giant jump is capped per action.
        let n = h.log.len();
        h.mv(16, 1, 300.0, 215.0 + 400.0);
        h.mv(0, 2, 360.0, 215.0 + 400.0);
        let big: Vec<i16> = h.log[n..]
            .iter()
            .filter_map(|a| match a {
                TouchAction::Wheel { delta, .. } => Some(*delta),
                _ => None,
            })
            .collect();
        assert!(!big.is_empty());
        assert!(big.iter().all(|d| d.abs() <= MAX_WHEEL_PER_EVENT));
    }

    #[test]
    fn pinch_out_zooms_in_pinch_in_zooms_out_within_limits() {
        let mut h = H::new();
        h.down(0, 1, 450.0, 275.0);
        h.down(5, 2, 550.0, 275.0);
        // Spread from 100 to 200 pt apart: 2x.
        for i in 1..=10 {
            h.mv(16, 1, 450.0 - 5.0 * i as f32, 275.0);
            h.mv(0, 2, 550.0 + 5.0 * i as f32, 275.0);
        }
        assert!((h.s.zoom() - 2.0).abs() < 0.05, "zoom={}", h.s.zoom());
        // Way past the cap.
        for i in 1..=40 {
            h.mv(16, 1, 400.0 - 10.0 * i as f32, 275.0);
            h.mv(0, 2, 600.0 + 10.0 * i as f32, 275.0);
        }
        assert_eq!(h.s.zoom(), MAX_ZOOM);
        // Pinch all the way in: floor at 1.0.
        for i in 0..60 {
            let d = (400.0 - 8.0 * i as f32).max(2.0);
            h.mv(16, 1, 500.0 - d / 2.0, 275.0);
            h.mv(0, 2, 500.0 + d / 2.0, 275.0);
        }
        assert_eq!(h.s.zoom(), MIN_ZOOM);
        assert!(buttons(&h.log).is_empty());
        assert!(wheel_total(&h.log, false) == 0);
    }

    #[test]
    fn pinch_keeps_the_point_under_the_fingers_fixed() {
        let g = geo();
        // Anchor a quarter across: after 2x zoom the focus (viewport centre)
        // must be such that the anchor's remote point is still under it.
        let anchor = pos2(g.video.min.x + 0.25 * g.video.width(), g.video.center().y);
        let (fx, fy) = pinch_focus(&g, anchor, 2.0);
        let new_size = g.video.size() * 2.0;
        let c = g.viewport.center();
        // Rect that puts (fx,fy) at the centre.
        let min = pos2(c.x - fx * new_size.x, c.y - fy * new_size.y);
        let under = (anchor.x - min.x) / new_size.x;
        assert!((under - 0.25).abs() < 1e-4, "under={under}");
    }

    #[test]
    fn touches_starting_outside_the_viewport_are_ignored_until_they_lift() {
        let mut h = H::new();
        // On the toolbar, above the viewport.
        assert!(h.down(0, 1, 300.0, 20.0).is_empty());
        // Dragging into the video does not start a gesture.
        assert!(h.mv(16, 1, 300.0, 200.0).is_empty());
        assert!(h.mv(16, 1, 400.0, 300.0).is_empty());
        assert!(!h.s.is_active());
        assert!(h.up(16, 1, 400.0, 300.0).is_empty());
        // A tap that begins outside, lifts inside: still nothing.
        h.down(0, 2, 50.0, 200.0);
        assert!(h.up(50, 2, 300.0, 200.0).is_empty());
        // And a new finger works normally afterwards.
        h.down(0, 3, 300.0, 200.0);
        assert_eq!(buttons(&h.up(50, 3, 300.0, 200.0)).len(), 2);
        assert_eq!(h.s.cursor(), (0.5, 0.5));
    }

    #[test]
    fn a_finger_outside_does_not_join_a_gesture() {
        let mut h = H::new();
        h.down(0, 1, 300.0, 200.0);
        h.down(5, 2, 300.0, 20.0); // toolbar finger, ignored
        h.mv(16, 2, 300.0, 100.0);
        // Still a plain one-finger gesture: tapping works.
        let a = h.up(50, 1, 300.0, 200.0);
        assert_eq!(buttons(&a).len(), 2);
    }

    #[test]
    fn a_third_finger_is_ignored() {
        let mut h = H::new();
        h.down(0, 1, 300.0, 200.0);
        h.down(5, 2, 400.0, 200.0);
        h.down(5, 3, 500.0, 300.0);
        assert!(h.mv(16, 3, 520.0, 320.0).is_empty());
        h.up(5, 3, 520.0, 320.0);
        let a = h.up(50, 1, 300.0, 200.0);
        assert_eq!(buttons(&a), vec![(R, true), (R, false)]);
    }

    #[test]
    fn unusable_geometry_swallows_input() {
        let mut h = H::new();
        h.geo.video = Rect::NOTHING;
        assert!(h.down(0, 1, 300.0, 200.0).is_empty());
        assert!(!h.s.is_active());
    }

    #[test]
    fn second_finger_mid_hold_drag_releases_the_button() {
        let mut h = H::new();
        h.down(0, 1, 300.0, 200.0);
        h.up(60, 1, 300.0, 200.0);
        h.down(100, 1, 300.0, 200.0);
        h.tick(500);
        assert!(h.s.button_held());
        let a = h.down(10, 2, 400.0, 200.0);
        assert_eq!(buttons(&a), vec![(L, false)]);
        assert!(!h.s.button_held());
    }

    #[test]
    fn cancel_releases_and_inerts_survivors() {
        let mut h = H::new();
        h.down(0, 1, 300.0, 200.0);
        h.up(60, 1, 300.0, 200.0);
        h.down(100, 1, 300.0, 200.0);
        h.tick(500);
        let a = h.ev(5, 1, TouchPhase::Cancel, 300.0, 200.0);
        assert_eq!(buttons(&a), vec![(L, false)]);
        assert!(!h.s.is_active());

        // Two fingers, cancel one: the other must not move the cursor.
        let mut h = H::new();
        h.down(0, 1, 300.0, 200.0);
        h.down(5, 2, 400.0, 200.0);
        h.ev(5, 1, TouchPhase::Cancel, 300.0, 200.0);
        assert!(h.mv(16, 2, 500.0, 300.0).is_empty());
        assert!(h.up(16, 2, 500.0, 300.0).is_empty());
        assert_eq!(h.s.cursor(), (0.5, 0.5));
    }

    #[test]
    fn reset_releases_and_forgets_everything() {
        let mut h = H::new();
        h.down(0, 1, 300.0, 200.0);
        h.up(60, 1, 300.0, 200.0);
        h.down(100, 1, 300.0, 200.0);
        h.tick(500);
        let a = h.s.reset();
        assert_eq!(buttons(&a), vec![(L, false)]);
        assert!(!h.s.is_active() && !h.s.button_held());
        // The orphaned finger's End is a no-op.
        assert!(h.up(10, 1, 300.0, 200.0).is_empty());
        // And a fresh tap works.
        h.down(0, 4, 300.0, 200.0);
        assert_eq!(buttons(&h.up(50, 4, 300.0, 200.0)).len(), 2);
    }

    #[test]
    fn from_egui_consumes_only_touch_events() {
        let t = egui::Event::Touch {
            device_id: egui::TouchDeviceId(0),
            id: egui::TouchId(7),
            phase: egui::TouchPhase::Start,
            pos: pos2(1.0, 2.0),
            force: None,
        };
        let e = TouchEvent::from_egui(&t).unwrap();
        assert_eq!(
            (e.id, e.phase, e.pos),
            (7, TouchPhase::Start, pos2(1.0, 2.0))
        );
        assert!(TouchEvent::from_egui(&egui::Event::PointerMoved(pos2(1.0, 1.0))).is_none());
        assert!(TouchEvent::from_egui(&egui::Event::PointerGone).is_none());
    }

    // ---- the no-stuck-button proof --------------------------------------

    type Script = Vec<(u64, u64, TouchPhase, f32, f32)>; // (dt, id, phase, x, y)

    #[allow(clippy::vec_init_then_push)]
    fn scripts() -> Vec<(&'static str, Script)> {
        use TouchPhase::*;
        let mut v: Vec<(&'static str, Script)> = Vec::new();
        v.push((
            "tap",
            vec![(0, 1, Start, 300., 200.), (80, 1, End, 300., 200.)],
        ));
        v.push((
            "double-tap",
            vec![
                (0, 1, Start, 300., 200.),
                (60, 1, End, 300., 200.),
                (100, 1, Start, 300., 200.),
                (60, 1, End, 300., 200.),
            ],
        ));
        v.push((
            "tap-hold-drag",
            vec![
                (0, 1, Start, 300., 200.),
                (60, 1, End, 300., 200.),
                (100, 1, Start, 300., 200.),
                (400, 1, Move, 300., 200.),
                (16, 1, Move, 340., 210.),
                (16, 1, Move, 380., 220.),
                (16, 1, End, 380., 220.),
            ],
        ));
        v.push((
            "tap-drag-immediately",
            vec![
                (0, 1, Start, 300., 200.),
                (60, 1, End, 300., 200.),
                (100, 1, Start, 300., 200.),
                (16, 1, Move, 330., 200.),
                (16, 1, Move, 360., 200.),
                (16, 1, End, 360., 200.),
            ],
        ));
        let mut lp: Script = vec![(0, 1, Start, 300., 200.)];
        for _ in 0..40 {
            lp.push((16, 1, Move, 300., 200.));
        }
        lp.push((16, 1, End, 300., 200.));
        v.push(("long-press", lp));
        v.push((
            "two-finger-tap",
            vec![
                (0, 1, Start, 300., 200.),
                (10, 2, Start, 400., 200.),
                (80, 2, End, 400., 200.),
                (5, 1, End, 300., 200.),
            ],
        ));
        let mut scroll: Script = vec![(0, 1, Start, 300., 200.), (5, 2, Start, 360., 200.)];
        for i in 1..=8 {
            scroll.push((16, 1, Move, 300., 200. + 10. * i as f32));
            scroll.push((0, 2, Move, 360., 200. + 10. * i as f32));
        }
        scroll.push((5, 1, End, 300., 280.));
        scroll.push((5, 2, End, 360., 280.));
        v.push(("two-finger-scroll", scroll));
        let mut pinch: Script = vec![(0, 1, Start, 450., 275.), (5, 2, Start, 550., 275.)];
        for i in 1..=8 {
            pinch.push((16, 1, Move, 450. - 6. * i as f32, 275.));
            pinch.push((0, 2, Move, 550. + 6. * i as f32, 275.));
        }
        pinch.push((5, 2, End, 598., 275.));
        pinch.push((5, 1, End, 402., 275.));
        v.push(("pinch", pinch));
        v.push((
            "drag-then-second-finger",
            vec![
                (0, 1, Start, 300., 200.),
                (16, 1, Move, 340., 200.),
                (16, 2, Start, 400., 200.),
                (16, 2, Move, 400., 240.),
                (16, 1, End, 340., 200.),
                (16, 2, End, 400., 240.),
            ],
        ));
        v.push((
            "hold-drag-then-second-finger",
            vec![
                (0, 1, Start, 300., 200.),
                (60, 1, End, 300., 200.),
                (100, 1, Start, 300., 200.),
                (16, 1, Move, 330., 200.),
                (16, 2, Start, 500., 300.),
                (16, 1, Move, 360., 200.),
                (16, 2, End, 500., 300.),
                (16, 1, End, 360., 200.),
            ],
        ));
        v.push((
            "toolbar-touch",
            vec![
                (0, 1, Start, 300., 10.),
                (16, 1, Move, 300., 200.),
                (16, 1, End, 300., 200.),
            ],
        ));
        v
    }

    /// Net (down - up) per button over a stream of actions.
    fn balance(actions: &[TouchAction]) -> [i32; 2] {
        let mut b = [0i32; 2];
        for a in actions {
            if let TouchAction::Button {
                button, pressed, ..
            } = a
            {
                b[button.index()] += if *pressed { 1 } else { -1 };
            }
        }
        b
    }

    #[test]
    fn no_button_sticks_for_any_gesture_cut_anywhere() {
        use TouchPhase::*;
        for (name, script) in scripts() {
            for cut in 0..=script.len() {
                for ending in 0..4 {
                    let mut h = H::new();
                    let mut open: Vec<u64> = Vec::new();
                    for (dt, id, phase, x, y) in script.iter().take(cut) {
                        h.ev(*dt, *id, *phase, *x, *y);
                        match phase {
                            Start => open.push(*id),
                            End | Cancel => open.retain(|o| o != id),
                            Move => {}
                        }
                    }
                    // Optionally let the long-press / hold timers run first.
                    if ending == 3 {
                        h.tick(900);
                    }
                    match ending {
                        // Abandoned: the app calls reset (disconnect/focus loss).
                        0 | 3 => {
                            let a = h.s.reset();
                            h.log.extend(a);
                        }
                        // The system cancels the touch stream.
                        1 => {
                            if let Some(id) = open.first() {
                                h.ev(1, *id, Cancel, 0.0, 0.0);
                            }
                        }
                        // Every finger lifts normally.
                        _ => {
                            for id in open.clone() {
                                h.ev(1, id, End, 0.0, 0.0);
                            }
                        }
                    }
                    assert_eq!(
                        balance(&h.log),
                        [0, 0],
                        "{name}: cut {cut} ending {ending} leaves a button down"
                    );
                    assert!(!h.s.button_held(), "{name}: cut {cut} ending {ending}");
                    // A reset leaves nothing for a later stray End to act on.
                    if ending == 0 || ending == 3 {
                        for id in open {
                            assert!(buttons(&h.ev(1, id, End, 0.0, 0.0)).is_empty());
                        }
                    }
                }
            }
        }
    }
}
