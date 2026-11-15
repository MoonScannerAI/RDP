//! The touch profile's app-shell glue that is pure enough to unit test: the
//! focus-flicker debounce, Back-key handling, the keyboard/video split, the
//! filter that keeps overlay touches away from the video, the compact
//! toolbar's auto-hide, and (Windows test aid) mouse-to-touch synthesis.
//!
//! Owned by the Phase-2 integrator. Everything here is inert in
//! `UiProfile::Desktop`: `ClientApp` only calls into it when the profile is
//! `Touch`.

use std::time::{Duration, Instant};

use egui::{Event, Pos2, Rect, TouchPhase};

/// Minimum touch target, in points, for anything the touch profile draws.
pub const TOUCH_TARGET_PTS: f32 = 36.0;

/// How long the expanded toolbar stays up without being touched.
pub const TOOLBAR_AUTO_HIDE: Duration = Duration::from_secs(5);

/// Consecutive unfocused frames before a focus loss counts as real. Android
/// reports `focused == false` for exactly one frame after a resume; that
/// flicker must not reset a gesture or drop capture.
pub const FOCUS_LOST_AFTER_FRAMES: u32 = 2;

// ---------------------------------------------------------------------------
// Focus debounce
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusEdge {
    None,
    Gained,
    Lost,
}

/// Window focus with single-frame dropouts filtered out. Starts unfocused, so
/// nothing is processed before the platform first reports focus.
#[derive(Debug, Clone)]
pub struct FocusDebounce {
    unfocused_frames: u32,
}

impl Default for FocusDebounce {
    fn default() -> Self {
        Self {
            unfocused_frames: FOCUS_LOST_AFTER_FRAMES,
        }
    }
}

impl FocusDebounce {
    pub fn is_focused(&self) -> bool {
        self.unfocused_frames < FOCUS_LOST_AFTER_FRAMES
    }

    /// Feed one frame's raw `focused` flag; returns the debounced transition.
    pub fn update(&mut self, focused: bool) -> FocusEdge {
        let was = self.is_focused();
        self.unfocused_frames = if focused {
            0
        } else {
            self.unfocused_frames.saturating_add(1)
        };
        match (was, self.is_focused()) {
            (false, true) => FocusEdge::Gained,
            (true, false) => FocusEdge::Lost,
            _ => FocusEdge::None,
        }
    }
}

/// Should capture be on? Live session, really focused, not released by the
/// operator (the release chord from a hardware keyboard).
pub fn touch_wants_capture(live: bool, focused: bool, user_released: bool) -> bool {
    live && focused && !user_released
}

// ---------------------------------------------------------------------------
// Back key
// ---------------------------------------------------------------------------

/// Remove every Back key event (press, release, repeat) from `events` and
/// return how many fresh presses there were. Back is the app's own control;
/// stripping it before egui sees the frame is what guarantees it can never
/// be forwarded to the host or reach a widget.
pub fn strip_back_key(events: &mut Vec<Event>) -> u32 {
    let mut presses = 0;
    events.retain(|e| match e {
        Event::Key {
            key,
            physical_key,
            pressed,
            repeat,
            ..
        } if *key == egui::Key::BrowserBack || *physical_key == Some(egui::Key::BrowserBack) => {
            if *pressed && !*repeat {
                presses += 1;
            }
            false
        }
        _ => true,
    });
    presses
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackAction {
    /// Streaming: show/hide the on-screen keyboard.
    ToggleKeyboard,
    /// Connect screen with a field focused: drop the focus (hides the keyboard).
    DismissLocalKeyboard,
    /// Nothing for the app to do.
    Nothing,
}

pub fn back_action(streaming: bool, local_keyboard_visible: bool) -> BackAction {
    if streaming {
        BackAction::ToggleKeyboard
    } else if local_keyboard_visible {
        BackAction::DismissLocalKeyboard
    } else {
        BackAction::Nothing
    }
}

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

/// Split `area` into (content above, keyboard strip at the bottom). A zero
/// height means no keyboard. The keyboard keeps its full height even if that
/// leaves no content (the widget sizes itself from the screen, so shrinking
/// its strip would only make it paint outside it).
pub fn split_for_keyboard(area: Rect, keyboard_h: f32) -> (Rect, Option<Rect>) {
    if keyboard_h.is_nan() || keyboard_h <= 0.0 {
        return (area, None);
    }
    let h = keyboard_h.min(area.height()).max(0.0);
    let y = area.max.y - h;
    (
        Rect::from_min_max(area.min, egui::pos2(area.max.x, y)),
        Some(Rect::from_min_max(egui::pos2(area.min.x, y), area.max)),
    )
}

/// On the connect screen, does a click at `click` drop text focus? Not when it
/// lands on the keyboard (that is how you type) or on a text field (egui moves
/// focus there itself).
pub fn click_dismisses_text_focus(
    click: Pos2,
    keyboard: Option<Rect>,
    text_edits: &[Rect],
) -> bool {
    !keyboard.is_some_and(|k| k.contains(click)) && !text_edits.iter().any(|r| r.contains(click))
}

// ---------------------------------------------------------------------------
// Event plumbing
// ---------------------------------------------------------------------------

/// `events` minus one occurrence of each event in `injected` — the on-screen
/// keyboard's local events this app put into the frame itself, which must
/// never be forwarded to the host as if typed on a hardware keyboard.
pub fn without_injected(events: &[Event], injected: &[Event]) -> Vec<Event> {
    if injected.is_empty() {
        return events.to_vec();
    }
    let mut pending: Vec<&Event> = injected.iter().collect();
    events
        .iter()
        .filter(|e| match pending.iter().position(|p| *p == *e) {
            Some(i) => {
                pending.swap_remove(i);
                false
            }
            None => true,
        })
        .cloned()
        .collect()
}

/// Keeps touches that *start* on an overlay (toolbar, a window, a banner) away
/// from the video's gesture layer for their whole life. egui still sees them
/// (through its synthesized pointer events), so the overlay's buttons work.
#[derive(Debug, Default)]
pub struct OverlayTouchFilter {
    blocked: Vec<u64>,
}

impl OverlayTouchFilter {
    pub fn filter(&mut self, events: &[Event], is_overlay: impl Fn(Pos2) -> bool) -> Vec<Event> {
        let mut out = Vec::with_capacity(events.len());
        for e in events {
            if let Event::Touch { id, phase, pos, .. } = e {
                let blocked = self.blocked.iter().position(|b| *b == id.0);
                let keep = match phase {
                    TouchPhase::Start => {
                        if is_overlay(*pos) {
                            if blocked.is_none() {
                                self.blocked.push(id.0);
                            }
                            false
                        } else {
                            if let Some(i) = blocked {
                                // A stale entry (its End was never seen).
                                self.blocked.swap_remove(i);
                            }
                            true
                        }
                    }
                    TouchPhase::Move => blocked.is_none(),
                    TouchPhase::End | TouchPhase::Cancel => match blocked {
                        Some(i) => {
                            self.blocked.swap_remove(i);
                            false
                        }
                        None => true,
                    },
                };
                if !keep {
                    continue;
                }
            }
            out.push(e.clone());
        }
        out
    }

    /// Forget every blocked finger (focus loss, session end).
    pub fn clear(&mut self) {
        self.blocked.clear();
    }
}

// ---------------------------------------------------------------------------
// Compact toolbar
// ---------------------------------------------------------------------------

/// Expanded until a deadline; every touch on it pushes the deadline out.
#[derive(Debug, Default)]
pub struct ToolbarState {
    shown_until: Option<Instant>,
}

impl ToolbarState {
    /// Expand (or keep expanded) for another [`TOOLBAR_AUTO_HIDE`].
    pub fn show(&mut self, now: Instant) {
        self.shown_until = Some(now + TOOLBAR_AUTO_HIDE);
    }

    pub fn hide(&mut self) {
        self.shown_until = None;
    }

    pub fn is_expanded(&self, now: Instant) -> bool {
        self.shown_until.is_some_and(|t| now < t)
    }

    /// Time until auto-hide, for a repaint deadline.
    pub fn remaining(&self, now: Instant) -> Option<Duration> {
        self.shown_until
            .filter(|t| now < *t)
            .map(|t| t.duration_since(now))
    }
}

// ---------------------------------------------------------------------------
// Mouse -> touch (Windows test aid; never compiled into the Android app)
// ---------------------------------------------------------------------------

/// The finger id synthesized touches use.
#[cfg(any(not(target_os = "android"), test))]
pub const SYNTH_TOUCH_ID: u64 = 0;

/// Turns the primary mouse button into a single finger (`--touch-ui` on
/// Windows), so the touch profile can be driven with a mouse: press = finger
/// down, drag = move, release = lift, holding still = long-press right click.
/// Real pointer events are left in place, exactly as Android's egui-winit
/// emits both. Switches itself off for good the first time a real touch is
/// seen, so a touchscreen laptop never gets double fingers.
#[cfg(any(not(target_os = "android"), test))]
#[derive(Debug, Default)]
pub struct MouseTouchSynth {
    down: bool,
    last_pos: Option<Pos2>,
    real_touch_seen: bool,
}

#[cfg(any(not(target_os = "android"), test))]
impl MouseTouchSynth {
    pub fn process(&mut self, events: &mut Vec<Event>) {
        if self.real_touch_seen {
            return;
        }
        if events.iter().any(|e| matches!(e, Event::Touch { .. })) {
            self.real_touch_seen = true;
            if self.down {
                self.down = false;
                if let Some(pos) = self.last_pos {
                    events.insert(0, synth_touch(TouchPhase::Cancel, pos));
                }
            }
            return;
        }
        let mut out = Vec::with_capacity(events.len() + 2);
        for e in events.drain(..) {
            let synth = match &e {
                Event::PointerMoved(pos) => {
                    self.last_pos = Some(*pos);
                    self.down.then(|| synth_touch(TouchPhase::Move, *pos))
                }
                Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed,
                    ..
                } => {
                    self.last_pos = Some(*pos);
                    match (*pressed, self.down) {
                        (true, false) => {
                            self.down = true;
                            Some(synth_touch(TouchPhase::Start, *pos))
                        }
                        (false, true) => {
                            self.down = false;
                            Some(synth_touch(TouchPhase::End, *pos))
                        }
                        _ => None,
                    }
                }
                Event::PointerGone if self.down => {
                    self.down = false;
                    self.last_pos
                        .map(|pos| synth_touch(TouchPhase::Cancel, pos))
                }
                _ => None,
            };
            out.push(e);
            out.extend(synth);
        }
        *events = out;
    }
}

#[cfg(any(not(target_os = "android"), test))]
fn synth_touch(phase: TouchPhase, pos: Pos2) -> Event {
    Event::Touch {
        device_id: egui::TouchDeviceId(0),
        id: egui::TouchId(SYNTH_TOUCH_ID),
        phase,
        pos,
        force: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use egui::{pos2, Key, Modifiers, PointerButton};

    fn key(k: Key, pressed: bool, repeat: bool) -> Event {
        Event::Key {
            key: k,
            physical_key: Some(k),
            pressed,
            repeat,
            modifiers: Modifiers::NONE,
        }
    }

    fn touch(id: u64, phase: TouchPhase, x: f32, y: f32) -> Event {
        Event::Touch {
            device_id: egui::TouchDeviceId(0),
            id: egui::TouchId(id),
            phase,
            pos: pos2(x, y),
            force: None,
        }
    }

    fn button(pressed: bool, x: f32, y: f32, b: PointerButton) -> Event {
        Event::PointerButton {
            pos: pos2(x, y),
            button: b,
            pressed,
            modifiers: Modifiers::NONE,
        }
    }

    fn touches(events: &[Event]) -> Vec<(TouchPhase, Pos2)> {
        events
            .iter()
            .filter_map(|e| match e {
                Event::Touch { phase, pos, .. } => Some((*phase, *pos)),
                _ => None,
            })
            .collect()
    }

    // -- focus ----------------------------------------------------------------

    #[test]
    fn focus_starts_lost_and_is_gained_on_the_first_focused_frame() {
        let mut f = FocusDebounce::default();
        assert!(!f.is_focused());
        assert_eq!(f.update(false), FocusEdge::None);
        assert_eq!(f.update(true), FocusEdge::Gained);
        assert!(f.is_focused());
    }

    #[test]
    fn a_one_frame_focus_flicker_is_not_a_loss() {
        let mut f = FocusDebounce::default();
        f.update(true);
        assert_eq!(f.update(false), FocusEdge::None, "resume flicker");
        assert!(f.is_focused());
        assert_eq!(f.update(true), FocusEdge::None);
        assert!(f.is_focused());
    }

    #[test]
    fn two_unfocused_frames_are_a_real_loss_reported_once() {
        let mut f = FocusDebounce::default();
        f.update(true);
        assert_eq!(f.update(false), FocusEdge::None);
        assert_eq!(f.update(false), FocusEdge::Lost);
        assert!(!f.is_focused());
        for _ in 0..10 {
            assert_eq!(f.update(false), FocusEdge::None);
        }
        assert_eq!(f.update(true), FocusEdge::Gained);
    }

    #[test]
    fn capture_needs_a_live_focused_unreleased_session() {
        assert!(touch_wants_capture(true, true, false));
        assert!(
            !touch_wants_capture(false, true, false),
            "not before go-live"
        );
        assert!(!touch_wants_capture(true, false, false), "not unfocused");
        assert!(!touch_wants_capture(true, true, true), "chord released");
    }

    // -- back -----------------------------------------------------------------

    #[test]
    fn back_is_stripped_whole_and_only_fresh_presses_count() {
        let mut evs = vec![
            key(Key::A, true, false),
            key(Key::BrowserBack, true, false),
            key(Key::BrowserBack, true, true),
            key(Key::BrowserBack, false, false),
            key(Key::A, false, false),
        ];
        assert_eq!(strip_back_key(&mut evs), 1);
        assert_eq!(
            evs,
            vec![key(Key::A, true, false), key(Key::A, false, false)]
        );
    }

    #[test]
    fn back_is_recognised_by_its_physical_key_too() {
        let mut evs = vec![Event::Key {
            key: Key::Escape,
            physical_key: Some(Key::BrowserBack),
            pressed: true,
            repeat: false,
            modifiers: Modifiers::NONE,
        }];
        assert_eq!(strip_back_key(&mut evs), 1);
        assert!(evs.is_empty());
    }

    #[test]
    fn back_never_reaches_the_host_scan_code_table() {
        // Belt and braces: even unstripped it has no scan code.
        assert!(crate::input_capture::egui_key_to_scancode(Key::BrowserBack).is_none());
    }

    #[test]
    fn back_toggles_the_keyboard_while_streaming_and_dismisses_it_locally() {
        assert_eq!(back_action(true, false), BackAction::ToggleKeyboard);
        assert_eq!(back_action(true, true), BackAction::ToggleKeyboard);
        assert_eq!(back_action(false, true), BackAction::DismissLocalKeyboard);
        assert_eq!(back_action(false, false), BackAction::Nothing);
    }

    // -- layout ---------------------------------------------------------------

    #[test]
    fn keyboard_takes_a_bottom_strip_and_the_video_keeps_the_rest() {
        let area = Rect::from_min_max(pos2(0.0, 0.0), pos2(865.0, 411.0));
        let (video, kb) = split_for_keyboard(area, 185.0);
        let kb = kb.expect("keyboard strip");
        assert_eq!(
            video,
            Rect::from_min_max(pos2(0.0, 0.0), pos2(865.0, 226.0))
        );
        assert_eq!(kb, Rect::from_min_max(pos2(0.0, 226.0), pos2(865.0, 411.0)));
        assert_eq!(video.height() + kb.height(), area.height());
    }

    #[test]
    fn no_keyboard_means_the_whole_area() {
        let area = Rect::from_min_max(pos2(10.0, 20.0), pos2(300.0, 200.0));
        assert_eq!(split_for_keyboard(area, 0.0), (area, None));
        assert_eq!(split_for_keyboard(area, f32::NAN), (area, None));
    }

    #[test]
    fn an_oversized_keyboard_is_capped_at_the_area() {
        let area = Rect::from_min_max(pos2(0.0, 0.0), pos2(300.0, 100.0));
        let (video, kb) = split_for_keyboard(area, 500.0);
        assert_eq!(video.height(), 0.0);
        assert_eq!(kb.unwrap(), area);
    }

    #[test]
    fn clicks_on_the_keyboard_or_a_field_keep_text_focus() {
        let kb = Rect::from_min_max(pos2(0.0, 200.0), pos2(800.0, 400.0));
        let field = Rect::from_min_max(pos2(100.0, 50.0), pos2(340.0, 80.0));
        assert!(!click_dismisses_text_focus(
            pos2(400.0, 300.0),
            Some(kb),
            &[field]
        ));
        assert!(!click_dismisses_text_focus(
            pos2(150.0, 60.0),
            Some(kb),
            &[field]
        ));
        assert!(click_dismisses_text_focus(
            pos2(600.0, 60.0),
            Some(kb),
            &[field]
        ));
        assert!(click_dismisses_text_focus(
            pos2(400.0, 300.0),
            None,
            &[field]
        ));
    }

    // -- events ---------------------------------------------------------------

    #[test]
    fn injected_events_are_removed_once_each_and_nothing_else() {
        let a = key(Key::A, true, false);
        let b = Event::Text("a".into());
        let events = vec![a.clone(), b.clone(), a.clone(), Event::PointerGone];
        // The frame had one hardware `A` and one injected `A` + text.
        let kept = without_injected(&events, &[a.clone(), b]);
        assert_eq!(kept, vec![a, Event::PointerGone]);
    }

    #[test]
    fn overlay_touches_are_withheld_for_their_whole_life() {
        let toolbar = Rect::from_min_max(pos2(400.0, 0.0), pos2(470.0, 36.0));
        let over = |p: Pos2| toolbar.contains(p);
        let mut f = OverlayTouchFilter::default();
        let frame1 = [
            touch(1, TouchPhase::Start, 430.0, 20.0),  // on the handle
            touch(2, TouchPhase::Start, 300.0, 300.0), // on the video
            Event::PointerMoved(pos2(430.0, 20.0)),
        ];
        let out = f.filter(&frame1, over);
        assert_eq!(touches(&out), vec![(TouchPhase::Start, pos2(300.0, 300.0))]);
        assert!(
            out.contains(&Event::PointerMoved(pos2(430.0, 20.0))),
            "egui keeps pointer events"
        );
        // The handle finger drags onto the video: still withheld.
        let frame2 = [
            touch(1, TouchPhase::Move, 430.0, 200.0),
            touch(2, TouchPhase::Move, 310.0, 300.0),
        ];
        assert_eq!(
            touches(&f.filter(&frame2, over)),
            vec![(TouchPhase::Move, pos2(310.0, 300.0))]
        );
        let frame3 = [
            touch(1, TouchPhase::End, 430.0, 200.0),
            touch(2, TouchPhase::End, 310.0, 300.0),
        ];
        assert_eq!(
            touches(&f.filter(&frame3, over)),
            vec![(TouchPhase::End, pos2(310.0, 300.0))]
        );
        // Id 1 is free again: a new finger 1 on the video passes.
        let frame4 = [touch(1, TouchPhase::Start, 300.0, 300.0)];
        assert_eq!(touches(&f.filter(&frame4, over)).len(), 1);
    }

    #[test]
    fn a_video_touch_dragged_over_the_toolbar_stays_with_the_video() {
        let toolbar = Rect::from_min_max(pos2(400.0, 0.0), pos2(470.0, 36.0));
        let mut f = OverlayTouchFilter::default();
        let evs = [
            touch(5, TouchPhase::Start, 430.0, 200.0),
            touch(5, TouchPhase::Move, 430.0, 20.0),
            touch(5, TouchPhase::End, 430.0, 20.0),
        ];
        assert_eq!(touches(&f.filter(&evs, |p| toolbar.contains(p))).len(), 3);
    }

    // -- toolbar --------------------------------------------------------------

    #[test]
    fn toolbar_auto_hides_and_touches_keep_it_up() {
        let t0 = Instant::now();
        let mut t = ToolbarState::default();
        assert!(!t.is_expanded(t0));
        t.show(t0);
        assert!(t.is_expanded(t0 + Duration::from_secs(4)));
        t.show(t0 + Duration::from_secs(4));
        assert!(t.is_expanded(t0 + Duration::from_secs(8)));
        assert!(!t.is_expanded(t0 + Duration::from_secs(10)));
        assert_eq!(t.remaining(t0 + Duration::from_secs(10)), None);
        t.show(t0);
        t.hide();
        assert!(!t.is_expanded(t0));
    }

    // -- mouse -> touch ---------------------------------------------------------

    #[test]
    fn a_mouse_click_becomes_one_finger_start_and_end() {
        let mut s = MouseTouchSynth::default();
        let mut evs = vec![
            Event::PointerMoved(pos2(10.0, 10.0)),
            button(true, 10.0, 10.0, PointerButton::Primary),
        ];
        s.process(&mut evs);
        assert_eq!(touches(&evs), vec![(TouchPhase::Start, pos2(10.0, 10.0))]);
        assert_eq!(evs.len(), 3, "pointer events stay for egui");
        let mut evs = vec![
            Event::PointerMoved(pos2(20.0, 10.0)),
            button(false, 20.0, 10.0, PointerButton::Primary),
        ];
        s.process(&mut evs);
        assert_eq!(
            touches(&evs),
            vec![
                (TouchPhase::Move, pos2(20.0, 10.0)),
                (TouchPhase::End, pos2(20.0, 10.0))
            ]
        );
        assert!(evs.iter().all(|e| match e {
            Event::Touch { id, .. } => id.0 == SYNTH_TOUCH_ID,
            _ => true,
        }));
    }

    #[test]
    fn hovering_and_other_buttons_make_no_fingers() {
        let mut s = MouseTouchSynth::default();
        let mut evs = vec![
            Event::PointerMoved(pos2(10.0, 10.0)),
            button(true, 10.0, 10.0, PointerButton::Secondary),
            button(false, 10.0, 10.0, PointerButton::Secondary),
        ];
        s.process(&mut evs);
        assert!(touches(&evs).is_empty());
    }

    #[test]
    fn leaving_the_window_mid_drag_cancels_the_finger() {
        let mut s = MouseTouchSynth::default();
        let mut evs = vec![button(true, 10.0, 10.0, PointerButton::Primary)];
        s.process(&mut evs);
        let mut evs = vec![Event::PointerMoved(pos2(30.0, 40.0)), Event::PointerGone];
        s.process(&mut evs);
        assert_eq!(
            touches(&evs),
            vec![
                (TouchPhase::Move, pos2(30.0, 40.0)),
                (TouchPhase::Cancel, pos2(30.0, 40.0))
            ]
        );
        // A release after the cancel does not invent an End.
        let mut evs = vec![button(false, 30.0, 40.0, PointerButton::Primary)];
        s.process(&mut evs);
        assert!(touches(&evs).is_empty());
    }

    #[test]
    fn a_real_touchscreen_turns_synthesis_off_for_good() {
        let mut s = MouseTouchSynth::default();
        let mut evs = vec![button(true, 10.0, 10.0, PointerButton::Primary)];
        s.process(&mut evs);
        // A real touch arrives while our fake finger is down: cancel ours.
        let real = touch(7, TouchPhase::Start, 50.0, 50.0);
        let mut evs = vec![real.clone()];
        s.process(&mut evs);
        assert_eq!(
            touches(&evs),
            vec![
                (TouchPhase::Cancel, pos2(10.0, 10.0)),
                (TouchPhase::Start, pos2(50.0, 50.0))
            ]
        );
        let mut evs = vec![button(true, 10.0, 10.0, PointerButton::Primary)];
        s.process(&mut evs);
        assert!(touches(&evs).is_empty(), "no synthesis after a real touch");
    }
}
