//! The on-screen keyboard for the touch UI profile, drawn in egui. Emits Set-1
//! scan codes directly (the protocol has no text message), including modifiers,
//! Esc/Tab/arrows/F-keys, with its own key repeat.
//!
//! Owned by W5 (Phase 1).
//!
//! # API
//!
//! * [`Keyboard::show`] draws the keyboard in the given `Ui` and returns a
//!   [`KeyboardOutput`]. With [`KeyboardTarget::Remote`] the output carries
//!   [`KeyStroke`]s (deliver with `InputCapture::send_key`); with
//!   [`KeyboardTarget::Local`] it carries `egui::Event`s to inject into
//!   egui's `RawInput` so local `TextEdit`s receive typing.
//! * [`Keyboard::tick`] produces key repeats on frames where `show` was not
//!   called (`show` ticks internally).
//! * [`Keyboard::release_all`] / [`Keyboard::release_all_output`] release every
//!   held key and modifier. Call on hide, disconnect and focus loss.
//!   [`Keyboard::set_visible`]`(false)` and a target switch do it for you and
//!   hand back the output to deliver.
//! * [`Keyboard::desired_height`] is the height `show` will occupy.
//!
//! # Modifiers
//!
//! Shift/Ctrl/Alt/Win latch: tap = one-shot (applies to the next key, then
//! releases), tap again = locked, tap again = off. One-shot modifiers are sent
//! around the key (`mod down, key down, key up, mod up`); locked modifiers are
//! held down on the host from the moment they lock until they unlock. Chars
//! that need Shift (`!`, `A`, `{`) add Shift automatically.
//!
//! # Layout
//!
//! Five rows on every page (so the height never jumps), at >= 30 pt per key,
//! taking about 45% of the available height. Pages: letters (number row +
//! QWERTY), symbols (US punctuation; Shift gives the shifted forms), and
//! function/navigation (Esc, F1-F12, PrtSc, Tab, nav cluster, arrows, Start).

use std::time::{Duration, Instant};

use egui::{Event, Key, Modifiers};

use crate::input_capture::egui_key_to_scancode;

/// First auto-repeat after this long held.
pub const REPEAT_DELAY: Duration = Duration::from_millis(400);
/// Then one repeat per this interval.
pub const REPEAT_INTERVAL: Duration = Duration::from_millis(33);

/// One key transition for the remote host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyStroke {
    pub scan_code: u16,
    pub extended: bool,
    pub down: bool,
}

/// Where keyboard output goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyboardTarget {
    /// Scan-code strokes for the remote host.
    Remote,
    /// `egui::Event`s for local widgets (connect screen).
    Local,
}

/// What a call produced. Only the field matching the target is filled.
#[derive(Default, Debug)]
pub struct KeyboardOutput {
    pub strokes: Vec<KeyStroke>,
    pub events: Vec<Event>,
}

impl KeyboardOutput {
    pub fn is_empty(&self) -> bool {
        self.strokes.is_empty() && self.events.is_empty()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mod {
    Shift,
    Ctrl,
    Alt,
    Win,
}

impl Mod {
    pub const ALL: [Mod; 4] = [Mod::Shift, Mod::Ctrl, Mod::Alt, Mod::Win];

    fn idx(self) -> usize {
        self as usize
    }

    /// Set-1 scan code and extended flag.
    pub fn scan(self) -> (u16, bool) {
        match self {
            Mod::Shift => (0x2A, false),
            Mod::Ctrl => (0x1D, false),
            Mod::Alt => (0x38, false),
            Mod::Win => (0x5B, true),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ModState {
    #[default]
    Off,
    OneShot,
    Locked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Page {
    Letters,
    Symbols,
    Function,
}

/// What a key does.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum KeyAct {
    /// A printable ASCII char in its unshifted form where one exists.
    Char(char),
    /// A non-printing key, via the shared egui -> scan code table.
    Key(Key),
    /// A key egui does not model (Win tap, PrintScreen). Remote only.
    Raw {
        scan_code: u16,
        extended: bool,
    },
    Mod(Mod),
    Page(Page),
    Spacer,
}

// ---------------------------------------------------------------------------
// Pure character mapping
// ---------------------------------------------------------------------------

const LETTER_KEYS: [Key; 26] = [
    Key::A,
    Key::B,
    Key::C,
    Key::D,
    Key::E,
    Key::F,
    Key::G,
    Key::H,
    Key::I,
    Key::J,
    Key::K,
    Key::L,
    Key::M,
    Key::N,
    Key::O,
    Key::P,
    Key::Q,
    Key::R,
    Key::S,
    Key::T,
    Key::U,
    Key::V,
    Key::W,
    Key::X,
    Key::Y,
    Key::Z,
];
const DIGIT_KEYS: [Key; 10] = [
    Key::Num0,
    Key::Num1,
    Key::Num2,
    Key::Num3,
    Key::Num4,
    Key::Num5,
    Key::Num6,
    Key::Num7,
    Key::Num8,
    Key::Num9,
];
const SHIFTED_DIGITS: &str = ")!@#$%^&*(";
/// (unshifted, shifted, key) for the punctuation keys.
const PUNCT: [(char, char, Key); 11] = [
    ('-', '_', Key::Minus),
    ('=', '+', Key::Equals),
    ('[', '{', Key::OpenBracket),
    (']', '}', Key::CloseBracket),
    ('\\', '|', Key::Backslash),
    (';', ':', Key::Semicolon),
    ('\'', '"', Key::Quote),
    (',', '<', Key::Comma),
    ('.', '>', Key::Period),
    ('/', '?', Key::Slash),
    ('`', '~', Key::Backtick),
];

/// Physical key and whether Shift is needed to produce `c` (US layout).
pub fn char_to_key(c: char) -> Option<(Key, bool)> {
    match c {
        ' ' => Some((Key::Space, false)),
        'a'..='z' => Some((LETTER_KEYS[(c as u8 - b'a') as usize], false)),
        'A'..='Z' => Some((LETTER_KEYS[(c as u8 - b'A') as usize], true)),
        '0'..='9' => Some((DIGIT_KEYS[(c as u8 - b'0') as usize], false)),
        _ => {
            if let Some(i) = SHIFTED_DIGITS.find(c) {
                return Some((DIGIT_KEYS[i], true));
            }
            PUNCT.iter().find_map(|&(u, s, k)| {
                if c == u {
                    Some((k, false))
                } else if c == s {
                    Some((k, true))
                } else {
                    None
                }
            })
        }
    }
}

/// `(scan_code, extended, needs_shift)` for a printable ASCII char.
pub fn char_to_scan(c: char) -> Option<(u16, bool, bool)> {
    let (key, shift) = char_to_key(c)?;
    let (sc, ext) = egui_key_to_scancode(key)?;
    Some((sc, ext, shift))
}

/// What `c` becomes with Shift held (`a` -> `A`, `1` -> `!`; unchanged if it
/// has no shifted form or is already shifted).
pub fn shifted_char(c: char) -> char {
    if c.is_ascii_lowercase() {
        return c.to_ascii_uppercase();
    }
    if let Some(d) = c.to_digit(10) {
        return SHIFTED_DIGITS.chars().nth(d as usize).unwrap_or(c);
    }
    PUNCT
        .iter()
        .find(|&&(u, _, _)| u == c)
        .map_or(c, |&(_, s, _)| s)
}

fn is_repeatable(act: KeyAct) -> bool {
    match act {
        KeyAct::Char(_) => true,
        KeyAct::Key(k) => matches!(
            k,
            Key::Backspace
                | Key::Delete
                | Key::ArrowUp
                | Key::ArrowDown
                | Key::ArrowLeft
                | Key::ArrowRight
        ),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Pure state machine
// ---------------------------------------------------------------------------

struct Held {
    next_repeat: Instant,
    repeatable: bool,
    /// Modifiers this key brought down; released after the key.
    release_mods: Vec<Mod>,
    remote: Option<(u16, bool)>,
    local_key: Option<(Key, Modifiers)>,
    local_text: Option<String>,
}

/// Modifier latching, stroke sequencing and repeat; no drawing.
pub struct Core {
    pub page: Page,
    mods: [ModState; 4],
    /// Modifiers currently down on the host (Remote).
    host_down: [bool; 4],
    held: Option<Held>,
}

impl Default for Core {
    fn default() -> Self {
        Self {
            page: Page::Letters,
            mods: [ModState::Off; 4],
            host_down: [false; 4],
            held: None,
        }
    }
}

fn stroke((scan_code, extended): (u16, bool), down: bool) -> KeyStroke {
    KeyStroke {
        scan_code,
        extended,
        down,
    }
}

fn key_event(key: Key, pressed: bool, repeat: bool, modifiers: Modifiers) -> Event {
    Event::Key {
        key,
        physical_key: Some(key),
        pressed,
        repeat,
        modifiers,
    }
}

impl Core {
    pub fn mod_state(&self, m: Mod) -> ModState {
        self.mods[m.idx()]
    }

    pub fn is_holding(&self) -> bool {
        self.held.is_some()
    }

    /// True if any key or modifier is down (on the host or locally).
    pub fn anything_held(&self) -> bool {
        self.held.is_some() || self.host_down.iter().any(|&d| d)
    }

    pub fn press(
        &mut self,
        act: KeyAct,
        target: KeyboardTarget,
        now: Instant,
        out: &mut KeyboardOutput,
    ) {
        match act {
            KeyAct::Mod(m) => self.tap_mod(m, target, out),
            KeyAct::Page(p) => self.page = p,
            KeyAct::Spacer => {}
            _ => self.press_key(act, target, now, out),
        }
    }

    fn tap_mod(&mut self, m: Mod, target: KeyboardTarget, out: &mut KeyboardOutput) {
        let i = m.idx();
        self.mods[i] = match self.mods[i] {
            ModState::Off => ModState::OneShot,
            ModState::OneShot => {
                if target == KeyboardTarget::Remote && !self.host_down[i] {
                    out.strokes.push(stroke(m.scan(), true));
                    self.host_down[i] = true;
                }
                ModState::Locked
            }
            ModState::Locked => {
                if self.host_down[i] {
                    out.strokes.push(stroke(m.scan(), false));
                    self.host_down[i] = false;
                }
                ModState::Off
            }
        };
    }

    fn press_key(
        &mut self,
        act: KeyAct,
        target: KeyboardTarget,
        now: Instant,
        out: &mut KeyboardOutput,
    ) {
        // Single finger: a new press ends any previous hold.
        self.release(out);

        let shift_on = self.mods[Mod::Shift.idx()] != ModState::Off;
        let mut want = [false; 4];
        for m in Mod::ALL {
            want[m.idx()] = self.mods[m.idx()] != ModState::Off;
        }

        // Resolve to a physical key (+ optional printable text).
        let mut text: Option<char> = None;
        let mut raw: Option<(u16, bool)> = None;
        let mut key: Option<Key> = None;
        match act {
            KeyAct::Char(c) => {
                let eff = if shift_on { shifted_char(c) } else { c };
                let Some((k, need_shift)) = char_to_key(eff) else {
                    return;
                };
                key = Some(k);
                text = Some(eff);
                if need_shift {
                    want[Mod::Shift.idx()] = true;
                }
            }
            KeyAct::Key(k) => key = Some(k),
            KeyAct::Raw {
                scan_code,
                extended,
            } => raw = Some((scan_code, extended)),
            _ => return,
        }

        let mut held = Held {
            next_repeat: now + REPEAT_DELAY,
            repeatable: is_repeatable(act),
            release_mods: Vec::new(),
            remote: None,
            local_key: None,
            local_text: None,
        };

        match target {
            KeyboardTarget::Remote => {
                let sc = raw.or_else(|| key.and_then(egui_key_to_scancode));
                let Some(sc) = sc else {
                    return;
                };
                for m in Mod::ALL {
                    let i = m.idx();
                    if want[i] && !self.host_down[i] {
                        out.strokes.push(stroke(m.scan(), true));
                        self.host_down[i] = true;
                        if self.mods[i] != ModState::Locked {
                            held.release_mods.push(m);
                        }
                    }
                }
                out.strokes.push(stroke(sc, true));
                held.remote = Some(sc);
            }
            KeyboardTarget::Local => {
                let modifiers = Modifiers {
                    alt: want[Mod::Alt.idx()],
                    ctrl: want[Mod::Ctrl.idx()],
                    shift: want[Mod::Shift.idx()],
                    mac_cmd: false,
                    command: want[Mod::Ctrl.idx()],
                };
                match (text, key) {
                    (Some(t), _) if !modifiers.ctrl && !modifiers.alt => {
                        out.events.push(Event::Text(t.to_string()));
                        held.local_text = Some(t.to_string());
                    }
                    (_, Some(k)) => {
                        out.events.push(key_event(k, true, false, modifiers));
                        held.local_key = Some((k, modifiers));
                    }
                    _ => {} // Raw keys have no local meaning.
                }
            }
        }

        // One-shots are consumed by this key.
        for m in Mod::ALL {
            if self.mods[m.idx()] == ModState::OneShot {
                self.mods[m.idx()] = ModState::Off;
            }
        }
        self.held = Some(held);
    }

    /// End the current hold: key up, then the modifiers it brought down.
    pub fn release(&mut self, out: &mut KeyboardOutput) {
        let Some(h) = self.held.take() else {
            return;
        };
        if let Some(sc) = h.remote {
            out.strokes.push(stroke(sc, false));
        }
        for m in h.release_mods {
            out.strokes.push(stroke(m.scan(), false));
            self.host_down[m.idx()] = false;
        }
        if let Some((k, mods)) = h.local_key {
            out.events.push(key_event(k, false, false, mods));
        }
    }

    /// Emit due repeats for the held key.
    pub fn tick(&mut self, now: Instant, out: &mut KeyboardOutput) {
        let Some(h) = self.held.as_mut() else {
            return;
        };
        if !h.repeatable || now < h.next_repeat {
            return;
        }
        h.next_repeat += REPEAT_INTERVAL;
        if h.next_repeat <= now {
            h.next_repeat = now + REPEAT_INTERVAL;
        }
        if let Some(sc) = h.remote {
            out.strokes.push(stroke(sc, true));
        }
        if let Some(t) = &h.local_text {
            out.events.push(Event::Text(t.clone()));
        }
        if let Some((k, mods)) = h.local_key {
            out.events.push(key_event(k, true, true, mods));
        }
    }

    /// Release everything and reset all latches; nothing stays down.
    pub fn release_all(&mut self, out: &mut KeyboardOutput) {
        self.release(out);
        for m in Mod::ALL {
            if self.host_down[m.idx()] {
                out.strokes.push(stroke(m.scan(), false));
                self.host_down[m.idx()] = false;
            }
        }
        self.mods = [ModState::Off; 4];
    }
}

// ---------------------------------------------------------------------------
// Layout (pure) and drawing
// ---------------------------------------------------------------------------

const ROWS: usize = 5;
const GAP: f32 = 3.0;
const PAD: f32 = 4.0;
const MIN_KEY_H: f32 = 30.0;
const MAX_KEY_H: f32 = 48.0;

#[derive(Clone, Debug)]
pub struct KeyDef {
    pub label: String,
    pub act: KeyAct,
    pub weight: f32,
}

fn kd(label: &str, act: KeyAct, weight: f32) -> KeyDef {
    KeyDef {
        label: label.to_string(),
        act,
        weight,
    }
}

fn ch(c: char, shift: bool) -> KeyDef {
    let shown = if shift { shifted_char(c) } else { c };
    kd(&shown.to_string(), KeyAct::Char(c), 1.0)
}

fn chars(s: &str, shift: bool) -> Vec<KeyDef> {
    s.chars().map(|c| ch(c, shift)).collect()
}

fn fixed(c: char) -> KeyDef {
    kd(&c.to_string(), KeyAct::Char(c), 1.0)
}

fn special(label: &str, k: Key, w: f32) -> KeyDef {
    kd(label, KeyAct::Key(k), w)
}

fn md(label: &str, m: Mod, w: f32) -> KeyDef {
    kd(label, KeyAct::Mod(m), w)
}

fn bottom_row(page: Page) -> Vec<KeyDef> {
    let mut r = vec![
        md("Ctrl", Mod::Ctrl, 1.3),
        md("Alt", Mod::Alt, 1.3),
        md("Win", Mod::Win, 1.3),
    ];
    r.push(match page {
        Page::Letters => kd("#+=", KeyAct::Page(Page::Symbols), 1.3),
        _ => kd("abc", KeyAct::Page(Page::Letters), 1.3),
    });
    r.push(kd("space", KeyAct::Char(' '), 4.0));
    r.push(special("Enter", Key::Enter, 1.6));
    r.push(match page {
        Page::Function => kd("#+=", KeyAct::Page(Page::Symbols), 1.1),
        _ => kd("Fn", KeyAct::Page(Page::Function), 1.1),
    });
    r
}

/// The rows of keys on `page`. Always [`ROWS`] rows. Labels follow `shift`.
pub fn page_rows(page: Page, shift: bool) -> Vec<Vec<KeyDef>> {
    let bksp = special("Bksp", Key::Backspace, 1.5);
    let shift_key = md("Shift", Mod::Shift, 1.5);
    let arrows = |w: f32| {
        vec![
            special("\u{2190}", Key::ArrowLeft, w),
            special("\u{2191}", Key::ArrowUp, w),
            special("\u{2193}", Key::ArrowDown, w),
            special("\u{2192}", Key::ArrowRight, w),
        ]
    };
    match page {
        Page::Letters => {
            let mut r0 = chars("1234567890", shift);
            r0.push(bksp);
            let r1 = chars("qwertyuiop", shift);
            let mut r2 = vec![kd("", KeyAct::Spacer, 0.5)];
            r2.extend(chars("asdfghjkl", shift));
            r2.push(kd("", KeyAct::Spacer, 0.5));
            let mut r3 = vec![shift_key];
            r3.extend(chars("zxcvbnm", shift));
            r3.extend([fixed(','), fixed('.')]);
            vec![r0, r1, r2, r3, bottom_row(page)]
        }
        Page::Symbols => {
            let mut r0 = chars("1234567890", false);
            r0.push(bksp);
            let r1: Vec<KeyDef> = SHIFTED_DIGITS
                .chars()
                .cycle()
                .skip(1)
                .take(10)
                .map(fixed)
                .collect();
            let r2 = chars("-=[]\\;',./", shift);
            let mut r3 = vec![shift_key];
            r3.extend(chars("`", shift));
            r3.push(fixed('~'));
            r3.extend(arrows(1.0));
            vec![r0, r1, r2, r3, bottom_row(page)]
        }
        Page::Function => {
            let fk = [
                Key::F1,
                Key::F2,
                Key::F3,
                Key::F4,
                Key::F5,
                Key::F6,
                Key::F7,
                Key::F8,
                Key::F9,
                Key::F10,
                Key::F11,
                Key::F12,
            ];
            let f = |i: usize| special(&format!("F{}", i + 1), fk[i], 1.0);
            let mut r0 = vec![special("Esc", Key::Escape, 1.3)];
            r0.extend((0..6).map(f));
            let mut r1: Vec<KeyDef> = (6..12).map(f).collect();
            r1.push(kd(
                "PrtSc",
                KeyAct::Raw {
                    scan_code: 0x37,
                    extended: true,
                },
                1.3,
            ));
            let r2 = vec![
                special("Tab", Key::Tab, 1.2),
                special("Ins", Key::Insert, 1.0),
                special("Del", Key::Delete, 1.0),
                special("Home", Key::Home, 1.2),
                special("End", Key::End, 1.0),
                special("PgUp", Key::PageUp, 1.2),
                special("PgDn", Key::PageDown, 1.2),
            ];
            let mut r3 = vec![shift_key];
            r3.extend(arrows(1.0));
            r3.push(bksp);
            r3.push(kd(
                "Start",
                KeyAct::Raw {
                    scan_code: 0x5B,
                    extended: true,
                },
                1.3,
            ));
            vec![r0, r1, r2, r3, bottom_row(page)]
        }
    }
}

/// Flatten rows into `(rect, key)` inside `area`.
pub fn layout_keys(
    rows: &[Vec<KeyDef>],
    area: egui::Rect,
    key_h: f32,
) -> Vec<(egui::Rect, KeyDef)> {
    let mut out = Vec::new();
    for (ri, row) in rows.iter().enumerate() {
        let total_w: f32 = row.iter().map(|k| k.weight).sum();
        let usable = area.width() - GAP * (row.len().saturating_sub(1)) as f32;
        let unit = usable / total_w.max(0.001);
        let y = area.top() + ri as f32 * (key_h + GAP);
        let mut x = area.left();
        for k in row {
            let w = unit * k.weight;
            let rect = egui::Rect::from_min_size(egui::pos2(x, y), egui::vec2(w, key_h));
            x += w + GAP;
            out.push((rect, k.clone()));
        }
    }
    out
}

/// Key height for a screen of `available`: about 45% of its height, clamped
/// to 30..48 pt.
pub fn key_height(available: egui::Rect) -> f32 {
    let budget = available.height() * 0.45 - 2.0 * PAD - GAP * (ROWS - 1) as f32;
    (budget / ROWS as f32).clamp(MIN_KEY_H, MAX_KEY_H)
}

/// Total keyboard height for a screen of `available`.
pub fn total_height(available: egui::Rect) -> f32 {
    key_height(available) * ROWS as f32 + GAP * (ROWS - 1) as f32 + 2.0 * PAD
}

// ---------------------------------------------------------------------------
// Keyboard widget
// ---------------------------------------------------------------------------

/// The on-screen keyboard widget. See the module docs.
pub struct Keyboard {
    core: Core,
    visible: bool,
    last_target: Option<KeyboardTarget>,
    /// Index (into this frame's layout) of the key the pointer is holding.
    pointer_key: Option<usize>,
}

impl Default for Keyboard {
    fn default() -> Self {
        Self::new()
    }
}

/// One frame of pointer state.
#[derive(Clone, Copy, Debug)]
pub struct PointerFrame {
    /// Primary button went down this frame.
    pub pressed: bool,
    /// Primary button is down at the end of the frame.
    pub down: bool,
    pub pos: Option<egui::Pos2>,
}

impl Keyboard {
    pub fn new() -> Self {
        Self {
            core: Core::default(),
            visible: true,
            last_target: None,
            pointer_key: None,
        }
    }

    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Hiding releases everything; the returned output must be delivered.
    pub fn set_visible(&mut self, visible: bool) -> KeyboardOutput {
        let mut out = KeyboardOutput::default();
        if !visible && self.visible {
            self.release_all_into(&mut out);
        }
        self.visible = visible;
        out
    }

    pub fn desired_height(&self, available: egui::Rect) -> f32 {
        if self.visible {
            total_height(available)
        } else {
            0.0
        }
    }

    pub fn page(&self) -> Page {
        self.core.page
    }

    pub fn mod_state(&self, m: Mod) -> ModState {
        self.core.mod_state(m)
    }

    fn release_all_into(&mut self, out: &mut KeyboardOutput) {
        self.core.release_all(out);
        self.pointer_key = None;
    }

    /// Release every held key and modifier (strokes and local events).
    pub fn release_all_output(&mut self) -> KeyboardOutput {
        let mut out = KeyboardOutput::default();
        self.release_all_into(&mut out);
        out
    }

    /// Strokes releasing every held key and modifier. Leaves nothing stuck.
    pub fn release_all(&mut self) -> Vec<KeyStroke> {
        self.release_all_output().strokes
    }

    /// Repeats for a held key when no pointer input arrived.
    pub fn tick(&mut self, now: Instant) -> KeyboardOutput {
        let mut out = KeyboardOutput::default();
        self.core.tick(now, &mut out);
        out
    }

    /// Apply one frame of pointer state to a laid-out keyboard. Pure apart
    /// from `self`, so it is unit-tested with synthetic rects.
    pub fn handle_pointer(
        &mut self,
        keys: &[(egui::Rect, KeyDef)],
        ptr: PointerFrame,
        target: KeyboardTarget,
        now: Instant,
        out: &mut KeyboardOutput,
    ) {
        let hit = ptr
            .pos
            .and_then(|p| keys.iter().position(|(r, _)| r.contains(p)));
        match self.pointer_key {
            Some(i) => {
                // Lifting or sliding off the key ends the hold.
                if !ptr.down || hit != Some(i) {
                    self.core.release(out);
                    self.pointer_key = None;
                }
            }
            None => {
                if ptr.pressed {
                    if let Some(i) = hit {
                        self.core.press(keys[i].1.act, target, now, out);
                        if self.core.is_holding() {
                            self.pointer_key = Some(i);
                        }
                        if !ptr.down {
                            self.core.release(out);
                            self.pointer_key = None;
                        }
                    }
                }
            }
        }
        self.core.tick(now, out);
    }

    /// Draw the keyboard in `ui` (full width, [`Self::desired_height`] tall)
    /// and return what this frame produced.
    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        target: KeyboardTarget,
        now: Instant,
    ) -> KeyboardOutput {
        let mut out = KeyboardOutput::default();
        if !self.visible {
            return out;
        }
        if self.last_target.is_some_and(|t| t != target) {
            self.release_all_into(&mut out);
        }
        self.last_target = Some(target);

        let screen = ui.ctx().content_rect();
        let key_h = key_height(screen);
        let h = total_height(screen);
        let (rect, _) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), h), egui::Sense::hover());
        let area = rect.shrink2(egui::vec2(PAD, PAD));

        let shift = self.core.mod_state(Mod::Shift) != ModState::Off;
        let rows = page_rows(self.core.page, shift);
        let keys = layout_keys(&rows, area, key_h);

        let ptr = ui.input(|i| PointerFrame {
            pressed: i.pointer.primary_pressed(),
            down: i.pointer.primary_down(),
            pos: i.pointer.interact_pos().or_else(|| i.pointer.latest_pos()),
        });
        let page_before = self.core.page;
        self.handle_pointer(&keys, ptr, target, now, &mut out);

        if self.core.page != page_before {
            ui.ctx().request_repaint();
        }
        if self.core.is_holding() {
            ui.ctx().request_repaint_after(Duration::from_millis(16));
        }

        let painter = ui.painter_at(rect);
        let vis = ui.visuals().clone();
        painter.rect_filled(rect, 0.0, vis.extreme_bg_color);
        for (i, (r, k)) in keys.iter().enumerate() {
            if k.act == KeyAct::Spacer {
                continue;
            }
            let mod_state = match k.act {
                KeyAct::Mod(m) => self.core.mod_state(m),
                _ => ModState::Off,
            };
            let is_down = self.pointer_key == Some(i);
            let fill = if is_down {
                vis.widgets.active.bg_fill
            } else if mod_state != ModState::Off {
                vis.selection.bg_fill
            } else {
                vis.widgets.inactive.weak_bg_fill
            };
            painter.rect_filled(*r, 5.0, fill);
            if mod_state == ModState::Locked {
                let bar = egui::Rect::from_min_size(
                    egui::pos2(r.left() + 6.0, r.bottom() - 6.0),
                    egui::vec2(r.width() - 12.0, 3.0),
                );
                painter.rect_filled(bar, 1.0, vis.selection.stroke.color);
            }
            let size = (key_h * 0.42).clamp(12.0, 20.0);
            let font_size = if k.label.chars().count() > 2 {
                size * 0.75
            } else {
                size
            };
            painter.text(
                r.center(),
                egui::Align2::CENTER_CENTER,
                &k.label,
                egui::FontId::proportional(font_size),
                vis.widgets.inactive.fg_stroke.color,
            );
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const R: KeyboardTarget = KeyboardTarget::Remote;
    const L: KeyboardTarget = KeyboardTarget::Local;

    fn t0() -> Instant {
        Instant::now()
    }

    fn st(sc: u16, ext: bool, down: bool) -> KeyStroke {
        KeyStroke {
            scan_code: sc,
            extended: ext,
            down,
        }
    }

    fn pf(pressed: bool, down: bool, x: f32) -> PointerFrame {
        PointerFrame {
            pressed,
            down,
            pos: Some(egui::pos2(x, 10.0)),
        }
    }

    /// Independent expectation, derived from the physical keyboard rows.
    fn expected(c: char) -> (u16, bool) {
        let rows: [(&str, &str, u16); 4] = [
            ("1234567890-=", "!@#$%^&*()_+", 0x02),
            ("qwertyuiop[]", "QWERTYUIOP{}", 0x10),
            ("asdfghjkl;'", "ASDFGHJKL:\"", 0x1E),
            ("zxcvbnm,./", "ZXCVBNM<>?", 0x2C),
        ];
        for (base, shifted, sc0) in rows {
            if let Some(i) = base.find(c) {
                return (sc0 + i as u16, false);
            }
            if let Some(i) = shifted.find(c) {
                return (sc0 + i as u16, true);
            }
        }
        match c {
            '`' => (0x29, false),
            '~' => (0x29, true),
            '\\' => (0x2B, false),
            '|' => (0x2B, true),
            ' ' => (0x39, false),
            _ => panic!("no expectation for {c:?}"),
        }
    }

    #[test]
    fn every_printable_ascii_maps_correctly() {
        for b in 0x20u8..=0x7E {
            let c = b as char;
            let (sc, ext, shift) = char_to_scan(c).unwrap_or_else(|| panic!("{c:?} unmapped"));
            let (esc, eshift) = expected(c);
            assert_eq!((sc, shift), (esc, eshift), "char {c:?}");
            assert!(!ext);
        }
        assert!(char_to_scan('\u{e9}').is_none());
        assert!(char_to_scan('\n').is_none());
    }

    #[test]
    fn shifted_char_agrees_with_scan_table() {
        for b in 0x21u8..=0x7E {
            let c = b as char;
            let (sc, _, need) = char_to_scan(c).unwrap();
            if !need {
                let s = shifted_char(c);
                if s != c {
                    let (sc2, _, need2) = char_to_scan(s).unwrap();
                    assert_eq!(sc, sc2, "{c:?} -> {s:?}");
                    assert!(need2);
                }
            }
        }
        assert_eq!(shifted_char('a'), 'A');
        assert_eq!(shifted_char('1'), '!');
        assert_eq!(shifted_char('0'), ')');
        assert_eq!(shifted_char('/'), '?');
        assert_eq!(shifted_char('!'), '!');
    }

    fn tap(core: &mut Core, act: KeyAct, target: KeyboardTarget, now: Instant) -> KeyboardOutput {
        let mut out = KeyboardOutput::default();
        core.press(act, target, now, &mut out);
        core.release(&mut out);
        out
    }

    fn press(core: &mut Core, act: KeyAct, target: KeyboardTarget) -> KeyboardOutput {
        let mut out = KeyboardOutput::default();
        core.press(act, target, t0(), &mut out);
        out
    }

    #[test]
    fn plain_char_is_down_up() {
        let mut c = Core::default();
        let out = tap(&mut c, KeyAct::Char('a'), R, t0());
        assert_eq!(
            out.strokes,
            vec![st(0x1E, false, true), st(0x1E, false, false)]
        );
    }

    #[test]
    fn needs_shift_chars_wrap_shift() {
        let mut c = Core::default();
        let out = tap(&mut c, KeyAct::Char('!'), R, t0());
        assert_eq!(
            out.strokes,
            vec![
                st(0x2A, false, true),
                st(0x02, false, true),
                st(0x02, false, false),
                st(0x2A, false, false)
            ]
        );
        assert!(!c.anything_held());
    }

    #[test]
    fn ctrl_c_sequence_order() {
        let mut c = Core::default();
        let out = press(&mut c, KeyAct::Mod(Mod::Ctrl), R);
        assert!(out.strokes.is_empty(), "one-shot sends nothing until a key");
        assert_eq!(c.mod_state(Mod::Ctrl), ModState::OneShot);
        let out = tap(&mut c, KeyAct::Char('c'), R, t0());
        assert_eq!(
            out.strokes,
            vec![
                st(0x1D, false, true),
                st(0x2E, false, true),
                st(0x2E, false, false),
                st(0x1D, false, false)
            ]
        );
        assert_eq!(c.mod_state(Mod::Ctrl), ModState::Off);
        let out = tap(&mut c, KeyAct::Char('c'), R, t0());
        assert_eq!(out.strokes.len(), 2, "next key is plain again");
    }

    #[test]
    fn multiple_modifiers_order() {
        let mut c = Core::default();
        press(&mut c, KeyAct::Mod(Mod::Win), R);
        press(&mut c, KeyAct::Mod(Mod::Alt), R);
        press(&mut c, KeyAct::Mod(Mod::Ctrl), R);
        let out = tap(&mut c, KeyAct::Key(Key::Delete), R, t0());
        assert_eq!(
            out.strokes,
            vec![
                st(0x1D, false, true),
                st(0x38, false, true),
                st(0x5B, true, true),
                st(0x53, true, true),
                st(0x53, true, false),
                st(0x1D, false, false),
                st(0x38, false, false),
                st(0x5B, true, false),
            ]
        );
    }

    #[test]
    fn locked_modifier_stays_until_tapped() {
        let mut c = Core::default();
        press(&mut c, KeyAct::Mod(Mod::Ctrl), R);
        let o = press(&mut c, KeyAct::Mod(Mod::Ctrl), R);
        assert_eq!(c.mod_state(Mod::Ctrl), ModState::Locked);
        assert_eq!(o.strokes, vec![st(0x1D, false, true)]);
        for _ in 0..2 {
            let out = tap(&mut c, KeyAct::Char('a'), R, t0());
            assert_eq!(
                out.strokes,
                vec![st(0x1E, false, true), st(0x1E, false, false)]
            );
            assert_eq!(c.mod_state(Mod::Ctrl), ModState::Locked);
        }
        let o = press(&mut c, KeyAct::Mod(Mod::Ctrl), R);
        assert_eq!(o.strokes, vec![st(0x1D, false, false)]);
        assert_eq!(c.mod_state(Mod::Ctrl), ModState::Off);
        assert!(!c.anything_held());
    }

    #[test]
    fn shift_modifies_chars() {
        let mut c = Core::default();
        press(&mut c, KeyAct::Mod(Mod::Shift), R);
        // One-shot Shift + '1' types '!'.
        let out = tap(&mut c, KeyAct::Char('1'), R, t0());
        assert_eq!(
            out.strokes,
            vec![
                st(0x2A, false, true),
                st(0x02, false, true),
                st(0x02, false, false),
                st(0x2A, false, false)
            ]
        );
        // Locked Shift: 'a' types 'A' with Shift held throughout.
        press(&mut c, KeyAct::Mod(Mod::Shift), R);
        let o = press(&mut c, KeyAct::Mod(Mod::Shift), R);
        assert_eq!(o.strokes, vec![st(0x2A, false, true)]);
        let out = tap(&mut c, KeyAct::Char('a'), R, t0());
        assert_eq!(
            out.strokes,
            vec![st(0x1E, false, true), st(0x1E, false, false)]
        );
        let out = tap(&mut c, KeyAct::Char('!'), R, t0());
        assert_eq!(out.strokes.len(), 2, "shift already held, not re-sent");
    }

    #[test]
    fn nav_and_function_keys() {
        let mut c = Core::default();
        let out = tap(&mut c, KeyAct::Key(Key::ArrowUp), R, t0());
        assert_eq!(
            out.strokes,
            vec![st(0x48, true, true), st(0x48, true, false)]
        );
        let out = tap(&mut c, KeyAct::Key(Key::F11), R, t0());
        assert_eq!(
            out.strokes,
            vec![st(0x57, false, true), st(0x57, false, false)]
        );
        let raw = KeyAct::Raw {
            scan_code: 0x37,
            extended: true,
        };
        let out = tap(&mut c, raw, R, t0());
        assert_eq!(
            out.strokes,
            vec![st(0x37, true, true), st(0x37, true, false)]
        );
    }

    #[test]
    fn repeat_timing() {
        let mut c = Core::default();
        let start = t0();
        let mut out = KeyboardOutput::default();
        c.press(KeyAct::Key(Key::Backspace), R, start, &mut out);
        assert_eq!(out.strokes, vec![st(0x0E, false, true)]);
        let mut at = |ms: u64| {
            let mut o = KeyboardOutput::default();
            c.tick(start + Duration::from_millis(ms), &mut o);
            assert!(o.strokes.iter().all(|s| s.down));
            o.strokes.len()
        };
        assert_eq!(at(0), 0);
        assert_eq!(at(399), 0);
        assert_eq!(at(400), 1);
        assert_eq!(at(410), 0);
        assert_eq!(at(433), 1);
        assert_eq!(at(466), 1);
        assert_eq!(at(470), 0);
        assert_eq!(at(2000), 1, "a stall yields one repeat, not a burst");
        let mut o = KeyboardOutput::default();
        c.release(&mut o);
        assert_eq!(o.strokes, vec![st(0x0E, false, false)]);
        let mut o = KeyboardOutput::default();
        c.tick(start + Duration::from_millis(3000), &mut o);
        assert!(o.is_empty());
    }

    #[test]
    fn non_repeatable_keys_do_not_repeat() {
        let mut c = Core::default();
        let start = t0();
        let mut o = KeyboardOutput::default();
        c.press(KeyAct::Key(Key::Enter), R, start, &mut o);
        c.tick(start + Duration::from_secs(2), &mut o);
        assert_eq!(o.strokes.len(), 1);
    }

    #[test]
    fn letters_repeat_with_modifiers_held() {
        let mut c = Core::default();
        let start = t0();
        press(&mut c, KeyAct::Mod(Mod::Ctrl), R);
        let mut o = KeyboardOutput::default();
        c.press(KeyAct::Char('z'), R, start, &mut o);
        c.tick(start + Duration::from_millis(400), &mut o);
        c.release(&mut o);
        assert_eq!(
            o.strokes,
            vec![
                st(0x1D, false, true),
                st(0x2C, false, true),
                st(0x2C, false, true),
                st(0x2C, false, false),
                st(0x1D, false, false),
            ]
        );
    }

    #[test]
    fn release_all_leaves_nothing_held() {
        let mut c = Core::default();
        // Locked Alt + one-shot Ctrl + a held 'A' (auto shift).
        press(&mut c, KeyAct::Mod(Mod::Alt), R);
        press(&mut c, KeyAct::Mod(Mod::Alt), R);
        press(&mut c, KeyAct::Mod(Mod::Ctrl), R);
        let o = press(&mut c, KeyAct::Char('A'), R);
        assert!(c.anything_held());
        let downs: Vec<(u16, bool)> = o
            .strokes
            .iter()
            .filter(|s| s.down)
            .map(|s| (s.scan_code, s.extended))
            .collect();
        assert!(downs.len() >= 3);
        let mut r = KeyboardOutput::default();
        c.release_all(&mut r);
        assert!(!c.anything_held());
        for d in &downs {
            assert!(
                r.strokes
                    .iter()
                    .any(|s| !s.down && (s.scan_code, s.extended) == *d),
                "{d:?} not released"
            );
        }
        for m in Mod::ALL {
            assert_eq!(c.mod_state(m), ModState::Off);
        }
        let mut r2 = KeyboardOutput::default();
        c.release_all(&mut r2);
        assert!(r2.is_empty(), "idempotent");
    }

    #[test]
    fn keyboard_release_all_and_hide() {
        let mut k = Keyboard::new();
        let mut o = KeyboardOutput::default();
        k.core.press(KeyAct::Mod(Mod::Win), R, t0(), &mut o);
        k.core.press(KeyAct::Mod(Mod::Win), R, t0(), &mut o);
        k.core.press(KeyAct::Key(Key::ArrowLeft), R, t0(), &mut o);
        let out = k.set_visible(false);
        assert!(!k.is_visible());
        assert!(out.strokes.contains(&st(0x4B, true, false)));
        assert!(out.strokes.contains(&st(0x5B, true, false)));
        assert!(k.release_all().is_empty());
        let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(865.0, 411.0));
        assert_eq!(k.desired_height(screen), 0.0);
    }

    #[test]
    fn local_plain_text() {
        let mut c = Core::default();
        let out = tap(&mut c, KeyAct::Char('a'), L, t0());
        assert!(out.strokes.is_empty());
        assert_eq!(out.events.len(), 1);
        assert!(matches!(&out.events[0], Event::Text(s) if s == "a"));
        let out = tap(&mut c, KeyAct::Char('!'), L, t0());
        assert!(matches!(&out.events[0], Event::Text(s) if s == "!"));
        let out = tap(&mut c, KeyAct::Char(' '), L, t0());
        assert!(matches!(&out.events[0], Event::Text(s) if s == " "));
    }

    #[test]
    fn local_shift_makes_capitals() {
        let mut c = Core::default();
        press(&mut c, KeyAct::Mod(Mod::Shift), L);
        let out = tap(&mut c, KeyAct::Char('q'), L, t0());
        assert!(matches!(&out.events[0], Event::Text(s) if s == "Q"));
        let out = tap(&mut c, KeyAct::Char('q'), L, t0());
        assert!(matches!(&out.events[0], Event::Text(s) if s == "q"));
    }

    #[test]
    fn local_editing_keys() {
        let mut c = Core::default();
        let out = tap(&mut c, KeyAct::Key(Key::Backspace), L, t0());
        assert_eq!(out.events.len(), 2);
        assert!(matches!(
            &out.events[0],
            Event::Key {
                key: Key::Backspace,
                pressed: true,
                repeat: false,
                ..
            }
        ));
        assert!(matches!(
            &out.events[1],
            Event::Key {
                key: Key::Backspace,
                pressed: false,
                ..
            }
        ));
        let out = tap(&mut c, KeyAct::Key(Key::Enter), L, t0());
        assert!(matches!(
            &out.events[0],
            Event::Key {
                key: Key::Enter,
                pressed: true,
                ..
            }
        ));
    }

    #[test]
    fn local_ctrl_a_is_a_key_event_with_modifiers() {
        let mut c = Core::default();
        let o = press(&mut c, KeyAct::Mod(Mod::Ctrl), L);
        assert!(o.is_empty());
        let out = tap(&mut c, KeyAct::Char('a'), L, t0());
        match &out.events[0] {
            Event::Key {
                key: Key::A,
                pressed: true,
                modifiers,
                ..
            } => assert!(modifiers.ctrl && modifiers.command && !modifiers.shift),
            e => panic!("unexpected {e:?}"),
        }
        assert!(!out.events.iter().any(|e| matches!(e, Event::Text(_))));
    }

    #[test]
    fn local_shift_arrow_selects() {
        let mut c = Core::default();
        press(&mut c, KeyAct::Mod(Mod::Shift), L);
        let out = tap(&mut c, KeyAct::Key(Key::ArrowLeft), L, t0());
        assert!(matches!(
            &out.events[0],
            Event::Key { key: Key::ArrowLeft, modifiers, .. } if modifiers.shift
        ));
    }

    #[test]
    fn local_repeat() {
        let mut c = Core::default();
        let start = t0();
        let mut o = KeyboardOutput::default();
        c.press(KeyAct::Key(Key::Backspace), L, start, &mut o);
        let mut r = KeyboardOutput::default();
        c.tick(start + Duration::from_millis(400), &mut r);
        assert!(matches!(
            &r.events[0],
            Event::Key {
                key: Key::Backspace,
                pressed: true,
                repeat: true,
                ..
            }
        ));
        let mut o = KeyboardOutput::default();
        c.press(KeyAct::Char('x'), L, start, &mut o);
        let mut r = KeyboardOutput::default();
        c.tick(start + Duration::from_millis(400), &mut r);
        assert!(matches!(&r.events[0], Event::Text(s) if s == "x"));
    }

    #[test]
    fn local_raw_keys_emit_nothing() {
        let mut c = Core::default();
        let raw = KeyAct::Raw {
            scan_code: 0x37,
            extended: true,
        };
        assert!(tap(&mut c, raw, L, t0()).is_empty());
    }

    #[test]
    fn pages_have_five_rows_and_every_key_maps() {
        for page in [Page::Letters, Page::Symbols, Page::Function] {
            for shift in [false, true] {
                let rows = page_rows(page, shift);
                assert_eq!(rows.len(), ROWS, "{page:?}");
                for k in rows.iter().flatten() {
                    match k.act {
                        KeyAct::Char(c) => assert!(char_to_scan(c).is_some(), "{c:?}"),
                        KeyAct::Key(key) => {
                            assert!(egui_key_to_scancode(key).is_some(), "{key:?}")
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    #[test]
    fn all_printable_chars_reachable() {
        use std::collections::HashSet;
        let mut reach: HashSet<char> = HashSet::new();
        for page in [Page::Letters, Page::Symbols] {
            for shift in [false, true] {
                for k in page_rows(page, shift).into_iter().flatten() {
                    if let KeyAct::Char(c) = k.act {
                        reach.insert(if shift { shifted_char(c) } else { c });
                    }
                }
            }
        }
        for b in 0x20u8..=0x7E {
            assert!(reach.contains(&(b as char)), "{:?} unreachable", b as char);
        }
    }

    #[test]
    fn function_page_has_f1_to_f12() {
        let labels: Vec<String> = page_rows(Page::Function, false)
            .into_iter()
            .flatten()
            .map(|k| k.label)
            .collect();
        for n in 1..=12 {
            assert!(labels.contains(&format!("F{n}")), "F{n}");
        }
    }

    #[test]
    fn short_landscape_fits_and_keeps_min_key_height() {
        let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(865.0, 411.0));
        let kh = key_height(screen);
        assert!(kh >= 30.0);
        let total = total_height(screen);
        assert!(total <= screen.height() * 0.5, "total {total}");
        let portrait = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(411.0, 865.0));
        assert!(total_height(portrait) <= portrait.height() * 0.5);
        let area = egui::Rect::from_min_size(egui::pos2(0.0, 0.0), egui::vec2(865.0, total));
        for page in [Page::Letters, Page::Symbols, Page::Function] {
            for (r, _) in layout_keys(&page_rows(page, false), area, kh) {
                assert!(r.min.x >= -0.01 && r.max.x <= 865.01, "{page:?} {r:?}");
                assert!(r.max.y <= total + 0.01);
            }
        }
    }

    fn two_keys() -> Vec<(egui::Rect, KeyDef)> {
        let a = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(100.0, 40.0));
        let b = egui::Rect::from_min_size(egui::pos2(110.0, 0.0), egui::vec2(100.0, 40.0));
        vec![
            (a, kd("Bksp", KeyAct::Key(Key::Backspace), 1.0)),
            (b, kd("a", KeyAct::Char('a'), 1.0)),
        ]
    }

    #[test]
    fn pointer_press_hold_and_slide_off() {
        let mut k = Keyboard::new();
        let keys = two_keys();
        let start = t0();
        let ms = Duration::from_millis;
        let mut out = KeyboardOutput::default();
        k.handle_pointer(&keys, pf(true, true, 10.0), R, start, &mut out);
        assert_eq!(out.strokes, vec![st(0x0E, false, true)]);
        let mut out = KeyboardOutput::default();
        k.handle_pointer(&keys, pf(false, true, 12.0), R, start + ms(400), &mut out);
        assert_eq!(out.strokes, vec![st(0x0E, false, true)]);
        // Slide onto the neighbour: Backspace released, 'a' not pressed.
        let mut out = KeyboardOutput::default();
        k.handle_pointer(&keys, pf(false, true, 150.0), R, start + ms(433), &mut out);
        assert_eq!(out.strokes, vec![st(0x0E, false, false)]);
        let mut out = KeyboardOutput::default();
        k.handle_pointer(&keys, pf(false, true, 150.0), R, start + ms(900), &mut out);
        assert!(out.is_empty());
        // Fast tap: pressed and already up in the same frame.
        let mut out = KeyboardOutput::default();
        k.handle_pointer(&keys, pf(true, false, 150.0), R, start + ms(1000), &mut out);
        assert_eq!(
            out.strokes,
            vec![st(0x1E, false, true), st(0x1E, false, false)]
        );
        assert!(!k.core.anything_held());
    }

    #[test]
    fn pointer_lift_releases() {
        let mut k = Keyboard::new();
        let keys = two_keys();
        let mut out = KeyboardOutput::default();
        k.handle_pointer(&keys, pf(true, true, 150.0), R, t0(), &mut out);
        let mut out = KeyboardOutput::default();
        let up = PointerFrame {
            pressed: false,
            down: false,
            pos: None,
        };
        k.handle_pointer(&keys, up, R, t0(), &mut out);
        assert_eq!(out.strokes, vec![st(0x1E, false, false)]);
    }

    #[test]
    fn page_switch_key_changes_page() {
        let mut k = Keyboard::new();
        let a = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(100.0, 40.0));
        let keys = vec![(a, kd("#+=", KeyAct::Page(Page::Symbols), 1.0))];
        let mut out = KeyboardOutput::default();
        k.handle_pointer(&keys, pf(true, true, 5.0), R, t0(), &mut out);
        assert_eq!(k.page(), Page::Symbols);
        assert!(out.is_empty());
    }
}
