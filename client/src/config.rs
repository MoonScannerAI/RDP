//! Client-side persisted settings: `%APPDATA%\DirectDesk\client.json`.
//!
//! SECURITY: this file holds **no secrets**. Pairing codes, long-term keys and
//! any other credential material live in the crypto store, never here. Keep it
//! that way — this file is world-readable by anything running as the user.

use std::path::PathBuf;

use directdesk_shared::protocol::{
    MonitorInfo, QualityMode, DEFAULT_UDP_PORT, MAX_MONITORS, MAX_TARGET_FPS, MIN_TARGET_FPS,
};
use serde::{Deserialize, Serialize};

use crate::monitors::MonitorChoice;

/// Cap on a cached [`MonitorInfo::name`] in `sanitized()`. Matches the cap the
/// host itself applies when it enumerates (see the field's own docs on
/// `MonitorInfo`) — this is a defensive re-clamp for a hand-edited config
/// file, not a new limit.
const MAX_CACHED_MONITOR_NAME_BYTES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClientConfig {
    /// Last host address typed by the user (hostname or IP, no port).
    pub host_address: String,
    pub udp_port: u16,
    /// Friendly name this client presents to the host. Empty means "derive one
    /// from the machine name"; never holds a secret.
    #[serde(default)]
    pub display_name: String,
    pub quality_mode: QualityMode,
    pub show_diagnostics: bool,
    pub start_fullscreen: bool,
    /// Keep forwarding the keyboard to the host while DirectDesk is in the
    /// background. Default **false**: with it off, alt-tabbing to a local app
    /// types into that local app, so a password typed into a local window is
    /// never shipped over the wire by accident. Turning it on is an explicit,
    /// informed choice (the toolbar toggle spells out the consequence).
    pub capture_in_background: bool,
    /// Client-requested frame rate ceiling. `0` means "Auto — follow whatever
    /// the host is already running at". The host only ever lowers its rate to
    /// match this (never raises it), so `0` reproduces today's behaviour
    /// exactly — an old config that has never heard of this field must not
    /// silently change the frame rate.
    pub preferred_fps: u32,
    /// Snap the window to a fixed integer scale with the host desktop as soon
    /// as its video format is learned, so text renders pixel-exact instead of
    /// being scaled. `0` = off, `1` = snap to 1:1, `2` = snap to 2x. Default
    /// **0 (off)**: auto-resizing a user's window without being asked is a
    /// bigger surprise than leaving them at a fractional scale.
    ///
    /// Superseded `auto_snap_1to1: bool`, which is no longer written but is
    /// still read for one-time migration in `sanitized()` below: a config
    /// saved by an older build with `auto_snap_1to1: true` and no
    /// `auto_snap_scale` field must keep behaving like "snap to 1:1", not
    /// silently revert to off.
    #[serde(default)]
    pub auto_snap_scale: u32,
    /// Deprecated, kept only so old config files still parse and migrate (see
    /// `sanitized()`). No longer read anywhere else and never written by this
    /// build — `auto_snap_scale` is the source of truth going forward.
    #[serde(default)]
    auto_snap_1to1: bool,
    /// Which outputs the operator asked for. Default `Primary` — a config
    /// written before multi-monitor existed must keep behaving exactly like
    /// today's single-stream client.
    #[serde(default)]
    pub monitor_choice: MonitorChoice,
    /// Host address the fields below were cached from. Only a label aid for
    /// the connect-screen picker — never compared for anything but an exact
    /// match against the host currently typed into the form. Empty means "no
    /// cache", and `sanitized()` enforces that `cached_monitors` is empty
    /// whenever this is.
    #[serde(default)]
    pub cached_monitor_host: String,
    /// The last `MonitorList` seen from `cached_monitor_host`, so the picker
    /// can show real dimensions/names before the next connect even starts.
    /// Display only — never parsed, never used to address a monitor; see
    /// `MonitorInfo::name`'s own docs for why the wire type already treats it
    /// that way.
    #[serde(default)]
    pub cached_monitors: Vec<MonitorInfo>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            host_address: String::new(),
            udp_port: DEFAULT_UDP_PORT,
            display_name: String::new(),
            // This is a remote *desktop*, so text is the primary workload. TextDesktop now carries
            // the highest bitrate ceiling because sharp glyph edges are high-frequency detail and
            // a low ceiling destroys them. Balanced caps at 15000 kbps, TextDesktop at 28000.
            quality_mode: QualityMode::TextDesktop,
            show_diagnostics: false,
            start_fullscreen: false,
            capture_in_background: false,
            preferred_fps: 0,
            auto_snap_scale: 0,
            auto_snap_1to1: false,
            monitor_choice: MonitorChoice::default(),
            cached_monitor_host: String::new(),
            cached_monitors: Vec::new(),
        }
    }
}

/// `%APPDATA%\DirectDesk\client.json` (roaming), or `None` if the OS has no
/// config directory for us.
pub fn config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("DirectDesk").join("client.json"))
}

impl ClientConfig {
    /// Never fails: a missing or corrupt file yields defaults (and a log line).
    pub fn load() -> Self {
        let Some(path) = config_path() else {
            return Self::default();
        };
        match std::fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str::<ClientConfig>(&text) {
                Ok(cfg) => {
                    tracing::debug!(path = %path.display(), "loaded client config");
                    cfg.sanitized()
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), "config unreadable ({e}); using defaults");
                    Self::default()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(e) => {
                tracing::warn!(path = %path.display(), "config read failed ({e}); using defaults");
                Self::default()
            }
        }
    }

    pub fn save(&self) {
        let Some(path) = config_path() else { return };
        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                tracing::warn!(path = %parent.display(), "cannot create config dir: {e}");
                return;
            }
        }
        match serde_json::to_string_pretty(self) {
            Ok(text) => {
                if let Err(e) = std::fs::write(&path, text) {
                    tracing::warn!(path = %path.display(), "config write failed: {e}");
                }
            }
            Err(e) => tracing::warn!("config serialize failed: {e}"),
        }
    }

    /// Clamp anything a hand-edited file could have broken.
    fn sanitized(mut self) -> Self {
        if self.udp_port == 0 {
            self.udp_port = DEFAULT_UDP_PORT;
        }
        self.host_address.truncate(255);
        // 0 is the sentinel for "Auto" and must pass through untouched; any
        // other hand-edited value gets pulled into a sane range.
        if self.preferred_fps != 0 {
            self.preferred_fps = self.preferred_fps.clamp(MIN_TARGET_FPS, MAX_TARGET_FPS);
        }
        // One-time migration: a config written before integer scales existed
        // has `auto_snap_1to1: true` and no opinion on `auto_snap_scale` (it
        // deserializes to the field default, 0). Carry the old preference
        // forward as "snap to 1:1" rather than silently turning auto-snap
        // off. A config that already has a nonzero `auto_snap_scale` (this
        // build or a newer one) is left alone — that field is now the source
        // of truth.
        if self.auto_snap_scale == 0 && self.auto_snap_1to1 {
            self.auto_snap_scale = 1;
        }
        // Never offer a scale this build doesn't know how to snap to (a
        // hand-edited or future-written file could set anything).
        if self.auto_snap_scale > 3 {
            self.auto_snap_scale = 0;
        }
        // The cache is only meaningful tied to a host; an empty host with a
        // non-empty list is not a state this build ever writes, but a
        // hand-edited file could claim it — treat it as no cache at all.
        if self.cached_monitor_host.is_empty() {
            self.cached_monitors.clear();
        }
        // A peer-declared count is never trusted verbatim even after landing
        // in a config file: cap it at the same MAX_MONITORS the wire itself
        // enforces (see `MonitorInfo`'s docs) rather than a fresh number.
        if self.cached_monitors.len() > MAX_MONITORS {
            self.cached_monitors.truncate(MAX_MONITORS);
        }
        for m in &mut self.cached_monitors {
            truncate_str_bytes(&mut m.name, MAX_CACHED_MONITOR_NAME_BYTES);
        }
        self
    }
}

/// Truncate `s` to at most `max_bytes` bytes, backing off to the nearest
/// earlier char boundary so this never panics or splits a multi-byte
/// character (unlike `String::truncate`, which requires the caller to
/// already know the string is ASCII at that offset).
fn truncate_str_bytes(s: &mut String, max_bytes: usize) {
    if s.len() <= max_bytes {
        return;
    }
    let mut cut = max_bytes;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    s.truncate(cut);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_use_contract_ports() {
        let c = ClientConfig::default();
        assert_eq!(c.udp_port, DEFAULT_UDP_PORT);
        assert_eq!(c.udp_port, 47990);
    }

    #[test]
    fn roundtrips_through_json() {
        let c = ClientConfig {
            host_address: "10.0.0.5".into(),
            quality_mode: QualityMode::Motion,
            ..Default::default()
        };
        let text = serde_json::to_string(&c).unwrap();
        let back: ClientConfig = serde_json::from_str(&text).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn partial_json_falls_back_to_defaults() {
        // `#[serde(default)]` must tolerate an older/newer file shape.
        let back: ClientConfig = serde_json::from_str(r#"{"host_address":"pc.lan"}"#).unwrap();
        assert_eq!(back.host_address, "pc.lan");
        assert_eq!(back.udp_port, DEFAULT_UDP_PORT);
        // A config written before background capture existed must not silently
        // opt the user into shipping their local keystrokes to the host.
        assert!(!back.capture_in_background);
        // Same for fps: a config written before this field existed must mean
        // "Auto", never a silent frame-rate change.
        assert_eq!(back.preferred_fps, 0);
        // A config written before integer-scale snapping existed must not
        // silently turn it on.
        assert_eq!(back.auto_snap_scale, 0);
        // A config written before multi-monitor existed must keep behaving
        // like today's single-stream client: Primary, no cache.
        assert_eq!(back.monitor_choice, MonitorChoice::Primary);
        assert_eq!(back.cached_monitor_host, "");
        assert!(back.cached_monitors.is_empty());
    }

    #[test]
    fn old_auto_snap_1to1_true_migrates_to_scale_one() {
        // A config saved by the pre-integer-scale build: `auto_snap_1to1:
        // true`, no `auto_snap_scale` field at all. Losing that preference on
        // upgrade would be exactly the kind of silent behaviour change this
        // field exists to avoid. The migration lives in `sanitized()`, which
        // `load()` always runs — mirror that here rather than asserting on
        // the raw deserialize.
        let back: ClientConfig =
            serde_json::from_str(r#"{"host_address":"pc.lan","auto_snap_1to1":true}"#).unwrap();
        assert_eq!(back.sanitized().auto_snap_scale, 1);
    }

    #[test]
    fn explicit_auto_snap_scale_wins_over_the_old_flag() {
        // A newer file that already set `auto_snap_scale` (even alongside a
        // stale `auto_snap_1to1`) must not be overridden by the migration.
        let back: ClientConfig = serde_json::from_str(
            r#"{"host_address":"pc.lan","auto_snap_1to1":true,"auto_snap_scale":2}"#,
        )
        .unwrap();
        assert_eq!(back.sanitized().auto_snap_scale, 2);
    }

    #[test]
    fn auto_snap_scale_above_three_is_reset_to_off() {
        let c = ClientConfig {
            auto_snap_scale: 9,
            ..Default::default()
        }
        .sanitized();
        assert_eq!(c.auto_snap_scale, 0);
    }

    #[test]
    fn orphan_monitor_cache_is_cleared_when_the_host_is_empty() {
        // A hand-edited (or otherwise inconsistent) file could carry a
        // non-empty cache with no host to anchor it to; sanitized() must
        // drop the cache rather than let the picker attribute it to
        // whatever host the operator later types in.
        let c = ClientConfig {
            cached_monitor_host: String::new(),
            cached_monitors: vec![MonitorInfo {
                id: 0,
                width: 1920,
                height: 1080,
                origin_x: 0,
                origin_y: 0,
                is_primary: true,
                name: "A".into(),
            }],
            ..Default::default()
        }
        .sanitized();
        assert!(c.cached_monitors.is_empty());
    }

    #[test]
    fn oversized_monitor_cache_is_truncated_to_max_monitors() {
        let cached_monitors = (0..(MAX_MONITORS as u8 + 5))
            .map(|id| MonitorInfo {
                id,
                width: 1920,
                height: 1080,
                origin_x: 0,
                origin_y: 0,
                is_primary: id == 0,
                name: "A".into(),
            })
            .collect();
        let c = ClientConfig {
            cached_monitor_host: "pc.lan".into(),
            cached_monitors,
            ..Default::default()
        }
        .sanitized();
        assert_eq!(c.cached_monitors.len(), MAX_MONITORS);
    }

    #[test]
    fn oversized_cached_monitor_name_is_truncated_at_a_char_boundary() {
        // A multi-byte character sitting right at the cut point must not
        // panic `String::truncate`; the helper backs off to the nearest
        // earlier boundary instead of splitting it.
        let long_name: String = "é".repeat(40); // 80 bytes, 40 chars
        let c = ClientConfig {
            cached_monitor_host: "pc.lan".into(),
            cached_monitors: vec![MonitorInfo {
                id: 0,
                width: 1920,
                height: 1080,
                origin_x: 0,
                origin_y: 0,
                is_primary: true,
                name: long_name,
            }],
            ..Default::default()
        }
        .sanitized();
        assert!(c.cached_monitors[0].name.len() <= MAX_CACHED_MONITOR_NAME_BYTES);
        assert!(c.cached_monitors[0]
            .name
            .is_char_boundary(c.cached_monitors[0].name.len()));
    }

    #[test]
    fn zero_ports_are_repaired() {
        let c = ClientConfig {
            udp_port: 0,
            ..Default::default()
        }
        .sanitized();
        assert_eq!(c.udp_port, DEFAULT_UDP_PORT);
    }

    #[test]
    fn preferred_fps_zero_means_auto_and_is_never_clamped() {
        let c = ClientConfig {
            preferred_fps: 0,
            ..Default::default()
        }
        .sanitized();
        assert_eq!(c.preferred_fps, 0);
    }

    #[test]
    fn preferred_fps_is_clamped_to_a_sane_range() {
        // The floor is MIN_TARGET_FPS (1), not the UI picker's floor (10): this
        // clamp only exists to keep a hand-edited config's arithmetic safe, so
        // a hand-edited 1..=4 (unreachable from the picker, which never offers
        // less than 10) passes through unclamped rather than being pulled up.
        let low = ClientConfig {
            preferred_fps: 1,
            ..Default::default()
        }
        .sanitized();
        assert_eq!(low.preferred_fps, 1);

        let high = ClientConfig {
            preferred_fps: 1_000,
            ..Default::default()
        }
        .sanitized();
        assert_eq!(high.preferred_fps, 240);
    }

    #[test]
    fn old_config_with_tcp_port_still_loads() {
        // A pre-removal client.json on a real machine has a `tcp_port` key that
        // no field claims anymore. Struct-level `#[serde(default)]` with no
        // `deny_unknown_fields` means serde_json silently ignores unknown keys
        // rather than failing the whole parse — verify the entire rest of a
        // realistic file still deserializes and survives sanitizing intact.
        let json = r#"{
            "host_address": "10.0.0.5",
            "udp_port": 47990,
            "tcp_port": 47991,
            "display_name": "my-laptop",
            "quality_mode": "Balanced",
            "show_diagnostics": true,
            "start_fullscreen": false,
            "capture_in_background": true,
            "preferred_fps": 30,
            "auto_snap_scale": 2
        }"#;
        let back: ClientConfig = serde_json::from_str(json).unwrap();
        let c = back.sanitized();
        assert_eq!(c.host_address, "10.0.0.5");
        assert_eq!(c.udp_port, 47990);
        assert_eq!(c.display_name, "my-laptop");
        assert_eq!(c.quality_mode, QualityMode::Balanced);
        assert!(c.show_diagnostics);
        assert!(!c.start_fullscreen);
        assert!(c.capture_in_background);
        assert_eq!(c.preferred_fps, 30);
        assert_eq!(c.auto_snap_scale, 2);
        // Nothing in this file has ever heard of multi-monitor either.
        assert_eq!(c.monitor_choice, MonitorChoice::Primary);
        assert!(c.cached_monitors.is_empty());
    }
}
