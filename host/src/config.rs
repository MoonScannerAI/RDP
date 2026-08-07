//! Host-side persisted settings: `%ProgramData%\DirectDesk\host.json`.
//!
//! SECURITY: this file holds **no secrets**. The host's Ed25519 identity, its
//! TLS key and the trusted-client list live in the DPAPI store
//! ([`directdesk_shared::crypto::storage::DpapiFileStore::host`]), which writes
//! into the same directory but as encrypted `*.dpapi` blobs. Anything added
//! here is readable by every local user — keep it that way.
//!
//! Loading is deliberately forgiving: a missing file yields defaults and is
//! written back, and a corrupt or partial file yields defaults with a warning
//! rather than refusing to start. A remote-access host that will not launch
//! because someone hand-edited a JSON file is worse than one that launches with
//! documented defaults.

use std::path::PathBuf;

use directdesk_shared::protocol::{QualityMode, DEFAULT_TCP_PORT, DEFAULT_UDP_PORT};
use serde::{Deserialize, Serialize};

/// Directory under `%ProgramData%` shared with the DPAPI secret store.
pub const APP_DIR: &str = "DirectDesk";
/// File name inside [`APP_DIR`].
pub const CONFIG_FILE: &str = "host.json";

/// Lowest bitrate the UI will let a user pin the encoder to.
pub const MIN_BITRATE_KBPS: u32 = 300;
/// Highest bitrate the UI will let a user pin the encoder to.
pub const MAX_BITRATE_KBPS: u32 = 60_000;

/// Lowest frame rate a *config file* may express. Deliberately 1, not the UI's
/// user-facing floor of 10: this bound only exists to keep a hand-edited `0`
/// from reaching a divisor. The floor a person can actually pick is a UI
/// concern and lives in the settings panel.
pub const MIN_TARGET_FPS: u32 = 1;
/// Highest frame rate the encoder is ever asked for.
pub const MAX_TARGET_FPS: u32 = 240;

/// Bounds for the lossless-tile knobs (see the fields on [`HostConfig`]).
///
/// The settle floor is deliberately above `STATIC_SETTLE_MS` (700): the H.264
/// settle keyframe should land *first*, so tiles refine on top of an already
/// decent picture rather than racing it and spending bandwidth twice on the
/// same region.
pub const MIN_TILE_SETTLE_MS: u32 = 750;
pub const MAX_TILE_SETTLE_MS: u32 = 10_000;
/// A lease shorter than a couple of settle periods would expire tiles faster
/// than they can be renewed, so the picture would visibly flicker between
/// refined and H.264.
pub const MIN_TILE_LEASE_MS: u32 = 1_500;
pub const MAX_TILE_LEASE_MS: u32 = 30_000;
/// deflate levels are 1..=9; 6 is the usual quality/CPU knee.
pub const MIN_TILE_DEFLATE_LEVEL: u32 = 1;
pub const MAX_TILE_DEFLATE_LEVEL: u32 = 9;
/// Strips compressed per refinement pass. The pass runs on idle frames inside
/// the existing frame-budget slack, so this bounds how much of that slack it
/// may take before yielding back to capture.
pub const MIN_TILES_PER_PASS: u32 = 1;
pub const MAX_TILES_PER_PASS: u32 = 512;
/// Hard ceiling on tile bandwidth. The real limiter is the dynamic budget
/// computed in `status_loop` from the adaptor's spare headroom; this is only a
/// backstop so a misconfiguration cannot starve the video it is meant to
/// improve.
pub const MAX_TILE_KBPS: u32 = 40_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HostConfig {
    /// Master switch. `false` means the QUIC listener is never opened — no
    /// hidden mode: the tray icon then reports "remote access off".
    pub remote_access_enabled: bool,
    /// UDP port for QUIC.
    pub udp_port: u16,
    /// TCP port reserved for the fallback transport (not opened by this build).
    pub tcp_port: u16,
    /// Friendly name sent to clients in `PairComplete` and shown in their UI.
    /// Only used the first time an identity is created; afterwards the stored
    /// identity keeps the name it was paired under.
    pub display_name: String,
    /// Default quality mode for a new session.
    pub quality_mode: QualityMode,
    /// Encoder frame-rate ceiling.
    pub target_fps: u32,
    /// Encoder starting bitrate.
    pub bitrate_kbps: u32,
    /// Hard ceiling the adaptive controller may never exceed. `None` = no cap.
    pub bitrate_cap_kbps: Option<u32>,
    /// Seconds between forced IDR frames.
    pub gop_seconds: u32,
    /// Re-send the last image after this long with no desktop change (ms).
    /// `0` disables the keepalive entirely. See the migration in [`sanitized`]:
    /// the old `33` default is healed on load.
    ///
    /// [`sanitized`]: HostConfig::sanitized
    pub idle_repeat_ms: u32,
    /// How long (ms) the desktop must sit unchanged before the encoder is
    /// given one settle keyframe. `0` disables it. Without this, a still
    /// screen keeps whatever quality the one frame that drew it happened to
    /// achieve forever — a repeated frame is just an all-skip P-frame
    /// reproducing the same picture, so nothing ever re-encodes it sharper.
    /// One refresh after things settle is what lets static text sharpen.
    pub static_settle_ms: u32,
    /// Quality (`AVEncCommonQuality`, 0..=100) the settle keyframe is encoded
    /// at, in constant-quality mode rather than at the streaming bitrate. `0`
    /// disables the refinement; the settle keyframe is then still sent, just
    /// inside the ordinary rate-control budget, which on a detailed 1080p
    /// screen is what left static text soft in the first place.
    ///
    /// Clamped by [`sanitized`] into
    /// `[MIN_STATIC_REFINE_QUALITY, MAX_STATIC_REFINE_QUALITY]` — the upper
    /// bound matters: the frame must stay small enough to fragment.
    ///
    /// [`sanitized`]: HostConfig::sanitized
    pub static_refine_quality: u32,
    /// Opt-in: once a region of the desktop stops changing, re-send it
    /// **losslessly** on a reliable side stream and composite it over the H.264
    /// video, so static text converges to pixel-exact instead of staying at the
    /// motion quantiser.
    ///
    /// Default `false` for the first installs. The host is remote, so the
    /// staged rollout ships the code first and turns it on separately — a
    /// binary that is byte-identical on the wire is a safe deploy, and a
    /// config flip is trivially reversible where a bad binary is not. It only
    /// ever activates when the client also advertises
    /// [`features::LOSSLESS_TILES`], so an old client sees nothing regardless.
    ///
    /// [`features::LOSSLESS_TILES`]: directdesk_shared::protocol::features::LOSSLESS_TILES
    pub lossless_tiles_enabled: bool,
    /// How long (ms) a tile must sit unchanged before it is refined. Clamped
    /// into `[MIN_TILE_SETTLE_MS, MAX_TILE_SETTLE_MS]`.
    pub lossless_tile_settle_ms: u32,
    /// Backstop ceiling (kbps) on tile traffic. `0` means "no explicit cap,
    /// use only the dynamic budget".
    pub lossless_tile_max_kbps: u32,
    /// deflate level for tile payloads. Clamped to `1..=9`.
    pub lossless_tile_deflate_level: u32,
    /// How long (ms) a refined tile stays paintable without renewal.
    ///
    /// This is the fail-safe that bounds every failure the stream's own
    /// ordering cannot cover — pump aborted, connection lost, host crashed, a
    /// `Revoke` never delivered. No failure mode may show stale pixels for
    /// longer than one lease, which is worth more than any bandwidth saving.
    pub lossless_tile_lease_ms: u32,
    /// Strips compressed per refinement pass. Clamped into
    /// `[MIN_TILES_PER_PASS, MAX_TILES_PER_PASS]`.
    pub lossless_tiles_per_pass: u32,
    /// Start with the window hidden in the tray. `--minimized` also sets this
    /// for one run without persisting it.
    pub start_minimized: bool,
    /// Opt-in: allow the operator to route input to a transient SYSTEM-integrity
    /// worker so a client can click through a UAC/elevation consent dialog that
    /// the medium-integrity host cannot reach via UIPI. Default `false` — this
    /// is a privileged, security-sensitive path and must be turned on explicitly.
    pub uac_clickthrough: bool,
    /// How long (seconds) a single elevation arming stays valid before it
    /// self-expires and the SYSTEM worker is torn down. Kept short on purpose.
    pub uac_arm_ttl_secs: u32,
    /// RDP-style bandwidth saver: blank the host's desktop to solid black
    /// while a remote session is active, and restore the exact previous
    /// wallpaper/background color when it ends. A detailed photo wallpaper
    /// makes every keyframe large and every mouse/window move over it
    /// expensive to encode; a flat black desktop makes keyframes tiny and
    /// deltas near-zero. Default `true` — most users would rather have the
    /// bandwidth than see their wallpaper during a remote session.
    pub blank_wallpaper_during_session: bool,
}

/// Lower/upper bounds for [`HostConfig::uac_arm_ttl_secs`].
pub const MIN_UAC_ARM_TTL_SECS: u32 = 5;
pub const MAX_UAC_ARM_TTL_SECS: u32 = 120;

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            remote_access_enabled: true,
            udp_port: DEFAULT_UDP_PORT,
            tcp_port: DEFAULT_TCP_PORT,
            display_name: default_display_name(),
            quality_mode: QualityMode::Balanced,
            target_fps: 60,
            bitrate_kbps: 12_000,
            bitrate_cap_kbps: None,
            gop_seconds: 4,
            idle_repeat_ms: 250,
            static_settle_ms: crate::session::STATIC_SETTLE_MS,
            static_refine_quality: crate::mf_encoder::DEFAULT_STATIC_REFINE_QUALITY,
            // Off by default: step 1 of the rollout ships this code inert.
            lossless_tiles_enabled: false,
            lossless_tile_settle_ms: 900,
            lossless_tile_max_kbps: 8_000,
            lossless_tile_deflate_level: 6,
            lossless_tile_lease_ms: 4_000,
            lossless_tiles_per_pass: 32,
            start_minimized: false,
            uac_clickthrough: false,
            uac_arm_ttl_secs: 20,
            blank_wallpaper_during_session: true,
        }
    }
}

/// This machine's name, trimmed to what [`validate_name`] accepts.
///
/// [`validate_name`]: directdesk_shared::crypto::identity::validate_name
pub fn default_display_name() -> String {
    let raw = std::env::var("COMPUTERNAME")
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_default();
    sanitize_name(&raw).unwrap_or_else(|| "DirectDesk host".to_string())
}

/// Make an arbitrary string safe to use as a DirectDesk friendly name, or
/// `None` if nothing usable survives.
///
/// Names cross the wire (`PairComplete`, and the label a paired client is
/// stored under), so control characters are stripped and the length is capped
/// at the shared crate's limit rather than trusted.
pub fn sanitize_name(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .to_string();
    if cleaned.is_empty() {
        return None;
    }
    let limit = directdesk_shared::crypto::identity::MAX_NAME_LEN;
    let mut out = String::with_capacity(limit.min(cleaned.len()));
    for c in cleaned.chars() {
        if out.len() + c.len_utf8() > limit {
            break;
        }
        out.push(c);
    }
    let out = out.trim_end().to_string();
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// `%ProgramData%\DirectDesk` — the same directory the DPAPI store uses.
pub fn config_dir() -> Option<PathBuf> {
    std::env::var_os("ProgramData").map(|base| PathBuf::from(base).join(APP_DIR))
}

/// `%ProgramData%\DirectDesk\host.json`.
pub fn config_path() -> Option<PathBuf> {
    config_dir().map(|d| d.join(CONFIG_FILE))
}

impl HostConfig {
    /// Load the config, creating it with defaults if it is missing.
    ///
    /// Never fails: every error path falls back to defaults and logs.
    pub fn load_or_create() -> Self {
        let Some(path) = config_path() else {
            tracing::warn!("ProgramData is not set; using in-memory host defaults");
            return Self::default();
        };
        match std::fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str::<HostConfig>(&text) {
                Ok(cfg) => {
                    tracing::info!(path = %path.display(), "loaded host config");
                    cfg.sanitized()
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), "host config unreadable ({e}); using defaults");
                    Self::default()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let cfg = Self::default();
                cfg.save();
                tracing::info!(path = %path.display(), "created host config with defaults");
                cfg
            }
            Err(e) => {
                tracing::warn!(path = %path.display(), "host config read failed ({e}); using defaults");
                Self::default()
            }
        }
    }

    /// Persist. Failures are logged, never fatal — a read-only ProgramData must
    /// not stop the host from serving.
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
                    tracing::warn!(path = %path.display(), "host config write failed: {e}");
                }
            }
            Err(e) => tracing::warn!("host config serialize failed: {e}"),
        }
    }

    /// Clamp everything a hand-edited file could have broken.
    pub fn sanitized(mut self) -> Self {
        if self.udp_port == 0 {
            self.udp_port = DEFAULT_UDP_PORT;
        }
        if self.tcp_port == 0 {
            self.tcp_port = DEFAULT_TCP_PORT;
        }
        self.target_fps = self.target_fps.clamp(MIN_TARGET_FPS, MAX_TARGET_FPS);
        self.gop_seconds = self.gop_seconds.clamp(1, 30);
        // Migration: 33 ms was the old default — ~30 identical full frames a
        // second on a still desktop. Every host that ever started once has it
        // persisted, so the fix would never reach them without healing it here.
        // The cost is that a *deliberate* 33 is no longer expressible; nothing
        // offers it and 30/s of identical frames is not what anyone meant.
        if self.idle_repeat_ms == 33 {
            self.idle_repeat_ms = 250;
        }
        self.idle_repeat_ms = self.idle_repeat_ms.min(5_000);
        // 0 stays 0 (disabled); anything larger is capped at a few seconds so a
        // hand-edited value can't leave static text unsharpened indefinitely.
        self.static_settle_ms = self.static_settle_ms.min(5_000);
        // 0 stays 0 (refinement off). Anything else is clamped into the band
        // the encoder will honour: too low is a pointless extra IDR, too high
        // is a frame the fragmenter would refuse — and a refused keyframe is a
        // frozen picture, not a dropped frame.
        if self.static_refine_quality != 0 {
            self.static_refine_quality = self.static_refine_quality.clamp(
                crate::mf_encoder::MIN_STATIC_REFINE_QUALITY,
                crate::mf_encoder::MAX_STATIC_REFINE_QUALITY,
            );
        }
        self.bitrate_kbps = self.bitrate_kbps.clamp(MIN_BITRATE_KBPS, MAX_BITRATE_KBPS);
        self.bitrate_cap_kbps = self
            .bitrate_cap_kbps
            .map(|c| c.clamp(MIN_BITRATE_KBPS, MAX_BITRATE_KBPS));
        self.display_name = sanitize_name(&self.display_name).unwrap_or_else(default_display_name);
        self.uac_arm_ttl_secs = self
            .uac_arm_ttl_secs
            .clamp(MIN_UAC_ARM_TTL_SECS, MAX_UAC_ARM_TTL_SECS);
        self.lossless_tile_settle_ms = self
            .lossless_tile_settle_ms
            .clamp(MIN_TILE_SETTLE_MS, MAX_TILE_SETTLE_MS);
        self.lossless_tile_lease_ms = self
            .lossless_tile_lease_ms
            .clamp(MIN_TILE_LEASE_MS, MAX_TILE_LEASE_MS);
        self.lossless_tile_deflate_level = self
            .lossless_tile_deflate_level
            .clamp(MIN_TILE_DEFLATE_LEVEL, MAX_TILE_DEFLATE_LEVEL);
        self.lossless_tiles_per_pass = self
            .lossless_tiles_per_pass
            .clamp(MIN_TILES_PER_PASS, MAX_TILES_PER_PASS);
        // 0 stays 0 (no explicit cap — the dynamic budget is the real limiter),
        // matching the `static_refine_quality` idiom above.
        if self.lossless_tile_max_kbps != 0 {
            self.lossless_tile_max_kbps = self.lossless_tile_max_kbps.min(MAX_TILE_KBPS);
        }
        // A lease must outlast the settle it is granted against, or a tile can
        // expire before the next pass could possibly renew it and the region
        // flickers between refined and H.264.
        if self.lossless_tile_lease_ms < self.lossless_tile_settle_ms.saturating_mul(2) {
            self.lossless_tile_lease_ms = self
                .lossless_tile_settle_ms
                .saturating_mul(2)
                .min(MAX_TILE_LEASE_MS);
        }
        self
    }

    /// The pipeline configuration implied by these settings.
    pub fn pipeline(&self) -> crate::session::SessionConfig {
        crate::session::SessionConfig {
            target_fps: self.target_fps,
            bitrate_kbps: self.bitrate_kbps,
            gop_seconds: self.gop_seconds,
            idle_repeat_ms: self.idle_repeat_ms,
            force_cpu_convert: false,
            frame_queue_depth: 8,
            static_settle_ms: self.static_settle_ms,
            static_refine_quality: self.static_refine_quality,
            lossless_tiles_enabled: self.lossless_tiles_enabled,
            lossless_tile_settle_ms: self.lossless_tile_settle_ms,
            lossless_tile_deflate_level: self.lossless_tile_deflate_level,
            lossless_tile_lease_ms: self.lossless_tile_lease_ms,
            lossless_tiles_per_pass: self.lossless_tiles_per_pass,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_use_contract_ports() {
        let c = HostConfig::default();
        assert_eq!(c.udp_port, DEFAULT_UDP_PORT);
        assert_eq!(c.udp_port, 47990);
        assert_eq!(c.tcp_port, 47991);
        assert!(c.remote_access_enabled);
    }

    #[test]
    fn roundtrips_through_json() {
        let c = HostConfig {
            display_name: "workstation".into(),
            quality_mode: QualityMode::Motion,
            bitrate_cap_kbps: Some(6_000),
            start_minimized: true,
            ..Default::default()
        };
        let text = serde_json::to_string(&c).unwrap();
        let back: HostConfig = serde_json::from_str(&text).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn partial_json_falls_back_to_defaults() {
        let back: HostConfig = serde_json::from_str(r#"{"udp_port":50000}"#).unwrap();
        assert_eq!(back.udp_port, 50_000);
        assert_eq!(back.tcp_port, DEFAULT_TCP_PORT);
        assert!(back.remote_access_enabled);
        assert_eq!(back.target_fps, 60);
    }

    #[test]
    fn unknown_keys_are_tolerated() {
        // A newer build's config must not brick an older one.
        let back: HostConfig =
            serde_json::from_str(r#"{"udp_port":47990,"future_option":true}"#).unwrap();
        assert_eq!(back.udp_port, 47990);
    }

    #[test]
    fn sanitize_repairs_nonsense() {
        let c = HostConfig {
            udp_port: 0,
            tcp_port: 0,
            target_fps: 0,
            gop_seconds: 9_999,
            bitrate_kbps: 1,
            bitrate_cap_kbps: Some(u32::MAX),
            display_name: String::new(),
            static_settle_ms: 99_999,
            ..Default::default()
        }
        .sanitized();
        assert_eq!(c.udp_port, DEFAULT_UDP_PORT);
        assert_eq!(c.tcp_port, DEFAULT_TCP_PORT);
        assert_eq!(c.target_fps, 1);
        assert_eq!(c.gop_seconds, 30);
        assert_eq!(c.bitrate_kbps, MIN_BITRATE_KBPS);
        assert_eq!(c.bitrate_cap_kbps, Some(MAX_BITRATE_KBPS));
        assert!(!c.display_name.is_empty());
        assert_eq!(c.static_settle_ms, 5_000);
    }

    #[test]
    fn static_settle_ms_zero_stays_disabled() {
        // 0 means "no settle keyframe"; sanitizing must not resurrect it.
        let c = HostConfig {
            static_settle_ms: 0,
            ..Default::default()
        }
        .sanitized();
        assert_eq!(c.static_settle_ms, 0);
    }

    #[test]
    fn target_fps_is_clamped_to_the_ceiling() {
        let c = HostConfig {
            target_fps: 9_999,
            ..Default::default()
        }
        .sanitized();
        assert_eq!(c.target_fps, MAX_TARGET_FPS);
    }

    #[test]
    fn tile_knobs_are_clamped() {
        let c = HostConfig {
            lossless_tile_settle_ms: 1,
            lossless_tile_lease_ms: 1,
            lossless_tile_deflate_level: 99,
            lossless_tiles_per_pass: 0,
            lossless_tile_max_kbps: 999_999,
            ..Default::default()
        }
        .sanitized();
        assert_eq!(c.lossless_tile_settle_ms, MIN_TILE_SETTLE_MS);
        assert_eq!(c.lossless_tile_deflate_level, MAX_TILE_DEFLATE_LEVEL);
        assert_eq!(c.lossless_tiles_per_pass, MIN_TILES_PER_PASS);
        assert_eq!(c.lossless_tile_max_kbps, MAX_TILE_KBPS);
    }

    #[test]
    fn tile_lease_always_outlasts_two_settles() {
        // A lease shorter than the refresh cadence would expire tiles faster
        // than the pass can renew them, so a static screen would visibly
        // flicker between refined and H.264. The clamp must hold even when the
        // settle is pushed to its own ceiling.
        for settle in [MIN_TILE_SETTLE_MS, 900, 3_000, MAX_TILE_SETTLE_MS] {
            let c = HostConfig {
                lossless_tile_settle_ms: settle,
                lossless_tile_lease_ms: MIN_TILE_LEASE_MS,
                ..Default::default()
            }
            .sanitized();
            assert!(
                c.lossless_tile_lease_ms >= c.lossless_tile_settle_ms * 2
                    || c.lossless_tile_lease_ms == MAX_TILE_LEASE_MS,
                "settle {settle} left lease {} too short",
                c.lossless_tile_lease_ms
            );
        }
    }

    #[test]
    fn tiles_are_off_by_default() {
        // Rollout step 1 ships this code inert: the first remote install must
        // be byte-identical on the wire to what is already deployed.
        assert!(!HostConfig::default().sanitized().lossless_tiles_enabled);
    }

    #[test]
    fn name_sanitizing_matches_shared_validation() {
        use directdesk_shared::crypto::identity::{validate_name, MAX_NAME_LEN};
        assert_eq!(sanitize_name("  desk  ").as_deref(), Some("desk"));
        assert_eq!(sanitize_name("bad\nname").as_deref(), Some("badname"));
        assert_eq!(sanitize_name("   ").as_deref(), None);
        assert_eq!(sanitize_name("").as_deref(), None);

        let long = sanitize_name(&"x".repeat(MAX_NAME_LEN * 3)).unwrap();
        assert_eq!(long.len(), MAX_NAME_LEN);
        assert!(validate_name(&long).is_ok());
        assert!(validate_name(&sanitize_name("héllo wörld").unwrap()).is_ok());
        assert!(validate_name(&default_display_name()).is_ok());
    }

    #[test]
    fn uac_clickthrough_defaults_off() {
        let c = HostConfig::default();
        assert!(
            !c.uac_clickthrough,
            "the SYSTEM click-through path must be opt-in"
        );
        assert_eq!(c.uac_arm_ttl_secs, 20);
    }

    #[test]
    fn uac_fields_roundtrip_through_json() {
        let c = HostConfig {
            uac_clickthrough: true,
            uac_arm_ttl_secs: 30,
            ..Default::default()
        };
        let text = serde_json::to_string(&c).unwrap();
        let back: HostConfig = serde_json::from_str(&text).unwrap();
        assert!(back.uac_clickthrough);
        assert_eq!(back.uac_arm_ttl_secs, 30);
        assert_eq!(c, back);
    }

    #[test]
    fn uac_missing_keys_fall_back_to_safe_defaults() {
        // An older config file without the UAC keys must default to OFF.
        let back: HostConfig = serde_json::from_str(r#"{"udp_port":47990}"#).unwrap();
        assert!(!back.uac_clickthrough);
        assert_eq!(back.uac_arm_ttl_secs, 20);
    }

    #[test]
    fn uac_arm_ttl_is_clamped() {
        let lo = HostConfig {
            uac_arm_ttl_secs: 0,
            ..Default::default()
        }
        .sanitized();
        assert_eq!(lo.uac_arm_ttl_secs, MIN_UAC_ARM_TTL_SECS);
        let hi = HostConfig {
            uac_arm_ttl_secs: 9_999,
            ..Default::default()
        }
        .sanitized();
        assert_eq!(hi.uac_arm_ttl_secs, MAX_UAC_ARM_TTL_SECS);
    }

    #[test]
    fn idle_repeat_heals_the_old_default() {
        // A host that has run before has 33 persisted; the bandwidth fix has to
        // reach it on load, not only on a fresh install.
        let healed = HostConfig {
            idle_repeat_ms: 33,
            ..Default::default()
        }
        .sanitized();
        assert_eq!(healed.idle_repeat_ms, 250);
        assert_eq!(HostConfig::default().idle_repeat_ms, 250);

        // Any other value is the operator's, including 0 (keepalive off).
        for kept in [0u32, 100] {
            let c = HostConfig {
                idle_repeat_ms: kept,
                ..Default::default()
            }
            .sanitized();
            assert_eq!(c.idle_repeat_ms, kept);
        }
        // The clamp still applies on top of the migration.
        let clamped = HostConfig {
            idle_repeat_ms: 99_999,
            ..Default::default()
        }
        .sanitized();
        assert_eq!(clamped.idle_repeat_ms, 5_000);
    }

    #[test]
    fn blank_wallpaper_defaults_on_and_roundtrips_through_json() {
        // The user explicitly wants this on by default: a fresh install (or
        // an in-memory default) must blank the wallpaper during a session.
        let c = HostConfig::default();
        assert!(c.blank_wallpaper_during_session);

        let c = HostConfig {
            blank_wallpaper_during_session: false,
            ..Default::default()
        };
        let text = serde_json::to_string(&c).unwrap();
        let back: HostConfig = serde_json::from_str(&text).unwrap();
        assert!(!back.blank_wallpaper_during_session);
        assert_eq!(c, back);
    }

    #[test]
    fn blank_wallpaper_missing_key_defaults_true() {
        // An older config file predating this option must still get the
        // bandwidth saving, not silently lose it.
        let back: HostConfig = serde_json::from_str(r#"{"udp_port":47990}"#).unwrap();
        assert!(back.blank_wallpaper_during_session);
    }

    #[test]
    fn pipeline_config_follows_settings() {
        let c = HostConfig {
            target_fps: 30,
            bitrate_kbps: 4_000,
            static_settle_ms: 1_200,
            ..Default::default()
        };
        let p = c.pipeline();
        assert_eq!(p.target_fps, 30);
        assert_eq!(p.bitrate_kbps, 4_000);
        assert_eq!(p.static_settle_ms, 1_200);
        assert_eq!(
            p.static_refine_quality,
            crate::mf_encoder::DEFAULT_STATIC_REFINE_QUALITY
        );

        // The knob reaches the pipeline, including its "off" value.
        let off = HostConfig {
            static_refine_quality: 0,
            ..Default::default()
        };
        assert_eq!(off.pipeline().static_refine_quality, 0);
    }

    #[test]
    fn static_refine_quality_is_clamped_but_zero_stays_off() {
        use crate::mf_encoder::{MAX_STATIC_REFINE_QUALITY, MIN_STATIC_REFINE_QUALITY};
        let hi = HostConfig {
            static_refine_quality: 100,
            ..Default::default()
        }
        .sanitized();
        assert_eq!(hi.static_refine_quality, MAX_STATIC_REFINE_QUALITY);

        let lo = HostConfig {
            static_refine_quality: 3,
            ..Default::default()
        }
        .sanitized();
        assert_eq!(lo.static_refine_quality, MIN_STATIC_REFINE_QUALITY);

        // 0 means "disabled"; sanitizing must not resurrect it.
        let off = HostConfig {
            static_refine_quality: 0,
            ..Default::default()
        }
        .sanitized();
        assert_eq!(off.static_refine_quality, 0);

        // A value already in band is left alone.
        let mid = HostConfig {
            static_refine_quality: 70,
            ..Default::default()
        }
        .sanitized();
        assert_eq!(mid.static_refine_quality, 70);
    }

    #[test]
    fn static_refine_quality_missing_key_defaults_on() {
        // An older config file predating this option must get the refinement,
        // not silently miss it.
        let back: HostConfig = serde_json::from_str(r#"{"udp_port":47990}"#).unwrap();
        assert_eq!(
            back.static_refine_quality,
            crate::mf_encoder::DEFAULT_STATIC_REFINE_QUALITY
        );
        assert!(back.static_refine_quality > 0);
    }
}
