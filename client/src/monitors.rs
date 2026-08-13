//! Client-side monitor vocabulary: what the operator can ask for, and how a
//! host's [`MonitorInfo`] list resolves that request into stream ids.
//!
//! Pure module — no `egui`, no network. Everything here is unit-tested in
//! isolation; the wiring that actually reads a live `MonitorList` off the
//! wire is milestone C2.

use directdesk_shared::protocol::MonitorInfo;
use serde::{Deserialize, Serialize};

/// What the operator asked the connect screen for.
///
/// `Second` and `Both` are requests, not guarantees: a host with only one
/// output, or an old host that never sends a `MonitorList` at all, cannot
/// honour them, and [`resolve_selection`] reports that with `degraded`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum MonitorChoice {
    /// Stream only the primary output (today's behaviour). Old configs that
    /// have never heard of this field deserialize to this variant.
    #[default]
    Primary,
    /// Stream only the first secondary output, if the host has one.
    Second,
    /// Stream the primary and the first secondary in two windows.
    Both,
}

impl MonitorChoice {
    /// The one user-facing wording for each choice, mirroring
    /// [`directdesk_shared::protocol::QualityMode::label`]: host and client
    /// never need to invent their own copy of this text.
    pub const fn label(self) -> &'static str {
        match self {
            MonitorChoice::Primary => "Primary monitor",
            MonitorChoice::Second => "Second monitor",
            MonitorChoice::Both => "Both (two windows)",
        }
    }
}

/// Result of resolving a [`MonitorChoice`] against a host's monitor list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// Stream ids to select, in order — `ids[0]` rides stream 0, `ids[1]`
    /// (if present) rides stream 1. Mirrors `ControlMsg::SelectMonitors`.
    pub ids: Vec<u8>,
    /// `true` when the choice could not be honoured as asked (no second
    /// monitor, or the host reported nothing at all) and the caller fell
    /// back to the primary. The UI should show a note when this is set.
    pub degraded: bool,
}

/// Resolve `choice` against the host's advertised monitors.
///
/// `id`s are session-scoped (see [`MonitorInfo`]'s own docs): `0` is always
/// the primary output and `1` is the first secondary, ordered by
/// `(origin_y, origin_x)` — this function trusts that ordering rather than
/// re-deriving it, since the host is the one that assigns ids.
///
/// * `Primary` always resolves to `[0]`.
/// * `Second` resolves to `[1]` when some entry in `monitors` has `id == 1`;
///   otherwise `[0]`, degraded.
/// * `Both` resolves to `[0, 1]` under the same condition; otherwise `[0]`,
///   degraded.
/// * An empty `monitors` list degrades every choice to `[0]` — the host said
///   nothing useful, so there is nothing to trust beyond "assume a primary
///   exists".
pub fn resolve_selection(choice: MonitorChoice, monitors: &[MonitorInfo]) -> Resolved {
    if monitors.is_empty() {
        return Resolved {
            ids: vec![0],
            degraded: true,
        };
    }
    let has_second = monitors.iter().any(|m| m.id == 1);
    match choice {
        MonitorChoice::Primary => Resolved {
            ids: vec![0],
            degraded: false,
        },
        MonitorChoice::Second => {
            if has_second {
                Resolved {
                    ids: vec![1],
                    degraded: false,
                }
            } else {
                Resolved {
                    ids: vec![0],
                    degraded: true,
                }
            }
        }
        MonitorChoice::Both => {
            if has_second {
                Resolved {
                    ids: vec![0, 1],
                    degraded: false,
                }
            } else {
                Resolved {
                    ids: vec![0],
                    degraded: true,
                }
            }
        }
    }
}

/// Label for the connect-screen picker.
///
/// With no cache, or a cache for a different host than the one currently
/// typed into the form (`host_matches == false`), this is just
/// [`MonitorChoice::label`]. When the cache *does* match the host in the
/// form and holds more than one entry (i.e. the last connect to this host
/// actually saw a `MonitorList`), the label for `Second`/`Both` is enriched
/// with the cached secondary's dimensions and device name, e.g.
/// `Second monitor — 1920x1080 "DELL U2720Q"`. `Primary` is left plain: its
/// output is always on screen already, so the extra text would not help.
///
/// Never trusts `cached` for anything beyond display — same rule as the wire
/// type's own `name` field.
pub fn picker_label(choice: MonitorChoice, cached: &[MonitorInfo], host_matches: bool) -> String {
    if !host_matches || cached.len() < 2 {
        return choice.label().to_string();
    }
    let target_id = match choice {
        MonitorChoice::Primary => return choice.label().to_string(),
        MonitorChoice::Second | MonitorChoice::Both => 1,
    };
    match cached.iter().find(|m| m.id == target_id) {
        Some(m) => format!(
            "{} — {}x{} \"{}\"",
            choice.label(),
            m.width,
            m.height,
            m.name
        ),
        None => choice.label().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn monitor(id: u8, is_primary: bool, name: &str) -> MonitorInfo {
        MonitorInfo {
            id,
            width: 1920,
            height: 1080,
            origin_x: 0,
            origin_y: 0,
            is_primary,
            name: name.into(),
        }
    }

    #[test]
    fn default_choice_is_primary() {
        assert_eq!(MonitorChoice::default(), MonitorChoice::Primary);
    }

    #[test]
    fn labels_match_the_connect_screen_wording() {
        assert_eq!(MonitorChoice::Primary.label(), "Primary monitor");
        assert_eq!(MonitorChoice::Second.label(), "Second monitor");
        assert_eq!(MonitorChoice::Both.label(), "Both (two windows)");
    }

    #[test]
    fn primary_always_resolves_to_zero() {
        let monitors = [monitor(0, true, "A"), monitor(1, false, "B")];
        let got = resolve_selection(MonitorChoice::Primary, &monitors);
        assert_eq!(
            got,
            Resolved {
                ids: vec![0],
                degraded: false
            }
        );
    }

    #[test]
    fn second_resolves_to_one_when_present() {
        let monitors = [monitor(0, true, "A"), monitor(1, false, "B")];
        let got = resolve_selection(MonitorChoice::Second, &monitors);
        assert_eq!(
            got,
            Resolved {
                ids: vec![1],
                degraded: false
            }
        );
    }

    #[test]
    fn second_degrades_to_primary_when_host_has_only_one_monitor() {
        let monitors = [monitor(0, true, "A")];
        let got = resolve_selection(MonitorChoice::Second, &monitors);
        assert_eq!(
            got,
            Resolved {
                ids: vec![0],
                degraded: true
            }
        );
    }

    #[test]
    fn both_resolves_to_zero_and_one_when_present() {
        let monitors = [monitor(0, true, "A"), monitor(1, false, "B")];
        let got = resolve_selection(MonitorChoice::Both, &monitors);
        assert_eq!(
            got,
            Resolved {
                ids: vec![0, 1],
                degraded: false
            }
        );
    }

    #[test]
    fn both_degrades_to_primary_when_host_has_only_one_monitor() {
        let monitors = [monitor(0, true, "A")];
        let got = resolve_selection(MonitorChoice::Both, &monitors);
        assert_eq!(
            got,
            Resolved {
                ids: vec![0],
                degraded: true
            }
        );
    }

    #[test]
    fn empty_monitor_list_degrades_every_choice() {
        for choice in [
            MonitorChoice::Primary,
            MonitorChoice::Second,
            MonitorChoice::Both,
        ] {
            let got = resolve_selection(choice, &[]);
            assert_eq!(
                got,
                Resolved {
                    ids: vec![0],
                    degraded: true
                },
                "{choice:?} must degrade on an empty MonitorList"
            );
        }
    }

    #[test]
    fn three_or_more_monitors_still_picks_only_ids_zero_and_one() {
        // A third+ output exists but is simply not addressable by this
        // client's MAX_VIDEO_STREAMS=2 vocabulary; resolve_selection must
        // never reach for id 2.
        let monitors = [
            monitor(0, true, "A"),
            monitor(1, false, "B"),
            monitor(2, false, "C"),
        ];
        assert_eq!(
            resolve_selection(MonitorChoice::Second, &monitors),
            Resolved {
                ids: vec![1],
                degraded: false
            }
        );
        assert_eq!(
            resolve_selection(MonitorChoice::Both, &monitors),
            Resolved {
                ids: vec![0, 1],
                degraded: false
            }
        );
    }

    #[test]
    fn no_is_primary_set_is_handled_defensively() {
        // The wire type allows every entry to have is_primary == false (a
        // malformed or defensive host); resolve_selection never reads
        // is_primary at all, only id, so this must behave identically to the
        // well-formed case.
        let monitors = [monitor(0, false, "A"), monitor(1, false, "B")];
        assert_eq!(
            resolve_selection(MonitorChoice::Both, &monitors),
            Resolved {
                ids: vec![0, 1],
                degraded: false
            }
        );
    }

    #[test]
    fn picker_label_is_plain_without_a_matching_cache() {
        let cached = [monitor(0, true, "A"), monitor(1, false, "DELL U2720Q")];
        // Different host: never used even though the cache has entries.
        assert_eq!(
            picker_label(MonitorChoice::Second, &cached, false),
            "Second monitor"
        );
        // Matching host but fewer than 2 cached entries: nothing learned yet.
        assert_eq!(
            picker_label(MonitorChoice::Second, &cached[..1], true),
            "Second monitor"
        );
        // No cache at all.
        assert_eq!(
            picker_label(MonitorChoice::Both, &[], true),
            "Both (two windows)"
        );
    }

    #[test]
    fn picker_label_enriches_second_and_both_for_a_matching_host() {
        let cached = [monitor(0, true, "A"), monitor(1, false, "DELL U2720Q")];
        assert_eq!(
            picker_label(MonitorChoice::Second, &cached, true),
            "Second monitor — 1920x1080 \"DELL U2720Q\""
        );
        assert_eq!(
            picker_label(MonitorChoice::Both, &cached, true),
            "Both (two windows) — 1920x1080 \"DELL U2720Q\""
        );
    }

    #[test]
    fn picker_label_leaves_primary_plain_even_with_a_matching_cache() {
        let cached = [monitor(0, true, "A"), monitor(1, false, "DELL U2720Q")];
        assert_eq!(
            picker_label(MonitorChoice::Primary, &cached, true),
            "Primary monitor"
        );
    }

    #[test]
    fn picker_label_falls_back_when_the_cache_has_no_id_one() {
        // Defensive: a cache with >= 2 entries but none tagged id 1 (should
        // not happen from a real host, but a hand-edited config could).
        let cached = [monitor(0, true, "A"), monitor(5, false, "Weird")];
        assert_eq!(
            picker_label(MonitorChoice::Second, &cached, true),
            "Second monitor"
        );
    }
}
