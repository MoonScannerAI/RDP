//! Splitting long messages for logcat. Platform-neutral so it is unit-tested
//! on Windows too.
//!
//! liblog truncates a single entry at roughly 4 KiB (LOGGER_ENTRY_MAX_PAYLOAD
//! minus the tag), which would silently cut a panic backtrace in half. Long
//! messages are therefore written as several entries, broken at line ends
//! where possible and never inside a UTF-8 sequence.

/// Comfortably under liblog's per-entry payload limit with a short tag.
pub const MAX_ENTRY_BYTES: usize = 4000;

/// Split `msg` into pieces of at most `max` bytes (`max` >= 4). A trailing
/// newline is dropped; an empty message yields one empty piece.
pub fn split(msg: &str, max: usize) -> Vec<&str> {
    let max = max.max(4);
    let mut rest = msg.strip_suffix('\n').unwrap_or(msg);
    let mut out = Vec::new();
    while rest.len() > max {
        // Largest char boundary <= max.
        let mut cut = max;
        while !rest.is_char_boundary(cut) {
            cut -= 1;
        }
        // Prefer breaking just after the last newline in the window.
        if let Some(nl) = rest[..cut].rfind('\n') {
            if nl > 0 {
                out.push(&rest[..nl]);
                rest = &rest[nl + 1..];
                continue;
            }
        }
        out.push(&rest[..cut]);
        rest = &rest[cut..];
    }
    out.push(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_message_is_one_piece_without_trailing_newline() {
        assert_eq!(split("hello\n", 4000), vec!["hello"]);
        assert_eq!(split("", 4000), vec![""]);
    }

    #[test]
    fn breaks_at_newlines_when_possible() {
        let msg = "aaaa\nbbbb\ncccc";
        assert_eq!(split(msg, 10), vec!["aaaa\nbbbb", "cccc"]);
    }

    #[test]
    fn hard_splits_long_lines_on_char_boundaries() {
        // 'é' is two bytes; a cut at an odd byte offset must back off.
        let msg = "éééééé"; // 12 bytes
        let parts = split(msg, 5);
        assert!(parts.iter().all(|p| p.len() <= 5));
        assert_eq!(parts.concat(), msg);
    }

    #[test]
    fn every_piece_respects_the_limit() {
        let msg: String = (0..500)
            .map(|i| format!("line {i} of a backtrace\n"))
            .collect();
        let parts = split(&msg, MAX_ENTRY_BYTES);
        assert!(parts.len() > 1);
        assert!(parts.iter().all(|p| p.len() <= MAX_ENTRY_BYTES));
        assert_eq!(parts.join("\n"), msg.trim_end_matches('\n'));
    }
}
