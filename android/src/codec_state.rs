//! Platform-neutral bookkeeping for the MediaCodec decoder.
//!
//! Everything here is plain Rust with no NDK types, so it is compiled (and its
//! tests run) on Windows as part of `cargo test --workspace`, while
//! `mediacodec.rs` — the part that actually talks to `AMediaCodec` — only
//! exists on Android.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// `MediaCodecInfo.CodecCapabilities.COLOR_FormatYUV420Flexible`. Asking for
/// it in ByteBuffer mode yields a concrete 4:2:0 layout (I420, NV12 or a
/// vendor NV12 variant) that the output format then names.
pub const COLOR_FORMAT_YUV420_FLEXIBLE: i32 = 0x7F42_0888;

/// After this many consecutive failed `decode` calls the codec is dropped;
/// the next keyframe builds a fresh one.
pub const ERROR_LIMIT: u32 = 3;

/// Cap on frames remembered as "queued, not yet output". A healthy decoder
/// holds 1-5 (the emulator's goldfish decoder peaks around 5); anything past
/// this was dropped inside the codec and is forgotten oldest-first.
const PTS_MAP_CAP: usize = 64;

/// One frame queued into the codec, waiting for its picture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pending {
    pub pts_us: u64,
    /// The sender's `EncodedFrame::timestamp_ms`, handed back on the
    /// matching `RawFrame` so end-to-end latency stays measurable.
    pub timestamp_ms: u32,
    pub queued_at: Instant,
}

/// Maps codec presentation timestamps back to sender timestamps.
///
/// MediaCodec only carries a `u64` pts through the pipeline, so each input
/// gets a fresh, strictly increasing pts (microseconds since the codec was
/// built — realistic values for codecs that look at them) and this map
/// remembers which sender frame it was. Output order equals input order for
/// the host's stream (no B-frames), so lookups pop from the front.
#[derive(Debug)]
pub struct PtsMap {
    origin: Instant,
    last_pts_us: Option<u64>,
    pending: VecDeque<Pending>,
    /// Frames that went in and never came out (skipped by a later output, or
    /// evicted by the cap). Cleared frames from a `flush` are not counted.
    dropped: u64,
    /// Fallback timestamp for an output whose pts is unknown.
    last_timestamp_ms: u32,
}

impl PtsMap {
    pub fn new(origin: Instant) -> Self {
        Self {
            origin,
            last_pts_us: None,
            pending: VecDeque::new(),
            dropped: 0,
            last_timestamp_ms: 0,
        }
    }

    /// Record a frame about to be queued and return the pts to queue it with.
    pub fn push(&mut self, now: Instant, timestamp_ms: u32) -> u64 {
        let elapsed = u64::try_from(now.saturating_duration_since(self.origin).as_micros())
            .unwrap_or(u64::MAX / 2);
        let pts_us = match self.last_pts_us {
            Some(last) => elapsed.max(last + 1),
            None => elapsed,
        };
        self.last_pts_us = Some(pts_us);
        if self.pending.len() >= PTS_MAP_CAP {
            self.pending.pop_front();
            self.dropped += 1;
        }
        self.pending.push_back(Pending {
            pts_us,
            timestamp_ms,
            queued_at: now,
        });
        self.last_timestamp_ms = timestamp_ms;
        pts_us
    }

    /// Resolve an output pts. Earlier pending entries were dropped by the
    /// codec and are discarded (and counted). `None` for a pts this map never
    /// issued or already forgot.
    pub fn take(&mut self, pts_us: u64) -> Option<Pending> {
        while let Some(front) = self.pending.front() {
            if front.pts_us < pts_us {
                self.pending.pop_front();
                self.dropped += 1;
            } else if front.pts_us == pts_us {
                return self.pending.pop_front();
            } else {
                return None;
            }
        }
        None
    }

    /// Timestamp to use for an output whose pts did not resolve: the newest
    /// input's, which is the best available upper bound.
    pub fn fallback_timestamp_ms(&self) -> u32 {
        self.last_timestamp_ms
    }

    /// Forget everything in flight (codec flush). The pts counter keeps
    /// increasing so a stale output can never alias a new input.
    pub fn clear(&mut self) {
        self.pending.clear();
    }

    pub fn in_flight(&self) -> usize {
        self.pending.len()
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}

/// Counts consecutive failed `decode` calls.
#[derive(Debug, Default)]
pub struct ErrorStreak {
    consecutive: u32,
}

impl ErrorStreak {
    /// Record a failure. Returns `true` exactly when the streak reaches
    /// [`ERROR_LIMIT`] — the caller then drops the codec — and restarts it.
    pub fn fail(&mut self) -> bool {
        self.consecutive += 1;
        if self.consecutive >= ERROR_LIMIT {
            self.consecutive = 0;
            true
        } else {
            false
        }
    }

    pub fn ok(&mut self) {
        self.consecutive = 0;
    }

    #[cfg(test)]
    pub fn consecutive(&self) -> u32 {
        self.consecutive
    }
}

/// The output-format keys `yuv::layout_from_format` needs, pulled out of an
/// `AMediaFormat` through a lookup function so the extraction rules are
/// testable without one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputFormatKeys {
    pub color_format: i32,
    pub width: i32,
    pub height: i32,
    /// 0 when the codec did not report it (`layout_from_format` falls back
    /// to `width` for anything <= 0).
    pub stride: i32,
    /// 0 when the codec did not report it (falls back to `height`).
    pub slice_height: i32,
    /// Inclusive (left, top, right, bottom), when the codec reported one.
    pub crop: Option<(i32, i32, i32, i32)>,
}

impl OutputFormatKeys {
    /// `get_i32` reads one int32 key. `crop_rect` is the API-28 `"crop"` rect
    /// when it could be read; otherwise the four Java-style `crop-*` int keys
    /// are tried, and only all four together count.
    pub fn read(
        get_i32: impl Fn(&str) -> Option<i32>,
        crop_rect: Option<(i32, i32, i32, i32)>,
    ) -> Result<Self, String> {
        let color_format = get_i32("color-format").ok_or("output format has no color-format")?;
        let width = get_i32("width")
            .filter(|w| *w > 0)
            .ok_or("output format has no width")?;
        let height = get_i32("height")
            .filter(|h| *h > 0)
            .ok_or("output format has no height")?;
        let crop = crop_rect.or_else(|| {
            Some((
                get_i32("crop-left")?,
                get_i32("crop-top")?,
                get_i32("crop-right")?,
                get_i32("crop-bottom")?,
            ))
        });
        Ok(Self {
            color_format,
            width,
            height,
            stride: get_i32("stride").unwrap_or(0),
            slice_height: get_i32("slice-height").unwrap_or(0),
            crop,
        })
    }
}

/// `max-input-size` for a `width x height` stream: an uncompressed 4:2:0
/// frame bounds any sane H.264 access unit, with a 1 MiB floor for small
/// streams whose IDRs can still be large at high bitrates.
pub fn max_input_size(width: u32, height: u32) -> i32 {
    let raw = u64::from(width)
        .saturating_mul(u64::from(height))
        .saturating_mul(3)
        / 2;
    raw.max(1 << 20).min(i32::MAX as u64) as i32
}

/// Which optional low-latency keys a configure attempt sets. Tried in order;
/// the codec is rebuilt with fewer hints until one configures.
///
/// There is deliberately no tier with `priority = 0` + a high
/// `operating-rate`: some vendor decoders are reported (Moonlight's
/// experience) to *crash* on that combination rather than fail configure,
/// and a crash is not something this ladder can recover from. The
/// `low-latency` flags are what matter for a single-frame-in-flight stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LatencyTier {
    /// Low-latency flags only; no realtime/operating-rate demands.
    LowLatencyOnly,
    /// No optional keys at all.
    Plain,
}

impl LatencyTier {
    pub const LADDER: [LatencyTier; 2] = [LatencyTier::LowLatencyOnly, LatencyTier::Plain];

    /// The int32 keys this tier adds to the format. Unknown keys (the vendor
    /// one on non-Qualcomm decoders) are ignored by the codec.
    pub fn keys(self) -> &'static [(&'static str, i32)] {
        match self {
            LatencyTier::LowLatencyOnly => &[
                ("low-latency", 1),
                ("vendor.qti-ext-dec-low-latency.enable", 1),
            ],
            LatencyTier::Plain => &[],
        }
    }
}

/// Counters for the periodic one-line summary.
#[derive(Debug)]
pub struct DecodeStats {
    interval: Duration,
    window_start: Instant,
    pub frames_in: u64,
    pub frames_out: u64,
    window_out: u64,
    window_max_in_flight: usize,
    window_max_latency: Option<Duration>,
    pub last_latency: Option<Duration>,
    pub errors: u64,
    pub codecs_built: u64,
}

impl DecodeStats {
    pub fn new(now: Instant, interval: Duration) -> Self {
        Self {
            interval,
            window_start: now,
            frames_in: 0,
            frames_out: 0,
            window_out: 0,
            window_max_in_flight: 0,
            window_max_latency: None,
            last_latency: None,
            errors: 0,
            codecs_built: 0,
        }
    }

    pub fn on_input(&mut self, in_flight: usize) {
        self.frames_in += 1;
        self.window_max_in_flight = self.window_max_in_flight.max(in_flight);
    }

    pub fn on_output(&mut self, latency: Option<Duration>) {
        self.frames_out += 1;
        self.window_out += 1;
        if let Some(l) = latency {
            self.last_latency = Some(l);
            self.window_max_latency = Some(self.window_max_latency.map_or(l, |m| m.max(l)));
        }
    }

    /// The summary line if a full interval has passed since the last one;
    /// starts a new window when it returns `Some`.
    pub fn summary_due(&mut self, now: Instant, in_flight: usize, dropped: u64) -> Option<String> {
        let elapsed = now.saturating_duration_since(self.window_start);
        if elapsed < self.interval {
            return None;
        }
        let fps = self.window_out as f64 / elapsed.as_secs_f64();
        let ms = |d: Option<Duration>| match d {
            Some(d) => format!("{:.1}", d.as_secs_f64() * 1000.0),
            None => "-".to_string(),
        };
        let line = format!(
            "mediacodec: in={} out={} out_fps={:.1} in_flight={} max_in_flight={} \
             latency_ms last={} max={} dropped={} errors={} codecs={}",
            self.frames_in,
            self.frames_out,
            fps,
            in_flight,
            self.window_max_in_flight,
            ms(self.last_latency),
            ms(self.window_max_latency),
            dropped,
            self.errors,
            self.codecs_built,
        );
        self.window_start = now;
        self.window_out = 0;
        self.window_max_in_flight = in_flight;
        self.window_max_latency = None;
        Some(line)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn pts_is_strictly_increasing_even_for_simultaneous_inputs() {
        let t0 = Instant::now();
        let mut m = PtsMap::new(t0);
        let a = m.push(t0, 1);
        let b = m.push(t0, 2);
        let c = m.push(t0 + ms(5), 3);
        assert!(a < b && b < c);
        assert_eq!(c, 5_000);
    }

    #[test]
    fn take_returns_matching_frame_and_counts_skipped_ones_as_dropped() {
        let t0 = Instant::now();
        let mut m = PtsMap::new(t0);
        let p1 = m.push(t0, 100);
        let p2 = m.push(t0 + ms(1), 200);
        let p3 = m.push(t0 + ms(2), 300);
        assert_eq!(m.in_flight(), 3);
        assert_eq!(m.take(p1).map(|p| p.timestamp_ms), Some(100));
        // p2 never comes out: p3 resolves and p2 is counted as dropped.
        assert_eq!(m.take(p3).map(|p| p.timestamp_ms), Some(300));
        assert_eq!(m.dropped(), 1);
        assert_eq!(m.in_flight(), 0);
        assert_eq!(m.take(p2), None);
    }

    #[test]
    fn unknown_pts_does_not_consume_pending_frames() {
        let t0 = Instant::now();
        let mut m = PtsMap::new(t0);
        let p1 = m.push(t0 + ms(10), 7);
        assert_eq!(m.take(p1 - 1), None);
        assert_eq!(m.in_flight(), 1);
        assert_eq!(m.fallback_timestamp_ms(), 7);
    }

    #[test]
    fn clear_forgets_in_flight_without_counting_drops_and_pts_keeps_rising() {
        let t0 = Instant::now();
        let mut m = PtsMap::new(t0);
        let p1 = m.push(t0 + ms(3), 1);
        m.clear();
        assert_eq!(m.in_flight(), 0);
        assert_eq!(m.dropped(), 0);
        // Same wall time after a flush still yields a fresh pts.
        let p2 = m.push(t0 + ms(3), 2);
        assert!(p2 > p1);
        assert_eq!(m.take(p1), None);
        assert_eq!(m.take(p2).map(|p| p.timestamp_ms), Some(2));
    }

    #[test]
    fn map_is_capped() {
        let t0 = Instant::now();
        let mut m = PtsMap::new(t0);
        for i in 0..(PTS_MAP_CAP as u32 + 10) {
            m.push(t0, i);
        }
        assert_eq!(m.in_flight(), PTS_MAP_CAP);
        assert_eq!(m.dropped(), 10);
    }

    #[test]
    fn error_streak_trips_at_limit_and_resets_on_success() {
        let mut e = ErrorStreak::default();
        assert!(!e.fail());
        assert!(!e.fail());
        e.ok();
        assert_eq!(e.consecutive(), 0);
        assert!(!e.fail());
        assert!(!e.fail());
        assert!(e.fail(), "third consecutive failure drops the codec");
        assert_eq!(e.consecutive(), 0, "streak restarts after tripping");
    }

    fn lookup(pairs: &[(&str, i32)]) -> impl Fn(&str) -> Option<i32> {
        let map: HashMap<String, i32> = pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect();
        move |k| map.get(k).copied()
    }

    #[test]
    fn format_keys_from_goldfish_like_format() {
        let get = lookup(&[
            ("color-format", 19),
            ("width", 2560),
            ("height", 1600),
            ("stride", 2560),
            ("slice-height", 1600),
        ]);
        let k = OutputFormatKeys::read(&get, Some((0, 0, 2559, 1599))).unwrap();
        assert_eq!(k.color_format, 19);
        assert_eq!(
            (k.width, k.height, k.stride, k.slice_height),
            (2560, 1600, 2560, 1600)
        );
        assert_eq!(k.crop, Some((0, 0, 2559, 1599)));
    }

    #[test]
    fn format_keys_fall_back_to_java_style_crop_and_missing_stride() {
        let get = lookup(&[
            ("color-format", 21),
            ("width", 1920),
            ("height", 1088),
            ("crop-left", 0),
            ("crop-top", 0),
            ("crop-right", 1919),
            ("crop-bottom", 1079),
        ]);
        let k = OutputFormatKeys::read(&get, None).unwrap();
        assert_eq!(k.crop, Some((0, 0, 1919, 1079)));
        assert_eq!((k.stride, k.slice_height), (0, 0));
    }

    #[test]
    fn format_keys_partial_crop_is_ignored_and_required_keys_enforced() {
        let get = lookup(&[
            ("color-format", 21),
            ("width", 64),
            ("height", 64),
            ("crop-left", 2),
        ]);
        assert_eq!(OutputFormatKeys::read(&get, None).unwrap().crop, None);
        let no_color = lookup(&[("width", 64), ("height", 64)]);
        assert!(OutputFormatKeys::read(no_color, None).is_err());
        let zero_w = lookup(&[("color-format", 19), ("width", 0), ("height", 64)]);
        assert!(OutputFormatKeys::read(zero_w, None).is_err());
    }

    #[test]
    fn flexible_color_format_constant_matches_the_sdk() {
        // MediaCodecInfo.CodecCapabilities.COLOR_FormatYUV420Flexible
        assert_eq!(COLOR_FORMAT_YUV420_FLEXIBLE, 2_135_033_992);
    }

    #[test]
    fn max_input_size_bounds() {
        assert_eq!(max_input_size(320, 240), 1 << 20);
        assert_eq!(max_input_size(2560, 1600), 2560 * 1600 * 3 / 2);
        assert_eq!(max_input_size(u32::MAX, u32::MAX), i32::MAX);
    }

    #[test]
    fn latency_ladder_degrades_to_plain() {
        assert_eq!(LatencyTier::LADDER[0], LatencyTier::LowLatencyOnly);
        assert!(LatencyTier::LowLatencyOnly
            .keys()
            .iter()
            .any(|(k, _)| *k == "low-latency"));
        assert!(!LatencyTier::LowLatencyOnly
            .keys()
            .iter()
            .any(|(k, _)| *k == "priority" || *k == "operating-rate"));
        assert!(LatencyTier::Plain.keys().is_empty());
    }

    #[test]
    fn stats_summary_once_per_interval() {
        let t0 = Instant::now();
        let mut s = DecodeStats::new(t0, Duration::from_secs(5));
        s.on_input(1);
        s.on_input(3);
        s.on_output(Some(ms(12)));
        s.on_output(Some(ms(9)));
        assert!(s.summary_due(t0 + ms(4_999), 1, 0).is_none());
        let line = s.summary_due(t0 + ms(5_000), 1, 2).unwrap();
        assert!(line.contains("in=2 out=2"), "{line}");
        assert!(line.contains("max_in_flight=3"), "{line}");
        assert!(line.contains("last=9.0 max=12.0"), "{line}");
        assert!(line.contains("dropped=2"), "{line}");
        // New window: nothing due until another interval passes.
        assert!(s.summary_due(t0 + ms(6_000), 0, 2).is_none());
    }
}
