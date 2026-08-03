//! A prioritised, byte-budgeted sender for the reliable fallback path.
//!
//! # What it models
//!
//! When UDP is blocked, M4 will carry video, input and control over a single
//! reliable connection. That collapses three independently scheduled QUIC
//! streams into one ordered byte stream, and reintroduces two problems QUIC had
//! solved:
//!
//! * **Head-of-line blocking.** A small control message written after a large
//!   video frame cannot arrive before it. The only defence is to choose the
//!   send order — hence the priority classes, and hence
//!   [`crate::event::EventLog::priority_bypasses`], which proves the choice was
//!   actually exercised rather than merely configured.
//! * **Unbounded backlog.** A link slower than the encoder turns queued video
//!   into ever-growing latency. Retransmitting a frame nobody will look at
//!   costs latency for nothing, so queued video is dropped once the backlog
//!   exceeds [`MuxConfig::max_video_backlog`] — the reliable-path equivalent of
//!   the datagram path simply losing it.
//!
//! # Bandwidth model
//!
//! [`ReliableMux::pump`] writes at most [`MuxConfig::bytes_per_tick`] bytes per
//! virtual tick. Records are split at byte granularity, so a control record
//! enqueued while a large video record is mid-flight waits for the *remainder
//! of that record* — the same partial-write behaviour a real socket has — but
//! never for the rest of the queue. That distinction is the entire point of the
//! priority queue, and it is why the queue is consulted only between records.

use directdesk_shared::error::Result;
use directdesk_shared::netsim::Endpoint;

use crate::event::SimEvent;
use crate::framing::{encode_mux_record, MuxClass};
use crate::pump::PumpCtx;

/// Tuning for [`ReliableMux`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MuxConfig {
    /// Stream id to write on.
    pub stream_id: u32,
    /// Bytes the sender may write per virtual tick. This is the bottleneck the
    /// backlog forms behind; set it above the video bitrate for an uncongested
    /// fallback.
    pub bytes_per_tick: usize,
    /// How many video records may sit queued before the oldest are dropped.
    /// Control and input are never dropped.
    pub max_video_backlog: usize,
}

impl MuxConfig {
    /// A mux on `stream_id` with the given budget and backlog cap.
    #[must_use]
    pub fn new(stream_id: u32, bytes_per_tick: usize, max_video_backlog: usize) -> Self {
        Self {
            stream_id,
            bytes_per_tick,
            max_video_backlog,
        }
    }
}

/// Cumulative counters, for assertions and diagnostics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MuxStats {
    /// Records handed to [`ReliableMux::enqueue`].
    pub records_enqueued: u64,
    /// Records fully written to the stream.
    pub records_sent: u64,
    /// Video records dropped because the backlog was full.
    pub video_dropped_stale: u64,
    /// Payload bytes written (excluding record headers).
    pub payload_bytes_sent: u64,
}

/// One queued application message.
#[derive(Debug, Clone)]
struct MuxItem {
    class: MuxClass,
    seq: u64,
    enqueued_ms: u64,
    /// Frame id, when the payload is a video record — only for logging drops.
    frame_id: Option<u32>,
    payload: Vec<u8>,
}

/// Priority sender over one netsim stream.
#[derive(Debug)]
pub struct ReliableMux {
    cfg: MuxConfig,
    queue: Vec<MuxItem>,
    /// The record currently being written, with how many of its bytes have gone
    /// out. Once a record starts it must finish: a byte stream cannot be
    /// interleaved, which is exactly the head-of-line cost being modelled.
    pending: Option<(Vec<u8>, usize)>,
    next_seq: u64,
    stats: MuxStats,
}

impl ReliableMux {
    /// An empty mux with the given configuration.
    #[must_use]
    pub fn new(cfg: MuxConfig) -> Self {
        Self {
            cfg,
            queue: Vec::new(),
            pending: None,
            next_seq: 0,
            stats: MuxStats::default(),
        }
    }

    /// Snapshot of the cumulative counters.
    #[must_use]
    pub fn stats(&self) -> MuxStats {
        self.stats
    }

    /// Records waiting to start transmission.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.queue.len()
    }

    /// Whether a record is part-way through transmission.
    #[must_use]
    pub fn is_sending(&self) -> bool {
        self.pending.is_some()
    }

    /// Queue an application message. Returns the sequence number assigned.
    ///
    /// `frame_id` is carried only so a dropped video record can be named in the
    /// event log; pass `None` for control and input.
    pub fn enqueue(
        &mut self,
        class: MuxClass,
        payload: Vec<u8>,
        frame_id: Option<u32>,
        now_ms: u64,
    ) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.stats.records_enqueued += 1;
        self.queue.push(MuxItem {
            class,
            seq,
            enqueued_ms: now_ms,
            frame_id,
            payload,
        });
        seq
    }

    /// Shed backlog, then write up to the tick's byte budget.
    ///
    /// # Errors
    ///
    /// Propagates a netsim send failure. `send_stream` is currently infallible,
    /// so in practice this only fires if that contract changes.
    pub fn pump(&mut self, ctx: &mut PumpCtx<'_>, from: Endpoint) -> Result<()> {
        self.drop_stale_video(ctx);

        let mut budget = self.cfg.bytes_per_tick;
        while budget > 0 {
            if self.pending.is_none() {
                let Some(index) = self.select_next() else {
                    break;
                };
                let item = self.queue.remove(index);
                let bytes =
                    encode_mux_record(item.class, item.seq, item.enqueued_ms, &item.payload);
                self.stats.records_sent += 1;
                self.stats.payload_bytes_sent += item.payload.len() as u64;
                self.pending = Some((bytes, 0));
            }
            let (bytes, offset) = self.pending.as_mut().expect("pending was just filled");
            let take = budget.min(bytes.len() - *offset);
            ctx.net
                .send_stream(from, self.cfg.stream_id, &bytes[*offset..*offset + take])?;
            *offset += take;
            budget -= take;
            if *offset >= bytes.len() {
                self.pending = None;
            }
        }
        Ok(())
    }

    /// Index of the record that should go next: lowest class rank, then lowest
    /// sequence number. Deterministic, and never consults a map.
    fn select_next(&self) -> Option<usize> {
        let mut best: Option<(usize, u8, u64)> = None;
        for (i, item) in self.queue.iter().enumerate() {
            let key = (item.class.rank(), item.seq);
            let take = match best {
                None => true,
                Some((_, rank, seq)) => key < (rank, seq),
            };
            if take {
                best = Some((i, key.0, key.1));
            }
        }
        best.map(|(i, _, _)| i)
    }

    /// Drop the oldest queued video records until the backlog fits the cap.
    ///
    /// The record already part-way out is untouched — it is on the wire, not in
    /// the queue.
    fn drop_stale_video(&mut self, ctx: &mut PumpCtx<'_>) {
        loop {
            let video: Vec<usize> = self
                .queue
                .iter()
                .enumerate()
                .filter(|(_, item)| item.class == MuxClass::Video)
                .map(|(i, _)| i)
                .collect();
            if video.len() <= self.cfg.max_video_backlog {
                return;
            }
            // Queue order is enqueue order, so the first video entry is oldest.
            let index = video[0];
            let item = self.queue.remove(index);
            self.stats.video_dropped_stale += 1;
            ctx.log.push(SimEvent::MuxVideoDropped {
                at_ms: ctx.now_ms,
                frame_id: item.frame_id.unwrap_or(0),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventLog;
    use crate::framing::MuxReader;
    use directdesk_shared::netsim::{NetParams, NetSim};

    fn harness() -> (NetSim, EventLog) {
        let mut params = NetParams::perfect();
        params.latency_ms = 0;
        (NetSim::new(params, 1).expect("valid"), EventLog::new())
    }

    /// A record the caller wants queued at a particular tick.
    type Schedule = Vec<(u64, MuxClass, Vec<u8>, Option<u32>)>;

    /// Drive `ticks` pumps, applying `schedule` as it goes, and return every
    /// record the far side received.
    fn run(
        mux: &mut ReliableMux,
        net: &mut NetSim,
        log: &mut EventLog,
        ticks: u64,
        schedule: &Schedule,
    ) -> Vec<crate::framing::MuxRecord> {
        let mut reader = MuxReader::new();
        let mut out = Vec::new();
        for t in 0..ticks {
            net.tick(t);
            for (at, class, payload, frame_id) in schedule.iter().filter(|(at, ..)| *at == t) {
                mux.enqueue(*class, payload.clone(), *frame_id, *at);
            }
            let mut ctx = PumpCtx {
                net,
                now_ms: t,
                log,
            };
            mux.pump(&mut ctx, Endpoint::A).expect("pump");
            let bytes = ctx.net.recv_stream(Endpoint::B, 4);
            reader.push_bytes(&bytes);
            out.extend(reader.drain().expect("drain"));
        }
        out
    }

    /// The case the fallback path actually hits: a video backlog is already
    /// draining when a small control message shows up. It cannot interrupt the
    /// record on the wire — a byte stream has no way to interleave — but it
    /// must not wait for the rest of the queue.
    #[test]
    fn control_overtakes_a_video_backlog_mid_flight() {
        let (mut net, mut log) = harness();
        let mut mux = ReliableMux::new(MuxConfig::new(4, 32, 16));
        let mut schedule: Schedule = (0..4u32)
            .map(|i| (0u64, MuxClass::Video, vec![i as u8; 200], Some(i)))
            .collect();
        // Three ticks in, the first video record is part-way out.
        schedule.push((3, MuxClass::Control, b"ping".to_vec(), None));

        let got = run(&mut mux, &mut net, &mut log, 200, &schedule);
        let order: Vec<(MuxClass, u64)> = got.iter().map(|r| (r.class, r.seq)).collect();
        assert_eq!(
            order,
            vec![
                (MuxClass::Video, 0),   // already on the wire, must finish
                (MuxClass::Control, 4), // queued last, leaves next
                (MuxClass::Video, 1),
                (MuxClass::Video, 2),
                (MuxClass::Video, 3),
            ]
        );
        // The control record waited only for the remainder of one video record,
        // not for the three still queued behind it.
        let ctrl = got
            .iter()
            .position(|r| r.class == MuxClass::Control)
            .expect("control delivered");
        assert_eq!(ctrl, 1);
    }

    #[test]
    fn queue_order_is_control_then_input_then_video() {
        let (mut net, mut log) = harness();
        let mut mux = ReliableMux::new(MuxConfig::new(4, 8, 16));
        let schedule: Schedule = vec![
            (0, MuxClass::Video, vec![0u8; 64], Some(1)),
            (0, MuxClass::Video, vec![1u8; 64], Some(2)),
            (0, MuxClass::Input, b"key".to_vec(), None),
            (0, MuxClass::Control, b"c".to_vec(), None),
        ];

        let got = run(&mut mux, &mut net, &mut log, 200, &schedule);
        let order: Vec<MuxClass> = got.iter().map(|r| r.class).collect();
        assert_eq!(
            order,
            vec![
                MuxClass::Control,
                MuxClass::Input,
                MuxClass::Video,
                MuxClass::Video,
            ],
            "nothing was on the wire yet, so rank decides outright"
        );
    }

    #[test]
    fn backlog_is_shed_oldest_first_and_only_for_video() {
        let (mut net, mut log) = harness();
        let mut mux = ReliableMux::new(MuxConfig::new(4, 4, 2));
        let mut schedule: Schedule = (1..=6u32)
            .map(|i| (0u64, MuxClass::Video, vec![i as u8; 40], Some(i)))
            .collect();
        schedule.push((0, MuxClass::Control, b"c".to_vec(), None));

        let got = run(&mut mux, &mut net, &mut log, 400, &schedule);
        let dropped = log.mux_video_drops();
        assert_eq!(mux.stats().video_dropped_stale as usize, dropped.len());
        // Cap is two, six were offered: the four oldest go, newest survive.
        assert_eq!(dropped, vec![1, 2, 3, 4]);
        let video_ids: Vec<u32> = got
            .iter()
            .filter(|r| r.class == MuxClass::Video)
            .map(|r| u32::from(r.payload[0]))
            .collect();
        assert_eq!(video_ids, vec![5, 6]);
        assert_eq!(
            got.iter().filter(|r| r.class == MuxClass::Control).count(),
            1,
            "control is never dropped"
        );
    }

    #[test]
    fn a_record_larger_than_the_budget_still_makes_progress() {
        let (mut net, mut log) = harness();
        let mut mux = ReliableMux::new(MuxConfig::new(4, 3, 8));
        let schedule: Schedule = vec![(0, MuxClass::Video, vec![7u8; 100], Some(1))];
        let got = run(&mut mux, &mut net, &mut log, 200, &schedule);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].payload.len(), 100);
        assert_eq!(mux.stats().records_sent, 1);
        assert_eq!(mux.stats().payload_bytes_sent, 100);
        assert!(!mux.is_sending());
        assert_eq!(mux.queued(), 0);
    }
}
