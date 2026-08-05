//! The typed event log every matrix assertion is written against.
//!
//! The harness never asserts "it didn't panic". Both cores emit a structured
//! record for everything observable — each capture, each send, each
//! presentation with its content-hash verdict and its capture-to-present age,
//! each keyframe request and each honouring of one, each input event on both
//! ends, each bitrate decision, each record delivered on the fallback mux. A
//! test then makes a statement about that transcript.
//!
//! Every timestamp is a virtual millisecond, so a log is a deterministic
//! function of `(config, seed)` and two runs of the same row compare equal
//! element for element.

use crate::framing::MuxClass;

/// Which transport path a frame took.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Route {
    /// Unreliable datagrams with fragment reassembly — the normal path.
    Datagram,
    /// The reliable multiplexed stream — the TCP-fallback shape.
    Fallback,
}

/// One observable thing that happened at a known virtual millisecond.
#[derive(Debug, Clone, PartialEq)]
pub enum SimEvent {
    /// The host's synthetic source produced a frame and the encoder labelled it.
    FrameCaptured {
        /// Virtual millisecond.
        at_ms: u64,
        /// Encoder-assigned id.
        frame_id: u32,
        /// Whether the encoder emitted it as a keyframe.
        keyframe: bool,
        /// Encoded payload size.
        bytes: usize,
    },
    /// The host handed a frame to the transport.
    FrameSent {
        /// Virtual millisecond.
        at_ms: u64,
        /// Encoder-assigned id.
        frame_id: u32,
        /// Whether it was a keyframe.
        keyframe: bool,
        /// Datagram fragments produced (always 1 on the fallback path).
        fragments: usize,
        /// Path taken.
        route: Route,
    },
    /// The client put a frame in its present slot.
    FramePresented {
        /// Virtual millisecond.
        at_ms: u64,
        /// Encoder-assigned id.
        frame_id: u32,
        /// Whether it was a keyframe.
        keyframe: bool,
        /// Whether the payload matched the content hash *and* the frame id.
        hash_ok: bool,
        /// Capture-to-present latency in virtual milliseconds.
        age_ms: u64,
        /// Path taken.
        route: Route,
    },
    /// A completed frame reached the client but was older than what is already
    /// on screen, so it was thrown away instead of shown.
    FrameDiscardedStale {
        /// Virtual millisecond.
        at_ms: u64,
        /// Id of the frame discarded.
        frame_id: u32,
        /// Id currently in the present slot.
        newest_presented: u32,
    },
    /// A completed delta frame reached the client but was refused by the
    /// keyframe gate (`SimConfig::gate_delta_after_gap`): its id did not
    /// follow the last frame admitted to the decoder, or the gate was still
    /// waiting out an earlier gap. Mirrors the client's `KeyframeGate` (B1) —
    /// a freeze-frame instead of decoding against a reference that was never
    /// received.
    FrameGated {
        /// Virtual millisecond.
        at_ms: u64,
        /// Id of the frame refused.
        frame_id: u32,
    },
    /// The client's reassembler demanded a keyframe and the request went out.
    KeyframeRequested {
        /// Virtual millisecond.
        at_ms: u64,
    },
    /// The host received a keyframe request and armed the encoder.
    KeyframeHonored {
        /// Virtual millisecond.
        at_ms: u64,
    },
    /// The client wrote an input event to the reliable input stream.
    InputSent {
        /// Virtual millisecond.
        at_ms: u64,
        /// Sequence number carried in the event's `x` field.
        seq: u32,
    },
    /// The host validated an input event and injected it.
    InputInjected {
        /// Virtual millisecond.
        at_ms: u64,
        /// Sequence number recovered from the event.
        seq: u32,
    },
    /// The adaptor changed the target bitrate.
    BitrateChanged {
        /// Virtual millisecond.
        at_ms: u64,
        /// New target.
        kbps: u32,
    },
    /// The client reported a measured loss fraction to the host.
    LossReported {
        /// Virtual millisecond.
        at_ms: u64,
        /// Fraction in `0.0..=1.0` over the reporting window.
        loss: f32,
    },
    /// The client completed a ping/pong round trip.
    RttSampled {
        /// Virtual millisecond.
        at_ms: u64,
        /// Measured round-trip time.
        rtt_ms: u64,
    },
    /// The client saw no datagrams for the probe window and asked to fall back.
    FallbackRequested {
        /// Virtual millisecond.
        at_ms: u64,
    },
    /// The host moved video onto the reliable multiplexed stream.
    FallbackEngaged {
        /// Virtual millisecond.
        at_ms: u64,
    },
    /// A record arrived complete on the fallback mux.
    MuxDelivered {
        /// Virtual millisecond of full delivery.
        at_ms: u64,
        /// Priority class it was sent under.
        class: MuxClass,
        /// Sender-side enqueue order.
        seq: u64,
        /// Virtual millisecond the sender enqueued it.
        enqueued_ms: u64,
    },
    /// The mux dropped a queued video frame rather than let the backlog grow.
    MuxVideoDropped {
        /// Virtual millisecond.
        at_ms: u64,
        /// Id of the frame thrown away.
        frame_id: u32,
    },
    /// A datagram was refused by the reassembler (malformed, contradictory, or
    /// outside the accepted frame-id window).
    DatagramRejected {
        /// Virtual millisecond.
        at_ms: u64,
        /// Human-readable cause.
        reason: String,
    },
    /// A message on a reliable channel could not be decoded.
    ControlRejected {
        /// Virtual millisecond.
        at_ms: u64,
        /// Human-readable cause.
        reason: String,
    },
}

impl SimEvent {
    /// The virtual millisecond this event carries.
    #[must_use]
    pub fn at_ms(&self) -> u64 {
        match self {
            SimEvent::FrameCaptured { at_ms, .. }
            | SimEvent::FrameSent { at_ms, .. }
            | SimEvent::FramePresented { at_ms, .. }
            | SimEvent::FrameDiscardedStale { at_ms, .. }
            | SimEvent::FrameGated { at_ms, .. }
            | SimEvent::KeyframeRequested { at_ms }
            | SimEvent::KeyframeHonored { at_ms }
            | SimEvent::InputSent { at_ms, .. }
            | SimEvent::InputInjected { at_ms, .. }
            | SimEvent::BitrateChanged { at_ms, .. }
            | SimEvent::LossReported { at_ms, .. }
            | SimEvent::RttSampled { at_ms, .. }
            | SimEvent::FallbackRequested { at_ms }
            | SimEvent::FallbackEngaged { at_ms }
            | SimEvent::MuxDelivered { at_ms, .. }
            | SimEvent::MuxVideoDropped { at_ms, .. }
            | SimEvent::DatagramRejected { at_ms, .. }
            | SimEvent::ControlRejected { at_ms, .. } => *at_ms,
        }
    }
}

/// A flattened [`SimEvent::FramePresented`], for readable assertions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Presented {
    /// Virtual millisecond of presentation.
    pub at_ms: u64,
    /// Encoder-assigned id.
    pub frame_id: u32,
    /// Whether it was a keyframe.
    pub keyframe: bool,
    /// Whether the payload verified against its hash and its id.
    pub hash_ok: bool,
    /// Capture-to-present latency.
    pub age_ms: u64,
    /// Path taken.
    pub route: Route,
}

/// A flattened [`SimEvent::MuxDelivered`], for readable assertions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MuxDelivery {
    /// Virtual millisecond of full delivery.
    pub at_ms: u64,
    /// Priority class.
    pub class: MuxClass,
    /// Sender-side enqueue order.
    pub seq: u64,
    /// Virtual millisecond of enqueue.
    pub enqueued_ms: u64,
}

impl MuxDelivery {
    /// Enqueue-to-delivery delay, the number the priority policy exists to keep
    /// small for control and input.
    #[must_use]
    pub fn queue_delay_ms(&self) -> u64 {
        self.at_ms.saturating_sub(self.enqueued_ms)
    }
}

/// An append-only transcript with query helpers.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EventLog {
    events: Vec<SimEvent>,
}

impl EventLog {
    /// An empty log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an event.
    pub fn push(&mut self, event: SimEvent) {
        self.events.push(event);
    }

    /// Every event, in the order it happened.
    #[must_use]
    pub fn events(&self) -> &[SimEvent] {
        &self.events
    }

    /// Number of recorded events.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether nothing has been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Every presented frame, in presentation order.
    #[must_use]
    pub fn presented(&self) -> Vec<Presented> {
        self.events
            .iter()
            .filter_map(|e| match e {
                SimEvent::FramePresented {
                    at_ms,
                    frame_id,
                    keyframe,
                    hash_ok,
                    age_ms,
                    route,
                } => Some(Presented {
                    at_ms: *at_ms,
                    frame_id: *frame_id,
                    keyframe: *keyframe,
                    hash_ok: *hash_ok,
                    age_ms: *age_ms,
                    route: *route,
                }),
                _ => None,
            })
            .collect()
    }

    /// Presented frames whose presentation instant lies in `[from_ms, to_ms)`.
    #[must_use]
    pub fn presented_between(&self, from_ms: u64, to_ms: u64) -> Vec<Presented> {
        self.presented()
            .into_iter()
            .filter(|p| p.at_ms >= from_ms && p.at_ms < to_ms)
            .collect()
    }

    /// When a specific frame id was captured, if it ever was.
    ///
    /// Capture is due-checked once per tick, so the real instant can drift a
    /// few milliseconds past the ideal `(id - 1) * frame_interval_ms` —
    /// exact, this is the honest anchor for a scenario bound.
    #[must_use]
    pub fn captured_at(&self, frame_id: u32) -> Option<u64> {
        self.events.iter().find_map(|e| match e {
            SimEvent::FrameCaptured {
                at_ms,
                frame_id: id,
                ..
            } if *id == frame_id => Some(*at_ms),
            _ => None,
        })
    }

    /// Ids of every frame the host captured, in capture order.
    #[must_use]
    pub fn captured_ids(&self) -> Vec<u32> {
        self.events
            .iter()
            .filter_map(|e| match e {
                SimEvent::FrameCaptured { frame_id, .. } => Some(*frame_id),
                _ => None,
            })
            .collect()
    }

    /// Frames that completed too late to be worth showing, as
    /// `(at_ms, frame_id, newest_presented)`.
    ///
    /// A non-empty list means the reassembler handed over a frame older than
    /// one already on screen — see [`crate::SimClient`] for why that can happen
    /// and why the present slot refuses it.
    #[must_use]
    pub fn stale_frames_discarded(&self) -> Vec<(u64, u32, u32)> {
        self.events
            .iter()
            .filter_map(|e| match e {
                SimEvent::FrameDiscardedStale {
                    at_ms,
                    frame_id,
                    newest_presented,
                } => Some((*at_ms, *frame_id, *newest_presented)),
                _ => None,
            })
            .collect()
    }

    /// Completed delta frames the keyframe gate refused to present, as
    /// `(at_ms, frame_id)` — see [`SimEvent::FrameGated`].
    #[must_use]
    pub fn gated_frames(&self) -> Vec<(u64, u32)> {
        self.events
            .iter()
            .filter_map(|e| match e {
                SimEvent::FrameGated { at_ms, frame_id } => Some((*at_ms, *frame_id)),
                _ => None,
            })
            .collect()
    }

    /// Instants at which the client asked for a keyframe.
    #[must_use]
    pub fn keyframe_requests(&self) -> Vec<u64> {
        self.timestamps_of(|e| matches!(e, SimEvent::KeyframeRequested { .. }))
    }

    /// Instants at which the host armed the encoder for a keyframe.
    #[must_use]
    pub fn keyframes_honored(&self) -> Vec<u64> {
        self.timestamps_of(|e| matches!(e, SimEvent::KeyframeHonored { .. }))
    }

    /// Every bitrate decision as `(at_ms, kbps)`, in order.
    #[must_use]
    pub fn bitrate_changes(&self) -> Vec<(u64, u32)> {
        self.events
            .iter()
            .filter_map(|e| match e {
                SimEvent::BitrateChanged { at_ms, kbps } => Some((*at_ms, *kbps)),
                _ => None,
            })
            .collect()
    }

    /// Every loss report as `(at_ms, loss)`, in order.
    #[must_use]
    pub fn loss_reports(&self) -> Vec<(u64, f32)> {
        self.events
            .iter()
            .filter_map(|e| match e {
                SimEvent::LossReported { at_ms, loss } => Some((*at_ms, *loss)),
                _ => None,
            })
            .collect()
    }

    /// Every completed ping/pong as `(at_ms, rtt_ms)`, in order.
    #[must_use]
    pub fn rtt_samples(&self) -> Vec<(u64, u64)> {
        self.events
            .iter()
            .filter_map(|e| match e {
                SimEvent::RttSampled { at_ms, rtt_ms } => Some((*at_ms, *rtt_ms)),
                _ => None,
            })
            .collect()
    }

    /// Input events written by the client, as `(seq, at_ms)` in send order.
    #[must_use]
    pub fn inputs_sent(&self) -> Vec<(u32, u64)> {
        self.events
            .iter()
            .filter_map(|e| match e {
                SimEvent::InputSent { at_ms, seq } => Some((*seq, *at_ms)),
                _ => None,
            })
            .collect()
    }

    /// Input events injected by the host, as `(seq, at_ms)` in injection order.
    #[must_use]
    pub fn inputs_injected(&self) -> Vec<(u32, u64)> {
        self.events
            .iter()
            .filter_map(|e| match e {
                SimEvent::InputInjected { at_ms, seq } => Some((*seq, *at_ms)),
                _ => None,
            })
            .collect()
    }

    /// One-way input delivery latency, joining each injection to its send.
    ///
    /// Returns `(seq, latency_ms)` in injection order. An injected sequence
    /// number with no matching send would be a harness bug and is skipped here;
    /// tests assert the counts match instead.
    #[must_use]
    pub fn input_latencies(&self) -> Vec<(u32, u64)> {
        let sent = self.inputs_sent();
        self.inputs_injected()
            .into_iter()
            .filter_map(|(seq, at)| {
                sent.iter()
                    .find(|(s, _)| *s == seq)
                    .map(|(_, t)| (seq, at.saturating_sub(*t)))
            })
            .collect()
    }

    /// Every record delivered on the fallback mux, in delivery order.
    #[must_use]
    pub fn mux_deliveries(&self) -> Vec<MuxDelivery> {
        self.events
            .iter()
            .filter_map(|e| match e {
                SimEvent::MuxDelivered {
                    at_ms,
                    class,
                    seq,
                    enqueued_ms,
                } => Some(MuxDelivery {
                    at_ms: *at_ms,
                    class: *class,
                    seq: *seq,
                    enqueued_ms: *enqueued_ms,
                }),
                _ => None,
            })
            .collect()
    }

    /// How many times a record of `class` overtook a video record that had been
    /// enqueued *earlier*.
    ///
    /// A non-zero count is direct evidence that the sender's priority policy —
    /// not luck — is what kept the class out of the video backlog. On a plain
    /// FIFO sender this is always zero.
    #[must_use]
    pub fn priority_bypasses(&self, class: MuxClass) -> usize {
        let deliveries = self.mux_deliveries();
        let mut count = 0usize;
        for (i, d) in deliveries.iter().enumerate() {
            if d.class != class {
                continue;
            }
            // Any video record still undelivered at this point that was queued
            // before `d` was overtaken by it.
            if deliveries[i + 1..]
                .iter()
                .any(|later| later.class == MuxClass::Video && later.seq < d.seq)
            {
                count += 1;
            }
        }
        count
    }

    /// Frames the mux threw away rather than let the backlog grow.
    #[must_use]
    pub fn mux_video_drops(&self) -> Vec<u32> {
        self.events
            .iter()
            .filter_map(|e| match e {
                SimEvent::MuxVideoDropped { frame_id, .. } => Some(*frame_id),
                _ => None,
            })
            .collect()
    }

    /// When the host moved video to the reliable path, if it ever did.
    #[must_use]
    pub fn fallback_engaged_at(&self) -> Option<u64> {
        self.events.iter().find_map(|e| match e {
            SimEvent::FallbackEngaged { at_ms } => Some(*at_ms),
            _ => None,
        })
    }

    /// When the client first asked to fall back, if it ever did.
    #[must_use]
    pub fn fallback_requested_at(&self) -> Option<u64> {
        self.events.iter().find_map(|e| match e {
            SimEvent::FallbackRequested { at_ms } => Some(*at_ms),
            _ => None,
        })
    }

    /// Datagrams the reassembler refused, as `(at_ms, reason)`.
    #[must_use]
    pub fn datagram_rejections(&self) -> Vec<(u64, String)> {
        self.events
            .iter()
            .filter_map(|e| match e {
                SimEvent::DatagramRejected { at_ms, reason } => Some((*at_ms, reason.clone())),
                _ => None,
            })
            .collect()
    }

    /// Reliable-channel messages that failed to decode, as `(at_ms, reason)`.
    #[must_use]
    pub fn control_rejections(&self) -> Vec<(u64, String)> {
        self.events
            .iter()
            .filter_map(|e| match e {
                SimEvent::ControlRejected { at_ms, reason } => Some((*at_ms, reason.clone())),
                _ => None,
            })
            .collect()
    }

    fn timestamps_of(&self, pred: impl Fn(&SimEvent) -> bool) -> Vec<u64> {
        self.events
            .iter()
            .filter(|e| pred(e))
            .map(SimEvent::at_ms)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_latency_joins_sends_to_injections() {
        let mut log = EventLog::new();
        log.push(SimEvent::InputSent { at_ms: 100, seq: 0 });
        log.push(SimEvent::InputSent { at_ms: 200, seq: 1 });
        log.push(SimEvent::InputInjected { at_ms: 300, seq: 0 });
        log.push(SimEvent::InputInjected { at_ms: 405, seq: 1 });
        assert_eq!(log.input_latencies(), vec![(0, 200), (1, 205)]);
    }

    #[test]
    fn priority_bypass_counts_only_real_overtakes() {
        let mut log = EventLog::new();
        // Video seq 0 is still queued when control seq 5 is delivered.
        log.push(SimEvent::MuxDelivered {
            at_ms: 10,
            class: MuxClass::Control,
            seq: 5,
            enqueued_ms: 8,
        });
        log.push(SimEvent::MuxDelivered {
            at_ms: 60,
            class: MuxClass::Video,
            seq: 0,
            enqueued_ms: 0,
        });
        assert_eq!(log.priority_bypasses(MuxClass::Control), 1);
        assert_eq!(log.priority_bypasses(MuxClass::Input), 0);

        // Strict FIFO: no overtaking anywhere.
        let mut fifo = EventLog::new();
        fifo.push(SimEvent::MuxDelivered {
            at_ms: 10,
            class: MuxClass::Video,
            seq: 0,
            enqueued_ms: 0,
        });
        fifo.push(SimEvent::MuxDelivered {
            at_ms: 20,
            class: MuxClass::Control,
            seq: 1,
            enqueued_ms: 5,
        });
        assert_eq!(fifo.priority_bypasses(MuxClass::Control), 0);
    }

    #[test]
    fn presented_between_is_half_open() {
        let mut log = EventLog::new();
        for at_ms in [100u64, 200, 300] {
            log.push(SimEvent::FramePresented {
                at_ms,
                frame_id: 1,
                keyframe: false,
                hash_ok: true,
                age_ms: 10,
                route: Route::Datagram,
            });
        }
        assert_eq!(log.presented_between(100, 300).len(), 2);
        assert_eq!(log.presented_between(0, 1000).len(), 3);
        assert_eq!(log.len(), 3);
        assert!(!log.is_empty());
    }
}
