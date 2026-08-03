//! The simulated client core: receive → reassemble → decode → present, plus
//! the reliable channels for input, keyframe demand and stats feedback.
//!
//! As with [`SimHost`](crate::SimHost), the platform pieces are the null
//! implementations from `directdesk-shared` and everything else is the
//! production path: the real [`Reassembler`], the real control framing, the
//! real keyframe rate limiter.
//!
//! # Present slot
//!
//! There is one slot, and a newer frame overwrites whatever is in it. That is
//! what a live screen share wants, and it is why the reassembler runs with
//! `latest_wins`: a frame that has been superseded before anyone looked at it
//! is worthless, and replaying it only adds latency.
//!
//! The slot enforces that policy itself rather than trusting the reassembler
//! to. [`Reassembler::pop_frame`] applies latest-wins to the frames sitting in
//! its ready queue, but a frame whose slot was *already open* when a newer
//! frame overtook it can still complete afterwards and be handed over — the
//! staleness check guards slot creation, not slot completion. Under jitter that
//! happens regularly, and showing such a frame would be a visible jump
//! backwards, so the slot drops it and records a
//! [`SimEvent::FrameDiscardedStale`](crate::SimEvent::FrameDiscardedStale).
//!
//! # Loss measurement
//!
//! The client estimates loss without any cooperation from the host. Frame ids
//! are contiguous and every frame has the same fragment count, so over a window
//! the fragments that *should* have arrived is `(newest_id - oldest_id + 1) *
//! frag_count`; comparing that to the fragments that did arrive gives the
//! fragment loss rate directly. Windows close on a frame boundary, never
//! mid-frame, so a frame straddling two windows can never make a clean link
//! look lossy.

use directdesk_shared::error::Result;
use directdesk_shared::input::{InputEvent, KeyAction, MouseButton};
use directdesk_shared::netsim::Endpoint;
use directdesk_shared::protocol::{decode_strict, encode_framed, ControlMsg, InputMsg};
use directdesk_shared::stats::{ConnStats, TransportRoute};
use directdesk_shared::traits::{Decoder, NullDecoder};
use directdesk_shared::transport::reassembly::{is_newer, Reassembler, ReassemblyStats};
use directdesk_shared::video::{EncodedFrame, FragHeader};

use crate::config::{SimConfig, STREAM_CONTROL_C2H, STREAM_CONTROL_H2C, STREAM_FALLBACK_H2C, STREAM_INPUT};
use crate::event::{Route, SimEvent};
use crate::frames::verify_payload;
use crate::framing::{decode_frame_record, FramedReader, MuxClass, MuxReader};
use crate::pump::PumpCtx;

/// What is currently on screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentSlot {
    /// Encoder-assigned id.
    pub frame_id: u32,
    /// Whether it was a keyframe.
    pub keyframe: bool,
    /// Whether the payload verified against its hash and its id.
    pub hash_ok: bool,
    /// Virtual millisecond it was presented.
    pub at_ms: u64,
    /// Capture-to-present latency.
    pub age_ms: u64,
    /// Path it arrived on.
    pub route: Route,
}

/// Fragment accounting for one loss-measurement window.
#[derive(Debug, Clone, Copy, Default)]
struct LossWindow {
    start_ms: u64,
    fragments: u64,
    oldest_id: Option<u32>,
    newest_id: Option<u32>,
    frag_count: u16,
}

impl LossWindow {
    fn record(&mut self, frame_id: u32, frag_count: u16) {
        self.fragments += 1;
        self.frag_count = frag_count;
        self.oldest_id = Some(self.oldest_id.map_or(frame_id, |o| o.min(frame_id)));
        self.newest_id = Some(self.newest_id.map_or(frame_id, |n| n.max(frame_id)));
    }

    /// Fragment loss fraction over the window, or `None` if nothing arrived.
    fn loss(&self) -> Option<f32> {
        let (oldest, newest) = (self.oldest_id?, self.newest_id?);
        let span = u64::from(newest - oldest) + 1;
        let expected = span * u64::from(self.frag_count.max(1));
        if expected == 0 {
            return None;
        }
        let received = self.fragments.min(expected);
        Some(1.0 - (received as f32 / expected as f32))
    }

    fn restart(&mut self, now_ms: u64) {
        *self = LossWindow {
            start_ms: now_ms,
            ..LossWindow::default()
        };
    }
}

/// The client side of a simulated session.
pub struct SimClient {
    cfg: SimConfig,
    reassembler: Reassembler,
    decoder: NullDecoder,
    control_reader: FramedReader,
    mux_reader: MuxReader,
    present: Option<PresentSlot>,
    route: Route,

    input_seq: u32,
    last_input_ms: Option<u64>,
    last_ping_ms: Option<u64>,
    next_ping_token: u64,
    pending_pings: Vec<(u64, u64)>,
    last_rtt_ms: Option<u64>,

    window: LossWindow,
    ever_received_datagram: bool,
    last_datagram_ms: Option<u64>,
    fallback_requested: bool,
}

impl std::fmt::Debug for SimClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimClient")
            .field("route", &self.route)
            .field("present", &self.present)
            .field("reassembly", &self.reassembler.stats())
            .field("last_rtt_ms", &self.last_rtt_ms)
            .field("inputs_sent", &self.input_seq)
            .finish()
    }
}

impl SimClient {
    /// A client wired for `cfg`.
    #[must_use]
    pub fn new(cfg: SimConfig) -> Self {
        Self {
            reassembler: Reassembler::new(cfg.reassembly),
            decoder: NullDecoder,
            control_reader: FramedReader::control(),
            mux_reader: MuxReader::new(),
            present: None,
            route: Route::Datagram,
            input_seq: 0,
            last_input_ms: None,
            last_ping_ms: None,
            next_ping_token: 1,
            pending_pings: Vec::new(),
            last_rtt_ms: None,
            window: LossWindow::default(),
            ever_received_datagram: false,
            last_datagram_ms: None,
            fallback_requested: false,
            cfg,
        }
    }

    /// What is on screen, if anything has been presented yet.
    #[must_use]
    pub fn present(&self) -> Option<&PresentSlot> {
        self.present.as_ref()
    }

    /// Counters from the real reassembler.
    #[must_use]
    pub fn reassembly_stats(&self) -> ReassemblyStats {
        self.reassembler.stats()
    }

    /// Which path the client believes video is taking.
    #[must_use]
    pub fn route(&self) -> Route {
        self.route
    }

    /// Number of input events written so far.
    #[must_use]
    pub fn inputs_sent(&self) -> u32 {
        self.input_seq
    }

    /// Most recent completed ping/pong measurement.
    #[must_use]
    pub fn last_rtt_ms(&self) -> Option<u64> {
        self.last_rtt_ms
    }

    /// Run one virtual tick.
    ///
    /// # Errors
    ///
    /// Propagates a transport or encoding failure. A datagram the reassembler
    /// refuses is *not* an error — it is logged and the session continues,
    /// which is the contract [`Reassembler::push`] documents.
    pub fn pump(&mut self, ctx: &mut PumpCtx<'_>) -> Result<()> {
        self.drain_control(ctx)?;
        self.drain_fallback(ctx)?;
        self.drain_datagrams(ctx)?;
        self.reassembler.tick(ctx.now_ms);
        self.present_ready(ctx)?;
        self.request_keyframe_if_needed(ctx)?;
        self.send_input(ctx)?;
        self.send_ping(ctx)?;
        self.close_idle_window(ctx)?;
        self.detect_blocked_datagrams(ctx)?;
        Ok(())
    }

    // -- video ---------------------------------------------------------------

    fn drain_datagrams(&mut self, ctx: &mut PumpCtx<'_>) -> Result<()> {
        while let Some(datagram) = ctx.net.recv_datagram(Endpoint::B) {
            self.ever_received_datagram = true;
            self.last_datagram_ms = Some(ctx.now_ms);
            if let Ok((header, _)) = FragHeader::decode(&datagram) {
                self.account_fragment(ctx, header.frame_id, header.frag_count)?;
            }
            match self.reassembler.push(&datagram, ctx.now_ms) {
                Ok(_) => {}
                Err(e) => ctx.log.push(SimEvent::DatagramRejected {
                    at_ms: ctx.now_ms,
                    reason: e.to_string(),
                }),
            }
        }
        Ok(())
    }

    fn present_ready(&mut self, ctx: &mut PumpCtx<'_>) -> Result<()> {
        while let Some(frame) = self.reassembler.pop_frame() {
            self.present_frame(ctx, &frame, Route::Datagram)?;
        }
        Ok(())
    }

    fn present_frame(
        &mut self,
        ctx: &mut PumpCtx<'_>,
        frame: &EncodedFrame,
        route: Route,
    ) -> Result<()> {
        // Latest wins at the slot, not just in the ready queue. This is now
        // defense-in-depth: the reassembler itself refuses to hand over a frame
        // older than one already delivered (counted in
        // `ReassemblyStats::frames_dropped_reorder`), so under normal operation
        // this branch never fires. It stays as a belt-and-suspenders guard in
        // case a consumer feeds frames from another source, since putting an
        // older frame on screen would be a visible jump backwards.
        if let Some(current) = &self.present {
            if !is_newer(frame.frame_id, current.frame_id) {
                ctx.log.push(SimEvent::FrameDiscardedStale {
                    at_ms: ctx.now_ms,
                    frame_id: frame.frame_id,
                    newest_presented: current.frame_id,
                });
                return Ok(());
            }
        }
        let decoded = self.decoder.decode(frame)?;
        let hash_ok = decoded
            .first()
            .is_some_and(|raw| verify_payload(frame.frame_id, &raw.data));
        let age_ms = ctx.now_ms.saturating_sub(u64::from(frame.timestamp_ms));
        self.present = Some(PresentSlot {
            frame_id: frame.frame_id,
            keyframe: frame.keyframe,
            hash_ok,
            at_ms: ctx.now_ms,
            age_ms,
            route,
        });
        ctx.log.push(SimEvent::FramePresented {
            at_ms: ctx.now_ms,
            frame_id: frame.frame_id,
            keyframe: frame.keyframe,
            hash_ok,
            age_ms,
            route,
        });
        Ok(())
    }

    /// Ask for a keyframe when the reassembler says the decoder has lost its
    /// reference.
    ///
    /// Only on the datagram path. Once video moves to the reliable stream the
    /// reassembler is no longer in the video path at all, and the demand raised
    /// by the reset at switchover would otherwise never be satisfied — the
    /// client would ask for a keyframe every rate-limit interval, for ever,
    /// against a link that is not losing anything. The host arms a keyframe
    /// itself when it engages the fallback, which is what actually re-anchors
    /// the decoder.
    fn request_keyframe_if_needed(&mut self, ctx: &mut PumpCtx<'_>) -> Result<()> {
        if self.route != Route::Datagram {
            return Ok(());
        }
        if self.reassembler.take_keyframe_request(ctx.now_ms) {
            self.send_control(ctx, &ControlMsg::RequestKeyframe)?;
            ctx.log.push(SimEvent::KeyframeRequested { at_ms: ctx.now_ms });
        }
        Ok(())
    }

    // -- reliable channels ---------------------------------------------------

    fn drain_control(&mut self, ctx: &mut PumpCtx<'_>) -> Result<()> {
        let bytes = ctx.net.recv_stream(Endpoint::B, STREAM_CONTROL_H2C);
        self.control_reader.push_bytes(&bytes);
        let messages = match self.control_reader.drain() {
            Ok(m) => m,
            Err(e) => {
                ctx.log.push(SimEvent::ControlRejected {
                    at_ms: ctx.now_ms,
                    reason: format!("control framing: {e}"),
                });
                return Ok(());
            }
        };
        for body in messages {
            match decode_strict::<ControlMsg>(&body) {
                Ok(msg) => self.on_control(ctx, msg),
                Err(e) => ctx.log.push(SimEvent::ControlRejected {
                    at_ms: ctx.now_ms,
                    reason: format!("control decode: {e}"),
                }),
            }
        }
        Ok(())
    }

    fn drain_fallback(&mut self, ctx: &mut PumpCtx<'_>) -> Result<()> {
        let bytes = ctx.net.recv_stream(Endpoint::B, STREAM_FALLBACK_H2C);
        if bytes.is_empty() && self.mux_reader.buffered() == 0 {
            return Ok(());
        }
        self.mux_reader.push_bytes(&bytes);
        let records = match self.mux_reader.drain() {
            Ok(r) => r,
            Err(e) => {
                ctx.log.push(SimEvent::ControlRejected {
                    at_ms: ctx.now_ms,
                    reason: format!("fallback framing: {e}"),
                });
                return Ok(());
            }
        };
        for record in records {
            ctx.log.push(SimEvent::MuxDelivered {
                at_ms: ctx.now_ms,
                class: record.class,
                seq: record.seq,
                enqueued_ms: record.enqueued_ms,
            });
            match record.class {
                MuxClass::Video => match decode_frame_record(&record.payload) {
                    Ok(frame) => self.present_frame(ctx, &frame, Route::Fallback)?,
                    Err(e) => ctx.log.push(SimEvent::ControlRejected {
                        at_ms: ctx.now_ms,
                        reason: format!("fallback video decode: {e}"),
                    }),
                },
                MuxClass::Control => match decode_strict::<ControlMsg>(&record.payload) {
                    Ok(msg) => self.on_control(ctx, msg),
                    Err(e) => ctx.log.push(SimEvent::ControlRejected {
                        at_ms: ctx.now_ms,
                        reason: format!("fallback control decode: {e}"),
                    }),
                },
                // The host's echo of an input event. Its only job is to put
                // latency-sensitive traffic in the video queue; the delivery
                // record in the log is the observation.
                MuxClass::Input => {}
            }
        }
        Ok(())
    }

    fn on_control(&mut self, ctx: &mut PumpCtx<'_>, msg: ControlMsg) {
        match msg {
            ControlMsg::Pong { token } => {
                if let Some(pos) = self.pending_pings.iter().position(|(t, _)| *t == token) {
                    let (_, sent_ms) = self.pending_pings.remove(pos);
                    let rtt = ctx.now_ms.saturating_sub(sent_ms);
                    self.last_rtt_ms = Some(rtt);
                    ctx.log.push(SimEvent::RttSampled {
                        at_ms: ctx.now_ms,
                        rtt_ms: rtt,
                    });
                }
            }
            ControlMsg::RouteReport(TransportRoute::DirectTcp)
                if self.route == Route::Datagram =>
            {
                self.route = Route::Fallback;
                // The path changed under the decoder; drop everything that
                // referenced the old one rather than present half a frame.
                self.reassembler.reset(ctx.now_ms);
                self.decoder.flush();
            }
            _ => {}
        }
    }

    fn send_control(&mut self, ctx: &mut PumpCtx<'_>, msg: &ControlMsg) -> Result<()> {
        let bytes = encode_framed(msg)?;
        ctx.net
            .send_stream(Endpoint::B, STREAM_CONTROL_C2H, &bytes)?;
        Ok(())
    }

    fn send_input(&mut self, ctx: &mut PumpCtx<'_>) -> Result<()> {
        let due = match self.last_input_ms {
            None => true,
            Some(last) => ctx.now_ms.saturating_sub(last) >= self.cfg.input_interval_ms,
        };
        if !due {
            return Ok(());
        }
        self.last_input_ms = Some(ctx.now_ms);
        let seq = self.input_seq;
        self.input_seq += 1;
        // The sequence number rides in `x`, so the host can report which event
        // it injected without the harness inventing a wire field.
        let event = InputEvent::MouseButton {
            button: MouseButton::Left,
            action: if seq.is_multiple_of(2) {
                KeyAction::Down
            } else {
                KeyAction::Up
            },
            x: seq as u16,
            y: 0,
        };
        let bytes = encode_framed(&InputMsg::Event(event))?;
        ctx.net.send_stream(Endpoint::B, STREAM_INPUT, &bytes)?;
        ctx.log.push(SimEvent::InputSent {
            at_ms: ctx.now_ms,
            seq,
        });
        Ok(())
    }

    fn send_ping(&mut self, ctx: &mut PumpCtx<'_>) -> Result<()> {
        let due = match self.last_ping_ms {
            None => true,
            Some(last) => ctx.now_ms.saturating_sub(last) >= self.cfg.ping_interval_ms,
        };
        if !due {
            return Ok(());
        }
        self.last_ping_ms = Some(ctx.now_ms);
        let token = self.next_ping_token;
        self.next_ping_token += 1;
        self.pending_pings.push((token, ctx.now_ms));
        // An unanswered ping is not a leak to grow forever; keep the recent few.
        if self.pending_pings.len() > 16 {
            self.pending_pings.remove(0);
        }
        self.send_control(ctx, &ControlMsg::Ping { token })
    }

    // -- loss feedback -------------------------------------------------------

    fn account_fragment(
        &mut self,
        ctx: &mut PumpCtx<'_>,
        frame_id: u32,
        frag_count: u16,
    ) -> Result<()> {
        let elapsed = ctx.now_ms.saturating_sub(self.window.start_ms);
        let boundary = self.window.newest_id.is_some_and(|n| n != frame_id);
        if elapsed >= self.cfg.stats_interval_ms && boundary {
            self.close_window(ctx)?;
        }
        self.window.record(frame_id, frag_count);
        Ok(())
    }

    fn close_window(&mut self, ctx: &mut PumpCtx<'_>) -> Result<()> {
        let loss = self.window.loss();
        self.window.restart(ctx.now_ms);
        if let Some(loss) = loss {
            self.report(ctx, loss)?;
        }
        Ok(())
    }

    /// A window in which *nothing* arrived never closes on a frame boundary,
    /// because there are no frames. Close it on time instead, so a link that
    /// has gone completely dark still reports total loss and the adaptor can
    /// react. Only meaningful once the datagram path has proved it works, and
    /// never once video has moved off it.
    fn close_idle_window(&mut self, ctx: &mut PumpCtx<'_>) -> Result<()> {
        if self.route == Route::Fallback || !self.ever_received_datagram {
            return Ok(());
        }
        if self.window.fragments > 0 {
            return Ok(());
        }
        if ctx.now_ms.saturating_sub(self.window.start_ms) < self.cfg.stats_interval_ms * 2 {
            return Ok(());
        }
        self.window.restart(ctx.now_ms);
        self.report(ctx, 1.0)
    }

    fn report(&mut self, ctx: &mut PumpCtx<'_>, loss: f32) -> Result<()> {
        let stats = ConnStats {
            rtt_ms: self.last_rtt_ms.unwrap_or(0) as f32,
            loss: loss.clamp(0.0, 1.0),
            ..ConnStats::default()
        };
        self.send_control(ctx, &ControlMsg::Stats(stats))
    }

    // -- transport fallback --------------------------------------------------

    /// Ask the host to move video onto the reliable path once the datagram path
    /// has been silent for a full probe window. A blocked-UDP network looks
    /// exactly like this: streams flow, datagrams never arrive.
    fn detect_blocked_datagrams(&mut self, ctx: &mut PumpCtx<'_>) -> Result<()> {
        if !self.cfg.fallback_enabled || self.fallback_requested || self.route == Route::Fallback {
            return Ok(());
        }
        let silent_for = match self.last_datagram_ms {
            Some(last) => ctx.now_ms.saturating_sub(last),
            None => ctx.now_ms,
        };
        if silent_for < self.cfg.fallback_probe_ms {
            return Ok(());
        }
        self.fallback_requested = true;
        self.send_control(ctx, &ControlMsg::RouteReport(TransportRoute::DirectTcp))?;
        ctx.log.push(SimEvent::FallbackRequested { at_ms: ctx.now_ms });
        Ok(())
    }
}
