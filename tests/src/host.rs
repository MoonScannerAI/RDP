//! The simulated host core: capture → encode → fragment → send, plus the
//! reliable channels for input injection and session control.
//!
//! This is the shape a real host agent has, with the platform pieces replaced
//! by the null implementations `directdesk-shared` already ships: a synthetic
//! frame source instead of DDA, [`NullEncoder`] instead of the Media Foundation
//! MFT, [`MockInjector`] instead of `SendInput`. Everything else — the
//! fragmenter, the adaptor, the wire framing — is the production code path.
//!
//! Two send paths exist. Normally frames go out as datagrams via
//! [`fragment_frame`]. When the client reports the datagram path dead, video
//! moves onto [`ReliableMux`] and shares one ordered byte stream with control
//! and input, which is the shape M4's TCP fallback will have.

use directdesk_shared::adapt::{AdaptConfig, BitrateAdaptor};
use directdesk_shared::error::Result;
use directdesk_shared::input::{validate_event, InputEvent};
use directdesk_shared::netsim::Endpoint;
use directdesk_shared::protocol::{
    decode_strict, encode_framed, ControlMsg, InputMsg, QualityMode, MAX_CONTROL_MSG,
};
use directdesk_shared::stats::{validate_stats, TransportRoute};
use directdesk_shared::traits::{Encoder, InputInjector, MockInjector, NullEncoder, PixelFormat, RawFrame};
use directdesk_shared::video::fragment_frame;

use crate::config::{SimConfig, STREAM_CONTROL_C2H, STREAM_CONTROL_H2C, STREAM_FALLBACK_H2C, STREAM_INPUT};
use crate::event::{Route, SimEvent};
use crate::frames::synth_payload;
use crate::framing::{encode_frame_record, strip_length_prefix, FramedReader, MuxClass};
use crate::mux::{MuxConfig, MuxStats, ReliableMux};
use crate::pump::PumpCtx;

/// The host side of a simulated session.
pub struct SimHost {
    cfg: SimConfig,
    encoder: NullEncoder,
    injector: MockInjector,
    adaptor: BitrateAdaptor,
    input_reader: FramedReader,
    control_reader: FramedReader,
    mux: ReliableMux,
    route: Route,
    frames_captured: u64,
    last_capture_ms: Option<u64>,
    bitrate_kbps: u32,
}

// The shared null components deliberately do not implement `Debug`, so the
// interesting state is spelled out by hand rather than dropped entirely.
impl std::fmt::Debug for SimHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimHost")
            .field("route", &self.route)
            .field("frames_captured", &self.frames_captured)
            .field("last_capture_ms", &self.last_capture_ms)
            .field("bitrate_kbps", &self.bitrate_kbps)
            .field("injected", &self.injector.events.len())
            .field("mux", &self.mux.stats())
            .finish()
    }
}

impl SimHost {
    /// A host wired for `cfg`, with the encoder armed for an opening keyframe
    /// (that is [`NullEncoder`]'s initial state, matching a real encoder's IDR
    /// at stream start).
    #[must_use]
    pub fn new(cfg: SimConfig) -> Self {
        let adapt_cfg = AdaptConfig::for_mode(cfg.quality);
        let mux = ReliableMux::new(MuxConfig::new(
            STREAM_FALLBACK_H2C,
            cfg.mux_bytes_per_tick,
            cfg.mux_max_video_backlog,
        ));
        Self {
            encoder: NullEncoder::new(),
            injector: MockInjector::default(),
            adaptor: BitrateAdaptor::new(adapt_cfg),
            input_reader: FramedReader::control(),
            control_reader: FramedReader::control(),
            mux,
            route: Route::Datagram,
            frames_captured: 0,
            last_capture_ms: None,
            bitrate_kbps: adapt_cfg.start_kbps,
            cfg,
        }
    }

    /// Input events the mock injector has accepted, in injection order.
    #[must_use]
    pub fn injected(&self) -> &[InputEvent] {
        &self.injector.events
    }

    /// Which path video is currently taking.
    #[must_use]
    pub fn route(&self) -> Route {
        self.route
    }

    /// The adaptor's current target bitrate.
    #[must_use]
    pub fn bitrate_kbps(&self) -> u32 {
        self.bitrate_kbps
    }

    /// Frames the synthetic source has produced.
    #[must_use]
    pub fn frames_captured(&self) -> u64 {
        self.frames_captured
    }

    /// Counters from the fallback mux.
    #[must_use]
    pub fn mux_stats(&self) -> MuxStats {
        self.mux.stats()
    }

    /// The quality mode in force.
    #[must_use]
    pub fn quality(&self) -> QualityMode {
        self.cfg.quality
    }

    /// Run one virtual tick: drain the reliable channels, capture and send if
    /// the frame interval has elapsed, then service the fallback mux.
    ///
    /// # Errors
    ///
    /// Propagates a fragmenter or transport failure. Malformed peer input is
    /// *not* an error: it is logged and the session continues, because a
    /// corrupt message must never be able to kill a host.
    pub fn pump(&mut self, ctx: &mut PumpCtx<'_>) -> Result<()> {
        self.drain_input(ctx);
        self.drain_control(ctx)?;
        self.capture_and_send(ctx)?;
        if self.route == Route::Fallback {
            self.mux.pump(ctx, Endpoint::A)?;
        }
        Ok(())
    }

    // -- reliable channels ---------------------------------------------------

    fn drain_input(&mut self, ctx: &mut PumpCtx<'_>) {
        let bytes = ctx.net.recv_stream(Endpoint::A, STREAM_INPUT);
        self.input_reader.push_bytes(&bytes);
        let messages = match self.input_reader.drain() {
            Ok(m) => m,
            Err(e) => {
                ctx.log.push(SimEvent::ControlRejected {
                    at_ms: ctx.now_ms,
                    reason: format!("input framing: {e}"),
                });
                return;
            }
        };
        for body in messages {
            match decode_strict::<InputMsg>(&body) {
                Ok(InputMsg::Event(ev)) => self.inject(ctx, ev),
                Ok(InputMsg::ReleaseAll) => {}
                Err(e) => ctx.log.push(SimEvent::ControlRejected {
                    at_ms: ctx.now_ms,
                    reason: format!("input decode: {e}"),
                }),
            }
        }
    }

    fn inject(&mut self, ctx: &mut PumpCtx<'_>, ev: InputEvent) {
        if let Err(e) = validate_event(&ev) {
            ctx.log.push(SimEvent::ControlRejected {
                at_ms: ctx.now_ms,
                reason: format!("input validation: {e}"),
            });
            return;
        }
        if self.injector.inject(&ev).is_err() {
            return;
        }
        ctx.log.push(SimEvent::InputInjected {
            at_ms: ctx.now_ms,
            seq: input_seq(&ev),
        });
        // On the fallback path the input channel shares the video connection.
        // Echoing the event back as an Input-class record is what puts
        // latency-sensitive traffic into the same queue as the video backlog,
        // which is the thing the priority policy has to survive.
        if self.route == Route::Fallback {
            if let Ok(body) = encode_framed(&InputMsg::Event(ev)).and_then(|f| mux_payload(&f)) {
                self.mux.enqueue(MuxClass::Input, body, None, ctx.now_ms);
            }
        }
    }

    fn drain_control(&mut self, ctx: &mut PumpCtx<'_>) -> Result<()> {
        let bytes = ctx.net.recv_stream(Endpoint::A, STREAM_CONTROL_C2H);
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
                Ok(msg) => self.on_control(ctx, msg)?,
                Err(e) => ctx.log.push(SimEvent::ControlRejected {
                    at_ms: ctx.now_ms,
                    reason: format!("control decode: {e}"),
                }),
            }
        }
        Ok(())
    }

    fn on_control(&mut self, ctx: &mut PumpCtx<'_>, msg: ControlMsg) -> Result<()> {
        match msg {
            ControlMsg::RequestKeyframe => {
                self.encoder.request_keyframe();
                ctx.log.push(SimEvent::KeyframeHonored { at_ms: ctx.now_ms });
            }
            ControlMsg::Ping { token } => {
                self.send_control(ctx, &ControlMsg::Pong { token })?;
            }
            ControlMsg::Stats(stats) => {
                if !validate_stats(&stats) {
                    ctx.log.push(SimEvent::ControlRejected {
                        at_ms: ctx.now_ms,
                        reason: "implausible peer stats".into(),
                    });
                    return Ok(());
                }
                ctx.log.push(SimEvent::LossReported {
                    at_ms: ctx.now_ms,
                    loss: stats.loss,
                });
                if let Some(kbps) = self.adaptor.observe(ctx.now_ms, stats.loss, stats.rtt_ms) {
                    self.bitrate_kbps = kbps;
                    self.encoder.set_bitrate(kbps)?;
                    ctx.log.push(SimEvent::BitrateChanged {
                        at_ms: ctx.now_ms,
                        kbps,
                    });
                }
            }
            ControlMsg::RouteReport(TransportRoute::DirectTcp)
                if self.route == Route::Datagram =>
            {
                self.engage_fallback(ctx)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Move video onto the reliable multiplexed stream.
    ///
    /// The acknowledgement goes out *before* the flip so it travels on the
    /// pre-existing control stream, which the client is already reading; the
    /// encoder is then armed for a keyframe, because the decoder has no usable
    /// reference after a path change.
    fn engage_fallback(&mut self, ctx: &mut PumpCtx<'_>) -> Result<()> {
        self.send_control(ctx, &ControlMsg::RouteReport(TransportRoute::DirectTcp))?;
        self.route = Route::Fallback;
        self.encoder.request_keyframe();
        ctx.log.push(SimEvent::FallbackEngaged { at_ms: ctx.now_ms });
        Ok(())
    }

    fn send_control(&mut self, ctx: &mut PumpCtx<'_>, msg: &ControlMsg) -> Result<()> {
        match self.route {
            Route::Datagram => {
                let bytes = encode_framed(msg)?;
                ctx.net
                    .send_stream(Endpoint::A, STREAM_CONTROL_H2C, &bytes)?;
            }
            Route::Fallback => {
                let body = mux_payload(&encode_framed(msg)?)?;
                self.mux.enqueue(MuxClass::Control, body, None, ctx.now_ms);
            }
        }
        Ok(())
    }

    // -- video ---------------------------------------------------------------

    fn capture_and_send(&mut self, ctx: &mut PumpCtx<'_>) -> Result<()> {
        let due = match self.last_capture_ms {
            None => true,
            Some(last) => ctx.now_ms.saturating_sub(last) >= self.cfg.frame_interval_ms,
        };
        if !due {
            return Ok(());
        }
        self.last_capture_ms = Some(ctx.now_ms);

        // `NullEncoder` numbers frames from 1 in capture order, so the content
        // can be bound to the id the encoder is about to assign. If that ever
        // stops holding, every frame fails the client's hash check — a loud
        // failure, not a silent one.
        let next_id = (self.frames_captured + 1) as u32;
        let raw = RawFrame {
            width: 1_920,
            height: 1_080,
            format: PixelFormat::Bgra8,
            data: synth_payload(next_id, self.cfg.frame_bytes),
            timestamp_ms: ctx.now_ms as u32,
        };
        self.frames_captured += 1;

        let Some(encoded) = self.encoder.encode(&raw)? else {
            return Ok(());
        };
        ctx.log.push(SimEvent::FrameCaptured {
            at_ms: ctx.now_ms,
            frame_id: encoded.frame_id,
            keyframe: encoded.keyframe,
            bytes: encoded.data.len(),
        });

        match self.route {
            Route::Datagram => {
                let mtu = ctx.net.params().mtu;
                let fragments = fragment_frame(&encoded, mtu)?;
                for fragment in &fragments {
                    ctx.net.send_datagram(Endpoint::A, fragment.clone())?;
                }
                ctx.log.push(SimEvent::FrameSent {
                    at_ms: ctx.now_ms,
                    frame_id: encoded.frame_id,
                    keyframe: encoded.keyframe,
                    fragments: fragments.len(),
                    route: Route::Datagram,
                });
            }
            Route::Fallback => {
                self.mux.enqueue(
                    MuxClass::Video,
                    encode_frame_record(&encoded),
                    Some(encoded.frame_id),
                    ctx.now_ms,
                );
                ctx.log.push(SimEvent::FrameSent {
                    at_ms: ctx.now_ms,
                    frame_id: encoded.frame_id,
                    keyframe: encoded.keyframe,
                    fragments: 1,
                    route: Route::Fallback,
                });
            }
        }
        Ok(())
    }
}

/// Strip the redundant length prefix off an already-framed message so it can
/// ride the mux, whose record header carries the length itself.
fn mux_payload(framed: &[u8]) -> Result<Vec<u8>> {
    strip_length_prefix(framed, MAX_CONTROL_MSG)
}

/// The sequence number the harness encodes in an input event's `x` field.
#[must_use]
pub fn input_seq(ev: &InputEvent) -> u32 {
    match ev {
        InputEvent::MouseButton { x, .. }
        | InputEvent::MouseMove { x, .. }
        | InputEvent::MouseWheel { x, .. } => u32::from(*x),
        InputEvent::Key { scan_code, .. } => u32::from(*scan_code),
    }
}
