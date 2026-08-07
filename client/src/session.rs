//! Session wiring: the single seam between the client UI/decode/render stack
//! and the (not yet written) transport wave.
//!
//! [`ClientSession::new`] creates both halves of every channel and hands back:
//!
//! * [`ClientSession`] — kept by the UI. Consumes inbound video/stats/route/
//!   control, produces outbound input/control.
//! * [`TransportEndpoints`] — handed to the transport. The mirror image.
//!
//! Channel technology is chosen per direction, deliberately:
//!
//! * **Inbound (transport → UI)** uses `crossbeam_channel`. The egui frame loop
//!   is a blocking thread with no tokio runtime in scope, so it must be able to
//!   `try_recv()` without an executor.
//! * **Outbound (UI → transport)** uses `tokio::sync::mpsc`. The transport is
//!   async and wants `.recv().await`. The UI (and the Win32 keyboard hook,
//!   which runs on the winit thread) only ever calls `try_send()`, which needs
//!   no runtime context and never blocks.
//!
//! Nothing here ever blocks the UI thread or the hook procedure.

use crossbeam_channel::{bounded, Receiver, Sender};
use directdesk_shared::protocol::{ControlMsg, InputMsg};
use directdesk_shared::stats::{ConnStats, TransportRoute};
use directdesk_shared::tiles::TileMsg;
use directdesk_shared::video::EncodedFrame;
use tokio::sync::mpsc;

/// Encoded frames buffered between transport and decoder. The decode thread
/// drains this eagerly and decodes **every** frame (P-frames reference their
/// predecessors); this depth only absorbs scheduling jitter, never policy.
pub const VIDEO_QUEUE_DEPTH: usize = 256;
/// Refinement tiles buffered between transport and the tile thread.
///
/// Deep enough to swallow the burst the host emits when a busy screen settles,
/// shallow enough that a wedged tile thread cannot grow an unbounded backlog:
/// a strip is capped at `MAX_STRIP_ENCODED` (~49 KiB worst case), so this depth
/// bounds the queue at a few MiB even if every message were incompressible.
/// Overflow is dropped, never awaited — see `net::forward_tiles`.
pub const TILE_QUEUE_DEPTH: usize = 256;
/// Outbound input events. Deep enough that a stalled transport cannot make the
/// UI thread block; overflow is dropped with a warning, never awaited.
pub const INPUT_QUEUE_DEPTH: usize = 4096;
/// Control-plane messages in either direction (low rate).
pub const CONTROL_QUEUE_DEPTH: usize = 256;
/// Stats / route / state updates (low rate).
pub const STATUS_QUEUE_DEPTH: usize = 64;

/// What the UI believes about the connection. Driven entirely by the transport
/// through [`TransportEndpoints::state_tx`] — the UI never invents a state.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ConnectionState {
    #[default]
    Disconnected,
    Connecting,
    Authenticating,
    Connected,
    Failed(String),
}

impl ConnectionState {
    pub fn label(&self) -> &str {
        match self {
            ConnectionState::Disconnected => "Disconnected",
            ConnectionState::Connecting => "Connecting…",
            ConnectionState::Authenticating => "Authenticating…",
            ConnectionState::Connected => "Connected",
            ConnectionState::Failed(reason) => reason,
        }
    }

    pub fn is_live(&self) -> bool {
        matches!(self, ConnectionState::Connected)
    }
}

/// UI-side channel endpoints.
pub struct ClientSession {
    /// Encoded frames from the host. Owned by the decode thread.
    pub video_rx: Receiver<EncodedFrame>,
    /// Periodic host stats (already `validate_stats`-checked by the transport).
    pub stats_rx: Receiver<ConnStats>,
    /// Active route. `None` means "not known / not connected" — the UI renders
    /// "—" for that and must never substitute a guess.
    pub route_rx: Receiver<Option<TransportRoute>>,
    /// Connection lifecycle.
    pub state_rx: Receiver<ConnectionState>,
    /// Inbound control messages (VideoConfig, ClipboardText, Bye, …).
    pub control_rx: Receiver<ControlMsg>,
    /// Outbound input. Keyboard hook + pointer mapping feed this.
    pub input_tx: mpsc::Sender<InputMsg>,
    /// Outbound control (StartStream, RequestKeyframe, QualityChange, …).
    pub control_tx: mpsc::Sender<ControlMsg>,

    /// Inbound lossless refinement tiles. Drained by the pipeline's tile
    /// thread, which is the only place a strip is decompressed.
    ///
    /// An ordinary inbound channel: the sending half rides in
    /// [`TransportEndpoints`] like every other one, and `net::run_client` only
    /// reads the stream when the host echoes `features::LOSSLESS_TILES`.
    pub tiles_rx: Receiver<TileMsg>,
}

/// Transport-side channel endpoints. The transport wave plugs into exactly
/// this struct and needs nothing else from the client.
pub struct TransportEndpoints {
    pub video_tx: Sender<EncodedFrame>,
    pub stats_tx: Sender<ConnStats>,
    pub route_tx: Sender<Option<TransportRoute>>,
    pub state_tx: Sender<ConnectionState>,
    pub control_tx: Sender<ControlMsg>,
    /// Refinement tiles, host -> UI. Bounded and lossy by design: a dropped
    /// tile only means that square keeps showing H.264 for another pass.
    pub tiles_tx: Sender<TileMsg>,
    pub input_rx: mpsc::Receiver<InputMsg>,
    pub control_rx: mpsc::Receiver<ControlMsg>,
}

impl ClientSession {
    /// Build both halves of the seam.
    pub fn new() -> (ClientSession, TransportEndpoints) {
        let (video_tx, video_rx) = bounded(VIDEO_QUEUE_DEPTH);
        let (stats_tx, stats_rx) = bounded(STATUS_QUEUE_DEPTH);
        let (route_tx, route_rx) = bounded(STATUS_QUEUE_DEPTH);
        let (state_tx, state_rx) = bounded(STATUS_QUEUE_DEPTH);
        let (ctl_in_tx, ctl_in_rx) = bounded(CONTROL_QUEUE_DEPTH);
        let (tiles_tx, tiles_rx) = bounded(TILE_QUEUE_DEPTH);
        let (input_tx, input_rx) = mpsc::channel(INPUT_QUEUE_DEPTH);
        let (ctl_out_tx, ctl_out_rx) = mpsc::channel(CONTROL_QUEUE_DEPTH);

        (
            ClientSession {
                video_rx,
                stats_rx,
                route_rx,
                state_rx,
                control_rx: ctl_in_rx,
                input_tx,
                control_tx: ctl_out_tx,
                tiles_rx,
            },
            TransportEndpoints {
                video_tx,
                stats_tx,
                route_tx,
                state_tx,
                control_tx: ctl_in_tx,
                tiles_tx,
                input_rx,
                control_rx: ctl_out_rx,
            },
        )
    }

    /// Non-blocking control send. Drops (with a warning) rather than ever
    /// stalling the frame loop.
    pub fn send_control(&self, msg: ControlMsg) {
        if let Err(e) = self.control_tx.try_send(msg) {
            tracing::warn!("control send dropped: {e}");
        }
    }
}

/// Fire-and-forget input send used by the UI *and* by the low-level keyboard
/// hook. Must stay allocation-free and lock-free on the hot path.
pub fn send_input(tx: &mpsc::Sender<InputMsg>, msg: InputMsg) -> bool {
    match tx.try_send(msg) {
        Ok(()) => true,
        Err(mpsc::error::TrySendError::Full(_)) => {
            tracing::warn!("input queue full — event dropped");
            false
        }
        Err(mpsc::error::TrySendError::Closed(_)) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use directdesk_shared::input::InputEvent;

    #[test]
    fn inbound_and_outbound_are_connected() {
        let (session, mut transport) = ClientSession::new();

        transport
            .video_tx
            .send(EncodedFrame {
                frame_id: 1,
                keyframe: true,
                timestamp_ms: 5,
                data: vec![9],
            })
            .unwrap();
        assert_eq!(session.video_rx.try_recv().unwrap().frame_id, 1);

        transport
            .route_tx
            .send(Some(TransportRoute::Relayed))
            .unwrap();
        assert_eq!(
            session.route_rx.try_recv().unwrap(),
            Some(TransportRoute::Relayed)
        );

        assert!(send_input(&session.input_tx, InputMsg::ReleaseAll));
        assert!(matches!(
            transport.input_rx.try_recv().unwrap(),
            InputMsg::ReleaseAll
        ));

        session.send_control(ControlMsg::RequestKeyframe);
        assert!(matches!(
            transport.control_rx.try_recv().unwrap(),
            ControlMsg::RequestKeyframe
        ));
    }

    #[test]
    fn route_none_is_representable() {
        // "unknown route" must be expressible so the UI can honestly show "—".
        let (session, transport) = ClientSession::new();
        transport.route_tx.send(None).unwrap();
        assert_eq!(session.route_rx.try_recv().unwrap(), None);
    }

    #[test]
    fn input_send_never_blocks_when_full() {
        let (session, _transport) = ClientSession::new();
        for _ in 0..INPUT_QUEUE_DEPTH {
            assert!(send_input(
                &session.input_tx,
                InputMsg::Event(InputEvent::MouseMove { x: 0, y: 0 })
            ));
        }
        // Queue is now full: the next send returns false immediately.
        assert!(!send_input(&session.input_tx, InputMsg::ReleaseAll));
    }

    #[test]
    fn tile_channel_round_trips_and_drops_when_full() {
        let (session, transport) = ClientSession::new();
        transport
            .tiles_tx
            .try_send(TileMsg::Reset {
                width: 1920,
                height: 1080,
                edge: 64,
            })
            .unwrap();
        assert!(matches!(
            session.tiles_rx.try_recv().unwrap(),
            TileMsg::Reset {
                width: 1920,
                height: 1080,
                edge: 64
            }
        ));

        // Overflow must be reported, never awaited: the transport drops the
        // message rather than let a stalled tile thread back-pressure QUIC.
        for _ in 0..TILE_QUEUE_DEPTH {
            transport
                .tiles_tx
                .try_send(TileMsg::Revoke { ids: vec![0] })
                .unwrap();
        }
        assert!(transport
            .tiles_tx
            .try_send(TileMsg::Revoke { ids: vec![1] })
            .is_err());
    }

    #[test]
    fn state_labels_are_readable() {
        assert!(ConnectionState::Connected.is_live());
        assert!(!ConnectionState::Connecting.is_live());
        assert_eq!(ConnectionState::Failed("nope".into()).label(), "nope");
    }
}
