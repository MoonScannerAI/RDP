//! The live session: everything an authenticated client gets, from the media
//! pipeline coming up to the last held key being released.
//!
//! [`run_session`] is the orchestrator. It brings the pipeline up, arms the
//! guards that have to fire on *every* exit path, spawns the four loops below
//! alongside the two pumps in [`super::egress`], and then does nothing at all
//! until the connection closes. The loops are deliberately small and
//! single-purpose: `input_loop` injects, `control_loop` answers the client,
//! `status_loop` measures one window and hands the result to the adaptor, and
//! `event_loop` relays driver events.
//!
//! The order of the local bindings in [`run_session`] is load-bearing, and the
//! reasons are written at the bindings themselves. Rust drops locals in reverse
//! declaration order, so moving one line silently changes what happens at
//! session end — and binding a guard to a bare `_` drops it immediately instead
//! of at scope end, which for [`ReleaseGuard`] would mean client-held input is
//! never released.
//!
//! What belongs here: session-scoped orchestration, and the loops that live for
//! exactly one client.
//!
//! What does not: how bytes reach the wire is [`super::egress`], *how much* to
//! send is decided in [`super::adaptation`], the UAC click-through is
//! [`super::elevation`], and getting as far as `AuthOk` is
//! [`super::handshake`]. The counters these loops read and reset stay in
//! [`crate::net`], because the pumps in [`super::egress`] write them.

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crossbeam_channel::Sender as CbSender;
use parking_lot::Mutex;
use quinn::Connection;
use tokio::sync::mpsc;

use directdesk_shared::adapt::{AdaptConfig, BitrateAdaptor};
use directdesk_shared::input::{validate_event, InputEvent};
use directdesk_shared::protocol::{
    features, Codec, ControlMsg, InputMsg, MonitorInfo, MAX_VIDEO_STREAMS,
};
use directdesk_shared::stats::ConnStats;
use directdesk_shared::transport::quic::{self, SessionStreams};
use directdesk_shared::transport::session::{
    QuicSession, Session, SessionConfig as DriverConfig, SessionEvent,
};
use directdesk_shared::{Error, Result};

use crate::capture::{MonitorKey, MonitorSelector};
use crate::session::{HostSession, SessionConfig as PipelineConfig, SessionState};

use super::adaptation::{
    clamp_to_cap, effective_cap, effective_fps, overrun_signal, split_bitrate, window_congestion,
    RateLimiter, StatusWindow, TileThrottle, WindowDelivery, STATUS_INTERVAL_MS,
};
use super::audio::{audio_pump, AudioTxConfig};
use super::egress::{tile_pump, video_pump};
use super::elevation::elevation_loop;
use super::{
    AudioCounters, AudioStatus, Inner, NetEvent, SecondaryStreamStatus, TileCounters,
    VideoCounters, CLOSE_CODE_REJECTED, HOST_ROUTE,
};

/// Floor on how often a *client's* `RequestKeyframe` is honoured. The client
/// only asks when its own decoder is stuck (a frame-id gap), and it rate-limits
/// itself; gating that a second time at 500 ms is what made recovery from a
/// scene-change stall take up to 1.5 s on a high-RTT link.
pub const CLIENT_KEYFRAME_MIN_INTERVAL_MS: u64 = 200;

/// How long a selected monitor may be missing from the desktop *and* its
/// encoder stalled before its stream is torn down.
///
/// Generous on purpose. A duplication is invalidated — and the output briefly
/// vanishes from the enumeration — by a mode change, a GPU switch, a fullscreen
/// app taking over, and by the display waking from sleep, none of which mean
/// the monitor is gone. Reaping on the first tick that missed it would turn
/// every one of those into a `StreamStopped` the client cannot recover from
/// without asking again. Five seconds is far longer than any of them and far
/// shorter than a user's patience with a dead panel.
const MONITOR_REAP_MS: u64 = 5_000;

// ---------------------------------------------------------------------------
// Stream slots
// ---------------------------------------------------------------------------
//
// A session carries between one and `MAX_VIDEO_STREAMS` video streams. Slot 0
// is the one every client has always received and is never empty for long; slot
// 1 exists only while a client has asked for a second monitor.
//
// The state is split across two locks on purpose, and the split is the whole
// reason this is not one struct:
//
// * [`StreamSlots`] is behind a **tokio** mutex. It owns the pipelines and the
//   pump threads, and its methods hold the guard across the multi-second
//   `spawn_blocking` that brings D3D11 and Media Foundation up for a new
//   monitor. Only the two loops that reconfigure streams ever take it.
// * The [`SlotHandle`] view is behind a **parking_lot** mutex and is republished
//   after every change. Input injection takes it once per event and the bitrate
//   split takes it once per status tick; neither may ever queue behind a
//   pipeline build, and a keystroke arriving 4 seconds late because the user
//   opened a second monitor is exactly the bug this split prevents.

/// What a stream slot looks like to the hot paths: enough to inject an event,
/// read geometry, and ask for a keyframe. Cheap to clone.
#[derive(Clone)]
struct SlotHandle {
    /// Id of the monitor this slot carries, in this session's `MonitorList`.
    monitor_id: u8,
    session: Arc<HostSession>,
    input: CbSender<InputEvent>,
}

/// The published view. Index = stream id; `None` = that stream is not running.
type SlotView = Arc<Mutex<Vec<Option<SlotHandle>>>>;

/// Everything one running stream needs to be steered and stopped.
struct StreamSlot {
    monitor_id: u8,
    /// `None` when this slot *is* the persistent primary pipeline — the
    /// singleton in [`Inner::pipeline`] that outlives every client, selects its
    /// output with [`MonitorSelector::Primary`], and must never be dropped with
    /// a session. `Some` for a session-scoped pipeline, which must.
    key: Option<MonitorKey>,
    session: Arc<HostSession>,
    pump: Option<std::thread::JoinHandle<()>>,
    /// This slot's own stop flag, **not** the session-wide one: a slot can be
    /// retargeted at a different monitor while audio, refinement tiles and the
    /// elevation loop carry on untouched.
    pump_stop: Arc<AtomicBool>,
    /// The encoder's frame count at the last topology tick, and when it stopped
    /// advancing. See [`StreamSlots::watch_topology`] for why this — and not
    /// [`SessionState`] — is the liveness signal.
    last_frames: u64,
    stalled_since: Option<u64>,
}

/// One session's video streams, and the reconciler that keeps them matching
/// what the client asked for.
struct StreamSlots {
    /// The negotiated `MULTI_MONITOR` bit.
    ///
    /// This is the gate the whole feature's rollout safety rests on. With it
    /// clear, this struct still runs — slot 0 is built and pumped exactly as it
    /// always was — but [`StreamSlots::send`] drops every message on the floor,
    /// no `SelectMonitors` is honoured, and no second pipeline is ever built.
    /// The wire is then byte-identical to a host that predates the feature.
    enabled: bool,
    conn: Connection,
    session: Arc<QuicSession>,
    /// Id -> (info, key) for this session, in `MonitorList` order. Rebuilt by
    /// the topology watchdog; ids are only meaningful within this session.
    monitors: Vec<(MonitorInfo, MonitorKey)>,
    slots: Vec<Option<StreamSlot>>,
    /// One per slot index, created once per session so a slot's lifetime
    /// totals survive being retargeted at a different monitor. Read (and the
    /// oversized-keyframe latch cleared) by `status_loop`.
    counters: Vec<Arc<VideoCounters>>,
    /// How many video pumps are alive. Read by every producer on the datagram
    /// path — both video pumps and the audio sender — to size the headroom it
    /// must leave the others. See [`super::egress::video_reserve`].
    active: Arc<AtomicU8>,
    view: SlotView,
    streaming: Arc<AtomicBool>,
    /// Template for a session-scoped pipeline: the host's own pipeline config
    /// with the monitor and the refinement flag overridden per slot.
    base_cfg: PipelineConfig,
}

/// One step of the reconciler's plan. See [`plan_slot_changes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotChange {
    /// Tear this slot down: stop and join its pump, and drop its pipeline
    /// unless it is the persistent primary one.
    Stop { slot: u8 },
    /// Bring this slot up on `monitor`.
    Start { slot: u8, monitor: u8 },
}

/// What one [`StreamSlots::reconcile`] pass left behind, for the caller that has
/// to tell the client about it.
///
/// Two variants rather than a `bool` and a vector, because the invariant between
/// them is the one that was got wrong: a fresh `VideoConfig` may only be built
/// from the split that this very pass applied. Carrying the split *inside* the
/// variant that permits the message makes reaching for the adaptor's total
/// instead a thing that does not compile.
enum Reconciled {
    /// The plan was empty — the client re-sent a selection it already has.
    /// Nothing was built, nothing was re-split, and nothing is said back.
    Unchanged,
    /// Streams changed.
    Changed {
        /// Slot 0's monitor changed, which the caller answers with a fresh
        /// legacy `VideoConfig`: a client that only understands one stream still
        /// has to be told the picture's dimensions moved.
        slot0_changed: bool,
        /// The re-split done after the last stream came up. Every rate the
        /// caller quotes comes out of this. See [`AppliedBitrate`].
        bitrate: AppliedBitrate,
    },
}

/// The key identifying the output a pipeline is **actually** duplicating.
///
/// Derived from the pipeline's own description rather than from the selector it
/// was built with, because the two can disagree: `MonitorSelector::Primary` is
/// resolved once at construction and the pipeline stays on that output for its
/// whole life, however the desktop is rearranged afterwards.
fn pipeline_key(session: &HostSession) -> MonitorKey {
    let d = session.describe();
    MonitorKey {
        adapter_luid: d.adapter_luid,
        device_name: d.output,
        origin: d.monitor_origin,
    }
}

/// The id, in one session's monitor table, of the output `key` names.
///
/// The single place the key -> id mapping lives, because two callers have to
/// agree on it exactly: [`StreamSlots::persistent_monitor_id`] asks it what the
/// persistent pipeline is really showing, and the topology watchdog asks it the
/// same question for every slot once an enumeration has renumbered the list.
/// Two answers to that question is the bug this function exists to make
/// impossible.
///
/// `None` means the output is not in the table — unplugged, or riding out the
/// mode change that made the topology interesting in the first place.
fn monitor_id_for_key(monitors: &[(MonitorInfo, MonitorKey)], key: &MonitorKey) -> Option<u8> {
    monitors.iter().find(|(_, k)| k == key).map(|(i, _)| i.id)
}

/// Turn a client's raw `SelectMonitors` list into the slot assignment the host
/// will actually run.
///
/// `known` is the set of monitor ids in this session's `MonitorList`. The list
/// comes off the wire, so every step here is a defence:
///
/// * **unknown ids are dropped**, not clamped — an id the host never advertised
///   names no output, and guessing which one was meant would point a stream at
///   the wrong desktop;
/// * **duplicates are dropped**, first occurrence winning, because two slots
///   duplicating one output means two DXGI duplications of the same monitor;
/// * **the list is truncated** to [`MAX_VIDEO_STREAMS`] — *after* the two
///   filters above, and preferring the resident monitor (next paragraph);
/// * **the persistent pipeline's own monitor, when selected, is moved to
///   slot 0** — `resident` is that monitor's id, from
///   [`StreamSlots::persistent_monitor_id`].
///
/// # Truncation keeps the resident monitor
///
/// Not "keep the first `MAX_VIDEO_STREAMS`". `SelectMonitors { [1, 2, 0] }` on a
/// two-stream host whose persistent pipeline is on monitor 0 would, under that
/// rule, run monitors 1 and 2: two brand-new Desktop Duplications, while the
/// persistent pipeline goes on duplicating monitor 0 for nobody at all. Three
/// duplications, one of them pure waste, and the client has lost the one monitor
/// that was free — slot 0 re-attaches that pipeline rather than building
/// anything (see [`StreamSlots::build`]).
///
/// So the rule is: **when the list is too long and the requester named the
/// resident monitor anywhere in it, the resident is kept and the last of the ids
/// that fitted gives way to it.** The requester's order is priority order and is
/// preserved among the survivors — the ids are still ordered slots per the wire
/// contract, and the resident, named later than everything it displaced, takes
/// the last kept slot before the slot-0 rule below moves it to the front. A
/// request that does *not* name the resident is truncated plainly: the client
/// has said it wants neither the free monitor nor slot 0's cheap attach, and
/// second-guessing that would hand it a monitor it did not ask for.
///
/// The slot-0 rule is the one deviation here from a literal reading of the
/// client's request. The persistent pipeline is never stopped — it outlives
/// every client so the next one does not wait for D3D11 and Media Foundation —
/// so its output is the one monitor that is always already being duplicated,
/// and slot 0 is where re-attaching it costs nothing. Which slot carries which
/// monitor is told to the client explicitly (`StreamConfig` names both), so
/// honouring the selection while choosing the slot costs the client nothing.
///
/// Note `resident` is usually but *not always* 0: see
/// [`StreamSlots::persistent_monitor_id`]. `None` (its output is unplugged)
/// means no id is preferred and none gets moved.
///
/// An empty result means "nothing the client asked for exists here"; the caller
/// keeps the current selection rather than tearing every stream down.
fn filter_selection(ids: &[u8], known: &[u8], resident: Option<u8>) -> Vec<u8> {
    let n = MAX_VIDEO_STREAMS as usize;
    // Dedup and drop the unknowns over the WHOLE request first. Truncating
    // before this step would let ids the host was never going to run — a stale
    // list's ghosts, a repeat — decide which real monitors survive.
    let mut out: Vec<u8> = Vec::with_capacity(ids.len());
    for id in ids {
        if known.contains(id) && !out.contains(id) {
            out.push(*id);
        }
    }
    if out.len() > n {
        // `out` has no duplicates, so "named but did not fit" is exactly
        // "present in the tail that is about to be cut".
        let rescue = resident.filter(|r| out[n..].contains(r));
        out.truncate(n);
        if let Some(r) = rescue {
            out[n - 1] = r;
        }
    }
    // The already-resident monitor belongs to slot 0. See the doc comment.
    if let Some(pos) = resident.and_then(|r| out.iter().position(|id| *id == r)) {
        out.swap(0, pos);
    }
    out
}

/// The changes that turn `current` into `desired`.
///
/// `current[i]` is the monitor slot `i` carries now (`None` = not running);
/// `desired[i]` is the monitor it should carry, and a `desired` shorter than
/// `current` means the trailing slots stop.
///
/// Two properties the reconciler depends on:
///
/// * **Idempotence.** A desired set equal to the current one produces an empty
///   plan, so a client re-sending its selection — which it does on reconnect,
///   and may do on any UI event — costs nothing and re-sends no `StreamConfig`.
/// * **Every stop precedes every start.** A monitor being handed from one slot
///   to another (or from a slot back to the persistent pipeline) must have its
///   duplication released before it is acquired again; DXGI will not hand the
///   same output to two duplications from the same process, and the failure is
///   an opaque `DXGI_ERROR_NOT_CURRENTLY_AVAILABLE` at the worst moment. A
///   slot whose monitor merely *changes* is therefore a stop plus a start, not
///   an in-place swap.
fn plan_slot_changes(current: &[Option<u8>], desired: &[u8]) -> Vec<SlotChange> {
    let n = MAX_VIDEO_STREAMS as usize;
    let mut plan = Vec::new();
    // Highest slot first, so a monitor moving down into a lower slot finds its
    // previous holder already gone.
    for slot in (0..n).rev() {
        let now = current.get(slot).copied().flatten();
        let want = desired.get(slot).copied();
        if now.is_some() && now != want {
            plan.push(SlotChange::Stop { slot: slot as u8 });
        }
    }
    for slot in 0..n {
        let now = current.get(slot).copied().flatten();
        let want = desired.get(slot).copied();
        if let Some(monitor) = want {
            if now != Some(monitor) {
                plan.push(SlotChange::Start {
                    slot: slot as u8,
                    monitor,
                });
            }
        }
    }
    plan
}

/// Fold every active pipeline's media statistics into the one [`ConnStats`] the
/// wire has room for.
///
/// [`ConnStats`] is pinned byte-for-byte by the anti-brick suite and is decoded
/// positionally by already-deployed peers, so a second monitor cannot add a
/// field to it — the whole session would fail on its first stats tick. The
/// numbers are therefore merged, and the merge rule is chosen per field to keep
/// each one meaning what a client already believes it means:
///
/// * **Summed** — `bitrate_kbps`, `frames_dropped`, `keyframes_requested`.
///   These are costs and losses; the client is reading "what is this session
///   spending / losing", and the answer is the total across its streams.
/// * **Stream 0's** — `fps_capture`, `fps_encode`. A rate cannot be summed
///   (60 + 60 is not 120 fps of anything) and averaging two monitors' rates
///   would report a number neither is running at. The primary's is the honest
///   one, and the second stream's own rate is reported host-side in
///   [`SecondaryStreamStatus`].
/// * **Maximum** — `pipeline_ms`. It is a latency, and the interesting latency
///   is the worst one: a client showing two monitors feels the slower.
fn merge_media_stats(primary: ConnStats, others: &[ConnStats]) -> ConnStats {
    let mut merged = primary;
    for s in others {
        merged.bitrate_kbps = merged.bitrate_kbps.saturating_add(s.bitrate_kbps);
        merged.frames_dropped = merged.frames_dropped.saturating_add(s.frames_dropped);
        merged.keyframes_requested = merged
            .keyframes_requested
            .saturating_add(s.keyframes_requested);
        merged.pipeline_ms = merged.pipeline_ms.max(s.pipeline_ms);
    }
    merged
}

impl StreamSlots {
    #[allow(clippy::too_many_arguments)]
    fn new(
        enabled: bool,
        conn: Connection,
        session: Arc<QuicSession>,
        monitors: Vec<(MonitorInfo, MonitorKey)>,
        streaming: Arc<AtomicBool>,
        base_cfg: PipelineConfig,
        counters: Vec<Arc<VideoCounters>>,
        view: SlotView,
    ) -> Self {
        let n = MAX_VIDEO_STREAMS as usize;
        Self {
            enabled,
            conn,
            session,
            monitors,
            slots: (0..n).map(|_| None).collect(),
            counters,
            active: Arc::new(AtomicU8::new(0)),
            view,
            streaming,
            base_cfg,
        }
    }

    /// Every wire message this feature introduces goes through here.
    ///
    /// The gate is code and not a comment because it is the thing the staged
    /// rollout is verified against: a legacy client, or a host with the config
    /// flag off, must produce the same bytes as a build that never heard of a
    /// second monitor. One place to check beats four call sites to audit.
    fn send(&self, msg: ControlMsg) {
        if !self.enabled {
            // Unreachable: nothing constructs these messages without first
            // checking the bit. Loud rather than a `debug_assert`, because the
            // correct response to reaching it is "the client never sees the
            // message", and a panic in a session task would instead take the
            // whole session down to avoid sending one control frame.
            tracing::error!(
                "a multi-monitor control message was built with the feature bit \
                 clear; dropping it rather than sending it to a peer that never \
                 asked for it"
            );
            return;
        }
        if let Err(e) = self.session.send_control(msg) {
            tracing::warn!("could not send a stream control message: {e}");
        }
    }

    /// The monitor each slot carries right now, for [`plan_slot_changes`].
    fn current(&self) -> Vec<Option<u8>> {
        self.slots
            .iter()
            .map(|s| s.as_ref().map(|s| s.monitor_id))
            .collect()
    }

    /// Ids in this session's `MonitorList`, for [`filter_selection`].
    fn known_ids(&self) -> Vec<u8> {
        self.monitors.iter().map(|(i, _)| i.id).collect()
    }

    fn monitor(&self, id: u8) -> Option<&(MonitorInfo, MonitorKey)> {
        self.monitors.iter().find(|(i, _)| i.id == id)
    }

    /// The id, in this session's list, of the monitor the persistent pipeline
    /// is **actually** duplicating — which is not reliably 0.
    ///
    /// `DdaCapture` resolves [`MonitorSelector::Primary`] once, in `new`, and
    /// stores the `IDXGIOutput1`; `recreate_duplication` re-duplicates that same
    /// stored output forever after. The persistent pipeline is therefore pinned
    /// to whichever output was primary when it first came up, and it outlives
    /// every client. `list_monitors` re-decides which output is primary on every
    /// call. An operator moving the primary display in Windows' display settings
    /// makes the two disagree, and everything that assumed "id 0 is the
    /// persistent pipeline" then does the wrong thing twice over: selecting id 0
    /// silently hands back a different monitor's picture, and selecting the
    /// pipeline's real output under its new id tries to build a *second*
    /// duplication of an output that pipeline still holds — the
    /// `DXGI_ERROR_NOT_CURRENTLY_AVAILABLE` this design exists to avoid.
    ///
    /// So it is asked, not assumed. `None` means the pipeline's output is not in
    /// the list at all (it was unplugged), in which case every id is free to be
    /// built session-scoped.
    fn persistent_monitor_id(&self, primary: &Arc<HostSession>) -> Option<u8> {
        monitor_id_for_key(&self.monitors, &pipeline_key(primary))
    }

    /// Republish the hot-path view and the live pump count.
    ///
    /// Called after *every* mutation, and deliberately the last thing each one
    /// does: until it runs, input is still being routed at the pipeline that
    /// was just torn down.
    fn publish(&self) {
        let handles: Vec<Option<SlotHandle>> = self
            .slots
            .iter()
            .map(|s| {
                s.as_ref().map(|s| SlotHandle {
                    monitor_id: s.monitor_id,
                    session: s.session.clone(),
                    input: s.session.input_sender(),
                })
            })
            .collect();
        let live = handles.iter().filter(|h| h.is_some()).count() as u8;
        *self.view.lock() = handles;
        // Stored after the view so a producer that reads a count of 2 is never
        // reading it before the second stream's pump exists.
        self.active.store(live, Ordering::Relaxed);
    }

    /// Install a pipeline in a slot and start its pump.
    async fn install(
        &mut self,
        slot: usize,
        monitor_id: u8,
        key: Option<MonitorKey>,
        session: Arc<HostSession>,
    ) {
        debug_assert!(
            slot < MAX_VIDEO_STREAMS as usize,
            "stream ids are encoded in one fragment-header flag bit; a third \
             stream would encode identically to stream 0 and interleave into \
             the peer's primary reassembler"
        );
        // Defence, not policy: `plan_slot_changes` guarantees a stop before
        // every start on the same slot, so this is unreachable. Reached anyway,
        // simply overwriting would leave an OS thread nobody holds a handle to,
        // fragmenting a dead pipeline's frames onto the wire under this slot's
        // stream id for the rest of the session — so it is stopped and *joined*
        // first. Doing that properly is the whole reason this function is
        // `async`.
        if self.slots[slot].is_some() {
            tracing::error!(
                stream = slot,
                "a video stream was installed over a running one; stopping the \
                 old one first (this is a reconciler bug)"
            );
            self.stop_slot(slot).await;
        }

        let pump_stop = Arc::new(AtomicBool::new(false));
        let pump = {
            let conn = self.conn.clone();
            let frames = session.frames();
            let pipeline = session.clone();
            let streaming = self.streaming.clone();
            let stop = pump_stop.clone();
            let counters = self.counters[slot].clone();
            let active = self.active.clone();
            let stream = slot as u8;
            // Slot 0 keeps the thread name every existing log line and profile
            // refers to; only the second stream's name is new.
            let name = if slot == 0 {
                "dd-video-tx".to_string()
            } else {
                format!("dd-video-tx-{slot}")
            };
            std::thread::Builder::new()
                .name(name)
                .spawn(move || {
                    video_pump(
                        conn, frames, pipeline, streaming, stop, counters, stream, active,
                    )
                })
                .ok()
        };
        if pump.is_none() {
            tracing::error!(stream = slot, "could not spawn the video sender thread");
        }
        self.slots[slot] = Some(StreamSlot {
            monitor_id,
            key,
            session,
            pump,
            pump_stop,
            last_frames: 0,
            stalled_since: None,
        });
        self.publish();
    }

    /// Stop a slot: release its input, stop and join its pump, and drop its
    /// pipeline unless it is the persistent primary one.
    ///
    /// The join and the drop both happen inside `spawn_blocking`. The pump can
    /// be inside a pacing sleep, and dropping the last `Arc<HostSession>` joins
    /// the `dd-media` and `dd-input` threads — neither is a wait that belongs on
    /// a runtime worker.
    ///
    /// # The order here is load-bearing
    ///
    /// The slot is not removed from the published view — and the live pump
    /// count with it — until the pump has actually been **joined**. Publishing
    /// first would be the obvious ordering and is wrong: the count is what every
    /// other producer on the datagram path sizes its reserve from, so dropping
    /// it to 1 while this pump is still paying out its last frame tells the
    /// surviving stream it has the buffer to itself. It does not, and quinn's
    /// answer to an over-offer is to evict the datagrams already queued. Holding
    /// the count high for the length of a join only ever over-reserves, which
    /// costs at most a frame; lowering it early corrupts one.
    async fn stop_slot(&mut self, slot: usize) {
        let Some(s) = self.slots.get(slot).and_then(Option::as_ref) else {
            return;
        };
        // Before anything else: a slot going away must not leave a key held on
        // the desktop it was injecting into.
        s.session.release_all_input();
        s.pump_stop.store(true, Ordering::SeqCst);

        let pump = self.slots[slot].as_mut().and_then(|s| s.pump.take());
        let _ = tokio::task::spawn_blocking(move || {
            if let Some(h) = pump {
                let _ = h.join();
            }
        })
        .await;

        // The pump is gone; now the slot can leave the view and the count can
        // come down.
        let Some(s) = self.slots[slot].take() else {
            return;
        };
        self.publish();

        let session = s.session;
        let monitor = s.monitor_id;
        // If this was the persistent pipeline, `Inner::pipeline` still holds an
        // `Arc` and this is a cheap refcount decrement. If it was
        // session-scoped, this is the last one and dropping it joins two more OS
        // threads that own COM objects.
        let _ = tokio::task::spawn_blocking(move || drop(session)).await;
        tracing::info!(stream = slot, monitor, "video stream stopped");
    }

    /// Bring `slot` up on `monitor`.
    ///
    /// Monitor 0 in slot 0 re-attaches the persistent pipeline rather than
    /// building anything: that pipeline is the singleton whose whole purpose is
    /// that a reconnecting client does not wait for D3D11 and Media Foundation.
    /// Everything else is session-scoped and dies with the session.
    async fn build(
        &mut self,
        slot: u8,
        monitor: u8,
        primary: &Arc<HostSession>,
        fps: u32,
    ) -> Result<()> {
        // Re-attach rather than build whenever the monitor asked for is the one
        // the persistent pipeline already holds — matched on the output it is
        // *really* duplicating, not on the id being 0. See
        // [`Self::persistent_monitor_id`] for why those differ.
        if Some(monitor) == self.persistent_monitor_id(primary) {
            self.install(slot as usize, monitor, None, primary.clone())
                .await;
            return Ok(());
        }
        let key = match self.monitor(monitor) {
            Some((_, key)) => key.clone(),
            None => {
                return Err(Error::Invalid(format!(
                    "monitor {monitor} is not in this session's list"
                )))
            }
        };

        let mut cfg = self.base_cfg.clone();
        cfg.target_fps = fps;
        cfg.monitor = MonitorSelector::Key(key.clone());
        // Lossless refinement belongs to the persistent pipeline and only to
        // it. The tile grid, the client's tile store and the refinement stream
        // are all sized and addressed against *one* geometry, opened once per
        // session for the primary; a second grid on a differently-sized desktop
        // would paint its strips over the wrong stream's pixels. Refinement for
        // a second monitor is its own milestone, and claiming it here by
        // inheriting the flag would be a silently wrong picture, not a missing
        // feature.
        cfg.lossless_tiles_enabled = false;

        let session = tokio::task::spawn_blocking(move || HostSession::start(cfg))
            .await
            .map_err(|e| Error::Other(format!("pipeline start task: {e}")))??;
        self.install(slot as usize, monitor, Some(key), Arc::new(session))
            .await;
        Ok(())
    }

    /// Reconcile the running streams with `desired` (already filtered).
    ///
    /// See [`Reconciled`] for what the caller owes the client afterwards.
    async fn reconcile(
        &mut self,
        desired: &[u8],
        inner: &Arc<Inner>,
        primary: &Arc<HostSession>,
        fps: u32,
        total_kbps: u32,
    ) -> Reconciled {
        let plan = plan_slot_changes(&self.current(), desired);
        if plan.is_empty() {
            tracing::debug!(?desired, "monitor selection unchanged; nothing to do");
            return Reconciled::Unchanged;
        }
        tracing::info!(?desired, ?plan, "reconciling video streams");

        let mut slot0_changed = false;
        let mut started: Vec<u8> = Vec::new();
        for change in plan {
            match change {
                SlotChange::Stop { slot } => {
                    self.stop_slot(slot as usize).await;
                    if slot == 0 {
                        slot0_changed = true;
                    } else {
                        self.send(ControlMsg::StreamStopped {
                            id: slot,
                            reason: "deselected".into(),
                        });
                    }
                }
                SlotChange::Start { slot, monitor } => {
                    match self.build(slot, monitor, primary, fps).await {
                        Ok(()) => {
                            started.push(slot);
                            if slot == 0 {
                                slot0_changed = true;
                            }
                        }
                        Err(e) => {
                            // A pipeline that will not build must never take the
                            // session with it — the same rule the audio thread
                            // follows, and for a stronger reason: the client is
                            // still watching the stream that *did* build.
                            let detail = format!(
                                "monitor {monitor} could not be opened for stream {slot}: {e}"
                            );
                            tracing::warn!("{detail}");
                            inner.emit(NetEvent::Warning {
                                detail: detail.clone(),
                            });
                            if slot == 0 {
                                // Slot 0 empty is no picture at all. Fall back to
                                // the persistent pipeline, which is already
                                // running and so cannot fail to start. Reported
                                // under the id its output really has, which is
                                // what the client needs to see it as.
                                let resident = self.persistent_monitor_id(primary).unwrap_or(0);
                                tracing::warn!(
                                    monitor = resident,
                                    "falling back to the resident pipeline for stream 0"
                                );
                                self.install(0, resident, None, primary.clone()).await;
                                started.push(0);
                                slot0_changed = true;
                            } else {
                                self.send(ControlMsg::StreamStopped {
                                    id: slot,
                                    reason: detail,
                                });
                            }
                        }
                    }
                }
            }
        }

        // Re-split the budget before anything quotes a share. The adaptor's
        // number is one connection's and is divided by pixel area between the
        // streams that are running *now*, which is a different set than it was
        // a moment ago — and a `StreamConfig` naming the old share, or the
        // total, would have the client sizing its expectations against a
        // bandwidth this stream will never use.
        let bitrate = apply_bitrate(inner, &self.view, total_kbps);
        for slot in started {
            if slot != 0 {
                self.announce(slot, fps, bitrate.share(slot));
            }
            // A stream nobody has sent an IDR to is a stream the client cannot
            // start decoding. Asked for after the announcement, so the format
            // message is already ahead of the first frame on the control stream.
            if let Some(s) = &self.slots[slot as usize] {
                s.session.request_keyframe();
            }
        }
        Reconciled::Changed {
            slot0_changed,
            bitrate,
        }
    }

    /// Tell the client the format of a secondary stream.
    ///
    /// `bitrate_kbps` is **this stream's share**, not the connection's total:
    /// `apply_bitrate` has already divided the adaptor's budget by pixel area,
    /// and quoting the total would tell the client to expect roughly twice the
    /// bandwidth this stream will ever use. It is passed in rather than read
    /// back off the pipeline because `set_bitrate` is write-only and the
    /// encoder's *observed* rate on a pipeline that started a moment ago is
    /// zero — a number that reads as "this stream is dead".
    fn announce(&self, slot: u8, fps: u32, bitrate_kbps: u32) {
        let Some(s) = self.slots.get(slot as usize).and_then(Option::as_ref) else {
            return;
        };
        let (width, height) = s.session.dimensions();
        self.send(ControlMsg::StreamConfig {
            id: slot,
            monitor: s.monitor_id,
            width,
            height,
            fps,
            bitrate_kbps,
            codec: Codec::H264,
        });
    }

    /// Re-enumerate the desktop and react to it having changed.
    ///
    /// Runs on the status tick, about once a second. Two jobs:
    ///
    /// 1. **Re-send `MonitorList`** when the set of outputs changes. Ids are
    ///    session-scoped and are reassigned by the enumeration, so a client
    ///    holding the old list would be selecting by numbers that now name
    ///    different monitors.
    /// 2. **Reap a stream that cannot recover.** Deliberately conservative: the
    ///    encoder must have stopped producing for [`MONITOR_REAP_MS`] *and* the
    ///    stream must be unrecoverable for one of two reasons — its monitor no
    ///    longer resolves, or the primary pipeline has landed on the same output
    ///    (see the undock note at the check itself). Stalling alone is not
    ///    enough: with `idle_repeat_ms` disabled a perfectly healthy stream of a
    ///    completely still desktop produces no frames at all, and reaping that
    ///    would turn "nothing is moving" into "your monitor was disconnected".
    ///
    /// # Why frames, and not [`SessionState`]
    ///
    /// The obvious signal is the pipeline reporting itself unhealthy, and it
    /// does not: a monitor that has been unplugged leaves `DdaCapture` in
    /// `CaptureState::NeedsRecreate`, and `capture::pause_reason` maps that to
    /// `None` precisely because a duplication rebuild is normally transparent.
    /// The session therefore stays `Running` forever, retrying every 50 ms.
    /// What actually stops is frames coming out of the encoder, so that is what
    /// is measured. `SessionState` is still consulted — a `Failed` pipeline is
    /// unhealthy by any reading — it is just not sufficient on its own.
    ///
    /// Slot 0 is never reaped. It keeps today's retry-forever behaviour: the
    /// primary pipeline is the one the host itself is built around, and a host
    /// with no stream at all is a host the client cannot tell from a crash.
    async fn watch_topology(&mut self, now_ms: u64) {
        if !self.enabled {
            return;
        }
        // `spawn_blocking`: this is a synchronous DXGI factory-and-output walk
        // that talks to the display driver, and it runs on the status tick with
        // the `slots` mutex held. On a runtime worker it would block the whole
        // executor thread for however long the driver takes — which, during the
        // mode change that made the topology interesting in the first place, is
        // exactly when it is slowest.
        let listed = match tokio::task::spawn_blocking(crate::capture::list_monitors).await {
            Ok(Ok(l)) => l,
            Ok(Err(e)) => {
                // Enumeration failing is itself usually transient (it is the
                // same DXGI factory walk duplication uses). Say so once and
                // leave every stream exactly as it is.
                tracing::debug!("monitor enumeration failed on the status tick: {e}");
                return;
            }
            Err(e) => {
                tracing::debug!("monitor enumeration task failed: {e}");
                return;
            }
        };

        // Compared on the full `MonitorInfo`, not just the key. The key is
        // identity (luid, device name, origin) and deliberately survives a mode
        // change — which means a key-only comparison would miss one entirely,
        // and the client's picker would keep offering the old resolution for the
        // rest of the session.
        let changed = listed.len() != self.monitors.len()
            || listed
                .iter()
                .zip(self.monitors.iter())
                .any(|((ai, ak), (bi, bk))| ak != bk || ai != bi);
        if changed {
            tracing::info!(
                was = self.monitors.len(),
                now = listed.len(),
                "desktop topology changed; re-sending the monitor list"
            );
            self.monitors = listed;
            self.send(ControlMsg::MonitorList {
                monitors: self.monitors.iter().map(|(i, _)| i.clone()).collect(),
            });
            // Ids are positional and the enumeration just reassigned them, so a
            // slot's recorded id can now name a different monitor than the one
            // it is capturing. `current()` feeds `plan_slot_changes`, which
            // compares by id, so a stale one would have the reconciler conclude
            // a slot already carries the requested monitor and skip a rebuild
            // the client did ask for. The key is the identity that survives
            // renumbering; re-derive the id from it.
            //
            // The persistent pipeline carries no key of its own, and its id is
            // emphatically **not** 0. It resolved `MonitorSelector::Primary`
            // once, at construction, and keeps that output for life, while
            // `list_monitors` re-decides which output is primary on every call
            // — so "the operator moved the Windows primary" is at once the
            // event that brings us here and the event that makes the two
            // disagree. Writing 0 would leave slot 0 claiming a monitor it is
            // not showing, and since `plan_slot_changes` compares by id the
            // reconciler would then answer `SelectMonitors { [0] }` by doing
            // nothing at all — the client keeps receiving the other panel — and
            // read a request for the pipeline's *real* monitor as a retarget,
            // building a second duplication of an output this process holds.
            // So it is asked, through the same [`monitor_id_for_key`] seam
            // `persistent_monitor_id` uses.
            //
            // Resolved into a vector before the mutation because both answers
            // are read back out of `self`.
            let resolved: Vec<Option<u8>> = self
                .slots
                .iter()
                .map(|slot| {
                    let s = slot.as_ref()?;
                    match &s.key {
                        Some(key) => monitor_id_for_key(&self.monitors, key),
                        None => self.persistent_monitor_id(&s.session),
                    }
                })
                .collect();
            for (slot, id) in self.slots.iter_mut().zip(resolved) {
                // A slot whose key resolves to nothing is either riding out a
                // transient or about to be reaped below. Either way the old id
                // is the best guess there is, and overwriting it with a wrong
                // one would be worse.
                if let (Some(s), Some(id)) = (slot.as_mut(), id) {
                    s.monitor_id = id;
                }
            }
        }

        // What output is each slot *actually* duplicating right now? Read from
        // the pipeline itself rather than from the selector it was built with,
        // which is the only way to catch the case below.
        let serving: Vec<Option<String>> = self
            .slots
            .iter()
            .map(|s| s.as_ref().map(|s| s.session.describe().output))
            .collect();

        // Liveness, for every slot, every tick — the counters have to be
        // sampled continuously or "stalled for 5 seconds" cannot be measured.
        let mut reap: Option<(usize, &'static str)> = None;
        for slot in 0..self.slots.len() {
            let Some(s) = self.slots[slot].as_mut() else {
                continue;
            };
            let frames = s.session.frames_encoded();
            let healthy = frames != s.last_frames && s.session.state().is_live();
            s.last_frames = frames;
            if healthy {
                s.stalled_since = None;
            } else if s.stalled_since.is_none() {
                s.stalled_since = Some(now_ms);
            }

            if slot == 0 {
                continue;
            }
            // Does this slot's monitor still exist? Matched on the key, not the
            // id: the enumeration above may have renumbered everything.
            let resolves = match &s.key {
                Some(key) => self.monitors.iter().any(|(_, k)| k == key),
                None => true,
            };

            // The undock case, which "does the key still resolve" cannot see.
            //
            // The persistent pipeline selects `MonitorSelector::Primary`, so
            // when the primary is unplugged it rebuilds onto whatever output is
            // left — which is the very output this slot is already duplicating.
            // Both keys still resolve and both slots look healthy by every
            // other measure, but DXGI will not hand one output to two
            // duplications from one process, so this stream's capture fails
            // forever while the client waits for a picture that cannot come.
            // Slot 0 wins the tie: it is the stream a client that never asked
            // for a second monitor is watching.
            let collides = serving[slot].is_some() && serving[slot] == serving[0];

            let stalled_for = s.stalled_since.map(|t| now_ms.saturating_sub(t));
            let stalled = stalled_for.is_some_and(|ms| ms >= MONITOR_REAP_MS);
            if stalled && !resolves {
                reap = Some((slot, "monitor detached"));
            } else if stalled && collides {
                reap = Some((slot, "monitor is now the primary"));
            }
        }

        if let Some((slot, reason)) = reap {
            tracing::warn!(
                stream = slot,
                reason,
                "this stream has produced nothing for {MONITOR_REAP_MS} ms and \
                 cannot recover; stopping it"
            );
            self.stop_slot(slot).await;
            self.send(ControlMsg::StreamStopped {
                id: slot as u8,
                reason: reason.into(),
            });
        }
    }

    /// Host-local diagnostics for the second stream, or `None` when there is
    /// not one. Never crosses the wire — see [`SecondaryStreamStatus`].
    fn secondary_status(&self) -> Option<SecondaryStreamStatus> {
        let s = self.slots.get(1)?.as_ref()?;
        let desc = s.session.describe();
        let counters = &self.counters[1];
        Some(SecondaryStreamStatus {
            monitor_id: s.monitor_id,
            resolution: (desc.width, desc.height),
            encoder: desc.encoder.clone(),
            hardware_encoder: desc.hardware_encoder,
            state: format!("{:?}", s.session.state()),
            target_kbps: s.session.stats().bitrate_kbps,
            fps: s.session.active_fps(),
            frames_sent: counters.frames_sent.load(Ordering::Relaxed),
            bytes_sent: counters.bytes_sent.load(Ordering::Relaxed),
            backpressured: counters.backpressured.load(Ordering::Relaxed),
        })
    }

    /// Stop every stream. Called once, at session end.
    async fn shutdown(&mut self) {
        for slot in (0..self.slots.len()).rev() {
            self.stop_slot(slot).await;
        }
    }
}

/// Releases every held key and button when a session ends, on every path.
///
/// Holds the slot view as well as the primary pipeline: with a second monitor
/// selected there are two injectors, and a key held on either is a key stuck on
/// an unattended machine. The view may already be empty by the time this runs
/// on the normal path (`StreamSlots::shutdown` releases as it tears each slot
/// down); this is the guard for the paths that never reach it.
struct ReleaseGuard(Arc<HostSession>, SlotView);

impl Drop for ReleaseGuard {
    fn drop(&mut self) {
        for h in self.1.lock().iter().flatten() {
            h.session.release_all_input();
        }
        self.0.release_all_input();
        // Stop refinement dead when the client goes away. The media pipeline is
        // a singleton that outlives every connection, and `status_loop` — the
        // only thing that ever lowers this — has just been aborted, so without
        // this the media thread would carry on compressing and queueing strips
        // at the departed client's measured budget, for a desktop nobody is
        // watching. Those stale bytes would then be the first thing the *next*
        // client's stream carried, ahead of its own `Reset`, competing with its
        // connect keyframe.
        self.0.set_tile_budget_kbps(0);
        tracing::info!("released all client-held input");
    }
}

/// Drive one authenticated client until the connection ends.
///
/// Returns the reason the session finished, for the log and the UI.
pub(super) async fn run_session(
    inner: &Arc<Inner>,
    conn: Connection,
    mut streams: SessionStreams,
    negotiated_features: u64,
) -> String {
    let pipeline = match inner.ensure_pipeline().await {
        Ok(p) => p,
        Err(e) => {
            let detail = format!("media pipeline unavailable: {e}");
            tracing::error!("{detail}");
            inner.status_mut(|s| s.last_error = Some(detail.clone()));
            conn.close(CLOSE_CODE_REJECTED.into(), b"host pipeline unavailable");
            return detail;
        }
    };
    let multi_monitor = negotiated_features & features::MULTI_MONITOR != 0;
    let slot_view: SlotView = Arc::new(Mutex::new(
        (0..MAX_VIDEO_STREAMS).map(|_| None).collect::<Vec<_>>(),
    ));
    // Nothing below may return without this guard being dropped.
    let _release = ReleaseGuard(pipeline.clone(), slot_view.clone());
    // The pipeline is a singleton that outlives any one connection, so a
    // reconnecting client inherits a grid that still believes the *previous*
    // client's tiles are resident. This client's store is empty. Reset
    // unconditionally — it costs one full refinement sweep on a screen we are
    // about to send a keyframe for anyway, and skipping it means a permanently
    // soft picture on every connection after the first.
    pipeline.reset_tiles();
    // Bandwidth saver: blank the desktop to black for the life of this
    // session and restore it on every exit path (this function's `String`
    // return covers all of them — success, error, timeout, disconnect). A
    // no-op guard when the config flag is off. Scoped to the session rather
    // than the pipeline because the pipeline outlives a single client.
    let _wallpaper =
        crate::wallpaper::WallpaperGuard::new(inner.cfg.blank_wallpaper_during_session);

    // ---- the monitor list, and why it is written HERE --------------------
    //
    // `MonitorList` must be the FIRST thing the host says after `AuthOk`, so a
    // client that has just read `AuthOk` can do one framed read and know it has
    // the list — the mirror image of the client writing `StartStream` blind
    // into an ordered stream. There is exactly one window in which that is
    // true: after `handshake::authenticate` wrote `AuthOk` (it is the last
    // thing it writes) and before `QuicSession::start` below takes ownership of
    // `streams` and its `write_loop` becomes the only writer. Once the driver
    // owns the stream, anything queued through `send_control` races the status
    // tick's `Stats` and `RouteReport`, and "first message" stops being a
    // guarantee anyone can rely on.
    //
    // Framing is identical either way: `quic::write_framed` is what the
    // driver's own `write_loop` calls, so this is the same length-prefixed
    // postcard frame the client would read from any other control message.
    //
    // Gated on the negotiated bit, like every other message this feature adds.
    let mut monitors: Vec<(MonitorInfo, MonitorKey)> = Vec::new();
    if multi_monitor {
        monitors = match crate::capture::list_monitors() {
            Ok(l) if !l.is_empty() => l,
            other => {
                // Enumeration failed, or returned nothing while a pipeline is
                // demonstrably capturing something. Describe the output that
                // pipeline is actually duplicating rather than sending an empty
                // list: the client has been promised a list and a client with
                // no monitors in it cannot select even the primary. One honest
                // entry degrades to exactly today's single-monitor behaviour.
                if let Err(e) = other {
                    tracing::warn!("could not enumerate monitors: {e}");
                }
                let d = pipeline.describe();
                vec![(
                    MonitorInfo {
                        id: 0,
                        width: d.width,
                        height: d.height,
                        origin_x: d.monitor_origin.0,
                        origin_y: d.monitor_origin.1,
                        is_primary: true,
                        name: d.output.clone(),
                    },
                    MonitorKey {
                        adapter_luid: d.adapter_luid,
                        device_name: d.output.clone(),
                        origin: d.monitor_origin,
                    },
                )]
            }
        };
        let msg = ControlMsg::MonitorList {
            monitors: monitors.iter().map(|(i, _)| i.clone()).collect(),
        };
        tracing::info!(count = monitors.len(), "sending the monitor list");
        if let Err(e) = quic::write_framed(&mut streams.control.0, &msg).await {
            // Not fatal. The client falls back to the primary monitor, which is
            // what it would have shown anyway, and the session runs on.
            tracing::warn!("could not send the monitor list: {e}");
        }
    }

    let driver_cfg = DriverConfig {
        heartbeat_ms: 2_000,
        stats_interval_ms: STATUS_INTERVAL_MS,
        control_capacity: 64,
        input_capacity: 512,
        // The host only ever *sends* video (`video_pump` below). Running the
        // driver's receive path here would keep a reassembler alive for
        // datagrams no client sends, and give the client a second, unlimited
        // route into `request_keyframe` — the `ControlMsg::RequestKeyframe`
        // path in `control_loop` is rate-limited, `SessionEvent::KeyframeNeeded`
        // is not.
        receive_video: false,
        ..DriverConfig::default()
    };
    let (session, receivers) =
        match QuicSession::start(conn.clone(), streams, HOST_ROUTE, driver_cfg) {
            Ok(v) => v,
            Err(e) => {
                let detail = format!("session driver failed to start: {e}");
                tracing::error!("{detail}");
                conn.close(CLOSE_CODE_REJECTED.into(), b"session start failed");
                return detail;
            }
        };
    let session = Arc::new(session);

    let streaming = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    // One set per stream slot, created here so a slot's lifetime totals survive
    // being retargeted at another monitor, and so this function's epilogue can
    // still fold them into the status snapshot after the slots are gone.
    let counters: Vec<Arc<VideoCounters>> = (0..MAX_VIDEO_STREAMS)
        .map(|_| Arc::new(VideoCounters::default()))
        .collect();
    let adaptor = Arc::new(Mutex::new(BitrateAdaptor::new(AdaptConfig::for_mode(
        *inner.quality.lock(),
    ))));

    // Slot 0 is the persistent primary pipeline and its pump — what every
    // session has always started with. `StreamSlots` owns it from here; when
    // multi-monitor is not negotiated it is the only slot that will ever exist
    // and this is the same single `dd-video-tx` thread as before.
    let slots = Arc::new(tokio::sync::Mutex::new(StreamSlots::new(
        multi_monitor,
        conn.clone(),
        session.clone(),
        monitors,
        streaming.clone(),
        inner.cfg.pipeline.clone(),
        counters.clone(),
        slot_view.clone(),
    )));
    let active_video_streams = {
        let mut s = slots.lock().await;
        // Under the id its output really has: usually 0, but not if the operator
        // moved the primary display since this pipeline came up. See
        // `StreamSlots::persistent_monitor_id`.
        let resident = s.persistent_monitor_id(&pipeline).unwrap_or(0);
        s.install(0, resident, None, pipeline.clone()).await;
        s.active.clone()
    };

    // System audio, only when BOTH ends asked for it — `negotiated_features` is
    // already the intersection, so this is a single bit test. It matters more
    // here than it does for tiles: audio shares the media *datagram* path with
    // video rather than getting a stream of its own, so a client that predates
    // the feature would hand an audio datagram to its video reassembler.
    //
    // A dedicated OS thread rather than a tokio task, and joined rather than
    // aborted, for the same reasons `dd-video-tx` is: it owns thread-affine COM
    // objects (a WASAPI endpoint and an MFT) whose teardown must happen on the
    // thread that created them, and an aborted task would leave the capture
    // endpoint and the silent keep-alive render stream open behind it.
    let audio_counters = Arc::new(AudioCounters::default());
    // Published by `status_loop` from the same value it sends the client as
    // `ControlMsg::SecureDesktopActive`, so the picture freezing and the audio
    // muting are the same fact rather than two that can disagree.
    let secure_desktop = Arc::new(AtomicBool::new(false));
    let audio = if negotiated_features & directdesk_shared::protocol::features::SYSTEM_AUDIO != 0 {
        let conn = conn.clone();
        let stop = stop.clone();
        let counters = audio_counters.clone();
        let muted = secure_desktop.clone();
        let cfg = AudioTxConfig {
            source: inner.cfg.system_audio_source,
            kbps: inner.cfg.system_audio_kbps,
            redundancy: inner.cfg.system_audio_redundancy,
        };
        let active = active_video_streams.clone();
        let spawned = std::thread::Builder::new()
            .name("dd-audio-tx".into())
            .spawn(move || audio_pump(conn, cfg, muted, stop, counters, active))
            .ok();
        if spawned.is_none() {
            // A warning, not an error: this costs sound and nothing else.
            tracing::warn!("could not spawn the audio sender thread; session continues silent");
        }
        spawned
    } else {
        None
    };

    // Elevation click-through: the control loop forwards `ArmElevation` here;
    // `elevation_loop` owns the state machine, the detector poll, and the SYSTEM
    // worker's lifecycle. It is NOT in `tasks` (which are hard-aborted): it is
    // stopped cooperatively via `stop` and awaited so it can tear the worker and
    // the input route down cleanly before the next client connects.
    let (arm_tx, arm_rx) = mpsc::unbounded_channel::<(bool, u32)>();
    let elevation = tokio::spawn(elevation_loop(
        inner.clone(),
        session.clone(),
        pipeline.clone(),
        arm_rx,
        stop.clone(),
    ));

    // Lossless refinement, only when BOTH ends asked for it. `negotiated_features`
    // is already the intersection, so this is a single bit test — and a client
    // that predates the feature never gets a stream opened at it.
    let tile_counters = Arc::new(TileCounters::default());
    let mut tasks = vec![
        tokio::spawn(input_loop(
            receivers.input,
            slot_view.clone(),
            pipeline.clone(),
        )),
        tokio::spawn(control_loop(
            inner.clone(),
            receivers.control,
            session.clone(),
            pipeline.clone(),
            streaming.clone(),
            adaptor.clone(),
            arm_tx,
            slots.clone(),
            slot_view.clone(),
        )),
        tokio::spawn(status_loop(
            inner.clone(),
            session.clone(),
            pipeline.clone(),
            adaptor,
            counters.clone(),
            streaming.clone(),
            tile_counters.clone(),
            audio_counters.clone(),
            secure_desktop.clone(),
            slots.clone(),
            slot_view.clone(),
        )),
        tokio::spawn(event_loop(
            inner.clone(),
            receivers.events,
            pipeline.clone(),
        )),
    ];

    if negotiated_features & directdesk_shared::protocol::features::LOSSLESS_TILES != 0 {
        tasks.push(tokio::spawn(tile_pump(
            conn.clone(),
            pipeline.tiles(),
            stop.clone(),
            tile_counters,
        )));
    }

    let reason = conn.closed().await.to_string();

    stop.store(true, Ordering::SeqCst);
    streaming.store(false, Ordering::SeqCst);
    for t in tasks {
        t.abort();
    }
    // Await (do not abort) the elevation loop so it tears down any live SYSTEM
    // worker and clears the input route before the next client connects.
    let _ = elevation.await;
    // Stop and join every video pump, release input on every slot, and drop the
    // session-scoped pipelines. The persistent primary one survives: only this
    // session's `Arc` clone of it goes away. Nothing here can deadlock on the
    // `slots` mutex — `control_loop` and `status_loop`, the only other holders,
    // were aborted above.
    slots.lock().await.shutdown().await;
    // Joined, not detached: the audio thread owns a WASAPI capture endpoint, a
    // silent keep-alive *render* stream on the default device, an AAC MFT and a
    // COM apartment. Letting it outlive the session would leave the host's audio
    // engine held open for a client that has already gone — and the next client
    // would then race a second capture onto the same endpoint.
    if let Some(a) = audio {
        let _ = a.join();
    }
    // Explicit, not just the guard: input must be released before the next
    // client can possibly connect.
    pipeline.release_all_input();

    // Every stream's totals, summed: this is the record of what the client
    // actually got, and with two monitors selected it got both.
    let totals = |f: fn(&VideoCounters) -> u64| -> u64 { counters.iter().map(|c| f(c)).sum() };
    inner.status_mut(|s| {
        s.frames_sent = totals(|c| c.frames_sent.load(Ordering::Relaxed));
        s.bytes_sent = totals(|c| c.bytes_sent.load(Ordering::Relaxed));
        s.frames_coalesced = totals(|c| c.coalesced.load(Ordering::Relaxed));
        s.frames_backpressured = totals(|c| c.backpressured.load(Ordering::Relaxed));
        s.pace_deadline_bursts = totals(|c| c.pace_deadline_bursts.load(Ordering::Relaxed));
        s.frames_unfragmentable = totals(|c| c.frames_unfragmentable.load(Ordering::Relaxed));
        // With the session over there is no second stream to report on, but the
        // monitor list stays: it is what the UI labels the host's outputs with.
        s.secondary = None;
        // A per-window gauge, like `delivery`: with no session there is no
        // window, so it reads zero rather than freezing at the last value.
        s.emit_ms_max = 0;
        s.transport = ConnStats::default();
        s.delivery = WindowDelivery::default();
        s.quality_mode = None;
        // The session's audio totals are kept (they are the record of what the
        // client actually got), but the live state is not: with the thread
        // joined there is nothing to be muted or streaming any more.
        s.audio_packets_sent = audio_counters.packets_sent.load(Ordering::Relaxed);
        s.audio_bytes_sent = audio_counters.bytes_sent.load(Ordering::Relaxed);
        s.audio_backpressured = audio_counters.backpressured.load(Ordering::Relaxed);
        s.audio_silent_suppressed = audio_counters.silent_suppressed.load(Ordering::Relaxed);
        s.audio_status = AudioStatus::Disabled;
    });
    reason
}

/// Which injector an event belongs to.
///
/// Pointer events carry coordinates normalized against **one** stream's frame,
/// so they must reach the injector that knows that stream's geometry — send a
/// click normalized against the second monitor to the first monitor's injector
/// and it lands somewhere else entirely.
///
/// Keys are the opposite case and the reason this is a function rather than a
/// field lookup: held-key and modifier state lives *in* an injector. Shift down
/// on one and the character typed on the other would arrive unshifted, and a
/// Ctrl held while the user moved to the other monitor would never be released
/// by the injector that is tracking it. There is one keyboard on the client's
/// desk, so there is one keyboard injector here: stream 0's, always.
fn route_for(stream: u8, ev: &InputEvent) -> u8 {
    match ev {
        InputEvent::Key { .. } => 0,
        InputEvent::MouseMove { .. }
        | InputEvent::MouseButton { .. }
        | InputEvent::MouseWheel { .. } => stream,
    }
}

/// Inbound input. The driver has already decoded and validated; validating
/// again is cheap and keeps this the last line of defence before injection.
async fn input_loop(mut rx: mpsc::Receiver<InputMsg>, view: SlotView, primary: Arc<HostSession>) {
    while let Some(msg) = rx.recv().await {
        // `Event` and `EventOn { id: 0 }` are the same message. The contract in
        // `InputMsg`'s own docs says so, and a client that has negotiated
        // multi-monitor may send either for the primary stream.
        let (stream, ev) = match msg {
            InputMsg::Event(ev) => (0u8, ev),
            InputMsg::EventOn { id, event } => (id, event),
            InputMsg::ReleaseAll => {
                tracing::info!("client asked for a full input release");
                // Every injector, not just the primary's: a key held on the
                // second monitor's is just as stuck.
                for h in view.lock().iter().flatten() {
                    h.session.release_all_input();
                }
                continue;
            }
        };

        if let Err(e) = validate_event(&ev) {
            tracing::warn!("rejected input event: {e}");
            continue;
        }

        let target = route_for(stream, &ev);
        // Cloned out from under the lock: `send` on an unbounded channel is
        // cheap but it is not this lock's business, and the reconciler wants
        // this mutex back.
        let route = view.lock().get(target as usize).and_then(Clone::clone);
        let sender = match (route, &ev) {
            (Some(route), _) => Some(route.input),
            // Slot 0 is empty for as long as retargeting the primary stream at
            // another monitor takes — seconds of D3D11 and Media Foundation
            // start-up. Before multiple monitors existed the injector was a
            // singleton that could not go away, so dropping here would be a new
            // way to lose a keystroke, and losing a key *down* whose key up
            // arrives later is how a modifier gets stuck. Keys are coordinate
            // free, so the resident pipeline's injector serves them correctly
            // whatever it happens to be showing.
            (None, InputEvent::Key { .. }) => {
                tracing::debug!("no stream 0 yet; injecting the key on the resident pipeline");
                Some(primary.input_sender())
            }
            // Pointer events are the opposite: their coordinates are normalized
            // against a frame this injector may not be showing, so a fallback
            // would click somewhere the user never pointed. Dropping one is
            // invisible — the next motion event corrects the position.
            (None, _) => {
                tracing::debug!(
                    stream = target,
                    "pointer input for a stream that is not running; dropping"
                );
                None
            }
        };

        if let Some(tx) = sender {
            if tx.send(ev).is_err() {
                // Never `return` here. This loop's one correct end condition is
                // the driver closing `rx`; a send failing means *this* pipeline
                // is going away, and on the retarget path another is about to
                // take its place — ending input forwarding would kill the
                // keyboard for the rest of the session over a transient race.
                tracing::warn!(
                    stream = target,
                    "input pipeline closed; dropping this event"
                );
            }
        }
    }
}

/// Session control from the client.
#[allow(clippy::too_many_arguments)]
async fn control_loop(
    inner: Arc<Inner>,
    mut rx: mpsc::Receiver<ControlMsg>,
    session: Arc<QuicSession>,
    pipeline: Arc<HostSession>,
    streaming: Arc<AtomicBool>,
    adaptor: Arc<Mutex<BitrateAdaptor>>,
    arm_tx: mpsc::UnboundedSender<(bool, u32)>,
    slots: Arc<tokio::sync::Mutex<StreamSlots>>,
    view: SlotView,
) {
    let mut keyframes = RateLimiter::new(CLIENT_KEYFRAME_MIN_INTERVAL_MS);

    while let Some(msg) = rx.recv().await {
        let now = inner.now_ms();
        match msg {
            ControlMsg::StartStream {
                max_width,
                max_height,
                preferred_fps,
                quality_mode,
            } => {
                // Slot 0's dimensions, which are the persistent pipeline's
                // unless the client has already retargeted the primary stream
                // at another monitor. `VideoConfig` describes stream 0 and
                // nothing else — it is the message a client that has never
                // heard of a second monitor reads.
                let (w, h) = slot_dimensions(&view, 0).unwrap_or_else(|| pipeline.dimensions());
                tracing::info!(
                    "stream requested: client canvas {max_width}x{max_height} @ {preferred_fps} \
                     fps, {quality_mode:?}; host sends {w}x{h}"
                );
                *inner.quality.lock() = quality_mode;
                // The client's preference narrows the host's frame rate, never
                // widens it — same contract as `BitrateLimit` (`effective_cap`).
                // The host side of that is the LIVE value, not `cfg.pipeline`:
                // an operator who lowered the rate mid-session must not have it
                // undone by the next StartStream.
                let host_fps = *inner.fps.lock();
                let fps = effective_fps(host_fps, preferred_fps);
                *inner.fps.lock() = fps;
                // Every stream, not just the primary: one client, one frame
                // rate. The second monitor's `StreamConfig` is re-sent below so
                // its decoder is not left believing the old one.
                for_each_slot(&view, |h| h.session.set_fps(fps));
                let bitrate = {
                    let mut a = adaptor.lock();
                    a.set_mode(quality_mode, now);
                    apply_bitrate(&inner, &view, a.current())
                };
                for_each_slot(&view, |h| h.session.request_keyframe());
                streaming.store(true, Ordering::SeqCst);

                // Order is contractual, not cosmetic: the legacy `VideoConfig`
                // for stream 0 FIRST, and a `StreamConfig { id: 1, .. }` after
                // it when a second stream is live. That is what the client's
                // handshake documentation specifies for *this reply*, and the
                // reason is the client's: `VideoConfig` is the message it sizes
                // its main window from, and being told a second stream exists
                // before it has been told the primary's format leaves it
                // holding the second window's geometry with nowhere to put it.
                //
                // The claim is about the `StartStream` reply and no more than
                // that, because it is not a property of the session as a whole
                // and must not be read as one. A client sends `SelectMonitors`
                // *before* `StartStream`, so on a two-monitor session the first
                // format message it ever sees is the `StreamConfig` that
                // `reconcile` announces when it builds slot 1 — and a single
                // `SelectMonitors` that both retargets slot 0 and starts slot 1
                // announces the second stream (inside `reconcile`, so that a
                // stream's format is on the wire ahead of its first keyframe)
                // before the caller sends slot 0's fresh `VideoConfig`. The
                // client is explicitly order-agnostic about those two arriving
                // in any order, which is what makes that acceptable; what it is
                // not agnostic about is a *reply* that leads with the secondary.
                let cfg = ControlMsg::VideoConfig {
                    width: w,
                    height: h,
                    // The intended rate, not `pipeline.active_fps()`: `set_fps`
                    // lands on the media thread on its next pass (up to one
                    // frame away), so reading it back here would still report
                    // the old value. `active_fps()` is for the status path,
                    // where observed truth is what is wanted.
                    fps,
                    // Stream 0's applied share, not the adaptor's total: this
                    // message describes stream 0 alone. See
                    // [`AppliedBitrate::share`].
                    bitrate_kbps: bitrate.share(0),
                    codec: Codec::H264,
                };
                if let Err(e) = session.send_control(cfg) {
                    tracing::warn!("could not send VideoConfig: {e}");
                }
                // Re-announced unconditionally, after the `VideoConfig` above.
                // Not merely cosmetic agreement: `SelectMonitors` arrives BEFORE
                // this message and the stream was announced then, at whatever
                // the adaptor happened to hold — but `set_mode` above has just
                // moved the whole budget (Balanced and TextDesktop are several
                // megabits apart), so the share quoted in that first
                // announcement is now stale. This is one small control message
                // per session, and the client treats it as UI state rather than
                // a decoder reconfiguration.
                {
                    let s = slots.lock().await;
                    if s.enabled && s.slots.get(1).is_some_and(Option::is_some) {
                        s.announce(1, fps, bitrate.share(1));
                    }
                }
            }
            ControlMsg::StopStream => {
                tracing::info!("client stopped the stream");
                streaming.store(false, Ordering::SeqCst);
            }
            ControlMsg::RequestKeyframe => {
                // One limiter for the whole session, not one per stream. The
                // client asks when *its* decoder is stuck, and a request that
                // fanned out per stream would let a two-monitor client extract
                // twice the IDRs from a link that is already struggling.
                if keyframes.allow(now) {
                    for_each_slot(&view, |h| h.session.request_keyframe());
                } else {
                    tracing::trace!("keyframe request rate-limited");
                }
            }
            ControlMsg::QualityChange(mode) => {
                tracing::info!("quality mode changed to {mode:?}");
                *inner.quality.lock() = mode;
                let mut a = adaptor.lock();
                a.set_mode(mode, now);
                apply_bitrate(&inner, &view, a.current());
            }
            ControlMsg::BitrateLimit { max_kbps } => {
                tracing::info!("client asked for a bitrate limit of {max_kbps:?} kbps");
                // The client's request narrows, never widens, the host's cap.
                let effective = effective_cap(*inner.bitrate_cap.lock(), max_kbps);
                *inner.bitrate_cap.lock() = effective;
                apply_bitrate(&inner, &view, adaptor.lock().current());
            }
            ControlMsg::SelectMonitors { ids } => {
                let mut s = slots.lock().await;
                if !s.enabled {
                    // Unreachable from a correct client: it only sends this
                    // after seeing MULTI_MONITOR come back in the host's Hello.
                    tracing::warn!("ignoring SelectMonitors: multi-monitor is not negotiated");
                    continue;
                }
                let resident = s.persistent_monitor_id(&pipeline);
                let desired = filter_selection(&ids, &s.known_ids(), resident);
                if desired.is_empty() {
                    // Not "stop everything". A selection naming nothing this
                    // host has is a client working from a stale list — the
                    // topology watchdog will have re-sent it — and tearing the
                    // picture down would turn a recoverable mismatch into a
                    // black screen.
                    tracing::warn!(
                        ?ids,
                        "no requested monitor exists here; keeping the current selection"
                    );
                    continue;
                }
                let fps = *inner.fps.lock();
                let total = adaptor.lock().current();
                // `reconcile` re-splits the budget itself, once, after the last
                // stream has come up: splitting per change would hand the
                // encoders a share computed against a set of streams that no
                // longer exists by the time the plan finishes.
                let outcome = s.reconcile(&desired, &inner, &pipeline, fps, total).await;
                let primary_is_the_persistent_pipeline =
                    s.slots[0].as_ref().is_some_and(|s| s.key.is_none());
                drop(s);

                // Refinement follows stream 0, and only stream 0. Its grid, its
                // leases and the client's tile store are all addressed against
                // the primary pipeline's geometry, so the moment stream 0 shows
                // a different monitor every refined tile the client is holding
                // is painted over the wrong picture. `reset_tiles` retracts all
                // of them; `status_loop` then zeroes the budget for as long as
                // stream 0 is elsewhere, and lets it refill when it comes back.
                if let Reconciled::Changed {
                    slot0_changed: true,
                    bitrate,
                } = outcome
                {
                    pipeline.reset_tiles();
                    let (w, h) = slot_dimensions(&view, 0).unwrap_or_else(|| pipeline.dimensions());
                    tracing::info!(
                        primary_is_the_persistent_pipeline,
                        "stream 0 now sends {w}x{h}"
                    );
                    // A legacy `VideoConfig`, because stream 0's format is what
                    // that message has always described and the client sizes
                    // its window from it.
                    let cfg = ControlMsg::VideoConfig {
                        width: w,
                        height: h,
                        fps: *inner.fps.lock(),
                        // Slot 0's share out of the split `reconcile` just
                        // applied — the set of running streams changed a moment
                        // ago, so the adaptor's total is now the wrong number by
                        // a factor the client cannot guess. See
                        // [`AppliedBitrate::share`].
                        bitrate_kbps: bitrate.share(0),
                        codec: Codec::H264,
                    };
                    if let Err(e) = session.send_control(cfg) {
                        tracing::warn!("could not send VideoConfig: {e}");
                    }
                }
            }
            ControlMsg::ClipboardText(text) => {
                // Clipboard is a later milestone. Say so rather than pretending.
                tracing::info!(
                    "ignoring {} bytes of clipboard text (not implemented)",
                    text.len()
                );
            }
            ControlMsg::Stats(peer) => {
                inner.status_mut(|s| {
                    s.transport.fps_decode = peer.fps_decode;
                    s.transport.fps_present = peer.fps_present;
                });
            }
            ControlMsg::ArmElevation { one_shot, ttl_secs } => {
                if !inner.cfg.uac_clickthrough {
                    tracing::warn!("client armed elevation but uac_clickthrough is off; ignoring");
                } else {
                    tracing::info!("client armed elevation (one_shot={one_shot}, ttl={ttl_secs}s)");
                    // Hand it to the elevation loop; if that task is gone the
                    // session is ending anyway.
                    let _ = arm_tx.send((one_shot, ttl_secs));
                }
            }
            other => tracing::debug!("ignoring control message from client: {other:?}"),
        }
    }
}

/// Every live stream's handle, cloned out from under the hot-path lock.
fn live_slots(view: &SlotView) -> Vec<SlotHandle> {
    view.lock().iter().flatten().cloned().collect()
}

/// Do something to every live stream's pipeline.
fn for_each_slot(view: &SlotView, f: impl Fn(&SlotHandle)) {
    for h in live_slots(view).iter() {
        f(h);
    }
}

/// Client input events every live injector has actually put on the desktop.
///
/// Falls back to the persistent pipeline while no slot is running, so the
/// counter never reads zero just because a stream is being rebuilt — it is a
/// lifetime total and going backwards would look like the input path failing.
fn injected_total(live: &[SlotHandle], fallback: &Arc<HostSession>) -> u64 {
    if live.is_empty() {
        return fallback.input_events_injected();
    }
    live.iter().map(|h| h.session.input_events_injected()).sum()
}

/// The picture size one stream is sending, if it is running.
fn slot_dimensions(view: &SlotView, slot: u8) -> Option<(u32, u32)> {
    view.lock()
        .get(slot as usize)
        .and_then(Option::as_ref)
        .map(|h| h.session.dimensions())
}

/// What [`apply_bitrate`] actually handed the encoders.
///
/// Every message that quotes a bitrate to the client quotes it from here, and
/// from nowhere else. The adaptor's own `current()` is two steps removed from
/// what any one stream is asked to produce — the client's `BitrateLimit` caps it
/// and the pixel-area split divides it — so a message built from `current()`
/// tells the client to expect bandwidth that is never going to arrive.
struct AppliedBitrate {
    /// The connection's budget after the cap: the number the live slots divided
    /// up, and the honest answer about a slot that is not running.
    capped_total: u32,
    /// Each slot's applied share, indexed by stream id. `None` = that stream is
    /// not running, so nothing was applied to it.
    per_slot: Vec<Option<u32>>,
}

impl AppliedBitrate {
    /// The bitrate a config message about `slot` must quote.
    ///
    /// This is the number `set_bitrate` was last handed for that stream:
    /// post-cap, post-split. It is what `StreamConfig` has always meant, and it
    /// is what the legacy `VideoConfig` means too — that message describes
    /// **stream 0 and nothing else**, so `share(0)` is its `bitrate_kbps`.
    /// Quoting the adaptor's total there would overstate stream 0 twice over
    /// (by the limit the client itself asked for, and by whatever share a second
    /// monitor is taking) and would have the host's two format messages
    /// contradict each other about one connection.
    ///
    /// A slot that is not running has no applied share, and the capped total is
    /// then the truthful fallback rather than zero: a lone stream's split is a
    /// pass-through, so it is exactly what that slot gets the moment it comes
    /// back. Never the *un*-capped total — no quote may exceed the ceiling the
    /// client asked for.
    fn share(&self, slot: u8) -> u32 {
        self.per_slot
            .get(slot as usize)
            .copied()
            .flatten()
            .unwrap_or(self.capped_total)
    }
}

/// Hand the adaptor's decision to the encoders.
///
/// The cap is applied to the **total** and the split happens underneath it, so
/// a `BitrateLimit` still means exactly what it says: a hard ceiling on what
/// this connection is ever asked to produce, however many monitors are on it.
/// Splitting first and capping each share would let two streams together
/// produce twice the limit the client asked for.
///
/// Returns what was applied, so a caller about to quote a rate quotes the number
/// that really reached an encoder rather than the connection's total or a stale
/// reading off a pipeline that started a moment ago. See [`AppliedBitrate`].
fn apply_bitrate(inner: &Arc<Inner>, view: &SlotView, kbps: u32) -> AppliedBitrate {
    // A `BitrateLimit`/host cap is a hard ceiling on what the encoder is ever
    // asked for, applied on top of whatever the adaptor picked within its mode
    // range. The encoder never sees a value above the cap.
    let capped = clamp_to_cap(kbps, *inner.bitrate_cap.lock());
    let snapshot: Vec<Option<SlotHandle>> = view.lock().clone();
    let live: Vec<(usize, &SlotHandle)> = snapshot
        .iter()
        .enumerate()
        .filter_map(|(i, h)| h.as_ref().map(|h| (i, h)))
        .collect();
    let areas: Vec<u64> = live
        .iter()
        .map(|(_, h)| {
            let (w, ht) = h.session.dimensions();
            w as u64 * ht as u64
        })
        .collect();
    // A single stream is a pass-through: `split_bitrate(x, &[a]) == [x]`, so
    // this is `pipeline.set_bitrate(capped)` and nothing else on a one-monitor
    // session.
    let shares = split_bitrate(capped, &areas);
    let mut applied: Vec<Option<u32>> = vec![None; snapshot.len()];
    for ((slot, h), share) in live.iter().zip(shares.iter().copied()) {
        h.session.set_bitrate(share);
        applied[*slot] = Some(share);
    }
    if live.len() > 1 {
        // Which monitor got which share, and at what geometry. The three
        // numbers only mean anything beside each other: a monitor sitting at
        // the floor while the other has most of the budget is the split working
        // as designed on mismatched panels, and the same line on two identical
        // panels is a geometry the pipeline has not published yet.
        tracing::debug!(
            monitors = ?live.iter().map(|(_, h)| h.monitor_id).collect::<Vec<_>>(),
            areas = ?areas,
            shares = ?shares,
            total_kbps = capped,
            "split the bitrate budget"
        );
    }
    // The total, not a share: this is what the UI and the overrun signal call
    // "the bitrate the adaptive controller currently asks the encoder for", and
    // it is the connection's number.
    inner.status_mut(|s| s.target_kbps = capped);
    AppliedBitrate {
        capped_total: capped,
        per_slot: applied,
    }
}

/// The encoder-vs-link overrun for one status window.
///
/// # The denominator is bytes CARRIED, and it must stay that way
///
/// `transport.bandwidth_kbps` is built in
/// [`directdesk_shared::transport::session`]'s `delta_stats` from quinn's own
/// `rx_bytes + tx_bytes` across the window: bytes that were actually **moved**.
/// That is the only figure available here with the property [`overrun_signal`]
/// depends on — it *falls when the link stalls*.
///
/// The tempting alternative is `WindowDelivery::throughput_kbps()`, on the
/// reasoning that the numerator is video so the denominator should be video
/// too. It is wrong, and wrong in the one direction that matters: it disables
/// the signal silently. `WindowDelivery::bytes` comes from
/// `VideoCounters::bytes_sent`, which [`super::egress`]'s `video_pump`
/// accumulates from `frag.len()` **before** each `send_datagram` call and
/// commits once the frame's last fragment has been *offered*. Those are bytes
/// offered, not bytes carried — and offering is precisely what keeps
/// succeeding after the link has stalled, because `send_datagram` never blocks
/// and never refuses: quinn takes the datagram, returns `Ok(())`, and then
/// discards it with no error, no packet loss and no room consumed. A
/// denominator built from it therefore tracks the encoder no matter how little
/// reaches the wire, which is exactly the failure [`overrun_signal`]'s own docs
/// say this signal exists to detect.
///
/// It is also *larger* than the numerator by construction — about 11% at a
/// 1200-byte MTU, from one 12-byte fragment header per fragment plus a
/// full-width XOR parity fragment per FEC block, none of which the encoder's
/// bitrate counts. Against [`overrun_signal`]'s 15% slack that means the ratio
/// cannot reach the threshold until more than a fifth of frames are already
/// being dropped outright — by which point `backpressure_ratio` has long since
/// reported the same congestion, and the diagnostic contributes nothing at all.
/// The tests below pin both halves of that.
///
/// # The known residual, deliberately NOT fixed here
///
/// `bandwidth_kbps` is every byte on the connection, so audio, refinement tiles
/// and even ACKs inflate it and deflate the signal. Against a 12 Mbps video
/// stream a 96 kbps audio track is ~1% and invisible; against
/// `QualityMode::LowBandwidth` with an adaptor that has already cut the encoder
/// toward its floor it is 13-43%, enough to hold the ratio inside the slack on
/// exactly the slow links where this is the only congestion evidence there is.
///
/// The fix for that is to **subtract** the window's known non-video bytes (the
/// `AudioCounters::bytes_sent` and `TileCounters::bytes_sent` deltas, both
/// already measured over this same window) from the transport figure, which
/// keeps it a measurement of what was carried. It is never to swap in a
/// measurement of what was offered.
fn window_overrun(encoder_kbps: u32, transport: &ConnStats) -> f32 {
    overrun_signal(encoder_kbps, transport.bandwidth_kbps)
}

/// Periodic host → client status, and the adaptive bitrate loop.
#[allow(clippy::too_many_arguments)]
async fn status_loop(
    inner: Arc<Inner>,
    session: Arc<QuicSession>,
    pipeline: Arc<HostSession>,
    adaptor: Arc<Mutex<BitrateAdaptor>>,
    counters: Vec<Arc<VideoCounters>>,
    streaming: Arc<AtomicBool>,
    tile_counters: Arc<TileCounters>,
    audio_counters: Arc<AudioCounters>,
    secure_desktop: Arc<AtomicBool>,
    slots: Arc<tokio::sync::Mutex<StreamSlots>>,
    view: SlotView,
) {
    let mut ticker = tokio::time::interval(Duration::from_millis(STATUS_INTERVAL_MS));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_paused: Option<bool> = None;
    let mut window = StatusWindow::new(inner.now_ms());
    let mut tile_throttle = TileThrottle::new();
    let mut prev_tile_bytes = 0u64;

    loop {
        ticker.tick().await;
        if session.is_closed() {
            return;
        }
        let now = inner.now_ms();

        // Outputs appearing and disappearing, and a stream whose monitor has
        // gone for good. Held only for the duration of this call: it can build
        // or tear down a pipeline, and the rest of this tick must not be inside
        // the same critical section as a `spawn_blocking`.
        let (secondary, monitors, primary_is_persistent) = {
            let mut s = slots.lock().await;
            s.watch_topology(now).await;
            (
                s.secondary_status(),
                s.monitors
                    .iter()
                    .map(|(i, _)| i.clone())
                    .collect::<Vec<_>>(),
                s.slots[0].as_ref().is_some_and(|s| s.key.is_none()),
            )
        };

        let transport = session.stats();
        // Stream 0's pipeline is the one whose capture and encode *rates* are
        // reported, and it is not always the persistent one: the client can
        // point the primary stream at another monitor. Fall back to the
        // persistent pipeline only while no slot is running at all, which is
        // the instant between a teardown and the rebuild that follows it.
        let live = live_slots(&view);
        // Indexed, not `live.first()`: `live_slots` flattens away the empty
        // slots, so during the moment slot 0 is being rebuilt the first live
        // handle is the *second* stream — and reporting its frame rate, state
        // and latency as stream 0's would have the UI and the client's stats
        // describing a monitor neither of them thinks it is looking at.
        let slot0 = view
            .lock()
            .first()
            .and_then(Option::as_ref)
            .map(|h| h.session.clone());
        let media_source = slot0.as_ref().unwrap_or(&pipeline);
        let media = merge_media_stats(
            media_source.stats(),
            &live
                .iter()
                .skip(1)
                .map(|h| h.session.stats())
                .collect::<Vec<_>>(),
        );
        let state = media_source.state();
        let paused = matches!(state, SessionState::Paused(_));
        // Publish the pause to the audio sender, from the same value that goes
        // to the client as `ControlMsg::SecureDesktopActive` a few lines below.
        // One store per tick against one relaxed load per audio packet: the
        // secure desktop is a human-timescale event and this is a mute, not a
        // synchronisation primitive. Sourcing it here rather than letting the
        // audio thread read `pipeline.state()` itself is what makes "the
        // picture is frozen" and "audio is muted" the same fact — they are
        // literally the same boolean — at the cost of muting landing within one
        // status interval instead of instantly.
        secure_desktop.store(paused, Ordering::Relaxed);

        // Merge: the transport owns RTT/loss/bandwidth, the pipeline owns the
        // capture and encode numbers. Neither invents the other's.
        let merged = ConnStats {
            rtt_ms: transport.rtt_ms,
            jitter_ms: transport.jitter_ms,
            loss: transport.loss,
            bandwidth_kbps: transport.bandwidth_kbps,
            fps_capture: media.fps_capture,
            fps_encode: media.fps_encode,
            fps_decode: 0.0,
            fps_present: 0.0,
            bitrate_kbps: media.bitrate_kbps,
            frames_dropped: media.frames_dropped,
            keyframes_requested: media.keyframes_requested,
            pipeline_ms: media.pipeline_ms,
            // End-to-end input confirmation: report how many client keystrokes
            // this host has actually injected, so the client can see whether the
            // keys it sent are landing here. Summed over every injector: with a
            // second monitor selected the pointer events landing on it are just
            // as much evidence the input path works.
            input_injected: injected_total(&live, &pipeline),
        };

        // Everything below is a delta over THIS window (a matched sliding
        // window, never a lifetime total), measured against the real elapsed
        // time so the throughput figure is honest even if a tick was skipped.
        // `StatusWindow` owns the previous tick's raw counters and folds them
        // into that delta, plus whether the stream is warm enough for the
        // overrun ratio (see its doc comment) to be trusted.
        //
        // Summed across streams, because there is one window, one link and one
        // adaptor: the congestion these feed is the connection's, not a
        // particular monitor's, and a per-stream window would have each stream
        // cutting for pressure the other also caused.
        let total = |f: fn(&VideoCounters) -> u64| -> u64 { counters.iter().map(|c| f(c)).sum() };
        let sent = total(|c| c.frames_sent.load(Ordering::Relaxed));
        let bytes = total(|c| c.bytes_sent.load(Ordering::Relaxed));
        let backpressured = total(|c| c.backpressured.load(Ordering::Relaxed));
        let pace_deadline_bursts = total(|c| c.pace_deadline_bursts.load(Ordering::Relaxed));
        // A gauge over this window only: take it and leave the counter at zero
        // so the next window measures itself rather than inheriting a spike.
        // The worst stream's, not the sum: it is a "how long did one frame take"
        // and adding two streams' answers would describe neither.
        let emit_ms_max = counters
            .iter()
            .map(|c| c.emit_ms_max.swap(0, Ordering::Relaxed))
            .max()
            .unwrap_or(0);
        let (delivery, warm) = window.close(now, sent, bytes, backpressured);

        // Backpressure is congestion the packet-level loss counter cannot see:
        // quinn accepted every datagram we offered and then dropped some itself.
        // It is a matched-window ratio, so it does not skew like the old
        // lifetime comparison did.
        let pressure = delivery.backpressure_ratio();

        // What the link CARRIED, and what the pump merely OFFERED. They are not
        // interchangeable and only the first belongs in the overrun signal —
        // see [`window_overrun`], which is where that reasoning is written down.
        let carried_kbps = transport.bandwidth_kbps;
        let offered_kbps = delivery.throughput_kbps();
        let overrun = window_overrun(media.bitrate_kbps, &transport);
        // A keyframe the fragmenter refused outranks every measured signal:
        // nothing of it reached the wire, and the next IDR would be the same
        // size unless the bitrate comes down. Read-and-clear, then hand the
        // adaptor a full congestion event.
        //
        // OR'd across streams, and every latch cleared whichever fired: one
        // adaptor decides for the whole connection, and a refused keyframe on
        // *either* monitor is a refused keyframe. `fold` rather than `any`, so
        // that a short-circuit never leaves the other stream's latch set to
        // fire again on a window it did not belong to.
        let oversized_keyframe = counters
            .iter()
            .map(|c| c.oversized_keyframe.swap(false, Ordering::Relaxed))
            .fold(false, |acc, hit| acc | hit);
        if oversized_keyframe {
            tracing::error!("a keyframe was too big to fragment; forcing a bitrate cut");
        }
        let congestion =
            window_congestion(transport.loss, delivery, overrun, warm, oversized_keyframe);
        if let Some(next) = adaptor.lock().observe(now, congestion, transport.rtt_ms) {
            // All three numbers, labelled for what they actually are. `offered`
            // sitting at ~1.1x the encoder while `carried` has collapsed is the
            // exact signature of quinn accepting datagrams and discarding them,
            // and it is only visible because the two are printed separately.
            tracing::info!(
                "adaptive bitrate → {next} kbps (loss {:.1}%, send pressure {:.1}%, \
                 overrun {:.1}%{}: encoder {} kbps, link carried {} kbps, \
                 video offered {} kbps)",
                transport.loss * 100.0,
                pressure * 100.0,
                overrun * 100.0,
                if warm { "" } else { " [gated]" },
                media.bitrate_kbps,
                carried_kbps,
                offered_kbps
            );
            apply_bitrate(&inner, &view, next);
        }
        let quality_mode = *inner.quality.lock();

        let _ = session.send_control(ControlMsg::Stats(merged));
        let _ = session.send_control(ControlMsg::RouteReport(HOST_ROUTE));
        if last_paused != Some(paused) {
            last_paused = Some(paused);
            tracing::info!(
                "secure desktop {}",
                if paused { "active" } else { "cleared" }
            );
            let _ = session.send_control(ControlMsg::SecureDesktopActive(paused));
            if !paused {
                // The desktop we came back to may look nothing like the one we
                // left; the client needs a fresh IDR to resync — on every
                // stream, since the secure desktop froze all of them.
                for_each_slot(&view, |h| h.session.request_keyframe());
            }
        }

        let injected = injected_total(&live, &pipeline);
        // Observed, not requested: a rebuild that failed must not be reported as
        // if it had taken. Stream 0's, which is what `target_fps` has always
        // meant; the second stream's own rate is in `secondary`.
        let active_fps = media_source.active_fps();
        inner.status_mut(|s| {
            s.transport = transport;
            s.pipeline = merged;
            s.pipeline_state = Some(format!("{state:?}"));
            s.secure_desktop = paused;
            s.quality_mode = Some(quality_mode);
            s.target_fps = active_fps;
            s.delivery = delivery;
            s.frames_sent = sent;
            s.bytes_sent = bytes;
            s.frames_coalesced = total(|c| c.coalesced.load(Ordering::Relaxed));
            s.frames_backpressured = backpressured;
            s.pace_deadline_bursts = pace_deadline_bursts;
            s.frames_unfragmentable = total(|c| c.frames_unfragmentable.load(Ordering::Relaxed));
            s.emit_ms_max = emit_ms_max;
            s.input_injected = injected;
            s.secondary = secondary.clone();
            s.monitors = monitors.clone();
            s.audio_status = audio_counters.status();
            s.audio_packets_sent = audio_counters.packets_sent.load(Ordering::Relaxed);
            s.audio_bytes_sent = audio_counters.bytes_sent.load(Ordering::Relaxed);
            s.audio_backpressured = audio_counters.backpressured.load(Ordering::Relaxed);
            s.audio_silent_suppressed = audio_counters.silent_suppressed.load(Ordering::Relaxed);
        });
        // Cumulative injected count beside the send rate: under full video load
        // this should keep climbing as the client types (proving input is not
        // starved by encode). It stalling while frames_sent races is the
        // signature of the input-priority bug.
        tracing::info!(
            input_injected = injected,
            frames_sent = sent,
            "host input diag"
        );

        // Refill the refinement allowance from this window's measurements. Done
        // here because every input is already computed once per second and
        // agrees with what the adaptor just decided — recomputing any of it
        // elsewhere would risk the two disagreeing.
        // What refinement actually spent over the window just closed. This is
        // the evidence the ceiling is learned from, so it must be a matched
        // delta over the same window as `delivery`, not a lifetime total.
        let tile_bytes_now = tile_counters.bytes_sent.load(Ordering::Relaxed);
        let tile_spent_kbps = {
            // `delivery.dt_ms`, not a fresh `now`-based diff: `window.close()`
            // already advanced its own previous-tick clock above, so measuring
            // elapsed time again here would always give zero.
            let dt_ms = delivery.dt_ms.max(1);
            let delta = tile_bytes_now.saturating_sub(prev_tile_bytes);
            ((delta * 8) / dt_ms) as u32
        };
        prev_tile_bytes = tile_bytes_now;

        let budget = tile_throttle.observe(
            tile_spent_kbps,
            adaptor.lock().current(),
            media.bitrate_kbps,
            pressure,
            transport.loss,
            oversized_keyframe,
            streaming.load(Ordering::Relaxed),
            inner.cfg.tile_max_kbps,
        );
        // Refinement is stream 0's, and stream 0 is not always the persistent
        // pipeline any more: a client can point the primary stream at another
        // monitor. While it is elsewhere the budget is forced to zero, because
        // the only tile stream open belongs to the persistent pipeline and its
        // strips describe a desktop the client is no longer being shown. The
        // already-delivered tiles were retracted by the `reset_tiles` in the
        // `SelectMonitors` handler; this is what stops new ones being planned.
        // The budget refills by itself the moment stream 0 comes home.
        let budget = if primary_is_persistent { budget } else { 0 };
        // Published to the media thread, which is the only place a strip can be
        // dropped safely — it owns the grid, so it can decline to *plan* work
        // rather than discard work it has already recorded as delivered.
        pipeline.set_tile_budget_kbps(budget);

        // Audio, logged together for the same reason the tile line is: the four
        // numbers only mean anything beside each other. `audio_backpressured`
        // climbing while `backpressured` stays flat is audio correctly yielding
        // the send buffer to video; both climbing is a link in real trouble;
        // `silent_suppressed` climbing alone is a quiet desktop costing nothing.
        let audio_status = audio_counters.status();
        if audio_status != AudioStatus::Disabled {
            tracing::info!(
                ?audio_status,
                audio_packets = audio_counters.packets_sent.load(Ordering::Relaxed),
                audio_kbytes = audio_counters.bytes_sent.load(Ordering::Relaxed) / 1024,
                audio_backpressured = audio_counters.backpressured.load(Ordering::Relaxed),
                audio_silent_suppressed = audio_counters.silent_suppressed.load(Ordering::Relaxed),
                backpressured,
                "audio diag"
            );
        }

        let tile_strips = tile_counters.strips_sent.load(Ordering::Relaxed);
        if tile_strips > 0 {
            // Hazard 6's observable signature, logged together on purpose: if
            // `backpressured` climbs while tile traffic flows and loss stays at
            // zero, tiles are stealing the congestion window from video and the
            // budget above is too generous.
            tracing::info!(
                tile_strips,
                tile_kbytes = tile_counters.bytes_sent.load(Ordering::Relaxed) / 1024,
                tile_spent_kbps,
                tile_budget_kbps = budget,
                tile_ceiling_kbps = tile_throttle.ceiling(),
                backpressured,
                loss = transport.loss,
                "tile diag"
            );
        }
    }
}

/// Driver-level events: warnings, peer `Bye`, keyframe requests from loss.
async fn event_loop(
    inner: Arc<Inner>,
    mut rx: mpsc::Receiver<SessionEvent>,
    pipeline: Arc<HostSession>,
) {
    while let Some(ev) = rx.recv().await {
        match ev {
            SessionEvent::KeyframeNeeded => pipeline.request_keyframe(),
            SessionEvent::PeerClosed { reason } => {
                tracing::info!("client said goodbye: {reason}");
            }
            SessionEvent::Warning { detail } => {
                tracing::warn!("session warning: {detail}");
                inner.emit(NetEvent::Warning { detail });
            }
            SessionEvent::Closed { reason } => {
                tracing::debug!("session closed: {reason}");
                return;
            }
            SessionEvent::Stats(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- the monitor selection filter --------------------------------------

    #[test]
    fn a_selection_is_filtered_deduped_and_truncated() {
        let known = [0u8, 1, 2];

        // The ordinary cases the client actually sends.
        assert_eq!(filter_selection(&[0], &known, Some(0)), vec![0]);
        assert_eq!(filter_selection(&[1], &known, Some(0)), vec![1]);
        assert_eq!(filter_selection(&[0, 1], &known, Some(0)), vec![0, 1]);

        // An id this host never advertised names no output here. Dropped, not
        // clamped: guessing which monitor was meant would point a stream at the
        // wrong desktop, and a client working from a stale list is exactly the
        // case this is defending against.
        assert_eq!(filter_selection(&[7], &known, Some(0)), Vec::<u8>::new());
        assert_eq!(filter_selection(&[7, 1], &known, Some(0)), vec![1]);
        assert_eq!(filter_selection(&[1, 7, 2], &known, Some(0)), vec![1, 2]);

        // Two slots duplicating one output is two DXGI duplications of the same
        // monitor. First occurrence wins.
        assert_eq!(filter_selection(&[1, 1], &known, Some(0)), vec![1]);
        assert_eq!(filter_selection(&[1, 1, 2], &known, Some(0)), vec![1, 2]);

        // More than the host can run.
        assert_eq!(filter_selection(&[0, 1, 2], &known, Some(0)), vec![0, 1]);
        assert_eq!(
            filter_selection(&[2, 1, 0], &known, Some(0)).len(),
            MAX_VIDEO_STREAMS as usize
        );

        // Nothing at all keeps the caller's current selection; it never means
        // "stop every stream".
        assert!(filter_selection(&[], &known, Some(0)).is_empty());
        assert!(filter_selection(&[3, 4, 5], &known, Some(0)).is_empty());
    }

    #[test]
    fn truncation_never_detaches_the_resident_pipeline() {
        let known = [0u8, 1, 2];
        let n = MAX_VIDEO_STREAMS as usize;

        // The case this rule exists for. Truncating to the first two would run
        // monitors 1 and 2 — two new Desktop Duplications — while the
        // persistent pipeline goes on duplicating monitor 0 for nobody: three
        // duplications, one of them waste, and the client has lost the monitor
        // that was free. Monitor 2 gives way instead, and 0 lands in slot 0
        // where re-attaching it builds nothing at all.
        let got = filter_selection(&[1, 2, 0], &known, Some(0));
        assert_eq!(
            got,
            vec![0, 1],
            "the resident monitor was named and must survive the truncation; \
             {got:?} detaches the persistent pipeline"
        );

        // The requester's order is priority order and survives among the
        // survivors: its first choice keeps its place, its last choice is the
        // one dropped. (Slot assignment is then the ordinary slot-0 rule.)
        assert_eq!(filter_selection(&[2, 1, 0], &known, Some(0)), vec![0, 2]);

        // `resident` is not id 0 in general — an operator can move the Windows
        // primary. The rule follows the pipeline, not the number.
        assert_eq!(filter_selection(&[0, 1, 2], &known, Some(2)), vec![2, 0]);

        // A request that does not name the resident is truncated plainly. The
        // client has said it wants neither the free monitor nor slot 0's cheap
        // attach, and substituting one in would hand it a monitor it did not
        // ask for.
        assert_eq!(filter_selection(&[1, 2], &known, Some(0)), vec![1, 2]);
        let known4 = [0u8, 1, 2, 3];
        assert_eq!(filter_selection(&[1, 2, 3], &known4, Some(0)), vec![1, 2]);

        // Nothing resident (the pipeline's output is unplugged): plain
        // truncation, exactly as before.
        assert_eq!(filter_selection(&[1, 2, 0], &known, None), vec![1, 2]);

        // Lists that fit are untouched by any of this.
        assert_eq!(filter_selection(&[0, 1], &known, Some(0)), vec![0, 1]);
        assert_eq!(filter_selection(&[1, 0], &known, Some(0)), vec![0, 1]);
        assert_eq!(filter_selection(&[1, 2], &known, Some(2)), vec![2, 1]);

        // Truncation happens AFTER the unknown/duplicate filters, so ids the
        // host was never going to run cannot decide which real monitors
        // survive. Under the old order `[1, 1, 0]` filled the two slots with
        // one monitor's repeats and dropped the resident.
        assert_eq!(filter_selection(&[1, 1, 0], &known, Some(0)), vec![0, 1]);
        assert_eq!(filter_selection(&[1, 7, 2, 0], &known, Some(0)), vec![0, 1]);

        // Whatever the request, the result is a set of known ids, without
        // duplicates, within the slot budget — the properties every caller
        // downstream relies on.
        for a in 0..4u8 {
            for b in 0..4u8 {
                for c in 0..4u8 {
                    for resident in [None, Some(0), Some(1), Some(2)] {
                        let got = filter_selection(&[a, b, c], &known, resident);
                        assert!(got.len() <= n, "{a},{b},{c} -> {got:?} overruns the slots");
                        assert!(got.iter().all(|id| known.contains(id)));
                        let mut sorted = got.clone();
                        sorted.sort_unstable();
                        sorted.dedup();
                        assert_eq!(sorted.len(), got.len(), "{got:?} duplicates a monitor");
                        // And the rule itself, as a property: a resident that
                        // was asked for is always in the result.
                        if let Some(r) = resident {
                            if [a, b, c].contains(&r) && known.contains(&r) {
                                assert!(
                                    got.contains(&r),
                                    "resident {r} was requested in {:?} but dropped: {got:?}",
                                    [a, b, c]
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn the_primary_is_always_served_by_slot_zero() {
        // Not cosmetic. Monitor 0 is duplicated by the persistent pipeline,
        // which is never stopped — it outlives every client so the next one
        // does not wait for D3D11. Serving it from slot 1 would mean building a
        // second duplication of an output that pipeline still holds.
        let known = [0u8, 1, 2];
        assert_eq!(filter_selection(&[1, 0], &known, Some(0)), vec![0, 1]);
        assert_eq!(filter_selection(&[2, 0], &known, Some(0)), vec![0, 2]);
        // The selection itself is honoured — only the slot is chosen for the
        // client, and `StreamConfig` names the monitor explicitly anyway.
        let got = filter_selection(&[2, 0], &known, Some(0));
        assert!(got.contains(&0) && got.contains(&2));
        // A selection without the primary is left exactly as it came.
        assert_eq!(filter_selection(&[2, 1], &known, Some(0)), vec![2, 1]);
    }

    #[test]
    fn the_slot_zero_rule_follows_the_resident_pipeline_not_the_id_zero() {
        // The persistent pipeline resolves `Primary` once, at construction, and
        // keeps that output for life; `list_monitors` re-decides which output is
        // primary on every call. An operator moving the primary display in
        // Windows' display settings makes id 0 name a monitor the pipeline is
        // NOT showing — so the rule has to follow the pipeline, or it would pin
        // the wrong monitor to slot 0 and then try to build a second
        // duplication of the one the pipeline still holds.
        let known = [0u8, 1, 2];

        // The pipeline is on monitor 2. Selecting {0, 2} must put 2 in slot 0.
        assert_eq!(filter_selection(&[0, 2], &known, Some(2)), vec![2, 0]);
        // And id 0 is now an ordinary monitor with no special claim on slot 0.
        assert_eq!(filter_selection(&[1, 0], &known, Some(2)), vec![1, 0]);

        // Its output unplugged entirely: nothing is resident, so nothing moves
        // and every id is free to be built session-scoped.
        assert_eq!(filter_selection(&[1, 0], &known, None), vec![1, 0]);
        assert_eq!(filter_selection(&[0, 1], &known, None), vec![0, 1]);
    }

    // -- the reconciler ----------------------------------------------------

    fn slots(a: Option<u8>, b: Option<u8>) -> Vec<Option<u8>> {
        vec![a, b]
    }

    #[test]
    fn an_unchanged_selection_produces_no_work_at_all() {
        // Idempotence. A client re-sends its selection on reconnect and may on
        // any UI event; if that rebuilt a pipeline the picture would black out
        // every time somebody opened a menu.
        assert!(plan_slot_changes(&slots(Some(0), None), &[0]).is_empty());
        assert!(plan_slot_changes(&slots(Some(0), Some(1)), &[0, 1]).is_empty());
        assert!(plan_slot_changes(&slots(None, None), &[]).is_empty());
    }

    #[test]
    fn adding_and_dropping_the_second_stream() {
        assert_eq!(
            plan_slot_changes(&slots(Some(0), None), &[0, 1]),
            vec![SlotChange::Start {
                slot: 1,
                monitor: 1
            }],
            "adding a monitor must not disturb the stream already running"
        );
        assert_eq!(
            plan_slot_changes(&slots(Some(0), Some(1)), &[0]),
            vec![SlotChange::Stop { slot: 1 }],
        );
    }

    #[test]
    fn retargeting_a_slot_is_a_stop_then_a_start_never_a_swap() {
        // DXGI will not hand the same output to two duplications from the same
        // process, and the failure is an opaque DXGI_ERROR_NOT_CURRENTLY_
        // AVAILABLE at the worst possible moment. So a monitor moving between
        // slots — or a slot changing which monitor it carries — must always
        // release before it acquires.
        assert_eq!(
            plan_slot_changes(&slots(Some(0), None), &[1]),
            vec![
                SlotChange::Stop { slot: 0 },
                SlotChange::Start {
                    slot: 0,
                    monitor: 1
                }
            ],
        );

        // The case that would deadlock on a naive in-place swap: monitor 1
        // moves down from slot 1 into slot 0.
        let plan = plan_slot_changes(&slots(Some(0), Some(1)), &[1]);
        assert_eq!(
            plan,
            vec![
                SlotChange::Stop { slot: 1 },
                SlotChange::Stop { slot: 0 },
                SlotChange::Start {
                    slot: 0,
                    monitor: 1
                }
            ],
        );

        // The general property, over every assignment of two monitors to two
        // slots: no `Start` for a monitor may be planned before the `Stop` of
        // whichever slot was holding it.
        let all: Vec<Option<u8>> = vec![None, Some(0), Some(1), Some(2)];
        for a in &all {
            for b in &all {
                for desired in [
                    vec![],
                    vec![0],
                    vec![1],
                    vec![2],
                    vec![0, 1],
                    vec![0, 2],
                    vec![1, 2],
                    vec![2, 1],
                ] {
                    let current = slots(*a, *b);
                    let plan = plan_slot_changes(&current, &desired);
                    let first_start = plan
                        .iter()
                        .position(|c| matches!(c, SlotChange::Start { .. }));
                    let last_stop = plan
                        .iter()
                        .rposition(|c| matches!(c, SlotChange::Stop { .. }));
                    if let (Some(s), Some(t)) = (first_start, last_stop) {
                        assert!(
                            t < s,
                            "current {current:?} desired {desired:?}: a start is \
                             planned before a stop, so two duplications of one \
                             output can overlap — {plan:?}"
                        );
                    }
                    // And the plan really does reach the desired assignment.
                    let mut end = current.clone();
                    for change in &plan {
                        match *change {
                            SlotChange::Stop { slot } => end[slot as usize] = None,
                            SlotChange::Start { slot, monitor } => {
                                end[slot as usize] = Some(monitor)
                            }
                        }
                    }
                    let want: Vec<Option<u8>> = (0..MAX_VIDEO_STREAMS as usize)
                        .map(|i| desired.get(i).copied())
                        .collect();
                    assert_eq!(
                        end, want,
                        "current {current:?} desired {desired:?} plan {plan:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_slot_that_was_never_running_is_only_started() {
        assert_eq!(
            plan_slot_changes(&slots(None, None), &[0, 1]),
            vec![
                SlotChange::Start {
                    slot: 0,
                    monitor: 0
                },
                SlotChange::Start {
                    slot: 1,
                    monitor: 1
                }
            ],
        );
    }

    // -- the persistent slot's id, after the primary moves ------------------

    fn key_of(device: &str) -> MonitorKey {
        MonitorKey {
            adapter_luid: 1,
            device_name: device.into(),
            origin: match device {
                r"\\.\DISPLAY1" => (0, 0),
                _ => (1920, 0),
            },
        }
    }

    /// One row of a session's monitor table: id `id` naming output `device`.
    fn table_row(id: u8, device: &str) -> (MonitorInfo, MonitorKey) {
        let key = key_of(device);
        (
            MonitorInfo {
                id,
                width: 1920,
                height: 1080,
                origin_x: key.origin.0,
                origin_y: key.origin.1,
                is_primary: id == 0,
                name: device.into(),
            },
            key,
        )
    }

    #[test]
    fn the_persistent_slot_carries_the_id_its_output_has_now() {
        // The operator moves the Windows primary from DISPLAY1 to DISPLAY2
        // mid-session. `DdaCapture` resolved `Primary` once, at construction,
        // so the persistent pipeline is still duplicating DISPLAY1 — but ids
        // are positional and `list_monitors` has just renumbered DISPLAY1 from
        // 0 to 1. This is what the topology watchdog must write into slot 0.
        let persistent = key_of(r"\\.\DISPLAY1");
        let was = vec![table_row(0, r"\\.\DISPLAY1"), table_row(1, r"\\.\DISPLAY2")];
        let now = vec![table_row(0, r"\\.\DISPLAY2"), table_row(1, r"\\.\DISPLAY1")];

        assert_eq!(monitor_id_for_key(&was, &persistent), Some(0));
        assert_eq!(
            monitor_id_for_key(&now, &persistent),
            Some(1),
            "the pipeline's output is now id 1; the watchdog derives slot 0's \
             id from the key, and hardcoding 0 is what makes everything below \
             wrong"
        );

        // What `current()` therefore hands the reconciler.
        let slot0 = monitor_id_for_key(&now, &persistent).expect("the output is still listed");
        let current = slots(Some(slot0), None);

        // Selecting the monitor the pipeline is really showing is a no-op: it
        // is already on the wire, and "rebuilding" it would mean a second DXGI
        // duplication of an output this process still holds.
        assert!(
            plan_slot_changes(&current, &[1]).is_empty(),
            "SelectMonitors {{ [1] }} names the output slot 0 already duplicates \
             and must plan no work"
        );

        // And id 0 now names DISPLAY2, which nothing is duplicating, so that is
        // a real retarget.
        assert_eq!(
            plan_slot_changes(&current, &[0]),
            vec![
                SlotChange::Stop { slot: 0 },
                SlotChange::Start {
                    slot: 0,
                    monitor: 0
                }
            ],
        );

        // The bug this pins, stated as the plans a hardcoded 0 would produce:
        // exactly inverted, and wrong in both directions.
        let stale = slots(Some(0), None);
        assert!(
            !plan_slot_changes(&stale, &[1]).is_empty(),
            "with the stale id, the pipeline's own monitor reads as a retarget — \
             a second duplication of an output this process holds"
        );
        assert!(
            plan_slot_changes(&stale, &[0]).is_empty(),
            "with the stale id, a request for DISPLAY2 is judged already-running \
             and the client goes on receiving DISPLAY1's picture"
        );

        // An output that has left the table keeps its slot's old id rather than
        // taking a wrong one: the watchdog writes nothing when this is `None`.
        assert_eq!(monitor_id_for_key(&[], &persistent), None);
        assert_eq!(
            monitor_id_for_key(&[table_row(0, r"\\.\DISPLAY2")], &persistent),
            None
        );
    }

    // -- what a config message may quote as a bitrate -----------------------

    #[test]
    fn a_video_config_quotes_stream_zeros_applied_share() {
        // `VideoConfig` describes stream 0 and nothing else, so its
        // `bitrate_kbps` is slot 0's share — which is two steps below the
        // adaptor's `current()`: the cap, then the split.
        let two = AppliedBitrate {
            capped_total: 8_000,
            per_slot: vec![Some(5_000), Some(3_000)],
        };
        assert_eq!(two.share(0), 5_000);
        assert_eq!(two.share(1), 3_000);

        // The concrete defect, through the pure pieces it is built from: the
        // adaptor wants 10 Mbps, the client capped the connection at 8, and two
        // identical panels halve it. `VideoConfig` used to say 10000.
        let capped = clamp_to_cap(10_000, Some(8_000));
        let split = split_bitrate(capped, &[1920 * 1080, 1920 * 1080]);
        let real = AppliedBitrate {
            capped_total: capped,
            per_slot: split.iter().copied().map(Some).collect(),
        };
        assert_eq!(real.share(0), 4_000);
        assert_eq!(real.share(0), real.per_slot[0].unwrap());
        assert_ne!(real.share(0), 10_000, "the adaptor's total is not a share");
        assert_ne!(
            real.share(0),
            capped,
            "nor is the connection's capped total"
        );
        // And `StreamConfig` reads the same accessor, so the two format
        // messages can no longer contradict each other about one connection.
        assert_eq!(real.share(0) + real.share(1), capped);

        // One monitor: the split is a pass-through, so the share IS the capped
        // total — still not the adaptor's raw number while a cap is in force.
        let lone = AppliedBitrate {
            capped_total: clamp_to_cap(10_000, Some(6_000)),
            per_slot: vec![Some(6_000), None],
        };
        assert_eq!(lone.share(0), 6_000);

        // A slot that is not running has no applied share. The capped total is
        // the honest fallback — never zero, which would read as a dead stream,
        // and never the uncapped total, which would exceed what the client
        // asked for.
        let idle = AppliedBitrate {
            capped_total: 4_000,
            per_slot: vec![None, None],
        };
        assert_eq!(idle.share(0), 4_000);
        assert_eq!(idle.share(1), 4_000);
        assert_eq!(idle.share(9), 4_000, "an out-of-range slot must not panic");
    }

    // -- input routing -----------------------------------------------------

    #[test]
    fn pointer_events_follow_their_stream_and_keys_never_do() {
        let key = InputEvent::Key {
            scan_code: 0x1E,
            extended: false,
            action: directdesk_shared::input::KeyAction::Down,
        };
        let moved = InputEvent::MouseMove { x: 100, y: 200 };
        let click = InputEvent::MouseButton {
            button: directdesk_shared::input::MouseButton::Left,
            action: directdesk_shared::input::KeyAction::Down,
            x: 1,
            y: 2,
        };
        let wheel = InputEvent::MouseWheel {
            delta: 120,
            horizontal: false,
            x: 1,
            y: 2,
        };

        // Pointer coordinates are normalized against one stream's frame, so
        // they must reach that stream's injector or they land somewhere else.
        for ev in [&moved, &click, &wheel] {
            assert_eq!(route_for(0, ev), 0);
            assert_eq!(route_for(1, ev), 1);
        }

        // Held-key and modifier state lives in an injector. Two of them and a
        // Shift pressed on one would not apply to the character typed on the
        // other — and a Ctrl held while the pointer moved across would never be
        // released by the injector still tracking it.
        assert_eq!(route_for(0, &key), 0);
        assert_eq!(
            route_for(1, &key),
            0,
            "there is one keyboard on the client's desk, so one keyboard injector here"
        );
    }

    // -- merging two pipelines into one pinned ConnStats --------------------

    fn media(bitrate: u32, dropped: u32, keyframes: u32, pipeline_ms: f32, fps: f32) -> ConnStats {
        ConnStats {
            bitrate_kbps: bitrate,
            frames_dropped: dropped,
            keyframes_requested: keyframes,
            pipeline_ms,
            fps_capture: fps,
            fps_encode: fps,
            ..ConnStats::default()
        }
    }

    #[test]
    fn one_stream_merges_to_itself_byte_for_byte() {
        // The regression guard for the single-monitor wire: `ConnStats` is
        // pinned by the anti-brick suite and read positionally by deployed
        // peers, so a one-stream session must produce exactly the struct it
        // produced before merging existed.
        let only = media(6_000, 3, 2, 17.0, 59.5);
        assert_eq!(merge_media_stats(only, &[]), only);
    }

    #[test]
    fn merging_sums_costs_keeps_stream_zeros_rates_and_takes_the_worst_latency() {
        let primary = media(6_000, 3, 2, 17.0, 60.0);
        let secondary = media(4_000, 5, 1, 42.0, 30.0);
        let merged = merge_media_stats(primary, &[secondary]);

        // Costs and losses are totals: the client is asking what this session
        // is spending, and it is spending both.
        assert_eq!(merged.bitrate_kbps, 10_000);
        assert_eq!(merged.frames_dropped, 8);
        assert_eq!(merged.keyframes_requested, 3);

        // A frame rate cannot be summed — 60 + 30 is not 90 fps of anything —
        // and averaging would report a rate neither monitor is running at.
        assert_eq!(merged.fps_capture, 60.0);
        assert_eq!(merged.fps_encode, 60.0);

        // Latency is the worst one: a user watching two monitors feels the
        // slower of them.
        assert_eq!(merged.pipeline_ms, 42.0);
    }

    #[test]
    fn merging_cannot_overflow_into_a_smaller_number() {
        // These are lifetime counters on a long session and the merge runs
        // every second. Wrapping would turn a busy host into one reporting
        // almost no traffic at all.
        let a = media(u32::MAX, u32::MAX, u32::MAX, 1_000.0, 60.0);
        let merged = merge_media_stats(a, &[a, a]);
        assert_eq!(merged.bitrate_kbps, u32::MAX);
        assert_eq!(merged.frames_dropped, u32::MAX);
        assert_eq!(merged.keyframes_requested, u32::MAX);
        assert_eq!(merged.pipeline_ms, 1_000.0);
    }

    /// One second of a mid-range stream, big enough that the ratios below are
    /// not dominated by rounding.
    const ENCODER_KBPS: u32 = 6_000;

    fn link_carrying(kbps: u32) -> ConnStats {
        ConnStats {
            bandwidth_kbps: kbps,
            ..ConnStats::default()
        }
    }

    /// The [`WindowDelivery`] `egress::video_pump` records for a window in
    /// which it offered every one of the encoder's bytes to `send_datagram`.
    ///
    /// Built from the fragmenter's real arithmetic rather than a fudge factor:
    /// the payload, one `FRAG_HEADER_LEN` header per `mtu - FRAG_HEADER_LEN`
    /// chunk, plus one full-width XOR parity fragment per FEC block. The point
    /// is not the exact number, it is that this is *strictly greater* than the
    /// encoder's own figure no matter how the fragmenter is tuned — the pump
    /// adds framing, it never removes any.
    ///
    /// `sent`/`offered` are set equal because that is the case under test:
    /// quinn accepted every frame. Nothing was backpressured, so
    /// `backpressure_ratio` reads zero and the overrun diagnostic is the only
    /// congestion evidence left.
    fn offered_everything(encoder_kbps: u32) -> WindowDelivery {
        const MTU: u64 = 1_200;
        const FRAG_HEADER_LEN: u64 = 12;
        const FEC_BLOCK: u64 = 10;
        let chunk = MTU - FRAG_HEADER_LEN;
        let payload = encoder_kbps as u64 * 1_000 / 8;
        let frags = payload.div_ceil(chunk);
        let parity = frags.div_ceil(FEC_BLOCK);
        WindowDelivery {
            sent: 60,
            offered: 60,
            bytes: payload + frags * FRAG_HEADER_LEN + parity * (chunk + FRAG_HEADER_LEN),
            dt_ms: 1_000,
        }
    }

    #[test]
    fn overrun_fires_when_the_link_carries_less_than_the_encoder_produces() {
        // The failure this signal exists for, and the only one that produces
        // it: quinn accepted every datagram we offered and then dropped most of
        // them itself. Nothing appears as packet loss (nothing was put on the
        // wire) and nothing appears as backpressure (the send buffer never
        // filled). The sole remaining evidence is that the transport moved far
        // fewer bytes than the encoder produced.
        let stalled = link_carrying(2_000);
        assert!(
            window_overrun(ENCODER_KBPS, &stalled) > 0.6,
            "a link carrying a third of the encoder's output must read as heavy \
             overrun, got {}",
            window_overrun(ENCODER_KBPS, &stalled)
        );

        // A healthy link carrying everything — plus protocol overhead and the
        // client's own uplink, which `bandwidth_kbps` also counts — reads as no
        // overrun at all. This is the direction the 15% slack protects.
        assert_eq!(window_overrun(ENCODER_KBPS, &link_carrying(6_400)), 0.0);
        assert_eq!(window_overrun(ENCODER_KBPS, &link_carrying(20_000)), 0.0);
    }

    #[test]
    fn the_overrun_denominator_is_bytes_carried_never_bytes_offered() {
        // REGRESSION GUARD. `delivery.throughput_kbps()` counts what
        // `egress::video_pump` handed to `send_datagram`, accumulated *before*
        // the call, and `send_datagram` never refuses. On a link that has
        // stalled completely that figure is unchanged, so an overrun computed
        // from it is structurally zero in exactly the case the signal exists to
        // catch. Read `window_overrun`'s doc comment before touching this.
        let offered = offered_everything(ENCODER_KBPS);
        assert!(
            offered.throughput_kbps() > ENCODER_KBPS,
            "the pump's own byte count is the encoder's output plus framing, so \
             it can only ever exceed it: {} vs {ENCODER_KBPS}",
            offered.throughput_kbps()
        );
        assert_eq!(
            overrun_signal(ENCODER_KBPS, offered.throughput_kbps()),
            0.0,
            "a bytes-offered denominator cannot report overrun even when the \
             link carried literally nothing — it is not a measurement of the \
             link at all"
        );

        // The measurement actually in use sees that same window for what it is.
        assert!(window_overrun(ENCODER_KBPS, &link_carrying(500)) > 0.0);
    }

    #[test]
    fn a_bytes_offered_denominator_stays_silent_past_a_fifth_of_frames_lost() {
        // Quantifies the previous test. Because the offered figure runs ~11%
        // above the encoder's own, `overrun_signal`'s 15% slack is not crossed
        // until over a fifth of frames are dropped outright — and at that point
        // `backpressure_ratio` has already reported the same congestion far
        // more directly, so the diagnostic adds nothing it did not already say.
        for dropped_pct in [0u64, 5, 10, 15, 20] {
            let mut window = offered_everything(ENCODER_KBPS);
            window.bytes = window.bytes * (100 - dropped_pct) / 100;
            assert_eq!(
                overrun_signal(ENCODER_KBPS, window.throughput_kbps()),
                0.0,
                "{dropped_pct}% of the stream gone and a bytes-offered \
                 denominator is still reporting a healthy link"
            );
        }
    }

    #[test]
    fn overrun_is_scale_free_and_safe_at_the_edges() {
        // Zero on either side is "no measurement", not "no congestion": a
        // window in which the encoder produced nothing, or one in which the
        // transport figure has not been sampled yet, must not drive the
        // adaptor. `StatusWindow`'s warm-up gate is the other half of this.
        assert_eq!(window_overrun(0, &link_carrying(6_000)), 0.0);
        assert_eq!(window_overrun(ENCODER_KBPS, &link_carrying(0)), 0.0);
        // And the ratio depends on the shortfall, not the absolute rate, so it
        // reads the same on a 500 kbps link as on a 50 Mbps one.
        assert_eq!(
            window_overrun(1_000, &link_carrying(500)),
            window_overrun(100_000, &link_carrying(50_000))
        );
    }
}
