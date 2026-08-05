//! Host-side driver for the UAC click-through.
//!
//! Three pieces, deliberately separable so the decision logic is testable
//! without any Windows call or real clock:
//!
//! * [`ElevationMachine`] — a **pure** arm/detect state machine. Given whether a
//!   consent prompt is on screen and an injected clock, it decides when to
//!   notify the client, when to begin routing input to the SYSTEM worker, and
//!   when to tear it all down (prompt gone, TTL expired, one-shot consumed).
//! * [`SvcControlClient`] — a one-shot client of the service's control pipe
//!   (`PIPE_NAME`) that asks it to start/stop the SYSTEM worker.
//! * [`UacDataClient`] — the client of the worker's own data pipe: presents the
//!   capability token, sends geometry, then streams input events.
//!
//! Only the state machine is unit-tested; the pipe clients need a live service
//! and a live SYSTEM worker, which cannot exist under an unelevated `cargo test`.

use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Pure arm/detect state machine
// ---------------------------------------------------------------------------

/// Where the click-through flow currently sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElevPhase {
    /// No consent prompt; nothing armed.
    Idle,
    /// A consent prompt is up; the client has been notified and may arm.
    Prompted,
    /// The client armed; waiting to (re)enter routing while a prompt is present.
    Armed,
    /// Input is being routed to the SYSTEM worker.
    Routing,
    /// This arming is finished (prompt gone / TTL expired / one-shot consumed);
    /// it will not route again without a fresh arm. Resets to [`Idle`] once the
    /// screen is clear of the prompt.
    Ended,
}

/// What the caller must do as a result of a [`ElevationMachine::observe`] /
/// [`ElevationMachine::arm`] step. Exactly one side effect per step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElevEffect {
    /// Nothing to do.
    None,
    /// A consent prompt just appeared — send `ControlMsg::ElevationPrompt`.
    Notify,
    /// Start the SYSTEM worker and route input to it.
    BeginRoute,
    /// Stop routing: tear the worker down and send `ControlMsg::ElevationEnded`.
    EndRoute,
    /// The arming/prompt ended before any routing began — send
    /// `ControlMsg::ElevationEnded` to clear the client's affordance. No worker
    /// was ever started, so there is nothing to tear down.
    Cleared,
}

/// The arm/detect state machine. Pure: every method takes the current prompt
/// state and an explicit `now`, so it is fully testable with a fake clock.
#[derive(Debug, Clone)]
pub struct ElevationMachine {
    phase: ElevPhase,
    one_shot: bool,
    ttl: Duration,
    armed_at: Option<Instant>,
}

impl Default for ElevationMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl ElevationMachine {
    pub fn new() -> Self {
        Self {
            phase: ElevPhase::Idle,
            one_shot: true,
            ttl: Duration::ZERO,
            armed_at: None,
        }
    }

    pub fn phase(&self) -> ElevPhase {
        self.phase
    }

    pub fn is_routing(&self) -> bool {
        self.phase == ElevPhase::Routing
    }

    /// The client opted in. Only accepted while a prompt is actually on screen
    /// (phase [`ElevPhase::Prompted`]); an arm with nothing to click is ignored.
    /// Returns whether it was accepted.
    pub fn arm(&mut self, one_shot: bool, ttl: Duration, now: Instant) -> bool {
        if self.phase != ElevPhase::Prompted {
            return false;
        }
        self.one_shot = one_shot;
        self.ttl = ttl;
        self.armed_at = Some(now);
        self.phase = ElevPhase::Armed;
        true
    }

    fn expired(&self, now: Instant) -> bool {
        match self.armed_at {
            Some(t) => now.saturating_duration_since(t) > self.ttl,
            None => false,
        }
    }

    /// Advance the machine given whether a consent prompt is currently on
    /// screen. Call this on every detector poll.
    pub fn observe(&mut self, prompt: bool, now: Instant) -> ElevEffect {
        match self.phase {
            ElevPhase::Idle => {
                if prompt {
                    self.phase = ElevPhase::Prompted;
                    ElevEffect::Notify
                } else {
                    ElevEffect::None
                }
            }
            ElevPhase::Prompted => {
                if !prompt {
                    // The prompt vanished before the operator armed; clear the
                    // client-side affordance.
                    self.reset();
                    ElevEffect::Cleared
                } else {
                    ElevEffect::None
                }
            }
            ElevPhase::Armed => {
                if self.expired(now) || !prompt && self.one_shot {
                    // Armed but the window to act closed (TTL, or a one-shot
                    // prompt withdrawn) before any routing started.
                    self.end();
                    ElevEffect::Cleared
                } else if prompt {
                    self.phase = ElevPhase::Routing;
                    ElevEffect::BeginRoute
                } else {
                    // TTL-mode, prompt momentarily gone but still armed: wait.
                    ElevEffect::None
                }
            }
            ElevPhase::Routing => {
                if self.expired(now) {
                    self.end();
                    ElevEffect::EndRoute
                } else if !prompt {
                    // The consent dialog closed — this elevation is done.
                    if self.one_shot {
                        self.end();
                    } else {
                        // TTL-mode: stay armed for another prompt within the TTL.
                        self.phase = ElevPhase::Armed;
                    }
                    ElevEffect::EndRoute
                } else {
                    ElevEffect::None
                }
            }
            ElevPhase::Ended => {
                if !prompt {
                    self.reset();
                }
                ElevEffect::None
            }
        }
    }

    /// Force the flow down (host stopping, worker died, client disconnected).
    /// Returns [`ElevEffect::EndRoute`] if it was actively routing, otherwise
    /// [`ElevEffect::Cleared`] if anything was pending, else [`ElevEffect::None`].
    pub fn cancel(&mut self) -> ElevEffect {
        let effect = match self.phase {
            ElevPhase::Routing => ElevEffect::EndRoute,
            ElevPhase::Idle => ElevEffect::None,
            _ => ElevEffect::Cleared,
        };
        self.reset();
        effect
    }

    fn reset(&mut self) {
        self.phase = ElevPhase::Idle;
        self.armed_at = None;
    }

    fn end(&mut self) {
        self.phase = ElevPhase::Ended;
        self.armed_at = None;
    }
}

// ---------------------------------------------------------------------------
// Windows pipe clients (not unit-tested: need a live service + SYSTEM worker)
// ---------------------------------------------------------------------------

#[cfg(windows)]
pub use win::{SvcControlClient, UacDataClient};

#[cfg(windows)]
mod win {
    use directdesk_shared::protocol::{decode_strict, encode_framed, parse_frame_len};
    use directdesk_shared::svc_ipc::{SvcRequest, SvcResponse, MAX_IPC_MSG, PIPE_NAME};
    use directdesk_shared::{Error, Result};

    use crate::uac_proto::{encode as encode_uac, UacWireMsg, MAX_UAC_MSG};
    use crate::winpipe::{pcwstr, wide, OwnedHandle};

    use windows::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, ReadFile, WriteFile, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE, OPEN_EXISTING,
    };
    use windows::Win32::System::Pipes::{
        SetNamedPipeHandleState, WaitNamedPipeW, PIPE_READMODE_MESSAGE,
    };

    fn winerr(what: &str) -> Error {
        Error::Transport(format!("{what}: {}", windows::core::Error::from_thread()))
    }

    /// Open a message-mode client handle to an existing named pipe, waiting up
    /// to `timeout_ms` for an instance to become available.
    fn connect_message_pipe(name: &str, timeout_ms: u32) -> Result<OwnedHandle> {
        let name_w = wide(name);
        // SAFETY: name_w is NUL-terminated and alive across both calls.
        unsafe {
            // Best-effort wait; a failure here just means CreateFileW will try
            // immediately and report the real error.
            let _ = WaitNamedPipeW(pcwstr(&name_w), timeout_ms);
            let h = CreateFileW(
                pcwstr(&name_w),
                (GENERIC_READ | GENERIC_WRITE).0,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            )
            .map_err(|e| Error::Transport(format!("open pipe {name}: {e}")))?;
            let handle = OwnedHandle::new(h);
            let mode = PIPE_READMODE_MESSAGE;
            SetNamedPipeHandleState(handle.raw(), Some(&mode), None, None)
                .map_err(|e| Error::Transport(format!("set message mode on {name}: {e}")))?;
            Ok(handle)
        }
    }

    fn write_all(handle: &OwnedHandle, bytes: &[u8]) -> Result<()> {
        let mut written = 0u32;
        // SAFETY: synchronous write on a connected message-mode pipe handle.
        unsafe {
            WriteFile(handle.raw(), Some(bytes), Some(&mut written), None)
                .map_err(|_| winerr("pipe write"))?;
        }
        if written as usize != bytes.len() {
            return Err(Error::Transport(format!(
                "short pipe write: {written}/{} bytes",
                bytes.len()
            )));
        }
        Ok(())
    }

    /// One-shot client of the service's control pipe. The service answers one
    /// request per connection and disconnects, matching `service/src/pipe.rs`.
    pub struct SvcControlClient;

    impl SvcControlClient {
        fn request(req: SvcRequest) -> Result<SvcResponse> {
            let handle = connect_message_pipe(PIPE_NAME, 5_000)?;
            let frame = encode_framed(&req)?;
            write_all(&handle, &frame)?;

            let mut buf = vec![0u8; 4 + MAX_IPC_MSG];
            let mut read = 0u32;
            // SAFETY: synchronous read on the connected message-mode pipe; buf
            // is large enough for a whole framed response.
            unsafe {
                ReadFile(handle.raw(), Some(&mut buf), Some(&mut read), None)
                    .map_err(|_| winerr("pipe read"))?;
            }
            let n = read as usize;
            if n < 4 {
                return Err(Error::Invalid(format!("short control reply: {n} bytes")));
            }
            let declared = parse_frame_len(buf[..4].try_into().unwrap(), MAX_IPC_MSG)?;
            if n - 4 != declared {
                return Err(Error::Invalid("control reply length mismatch".into()));
            }
            decode_strict::<SvcResponse>(&buf[4..n])
        }

        /// Ask the service to start a SYSTEM injector worker. On success the
        /// response is [`SvcResponse::UacInjectorReady`] with the data-pipe name
        /// and the one-time capability token.
        pub fn start_uac_injector() -> Result<SvcResponse> {
            Self::request(SvcRequest::StartUacInjector)
        }

        /// Ask the service to stop any running injector worker.
        pub fn stop_uac_injector() -> Result<SvcResponse> {
            Self::request(SvcRequest::StopUacInjector)
        }
    }

    /// Client of the worker's data pipe. Presents the capability token, sends
    /// the frame geometry once, then streams input events.
    pub struct UacDataClient {
        handle: OwnedHandle,
    }

    impl UacDataClient {
        /// Connect and authenticate. The worker may still be creating its pipe,
        /// so [`connect_message_pipe`] waits for an instance.
        pub fn connect(pipe_name: &str, cap_token: &str) -> Result<Self> {
            let handle = connect_message_pipe(pipe_name, 5_000)?;
            let client = Self { handle };
            client.send(&UacWireMsg::Hello {
                cap_token: cap_token.to_string(),
            })?;
            Ok(client)
        }

        fn send(&self, msg: &UacWireMsg) -> Result<()> {
            let frame = encode_uac(msg)?;
            if frame.len() > 4 + MAX_UAC_MSG {
                return Err(Error::Oversized {
                    got: frame.len(),
                    limit: 4 + MAX_UAC_MSG,
                });
            }
            write_all(&self.handle, &frame)
        }

        /// Send the frame geometry the worker needs to map coordinates.
        pub fn send_geometry(&self, width: u32, height: u32, origin: (i32, i32)) -> Result<()> {
            self.send(&UacWireMsg::Geometry {
                width,
                height,
                origin_x: origin.0,
                origin_y: origin.1,
            })
        }

        /// Forward one input message to the worker.
        pub fn send_input(&self, msg: directdesk_shared::protocol::InputMsg) -> Result<()> {
            self.send(&UacWireMsg::Input(msg))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    /// Drive: Idle → Prompted → Armed → Routing, then the prompt closes.
    #[test]
    fn happy_path_one_shot() {
        let t0 = Instant::now();
        let mut m = ElevationMachine::new();
        assert_eq!(m.phase(), ElevPhase::Idle);

        // Prompt appears.
        assert_eq!(m.observe(true, t0), ElevEffect::Notify);
        assert_eq!(m.phase(), ElevPhase::Prompted);

        // Operator arms (one-shot, 20s TTL).
        assert!(m.arm(true, secs(20), t0 + secs(1)));
        assert_eq!(m.phase(), ElevPhase::Armed);

        // Next poll with the prompt still up begins routing.
        assert_eq!(m.observe(true, t0 + secs(2)), ElevEffect::BeginRoute);
        assert!(m.is_routing());

        // Still routing while the prompt is up.
        assert_eq!(m.observe(true, t0 + secs(3)), ElevEffect::None);

        // The consent dialog closes — the elevation is done.
        assert_eq!(m.observe(false, t0 + secs(4)), ElevEffect::EndRoute);
        assert_eq!(m.phase(), ElevPhase::Ended);

        // A one-shot arming does not route again on its own.
        assert_eq!(m.observe(false, t0 + secs(5)), ElevEffect::None);
        assert_eq!(m.phase(), ElevPhase::Idle);
    }

    #[test]
    fn arm_is_ignored_without_a_prompt() {
        let t0 = Instant::now();
        let mut m = ElevationMachine::new();
        assert!(!m.arm(true, secs(20), t0), "cannot arm from Idle");
        assert_eq!(m.phase(), ElevPhase::Idle);
    }

    #[test]
    fn prompt_withdrawn_before_arming_clears() {
        let t0 = Instant::now();
        let mut m = ElevationMachine::new();
        assert_eq!(m.observe(true, t0), ElevEffect::Notify);
        assert_eq!(m.observe(false, t0 + secs(1)), ElevEffect::Cleared);
        assert_eq!(m.phase(), ElevPhase::Idle);
    }

    #[test]
    fn ttl_expiry_while_routing_ends_it() {
        let t0 = Instant::now();
        let mut m = ElevationMachine::new();
        m.observe(true, t0);
        assert!(m.arm(true, secs(20), t0));
        assert_eq!(m.observe(true, t0 + secs(1)), ElevEffect::BeginRoute);
        // Still within TTL.
        assert_eq!(m.observe(true, t0 + secs(20)), ElevEffect::None);
        // One tick past TTL, even with the prompt still up, tears it down.
        assert_eq!(m.observe(true, t0 + secs(21)), ElevEffect::EndRoute);
        assert_eq!(m.phase(), ElevPhase::Ended);
        // Lingering prompt does not re-route.
        assert_eq!(m.observe(true, t0 + secs(22)), ElevEffect::None);
        assert_eq!(m.phase(), ElevPhase::Ended);
        // Only once the prompt clears does it reset.
        assert_eq!(m.observe(false, t0 + secs(23)), ElevEffect::None);
        assert_eq!(m.phase(), ElevPhase::Idle);
    }

    #[test]
    fn ttl_expiry_while_only_armed_clears_without_routing() {
        let t0 = Instant::now();
        let mut m = ElevationMachine::new();
        m.observe(true, t0);
        assert!(m.arm(true, secs(10), t0));
        // Prompt momentarily gone, one-shot: closes the opportunity.
        assert_eq!(m.observe(false, t0 + secs(1)), ElevEffect::Cleared);
        assert_eq!(m.phase(), ElevPhase::Ended);
    }

    #[test]
    fn ttl_mode_reroutes_across_multiple_prompts() {
        let t0 = Instant::now();
        let mut m = ElevationMachine::new();
        m.observe(true, t0);
        // Not one-shot: armed for the whole TTL window.
        assert!(m.arm(false, secs(30), t0));
        assert_eq!(m.observe(true, t0 + secs(1)), ElevEffect::BeginRoute);
        // First prompt closes — but the TTL arming survives for the next one.
        assert_eq!(m.observe(false, t0 + secs(2)), ElevEffect::EndRoute);
        assert_eq!(m.phase(), ElevPhase::Armed);
        // TTL-mode holds while there is no prompt.
        assert_eq!(m.observe(false, t0 + secs(3)), ElevEffect::None);
        // A second prompt within the TTL routes again without re-arming.
        assert_eq!(m.observe(true, t0 + secs(4)), ElevEffect::BeginRoute);
        // ...until the TTL finally expires.
        assert_eq!(m.observe(true, t0 + secs(31)), ElevEffect::EndRoute);
        assert_eq!(m.phase(), ElevPhase::Ended);
    }

    #[test]
    fn cancel_from_routing_reports_endroute() {
        let t0 = Instant::now();
        let mut m = ElevationMachine::new();
        m.observe(true, t0);
        m.arm(true, secs(20), t0);
        m.observe(true, t0 + secs(1));
        assert!(m.is_routing());
        assert_eq!(m.cancel(), ElevEffect::EndRoute);
        assert_eq!(m.phase(), ElevPhase::Idle);
    }

    #[test]
    fn cancel_from_prompted_reports_cleared_and_from_idle_none() {
        let t0 = Instant::now();
        let mut m = ElevationMachine::new();
        assert_eq!(m.cancel(), ElevEffect::None);
        m.observe(true, t0);
        assert_eq!(m.cancel(), ElevEffect::Cleared);
        assert_eq!(m.phase(), ElevPhase::Idle);
    }

    #[test]
    fn a_fresh_prompt_after_completion_notifies_again() {
        let t0 = Instant::now();
        let mut m = ElevationMachine::new();
        m.observe(true, t0);
        m.arm(true, secs(20), t0);
        m.observe(true, t0 + secs(1));
        m.observe(false, t0 + secs(2)); // EndRoute -> Ended
        m.observe(false, t0 + secs(3)); // -> Idle
        // A brand-new prompt starts the cycle over.
        assert_eq!(m.observe(true, t0 + secs(10)), ElevEffect::Notify);
        assert_eq!(m.phase(), ElevPhase::Prompted);
    }
}
