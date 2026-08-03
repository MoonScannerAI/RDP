//! The service's local IPC endpoint: an ACL'd, message-mode named pipe that
//! speaks exactly the [`SvcRequest`]/[`SvcResponse`] contract and nothing else.
//!
//! Hardening, in order of importance:
//!
//! * **Explicit DACL** ([`PIPE_SDDL`]) — only SYSTEM, Administrators, and
//!   INTERACTIVE users may touch the pipe. No `NULL` DACL, no "everyone".
//! * **`FILE_FLAG_FIRST_PIPE_INSTANCE`** on the first instance — if anything
//!   already owns this pipe name, we fail to start rather than share the name
//!   with a squatter that could impersonate the service.
//! * **`PIPE_REJECT_REMOTE_CLIENTS`** — local callers only.
//! * **Message mode with a hard cap** — one request is one message, capped at
//!   [`MAX_IPC_MSG`]; oversize and malformed input are answered with a `Failed`
//!   response and a disconnect, never a panic and never a large allocation.
//!
//! The payload itself carries no parameters at all (see [`crate::dispatch`]),
//! so nothing a client sends is ever interpreted as a path or a command.

use std::sync::Arc;
use std::thread::JoinHandle;

use directdesk_shared::protocol::{decode_strict, parse_frame_len};
use directdesk_shared::svc_ipc::{SvcRequest, SvcResponse, MAX_IPC_MSG};
use windows::Win32::Foundation::{
    LocalFree, ERROR_IO_PENDING, ERROR_MORE_DATA, ERROR_PIPE_CONNECTED, HANDLE, HLOCAL,
    WAIT_OBJECT_0,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::{
    ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_MESSAGE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE, PIPE_WAIT,
};
use windows::Win32::System::Threading::{WaitForMultipleObjects, INFINITE};
use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

use crate::dispatch::{dispatch, Backend};
use crate::winutil::{pcwstr, wide, Event, OwnedHandle};

/// DACL for the pipe, in SDDL:
/// * `D:P`            — protected DACL, no inherited ACEs
/// * `(A;;GA;;;SY)`   — LocalSystem: full access
/// * `(A;;GA;;;BA)`   — Builtin\Administrators: full access
/// * `(A;;GRGW;;;IU)` — INTERACTIVE users: read + write (that's all a client needs)
pub const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

/// Concurrent pipe instances. Requests are tiny and rare; a handful is plenty
/// and bounds how much a misbehaving local client can occupy.
pub const DEFAULT_INSTANCES: u32 = 4;

/// A connected client that sends nothing (or reads nothing) is dropped after
/// this long, so it cannot pin a pipe instance indefinitely.
const CLIENT_IO_TIMEOUT_MS: u32 = 5_000;

/// Largest wire frame: 4-byte length prefix plus the capped body.
const MAX_FRAME: usize = 4 + MAX_IPC_MSG;

// ---------------------------------------------------------------------------
// Framing (pure, no Windows involved — unit-tested directly)
// ---------------------------------------------------------------------------

/// Serialize a response as `u32-le length || postcard body`, capped at
/// [`MAX_IPC_MSG`].
pub fn encode_frame<T: serde::Serialize>(msg: &T) -> anyhow::Result<Vec<u8>> {
    let body = postcard::to_stdvec(msg)?;
    if body.len() > MAX_IPC_MSG {
        anyhow::bail!("outgoing message {} bytes exceeds cap {MAX_IPC_MSG}", body.len());
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Parse one complete frame (prefix included) into a request.
///
/// Rejects: short frames, zero-length bodies, bodies over [`MAX_IPC_MSG`],
/// prefix/body length disagreement, unknown enum variants, trailing bytes.
pub fn decode_request(frame: &[u8]) -> anyhow::Result<SvcRequest> {
    if frame.len() < 4 {
        anyhow::bail!("short frame: {} bytes", frame.len());
    }
    let prefix: [u8; 4] = frame[..4].try_into().expect("checked length");
    let declared = parse_frame_len(prefix, MAX_IPC_MSG)?;
    let body = &frame[4..];
    if body.len() != declared {
        anyhow::bail!("frame length mismatch: prefix says {declared}, body is {}", body.len());
    }
    Ok(decode_strict::<SvcRequest>(body)?)
}

// ---------------------------------------------------------------------------
// Handles
// ---------------------------------------------------------------------------

/// The manual-reset event used to wake every blocked pipe instance at shutdown.
pub type StopSignal = Event;

/// A security descriptor built from SDDL; frees itself with `LocalFree`.
struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

// SAFETY: the descriptor is a plain heap allocation with no thread affinity.
unsafe impl Send for SecurityDescriptor {}

impl SecurityDescriptor {
    /// Convert an SDDL string into a self-relative security descriptor.
    fn from_sddl(sddl: &str) -> anyhow::Result<Self> {
        let sddl_w = wide(sddl);
        let mut psd = PSECURITY_DESCRIPTOR::default();
        // SAFETY: sddl_w outlives the call; psd receives a LocalAlloc'd buffer.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                pcwstr(&sddl_w),
                SDDL_REVISION_1,
                &mut psd,
                None,
            )
        }
        .map_err(|e| anyhow::anyhow!("SDDL {sddl:?} could not be converted: {e}"))?;
        Ok(Self(psd))
    }

    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0 .0,
            bInheritHandle: false.into(),
        }
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: the buffer came from ConvertStringSecurityDescriptor... (LocalAlloc).
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0 .0)));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// A running pipe server. Dropping it (or calling [`PipeServer::shutdown`])
/// stops every instance and joins its thread.
pub struct PipeServer {
    stop: Arc<StopSignal>,
    threads: Vec<JoinHandle<()>>,
    name: String,
}

impl PipeServer {
    /// Signal shutdown and join all instance threads.
    pub fn shutdown(&mut self) {
        if self.threads.is_empty() {
            return;
        }
        tracing::info!("stopping pipe server {}", self.name);
        self.stop.signal();
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
        tracing::info!("pipe server {} stopped", self.name);
    }
}

impl Drop for PipeServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Create `instances` pipe instances under `pipe_name` and serve them.
///
/// Every instance handle is created up front (on the calling thread) so a
/// failure — most importantly a `FILE_FLAG_FIRST_PIPE_INSTANCE` collision,
/// i.e. someone already squatting the name — is reported synchronously and the
/// service refuses to start rather than half-running.
pub fn start(pipe_name: &str, backend: Backend, instances: u32) -> anyhow::Result<PipeServer> {
    anyhow::ensure!(instances >= 1, "pipe server needs at least one instance");

    let sd = SecurityDescriptor::from_sddl(PIPE_SDDL)?;
    let sa = sd.attributes();
    let name_w = wide(pipe_name);

    let mut handles = Vec::with_capacity(instances as usize);
    for i in 0..instances {
        match create_instance(&name_w, &sa, i == 0, instances) {
            Ok(h) => handles.push(h),
            Err(e) if i == 0 => {
                return Err(e.context(format!(
                    "could not claim {pipe_name} as the first pipe instance \
                     (another process may already own this name)"
                )));
            }
            Err(e) => {
                tracing::warn!("only {i} of {instances} pipe instances created: {e}");
                break;
            }
        }
    }

    let stop = Arc::new(StopSignal::manual_reset()?);
    let mut threads = Vec::with_capacity(handles.len());
    for (i, handle) in handles.into_iter().enumerate() {
        let backend = backend.clone();
        let stop = stop.clone();
        let name = pipe_name.to_string();
        threads.push(
            std::thread::Builder::new()
                .name(format!("dd-pipe-{i}"))
                .spawn(move || instance_loop(handle, backend, stop, &name))?,
        );
    }

    tracing::info!("pipe server listening on {pipe_name} ({} instances)", threads.len());
    Ok(PipeServer { stop, threads, name: pipe_name.to_string() })
}

fn create_instance(
    name_w: &[u16],
    sa: &SECURITY_ATTRIBUTES,
    first: bool,
    max_instances: u32,
) -> anyhow::Result<OwnedHandle> {
    let mut open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
    if first {
        open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }
    let pipe_mode = PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;

    // SAFETY: name_w is NUL-terminated; sa outlives the call.
    let handle = unsafe {
        CreateNamedPipeW(
            pcwstr(name_w),
            open_mode,
            pipe_mode,
            max_instances,
            MAX_FRAME as u32,
            MAX_FRAME as u32,
            0,
            Some(sa as *const SECURITY_ATTRIBUTES),
        )
    };
    if handle.is_invalid() {
        return Err(anyhow::Error::from(windows::core::Error::from_thread())
            .context("CreateNamedPipeW failed"));
    }
    // SAFETY: valid handle, exclusively owned by the returned wrapper.
    Ok(unsafe { OwnedHandle::new(handle) })
}

fn instance_loop(pipe: OwnedHandle, backend: Backend, stop: Arc<StopSignal>, name: &str) {
    while !stop.is_signaled() {
        match accept(&pipe, &stop) {
            Ok(true) => {
                if let Err(e) = serve_one(&pipe, &backend, &stop) {
                    tracing::warn!("{name}: client session ended: {e}");
                }
                // SAFETY: our own pipe instance; discards any unread data.
                unsafe {
                    let _ = DisconnectNamedPipe(pipe.raw());
                }
            }
            Ok(false) => break, // shutdown requested
            Err(e) => {
                tracing::warn!("{name}: accept failed: {e}");
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }
}

/// Wait for a client. `Ok(true)` = connected, `Ok(false)` = shutting down.
fn accept(pipe: &OwnedHandle, stop: &StopSignal) -> anyhow::Result<bool> {
    let ev = Event::manual_reset()?;
    let mut ov = OVERLAPPED { hEvent: ev.raw(), ..Default::default() };

    // SAFETY: ov and its event outlive the operation (we always wait or cancel).
    let r = unsafe { ConnectNamedPipe(pipe.raw(), Some(&mut ov)) };
    match r {
        Ok(()) => Ok(true),
        Err(e) if e.code() == ERROR_PIPE_CONNECTED.to_hresult() => Ok(true),
        Err(e) if e.code() == ERROR_IO_PENDING.to_hresult() => {
            let handles = [ev.raw(), stop.raw()];
            // SAFETY: both handles are alive for the duration of the wait.
            let w = unsafe { WaitForMultipleObjects(&handles, false, INFINITE) };
            if w == WAIT_OBJECT_0 {
                let mut transferred = 0u32;
                // SAFETY: the operation has completed; ov is still valid.
                unsafe { GetOverlappedResult(pipe.raw(), &ov, &mut transferred, true) }?;
                Ok(true)
            } else {
                cancel(pipe, &ov);
                Ok(false)
            }
        }
        Err(e) => Err(e.into()),
    }
}

/// Read one request, dispatch it, write one response.
fn serve_one(pipe: &OwnedHandle, backend: &Backend, stop: &StopSignal) -> anyhow::Result<()> {
    let mut buf = vec![0u8; MAX_FRAME];
    let response = match read_message(pipe, stop, &mut buf) {
        Ok(n) => match decode_request(&buf[..n]) {
            Ok(req) => dispatch(req, backend),
            Err(e) => {
                tracing::warn!("rejecting malformed request: {e}");
                SvcResponse::Failed { reason: "malformed request".to_string() }
            }
        },
        Err(ReadError::Oversize) => {
            tracing::warn!("rejecting oversize request (cap {MAX_IPC_MSG} bytes)");
            SvcResponse::Failed { reason: format!("request exceeds {MAX_IPC_MSG} bytes") }
        }
        Err(ReadError::Shutdown) => return Ok(()),
        Err(ReadError::Io(e)) => return Err(e),
    };

    let frame = encode_frame(&response)?;
    write_message(pipe, stop, &frame)
}

enum ReadError {
    /// Client sent a message larger than the buffer / cap.
    Oversize,
    /// The service is stopping (or the client stalled past the I/O timeout).
    Shutdown,
    Io(anyhow::Error),
}

impl From<anyhow::Error> for ReadError {
    fn from(e: anyhow::Error) -> Self {
        ReadError::Io(e)
    }
}

fn read_message(pipe: &OwnedHandle, stop: &StopSignal, buf: &mut [u8]) -> Result<usize, ReadError> {
    let ev = Event::manual_reset().map_err(ReadError::Io)?;
    let mut ov = OVERLAPPED { hEvent: ev.raw(), ..Default::default() };
    let mut read = 0u32;

    // SAFETY: buf, ov and the event outlive the operation.
    let started = unsafe { ReadFile(pipe.raw(), Some(buf), Some(&mut read), Some(&mut ov)) };
    match started {
        Ok(()) => Ok(read as usize),
        Err(e) if e.code() == ERROR_MORE_DATA.to_hresult() => Err(ReadError::Oversize),
        Err(e) if e.code() == ERROR_IO_PENDING.to_hresult() => {
            match wait_io(pipe, stop, &ov, ev.raw()) {
                Ok(Some(n)) => Ok(n),
                Ok(None) => Err(ReadError::Shutdown),
                Err(e) if e.downcast_ref::<WinErr>().is_some_and(|w| w.is(ERROR_MORE_DATA)) => {
                    Err(ReadError::Oversize)
                }
                Err(e) => Err(ReadError::Io(e)),
            }
        }
        Err(e) => Err(ReadError::Io(e.into())),
    }
}

fn write_message(pipe: &OwnedHandle, stop: &StopSignal, data: &[u8]) -> anyhow::Result<()> {
    let ev = Event::manual_reset()?;
    let mut ov = OVERLAPPED { hEvent: ev.raw(), ..Default::default() };
    let mut written = 0u32;

    // SAFETY: data, ov and the event outlive the operation.
    let started = unsafe { WriteFile(pipe.raw(), Some(data), Some(&mut written), Some(&mut ov)) };
    match started {
        Ok(()) => Ok(()),
        Err(e) if e.code() == ERROR_IO_PENDING.to_hresult() => {
            wait_io(pipe, stop, &ov, ev.raw())?;
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// A Win32 error carried through `anyhow` so callers can match on the code.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct WinErr(windows::core::Error);

impl WinErr {
    fn is(&self, code: windows::Win32::Foundation::WIN32_ERROR) -> bool {
        self.0.code() == code.to_hresult()
    }
}

/// Wait for a pending overlapped operation, the stop signal, or the client
/// timeout. `Ok(None)` means "give up on this client".
fn wait_io(
    pipe: &OwnedHandle,
    stop: &StopSignal,
    ov: &OVERLAPPED,
    event: HANDLE,
) -> anyhow::Result<Option<usize>> {
    let handles = [event, stop.raw()];
    // SAFETY: both handles are alive for the duration of the wait.
    let w = unsafe { WaitForMultipleObjects(&handles, false, CLIENT_IO_TIMEOUT_MS) };
    if w == WAIT_OBJECT_0 {
        let mut transferred = 0u32;
        // SAFETY: the operation has completed; ov is still valid.
        match unsafe { GetOverlappedResult(pipe.raw(), ov, &mut transferred, true) } {
            Ok(()) => Ok(Some(transferred as usize)),
            Err(e) => Err(WinErr(e).into()),
        }
    } else {
        // Stop signalled, timed out, or the wait itself failed: abandon the I/O.
        cancel(pipe, ov);
        Ok(None)
    }
}

fn cancel(pipe: &OwnedHandle, ov: &OVERLAPPED) {
    // SAFETY: cancelling our own pending operation, then draining its result so
    // `ov` is no longer referenced by the kernel before it is dropped.
    unsafe {
        let _ = CancelIoEx(pipe.raw(), Some(ov));
        let mut n = 0u32;
        let _ = GetOverlappedResult(pipe.raw(), ov, &mut n, true);
    }
}

// ---------------------------------------------------------------------------
// Tests (including a real client<->server roundtrip on a test pipe name)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::mock::harness;
    use std::time::Duration;

    use windows::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE, OPEN_EXISTING,
    };
    use windows::Win32::System::Pipes::{SetNamedPipeHandleState, WaitNamedPipeW};

    fn test_pipe_name(tag: &str) -> String {
        format!(r"\\.\pipe\DirectDeskSvc-test-{}-{tag}", std::process::id())
    }

    /// Minimal synchronous client, used only by these tests.
    struct TestClient(OwnedHandle);

    impl TestClient {
        fn connect(name: &str) -> anyhow::Result<Self> {
            let name_w = wide(name);
            // SAFETY: name_w is NUL-terminated and alive for both calls.
            unsafe {
                let _ = WaitNamedPipeW(pcwstr(&name_w), 5_000);
                let h = CreateFileW(
                    pcwstr(&name_w),
                    (GENERIC_READ | GENERIC_WRITE).0,
                    FILE_SHARE_MODE(0),
                    None,
                    OPEN_EXISTING,
                    FILE_FLAGS_AND_ATTRIBUTES(0),
                    None,
                )?;
                let mode = PIPE_READMODE_MESSAGE;
                SetNamedPipeHandleState(h, Some(&mode), None, None)?;
                Ok(Self(OwnedHandle::new(h)))
            }
        }

        fn send_raw(&self, bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
            let mut written = 0u32;
            // SAFETY: synchronous I/O on a connected message-mode pipe.
            unsafe {
                WriteFile(self.0.raw(), Some(bytes), Some(&mut written), None)?;
                let mut buf = vec![0u8; MAX_FRAME];
                let mut read = 0u32;
                ReadFile(self.0.raw(), Some(&mut buf), Some(&mut read), None)?;
                buf.truncate(read as usize);
                Ok(buf)
            }
        }

        fn request(&self, req: SvcRequest) -> anyhow::Result<SvcResponse> {
            let frame = encode_frame(&req)?;
            let reply = self.send_raw(&frame)?;
            anyhow::ensure!(reply.len() >= 4, "short reply");
            let declared = parse_frame_len(reply[..4].try_into().unwrap(), MAX_IPC_MSG)?;
            anyhow::ensure!(reply.len() - 4 == declared, "reply length mismatch");
            Ok(decode_strict::<SvcResponse>(&reply[4..])?)
        }
    }

    // ---------- framing ----------

    #[test]
    fn frame_roundtrip() {
        let frame = encode_frame(&SvcRequest::Ping).unwrap();
        assert_eq!(u32::from_le_bytes(frame[..4].try_into().unwrap()) as usize, frame.len() - 4);
        assert_eq!(decode_request(&frame).unwrap(), SvcRequest::Ping);
    }

    #[test]
    fn every_request_variant_frames_within_cap() {
        for req in [
            SvcRequest::Ping,
            SvcRequest::GetStatus,
            SvcRequest::EnsureFirewallRules,
            SvcRequest::RemoveFirewallRules,
            SvcRequest::RestartHostRequested,
        ] {
            let frame = encode_frame(&req).unwrap();
            assert!(frame.len() <= MAX_FRAME);
            assert_eq!(decode_request(&frame).unwrap(), req);
        }
    }

    #[test]
    fn rejects_short_frames() {
        assert!(decode_request(&[]).is_err());
        assert!(decode_request(&[0, 0, 0]).is_err());
    }

    #[test]
    fn rejects_zero_length_body() {
        assert!(decode_request(&[0, 0, 0, 0]).is_err());
    }

    #[test]
    fn rejects_oversize_prefix_without_allocating() {
        let mut frame = ((MAX_IPC_MSG + 1) as u32).to_le_bytes().to_vec();
        frame.push(0);
        let err = decode_request(&frame).unwrap_err().to_string();
        assert!(err.contains("too large"), "unexpected error: {err}");

        let mut huge = u32::MAX.to_le_bytes().to_vec();
        huge.push(0);
        assert!(decode_request(&huge).is_err());
    }

    #[test]
    fn rejects_length_mismatch() {
        let mut frame = encode_frame(&SvcRequest::Ping).unwrap();
        frame.push(0xAA); // body longer than the prefix claims
        assert!(decode_request(&frame).is_err());

        let mut short = encode_frame(&SvcRequest::Ping).unwrap();
        short[0] = short[0].wrapping_add(1); // prefix claims more than we sent
        assert!(decode_request(&short).is_err());
    }

    #[test]
    fn rejects_unknown_variant_and_trailing_bytes() {
        // 0xFF is not a valid SvcRequest discriminant.
        let frame = [1u8, 0, 0, 0, 0xFF];
        assert!(decode_request(&frame).is_err());

        let mut trailing = vec![2u8, 0, 0, 0];
        trailing.extend_from_slice(&[0x00, 0x00]); // Ping + one junk byte
        assert!(decode_request(&trailing).is_err());
    }

    #[test]
    fn encode_frame_rejects_oversize_payload() {
        let big = SvcResponse::Failed { reason: "x".repeat(MAX_IPC_MSG + 100) };
        assert!(encode_frame(&big).is_err());
    }

    // ---------- security descriptor ----------

    #[test]
    fn pipe_sddl_converts_to_a_security_descriptor() {
        let sd = SecurityDescriptor::from_sddl(PIPE_SDDL)
            .expect("the pipe DACL must be a valid SDDL string");
        assert!(!sd.0.is_invalid());
        let sa = sd.attributes();
        assert_eq!(sa.nLength as usize, std::mem::size_of::<SECURITY_ATTRIBUTES>());
        assert!(!sa.lpSecurityDescriptor.is_null());
    }

    #[test]
    fn sddl_grants_exactly_system_admins_and_interactive() {
        // Guard against an accidental widening of the DACL.
        assert!(PIPE_SDDL.starts_with("D:P"), "DACL must be protected");
        assert!(PIPE_SDDL.contains("(A;;GA;;;SY)"));
        assert!(PIPE_SDDL.contains("(A;;GA;;;BA)"));
        assert!(PIPE_SDDL.contains("(A;;GRGW;;;IU)"));
        for forbidden in [";;;WD)", ";;;AN)", ";;;NU)", "(D;", "S:"] {
            assert!(!PIPE_SDDL.contains(forbidden), "unexpected ACE component {forbidden}");
        }
        assert_eq!(PIPE_SDDL.matches("(A;").count(), 3, "exactly three allow ACEs");
    }

    #[test]
    fn invalid_sddl_is_rejected() {
        assert!(SecurityDescriptor::from_sddl("this is not sddl").is_err());
    }

    // ---------- live server ----------

    #[test]
    fn ping_roundtrip_over_a_real_pipe() {
        let name = test_pipe_name("ping");
        let h = harness();
        let server = start(&name, h.backend.clone(), 2).expect("pipe server should start");

        let client = TestClient::connect(&name).expect("client should connect");
        assert_eq!(client.request(SvcRequest::Ping).unwrap(), SvcResponse::Pong);
        drop(client);

        // A second connection on a (possibly) recycled instance must also work.
        let client = TestClient::connect(&name).expect("second client should connect");
        assert_eq!(client.request(SvcRequest::Ping).unwrap(), SvcResponse::Pong);
        drop(client);

        drop(server);
    }

    #[test]
    fn status_and_actions_over_a_real_pipe() {
        let name = test_pipe_name("status");
        let h = harness();
        *h.supervisor.running.lock() = true;
        let server = start(&name, h.backend.clone(), 2).unwrap();

        // One request per connection: the server answers and disconnects, so
        // each call below opens a fresh connection.
        let one = |req| TestClient::connect(&name).unwrap().request(req).unwrap();

        match one(SvcRequest::GetStatus) {
            SvcResponse::Status(s) => {
                assert_eq!(s.service_version, "9.9.9-test");
                assert!(s.host_running);
                assert!(!s.firewall_rules_present);
            }
            other => panic!("expected Status, got {other:?}"),
        }
        assert_eq!(one(SvcRequest::EnsureFirewallRules), SvcResponse::Ok);
        match one(SvcRequest::GetStatus) {
            SvcResponse::Status(s) => assert!(s.firewall_rules_present),
            other => panic!("expected Status, got {other:?}"),
        }
        assert_eq!(one(SvcRequest::RemoveFirewallRules), SvcResponse::Ok);
        assert_eq!(one(SvcRequest::RestartHostRequested), SvcResponse::Ok);
        assert_eq!(*h.supervisor.restarts.lock(), 1);
        drop(server);
    }

    #[test]
    fn a_second_request_on_the_same_connection_is_not_served() {
        // Documents the contract: one request, one response, then disconnect.
        let name = test_pipe_name("oneshot");
        let h = harness();
        let server = start(&name, h.backend, 2).unwrap();

        let client = TestClient::connect(&name).unwrap();
        assert_eq!(client.request(SvcRequest::Ping).unwrap(), SvcResponse::Pong);
        assert!(
            client.request(SvcRequest::Ping).is_err(),
            "the server must have disconnected after answering"
        );
        drop(client);
        drop(server);
    }

    #[test]
    fn malformed_and_oversize_requests_are_rejected_and_the_server_survives() {
        let name = test_pipe_name("hostile");
        let h = harness();
        let server = start(&name, h.backend.clone(), 2).unwrap();

        // Garbage bytes.
        let c = TestClient::connect(&name).unwrap();
        let reply = c.send_raw(&[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02]).unwrap();
        let resp: SvcResponse = decode_strict(&reply[4..]).unwrap();
        assert!(matches!(resp, SvcResponse::Failed { .. }), "got {resp:?}");
        drop(c);

        // A prefix that claims more than the cap.
        let c = TestClient::connect(&name).unwrap();
        let mut frame = ((MAX_IPC_MSG + 1) as u32).to_le_bytes().to_vec();
        frame.push(0x00);
        let reply = c.send_raw(&frame).unwrap();
        let resp: SvcResponse = decode_strict(&reply[4..]).unwrap();
        assert!(matches!(resp, SvcResponse::Failed { .. }), "got {resp:?}");
        drop(c);

        // An actual oversize message (bigger than the pipe buffer / cap).
        let c = TestClient::connect(&name).unwrap();
        let big = vec![0x41u8; MAX_FRAME * 2];
        // The server answers Failed; the write itself may also fail if the
        // server disconnects first — either way it must not take the service down.
        let _ = c.send_raw(&big);
        drop(c);

        // Server is still healthy.
        let c = TestClient::connect(&name).unwrap();
        assert_eq!(c.request(SvcRequest::Ping).unwrap(), SvcResponse::Pong);
        drop(c);
        drop(server);
    }

    #[test]
    fn a_client_that_connects_and_says_nothing_is_dropped_not_fatal() {
        let name = test_pipe_name("silent");
        let h = harness();
        let server = start(&name, h.backend.clone(), 2).unwrap();

        let silent = TestClient::connect(&name).unwrap();
        // Do not send anything; another client must still be served immediately
        // (that's what multiple instances are for).
        let c = TestClient::connect(&name).unwrap();
        assert_eq!(c.request(SvcRequest::Ping).unwrap(), SvcResponse::Pong);
        drop(c);
        drop(silent);
        drop(server);
    }

    #[test]
    fn first_instance_flag_blocks_a_second_server_on_the_same_name() {
        let name = test_pipe_name("squat");
        let h = harness();
        let server = start(&name, h.backend.clone(), 1).unwrap();
        let second = start(&name, h.backend.clone(), 1);
        assert!(second.is_err(), "a second server must not be able to claim the pipe name");
        drop(server);
    }

    #[test]
    fn shutdown_is_prompt_and_idempotent() {
        let name = test_pipe_name("shutdown");
        let h = harness();
        let mut server = start(&name, h.backend.clone(), 4).unwrap();
        let t0 = std::time::Instant::now();
        server.shutdown();
        server.shutdown(); // second call is a no-op
        assert!(t0.elapsed() < Duration::from_secs(3), "shutdown took {:?}", t0.elapsed());

        // The name is free again once the instances are closed.
        let again = start(&name, h.backend, 1).expect("name should be reusable after shutdown");
        drop(again);
    }

    #[test]
    fn start_rejects_zero_instances() {
        assert!(start(&test_pipe_name("zero"), harness().backend, 0).is_err());
    }
}
