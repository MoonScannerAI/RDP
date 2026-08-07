//! QUIC endpoints (quinn 0.11) and framed control-plane I/O.
//!
//! # Configuration decisions
//!
//! - **ALPN `directdesk/1`** on both ends. A peer speaking anything else is
//!   rejected during the handshake instead of at the first bad message.
//! - **0-RTT disabled.** Early data is replayable by construction. Replaying
//!   input events into a remote desktop would be a real security bug, so the
//!   whole mechanism is off: `max_early_data_size = 0` on the server and
//!   `enable_early_data = false` on the client.
//! - **Keep-alive [`DEFAULT_KEEP_ALIVE_MS`], idle timeout
//!   [`DEFAULT_IDLE_TIMEOUT_MS`].** Keep-alive is a third of the idle timeout so
//!   two consecutive lost keep-alives still do not trip it. It also holds NAT
//!   mappings open, which matters on the aggressive-rebind gateways the
//!   connection prober flags.
//! - **Datagrams enabled** for video. The receive buffer is sized for several
//!   frames' worth of fragments so a scheduling hiccup does not shred a frame.
//! - **UDP socket buffers sized explicitly.** quinn's own `Endpoint::server`
//!   and `Endpoint::client` bind a socket with the OS default `SO_SNDBUF`/
//!   `SO_RCVBUF` — ~64 KiB on Windows. A 2560x1600 stream bursts a keyframe of
//!   ~150 fragments (~180 KiB) in one scheduler slice; when the sender's or
//!   receiver's poller is briefly starved, a 64 KiB buffer cannot hold the
//!   burst and the kernel drops the overflow. Such a drop is invisible to
//!   `Connection::stats().path.lost` when it happens on the send side (the
//!   datagram was never a tracked packet), so a host watching only `loss` would
//!   see a clean link. We build the socket ourselves with [`socket2`], set both
//!   buffers to [`DEFAULT_UDP_SEND_BUFFER`] / [`DEFAULT_UDP_RECV_BUFFER`], and
//!   hand the std socket to `Endpoint::new`. (On a *fast* path — loopback — the
//!   default buffers already suffice; this hardening matters on real Wi-Fi/LTE
//!   links where a stalled poller and a small buffer coincide.)
//! - **BBR congestion control** ([`Congestion::Bbr`], the default). quinn 0.11
//!   ships `quinn::congestion::BbrConfig`, so no fallback is needed — but
//!   [`Congestion::Cubic`] and [`Congestion::NewReno`] remain selectable
//!   because BBR's behaviour on very lossy links is worth being able to A/B.
//! - **Migration left enabled on the server.** A client that changes address
//!   (Wi-Fi to LTE) keeps its session, and QUIC's path validation makes that
//!   safe.
//!
//! # Framing
//!
//! Control-plane streams carry `u32-le length || postcard bytes`, exactly as
//! [`crate::protocol::encode_framed`] produces. The read side takes an explicit
//! `limit` so the caller can enforce [`MAX_AUTH_MSG`] during the handshake and
//! [`MAX_CONTROL_MSG`] afterwards — the cap is checked before a single byte of
//! body is allocated.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{Connection, Endpoint, RecvStream, SendStream, VarInt};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::crypto::identity::TlsIdentity;
use crate::crypto::tls::{self, ServerPinning};
use crate::crypto::{Exporter, EXPORTER_CONTEXT, EXPORTER_LABEL};
use crate::error::{Error, Result};
use crate::protocol::{
    decode_strict, encode_framed, parse_frame_len, MAX_AUTH_MSG, MAX_CONTROL_MSG,
};

/// Keep-alive interval. Also holds NAT mappings open.
pub const DEFAULT_KEEP_ALIVE_MS: u64 = 5_000;

/// Idle timeout. Sized so a session survives a multi-second capture stall (a
/// host UAC/secure-desktop prompt freezes video until an operator dismisses it,
/// often over a side channel) without the connection idling out. Six keep-alive
/// intervals: several lost keep-alives, or a long freeze during which the host
/// still emits keep-alives, do not kill a working session.
pub const DEFAULT_IDLE_TIMEOUT_MS: u64 = 30_000;

/// Datagram receive buffer: roughly a few 1080p frames of fragments.
pub const DEFAULT_DATAGRAM_RECV_BUFFER: usize = 4 * 1024 * 1024;

/// Datagram send buffer.
pub const DEFAULT_DATAGRAM_SEND_BUFFER: usize = 2 * 1024 * 1024;

/// Conservative initial MTU. QUIC's PLPMTUD raises it from here.
pub const DEFAULT_INITIAL_MTU: u16 = 1200;

/// UDP socket send buffer (`SO_SNDBUF`). 4 MiB holds many frames' worth of
/// fragments, so a burst from the encoder is absorbed by the kernel rather than
/// dropped when the sender's poller cannot drain the socket in one slice. Far
/// above the OS default (~64 KiB on Windows).
pub const DEFAULT_UDP_SEND_BUFFER: usize = 4 * 1024 * 1024;

/// UDP socket receive buffer (`SO_RCVBUF`). Same 4 MiB, for the mirror problem:
/// a fast sender overruns a small receive buffer and the kernel discards
/// datagrams before the receiver's poller reads them — a loss quinn never
/// reports because the packet never reached it.
pub const DEFAULT_UDP_RECV_BUFFER: usize = 4 * 1024 * 1024;

/// Congestion controller selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Congestion {
    /// BBR — the default. Keeps queues short, which is what interactivity
    /// needs; loss-based controllers fill buffers and add latency.
    #[default]
    Bbr,
    /// CUBIC — the internet default. Fallback for links where BBR misbehaves.
    Cubic,
    /// NewReno — simplest, mostly for experiments.
    NewReno,
}

/// Tunables for both endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicParams {
    /// Keep-alive interval in milliseconds. `0` disables keep-alive.
    pub keep_alive_ms: u64,
    /// Idle timeout in milliseconds. Must be greater than `keep_alive_ms`.
    pub idle_timeout_ms: u64,
    /// Congestion controller.
    pub congestion: Congestion,
    /// Datagram receive buffer size in bytes. `0` disables datagram receive.
    pub datagram_recv_buffer: usize,
    /// Datagram send buffer size in bytes.
    pub datagram_send_buffer: usize,
    /// Initial MTU guess.
    pub initial_mtu: u16,
    /// UDP socket send buffer (`SO_SNDBUF`) in bytes. `0` leaves the OS default.
    pub udp_send_buffer: usize,
    /// UDP socket receive buffer (`SO_RCVBUF`) in bytes. `0` leaves the OS
    /// default.
    pub udp_recv_buffer: usize,
}

impl Default for QuicParams {
    fn default() -> Self {
        Self {
            keep_alive_ms: DEFAULT_KEEP_ALIVE_MS,
            idle_timeout_ms: DEFAULT_IDLE_TIMEOUT_MS,
            congestion: Congestion::default(),
            datagram_recv_buffer: DEFAULT_DATAGRAM_RECV_BUFFER,
            datagram_send_buffer: DEFAULT_DATAGRAM_SEND_BUFFER,
            initial_mtu: DEFAULT_INITIAL_MTU,
            udp_send_buffer: DEFAULT_UDP_SEND_BUFFER,
            udp_recv_buffer: DEFAULT_UDP_RECV_BUFFER,
        }
    }
}

impl QuicParams {
    /// Reject combinations that would silently misbehave.
    pub fn validate(&self) -> Result<()> {
        if self.idle_timeout_ms == 0 {
            return Err(Error::Invalid("idle timeout must be non-zero".into()));
        }
        if self.keep_alive_ms >= self.idle_timeout_ms {
            return Err(Error::Invalid(
                "keep-alive interval must be shorter than the idle timeout".into(),
            ));
        }
        if self.initial_mtu < 1200 {
            return Err(Error::Invalid(
                "initial MTU below the QUIC minimum of 1200".into(),
            ));
        }
        Ok(())
    }
}

/// Build the shared transport configuration.
pub fn transport_config(params: &QuicParams) -> Result<Arc<quinn::TransportConfig>> {
    params.validate()?;
    let mut tc = quinn::TransportConfig::default();

    let idle = quinn::IdleTimeout::try_from(Duration::from_millis(params.idle_timeout_ms))
        .map_err(|e| Error::Transport(format!("idle timeout out of range: {e}")))?;
    tc.max_idle_timeout(Some(idle));

    if params.keep_alive_ms > 0 {
        tc.keep_alive_interval(Some(Duration::from_millis(params.keep_alive_ms)));
    } else {
        tc.keep_alive_interval(None);
    }

    match params.congestion {
        Congestion::Bbr => {
            tc.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
        }
        Congestion::Cubic => {
            tc.congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default()));
        }
        Congestion::NewReno => {
            tc.congestion_controller_factory(Arc::new(quinn::congestion::NewRenoConfig::default()));
        }
    }

    if params.datagram_recv_buffer > 0 {
        tc.datagram_receive_buffer_size(Some(params.datagram_recv_buffer));
    } else {
        tc.datagram_receive_buffer_size(None);
    }
    tc.datagram_send_buffer_size(params.datagram_send_buffer);
    tc.initial_mtu(params.initial_mtu);

    // Control + input, one each way. Anything else is a protocol violation, and
    // a tight cap makes stream-flood attacks pointless.
    tc.max_concurrent_bidi_streams(VarInt::from_u32(4));
    tc.max_concurrent_uni_streams(VarInt::from_u32(2));

    Ok(Arc::new(tc))
}

/// Build a listening (host) endpoint.
///
/// Bind to `0.0.0.0:port` for IPv4 or `[::]:port` for dual-stack.
pub fn server_endpoint(
    bind: SocketAddr,
    identity: &TlsIdentity,
    params: &QuicParams,
) -> Result<Endpoint> {
    let rustls_cfg = tls::server_config(identity)?;
    let quic_crypto = QuicServerConfig::try_from(rustls_cfg.as_ref().clone())
        .map_err(|e| Error::Transport(format!("quinn server crypto: {e}")))?;

    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    cfg.transport_config(transport_config(params)?);
    // Address migration stays on: a client roaming between networks keeps its
    // session, and QUIC path validation makes that safe.
    cfg.migration(true);

    let socket = bind_udp_socket(bind, params)?;
    let runtime = quinn::default_runtime()
        .ok_or_else(|| Error::Transport("no tokio runtime for the QUIC endpoint".into()))?;
    Endpoint::new(quinn::EndpointConfig::default(), Some(cfg), socket, runtime)
        .map_err(|e| Error::Transport(format!("bind {bind}: {e}")))
}

/// Bind a UDP socket with the send/receive buffers `params` asks for.
///
/// This is the whole point of not using `Endpoint::server`/`client`: those bind
/// a socket with the OS default buffers, and on Windows that default (~64 KiB)
/// is far too small to hold a keyframe's worth of fragments. A fast sender then
/// overruns the kernel buffer and the datagrams are dropped *before quinn sees
/// them* — loss quinn cannot count. Buffer sizing is best-effort: the OS may
/// clamp the request (and often doubles it for bookkeeping), so a failure to
/// grow is logged, not fatal.
fn bind_udp_socket(bind: SocketAddr, params: &QuicParams) -> Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::for_address(bind), Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| Error::Transport(format!("create UDP socket: {e}")))?;

    // Match quinn's own dual-stack behaviour when binding the IPv6 wildcard, so
    // an IPv4 client can still reach a `[::]`-bound host.
    if bind.is_ipv6() && bind.ip().is_unspecified() {
        let _ = socket.set_only_v6(false);
    }

    // Set buffers before bind. Best-effort; the OS may clamp to its own max.
    if params.udp_send_buffer > 0 {
        if let Err(e) = socket.set_send_buffer_size(params.udp_send_buffer) {
            tracing::warn!(
                "could not set UDP send buffer to {}: {e}",
                params.udp_send_buffer
            );
        }
    }
    if params.udp_recv_buffer > 0 {
        if let Err(e) = socket.set_recv_buffer_size(params.udp_recv_buffer) {
            tracing::warn!(
                "could not set UDP recv buffer to {}: {e}",
                params.udp_recv_buffer
            );
        }
    }

    socket
        .bind(&bind.into())
        .map_err(|e| Error::Transport(format!("bind {bind}: {e}")))?;
    Ok(socket.into())
}

/// Build a connecting (client) endpoint with a pinning policy baked in.
///
/// `bind` is normally `0.0.0.0:0`.
pub fn client_endpoint(
    bind: SocketAddr,
    pinning: ServerPinning,
    params: &QuicParams,
) -> Result<Endpoint> {
    let rustls_cfg = tls::client_config(pinning)?;
    let quic_crypto = QuicClientConfig::try_from(rustls_cfg.as_ref().clone())
        .map_err(|e| Error::Transport(format!("quinn client crypto: {e}")))?;

    let mut cfg = quinn::ClientConfig::new(Arc::new(quic_crypto));
    cfg.transport_config(transport_config(params)?);

    let socket = bind_udp_socket(bind, params)?;
    let runtime = quinn::default_runtime()
        .ok_or_else(|| Error::Transport("no tokio runtime for the QUIC endpoint".into()))?;
    let mut endpoint = Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)
        .map_err(|e| Error::Transport(format!("bind {bind}: {e}")))?;
    endpoint.set_default_client_config(cfg);
    Ok(endpoint)
}

/// Connect to a host. The SNI is the fixed [`tls::SNI_NAME`]; the trust
/// decision is made entirely by the pinning verifier.
pub async fn connect(endpoint: &Endpoint, addr: SocketAddr) -> Result<Connection> {
    endpoint
        .connect(addr, tls::SNI_NAME)
        .map_err(|e| Error::Transport(format!("connect {addr}: {e}")))?
        .await
        .map_err(|e| Error::Transport(format!("handshake with {addr}: {e}")))
}

/// Extract the RFC 5705 channel binding for this connection.
///
/// This is the value fed to [`crate::crypto::pairing`] and
/// [`crate::crypto::auth`]. quinn exposes it as
/// `Connection::export_keying_material(&mut out, label, context)`.
pub fn channel_binding(conn: &Connection) -> Result<Exporter> {
    let mut out = [0u8; 32];
    conn.export_keying_material(&mut out, EXPORTER_LABEL, EXPORTER_CONTEXT)
        .map_err(|e| Error::Crypto(format!("export_keying_material: {e:?}")))?;
    crate::crypto::check_exporter(&out)?;
    Ok(out)
}

/// The peer's TLS pin as observed on this connection.
///
/// Only meaningful on the client side, where `peer_identity()` yields the
/// server's certificate chain.
pub fn peer_spki_pin(conn: &Connection) -> Result<crate::crypto::SpkiHash> {
    let identity = conn
        .peer_identity()
        .ok_or_else(|| Error::Crypto("connection has no peer certificate".into()))?;
    let chain = identity
        .downcast::<Vec<rustls_pki_types::CertificateDer<'static>>>()
        .map_err(|_| Error::Crypto("unexpected peer identity type".into()))?;
    let first = chain
        .first()
        .ok_or_else(|| Error::Crypto("empty certificate chain".into()))?;
    crate::crypto::spki_sha256_from_cert_der(first.as_ref())
}

/// Largest datagram payload the connection will currently accept.
///
/// `None` from quinn means the peer did not advertise datagram support, which
/// for us is fatal: video has nowhere to go.
pub fn max_datagram(conn: &Connection) -> Result<usize> {
    conn.max_datagram_size()
        .ok_or_else(|| Error::Transport("peer does not support QUIC datagrams".into()))
}

// ---------------------------------------------------------------------------
// Framed stream I/O
// ---------------------------------------------------------------------------

/// Write one length-prefixed postcard message.
pub async fn write_framed<T: Serialize>(stream: &mut SendStream, msg: &T) -> Result<()> {
    let bytes = encode_framed(msg)?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|e| Error::Transport(format!("stream write: {e}")))?;
    Ok(())
}

/// Read one length-prefixed postcard message, refusing anything over `limit`.
///
/// The length prefix is validated by [`parse_frame_len`] *before* the body
/// buffer is allocated, so a hostile 4-gigabyte prefix costs us nothing.
pub async fn read_framed<T: DeserializeOwned>(stream: &mut RecvStream, limit: usize) -> Result<T> {
    let mut prefix = [0u8; 4];
    stream
        .read_exact(&mut prefix)
        .await
        .map_err(|e| Error::Transport(format!("stream read (length): {e}")))?;
    let len = parse_frame_len(prefix, limit)?;

    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|e| Error::Transport(format!("stream read (body): {e}")))?;
    decode_strict::<T>(&body)
}

/// Read a control-plane message with the post-authentication cap.
pub async fn read_control<T: DeserializeOwned>(stream: &mut RecvStream) -> Result<T> {
    read_framed(stream, MAX_CONTROL_MSG).await
}

/// Read a handshake message with the (much smaller) authentication cap.
pub async fn read_auth<T: DeserializeOwned>(stream: &mut RecvStream) -> Result<T> {
    read_framed(stream, MAX_AUTH_MSG).await
}

// ---------------------------------------------------------------------------
// Stream establishment
// ---------------------------------------------------------------------------

/// The two reliable streams of a session.
pub struct SessionStreams {
    /// Control channel: auth, session control, stats, heartbeats.
    pub control: (SendStream, RecvStream),
    /// Input channel: key/button events and clipboard.
    pub input: (SendStream, RecvStream),
}

impl std::fmt::Debug for SessionStreams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionStreams")
            .field("control", &self.control.0.id())
            .field("input", &self.input.0.id())
            .finish()
    }
}

/// Open the session's streams from the client side, tagging each one.
///
/// Priorities are set here rather than by the caller so no code path can forget
/// them: input starving behind a bulk transfer is a latency bug that only shows
/// up under load.
pub async fn open_streams(conn: &Connection) -> Result<SessionStreams> {
    let control = open_tagged(
        conn,
        crate::protocol::Channel::Control,
        super::PRIORITY_CONTROL,
    )
    .await?;
    let input = open_tagged(conn, crate::protocol::Channel::Input, super::PRIORITY_INPUT).await?;
    Ok(SessionStreams { control, input })
}

async fn open_tagged(
    conn: &Connection,
    channel: crate::protocol::Channel,
    priority: i32,
) -> Result<(SendStream, RecvStream)> {
    let (mut send, recv) = conn
        .open_bi()
        .await
        .map_err(|e| Error::Transport(format!("open_bi({channel:?}): {e}")))?;
    send.set_priority(priority)
        .map_err(|e| Error::Transport(format!("set_priority: {e}")))?;
    send.write_all(&[super::channel_tag(channel)?])
        .await
        .map_err(|e| Error::Transport(format!("write channel tag: {e}")))?;
    Ok((send, recv))
}

// ---------------------------------------------------------------------------
// Bulk unidirectional stream (lossless refinement tiles)
// ---------------------------------------------------------------------------
//
// Deliberately separate from the tagged bidirectional machinery above. Tiles
// travel host→client only and are opened *after* the handshake, gated on a
// mutually-agreed `Hello.features` bit — so there is no tag byte, no `Channel`
// variant, and crucially no change to `accept_streams`' `for _ in 0..2`.
//
// That last point is the whole design: widening that loop would make a new host
// wait for a third stream an old client never opens, and the only bound is the
// 15 s handshake timeout, which lands in the auth-failure path and locks the
// client out. Uni streams sidestep it entirely — the budget for them
// (`max_concurrent_uni_streams(2)`) was already granted by shipped builds.

/// Open the host→client bulk stream for refinement tiles.
///
/// Priority is [`PRIORITY_BULK`], below everything else, so tiles never delay a
/// keystroke. Note this orders tiles only against other *streams*: video rides
/// datagrams and shares the congestion window, which the caller must throttle.
///
/// [`PRIORITY_BULK`]: super::PRIORITY_BULK
pub async fn open_bulk(conn: &Connection) -> Result<SendStream> {
    let send = conn
        .open_uni()
        .await
        .map_err(|e| Error::Transport(format!("open_uni(bulk): {e}")))?;
    send.set_priority(super::PRIORITY_BULK)
        .map_err(|e| Error::Transport(format!("set_priority(bulk): {e}")))?;
    Ok(send)
}

/// Accept the host's bulk stream on the client side.
///
/// The caller only ever awaits this when it advertised the feature bit and the
/// host echoed it, so a host that never opens the stream simply leaves this
/// future pending — it must not be awaited on a path that would time the
/// session out.
pub async fn accept_bulk(conn: &Connection) -> Result<RecvStream> {
    conn.accept_uni()
        .await
        .map_err(|e| Error::Transport(format!("accept_uni(bulk): {e}")))
}

/// Accept the session's streams on the host side, using the tag byte rather
/// than accept order so the two ends cannot disagree.
pub async fn accept_streams(conn: &Connection) -> Result<SessionStreams> {
    let mut control = None;
    let mut input = None;

    for _ in 0..2 {
        let (send, mut recv) = conn
            .accept_bi()
            .await
            .map_err(|e| Error::Transport(format!("accept_bi: {e}")))?;
        let mut tag = [0u8; 1];
        recv.read_exact(&mut tag)
            .await
            .map_err(|e| Error::Transport(format!("read channel tag: {e}")))?;

        match super::parse_channel_tag(tag[0])? {
            crate::protocol::Channel::Control if control.is_none() => {
                send.set_priority(super::PRIORITY_CONTROL)
                    .map_err(|e| Error::Transport(format!("set_priority: {e}")))?;
                control = Some((send, recv));
            }
            crate::protocol::Channel::Input if input.is_none() => {
                send.set_priority(super::PRIORITY_INPUT)
                    .map_err(|e| Error::Transport(format!("set_priority: {e}")))?;
                input = Some((send, recv));
            }
            other => {
                return Err(Error::Protocol(format!(
                    "unexpected or duplicate stream channel {other:?}"
                )));
            }
        }
    }

    match (control, input) {
        (Some(control), Some(input)) => Ok(SessionStreams { control, input }),
        _ => Err(Error::Protocol(
            "client did not open both session streams".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::HostIdentity;
    use crate::protocol::{AuthMsg, ControlMsg};

    fn loopback() -> SocketAddr {
        "127.0.0.1:0".parse().expect("literal address")
    }

    #[test]
    fn params_validation() {
        let p = QuicParams::default();
        assert!(p.validate().is_ok());
        assert!(transport_config(&p).is_ok());

        let mut bad = QuicParams {
            idle_timeout_ms: 0,
            ..QuicParams::default()
        };
        assert!(bad.validate().is_err());

        bad = QuicParams {
            keep_alive_ms: 20_000,
            idle_timeout_ms: 15_000,
            ..Default::default()
        };
        assert!(bad.validate().is_err());

        bad = QuicParams {
            initial_mtu: 500,
            ..Default::default()
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn all_congestion_controllers_build() {
        for c in [Congestion::Bbr, Congestion::Cubic, Congestion::NewReno] {
            let p = QuicParams {
                congestion: c,
                ..Default::default()
            };
            assert!(transport_config(&p).is_ok(), "{c:?} failed to build");
        }
    }

    #[test]
    fn keep_alive_is_well_under_idle_timeout() {
        // Two consecutive lost keep-alives must not trip the idle timeout.
        const { assert!(DEFAULT_KEEP_ALIVE_MS * 3 <= DEFAULT_IDLE_TIMEOUT_MS) };
    }

    // `quinn::Endpoint` binds its socket through the tokio runtime, so this one
    // needs a reactor even though it never sends anything.
    #[tokio::test]
    async fn endpoints_build() {
        let id = HostIdentity::generate("test").unwrap();
        let params = QuicParams::default();
        let server = server_endpoint(loopback(), id.tls(), &params).unwrap();
        assert!(server.local_addr().is_ok());

        let client = client_endpoint(
            loopback(),
            ServerPinning::Pinned(*id.spki_sha256()),
            &params,
        )
        .unwrap();
        assert!(client.local_addr().is_ok());
    }

    /// A full loopback handshake: pinning, ALPN, exporter agreement, tagged
    /// stream setup, framed I/O in both directions, and datagram transfer.
    #[tokio::test]
    async fn loopback_session_end_to_end() {
        let id = HostIdentity::generate("test-host").unwrap();
        let params = QuicParams::default();
        let server = server_endpoint(loopback(), id.tls(), &params).unwrap();
        let server_addr = server.local_addr().unwrap();

        let host_task = tokio::spawn(async move {
            let incoming = server.accept().await.expect("incoming");
            let conn = incoming.await.expect("host handshake");
            let host_exporter = channel_binding(&conn).expect("host exporter");
            let mut streams = accept_streams(&conn).await.expect("accept streams");

            let auth: AuthMsg = read_auth(&mut streams.control.1).await.expect("read auth");
            assert!(matches!(auth, AuthMsg::PairStart { .. }));
            write_framed(&mut streams.control.0, &ControlMsg::Ping { token: 7 })
                .await
                .expect("write ping");

            let dgram = conn.read_datagram().await.expect("datagram");
            assert_eq!(dgram.as_ref(), b"video-fragment");

            // Hold the connection open until the client has read everything.
            let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
            host_exporter
        });

        let client_ep = client_endpoint(
            loopback(),
            ServerPinning::Pinned(*id.spki_sha256()),
            &params,
        )
        .unwrap();
        let conn = connect(&client_ep, server_addr)
            .await
            .expect("client handshake");
        let client_exporter = channel_binding(&conn).expect("client exporter");

        assert_eq!(peer_spki_pin(&conn).unwrap(), *id.spki_sha256());
        assert!(max_datagram(&conn).unwrap() > 100);

        let mut streams = open_streams(&conn).await.expect("open streams");
        write_framed(
            &mut streams.control.0,
            &AuthMsg::PairStart {
                spake_msg: vec![0xAB; 33],
            },
        )
        .await
        .expect("write auth");

        let pong: ControlMsg = read_control(&mut streams.control.1)
            .await
            .expect("read control");
        assert!(matches!(pong, ControlMsg::Ping { token: 7 }));

        conn.send_datagram(bytes::Bytes::from_static(b"video-fragment"))
            .expect("send datagram");

        let host_exporter = tokio::time::timeout(Duration::from_secs(10), host_task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            host_exporter, client_exporter,
            "both ends must derive the same channel binding"
        );

        conn.close(0u32.into(), b"done");
        client_ep.wait_idle().await;
    }

    /// Establish a real loopback QUIC connection with `params`, feed `frames`
    /// video-sized frames of `frags` datagrams each — one burst every 16 ms,
    /// exactly how the host's `video_pump` paces a 60 fps stream from a
    /// dedicated thread — and return `(offered, received)`.
    ///
    /// `offered` counts `send_datagram` calls that returned `Ok`; `received`
    /// counts datagrams the far end actually read. quinn returns `Ok` even while
    /// silently evicting an older buffered datagram to make room, so `received`
    /// is the only honest measure of what crossed — the whole reason the
    /// application-level loss estimator exists.
    async fn measure_datagram_delivery(
        params: &QuicParams,
        frames: usize,
        frags: usize,
        payload_len: usize,
    ) -> (usize, usize) {
        let id = HostIdentity::generate("burst-host").unwrap();
        let server = server_endpoint(loopback(), id.tls(), params).unwrap();
        let server_addr = server.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let conn = server
                .accept()
                .await
                .expect("incoming")
                .await
                .expect("handshake");
            let send_conn = conn.clone();
            let sent = tokio::task::spawn_blocking(move || {
                let payload = vec![0xABu8; payload_len];
                let mut ok = 0usize;
                for _ in 0..frames {
                    for _ in 0..frags {
                        if send_conn
                            .send_datagram(bytes::Bytes::from(payload.clone()))
                            .is_ok()
                        {
                            ok += 1;
                        }
                    }
                    std::thread::sleep(Duration::from_millis(16));
                }
                ok
            })
            .await
            .unwrap();
            // Stay open until the receiver has drained.
            let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
            sent
        });

        let client_ep =
            client_endpoint(loopback(), ServerPinning::Pinned(*id.spki_sha256()), params).unwrap();
        let conn = connect(&client_ep, server_addr).await.expect("connect");

        let mut received = 0usize;
        // Read until the link falls quiet for a beat past the last burst.
        while let Ok(Ok(_)) =
            tokio::time::timeout(Duration::from_millis(500), conn.read_datagram()).await
        {
            received += 1;
        }

        conn.close(0u32.into(), b"done");
        let sent = server_task.await.unwrap();
        client_ep.wait_idle().await;
        (sent, received)
    }

    /// A bursty, video-shaped datagram stream on loopback arrives essentially
    /// intact with the configured buffers — the transport is not where video is
    /// being lost. Guards the endpoint/socket construction (custom `socket2`
    /// socket handed to `Endpoint::new`, enlarged UDP buffers) against a
    /// regression that would start dropping datagrams a receiver never counts.
    ///
    /// ~130 fragments per frame is a 2560x1600-sized keyframe burst; 200 frames
    /// at 60 fps is a few seconds of the heaviest traffic the encoder produces.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn bursty_video_datagrams_are_delivered_intact() {
        const FRAMES: usize = 200;
        const FRAGS: usize = 130;
        const PAYLOAD: usize = 1100;

        let (offered, received) =
            measure_datagram_delivery(&QuicParams::default(), FRAMES, FRAGS, PAYLOAD).await;
        let ratio = received as f64 / offered.max(1) as f64;
        println!(
            "bursty delivery: {received}/{offered} = {:.1}%",
            ratio * 100.0
        );

        assert!(
            ratio > 0.95,
            "loopback must deliver a bursty video flow ~intact, got {:.1}% ({received}/{offered})",
            ratio * 100.0
        );
    }

    /// A client pinning the wrong key must not complete the handshake.
    #[tokio::test]
    async fn wrong_pin_is_refused() {
        let id = HostIdentity::generate("real").unwrap();
        let impostor = HostIdentity::generate("impostor").unwrap();
        let params = QuicParams::default();
        let server = server_endpoint(loopback(), id.tls(), &params).unwrap();
        let server_addr = server.local_addr().unwrap();

        let host_task = tokio::spawn(async move {
            if let Some(incoming) = server.accept().await {
                let _ = incoming.await;
            }
        });

        let client_ep = client_endpoint(
            loopback(),
            ServerPinning::Pinned(*impostor.spki_sha256()),
            &params,
        )
        .unwrap();
        let res = tokio::time::timeout(Duration::from_secs(10), connect(&client_ep, server_addr))
            .await
            .expect("connect attempt should not hang");
        assert!(res.is_err(), "handshake must fail on a pin mismatch");

        host_task.abort();
    }

    /// Trust-on-pair records the pin it saw, which pairing later cross-checks.
    #[tokio::test]
    async fn trust_on_pair_records_pin() {
        let id = HostIdentity::generate("first-contact").unwrap();
        let params = QuicParams::default();
        let server = server_endpoint(loopback(), id.tls(), &params).unwrap();
        let server_addr = server.local_addr().unwrap();

        let host_task = tokio::spawn(async move {
            let incoming = server.accept().await.expect("incoming");
            let conn = incoming.await.expect("host handshake");
            let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
        });

        let recorder = crate::crypto::tls::ObservedPin::new();
        let client_ep = client_endpoint(
            loopback(),
            ServerPinning::TrustOnPair(recorder.clone()),
            &params,
        )
        .unwrap();
        let conn = connect(&client_ep, server_addr)
            .await
            .expect("client handshake");

        assert_eq!(recorder.get(), Some(*id.spki_sha256()));
        assert_eq!(peer_spki_pin(&conn).unwrap(), *id.spki_sha256());

        conn.close(0u32.into(), b"done");
        client_ep.wait_idle().await;
        host_task.abort();
    }

    /// The read side must reject an oversized length prefix before allocating.
    #[tokio::test]
    async fn framed_read_enforces_caps() {
        let id = HostIdentity::generate("caps").unwrap();
        let params = QuicParams::default();
        let server = server_endpoint(loopback(), id.tls(), &params).unwrap();
        let server_addr = server.local_addr().unwrap();

        let host_task = tokio::spawn(async move {
            let incoming = server.accept().await.expect("incoming");
            let conn = incoming.await.expect("host handshake");
            let mut streams = accept_streams(&conn).await.expect("accept streams");
            // A control-sized message is legal on the control channel but must
            // be refused when the auth cap is in force.
            let err = read_auth::<ControlMsg>(&mut streams.control.1)
                .await
                .unwrap_err();
            assert!(matches!(err, Error::Oversized { .. }), "got {err:?}");
            let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
        });

        let client_ep = client_endpoint(
            loopback(),
            ServerPinning::Pinned(*id.spki_sha256()),
            &params,
        )
        .unwrap();
        let conn = connect(&client_ep, server_addr)
            .await
            .expect("client handshake");
        let mut streams = open_streams(&conn).await.expect("open streams");

        let big = ControlMsg::ClipboardText("x".repeat(MAX_AUTH_MSG + 100));
        write_framed(&mut streams.control.0, &big)
            .await
            .expect("write big");

        tokio::time::timeout(Duration::from_secs(10), host_task)
            .await
            .unwrap()
            .unwrap();
        conn.close(0u32.into(), b"done");
        client_ep.wait_idle().await;
    }
}
