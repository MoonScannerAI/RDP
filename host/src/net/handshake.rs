//! Everything between a connection arriving and a client being trusted: the
//! accept loop, the one-client-at-a-time admission decision, the `Hello`
//! exchange, and the two authentication branches — a signature from a key
//! already on the trusted list, or the SPAKE2 pairing that puts one there.
//!
//! The protocol diagram this file implements is in [`crate::net`]'s own module
//! doc, and this is the only module that ever writes an [`AuthMsg`] to the
//! wire. The rule it enforces is that a connection reaches
//! [`super::serve::run_session`] only after `AuthOk`; every path that does not
//! get there tells the client `AuthFail` with a deliberately vague reason,
//! records a throttle failure against the source address, and closes with
//! [`CLOSE_CODE_REJECTED`].
//!
//! What belongs here: accepting, refusing, pairing, authenticating, and the
//! bookkeeping that goes with a client arriving or leaving.
//!
//! What does not: the two admission *gates* — the pairing window and the
//! failed-authentication lockout — are the pure state machines in
//! [`super::pairing`], everything that happens after `AuthOk` is
//! [`super::serve`], and the shared state both halves read ([`Inner`], the
//! status snapshot, the event channel) is owned by [`crate::net`].

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use quinn::Connection;
use tokio::sync::mpsc;

use directdesk_shared::crypto::auth::{
    HostAuthenticator, TrustedPeer, TrustedPeers, TRUSTED_CLIENTS_KEY,
};
use directdesk_shared::crypto::fingerprint_short;
use directdesk_shared::crypto::pairing::PairingHost;
use directdesk_shared::protocol::{AuthMsg, Hello, MAX_AUTH_MSG, PROTOCOL_VERSION};
use directdesk_shared::transport::quic::{self, SessionStreams};
use directdesk_shared::{Error, Result};

use super::pairing::{AUTH_LOCKOUT_MS, HANDSHAKE_TIMEOUT_MS};
use super::serve::run_session;
use super::{
    advertised_addresses, handle_command, ClientInfo, Inner, NetCommand, NetConfig, NetEvent,
    CLOSE_CODE_DISCONNECT, CLOSE_CODE_REJECTED, HOST_ROUTE,
};

pub(super) async fn accept_loop(inner: Arc<Inner>, mut cmds: mpsc::UnboundedReceiver<NetCommand>) {
    let endpoint =
        match quic::server_endpoint(inner.cfg.bind, inner.identity.tls(), &inner.cfg.quic) {
            Ok(e) => e,
            Err(e) => {
                let detail = e.to_string();
                tracing::error!("listener bind failed: {detail}");
                inner.status_mut(|s| {
                    s.listening = false;
                    s.last_error = Some(detail.clone());
                });
                inner.emit(NetEvent::ListenFailed { detail });
                return;
            }
        };

    let bound = endpoint.local_addr().unwrap_or(inner.cfg.bind);
    let addresses = advertised_addresses(bound.port());
    inner.status_mut(|s| {
        s.listening = true;
        s.bound = Some(bound);
        s.addresses = addresses.clone();
        s.last_error = None;
    });
    tracing::info!(
        "listening on {bound} (advertising {} address(es))",
        addresses.len()
    );
    inner.emit(NetEvent::Listening { bound, addresses });

    loop {
        tokio::select! {
            cmd = cmds.recv() => {
                match cmd {
                    None | Some(NetCommand::Shutdown) => break,
                    Some(other) => handle_command(&inner, other),
                }
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let peer_ip = incoming.remote_address().ip();
                if let Some(for_ms) = inner.throttle.lock().locked_for_ms(&peer_ip, inner.now_ms()) {
                    tracing::warn!(peer = %peer_ip, "refusing connection: locked out for {for_ms} ms");
                    inner.emit(NetEvent::LockedOut { peer: peer_ip, for_ms });
                    incoming.refuse();
                    continue;
                }
                let inner = inner.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(inner.clone(), incoming).await {
                        tracing::warn!(peer = %peer_ip, "connection ended: {e}");
                    }
                });
            }
        }
    }

    // Shutting down: drop the client first so input is released before the
    // endpoint stops draining.
    if let Some(conn) = inner.current.lock().take() {
        conn.close(CLOSE_CODE_DISCONNECT.into(), b"host shutting down");
    }
    inner.pairing.clear();
    endpoint.close(0u32.into(), b"host shutting down");
    endpoint.wait_idle().await;
    inner.stop_pipeline().await;
    inner.status_mut(|s| {
        s.listening = false;
        s.client = None;
        s.bound = None;
    });
    inner.emit(NetEvent::Stopped);
    tracing::info!("listener stopped");
}

/// Clears the "a client is connected" flag however the connection ends.
struct BusyGuard(Arc<Inner>);

impl Drop for BusyGuard {
    fn drop(&mut self) {
        *self.0.current.lock() = None;
        self.0.busy.store(false, Ordering::SeqCst);
        self.0.status_mut(|s| s.client = None);
    }
}

async fn handle_connection(inner: Arc<Inner>, incoming: quinn::Incoming) -> Result<()> {
    let peer = incoming.remote_address();
    let conn = incoming
        .await
        .map_err(|e| Error::Transport(format!("handshake with {peer}: {e}")))?;

    if inner
        .busy
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        tracing::info!(peer = %peer, "refusing second client: host busy");
        reject_busy(&conn).await;
        return Ok(());
    }
    let _busy = BusyGuard(inner.clone());
    *inner.current.lock() = Some(conn.clone());

    let handshake = tokio::time::timeout(
        Duration::from_millis(HANDSHAKE_TIMEOUT_MS),
        authenticate(&inner, &conn),
    )
    .await;

    let (streams, client, negotiated_features) = match handshake {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            let locked = inner
                .throttle
                .lock()
                .record_failure(peer.ip(), inner.now_ms());
            tracing::warn!(peer = %peer, "authentication failed: {e}");
            inner.emit(NetEvent::AuthRejected {
                peer: peer.ip(),
                detail: e.to_string(),
            });
            if locked {
                inner.emit(NetEvent::LockedOut {
                    peer: peer.ip(),
                    for_ms: AUTH_LOCKOUT_MS,
                });
            }
            conn.close(CLOSE_CODE_REJECTED.into(), b"authentication failed");
            return Err(e);
        }
        Err(_) => {
            let locked = inner
                .throttle
                .lock()
                .record_failure(peer.ip(), inner.now_ms());
            tracing::warn!(peer = %peer, "authentication timed out");
            inner.emit(NetEvent::AuthRejected {
                peer: peer.ip(),
                detail: "handshake timed out".into(),
            });
            if locked {
                inner.emit(NetEvent::LockedOut {
                    peer: peer.ip(),
                    for_ms: AUTH_LOCKOUT_MS,
                });
            }
            conn.close(CLOSE_CODE_REJECTED.into(), b"handshake timeout");
            return Err(Error::Auth("handshake timed out".into()));
        }
    };

    inner.throttle.lock().record_success(&peer.ip());
    let fingerprint = client.fingerprint_short();
    tracing::info!(peer = %peer, client = %client.name, key = %fingerprint, "client authenticated");
    inner.status_mut(|s| {
        s.client = Some(ClientInfo {
            name: client.name.clone(),
            fingerprint: fingerprint.clone(),
            route: HOST_ROUTE,
            peer,
            connected_at: Instant::now(),
        });
        s.trusted_clients = s.trusted_clients.max(1);
    });
    inner.emit(NetEvent::ClientConnected {
        name: client.name.clone(),
        fingerprint,
        peer,
    });

    let reason = run_session(&inner, conn, streams, negotiated_features).await;
    tracing::info!(peer = %peer, "client disconnected: {reason}");
    inner.emit(NetEvent::ClientDisconnected { reason });
    Ok(())
}

/// The host's reply to a client `Hello`, advertising the **intersection** of
/// what the client asked for and what this host supports.
///
/// Answering with the intersection rather than the host's full capability set
/// means the client's check is a single bit test, and neither side can end up
/// believing a feature is on while the other thinks it is off. `offered` is
/// derived from config, so an operator turning a feature off is indistinguishable
/// from a host that never had it.
fn host_hello(client_features: u64, offered: u64) -> Hello {
    Hello {
        version: PROTOCOL_VERSION,
        features: client_features & offered,
        agent: concat!("directdesk-host ", env!("CARGO_PKG_VERSION")).to_string(),
    }
}

/// Feature bits this host is willing to turn on, given its configuration.
fn offered_features(cfg: &NetConfig) -> u64 {
    let mut bits = 0;
    if cfg.pipeline.lossless_tiles_enabled {
        bits |= directdesk_shared::protocol::features::LOSSLESS_TILES;
    }
    bits
}

/// Tell a second client the host is taken, in the framing it is expecting.
async fn reject_busy(conn: &Connection) {
    let deadline = Duration::from_millis(3_000);
    let _ = tokio::time::timeout(deadline, async {
        let mut streams = quic::accept_streams(conn).await?;
        let _ = quic::read_framed::<Hello>(&mut streams.control.1, MAX_AUTH_MSG).await;
        // A host that is turning this client away offers nothing: the session
        // is about to be closed, so advertising capabilities would be noise.
        quic::write_framed(&mut streams.control.0, &host_hello(0, 0)).await?;
        quic::write_framed(
            &mut streams.control.0,
            &AuthMsg::AuthFail {
                reason: "host busy: another client is connected".into(),
            },
        )
        .await?;
        Ok::<(), Error>(())
    })
    .await;
    conn.close(CLOSE_CODE_REJECTED.into(), b"busy");
}

/// Hello exchange plus the pairing-or-authentication branch.
///
/// Returns the session's streams, the client record, and the **negotiated
/// feature bits** on success. Every error path has already told the client
/// `AuthFail` with a deliberately vague reason: "not paired" and "bad
/// signature" must not be distinguishable.
///
/// Ordering note that the whole tile feature rests on: the client writes its
/// `Hello` blind, the host reads it *before* writing its own reply, and the
/// client reads the host's reply before doing anything else. So both ends know
/// the intersection before either acts on it, and the host opens the tile
/// stream only to a client that asked for it.
async fn authenticate(
    inner: &Arc<Inner>,
    conn: &Connection,
) -> Result<(SessionStreams, TrustedPeer, u64)> {
    let mut streams = quic::accept_streams(conn).await?;

    let hello: Hello = quic::read_framed(&mut streams.control.1, MAX_AUTH_MSG).await?;
    directdesk_shared::protocol::validate_hello(&hello)?;
    let negotiated = hello.features & offered_features(&inner.cfg);
    quic::write_framed(
        &mut streams.control.0,
        &host_hello(hello.features, offered_features(&inner.cfg)),
    )
    .await?;
    tracing::debug!(
        agent = %hello.agent,
        client_features = format_args!("{:#x}", hello.features),
        negotiated = format_args!("{negotiated:#x}"),
        "client hello accepted"
    );

    let exporter = quic::channel_binding(conn)?;
    let (mut authenticator, challenge) = HostAuthenticator::start(&exporter)?;
    quic::write_framed(&mut streams.control.0, &challenge).await?;

    let first: AuthMsg = quic::read_auth(&mut streams.control.1).await?;
    let outcome = match &first {
        AuthMsg::ClientAuth {
            client_ed25519_pub, ..
        } => {
            let attempted = fingerprint_short(client_ed25519_pub);
            let trusted = inner.trusted.lock().clone();
            match authenticator.on_client_auth(&first, &trusted) {
                Ok(peer) => Ok((peer, false)),
                Err(e) => {
                    tracing::warn!(key = %attempted, "rejected client identity: {e}");
                    Err(e)
                }
            }
        }
        AuthMsg::PairStart { .. } => pair(
            inner,
            &mut streams,
            &mut authenticator,
            &exporter,
            &first,
            &hello,
        )
        .await
        .map(|peer| (peer, true)),
        other => Err(Error::Auth(format!(
            "expected ClientAuth or PairStart, got {}",
            variant_name(other)
        ))),
    };

    let (peer, newly_paired) = match outcome {
        Ok(v) => v,
        Err(e) => {
            let _ = quic::write_framed(
                &mut streams.control.0,
                &AuthMsg::AuthFail {
                    reason: "authentication rejected".into(),
                },
            )
            .await;
            return Err(e);
        }
    };

    // Same tail for both branches: the client challenges us back.
    let client_challenge: AuthMsg = quic::read_auth(&mut streams.control.1).await?;
    let (server_auth, ok) =
        match authenticator.on_client_challenge(&client_challenge, inner.identity.signing_key()) {
            Ok(v) => v,
            Err(e) => {
                let _ = quic::write_framed(
                    &mut streams.control.0,
                    &AuthMsg::AuthFail {
                        reason: "authentication rejected".into(),
                    },
                )
                .await;
                return Err(e);
            }
        };
    quic::write_framed(&mut streams.control.0, &server_auth).await?;
    quic::write_framed(&mut streams.control.0, &ok).await?;

    if newly_paired {
        inner.emit(NetEvent::Paired {
            name: peer.name.clone(),
            fingerprint: peer.fingerprint_short(),
        });
    }
    Ok((streams, peer, negotiated))
}

/// The SPAKE2 exchange, then the client's proof of which key it owns.
async fn pair(
    inner: &Arc<Inner>,
    streams: &mut SessionStreams,
    authenticator: &mut HostAuthenticator,
    exporter: &directdesk_shared::crypto::Exporter,
    pair_start: &AuthMsg,
    hello: &Hello,
) -> Result<TrustedPeer> {
    let Some(armed) = inner.pairing.take(inner.now_ms()) else {
        return Err(Error::Pairing(
            "no pairing window is open on the host".into(),
        ));
    };
    // Whatever happens now, the code is burned: `take` removed it.
    inner.emit(NetEvent::PairingCleared);

    let mut host = PairingHost::with_code(armed.code, armed.armed_ms, armed.ttl_ms);
    let response = host.on_pair_start(pair_start, exporter, inner.now_ms())?;
    quic::write_framed(&mut streams.control.0, &response).await?;

    let confirm: AuthMsg = quic::read_auth(&mut streams.control.1).await?;
    let ours = host.on_pair_confirm(&confirm, inner.now_ms())?;
    quic::write_framed(&mut streams.control.0, &ours).await?;
    quic::write_framed(&mut streams.control.0, &inner.identity.pair_complete()).await?;
    tracing::info!("pairing confirmed; awaiting the client's identity proof");

    // Pairing proved the user typed the code. This proves which key belongs to
    // the machine that typed it — signed over the challenge nonce this
    // connection already issued, so it cannot be replayed from elsewhere.
    let client_auth: AuthMsg = quic::read_auth(&mut streams.control.1).await?;
    let AuthMsg::ClientAuth {
        client_ed25519_pub, ..
    } = &client_auth
    else {
        return Err(Error::Auth("expected ClientAuth after PairComplete".into()));
    };
    let name =
        crate::config::sanitize_name(&hello.agent).unwrap_or_else(|| "paired client".to_string());
    let candidate = host.accept_client(client_ed25519_pub, &name, wall_clock_ms())?;

    let mut provisional = TrustedPeers::new();
    provisional.upsert(candidate)?;
    let peer = authenticator.on_client_auth(&client_auth, &provisional)?;

    {
        let mut trusted = inner.trusted.lock();
        trusted.upsert(peer.clone())?;
        trusted.save(&*inner.store, TRUSTED_CLIENTS_KEY)?;
        inner.status_mut(|s| s.trusted_clients = trusted.len());
    }
    tracing::info!(client = %peer.name, key = %peer.fingerprint_short(), "new client paired");
    Ok(peer)
}

fn wall_clock_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn variant_name(msg: &AuthMsg) -> &'static str {
    match msg {
        AuthMsg::PairStart { .. } => "PairStart",
        AuthMsg::PairResponse { .. } => "PairResponse",
        AuthMsg::PairConfirm { .. } => "PairConfirm",
        AuthMsg::PairComplete { .. } => "PairComplete",
        AuthMsg::ClientAuth { .. } => "ClientAuth",
        AuthMsg::ServerChallenge { .. } => "ServerChallenge",
        AuthMsg::ServerAuth { .. } => "ServerAuth",
        AuthMsg::ClientChallenge { .. } => "ClientChallenge",
        AuthMsg::AuthOk => "AuthOk",
        AuthMsg::AuthFail { .. } => "AuthFail",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- hello and feature negotiation -------------------------------------

    #[test]
    fn host_hello_matches_the_contract() {
        let h = host_hello(0, 0);
        assert_eq!(h.version, PROTOCOL_VERSION);
        assert!(directdesk_shared::protocol::validate_hello(&h).is_ok());
        assert!(h.agent.starts_with("directdesk-host"));
    }

    #[test]
    fn host_hello_advertises_the_intersection() {
        use directdesk_shared::protocol::features::LOSSLESS_TILES;

        // Both sides want it → on.
        assert_eq!(
            host_hello(LOSSLESS_TILES, LOSSLESS_TILES).features,
            LOSSLESS_TILES
        );
        // Client asks, host is not configured for it → off. This is the case
        // that must hold for rollout step 1, where the code ships inert.
        assert_eq!(host_hello(LOSSLESS_TILES, 0).features, 0);
        // Host offers, an older client never asked → off, and the host must
        // therefore never open the stream.
        assert_eq!(host_hello(0, LOSSLESS_TILES).features, 0);
        // A client advertising bits this host has never heard of must not cause
        // the host to echo them back as if it understood.
        assert_eq!(
            host_hello(u64::MAX, LOSSLESS_TILES).features,
            LOSSLESS_TILES
        );
    }

    #[test]
    fn offered_features_follow_config() {
        use directdesk_shared::protocol::features::LOSSLESS_TILES;

        let mut cfg =
            NetConfig::from_host_config(&crate::config::HostConfig::default().sanitized());
        assert_eq!(
            offered_features(&cfg) & LOSSLESS_TILES,
            0,
            "shipped default must offer nothing — rollout step 1 is byte-identical on the wire"
        );
        cfg.pipeline.lossless_tiles_enabled = true;
        assert_eq!(offered_features(&cfg) & LOSSLESS_TILES, LOSSLESS_TILES);
    }

    // -- auth messages -----------------------------------------------------

    #[test]
    fn auth_variant_names_are_distinct() {
        let names = [
            variant_name(&AuthMsg::AuthOk),
            variant_name(&AuthMsg::PairStart { spake_msg: vec![] }),
            variant_name(&AuthMsg::ClientAuth {
                client_ed25519_pub: [0; 32],
                sig: vec![],
            }),
        ];
        assert_eq!(names, ["AuthOk", "PairStart", "ClientAuth"]);
    }
}
