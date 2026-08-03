# Security

This document describes DirectDesk's threat model, its pairing/authentication
design, what the privileged Windows service will and will not do, how
secrets are stored, and — just as importantly — what is **not** protected.
Read it before exposing a DirectDesk host to the open Internet.

## Threat model

DirectDesk is designed for one specific scenario: **an individual remotely
administering machines they own**, over an untrusted network (the public
Internet), where the two endpoints are not on the same LAN and cannot
necessarily meet in person to exchange keys out-of-band except through the
pairing code itself.

In scope (things DirectDesk actively defends against):

- A **network attacker** (anywhere between client and host — ISP, Wi-Fi
  sniffer, on-path router) who can observe or tamper with traffic, and who
  may attempt to intercept or replay the pairing exchange.
- A party who obtains **the pairing code alone**, after it has expired or
  been used — replay of a stale/used code must fail.
- A party who can connect to the host's listening port but does not possess
  a previously-paired client identity — such a connection must fail
  authentication and get nothing.
- Accidental **secret disclosure via logs**: nothing turns key material,
  pairing codes, or clipboard content into a log line (see "Secret
  handling in code" below).

Out of scope / explicitly not defended against (see "What is NOT
protected" for the full list): a fully compromised endpoint (if the host OS
is owned by malware, DirectDesk cannot protect itself — the attacker already
has the desktop), a local administrator on either machine, and physical
access to either machine.

## Pairing and authentication design

This is implemented by `shared::crypto` (identity, pairing, DPAPI storage)
and `shared::protocol::AuthMsg` (the wire messages) — see
`shared/src/protocol.rs` for the exact message shapes referenced below.

1. **TLS first.** Every connection — QUIC or the TCP fallback — is TLS
   underneath (QUIC via `quinn`+`rustls`, TCP fallback via `rustls`
   directly), using ALPN `directdesk/1`. Pairing and auth messages never
   travel in the clear.

2. **Pairing code.** The host generates a fresh **8-digit numeric code**,
   valid for **120 seconds**, **single-use**. It is shown on the host (tray
   icon) and entered on the client — this is the only secret a human ever
   has to move between the two machines, and it never touches the network
   as plaintext.

3. **SPAKE2, bound to the TLS channel.** The pairing code seeds a
   [SPAKE2](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-spake2)
   password-authenticated key exchange: `AuthMsg::PairStart` /
   `PairResponse` carry the SPAKE2 protocol messages, and both sides then
   send `PairConfirm { mac }` — an HMAC over `(transcript || tls_exporter
   || role)`. Including the **TLS exporter keying material** in that MAC is
   what binds the pairing to *this specific* TLS connection: even if a
   network attacker relayed the SPAKE2 messages over a *different* TLS
   connection they control (a classic MITM-relay), the exporter value would
   differ and the confirm MAC would not match. A guessed/brute-forced code
   without ever seeing the real TLS session gets nowhere, and — because the
   code is single-use and 120-second-lived — even an attacker who tried
   many codes against a live host session gets at most a handful of guesses
   before the code rotates.

4. **Long-term identity: Ed25519.** After a successful pairing,
   `AuthMsg::PairComplete` hands the client the host's Ed25519 public key
   (`host_ed25519_pub`) plus the host's TLS certificate's SPKI-SHA256 hash
   (`host_spki_sha256`) — see SPKI pinning below. The client's own Ed25519
   keypair is established during pairing so future connections don't need
   the human pairing step again.

5. **Steady-state (re-)authentication**, once paired, is a mutual
   challenge/response over Ed25519, again bound to the live TLS session:
   `ServerChallenge{nonce}` / `ClientAuth{client_ed25519_pub, sig}` where
   `sig` is a signature over `(tls_exporter || server_nonce)`, and
   symmetrically `ClientChallenge{nonce}` / `ServerAuth{sig}` the other
   direction. Binding every signature to the current TLS exporter value
   again defeats relay/MITM: a signature valid on one TLS connection is not
   valid replayed onto another. The exchange ends in `AuthOk` or
   `AuthFail{reason}`.

6. **SPKI-SHA256 pinning.** Once paired, the client remembers the host's
   certificate public key hash (`host_spki_sha256`) and will refuse to
   proceed if a future connection to "the same host" presents a different
   certificate — this catches a certificate swap (compromised host, or an
   attacker impersonating the host's IP/port) that plain TLS validation
   alone wouldn't catch, since DirectDesk doesn't rely on a public CA/WebPKI
   chain for host identity — it's pinned identity by design, not
   CA-issued trust.

7. **Message hygiene.** Every control message travels as `u32-le length ||
   postcard bytes`, with length caps enforced *before* allocation
   (`MAX_CONTROL_MSG` = 64 KiB general, `MAX_AUTH_MSG` = 4 KiB for
   pairing/auth specifically — auth messages are small, so anything bigger
   claiming to be one is presumptively hostile and rejected before
   decoding). `postcard` decoding is strict: unknown enum variants and
   trailing bytes are rejected outright (`decode_strict`), not tolerated —
   see the `rejects_trailing_bytes` / `rejects_wrong_version` tests in
   `shared/src/protocol.rs`.

## What the Windows service will and will not do

`DirectDeskService.exe` exists so the host application doesn't need to run
elevated just to manage firewall rules or autostart — but a privileged
service listening on a named pipe is exactly the kind of component that, if
designed carelessly, turns into "type any command, run it as SYSTEM." So it
is designed narrowly on purpose:

- **Fixed, zero-parameter operation menu only.** The entire IPC surface
  (`shared::svc_ipc::SvcRequest`) is a closed Rust enum with **no**
  string/path/argv fields:
  ```rust
  pub enum SvcRequest {
      Ping,
      GetStatus,
      EnsureFirewallRules,
      RemoveFirewallRules,
      RestartHostRequested,
  }
  ```
  There is no `RunCommand`, no `WriteFile`, no `SetRegistryValue` — and
  there never will be without a deliberate, reviewed wire-protocol change
  (any such change bumps `protocol::PROTOCOL_VERSION`). **The service will
  never execute arbitrary commands, scripts, or paths supplied by a
  client**, full stop.
- **ACL'd named pipe.** The IPC endpoint is `\\.\pipe\DirectDeskSvc`. Only
  the operations above are reachable through it, and the pipe's ACL
  restricts which local principals may even open a handle to it (no
  network exposure — named pipes of this form are local-machine only).
- **Small, capped messages.** `MAX_IPC_MSG` = 4 KiB, same strict
  `decode_strict` postcard handling as the main protocol — see the
  `ipc_roundtrip` test in `shared/src/svc_ipc.rs`.
- **`EnsureFirewallRules`/`RemoveFirewallRules`** create/remove a single
  firewall rule *group* scoped to the DirectDesk executable's own path and
  the configured ports — not a general "open a port" primitive parameterized
  by the caller.
- **`RestartHostRequested`** restarts the host agent in the interactive
  user session — it does not accept a session ID, executable path, or
  arguments from the caller; the service already knows what to restart and
  how.
- **`GetStatus`** returns `SvcStatus { service_version, host_running,
  firewall_rules_present, autostart_enabled }` — read-only diagnostic
  information, nothing sensitive.

## Secret storage: DPAPI

Paired identity material (the long-term Ed25519 keys and any derived
session-establishment secrets) is stored using Windows **DPAPI**
(`CryptProtectData`/`CryptUnprotectData`), not a custom-rolled encryption
scheme:

- **Host**: machine scope. This lets `DirectDeskHost.exe` (and, if needed,
  `DirectDeskService.exe` acting on its behalf) unprotect its stored
  identity without requiring a specific user to be logged in and unlocked
  — necessary because the host may need to run before/without an
  interactive logon (e.g. via the autostart service path).
- **Client**: user scope. The client is a user-interactive application by
  design (you're sitting at it), so its paired identities are protected to
  the logged-in user, matching normal Windows expectations for
  per-user secret storage (comparable to how browsers/credential managers
  scope their DPAPI use).

DPAPI ties protection to the Windows account (and, for machine scope, to
the machine) — see "What is NOT protected" for what this does and does not
defend against.

## Secret handling in code

`shared::secret::Secret<T>` is the vault type for anything sensitive in
memory: it deliberately does **not** implement `Serialize`/`Deserialize`
(so it can't be accidentally wire-transmitted) or a real `Debug`/`Display`
(both are overridden to print `[REDACTED]`), and it zeroizes its contents
on drop. Pairing codes, key material, and any derived secrets are meant to
live inside this type from the moment they're read until they're consumed.
Log output is never a place secret material should appear — the
`shared::logging` module's own doc comment states this as a rule for every
executable.

## What is NOT protected

Being honest about the edges of this design matters more than the design
itself. DirectDesk does **not** protect against:

- **A fully compromised host OS.** If malware or an attacker already has
  code execution on the host machine, DirectDesk's protocol security is
  irrelevant — they already have the desktop DirectDesk would be
  protecting. DirectDesk is a remote-access tool, not an endpoint security
  product.
- **Local administrator access on either machine.** An admin on the host or
  client can read process memory, dump DPAPI-protected blobs under that
  same user/machine context, attach a debugger, or simply read the
  installed files. DPAPI protects secrets from *other* users/machines, not
  from someone with admin rights on the same box.
- **Unsigned binaries.** `DirectDeskHost.exe`, `DirectDeskClient.exe`, and
  `DirectDeskService.exe` are **not code-signed** in this build. Windows
  SmartScreen will show an "unrecognized app" warning on first run on each
  machine, and some antivirus products may flag an unsigned executable
  that captures the screen and injects input more aggressively than a
  signed one would be flagged. This is expected, not a bug — code signing
  requires a certificate and process that's out of scope for this MVP.
  Verify you're running a build you (or someone you trust) actually
  compiled or that came from a source you trust, since there is no
  publisher signature to anchor that trust to.
- **No relay server exists.** There is nothing to add end-to-end encryption
  "on top of" for a relay hop, because there is no relay hop in this build
  — see [LIMITATIONS.md](LIMITATIONS.md). This is a limitations note more
  than a security one, but it's worth repeating here: don't assume a
  relay-hardening story exists yet.
- **Availability / DoS.** DirectDesk does not attempt to defend against a
  network flood aimed at the host's listening ports. Rate limiting exists
  narrowly for specific things (e.g. keyframe request throttling) but this
  is not a hardened Internet-facing service in the DDoS-resistance sense.
- **The pairing code channel itself.** The 120-second/single-use/
  SPAKE2-bound design defeats network-level attacks on the code, but if you
  read the pairing code out loud over a compromised phone call, screen-share
  it to someone untrusted, or otherwise leak it out-of-band, DirectDesk has
  no way to know that.
- **Physical access.** Neither endpoint is hardened against someone with
  physical access to the machine (that's what the PiKVM/TinyPilot
  out-of-band fallback mentioned in [NETWORK_SETUP.md](NETWORK_SETUP.md) is
  for on the host side — a hardware-level access path is a *different*
  problem DirectDesk doesn't attempt to solve).
- **Config file confidentiality from a local admin.** Host/client
  configuration (ports, quality defaults, etc.) is plain, readable
  configuration — it is not itself a secret and is not DPAPI-protected;
  only the paired identity material is. A local admin can read your
  DirectDesk settings.

If any of the above matter for your deployment more than they do for "one
person administering their own two machines," DirectDesk in its current
form is not the right tool.
