# Integration / review-pass notes (internal)

Open items surfaced by builder agents, to resolve in the review/integration pass
once the transport files are no longer held by active agents. Not user-facing.

## Confirmed defects (fix in review pass)

1. **`transport::reassembly::Reassembler::pop_frame` can deliver out of order.**
   The latest-wins `is_late` guard checks slot *creation*, not slot *completion*.
   A slot opened before a newer frame overtook it still completes and is handed
   over — reproduced by the netsim matrix (frame 151 delivered after 152 at
   5530 ms, hostile row). Fix: guard `pop_frame` against `last_delivered`
   (drop-and-count anything not newer), OR every consumer must add a present-slot
   latest-wins guard. The SimClient added `FrameDiscardedStale`; the real client
   present slot (client/src/renderer.rs FrameSlot) already does latest-wins, so
   playback is protected — but fix belongs in `pop_frame` so all consumers are safe.

## Shared-API gaps to fill (M4/M5 integration)

2. No explicit control variant meaning "datagram path dead → use reliable path."
   Matrix overloaded `RouteReport(DirectTcp)`. TCP-fallback agent (in flight) may
   already add one — reconcile.
3. No wire codec for `EncodedFrame` on a reliable path (`EncodedFrame` isn't
   `Serialize`, no length-prefixed form). Matrix hand-rolled `encode_frame_record`.
   TCP-fallback agent needs this in `shared` — reconcile / promote the harness codec.
4. Nothing computes `ConnStats.loss` — field exists, no estimator. Matrix built a
   frame-boundary fragment-accounting window in SimClient; transport-agnostic,
   belongs in `shared`.
5. `NullEncoder::set_bitrate` is a no-op (fine; bitrate adaptation asserted at
   adaptor output, not end-to-end byte rate).
6. Minor: Null{Encoder,Decoder}/MockInjector lack `Debug`; `BitrateAdaptor` doesn't
   expose its `AdaptConfig` back.

## Decisions made (Fable)

- **Segment TCP media (M4 refinement).** `tcp.rs` currently sends one
  length-prefixed message per video frame. A 2 MiB keyframe mid-write on a slow
  uplink can head-of-line-block input for hundreds of ms — violates the spec's
  top priority (input never trapped behind video). Review pass: segment media on
  the reliable channel into ~64 KiB chunks with a last-segment flag so the writer
  yields between chunks and Control/Input interleave. Reassemble on the client
  before handing to the decoder. QUIC path already fragments into datagrams, so it
  is unaffected. This intentionally diverges from the original "no fragmentation
  on TCP" note, because input-priority outranks it.

## TOP RECONCILIATION — handshake contract (two independent definitions)

The client-net agent and host-net agent EACH defined the application handshake
independently (client looked before host/src/net.rs existed). They may diverge.
When host-net lands, reconcile to ONE canonical handshake and make both sides +
both e2e tests agree:
- Client's version (in client/src/net.rs + client/tests/e2e_loopback.rs): Hello →
  pairing OR steady-state auth → StartStream → session; `FEATURE_PAIRING_REQUEST`
  Hello bit signals pairing intent; `PAIR_BIND_NONCE` binds client Ed25519 key to
  the pairing session. This version is PROVEN end-to-end (131 real frames, MITM
  rejected) — prefer it as canonical unless host-net's is clearly better.
- Verify: message ordering, the pairing-intent signal, channel-binding label/ctx,
  and that mouse-move goes datagram vs stream identically on both ends.
- The client's e2e built a host-side mirror from production primitives; once the
  real host listener exists, repoint the e2e at it (or keep the mirror as a second
  independent check).

## Cross-module contract reconciliations

- **Service pipe is one-request-per-connection** (connect → 1 msg → 1 response →
  disconnect). Any pipe client must reconnect per op. Confirm the tray/host code
  that calls EnsureFirewallRules etc. follows this.
- Auth signatures cover `role_domain_separator || exporter || peer_nonce` (crypto
  agent added the role prefix vs the contract's `exporter || peer_nonce`). Host and
  client net agents must both use the crypto helpers, not hand-roll — verify.

## Elevated smoke tests still owed (M3/M7 gate, needs admin)

- Firewall rule create/remove (INetFwRules::Add returns 0x80070005 unelevated).
- WTSQueryUserToken → CreateProcessAsUser host launch into user session.
- Real service install → start → EnsureFirewallRules → host appears in user session.

## Environment limits (need real two-machine test, documented in LIMITATIONS.md)

- WH_KEYBOARD_LL hook installs but never fires in this sandbox — key forwarding
  unverified end-to-end (mouse path IS verified). Retest on normal desktop.
- NVENC MFT ActivateObject fails 0x8000FFFF here; Intel QSV is the capture-adapter
  encoder and works. NVENC path unproven on mux'd/discrete-driven displays.
