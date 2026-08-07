# Test Report

This is the running record of what has actually been tested, how, and with
what result, milestone by milestone. Every row must have a real date and a
real result — "should work" is not a result. When a milestone's code lands,
its section gets filled in by whoever did that work (or verified it); don't
pre-fill future milestones with assumed passes.

Milestone naming below follows the `// M<n> fills this in` /
`// Implemented in M<n>` markers already present in the codebase
(`host/src/main.rs`, `client/src/main.rs`, `service/src/main.rs`,
`shared/src/crypto/mod.rs`, `shared/src/transport/mod.rs`,
`shared/src/nettest.rs`, `tests/src/lib.rs`, and the M7 reference in
`tools/smoke-install.ps1`). Milestone names follow the approved plan:
M4 = TCP/TLS fallback, M5 = adaptive bitrate + quality modes. UI/tray
polish is covered inside M1/M3 rows.

## M0 — Workspace foundation, shared protocol/types

**Status: DONE.**

| Feature | How tested | Result | Date |
|---|---|---|---|
| Cargo workspace builds (`shared`, `host`, `client`, `service`, `tests` members) | `cargo build --workspace` | PASS | 2026-08-04 |
| `directdesk-shared` unit test suite | `cargo test --workspace` (via native PowerShell; see note below) | PASS — 19/19 tests green | 2026-08-04 |
| Wire framing round-trip (`encode_framed`/`parse_frame_len`/`decode_strict`) | `protocol::tests::framed_roundtrip` | PASS | 2026-08-04 |
| Strict decode rejects trailing bytes | `protocol::tests::rejects_trailing_bytes` | PASS | 2026-08-04 |
| Oversized frame prefix rejected pre-allocation | `protocol::tests::rejects_oversized_prefix` | PASS | 2026-08-04 |
| Protocol version mismatch rejected | `protocol::tests::rejects_wrong_version` | PASS | 2026-08-04 |
| Route labels never claim "direct" for relayed | `stats::tests::route_labels_honest` | PASS | 2026-08-04 |
| Stats validation rejects NaN/out-of-range | `stats::tests::stats_validation` | PASS | 2026-08-04 |
| Service IPC request round-trip | `svc_ipc::tests::ipc_roundtrip` | PASS | 2026-08-04 |
| Video fragment header encode/decode round-trip | `video::tests::header_roundtrip` | PASS | 2026-08-04 |
| Frame fragmentation respects datagram size | `video::tests::fragment_then_sizes_ok` | PASS | 2026-08-04 |
| Fragment header validation rejects malformed input | `video::tests::rejects_bad_headers` | PASS | 2026-08-04 |
| Adaptive bitrate backs off on loss, recovers when clean | `adapt::tests::decreases_on_loss_and_recovers` | PASS | 2026-08-04 |
| Adaptive bitrate respects configured floor | `adapt::tests::respects_floor` | PASS | 2026-08-04 |
| Normalized-coordinate round-trip at frame corners | `geometry::tests::norm_roundtrip_corners` | PASS | 2026-08-04 |
| Normalized-coordinate round-trip error bounded | `geometry::tests::norm_roundtrip_error_bounded` | PASS | 2026-08-04 |
| Letterbox rect calculation | `geometry::tests::fit_rect_letterboxes` | PASS | 2026-08-04 |
| Exact rect calculation (no scaling, no letterbox) | `geometry::tests::fit_rect_is_exact_when_dst_matches_src` | PASS | 2026-08-04 |
| Input event validation rejects zero scan code | `input::tests::rejects_zero_scan_code` | PASS | 2026-08-04 |
| Input event validation accepts normal events | `input::tests::accepts_normal_events` | PASS | 2026-08-04 |
| Held-input tracking releases everything on demand | `input_state::tests::releases_everything_held` | PASS | 2026-08-04 |
| Secret redaction in Debug/Display | `secret::tests::debug_and_display_redact` | PASS | 2026-08-04 |
| `cargo clippy --workspace -- -D warnings` | Direct run | PASS (no warnings) | 2026-08-04 |
| `cargo fmt --check` | Direct run | **FAIL** — pre-existing formatting drift in `shared/src/video.rs` (multi-line struct literals need rustfmt reformatting); not caused by this milestone's docs/tools/installer work and out of that work's file ownership to fix | 2026-08-04 |

Note: `cargo build`/`cargo test` occasionally report a spurious
`LINK : fatal error LNK1104` when run through an emulated POSIX shell
(Git-Bash/MSYS) on this toolchain — re-running, or running from native
PowerShell, resolves it. This is an environment quirk, not a code defect;
see [BUILDING.md](BUILDING.md).

## M1 — Host/client core (capture → encode → stream → decode → display → input)

| Feature | How tested | Result | Date |
|---|---|---|---|
| `DirectDeskHost.exe --selftest` (self-check without a peer) | | Not yet implemented | |
| `DirectDeskClient.exe --loopback-demo` (client against a local loopback host) | | Not yet implemented | |
| Desktop capture (Desktop Duplication API) | | | |
| H.264 hardware encode via Media Foundation (adapter LUID selection) | | | |
| H.264 decode + present on client | | | |
| Keyboard/mouse input injection round-trip | | | |
| Release chord (Ctrl+Alt+Shift+F12) | | | |

## M2 — Pairing, identity, transport (SPAKE2 / Ed25519 / QUIC+TCP)

| Feature | How tested | Result | Date |
|---|---|---|---|
| SPAKE2 pairing exchange, bound to TLS exporter | | | |
| Pairing code single-use + 120s expiry enforcement | | | |
| Ed25519 identity issuance and steady-state challenge/response | | | |
| SPKI-SHA256 pinning rejects a swapped host certificate | | | |
| QUIC direct connect (IPv4) | | | |
| QUIC direct connect (IPv6) | | | |
| TCP/TLS fallback connect | | | |
| DPAPI secret storage round-trip (host machine-scope, client user-scope) | | | |

## M3 — Windows service (privileged ops, autostart)

| Feature | How tested | Result | Date |
|---|---|---|---|
| `DirectDeskService.exe install` / `uninstall` / `start` / `stop` verbs (SYNC-POINT — confirm against `installer/directdesk.iss`) | | | |
| Named pipe `\\.\pipe\DirectDeskSvc` ACL restricts non-local/unauthorized access | | | |
| `Ping` / `GetStatus` round-trip | | | |
| `EnsureFirewallRules` creates the expected exe+port-scoped rule group | | | |
| `RemoveFirewallRules` fully reverses `EnsureFirewallRules` | | | |
| `RestartHostRequested` restarts host in the interactive session | | | |
| Service rejects any request outside the fixed `SvcRequest` enum | | | |

## M4 — TCP/TLS fallback

| Feature | How tested | Result | Date |
|---|---|---|---|
| TCP/TLS session over loopback with SPKI pinning + exporter agreement | `tcp.rs` unit tests (real 127.0.0.1 TLS) | PASS | 2026-08-04 |
| Input-priority queues: video backlog never delays input | `input_beats_the_queued_video_backlog` | PASS | 2026-08-04 |
| Media segmentation: input interleaves mid-frame (~64 KiB, not whole frame) | `input_interleaves_within_a_multi_segment_frame` — input overtook 29/32 segments of a 2 MiB frame | PASS | 2026-08-04 |
| Obsolete queued video dropped (latest-wins) + IDR requested on drop/gap | `reassembler_handles_gaps_drops_and_corruption` | PASS | 2026-08-04 |
| Staggered route racing (happy-eyeballs) picks + labels route honestly | `race.rs` 19 tests (ManualClock) | PASS | 2026-08-04 |
| Full end-to-end TCP host↔client swap under live UDP block | needs two machines / induced UDP block | NOT RUN | — |

## M5 — Adaptive bitrate + quality modes

| Feature | How tested | Result | Date |
|---|---|---|---|
| Quality mode switch applies mode ceiling/floor; BitrateLimit clamps | `quality_mode_switch_applies_ceiling_and_floor`, `caps_narrow_but_never_widen`, `bitrate_limit_clamps_the_adaptor_output` | PASS | 2026-08-04 |
| Bitrate adapts DOWN on real loss and recovers UP when clean | `adaptor_backs_off_on_real_loss_then_recovers` (synthetic ConnStats) | PASS | 2026-08-04 |
| Adaptor driven by TRUE app-level loss (sees quinn's silent datagram discards) | `session::video_loss` unit tests + wired in host `status_loop` | PASS | 2026-08-04 |
| Clean link raises bitrate, no false downshift (startup overrun gated) | real loopback: raised to 8750 kbps at 0% loss; `startup_overrun_does_not_spuriously_downshift` | PASS | 2026-08-04 |
| Quality mode bitrate ceiling (TextDesktop now highest due to text detail demands) | `quality_mode_switch_applies_ceiling_and_floor` (M5 tests); TextDesktop carries 20,000 kbps ceiling as glyph edges are bitrate-hungry high-frequency detail | PASS | 2026-08-04 |

## Cross-binary interop (keystone)

| Feature | How tested | Result | Date |
|---|---|---|---|
| REAL DirectDeskHost ↔ REAL DirectDeskClient: fresh pairing streams video | `client/tests/interop.rs` case (a) — 147 real frames | PASS | 2026-08-04 |
| Steady-state reconnect (no code) against trusted host | interop case (b) | PASS | 2026-08-04 |
| Wrong pairing code fails cleanly, host burns the code | interop case (c) | PASS | 2026-08-04 |
| Host presenting a different SPKI rejected at pinning (anti-MITM) | interop case (d) | PASS | 2026-08-04 |

## M6 — Integration test matrix (netsim-driven)

| Feature | How tested | Result | Date |
|---|---|---|---|
| In-process host+client core test harness (`tests` crate) builds and runs | | | |
| Netsim scenario: baseline (no impairment) | | | |
| Netsim scenario: high latency (150–300ms, matching the reference WAN path) | | | |
| Netsim scenario: packet loss | | | |
| Netsim scenario: jitter/reorder | | | |
| Netsim scenario: outage window + recovery | | | |

## M7 — Installer

| Feature | How tested | Result | Date |
|---|---|---|---|
| `tools/build-installer.ps1` produces `installer/Output/*.exe` via Inno Setup 6 | | | |
| Fresh-machine install: three exes land in `{autopf}\DirectDesk` | | | |
| Start Menu shortcuts (host + client) created | | | |
| Optional "Start DirectDesk automatically with Windows" installs+starts the service and adds the HKCU Run entry | | | |
| Uninstall reverses service install, HKCU Run entry, and firewall rules | | | |
| Uninstall prompts before deleting `%ProgramData%\DirectDesk` | | | |
| `tools/smoke-install.ps1` scripted verification | | Placeholder only — steps not yet automated | |

## M8 — Connection test / NAT diagnostics (`shared::nettest`)

| Feature | How tested | Result | Date |
|---|---|---|---|
| STUN-based reachability discovery | | | |
| CGNAT detection (compares discovered public IP against router-reported WAN IP) | | | |
| UDP reachability probe | | | |
| Connection test correctly names a port-collision culprit (e.g. Sunshine) when bind fails | | | |
| End-to-end WAN validation: Philippines client ↔ Ohio host, real Spectrum connection | | | |

## Lossless static-region refinement (tiles)

Once a region of the desktop stops changing, the host re-sends it losslessly on
a reliable side stream and the client composites it over the H.264 video, so
static text converges to pixel-exact. Off by default on the host
(`lossless_tiles_enabled`); it activates only when the client also advertises
`features::LOSSLESS_TILES` and the host echoes the bit back.

**Status: implemented, headless verification green, and first activated on the
real Philippines↔Ohio link on 2026-08-07 — the feature negotiates and streams,
and the operator reports a clear image-quality improvement. The congestion
residual below is still UNMEASURED on a real link; see the staged rollout in
the plan.**

### Wire stability (the anti-brick suite)

These guard the ways a wire change can lock a *remote* host out permanently.
Read the comments in `shared/src/protocol.rs` before adding any wire feature.

| Feature | How tested | Result | Date |
|---|---|---|---|
| `PROTOCOL_VERSION` pinned at 1 (a bump causes a permanent auth-lockout loop: 3 failures → 30 s IP lockout vs the client's 10 s max backoff) | `protocol::tests::protocol_version_is_pinned` | PASS | 2026-08-07 |
| `Hello` postcard encoding pinned to exact bytes; setting a feature bit changes only the features field | `protocol::tests::hello_encoding_is_stable` | PASS | 2026-08-07 |
| `ConnStats` encoding pinned to exact bytes (a new field breaks every deployed peer via `decode_strict` "trailing bytes" on the first stats tick) | `protocol::tests::conn_stats_encoding_is_pinned` | PASS | 2026-08-07 |
| `ControlMsg` discriminants pinned so a variant can only be appended, never inserted | `protocol::tests::control_msg_discriminants_are_pinned` | PASS | 2026-08-07 |
| Feature bits are distinct single bits and stay out of the client's high-bit hint range | `protocol::tests::feature_bits_are_distinct` | PASS | 2026-08-07 |

### Codec — losslessness is the premise

| Feature | How tested | Result | Date |
|---|---|---|---|
| **compress → decompress is byte-identical** over random, solid, gradient and synthetic-text inputs (property test) | `tiles::tests::compress_decompress_is_byte_identical` (proptest) | PASS | 2026-08-07 |
| Solid strip costs 3 bytes (matters: `blank_wallpaper_during_session` makes much of the screen solid black) | `tiles::tests::solid_strip_costs_three_bytes` | PASS | 2026-08-07 |
| Synthetic monochrome text compresses hard and exactly | `tiles::tests::synthetic_text_compresses_hard_and_exactly` | PASS | 2026-08-07 |
| Partial edge strips (not a multiple of 64) round-trip | `tiles::tests::partial_edge_strip_roundtrips` | PASS | 2026-08-07 |
| Extents past the source buffer are rejected | `tiles::tests::rejects_extent_past_buffer` | PASS | 2026-08-07 |
| Malformed payloads and wrong-dimension decodes are rejected, never reinterpreted | `tiles::tests::rejects_malformed_payloads` | PASS | 2026-08-07 |
| Worst-case strip fits inside `MAX_CONTROL_MSG`, so `encode_framed` needs no change | `const _: () = assert!(MAX_STRIP_ENCODED < MAX_CONTROL_MSG)` | PASS (compile-time) | 2026-08-07 |

### Host grid state machine (`host::tiles`) — 47 tests

| Feature | How tested | Result | Date |
|---|---|---|---|
| Strips never cross a tile row nor exceed 4 tiles; emitted in raster order | `strips_never_cross_a_row_or_exceed_the_tile_cap`, `strips_are_emitted_in_raster_order` | PASS | 2026-08-07 |
| An unanswerable dirty-rect query marks the **entire** grid (the governing invariant) | `unanswerable_dirty_query_marks_the_entire_grid` | PASS | 2026-08-07 |
| Move rects mark both source and destination | `move_rect_marks_source_and_destination` | PASS | 2026-08-07 |
| Inverted rects are normalised, not discarded | `inverted_dirty_rect_is_normalised_not_dropped` | PASS | 2026-08-07 |
| Wrapping capture clock correct across `u32::MAX` (settle, leases, due-ness) | `reached_is_correct_across_u32_max`, `tile_due_crosses_u32_max`, `leases_expire_across_u32_max` | PASS | 2026-08-07 |
| Hash suppression fails closed — a comparison that cannot be made answers "different" | `strip_matches_sent_fails_closed`, `suppression_never_fires_on_a_tile_the_client_no_longer_holds` | PASS | 2026-08-07 |
| Identical repaint of a resident tile is renewed, not re-sent (caret blink) | `identical_repaint_of_a_resident_tile_is_renewed_not_resent` | PASS | 2026-08-07 |
| Re-verification that finds different pixels revokes rather than blindly renewing | `reverify_that_finds_different_pixels_revokes` | PASS | 2026-08-07 |
| **Reset forgets hashes so a reconnect re-sends everything** (the pipeline outlives a connection) | `reset_forgets_hashes_so_a_reconnect_resends_everything` | PASS | 2026-08-07 |
| A revoke list past half the grid collapses into one `Reset`; dedupes before measuring | `revoke_or_reset_boundaries`, `revoke_or_reset_dedupes_before_measuring` | PASS | 2026-08-07 |

### Client store + compositor (`client::tiles`) — 33 tests

| Feature | How tested | Result | Date |
|---|---|---|---|
| Right/bottom edge clipping; offsets need not be multiples of 64 | `right_edge_tile_is_clipped_not_wrapped`, `bottom_edge_tile_is_clipped`, `offsets_need_not_be_multiples_of_the_tile_edge` | PASS | 2026-08-07 |
| **Every byte outside the clipped union is unchanged** (the blit never writes out of bounds) | `every_byte_outside_the_clipped_union_is_unchanged` | PASS | 2026-08-07 |
| Absurd dimensions neither panic nor over-allocate; malformed payloads rejected | `absurd_dimensions_neither_panic_nor_allocate`, `corrupt_strip_payload_is_rejected_without_panicking` | PASS | 2026-08-07 |
| Store/frame resolution mismatch paints nothing | `resolution_mismatch_paints_nothing` | PASS | 2026-08-07 |
| Lease expiry, inclusive at both ends, correct across `u32::MAX` | `lease_comparator_is_inclusive_at_both_ends`, `lease_window_wraps_across_u32_max`, `store_composites_across_the_clock_wrap` | PASS | 2026-08-07 |
| `clear()` disarms the store until the host's next `Reset` (closes the in-flight-tile race) | `clear_disarms_until_the_next_reset` | PASS | 2026-08-07 |
| Capacity overflow drops the incoming tile and never evicts a resident one | `capacity_overflow_drops_the_incoming_tile_and_keeps_residents` | PASS | 2026-08-07 |
| Messages before the first `Reset` are refused | `messages_before_the_first_reset_are_refused` | PASS | 2026-08-07 |

### Negotiation and congestion coupling (`host::net`)

| Feature | How tested | Result | Date |
|---|---|---|---|
| Host advertises the **intersection** of client-requested and host-offered features | `net::tests::host_hello_advertises_the_intersection` | PASS | 2026-08-07 |
| Shipped default offers nothing — rollout step 1 is byte-identical on the wire | `net::tests::offered_features_follow_config`, `config::tests::tiles_are_off_by_default` | PASS | 2026-08-07 |
| Tile budget is zeroed by any strain signal (backpressure, >2% loss, oversized keyframe, not streaming) | `net::tests::tiles_never_spend_a_link_that_is_already_strained` | PASS | 2026-08-07 |
| Tiles claim only a quarter of *demonstrated* headroom; never negative or wrapped | `net::tests::tiles_claim_only_a_quarter_of_demonstrated_headroom` | PASS | 2026-08-07 |
| Configured ceiling narrows but never widens; `0` means "no ceiling", not "no bandwidth" | `net::tests::the_configured_ceiling_narrows_but_never_widens` | PASS | 2026-08-07 |
| Tile knobs clamped; lease always outlasts two settle periods (else the picture flickers) | `config::tests::tile_knobs_are_clamped`, `config::tests::tile_lease_always_outlasts_two_settles` | PASS | 2026-08-07 |

### Real-QUIC cross-version behaviour (`host/tests/tiles_interop.rs`)

The host being upgraded is in Ohio and is reached *through* this protocol, so a
handshake regression is close to unrecoverable. These run the real host over real
QUIC on loopback. 4/4 passed on each of 4 runs (both `--test-threads=1` and
default parallelism); none depends on frame rate, so none inherits the
`loopback.rs` throughput flake.

| Feature | How tested | Result | Date |
|---|---|---|---|
| A legacy client (`features: 0`) gets NO tile stream even from a host with tiles **enabled** — host reply is exactly 0, `accept_uni` never resolves across ~10 heartbeats, video and stats keep flowing | `legacy_client_gets_no_tile_stream_from_a_tiles_enabled_host` | PASS | 2026-08-07 |
| New client + host at the shipped default (`lossless_tiles_enabled: false`) is wire-identical to the old build — empty intersection, no stream, session otherwise unchanged (**rollout step 1's core property**) | `new_client_and_disabled_host_are_wire_identical_to_the_old_build` | PASS | 2026-08-07 |
| Both ends enabled: the uni stream opens and a `TileMsg::Reset` arrives and decodes (observed 2560x1600, edge 64) | `both_ends_enabled_opens_the_stream_and_delivers_a_reset` | PASS | 2026-08-07 |
| A dead/malformed tile stream degrades the picture, never the session — `decode_strict`/`decompress_strip` reject garbage without panicking, and video + stats keep *increasing* for 3 s after the tile stream is reset | `a_dead_tile_stream_degrades_the_picture_not_the_session` | PASS | 2026-08-07 |

Scope limit recorded honestly: the production client's malformed-message policy
(`client::net::forward_tiles` never touching the session) is not reachable from a
host integration test — `directdesk-host` does not depend on `directdesk-client`.
That policy is covered by unit tests in `client/src/tiles.rs` instead.

### Not yet verified — required before this is trusted on the real link

| Feature | How tested | Result | Date |
|---|---|---|---|
| DXGI dirty rects are a true superset of what changed, on real hardware | `host/src/bin/capture_harness.rs --dirty` on the Ohio host | NOT RUN (see note below) | |
| Cross-version against `DirectDesk-bins.zip` (old client ↔ new host, and the reverse), real QUIC, incl. pairing + reconnect | rollout step 0 | **FAIL — but pre-existing, not caused by tiles.** See below | 2026-08-07 |
| Cross-version against a **binary built from `a5a928f`** — the commit the Ohio host is believed to be running. Real exes, real QUIC, pairing + reconnect, fresh secret stores per scenario | rollout step 0, rebuilt baseline | **PASS — all four pairings** | 2026-08-07 |
| Feature actually negotiates and streams over the real WAN link, host `lossless_tiles_enabled: true` | Ohio host at `f7255c1` (hash-verified against the local build), live session. Client logged `host accepted lossless tile refinement`, host logged `lossless tile stream open` ~2 s later; no `lossless tiles disabled` and no `tile stream write failed` for the session's duration | **PASS** | 2026-08-07 |
| Image quality on the real link with tiles on | Operator judgement on a live session, not a measurement | **PASS (subjective)** | 2026-08-07 |
| Video-budget residual (the ~59% figure below) under real, supply-limited demand | Not measured. The sessions used for the check sat on a near-static desktop, so frame cadence was governed by `idle_repeat_ms`, not by refinement demand — the residual cannot be read off these logs | NOT RUN | |

**Note (2026-08-07):** `capture_harness.rs` used to build its own capture/convert/encode pipeline from hardcoded numbers that had drifted from production — `idle_repeat_ms` 33 (a value `HostConfig::sanitized()` actively heals to 250, since a hand-edited/legacy 33 produced ~30 identical full frames a second on a still desktop), `fps` 60, `bitrate_kbps` 15000, `gop_seconds` 4. It now builds its `SessionConfig` from `HostConfig::default().sanitized().pipeline()` and gets its capture/convert/encode stage from `session::build_pipeline` — the same construction production uses — keeping only its own decoder and HUD, which production has no reason to own. This means the harness now measures the real, currently-shipping pipeline instead of a look-alike with its own idea of the numbers, but it also means **any dirty-rect (or other capture_harness) result recorded before this date is not directly comparable to one recorded after it.** To interpret an old result, use the hardcoded values above rather than today's `HostConfig` defaults.

### Congestion coupling (netsim matrix, `tests/tests/tiles_netsim.rs`)

Tiles ride streams and video rides datagrams, so they never share a send buffer —
but they do share one congestion window. Unthrottled tiles inflate the host's
`backpressured` counter, which the adaptor reads as congestion and answers by
cutting **video** bitrate, with zero packet loss and no obvious cause. The
netsim has no bandwidth model, so the harness models the shared window itself
(token bucket) in front of it; video still goes through the real fragmenter,
reassembler and adaptor, and the throttle under test is the shipped one.

| Feature | How tested | Result | Date |
|---|---|---|---|
| **Supply-limited refinement (a real screen) costs the video path nothing** — at 300/600/1200 kbps of refinement demand on a 2500 kbps link, presented frames, mean adaptor and pressure windows are **bit-identical to tiles-off** | `a_quiet_screen_is_free_and_parks_the_ceiling_above_its_own_demand` | PASS | 2026-08-07 |
| Clean link (6000 kbps): video path identical with tiles on, 8.9 MB of tiles carried | matrix, clean row | PASS | 2026-08-07 |
| Lossy link (3%): video path identical; every window from the 2nd grants exactly what an unthrottled policy would | matrix, lossy row | PASS | 2026-08-07 |
| Negative control — with the throttle removed the same link collapses to 30 presented frames (from 856), proving the passing rows are not vacuous | `TilePolicy::Unthrottled` | PASS | 2026-08-07 |
| The learned ceiling beats the raw-gap policy on a constrained link, without buying it by refining less | `the_learned_ceiling_beats_the_raw_policy_on_a_constrained_link` | PASS (+6.7% mean adaptor) | 2026-08-07 |
| Link loss without backpressure does not lower the learned ceiling (false attribution) | `loss_without_backpressure_does_not_lower_the_ceiling` | PASS | 2026-08-07 |

**Known residual — the one thing not closed.** When refinement demand is
*unbounded* and the link is constrained (2500 kbps, saturated supply), tiles
still depress the mean video target to ~59% of its tiles-off value (6698 vs
11258). Three of 29 windows overshoot; that count is unchanged across every
revision of the throttle so far, and each overshoot costs a 30% multiplicative
cut that takes seconds of additive recovery to undo. `constrained_link_should_not_lower_the_video_target`
is kept `#[ignore]`d as the property that *should* hold, and
`constrained_link_headroom_estimate_overshoots` characterises the current
behaviour so it fails if this gets better **or** worse.

This is why the feature ships **off by default** and why rollout step 4 is
"tune". Watch the host's `tile diag` line: `backpressured` climbing while
`tile_strips` flows and `loss` stays at zero is the signature.

| Feature | How tested | Result | Date |
|---|---|---|---|
| Constrained link with unbounded refinement demand: video target not lower than tiles-off | `constrained_link_should_not_lower_the_video_target` | **IGNORED — still fails (59%)** | 2026-08-07 |
| Real link: text snaps to pixel-exact within ~1 s; compression ratio 0.02–0.08 on monochrome text | Philippines ↔ Ohio, host `tile diag` log | NOT RUN | |

### ⚠ Wire compatibility with already-deployed builds — read before any deploy

Rollout step 0 was run with the binaries in `DirectDesk-bins.zip` and **failed in
both directions**: pairing and authentication succeed, then the control stream
dies ~1 s in with `1 trailing bytes` / `Hit the end of buffer`, and the client
enters a permanent reconnect loop with no video. The host meanwhile logs a
healthy `client authenticated`, which is what makes it dangerous.

**This is not caused by the tiles feature, and turning `lossless_tiles_enabled`
off does not help.** The cause is already committed and pushed:

- `a5a928f` (UAC click-through) **inserted** `ElevationPrompt` / `ArmElevation` /
  `ElevationEnded` into the middle of `ControlMsg`, renumbering `Bye`, `Ping` and
  `Pong` from 10/11/12 to 13/14/15. postcard addresses variants by index, so a
  peer from before that commit misreads every heartbeat — hence the ~1 s death.
- `66b8c7b` / `6693c74` separately changed the FEC video datagram format.
- `PROTOCOL_VERSION` stayed `1` throughout, so nothing detects the mismatch.

`DirectDesk-bins.zip` is dated 2026-08-04 and therefore predates all of that. It
is **not** a valid stand-in for the Ohio host, which was updated through
`a5a928f` and confirmed on the real link on 2026-08-05.

**Verified by direct comparison against `a5a928f`:** the `ControlMsg` enum body
and the `ConnStats` struct are *byte-identical* to that commit, `shared/src/video.rs`
and `shared/src/transport/reassembly.rs` are unchanged since it, and the only
protocol edit is additive (one `features` bit constant plus tests). So **HEAD is
wire-compatible with `a5a928f`**, which is what the staged rollout depends on.

**Rollout step 0 against a rebuilt `a5a928f` baseline: PASS, all four pairings**
(2026-08-07). Real binaries over real QUIC, each with a pairing run and a
reconnect on the stored identity, isolated secret stores per scenario:

| pairing | auth | video | duration | errors |
|---|---|---|---|---|
| old client → **new host** (the deploy scenario) | pair + reconnect | 2213 & 4390 frames | 97 s / 82 s | 0 |
| **new client** → old host | pair + reconnect | 2326 & 1937 | 42 s / 38 s | 0 |
| new ↔ new | pair + reconnect | 1621 & 2013 | 30 s / 40 s | 0 |
| old ↔ old (control — proves the harness) | pair + reconnect | 1735 & 2353 | 30 s / 40 s | 0 |

Zero `trailing bytes`, `Hit the end of buffer`, serialization errors or panics
across all 16 logs. The old client also handles the **H.264 High profile** switch
from `449aa23` (host emits `profile_idc = 100`, old client reports
`H.264 stream change → 2560x1600`, ~57 fps) — a risk that had nothing to do with
tiles. The host's own negotiation logging confirms the tile stream is inert:
`client_features=0x100000000 negotiated=0x0` for the old client, and even for a
new client `0x100000008 → 0x0` while the host default is off. No `open_uni` in
any host log.

**Verdict: deploying the new host to an Ohio box running `a5a928f` does not
require touching the client.**

Caveats worth keeping: this was loopback (no real WAN loss/reordering/MTU) on one
machine, so both ends shared an Intel QSV encoder; heartbeats are proven only
indirectly (Ping/Pong are never logged, but a renumbered discriminant would fail
`decode_strict` and an unmatched Pong raises an explicit error, and 30-97 s
sessions exchanged ~15-40 of them silently); and it tested a locally built
`a5a928f`, not Ohio's actual binary. **If Ohio predates `a5a928f`, host and client
must be upgraded together** — see the renumbering above.

**Structural gap this exposed:** no test in this repo drives the real `.exe`s.
`host/tests/loopback.rs` and `client/tests/e2e_loopback.rs` link both sides into
one binary from one source version, so they cannot catch a cross-version break by
construction. That is why this had to be done by hand, and why it should be
repeated by hand before each host deploy.

## System audio (host → client)

WASAPI loopback capture → Media Foundation AAC-LC → QUIC datagram, one AAC
access unit per packet, sharing the video path's flags byte for demux. Client
side: a network-domain jitter buffer with adaptive depth and clock-drift
correction, an MF AAC-LC decoder, and a WASAPI shared-mode render endpoint
with its own device-domain drift corrector. Negotiated as a `Hello` feature
bit (`features::SYSTEM_AUDIO`); off by default on the host
(`system_audio_enabled: false`).

**Status: implemented and committed** on 2026-08-07, across eight commits from
the audio datagram format through to this section.

The gate has since run: `powershell -NoProfile -File tools\check.ps1` on
2026-08-07 reported **OVERALL: PASS** — `cargo fmt --check`, `cargo clippy
--workspace --all-features -- -D warnings`, and `cargo test --workspace` all
green. `directdesk-shared` lib: 347 passed, 1 ignored (a pre-existing
public-STUN test, unrelated to audio). `directdesk-host` lib: 347 passed.
`directdesk-service`: 93 passed. `host/tests/audio_interop.rs`: 4 passed, 0
failed. The pre-existing `host/tests/loopback.rs`, `host/tests/tiles_interop.rs`,
`client/tests/interop.rs`, and `client/tests/e2e_loopback.rs` all continued to
pass — no regression from adding audio.

The rows below are updated to PASS where the test named in that row is covered
by that run. Rows still marked NOT RUN are exactly the ones the gate did not
and could not exercise: real WASAPI capture/playback against actual hardware,
the real WAN link, multi-hour real-time drift, and measured (as opposed to
predicted) A/V skew — see "Not yet verified" below. Do not read "the gate
passed" as "audio is audible" — nobody has yet heard anything play back on
real hardware.

### Wire format and demux (`shared/src/audio/mod.rs`)

| Feature | How tested | Result | Date |
|---|---|---|---|
| Audio packet header encode/decode round-trips; byte layout pinned | `audio::tests::audio_header_layout_is_pinned`, `packet_roundtrips` | PASS | 2026-08-07 |
| Decoder rejects short/malformed datagrams, reserved flag bits, missing `FLAG_AUDIO`, unknown format codes, oversized payloads | `audio::tests::decode_rejects_*` (5 tests) | PASS | 2026-08-07 |
| Audio/video datagram demux has no false positives in either direction, incl. against generated video traffic across frame sizes/MTU/FEC block size | `audio::tests::a_real_audio_packet_is_rejected_by_the_video_decoder`, `is_audio_datagram_never_claims_a_real_video_fragment` (proptest) | PASS | 2026-08-07 |

### Jitter buffer (`shared/src/audio/jitter.rs`)

| Feature | How tested | Result | Date |
|---|---|---|---|
| In-order delivery, reorder repair, loss declared only after the reorder wait (or immediately on a full window) | `jitter::tests::packets_arriving_in_order_are_delivered_in_order_with_no_loss`, `a_single_swapped_pair_is_repaired_without_declaring_loss`, `a_missing_packet_is_declared_lost_once_the_reorder_wait_expires`, `a_full_window_declares_loss_immediately_without_waiting` | PASS | 2026-08-07 |
| Sequence numbers wrap through `u32::MAX`, including reordering across the wrap | `jitter::tests::sequence_numbers_wrap_through_u32_max_without_stalling`, `reordering_across_the_wrap_is_repaired_and_pre_wrap_stragglers_are_late` | PASS | 2026-08-07 |
| Discontinuity clears the window, forces a decoder flush, and re-seeds the drift corrector | `jitter::tests::discontinuity_clears_the_window_and_signals_a_decoder_flush`, `discontinuity_overrides_a_backwards_sequence_jump`, `discontinuity_reseeds_the_drift_corrector` | PASS | 2026-08-07 |
| Prebuffer withholds delivery until the target depth, without demanding more than the window can hold | `jitter::tests::delivery_waits_for_the_prebuffer_then_runs_freely`, `prebuffer_never_demands_more_than_the_window_can_hold` | PASS | 2026-08-07 |
| Depth controller raises on underrun (rate-limited) and decays only after a full clean window, clamped to its configured range | `jitter::tests::depth_controller_raises_on_underrun_and_stops_at_the_ceiling`, `depth_controller_raises_at_most_once_per_interval`, `depth_controller_decays_at_most_once_per_clean_window_and_stops_at_the_floor`, `depth_controller_respects_both_clamps_from_any_seed` | PASS | 2026-08-07 |
| Drift corrector idle inside its deadband, drops/inserts a frame outside it, fires at most once per window, and converges from both directions | `jitter::tests::drift_corrector_is_idle_inside_the_deadband`, `drift_corrector_drops_a_frame_when_the_buffer_runs_deep`, `drift_corrector_inserts_silence_when_the_buffer_runs_shallow`, `drift_corrector_fires_at_most_once_per_window`, `drift_corrector_converges_from_both_directions_and_then_goes_idle` | PASS | 2026-08-07 |
| Long synthetic-clock runs: a 2-hour session at 50 ppm drift stays bounded **with** correction; the same session overflows **without** it | `jitter::tests::a_two_hour_run_at_fifty_ppm_stays_bounded_with_drift_correction`, `an_hour_at_minus_fifty_ppm_stays_bounded_with_drift_correction`, `without_drift_correction_a_fifty_ppm_session_overflows_eventually` | PASS | 2026-08-07 |
| Property tests: random arrival order never delivers out of order or twice; the window never exceeds its configured bound | `jitter::tests::random_arrival_orders_never_deliver_out_of_order_or_twice`, `the_window_is_bounded_under_any_arrival_pattern` (proptest) | PASS | 2026-08-07 |

### Host capture and encode (`host/src/audio_capture.rs`, `host/src/audio_encoder.rs`)

| Feature | How tested | Result | Date |
|---|---|---|---|
| `classify_mix_format` accepts the four supported (rate, channels) combinations and refuses everything else (5.1, 96 kHz, 24-bit, malformed extensible headers) by hand-built `WAVEFORMATEX`/`WAVEFORMATEXTENSIBLE` fixtures — no real device needed | `audio_capture::tests::classifies_*`, `refuses_*` (headless) | PASS | 2026-08-07 |
| f32→i16 conversion clamps out-of-range samples, survives NaN/infinity, rounds rather than truncates | `audio_capture::tests::f32_to_i16_*` | PASS | 2026-08-07 |
| `AudioSpecificConfig` bytes pinned for all 4 formats and independently re-derived bit-for-bit | `audio_encoder::tests::asc_*`, `asc_decodes_back_to_its_fields`, `asc_distinguishes_all_four_formats` | PASS | 2026-08-07 |
| AAC output-type selection picks the lowest documented offer at/above target, falls back to the highest offer rather than refusing, ignores offers with no declared bitrate | `audio_encoder::tests::output_type_*` | PASS | 2026-08-07 |
| Real WASAPI loopback capture and real MF AAC-LC encode against actual audio hardware | Ohio host, live session. Log: `AAC-LC encoder ready (48000 Hz stereo, 96 kbps) asc="11 90"` then `system audio streaming: WASAPI loopback — 48000 Hz stereo (F32), silent keep-alive on / MF AAC-LC — 48000 Hz stereo at 96 kbps`. The `(F32)` confirms the mandatory float→i16 conversion is on the live path, and `silent keep-alive on` confirms the idle-loopback counterweight is running | **PASS** | 2026-08-07 |

### Client decode and render (`client/src/audio_decoder.rs`, `client/src/audio_render.rs`)

| Feature | How tested | Result | Date |
|---|---|---|---|
| `AudioSpecificConfig` and `HEAACWAVEINFO` tail bytes pinned and independently re-derived (must agree byte-for-byte with the host's encoder-side pins) | `audio_decoder::tests::audio_specific_config_matches_the_pinned_bytes`, `heaac_tail_layout_is_pinned`, `user_data_is_the_tail_then_the_config` | PASS | 2026-08-07 |
| `NullAudioDecoder` / `RecordingSink` test doubles enforce the same whole-frame and admission rules as the real MFT/WASAPI paths | `audio_decoder::tests::null_audio_decoder_*`, `audio_render::tests::recording_sink_*`, `writable_frames_never_exceeds_the_space_or_the_offer` | PASS | 2026-08-07 |
| Real MF AAC-LC decode and real WASAPI shared-mode render against actual audio hardware | Philippines client, live session. Log: `Media Foundation AAC-LC decoder ready: 48000 Hz, 2 ch` and `WASAPI render open: 48000 Hz 2 ch, buffer 19200 frames (400 ms), endpoint mix 48000 Hz 2 ch 32-bit`. The decoder accepted the host's runtime `asc="11 90"`, so the pinned constant, both independent derivations and real Media Foundation all agree | **PASS** | 2026-08-07 |

### Host send path and playback loop, end to end with test doubles (`host/src/net/audio.rs`, `client/src/pipeline.rs`)

| Feature | How tested | Result | Date |
|---|---|---|---|
| Capture-format → wire-format mapping is total and injective across the 4 supported formats | `net::audio::tests::every_capture_format_maps_to_a_wire_format`, `the_mapping_is_injective` | PASS | 2026-08-07 |
| Access-unit timestamps derived from the sample clock, not wall clock; strictly increasing; correct at both 48 kHz and 44.1 kHz; wrap cleanly rather than panic | `net::audio::tests::capture_ms_*`, `access_units_advance_one_aac_frame_at_a_time` | PASS | 2026-08-07 |
| Audio yields its entire backpressure reserve to video — never takes the last of the datagram send buffer even when its own packet would fit | `net::audio::tests::audio_yields_the_whole_reserve_to_video`, `the_room_check_cannot_overflow_into_permission` | PASS | 2026-08-07 |
| Headless playback loop: an access unit flows jitter buffer → AAC decoder → PCM sink end to end with `NullAudioDecoder`/`RecordingSink` | `pipeline::tests::an_access_unit_flows_from_the_jitter_buffer_through_the_decoder_into_the_sink` (and neighboring cases in the same module) | PASS | 2026-08-07 |
| Feature negotiation: client requests `SYSTEM_AUDIO` by default (cost-free ask); host offers it only when both configured and requested; shipped host default keeps the intersection empty | `client::net::tests` (StreamCaps/offer cases around `SYSTEM_AUDIO`), `host::net` `NetConfig::system_audio_enabled` wiring | PASS | 2026-08-07 |

### Real end-to-end over a live QUIC session, test tone in / recording sink out (`host/tests/audio_interop.rs`)

Real `DirectDeskHost` ↔ real `DirectDeskClient`, real MF AAC-LC encode on the
host, real transport sharing the video datagram path, real jitter buffer —
capture source is a synthetic tone (`TestTone`), not a real WASAPI loopback
endpoint. 4 scenarios, 0 failed.

| Feature | How tested | Result | Date |
|---|---|---|---|
| Both ends enabled: audio negotiates and streams decodable AAC access units over a live session | `audio_interop.rs::both_ends_enabled_deliver_decodable_audio` | PASS — 4/4 scenarios in the file | 2026-08-07 |
| Audio costs video nothing: zero incomplete/stale/rejected frames in the window audio is streaming | same run, `--nocapture`: `frames_dropped_incomplete: 0`, `frames_dropped_stale: 0`, `fragments_rejected: 0` while 238 audio datagrams (of 845 total) flowed | PASS | 2026-08-07 |
| The audio-yields-to-video precheck does not starve audio | same run: `audio_backpressured=0` while 449 audio packets were sent | PASS | 2026-08-07 |
| `AudioSpecificConfig` agrees three ways — pinned constant, two independent derivations (host encoder, client decoder), and the live encoder's own runtime log | same run: encoder log reports `asc="11 90"` for 48 kHz stereo, matching the pinned/derived value | PASS | 2026-08-07 |

### Not yet verified — needs real hardware, a real link, or both

| Feature | How tested | Result | Date |
|---|---|---|---|
| End-to-end: real host captures real system audio, real client plays it audibly | Philippines ↔ Ohio, real WAN (258 ms RTT, direct), both ends on real hardware. Operator confirmed the audio is audible and good. Host: `audio_status=Streaming audio_packets=3550 audio_kbytes=923`. **`audio_backpressured=0`** — the audio-yields-to-video reserve never starved audio on a real link, which loopback could not establish. **`audio_silent_suppressed=4376`** against 3550 sent, so a quiet desktop genuinely costs nothing. Video unaffected: host `backpressured=0`, adaptor climbing normally (`overrun 0.0%: encoder 3796, link carried 5021, video offered 4729`) | **PASS** | 2026-08-07 |
| A 5.1 or 96 kHz playback endpoint on a real host: session runs with no audio, rest of the session (video/input) unaffected | real hardware with a non-standard default endpoint | NOT RUN | — |
| Redundancy mode (`system_audio_redundancy`) measurably reduces audible loss on a lossy real or netsim link | netsim or real lossy link | NOT RUN | — |
| Secure desktop / lock screen mutes audio within one status interval, unmutes on return | interactive session with a real UAC prompt or lock screen | NOT RUN | — |
| A/V sync skew (predicted ~95 ms) measured on the real Philippines↔Ohio link | real WAN session with a timestamped source | NOT RUN | — |
| Clock-drift correction observed on a real multi-hour session (as opposed to the synthetic-clock unit tests above) | real multi-hour session, both ends | NOT RUN | — |

### Staged rollout (mirrors the tiles rollout above)

Not started. The code is committed and the gate is green, but nothing has been
deployed to the remote host. Recorded here so the plan is on paper before step 1
happens, the same way the tiles rollout was.

| Step | What it means | Result | Date |
|---|---|---|---|
| Step 1: ship the code inert | Deploy with `system_audio_enabled: false`. The host never offers `features::SYSTEM_AUDIO` (`host/src/net.rs`), so the negotiated intersection with any client — old or new — is empty, no audio thread spawns, and no audio datagram is ever sent; the deployed build's on-wire behavior for video/control is unchanged. This is the same property the tiles rollout's step 1 established for `lossless_tiles_enabled: false`. | NOT RUN | — |
| Step 2: flip the flag on the remote host | Set `system_audio_enabled: true` on the Ohio host and confirm audio negotiates and streams over the real link, the way tiles' step-2-equivalent activation was confirmed on 2026-08-07. | **DONE** — host binary `A1F7A8E980910071` deployed, `system_audio_enabled: true` written BOM-free and reparsed, client logged `host accepted system audio`, audio streamed and was audible | 2026-08-07 |
