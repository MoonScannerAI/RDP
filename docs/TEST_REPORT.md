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

**Status: implemented, headless verification green. NOT yet exercised on the
real Philippines↔Ohio link — see the staged rollout in the plan.**

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
| DXGI dirty rects are a true superset of what changed, on real hardware | `host/src/bin/capture_harness.rs --dirty` on the Ohio host | NOT RUN | |
| Cross-version against `DirectDesk-bins.zip` (old client ↔ new host, and the reverse), real QUIC, incl. pairing + reconnect | rollout step 0 | **FAIL — but pre-existing, not caused by tiles.** See below | 2026-08-07 |
| Cross-version against a **binary built from `a5a928f`** — the commit the Ohio host is believed to be running | rollout step 0, rebuilt baseline | NOT RUN — this is the pairing that actually gates the deploy | |
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

Before deploying, confirm what Ohio is actually running and re-run step 0 against
a binary built from that commit. If Ohio turns out to predate `a5a928f`, the host
and client must be upgraded **together** — upgrading the host alone would strand
it, and it is reached through this very protocol.
