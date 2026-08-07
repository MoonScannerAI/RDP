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
