# Troubleshooting

## Where logs live

Every DirectDesk executable calls `shared::logging::init(component, ...)`
as the first thing in `main()`, writing a daily-rotated log file to:

```
%LOCALAPPDATA%\DirectDesk\logs\<component>.<YYYY-MM-DD>.log
```

i.e. typically `C:\Users\<you>\AppData\Local\DirectDesk\logs\host.2026-08-04.log`,
`client.2026-08-04.log`, or `service.2026-08-04.log`. Console output mirrors
the same content while the app is running in a visible window.

Default verbosity is `info` (with noisy third-party crates — `quinn`,
`rustls`, `wgpu_core`, `wgpu_hal` — turned down to `warn`). To get more
detail for a specific troubleshooting session, set the `DIRECTDESK_LOG`
environment variable before launching (standard `tracing_subscriber`
`EnvFilter` syntax), e.g.:

```powershell
$env:DIRECTDESK_LOG="debug,directdesk_shared=trace"
& "C:\Program Files\DirectDesk\DirectDeskHost.exe"
```

Panics are also logged (a panic hook installs itself in `logging::init`) —
if an executable disappeared without an obvious error dialog, check the log
for a `panic:` line before assuming it's a silent network issue.

## The host won't start / fails to bind

**Symptom**: `DirectDeskHost.exe` exits immediately, or logs a bind
failure on UDP 47990 or TCP 47991.

1. **Check for the Sunshine/GameStream port collision first.** Port 47990
   sits inside Sunshine/GameStream's reserved range (47984–48010). If
   Sunshine, Moonlight's host component, or NVIDIA GameStream is installed
   and running, it likely already owns 47990. Identify the culprit:
   ```powershell
   Get-NetTCPConnection -LocalPort 47991 -ErrorAction SilentlyContinue | Select-Object OwningProcess
   Get-NetUDPEndpoint -LocalPort 47990 -ErrorAction SilentlyContinue | Select-Object OwningProcess
   Get-Process -Id <OwningProcess printed above>
   ```
   If that resolves to `sunshine.exe` (or similar), either stop that
   service (`Stop-Service sunshine` or via Services.msc) or reconfigure
   DirectDesk to use a different port pair outside 47984–48010 on both
   host and client (see [NETWORK_SETUP.md](NETWORK_SETUP.md)).
2. **Check for a leftover DirectDesk process.** A previous host instance
   that didn't exit cleanly can hold the port:
   ```powershell
   Get-Process DirectDeskHost -ErrorAction SilentlyContinue
   ```
   Kill it and retry.
3. **Check Windows Firewall isn't the reason the bind itself fails** —
   firewall rules affect inbound *reachability*, not whether the local
   `bind()` succeeds, so a firewall issue shows up differently (host starts
   fine, but the client can't reach it — see the next section). A bind
   failure is a *local* port ownership problem, not a firewall problem.

## Client can't connect (host starts fine, port isn't in use by something else)

Work through these roughly in order of likelihood for the
Philippines-client → Ohio-host deployment:

1. **Windows Firewall on the host.** Confirm the inbound allow rules exist:
   ```powershell
   Get-NetFirewallRule -DisplayGroup "DirectDesk" | Format-Table DisplayName,Direction,Action,Enabled
   ```
   If missing, either let the installer's autostart option create them (it
   runs the service's `EnsureFirewallRules` op) or add them manually — see
   [SPECTRUM_PORT_FORWARDING.md](SPECTRUM_PORT_FORWARDING.md) step 3.
2. **Router port forwarding.** Verify both rules exist and point at the
   host's *current* LAN IP (not a stale one from before a DHCP reservation
   was set) — see [SPECTRUM_PORT_FORWARDING.md](SPECTRUM_PORT_FORWARDING.md).
3. **CGNAT on the host's WAN.** If the host's router WAN IP doesn't match
   what `whatismyip.com` reports from the host's own network, you're behind
   CGNAT and no forward can work — see the CGNAT section of
   [NETWORK_SETUP.md](NETWORK_SETUP.md) and step 0 of
   [SPECTRUM_PORT_FORWARDING.md](SPECTRUM_PORT_FORWARDING.md).
4. **UDP is blocked somewhere on the client's network** (hotel/hospitality
   Wi-Fi is the classic case). DirectDesk should fall back to Direct TCP
   (47991) automatically — if the client's route label ends up on "Direct
   TCP" that's expected and fine on such a network; if *both* UDP and TCP
   fail, the network is likely blocking non-standard ports entirely (some
   very locked-down guest Wi-Fi only allows 80/443).
5. **Wrong host address or stale DDNS.** If using a dynamic DNS hostname,
   confirm it currently resolves to the host's actual current public IP.
6. **Pairing code expired or already used.** Codes are single-use and
   120-second-lived by design — generate a fresh one on the host if the
   client is retrying with an old one.
7. **Route stuck on "Relayed" or a route report you don't expect.** There
   is no relay server in this MVP — if you ever see a "Relayed" label,
   something is misconfigured or you're looking at stale UI state; direct
   connectivity is the only real path right now.

## Secure desktop / UAC limitation

**Symptom**: the client shows a black or frozen screen the moment a UAC
elevation prompt appears on the host, a Ctrl+Alt+Del screen shows, or the
host locks (Win+L).

This is an inherent Windows limitation, not a DirectDesk bug:  Windows
renders UAC consent prompts, the Ctrl+Alt+Del screen, and the lock screen
on a separate, isolated **secure desktop**, which ordinary user-mode screen
capture (and DirectDesk's capture path is user-mode, running as the
logged-in user) cannot see into or inject input into. This is a deliberate
Windows security boundary that exists precisely to stop exactly the kind of
software DirectDesk is (remote screen/input tools) from being able to
intercept credential entry or silently approve elevation prompts.

DirectDesk detects this transition and reports it honestly rather than
showing a stale or black frame with no explanation — watch for
`ControlMsg::SecureDesktopActive(true)` in the logs / the client UI's
status indicator. What this means practically:

- You cannot approve a UAC prompt on the host remotely through DirectDesk.
  Either have the prompt avoided in advance (disable UAC prompting for
  specific trusted tasks, or run the action already-elevated), or use the
  out-of-band hardware KVM fallback (PiKVM/TinyPilot — see
  [NETWORK_SETUP.md](NETWORK_SETUP.md)) to click through it.
- If the host machine **locks** (idle timeout or Win+L), the same
  limitation applies to the actual Windows lock screen credential entry —
  DirectDesk running as a service *could* in principle unlock a session in
  future work, but that is not implemented in this MVP. Plan around this
  (disable lock-on-idle on a host you intend to leave remotely accessible,
  understanding the physical-security tradeoff that implies) or use the
  out-of-band fallback.

## Black screen cases (not secure-desktop related)

If the client shows black but the host is not on a secure desktop:

1. Check the host log for capture errors (`capture:` prefixed errors from
   `shared::error::Error::Capture`) — Desktop Duplication can fail
   transiently on a display mode change (resolution change, monitor
   sleep/wake, GPU driver reset) and should recover on its own; a
   *persistent* black screen after such an event suggests the capture path
   didn't reinitialize — restart `DirectDeskHost.exe`.
2. Confirm the host isn't rendering to a display that's actually powered
   off/disconnected (e.g. RDP'd in over a *different* tool that changed the
   active display configuration, or a monitor put to sleep by Windows power
   settings) — DirectDesk MVP is single-monitor and captures a specific
   adapter/output; if that output goes away, capture has nothing to read.
3. Check for a `Encoder`/`Decoder` error in the logs — a hardware encoder
   MFT can occasionally fail to initialize (driver issue) and should fall
   back to software; a stuck black screen with encoder errors in the log
   points at a GPU driver problem worth updating.
4. As a blunt diagnostic, request a fresh keyframe from the client UI (or
   restart the connection) — `ControlMsg::RequestKeyframe` — a corrupted
   decoder state after packet loss self-heals on the next IDR frame in
   normal operation, so if a manual keyframe request doesn't fix a black
   frame, the problem is upstream of decode (capture/encode/network), not
   the decoder.

## High latency checklist

Expected baseline for the reference deployment (Philippines client ↔ Ohio
host) is roughly **150–300ms RTT** — this is consumer, cross-Pacific,
residential-Internet reality, not a bug. If you're seeing meaningfully
worse than that, or the *experience* feels far worse than the RTT number
alone would suggest, work through:

1. **Confirm the actual route.** "Direct TCP" instead of "Direct UDP" adds
   TCP's head-of-line blocking on any loss, which feels much worse than the
   same RTT over QUIC/UDP under real-world loss — check the route label
   first, always.
2. **Check the live stats.** `ControlMsg::Stats` (`ConnStats`) carries
   `rtt_ms`, `jitter_ms`, `loss`, `bandwidth_kbps`, per-stage FPS
   (`fps_capture`/`fps_encode`/`fps_decode`/`fps_present`), and
   `pipeline_ms` (capture→send on host, receive→present on client). High
   `loss` (above a couple percent) or high `jitter_ms` relative to `rtt_ms`
   points at network quality, not DirectDesk's pipeline.
3. **Check quality mode.** If you're on "Motion" or default "Balanced" over
   a genuinely constrained link, switch to "Low bandwidth" — the adaptive
   bitrate controller (`shared::adapt::BitrateAdaptor`) will already be
   backing off on sustained loss/RTT inflation, but starting from a lower
   ceiling avoids the overshoot-then-recover cycle entirely.
4. **Compare `pipeline_ms` against `rtt_ms`.** If `pipeline_ms` (local
   capture/encode or decode/present time) is a significant fraction of the
   total perceived latency, that's a local host/client performance issue
   (encoder falling back to software, GPU contention, CPU-bound decode) —
   check which encoder actually got selected (`Encoder::describe()`, logged
   at startup) rather than assuming hardware encode is active.
5. **Rule out Wi-Fi on either end.** Prefer Ethernet on the host always;
   Wi-Fi jitter on either side shows up directly in `jitter_ms` and can
   dominate a link that otherwise has a fine base RTT.
6. **Don't fight physics.** 150–300ms RTT for a genuinely trans-Pacific
   consumer path is close to the practical floor; DirectDesk's low-latency
   design targets minimizing the *added* latency on top of that RTT
   (encode/decode/pipeline overhead), not eliminating the RTT itself.

## Quick reference: log file locations

| Component | Log path |
|---|---|
| Host | `%LOCALAPPDATA%\DirectDesk\logs\host.<date>.log` |
| Client | `%LOCALAPPDATA%\DirectDesk\logs\client.<date>.log` |
| Service | `%LOCALAPPDATA%\DirectDesk\logs\service.<date>.log` (note: this is the *service account's* `%LOCALAPPDATA%`, i.e. under the `LocalSystem`/service profile, not your own user profile, since the service normally runs as a system account — check `C:\Windows\System32\config\systemprofile\AppData\Local\DirectDesk\logs\` if you don't find it under your own user) |
