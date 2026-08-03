# Limitations (MVP honesty)

DirectDesk is being built incrementally (milestones M0–M8; see
[TEST_REPORT.md](TEST_REPORT.md)). This document is a single, current,
honest list of what is **not** done yet, what's a stub, and what has not
been validated — so nobody relies on this for something it can't actually
do. If something you need is listed here as missing, it's missing; it is
not "probably fine, just untested."

## Protocol-level stubs (real enum variants, no working implementation)

- **UDP hole punching** (`TransportRoute::UdpHolePunched`) is a defined
  route in the protocol and route-priority list, but there is **no
  implementation behind it**. It is never actually attempted. NAT traversal
  in this MVP works only via explicit port forwarding, direct public
  addressing, or the TCP fallback — not via hole punching. See
  [NETWORK_SETUP.md](NETWORK_SETUP.md).
- **Relay** (`TransportRoute::Relayed`) is a defined route and a real,
  honestly-labeled UI state, but **no relay server exists anywhere in this
  deployment**. If direct connectivity (including the TCP fallback) fails,
  the connection fails — it does not silently fall back to a relay that
  isn't there, and it will never mislabel a relayed hop as direct (that's
  a design invariant, not just a current-state fact — see
  `TransportRoute::is_direct()` and its test in `shared/src/stats.rs`).

## Features not implemented at all in this MVP

- **No audio.** Screen + input only. No system audio capture/playback,
  no microphone passthrough.
- **No file transfer.** There is no mechanism to move files between host
  and client through DirectDesk. Use a separate tool (e.g. a cloud drive,
  SMB share, or `scp`) alongside DirectDesk for file movement.
- **Clipboard is text-only.** `ControlMsg::ClipboardText(String)` exists
  and is capped at `MAX_CLIPBOARD_BYTES` (1 MiB); images, files, and rich
  formats on the clipboard are not synchronized — only plain text.
- **Single monitor.** The MVP captures and streams one display/adapter
  output. Multi-monitor host setups are not selectable or spanned; whichever
  single display is configured is what you get.
- **No relay, no hole punch** — repeated here deliberately since it's the
  single most consequential gap for a WAN deployment behind restrictive
  NAT: see above.
- **No BIOS/firmware-level access.** DirectDesk is OS-resident software; if
  the host OS won't boot or the network stack is down, DirectDesk cannot
  help — that's what the PiKVM/TinyPilot out-of-band hardware fallback is
  for (see [NETWORK_SETUP.md](NETWORK_SETUP.md)).
- **No remote unlock of a locked/secure-desktop session** in this MVP — see
  the secure desktop / UAC limitation in
  [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## Trust and distribution

- **Binaries are unsigned.** No code-signing certificate is used for
  `DirectDeskHost.exe`, `DirectDeskClient.exe`, or `DirectDeskService.exe`
  in this build. Expect a Windows SmartScreen "unrecognized publisher"
  warning on first run of each executable on each machine, and possibly
  more aggressive antivirus scrutiny than a signed binary would get (an
  unsigned exe that captures screens and injects input is exactly the
  shape of a lot of real malware, so this reaction from AV/SmartScreen is
  expected, not a bug in DirectDesk). See [SECURITY.md](SECURITY.md) for
  the fuller trust discussion.

## Validation status

- **Built and unit-tested on a local dev machine.** As of M0, the 19
  `directdesk-shared` unit tests pass and the workspace builds cleanly.
  See [TEST_REPORT.md](TEST_REPORT.md) for the milestone-by-milestone
  breakdown as later milestones land.
- **Not yet validated end-to-end over the real target WAN path**
  (Philippines client ↔ Ohio host over Spectrum residential Internet,
  ~150–300ms RTT). Everything in [NETWORK_SETUP.md](NETWORK_SETUP.md) and
  [SPECTRUM_PORT_FORWARDING.md](SPECTRUM_PORT_FORWARDING.md) is written
  from the documented design and standard networking facts, not from a
  confirmed live session across that specific link — treat the WAN
  behavior sections as "should work, not yet proven" until a milestone
  test entry says otherwise.
- **Not tested against Sunshine/GameStream actually running concurrently**
  — the port-collision risk (47990 inside 47984–48010) is a documented,
  structural fact about the port ranges, not something confirmed by a
  reproduced bind failure in this environment yet.
- **No third-party security review.** The crypto design (SPAKE2 + Ed25519 +
  TLS-exporter binding + SPKI pinning) is described in
  [SECURITY.md](SECURITY.md) as-designed; it has not been independently
  audited.

## What "MVP" means here

Every item above is a scope decision for the current milestone set, not a
promise of "coming very soon" for all of them — hole punching and relay in
particular are meaningful engineering efforts on their own and may or may
not land in a future milestone. Don't plan a deployment around a feature
listed here as missing.
