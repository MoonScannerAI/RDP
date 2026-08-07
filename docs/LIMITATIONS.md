# Limitations (MVP honesty)

DirectDesk is being built incrementally (milestones M0–M8; see
[TEST_REPORT.md](TEST_REPORT.md)). This document is a single, current,
honest list of what is **not** done yet, what's a stub, and what has not
been validated — so nobody relies on this for something it can't actually
do. If something you need is listed here as missing, it's missing; it is
not "probably fine, just untested."

## Protocol-level stubs (real enum variants, no working implementation)

- **TCP/TLS fallback and route racing are written but unwired.**
  `directdesk_shared::transport::{tcp, race}` are complete and unit-tested,
  but **no binary selects them** — the client's `connect_race` is QUIC-only
  by decision, so `TransportRoute::DirectTcp` is never produced and a
  UDP-blackholing network still fails outright. Turning it on is a wiring
  change behind the `transport-race` cargo feature, not new implementation
  work.
- **UDP hole punching** (`TransportRoute::UdpHolePunched`) is a defined
  route in the protocol and route-priority list, but there is **no
  implementation behind it**. It is never actually attempted. NAT traversal
  in this MVP works only via explicit port forwarding or direct public
  addressing — not via hole punching, and not via the TCP fallback while
  that stays unwired (see above). See
  [NETWORK_SETUP.md](NETWORK_SETUP.md).
- **Relay** (`TransportRoute::Relayed`) is a defined route and a real,
  honestly-labeled UI state, but **no relay server exists anywhere in this
  deployment**. If direct connectivity fails (and the TCP fallback is not
  wired up to be tried at all — see above), the connection fails — it
  does not silently fall back to a relay that
  isn't there, and it will never mislabel a relayed hop as direct (that's
  a design invariant, not just a current-state fact — see
  `TransportRoute::is_direct()` and its test in `shared/src/stats.rs`).

## Features not implemented at all in this MVP

- **No microphone, no audio return path.** The client's microphone is never
  captured and never sent to the host, in either direction beyond what's
  described below. This is deliberate, not an oversight: a remote host
  silently opening a client's microphone is a materially different feature
  from the one that exists (see "Audio" below) — it needs its own feature
  bit and a consent affordance on the client, not a reuse of the existing
  one — and neither exists in this MVP.
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

## Audio (host → client, opt-in, off by default)

System audio now exists — host capture, streamed to the client — but read
every bullet below before assuming it does what a normal remote-desktop
audio feature does.

- **Host → client only, and off by default.** Audio flows one direction:
  whatever the host machine is playing goes to the client. It is negotiated
  as a `Hello.features` bit (`features::SYSTEM_AUDIO`,
  `shared/src/protocol.rs`) and gated on the host by
  `HostConfig::system_audio_enabled`, which defaults to `false`
  (`host/src/config.rs`) — an operator has to turn it on. When it's off the
  host never offers the bit, the two ends' feature sets never intersect on
  it, and no audio thread ever spawns (`host/src/net.rs`,
  `host/src/net/serve.rs`) — a build with this feature behaves exactly like
  one without it until the operator opts in.
- **No microphone, no return path.** See above.
- **Audio and video are not synchronized, and audio lags video.** No A/V sync
  is attempted anywhere in the pipeline. Predicted skew is audio arriving
  roughly **95 ms behind video**: video's one-way latency is on the order of
  185 ms, audio's is on the order of 280 ms, and the gap is dominated by two
  numbers that are already part of this product's own design point — the
  network's ~129 ms one-way delay (half of the ~258 ms RTT this codebase is
  built and tuned around; see e.g. `host/src/audio_capture.rs`,
  `host/src/session.rs`, `host/src/mf_encoder.rs`) and the audio jitter
  buffer's 80 ms starting target depth
  (`JitterConfig::target_start_ms`, `shared/src/audio/jitter.rs`). By
  ITU-R BT.1359-1, lagging audio becomes *detectable* around 45 ms of skew
  and *unacceptable* around 125 ms — so at ~95 ms this is fine for
  notification sounds, alarms, and music/game audio, and **detectable on lip
  movement** in anything like a video call. The only correction available
  would be to delay video to match audio, which runs directly against this
  product's whole optimization target (the lowest achievable input and
  picture latency) — so this is a deliberate scope decision, not a defect.
  Do not file it as a bug; file a design discussion instead if it needs to
  change.
- **Only 48 kHz / 44.1 kHz, mono or stereo, is supported — anything else is
  refused outright, never downmixed or resampled.**
  `host::audio_capture::classify_mix_format` reads the render endpoint's real
  mix format and refuses (with a log line naming exactly what it found)
  anything outside those four combinations — a 5.1 receiver or a 96 kHz
  audio interface, for example. That session simply runs with no audio.
  Silently reinterpreting six channels as two, or 96 kHz samples as 48, was
  considered and rejected: it produces a stream at the wrong pitch and the
  wrong speed with nothing anywhere to say why, which is worse than silence
  plus a log line.
- **Codec is Media Foundation AAC-LC, not Opus.** Opus was ruled out because
  every production Rust Opus binding needs a C toolchain, which this project
  deliberately avoids elsewhere too (see the `flate2` dependency note in
  `shared/Cargo.toml`). The cost of that choice is roughly 20 ms more
  algorithmic latency than Opus would have had, and a **96 kbps floor for
  stereo** — the lowest bitrate the Windows AAC encoder documents
  (`audio_encoder::DOCUMENTED_BYTES_PER_SECOND`,
  `host/src/audio_encoder.rs`). The host config technically accepts a lower
  target, but the encoder rounds any target up to the cheapest rate it
  actually offers, so nothing streams below 96 kbps in practice.
- **No packet-loss concealment.** A lost audio packet is a silent ~21 ms hole
  (one AAC-LC frame at 48 kHz is 1024 samples ≈ 21.3 ms) — nothing conceals
  it. There is an opt-in redundancy mode (`system_audio_redundancy`, default
  `false`) that re-sends the previous packet behind every new one, at double
  the audio bitrate; it is off unless the operator turns it on.
- **Audio mutes whenever the picture freezes for the secure desktop or the
  lock screen** — a deliberate privacy choice, not a technical limitation.
  WASAPI would happily go on capturing system audio while the host's screen
  is locked; muting it is a product decision, on the reasoning that a host
  owner who has locked their machine, or been dropped onto the UAC secure
  desktop, should not have their room's audio still leaving the machine.
- **Clock drift is corrected by dropping or inserting whole 21.3 ms frames**,
  nothing subtler. A multi-hour session gets an occasional inaudible
  correction (at a typical ~50 ppm host/client crystal mismatch, roughly once
  every 7 minutes) rather than unbounded latency growth — this keeps drift
  bounded, it does not eliminate it, and it does nothing for the A/V sync gap
  described above.

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
