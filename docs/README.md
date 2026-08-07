# DirectDesk

DirectDesk is a purpose-built, secure, low-latency remote desktop system for
Windows, written in Rust. It exists to remotely administer machines **you
own** — for example, a client laptop in the Philippines controlling a host
laptop in Ohio over the open Internet. It is not a general-purpose commercial
RDP replacement, and it is not trying to be Chrome Remote Desktop or
AnyDesk. It is small, auditable, and honest about what it does.

DirectDesk ships as three executables built from one Cargo workspace:

| Executable | Role |
|---|---|
| `DirectDeskHost.exe` | Runs on the machine being controlled. Captures the desktop, encodes H.264, streams it, injects remote input. |
| `DirectDeskClient.exe` | Runs on the machine you're sitting at. Connects, decodes, displays, sends input. |
| `DirectDeskService.exe` | Optional Windows service. Owns a fixed, zero-parameter menu of privileged operations (firewall rules, autostart) so the host itself never needs to run elevated. |

## Design principles (non-negotiable)

- **Nothing hidden.** While DirectDeskHost is streaming your desktop, a tray
  icon is mandatory and always visible. There is no "stealth mode."
- **No disguised processes.** The three executables are named exactly what
  they are. Nothing masquerades as a system process.
- **No hidden persistence.** Autostart, if enabled, is a normal HKCU `Run`
  key entry literally named "DirectDesk Host" and/or a normal Windows
  service — both visible in Task Manager / Services / Autoruns, both removed
  cleanly by the uninstaller.
- **The service can't be turned into a remote shell.** `DirectDeskService.exe`
  exposes only a fixed set of zero-parameter operations over an ACL'd named
  pipe (`\\.\pipe\DirectDeskSvc`): `Ping`, `GetStatus`,
  `EnsureFirewallRules`, `RemoveFirewallRules`, `RestartHostRequested`. It
  never accepts a command line, a path, or script text from a client. See
  [SECURITY.md](SECURITY.md).
- **Routes are labeled truthfully.** The UI will tell you exactly which
  transport path is active (e.g. "Direct UDP" vs "Relayed") and a relayed
  connection is never shown as direct. See [NETWORK_SETUP.md](NETWORK_SETUP.md).

## How a connection is made

1. **Transport**: QUIC over UDP is primary (default port **47990**, UDP),
   with a TCP+TLS fallback (default port **47991**, TCP) for networks that
   block UDP outright (e.g. some hotel/hospitality Wi-Fi). Both ports are
   configurable.
2. **Route selection**, attempted in priority order:
   1. Direct QUIC over IPv4
   2. Direct QUIC over IPv6
   3. UDP hole punch (**stub in this MVP — not implemented, always falls
      through**)
   4. Direct TCP (TLS fallback)
   5. Relay (**stub in this MVP — no relay server exists**; if every direct
      path fails, the connection simply fails rather than silently claiming
      success)
3. **Pairing**: a fresh 8-digit numeric code, valid for 120 seconds and
   single-use, is generated on the host and entered on the client. It runs
   through SPAKE2 (a password-authenticated key exchange) bound to the live
   TLS channel via exporter keying material, so the pairing code cannot be
   replayed against a different connection or MITM'd by a network attacker.
4. **Identity**: after pairing, each side has an Ed25519 keypair. The host's
   TLS certificate public key is pinned by SPKI-SHA256 so re-connection
   doesn't require re-pairing but also can't be silently swapped out.
5. **Storage**: the paired secrets are stored via Windows DPAPI — machine
   scope on the host (so the service/host can use them without a logged-in
   user), user scope on the client.

See [SECURITY.md](SECURITY.md) for the full threat model and
[NETWORK_SETUP.md](NETWORK_SETUP.md) for routing and firewall detail.

## Video and input

- Codec: H.264, chosen for low-latency hardware encode/decode support via
  Media Foundation.
- Encoder selection: the Media Foundation hardware H.264 encoder is chosen
  per the active GPU adapter's LUID — NVENC, Quick Sync (QSV), or AMF,
  falling back to a software encoder if no hardware MFT is available. The
  actually-selected encoder is reported in the UI/logs (e.g. "MF HW H.264
  (NVIDIA, NVENC)"), never assumed.
- Default target: 1080p30 at an 8 Mbps target bitrate, 15 Mbps ceiling for
  the default "Balanced" quality mode. Actual floor/ceiling varies by
  quality mode (see below) and adapts automatically to measured loss/RTT.
- Quality modes: **Text/Desktop** (sharp static text, lower motion budget),
  **Balanced** (default), **Motion** (video/gaming-oriented), **Low
  bandwidth** (for constrained/mobile links).
- Input: keyboard and mouse only in this MVP, using Windows scan codes
  (layout-independent) and frame-normalized coordinates so DPI/scaling
  differences between host and client never corrupt pointer position.
- Client release chord: **Ctrl+Alt+Shift+F12** immediately releases
  keyboard/mouse capture and stops sending input — a hard, unconditional
  escape hatch.

## Audio

System audio, host → client only: WASAPI loopback capture on the host,
encoded as AAC-LC via Media Foundation, carried over the same QUIC datagram
path as video. It is negotiated as a `Hello` feature bit and is **off by
default** on the host (an operator has to enable it) — a build with this
feature behaves exactly like one without it until then. There is no
microphone capture and no client → host audio path. Audio is not
synchronized to video and lags it by roughly 95 ms — fine for notification
sounds and music, noticeable on lip movement. See
[LIMITATIONS.md](LIMITATIONS.md) for the full breakdown: format restrictions,
the codec tradeoff, loss handling, and why the lag is a scope decision
rather than a bug.

## What's real in this build vs. what's a stub

This is an honest project. Read [LIMITATIONS.md](LIMITATIONS.md) before
relying on this for anything important. In short, as of this MVP:

- UDP hole punching is a stub — only truly-direct routes and the TCP
  fallback work.
- There is no relay server. If direct connectivity fails (e.g. both ends
  behind strict NAT/CGNAT with no port forwarding), the connection fails.
  It does not silently degrade to a working-but-unlabeled path.
- System audio (host → client) exists but is off by default and not
  synchronized to video — see Audio above. No microphone / audio return
  path, no file transfer, clipboard is text-only, single monitor only.
- The executables are **not code-signed**. Windows SmartScreen will warn on
  first run. This is expected; see [SECURITY.md](SECURITY.md).
- Built and exercised on a LAN/dev machine; the primary real-world WAN path
  (Philippines client → Ohio host over Spectrum residential Internet,
  150–300ms RTT) has not yet been end-to-end validated in this milestone.
  See [TEST_REPORT.md](TEST_REPORT.md).

## Quick start (once M1+ lands host/client functionality)

1. Install DirectDesk on **both** machines (see [BUILDING.md](BUILDING.md)
   to build from source, or use the Inno Setup installer once built —
   `installer/directdesk.iss`).
2. On the host machine, run `DirectDeskHost.exe`. A tray icon appears — this
   is mandatory and confirms hosting is active. Right-click it to see/copy
   the current 8-digit pairing code.
3. If the host is behind a router (the common case for a home connection),
   forward the ports first — see
   [SPECTRUM_PORT_FORWARDING.md](SPECTRUM_PORT_FORWARDING.md) for the
   Spectrum-specific walkthrough, or [NETWORK_SETUP.md](NETWORK_SETUP.md)
   for the general case.
4. On the client machine, run `DirectDeskClient.exe`, enter the host's
   address and the pairing code. The code expires after 120 seconds and can
   only be used once.
5. Once connected, the client window shows the active route label (e.g.
   "Direct UDP") and live stats. Press **Ctrl+Alt+Shift+F12** at any time to
   release input capture.

If something doesn't connect, start with
[TROUBLESHOOTING.md](TROUBLESHOOTING.md) — it covers the most likely
failure, a port collision with Sunshine/GameStream on 47990.

## Repository layout

```
rdp/                     cargo workspace root
├── shared/               directdesk-shared: wire protocol, crypto, stats, IPC contract — the compatibility contract every exe depends on
├── host/                 DirectDeskHost.exe
├── client/                DirectDeskClient.exe
├── service/               DirectDeskService.exe
├── tests/                 integration test harness (netsim-driven)
├── docs/                  this documentation set
├── tools/                 developer scripts (check.ps1, build-installer.ps1, smoke tests)
└── installer/             Inno Setup script + manual install/uninstall PowerShell
```

## Documentation index

- [BUILDING.md](BUILDING.md) — toolchain, build commands, workspace layout
- [NETWORK_SETUP.md](NETWORK_SETUP.md) — ports, routes, CGNAT, IPv6, hotel Wi-Fi
- [SPECTRUM_PORT_FORWARDING.md](SPECTRUM_PORT_FORWARDING.md) — the exact steps for the reference deployment's router
- [SECURITY.md](SECURITY.md) — threat model, crypto design, what is and isn't protected
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — connection and quality problems, log locations
- [LIMITATIONS.md](LIMITATIONS.md) — MVP scope honesty
- [TEST_REPORT.md](TEST_REPORT.md) — milestone-by-milestone test status

## License

MIT (see `Cargo.toml` workspace metadata).
