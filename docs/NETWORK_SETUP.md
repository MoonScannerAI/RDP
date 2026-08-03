# Network Setup

DirectDesk needs a network path from the client machine to the host
machine. This document explains the ports, the route-selection order, and
the network conditions (CGNAT, IPv6, UDP-hostile networks) that affect
which route you actually get. For the specific router walkthrough used in
the reference deployment (a Spectrum residential router in Ohio), see
[SPECTRUM_PORT_FORWARDING.md](SPECTRUM_PORT_FORWARDING.md).

## Ports

| Purpose | Default port | Protocol | Configurable |
|---|---|---|---|
| Primary transport (QUIC) | **47990** | UDP | Yes |
| Fallback transport (TLS) | **47991** | TCP | Yes |

Both are listened on by `DirectDeskHost.exe`. The client attempts the
primary UDP port first and falls back to the TCP port only if UDP
connectivity to the host doesn't work at all (see route order below) —
it is not a per-packet fallback, it's a whole-connection fallback decided
once at connect time.

### Important: the 47990 collision with Sunshine/GameStream

Port **47990** sits *inside* the reserved port range used by
[Sunshine](https://github.com/LizardByte/Sunshine)/NVIDIA GameStream
(**47984–48010 UDP/TCP**). If the host machine also runs Sunshine, Moonlight,
or has ever had NVIDIA GameStream enabled, something may already be bound
to 47990, and `DirectDeskHost.exe` will fail to bind its UDP listener.

This is a known, documented collision, not a bug you need to hunt for. Two
ways to deal with it:

1. **Change DirectDesk's port.** Set the UDP/TCP ports in DirectDesk's
   configuration to something outside 47984–48010 (e.g. 51990/51991) on
   both host and client, and update your port forward accordingly.
2. **Stop the conflicting service** (e.g. stop the Sunshine service) if you
   aren't using it concurrently with DirectDesk.

[TROUBLESHOOTING.md](TROUBLESHOOTING.md) has the exact `netstat` command to
identify what's holding the port if a bind failure happens.

## Route priority

On every connection attempt, the client races candidate paths and the
session settles on the first one that actually completes a handshake, in
this priority order:

1. **Direct QUIC over IPv4** — host's public/forwarded IPv4 address, UDP
   47990.
2. **Direct QUIC over IPv6** — if both ends have routable IPv6 (see IPv6
   notes below).
3. **UDP hole punch** — **stub in this MVP.** The code path exists in the
   protocol/route enum (`TransportRoute::UdpHolePunched`) but there is no
   implementation behind it yet; it is not attempted. Don't rely on it for
   NAT traversal without port forwarding.
4. **Direct TCP** (TLS fallback) — host's forwarded TCP 47991. Used when UDP
   is blocked or filtered end-to-end (common on hotel/hospitality/campus
   Wi-Fi that only allows TCP 80/443-style egress, or corporate proxies).
5. **Relay** — **stub in this MVP.** No relay server exists anywhere in this
   deployment. `TransportRoute::Relayed` is a real enum variant so the
   protocol and UI are ready for it, but there is nothing to connect to. If
   every route above fails, the connection fails outright — it does not
   silently claim success over a route that isn't real.

The route actually in use is reported honestly in the client UI (via
`ControlMsg::RouteReport` / `TransportRoute::label()`): "Direct UDP",
"Direct IPv6", "UDP hole punched", "Direct TCP", or "Relayed". A relayed
session is never labeled as direct, and — since there is no relay server in
this build — you should never actually see "Relayed" reported; if you do,
something is misconfigured.

## What port forwarding actually requires

For any *direct* route to work, the host's home router must forward:

- **UDP 47990** → host machine's LAN IP, port 47990
- **TCP 47991** → host machine's LAN IP, port 47991

...and the host's Windows Firewall must allow inbound on those same
ports/protocols for `DirectDeskHost.exe` (the installer offers to run
`DirectDeskService.exe EnsureFirewallRules`, which creates exe+port-scoped
rules; see [SECURITY.md](SECURITY.md) for exactly what that rule looks
like).

For the router-side steps on the reference deployment's ISP router, see
[SPECTRUM_PORT_FORWARDING.md](SPECTRUM_PORT_FORWARDING.md).

## CGNAT: why the client side usually doesn't need forwarding, but the host side must have a real public IP

**Carrier-Grade NAT (CGNAT)** is when your ISP hands your router a *private*
IP address (from `100.64.0.0/10`, or occasionally regular RFC1918 space)
instead of a real public IPv4 address, and does the NAT translation to the
real Internet somewhere inside the ISP's network instead of at your router.
When this is the case, **no port forward you configure on your own router
will ever work**, because your router was never given a public address to
forward *to* in the first place — the actual public IP lives upstream, on
equipment you don't control and can't configure.

- **The client side** (in the reference deployment: a laptop in the
  Philippines, likely behind mobile/ISP CGNAT) is fine being behind CGNAT.
  It only originates outbound connections; it never needs to accept inbound
  traffic. No forwarding is needed on the client's network.
- **The host side** (the Ohio Spectrum laptop) is the one that needs to
  *accept* an inbound connection. If the host's ISP connection is behind
  CGNAT, direct routes are not possible at all (the port forward has
  nothing real to attach to), and since this MVP has no relay server and no
  working hole punch, **there is no fallback** — you would need to either
  get a non-CGNAT plan from the ISP, use a VPN with port forwarding, or use
  the out-of-band fallback (see below).
- Spectrum residential service, at the time of writing, is normally
  public-IPv4 (not CGNAT) — but it's worth checking (see
  [SPECTRUM_PORT_FORWARDING.md](SPECTRUM_PORT_FORWARDING.md) for exactly
  how to check your WAN IP for CGNAT ranges before you spend time
  debugging a forward that can never work).

## IPv6 notes

If both the host's ISP and the client's ISP/network hand out routable
(non-CGNAT, non-link-local) IPv6 addresses, DirectDesk can connect directly
over IPv6 without any port forwarding at all — IPv6 addresses are typically
globally routable per-device, and Windows Firewall (not a NAT) is the only
gate, which the installer/service can open automatically.

Caveats:

- Many home routers still firewall inbound IPv6 by default even when the
  WAN has a routable IPv6 prefix — you may need an explicit inbound allow
  rule on the router for UDP/TCP 47990/47991 in addition to the Windows
  Firewall rule.
- IPv6 is only attempted as route priority #2, after IPv4 — it is a nice
  bonus path, not something to depend on for the primary Philippines↔Ohio
  link, since mobile/ISP IPv6 support on the client end is inconsistent.
- `ipconfig` on the host will show whether you have a genuine routable
  IPv6 address (a `2xxx:`/`3xxx:` global unicast address) versus only a
  link-local (`fe80::`) one, which is not usable for this purpose.

## UDP-blocked networks (hotel/hospitality/campus Wi-Fi)

Some networks — hotel guest Wi-Fi is the classic case, but also many
campus, airport, and corporate guest networks — only permit outbound TCP
on a small set of ports (often just 80/443) and silently drop UDP
entirely. On such a network:

- Direct QUIC (UDP 47990) will simply never complete a handshake; the
  client will time out on it.
- DirectDesk falls back to **Direct TCP** (TLS fallback, port 47991) — this
  is exactly the scenario the TCP fallback exists for.
- If the network *also* blocks non-standard TCP ports (some very locked-down
  guest networks only allow 80/443), TCP 47991 will fail too and there is no
  further fallback in this MVP (no relay). In that situation your only
  options are: get the network administrator to allow the port, use a VPN
  that tunnels arbitrary TCP, or fall back to the out-of-band access method
  below.
- The client will report which route it's using — if you see it sitting on
  "Direct TCP" instead of "Direct UDP", that's diagnostic evidence the
  network you're on is filtering UDP.

## Out-of-band fallback

DirectDesk is software running *inside* the host's OS — if the host machine
is unreachable at the OS level (network misconfigured, Windows Update
stuck, BSOD, host powered off but reachable via WoL, etc.), DirectDesk
cannot help you, by design (it isn't a BIOS-level KVM). The documented
out-of-band recovery path for the reference deployment is a **PiKVM or
TinyPilot** hardware KVM-over-IP device attached to the Ohio host laptop,
which gives BIOS-level video + keyboard/mouse access independent of the
host's OS or network stack. This is out of scope for DirectDesk itself but
is part of the overall deployment plan and is worth having before you need
it.

## UPnP

DirectDesk does **not** attempt automatic UPnP/NAT-PMP port mapping by
default — **UPnP support is off by default**. If/when enabled, it is an
explicit, opt-in action that shows you the exact mapping it's about to
request (protocol, external port, internal port, internal IP) before doing
anything, rather than silently punching holes in your router. Manual port
forwarding (see [SPECTRUM_PORT_FORWARDING.md](SPECTRUM_PORT_FORWARDING.md))
is the supported, recommended path for the reference deployment.
