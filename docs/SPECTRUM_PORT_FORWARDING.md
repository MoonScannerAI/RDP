# Spectrum Port Forwarding (reference deployment: Ohio host)

This walks through getting inbound connections from the DirectDesk client
(Philippines) to the DirectDesk host (Ohio laptop, on a residential
Spectrum Internet connection) working. Read
[NETWORK_SETUP.md](NETWORK_SETUP.md) first for what these ports are and why
UDP 47990 collides with Sunshine/GameStream.

Spectrum ships several different router models over time (Sagemcom,
Netgear/CODA, and their own "Advanced WiFi" panel at
`https://spectrum.net` / `http://192.168.1.1`). The exact menu wording below
may differ slightly from your unit's firmware — the concepts and settings
are the same; look for the equivalent screen.

## 0. Before you start: confirm you're not behind CGNAT

There is no point configuring a port forward if Spectrum has actually
handed your router a CGNAT address — the forward would have nothing real to
attach to. Check first:

1. On the host laptop, open a browser and go to a "what's my IP" site (e.g.
   `https://whatismyip.com` or `https://ifconfig.me`). Note the IPv4
   address shown — call this the **WAN-as-seen-from-outside** address.
2. Log into the router admin UI (see step 2 below) and find the **WAN IP**
   / **Internet IP** shown on its status page.
3. **Compare them.** If they match, you have a real public IPv4 and
   forwarding will work. If the router's WAN IP is in one of these ranges,
   you are behind CGNAT and a port forward on this router cannot work no
   matter how you configure it:
   - `100.64.0.0/10` (i.e. `100.64.0.0`–`100.127.255.255`) — the standard
     CGNAT range (RFC 6598). This is the one to watch for specifically.
   - A private range (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) on
     the WAN side (not the LAN side, where private ranges are normal) is
     also a sign of double-NAT/CGNAT.
4. If you're behind CGNAT, stop here and call Spectrum to ask about a
   "public IP" or "bridge mode" add-on, or see the CGNAT section in
   [NETWORK_SETUP.md](NETWORK_SETUP.md) for alternatives. Spectrum
   residential plans are normally public IPv4, but it's cheap to verify
   before debugging a forward for an hour.

## 1. Reserve a fixed LAN IP for the host laptop (DHCP reservation)

Port forwards target an IP address. If the host laptop's LAN IP changes
(default DHCP behavior), the forward silently stops working. Fix the
address first.

1. Find the host laptop's current LAN IP and MAC address:
   ```powershell
   ipconfig /all
   ```
   Note the **IPv4 Address** (e.g. `192.168.1.50`) and the **Physical
   Address** (MAC, e.g. `AA-BB-CC-DD-EE-FF`) of the active adapter
   (Ethernet is strongly preferred over Wi-Fi for a host machine — more
   stable, lower latency).
2. Log into the router: browse to `http://192.168.1.1` (Spectrum's default
   gateway on most of their routers) or `https://spectrum.net` if you're
   using their cloud-managed "Advanced WiFi" panel. Sign in with the
   router admin credentials (printed on the router label, or your
   Spectrum.net account if using Advanced WiFi).
3. Find **DHCP reservations** — typically under *Advanced Settings* →
   *Local Network* → *IP Address Reservation* (self-install Sagemcom/CODA
   units) or under the *Network* → *Devices* view if you're on the
   Spectrum.net "Advanced WiFi" panel (click the host laptop's device →
   "Keep this IP address" / "Reserve IP").
4. Reserve the LAN IP noted in step 1 to the MAC address noted in step 1.
   Save/apply. Some routers require a reboot for this to take effect.

## 2. Forward the ports

Still in the router admin UI:

1. Find **Port Forwarding** — typically *Advanced Settings* → *Port
   Forwarding* (self-install units) or *Network* → *Port Forwarding* on the
   Spectrum.net Advanced WiFi panel.
2. Add a rule:
   - **Service name / description**: `DirectDesk-QUIC`
   - **Protocol**: UDP
   - **External/WAN port**: `47990`
   - **Internal/LAN port**: `47990`
   - **Internal/LAN IP address**: the host laptop's reserved IP from step 1
     (e.g. `192.168.1.50`)
3. Add a second rule:
   - **Service name / description**: `DirectDesk-TCP`
   - **Protocol**: TCP
   - **External/WAN port**: `47991`
   - **Internal/LAN port**: `47991`
   - **Internal/LAN IP address**: same host laptop IP
4. Save/apply. Some Spectrum router firmware requires a reboot of the
   router (not just "apply") for new port forward rules to take effect —
   if the port test in step 5 fails, reboot the router and retest before
   troubleshooting further.

If you changed DirectDesk's configured ports because of the Sunshine/
GameStream collision (see [NETWORK_SETUP.md](NETWORK_SETUP.md)), forward
whatever ports you actually configured instead of 47990/47991.

## 3. Allow the ports through Windows Firewall on the host

DirectDeskService, if installed, can do this for you automatically —
during install, the option "Start DirectDesk automatically with Windows"
runs `DirectDeskService.exe install`, and the service's
`EnsureFirewallRules` operation creates inbound allow rules scoped to
`DirectDeskHost.exe`'s path and the configured ports (see
[SECURITY.md](SECURITY.md) for exactly what that means).

To do it manually instead (or to verify the automatic rule exists):

```powershell
# Verify (run as the installing user; requires the rule group to exist)
Get-NetFirewallRule -DisplayGroup "DirectDesk" | Format-Table DisplayName,Direction,Action,Enabled

# Manual creation if needed (run as Administrator)
New-NetFirewallRule -DisplayName "DirectDesk Host (UDP 47990)" -DisplayGroup "DirectDesk" `
  -Direction Inbound -Protocol UDP -LocalPort 47990 -Action Allow `
  -Program "C:\Program Files\DirectDesk\DirectDeskHost.exe"

New-NetFirewallRule -DisplayName "DirectDesk Host (TCP 47991)" -DisplayGroup "DirectDesk" `
  -Direction Inbound -Protocol TCP -LocalPort 47991 -Action Allow `
  -Program "C:\Program Files\DirectDesk\DirectDeskHost.exe"
```

## 4. Verify the port is actually reachable from outside

1. Start `DirectDeskHost.exe` on the host laptop so it's actually listening.
2. From an *external* network (not the same LAN — use the client machine
   on its own connection, or your phone on cellular data, or a site like
   `https://canyouseeme.org` / `https://portchecker.co` for the TCP port
   specifically — most public port checkers only test TCP, not UDP, so a
   green TCP 47991 result plus a real DirectDesk connection attempt on UDP
   47990 is the practical way to confirm both).
3. Note the **public WAN IPv4** you found in step 0 — this is the address
   the client connects to.

## 5. Optional: Dynamic DNS, if the WAN IP isn't static

Spectrum residential IPs are typically stable but not contractually static
— they can change (router reboot, DHCP lease renewal, ISP-side
maintenance). If you don't want to re-check the WAN IP every time you
connect from the Philippines:

1. Sign up for a dynamic DNS provider (e.g. DuckDNS, No-IP, Dynu — any
   provider that gives you a hostname like `yourhost.duckdns.org`).
2. Either run that provider's update client on the host laptop (as a
   scheduled task, so it re-registers your current IP periodically), or
   check whether your specific Spectrum router model has built-in DDNS
   client support (self-install Sagemcom/CODA units sometimes do, under
   *Advanced Settings* → *Dynamic DNS* — Spectrum's cloud-managed Advanced
   WiFi panel generally does not).
3. Point the DirectDesk client at the DDNS hostname instead of a raw IP.
   DirectDesk itself does not manage DNS or DDNS — this is purely a
   convenience so you don't have to re-enter an IP after it changes.

## Quick checklist

- [ ] Confirmed router WAN IP matches `whatismyip.com` (not CGNAT)
- [ ] DHCP reservation set for the host laptop's LAN IP
- [ ] Port forward: UDP 47990 → host LAN IP
- [ ] Port forward: TCP 47991 → host LAN IP
- [ ] Router rebooted if the firmware needs it for forwards to apply
- [ ] Windows Firewall allows `DirectDeskHost.exe` on both ports
- [ ] External port check confirms TCP 47991 reachable
- [ ] (Optional) Dynamic DNS hostname configured
