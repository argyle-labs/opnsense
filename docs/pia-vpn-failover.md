# PIA WireGuard + VPN failover (plugin implementation notes)

Durable design notes for what the `opnsense` plugin must own for the PIA
WireGuard tunnel that carries a torrent host's traffic. Today this is
hand-maintained on the firewall over root SSH via the third-party
[FingerlessGloves `PIAWireguard.py`](https://github.com/FingerlessGlov3s/OPNsensePIAWireguard)
script plus ad-hoc `pia-watchdog`/`pia-refresh` shell scripts. The plugin
should replace all of it with typed `configure`/`status` logic driven by the
OPNsense API.

## Goal

A single always-configured PIA WireGuard tunnel that:
1. Routes a defined set of hosts (policy-based routing) out PIA, never leaking.
2. Uses a **fast, torrent-friendly, port-forward-capable** region (e.g. PIA
   Montreal — region id `ca`; NL `nl_amsterdam` as the fallback region).
3. Keeps its **forwarded port** wired end-to-end to the torrent client.
4. **Self-heals**: detects a dead/degraded tunnel and reprovisions (rotate
   server within region, then flip region) — **Option B, handshake-based**.

## Why NOT an OPNsense gateway group (the obvious approach) — it's broken

OPNsense **WireGuard gateways in a failover/LB gateway group do not work** —
traffic routes out the default gateway instead of the group. Closed WONT-FIX:
[opnsense/core#6981](https://github.com/opnsense/core/issues/6981); related WG
gateway-monitoring bugs [#8987–#8990](https://github.com/opnsense/core/issues/8990).
Works with OpenVPN, not WireGuard. **Do not build failover on gateway groups.**

## Why NOT dpinger ICMP monitoring of the tunnel

- **PIA servers do not answer ICMP on the tunnel VIP** (`server_vip`, e.g.
  `10.20.128.1`). A short burst may get lucky; sustained pings = 100% loss →
  dpinger marks the gateway permanently down. Verified in the field.
- A **public** monitor IP (e.g. `9.9.9.9`) routes out the **WAN**, not the
  tunnel (`route get 9.9.9.9` → WAN iface), so it validates internet, not the
  VPN. OPNsense is supposed to auto-add a `/32` monitor route via the gateway
  but for WireGuard **far-gateways this insertion is unreliable**, and enabling
  it disturbed the WAN gateway's monitor in testing.
- Net: the original firewall admin had deliberately set
  `<monitor_disable>1</monitor_disable>` — for good reason.

## Option B — handshake-based watchdog failover (the chosen design)

WireGuard's honest health signal is **latest-handshake age**, not ICMP.

1. **Health check**: every 60–120s read `wg show <iface> latest-handshakes`.
   Stale (> ~180s) ⇒ tunnel dead.  **Monitor the REAL interface** — the live
   tunnel is `wg4`, not `wg0/wg1/wg2` (the shipped `pia-watchdog` watched the
   wrong interfaces and was therefore a no-op).
2. **Remediate** on stale handshake:
   - re-register the PIA session / rotate to a fresh server in the current
     region (PIA token → addKey handshake → write new peer endpoint/pubkey +
     assigned tunnel IP);
   - after N consecutive in-region failures, **flip region** to the fallback
     (`ca` → `nl_amsterdam`) and reprovision there.
3. **Kill switch (mandatory, leak safety)** — firewall rule ordering, NOT
   gateway monitoring:
   - Pass rule: PIA-routed source hosts → gateway = PIA WG gateway.
   - **Block rule directly below** with no gateway → when the tunnel is down the
     pass rule can't match and the block rule drops the traffic. Prevents the
     deanonymizing WAN leak that a torrent box must never have.
4. Reprovision-speed failover (~1–3 min) is acceptable for this workload; it
   avoids the WG gateway-group bug and keeps a single forwarded port.

Upgrade path (only if seconds-fast failover is ever needed): two always-on
tunnels with **firewall-rule-tier** failover (pass-via-A, then pass-via-B, then
block) driven by the watchdog force-*down*ing a gateway on stale handshake —
still avoids gateway groups. Downside: two PIA connections + two forwarded
ports (client binds one → inbound degrades on failover, downloads continue).

## Port forwarding — wire it end to end (was fully broken)

PIA gives a **different forwarded port per server**, re-acquired after every
region/server change. It must reach the torrent client or inbound peer
connectivity is dead (slow swarms). The plugin must:

1. After (re)connect, run PIA's port-forward `getSignature` → `bindPort` against
   the connected server, bound to the tunnel interface.
2. Publish the port to a firewall **alias** (field-observed name
   `pia_vancouver_port`) AND create/maintain an **inbound NAT port-forward**
   mapping `WAN:<pia_port>` → `<torrent_host>:<listen_port>`. In the field the
   ONLY inbound forwards were Plex (`:32400`); there was **no** torrent
   forward at all.
3. Keep the torrent client's **listen port** in sync with the PIA forwarded
   port (or NAT `pia_port → fixed client port`, e.g. qBittorrent `6881`).

### Alias-update gotchas (OPNsense 26.1)

- `PIAWireguard.json` had `opnsenseURL: http://127.0.0.1` → OPNsense **301**
  redirects to https → every alias write silently failed → the port alias sat
  **empty**. Use `https://` and accept the self-signed cert.
- Even over https the FingerlessGloves `setItem alias` call fails on 26.1
  ("GET Request Failed non-200, Unexpected error") — its `requests` session
  verifies TLS against the self-signed cert. The plugin should call the current
  `/api/firewall/alias*` + `/api/firewall/alias_util/*` endpoints directly with
  cert handling, then `alias/reconfigure`.

## Region selection reference

Valid region ids come from
`https://serverlist.piaservers.net/vpninfo/servers/v6` (filter
`port_forward: true` for torrent PF). Notable ids: `ca` = **CA Montreal**
(NOT `ca_montreal`), `ca_toronto`, `ca_vancouver`, `nl_amsterdam` = Netherlands.
Throughput is latency-bound from the US → prefer nearest PF-capable region.

## Cleanup the plugin should reconcile

Field state is a half-finished Sweden→Vancouver→Montreal migration:
- Stale enabled gateways `GW_PIA_SWEDEN` (opt3) + `GW_PIA_USWEST` (opt5) — the
  live tunnel is `GW_PIA_VANCOUVER` (opt4/wg4), now pointed at Montreal.
- Rules/aliases still named `*sweden*` (source alias `vpn_hosts_sweden` actually
  contains just the torrent host); the far-gateway `<gateway>` VIP was a stale
  Vancouver value. The plugin should converge naming/state to the live region
  and prune dead gateways.

## `status` should surface

tunnel handshake age, current region/server + `server_ip`, PIA forwarded port,
whether the inbound NAT + alias match the live port, kill-switch rule presence,
and last watchdog remediation.
