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

## Kill switch — the non-obvious required setting

Rule ordering alone is NOT enough. Field state had the correct rules already:
`pass … route-to (PIA gw) from <src> to any`, immediately followed by
`block drop quick from <src> to any`. **But it leaked**, because the global
**`<skiprulewhengwdown>`** (System → Settings → Advanced → "Skip rules when
gateway is down") was OFF. With it off, when the PIA gateway goes down OPNsense
*strips the route-to* and the pass rule becomes a plain pass → traffic exits the
**WAN** (deanonymizing leak) and the block-below is never reached. The plugin
MUST ensure `skiprulewhengwdown=1` whenever it manages a VPN kill-switch, then
`configctl filter reload`. Verify with `pfctl -sr` that the `route-to` pass is
immediately followed by the `block drop quick` for the same source.

## Field implementation as of 2026-07-21 (what the plugin should absorb)

Interim hand-built pieces now live on the firewall (to be replaced by the
plugin's typed logic):
- **`/conf/pia-failover.py`** — companion to the existing `piawireguard monitor`
  configd cron (`*/5`). Runs at `3-59/5` (offset). Two jobs: (1) sync the
  forwarded-port alias to the live PF port every cycle (works around the broken
  `setItem`); (2) region-flip fallback — after 3 consecutive stale-handshake
  cycles, toggle `regionId` `ca`↔`nl_amsterdam` and `--changeserver`. State in
  `/tmp/pia_failover_state.json`. Logs best-effort to `/conf/pia-failover.log`
  (NOT `/var/log` — see RAM-disk note). Wired via configd action
  `actions_piafailover.conf` + a `<cron>` job in config.xml.
- **`skiprulewhengwdown=1`** enabled (kill-switch enabler, above).

### `/var/log` RAM-disk caveat

OPNsense "Use RAM disks" mounts a **tmpfs over `/var/log`** (observed 2.5G).
Heavy filter + `flowd.log` (NetFlow) logging — amplified by torrent traffic —
filled it to 100%, which breaks logging system-wide and makes any tool that
writes under `/var/log` crash with `ENOSPC`. The plugin's own logging must NOT
depend on `/var/log`; log to a persistent path or syslog. Operationally the box
also needs flow/filter log retention trimmed (or a larger RAM disk) so it does
not refill.

### Gateway far-VIP drift

The PIA gateway's `<gateway>` far-VIP (e.g. `10.20.128.1`) is server-specific
and changes on every server rotation, yet route-to still works via the WG iface
even when the value is stale (point-to-point). The plugin should re-sync the
gateway `<gateway>` to the live `server_vip` on each reprovision (config.xml +
`configctl interface routes configure`) so gateway state stays coherent.

## Field artifacts inventory (what is live on the firewall today)

The interim hand-built solution the plugin must absorb and then replace:

| Artifact | Location (OPNsense) | Purpose |
|---|---|---|
| `PIAWireguard.py` + `PIAWireguard.json` | `/conf/` | 3rd-party: region/server provisioning, in-region rotation. `regionId` currently `ca` (Montreal). Cron `piawireguard monitor` `*/5`. |
| `pia-failover.py` | `/conf/` | Our companion: PF-alias sync + `configctl filter reload` on port change + region-flip `ca`↔`nl_amsterdam` after 3 stale cycles. Cron `piafailover run` `3-59/5`. Logs `/conf/pia-failover.log`. |
| configd action | `actions.d/actions_piafailover.conf` | exposes `piafailover run`. |
| Forwarded-port alias | firewall alias `pia_vancouver_port` (port type) | holds live PIA PF port; kept in sync by `pia-failover.py`. |
| Source alias | firewall alias `vpn_hosts_sweden` = `[10.10.10.15]` | hosts policy-routed via PIA (freyr). |
| Policy-route pass | filter rule, LAN, src `vpn_hosts_sweden` → any, gw `GW_PIA_VANCOUVER` | forces freyr out PIA. |
| Kill-switch block | filter rule directly below, block quick, src `vpn_hosts_sweden` → any | drops freyr if PIA down (requires `skiprulewhengwdown=1`). |
| Inbound port-forward | NAT rdr on `opt4` (WG), dst `opt4ip`:`pia_vancouver_port` → `10.10.10.15:6881` | incoming torrent peers reach qBittorrent. |
| Global setting | `<system><skiprulewhengwdown>1` | makes the kill-switch actually engage. |
| Live gateway/iface | `GW_PIA_VANCOUVER` = `opt4` = `wg4` | the one live tunnel (Montreal). |
| Stale to prune | `GW_PIA_SWEDEN` (opt3), `GW_PIA_USWEST` (opt5) + `*sweden*` naming | migration remnants. |

## Integration checklist (move the above into plugin code)

`configure` (idempotent, driven by a typed PIA-VPN config block):
- [ ] **Region/server**: set PIA region (validate id against the live server
  list), provision the WG instance/peer via OPNsense API, MTU 1420.
- [ ] **Forwarded port**: acquire PIA PF signature/bindPort bound to the tunnel;
  write `pia_vancouver_port` alias via `/api/firewall/alias*` (https, self-signed
  cert) + `alias/reconfigure` + **`filter reload`** (port aliases are macros).
- [ ] **Inbound rdr**: NAT port-forward on the WG interface, dst `<wgif>ip`:PF-port
  → `<torrent_host>:<listen_port>`, tcp/udp, `associated-rule-id: pass`.
- [ ] **Kill switch**: ensure the pass-via-gw rule + block-below pair AND set
  `skiprulewhengwdown=1`; verify with `pfctl`.
- [ ] **Failover (Option B)**: handshake-age check on the real WG iface; on
  persistent stale, rotate in-region then flip region; re-sync gateway far-VIP
  to `server_vip` on reprovision.
- [ ] **Cleanup/converge**: prune stale gateways, converge naming to live region.
- [ ] Own the `*/5` cadence (replace the two cron/configd shims).

`status`:
- [ ] handshake age, region/server + `server_ip`, PF port, alias-vs-live match,
  rdr present, kill-switch present + `skiprulewhengwdown`, last remediation,
  `/var/log` RAM-disk headroom.

Design references: this doc + the interim scripts in `/conf/` on the firewall
are the source-of-truth for behavior to port.

## `status` should surface

tunnel handshake age, current region/server + `server_ip`, PIA forwarded port,
whether the inbound NAT + alias match the live port, kill-switch rule presence,
and last watchdog remediation.
