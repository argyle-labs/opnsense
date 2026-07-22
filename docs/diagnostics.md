# opnsense plugin — diagnostics registry

First-class **diagnose + repair** capability for the `opnsense` plugin, in the
checks/repairs style. Each check has: detection (read-only), healthy criteria,
symptom, and a remediation the plugin's `status`/`diagnose`/`repair` performs.
Every entry below was validated in the field on 2026-07-21 (OPNsense
stable/26.1, FreeBSD 14.3). All repairs are **backup-first + health-gated +
auto-rollback** (see the guardian pattern at the end).

Severity: 🔴 breaks traffic/leaks · 🟠 degrades · 🟡 hygiene.

## PIA WireGuard VPN

### vpn.tunnel.handshake 🔴
- **Detect:** `wg show <wgif> latest-handshakes`; age = now − ts.
- **Healthy:** age ≤ 180s on the *real* live interface (field: `wg4`, not
  `wg0/1/2`).
- **Symptom:** stale/no handshake → tunnel dead, policy-routed hosts blackhole.
- **Repair:** re-register PIA session / rotate server in-region; after N stale
  cycles flip region (`ca`↔`nl_amsterdam`) and reprovision. (See `pia-vpn-failover.md`.)

### vpn.region.correct 🟠
- **Detect:** `regionId` in config vs live `server_name`/`server_ip`; validate id
  against `serverlist.piaservers.net/vpninfo/servers/v6` (`ca`=Montreal, NOT
  `ca_montreal`); confirm region is `port_forward:true`.
- **Repair:** set intended region + `--changeserver`.

### vpn.gateway.vip_drift 🟠
- **Detect:** gateway `<gateway>` far-VIP vs live `server_vip` (changes per
  server; field had stale Vancouver `10.21.128.1` while live was `10.20.128.1`).
- **Repair:** re-sync `<gateway>` to `server_vip` on each reprovision +
  `interface routes configure` (transactional — see guardian).

### vpn.monitor.antipattern 🟡
- **Detect:** a dpinger `<monitor>` set to a public IP (exits WAN, false-healthy)
  or the PIA VIP (ICMP-blocked → false-down).
- **Note:** WG tunnel health = handshake age, NOT dpinger ICMP. Prefer
  `<monitor_disable>1` and rely on `vpn.tunnel.handshake`.

## Forwarded port (inbound peer connectivity)

### pf.alias.synced 🟠
- **Detect:** firewall alias `pia_vancouver_port` content vs live PIA forwarded
  port (from the PF signature).
- **Symptom:** empty/stale alias → no incoming peers → slow swarms.
- **Gotchas:** `opnsenseURL` must be `https` (http → 301 → silent write fail);
  call `/api/firewall/alias*` directly (self-signed cert). After change:
  `alias/reconfigure` **AND `filter reload`** (port aliases are ruleset macros,
  not live tables — rdr won't pick up the new port without a filter reload).

### pf.nat.inbound 🔴 (for connectivity)
- **Detect:** `pfctl -sn | grep 'rdr pass on <wgif>.*-> <torrent_host> port <listen>'`.
- **Symptom:** absent → qBittorrent unreachable inbound (field: only Plex
  `:32400` rdr existed; no torrent forward).
- **Repair:** rdr on the WG interface, dst `<wgif>ip`:`pia_*_port` alias →
  torrent host:listen-port, tcp/udp, `associated-rule-id: pass`. NB: the rdr
  `<rule>` must be a **direct child of `<nat>` after `</outbound>`** — placing it
  inside `<outbound>` renders a bogus SNAT, not a port-forward.

## Leak safety

### leak.killswitch 🔴
- **Detect:** in `pfctl -sr`, a `pass … route-to (<wgif> …) from <src> to any`
  immediately followed by `block drop quick … from <src> to any`; **AND** global
  `<skiprulewhengwdown>1`.
- **Symptom:** without `skiprulewhengwdown`, a down gateway makes the pass rule a
  plain pass → traffic exits WAN (deanonymizing leak); the block-below never runs.
- **Verify (active):** compare the policy-routed host's public IP vs WAN IP.
- **Repair:** ensure the pass/block pair + set `skiprulewhengwdown=1` +
  `filter reload`.

### route.membership 🟠
- **Detect:** source alias (field: `vpn_hosts_sweden`) resolves to the intended
  hosts (field: `[10.10.10.15]`=freyr).

## Gateway hygiene 🟡

### gw.stale / gw.default_pinned
- **Detect:** enabled gateways on down interfaces (field: `GW_PIA_SWEDEN`/opt3/wg0,
  `GW_PIA_USWEST`/opt5/wg2); `defaultgw4` = automatic.
- **Repair (TRANSACTIONAL ONLY):** removing/disabling any gateway forces
  `configctl interface routes configure`, which churns routing and **dropped the
  live PIA exit twice in the field**. Pin `defaultgw4`=WAN_GW first; converge
  naming + remove dead wg0/wg2 instances + opt3/opt5 + masquerade NAT as one
  atomic change, health-gated with auto-rollback. Do NOT do piecemeal on a live box.

## NetFlow / Insight (reporting)

### insight.aggregator 🟠
- **Detect:** `pgrep -f flowd_aggregate.py`; stale `/var/run/flowd_aggregate*.pid`;
  log signature `sqlite3.DatabaseError: database disk image is malformed`.
- **Symptom:** crash loop; Insight/Reporting stops updating.
- **Repair:** stop, clear stale pidfile, `PRAGMA integrity_check` each
  `/var/netflow/*.sqlite`, quarantine malformed (rebuild fresh), restart
  collector+aggregator. (Interim: `/conf/netflow-selfheal.sh`, issue #8.)

### insight.db_bloat 🟡
- **Detect:** `/var/netflow/*_000300.sqlite` size (field: src_addr 745M, dst_port
  526M — torrent flow cardinality). Large 5-min DBs precede corruption.
- **Repair/lever:** narrow NetFlow capture (exclude torrent path), cap retention,
  or disable Insight if unused.

## Host

### host.varlog_ramdisk 🟠
- **Detect:** `df /var/log` (tmpfs RAM disk when "Use RAM disks" on; field 2.5G).
- **Symptom:** at 100% (field: filter 1.4G + flowd.log 1.1G) logging fails
  system-wide (`ENOSPC`) and tools crash. Plugin's own logging must NOT depend on
  `/var/log`.
- **Repair:** truncate volatile logs; recommend larger RAM disk or reduced
  filter/flow logging retention.

## Automation presence 🟡
- **Detect:** the health/failover loops exist and target the *right* interface
  (field: `piawireguard monitor` + `piafailover run` crons; the legacy
  `pia-watchdog` watched dead `wg0/1/2`). Plugin should own these, not shims.

---

## Repair safety contract (applies to every 🔴/🟠 repair)

1. `cp -p` a timestamped `config.xml` backup before any edit.
2. Apply, then **health-gate**: verify the live exit — WG handshake fresh **and**
   the policy-route `route-to` rule present in `pfctl` — for a settle window.
3. **Auto-rollback** on failure. Field-proven guardian: `/conf/freyr-exit-guardian.sh`
   — bg loop, 3× consecutive unhealthy → restore backup + `routes configure` +
   `filter reload`; recovered in ~40s.
4. Prefer the graceful GUI/apply path over raw `config.xml` + `routes configure`
   for routing-affecting changes.
