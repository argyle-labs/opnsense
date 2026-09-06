# OPNsense plugin — Unbound host-override (split-horizon DNS) capability (impl notes)

> **Status:** design notes seeded 2026-08-10. The orca `opnsense` plugin is
> `unreleased`/not-installed; DNS records are managed by hand in the OPNsense UI /
> `config.xml` today. These notes exist so the plugin can later own internal DNS
> overrides declaratively over the orca API. Design intent: **orca defines the
> record; the plugin writes it into OPNsense.**

## What this capability manages

OPNsense (`opn.scottkey.me`, `10.10.10.1`) runs **Unbound**, which is authoritative
for internal (split-horizon) resolution of `*.scottkey.me`. Internal clients
resolve public names to LAN IPs here, so LAN traffic to a service stays on-LAN
instead of hairpinning out to the WAN/proxy.

### Ground truth (from `/conf/config.xml`, 2026-08-10)

- Schema is the **newer `unboundplus`** host-override tree, NOT legacy `unbound->hosts`:
  ```
  OPNsense->unboundplus->hosts->host { enabled, hostname, domain, server, description }
  ```
  Existing override: `opnsense.scottkey.me -> 10.10.10.1 (enabled=1)`.
- Host inventory for reservations lives in **Kea DHCP** (`OPNsense->Kea->dhcp4->
  reservations`), e.g. `gitea ip=10.10.10.20 descr="Gitea CT117@frigg (static)"`.

## Split-horizon lesson learned (Gitea case — DO NOT naively repoint)

`gitea.scottkey.me` internally resolves to **`10.10.10.6` (baldur)** — the Docker
Caddy reverse proxy, which terminates TLS. The real Gitea host `10.10.10.20`
serves **plain HTTP :3000 only (no cert, 443 closed)**. Therefore a host-override
repointing `gitea.scottkey.me → 10.10.10.20` would **break HTTPS for every LAN
client**. The correct place to add the missing SSH:2222 route was the proxy
(Caddy L4 passthrough), NOT DNS. See the `caddy` plugin notes
(`docs/layer4-tcp-and-gitea-ssh.md`).

**Rule for the plugin:** a host-override that moves a name off a TLS-terminating
proxy is only valid if the new target also serves valid TLS for that name.
The plugin should be able to detect/flag this (probe 443 + cert SAN on the
proposed target) before applying — a split-horizon override that silently drops
TLS is a footgun. This is a concrete instance of the route-eligibility theme
([[route-eligibility-core-theme-and-plugin-models]]): a DNS route is only
eligible if the target actually serves the expected protocol+cert.

## Plugin capability shape (for later orca implementation)

- **CRUD of Unbound host overrides** (`unboundplus->hosts->host`) — typed record
  {hostname, domain, server(ip), enabled, description}, then apply
  (`configctl unbound reconfigure` / restart). No opaque XML in the API surface.
- **Read Kea/DHCP static reservations** so an override can be authored from the
  known host inventory (name→IP) rather than hand-typed.
- **Validity guard** (above): before applying an override that repoints a
  TLS-fronted name, probe the target for 443 + matching cert; refuse/warn otherwise.
- **Apply model:** OPNsense plugin is an **api-client plugin** — drive it over the
  OPNsense API (or ssh to `opn` for `config.xml` + `configctl`) from any host;
  do NOT install orca on the firewall. Credential by secret reference.

## Cross-refs
- Caddy L4/reverse-proxy side → `caddy` plugin: `docs/layer4-tcp-and-gitea-ssh.md`.
- Same-subnet caveat: OPNsense NAT/port-forward does NOT sit in the path for
  intra-LAN traffic (both proxy and target on 10.10.10.0/24), so firewall
  port-forwarding is NOT a substitute for the proxy L4 route in that case.
