# OPNsense Setup — <your-domain> Homelab

**Router VM:** VMID 103 on <host> (Proxmox, <ip>)
**OS:** OPNsense <subnet> (FreeBSD-based)
**LAN:** <ip>/24 — gateway <ip>
**Domain:** <your-domain>

WireGuard private keys are stored in `.env` (gitignored) in this repo root.

---

## Table of Contents

- [OPNsense Setup — <your-domain> Homelab](#opnsense-setup--homelab-homelab)
  - [Table of Contents](#table-of-contents)
  - [Network Overview](#network-overview)
    - [Proxmox Bridges on <host>](#proxmox-bridges-on-<host>)
    - [VM Network Interfaces](#vm-network-interfaces)
    - [Subnets](#subnets)
  - [Part 1: VM Creation (run on <host>)](#part-1-vm-creation-run-on-<host>)
    - [Download OPNsense image](#download-opnsense-image)
    - [Upload ISO to Proxmox storage](#upload-iso-to-proxmox-storage)
    - [Create the VM](#create-the-vm)
  - [Part 2: First Boot](#part-2-first-boot)
  - [Part 3: Interface Assignment](#part-3-interface-assignment)
    - [LAN and WAN](#lan-and-wan)
    - [VLANs](#vlans)
    - [Assign VLAN Interfaces](#assign-vlan-interfaces)
  - [Part 3b: Kea DHCP and IPv6 Cleanup](#part-3b-kea-dhcp-and-ipv6-cleanup)
    - [Confirm Kea DHCP is active (not legacy ISC DHCP)](#confirm-kea-dhcp-is-active-not-legacy-isc-dhcp)
    - [Disable IPv6 services (cleanup)](#disable-ipv6-services-cleanup)
  - [Part 3c: Remove Dead OpenVPN Client](#part-3c-remove-dead-openvpn-client)
  - [Part 4: DNS (Unbound)](#part-4-dns-unbound)
  - [Part 5: DHCP Server](#part-5-dhcp-server)
  - [Part 6: Static DHCP Leases](#part-6-static-dhcp-leases)
  - [Part 6b: IoT VLAN DHCP](#part-6b-iot-vlan-dhcp)
  - [Part 7: <vpn-provider> WireGuard Tunnels](#part-7-vpn-wireguard-tunnels)
    - [Install the WireGuard Plugin](#install-the-wireguard-plugin)
    - [Create WireGuard Instances and Peers](#create-wireguard-instances-and-peers)
    - [Assign WG Interfaces](#assign-wg-interfaces)
    - [Add WireGuard Gateways](#add-wireguard-gateways)
    - [Verify Tunnels](#verify-tunnels)
    - [Refreshing <vpn-provider> Sessions](#refreshing-vpn-sessions)
      - [Auto-refresh watchdog (cron)](#auto-refresh-watchdog-cron)
  - [Part 8: Selective Host VPN Routing](#part-8-selective-host-vpn-routing)
    - [Step 1: Create a firewall alias for VPN-routed hosts](#step-1-create-a-firewall-alias-for-vpn-routed-hosts)
    - [Step 2: Add floating firewall rules (VPN route + kill switch)](#step-2-add-floating-firewall-rules-vpn-route--kill-switch)
    - [Step 3: Allow VPN return traffic (outbound NAT)](#step-3-allow-vpn-return-traffic-outbound-nat)
    - [Step 4: DNS for VPN-routed hosts](#step-4-dns-for-vpn-routed-hosts)
    - [Verify](#verify)
    - [Adding a host to VPN routing (day-to-day)](#adding-a-host-to-vpn-routing-day-to-day)
  - [Part 9: Port Forwards](#part-9-port-forwards)
  - [Part 10: Firewall Rules](#part-10-firewall-rules)
    - [IoT Interface Rules](#iot-interface-rules)
    - [Guest Interface Rules](#guest-interface-rules)
    - [LAN → Home Assistant Access](#lan--home-assistant-access)
    - [WAN Hardening](#wan-hardening)
  - [Part 11: NFS Config Backup](#part-11-nfs-config-backup)
    - [Mount NFS share](#mount-nfs-share)
    - [Backup script](#backup-script)
    - [Configure ntfy alerting](#configure-ntfy-alerting)
    - [Schedule nightly cron job](#schedule-nightly-cron-job)
    - [Test it](#test-it)
  - [Part 12: IoT VLAN — Device Isolation with Home Assistant Access](#part-12-iot-vlan--device-isolation-with-home-assistant-access)
    - [IoT Device List](#iot-device-list)
    - [Network Architecture](#network-architecture)
    - [Implementation](#implementation)
  - [Part 13: Upgrading OPNsense](#part-13-upgrading-opnsense)
  - [Troubleshooting](#troubleshooting)

---

## Network Overview

### Proxmox Bridges on <host>

| Bridge | Physical NIC | Role |
|--------|-------------|------|
| vmbr0 | enp1s0 | LAN (<ip>/24) |
| vmbr5 | enp7s0 | WAN (ISP uplink) |

### VM Network Interfaces

| VM interface | Proxmox bridge | OPNsense device | Role |
|-------------|---------------|----------------|------|
| net0 | vmbr0 | vtnet0 | LAN |
| net5 | vmbr5 | vtnet5 | WAN |

> **Note:** vtnet1–4 exist (unused NICs from Proxmox bridge assignments) but WAN landed on vtnet5, not vtnet1.

### Subnets

| Network | Subnet | Gateway | DHCP Range |
|---------|--------|---------|-----------|
| LAN | <ip>/24 | <ip> | <ip>–253 |
| IoT VLAN (tag 20) | <ip>/24 | <ip> | <ip>–200 |
| Guest VLAN (tag 30) | <ip>/24 | <ip> | <ip>–200 |

---

## Part 1: VM Creation (run on <host>)

### Download OPNsense image

```bash
# On <host> — download the amd64 dvd installer ISO
# Check https://opnsense.org/download/ for current version
wget -O /tmp/opnsense.iso.bz2 \
  https://<distro-mirror>/opnsense/releases/26.1/OPNsense-26.1-dvd-amd64.iso.bz2

bzip2 -d /tmp/opnsense.iso.bz2
```

### Upload ISO to Proxmox storage

In the Proxmox web UI: Datacenter > <host> > local > ISO Images > Upload, and upload `/tmp/OPNsense-26.1-dvd-amd64.iso`.

### Create the VM

```bash
qm create 103 \
  --name opnsense \
  --memory 2048 \
  --cores 2 \
  --cpu x86-64-v2-AES \
  --ostype other \
  --scsihw virtio-scsi-single \
  --cdrom local:iso/OPNsense-26.1-dvd-amd64.iso \
  --onboot 0

# Disk — 16GB is plenty for OPNsense
qm set 103 --scsi0 local-lvm:16

# Network interfaces
qm set 103 --net0 virtio,bridge=vmbr0   # LAN
qm set 103 --net1 virtio,bridge=vmbr5   # WAN

# Enable boot from CD
qm set 103 --boot order=ide2
```

> OPNsense does not require serial console — it uses standard VGA output. The Proxmox web console (noVNC) works fine.

---

## Part 2: First Boot

1. In Proxmox UI, open the console for VM 112 (noVNC).
2. Start the VM: `qm start 112`
3. Boot from the DVD. Select **Install** at the menu.
4. At the **Install OPNsense** prompt:
   - Keymap: US
   - Install mode: **ZFS** (recommended) or UFS
   - ZFS disk: select the 16GB virtio disk (`ada0` or `vtbd0`)
   - Root password: set a strong password
5. After installation completes, eject the ISO and reboot:
   ```bash
   qm set 103 --ide2 none --boot order=scsi0
   qm reboot 103
   ```
6. At first boot, OPNsense detects interfaces. At the interface assignment prompt:
   - **WAN:** vtnet1 (the vmbr5/ISP-facing NIC)
   - **LAN:** vtnet0 (the vmbr0/LAN-facing NIC)
7. OPNsense will set LAN to `<ip>` by default. At the shell menu, change it:
   - Select **2) Set interface IP address**
   - Choose LAN
   - Enter `<ip>` / prefix 24
   - No IPv6
   - Enable DHCP server on LAN: yes (temporary, configure properly via web UI)
   - Web GUI HTTP: yes

8. Access the web UI from your LAN: `http://<ip>`
   - Username: `root`
   - Password: (what you set during install)

> All further configuration is done via the web UI unless noted otherwise.

---

## Part 3: Interface Assignment

### LAN and WAN

OPNsense should have assigned vtnet0 as LAN and vtnet5 as WAN during setup. Verify:

**Interfaces > Assignments**

| Interface | Device | Description |
|-----------|--------|-------------|
| WAN | vtnet5 | ISP uplink |
| LAN | vtnet0 | <ip>/24 |

Set the LAN interface static IP:
- **Interfaces > LAN**
  - IPv4 Configuration Type: Static IPv4
  - IPv4 Address: `<ip> / 24`
  - Save → Apply Changes

Disable ISP DNS on WAN:
- **Interfaces > WAN** → uncheck "Allow DNS server list to be overridden by DHCP/PPP on WAN"

### VLANs

**Interfaces > Other Types > VLAN** — Add:

| Parent | VLAN Tag | Description |
|--------|----------|-------------|
| vtnet0 | 20 | IoT |
| vtnet0 | 30 | Guest |

### Assign VLAN Interfaces

**Interfaces > Assignments** — Add each VLAN device:

| New Interface Name | Device | Static IP |
|-------------------|--------|-----------|
| IOT | vtnet0.20 | <ip> / 24 |
| GUEST | vtnet0.30 | <ip> / 24 |

For each new interface:
- Enable: ✓
- Description: IoT (or Guest)
- IPv4 Configuration Type: Static IPv4
- IPv4 Address: as above
- Block private networks: **unchecked**
- Block bogon networks: **unchecked**
- Save → Apply Changes

---

## Part 3b: Kea DHCP and IPv6 Cleanup

### Confirm Kea DHCP is active (not legacy ISC DHCP)

OPNsense 24.7+ deprecated ISC DHCP and 26.x uses Kea by default for new installs. Upgraded installs may still be running ISC. Kea is required for reliable lease persistence — it writes leases to a database that survives restarts, so clients automatically resume working after OPNsense reboots without needing to renew.

**Check which backend is active:**

**Services > DHCPv4** — if you see a yellow warning banner about "legacy DHCP" or "ISC DHCP", you are on the old backend.

**To confirm via shell:**
```bash
# If this returns output, ISC is still running:
pgrep -x dhcpd && echo "ISC running" || echo "ISC not running"

# Kea:
pgrep -x kea-dhcp4 && echo "Kea running" || echo "Kea not running"
```

**If ISC is still active — migrate to Kea:**

**Services > DHCPv4 > General** → look for **DHCP Backend** setting and switch to **Kea**. OPNsense will migrate static mappings automatically. Verify all static leases survived under **Services > DHCPv4 > LAN > Static Mappings** after switching.

> **Why this matters for recovery:** ISC DHCP loses its lease database on restart. Kea persists leases and restores them on startup. When OPNsense comes back after a reboot, Kea immediately knows all active leases. Clients with valid leases don't need to re-acquire — OPNsense sends a gratuitous ARP for each interface IP (<ip>, etc.) on startup, clients update their ARP cache, and traffic flows again within seconds.

**Lease time strategy:**

Default lease times of 12h (43200s) are correct. Do not use very short lease times (e.g., 300s) — if OPNsense is down long enough that a client's lease expires, the client falls back to APIPA (<subnet>) and cannot recover without manual intervention. 12h means clients will only be affected if OPNsense is down for over 6 hours (T1 renewal attempt at 50% of lease time).

---

### Disable IPv6 services (cleanup)

This setup does not use IPv6. The ISP WAN may offer DHCPv6, but OPNsense should not be accepting or distributing IPv6 addresses.

**Interfaces > WAN:**
- IPv6 Configuration Type: **None** (not DHCPv6, not SLAAC)
- Save → Apply

**Interfaces > LAN, IOT, GUEST:**
- IPv6 Configuration Type: **None**
- Save → Apply

**Services > Router Advertisements** (if visible): Disable RA on all interfaces.

**Remove the WAN_DHCP6 gateway (if present):**

The live config may have a `WAN_DHCP6` gateway object left over from an earlier IPv6 attempt. If present:

**System > Gateways > Configuration** — find `WAN_DHCP6` → Delete.

> This gateway object serves no purpose without IPv6 on WAN and can cause spurious gateway monitoring alerts.

**Verify no IPv6 addresses are assigned:**
```bash
# Run on OPNsense shell — should show no inet6 except fe80:: link-local:
ifconfig vtnet0 | grep inet6
ifconfig vtnet5 | grep inet6
```

Link-local (`fe80::`) addresses are normal and harmless — they're assigned by the OS regardless of configuration. Global IPv6 addresses (`2001:`, `2600:`, etc.) should not appear.

---

## Part 3c: Remove Dead OpenVPN Client

If a dead OpenVPN client (e.g. `vpnca-region-b.<vpn-provider-domain>`) exists, Unbound will reference `ovpnc1` as its outgoing interface — causing Unbound to fail to start.

**VPN > OpenVPN > Clients** — find any <vpn-provider> or dead clients → Delete all.

Then verify Unbound starts cleanly:

```bash
# SSH to OPNsense
configctl unbound restart
sleep 2
drill google.com @127.0.0.1
```

If Unbound still won't start, check for the stale interface reference:

```bash
grep outgoing_interface /var/unbound/unbound.conf
```

If `outgoing_interface: ovpnc1` appears, the config.xml still has a reference — restart the web UI service to regenerate:

```bash
configctl unbound restart
```

---

## Part 4: DNS (Unbound)

OPNsense uses Unbound as its resolver.

**Services > Unbound DNS > General**

| Setting | Value |
|---------|-------|
| Enable | ✓ |
| Listen Port | 53 |
| Network Interfaces | LAN, IOT, GUEST, Localhost |
| DNSSEC | optional |
| Register DHCP Leases | ✗ |
| Register DHCP static mappings | ✗ |
| Local Zone Type | static |
| Local Domain | <your-domain> |

> **Why both registration settings are off:** Enabling "Register DHCP Leases" or "Register DHCP static mappings" causes Unbound to inject `local-data` entries for every hostname (e.g. `<host>.<your-domain> → <ip>`). These take precedence over AdGuard's DNS rewrites, so `*.<your-domain>` wildcards stop working for any host with a Kea reservation. All hostname resolution is handled by AdGuard DNS rewrites instead.

**Services > Unbound DNS > Query Forwarding**

Add a single forwarder entry:

| Server | Port | Type |
|--------|------|------|
| <ip> | (blank) | Forward |

Enable "Use SSL/TLS": **no**. Enable "Forward first": **yes** (fallback to recursive if AdGuard is unreachable).

> **Do NOT add multiple forwarders (e.g. AdGuard + 1.1.1.1).** Unbound sends to all in parallel — Cloudflare responds faster, bypassing ad-blocking. Keep only AdGuard with `forward-first: yes`.

Save → Apply.

**Services > Unbound DNS > Advanced**

Two settings are required for local DNS to work correctly with a public domain (`<your-domain>` is DNSSEC-signed via Cloudflare — without these, Unbound strips private-IP answers):

| Setting | Value |
|---------|-------|
| Private Domains | `<your-domain>` |
| Insecure Domains | `<your-domain>` |

- **Private Domains** (`private-domain`): allows Unbound to return private RFC1918 addresses for responses to `*.<your-domain>` queries (otherwise Unbound sanitizes them out as "public name with private address").
- **Insecure Domains** (`domain-insecure`): disables DNSSEC validation for `<your-domain>` (AdGuard's synthetic DNS rewrite records are unsigned — without this, the validator module may reject them).

Save → Apply.

**Filters > DNS rewrites** (in AdGuard Home at `http://<ip>`)

Add two rewrites:

| Domain | Answer |
|--------|--------|
| `<your-domain>` | `<ip>` |
| `*.<your-domain>` | `<ip>` |

This makes all `*.<your-domain>` queries resolve to the reverse proxy. When clients query AdGuard directly (recommended, see Part 5) AdGuard answers with the rewrite; if clients still use Unbound, Unbound forwards to AdGuard.

Verify:
```bash
drill nginx.<your-domain> @127.0.0.1
# Should return: nginx.<your-domain>. 10 IN A <ip>
drill google.com @127.0.0.1
# Should resolve normally
```

> **Do NOT use Unbound Host Overrides for `*.<your-domain>`.** Adding a `*` wildcard host override creates a `redirect` local-zone — but DHCP lease registration adds device hostnames (e.g. `adguard.<your-domain>`) as local-data inside that redirect zone, which causes a fatal Unbound startup error. Use AdGuard DNS rewrites instead.

---

## Part 5: DHCP Server

> **Requires Part 3b complete** — confirm Kea DHCP is active before configuring. Kea is the non-deprecated DHCP backend in OPNsense 26.x.

**Services > DHCPv4 > LAN**

| Setting | Value |
|---------|-------|
| Enable | ✓ |
| Range | <ip> – <ip> |
| DNS Servers | `<adguard-ip>,<router-ip>` (AdGuard primary, router/Unbound fallback) |
| Gateway | <ip> |
| Domain | <your-domain> |
| Default Lease Time | 43200 (12h) |
| Maximum Lease Time | 86400 (24h) |

> **Hand clients AdGuard primary + the router/Unbound as fallback.** Set the LAN
> subnet's DNS servers to `<adguard-ip>,<router-ip>` (comma-separated, ordered),
> applied via the same Kea subnet editor used for IoT below (**Services > Kea
> DHCP > Subnets** → edit the LAN subnet → advanced mode → uncheck **Auto collect
> option data** → set **DNS servers** → Save → apply). AdGuard authoritatively
> serves the `*.<your-domain>` wildcard rewrite; if clients were pointed only at
> Unbound they could get **NXDOMAIN for wildcard-only names** (only explicitly
> overridden hosts resolve).
>
> **Fallback completeness caveat.** With the router as secondary, Unbound's
> `forward-first` recurses when AdGuard is down, so **external** names keep
> working — but **internal `*.<your-domain>` names do not** during an AdGuard
> outage (Unbound forwards the domain to the dead AdGuard; recursion hits public
> DNS with no service records). A true local wildcard is **not cleanly possible
> on OPNsense 26 unboundplus**: no custom-options field, wildcard host overrides
> validate but are silently dropped (never rendered into `host_entries.conf`),
> and `/var/unbound/etc/*.conf` custom files are wiped on `unbound restart`/boot.
> To fully close it: explicit per-service host overrides → the reverse proxy, or
> **resolver HA** (a second AdGuard/Pi-hole instance as a real secondary — on the
> roadmap). This gap may be acceptable to leave for a homelab.

**Services > DHCPv4 > IOT**

IoT devices bypass AdGuard and go directly to Cloudflare — no ad-blocking on IoT.

DNS on IoT is set via the Kea subnet editor (**Services > Kea DHCP > Subnets** → edit `<ip>/24`):
- Enable **advanced mode** (toggle top-left of the dialog)
- Uncheck **Auto collect option data** — this reveals the DNS field
- Set **DNS servers**: `1.1.1.1`
- Save

| Setting | Value |
|---------|-------|
| Enable | ✓ |
| Range | <ip> – <ip> |
| DNS Servers | `1.1.1.1` (Cloudflare — direct, bypasses AdGuard) |
| Gateway | <ip> |
| Domain | <your-domain> |
| Default Lease Time | 43200 (12h) |

**Services > DHCPv4 > GUEST**

| Setting | Value |
|---------|-------|
| Enable | ✓ |
| Range | <ip> – <ip> |
| DNS Servers | <ip> |
| Gateway | <ip> |
| Domain | <your-domain> |
| Default Lease Time | 43200 (12h) |

---

## Part 6: Static DHCP Leases

**Services > DHCPv4 > LAN** — scroll to **DHCP Static Mappings** — Add each host:

| Hostname | MAC | IP |
|----------|-----|----|
| <host> | <mac> | <ip> |
| <host> | <mac> | <ip> |
| <host> | <mac> | <ip> |
| <host> | <mac> | <ip> |
| <host> | <mac> | <ip> |
| <host> | <mac> | <ip> |
| <host> | <mac> | <ip> |
| <host> | <mac> | <ip> |
| home-assistant | <mac> | <ip> |
| zwave-js-ui | <mac> | <ip> |
| <host> | <mac> | <ip> |
| <host> | <mac> | <ip> |
| <host> | <mac> | <ip> |
| <host> | <mac> | <ip> |
| <host> | <mac> | <ip> |
| <host> | <mac> | <ip> |
| <host> | <mac> | <ip> |
| <host> | <mac> | <ip> |
| <host> | <mac> | <ip> |
| <host> | <mac> | <ip> |
| <host> | <mac> | <ip> |
| <host> | <mac> | <ip> |
| <host> | <mac> | <ip> |
| <host> | <mac> | <ip> |
| <host> | <mac> | <ip> |
| <host> | <mac> | <ip> |
| <host> | <mac> | <ip> |
| <host> | <mac> | <ip> |
| <host> | <mac> | <ip> |
| <host> | <mac> | <ip> |
| <host> | <mac> | <ip> |
| <host> | <mac> | <ip> |
| <host> | <mac> | <ip> |
| <host> | <mac> | <ip> |
| <host> | <mac> | <ip> |

**Static host IPs (no DHCP — configured on the device itself):**
- `<ip>` — nginx proxy manager (LXC on <host>)

---

## Part 6b: IoT VLAN DHCP

IoT devices that should be on the IoT VLAN get static leases under **Services > DHCPv4 > IOT** instead of LAN:

| Hostname | MAC | IP |
|----------|-----|----|
| home-assistant | <mac> | <ip> |
| zwave-js-ui | <mac> | <ip> |
| <host> | <mac> | <ip> |
| <host> | <mac> | <ip> |
| <host> | <mac> | <ip> |
| <host> | <mac> | <ip> |
| <host> | <mac> | <ip> |
| <host> | <mac> | <ip> |

> A device receives its IoT IP only when it connects via a port or SSID tagged for VLAN 20. A device connecting via untagged LAN falls into the LAN DHCP pool (unless you also add a deny entry under LAN). For true isolation, connect devices to the correct VLAN segment.

---

## Part 7: <vpn-provider> WireGuard Tunnels

Three tunnels: `vpn_region-a` (table 200), `vpn_region-b` (table 201), `vpn_region-c` (table 202).

<vpn-provider> WireGuard is session-based — endpoint IPs and peer keys rotate. See [Refreshing <vpn-provider> sessions](#refreshing-vpn-sessions) when tunnels drop.

### Install the WireGuard Plugin

**System > Firmware > Plugins** — search for `os-wireguard` → Install.

After install, a new menu appears: **VPN > WireGuard**.

### Create WireGuard Instances and Peers

**VPN > WireGuard > Instances** — Add one instance per tunnel:

> **Live config note:** The wg0 instance is currently named `vpn-region-d` in OPNsense — it must be renamed to `vpn_region-a` for consistency. Do this in **VPN > WireGuard > Instances > Edit**. Also delete the duplicate old peer for <ip> (named "vpn-region-d-server") — only the current peer at <ip> should remain.

**Instance: vpn_region-a**

| Field | Value |
|-------|-------|
| Name | vpn_region-a |
| Public key | (generated — note it for <vpn-provider> registration) |
| Private key | (from `.env`: `<redacted-key>=`) |
| Listen port | 51815 |
| Tunnel address | <ip>/32 |
| DNS | (leave blank — OPNsense Unbound handles DNS) |
| Disable routes | ✓ (required — policy routing handles this, not WireGuard auto-routes) |

> **Disable routes** is critical. Without it, WireGuard installs a default route that sends all traffic through the tunnel.

**Instance: vpn_region-b**

| Field | Value |
|-------|-------|
| Name | vpn_region-b |
| Private key | (from `.env`: `<redacted-key>=`) |
| Listen port | 51816 |
| Tunnel address | <ip>/32 |
| Disable routes | ✓ |

**Instance: vpn_region-c**

| Field | Value |
|-------|-------|
| Name | vpn_region-c |
| Private key | (from `.env`: `<redacted-key>=`) |
| Listen port | 51817 |
| Tunnel address | <ip>/32 |
| Disable routes | ✓ |

**VPN > WireGuard > Peers** — Add one peer per tunnel:

**Peer: vpn_region-a_peer**

| Field | Value |
|-------|-------|
| Name | vpn_region-a_peer |
| Instance | vpn_region-a |
| Public key | <redacted-key>= |
| Endpoint address | <ip> |
| Endpoint port | 1337 |
| Allowed IPs | 0.0.0.0/0, ::/0 |
| Keepalive | 25 |

**Peer: vpn_region-b_peer**

| Field | Value |
|-------|-------|
| Name | vpn_region-b_peer |
| Instance | vpn_region-b |
| Public key | <redacted-key>= |
| Endpoint address | <ip> |
| Endpoint port | 1337 |
| Allowed IPs | 0.0.0.0/0, ::/0 |
| Keepalive | 25 |

**Peer: vpn_region-c_peer**

| Field | Value |
|-------|-------|
| Name | vpn_region-c_peer |
| Instance | vpn_region-c |
| Public key | <redacted-key>= |
| Endpoint address | <ip> |
| Endpoint port | 1337 |
| Allowed IPs | 0.0.0.0/0, ::/0 |
| Keepalive | 25 |

Enable WireGuard: **VPN > WireGuard > General** → Enable WireGuard → Save.

### Assign WG Interfaces

**Interfaces > Assignments** — the WireGuard instances appear as `wg0`, `wg1`, `wg2`. Assign and enable each:

| New Interface Name | Device | Description |
|-------------------|--------|-------------|
| WG_region-a | wg0 | <vpn-provider> region-a |
| WG_region-b | wg1 | <vpn-provider> region-b |
| WG_region-c | wg2 | <vpn-provider> US West |

For each:
- Enable: ✓
- IPv4 Configuration Type: Static IPv4, address set to the tunnel IP assigned by <vpn-provider> (updated automatically by `vpn-refresh`)
- Block private/bogon: unchecked
- Save → Apply

### Add WireGuard Gateways

OPNsense needs gateway objects to use WireGuard tunnels in policy routing.

**System > Gateways > Configuration** — Add:

**Gateway: GW_VPN_region-a**

| Field | Value |
|-------|-------|
| Name | GW_VPN_region-a |
| Interface | WG_region-a |
| Gateway | *(set to 10.X.128.1 pattern, derived from <vpn-provider>-assigned tunnel IP — updated by `vpn-refresh`)* |
| Far Gateway | ✓ (required for point-to-point WireGuard) |
| Disable Gateway Monitoring | ✓ |
| Description | <vpn-provider> region-a WireGuard gateway |

**Gateway: GW_VPN_region-b**

| Field | Value |
|-------|-------|
| Name | GW_VPN_region-b |
| Interface | WG_region-b |
| Gateway | *(derived from tunnel IP — updated by `vpn-refresh`)* |
| Far Gateway | ✓ |
| Disable Gateway Monitoring | ✓ |

**Gateway: GW_VPN_region-c**

| Field | Value |
|-------|-------|
| Name | GW_VPN_region-c |
| Interface | WG_region-c |
| Gateway | *(derived from tunnel IP — updated by `vpn-refresh`)* |
| Far Gateway | ✓ |
| Disable Gateway Monitoring | ✓ |

> **Gateway IPs rotate with <vpn-provider> sessions.** The `vpn-refresh` script derives the gateway using the pattern `10.X.128.1` where `X` is the second octet of the <vpn-provider>-assigned tunnel IP, and updates both `config.xml` and the live firewall rules automatically. Do not set static gateway IPs here.

### Verify Tunnels

**VPN > WireGuard > Status** — all three instances should show a peer with a recent handshake.

From the OPNsense shell (**System > Shell** or SSH):
```bash
wg show all
```
All three should show `latest handshake` within the last few minutes.

| Symptom | Cause | Fix |
|---------|-------|-----|
| No handshake, 0 B received | <vpn-provider> session expired | Run `vpn-refresh` |
| Handshake present, bytes sent but none received | Gateway IP stale after session rotation | Run `vpn-refresh` — it updates interface IP, gateway, and reloads firewall |
| Policy-routed host has no internet (DNS timeout) | Tunnel up but firewall route-to has old gateway | Run `vpn-refresh` to sync everything |
| Interface missing from `wg show` | Plugin not enabled or instance disabled | VPN > WireGuard > General → ensure enabled |

### Refreshing <vpn-provider> Sessions

<vpn-provider> WireGuard sessions expire (roughly every 24 hours). Endpoint IPs and peer public keys rotate. Refresh all tunnels by running the `vpn-refresh` script (from this repo's `scripts/openwrt/` directory — it works on OPNsense too since it just calls <vpn-provider>'s REST API).

Copy to OPNsense from your Mac:
```bash
scp scripts/opnsense/vpn-ip       root@<ip>:/usr/local/bin/vpn-ip
scp scripts/opnsense/vpn-refresh  root@<ip>:/usr/local/bin/vpn-refresh
scp scripts/opnsense/vpn-watchdog root@<ip>:/usr/local/bin/vpn-watchdog
chmod +x /usr/local/bin/vpn-ip /usr/local/bin/vpn-refresh /usr/local/bin/vpn-watchdog
```

Run on OPNsense (via shell or SSH):
```bash
/usr/local/bin/vpn-refresh
```

Enter your <vpn-provider> username and password. The script saves credentials to `/etc/vpn.conf` (mode 600). It handles everything:
1. Authenticates with <vpn-provider> API
2. Fetches the <vpn-provider> server list and registers all 3 tunnels
3. Updates `config.xml` — peer keys, tunnel addresses, and gateway IPs
4. Applies new peer config live via `wg set` (no WireGuard restart needed)
5. Updates live interface addresses via `ifconfig` (avoids stale IP after session rotation)
6. Reloads firewall rules via `configctl filter reload` (updates `route-to` gateway in pf rules)

After ~30 seconds, verify:
```bash
wg show all
# All 3 interfaces should show "latest handshake: X seconds ago"
```

#### Auto-refresh watchdog (cron)

`vpn-watchdog` checks handshake age on all 3 tunnels every 5 minutes and calls `vpn-refresh --auto` (non-interactive, uses saved `/etc/vpn.conf`) if any tunnel is stale (no handshake in 3+ minutes).

Enable on OPNsense via **System > Settings > Cron** — Add:

| Field | Value |
|-------|-------|
| Minutes | `*/5` |
| Hours | `*` |
| Day of month | `*` |
| Month | `*` |
| Day of week | `*` |
| Command | `/usr/local/bin/vpn-watchdog` |
| Description | `<vpn-provider> WireGuard auto-refresh` |

Or via shell:
```bash
echo '*/5 * * * * root /usr/local/bin/vpn-watchdog' >> /etc/cron.d/vpn-watchdog
```

Monitor watchdog activity:
```bash
tail -f /var/log/vpn-watchdog.log
```

**To look up current endpoints manually:**
```bash
/usr/local/bin/vpn-ip region-a      # returns endpoint IP and public key
/usr/local/bin/vpn-ip ca_region-b
/usr/local/bin/vpn-ip us_california
```

**Client public keys** (the router's keys — generated by OPNsense, never change):
- Read them from **VPN > WireGuard > Instances** — the "Public key" field for each instance.
- Register each with <vpn-provider> during `vpn-refresh`.

**<vpn-provider> region IDs and server IPs:**

| OPNsense interface | <vpn-provider> region | Notes |
|-------------------|-----------|-------|
| WG_region-a | `region-a` | ca_region-d was removed by <vpn-provider> |
| WG_region-b | `ca_region-b` | still valid |
| WG_region-c | `us_california` | verify — <vpn-provider> renames US regions |

To find current region IDs:
```bash
curl -s --max-time 15 'https://<vpn-provider-serverlist>/vpninfo/servers/v6' -o /tmp/<vpn-provider>-servers.txt
grep -o '"id":"[^"]*"' /tmp/<vpn-provider>-servers.txt
```

---

## Part 8: Selective Host VPN Routing

OPNsense routes specific hosts through a VPN tunnel using **floating firewall rules** with a gateway override.

This is equivalent to OpenWrt's `ip rule add from <host> lookup 200` — but implemented in the OPNsense firewall rule engine.

**Current policy:**

| Host | IP | Tunnel |
|------|----|--------|
| <host> | <ip> | vpn_region-a |

### Step 1: Create a firewall alias for VPN-routed hosts

**Firewall > Aliases** — Add:

| Field | Value |
|-------|-------|
| Name | vpn_hosts_region-a |
| Type | Host(s) |
| Content | <ip> |
| Description | Hosts routed via <vpn-provider> region-a |

### Step 2: Add floating firewall rules (GitHub bypass + VPN route + kill switch)

**Firewall > Rules > Floating** — Add three rules in this order:

#### Step 2a: Create GitHub alias

**Firewall > Aliases** — Add:

| Field | Value |
|-------|-------|
| Name | github_hosts |
| Type | Host(s) |
| Content | `github.com`, `*.github.com`, `*.githubusercontent.com`, `ghcr.io`, `*.ghcr.io`, `pkg-containers.githubusercontent.com` |
| Description | GitHub and GHCR — bypasses VPN for image pulls and git clone |

#### Step 2b: Floating rules

**Rule 1 — GitHub bypass (must be first):**

| Field | Value |
|-------|-------|
| Action | Pass |
| Quick | ✓ |
| Interface | LAN |
| Direction | **in** |
| TCP/IP Version | IPv4 |
| Protocol | any |
| Source | `vpn_hosts_region-a` |
| Destination | `github_hosts` |
| Gateway | **WAN** (default WAN gateway, not GW_VPN_region-a) |
| Description | GitHub bypass — allow VPN hosts to reach GitHub via WAN |

> **Why this rule exists:** <host> needs to reach GitHub for `git pull` (<repo> repo) and Docker image pulls from ghcr.io. Without this rule, the VPN route rule below catches all traffic and sends it through <vpn-provider> region-a, where GitHub connections hang or time out.

**Rule 2 — VPN route (must be second):**

| Field | Value |
|-------|-------|
| Action | Pass |
| Quick | ✓ |
| Interface | LAN |
| Direction | **in** ← critical, must be "in" not "out" or "any" |
| TCP/IP Version | IPv4 |
| Protocol | any |
| Source | `vpn_hosts_region-a` |
| Destination | any |
| Gateway | `GW_VPN_region-a` |
| Description | Route <host> through <vpn-provider> region-a |

**Rule 3 — Kill switch (must be third):**

| Field | Value |
|-------|-------|
| Action | Block |
| Quick | ✓ |
| Interface | LAN |
| Direction | any |
| Protocol | any |
| Source | `vpn_hosts_region-a` |
| Destination | any |
| Gateway | — (none) |
| Description | Kill switch — block <host> if VPN down |

> **Why direction "in":** The rule must match traffic as it enters the router from the LAN interface. "out" or "any" compiles to `pass out on vtnet0` which matches traffic going *to* the LAN — the opposite of what's needed. "in" compiles to `pass in on vtnet0 route-to (wg0 ...)` which correctly intercepts <host>'s outbound traffic.

> **Kill switch behavior:** With gateway monitoring disabled on WG gateways, OPNsense always considers GW_VPN_region-a "up". If the WireGuard peer becomes unreachable, traffic is blackholed in the tunnel — <host> loses internet but does NOT fall back to WAN. The kill switch block rule fires only if wg0 disappears entirely (e.g., WireGuard plugin disabled).

Save → Apply.

### Step 3: Allow VPN return traffic (outbound NAT)

OPNsense needs to masquerade traffic leaving through WireGuard:

**Firewall > NAT > Outbound** — switch to **Manual** mode, then Add:

| Field | Value |
|-------|-------|
| Interface | WG_region-a |
| Source | **LAN net** (select from dropdown) |
| Destination | any |
| Translation / target | Interface address |
| Description | Masquerade LAN through <vpn-provider> region-a |

Repeat for WG_region-b and WG_region-c.

### Step 4: DNS for VPN-routed hosts

VPN-routed hosts (<host>) should use a **public DNS resolver, not OPNsense**. The floating `route-to` rule sends ALL traffic through the tunnel including DNS to <ip>, which breaks resolution. Set the host's DNS directly to a public resolver that routes through the VPN:

On <host> (Alpine Linux):
```bash
echo "nameserver 1.1.1.1" > /etc/resolv.conf
chattr +i /etc/resolv.conf   # prevent overwrite on DHCP renew
```

DNS queries to 1.1.1.1 go through the VPN tunnel (region-a → Cloudflare) — no DNS leak.

### Verify

From <host> (`<ip>`):
```bash
curl -s https://ipinfo.io
# Should show a <vpn-provider>/region-a IP (e.g. <ip>, org: <upstream-org>)
```

From any other LAN host:
```bash
curl -s https://ipinfo.io
# Should show your ISP IP
```

### Adding a host to VPN routing (day-to-day)

1. Ensure the host has a static DHCP lease (Part 6).
2. Add its IP to the alias: **Firewall > Aliases > vpn_hosts_region-a** → add IP.
3. Set the host's DNS to `1.1.1.1` directly (not OPNsense).
4. Or create a new alias + floating rule for a different tunnel (GW_VPN_region-b, GW_VPN_region-c).

---

## Part 9: Port Forwards

**Firewall > NAT > Port Forward** — Add:

**Plex on <host> (external 32400 → internal 32400)**

| Field | Value |
|-------|-------|
| Interface | WAN |
| TCP/IP Version | IPv4 |
| Protocol | TCP |
| Destination | WAN address |
| Destination port range | 32400 |
| Redirect target IP | <ip> |
| Redirect target port | 32400 |
| Description | Plex - <host> |

**Plex on <host> (external 32401 → internal 32400)**

| Field | Value |
|-------|-------|
| Interface | WAN |
| Protocol | TCP |
| Destination port range | 32401 |
| Redirect target IP | <ip> |
| Redirect target port | 32400 |
| Description | Plex - <host> |

OPNsense auto-creates the associated firewall allow rules for port forwards. Verify under **Firewall > Rules > WAN** that the rules appear.

---

## Part 10: Firewall Rules

OPNsense firewall uses per-interface rule sets (not zones like OpenWrt), evaluated top-to-bottom. The defaults allow LAN→WAN. You need to add rules for VLAN interfaces.

### IoT Interface Rules

**Firewall > Rules > IOT_VLAN** — Add in this exact order (order matters):

> **Note:** Do NOT use `RFC1918` as a destination — OPNsense does not have a built-in alias by that name. Instead, block `LAN net` explicitly first, then allow `any`. Rules are evaluated top-down: LAN traffic hits the block rule; internet traffic falls through to the allow rule.

**1. Allow DHCP**

| Field | Value |
|-------|-------|
| Action | Pass |
| Protocol | UDP |
| Source | IOT_VLAN net |
| Destination | IOT_VLAN address |
| Destination port | 67 |
| Description | IoT DHCP |

**2. Allow DNS**

| Field | Value |
|-------|-------|
| Action | Pass |
| Protocol | TCP/UDP |
| Source | IOT_VLAN net |
| Destination | IOT_VLAN address |
| Destination port | 53 |
| Description | IoT DNS |

**3. Block IoT → LAN** ← must be BEFORE the allow-any rule

| Field | Value |
|-------|-------|
| Action | Block |
| Protocol | any |
| Source | IOT_VLAN net |
| Destination | **LAN net** (select from dropdown) |
| Description | Block IoT → LAN |

**4. Allow IoT internet**

| Field | Value |
|-------|-------|
| Action | Pass |
| Protocol | any |
| Source | IOT_VLAN net |
| Destination | any |
| Description | Allow internet |

### Guest Interface Rules

**Firewall > Rules > GUEST_VLAN** — same 4-rule pattern:

1. Pass UDP, source: GUEST_VLAN net, dest: GUEST_VLAN address, port 67 — Guest DHCP
2. Pass TCP/UDP, source: GUEST_VLAN net, dest: GUEST_VLAN address, port 53 — Guest DNS
3. Block any, source: GUEST_VLAN net, dest: **LAN net** — Block Guest → LAN
4. Pass any, source: GUEST_VLAN net, dest: any — Allow internet

### LAN → Home Assistant Access

To allow LAN devices to reach Home Assistant (<ip>:8123) and Z-Wave JS UI (<ip>:8091) on the IoT VLAN:

**Firewall > Rules > LAN** — Add before any blocking rules:

| Description | Protocol | Source | Destination | Port |
|-------------|----------|--------|-------------|------|
| LAN to Home Assistant | TCP | LAN net | <ip> | 8123 |
| LAN to Z-Wave JS UI | TCP | LAN net | <ip> | 8091 |

### WAN Hardening

OPNsense defaults are already restrictive on WAN (block all inbound except replies and port forwards). Verify:

**Firewall > Rules > WAN** — confirm no rule allows inbound ICMP echo:
- If there is an "Allow ping from WAN" rule, delete it or set action to Block.
- IPsec passthrough rules: if present and IPsec is not in use, delete them.

**System > Settings > Administration** — disable "HTTPS management via WAN" if not needed.

---

## Part 11: NFS Config Backup

Mounts <host>'s backups NFS share and runs a nightly config backup.

### Mount NFS share

SSH to OPNsense (`ssh root@<ip>`) and create the mount point:

```bash
mkdir -p /mnt/<host>/backups/opnsense
```

> **Do NOT add NFS to `/etc/fstab` on OPNsense.** The network is not available when fstab mounts run during early boot — an NFS fstab entry will hang or fail the boot process. The backup script mounts on-demand instead.

### Backup script

```bash
mkdir -p /mnt/<host>/backups/opnsense /usr/local/bin

cat > /usr/local/bin/opnsense-backup.sh << 'EOF'
#!/bin/sh
BACKUP_DIR="/mnt/<host>/backups/opnsense"
DATE=$(date +%Y-%m-%d)
BACKUP_FILE="${BACKUP_DIR}/opnsense-${DATE}.xml"
STATUS_FILE="${BACKUP_DIR}/.backup-status"
KEEP_DAYS=30

NTFY_URL=""
if [ -f /etc/opnsense-alerts.conf ]; then
  . /etc/opnsense-alerts.conf
fi

ntfy_alert() {
  TITLE="$1"; MSG="$2"; PRIORITY="${3:-default}"
  if [ -n "$NTFY_URL" ]; then
    curl -sf -X POST "$NTFY_URL" \
      -H "Title: ${TITLE}" \
      -H "Priority: ${PRIORITY}" \
      -d "$MSG" >/dev/null 2>&1 || true
  fi
}

# Ensure NFS is mounted (never in fstab — mount on-demand only)
if ! mount | grep -q "/mnt/<host>/backups"; then
  mount -t nfs <ip>:/mnt/user/backups /mnt/<host>/backups
  if ! mount | grep -q "/mnt/<host>/backups"; then
    logger -t opnsense-backup "ERROR: Failed to mount /mnt/<host>/backups"
    ntfy_alert "OPNsense Backup FAILED" "opnsense: NFS mount failed" "high"
    exit 1
  fi
fi

mkdir -p "$BACKUP_DIR"

# OPNsense config backup — copy the live config.xml
cp /conf/config.xml "$BACKUP_FILE"
if [ $? -ne 0 ]; then
  logger -t opnsense-backup "ERROR: Failed to copy config.xml"
  ntfy_alert "OPNsense Backup FAILED" "opnsense: config copy failed" "high"
  echo "FAIL $(date): config copy failed" > "$STATUS_FILE"
  exit 1
fi

# Prune old backups
find "$BACKUP_DIR" -name "*.xml" -mtime "+${KEEP_DAYS}" -exec rm -f {} \;

SIZE=$(ls -lh "$BACKUP_FILE" 2>/dev/null | awk '{print $5}')
MSG="OK $(date): $BACKUP_FILE ($SIZE)"
echo "$MSG" > "$STATUS_FILE"
logger -t opnsense-backup "Backup complete: $BACKUP_FILE ($SIZE)"
echo "Backup complete: $BACKUP_FILE ($SIZE)"
EOF

chmod +x /usr/local/bin/opnsense-backup.sh
```

### Configure ntfy alerting

```bash
echo 'NTFY_URL="http://<ip>/opnsense-backup"' > /etc/opnsense-alerts.conf
chmod 600 /etc/opnsense-alerts.conf
```

### Schedule nightly cron job

OPNsense uses the standard FreeBSD cron. Add via shell:

```bash
echo '0 2 * * * root /usr/local/bin/opnsense-backup.sh >> /var/log/opnsense-backup.log 2>&1' \
  >> /etc/cron.d/opnsense-backup
```

Or use the web UI: **System > Settings > Cron** — Add:

| Field | Value |
|-------|-------|
| Minutes | 0 |
| Hours | 2 |
| Command | /usr/local/bin/opnsense-backup.sh |
| Description | Nightly config backup to NFS |

### Test it

```bash
/usr/local/bin/opnsense-backup.sh
ls -lh /mnt/<host>/backups/opnsense/
```

> **Restoring:** Copy the desired `.xml` back to `/conf/config.xml` and reboot, or use **System > Configuration > Backups** in the web UI to upload and restore a config file.

---

## Part 12: IoT VLAN — Device Isolation with Home Assistant Access

### IoT Device List

| Device | IoT IP | Notes |
|--------|--------|-------|
| home-assistant | <ip> | LAN firewall rule required (port 8123) |
| zwave-js-ui | <ip> | LAN firewall rule required (port 8091) |
| <host> | <ip> | Robot vacuum |
| <host> | <ip> | Air purifier |
| <host> | <ip> | Smart lighting bridge |
| <host> | <ip> | Philips <host> bridge |
| <host> | <ip> | Smart TV |
| <host> | <ip> | Smart soundbar |

### Network Architecture

```
LAN (<subnet>)
  └─ can access HA UI port 8123 and zwave-js-ui port 8091 on IoT VLAN
  └─ cannot access other IoT devices

IoT VLAN (<subnet>)
  └─ internet access ✓
  └─ can reach each other (same subnet) — HA can control IoT devices ✓
  └─ cannot initiate connections to LAN ✗
```

### Implementation

Static DHCP leases for IoT devices are already in Part 6b.

Firewall rules are already in Part 10 (IoT rules block LAN access; specific rules allow LAN→HA and LAN→zwave-js-ui).

**Moving home-assistant and zwave-js-ui LXC containers to IoT VLAN:**

This is a Proxmox-level change. In the Proxmox web UI:
- Select the LXC container (home-assistant, zwave-js-ui) on <host>
- Network → edit the network interface → change VLAN tag to 20
- Apply and reboot the container
- The container will receive its IoT IP from the OPNsense DHCP server

---

## Part 13: Upgrading OPNsense

**System > Firmware > Updates** — OPNsense checks for updates automatically.

Before upgrading:
1. Take a config backup: **System > Configuration > Backups** → Download
2. Or run the NFS backup script: `/usr/local/bin/opnsense-backup.sh`

Apply update via **System > Firmware > Updates** → Update. OPNsense preserves all config across upgrades (unlike OpenWrt's package-wiping sysupgrade). Plugin packages are also preserved.

After upgrade, verify:
- `wg show all` — tunnels up
- DHCP leases active: **Services > DHCPv4 > Leases**
- Firewall rules intact: **Firewall > Rules**
- DNS resolving: from a LAN host, `nslookup <your-domain> <ip>`

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Can't access web UI after first boot | LAN IP not set | Use console: select option 2, set LAN to <ip>/24 |
| Clients don't recover after OPNsense restart | ISC DHCP (not Kea) — loses lease DB on restart | Migrate to Kea: Part 3b |
| Gateway monitoring shows spurious alerts for WAN_DHCP6 | Leftover IPv6 gateway object with no active IPv6 | System > Gateways — delete WAN_DHCP6 |
| IoT/Guest devices don't get IPs | DHCP not enabled on VLAN interface, or VLAN not tagged | Enable DHCPv4 for IOT/GUEST interfaces; verify switch/AP VLAN tagging |
| WireGuard shows no handshake | <vpn-provider> session expired | `vpn-watchdog` should auto-refresh; or run `vpn-refresh` manually |
| Policy-routed host uses WAN instead of VPN | Floating rule not matching, or gateway monitoring killed the WG gateway | Check floating rule order (Quick must be ✓); set "Disable Gateway Monitoring" on WG gateways |
| VPN host has 100% packet loss through tunnel | Outbound NAT missing on WG interface | Firewall > NAT > Outbound — add masquerade rule for WG_region-a |
| DNS not resolving wildcard *.<your-domain> | AdGuard DNS rewrite missing, or Unbound not forwarding to AdGuard, or private-domain/insecure-domain not set | Check: (1) AdGuard Filters > DNS rewrites has `*.<your-domain> → <ip>`; (2) Unbound Advanced > Private Domains = `<your-domain>`; (3) Unbound Advanced > Insecure Domains = `<your-domain>`. Do NOT use Unbound Host Overrides for `*` wildcard — causes startup crash. |
| NFS mount fails | <host> down, or NFS not exported | Check <host> NFS export; backup script mounts on-demand — do NOT add NFS to fstab |
| Plex port forward not working | Associated firewall rule not created | Firewall > Rules > WAN — verify auto-created rule exists |
| IoT device reaches LAN | Rule order wrong — allow rule before block | Move block IoT→any below the WAN-allow rule; ensure no overlapping pass rule |
| WireGuard gateway shows offline | Monitoring probes failing through tunnel | Set "Disable Gateway Monitoring" on all WG gateways |
