<p align="center">
  <img src="assets/icon-256.png" width="120" alt="opnsense" />
</p>

# opnsense

OPNsense is an open-source FreeBSD-based firewall and routing platform.

A first-party [orca](https://github.com/argyle-labs/orca) plugin (appliance integration).

This plugin **connects orca to an existing opnsense install** — opnsense is a full OS, not a container, so there's nothing for orca to deploy. Stand it up on bare metal or in a VM (below), then point orca at its API endpoint.

This repo is **self-contained** — the steps below stand up, back up, and restore opnsense **by hand, without orca**.

---

## Run it without orca

OPNsense installs as a standalone OS from the amd64 installer image (<https://opnsense.org/download/>). It is **not** a container — pick bare metal or a VM. Minimum: 2 GB RAM, ~16 GB disk, and **two network interfaces** (WAN + LAN).

### Bare metal

1. Download the `vga` (USB) amd64 image from <https://opnsense.org/download/> (select architecture `amd64`, type `vga`), decompress it, and write it to a USB stick:
   ```sh
   # macOS/Linux — replace /dev/diskN with your USB device
   bunzip2 OPNsense-*-vga-amd64.img.bz2
   dd if=OPNsense-*-vga-amd64.img of=/dev/diskN bs=1m
   ```
2. Boot the target machine from the USB stick, log in as `installer` / `opnsense`, and run the guided installer (install to disk, set root password).
3. On first boot, assign interfaces (WAN = uplink NIC, LAN = internal NIC), then browse to `https://192.168.1.1` (default LAN) as `root`.

### VM (Proxmox / ESXi / Hyper-V)

Create a VM with **two virtual NICs** (one on the WAN bridge, one on the LAN bridge), ~16 GB disk, 2 GB+ RAM, and boot the installer ISO. The full worked Proxmox walkthrough — VM creation, interface assignment, VLANs, DHCP/DNS, WireGuard, firewall rules — is in [opnsense-setup.md](docs/opnsense-setup.md).

```sh
# On a Proxmox host — download the installer ISO to local storage
cd /var/lib/vz/template/iso
wget https://mirror.ams1.nl.leaseweb.net/opnsense/releases/mirror/OPNsense-<version>-dvd-amd64.iso.bz2
bunzip2 OPNsense-<version>-dvd-amd64.iso.bz2
```

### Dependencies

Two network interfaces (WAN + LAN). Everything else — DHCP, DNS (Unbound), VPN, IDS — ships in the base system or as in-GUI plugins.

### Ports & data

| | |
|---|---|
| Web GUI | `443/tcp` (HTTPS; `80` redirects) |
| SSH | `22/tcp` (opt-in) |
| State | the single `config.xml` (all rules, interfaces, VPN, DHCP, DNS) |
| Upstream | <https://opnsense.org/> |
| Operator notes | [opnsense-setup.md](docs/opnsense-setup.md) |

### Backup & restore

All opnsense state lives in **one file**, `config.xml`.

- **Backup (GUI):** *System → Configuration → Backups → Download configuration*. Optionally enable scheduled cloud backup (Google Drive / Nextcloud) on the same page.
- **Backup (automated):** the repo documents a nightly cron that copies the live `config.xml` to an NFS share — see [Part 11: NFS Config Backup](docs/opnsense-setup.md#part-11-nfs-config-backup).
- **Restore:** on a fresh install, *System → Configuration → Backups → Restore configuration*, upload the saved `config.xml`, and reboot. Rules, interfaces, VPN tunnels, DHCP leases, and DNS all come back.

> With orca this is **`service.backup` / `service.restore`** — the plugin pulls/pushes `config.xml` through the opnsense API, so backup/restore is one command regardless of where opnsense runs.

## With orca

orca drives this plugin through its generic surface — rich, opnsense-specific data comes back in the typed `service.status` payload, never bespoke tools.

```sh
orca service.status opnsense      # firewall/interface/VPN health (typed payload)
orca service.backup opnsense      # pull config.xml
orca service.configure opnsense   # apply config via the opnsense API
```

### NAT port forwards

`opnsense.nat.forward.{list,set,delete}` manage destination NAT rules through `firewall/d_nat` (OPNsense 26.1+). `set` is an upsert keyed by description; orca stores and only touches rules prefixed `orca:` (pass `adopt` to take over an existing rule). Writes are admin-only and support `dryRun`.

Safety:

- OPNsense has no rollback for NAT (its savepoint/rollback timer restores filter rules only), so orca compensates itself and `rollback_protected` is always `false`. Before changing or deleting a rule it snapshots it with `get_rule`. If apply or the post-apply health check fails, orca undoes the write — deletes a created rule, restores an updated rule from the snapshot, or re-adds a deleted one — re-applies, and reports whether that worked. The undo needs the API reachable; if the change cut orca off, it fails and says so. Errors carry `compensated: true|false`.
- The health check only proves the OPNsense API still answers orca. It does not test that the forward works from the WAN side; there is no TCP probe in the plugin toolkit yet, so verify external reachability separately.
- Undoing a delete re-adds the rule from the snapshot, which gives it a **new uuid** (reported in the error). `associated-rule-id` is a deprecated field OPNsense always clears, so it is dropped. The rule's filter behaviour comes from its `pass` setting (Pass / Register rule / Manual), which is restored from the snapshot.
- `firewall/d_nat/apply` applies the whole NAT configuration, including any other changes staged in the GUI; the compensation re-apply does too.
- If `add_rule` saves but returns no uuid, orca finds the staged rule by its `orca:` description and deletes it before applying (reported as `compensated: true`); if it can't, the error names the description and says `compensated: false`.
- Only an exact `wan` counts as WAN. If the current or desired interface is anything else (`opt*` and multi-interface rules included), `allow_unprotected` is required.
- On non-WAN interfaces, forwards touching 22/80/443 (plus the endpoint's `management_ports`, comma-separated) are refused unless the destination is a literal host address that is not a firewall interface address.

## Layout

- `src/` — the plugin (pure Rust): the `ServiceBackend` descriptor + `configure` / `status`.
- `docs/` — standalone operator notes (full Proxmox-VM setup walkthrough).
- [CAPABILITIES.md](CAPABILITIES.md) — the service-backend contract checklist.
- `assets/` — plugin icon.
