#!/usr/bin/env bash
# Creates and configures a opnsense VM on Proxmox VE. Run on the host as root.
set -euo pipefail
VMID="${1:?Usage: $0 <vmid> [options]}"
# TODO: qm create / cloud-init / install opnsense.
echo "[provision] opnsense VM $VMID — not yet implemented"
