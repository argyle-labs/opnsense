//! opnsense service backend — OPNsense firewall/router appliance.
//!
//! Implements `ServiceBackend` so the generic `service.*` tools
//! (deploy/backup/restore/configure/status/connect/sync) drive opnsense. No
//! `#[orca_tool]`s — the only orca dep is `plugin-toolkit`. Modeled on the
//! nfs StorageBackend. See orca/docs/PLUGIN-PROGRAM.md.
#![allow(clippy::disallowed_types)]

use plugin_toolkit::service::{
    BoxFuture, Endpoint, Runtime, ServiceBackend, ServiceCapability, ServiceError, ServiceStatus,
    WorkloadSpec,
};

mod abi_export;

/// opnsense backend. Holds only the provider name; per-instance endpoint/creds
/// come from the `Endpoint` the generic `service.*` tools hand each op.
#[derive(Debug, Clone)]
pub struct OpnsenseBackend {
    provider: &'static str,
}

impl OpnsenseBackend {
    pub fn new(provider: &'static str) -> Self {
        Self { provider }
    }
}

impl ServiceBackend for OpnsenseBackend {
    fn provider(&self) -> &str {
        self.provider
    }

    /// Runtimes opnsense can be placed on. `service.deploy` hands the
    /// `workload_spec` below to a matching deploy target — this backend never
    /// drives pct/docker itself (that mechanic lives in the deploy-target domain).
    fn runtimes(&self) -> Vec<Runtime> {
        vec![Runtime::Vm]
    }

    fn capabilities(&self) -> Vec<ServiceCapability> {
        vec![
            ServiceCapability::Deploy,
            ServiceCapability::Backup,
            ServiceCapability::Restore,
            ServiceCapability::Configure,
            ServiceCapability::Status,
        ]
    }

    fn default_port(&self) -> u16 {
        443
    }

    /// In-workload paths holding config/data. This is ALL opnsense declares for
    /// backup — the generic pluggable backup (tar for containers/LXC, PBS for
    /// Proxmox guests when available) snapshots these. No backup/restore code
    /// here; those are inherited from ServiceBackend's defaults.
    fn data_paths(&self) -> Vec<String> {
        vec!["/config".to_string()]
    }

    fn workload_spec<'a>(
        &'a self,
        _runtime: Runtime,
        _ep: &'a Endpoint,
    ) -> BoxFuture<'a, Result<WorkloadSpec, ServiceError>> {
        // TODO: describe the opnsense workload (image/template, ports, mounts,
        // env) for the chosen runtime. The deploy target turns this into a
        // compose service / LXC config / VM. See deploy-target::WorkloadSpec.
        Box::pin(async move { Err(ServiceError::unimplemented("opnsense.workload_spec")) })
    }

    fn configure<'a>(
        &'a self,
        _ep: &'a Endpoint,
        _config: &'a str,
    ) -> BoxFuture<'a, Result<(), ServiceError>> {
        // TODO: apply opnsense-specific config idempotently via the OPNsense
        // REST API (requires API key/secret; the appliance exposes it under
        // System > Access > Users > API keys). Planned operations, in priority
        // order:
        //
        // 1. Kea DHCPv4 per-subnet DNS servers — set the ordered resolver list a
        //    subnet's clients are handed. Concretely: ad-blocking resolver first
        //    (primary), router/Unbound second (fallback). The ad-blocker serves
        //    the `*.<domain>` wildcard rewrite authoritatively; the router
        //    fallback keeps external DNS working via Unbound forward-first when
        //    the ad-blocker is down (internal names degrade — see note). API:
        //    `POST /api/kea/dhcpv4/set_subnet` (option_data_autocollect=0, then
        //    set domain-name-servers to the comma-separated list), then
        //    `/api/kea/service/reconfigure`. Applied manually on the reference
        //    fleet 2026-07-09 (edited the LAN subnet4 in config.xml + configctl
        //    template reload OPNsense/Kea + kea restart); automate it here.
        //    NOTE: a true local wildcard fallback in Unbound is not achievable on
        //    OPNsense 26 unboundplus (no custom-options field; wildcard host
        //    overrides silently dropped; /var/unbound/etc/*.conf wiped on
        //    restart). Resolver HA (second ad-blocker instance) is the roadmap
        //    fix; until then internal names during an ad-blocker outage are an
        //    accepted gap.
        // 2. Router Advertisement / DHCPv6 RDNSS — ensure IPv6 clients are not
        //    handed a non-ad-blocking resolver (or that IPv6 RA is disabled), so
        //    dual-stack clients don't bypass the chosen DNS over v6.
        // 3. Unbound Query Forwarding + Private/Insecure Domains — repair the
        //    forward-to-ad-blocker fallback so the router remains a viable
        //    secondary resolver.
        // 4. IDS/IPS (Suricata) enable/disable — toggle `<IDS><general><enabled>`
        //    + regen (`configctl template reload OPNsense/IDS`); disabling is the
        //    single biggest CPU/RAM reclaim on a lean router. Managed as a
        //    declared capability so it can be turned on with rules when wanted.
        // 5. Footprint right-sizing knobs — cap ZFS ARC (loader.conf.local
        //    `vfs.zfs.arc.max`) and strip unused optional services (netflow/
        //    Insight, unused plugins). VM RAM/vCPU sizing itself is the proxmox
        //    domain, not here.
        Box::pin(async move { Err(ServiceError::unimplemented("opnsense.configure")) })
    }

    fn status<'a>(
        &'a self,
        _ep: &'a Endpoint,
    ) -> BoxFuture<'a, Result<ServiceStatus, ServiceError>> {
        // TODO: real health/diagnostics.
        Box::pin(async move { Err(ServiceError::unimplemented("opnsense.status")) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declares_provider() {
        let b = OpnsenseBackend::new("opnsense");
        assert_eq!(b.provider(), "opnsense");
    }
}
