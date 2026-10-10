//! OPNsense tool surface.
//!
//! Endpoint registry: `opnsense.{list, detail, create, update, delete}` —
//! generated wholesale by `#[endpoint_resource]` (row struct, db helpers, schema
//! fragment, args/output types, and the five `#[orca_tool]` fns).
//!
//! Hand-written tools over the `/api/<module>/<controller>/<command>` REST API:
//!   - `opnsense.status`                        Unbound resolver run state
//!   - `opnsense.reconfigure`                   apply staged Unbound / DHCP settings
//!   - `opnsense.unbound.hostoverride.list`     list Unbound host overrides
//!   - `opnsense.unbound.hostoverride.set`      idempotent upsert of an A/AAAA override
//!   - `opnsense.unbound.hostoverride.delete`   delete the override for (hostname, domain)
//!   - `opnsense.unbound.dot.list`              list Unbound DoT upstreams
//!   - `opnsense.unbound.dot.set`               idempotent upsert of a DoT upstream
//!   - `opnsense.unbound.dot.delete`            delete the DoT upstream for (server, domain)
//!   - `opnsense.dhcp.reservation.list`         list Kea DHCP reservations
//!   - `opnsense.dhcp.reservation.set`          idempotent upsert of a MAC->IP reservation
//!   - `opnsense.dhcp.reservation.delete`       delete the reservation for a MAC
//!   - `opnsense.pia.forwarded_port`            read the PIA forwarded port from its alias
//!
//! Every mutating verb needs the admin role (also for its dry run) and only
//! writes with `--execute`; without it the verb returns the plan. A `set` or
//! `delete` that changes something is followed by a `reconfigure` of the
//! owning module so the change takes effect. Imports flow through `plugin_toolkit::prelude::*`.

use plugin_toolkit::prelude::*;

use crate::authz::require_admin;
use crate::plan::{Action, ReconfigurePlan, WritePlan};
use crate::{
    Config, DotUpstream, HostOverride, Module, PiaForwardedPort, Reservation, ServiceState,
};

// ═══════════════════════════════════════════════════════════════════════════
// opnsense.{list,detail,create,update,delete} — endpoint registry CRUD.
// ═══════════════════════════════════════════════════════════════════════════

// `routes` is a built-in column on every `#[endpoint_resource]` — an ordered
// fallback list (`--route kind=url`, repeatable, e.g. `--route lan=https://host`)
// resolved by `route::resolve_reachable`. Each entry's free-form `kind`
// (`fqdn` / `lan` / `tailscale`) doubles as the locality class the fewest-hop
// router consumes.
#[endpoint_resource(plugin = "opnsense")]
pub struct OpnsenseEndpoint {
    pub name: String,
    pub api_key: String,
    #[secret]
    pub api_secret: String,
    pub insecure: bool,
    pub enabled: bool,
}

// ── HTTP client helper ─────────────────────────────────────────────────────

/// Resolve a registered endpoint into a ready [`Config`]: the first reachable
/// base URL (`resolve_reachable` over the endpoint's `routes` fallback list)
/// plus the secure-first API secret.
pub(crate) async fn resolve_config(name: &str) -> Result<Config> {
    let row = endpoint_db::require(name)?;
    // Prefer the abstract secrets domain (`opnsense.<endpoint>.api_secret`),
    // falling back to a legacy plaintext column value only if the domain has none.
    let api_secret = plugin_toolkit::secrets::resolve_scoped(
        "opnsense",
        name,
        "api_secret",
        (!row.api_secret.is_empty()).then_some(row.api_secret.as_str()),
    )?;
    let base_url = route::resolve_reachable(name, &row.routes, row.insecure).await?;
    Ok(Config::new(base_url, row.api_key, api_secret).insecure(row.insecure))
}

// ═══════════════════════════════════════════════════════════════════════════
// opnsense.status
// ═══════════════════════════════════════════════════════════════════════════

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct EndpointArgs {
    /// Registered opnsense endpoint name.
    #[arg(long)]
    pub name: String,
}

/// Read an OPNsense appliance's Unbound resolver run state.
#[orca_tool(domain = "opnsense", verb = "status", role = "any")]
async fn opnsense_status(args: EndpointArgs, _ctx: &ToolCtx) -> Result<ServiceState> {
    let cfg = resolve_config(&args.name).await?;
    let client = cfg.build_client()?;
    Ok(crate::status(&client, &cfg).await?)
}

// ═══════════════════════════════════════════════════════════════════════════
// opnsense.reconfigure
// ═══════════════════════════════════════════════════════════════════════════

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct ReconfigureArgs {
    /// Registered opnsense endpoint name.
    #[arg(long)]
    pub name: String,
    /// Module to apply: `unbound` (resolver) or `dhcp` (Kea DHCPv4).
    #[arg(long, value_enum)]
    pub module: Module,
    /// Apply. Without it the verb only reports the plan.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

/// [MUTATES STATE with --execute] Apply staged settings for a module so they
/// take effect. Dry run by default.
#[orca_tool(domain = "opnsense", verb = "reconfigure", data_mutation = true)]
async fn opnsense_reconfigure(args: ReconfigureArgs, ctx: &ToolCtx) -> Result<ReconfigurePlan> {
    require_admin(ctx)?;
    let mut plan = crate::plan::reconfigure_plan(args.module, args.execute);
    if args.execute {
        let cfg = resolve_config(&args.name).await?;
        let client = cfg.build_client()?;
        plan.result = Some(crate::reconfigure(&client, &cfg, args.module).await?);
    }
    Ok(plan)
}

// ═══════════════════════════════════════════════════════════════════════════
// opnsense.unbound.hostoverride.{list,set,delete}
// ═══════════════════════════════════════════════════════════════════════════

/// List every Unbound host override configured on an OPNsense appliance.
#[orca_tool(domain = "opnsense", verb = "unbound.hostoverride.list", role = "any")]
async fn opnsense_hostoverride_list(
    args: EndpointArgs,
    _ctx: &ToolCtx,
) -> Result<Vec<HostOverride>> {
    let cfg = resolve_config(&args.name).await?;
    let client = cfg.build_client()?;
    Ok(crate::list_host_overrides(&client, &cfg).await?)
}

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct HostOverrideArgs {
    /// Registered opnsense endpoint name.
    #[arg(long)]
    pub name: String,
    /// Host part of the record (e.g. `gitea`).
    #[arg(long)]
    pub hostname: String,
    /// Domain part of the record (e.g. `example.com`).
    #[arg(long)]
    pub domain: String,
    /// The IP the name resolves to.
    #[arg(long)]
    pub server: String,
    /// Resource-record type (default `A`).
    #[arg(long, default_value = "A")]
    pub rr: String,
    /// Free-form description.
    #[arg(long, default_value = "")]
    pub description: String,
    /// Apply. Without it the verb only reports the plan.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

/// [MUTATES STATE with --execute] Point `hostname.domain` at `server`,
/// upserting the matching override in place, then reconfigure Unbound. An
/// unchanged override is left alone. Dry run by default.
#[orca_tool(
    domain = "opnsense",
    verb = "unbound.hostoverride.set",
    data_mutation = true
)]
async fn opnsense_hostoverride_set(
    args: HostOverrideArgs,
    ctx: &ToolCtx,
) -> Result<WritePlan<HostOverride>> {
    require_admin(ctx)?;
    let cfg = resolve_config(&args.name).await?;
    let client = cfg.build_client()?;
    let desired = HostOverride {
        uuid: None,
        enabled: "1".to_string(),
        hostname: args.hostname.clone(),
        domain: args.domain.clone(),
        rr: args.rr.clone(),
        server: args.server.clone(),
        description: args.description.clone(),
    };
    let mut plan = crate::plan::host_override_set(&client, &cfg, desired, args.execute).await?;
    if !args.execute || plan.action == Action::Unchanged {
        return Ok(plan);
    }
    let record = crate::set_host_override(
        &client,
        &cfg,
        &args.hostname,
        &args.domain,
        &args.rr,
        &args.server,
        &args.description,
    )
    .await?;
    plan.desired = Some(record);
    plan.executed = true;
    crate::reconfigure(&client, &cfg, Module::Unbound).await?;
    Ok(plan)
}

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct HostOverrideKeyArgs {
    /// Registered opnsense endpoint name.
    #[arg(long)]
    pub name: String,
    /// Host part of the record (e.g. `gitea`).
    #[arg(long)]
    pub hostname: String,
    /// Domain part of the record (e.g. `example.com`).
    #[arg(long)]
    pub domain: String,
    /// Apply. Without it the verb only reports the plan.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

/// [MUTATES STATE with --execute] Delete the host override for
/// `(hostname, domain)`, then reconfigure Unbound. Dry run by default.
#[orca_tool(
    domain = "opnsense",
    verb = "unbound.hostoverride.delete",
    data_mutation = true
)]
async fn opnsense_hostoverride_delete(
    args: HostOverrideKeyArgs,
    ctx: &ToolCtx,
) -> Result<WritePlan<HostOverride>> {
    require_admin(ctx)?;
    let cfg = resolve_config(&args.name).await?;
    let client = cfg.build_client()?;
    let mut plan = crate::plan::host_override_delete(
        &client,
        &cfg,
        &args.hostname,
        &args.domain,
        args.execute,
    )
    .await?;
    if !args.execute {
        return Ok(plan);
    }
    crate::delete_host_override(&client, &cfg, &args.hostname, &args.domain).await?;
    plan.executed = true;
    crate::reconfigure(&client, &cfg, Module::Unbound).await?;
    Ok(plan)
}

// ═══════════════════════════════════════════════════════════════════════════
// opnsense.unbound.dot.{list,set,delete}
// ═══════════════════════════════════════════════════════════════════════════

/// List every Unbound DNS-over-TLS upstream on an OPNsense appliance.
#[orca_tool(domain = "opnsense", verb = "unbound.dot.list", role = "any")]
async fn opnsense_dot_list(args: EndpointArgs, _ctx: &ToolCtx) -> Result<Vec<DotUpstream>> {
    let cfg = resolve_config(&args.name).await?;
    let client = cfg.build_client()?;
    Ok(crate::list_dot(&client, &cfg).await?)
}

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct DotArgs {
    /// Registered opnsense endpoint name.
    #[arg(long)]
    pub name: String,
    /// Upstream resolver IP.
    #[arg(long)]
    pub server: String,
    /// Upstream port (853 for DoT).
    #[arg(long, default_value = "853")]
    pub port: String,
    /// Zone to forward (empty = forward everything).
    #[arg(long, default_value = "")]
    pub domain: String,
    /// TLS certificate name to validate (empty = opportunistic).
    #[arg(long, default_value = "")]
    pub verify: String,
    /// Free-form description.
    #[arg(long, default_value = "")]
    pub description: String,
    /// Apply. Without it the verb only reports the plan.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

/// [MUTATES STATE with --execute] Upsert a DoT upstream keyed on
/// `(server, domain)`, then reconfigure Unbound. An unchanged upstream is left
/// alone. Dry run by default.
#[orca_tool(domain = "opnsense", verb = "unbound.dot.set", data_mutation = true)]
async fn opnsense_dot_set(args: DotArgs, ctx: &ToolCtx) -> Result<WritePlan<DotUpstream>> {
    require_admin(ctx)?;
    let cfg = resolve_config(&args.name).await?;
    let client = cfg.build_client()?;
    let desired = DotUpstream {
        uuid: None,
        enabled: "1".to_string(),
        domain: args.domain.clone(),
        server: args.server.clone(),
        port: args.port.clone(),
        verify: args.verify.clone(),
        description: args.description.clone(),
    };
    let mut plan = crate::plan::dot_set(&client, &cfg, desired, args.execute).await?;
    if !args.execute || plan.action == Action::Unchanged {
        return Ok(plan);
    }
    let record = crate::set_dot(
        &client,
        &cfg,
        &args.server,
        &args.port,
        &args.domain,
        &args.verify,
        &args.description,
    )
    .await?;
    plan.desired = Some(record);
    plan.executed = true;
    crate::reconfigure(&client, &cfg, Module::Unbound).await?;
    Ok(plan)
}

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct DotKeyArgs {
    /// Registered opnsense endpoint name.
    #[arg(long)]
    pub name: String,
    /// Upstream resolver IP.
    #[arg(long)]
    pub server: String,
    /// Zone the upstream forwards (empty = forward everything).
    #[arg(long, default_value = "")]
    pub domain: String,
    /// Apply. Without it the verb only reports the plan.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

/// [MUTATES STATE with --execute] Delete the DoT upstream for
/// `(server, domain)`, then reconfigure Unbound. Dry run by default.
#[orca_tool(domain = "opnsense", verb = "unbound.dot.delete", data_mutation = true)]
async fn opnsense_dot_delete(args: DotKeyArgs, ctx: &ToolCtx) -> Result<WritePlan<DotUpstream>> {
    require_admin(ctx)?;
    let cfg = resolve_config(&args.name).await?;
    let client = cfg.build_client()?;
    let mut plan =
        crate::plan::dot_delete(&client, &cfg, &args.server, &args.domain, args.execute).await?;
    if !args.execute {
        return Ok(plan);
    }
    crate::delete_dot(&client, &cfg, &args.server, &args.domain).await?;
    plan.executed = true;
    crate::reconfigure(&client, &cfg, Module::Unbound).await?;
    Ok(plan)
}

// ═══════════════════════════════════════════════════════════════════════════
// opnsense.dhcp.reservation.{list,set,delete}
// ═══════════════════════════════════════════════════════════════════════════

/// List every Kea DHCPv4 reservation on an OPNsense appliance.
#[orca_tool(domain = "opnsense", verb = "dhcp.reservation.list", role = "any")]
async fn opnsense_reservation_list(args: EndpointArgs, _ctx: &ToolCtx) -> Result<Vec<Reservation>> {
    let cfg = resolve_config(&args.name).await?;
    let client = cfg.build_client()?;
    Ok(crate::list_reservations(&client, &cfg).await?)
}

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct ReservationArgs {
    /// Registered opnsense endpoint name.
    #[arg(long)]
    pub name: String,
    /// UUID of the Kea subnet (from the subnet list) this reservation belongs to.
    #[arg(long)]
    pub subnet: String,
    /// The fixed IP to reserve.
    #[arg(long)]
    pub ip_address: String,
    /// The MAC address to reserve it for.
    #[arg(long)]
    pub hw_address: String,
    /// Optional hostname handed out with the lease.
    #[arg(long, default_value = "")]
    pub hostname: String,
    /// Free-form description.
    #[arg(long, default_value = "")]
    pub description: String,
    /// Apply. Without it the verb only reports the plan.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

/// [MUTATES STATE with --execute] Upsert a MAC->IP reservation keyed on the
/// MAC, then reconfigure Kea DHCP. An unchanged reservation is left alone. Dry
/// run by default.
#[orca_tool(
    domain = "opnsense",
    verb = "dhcp.reservation.set",
    data_mutation = true
)]
async fn opnsense_reservation_set(
    args: ReservationArgs,
    ctx: &ToolCtx,
) -> Result<WritePlan<Reservation>> {
    require_admin(ctx)?;
    let cfg = resolve_config(&args.name).await?;
    let client = cfg.build_client()?;
    let desired = Reservation {
        uuid: None,
        subnet: args.subnet.clone(),
        ip_address: args.ip_address.clone(),
        hw_address: args.hw_address.clone(),
        hostname: args.hostname.clone(),
        description: args.description.clone(),
    };
    let mut plan = crate::plan::reservation_set(&client, &cfg, desired, args.execute).await?;
    if !args.execute || plan.action == Action::Unchanged {
        return Ok(plan);
    }
    let record = crate::set_reservation(
        &client,
        &cfg,
        &args.subnet,
        &args.ip_address,
        &args.hw_address,
        &args.hostname,
        &args.description,
    )
    .await?;
    plan.desired = Some(record);
    plan.executed = true;
    crate::reconfigure(&client, &cfg, Module::Dhcp).await?;
    Ok(plan)
}

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct ReservationKeyArgs {
    /// Registered opnsense endpoint name.
    #[arg(long)]
    pub name: String,
    /// The MAC address whose reservation to delete.
    #[arg(long)]
    pub hw_address: String,
    /// Apply. Without it the verb only reports the plan.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

/// [MUTATES STATE with --execute] Delete the reservation for a MAC, then
/// reconfigure Kea DHCP. Dry run by default.
#[orca_tool(
    domain = "opnsense",
    verb = "dhcp.reservation.delete",
    data_mutation = true
)]
async fn opnsense_reservation_delete(
    args: ReservationKeyArgs,
    ctx: &ToolCtx,
) -> Result<WritePlan<Reservation>> {
    require_admin(ctx)?;
    let cfg = resolve_config(&args.name).await?;
    let client = cfg.build_client()?;
    let mut plan =
        crate::plan::reservation_delete(&client, &cfg, &args.hw_address, args.execute).await?;
    if !args.execute {
        return Ok(plan);
    }
    crate::delete_reservation(&client, &cfg, &args.hw_address).await?;
    plan.executed = true;
    crate::reconfigure(&client, &cfg, Module::Dhcp).await?;
    Ok(plan)
}

// ═══════════════════════════════════════════════════════════════════════════
// opnsense.pia.forwarded_port
// ═══════════════════════════════════════════════════════════════════════════

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct PiaForwardedPortArgs {
    /// Registered opnsense endpoint name.
    #[arg(long)]
    pub name: String,
    /// Firewall alias holding the PIA forwarded port. Omit to discover the
    /// alias `PIAWireguard.py` maintains.
    #[arg(long)]
    #[serde(default)]
    pub alias: Option<String>,
}

/// Return the port the PIA firewall alias currently holds, as written by the PIA
/// WireGuard script. NOT verified against PIA: the value can be stale (the script
/// may not have run or may have failed); empty aliases error.
#[orca_tool(domain = "opnsense", verb = "pia.forwarded_port", role = "any")]
async fn opnsense_pia_forwarded_port(
    args: PiaForwardedPortArgs,
    _ctx: &ToolCtx,
) -> Result<PiaForwardedPort> {
    let cfg = resolve_config(&args.name).await?;
    let client = cfg.build_client()?;
    Ok(crate::pia_forwarded_port(&client, &cfg, args.alias.as_deref()).await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use plugin_toolkit::contract::CallerIdentity;
    use plugin_toolkit::contract::config::{Config as OrcaConfig, Model, Ports};
    use std::sync::Arc;

    fn ctx(role: Option<&str>) -> ToolCtx {
        let cfg = OrcaConfig {
            anthropic_api_key: None,
            lmstudio_url: String::new(),
            ollama_url: String::new(),
            default_model: Model::parse("test"),
            app_dir: "/nonexistent".into(),
            memory_root: "/nonexistent".into(),
            db_path: "/nonexistent".into(),
            ports: Ports {
                http: 0,
                https: 0,
                mesh: 0,
            },
        };
        let c = ToolCtx::new(Arc::new(cfg));
        match role {
            Some(r) => c.with_auth(CallerIdentity {
                user_id: "u".into(),
                username: "u".into(),
                role: r.into(),
                can_mutate: true,
            }),
            None => c,
        }
    }

    fn refused<T: std::fmt::Debug>(r: Result<T>) {
        let e = r.unwrap_err().to_string();
        assert!(e.contains("admin") && e.contains("dry run"), "{e}");
    }

    /// Every mutating verb refuses non-admin callers before reading anything,
    /// dry run included (no endpoint is registered, so reaching the lookup
    /// would fail differently).
    #[test]
    fn mutating_verbs_refuse_non_admins_even_for_a_dry_run() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for role in [Some("read"), None] {
            let c = ctx(role);
            let n = || "fw".to_string();
            rt.block_on(async {
                refused(
                    opnsense_reconfigure(
                        ReconfigureArgs {
                            name: n(),
                            module: Module::Unbound,
                            execute: false,
                        },
                        &c,
                    )
                    .await,
                );
                refused(
                    opnsense_hostoverride_set(
                        HostOverrideArgs {
                            name: n(),
                            hostname: "h".into(),
                            domain: "d".into(),
                            server: "10.0.0.5".into(),
                            rr: "A".into(),
                            description: String::new(),
                            execute: false,
                        },
                        &c,
                    )
                    .await,
                );
                refused(
                    opnsense_hostoverride_delete(
                        HostOverrideKeyArgs {
                            name: n(),
                            hostname: "h".into(),
                            domain: "d".into(),
                            execute: false,
                        },
                        &c,
                    )
                    .await,
                );
                refused(
                    opnsense_dot_set(
                        DotArgs {
                            name: n(),
                            server: "9.9.9.9".into(),
                            port: "853".into(),
                            domain: String::new(),
                            verify: String::new(),
                            description: String::new(),
                            execute: false,
                        },
                        &c,
                    )
                    .await,
                );
                refused(
                    opnsense_dot_delete(
                        DotKeyArgs {
                            name: n(),
                            server: "9.9.9.9".into(),
                            domain: String::new(),
                            execute: false,
                        },
                        &c,
                    )
                    .await,
                );
                refused(
                    opnsense_reservation_set(
                        ReservationArgs {
                            name: n(),
                            subnet: "s".into(),
                            ip_address: "10.0.0.7".into(),
                            hw_address: "aa:bb:cc:dd:ee:ff".into(),
                            hostname: String::new(),
                            description: String::new(),
                            execute: false,
                        },
                        &c,
                    )
                    .await,
                );
                refused(
                    opnsense_reservation_delete(
                        ReservationKeyArgs {
                            name: n(),
                            hw_address: "aa:bb:cc:dd:ee:ff".into(),
                            execute: false,
                        },
                        &c,
                    )
                    .await,
                );
            });
        }
    }
}
