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
//!
//! Every `set`/`delete` is followed by a `reconfigure` of the owning module so
//! the change takes effect. Imports flow through `plugin_toolkit::prelude::*`.

use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::Value;

use crate::{Config, DotUpstream, HostOverride, Module, Reservation, ServiceState};

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
}

/// [MUTATES STATE] Apply staged settings for a module so they take effect.
#[orca_tool(domain = "opnsense", verb = "reconfigure", data_mutation = true)]
async fn opnsense_reconfigure(args: ReconfigureArgs, _ctx: &ToolCtx) -> Result<Value> {
    let cfg = resolve_config(&args.name).await?;
    let client = cfg.build_client()?;
    Ok(crate::reconfigure(&client, &cfg, args.module).await?)
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
}

/// [MUTATES STATE] Point `hostname.domain` at `server`, upserting the matching
/// override in place, then reconfigure Unbound. Idempotent.
#[orca_tool(
    domain = "opnsense",
    verb = "unbound.hostoverride.set",
    data_mutation = true
)]
async fn opnsense_hostoverride_set(args: HostOverrideArgs, _ctx: &ToolCtx) -> Result<HostOverride> {
    let cfg = resolve_config(&args.name).await?;
    let client = cfg.build_client()?;
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
    crate::reconfigure(&client, &cfg, Module::Unbound).await?;
    Ok(record)
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
}

/// [MUTATES STATE] Delete the host override for `(hostname, domain)`, then
/// reconfigure Unbound.
#[orca_tool(
    domain = "opnsense",
    verb = "unbound.hostoverride.delete",
    data_mutation = true
)]
async fn opnsense_hostoverride_delete(args: HostOverrideKeyArgs, _ctx: &ToolCtx) -> Result<String> {
    let cfg = resolve_config(&args.name).await?;
    let client = cfg.build_client()?;
    let uuid = crate::delete_host_override(&client, &cfg, &args.hostname, &args.domain).await?;
    crate::reconfigure(&client, &cfg, Module::Unbound).await?;
    Ok(uuid)
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
}

/// [MUTATES STATE] Upsert a DoT upstream keyed on `(server, domain)`, then
/// reconfigure Unbound. Idempotent.
#[orca_tool(domain = "opnsense", verb = "unbound.dot.set", data_mutation = true)]
async fn opnsense_dot_set(args: DotArgs, _ctx: &ToolCtx) -> Result<DotUpstream> {
    let cfg = resolve_config(&args.name).await?;
    let client = cfg.build_client()?;
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
    crate::reconfigure(&client, &cfg, Module::Unbound).await?;
    Ok(record)
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
}

/// [MUTATES STATE] Delete the DoT upstream for `(server, domain)`, then
/// reconfigure Unbound.
#[orca_tool(domain = "opnsense", verb = "unbound.dot.delete", data_mutation = true)]
async fn opnsense_dot_delete(args: DotKeyArgs, _ctx: &ToolCtx) -> Result<String> {
    let cfg = resolve_config(&args.name).await?;
    let client = cfg.build_client()?;
    let uuid = crate::delete_dot(&client, &cfg, &args.server, &args.domain).await?;
    crate::reconfigure(&client, &cfg, Module::Unbound).await?;
    Ok(uuid)
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
}

/// [MUTATES STATE] Upsert a MAC->IP reservation keyed on the MAC, then
/// reconfigure Kea DHCP. Idempotent.
#[orca_tool(
    domain = "opnsense",
    verb = "dhcp.reservation.set",
    data_mutation = true
)]
async fn opnsense_reservation_set(args: ReservationArgs, _ctx: &ToolCtx) -> Result<Reservation> {
    let cfg = resolve_config(&args.name).await?;
    let client = cfg.build_client()?;
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
    crate::reconfigure(&client, &cfg, Module::Dhcp).await?;
    Ok(record)
}

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct ReservationKeyArgs {
    /// Registered opnsense endpoint name.
    #[arg(long)]
    pub name: String,
    /// The MAC address whose reservation to delete.
    #[arg(long)]
    pub hw_address: String,
}

/// [MUTATES STATE] Delete the reservation for a MAC, then reconfigure Kea DHCP.
#[orca_tool(
    domain = "opnsense",
    verb = "dhcp.reservation.delete",
    data_mutation = true
)]
async fn opnsense_reservation_delete(args: ReservationKeyArgs, _ctx: &ToolCtx) -> Result<String> {
    let cfg = resolve_config(&args.name).await?;
    let client = cfg.build_client()?;
    let uuid = crate::delete_reservation(&client, &cfg, &args.hw_address).await?;
    crate::reconfigure(&client, &cfg, Module::Dhcp).await?;
    Ok(uuid)
}
