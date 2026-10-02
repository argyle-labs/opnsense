//! OPNsense plugin — firewall/router appliance driven over its REST API.
//!
//! A DUAL-facet plugin: one `Plugin` builder chain registers BOTH the
//! [`OpnsenseBackend`] (generic `service.*` lifecycle) AND the `opnsense.`
//! `#[orca_tool]` surface. The tool surface covers endpoint registry CRUD,
//! Unbound host-override and DoT-upstream CRUD, Kea DHCP reservation CRUD, plus
//! reconfigure and status. The builder emits all the wire dispatch, so the
//! plugin hand-writes no op strings and owns no runtime; it reaches orca only
//! through the socket.
//!
//! The wire surface is the toolkit's cap-backed HTTP client (`delegated-http`),
//! so every request rides orca's `http.request` capability and this plugin links
//! no reqwest/rustls. OPNsense's MVC API is controller-based, shaped as
//! `/api/<module>/<controller>/<command>`, with HTTP Basic auth over the API
//! key/secret pair. Every settings write is staged and only takes effect after
//! the module's `service/reconfigure`.
#![allow(clippy::disallowed_types)]

pub mod tools;

use plugin_toolkit::clap;
use plugin_toolkit::reqwest;
use plugin_toolkit::serde_json::{Value, json};
use plugin_toolkit::service::{
    BoxFuture, Routes, Runtime, ServiceBackend, ServiceCapability, ServiceError, ServiceStatus,
    WorkloadSpec,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// opnsense service backend — OPNsense firewall/router appliance.
///
/// Implements `ServiceBackend` so the generic `service.*` tools
/// (deploy/backup/restore/configure/status/connect/sync) drive opnsense. This
/// facet is registered ALONGSIDE the `#[orca_tool]` REST surface in [`tools`] —
/// one binary, both facets, via the `Plugin` builder. Modeled on the nfs
/// StorageBackend. See orca/docs/PLUGIN-PROGRAM.md.
///
/// Holds only the provider name; per-instance routes/creds come from the
/// `Routes` the generic `service.*` tools hand each op.
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
        vec!["/conf".to_string()]
    }

    fn workload_spec<'a>(
        &'a self,
        _runtime: Runtime,
        _instance: &'a str,
        _routes: &'a Routes,
    ) -> BoxFuture<'a, Result<WorkloadSpec, ServiceError>> {
        // TODO: describe the opnsense workload (image/template, ports, mounts,
        // env) for the chosen runtime. The deploy target turns this into a
        // compose service / LXC config / VM. See deploy-target::WorkloadSpec.
        Box::pin(async move { Err(ServiceError::unimplemented("opnsense.workload_spec")) })
    }

    fn configure<'a>(
        &'a self,
        _instance: &'a str,
        _routes: &'a Routes,
        _config: &'a str,
    ) -> BoxFuture<'a, Result<(), ServiceError>> {
        // TODO: apply opnsense-specific config idempotently.
        Box::pin(async move { Err(ServiceError::unimplemented("opnsense.configure")) })
    }

    fn status<'a>(
        &'a self,
        _instance: &'a str,
        _routes: &'a Routes,
    ) -> BoxFuture<'a, Result<ServiceStatus, ServiceError>> {
        // TODO: real health/diagnostics.
        Box::pin(async move { Err(ServiceError::unimplemented("opnsense.status")) })
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Wire types
// ═══════════════════════════════════════════════════════════════════════════

/// A single Unbound host override (split-horizon A/AAAA record):
/// `hostname.domain -> server`. Mirrors OPNsense's `unboundplus->hosts->host`
/// element. Boolean/enum fields come off the wire as strings (`"1"`, `"A"`),
/// so they are surfaced verbatim rather than lossily coerced.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HostOverride {
    /// OPNsense row UUID (present on reads; absent when authoring a new record).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(default)]
    pub enabled: String,
    pub hostname: String,
    pub domain: String,
    /// Resource-record type — `A`, `AAAA`, etc.
    #[serde(default)]
    pub rr: String,
    /// The IP the name resolves to (for `A`/`AAAA`).
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub description: String,
}

/// A single Unbound DNS-over-TLS upstream forward target. Mirrors OPNsense's
/// `dot` item (the TLS variant of a forward).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DotUpstream {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(default)]
    pub enabled: String,
    /// Zone to forward (empty = forward everything).
    #[serde(default)]
    pub domain: String,
    /// Upstream resolver IP.
    #[serde(default)]
    pub server: String,
    /// Upstream port (853 for DoT).
    #[serde(default)]
    pub port: String,
    /// TLS certificate name to validate (empty = opportunistic).
    #[serde(default)]
    pub verify: String,
    #[serde(default)]
    pub description: String,
}

/// A single Kea DHCPv4 reservation (MAC -> fixed IP static mapping).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Reservation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    /// UUID of the Kea subnet this reservation belongs to (from `search_subnet`).
    #[serde(default)]
    pub subnet: String,
    pub ip_address: String,
    /// The reserved MAC address.
    pub hw_address: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub description: String,
}

/// The subset of a module's `service/status` this plugin surfaces.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ServiceState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// Which OPNsense module to apply after a settings write.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum Module {
    /// Unbound resolver (`/api/unbound/service/reconfigure`).
    Unbound,
    /// Kea DHCPv4 (`/api/kea/service/reconfigure`).
    Dhcp,
}

impl Module {
    /// The URL path segment of the module owning the `service` controller.
    fn service_module(self) -> &'static str {
        match self {
            Module::Unbound => "unbound",
            Module::Dhcp => "kea",
        }
    }
}

/// OPNsense's bootgrid search envelope: `{ "rows": [...], "total": n, ... }`.
#[derive(Debug, Deserialize)]
struct SearchResult<T> {
    #[serde(default = "Vec::new")]
    rows: Vec<T>,
}

/// OPNsense's write-endpoint response: `{ "result": "saved", "uuid": "..." }`.
#[derive(Debug, Deserialize)]
struct WriteResult {
    #[serde(default)]
    result: String,
    #[serde(default)]
    uuid: Option<String>,
}

#[derive(Debug, Error)]
pub enum OpnsenseError {
    #[error("opnsense transport: {0}")]
    Transport(String),
    #[error("opnsense api error (status {status}): {body}")]
    Api { status: u16, body: String },
    #[error("opnsense rejected the write (result={result}): {body}")]
    Rejected { result: String, body: String },
    #[error("malformed opnsense response: {0}")]
    Malformed(String),
    #[error("no {kind} matching {selector}")]
    NotFound {
        kind: &'static str,
        selector: String,
    },
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Base URL of the OPNsense appliance (e.g. `https://host`). The
    /// `/api/<module>/<controller>/<command>` path is joined onto this.
    pub base_url: String,
    /// OPNsense API key — the username half of the Basic credential.
    pub api_key: String,
    /// OPNsense API secret — the password half of the Basic credential.
    pub api_secret: String,
    /// Skip TLS verification (self-signed appliance certs).
    pub insecure: bool,
}

impl Config {
    pub fn new(
        base_url: impl Into<String>,
        api_key: impl Into<String>,
        api_secret: impl Into<String>,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            api_key: api_key.into(),
            api_secret: api_secret.into(),
            insecure: false,
        }
    }

    pub fn insecure(mut self, on: bool) -> Self {
        self.insecure = on;
        self
    }

    /// `Basic <base64(key:secret)>` — OPNsense's API auth scheme.
    fn auth_header_value(&self) -> String {
        let raw = format!("{}:{}", self.api_key, self.api_secret);
        format!("Basic {}", base64_encode(raw.as_bytes()))
    }

    /// Build the cap-backed HTTP client with the Basic auth header pre-attached
    /// and TLS verification toggled per `insecure`.
    pub fn build_client(&self) -> Result<reqwest::Client, OpnsenseError> {
        plugin_toolkit::api_client::ApiClientBuilder::new()
            .header("authorization", self.auth_header_value())
            .and_then(|b| b.insecure(self.insecure).build())
            .map_err(|e| OpnsenseError::Transport(format!("client build: {e}")))
    }

    /// Join an `<module>/<controller>/<command>` route onto the `/api` root.
    fn api_url(&self, path: &str) -> String {
        format!(
            "{}/api/{}",
            self.base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }
}

fn transport(e: impl std::fmt::Display) -> OpnsenseError {
    OpnsenseError::Transport(e.to_string())
}

// ── generic request helpers ──────────────────────────────────────────────────

/// `GET <url>` -> deserialize the JSON body into `T`.
async fn get_json<T: DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
) -> Result<T, OpnsenseError> {
    let resp = client.get(url).send().await.map_err(transport)?;
    let status = resp.status();
    let body = resp.text().await.map_err(transport)?;
    if !status.is_success() {
        return Err(OpnsenseError::Api {
            status: status.as_u16(),
            body,
        });
    }
    plugin_toolkit::serde_json::from_str(&body).map_err(|e| OpnsenseError::Malformed(e.to_string()))
}

/// `POST <url>` with a JSON body -> parsed `Value` on a 2xx (or an `Api` error).
async fn post_json(
    client: &reqwest::Client,
    url: &str,
    body: &Value,
) -> Result<Value, OpnsenseError> {
    let resp = client
        .post(url)
        .json(body)
        .send()
        .await
        .map_err(transport)?;
    let status = resp.status();
    let text = resp.text().await.map_err(transport)?;
    if !status.is_success() {
        return Err(OpnsenseError::Api {
            status: status.as_u16(),
            body: text,
        });
    }
    plugin_toolkit::serde_json::from_str(&text).map_err(|e| OpnsenseError::Malformed(e.to_string()))
}

/// POST a settings write and require OPNsense's `result: "saved"` acknowledgement,
/// returning the new/updated row UUID when the API reports one.
async fn post_write(
    client: &reqwest::Client,
    url: &str,
    body: &Value,
) -> Result<Option<String>, OpnsenseError> {
    let value = post_json(client, url, body).await?;
    let wr: WriteResult = plugin_toolkit::serde_json::from_value(value.clone())
        .map_err(|e| OpnsenseError::Malformed(e.to_string()))?;
    if wr.result != "saved" && wr.result != "deleted" {
        return Err(OpnsenseError::Rejected {
            result: wr.result,
            body: value.to_string(),
        });
    }
    Ok(wr.uuid)
}

/// `GET <module>/settings/<search_command>` -> the search rows.
async fn search<T: DeserializeOwned>(
    client: &reqwest::Client,
    cfg: &Config,
    module: &str,
    search_command: &str,
) -> Result<Vec<T>, OpnsenseError> {
    let url = cfg.api_url(&format!("{module}/settings/{search_command}"));
    let result: SearchResult<T> = get_json(client, &url).await?;
    Ok(result.rows)
}

// ═══════════════════════════════════════════════════════════════════════════
// Unbound host overrides
// ═══════════════════════════════════════════════════════════════════════════

/// `GET /api/unbound/settings/search_host_override` — every host override.
pub async fn list_host_overrides(
    client: &reqwest::Client,
    cfg: &Config,
) -> Result<Vec<HostOverride>, OpnsenseError> {
    search(client, cfg, "unbound", "search_host_override").await
}

/// Idempotent upsert of a host override keyed on `(hostname, domain)`: update the
/// matching row if one exists, else add it. Does NOT reconfigure — callers apply
/// via [`reconfigure`]. Returns the applied record (with UUID when known).
pub async fn set_host_override(
    client: &reqwest::Client,
    cfg: &Config,
    hostname: &str,
    domain: &str,
    rr: &str,
    server: &str,
    description: &str,
) -> Result<HostOverride, OpnsenseError> {
    let body = json!({
        "host": {
            "enabled": "1",
            "hostname": hostname,
            "domain": domain,
            "rr": rr,
            "server": server,
            "description": description,
        }
    });
    let existing = list_host_overrides(client, cfg).await?;
    let matched = existing
        .into_iter()
        .find(|h| h.hostname == hostname && h.domain == domain)
        .and_then(|h| h.uuid);
    let uuid = match matched {
        Some(uuid) => {
            let url = cfg.api_url(&format!("unbound/settings/set_host_override/{uuid}"));
            post_write(client, &url, &body).await?;
            Some(uuid)
        }
        None => {
            let url = cfg.api_url("unbound/settings/add_host_override");
            post_write(client, &url, &body).await?
        }
    };
    Ok(HostOverride {
        uuid,
        enabled: "1".to_string(),
        hostname: hostname.to_string(),
        domain: domain.to_string(),
        rr: rr.to_string(),
        server: server.to_string(),
        description: description.to_string(),
    })
}

/// Delete the host override matching `(hostname, domain)`. Does NOT reconfigure.
pub async fn delete_host_override(
    client: &reqwest::Client,
    cfg: &Config,
    hostname: &str,
    domain: &str,
) -> Result<String, OpnsenseError> {
    let existing = list_host_overrides(client, cfg).await?;
    let uuid = existing
        .into_iter()
        .find(|h| h.hostname == hostname && h.domain == domain)
        .and_then(|h| h.uuid)
        .ok_or_else(|| OpnsenseError::NotFound {
            kind: "host override",
            selector: format!("{hostname}.{domain}"),
        })?;
    let url = cfg.api_url(&format!("unbound/settings/del_host_override/{uuid}"));
    post_write(client, &url, &json!({})).await?;
    Ok(uuid)
}

// ═══════════════════════════════════════════════════════════════════════════
// Unbound DNS-over-TLS upstreams
// ═══════════════════════════════════════════════════════════════════════════

/// `GET /api/unbound/settings/search_dot` — every DoT upstream.
pub async fn list_dot(
    client: &reqwest::Client,
    cfg: &Config,
) -> Result<Vec<DotUpstream>, OpnsenseError> {
    search(client, cfg, "unbound", "search_dot").await
}

/// Idempotent upsert of a DoT upstream keyed on `(server, domain)`. Does NOT
/// reconfigure.
#[allow(clippy::too_many_arguments)]
pub async fn set_dot(
    client: &reqwest::Client,
    cfg: &Config,
    server: &str,
    port: &str,
    domain: &str,
    verify: &str,
    description: &str,
) -> Result<DotUpstream, OpnsenseError> {
    let body = json!({
        "dot": {
            "enabled": "1",
            "type": "dot",
            "domain": domain,
            "server": server,
            "port": port,
            "verify": verify,
            "description": description,
        }
    });
    let existing = list_dot(client, cfg).await?;
    let matched = existing
        .into_iter()
        .find(|d| d.server == server && d.domain == domain)
        .and_then(|d| d.uuid);
    let uuid = match matched {
        Some(uuid) => {
            let url = cfg.api_url(&format!("unbound/settings/set_dot/{uuid}"));
            post_write(client, &url, &body).await?;
            Some(uuid)
        }
        None => {
            let url = cfg.api_url("unbound/settings/add_dot");
            post_write(client, &url, &body).await?
        }
    };
    Ok(DotUpstream {
        uuid,
        enabled: "1".to_string(),
        domain: domain.to_string(),
        server: server.to_string(),
        port: port.to_string(),
        verify: verify.to_string(),
        description: description.to_string(),
    })
}

/// Delete the DoT upstream matching `(server, domain)`. Does NOT reconfigure.
pub async fn delete_dot(
    client: &reqwest::Client,
    cfg: &Config,
    server: &str,
    domain: &str,
) -> Result<String, OpnsenseError> {
    let existing = list_dot(client, cfg).await?;
    let uuid = existing
        .into_iter()
        .find(|d| d.server == server && d.domain == domain)
        .and_then(|d| d.uuid)
        .ok_or_else(|| OpnsenseError::NotFound {
            kind: "dot upstream",
            selector: format!("{server} ({domain})"),
        })?;
    let url = cfg.api_url(&format!("unbound/settings/del_dot/{uuid}"));
    post_write(client, &url, &json!({})).await?;
    Ok(uuid)
}

// ═══════════════════════════════════════════════════════════════════════════
// Kea DHCPv4 reservations
// ═══════════════════════════════════════════════════════════════════════════

/// `GET /api/kea/dhcpv4/search_reservation` — every DHCP reservation.
pub async fn list_reservations(
    client: &reqwest::Client,
    cfg: &Config,
) -> Result<Vec<Reservation>, OpnsenseError> {
    let url = cfg.api_url("kea/dhcpv4/search_reservation");
    let result: SearchResult<Reservation> = get_json(client, &url).await?;
    Ok(result.rows)
}

/// Idempotent upsert of a Kea DHCP reservation keyed on `hw_address` (MAC). Does
/// NOT reconfigure.
pub async fn set_reservation(
    client: &reqwest::Client,
    cfg: &Config,
    subnet: &str,
    ip_address: &str,
    hw_address: &str,
    hostname: &str,
    description: &str,
) -> Result<Reservation, OpnsenseError> {
    let body = json!({
        "reservation": {
            "subnet": subnet,
            "ip_address": ip_address,
            "hw_address": hw_address,
            "hostname": hostname,
            "description": description,
        }
    });
    let existing = list_reservations(client, cfg).await?;
    let matched = existing
        .into_iter()
        .find(|r| r.hw_address.eq_ignore_ascii_case(hw_address))
        .and_then(|r| r.uuid);
    let uuid = match matched {
        Some(uuid) => {
            let url = cfg.api_url(&format!("kea/dhcpv4/set_reservation/{uuid}"));
            post_write(client, &url, &body).await?;
            Some(uuid)
        }
        None => {
            let url = cfg.api_url("kea/dhcpv4/add_reservation");
            post_write(client, &url, &body).await?
        }
    };
    Ok(Reservation {
        uuid,
        subnet: subnet.to_string(),
        ip_address: ip_address.to_string(),
        hw_address: hw_address.to_string(),
        hostname: hostname.to_string(),
        description: description.to_string(),
    })
}

/// Delete the DHCP reservation matching `hw_address` (MAC). Does NOT reconfigure.
pub async fn delete_reservation(
    client: &reqwest::Client,
    cfg: &Config,
    hw_address: &str,
) -> Result<String, OpnsenseError> {
    let existing = list_reservations(client, cfg).await?;
    let uuid = existing
        .into_iter()
        .find(|r| r.hw_address.eq_ignore_ascii_case(hw_address))
        .and_then(|r| r.uuid)
        .ok_or_else(|| OpnsenseError::NotFound {
            kind: "reservation",
            selector: hw_address.to_string(),
        })?;
    let url = cfg.api_url(&format!("kea/dhcpv4/del_reservation/{uuid}"));
    post_write(client, &url, &json!({})).await?;
    Ok(uuid)
}

// ═══════════════════════════════════════════════════════════════════════════
// Apply / status
// ═══════════════════════════════════════════════════════════════════════════

/// `POST /api/<module>/service/reconfigure` — apply staged settings so they take
/// effect. Every settings write must be followed by this on the owning module.
pub async fn reconfigure(
    client: &reqwest::Client,
    cfg: &Config,
    module: Module,
) -> Result<Value, OpnsenseError> {
    let url = cfg.api_url(&format!("{}/service/reconfigure", module.service_module()));
    post_json(client, &url, &json!({})).await
}

/// `GET /api/unbound/service/status` — Unbound resolver run state.
pub async fn status(client: &reqwest::Client, cfg: &Config) -> Result<ServiceState, OpnsenseError> {
    let url = cfg.api_url("unbound/service/status");
    get_json(client, &url).await
}

/// Standard-alphabet base64 for the Basic auth header. Hand-rolled to keep the
/// dependency set minimal (Basic auth is the only base64 use in the plugin).
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18 & 0x3f) as usize] as char);
        out.push(ALPHABET[(n >> 12 & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6 & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declares_provider() {
        let b = OpnsenseBackend::new("opnsense");
        assert_eq!(b.provider(), "opnsense");
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn auth_header_is_basic_scheme() {
        let cfg = Config::new("https://host", "key", "secret");
        // base64("key:secret")
        assert_eq!(cfg.auth_header_value(), "Basic a2V5OnNlY3JldA==");
    }

    #[test]
    fn api_url_joins_cleanly() {
        let cfg = Config::new("https://host/", "k", "s");
        assert_eq!(
            cfg.api_url("unbound/settings/search_host_override"),
            "https://host/api/unbound/settings/search_host_override"
        );
        assert_eq!(
            cfg.api_url("/kea/service/reconfigure"),
            "https://host/api/kea/service/reconfigure"
        );
    }

    #[test]
    fn module_service_paths() {
        assert_eq!(Module::Unbound.service_module(), "unbound");
        assert_eq!(Module::Dhcp.service_module(), "kea");
    }

    #[test]
    fn search_envelope_defaults_empty() {
        let empty: SearchResult<HostOverride> = plugin_toolkit::serde_json::from_str("{}").unwrap();
        assert!(empty.rows.is_empty());
    }

    #[test]
    fn host_override_row_parses() {
        let row: HostOverride = plugin_toolkit::serde_json::from_str(
            r#"{"uuid":"abc","enabled":"1","hostname":"gitea","domain":"example.com","rr":"A","server":"10.0.0.16","description":""}"#,
        )
        .unwrap();
        assert_eq!(row.uuid.as_deref(), Some("abc"));
        assert_eq!(row.hostname, "gitea");
        assert_eq!(row.server, "10.0.0.16");
    }
}
