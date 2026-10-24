use std::net::Ipv4Addr;

use plugin_toolkit::clap;
use plugin_toolkit::reqwest;
use plugin_toolkit::serde_json::{Value, json};
use serde::{Deserialize, Serialize};

use crate::plan::{Action, WritePlan};
use crate::{Config, OpnsenseError, SearchResult, get_json, post_json, post_write};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, clap::ValueEnum,
)]
#[serde(rename_all = "snake_case")]
pub enum NatProtocol {
    Tcp,
    Udp,
    #[value(name = "tcp/udp")]
    #[serde(rename = "tcp/udp")]
    TcpUdp,
}

impl NatProtocol {
    fn wire(self) -> &'static str {
        match self {
            NatProtocol::Tcp => "tcp",
            NatProtocol::Udp => "udp",
            NatProtocol::TcpUdp => "tcp/udp",
        }
    }

    fn from_wire(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "tcp" => Some(NatProtocol::Tcp),
            "udp" => Some(NatProtocol::Udp),
            "tcp/udp" => Some(NatProtocol::TcpUdp),
            _ => None,
        }
    }
}
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, clap::ValueEnum,
)]
#[serde(rename_all = "snake_case")]
pub enum FilterRule {
    Pass,
    Rule,
    Manual,
}

impl FilterRule {
    fn wire(self) -> &'static str {
        match self {
            FilterRule::Pass => "pass",
            FilterRule::Rule => "rule",
            FilterRule::Manual => "",
        }
    }

    fn from_wire(s: &str) -> Self {
        match s {
            "pass" => FilterRule::Pass,
            "rule" => FilterRule::Rule,
            _ => FilterRule::Manual,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PortForward {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    pub enabled: bool,
    pub interface: String,
    pub ip_protocol: String,
    pub protocol: Option<NatProtocol>,
    pub destination: String,
    pub destination_port: String,
    pub target: String,
    pub target_port: String,
    pub description: String,
    pub filter_rule: FilterRule,
}

impl PortForward {
    fn from_row(row: &Value) -> Self {
        let s = |k: &str| match row.get(k) {
            Some(Value::String(v)) => v.clone(),
            Some(Value::Number(n)) => n.to_string(),
            _ => String::new(),
        };
        PortForward {
            uuid: Some(s("uuid")).filter(|u| !u.is_empty()),
            enabled: s("disabled") != "1",
            interface: s("interface"),
            ip_protocol: s("ipprotocol"),
            protocol: NatProtocol::from_wire(&s("protocol")),
            destination: s("destination.network"),
            destination_port: s("destination.port"),
            target: s("target"),
            target_port: s("local-port"),
            description: s("descr"),
            filter_rule: FilterRule::from_wire(&s("pass")),
        }
    }

    fn same_settings(&self, other: &PortForward) -> bool {
        self.enabled == other.enabled
            && self.interface == other.interface
            && self.ip_protocol == other.ip_protocol
            && self.protocol == other.protocol
            && self.destination == other.destination
            && self.destination_port == other.destination_port
            && self.target == other.target
            && self.target_port == other.target_port
            && self.filter_rule == other.filter_rule
    }

    fn body(&self) -> Value {
        json!({
            "rule": {
                "disabled": if self.enabled { "0" } else { "1" },
                "interface": self.interface,
                "ipprotocol": self.ip_protocol,
                "protocol": self.protocol.map(NatProtocol::wire).unwrap_or_default(),
                "destination": {
                    "network": self.destination,
                    "port": self.destination_port,
                },
                "target": self.target,
                "local-port": self.target_port,
                "descr": self.description,
                "pass": self.filter_rule.wire(),
            }
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ApplyResult {
    pub revision: Option<String>,
    pub rollback_protected: bool,
    pub status: Value,
}

#[derive(Debug, Clone, Default)]
pub struct WriteOptions {
    pub execute: bool,
    pub adopt: bool,
    pub allow_unprotected: bool,
    pub management_ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct NatWritePlan {
    #[serde(flatten)]
    pub plan: WritePlan<PortForward>,
    pub apply: Option<ApplyResult>,
}

fn invalid(msg: String) -> OpnsenseError {
    OpnsenseError::InvalidArgument(msg)
}

pub fn validate_description(d: &str) -> Result<(), OpnsenseError> {
    let ok = !d.trim().is_empty()
        && marked(d).len() <= 255
        && d.chars()
            .all(|c| c.is_ascii_alphanumeric() || " ._-:/()@,+".contains(c));
    if ok {
        Ok(())
    } else {
        Err(invalid(format!(
            "description {d:?} must be 1-250 chars (255 with the orca: prefix) of [A-Za-z0-9 ._-:/()@,+]"
        )))
    }
}

pub fn validate_interface(i: &str) -> Result<(), OpnsenseError> {
    let ok = !i.is_empty()
        && i.len() <= 32
        && i.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_');
    if ok {
        Ok(())
    } else {
        Err(invalid(format!(
            "interface {i:?} must be an OPNsense interface id like wan, lan, opt1"
        )))
    }
}
pub fn validate_destination(d: &str) -> Result<(), OpnsenseError> {
    if d == "any" || d.parse::<Ipv4Addr>().is_ok() {
        return Ok(());
    }
    if let Some((ip, bits)) = d.split_once('/') {
        if ip.parse::<Ipv4Addr>().is_ok() && bits.parse::<u8>().is_ok_and(|b| b <= 32) {
            return Ok(());
        }
        return Err(invalid(format!(
            "destination {d:?} is not a valid IPv4 CIDR"
        )));
    }
    crate::validate_alias_name(d).map_err(|_| {
        invalid(format!(
            "destination {d:?} must be any, IPv4, IPv4/CIDR, or an alias/network name"
        ))
    })
}

fn port(s: &str) -> Option<u16> {
    if s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    s.parse::<u16>().ok().filter(|p| *p >= 1)
}
pub fn validate_port_range(p: &str) -> Result<(), OpnsenseError> {
    let ok = match p.split_once('-') {
        Some((a, b)) => matches!((port(a), port(b)), (Some(a), Some(b)) if a <= b),
        None => port(p).is_some(),
    };
    if ok {
        Ok(())
    } else {
        Err(invalid(format!(
            "port {p:?} must be N or N-M with 1 <= N <= M <= 65535"
        )))
    }
}

pub fn validate_target_port(p: &str) -> Result<(), OpnsenseError> {
    port(p)
        .map(|_| ())
        .ok_or_else(|| invalid(format!("target port {p:?} must be 1-65535")))
}

pub fn validate(rule: &PortForward) -> Result<(), OpnsenseError> {
    validate_description(&rule.description)?;
    validate_interface(&rule.interface)?;
    if rule.ip_protocol != "inet" {
        return Err(invalid(format!(
            "ip protocol {:?} unsupported; only inet (IPv4) is managed",
            rule.ip_protocol
        )));
    }
    if rule.protocol.is_none() {
        return Err(invalid("protocol is required".into()));
    }
    validate_destination(&rule.destination)?;
    validate_port_range(&rule.destination_port)?;
    rule.target
        .parse::<Ipv4Addr>()
        .map_err(|_| invalid(format!("target {:?} must be an IPv4 address", rule.target)))?;
    validate_target_port(&rule.target_port)
}
pub const MARKER: &str = "orca:";

pub fn marked(description: &str) -> String {
    if description.starts_with(MARKER) {
        description.to_string()
    } else {
        format!("{MARKER}{description}")
    }
}

pub const DEFAULT_MANAGEMENT_PORTS: [u16; 3] = [22, 80, 443];

pub fn parse_management_ports(raw: Option<&str>) -> Result<Vec<u16>, OpnsenseError> {
    let mut ports = DEFAULT_MANAGEMENT_PORTS.to_vec();
    for part in raw
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        let p = port(part)
            .ok_or_else(|| invalid(format!("management port {part:?} must be 1-65535")))?;
        if !ports.contains(&p) {
            ports.push(p);
        }
    }
    Ok(ports)
}

fn port_bounds(p: &str) -> Option<(u16, u16)> {
    match p.split_once('-') {
        Some((a, b)) => Some((port(a)?, port(b)?)),
        None => port(p).map(|p| (p, p)),
    }
}

fn literal_host(destination: &str) -> Option<Ipv4Addr> {
    destination
        .strip_suffix("/32")
        .unwrap_or(destination)
        .parse()
        .ok()
}

pub fn guard_management(
    rule: &PortForward,
    management_ports: &[u16],
) -> Result<Option<Ipv4Addr>, OpnsenseError> {
    if rule.interface == "wan" {
        return Ok(None);
    }
    let (lo, hi) = port_bounds(&rule.destination_port).ok_or_else(|| {
        invalid(format!(
            "port {:?} is not a port or range",
            rule.destination_port
        ))
    })?;
    let mut ports = DEFAULT_MANAGEMENT_PORTS.iter().chain(management_ports);
    let Some(p) = ports.find(|p| (lo..=hi).contains(*p)) else {
        return Ok(None);
    };
    literal_host(&rule.destination).map(Some).ok_or_else(|| {
        invalid(format!(
            "refusing a forward of {} port {p} on non-WAN interface {:?}: only a literal host address that is not the firewall may be forwarded on a management port",
            rule.destination, rule.interface
        ))
    })
}

pub async fn ensure_not_firewall_address(
    client: &reqwest::Client,
    cfg: &Config,
    ip: Ipv4Addr,
) -> Result<(), OpnsenseError> {
    let details: Value = get_json(
        client,
        &cfg.api_url("diagnostics/interface/get_interface_config"),
    )
    .await?;
    let Some(devices) = details.as_object() else {
        return Err(OpnsenseError::Malformed(format!(
            "interface config is not an object: {details}"
        )));
    };
    let own = devices
        .values()
        .filter_map(|d| d.get("ipv4").and_then(Value::as_array))
        .flatten()
        .filter_map(|a| a.get("ipaddr").and_then(Value::as_str))
        .any(|a| a.parse::<Ipv4Addr>().ok() == Some(ip));
    if own {
        Err(invalid(format!(
            "refusing a management-port forward to {ip}: it is a firewall interface address"
        )))
    } else {
        Ok(())
    }
}

pub async fn list_port_forwards(
    client: &reqwest::Client,
    cfg: &Config,
) -> Result<Vec<PortForward>, OpnsenseError> {
    let url = cfg.api_url("firewall/d_nat/search_rule?current=1&rowCount=-1");
    let result: SearchResult<Value> = get_json(client, &url).await?;
    Ok(result
        .rows
        .iter()
        .filter(|r| !crate::truthy(r.get("is_automatic").unwrap_or(&Value::Null)))
        .map(PortForward::from_row)
        .collect())
}

fn single(rules: &[PortForward], description: &str) -> Result<Option<PortForward>, OpnsenseError> {
    let matches: Vec<&PortForward> = rules
        .iter()
        .filter(|r| r.description == description)
        .collect();
    match matches.as_slice() {
        [] => Ok(None),
        [one] => Ok(Some((*one).clone())),
        many => Err(invalid(format!(
            "{} port forwards share description {description:?}; resolve the duplicates first",
            many.len()
        ))),
    }
}

async fn find_owned(
    client: &reqwest::Client,
    cfg: &Config,
    description: &str,
    adopt: bool,
) -> Result<Option<PortForward>, OpnsenseError> {
    let rules = list_port_forwards(client, cfg).await?;
    let key = marked(description);
    if let Some(owned) = single(&rules, &key)? {
        return Ok(Some(owned));
    }
    if key == description {
        return Ok(None);
    }
    match single(&rules, description)? {
        Some(_) if !adopt => Err(invalid(format!(
            "port forward {description:?} is not orca-owned (no {MARKER:?} prefix); pass adopt to take it over"
        ))),
        found => Ok(found),
    }
}

fn rule_uuid(rule: &PortForward) -> Result<&str, OpnsenseError> {
    rule.uuid
        .as_deref()
        .filter(|u| u.bytes().all(|c| c.is_ascii_hexdigit() || c == b'-'))
        .ok_or_else(|| {
            OpnsenseError::Malformed(format!("rule {:?} has no usable uuid", rule.description))
        })
}

async fn savepoint(
    client: &reqwest::Client,
    cfg: &Config,
) -> Result<Option<String>, OpnsenseError> {
    match post_json(client, &cfg.api_url("firewall/d_nat/savepoint"), &json!({})).await {
        Ok(v) => v
            .get("revision")
            .and_then(Value::as_str)
            .filter(|r| !r.is_empty() && r.bytes().all(|c| c.is_ascii_digit() || c == b'.'))
            .map(|r| Some(r.to_string()))
            .ok_or_else(|| {
                OpnsenseError::Malformed(format!("savepoint returned no revision: {v}"))
            }),
        Err(OpnsenseError::Api { status: 404, .. }) => Ok(None),
        Err(e) => Err(e),
    }
}

const APPLIED: &str = "OK";
const ROLLBACK_CANCELLED: &str = "";
const REVERTED: &str = "ok";

fn status_is(v: &Value, expected: &str) -> bool {
    v.get("status")
        .and_then(Value::as_str)
        .is_some_and(|s| s.trim() == expected)
}

async fn post_ok(
    client: &reqwest::Client,
    cfg: &Config,
    path: &str,
    expected: &str,
) -> Result<Value, OpnsenseError> {
    let v = post_json(client, &cfg.api_url(path), &json!({})).await?;
    if status_is(&v, expected) {
        Ok(v)
    } else {
        Err(OpnsenseError::Rejected {
            result: v.get("status").map(Value::to_string).unwrap_or_default(),
            body: v.to_string(),
        })
    }
}

async fn revert(client: &reqwest::Client, cfg: &Config, revision: &str) -> String {
    match post_ok(
        client,
        cfg,
        &format!("firewall/d_nat/revert/{revision}"),
        REVERTED,
    )
    .await
    {
        Ok(_) => format!("reverted to savepoint {revision}"),
        Err(e) => format!("NOT reverted to savepoint {revision}: {e}"),
    }
}

async fn guarded_write(
    client: &reqwest::Client,
    cfg: &Config,
    interface: &str,
    allow_unprotected: bool,
    write: impl AsyncFnOnce() -> Result<Option<String>, OpnsenseError>,
) -> Result<(Option<String>, ApplyResult), OpnsenseError> {
    let revision = savepoint(client, cfg).await?;
    if revision.is_none() && interface != "wan" && !allow_unprotected {
        return Err(invalid(format!(
            "appliance has no savepoint/rollback; refusing an unguarded change on non-WAN interface {interface:?} without allow_unprotected"
        )));
    }
    let uuid = match write().await {
        Ok(uuid) => uuid,
        Err(e) => {
            return Err(match &revision {
                Some(rev) => {
                    OpnsenseError::Transport(format!("{e}; {}", revert(client, cfg, rev).await))
                }
                None => e,
            });
        }
    };
    let Some(rev) = revision else {
        let status = post_ok(client, cfg, "firewall/d_nat/apply", APPLIED)
            .await
            .map_err(|e| OpnsenseError::NotApplied {
                uuid: uuid.clone().unwrap_or_default(),
                reason: e.to_string(),
            })?;
        return Ok((
            uuid,
            ApplyResult {
                revision: None,
                rollback_protected: false,
                status,
            },
        ));
    };
    let status = match post_ok(client, cfg, &format!("firewall/d_nat/apply/{rev}"), APPLIED).await {
        Ok(s) => s,
        Err(e) => {
            return Err(OpnsenseError::NotApplied {
                uuid: uuid.unwrap_or_default(),
                reason: format!("{e}; {}", revert(client, cfg, &rev).await),
            });
        }
    };
    if let Err(e) = list_port_forwards(client, cfg).await {
        return Err(OpnsenseError::RollbackArmed {
            revision: rev,
            reason: e.to_string(),
        });
    }
    if let Err(e) = post_ok(
        client,
        cfg,
        &format!("firewall/d_nat/cancel_rollback/{rev}"),
        ROLLBACK_CANCELLED,
    )
    .await
    {
        return Err(OpnsenseError::RollbackArmed {
            revision: rev,
            reason: format!("cancel_rollback failed: {e}"),
        });
    }
    Ok((
        uuid,
        ApplyResult {
            revision: Some(rev),
            rollback_protected: true,
            status,
        },
    ))
}

const APPLY_STEPS: [&str; 3] = [
    "POST firewall/d_nat/apply/<savepoint>",
    "GET firewall/d_nat/search_rule (health)",
    "POST firewall/d_nat/cancel_rollback/<savepoint>",
];

fn steps(write: String) -> Vec<String> {
    let mut s = vec!["POST firewall/d_nat/savepoint".to_string(), write];
    s.extend(APPLY_STEPS.iter().map(|x| x.to_string()));
    s
}

pub async fn plan_set(
    client: &reqwest::Client,
    cfg: &Config,
    mut desired: PortForward,
    adopt: bool,
    execute: bool,
    management_ports: &[u16],
) -> Result<NatWritePlan, OpnsenseError> {
    validate(&desired)?;
    if let Some(ip) = guard_management(&desired, management_ports)? {
        ensure_not_firewall_address(client, cfg, ip).await?;
    }
    let current = find_owned(client, cfg, &desired.description, adopt).await?;
    desired.description = marked(&desired.description);
    let (action, steps) = match &current {
        Some(c) if c.same_settings(&desired) && c.description == desired.description => {
            (Action::Unchanged, Vec::new())
        }
        Some(c) => (
            Action::Update,
            steps(format!("POST firewall/d_nat/set_rule/{}", rule_uuid(c)?)),
        ),
        None => (Action::Create, steps("POST firewall/d_nat/add_rule".into())),
    };
    Ok(NatWritePlan {
        plan: WritePlan {
            action,
            current,
            desired: Some(desired),
            dry_run: !execute,
            executed: false,
            steps,
        },
        apply: None,
    })
}

pub async fn set_port_forward(
    client: &reqwest::Client,
    cfg: &Config,
    desired: PortForward,
    opts: WriteOptions,
) -> Result<NatWritePlan, OpnsenseError> {
    let mut out = plan_set(
        client,
        cfg,
        desired,
        opts.adopt,
        opts.execute,
        &opts.management_ports,
    )
    .await?;
    if !opts.execute || out.plan.action == Action::Unchanged {
        return Ok(out);
    }
    let Some(desired) = out.plan.desired.clone() else {
        return Ok(out);
    };
    let existing = out
        .plan
        .current
        .as_ref()
        .map(rule_uuid)
        .transpose()?
        .map(str::to_string);
    let body = desired.body();
    let (uuid, applied) = guarded_write(
        client,
        cfg,
        &desired.interface,
        opts.allow_unprotected,
        async || match &existing {
            Some(uuid) => {
                post_write(
                    client,
                    &cfg.api_url(&format!("firewall/d_nat/set_rule/{uuid}")),
                    &body,
                )
                .await?;
                Ok(Some(uuid.clone()))
            }
            None => post_write(client, &cfg.api_url("firewall/d_nat/add_rule"), &body).await,
        },
    )
    .await?;
    out.plan.desired = Some(PortForward { uuid, ..desired });
    out.plan.executed = true;
    out.apply = Some(applied);
    Ok(out)
}

pub async fn plan_delete(
    client: &reqwest::Client,
    cfg: &Config,
    description: &str,
    adopt: bool,
    execute: bool,
) -> Result<NatWritePlan, OpnsenseError> {
    validate_description(description)?;
    let current = find_owned(client, cfg, description, adopt).await?;
    let (action, steps) = match &current {
        Some(c) => (
            Action::Delete,
            steps(format!("POST firewall/d_nat/del_rule/{}", rule_uuid(c)?)),
        ),
        None => (Action::Absent, Vec::new()),
    };
    Ok(NatWritePlan {
        plan: WritePlan {
            action,
            current,
            desired: None,
            dry_run: !execute,
            executed: false,
            steps,
        },
        apply: None,
    })
}

pub async fn delete_port_forward(
    client: &reqwest::Client,
    cfg: &Config,
    description: &str,
    opts: WriteOptions,
) -> Result<NatWritePlan, OpnsenseError> {
    let mut out = plan_delete(client, cfg, description, opts.adopt, opts.execute).await?;
    if !opts.execute {
        return Ok(out);
    }
    let Some(current) = out.plan.current.clone() else {
        return Err(OpnsenseError::NotFound {
            kind: "port forward",
            selector: description.to_string(),
        });
    };
    let uuid = rule_uuid(&current)?.to_string();
    let (_, applied) = guarded_write(
        client,
        cfg,
        &current.interface,
        opts.allow_unprotected,
        async || {
            post_write(
                client,
                &cfg.api_url(&format!("firewall/d_nat/del_rule/{uuid}")),
                &json!({}),
            )
            .await?;
            Ok(Some(uuid.clone()))
        },
    )
    .await?;
    out.plan.executed = true;
    out.apply = Some(applied);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use plugin_toolkit::abi::{HttpRequest, HttpResponse};
    use std::sync::{Arc, Mutex};

    type Call = (String, String, String);
    type Calls = Arc<Mutex<Vec<Call>>>;

    fn with_mock<T>(
        routes: &[(&str, &str, u16, &str)],
        f: impl AsyncFnOnce(&reqwest::Client, &Config) -> Result<T, OpnsenseError>,
    ) -> (Result<T, OpnsenseError>, Vec<Call>) {
        let routes: Vec<(String, String, u16, String)> = routes
            .iter()
            .map(|(m, p, s, b)| (m.to_string(), p.to_string(), *s, b.to_string()))
            .collect();
        let calls: Calls = Arc::default();
        let log = calls.clone();
        let sink = Box::new(move |cap: &str, op: &str| {
            assert_eq!(cap, "http.request");
            let req: HttpRequest = plugin_toolkit::serde_json::from_str(op).unwrap();
            let body = String::from_utf8(req.body.clone()).unwrap();
            log.lock()
                .unwrap()
                .push((req.method.clone(), req.url.clone(), body));
            let (_, _, status, body) = routes
                .iter()
                .find(|(m, suffix, _, _)| *m == req.method && req.url.ends_with(suffix.as_str()))
                .unwrap_or_else(|| panic!("unexpected request {} {}", req.method, req.url));
            Ok::<String, String>(
                plugin_toolkit::serde_json::to_string(&HttpResponse {
                    status: *status,
                    headers: vec![],
                    body: body.as_bytes().to_vec(),
                })
                .unwrap(),
            )
        });
        let cfg = Config::new("https://10.0.0.1", "k", "s").insecure(true);
        let result = plugin_toolkit::capsink::with_cap_sink(sink, || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            rt.block_on(async {
                let client = cfg.build_client()?;
                f(&client, &cfg).await
            })
        });
        let calls = calls.lock().unwrap().clone();
        (result, calls)
    }

    fn with_stateful_mock<T>(
        respond: impl Fn(&str, &str, usize) -> (u16, String) + Send + Sync + 'static,
        f: impl AsyncFnOnce(&reqwest::Client, &Config) -> Result<T, OpnsenseError>,
    ) -> (Result<T, OpnsenseError>, Vec<String>) {
        let calls: Calls = Arc::default();
        let log = calls.clone();
        let sink = Box::new(move |_cap: &str, op: &str| {
            let req: HttpRequest = plugin_toolkit::serde_json::from_str(op).unwrap();
            let mut log = log.lock().unwrap();
            let seen = log
                .iter()
                .filter(|(m, u, _)| *m == req.method && *u == req.url)
                .count();
            log.push((req.method.clone(), req.url.clone(), String::new()));
            let (status, body) = respond(&req.method, &req.url, seen);
            Ok::<String, String>(
                plugin_toolkit::serde_json::to_string(&HttpResponse {
                    status,
                    headers: vec![],
                    body: body.into_bytes(),
                })
                .unwrap(),
            )
        });
        let cfg = Config::new("https://10.0.0.1", "k", "s").insecure(true);
        let result = plugin_toolkit::capsink::with_cap_sink(sink, || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            rt.block_on(async {
                let client = cfg.build_client()?;
                f(&client, &cfg).await
            })
        });
        let calls = calls.lock().unwrap().clone();
        (result, paths(&calls))
    }

    const SEARCH: &str = "/firewall/d_nat/search_rule?current=1&rowCount=-1";
    const UUID: &str = "aaaa-1111";

    fn row(descr: &str, target: &str) -> Value {
        json!({
            "uuid": UUID, "disabled": "0", "interface": "wan", "ipprotocol": "inet",
            "protocol": "tcp", "destination.network": "wanip", "destination.port": "443",
            "target": target, "local-port": "443", "descr": descr, "pass": "pass",
        })
    }

    fn search(rows: &[Value]) -> String {
        let mut all = vec![json!({
            "uuid": "lockout_0", "is_automatic": true, "descr": "Anti-Lockout Rule",
            "interface": "lan", "protocol": "tcp", "destination.port": "443"
        })];
        all.extend_from_slice(rows);
        json!({ "rows": all, "total": all.len() }).to_string()
    }

    fn desired(target: &str) -> PortForward {
        PortForward {
            uuid: None,
            enabled: true,
            interface: "wan".into(),
            ip_protocol: "inet".into(),
            protocol: Some(NatProtocol::Tcp),
            destination: "wanip".into(),
            destination_port: "443".into(),
            target: target.into(),
            target_port: "443".into(),
            description: "orca https".into(),
            filter_rule: FilterRule::Pass,
        }
    }

    const REV: &str = "1729700000.12";
    const SAVEPOINT: &str = r#"{"status":"ok","retention":"60","revision":"1729700000.12"}"#;
    const SAVED: &str = r#"{"result":"saved","uuid":"bbbb-2222"}"#;
    const OK: &str = "{\"status\":\"OK\\n\\n\"}";
    const CANCELLED: &str = r#"{"status":"\n\n"}"#;
    const OWNED: &str = "orca:orca https";

    type Route = (&'static str, String, u16, String);

    fn r(m: &'static str, p: &str, s: u16, b: &str) -> Route {
        (m, p.to_string(), s, b.to_string())
    }

    fn guarded_routes(write: Route) -> Vec<Route> {
        vec![
            r("POST", "/firewall/d_nat/savepoint", 200, SAVEPOINT),
            write,
            r("POST", &format!("/firewall/d_nat/apply/{REV}"), 200, OK),
            r(
                "POST",
                &format!("/firewall/d_nat/cancel_rollback/{REV}"),
                200,
                CANCELLED,
            ),
        ]
    }

    fn run<T>(
        search_body: &str,
        extra: Vec<Route>,
        f: impl AsyncFnOnce(&reqwest::Client, &Config) -> Result<T, OpnsenseError>,
    ) -> (Result<T, OpnsenseError>, Vec<String>, Vec<Call>) {
        let mut routes = vec![r("GET", SEARCH, 200, search_body)];
        routes.extend(extra);
        let borrowed: Vec<(&str, &str, u16, &str)> = routes
            .iter()
            .map(|(m, p, s, b)| (*m, p.as_str(), *s, b.as_str()))
            .collect();
        let (got, calls) = with_mock(&borrowed, f);
        (got, paths(&calls), calls)
    }

    fn exec() -> WriteOptions {
        WriteOptions {
            execute: true,
            ..WriteOptions::default()
        }
    }

    fn paths(calls: &[Call]) -> Vec<String> {
        calls
            .iter()
            .map(|(m, u, _)| format!("{m} {}", u.trim_start_matches("https://10.0.0.1/api/")))
            .collect()
    }

    fn search_path() -> String {
        format!("GET {}", SEARCH.trim_start_matches('/'))
    }

    #[test]
    fn list_drops_automatic_rows_and_maps_fields() {
        let body = search(&[row(OWNED, "10.0.0.5")]);
        let (got, _, _) = run(&body, vec![], async |c, cfg| {
            list_port_forwards(c, cfg).await
        });
        let got = got.unwrap();
        assert_eq!(got.len(), 1);
        let mut expected = desired("10.0.0.5");
        expected.uuid = Some(UUID.into());
        expected.description = OWNED.into();
        assert_eq!(got[0], expected);
    }

    #[test]
    fn dry_run_reports_create_without_writing() {
        let (got, paths, _) = run(&search(&[]), vec![], async |c, cfg| {
            set_port_forward(c, cfg, desired("10.0.0.5"), WriteOptions::default()).await
        });
        let got = got.unwrap();
        assert_eq!(got.plan.action, Action::Create);
        assert!(got.plan.dry_run && !got.plan.executed);
        assert_eq!(got.plan.desired.unwrap().description, OWNED);
        assert_eq!(got.plan.steps[0], "POST firewall/d_nat/savepoint");
        assert_eq!(paths, vec![search_path()]);
    }

    #[test]
    fn dry_run_reports_update_with_current_and_desired() {
        let body = search(&[row(OWNED, "10.0.0.5")]);
        let (got, paths, _) = run(&body, vec![], async |c, cfg| {
            set_port_forward(c, cfg, desired("10.0.0.6"), WriteOptions::default()).await
        });
        let got = got.unwrap();
        assert_eq!(got.plan.action, Action::Update);
        assert_eq!(got.plan.current.unwrap().target, "10.0.0.5");
        assert_eq!(got.plan.desired.unwrap().target, "10.0.0.6");
        assert_eq!(paths.len(), 1);
    }

    #[test]
    fn set_takes_savepoint_before_creating_then_applies_and_confirms() {
        let (got, paths, calls) = run(
            &search(&[]),
            guarded_routes(r("POST", "/firewall/d_nat/add_rule", 200, SAVED)),
            async |c, cfg| set_port_forward(c, cfg, desired("10.0.0.5"), exec()).await,
        );
        let got = got.unwrap();
        assert_eq!(got.plan.action, Action::Create);
        assert!(got.plan.executed);
        assert_eq!(got.plan.desired.unwrap().uuid.as_deref(), Some("bbbb-2222"));
        assert!(got.apply.unwrap().rollback_protected);
        assert_eq!(
            paths,
            vec![
                search_path(),
                "POST firewall/d_nat/savepoint".into(),
                "POST firewall/d_nat/add_rule".into(),
                format!("POST firewall/d_nat/apply/{REV}"),
                search_path(),
                format!("POST firewall/d_nat/cancel_rollback/{REV}"),
            ]
        );
        let sent: Value = plugin_toolkit::serde_json::from_str(&calls[2].2).unwrap();
        assert_eq!(sent["rule"]["descr"], OWNED);
        assert_eq!(sent["rule"]["destination"]["network"], "wanip");
        assert_eq!(sent["rule"]["local-port"], "443");
        assert_eq!(sent["rule"]["protocol"], "tcp");
        assert_eq!(sent["rule"]["pass"], "pass");
        assert_eq!(sent["rule"]["disabled"], "0");
    }

    #[test]
    fn health_failure_after_apply_returns_rollback_armed_with_savepoint_revision() {
        let mock = |method: &str, url: &str, n: usize| -> (u16, String) {
            match (method, url) {
                ("GET", u) if u.ends_with(SEARCH) && n == 0 => (200, search(&[])),
                ("GET", u) if u.ends_with(SEARCH) => (502, "bad gateway".into()),
                ("POST", u) if u.ends_with("/savepoint") => (200, SAVEPOINT.into()),
                ("POST", u) if u.ends_with("/add_rule") => (200, SAVED.into()),
                ("POST", u) if u.ends_with(&format!("/apply/{REV}")) => (200, OK.into()),
                _ => panic!("unexpected {method} {url}"),
            }
        };
        let (got, p) = with_stateful_mock(mock, async |c, cfg| {
            set_port_forward(c, cfg, desired("10.0.0.5"), exec()).await
        });
        match got {
            Err(OpnsenseError::RollbackArmed { revision, .. }) => assert_eq!(revision, REV),
            other => panic!("expected RollbackArmed, got {other:?}"),
        }
        let sp = p.iter().position(|x| x.ends_with("savepoint")).unwrap();
        let add = p.iter().position(|x| x.ends_with("add_rule")).unwrap();
        assert!(sp < add);
        assert!(!p.iter().any(|x| x.contains("cancel_rollback")));
    }

    #[test]
    fn write_failure_after_savepoint_reverts_to_it() {
        let (got, paths, _) = run(
            &search(&[]),
            vec![
                r("POST", "/firewall/d_nat/savepoint", 200, SAVEPOINT),
                r(
                    "POST",
                    "/firewall/d_nat/add_rule",
                    200,
                    r#"{"result":"failed"}"#,
                ),
                r(
                    "POST",
                    &format!("/firewall/d_nat/revert/{REV}"),
                    200,
                    r#"{"status":"ok"}"#,
                ),
            ],
            async |c, cfg| set_port_forward(c, cfg, desired("10.0.0.5"), exec()).await,
        );
        assert!(got.is_err());
        assert_eq!(
            paths.last().unwrap(),
            &format!("POST firewall/d_nat/revert/{REV}")
        );
        assert!(!paths.iter().any(|x| x.contains("/apply")));
    }

    #[test]
    fn apply_failure_reverts_and_reports_not_applied() {
        let (got, paths, _) = run(
            &search(&[]),
            vec![
                r("POST", "/firewall/d_nat/savepoint", 200, SAVEPOINT),
                r("POST", "/firewall/d_nat/add_rule", 200, SAVED),
                r("POST", &format!("/firewall/d_nat/apply/{REV}"), 500, "boom"),
                r(
                    "POST",
                    &format!("/firewall/d_nat/revert/{REV}"),
                    200,
                    r#"{"status":"ok"}"#,
                ),
            ],
            async |c, cfg| set_port_forward(c, cfg, desired("10.0.0.5"), exec()).await,
        );
        match got {
            Err(OpnsenseError::NotApplied { uuid, reason }) => {
                assert_eq!(uuid, "bbbb-2222");
                assert!(reason.contains("reverted"));
            }
            other => panic!("expected NotApplied, got {other:?}"),
        }
        assert!(paths.iter().any(|x| x.ends_with(&format!("revert/{REV}"))));
    }

    #[test]
    fn set_updates_owned_rule_by_description() {
        let body = search(&[row(OWNED, "10.0.0.5")]);
        let (got, paths, _) = run(
            &body,
            guarded_routes(r(
                "POST",
                "/firewall/d_nat/set_rule/aaaa-1111",
                200,
                r#"{"result":"saved"}"#,
            )),
            async |c, cfg| set_port_forward(c, cfg, desired("10.0.0.6"), exec()).await,
        );
        let got = got.unwrap();
        assert_eq!(got.plan.action, Action::Update);
        assert_eq!(got.plan.desired.unwrap().uuid.as_deref(), Some(UUID));
        assert!(paths.contains(&"POST firewall/d_nat/set_rule/aaaa-1111".to_string()));
    }

    #[test]
    fn set_refuses_unowned_rule_without_adopt() {
        let body = search(&[row("orca https", "10.0.0.5")]);
        let (got, paths, _) = run(&body, vec![], async |c, cfg| {
            set_port_forward(c, cfg, desired("10.0.0.6"), exec()).await
        });
        assert!(matches!(got, Err(OpnsenseError::InvalidArgument(m)) if m.contains("adopt")));
        assert_eq!(paths.len(), 1);
    }

    #[test]
    fn adopt_takes_over_and_marks_unowned_rule() {
        let body = search(&[row("orca https", "10.0.0.5")]);
        let (got, _, calls) = run(
            &body,
            guarded_routes(r(
                "POST",
                "/firewall/d_nat/set_rule/aaaa-1111",
                200,
                r#"{"result":"saved"}"#,
            )),
            async |c, cfg| {
                let opts = WriteOptions {
                    adopt: true,
                    ..exec()
                };
                set_port_forward(c, cfg, desired("10.0.0.5"), opts).await
            },
        );
        assert_eq!(got.unwrap().plan.action, Action::Update);
        let sent: Value = plugin_toolkit::serde_json::from_str(&calls[2].2).unwrap();
        assert_eq!(sent["rule"]["descr"], OWNED);
    }

    #[test]
    fn set_unchanged_rule_writes_nothing() {
        let body = search(&[row(OWNED, "10.0.0.5")]);
        let (got, paths, _) = run(&body, vec![], async |c, cfg| {
            set_port_forward(c, cfg, desired("10.0.0.5"), exec()).await
        });
        let got = got.unwrap();
        assert_eq!(got.plan.action, Action::Unchanged);
        assert!(got.apply.is_none());
        assert_eq!(paths.len(), 1);
    }

    #[test]
    fn set_refuses_duplicate_descriptions() {
        let body = search(&[row(OWNED, "10.0.0.5"), row(OWNED, "10.0.0.6")]);
        let (got, paths, _) = run(&body, vec![], async |c, cfg| {
            set_port_forward(c, cfg, desired("10.0.0.7"), exec()).await
        });
        assert!(matches!(got, Err(OpnsenseError::InvalidArgument(_))));
        assert_eq!(paths.len(), 1);
    }

    #[test]
    fn delete_takes_savepoint_before_removing_owned_rule() {
        let body = search(&[row(OWNED, "10.0.0.5")]);
        let (got, paths, _) = run(
            &body,
            guarded_routes(r(
                "POST",
                "/firewall/d_nat/del_rule/aaaa-1111",
                200,
                r#"{"result":"deleted"}"#,
            )),
            async |c, cfg| delete_port_forward(c, cfg, "orca https", exec()).await,
        );
        let got = got.unwrap();
        assert_eq!(got.plan.action, Action::Delete);
        assert!(got.apply.unwrap().rollback_protected);
        let sp = paths.iter().position(|x| x.ends_with("savepoint")).unwrap();
        let del = paths.iter().position(|x| x.contains("del_rule")).unwrap();
        assert!(sp < del);
    }

    #[test]
    fn delete_dry_run_and_missing_rule() {
        let body = search(&[row(OWNED, "10.0.0.5")]);
        let (got, paths, _) = run(&body, vec![], async |c, cfg| {
            delete_port_forward(c, cfg, "orca https", WriteOptions::default()).await
        });
        let got = got.unwrap();
        assert_eq!(got.plan.action, Action::Delete);
        assert!(got.plan.dry_run);
        assert_eq!(paths.len(), 1);
        let (got, _, _) = run(&search(&[]), vec![], async |c, cfg| {
            delete_port_forward(c, cfg, "Anti-Lockout Rule", exec()).await
        });
        assert!(matches!(got, Err(OpnsenseError::NotFound { .. })));
    }

    #[test]
    fn delete_refuses_unowned_rule_without_adopt() {
        let body = search(&[row("orca https", "10.0.0.5")]);
        let (got, _, _) = run(&body, vec![], async |c, cfg| {
            delete_port_forward(c, cfg, "orca https", exec()).await
        });
        assert!(matches!(got, Err(OpnsenseError::InvalidArgument(m)) if m.contains("adopt")));
    }

    #[test]
    fn without_savepoint_wan_applies_unguarded() {
        let (got, paths, _) = run(
            &search(&[]),
            vec![
                r("POST", "/firewall/d_nat/savepoint", 404, "not found"),
                r("POST", "/firewall/d_nat/add_rule", 200, SAVED),
                r("POST", "/firewall/d_nat/apply", 200, OK),
            ],
            async |c, cfg| set_port_forward(c, cfg, desired("10.0.0.5"), exec()).await,
        );
        let applied = got.unwrap().apply.unwrap();
        assert!(!applied.rollback_protected && applied.revision.is_none());
        assert!(paths.iter().any(|x| x.ends_with("firewall/d_nat/apply")));
    }

    #[test]
    fn without_savepoint_non_wan_needs_allow_unprotected() {
        let mut rule = desired("10.0.0.5");
        rule.interface = "opt1".into();
        rule.destination = "10.0.0.9".into();
        rule.destination_port = "8443".into();
        let (got, paths, _) = run(
            &search(&[]),
            vec![r("POST", "/firewall/d_nat/savepoint", 404, "not found")],
            async |c, cfg| set_port_forward(c, cfg, rule, exec()).await,
        );
        assert!(
            matches!(got, Err(OpnsenseError::InvalidArgument(m)) if m.contains("allow_unprotected"))
        );
        assert!(!paths.iter().any(|x| x.contains("add_rule")));
    }

    #[test]
    fn unprotected_apply_failure_reports_saved_uuid() {
        let (got, _, _) = run(
            &search(&[]),
            vec![
                r("POST", "/firewall/d_nat/savepoint", 404, "not found"),
                r("POST", "/firewall/d_nat/add_rule", 200, SAVED),
                r("POST", "/firewall/d_nat/apply", 500, "boom"),
            ],
            async |c, cfg| set_port_forward(c, cfg, desired("10.0.0.5"), exec()).await,
        );
        assert!(matches!(got, Err(OpnsenseError::NotApplied { uuid, .. }) if uuid == "bbbb-2222"));
    }

    #[test]
    fn unsafe_savepoint_revision_is_rejected_before_writing() {
        let (got, paths, _) = run(
            &search(&[]),
            vec![r(
                "POST",
                "/firewall/d_nat/savepoint",
                200,
                r#"{"revision":"../x"}"#,
            )],
            async |c, cfg| set_port_forward(c, cfg, desired("10.0.0.5"), exec()).await,
        );
        assert!(matches!(got, Err(OpnsenseError::Malformed(_))));
        assert!(!paths.iter().any(|x| x.contains("add_rule")));
    }

    #[test]
    fn management_ports_off_wan_fail_closed_except_literal_hosts() {
        let mut rule = desired("10.0.0.5");
        rule.interface = "opt1".into();
        for d in ["lanip", "lannet", "any", "10.0.0.0/24", "some_alias"] {
            rule.destination = d.into();
            for p in ["22", "80", "443", "1-1024"] {
                rule.destination_port = p.into();
                assert!(guard_management(&rule, &[]).is_err(), "accepted {d}:{p}");
            }
        }
        rule.destination = "lanip".into();
        rule.destination_port = "8443".into();
        assert_eq!(guard_management(&rule, &[]).unwrap(), None);
        assert!(guard_management(&rule, &[8443]).is_err());
        rule.destination_port = "443".into();
        for d in ["10.0.0.9", "10.0.0.9/32"] {
            rule.destination = d.into();
            assert_eq!(
                guard_management(&rule, &[]).unwrap(),
                Some("10.0.0.9".parse().unwrap())
            );
        }
        let mut wan = desired("10.0.0.5");
        wan.destination = "any".into();
        assert_eq!(guard_management(&wan, &[]).unwrap(), None);
    }

    #[test]
    fn management_ports_merge_endpoint_config() {
        assert_eq!(parse_management_ports(None).unwrap(), vec![22, 80, 443]);
        assert_eq!(
            parse_management_ports(Some("8443, 22")).unwrap(),
            vec![22, 80, 443, 8443]
        );
        assert!(parse_management_ports(Some("0")).is_err());
        assert!(parse_management_ports(Some("x")).is_err());
    }

    const IFCONFIG: &str = r#"{"vtnet1":{"ipv4":[{"ipaddr":"10.0.0.1","subnetbits":24}]},"lo0":{"ipv4":[{"ipaddr":"127.0.0.1"}]}}"#;

    fn lan_rule(dest: &str) -> PortForward {
        let mut rule = desired("10.0.0.5");
        rule.interface = "lan".into();
        rule.destination = dest.into();
        rule
    }

    #[test]
    fn management_port_to_firewall_address_is_refused() {
        let (got, paths, _) = run(
            &search(&[]),
            vec![r(
                "GET",
                "/diagnostics/interface/get_interface_config",
                200,
                IFCONFIG,
            )],
            async |c, cfg| {
                set_port_forward(c, cfg, lan_rule("10.0.0.1"), WriteOptions::default()).await
            },
        );
        assert!(
            matches!(got, Err(OpnsenseError::InvalidArgument(m)) if m.contains("firewall interface address"))
        );
        assert!(!paths.iter().any(|x| x.contains("search_rule")));
    }

    #[test]
    fn management_port_to_other_literal_host_is_planned() {
        let (got, paths, _) = run(
            &search(&[]),
            vec![r(
                "GET",
                "/diagnostics/interface/get_interface_config",
                200,
                IFCONFIG,
            )],
            async |c, cfg| {
                set_port_forward(c, cfg, lan_rule("10.0.0.9"), WriteOptions::default()).await
            },
        );
        assert_eq!(got.unwrap().plan.action, Action::Create);
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn non_ok_apply_status_reverts_and_reports_not_applied() {
        let (got, paths, _) = run(
            &search(&[]),
            vec![
                r("POST", "/firewall/d_nat/savepoint", 200, SAVEPOINT),
                r("POST", "/firewall/d_nat/add_rule", 200, SAVED),
                r(
                    "POST",
                    &format!("/firewall/d_nat/apply/{REV}"),
                    200,
                    r#"{"status":"error"}"#,
                ),
                r(
                    "POST",
                    &format!("/firewall/d_nat/revert/{REV}"),
                    200,
                    r#"{"status":"ok"}"#,
                ),
            ],
            async |c, cfg| set_port_forward(c, cfg, desired("10.0.0.5"), exec()).await,
        );
        assert!(
            matches!(got, Err(OpnsenseError::NotApplied { reason, .. }) if reason.contains("reverted to savepoint"))
        );
        assert!(paths.iter().any(|x| x.ends_with(&format!("revert/{REV}"))));
    }

    #[test]
    fn non_ok_revert_is_reported_as_not_reverted() {
        let (got, _, _) = run(
            &search(&[]),
            vec![
                r("POST", "/firewall/d_nat/savepoint", 200, SAVEPOINT),
                r("POST", "/firewall/d_nat/add_rule", 200, SAVED),
                r("POST", &format!("/firewall/d_nat/apply/{REV}"), 500, "boom"),
                r(
                    "POST",
                    &format!("/firewall/d_nat/revert/{REV}"),
                    200,
                    r#"{"status":"unknown (or removed) savepoint"}"#,
                ),
            ],
            async |c, cfg| set_port_forward(c, cfg, desired("10.0.0.5"), exec()).await,
        );
        assert!(
            matches!(got, Err(OpnsenseError::NotApplied { reason, .. }) if reason.contains("NOT reverted"))
        );
    }

    #[test]
    fn status_text_matches_configd_exactly() {
        assert!(status_is(&json!({"status": "OK\n\n"}), APPLIED));
        assert!(!status_is(&json!({"status": "ok"}), APPLIED));
        assert!(!status_is(&json!({"status": "Error (1)"}), APPLIED));
        assert!(status_is(&json!({"status": "\n\n"}), ROLLBACK_CANCELLED));
        assert!(!status_is(
            &json!({"status": "Execute error"}),
            ROLLBACK_CANCELLED
        ));
        assert!(!status_is(&json!({}), ROLLBACK_CANCELLED));
        assert!(status_is(&json!({"status": "ok"}), REVERTED));
        assert!(!status_is(
            &json!({"status": "unknown (or removed) savepoint"}),
            REVERTED
        ));
    }

    #[test]
    fn cancel_rollback_failure_reports_rollback_armed() {
        for (status, body) in [(200, r#"{"status":"Execute error"}"#), (500, "boom")] {
            let (got, _, _) = run(
                &search(&[]),
                vec![
                    r("POST", "/firewall/d_nat/savepoint", 200, SAVEPOINT),
                    r("POST", "/firewall/d_nat/add_rule", 200, SAVED),
                    r("POST", &format!("/firewall/d_nat/apply/{REV}"), 200, OK),
                    r(
                        "POST",
                        &format!("/firewall/d_nat/cancel_rollback/{REV}"),
                        status,
                        body,
                    ),
                ],
                async |c, cfg| set_port_forward(c, cfg, desired("10.0.0.5"), exec()).await,
            );
            match got {
                Err(OpnsenseError::RollbackArmed { revision, .. }) => assert_eq!(revision, REV),
                other => panic!("expected RollbackArmed, got {other:?}"),
            }
        }
    }

    #[test]
    fn validation_rejects_bad_inputs_before_any_request() {
        let cases: Vec<fn(&mut PortForward)> = vec![
            |r| r.description = String::new(),
            |r| r.description = "bad\"quote".into(),
            |r| r.description = "x".repeat(256),
            |r| r.interface = "WAN;".into(),
            |r| r.ip_protocol = "inet6".into(),
            |r| r.protocol = None,
            |r| r.destination = "10.0.0.0/33".into(),
            |r| r.destination = "../etc".into(),
            |r| r.destination_port = "0".into(),
            |r| r.destination_port = "65536".into(),
            |r| r.destination_port = "2000-1000".into(),
            |r| r.destination_port = "+80".into(),
            |r| r.target = "10.0.0.256".into(),
            |r| r.target = "host.lan".into(),
            |r| r.target_port = "80-90".into(),
        ];
        for mutate in cases {
            let mut r = desired("10.0.0.5");
            mutate(&mut r);
            assert!(validate(&r).is_err(), "accepted {r:?}");
        }
        let mut ok = desired("10.0.0.5");
        ok.destination = "10.0.0.0/24".into();
        ok.destination_port = "1000-2000".into();
        assert!(validate(&ok).is_ok());
        ok.destination = "any".into();
        ok.destination_port = "65535".into();
        assert!(validate(&ok).is_ok());
    }
}
