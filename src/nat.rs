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
        && d.len() <= 255
        && d.chars()
            .all(|c| c.is_ascii_alphanumeric() || " ._-:/()@,+".contains(c));
    if ok {
        Ok(())
    } else {
        Err(invalid(format!(
            "description {d:?} must be 1-255 chars of [A-Za-z0-9 ._-:/()@,+]"
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

async fn find_by_description(
    client: &reqwest::Client,
    cfg: &Config,
    description: &str,
) -> Result<Option<PortForward>, OpnsenseError> {
    let mut matches: Vec<PortForward> = list_port_forwards(client, cfg)
        .await?
        .into_iter()
        .filter(|r| r.description == description)
        .collect();
    if matches.len() > 1 {
        return Err(invalid(format!(
            "{} port forwards share description {description:?}; resolve the duplicates first",
            matches.len()
        )));
    }
    Ok(matches.pop())
}

fn rule_uuid(rule: &PortForward) -> Result<&str, OpnsenseError> {
    rule.uuid
        .as_deref()
        .filter(|u| u.bytes().all(|c| c.is_ascii_hexdigit() || c == b'-'))
        .ok_or_else(|| {
            OpnsenseError::Malformed(format!("rule {:?} has no usable uuid", rule.description))
        })
}
pub async fn apply(client: &reqwest::Client, cfg: &Config) -> Result<ApplyResult, OpnsenseError> {
    let savepoint = post_json(client, &cfg.api_url("firewall/d_nat/savepoint"), &json!({})).await;
    let revision = match savepoint {
        Ok(v) => v
            .get("revision")
            .and_then(Value::as_str)
            .filter(|r| !r.is_empty() && r.bytes().all(|c| c.is_ascii_digit() || c == b'.'))
            .map(str::to_string)
            .ok_or_else(|| {
                OpnsenseError::Malformed(format!("savepoint returned no revision: {v}"))
            })?,
        Err(OpnsenseError::Api { status: 404, .. }) => {
            let status =
                post_json(client, &cfg.api_url("firewall/d_nat/apply"), &json!({})).await?;
            return Ok(ApplyResult {
                revision: None,
                rollback_protected: false,
                status,
            });
        }
        Err(e) => return Err(e),
    };
    let status = post_json(
        client,
        &cfg.api_url(&format!("firewall/d_nat/apply/{revision}")),
        &json!({}),
    )
    .await?;
    list_port_forwards(client, cfg).await?;
    post_json(
        client,
        &cfg.api_url(&format!("firewall/d_nat/cancel_rollback/{revision}")),
        &json!({}),
    )
    .await?;
    Ok(ApplyResult {
        revision: Some(revision),
        rollback_protected: true,
        status,
    })
}
pub async fn set_port_forward(
    client: &reqwest::Client,
    cfg: &Config,
    desired: PortForward,
) -> Result<NatWritePlan, OpnsenseError> {
    validate(&desired)?;
    let current = find_by_description(client, cfg, &desired.description).await?;
    let action = match &current {
        Some(c) if c.same_settings(&desired) => Action::Unchanged,
        Some(_) => Action::Update,
        None => Action::Create,
    };
    let mut plan = WritePlan {
        action,
        current: current.clone(),
        desired: Some(desired.clone()),
        dry_run: false,
        executed: false,
        steps: Vec::new(),
    };
    if action == Action::Unchanged {
        return Ok(NatWritePlan { plan, apply: None });
    }
    let uuid = match &current {
        Some(c) => {
            let uuid = rule_uuid(c)?.to_string();
            plan.steps
                .push(format!("POST firewall/d_nat/set_rule/{uuid}"));
            post_write(
                client,
                &cfg.api_url(&format!("firewall/d_nat/set_rule/{uuid}")),
                &desired.body(),
            )
            .await?;
            Some(uuid)
        }
        None => {
            plan.steps.push("POST firewall/d_nat/add_rule".into());
            post_write(
                client,
                &cfg.api_url("firewall/d_nat/add_rule"),
                &desired.body(),
            )
            .await?
        }
    };
    plan.steps
        .push("POST firewall/d_nat/savepoint + apply + cancel_rollback".into());
    let applied = apply(client, cfg).await?;
    plan.desired = Some(PortForward { uuid, ..desired });
    plan.executed = true;
    Ok(NatWritePlan {
        plan,
        apply: Some(applied),
    })
}
pub async fn delete_port_forward(
    client: &reqwest::Client,
    cfg: &Config,
    description: &str,
) -> Result<NatWritePlan, OpnsenseError> {
    validate_description(description)?;
    let current = find_by_description(client, cfg, description)
        .await?
        .ok_or_else(|| OpnsenseError::NotFound {
            kind: "port forward",
            selector: description.to_string(),
        })?;
    let uuid = rule_uuid(&current)?.to_string();
    post_write(
        client,
        &cfg.api_url(&format!("firewall/d_nat/del_rule/{uuid}")),
        &json!({}),
    )
    .await?;
    let applied = apply(client, cfg).await?;
    Ok(NatWritePlan {
        plan: WritePlan {
            action: Action::Delete,
            current: Some(current),
            desired: None,
            dry_run: false,
            executed: true,
            steps: vec![
                format!("POST firewall/d_nat/del_rule/{uuid}"),
                "POST firewall/d_nat/savepoint + apply + cancel_rollback".into(),
            ],
        },
        apply: Some(applied),
    })
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

    const SAVEPOINT: &str = r#"{"status":"ok","retention":"60","revision":"1729700000.12"}"#;
    const SAVED: &str = r#"{"result":"saved","uuid":"bbbb-2222"}"#;

    fn apply_routes() -> Vec<(&'static str, &'static str, u16, &'static str)> {
        vec![
            ("POST", "/firewall/d_nat/savepoint", 200, SAVEPOINT),
            (
                "POST",
                "/firewall/d_nat/apply/1729700000.12",
                200,
                r#"{"status":"OK"}"#,
            ),
            (
                "POST",
                "/firewall/d_nat/cancel_rollback/1729700000.12",
                200,
                r#"{"status":"OK"}"#,
            ),
        ]
    }

    fn paths(calls: &[Call]) -> Vec<String> {
        calls
            .iter()
            .map(|(m, u, _)| format!("{m} {}", u.trim_start_matches("https://10.0.0.1/api/")))
            .collect()
    }

    #[test]
    fn list_drops_automatic_rows_and_maps_fields() {
        let body = search(&[row("orca https", "10.0.0.5")]);
        let (got, _) = with_mock(&[("GET", SEARCH, 200, &body)], async |c, cfg| {
            list_port_forwards(c, cfg).await
        });
        let got = got.unwrap();
        assert_eq!(got.len(), 1);
        let mut expected = desired("10.0.0.5");
        expected.uuid = Some(UUID.into());
        assert_eq!(got[0], expected);
    }

    #[test]
    fn set_creates_then_applies_with_rollback_guard() {
        let body = search(&[]);
        let mut routes = vec![
            ("GET", SEARCH, 200, body.as_str()),
            ("POST", "/firewall/d_nat/add_rule", 200, SAVED),
        ];
        routes.extend(apply_routes());
        let (got, calls) = with_mock(&routes, async |c, cfg| {
            set_port_forward(c, cfg, desired("10.0.0.5")).await
        });
        let got = got.unwrap();
        assert_eq!(got.plan.action, Action::Create);
        assert!(got.plan.executed);
        assert_eq!(got.plan.desired.unwrap().uuid.as_deref(), Some("bbbb-2222"));
        let apply = got.apply.unwrap();
        assert!(apply.rollback_protected);
        assert_eq!(
            paths(&calls),
            vec![
                format!("GET {}", SEARCH.trim_start_matches('/')),
                "POST firewall/d_nat/add_rule".into(),
                "POST firewall/d_nat/savepoint".into(),
                "POST firewall/d_nat/apply/1729700000.12".into(),
                format!("GET {}", SEARCH.trim_start_matches('/')),
                "POST firewall/d_nat/cancel_rollback/1729700000.12".into(),
            ]
        );
        let sent: Value = plugin_toolkit::serde_json::from_str(&calls[1].2).unwrap();
        assert_eq!(sent["rule"]["destination"]["network"], "wanip");
        assert_eq!(sent["rule"]["local-port"], "443");
        assert_eq!(sent["rule"]["protocol"], "tcp");
        assert_eq!(sent["rule"]["pass"], "pass");
        assert_eq!(sent["rule"]["disabled"], "0");
    }

    #[test]
    fn set_updates_existing_rule_by_description() {
        let body = search(&[row("orca https", "10.0.0.5")]);
        let mut routes = vec![
            ("GET", SEARCH, 200, body.as_str()),
            (
                "POST",
                "/firewall/d_nat/set_rule/aaaa-1111",
                200,
                r#"{"result":"saved"}"#,
            ),
        ];
        routes.extend(apply_routes());
        let (got, calls) = with_mock(&routes, async |c, cfg| {
            set_port_forward(c, cfg, desired("10.0.0.6")).await
        });
        let got = got.unwrap();
        assert_eq!(got.plan.action, Action::Update);
        assert_eq!(got.plan.desired.unwrap().uuid.as_deref(), Some(UUID));
        assert!(paths(&calls).contains(&"POST firewall/d_nat/set_rule/aaaa-1111".to_string()));
    }

    #[test]
    fn set_unchanged_rule_writes_nothing() {
        let body = search(&[row("orca https", "10.0.0.5")]);
        let (got, calls) = with_mock(&[("GET", SEARCH, 200, &body)], async |c, cfg| {
            set_port_forward(c, cfg, desired("10.0.0.5")).await
        });
        let got = got.unwrap();
        assert_eq!(got.plan.action, Action::Unchanged);
        assert!(got.apply.is_none());
        assert_eq!(calls.len(), 1);
    }

    #[test]
    fn set_refuses_duplicate_descriptions() {
        let body = search(&[row("orca https", "10.0.0.5"), row("orca https", "10.0.0.6")]);
        let (got, calls) = with_mock(&[("GET", SEARCH, 200, &body)], async |c, cfg| {
            set_port_forward(c, cfg, desired("10.0.0.7")).await
        });
        assert!(matches!(got, Err(OpnsenseError::InvalidArgument(_))));
        assert_eq!(calls.len(), 1);
    }

    #[test]
    fn delete_removes_matching_rule_and_applies() {
        let body = search(&[row("orca https", "10.0.0.5")]);
        let mut routes = vec![
            ("GET", SEARCH, 200, body.as_str()),
            (
                "POST",
                "/firewall/d_nat/del_rule/aaaa-1111",
                200,
                r#"{"result":"deleted"}"#,
            ),
        ];
        routes.extend(apply_routes());
        let (got, calls) = with_mock(&routes, async |c, cfg| {
            delete_port_forward(c, cfg, "orca https").await
        });
        let got = got.unwrap();
        assert_eq!(got.plan.action, Action::Delete);
        assert!(got.apply.unwrap().rollback_protected);
        assert!(paths(&calls).contains(&"POST firewall/d_nat/del_rule/aaaa-1111".to_string()));
    }

    #[test]
    fn delete_missing_rule_is_not_found() {
        let body = search(&[]);
        let (got, calls) = with_mock(&[("GET", SEARCH, 200, &body)], async |c, cfg| {
            delete_port_forward(c, cfg, "Anti-Lockout Rule").await
        });
        assert!(matches!(got, Err(OpnsenseError::NotFound { .. })));
        assert_eq!(calls.len(), 1);
    }

    #[test]
    fn apply_leaves_rollback_armed_when_api_stops_answering() {
        let routes = vec![
            ("POST", "/firewall/d_nat/savepoint", 200, SAVEPOINT),
            (
                "POST",
                "/firewall/d_nat/apply/1729700000.12",
                200,
                r#"{"status":"OK"}"#,
            ),
            ("GET", SEARCH, 502, "bad gateway"),
        ];
        let (got, calls) = with_mock(&routes, async |c, cfg| apply(c, cfg).await);
        assert!(got.is_err());
        assert!(!paths(&calls).iter().any(|p| p.contains("cancel_rollback")));
    }

    #[test]
    fn apply_falls_back_without_savepoint_endpoint() {
        let routes = vec![
            ("POST", "/firewall/d_nat/savepoint", 404, "not found"),
            ("POST", "/firewall/d_nat/apply", 200, r#"{"status":"OK"}"#),
        ];
        let (got, _) = with_mock(&routes, async |c, cfg| apply(c, cfg).await);
        let got = got.unwrap();
        assert!(!got.rollback_protected);
        assert!(got.revision.is_none());
    }

    #[test]
    fn apply_rejects_unsafe_revision() {
        let routes = vec![(
            "POST",
            "/firewall/d_nat/savepoint",
            200,
            r#"{"revision":"../x"}"#,
        )];
        let (got, calls) = with_mock(&routes, async |c, cfg| apply(c, cfg).await);
        assert!(matches!(got, Err(OpnsenseError::Malformed(_))));
        assert_eq!(calls.len(), 1);
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
