//! Write plans for the DNS/DHCP write verbs.
//!
//! Each verb reads the current rows and decides what it will do; the plan is
//! returned with the result. An unchanged record is not rewritten and its
//! module is not reconfigured.

use plugin_toolkit::reqwest;
use serde::{Deserialize, Serialize};

use crate::{
    Config, DotUpstream, HostOverride, Module, OpnsenseError, Reservation, list_dot,
    list_host_overrides, list_reservations,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Create,
    Update,
    Unchanged,
    Delete,
    /// Delete target not found; executing returns not-found.
    Absent,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WritePlan<T> {
    pub action: Action,
    pub current: Option<T>,
    /// The record after the write; `None` for deletes.
    pub desired: Option<T>,
    pub dry_run: bool,
    pub executed: bool,
    pub steps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReconfigurePlan {
    pub module: Module,
    pub dry_run: bool,
    pub steps: Vec<String>,
    /// The reconfigure response, when executed.
    pub result: Option<plugin_toolkit::serde_json::Value>,
}

pub fn reconfigure_step(module: Module) -> String {
    format!("POST {}/service/reconfigure", module.service_module())
}

pub fn reconfigure_plan(module: Module) -> ReconfigurePlan {
    ReconfigurePlan {
        module,
        dry_run: false,
        steps: vec![reconfigure_step(module)],
        result: None,
    }
}

fn upsert<T>(
    current: Option<T>,
    desired: T,
    same: impl Fn(&T, &T) -> bool,
    write: String,
    add: String,
    module: Module,
) -> WritePlan<T> {
    let (action, steps) = match &current {
        Some(c) if same(c, &desired) => (Action::Unchanged, Vec::new()),
        Some(_) => (Action::Update, vec![write, reconfigure_step(module)]),
        None => (Action::Create, vec![add, reconfigure_step(module)]),
    };
    WritePlan {
        action,
        current,
        desired: Some(desired),
        dry_run: false,
        executed: false,
        steps,
    }
}

fn delete<T>(current: Option<T>, del: impl Fn(&T) -> String, module: Module) -> WritePlan<T> {
    let (action, steps) = match &current {
        Some(c) => (Action::Delete, vec![del(c), reconfigure_step(module)]),
        None => (Action::Absent, Vec::new()),
    };
    WritePlan {
        action,
        current,
        desired: None,
        dry_run: false,
        executed: false,
        steps,
    }
}

fn uuid_of(u: &Option<String>) -> &str {
    u.as_deref().unwrap_or("?")
}

pub async fn host_override_set(
    client: &reqwest::Client,
    cfg: &Config,
    desired: HostOverride,
) -> Result<WritePlan<HostOverride>, OpnsenseError> {
    let current = list_host_overrides(client, cfg)
        .await?
        .into_iter()
        .find(|h| h.hostname == desired.hostname && h.domain == desired.domain);
    let write = format!(
        "POST unbound/settings/set_host_override/{}",
        current.as_ref().map(|c| uuid_of(&c.uuid)).unwrap_or("?")
    );
    Ok(upsert(
        current,
        desired,
        |c, d| {
            c.enabled == "1"
                && c.rr == d.rr
                && c.server == d.server
                && c.description == d.description
        },
        write,
        "POST unbound/settings/add_host_override".into(),
        Module::Unbound,
    ))
}

pub async fn host_override_delete(
    client: &reqwest::Client,
    cfg: &Config,
    hostname: &str,
    domain: &str,
) -> Result<WritePlan<HostOverride>, OpnsenseError> {
    let current = list_host_overrides(client, cfg)
        .await?
        .into_iter()
        .find(|h| h.hostname == hostname && h.domain == domain);
    Ok(delete(
        current,
        |c| {
            format!(
                "POST unbound/settings/del_host_override/{}",
                uuid_of(&c.uuid)
            )
        },
        Module::Unbound,
    ))
}

pub async fn dot_set(
    client: &reqwest::Client,
    cfg: &Config,
    desired: DotUpstream,
) -> Result<WritePlan<DotUpstream>, OpnsenseError> {
    let current = list_dot(client, cfg)
        .await?
        .into_iter()
        .find(|d| d.server == desired.server && d.domain == desired.domain);
    let write = format!(
        "POST unbound/settings/set_dot/{}",
        current.as_ref().map(|c| uuid_of(&c.uuid)).unwrap_or("?")
    );
    Ok(upsert(
        current,
        desired,
        |c, d| {
            c.enabled == "1"
                && c.port == d.port
                && c.verify == d.verify
                && c.description == d.description
        },
        write,
        "POST unbound/settings/add_dot".into(),
        Module::Unbound,
    ))
}

pub async fn dot_delete(
    client: &reqwest::Client,
    cfg: &Config,
    server: &str,
    domain: &str,
) -> Result<WritePlan<DotUpstream>, OpnsenseError> {
    let current = list_dot(client, cfg)
        .await?
        .into_iter()
        .find(|d| d.server == server && d.domain == domain);
    Ok(delete(
        current,
        |c| format!("POST unbound/settings/del_dot/{}", uuid_of(&c.uuid)),
        Module::Unbound,
    ))
}

pub async fn reservation_set(
    client: &reqwest::Client,
    cfg: &Config,
    desired: Reservation,
) -> Result<WritePlan<Reservation>, OpnsenseError> {
    let current = list_reservations(client, cfg)
        .await?
        .into_iter()
        .find(|r| r.hw_address.eq_ignore_ascii_case(&desired.hw_address));
    let write = format!(
        "POST kea/dhcpv4/set_reservation/{}",
        current.as_ref().map(|c| uuid_of(&c.uuid)).unwrap_or("?")
    );
    Ok(upsert(
        current,
        desired,
        |c, d| {
            c.subnet == d.subnet
                && c.ip_address == d.ip_address
                && c.hostname == d.hostname
                && c.description == d.description
        },
        write,
        "POST kea/dhcpv4/add_reservation".into(),
        Module::Dhcp,
    ))
}

pub async fn reservation_delete(
    client: &reqwest::Client,
    cfg: &Config,
    hw_address: &str,
) -> Result<WritePlan<Reservation>, OpnsenseError> {
    let current = list_reservations(client, cfg)
        .await?
        .into_iter()
        .find(|r| r.hw_address.eq_ignore_ascii_case(hw_address));
    Ok(delete(
        current,
        |c| format!("POST kea/dhcpv4/del_reservation/{}", uuid_of(&c.uuid)),
        Module::Dhcp,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use plugin_toolkit::abi::{HttpRequest, HttpResponse};

    /// Answer GETs by URL suffix; any write fails the test.
    fn read_only<T>(
        routes: &[(&str, &str)],
        f: impl FnOnce(
            reqwest::Client,
            Config,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = T>>>,
    ) -> T {
        let routes: Vec<(String, String)> = routes
            .iter()
            .map(|(p, b)| (p.to_string(), b.to_string()))
            .collect();
        let sink = Box::new(move |cap: &str, op: &str| {
            assert_eq!(cap, "http.request");
            let req: HttpRequest = plugin_toolkit::serde_json::from_str(op).unwrap();
            assert_eq!(req.method, "GET", "a dry run must not write: {}", req.url);
            let (_, body) = routes
                .iter()
                .find(|(s, _)| req.url.ends_with(s.as_str()))
                .unwrap_or_else(|| panic!("unexpected request {}", req.url));
            Ok::<String, String>(
                plugin_toolkit::serde_json::to_string(&HttpResponse {
                    status: 200,
                    headers: vec![],
                    body: body.as_bytes().to_vec(),
                })
                .unwrap(),
            )
        });
        let cfg = Config::new("https://10.0.0.1", "k", "s").insecure(true);
        plugin_toolkit::capsink::with_cap_sink(sink, || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let client = cfg.build_client().unwrap();
            rt.block_on(f(client, cfg))
        })
    }

    const HOSTS: &str = r#"{"rows":[{"uuid":"h1","enabled":"1","hostname":"gitea","domain":"example.com","rr":"A","server":"10.0.0.5","description":""}]}"#;
    const DOTS: &str = r#"{"rows":[{"uuid":"d1","enabled":"1","domain":"","server":"9.9.9.9","port":"853","verify":"dns.quad9.net","description":""}]}"#;
    const RES: &str = r#"{"rows":[{"uuid":"r1","subnet":"s1","ip_address":"10.0.0.7","hw_address":"AA:BB:CC:DD:EE:FF","hostname":"nas","description":""}]}"#;

    fn host(server: &str) -> HostOverride {
        HostOverride {
            uuid: None,
            enabled: "1".into(),
            hostname: "gitea".into(),
            domain: "example.com".into(),
            rr: "A".into(),
            server: server.into(),
            description: String::new(),
        }
    }

    #[test]
    fn host_override_plans_update_unchanged_and_create_without_writing() {
        let p = read_only(&[("search_host_override", HOSTS)], |c, cfg| {
            Box::pin(async move { host_override_set(&c, &cfg, host("10.0.0.6")).await })
        })
        .unwrap();
        assert_eq!(p.action, Action::Update);
        assert_eq!(
            p.steps,
            [
                "POST unbound/settings/set_host_override/h1",
                "POST unbound/service/reconfigure"
            ]
        );
        assert!(!p.dry_run && !p.executed);

        let p = read_only(&[("search_host_override", HOSTS)], |c, cfg| {
            Box::pin(async move { host_override_set(&c, &cfg, host("10.0.0.5")).await })
        })
        .unwrap();
        assert_eq!(p.action, Action::Unchanged);
        assert!(p.steps.is_empty());

        let p = read_only(&[("search_host_override", r#"{"rows":[]}"#)], |c, cfg| {
            Box::pin(async move { host_override_set(&c, &cfg, host("10.0.0.5")).await })
        })
        .unwrap();
        assert_eq!(p.action, Action::Create);
    }

    #[test]
    fn deletes_plan_delete_or_absent() {
        let p = read_only(&[("search_host_override", HOSTS)], |c, cfg| {
            Box::pin(async move { host_override_delete(&c, &cfg, "gitea", "example.com").await })
        })
        .unwrap();
        assert_eq!(p.action, Action::Delete);
        assert_eq!(p.steps[0], "POST unbound/settings/del_host_override/h1");
        let p = read_only(&[("search_dot", DOTS)], |c, cfg| {
            Box::pin(async move { dot_delete(&c, &cfg, "1.1.1.1", "").await })
        })
        .unwrap();
        assert_eq!(p.action, Action::Absent);
        assert!(p.steps.is_empty());
        let p = read_only(&[("search_reservation", RES)], |c, cfg| {
            Box::pin(async move { reservation_delete(&c, &cfg, "aa:bb:cc:dd:ee:ff").await })
        })
        .unwrap();
        assert_eq!(p.action, Action::Delete);
        assert_eq!(p.steps[1], "POST kea/service/reconfigure");
    }

    #[test]
    fn dot_and_reservation_compare_every_written_field() {
        let dot = DotUpstream {
            uuid: None,
            enabled: "1".into(),
            domain: String::new(),
            server: "9.9.9.9".into(),
            port: "853".into(),
            verify: "dns.quad9.net".into(),
            description: String::new(),
        };
        let d2 = dot.clone();
        let p = read_only(&[("search_dot", DOTS)], |c, cfg| {
            Box::pin(async move { dot_set(&c, &cfg, d2).await })
        })
        .unwrap();
        assert_eq!(p.action, Action::Unchanged);
        let p = read_only(&[("search_dot", DOTS)], |c, cfg| {
            Box::pin(async move {
                dot_set(
                    &c,
                    &cfg,
                    DotUpstream {
                        verify: String::new(),
                        ..dot
                    },
                )
                .await
            })
        })
        .unwrap();
        assert_eq!(p.action, Action::Update);

        let res = Reservation {
            uuid: None,
            subnet: "s1".into(),
            ip_address: "10.0.0.8".into(),
            hw_address: "aa:bb:cc:dd:ee:ff".into(),
            hostname: "nas".into(),
            description: String::new(),
        };
        let p = read_only(&[("search_reservation", RES)], |c, cfg| {
            Box::pin(async move { reservation_set(&c, &cfg, res).await })
        })
        .unwrap();
        assert_eq!(p.action, Action::Update);
        assert_eq!(p.steps[0], "POST kea/dhcpv4/set_reservation/r1");
    }

    #[test]
    fn reconfigure_plan_lists_the_call() {
        let p = reconfigure_plan(Module::Dhcp);
        assert!(!p.dry_run && p.result.is_none());
        assert_eq!(p.steps, ["POST kea/service/reconfigure"]);
    }
}
