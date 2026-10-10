//! Caller authorization shared by the mutating tool verbs.

use plugin_toolkit::prelude::*;

/// Admin gate for mutating verbs, applied before any planning so a dry run
/// needs the same role as the execute it previews.
pub fn require_admin(ctx: &ToolCtx) -> Result<()> {
    check_admin(ctx.caller().as_ref().map(|c| c.role.as_str()))
}

fn check_admin(role: Option<&str>) -> Result<()> {
    match role {
        Some("admin") => Ok(()),
        Some(other) => {
            bail!("this verb needs the admin role (caller has {other:?}), also for a dry run")
        }
        None => bail!("this verb needs an authenticated admin caller, also for a dry run"),
    }
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

    #[test]
    fn require_admin_reads_the_ctx_caller() {
        assert!(require_admin(&ctx(Some("admin"))).is_ok());
        assert!(require_admin(&ctx(Some("read"))).is_err());
        assert!(require_admin(&ctx(None)).is_err(), "no caller = refused");
    }

    #[test]
    fn only_admin_passes() {
        assert!(check_admin(Some("admin")).is_ok());
    }

    #[test]
    fn non_admin_and_anonymous_callers_are_refused() {
        for role in [
            Some("read"),
            Some("any"),
            Some("wizard"),
            Some("Admin"),
            Some(""),
            None,
        ] {
            let err = check_admin(role).unwrap_err().to_string();
            assert!(
                err.contains("admin") && err.contains("dry run"),
                "{role:?}: {err}"
            );
        }
    }
}
