<p align="center">
  <img src="assets/icon-256.png" width="120" alt="opnsense" />
</p>

# opnsense

OPNsense is an open-source FreeBSD-based firewall and routing platform.

A first-party [orca](https://github.com/argyle-labs/orca) plugin (appliance integration).

This plugin **connects orca to an existing opnsense install** — there's nothing to deploy here. Stand up opnsense from the upstream project, then point orca at it.

---

## Run it without orca

Install opnsense per the upstream project: <https://opnsense.org/>. It listens on port `443` by default; this plugin talks to that endpoint (host, credentials/token) — no container is deployed.


See [opnsense-setup.md](docs/opnsense-setup.md) for worked operator notes.

## With orca

orca drives this plugin through its generic surface — rich, opnsense-specific data comes back in the typed `service.status` payload, never bespoke tools.

## Layout

- `src/` — the plugin (pure Rust): the `ServiceBackend` descriptor + `configure` / `status`.
- `docs/` — standalone operator notes.
- [CAPABILITIES.md](CAPABILITIES.md) — the service-backend contract checklist.
- `assets/` — plugin icon.
