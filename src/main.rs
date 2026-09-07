//! Dynamic (subprocess) entrypoint for the opnsense plugin.
//!
//! A DUAL-facet plugin: one `Plugin` builder chain registers BOTH the
//! [`OpnsenseBackend`](opnsense::OpnsenseBackend) (generic `service.*`
//! lifecycle) AND the `opnsense.` `#[orca_tool]` surface (endpoint registry
//! CRUD, Unbound and DHCP CRUD, reconfigure, status). The plugin is a
//! `[[bin]]`, owns no runtime, and reaches orca only through the socket.
plugin_toolkit::instrument::bootstrap!();

use opnsense::OpnsenseBackend;
use plugin_toolkit::plugin::Plugin;

// Force-link this plugin's OWN lib crate so the linker doesn't dead-strip the
// rlib (and with it every `#[orca_tool]` / `#[endpoint_resource]` registration).
// The builder does NOT force-link for you, so this `use ... as _;` is required.
#[allow(unused_imports)]
use opnsense::tools as _;

fn main() -> plugin_toolkit::anyhow::Result<()> {
    Plugin::named("opnsense")
        .version(env!("CARGO_PKG_VERSION"))
        .service(OpnsenseBackend::new("opnsense"))
        .tools(["opnsense."])
        .serve()
}
