//! Dynamic (subprocess) entrypoint for the opnsense plugin.
//!
//! Serves this plugin over the orca socket via the typed `Plugin` builder.
//! The plugin is a `[[bin]]`, owns no runtime, and reaches orca only through
//! the socket. Advertises a single `service` backend.
plugin_toolkit::instrument::bootstrap!();
use opnsense::OpnsenseBackend;
use plugin_toolkit::plugin::Plugin;

fn main() -> plugin_toolkit::anyhow::Result<()> {
    Plugin::named("opnsense")
        .version(env!("CARGO_PKG_VERSION"))
        .service(OpnsenseBackend::new("opnsense"))
        .serve()
}
