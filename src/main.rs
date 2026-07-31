//! Dynamic (subprocess) entrypoint for the opnsense plugin.
//!
//! The toolkit's `serve_service_plugin!` emits `fn main`, serving this plugin over the orca
//! socket. The plugin is a
//! `[[bin]]`, owns no runtime, and reaches orca only through the socket.
plugin_toolkit::serve_service_plugin! {
    name: "opnsense",
    target_compat: "any",
    backend: opnsense::OpnsenseBackend::new("opnsense"),
}
