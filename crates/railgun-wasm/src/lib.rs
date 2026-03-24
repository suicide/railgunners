//! Thin WASM-oriented surface over shared Rust crates.

use railgun_core::sdk_info;

/// Returns a string describing the current scaffold state.
#[must_use]
pub fn workspace_summary() -> String {
    let info = sdk_info();
    format!("{} {}: WASM bindings scaffolded over shared Rust crates", info.name, info.version)
}
