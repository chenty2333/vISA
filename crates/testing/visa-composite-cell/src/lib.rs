//! Composite continuity cell: one component holding a timer, a key-value
//! namespace, a regular file, and a logical request across a single
//! Wasmtime-to-Wasmtime handoff.

pub mod adapter;
pub mod bindings;
pub mod cell;
pub mod component;
pub mod fixture;
pub mod host;
pub mod state;
pub mod verify;

use std::path::{Path, PathBuf};

/// Run the cell and write its JSON report under the artifact root.
pub fn run(artifact_root: &Path, case_id: &str, timer_delay_ns: u64) -> Result<PathBuf, String> {
    let outcome = cell::run_composite_cell(artifact_root, case_id, timer_delay_ns)?;
    let verification = verify::verify(&outcome);
    let report = serde_json::json!({
        "schema": "visa-composite-cell-report-v1",
        "runtime": {
            "source": "visa_composite_cell",
            "destination": "visa_composite_cell",
            "engine": "wasmtime",
            "engine_version": adapter::WASMTIME_VERSION,
        },
        "resources": ["timer", "key-value", "regular-file", "logical-request"],
        "passed": verification.passed(),
        "observations": verification.trace,
    });
    let path = artifact_root.join(format!("{case_id}-composite-cell.json"));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    }
    let encoded = serde_json::to_vec_pretty(&report)
        .map_err(|error| format!("cannot encode composite report: {error}"))?;
    std::fs::write(&path, encoded)
        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    if !verification.passed() {
        return Err(format!("composite cell assertions failed: {:?}", verification.failures()));
    }
    Ok(path)
}
