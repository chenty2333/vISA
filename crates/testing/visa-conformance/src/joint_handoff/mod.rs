mod durable_cell_verify;
mod host_cell_verify;
mod model;
mod provenance;
mod verify;
mod writer;

pub use model::*;
pub use provenance::{joint_evidence_bundle_id, seal_joint_evidence_bundle_id};
pub use verify::*;
pub use writer::build_reference_joint_evidence_bundle;

/// Verify one decoded HostSubstrate report from its raw receipts, journals,
/// leases, and durable projection transcripts. Artifact inventory and report
/// file digest binding remain the responsibility of the full bundle gate.
pub fn validate_joint_host_substrate_raw_material(
    report: &JointHostSubstrateCellReport,
) -> Result<(), String> {
    host_cell_verify::validate_host_substrate_raw_material(report)
}

#[cfg(test)]
mod tests;
