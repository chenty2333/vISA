use crate::types::{ConformanceReport, EvidenceArtifact};

pub fn attach_evidence_artifact(
    report: &mut ConformanceReport,
    spec_id: &str,
    artifact: EvidenceArtifact,
) -> usize {
    let mut attached = 0;
    for result in &mut report.results {
        if spec_id == "*" || result.spec_id == spec_id {
            result.evidence_artifacts.push(artifact.clone());
            attached += 1;
        }
    }
    attached
}
