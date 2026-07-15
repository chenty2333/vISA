use serde::Serialize;
use sha2::{Digest as _, Sha256};

use super::model::*;

const BUNDLE_ID_DOMAIN: &[u8] = b"vISA/joint-handoff/evidence-bundle-id/v2\0";

#[derive(Serialize)]
struct BundleIdProjection<'a> {
    schema_version: &'a str,
    claim_id: &'a str,
    source_lock_sha256: &'a str,
    neutral_tree: &'a str,
    neutral_bundle_sha256: &'a str,
    registry_sha256: &'a str,
    protocol_schema_sha256: &'a str,
    machine_contract_sha256: &'a str,
    refinement_map_sha256: &'a str,
    abstract_registry_sha256: &'a str,
    visa: &'a JointSourceRevision,
    nexus: &'a JointSourceRevision,
    neutral: &'a JointSourceRevision,
    tcb: &'a JointTcbDeclaration,
    production_replay_sha256: &'a Option<String>,
    cases: &'a [JointCaseEvidence],
}

pub fn joint_evidence_bundle_id(bundle: &JointEvidenceBundle) -> Result<String, String> {
    let projection = BundleIdProjection {
        schema_version: &bundle.schema_version,
        claim_id: &bundle.claim_id,
        source_lock_sha256: &bundle.source_lock_sha256,
        neutral_tree: &bundle.neutral_tree,
        neutral_bundle_sha256: &bundle.neutral_bundle_sha256,
        registry_sha256: &bundle.registry_sha256,
        protocol_schema_sha256: &bundle.protocol_schema_sha256,
        machine_contract_sha256: &bundle.machine_contract_sha256,
        refinement_map_sha256: &bundle.refinement_map_sha256,
        abstract_registry_sha256: &bundle.abstract_registry_sha256,
        visa: &bundle.visa,
        nexus: &bundle.nexus,
        neutral: &bundle.neutral,
        tcb: &bundle.tcb,
        production_replay_sha256: &bundle.production_replay_sha256,
        cases: &bundle.cases,
    };
    let bytes = serde_json::to_vec(&projection)
        .map_err(|error| format!("cannot encode joint bundle-ID projection: {error}"))?;
    let length = u64::try_from(bytes.len())
        .map_err(|_| "joint bundle-ID projection is too large".to_owned())?;
    let mut digest = Sha256::new();
    digest.update(BUNDLE_ID_DOMAIN);
    digest.update(length.to_be_bytes());
    digest.update(bytes);
    let value = digest.finalize().iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    Ok(format!("sha256:{value}"))
}

pub fn seal_joint_evidence_bundle_id(bundle: &mut JointEvidenceBundle) -> Result<(), String> {
    if bundle.production_replay_sha256.is_none() {
        return Err("cannot seal an unpublished joint bundle without production replay".to_owned());
    }
    bundle.bundle_id = joint_evidence_bundle_id(bundle)?;
    Ok(())
}
