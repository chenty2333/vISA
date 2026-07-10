use artifact_manifest::{
    ContractCoreCoverageUnitManifest, ContractCoreEvidenceManifest, ContractCoreFactManifest,
};
use contract_core::{
    FEATURE_002_EVIDENCE_BOUNDARY, FEATURE_002_EVIDENCE_SHAPE_STATUS, FEATURE_002_ID,
    phase2_coverage_units,
};

use super::*;

fn feature_002_evidence(carrier_kind: &str) -> ContractCoreEvidenceManifest {
    ContractCoreEvidenceManifest {
        feature_id: FEATURE_002_ID.to_owned(),
        evidence_boundary: FEATURE_002_EVIDENCE_BOUNDARY.as_str().to_owned(),
        carrier_kind: carrier_kind.to_owned(),
        evidence_shape_status: FEATURE_002_EVIDENCE_SHAPE_STATUS.to_owned(),
        contract_facts: phase2_coverage_units()
            .iter()
            .map(|unit| ContractCoreFactManifest {
                kind: "semantic-family".to_owned(),
                subject: unit.unit_id.to_owned(),
                relation: "covers".to_owned(),
                detail: unit.surface.to_owned(),
                evidence_boundary: FEATURE_002_EVIDENCE_BOUNDARY.as_str().to_owned(),
            })
            .collect(),
        coverage_matrix: phase2_coverage_units()
            .iter()
            .map(|unit| ContractCoreCoverageUnitManifest {
                unit_id: unit.unit_id.to_owned(),
                semantic_family: unit.family.as_str().to_owned(),
                owned_surface: unit.surface.to_owned(),
                positive_scenario: unit.positive_scenario.to_owned(),
                negative_scenario: unit.negative_scenario.to_owned(),
                coverage_status: CONTRACT_CORE_COVERAGE_STATUS_COVERED.to_owned(),
            })
            .collect(),
        overclaim_guards: vec![
            "artifact-profile-completion".to_owned(),
            "frontend-personality-breadth".to_owned(),
            "real-target-substrate-behavior".to_owned(),
            "migration-restoration".to_owned(),
            "cross-isa-portability".to_owned(),
        ],
    }
}

fn assert_rejected(envelope: &ContractCoreEvidenceManifest, expected: &str) {
    let message = validate_contract_core_evidence(envelope).expect_err("envelope should reject");
    assert!(message.to_string().contains(expected), "expected {expected:?} in {message}");
}

#[test]
fn feature_002_evidence_fixture_maps_to_artifact_and_migration_carriers() {
    let artifact_evidence = feature_002_evidence("artifact-shaped");
    validate_contract_core_evidence(&artifact_evidence).expect("artifact-shaped evidence");

    let mut manifest = valid_manifest();
    manifest.contract_core_evidence = Some(artifact_evidence);
    validate_artifact_manifest(&manifest).expect("artifact manifest with Feature 002 evidence");

    let migration_evidence = feature_002_evidence("migration-shaped");
    validate_contract_core_evidence(&migration_evidence).expect("migration-shaped evidence");

    let mut package = minimal_migration_package();
    package.contract_core_evidence = Some(migration_evidence);
    validate_migration_package(&package).expect("migration package with Feature 002 evidence");
}

#[test]
fn coverage_matrix_requires_every_canonical_phase2_unit_with_positive_and_negative_cases() {
    let mut missing = feature_002_evidence("artifact-shaped");
    missing.coverage_matrix.pop();
    assert_rejected(&missing, "coverage matrix size mismatch");

    let mut positive_only = feature_002_evidence("artifact-shaped");
    positive_only.coverage_matrix[0].negative_scenario.clear();
    assert_rejected(&positive_only, "positive and negative scenarios");

    let mut deferred = feature_002_evidence("artifact-shaped");
    deferred.coverage_matrix[0].coverage_status = "deferred".to_owned();
    assert_rejected(&deferred, "is not covered");

    let mut unknown = feature_002_evidence("artifact-shaped");
    unknown.coverage_matrix[0].unit_id = "phase2.unknown".to_owned();
    assert_rejected(&unknown, "unknown contract core coverage unit");
}

#[test]
fn feature_002_carriers_reject_overclaims_and_missing_scope_guards() {
    let mut overclaim = feature_002_evidence("artifact-shaped");
    overclaim.contract_facts[0].detail =
        "claims real-target-substrate behavior for guest memory".to_owned();
    assert_rejected(&overclaim, "overclaims deferred roadmap surface");

    let mut missing_guard = feature_002_evidence("artifact-shaped");
    missing_guard.overclaim_guards.retain(|entry| entry != "migration-restoration");
    assert_rejected(&missing_guard, "missing overclaim guard");
}

#[test]
fn feature_002_evidence_boundary_is_semantic_model_only() {
    let mut carrier_overclaim = feature_002_evidence("artifact-shaped");
    carrier_overclaim.evidence_boundary = "portable-artifact-execution".to_owned();
    assert_rejected(&carrier_overclaim, "semantic-model boundary");

    let mut fact_overclaim = feature_002_evidence("artifact-shaped");
    fact_overclaim.contract_facts[0].evidence_boundary = "reference-service".to_owned();
    assert_rejected(&fact_overclaim, "fact must stay at the semantic-model boundary");
}

#[test]
fn artifact_and_migration_paths_reject_the_wrong_carrier_shape() {
    let mut manifest = valid_manifest();
    manifest.contract_core_evidence = Some(feature_002_evidence("migration-shaped"));
    let message = validate_artifact_manifest(&manifest).expect_err("artifact carrier mismatch");
    assert!(message.to_string().contains("carrier kind mismatch"));

    let mut package = minimal_migration_package();
    package.contract_core_evidence = Some(feature_002_evidence("artifact-shaped"));
    let message = validate_migration_package(&package).expect_err("migration carrier mismatch");
    assert!(message.to_string().contains("carrier kind mismatch"));
}
