use super::*;

pub const CONTRACT_CORE_COVERAGE_STATUS_COVERED: &str = "covered";

const REQUIRED_OVERCLAIM_GUARDS: [&str; 5] = [
    "artifact-profile-completion",
    "frontend-personality-breadth",
    "real-target-substrate-behavior",
    "migration-restoration",
    "cross-isa-portability",
];

const OVERCLAIM_FACT_MARKERS: [&str; 8] = [
    "reference-service",
    "reference-aot-harness",
    "portable-artifact-execution",
    "real-target-substrate",
    "artifact-profile-completion",
    "frontend-personality-breadth",
    "migration-restoration",
    "cross-isa-portability",
];

pub fn artifact_contract_core_evidence(
    manifest: &ArtifactBundleManifest,
) -> Option<&ContractCoreEvidenceManifest> {
    manifest.contract_core_evidence.as_ref()
}

pub fn migration_contract_core_evidence(
    package: &MigrationPackageManifest,
) -> Option<&ContractCoreEvidenceManifest> {
    package.contract_core_evidence.as_ref()
}

pub fn validate_artifact_contract_core_evidence(
    manifest: &ArtifactBundleManifest,
) -> ContractResult<()> {
    match artifact_contract_core_evidence(manifest) {
        Some(envelope) => validate_contract_core_evidence_carrier(
            envelope,
            ContractEvidenceCarrierKind::ArtifactShaped,
        ),
        None => Ok(()),
    }
}

pub fn validate_migration_contract_core_evidence(
    package: &MigrationPackageManifest,
) -> ContractResult<()> {
    match migration_contract_core_evidence(package) {
        Some(envelope) => validate_contract_core_evidence_carrier(
            envelope,
            ContractEvidenceCarrierKind::MigrationShaped,
        ),
        None => Ok(()),
    }
}

pub fn validate_contract_core_evidence(
    envelope: &ContractCoreEvidenceManifest,
) -> ContractResult<()> {
    let carrier_kind = parse_carrier_kind(envelope)?;
    validate_contract_core_evidence_carrier(envelope, carrier_kind)
}

pub fn validate_contract_core_evidence_carrier(
    envelope: &ContractCoreEvidenceManifest,
    expected_carrier: ContractEvidenceCarrierKind,
) -> ContractResult<()> {
    if envelope.feature_id != FEATURE_002_ID {
        return Err(ContractError::new("contract core evidence feature id mismatch"));
    }
    let carrier_kind = parse_carrier_kind(envelope)?;
    if carrier_kind != expected_carrier {
        return Err(ContractError::new("contract core evidence carrier kind mismatch"));
    }
    if envelope.evidence_shape_status != FEATURE_002_EVIDENCE_SHAPE_STATUS {
        return Err(ContractError::new("contract core evidence shape must remain feature-local"));
    }
    let evidence_boundary = EvidenceBoundaryLevel::parse(&envelope.evidence_boundary)
        .ok_or_else(|| ContractError::new("unknown contract core evidence boundary"))?;
    if evidence_boundary != FEATURE_002_EVIDENCE_BOUNDARY {
        return Err(ContractError::new(
            "Feature 002 evidence must stay at the semantic-model boundary",
        ));
    }

    validate_overclaim_guards(envelope)?;
    validate_contract_facts(envelope)?;
    validate_coverage_matrix(envelope)?;
    Ok(())
}

fn parse_carrier_kind(
    envelope: &ContractCoreEvidenceManifest,
) -> ContractResult<ContractEvidenceCarrierKind> {
    ContractEvidenceCarrierKind::parse(&envelope.carrier_kind)
        .ok_or_else(|| ContractError::new("unknown contract core evidence carrier kind"))
}

fn validate_overclaim_guards(envelope: &ContractCoreEvidenceManifest) -> ContractResult<()> {
    for guard in REQUIRED_OVERCLAIM_GUARDS {
        if !envelope.overclaim_guards.iter().any(|entry| entry == guard) {
            return Err(ContractError::new(format!(
                "contract core evidence missing overclaim guard: {guard}"
            )));
        }
    }
    Ok(())
}

fn validate_contract_facts(envelope: &ContractCoreEvidenceManifest) -> ContractResult<()> {
    if envelope.contract_facts.is_empty() {
        return Err(ContractError::new("contract core evidence contains no contract facts"));
    }
    for fact in &envelope.contract_facts {
        if fact.kind.is_empty()
            || fact.subject.is_empty()
            || fact.relation.is_empty()
            || fact.detail.is_empty()
        {
            return Err(ContractError::new("contract core evidence contains an empty fact field"));
        }
        let boundary = EvidenceBoundaryLevel::parse(&fact.evidence_boundary)
            .ok_or_else(|| ContractError::new("unknown contract core fact evidence boundary"))?;
        if boundary != FEATURE_002_EVIDENCE_BOUNDARY {
            return Err(ContractError::new(
                "contract core fact must stay at the semantic-model boundary",
            ));
        }
        reject_fact_overclaim(&fact.kind)?;
        reject_fact_overclaim(&fact.subject)?;
        reject_fact_overclaim(&fact.relation)?;
        reject_fact_overclaim(&fact.detail)?;
    }
    Ok(())
}

fn reject_fact_overclaim(value: &str) -> ContractResult<()> {
    for marker in OVERCLAIM_FACT_MARKERS {
        if value.contains(marker) {
            return Err(ContractError::new(format!(
                "contract core fact overclaims deferred roadmap surface: {marker}"
            )));
        }
    }
    Ok(())
}

fn validate_coverage_matrix(envelope: &ContractCoreEvidenceManifest) -> ContractResult<()> {
    let expected = phase2_coverage_units();
    if envelope.coverage_matrix.len() != expected.len() {
        return Err(ContractError::new("contract core coverage matrix size mismatch"));
    }

    for entry in &envelope.coverage_matrix {
        if phase2_coverage_unit(&entry.unit_id).is_none() {
            return Err(ContractError::new(format!(
                "unknown contract core coverage unit: {}",
                entry.unit_id
            )));
        }
    }

    for expected_unit in expected {
        let Some(entry) =
            envelope.coverage_matrix.iter().find(|entry| entry.unit_id == expected_unit.unit_id)
        else {
            return Err(ContractError::new(format!(
                "missing contract core coverage unit: {}",
                expected_unit.unit_id
            )));
        };
        if entry.semantic_family != expected_unit.family.as_str()
            || entry.owned_surface != expected_unit.surface
        {
            return Err(ContractError::new(format!(
                "contract core coverage unit {} does not match canonical registry",
                expected_unit.unit_id
            )));
        }
        if entry.positive_scenario.is_empty() || entry.negative_scenario.is_empty() {
            return Err(ContractError::new(format!(
                "contract core coverage unit {} must include positive and negative scenarios",
                expected_unit.unit_id
            )));
        }
        if entry.coverage_status != CONTRACT_CORE_COVERAGE_STATUS_COVERED {
            return Err(ContractError::new(format!(
                "contract core coverage unit {} is not covered",
                expected_unit.unit_id
            )));
        }
    }
    Ok(())
}
