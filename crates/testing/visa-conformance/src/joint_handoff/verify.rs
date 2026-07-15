use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use contract_core::{Digest, Identity, canonical_bytes, canonical_digest};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use super::{model::*, provenance::joint_evidence_bundle_id};

const RECEIPT_DOMAIN: &[u8] = b"vISA/joint-handoff/receipt/v1\0";
const REQUEST_PARAMETERS_DOMAIN: &[u8] = b"vISA/joint-handoff/request-parameters/v1\0";
const REQUEST_BINDING_DOMAIN: &[u8] = b"vISA/joint-handoff/request-binding/v1\0";
const REFERENCE_AUTHENTICATION_DOMAIN: &[u8] =
    b"vISA/joint-handoff/reference-authentication/v1/not-cryptographic\0";

pub fn parse_joint_handoff_evidence_bundle_json(
    bytes: &[u8],
) -> Result<JointEvidenceBundle, JointEvidenceLoadError> {
    serde_json::from_slice(bytes).map_err(|source| JointEvidenceLoadError {
        code: "invalid-joint-handoff-evidence-json".to_owned(),
        detail: source.to_string(),
    })
}

pub fn gate_joint_handoff_evidence_bundle_json(bytes: &[u8]) -> JointEvidenceGateResult {
    let bundle = match parse_joint_handoff_evidence_bundle_json(bytes) {
        Ok(bundle) => bundle,
        Err(load_error) => {
            return JointEvidenceGateResult {
                ok: false,
                load_error: Some(load_error),
                validation: None,
            };
        }
    };
    let validation = validate_joint_handoff_evidence_bundle(&bundle);
    JointEvidenceGateResult { ok: validation.ok, load_error: None, validation: Some(validation) }
}

/// Structural artifact validation without a trusted source-lock context.
/// Production and downloaded-artifact verification must use the expectations
/// variant below.
#[doc(hidden)]
pub fn gate_joint_handoff_evidence_bundle_json_with_artifacts(
    bytes: &[u8],
    artifact_root: &Path,
) -> JointEvidenceGateResult {
    let bundle = match parse_joint_handoff_evidence_bundle_json(bytes) {
        Ok(bundle) => bundle,
        Err(load_error) => {
            return JointEvidenceGateResult {
                ok: false,
                load_error: Some(load_error),
                validation: None,
            };
        }
    };
    let mut validation = validate_joint_handoff_evidence_bundle(&bundle);
    validate_joint_artifacts(&bundle, bytes, artifact_root, &mut validation.findings);
    validation.ok = validation.findings.is_empty();
    JointEvidenceGateResult { ok: validation.ok, load_error: None, validation: Some(validation) }
}

pub fn gate_joint_handoff_evidence_bundle_json_with_artifacts_and_expectations(
    bytes: &[u8],
    artifact_root: &Path,
    expectations: &JointEvidenceExpectations,
) -> JointEvidenceGateResult {
    let bundle = match parse_joint_handoff_evidence_bundle_json(bytes) {
        Ok(bundle) => bundle,
        Err(load_error) => {
            return JointEvidenceGateResult {
                ok: false,
                load_error: Some(load_error),
                validation: None,
            };
        }
    };
    let mut validation = validate_joint_handoff_evidence_bundle(&bundle);
    validate_joint_evidence_expectations(&bundle, expectations, &mut validation.findings);
    validate_joint_artifacts(&bundle, bytes, artifact_root, &mut validation.findings);
    validation.ok = validation.findings.is_empty();
    JointEvidenceGateResult { ok: validation.ok, load_error: None, validation: Some(validation) }
}

pub fn joint_handoff_registry_sha256() -> String {
    let bytes = serde_json::to_vec(JOINT_HANDOFF_CASE_DEFINITIONS)
        .expect("static joint-handoff registry serializes");
    sha256_hex(&bytes)
}

pub fn joint_raw_trace_sha256(trace: &JointRawTrace) -> Result<String, String> {
    serde_json::to_vec(trace)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|source| format!("cannot encode raw joint trace: {source}"))
}

pub fn joint_mapping_digest(mapping: &JointMappingManifest) -> Result<Digest, String> {
    canonical_digest(mapping).map_err(|_| "cannot encode joint mapping manifest".to_owned())
}

pub fn joint_effect_cohort_digest(
    key: JointHandoffKey,
    effects: impl IntoIterator<Item = JointEffectRecord>,
) -> Result<Digest, String> {
    let mut effects: Vec<_> = effects.into_iter().collect();
    effects.sort_by_key(|record| record.effect);
    canonical_digest(&JointEffectCohortManifest {
        schema_version: JOINT_HANDOFF_EFFECT_MANIFEST_SCHEMA_VERSION.to_owned(),
        key,
        effects,
    })
    .map_err(|_| "cannot encode joint effect cohort".to_owned())
}

pub fn joint_classification_root(
    key: JointHandoffKey,
    effects: impl IntoIterator<Item = JointEffectRecord>,
) -> Result<Digest, String> {
    #[derive(Serialize)]
    struct ClassificationProjection {
        schema_version: &'static str,
        key: JointHandoffKey,
        entries: Vec<ClassificationEntry>,
    }

    #[derive(Serialize)]
    struct ClassificationEntry {
        effect: Identity,
        classification: JointEffectClassification,
        outcome_digest: Option<Digest>,
        tombstone_digest: Option<Digest>,
    }

    let mut entries: Vec<_> = effects
        .into_iter()
        .map(|record| ClassificationEntry {
            effect: record.effect,
            classification: record.classification,
            outcome_digest: record.outcome_digest,
            tombstone_digest: record.tombstone_digest,
        })
        .collect();
    entries.sort_by_key(|record| record.effect);
    canonical_digest(&ClassificationProjection {
        schema_version: JOINT_HANDOFF_EFFECT_MANIFEST_SCHEMA_VERSION,
        key,
        entries,
    })
    .map_err(|_| "cannot encode joint classification projection".to_owned())
}

pub fn joint_classification_counts(
    effects: impl IntoIterator<Item = JointEffectRecord>,
) -> ClassificationCounts {
    let mut counts = ClassificationCounts::default();
    for effect in effects {
        counts.registered = counts.registered.saturating_add(1);
        match effect.classification {
            JointEffectClassification::Registered => {}
            JointEffectClassification::Committed => {
                counts.committed = counts.committed.saturating_add(1);
            }
            JointEffectClassification::Aborted => {
                counts.aborted = counts.aborted.saturating_add(1);
            }
            JointEffectClassification::ResolvedTombstone => {
                counts.committed = counts.committed.saturating_add(1);
                counts.tombstones = counts.tombstones.saturating_add(1);
            }
            JointEffectClassification::UnresolvedTombstone => {
                counts.unresolved = counts.unresolved.saturating_add(1);
                counts.tombstones = counts.tombstones.saturating_add(1);
            }
        }
    }
    counts
}

pub fn joint_receipt_ref(receipt: &JointReceipt) -> Result<ReceiptRef, String> {
    let header = receipt.header();
    let bytes = match receipt {
        JointReceipt::PrepareIntent(value) => canonical_bytes(value),
        JointReceipt::VisaFreeze(value) => canonical_bytes(value),
        JointReceipt::EffectFreeze(value) => canonical_bytes(value),
        JointReceipt::DestinationPrepared(value) => canonical_bytes(value.as_ref()),
        JointReceipt::OwnershipPrepared(value) => canonical_bytes(value.as_ref()),
        JointReceipt::OwnershipAbort(value) => canonical_bytes(value),
        JointReceipt::OwnershipCommit(value) => canonical_bytes(value),
        JointReceipt::EffectThaw(value) => canonical_bytes(value),
        JointReceipt::ClosureProgress(value) => canonical_bytes(value),
        JointReceipt::Closure(value) => canonical_bytes(value),
        JointReceipt::RetainedTombstone(value) => canonical_bytes(value),
        JointReceipt::VisaSourceFence(value) => canonical_bytes(value),
        JointReceipt::VisaSourceResume(value) => canonical_bytes(value),
        JointReceipt::VisaDestinationActivation(value) => canonical_bytes(value),
    }
    .map_err(|_| "cannot encode joint receipt".to_owned())?;
    let length = u64::try_from(bytes.len()).map_err(|_| "joint receipt is too large")?;
    let mut digest = Sha256::new();
    digest.update(RECEIPT_DOMAIN);
    digest.update([receipt.kind() as u8]);
    digest.update(length.to_be_bytes());
    digest.update(bytes);
    Ok(ReceiptRef {
        version: header.version,
        kind: receipt.kind(),
        handoff: receipt.key().handoff,
        issuer: header.issuer,
        issuer_incarnation: header.issuer_incarnation,
        key_id: header.key_id,
        log_id: header.log_id,
        sequence: header.sequence,
        digest: Digest::from_bytes(digest.finalize().into()),
    })
}

pub fn joint_receipt_payload_digest(receipt: &JointReceipt) -> Result<Digest, String> {
    match receipt {
        JointReceipt::PrepareIntent(value) => canonical_digest(value),
        JointReceipt::VisaFreeze(value) => canonical_digest(value),
        JointReceipt::EffectFreeze(value) => canonical_digest(value),
        JointReceipt::DestinationPrepared(value) => canonical_digest(value.as_ref()),
        JointReceipt::OwnershipPrepared(value) => canonical_digest(value.as_ref()),
        JointReceipt::OwnershipAbort(value) => canonical_digest(value),
        JointReceipt::OwnershipCommit(value) => canonical_digest(value),
        JointReceipt::EffectThaw(value) => canonical_digest(value),
        JointReceipt::ClosureProgress(value) => canonical_digest(value),
        JointReceipt::Closure(value) => canonical_digest(value),
        JointReceipt::RetainedTombstone(value) => canonical_digest(value),
        JointReceipt::VisaSourceFence(value) => canonical_digest(value),
        JointReceipt::VisaSourceResume(value) => canonical_digest(value),
        JointReceipt::VisaDestinationActivation(value) => canonical_digest(value),
    }
    .map_err(|_| "cannot encode joint receipt payload".to_owned())
}

pub fn joint_receipt_request(receipt: &JointReceipt, operation: Identity) -> ReceiptRequest {
    let header = receipt.header();
    ReceiptRequest {
        version: header.version,
        kind: receipt.kind(),
        key: receipt.key(),
        operation,
        expected_state_sequence: header.sequence,
        expected_previous_receipt_digest: header.previous_digest,
        parameters: joint_receipt_request_parameters(receipt),
    }
}

pub fn joint_receipt_request_parameters(receipt: &JointReceipt) -> ReceiptRequestParameters {
    match receipt {
        JointReceipt::PrepareIntent(value) => ReceiptRequestParameters::PrepareIntent {
            ownership_service: value.ownership_service,
            service_incarnation: value.service_incarnation,
            reservation: value.reservation,
            intent_revision: value.intent_revision,
            service_request_digest: value.request_digest,
        },
        JointReceipt::VisaFreeze(value) => {
            ReceiptRequestParameters::VisaFreeze { intent: value.intent }
        }
        JointReceipt::EffectFreeze(value) => ReceiptRequestParameters::NexusFreeze {
            intent: value.intent,
            registry_instance: value.registry_instance,
            scope_id: value.scope_id,
            scope_generation: value.scope_generation,
            authority_epoch: value.authority_epoch,
            freeze_generation: value.freeze_generation,
            domain_bindings_digest: value.domain_bindings_digest,
            effect_cohort_digest: value.effect_cohort_digest,
        },
        JointReceipt::DestinationPrepared(value) => ReceiptRequestParameters::DestinationPrepared {
            intent: value.intent,
            visa_freeze: value.visa_freeze,
            nexus_freeze: value.nexus_freeze,
            snapshot: value.snapshot,
            joint_mapping_manifest_digest: value.joint_mapping_manifest_digest,
            lease_commit_operation: value.lease_commit_operation,
            lease_commit_idempotency: value.lease_commit_idempotency,
            lease_commit_request_digest: value.lease_commit_request_digest,
        },
        JointReceipt::OwnershipPrepared(value) => ReceiptRequestParameters::OwnershipPrepared {
            reservation: value.reservation,
            intent: value.intent,
            visa_freeze: value.visa_freeze,
            nexus_freeze: value.nexus_freeze,
            destination_prepared: value.destination_prepared,
            bindings: Box::new(value.bindings),
            prepared_revision: value.prepared_revision,
        },
        JointReceipt::OwnershipAbort(value) => ReceiptRequestParameters::OwnershipAbort {
            reservation: value.reservation,
            basis: value.basis,
            basis_revision: value.basis_revision,
            decision_sequence: value.decision_sequence,
        },
        JointReceipt::OwnershipCommit(value) => ReceiptRequestParameters::OwnershipCommit {
            reservation: value.reservation,
            prepared: value.prepared,
            prepared_revision: value.prepared_revision,
            decision_sequence: value.decision_sequence,
        },
        JointReceipt::EffectThaw(value) => ReceiptRequestParameters::NexusThaw {
            abort: value.abort,
            nexus_freeze: value.nexus_freeze,
            thaw_generation: value.thaw_generation,
        },
        JointReceipt::ClosureProgress(value) => ReceiptRequestParameters::ClosureProgress {
            commit: value.commit,
            nexus_freeze: value.nexus_freeze,
            closure_revision: value.closure_revision,
        },
        JointReceipt::Closure(value) => ReceiptRequestParameters::Closure {
            commit: value.commit,
            nexus_freeze: value.nexus_freeze,
            closure_revision: value.closure_revision,
            effect_manifest_digest: value.effect_manifest_digest,
            closed_authority_epoch: value.closed_authority_epoch,
        },
        JointReceipt::RetainedTombstone(value) => ReceiptRequestParameters::RetainedTombstone {
            commit: value.commit,
            nexus_freeze: value.nexus_freeze,
            closure_revision: value.closure_revision,
        },
        JointReceipt::VisaSourceFence(value) => ReceiptRequestParameters::VisaSourceFence {
            commit: value.commit,
            closure: value.closure,
        },
        JointReceipt::VisaSourceResume(value) => {
            ReceiptRequestParameters::VisaSourceResume { abort: value.abort, thaw: value.thaw }
        }
        JointReceipt::VisaDestinationActivation(value) => {
            ReceiptRequestParameters::VisaDestinationActivation {
                commit: value.commit,
                closure: value.closure,
                source_fence: value.source_fence,
                activation_command: value.activation_command,
                resume_command: value.resume_command,
                activation_attempt_record_digest: value.activation_attempt_record_digest,
            }
        }
    }
}

pub fn joint_receipt_request_parameters_digest(
    parameters: &ReceiptRequestParameters,
) -> Result<Digest, String> {
    domain_digest(REQUEST_PARAMETERS_DOMAIN, parameters)
}

pub fn joint_receipt_request_binding(
    request: &ReceiptRequest,
) -> Result<ReceiptRequestBinding, String> {
    Ok(ReceiptRequestBinding {
        version: request.version,
        kind: request.kind,
        key: request.key,
        operation: request.operation,
        expected_state_sequence: request.expected_state_sequence,
        expected_previous_receipt_digest: request.expected_previous_receipt_digest,
        parameters_digest: joint_receipt_request_parameters_digest(&request.parameters)?,
    })
}

pub fn joint_receipt_request_digest(request: &ReceiptRequest) -> Result<Digest, String> {
    domain_digest(REQUEST_BINDING_DOMAIN, &joint_receipt_request_binding(request)?)
}

pub fn joint_receipt_request_matches(request: &ReceiptRequest, receipt: &JointReceipt) -> bool {
    let header = receipt.header();
    request.version == header.version
        && request.version == JointProtocolVersion::V1
        && request.kind == receipt.kind()
        && request.key == receipt.key()
        && !request.operation.is_zero()
        && request.expected_state_sequence == header.sequence
        && request.expected_previous_receipt_digest == header.previous_digest
        && request.parameters.kind() == request.kind
        && request.parameters == joint_receipt_request_parameters(receipt)
}

pub fn joint_receipt_envelope(
    receipt: &JointReceipt,
    request: &ReceiptRequest,
) -> Result<ReceiptEnvelope, String> {
    if !joint_receipt_request_matches(request, receipt) {
        return Err("typed receipt issuance binding does not match receipt inputs".to_owned());
    }
    let header = receipt.header();
    let mut envelope = ReceiptEnvelope {
        schema: header.version,
        issuer: header.issuer,
        issuer_incarnation: header.issuer_incarnation,
        kind: receipt.kind(),
        handoff: receipt.key().handoff,
        request_digest: joint_receipt_request_digest(request)?,
        state_sequence: header.sequence,
        payload_digest: joint_receipt_payload_digest(receipt)?,
        previous_receipt_digest: header.previous_digest,
        authentication: Vec::new(),
    };
    envelope.authentication = joint_reference_authentication(&envelope)?;
    Ok(envelope)
}

/// Recomputable reference checksum. This is intentionally not cryptographic
/// issuer authentication and must not be treated as a signature or MAC.
pub fn joint_reference_authentication(envelope: &ReceiptEnvelope) -> Result<Vec<u8>, String> {
    let digest = canonical_digest(&(
        REFERENCE_AUTHENTICATION_DOMAIN,
        JOINT_REFERENCE_AUTHENTICATION_SCHEME,
        envelope.schema,
        envelope.issuer,
        envelope.issuer_incarnation,
        envelope.kind,
        envelope.handoff,
        envelope.request_digest,
        envelope.state_sequence,
        envelope.payload_digest,
        envelope.previous_receipt_digest,
    ))
    .map_err(|_| "cannot encode reference authentication projection".to_owned())?;
    let mut authentication = JOINT_REFERENCE_AUTHENTICATION_SCHEME.as_bytes().to_vec();
    authentication.push(0);
    authentication.extend_from_slice(&digest.0);
    Ok(authentication)
}

fn domain_digest<T: Serialize + ?Sized>(domain: &[u8], value: &T) -> Result<Digest, String> {
    let encoded =
        canonical_bytes(value).map_err(|_| "cannot encode request projection".to_owned())?;
    let length =
        u64::try_from(encoded.len()).map_err(|_| "request projection is too large".to_owned())?;
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(length.to_be_bytes());
    digest.update(encoded);
    Ok(Digest::from_bytes(digest.finalize().into()))
}

pub fn validate_joint_handoff_evidence_bundle(
    bundle: &JointEvidenceBundle,
) -> JointValidationReport {
    let mut findings = Vec::new();
    validate_bundle_shape(bundle, &mut findings);
    validate_cases(bundle, &mut findings);
    validate_bundle_native_namespaces(bundle, &mut findings);
    JointValidationReport { ok: findings.is_empty(), findings }
}

fn validate_bundle_shape(bundle: &JointEvidenceBundle, findings: &mut Vec<JointValidationFinding>) {
    if bundle.schema_version != JOINT_HANDOFF_EVIDENCE_SCHEMA_VERSION {
        finding(
            findings,
            "unsupported-joint-evidence-schema",
            None,
            None,
            bundle.schema_version.clone(),
        );
    }
    if bundle.claim_id != JOINT_HANDOFF_CLAIM_ID {
        finding(findings, "invalid-joint-claim", None, None, bundle.claim_id.clone());
    }
    if bundle.production_replay_sha256.as_deref().is_some_and(|digest| !valid_sha256(digest)) {
        finding(
            findings,
            "invalid-joint-production-replay-digest",
            None,
            None,
            "production replay digest is not lowercase SHA-256",
        );
    }
    for (label, digest) in [
        ("source lock", &bundle.source_lock_sha256),
        ("neutral Git bundle", &bundle.neutral_bundle_sha256),
        ("protocol Markdown", &bundle.protocol_schema_sha256),
        ("machine TOML", &bundle.machine_contract_sha256),
        ("refinement map", &bundle.refinement_map_sha256),
        ("abstract registry", &bundle.abstract_registry_sha256),
    ] {
        if valid_sha256(digest) {
            continue;
        }
        finding(
            findings,
            "invalid-joint-input-digest",
            None,
            None,
            format!("{label} digest is not lowercase SHA-256"),
        );
    }
    if !valid_git_sha(&bundle.neutral_tree) {
        finding(
            findings,
            "invalid-joint-input-digest",
            None,
            None,
            "neutral tree is not a lowercase 40-hex Git object ID",
        );
    }
    match &bundle.production_replay_sha256 {
        None if bundle.bundle_id != JOINT_UNPUBLISHED_BUNDLE_ID => finding(
            findings,
            "invalid-joint-bundle-id",
            None,
            None,
            "an unpublished bundle must use the explicit unpublished sentinel",
        ),
        Some(_) => match joint_evidence_bundle_id(bundle) {
            Ok(expected) if bundle.bundle_id == expected => {}
            Ok(expected) => finding(
                findings,
                "invalid-joint-bundle-id",
                None,
                None,
                format!("bundle={}, recomputed={expected}", bundle.bundle_id),
            ),
            Err(error) => finding(findings, "invalid-joint-bundle-id", None, None, error),
        },
        None => {}
    }
    let computed_registry = joint_handoff_registry_sha256();
    if bundle.registry_sha256 != JOINT_HANDOFF_ACCEPTED_REGISTRY_SHA256
        || computed_registry != JOINT_HANDOFF_ACCEPTED_REGISTRY_SHA256
    {
        finding(
            findings,
            "invalid-joint-case-registry",
            None,
            None,
            format!(
                "bundle={}, computed={}, accepted={}",
                bundle.registry_sha256, computed_registry, JOINT_HANDOFF_ACCEPTED_REGISTRY_SHA256
            ),
        );
    }
    for (label, revision, repository, role, checkout_clean) in [
        (
            "vISA",
            &bundle.visa,
            JOINT_VISA_REPOSITORY,
            JointSourceRole::ExecutedCheckout,
            Some(true),
        ),
        ("Nexus", &bundle.nexus, JOINT_NEXUS_REPOSITORY, JointSourceRole::SourceLockOnly, None),
        (
            "neutral artifact",
            &bundle.neutral,
            JOINT_NEUTRAL_REPOSITORY,
            JointSourceRole::SourceLockOnly,
            None,
        ),
    ] {
        if revision.repository != repository
            || !valid_git_sha(&revision.git_sha)
            || revision.role != role
            || revision.checkout_clean != checkout_clean
        {
            finding(
                findings,
                "invalid-joint-source-revision",
                None,
                None,
                format!(
                    "{label} does not have its canonical repository, role, clean-state semantics, and exact lowercase 40-hex revision"
                ),
            );
        }
    }
    let tcb = &bundle.tcb;
    if !tcb.ownership_log_non_equivocating
        || !tcb.ownership_log_not_rolled_back
        || !tcb.native_receipt_verifiers_pinned
        || !tcb.exclusive_trusted_coordinator_api
        || !tcb.crash_stable_freeze_marker
        || !tcb.fail_closed_recovery
        || !tcb.same_boot_only
        || tcb.hostile_storage_rollback_covered
        || tcb.host_reboot_covered
        || tcb.confidential_transport_covered
    {
        finding(
            findings,
            "invalid-joint-tcb-declaration",
            None,
            None,
            "TCB declaration widens or weakens the bounded same-boot qualification profile",
        );
    }
}

fn validate_joint_evidence_expectations(
    bundle: &JointEvidenceBundle,
    expectations: &JointEvidenceExpectations,
    findings: &mut Vec<JointValidationFinding>,
) {
    for (label, value, valid) in [
        ("vISA revision", &expectations.visa_git_sha, valid_git_sha(&expectations.visa_git_sha)),
        ("Nexus revision", &expectations.nexus_git_sha, valid_git_sha(&expectations.nexus_git_sha)),
        (
            "neutral revision",
            &expectations.neutral_git_sha,
            valid_git_sha(&expectations.neutral_git_sha),
        ),
        ("neutral tree", &expectations.neutral_tree, valid_git_sha(&expectations.neutral_tree)),
        (
            "neutral Git bundle digest",
            &expectations.neutral_bundle_sha256,
            valid_sha256(&expectations.neutral_bundle_sha256),
        ),
        (
            "source-lock digest",
            &expectations.source_lock_sha256,
            valid_sha256(&expectations.source_lock_sha256),
        ),
        (
            "protocol Markdown digest",
            &expectations.protocol_schema_sha256,
            valid_sha256(&expectations.protocol_schema_sha256),
        ),
        (
            "machine TOML digest",
            &expectations.machine_contract_sha256,
            valid_sha256(&expectations.machine_contract_sha256),
        ),
        (
            "refinement-map digest",
            &expectations.refinement_map_sha256,
            valid_sha256(&expectations.refinement_map_sha256),
        ),
        (
            "abstract-registry digest",
            &expectations.abstract_registry_sha256,
            valid_sha256(&expectations.abstract_registry_sha256),
        ),
    ] {
        if !valid {
            finding(
                findings,
                "invalid-joint-evidence-expectations",
                None,
                None,
                format!("{label} is malformed: {value}"),
            );
        }
    }
    for (label, actual, expected) in [
        ("vISA revision", bundle.visa.git_sha.as_str(), expectations.visa_git_sha.as_str()),
        ("Nexus revision", bundle.nexus.git_sha.as_str(), expectations.nexus_git_sha.as_str()),
        (
            "neutral revision",
            bundle.neutral.git_sha.as_str(),
            expectations.neutral_git_sha.as_str(),
        ),
        ("neutral tree", bundle.neutral_tree.as_str(), expectations.neutral_tree.as_str()),
        (
            "neutral Git bundle digest",
            bundle.neutral_bundle_sha256.as_str(),
            expectations.neutral_bundle_sha256.as_str(),
        ),
        (
            "source-lock digest",
            bundle.source_lock_sha256.as_str(),
            expectations.source_lock_sha256.as_str(),
        ),
        (
            "protocol Markdown digest",
            bundle.protocol_schema_sha256.as_str(),
            expectations.protocol_schema_sha256.as_str(),
        ),
        (
            "machine TOML digest",
            bundle.machine_contract_sha256.as_str(),
            expectations.machine_contract_sha256.as_str(),
        ),
        (
            "refinement-map digest",
            bundle.refinement_map_sha256.as_str(),
            expectations.refinement_map_sha256.as_str(),
        ),
        (
            "abstract-registry digest",
            bundle.abstract_registry_sha256.as_str(),
            expectations.abstract_registry_sha256.as_str(),
        ),
    ] {
        if actual != expected {
            finding(
                findings,
                "joint-evidence-expectation-mismatch",
                None,
                None,
                format!("{label}: bundle={actual}, expected={expected}"),
            );
        }
    }
}

fn validate_cases(bundle: &JointEvidenceBundle, findings: &mut Vec<JointValidationFinding>) {
    if bundle.cases.len() != JOINT_HANDOFF_CASE_COUNT
        || JOINT_HANDOFF_CASE_DEFINITIONS.len() != JOINT_HANDOFF_CASE_COUNT
    {
        finding(
            findings,
            "invalid-joint-case-count",
            None,
            None,
            format!("expected {JOINT_HANDOFF_CASE_COUNT}, observed {}", bundle.cases.len()),
        );
    }
    let mut ids = BTreeSet::new();
    for (index, definition) in JOINT_HANDOFF_CASE_DEFINITIONS.iter().enumerate() {
        let Some(case) = bundle.cases.get(index) else {
            continue;
        };
        if !ids.insert(case.case_id.as_str()) {
            finding(
                findings,
                "duplicate-joint-case",
                Some(&case.case_id),
                None,
                "case ID appears more than once",
            );
        }
        if case.case_id != definition.id {
            finding(
                findings,
                "invalid-joint-case-order",
                Some(&case.case_id),
                None,
                format!("expected {} at registry position {index}", definition.id),
            );
        }
        validate_case(case, definition, findings);
    }
}

type NativeLogNamespace = (Identity, Identity, Identity, Identity);
type NativeLogSlot = (Identity, Identity, Identity, Identity, u64);

fn validate_bundle_native_namespaces(
    bundle: &JointEvidenceBundle,
    findings: &mut Vec<JointValidationFinding>,
) {
    let mut handoffs = BTreeMap::<Identity, String>::new();
    let mut reservations = BTreeMap::<Identity, String>::new();
    let mut namespaces = BTreeMap::<NativeLogNamespace, (String, &'static str)>::new();
    let mut slots = BTreeMap::<NativeLogSlot, (Digest, String)>::new();
    let mut terminals = BTreeMap::<(Identity, Identity), (ReceiptKind, Digest, String)>::new();

    for case in &bundle.cases {
        if let Some(previous) = handoffs.insert(case.trace.key.handoff, case.case_id.clone()) {
            finding(
                findings,
                "duplicate-joint-case-handoff",
                Some(&case.case_id),
                None,
                format!("handoff aliases case {previous}"),
            );
        }
        for (role, issuer) in [
            ("ownership", case.trace.issuers.ownership),
            ("visa-source", case.trace.issuers.visa_source),
            ("visa-destination", case.trace.issuers.visa_destination),
            ("effect-closure", case.trace.issuers.effect_closure),
        ] {
            let namespace = issuer_namespace(issuer);
            if let Some((previous_case, previous_role)) =
                namespaces.insert(namespace, (case.case_id.clone(), role))
            {
                finding(
                    findings,
                    "aliased-joint-native-log-namespace",
                    Some(&case.case_id),
                    None,
                    format!("{role} aliases {previous_role} in case {previous_case}"),
                );
            }
        }

        for event in &case.trace.events {
            match &event.event {
                JointRawEventKind::ReceiptAccepted { receipt, .. } => {
                    if let JointReceipt::PrepareIntent(intent) = receipt
                        && let Some(previous) =
                            reservations.insert(intent.reservation, case.case_id.clone())
                        && previous != case.case_id
                    {
                        finding(
                            findings,
                            "duplicate-joint-case-reservation",
                            Some(&case.case_id),
                            Some(event.index),
                            format!("reservation aliases case {previous}"),
                        );
                    }
                    observe_bundle_receipt(
                        receipt,
                        &case.case_id,
                        event.index,
                        &mut slots,
                        &mut terminals,
                        findings,
                    );
                }
                JointRawEventKind::ExternalFault {
                    fault: JointExternalFault::CommitAcknowledgementLost { durable_commit },
                    ..
                } => observe_bundle_receipt(
                    &JointReceipt::OwnershipCommit(durable_commit.receipt.clone()),
                    &case.case_id,
                    event.index,
                    &mut slots,
                    &mut terminals,
                    findings,
                ),
                JointRawEventKind::OwnershipQuery {
                    result: OwnershipQueryResult::AbortDecided { observation },
                } => observe_bundle_receipt(
                    &JointReceipt::OwnershipAbort(observation.receipt.clone()),
                    &case.case_id,
                    event.index,
                    &mut slots,
                    &mut terminals,
                    findings,
                ),
                JointRawEventKind::OwnershipQuery {
                    result: OwnershipQueryResult::CommitDecided { observation },
                } => observe_bundle_receipt(
                    &JointReceipt::OwnershipCommit(observation.receipt.clone()),
                    &case.case_id,
                    event.index,
                    &mut slots,
                    &mut terminals,
                    findings,
                ),
                _ => {}
            }
        }
    }
}

fn observe_bundle_receipt(
    receipt: &JointReceipt,
    case_id: &str,
    event_index: u64,
    slots: &mut BTreeMap<NativeLogSlot, (Digest, String)>,
    terminals: &mut BTreeMap<(Identity, Identity), (ReceiptKind, Digest, String)>,
    findings: &mut Vec<JointValidationFinding>,
) {
    let Ok(reference) = joint_receipt_ref(receipt) else {
        return;
    };
    let header = receipt.header();
    let slot =
        (header.issuer, header.issuer_incarnation, header.key_id, header.log_id, header.sequence);
    if let Some((digest, previous_case)) = slots.get(&slot)
        && *digest != reference.digest
    {
        finding(
            findings,
            "equivocating-joint-native-log-slot",
            Some(case_id),
            Some(event_index),
            format!("native log slot conflicts with case {previous_case}"),
        );
    } else {
        slots.insert(slot, (reference.digest, case_id.to_owned()));
    }

    let terminal = match receipt {
        JointReceipt::OwnershipAbort(value) => {
            Some((value.reservation, ReceiptKind::OwnershipAbort))
        }
        JointReceipt::OwnershipCommit(value) => {
            Some((value.reservation, ReceiptKind::OwnershipCommit))
        }
        _ => None,
    };
    if let Some((reservation, kind)) = terminal {
        let key = (receipt.key().handoff, reservation);
        if let Some((existing_kind, existing_digest, previous_case)) = terminals.get(&key)
            && (*existing_kind != kind || *existing_digest != reference.digest)
        {
            finding(
                findings,
                "conflicting-joint-terminal-authority-facts",
                Some(case_id),
                Some(event_index),
                format!("terminal authority conflicts with case {previous_case}"),
            );
        } else {
            terminals.insert(key, (kind, reference.digest, case_id.to_owned()));
        }
    }
}

fn issuer_namespace(issuer: ReceiptIssuerIdentity) -> NativeLogNamespace {
    (issuer.issuer, issuer.issuer_incarnation, issuer.key_id, issuer.log_id)
}

fn validate_joint_artifacts(
    bundle: &JointEvidenceBundle,
    bundle_bytes: &[u8],
    artifact_root: &Path,
    findings: &mut Vec<JointValidationFinding>,
) {
    match fs::symlink_metadata(artifact_root) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => {
            finding(
                findings,
                "invalid-joint-artifact-root",
                None,
                None,
                "artifact root is not a non-symlink directory",
            );
            return;
        }
        Err(error) => {
            finding(findings, "missing-joint-artifact-root", None, None, error.to_string());
            return;
        }
    }

    let entries = match fs::read_dir(artifact_root) {
        Ok(entries) => entries,
        Err(error) => {
            finding(findings, "unreadable-joint-artifact-root", None, None, error.to_string());
            return;
        }
    };
    let mut names = BTreeSet::new();
    for entry in entries {
        match entry {
            Ok(entry) => {
                let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                    finding(
                        findings,
                        "invalid-joint-artifact-name",
                        None,
                        None,
                        "artifact name is not UTF-8",
                    );
                    continue;
                };
                names.insert(name);
            }
            Err(error) => {
                finding(findings, "unreadable-joint-artifact-entry", None, None, error.to_string())
            }
        }
    }
    let expected = BTreeSet::from([
        "joint-handoff-evidence.json".to_owned(),
        "production-replay.json".to_owned(),
    ]);
    if names != expected {
        finding(
            findings,
            "invalid-joint-artifact-inventory",
            None,
            None,
            format!("expected={expected:?}, actual={names:?}"),
        );
    }

    let published_bundle = read_regular_artifact(
        &artifact_root.join("joint-handoff-evidence.json"),
        "joint-handoff-evidence.json",
        findings,
    );
    if published_bundle.as_deref().is_some_and(|published| published != bundle_bytes) {
        finding(
            findings,
            "joint-bundle-path-content-mismatch",
            None,
            None,
            "the supplied bundle bytes differ from the artifact-root bundle",
        );
    }

    let Some(production_bytes) = read_regular_artifact(
        &artifact_root.join("production-replay.json"),
        "production-replay.json",
        findings,
    ) else {
        return;
    };
    let actual_digest = sha256_hex(&production_bytes);
    if bundle.production_replay_sha256.as_deref() != Some(actual_digest.as_str()) {
        finding(
            findings,
            "joint-production-replay-digest-mismatch",
            None,
            None,
            format!("bundle={:?}, actual={actual_digest}", bundle.production_replay_sha256),
        );
    }
    validate_production_replay_json(bundle, &production_bytes, findings);
}

fn read_regular_artifact(
    path: &Path,
    label: &str,
    findings: &mut Vec<JointValidationFinding>,
) -> Option<Vec<u8>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {}
        Ok(_) => {
            finding(
                findings,
                "invalid-joint-artifact-file",
                None,
                None,
                format!("{label} is not a regular non-symlink file"),
            );
            return None;
        }
        Err(error) => {
            finding(
                findings,
                "missing-joint-artifact-file",
                None,
                None,
                format!("{label}: {error}"),
            );
            return None;
        }
    }
    match fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(error) => {
            finding(
                findings,
                "unreadable-joint-artifact-file",
                None,
                None,
                format!("{label}: {error}"),
            );
            None
        }
    }
}

fn validate_production_replay_json(
    bundle: &JointEvidenceBundle,
    bytes: &[u8],
    findings: &mut Vec<JointValidationFinding>,
) {
    let value: serde_json::Value = match serde_json::from_slice(bytes) {
        Ok(value) => value,
        Err(error) => {
            finding(
                findings,
                "invalid-joint-production-replay-json",
                None,
                None,
                error.to_string(),
            );
            return;
        }
    };
    let Some(object) = value.as_object() else {
        finding(
            findings,
            "invalid-joint-production-replay-shape",
            None,
            None,
            "production replay is not an object",
        );
        return;
    };
    let actual_keys = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected_keys = BTreeSet::from([
        "case_count",
        "accepted_receipts",
        "rejected_receipts",
        "replayed_receipts",
        "all_matched",
        "reference_cell",
        "durable_projection_cell",
        "host_substrate_cell",
    ]);
    if actual_keys != expected_keys {
        finding(
            findings,
            "invalid-joint-production-replay-shape",
            None,
            None,
            format!("expected={expected_keys:?}, actual={actual_keys:?}"),
        );
        return;
    }
    let (accepted, rejected, replayed) = expected_production_counts(bundle);
    for (field, expected) in [
        ("case_count", bundle.cases.len()),
        ("accepted_receipts", accepted),
        ("rejected_receipts", rejected),
        ("replayed_receipts", replayed),
    ] {
        if object.get(field).and_then(serde_json::Value::as_u64) != u64::try_from(expected).ok() {
            finding(
                findings,
                "joint-production-replay-summary-mismatch",
                None,
                None,
                format!("{field} does not equal independently recomputed value {expected}"),
            );
        }
    }
    if object.get("all_matched").and_then(serde_json::Value::as_bool) != Some(true) {
        finding(
            findings,
            "joint-production-replay-summary-mismatch",
            None,
            None,
            "production reducer did not report all traces matched",
        );
    }
    validate_reference_cell_report(object.get("reference_cell"), findings);
    validate_durable_projection_cell(object.get("durable_projection_cell"), findings);
    validate_host_substrate_cell(object.get("host_substrate_cell"), findings);
}

fn validate_durable_projection_cell(
    value: Option<&serde_json::Value>,
    findings: &mut Vec<JointValidationFinding>,
) {
    let Some(value) = value else {
        finding(
            findings,
            "missing-joint-durable-projection-cell",
            None,
            None,
            "production replay does not contain the SQLite durable projection cell",
        );
        return;
    };
    let report: JointDurableProjectionCellReport = match serde_json::from_value(value.clone()) {
        Ok(report) => report,
        Err(error) => {
            finding(
                findings,
                "invalid-joint-durable-projection-cell",
                None,
                None,
                format!("cannot strictly decode durable projection cell: {error}"),
            );
            return;
        }
    };
    if let Err(detail) =
        super::durable_cell_verify::validate_durable_projection_raw_material(&report)
    {
        finding(findings, "invalid-joint-durable-projection-cell", None, None, detail);
        return;
    }
    if report.schema != JOINT_DURABLE_PROJECTION_CELL_SCHEMA_VERSION
        || report.record_count != 3
        || report.recovered_phase != "frozen-unsealed"
        || report.recovered_authentication_count != 2
        || report.abort_probe_authentication_count != 1
        || !report.unknown_effect_freeze_retained
        || !report.abort_blocked_while_unknown
    {
        finding(
            findings,
            "invalid-joint-durable-projection-cell",
            None,
            None,
            format!(
                "schema={}, records={}, phase={}, replay_authenticated={}, probe_authenticated={}, unknown_retained={}, abort_blocked={}",
                report.schema,
                report.record_count,
                report.recovered_phase,
                report.recovered_authentication_count,
                report.abort_probe_authentication_count,
                report.unknown_effect_freeze_retained,
                report.abort_blocked_while_unknown,
            ),
        );
    }
}

fn validate_host_substrate_cell(
    value: Option<&serde_json::Value>,
    findings: &mut Vec<JointValidationFinding>,
) {
    let Some(value) = value else {
        finding(
            findings,
            "missing-joint-host-substrate-cell",
            None,
            None,
            "production replay does not contain the real Coordinator<SqliteProvider> cell",
        );
        return;
    };
    let report: JointHostSubstrateCellReport = match serde_json::from_value(value.clone()) {
        Ok(report) => report,
        Err(error) => {
            finding(
                findings,
                "invalid-joint-host-substrate-cell",
                None,
                None,
                format!("cannot strictly decode HostSubstrate cell: {error}"),
            );
            return;
        }
    };
    if let Err(detail) = super::host_cell_verify::validate_host_substrate_raw_material(&report) {
        finding(findings, "invalid-joint-host-substrate-cell", None, None, detail);
        return;
    }
    let expected_lifecycle = [
        "source-activated",
        "source-quiescing",
        "source-frozen",
        "source-exported",
        "destination-restored",
        "destination-prepared",
        "source-committed-fenced",
        "destination-committed",
        "destination-running-active",
        "source-reopened-committed-fenced",
    ];
    let expected_receipts = [
        "prepare-intent",
        "visa-freeze",
        "nexus-freeze",
        "destination-prepared",
        "ownership-prepared",
        "ownership-commit",
        "closure",
        "visa-source-fence",
        "visa-destination-activation",
    ];
    let lifecycle = report.lifecycle.iter().map(String::as_str).collect::<Vec<_>>();
    let receipt_chain = report.receipt_chain.iter().map(String::as_str).collect::<Vec<_>>();
    let digests = [
        report.source_state_digest,
        report.destination_state_digest,
        report.snapshot_integrity,
        report.prepared_destination_digest,
        report.lease_commit_request_digest,
    ];
    if report.schema != JOINT_HOST_SUBSTRATE_CELL_SCHEMA_VERSION
        || lifecycle != expected_lifecycle
        || receipt_chain != expected_receipts
        || report.authenticated_receipt_count != expected_receipts.len()
        || report.joint_phase != "destination-active"
        || !report.source_reopened
        || report.source_phase != "committed"
        || report.source_activation != "fenced"
        || !report.source_owner_is_destination
        || report.destination_phase != "running"
        || report.destination_activation != "active"
        || !report.destination_owner_is_destination
        || report.source_component_generation != 0
        || report.destination_component_generation != 1
        || report.source_journal_position.0 != 5
        || report.destination_journal_position.0 != 8
        || digests.into_iter().any(|digest| !nonzero(digest))
        || report.source_state_digest == report.destination_state_digest
        || !report.independent_source_destination_databases
        || !report.same_boot_only
    {
        finding(
            findings,
            "invalid-joint-host-substrate-cell",
            None,
            None,
            format!(
                "schema={}, lifecycle={lifecycle:?}, receipts={receipt_chain:?}, authenticated={}, joint={}, source={}/{}/reopened:{}/owner:{}/g{}/p{}, destination={}/{}/owner:{}/g{}/p{}, independent={}, same_boot={}",
                report.schema,
                report.authenticated_receipt_count,
                report.joint_phase,
                report.source_phase,
                report.source_activation,
                report.source_reopened,
                report.source_owner_is_destination,
                report.source_component_generation,
                report.source_journal_position.0,
                report.destination_phase,
                report.destination_activation,
                report.destination_owner_is_destination,
                report.destination_component_generation,
                report.destination_journal_position.0,
                report.independent_source_destination_databases,
                report.same_boot_only,
            ),
        );
    }
}

fn expected_production_counts(bundle: &JointEvidenceBundle) -> (usize, usize, usize) {
    let mut accepted = 0_usize;
    let mut rejected = 0_usize;
    let mut replayed = 0_usize;
    for case in &bundle.cases {
        let mut seen = BTreeSet::new();
        for event in &case.trace.events {
            match &event.event {
                JointRawEventKind::ReceiptAccepted { receipt, .. } => {
                    if let Ok(reference) = joint_receipt_ref(receipt) {
                        if seen.insert(reference.digest) {
                            accepted = accepted.saturating_add(1);
                        } else {
                            replayed = replayed.saturating_add(1);
                        }
                    }
                }
                JointRawEventKind::ReceiptRejected { .. } => {
                    rejected = rejected.saturating_add(1);
                }
                _ => {}
            }
        }
    }
    (accepted, rejected, replayed)
}

fn validate_reference_cell_report(
    value: Option<&serde_json::Value>,
    findings: &mut Vec<JointValidationFinding>,
) {
    let Some(value) = value else {
        finding(
            findings,
            "missing-joint-reference-cell-report",
            None,
            None,
            "production replay does not contain a reference-cell report",
        );
        return;
    };
    let report: JointReferenceCellReport = match serde_json::from_value(value.clone()) {
        Ok(report) => report,
        Err(error) => {
            finding(
                findings,
                "invalid-joint-reference-cell-report",
                None,
                None,
                format!("cannot strictly decode reference-cell report: {error}"),
            );
            return;
        }
    };
    if report.schema_version != JOINT_REFERENCE_CELL_SCHEMA_VERSION
        || report.fixed_case_count != JOINT_HANDOFF_CASE_COUNT
        || report.scenario_count != JOINT_REFERENCE_CELL_SCENARIO_COUNT
        || report.scenario_count != report.traces.len()
        || !report.all_passed
        || !report.ownership_effect_peers_observed
        || report.runtime_projection_observed
        || report.visa_reference_mode != JOINT_REFERENCE_CELL_VISA_MODE
    {
        finding(
            findings,
            "invalid-joint-reference-cell-report",
            None,
            None,
            format!(
                "schema={}, fixed={}, scenarios={}, traces={}, all_passed={}, peers_observed={}, runtime_observed={}, visa_mode={}",
                report.schema_version,
                report.fixed_case_count,
                report.scenario_count,
                report.traces.len(),
                report.all_passed,
                report.ownership_effect_peers_observed,
                report.runtime_projection_observed,
                report.visa_reference_mode,
            ),
        );
    }

    let mut expected_ids = JOINT_HANDOFF_CASE_DEFINITIONS
        .iter()
        .map(|definition| definition.id)
        .collect::<BTreeSet<_>>();
    expected_ids.insert(JOINT_REFERENCE_CELL_SUPPLEMENTAL_CASE_ID);
    let mut observed_ids = BTreeSet::new();
    let mut handoffs = BTreeMap::new();
    let mut log_namespaces = BTreeMap::new();
    let mut receipt_slots = BTreeMap::new();
    for trace in &report.traces {
        if !observed_ids.insert(trace.case_id.as_str()) {
            finding(
                findings,
                "duplicate-joint-reference-cell-case",
                Some(&trace.case_id),
                None,
                "case ID occurs more than once",
            );
        }
        if let Some(previous) = handoffs.insert(trace.handoff, trace.case_id.as_str()) {
            finding(
                findings,
                "joint-reference-cell-namespace-alias",
                Some(&trace.case_id),
                None,
                format!("handoff is shared with {previous}"),
            );
        }
        for (role, log_id) in [
            (ReferenceReceiptRole::Ownership, trace.ownership_log_id),
            (ReferenceReceiptRole::Effect, trace.effect_log_id),
        ] {
            if log_id.is_zero() {
                finding(
                    findings,
                    "joint-reference-cell-namespace-alias",
                    Some(&trace.case_id),
                    None,
                    format!("{role:?} log identity is zero"),
                );
            }
            if let Some((previous_case, previous_role)) =
                log_namespaces.insert(log_id, (trace.case_id.as_str(), role))
            {
                finding(
                    findings,
                    "joint-reference-cell-namespace-alias",
                    Some(&trace.case_id),
                    None,
                    format!("{role:?} log is shared with {previous_case}/{previous_role:?}"),
                );
            }
        }
        validate_reference_cell_trace(trace, &mut receipt_slots, findings);
    }
    if observed_ids != expected_ids {
        finding(
            findings,
            "joint-reference-cell-case-set-mismatch",
            None,
            None,
            format!("expected={expected_ids:?}, observed={observed_ids:?}"),
        );
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReferenceReceiptRole {
    Ownership,
    Effect,
}

#[derive(Default)]
struct ReferenceTraceState {
    key: Option<JointHandoffKey>,
    reservation: Option<Identity>,
    intent: Option<ReceiptRef>,
    nexus_freeze: Option<ReceiptRef>,
    nexus_freeze_receipt: Option<NexusFreezeReceipt>,
    prepared: Option<ReceiptRef>,
    abort: Option<ReceiptRef>,
    commit: Option<ReceiptRef>,
    thaw: Option<ReceiptRef>,
    effect_parent: Option<ReceiptRef>,
    effect_revision: u64,
    issuer_namespaces: BTreeMap<Identity, (Identity, Identity, Identity)>,
    last_sequences: BTreeMap<Identity, u64>,
}

fn validate_reference_cell_trace(
    trace: &JointReferenceCellTrace,
    receipt_slots: &mut BTreeMap<(Identity, u64), (ReceiptRef, String)>,
    findings: &mut Vec<JointValidationFinding>,
) {
    let Some((expected_terminal, expected_events)) = reference_case_contract(&trace.case_id) else {
        finding(
            findings,
            "joint-reference-cell-case-set-mismatch",
            Some(&trace.case_id),
            None,
            "case is not in the fixed registry or the single supplemental slot",
        );
        return;
    };
    if trace.terminal != expected_terminal {
        finding(
            findings,
            "joint-reference-cell-terminal-mismatch",
            Some(&trace.case_id),
            None,
            format!("expected={expected_terminal}, observed={}", trace.terminal),
        );
    }
    if trace.handoff.is_zero() || trace.events.is_empty() {
        finding(
            findings,
            "invalid-joint-reference-cell-trace",
            Some(&trace.case_id),
            None,
            "trace handoff is zero or the event stream is empty",
        );
    }

    let mut state = ReferenceTraceState::default();
    for (index, event) in trace.events.iter().enumerate() {
        let event_index = u64::try_from(index).unwrap_or(u64::MAX);
        match (&event.receipt_kind, &event.receipt) {
            (None, None) => {}
            (Some(kind), Some(payload)) if event.outcome == "accepted" => {
                match decode_reference_receipt(kind, payload) {
                    Ok(receipt) => validate_reference_receipt(
                        trace,
                        event_index,
                        &receipt,
                        &mut state,
                        receipt_slots,
                        findings,
                    ),
                    Err(detail) => finding(
                        findings,
                        "invalid-joint-reference-cell-receipt",
                        Some(&trace.case_id),
                        Some(event_index),
                        detail,
                    ),
                }
            }
            _ => finding(
                findings,
                "invalid-joint-reference-cell-event",
                Some(&trace.case_id),
                Some(event_index),
                "receipt_kind and receipt must occur together with outcome=accepted",
            ),
        }
        if event.effect_record.is_some()
            && (event.receipt_kind.is_some() || event.receipt.is_some())
        {
            finding(
                findings,
                "invalid-joint-reference-cell-event",
                Some(&trace.case_id),
                Some(event_index),
                "an effect observation cannot masquerade as a native receipt",
            );
        }
    }
    if !contains_reference_event_sequence(&trace.events, &expected_events) {
        finding(
            findings,
            "joint-reference-cell-event-order-mismatch",
            Some(&trace.case_id),
            None,
            "required peer outcomes and receipts are absent or reordered",
        );
    }
    validate_reference_effect_transition(trace, &state, findings);
}

fn validate_reference_effect_transition(
    trace: &JointReferenceCellTrace,
    state: &ReferenceTraceState,
    findings: &mut Vec<JointValidationFinding>,
) {
    const CASE_ID: &str = "precommit-abort-preserves-uncommitted-effect";
    let observed: Vec<_> = trace
        .events
        .iter()
        .enumerate()
        .filter_map(|(index, event)| {
            event.effect_record.as_ref().map(|record| (index, event, record))
        })
        .collect();
    if trace.case_id != CASE_ID {
        if !observed.is_empty() {
            reference_effect_transition_finding(
                trace,
                findings,
                "structured effect observations are only valid for the registered-effect retry case",
            );
        }
        return;
    }

    let registered: Vec<_> = observed
        .iter()
        .filter(|(_, event, _)| {
            event.step == "registered-effect-before-freeze" && event.outcome == "published"
        })
        .collect();
    let committed: Vec<_> = observed
        .iter()
        .filter(|(_, event, _)| {
            event.step == "registered-effect-committed-after-thaw" && event.outcome == "published"
        })
        .collect();
    if observed.len() != 2 || registered.len() != 1 || committed.len() != 1 {
        reference_effect_transition_finding(
            trace,
            findings,
            "the retry case must contain exactly one frozen Registered observation and one resumed Committed observation",
        );
        return;
    }
    let (registered_index, _, registered) = *registered[0];
    let (committed_index, _, committed) = *committed[0];
    let Some(freeze) = state.nexus_freeze_receipt.as_ref() else {
        reference_effect_transition_finding(
            trace,
            findings,
            "the retry case has no decoded Nexus freeze receipt",
        );
        return;
    };
    let expected_effects = [registered.clone()];
    let cohort = joint_effect_cohort_digest(freeze.key, expected_effects.clone());
    let classification = joint_classification_root(freeze.key, expected_effects.clone());
    let counts = joint_classification_counts(expected_effects);
    let blocked_by_registered = classification.as_ref().is_ok_and(|root| {
        matches!(
            freeze.disposition,
            FreezeDisposition::Blocked { blocker_digest } if blocker_digest == *root
        )
    });
    let exact_identity = registered.effect == committed.effect
        && registered.operation == committed.operation
        && registered.domain == committed.domain
        && registered.binding_generation == committed.binding_generation;
    let valid_registered = !registered.effect.is_zero()
        && !registered.operation.is_zero()
        && !registered.domain.is_zero()
        && registered.binding_generation == freeze.scope_generation
        && registered.classification == JointEffectClassification::Registered
        && registered.outcome_digest.is_none()
        && registered.tombstone_digest.is_none();
    let valid_committed = committed.classification == JointEffectClassification::Committed
        && committed.outcome_digest.is_some_and(nonzero)
        && committed.tombstone_digest.is_none();
    let exact_frozen_cohort = cohort.is_ok_and(|digest| digest == freeze.effect_cohort_digest)
        && classification.is_ok_and(|root| root == freeze.classification_root)
        && counts == freeze.counts
        && counts.registered == 1
        && counts.committed == 0
        && counts.aborted == 0
        && counts.unresolved == 0
        && counts.tombstones == 0
        && blocked_by_registered;
    if registered_index >= committed_index
        || !valid_registered
        || !valid_committed
        || !exact_identity
        || !exact_frozen_cohort
        || state.abort.is_none()
        || state.thaw.is_none()
        || state.commit.is_some()
    {
        reference_effect_transition_finding(
            trace,
            findings,
            "the resumed commit is not the same frozen effect, operation, domain, and current binding authorized by exact abort/thaw",
        );
    }
}

fn reference_effect_transition_finding(
    trace: &JointReferenceCellTrace,
    findings: &mut Vec<JointValidationFinding>,
    detail: impl Into<String>,
) {
    finding(
        findings,
        "invalid-joint-reference-cell-effect-transition",
        Some(&trace.case_id),
        None,
        detail,
    );
}

fn decode_reference_receipt(
    kind: &str,
    payload: &serde_json::Value,
) -> Result<JointReceipt, String> {
    macro_rules! decode {
        ($type:ty, $variant:ident) => {
            serde_json::from_value::<$type>(payload.clone())
                .map(JointReceipt::$variant)
                .map_err(|error| format!("cannot decode {kind} receipt: {error}"))
        };
    }
    match kind {
        "PrepareIntent" => decode!(PrepareIntentReceipt, PrepareIntent),
        "NexusFreeze" => decode!(NexusFreezeReceipt, EffectFreeze),
        "OwnershipPrepared" => serde_json::from_value::<OwnershipPreparedReceipt>(payload.clone())
            .map(|value| JointReceipt::OwnershipPrepared(Box::new(value)))
            .map_err(|error| format!("cannot decode {kind} receipt: {error}")),
        "OwnershipAbort" => decode!(OwnershipAbortReceipt, OwnershipAbort),
        "OwnershipCommit" => decode!(OwnershipCommitReceipt, OwnershipCommit),
        "NexusThaw" => decode!(NexusThawReceipt, EffectThaw),
        "ClosureProgress" => decode!(ClosureProgressReceipt, ClosureProgress),
        "Closure" => decode!(ClosureReceipt, Closure),
        "RetainedTombstone" => decode!(RetainedTombstoneReceipt, RetainedTombstone),
        _ => Err(format!("unsupported reference-cell receipt kind {kind}")),
    }
}

fn validate_reference_receipt(
    trace: &JointReferenceCellTrace,
    event_index: u64,
    receipt: &JointReceipt,
    state: &mut ReferenceTraceState,
    receipt_slots: &mut BTreeMap<(Identity, u64), (ReceiptRef, String)>,
    findings: &mut Vec<JointValidationFinding>,
) {
    let role = match receipt.kind() {
        ReceiptKind::PrepareIntent
        | ReceiptKind::OwnershipPrepared
        | ReceiptKind::OwnershipAbort
        | ReceiptKind::OwnershipCommit => ReferenceReceiptRole::Ownership,
        ReceiptKind::NexusFreeze
        | ReceiptKind::NexusThaw
        | ReceiptKind::ClosureProgress
        | ReceiptKind::Closure
        | ReceiptKind::RetainedTombstone => ReferenceReceiptRole::Effect,
        kind => {
            reference_receipt_finding(
                findings,
                trace,
                event_index,
                format!("receipt kind {kind:?} is outside the ownership/effect peer cell"),
            );
            return;
        }
    };
    let header = receipt.header();
    let expected_log = match role {
        ReferenceReceiptRole::Ownership => trace.ownership_log_id,
        ReferenceReceiptRole::Effect => trace.effect_log_id,
    };
    if header.version != JointProtocolVersion::V1
        || header.kind != receipt.kind()
        || header.log_id != expected_log
        || header.sequence == 0
        || [header.issuer, header.issuer_incarnation, header.key_id, header.log_id]
            .into_iter()
            .any(Identity::is_zero)
        || header.previous_digest.is_some_and(|digest| !nonzero(digest))
    {
        reference_receipt_finding(
            findings,
            trace,
            event_index,
            format!("invalid {role:?} receipt header or log namespace"),
        );
    }
    let namespace = (header.issuer, header.issuer_incarnation, header.key_id);
    if let Some(previous) = state.issuer_namespaces.insert(header.log_id, namespace)
        && previous != namespace
    {
        reference_receipt_finding(
            findings,
            trace,
            event_index,
            "one native log changed issuer, incarnation, or key identity",
        );
    }
    if let Some(previous) = state.last_sequences.insert(header.log_id, header.sequence)
        && header.sequence < previous
    {
        reference_receipt_finding(
            findings,
            trace,
            event_index,
            format!("receipt sequence regressed from {previous} to {}", header.sequence),
        );
    }
    let reference = match joint_receipt_ref(receipt) {
        Ok(reference) => reference,
        Err(detail) => {
            reference_receipt_finding(findings, trace, event_index, detail);
            return;
        }
    };
    match receipt_slots.get(&(header.log_id, header.sequence)) {
        Some((previous, previous_case)) if *previous != reference => reference_receipt_finding(
            findings,
            trace,
            event_index,
            format!("native log slot equivocates with receipt from case {previous_case}"),
        ),
        Some(_) => {}
        None => {
            receipt_slots
                .insert((header.log_id, header.sequence), (reference, trace.case_id.clone()));
        }
    }
    let key = receipt.key();
    if !well_formed_key(key) || key.handoff != trace.handoff {
        reference_receipt_finding(
            findings,
            trace,
            event_index,
            "receipt key is malformed or belongs to another handoff",
        );
    }
    if let Some(previous) = state.key
        && previous != key
    {
        reference_receipt_finding(
            findings,
            trace,
            event_index,
            "one reference trace contains receipts for different handoff keys",
        );
    } else {
        state.key = Some(key);
    }

    match receipt {
        JointReceipt::PrepareIntent(value) => {
            if value.header.previous_digest.is_some()
                || value.ownership_service != value.header.issuer
                || value.service_incarnation != value.header.issuer_incarnation
                || value.reservation.is_zero()
                || value.intent_revision == 0
                || !nonzero(value.request_digest)
            {
                reference_receipt_finding(
                    findings,
                    trace,
                    event_index,
                    "prepare-intent fields or root parent are invalid",
                );
            }
            remember_reservation(state, value.reservation, trace, event_index, findings);
            remember_receipt(
                &mut state.intent,
                reference,
                "prepare intent",
                trace,
                event_index,
                findings,
            );
        }
        JointReceipt::EffectFreeze(value) => {
            if value.header.previous_digest.is_some()
                || !valid_reference_parent(
                    value.intent,
                    ReceiptKind::PrepareIntent,
                    Some(trace.ownership_log_id),
                    trace.handoff,
                )
                || state.intent.is_some_and(|intent| intent != value.intent)
                || value.registry_instance.is_zero()
                || value.scope_id.is_zero()
                || value.scope_generation == 0
                || value.authority_epoch == 0
                || value.freeze_generation == 0
                || !nonzero(value.domain_bindings_digest)
                || !nonzero(value.effect_cohort_digest)
                || !nonzero(value.classification_root)
            {
                reference_receipt_finding(
                    findings,
                    trace,
                    event_index,
                    "Nexus freeze is not bound to the ownership intent and effect scope",
                );
            }
            remember_receipt(
                &mut state.nexus_freeze,
                reference,
                "Nexus freeze",
                trace,
                event_index,
                findings,
            );
            if state.nexus_freeze_receipt.as_ref().is_some_and(|observed| observed != value) {
                reference_receipt_finding(
                    findings,
                    trace,
                    event_index,
                    "Nexus freeze payload was substituted within one trace",
                );
            } else {
                state.nexus_freeze_receipt = Some(value.clone());
            }
        }
        JointReceipt::OwnershipPrepared(value) => {
            let bindings = &value.bindings;
            if value.header.previous_digest != Some(value.intent.digest)
                || !valid_reference_parent(
                    value.intent,
                    ReceiptKind::PrepareIntent,
                    Some(trace.ownership_log_id),
                    trace.handoff,
                )
                || !valid_reference_parent(
                    value.visa_freeze,
                    ReceiptKind::VisaFreeze,
                    None,
                    trace.handoff,
                )
                || !valid_reference_parent(
                    value.nexus_freeze,
                    ReceiptKind::NexusFreeze,
                    Some(trace.effect_log_id),
                    trace.handoff,
                )
                || !valid_reference_parent(
                    value.destination_prepared,
                    ReceiptKind::DestinationPrepared,
                    None,
                    trace.handoff,
                )
                || state.intent.is_some_and(|intent| intent != value.intent)
                || state.nexus_freeze.is_some_and(|freeze| freeze != value.nexus_freeze)
                || value.prepared_revision == 0
                || bindings.prepare_intent_receipt_digest != value.intent.digest
                || bindings.visa_freeze_receipt_digest != value.visa_freeze.digest
                || bindings.effect_freeze_receipt_digest != value.nexus_freeze.digest
                || bindings.destination_prepared_receipt_digest != value.destination_prepared.digest
                || !valid_prepared_bindings(bindings)
            {
                reference_receipt_finding(
                    findings,
                    trace,
                    event_index,
                    "ownership prepared receipt has an invalid parent or sealed binding",
                );
            }
            remember_reservation(state, value.reservation, trace, event_index, findings);
            remember_receipt(
                &mut state.prepared,
                reference,
                "ownership prepared",
                trace,
                event_index,
                findings,
            );
        }
        JointReceipt::OwnershipAbort(value) => {
            let basis_kind = value.basis.kind;
            let valid_basis_kind =
                matches!(basis_kind, ReceiptKind::PrepareIntent | ReceiptKind::OwnershipPrepared);
            let observed_basis = if basis_kind == ReceiptKind::OwnershipPrepared {
                state.prepared
            } else {
                state.intent
            };
            if value.header.previous_digest != Some(value.basis.digest)
                || !valid_basis_kind
                || !valid_reference_parent(
                    value.basis,
                    basis_kind,
                    Some(trace.ownership_log_id),
                    trace.handoff,
                )
                || observed_basis.is_some_and(|basis| basis != value.basis)
                || value.basis_revision == 0
                || value.decision_sequence != value.header.sequence
                || value.decision_sequence <= value.basis_revision
                || !nonzero(value.non_equivocation_root)
                || state.commit.is_some()
            {
                reference_receipt_finding(
                    findings,
                    trace,
                    event_index,
                    "ownership abort is not an immutable descendant of its exact basis",
                );
            }
            remember_reservation(state, value.reservation, trace, event_index, findings);
            remember_receipt(
                &mut state.abort,
                reference,
                "ownership abort",
                trace,
                event_index,
                findings,
            );
        }
        JointReceipt::OwnershipCommit(value) => {
            if value.header.previous_digest != Some(value.prepared.digest)
                || !valid_reference_parent(
                    value.prepared,
                    ReceiptKind::OwnershipPrepared,
                    Some(trace.ownership_log_id),
                    trace.handoff,
                )
                || state.prepared.is_some_and(|prepared| prepared != value.prepared)
                || value.prepared_revision == 0
                || value.decision_sequence != value.header.sequence
                || value.decision_sequence <= value.prepared_revision
                || !nonzero(value.non_equivocation_root)
                || state.abort.is_some()
            {
                reference_receipt_finding(
                    findings,
                    trace,
                    event_index,
                    "ownership commit is not an immutable descendant of exact Prepared",
                );
            }
            remember_reservation(state, value.reservation, trace, event_index, findings);
            remember_receipt(
                &mut state.commit,
                reference,
                "ownership commit",
                trace,
                event_index,
                findings,
            );
        }
        JointReceipt::EffectThaw(value) => {
            if value.header.previous_digest != Some(value.nexus_freeze.digest)
                || !valid_reference_parent(
                    value.abort,
                    ReceiptKind::OwnershipAbort,
                    Some(trace.ownership_log_id),
                    trace.handoff,
                )
                || !valid_reference_parent(
                    value.nexus_freeze,
                    ReceiptKind::NexusFreeze,
                    Some(trace.effect_log_id),
                    trace.handoff,
                )
                || state.abort.is_some_and(|abort| abort != value.abort)
                || state.nexus_freeze.is_some_and(|freeze| freeze != value.nexus_freeze)
                || value.thaw_generation == 0
            {
                reference_receipt_finding(
                    findings,
                    trace,
                    event_index,
                    "Nexus thaw lacks exact abort and freeze authorization",
                );
            }
            remember_receipt(
                &mut state.thaw,
                reference,
                "Nexus thaw",
                trace,
                event_index,
                findings,
            );
        }
        JointReceipt::ClosureProgress(value) => {
            validate_effect_terminal_parents(
                trace,
                event_index,
                EffectTerminalObservation {
                    previous_digest: value.header.previous_digest,
                    commit: value.commit,
                    nexus_freeze: value.nexus_freeze,
                    revision: value.closure_revision,
                },
                state,
                findings,
            );
            if !nonzero(value.progress_root) {
                reference_receipt_finding(
                    findings,
                    trace,
                    event_index,
                    "closure progress root is zero",
                );
            }
            state.effect_revision = state.effect_revision.max(value.closure_revision);
            state.effect_parent = Some(reference);
        }
        JointReceipt::RetainedTombstone(value) => {
            validate_effect_terminal_parents(
                trace,
                event_index,
                EffectTerminalObservation {
                    previous_digest: value.header.previous_digest,
                    commit: value.commit,
                    nexus_freeze: value.nexus_freeze,
                    revision: value.closure_revision,
                },
                state,
                findings,
            );
            if value.tombstone_count == 0 || !nonzero(value.tombstone_manifest_digest) {
                reference_receipt_finding(
                    findings,
                    trace,
                    event_index,
                    "retained tombstone receipt has no retained obligation",
                );
            }
            state.effect_revision = state.effect_revision.max(value.closure_revision);
            state.effect_parent = Some(reference);
        }
        JointReceipt::Closure(value) => {
            validate_effect_terminal_parents(
                trace,
                event_index,
                EffectTerminalObservation {
                    previous_digest: value.header.previous_digest,
                    commit: value.commit,
                    nexus_freeze: value.nexus_freeze,
                    revision: value.closure_revision,
                },
                state,
                findings,
            );
            if !nonzero(value.effect_manifest_digest) || value.closed_authority_epoch == 0 {
                reference_receipt_finding(
                    findings,
                    trace,
                    event_index,
                    "closure receipt has an invalid manifest or closed authority epoch",
                );
            }
            state.effect_revision = state.effect_revision.max(value.closure_revision);
        }
        JointReceipt::VisaFreeze(_)
        | JointReceipt::DestinationPrepared(_)
        | JointReceipt::VisaSourceFence(_)
        | JointReceipt::VisaSourceResume(_)
        | JointReceipt::VisaDestinationActivation(_) => unreachable!(),
    }
}

#[derive(Clone, Copy)]
struct EffectTerminalObservation {
    previous_digest: Option<Digest>,
    commit: ReceiptRef,
    nexus_freeze: ReceiptRef,
    revision: u64,
}

fn validate_effect_terminal_parents(
    trace: &JointReferenceCellTrace,
    event_index: u64,
    observation: EffectTerminalObservation,
    state: &ReferenceTraceState,
    findings: &mut Vec<JointValidationFinding>,
) {
    let expected_parent = state.effect_parent.unwrap_or(observation.nexus_freeze);
    if observation.previous_digest != Some(expected_parent.digest)
        || !valid_reference_parent(
            observation.commit,
            ReceiptKind::OwnershipCommit,
            Some(trace.ownership_log_id),
            trace.handoff,
        )
        || !valid_reference_parent(
            observation.nexus_freeze,
            ReceiptKind::NexusFreeze,
            Some(trace.effect_log_id),
            trace.handoff,
        )
        || state.commit.is_some_and(|observed| observed != observation.commit)
        || state.nexus_freeze.is_some_and(|observed| observed != observation.nexus_freeze)
        || observation.revision <= state.effect_revision
    {
        reference_receipt_finding(
            findings,
            trace,
            event_index,
            "effect terminal/progress receipt has a substituted commit, freeze, parent, or revision",
        );
    }
}

fn valid_reference_parent(
    reference: ReceiptRef,
    expected_kind: ReceiptKind,
    expected_log: Option<Identity>,
    handoff: Identity,
) -> bool {
    reference.version == JointProtocolVersion::V1
        && reference.kind == expected_kind
        && reference.handoff == handoff
        && expected_log.is_none_or(|log_id| reference.log_id == log_id)
        && reference.sequence > 0
        && !reference.digest.eq(&Digest::ZERO)
        && [reference.issuer, reference.issuer_incarnation, reference.key_id, reference.log_id]
            .into_iter()
            .all(|identity| !identity.is_zero())
}

fn valid_prepared_bindings(bindings: &PreparedBindings) -> bool {
    !bindings.snapshot.is_zero()
        && bindings.source_journal_position.0 > 0
        && [
            bindings.snapshot_integrity_digest,
            bindings.source_state_digest,
            bindings.component_digest,
            bindings.profile_digest,
            bindings.destination_state_digest,
            bindings.prepared_authorities_digest,
            bindings.prepared_bindings_digest,
            bindings.effect_cohort_manifest_digest,
            bindings.joint_mapping_manifest_digest,
        ]
        .into_iter()
        .all(nonzero)
}

fn remember_reservation(
    state: &mut ReferenceTraceState,
    reservation: Identity,
    trace: &JointReferenceCellTrace,
    event_index: u64,
    findings: &mut Vec<JointValidationFinding>,
) {
    if reservation.is_zero() || state.reservation.is_some_and(|previous| previous != reservation) {
        reference_receipt_finding(
            findings,
            trace,
            event_index,
            "ownership reservation was substituted within one trace",
        );
    } else {
        state.reservation = Some(reservation);
    }
}

fn remember_receipt(
    slot: &mut Option<ReceiptRef>,
    reference: ReceiptRef,
    label: &str,
    trace: &JointReferenceCellTrace,
    event_index: u64,
    findings: &mut Vec<JointValidationFinding>,
) {
    if slot.is_some_and(|previous| previous != reference) {
        reference_receipt_finding(
            findings,
            trace,
            event_index,
            format!("{label} receipt was substituted within one trace"),
        );
    } else {
        *slot = Some(reference);
    }
}

fn reference_receipt_finding(
    findings: &mut Vec<JointValidationFinding>,
    trace: &JointReferenceCellTrace,
    event_index: u64,
    detail: impl Into<String>,
) {
    finding(
        findings,
        "invalid-joint-reference-cell-receipt",
        Some(&trace.case_id),
        Some(event_index),
        detail,
    );
}

#[derive(Clone, Copy)]
struct ReferenceEventContract {
    step: &'static str,
    outcome: &'static str,
    receipt_kind: Option<&'static str>,
    effect_classification: Option<JointEffectClassification>,
}

const fn reference_receipt_event(
    step: &'static str,
    receipt_kind: &'static str,
) -> ReferenceEventContract {
    ReferenceEventContract {
        step,
        outcome: "accepted",
        receipt_kind: Some(receipt_kind),
        effect_classification: None,
    }
}

const fn reference_outcome_event(
    step: &'static str,
    outcome: &'static str,
) -> ReferenceEventContract {
    ReferenceEventContract { step, outcome, receipt_kind: None, effect_classification: None }
}

const fn reference_effect_event(
    step: &'static str,
    outcome: &'static str,
    classification: JointEffectClassification,
) -> ReferenceEventContract {
    ReferenceEventContract {
        step,
        outcome,
        receipt_kind: None,
        effect_classification: Some(classification),
    }
}

fn contains_reference_event_sequence(
    events: &[JointReferenceCellEvent],
    expected: &[ReferenceEventContract],
) -> bool {
    let mut cursor = 0;
    for contract in expected {
        let Some(offset) = events[cursor..].iter().position(|event| {
            event.step == contract.step
                && event.outcome == contract.outcome
                && event.receipt_kind.as_deref() == contract.receipt_kind
                && event.receipt.is_some() == contract.receipt_kind.is_some()
                && event.effect_record.as_ref().map(|record| record.classification)
                    == contract.effect_classification
        }) else {
            return false;
        };
        cursor = cursor.saturating_add(offset).saturating_add(1);
    }
    true
}

fn reference_case_contract(case_id: &str) -> Option<(&'static str, Vec<ReferenceEventContract>)> {
    let contract = match case_id {
        "effect-commit-wins-freeze" => (
            "source-closed",
            vec![
                reference_receipt_event("reserve", "PrepareIntent"),
                reference_outcome_event("effect-publication", "published"),
                reference_outcome_event("effect-publication", "published"),
                reference_receipt_event("effect-freeze", "NexusFreeze"),
                reference_receipt_event("ownership-commit", "OwnershipCommit"),
                reference_receipt_event("closure-progress", "ClosureProgress"),
                reference_receipt_event("effect-closure", "Closure"),
            ],
        ),
        "freeze-wins-effect-commit" => (
            "source-closed",
            vec![
                reference_receipt_event("reserve", "PrepareIntent"),
                reference_receipt_event("effect-freeze", "NexusFreeze"),
                reference_outcome_event("effect-publication", "gate-closed"),
                reference_receipt_event("ownership-commit", "OwnershipCommit"),
                reference_receipt_event("effect-closure", "Closure"),
            ],
        ),
        "destination-prepare-fails-abort-thaw" => (
            "source-thawed",
            vec![
                reference_receipt_event("reserve", "PrepareIntent"),
                reference_receipt_event("effect-freeze", "NexusFreeze"),
                reference_outcome_event("destination-prepare", "failed-before-seal"),
                reference_receipt_event("ownership-abort", "OwnershipAbort"),
                reference_receipt_event("effect-thaw", "NexusThaw"),
            ],
        ),
        "commit-ack-lost-query-close" => (
            "source-closed-after-recovery",
            vec![
                reference_receipt_event("reserve", "PrepareIntent"),
                reference_receipt_event("effect-freeze", "NexusFreeze"),
                reference_receipt_event("ownership-commit-ack-lost", "OwnershipCommit"),
                reference_receipt_event("ownership-query-after-reopen", "OwnershipCommit"),
                reference_receipt_event("effect-closure", "Closure"),
            ],
        ),
        "frozen-service-crash-rebind" => (
            "source-closed-after-rebind",
            vec![
                reference_outcome_event("stale-binding-publication", "stale-registry"),
                reference_receipt_event("effect-freeze", "NexusFreeze"),
                reference_receipt_event("ownership-commit", "OwnershipCommit"),
                reference_receipt_event("effect-closure", "Closure"),
            ],
        ),
        "unresolved-tombstone-blocks-seal" => (
            "commit-blocked-frozen",
            vec![reference_receipt_event("blocked-effect-freeze", "NexusFreeze")],
        ),
        "stale-token-scope-epoch-probes" => (
            "source-thawed",
            vec![
                reference_receipt_event("reserve", "PrepareIntent"),
                reference_outcome_event("stale-registry-freeze", "rejected-no-effect"),
                reference_outcome_event("stale-scope-freeze", "rejected-no-effect"),
                reference_outcome_event("stale-freeze-generation", "rejected-no-effect"),
                reference_outcome_event("stale-source-epoch", "rejected-no-effect"),
                reference_receipt_event("effect-freeze", "NexusFreeze"),
                reference_outcome_event("stale-thaw-token", "rejected-no-effect"),
                reference_receipt_event("effect-thaw", "NexusThaw"),
            ],
        ),
        "abort-commit-race-abort-wins" => (
            "abort-terminal",
            vec![
                reference_receipt_event("reserve", "PrepareIntent"),
                reference_receipt_event("effect-freeze", "NexusFreeze"),
                reference_receipt_event("ownership-prepared", "OwnershipPrepared"),
                reference_receipt_event("ownership-abort-winner", "OwnershipAbort"),
                reference_outcome_event("commit-racer", "existing-abort"),
                reference_receipt_event("effect-thaw", "NexusThaw"),
            ],
        ),
        "abort-commit-race-commit-wins" => (
            "commit-terminal-source-closed",
            vec![
                reference_receipt_event("reserve", "PrepareIntent"),
                reference_receipt_event("effect-freeze", "NexusFreeze"),
                reference_receipt_event("ownership-commit-winner", "OwnershipCommit"),
                reference_outcome_event("abort-racer", "existing-commit"),
                reference_receipt_event("effect-closure", "Closure"),
            ],
        ),
        "source-crash-after-commit-before-close" => (
            "source-closed-after-restart",
            vec![
                reference_receipt_event("ownership-commit", "OwnershipCommit"),
                reference_outcome_event("source-process", "crashed-before-close"),
                reference_receipt_event("query-after-restart", "OwnershipCommit"),
                reference_receipt_event("effect-closure", "Closure"),
            ],
        ),
        "destination-crash-before-activation" => (
            "source-closed-destination-prepared",
            vec![
                reference_receipt_event("reserve", "PrepareIntent"),
                reference_receipt_event("effect-freeze", "NexusFreeze"),
                reference_receipt_event("effect-closure", "Closure"),
                reference_outcome_event(
                    "destination-process",
                    "restart-remained-inactive-until-closure",
                ),
            ],
        ),
        "concurrent-two-destinations" => (
            "single-destination-source-closed",
            vec![
                reference_receipt_event("winning-reservation", "PrepareIntent"),
                reference_outcome_event("competing-reservation", "conflict-no-second-owner"),
                reference_receipt_event("effect-freeze", "NexusFreeze"),
                reference_receipt_event("effect-closure", "Closure"),
            ],
        ),
        "crash-after-freeze-before-seal" => (
            "source-thawed-after-restart",
            vec![
                reference_receipt_event("effect-freeze", "NexusFreeze"),
                reference_outcome_event("coordinator", "crashed-before-seal"),
                reference_receipt_event("ownership-abort", "OwnershipAbort"),
                reference_receipt_event("effect-thaw", "NexusThaw"),
            ],
        ),
        "stale-destination-prepared-receipt" => (
            "source-thawed-no-seal",
            vec![
                reference_receipt_event("reserve", "PrepareIntent"),
                reference_receipt_event("effect-freeze", "NexusFreeze"),
                reference_outcome_event("substituted-destination-prepared", "rejected-no-seal"),
                reference_receipt_event("ownership-abort", "OwnershipAbort"),
                reference_receipt_event("effect-thaw", "NexusThaw"),
            ],
        ),
        "duplicate-reordered-receipts" => (
            "duplicate-idempotent-source-closed",
            vec![
                reference_receipt_event("effect-freeze", "NexusFreeze"),
                reference_receipt_event("effect-freeze-duplicate", "NexusFreeze"),
                reference_outcome_event("reordered-seal", "stale-sequence-no-effect"),
                reference_receipt_event("effect-closure", "Closure"),
            ],
        ),
        "precommit-abort-preserves-uncommitted-effect" => (
            "source-thawed-registered-effect-committed",
            vec![
                reference_effect_event(
                    "registered-effect-before-freeze",
                    "published",
                    JointEffectClassification::Registered,
                ),
                reference_receipt_event("reserve", "PrepareIntent"),
                reference_receipt_event("effect-freeze", "NexusFreeze"),
                reference_outcome_event("destination-prepare", "failed-before-seal"),
                reference_receipt_event("ownership-abort", "OwnershipAbort"),
                reference_receipt_event("effect-thaw", "NexusThaw"),
                reference_effect_event(
                    "registered-effect-committed-after-thaw",
                    "published",
                    JointEffectClassification::Committed,
                ),
            ],
        ),
        JOINT_REFERENCE_CELL_SUPPLEMENTAL_CASE_ID => (
            "source-closed-after-tombstone-recovery",
            vec![
                reference_receipt_event("retained-tombstone", "RetainedTombstone"),
                reference_outcome_event("destination-activation", "blocked-recovery-required"),
                reference_receipt_event("recovery-closure", "Closure"),
            ],
        ),
        _ => return None,
    };
    Some(contract)
}

fn validate_case(
    case: &JointCaseEvidence,
    definition: &JointCaseDefinition,
    findings: &mut Vec<JointValidationFinding>,
) {
    if case.trace.schema_version != JOINT_HANDOFF_RAW_TRACE_SCHEMA_VERSION {
        finding(
            findings,
            "unsupported-joint-raw-trace-schema",
            Some(&case.case_id),
            None,
            case.trace.schema_version.clone(),
        );
    }
    if case.trace.case_id != case.case_id {
        finding(
            findings,
            "joint-trace-case-mismatch",
            Some(&case.case_id),
            None,
            case.trace.case_id.clone(),
        );
    }
    match joint_raw_trace_sha256(&case.trace) {
        Ok(digest) if digest == case.trace_sha256 => {}
        Ok(digest) => finding(
            findings,
            "joint-raw-trace-digest-mismatch",
            Some(&case.case_id),
            None,
            format!("claimed={}, recomputed={digest}", case.trace_sha256),
        ),
        Err(detail) => {
            finding(findings, "unencodable-joint-raw-trace", Some(&case.case_id), None, detail)
        }
    }

    let replay = replay_trace(&case.trace, findings);
    if case.claimed_terminal != definition.terminal || replay.terminal != Some(definition.terminal)
    {
        finding(
            findings,
            "joint-terminal-mismatch",
            Some(&case.case_id),
            None,
            format!(
                "expected={:?}, claimed={:?}, recomputed={:?}",
                definition.terminal, case.claimed_terminal, replay.terminal
            ),
        );
    }
    let mut claimed = BTreeSet::new();
    for assertion in &case.claimed_assertions {
        if !claimed.insert(*assertion) {
            finding(
                findings,
                "duplicate-joint-assertion",
                Some(&case.case_id),
                None,
                format!("{assertion:?}"),
            );
        }
        if !replay.assertions.contains(assertion) {
            finding(
                findings,
                "unearned-joint-assertion",
                Some(&case.case_id),
                None,
                format!("{assertion:?}"),
            );
        }
    }
    for assertion in definition.required_assertions {
        if !claimed.contains(assertion) || !replay.assertions.contains(assertion) {
            finding(
                findings,
                "missing-required-joint-assertion",
                Some(&case.case_id),
                None,
                format!("{assertion:?}"),
            );
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
enum OraclePhase {
    SourceOwned,
    PrepareIntent,
    FrozenUnsealed,
    PreparedFrozen,
    AbortDecided,
    SourceThawPending,
    SourceActive,
    CommitDecided,
    ClosurePending,
    SourceClosed,
    DestinationActivationPending,
    DestinationActive,
    RecoveryRequired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
enum OracleDecision {
    Undecided,
    Abort(ReceiptRef),
    Commit(ReceiptRef),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
enum PendingOwnershipObservation {
    Abort(OwnershipAbortObservation),
    Commit(OwnershipCommitObservation),
}

#[derive(Clone, Debug)]
struct OracleState {
    key: JointHandoffKey,
    phase: OraclePhase,
    issuers: JointIssuerSet,
    scope: EffectScopeVersion,
    reservation: Option<Identity>,
    intent: Option<ReceiptRef>,
    intent_revision: Option<u64>,
    visa_freeze: Option<ReceiptRef>,
    source_journal_position: Option<contract_core::JournalPosition>,
    source_state_digest: Option<Digest>,
    nexus_freeze: Option<ReceiptRef>,
    nexus_disposition: Option<FreezeDisposition>,
    nexus_domain_bindings_digest: Option<Digest>,
    destination_prepared: Option<ReceiptRef>,
    prepared: Option<ReceiptRef>,
    prepared_revision: Option<u64>,
    decision: OracleDecision,
    thaw: Option<ReceiptRef>,
    closure_progress: Option<ReceiptRef>,
    closure_revision: u64,
    closure: Option<ReceiptRef>,
    source_fence: Option<ReceiptRef>,
    source_resume: Option<ReceiptRef>,
    destination_activation_command: Option<Identity>,
    destination_activation: Option<ReceiptRef>,
    effects: BTreeMap<Identity, JointEffectRecord>,
    accepted_receipts: BTreeMap<Digest, ReceiptRef>,
    accepted_request_digests: BTreeMap<Digest, Digest>,
    issuer_sequences: BTreeMap<(Identity, Identity, Identity), u64>,
    actors_running: BTreeMap<JointActor, bool>,
    source_execution: bool,
    destination_execution: bool,
    native_effect_gate_closed: bool,
    blocked_seal: bool,
    durable_commit: Option<OwnershipCommitObservation>,
    queried_ownership: Option<PendingOwnershipObservation>,
    assertions: BTreeSet<JointAssertion>,
    receipt_error: bool,
}

#[derive(Serialize)]
struct OracleStateDigestProjection<'a> {
    domain: &'static str,
    key: JointHandoffKey,
    phase: OraclePhase,
    issuers: JointIssuerSet,
    scope: EffectScopeVersion,
    reservation: Option<Identity>,
    intent: Option<ReceiptRef>,
    intent_revision: Option<u64>,
    visa_freeze: Option<ReceiptRef>,
    source_journal_position: Option<contract_core::JournalPosition>,
    source_state_digest: Option<Digest>,
    nexus_freeze: Option<ReceiptRef>,
    nexus_disposition: Option<FreezeDisposition>,
    nexus_domain_bindings_digest: Option<Digest>,
    destination_prepared: Option<ReceiptRef>,
    prepared: Option<ReceiptRef>,
    prepared_revision: Option<u64>,
    decision: OracleDecision,
    thaw: Option<ReceiptRef>,
    closure_progress: Option<ReceiptRef>,
    closure_revision: u64,
    closure: Option<ReceiptRef>,
    source_fence: Option<ReceiptRef>,
    source_resume: Option<ReceiptRef>,
    destination_activation_command: Option<Identity>,
    destination_activation: Option<ReceiptRef>,
    effects: &'a BTreeMap<Identity, JointEffectRecord>,
    accepted_receipts: &'a BTreeMap<Digest, ReceiptRef>,
    accepted_request_digests: &'a BTreeMap<Digest, Digest>,
    issuer_sequences: &'a BTreeMap<(Identity, Identity, Identity), u64>,
    actors_running: &'a BTreeMap<JointActor, bool>,
    source_execution: bool,
    destination_execution: bool,
    native_effect_gate_closed: bool,
    durable_commit: &'a Option<OwnershipCommitObservation>,
    queried_ownership: &'a Option<PendingOwnershipObservation>,
}

impl OracleState {
    fn new(trace: &JointRawTrace) -> Self {
        Self {
            key: trace.key,
            phase: OraclePhase::SourceOwned,
            issuers: trace.issuers,
            scope: trace.initial_scope,
            reservation: None,
            intent: None,
            intent_revision: None,
            visa_freeze: None,
            source_journal_position: None,
            source_state_digest: None,
            nexus_freeze: None,
            nexus_disposition: None,
            nexus_domain_bindings_digest: None,
            destination_prepared: None,
            prepared: None,
            prepared_revision: None,
            decision: OracleDecision::Undecided,
            thaw: None,
            closure_progress: None,
            closure_revision: 0,
            closure: None,
            source_fence: None,
            source_resume: None,
            destination_activation_command: None,
            destination_activation: None,
            effects: BTreeMap::new(),
            accepted_receipts: BTreeMap::new(),
            accepted_request_digests: BTreeMap::new(),
            issuer_sequences: BTreeMap::new(),
            actors_running: BTreeMap::from([
                (JointActor::Coordinator, true),
                (JointActor::Source, true),
                (JointActor::Destination, true),
                (JointActor::OwnershipService, true),
                (JointActor::NexusService, true),
            ]),
            source_execution: true,
            destination_execution: false,
            native_effect_gate_closed: false,
            blocked_seal: false,
            durable_commit: None,
            queried_ownership: None,
            assertions: BTreeSet::new(),
            receipt_error: false,
        }
    }
}

fn oracle_state_sha256(state: &OracleState) -> String {
    let projection = OracleStateDigestProjection {
        domain: "visa-joint-independent-oracle-state-v1",
        key: state.key,
        phase: state.phase,
        issuers: state.issuers,
        scope: state.scope,
        reservation: state.reservation,
        intent: state.intent,
        intent_revision: state.intent_revision,
        visa_freeze: state.visa_freeze,
        source_journal_position: state.source_journal_position,
        source_state_digest: state.source_state_digest,
        nexus_freeze: state.nexus_freeze,
        nexus_disposition: state.nexus_disposition,
        nexus_domain_bindings_digest: state.nexus_domain_bindings_digest,
        destination_prepared: state.destination_prepared,
        prepared: state.prepared,
        prepared_revision: state.prepared_revision,
        decision: state.decision,
        thaw: state.thaw,
        closure_progress: state.closure_progress,
        closure_revision: state.closure_revision,
        closure: state.closure,
        source_fence: state.source_fence,
        source_resume: state.source_resume,
        destination_activation_command: state.destination_activation_command,
        destination_activation: state.destination_activation,
        effects: &state.effects,
        accepted_receipts: &state.accepted_receipts,
        accepted_request_digests: &state.accepted_request_digests,
        issuer_sequences: &state.issuer_sequences,
        actors_running: &state.actors_running,
        source_execution: state.source_execution,
        destination_execution: state.destination_execution,
        native_effect_gate_closed: state.native_effect_gate_closed,
        durable_commit: &state.durable_commit,
        queried_ownership: &state.queried_ownership,
    };
    let bytes = canonical_bytes(&projection).expect("oracle state projection serializes");
    sha256_hex(&bytes)
}

fn pending_observation_matches(
    pending: &PendingOwnershipObservation,
    request: &ReceiptRequest,
    envelope: &ReceiptEnvelope,
    receipt: &JointReceipt,
) -> bool {
    match (pending, receipt) {
        (PendingOwnershipObservation::Abort(expected), JointReceipt::OwnershipAbort(actual)) => {
            expected.request == *request
                && expected.envelope == *envelope
                && expected.receipt == *actual
        }
        (PendingOwnershipObservation::Commit(expected), JointReceipt::OwnershipCommit(actual)) => {
            expected.request == *request
                && expected.envelope == *envelope
                && expected.receipt == *actual
        }
        _ => false,
    }
}

fn validate_pending_ownership_observation(
    state: &OracleState,
    trace: &JointRawTrace,
    pending: &PendingOwnershipObservation,
) -> Result<(), OracleRejection> {
    let mut candidate = state.clone();
    let applied = match pending {
        PendingOwnershipObservation::Abort(observation) => apply_observed_receipt(
            &mut candidate,
            trace,
            &observation.request,
            &observation.envelope,
            &JointReceipt::OwnershipAbort(observation.receipt.clone()),
        ),
        PendingOwnershipObservation::Commit(observation) => apply_observed_receipt(
            &mut candidate,
            trace,
            &observation.request,
            &observation.envelope,
            &JointReceipt::OwnershipCommit(observation.receipt.clone()),
        ),
    }?;
    if applied == ReceiptApply::Applied { Ok(()) } else { Err(OracleRejection::ConflictingReceipt) }
}

struct ReplayResult {
    terminal: Option<JointTerminal>,
    assertions: BTreeSet<JointAssertion>,
}

fn replay_trace(trace: &JointRawTrace, findings: &mut Vec<JointValidationFinding>) -> ReplayResult {
    validate_trace_header(trace, findings);
    let mut state = OracleState::new(trace);
    for (position, raw) in trace.events.iter().enumerate() {
        let expected = u64::try_from(position).unwrap_or(u64::MAX);
        if raw.index != expected {
            finding(
                findings,
                "noncontiguous-joint-event-index",
                Some(&trace.case_id),
                Some(raw.index),
                format!("expected event index {expected}"),
            );
        }
        let before = oracle_state_sha256(&state);
        apply_raw_event(&mut state, trace, raw, findings);
        let after = oracle_state_sha256(&state);
        validate_state_observation(raw, trace, &before, &after, findings);
        validate_safety_invariants(&state, trace, raw.index, findings);
    }
    if state.queried_ownership.is_some() {
        finding(
            findings,
            "queried-ownership-receipt-not-replayed",
            Some(&trace.case_id),
            None,
            "a terminal ownership query was not followed by its exact typed receipt",
        );
    }
    if !state.receipt_error && !state.accepted_receipts.is_empty() {
        state.assertions.insert(JointAssertion::ReceiptChainRecomputed);
    }
    if !matches!(state.decision, OracleDecision::Undecided) {
        state.assertions.insert(JointAssertion::SingleTerminalDecision);
    }
    if state.nexus_freeze.is_some() {
        state.assertions.insert(JointAssertion::EffectCohortRecomputed);
    }
    let terminal = match state.phase {
        OraclePhase::SourceActive => Some(JointTerminal::SourceActive),
        OraclePhase::PreparedFrozen => Some(JointTerminal::PreparedFrozen),
        OraclePhase::FrozenUnsealed if state.blocked_seal => Some(JointTerminal::CommitBlocked),
        OraclePhase::DestinationActive => Some(JointTerminal::DestinationActive),
        _ => None,
    };
    ReplayResult { terminal, assertions: state.assertions }
}

pub fn annotate_joint_trace_observations(trace: &mut JointRawTrace) -> Result<(), String> {
    let mut state = OracleState::new(trace);
    let mut findings = Vec::new();
    for index in 0..trace.events.len() {
        let raw = trace.events[index].clone();
        let before = oracle_state_sha256(&state);
        apply_raw_event(&mut state, trace, &raw, &mut findings);
        let after = oracle_state_sha256(&state);
        match &mut trace.events[index].event {
            JointRawEventKind::ReceiptRejected {
                state_before_sha256, state_after_sha256, ..
            }
            | JointRawEventKind::ExternalFault {
                state_before_sha256, state_after_sha256, ..
            } => {
                *state_before_sha256 = before;
                *state_after_sha256 = after;
            }
            _ => {}
        }
        validate_safety_invariants(&state, trace, raw.index, &mut findings);
    }
    if findings.is_empty() {
        Ok(())
    } else {
        Err(format!("reference trace annotation failed: {findings:?}"))
    }
}

fn validate_trace_header(trace: &JointRawTrace, findings: &mut Vec<JointValidationFinding>) {
    if trace.protocol_version != JointProtocolVersion::V1 {
        finding(
            findings,
            "unsupported-joint-protocol-version",
            Some(&trace.case_id),
            None,
            format!("{:?}", trace.protocol_version),
        );
    }
    if !well_formed_key(trace.key) {
        finding(
            findings,
            "invalid-joint-handoff-key",
            Some(&trace.case_id),
            None,
            "handoff key is zero, aliases source/destination, or has a non-successor epoch",
        );
    }
    let issuer_values = [
        trace.issuers.ownership,
        trace.issuers.visa_source,
        trace.issuers.visa_destination,
        trace.issuers.effect_closure,
    ];
    if issuer_values.iter().any(|issuer| !well_formed_issuer(*issuer)) {
        finding(
            findings,
            "invalid-joint-issuer-set",
            Some(&trace.case_id),
            None,
            "issuer identities must all be nonzero",
        );
    }
    for (index, issuer) in issuer_values.iter().enumerate() {
        if issuer_values[..index].iter().any(|other| other.issuer == issuer.issuer) {
            finding(
                findings,
                "aliased-joint-issuer",
                Some(&trace.case_id),
                None,
                "two issuer roles share one authority identity",
            );
        }
    }
    if !well_formed_scope(trace.initial_scope) {
        finding(
            findings,
            "invalid-joint-effect-scope",
            Some(&trace.case_id),
            None,
            "initial effect scope is not well formed",
        );
    }
    if trace.mapping.version != JointProtocolVersion::V1
        || trace.mapping.key != trace.key
        || trace.mapping.protocol_revision == 0
        || !nonzero(trace.mapping.visa_operation_cohort_digest)
        || !nonzero(trace.mapping.effect_cohort_digest)
        || !nonzero(trace.mapping.domain_bindings_manifest_digest)
    {
        finding(
            findings,
            "invalid-joint-mapping-manifest",
            Some(&trace.case_id),
            None,
            "mapping schema, key, protocol, or digest binding is invalid",
        );
    }
    let prepared = &trace.prepared_input;
    if prepared.snapshot.snapshot.is_zero()
        || prepared.snapshot.source_journal_position.0 == 0
        || prepared.destination_journal_position.0 == 0
        || prepared.lease_commit_operation.is_zero()
        || [
            prepared.snapshot.integrity,
            prepared.snapshot.body_digest,
            prepared.snapshot.component_digest,
            prepared.snapshot.profile_digest,
            prepared.destination_state_digest,
            prepared.prepared_destination_digest,
            prepared.prepared_authorities_digest,
            prepared.prepared_bindings_digest,
            prepared.lease_commit_request_digest,
        ]
        .into_iter()
        .any(|digest| !nonzero(digest))
    {
        finding(
            findings,
            "invalid-joint-prepared-input",
            Some(&trace.case_id),
            None,
            "expected snapshot, destination state, authority, or binding input is invalid",
        );
    }
}

fn apply_raw_event(
    state: &mut OracleState,
    trace: &JointRawTrace,
    raw: &JointRawEvent,
    findings: &mut Vec<JointValidationFinding>,
) {
    if let Some(expected) = &state.queried_ownership {
        let exact_replay = matches!(
            &raw.event,
            JointRawEventKind::ReceiptAccepted { request, envelope, receipt }
                if pending_observation_matches(expected, request, envelope, receipt)
        );
        if !exact_replay {
            finding(
                findings,
                "queried-ownership-receipt-not-replayed",
                Some(&trace.case_id),
                Some(raw.index),
                "the event after a terminal query is not its exact typed native receipt",
            );
            return;
        }
    }
    match &raw.event {
        JointRawEventKind::ReceiptAccepted { request, envelope, receipt } => {
            match apply_observed_receipt(state, trace, request, envelope, receipt) {
                Ok(ReceiptApply::Applied) => {
                    let recovered = state.queried_ownership.take();
                    if matches!(recovered, Some(PendingOwnershipObservation::Commit(_))) {
                        state.durable_commit = None;
                    }
                }
                Ok(ReceiptApply::Replayed) => {
                    state.queried_ownership = None;
                    state.assertions.insert(JointAssertion::DuplicateReceiptIdempotent);
                }
                Err(rejection) => {
                    state.receipt_error = true;
                    finding(
                        findings,
                        "accepted-joint-receipt-rejected-by-oracle",
                        Some(&trace.case_id),
                        Some(raw.index),
                        format!("kind={:?}, rejection={rejection:?}", receipt.kind()),
                    );
                }
            }
        }
        JointRawEventKind::ReceiptRejected { request, envelope, receipt, rejection, .. } => {
            let mut candidate = state.clone();
            match apply_observed_receipt(&mut candidate, trace, request, envelope, receipt) {
                Err(actual) if actual == *rejection => {
                    state.assertions.insert(JointAssertion::StaleInputHadNoEffect);
                    if actual == OracleRejection::DecisionConflict {
                        state.assertions.insert(JointAssertion::SingleTerminalDecision);
                    }
                    if matches!(
                        actual,
                        OracleRejection::StaleIssuerIncarnation
                            | OracleRejection::StaleScope
                            | OracleRejection::StaleFreezeGeneration
                    ) && receipt.kind() == ReceiptKind::NexusFreeze
                    {
                        state.assertions.insert(JointAssertion::RebindRejectedStaleIssuer);
                    }
                    if actual == OracleRejection::CompetingDestination {
                        state.assertions.insert(JointAssertion::SingleDestinationSelected);
                    }
                    if actual == OracleRejection::ReceiptMismatch
                        && receipt.kind() == ReceiptKind::DestinationPrepared
                    {
                        state.assertions.insert(JointAssertion::DestinationPreparedBound);
                    }
                    if matches!(
                        actual,
                        OracleRejection::MissingPrerequisite | OracleRejection::InvalidPhase
                    ) {
                        state.assertions.insert(JointAssertion::ReorderedReceiptRejected);
                    }
                    if actual == OracleRejection::ClosureBlocked
                        && receipt.kind() == ReceiptKind::OwnershipPrepared
                    {
                        state.blocked_seal = true;
                        state.assertions.insert(JointAssertion::UnresolvedTombstoneBlockedSeal);
                    }
                }
                Err(actual) => finding(
                    findings,
                    "joint-rejection-mismatch",
                    Some(&trace.case_id),
                    Some(raw.index),
                    format!("claimed={rejection:?}, recomputed={actual:?}"),
                ),
                Ok(_) => finding(
                    findings,
                    "rejected-joint-receipt-accepted-by-oracle",
                    Some(&trace.case_id),
                    Some(raw.index),
                    format!("kind={:?}", receipt.kind()),
                ),
            }
        }
        JointRawEventKind::EffectPublication { .. } => {
            apply_effect_publication(state, trace, raw.index, &raw.event, findings)
        }
        JointRawEventKind::OwnershipQuery { result } => match result {
            OwnershipQueryResult::Unavailable
            | OwnershipQueryResult::Reserved
            | OwnershipQueryResult::Prepared => {
                if state.durable_commit.is_some()
                    && !matches!(result, OwnershipQueryResult::Unavailable)
                {
                    finding(
                        findings,
                        "ownership-query-equivocated-after-durable-commit",
                        Some(&trace.case_id),
                        Some(raw.index),
                        "a durable commit cannot later query as reserved or prepared",
                    );
                    return;
                }
                if matches!(state.decision, OracleDecision::Undecided)
                    && matches!(
                        state.phase,
                        OraclePhase::PrepareIntent
                            | OraclePhase::FrozenUnsealed
                            | OraclePhase::PreparedFrozen
                    )
                {
                    state.assertions.insert(JointAssertion::UnknownDecisionRemainedFrozen);
                }
            }
            OwnershipQueryResult::AbortDecided { observation } => {
                let pending = PendingOwnershipObservation::Abort(observation.clone());
                if validate_pending_ownership_observation(state, trace, &pending).is_err() {
                    finding(
                        findings,
                        "invalid-terminal-ownership-query",
                        Some(&trace.case_id),
                        Some(raw.index),
                        "abort query did not return a valid exact typed receipt",
                    );
                } else {
                    state.queried_ownership = Some(pending);
                }
            }
            OwnershipQueryResult::CommitDecided { observation } => {
                let pending = PendingOwnershipObservation::Commit(observation.clone());
                if state.durable_commit.as_ref() != Some(observation)
                    || validate_pending_ownership_observation(state, trace, &pending).is_err()
                {
                    finding(
                        findings,
                        "invalid-terminal-ownership-query",
                        Some(&trace.case_id),
                        Some(raw.index),
                        "commit query did not recover the exact durable lost-ack receipt",
                    );
                } else {
                    state.queried_ownership = Some(pending);
                }
            }
        },
        JointRawEventKind::ExternalFault { fault, .. } => match fault {
            JointExternalFault::DestinationPreparationFailed
                if state.phase == OraclePhase::FrozenUnsealed && state.nexus_freeze.is_some() =>
            {
                state.assertions.insert(JointAssertion::StaleInputHadNoEffect);
            }
            JointExternalFault::CommitAcknowledgementLost { durable_commit }
                if state.phase == OraclePhase::PreparedFrozen && state.durable_commit.is_none() =>
            {
                let pending = PendingOwnershipObservation::Commit(durable_commit.as_ref().clone());
                if validate_pending_ownership_observation(state, trace, &pending).is_err() {
                    finding(
                        findings,
                        "invalid-lost-ack-durable-commit",
                        Some(&trace.case_id),
                        Some(raw.index),
                        "lost acknowledgement did not retain a valid authoritative commit",
                    );
                } else {
                    state.durable_commit = Some(durable_commit.as_ref().clone());
                }
            }
            _ => finding(
                findings,
                "invalid-joint-fault-injection-point",
                Some(&trace.case_id),
                Some(raw.index),
                format!("fault={fault:?}, phase={:?}", state.phase),
            ),
        },
        JointRawEventKind::ActorCrashed { actor } => {
            if state.actors_running.insert(*actor, false) != Some(true) {
                finding(
                    findings,
                    "invalid-joint-actor-crash",
                    Some(&trace.case_id),
                    Some(raw.index),
                    format!("{actor:?} was not running"),
                );
            }
        }
        JointRawEventKind::ActorRestarted { actor } => {
            if state.actors_running.insert(*actor, true) != Some(false) {
                finding(
                    findings,
                    "invalid-joint-actor-restart",
                    Some(&trace.case_id),
                    Some(raw.index),
                    format!("{actor:?} had not crashed"),
                );
            }
            if requires_fail_closed_restart(state.phase) {
                if restart_projection_is_fail_closed(state) {
                    state.assertions.insert(JointAssertion::CrashRecoveryFailedClosed);
                } else {
                    finding(
                        findings,
                        "joint-restart-failed-open",
                        Some(&trace.case_id),
                        Some(raw.index),
                        format!("{actor:?} replayed unsafe authority in phase {:?}", state.phase),
                    );
                }
            }
        }
        JointRawEventKind::NexusServiceRebound { .. } => {
            apply_nexus_rebind(state, trace, raw.index, &raw.event, findings)
        }
        JointRawEventKind::DestinationActivationStarted { commit, closure, activation_command } => {
            if state.phase != OraclePhase::SourceClosed
                || state.source_fence.is_none()
                || activation_command.is_zero()
                || !matches!(state.decision, OracleDecision::Commit(value) if value == *commit)
                || state.closure != Some(*closure)
            {
                finding(
                    findings,
                    "destination-activation-before-source-closure",
                    Some(&trace.case_id),
                    Some(raw.index),
                    "activation did not bind the committed decision, closure, and source fence",
                );
            } else {
                state.destination_activation_command = Some(*activation_command);
                state.phase = OraclePhase::DestinationActivationPending;
            }
        }
    }
}

fn apply_effect_publication(
    state: &mut OracleState,
    trace: &JointRawTrace,
    event_index: u64,
    event: &JointRawEventKind,
    findings: &mut Vec<JointValidationFinding>,
) {
    let JointRawEventKind::EffectPublication {
        record,
        source_epoch,
        scope_generation,
        accepted,
        rejection,
    } = event
    else {
        unreachable!()
    };
    let resumed_registered_commit = state.effects.get(&record.effect).is_some_and(|existing| {
        state.phase == OraclePhase::SourceActive
            && matches!(state.decision, OracleDecision::Abort(_))
            && existing.classification == JointEffectClassification::Registered
            && record.classification == JointEffectClassification::Committed
            && existing.operation == record.operation
            && existing.domain == record.domain
            && existing.binding_generation == record.binding_generation
            && existing.outcome_digest.is_none()
            && existing.tombstone_digest.is_none()
            && record.outcome_digest.is_some()
            && record.tombstone_digest.is_none()
    });
    let expected_rejection = if *source_epoch != state.key.expected_epoch {
        Some(OracleRejection::StaleEpoch)
    } else if *scope_generation != state.scope.scope_generation
        || record.binding_generation != state.scope.scope_generation
    {
        Some(OracleRejection::StaleScope)
    } else if state.native_effect_gate_closed {
        Some(OracleRejection::EffectGateClosed)
    } else if (state.effects.contains_key(&record.effect) && !resumed_registered_commit)
        || record.effect.is_zero()
    {
        Some(OracleRejection::ConflictingReceipt)
    } else {
        None
    };
    match (expected_rejection, *accepted, *rejection) {
        (None, true, None) => {
            state.effects.insert(record.effect, record.clone());
            state.assertions.insert(JointAssertion::FreezeSerializedPublication);
            if resumed_registered_commit {
                state.assertions.insert(JointAssertion::PrecommitAbortPreservedRegisteredEffect);
            }
        }
        (Some(expected), false, Some(actual)) if expected == actual => {
            state.assertions.insert(JointAssertion::FreezeSerializedPublication);
            state.assertions.insert(JointAssertion::StaleInputHadNoEffect);
        }
        (expected, actual_accepted, actual_rejection) => finding(
            findings,
            "joint-effect-publication-result-mismatch",
            Some(&trace.case_id),
            Some(event_index),
            format!(
                "expected_rejection={expected:?}, accepted={actual_accepted}, rejection={actual_rejection:?}"
            ),
        ),
    }
}

fn apply_nexus_rebind(
    state: &mut OracleState,
    trace: &JointRawTrace,
    event_index: u64,
    event: &JointRawEventKind,
    findings: &mut Vec<JointValidationFinding>,
) {
    let JointRawEventKind::NexusServiceRebound {
        previous,
        current,
        previous_scope,
        current_scope,
        domain_bindings_manifest_digest,
    } = event
    else {
        unreachable!()
    };
    let nexus_running =
        state.actors_running.get(&JointActor::NexusService).copied().unwrap_or(true);
    if nexus_running
        || state.phase != OraclePhase::FrozenUnsealed
        || state.nexus_freeze.is_some()
        || *previous != state.issuers.effect_closure
        || *previous_scope != state.scope
        || !well_formed_issuer(*current)
        || !well_formed_scope(*current_scope)
        || *current != *previous
        || current_scope.registry_instance == previous_scope.registry_instance
        || current_scope.scope_generation <= previous_scope.scope_generation
        || current_scope.freeze_generation <= previous_scope.freeze_generation
        || !nonzero(*domain_bindings_manifest_digest)
    {
        finding(
            findings,
            "invalid-joint-nexus-rebind",
            Some(&trace.case_id),
            Some(event_index),
            "rebind changed the pinned signer or did not advance the service/scope lineage",
        );
        return;
    }
    state.scope = *current_scope;
    state.actors_running.insert(JointActor::NexusService, true);
    state.assertions.insert(JointAssertion::CrashRecoveryFailedClosed);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReceiptApply {
    Applied,
    Replayed,
}

fn apply_observed_receipt(
    state: &mut OracleState,
    trace: &JointRawTrace,
    request: &ReceiptRequest,
    envelope: &ReceiptEnvelope,
    receipt: &JointReceipt,
) -> Result<ReceiptApply, OracleRejection> {
    validate_receipt_envelope(request, envelope, receipt)?;
    let receipt_digest =
        joint_receipt_ref(receipt).map_err(|_| OracleRejection::InvalidDigest)?.digest;
    if let Some(existing) = state.accepted_request_digests.get(&receipt_digest)
        && *existing != envelope.request_digest
    {
        return Err(OracleRejection::ConflictingReceipt);
    }
    let applied = apply_receipt(state, trace, receipt)?;
    if applied == ReceiptApply::Applied {
        state.accepted_request_digests.insert(receipt_digest, envelope.request_digest);
    }
    Ok(applied)
}

fn validate_receipt_envelope(
    request: &ReceiptRequest,
    envelope: &ReceiptEnvelope,
    receipt: &JointReceipt,
) -> Result<(), OracleRejection> {
    let header = receipt.header();
    let payload =
        joint_receipt_payload_digest(receipt).map_err(|_| OracleRejection::InvalidDigest)?;
    let expected_request_digest =
        joint_receipt_request_digest(request).map_err(|_| OracleRejection::InvalidDigest)?;
    let expected_authentication =
        joint_reference_authentication(envelope).map_err(|_| OracleRejection::InvalidDigest)?;
    if envelope.schema != header.version
        || envelope.schema != JointProtocolVersion::V1
        || envelope.issuer != header.issuer
        || envelope.issuer_incarnation != header.issuer_incarnation
        || envelope.kind != receipt.kind()
        || envelope.handoff != receipt.key().handoff
        || envelope.state_sequence != header.sequence
        || envelope.previous_receipt_digest != header.previous_digest
        || envelope.payload_digest != payload
        || !joint_receipt_request_matches(request, receipt)
        || envelope.request_digest != expected_request_digest
        || envelope.authentication != expected_authentication
    {
        return Err(OracleRejection::InvalidReceiptHeader);
    }
    Ok(())
}

fn apply_receipt(
    state: &mut OracleState,
    trace: &JointRawTrace,
    receipt: &JointReceipt,
) -> Result<ReceiptApply, OracleRejection> {
    validate_receipt_key(state.key, receipt.key())?;
    if receipt.header().version != JointProtocolVersion::V1 {
        return Err(OracleRejection::UnsupportedVersion);
    }
    if receipt.header().kind != receipt.kind() {
        return Err(OracleRejection::InvalidReceiptKind);
    }
    let reference = joint_receipt_ref(receipt).map_err(|_| OracleRejection::InvalidDigest)?;
    if let Some(existing) = state.accepted_receipts.get(&reference.digest) {
        return if *existing == reference {
            Ok(ReceiptApply::Replayed)
        } else {
            Err(OracleRejection::ConflictingReceipt)
        };
    }
    let expected_issuer = issuer_for_kind(&state.issuers, receipt.kind());
    validate_receipt_header(state, receipt.header(), expected_issuer)?;

    match receipt {
        JointReceipt::PrepareIntent(value) => apply_prepare_intent(state, value, reference)?,
        JointReceipt::VisaFreeze(value) => apply_visa_freeze(state, value, reference)?,
        JointReceipt::EffectFreeze(value) => apply_nexus_freeze(state, value, reference)?,
        JointReceipt::DestinationPrepared(value) => {
            apply_destination_prepared(state, trace, value, reference)?
        }
        JointReceipt::OwnershipPrepared(value) => {
            apply_ownership_prepared(state, trace, value, reference)?
        }
        JointReceipt::OwnershipAbort(value) => apply_abort(state, value, reference)?,
        JointReceipt::OwnershipCommit(value) => apply_commit(state, value, reference)?,
        JointReceipt::EffectThaw(value) => apply_thaw(state, value, reference)?,
        JointReceipt::ClosureProgress(value) => apply_closure_progress(state, value, reference)?,
        JointReceipt::Closure(value) => apply_closure(state, value, reference)?,
        JointReceipt::RetainedTombstone(value) => {
            apply_retained_tombstone(state, value, reference)?
        }
        JointReceipt::VisaSourceFence(value) => apply_source_fence(state, value, reference)?,
        JointReceipt::VisaSourceResume(value) => apply_source_resume(state, value, reference)?,
        JointReceipt::VisaDestinationActivation(value) => {
            apply_destination_activation(state, value, reference)?
        }
    }
    commit_receipt_header(state, receipt.header(), reference);
    Ok(ReceiptApply::Applied)
}

fn apply_prepare_intent(
    state: &mut OracleState,
    receipt: &PrepareIntentReceipt,
    reference: ReceiptRef,
) -> Result<(), OracleRejection> {
    if state.phase != OraclePhase::SourceOwned {
        return Err(OracleRejection::InvalidPhase);
    }
    require_previous(receipt.header.previous_digest, None)?;
    let ownership = state.issuers.ownership;
    if receipt.ownership_service != ownership.issuer
        || receipt.service_incarnation != ownership.issuer_incarnation
        || receipt.reservation.is_zero()
        || receipt.intent_revision == 0
        || !nonzero(receipt.request_digest)
    {
        return Err(OracleRejection::InvalidRevision);
    }
    state.intent = Some(reference);
    state.reservation = Some(receipt.reservation);
    state.intent_revision = Some(receipt.intent_revision);
    state.phase = OraclePhase::PrepareIntent;
    Ok(())
}

fn apply_visa_freeze(
    state: &mut OracleState,
    receipt: &VisaFreezeReceipt,
    reference: ReceiptRef,
) -> Result<(), OracleRejection> {
    if state.phase != OraclePhase::PrepareIntent {
        return Err(OracleRejection::InvalidPhase);
    }
    let intent = required(state.intent)?;
    require_reference(receipt.intent, intent)?;
    require_previous(receipt.header.previous_digest, None)?;
    if receipt.journal_position.0 == 0
        || !nonzero(receipt.state_digest)
        || !nonzero(receipt.portable_state_digest)
    {
        return Err(OracleRejection::InvalidDigest);
    }
    state.visa_freeze = Some(reference);
    state.source_journal_position = Some(receipt.journal_position);
    state.source_state_digest = Some(receipt.state_digest);
    state.source_execution = false;
    state.phase = OraclePhase::FrozenUnsealed;
    Ok(())
}

fn apply_nexus_freeze(
    state: &mut OracleState,
    receipt: &NexusFreezeReceipt,
    reference: ReceiptRef,
) -> Result<(), OracleRejection> {
    if state.phase != OraclePhase::FrozenUnsealed || state.visa_freeze.is_none() {
        return Err(OracleRejection::MissingPrerequisite);
    }
    if state.nexus_freeze.is_some() {
        return Err(OracleRejection::ConflictingReceipt);
    }
    let intent = required(state.intent)?;
    require_reference(receipt.intent, intent)?;
    require_previous(receipt.header.previous_digest, None)?;
    if receipt.registry_instance != state.scope.registry_instance
        || receipt.scope_id != state.scope.scope_id
        || receipt.scope_generation != state.scope.scope_generation
    {
        return Err(OracleRejection::StaleScope);
    }
    if receipt.authority_epoch != state.scope.authority_epoch {
        return Err(OracleRejection::StaleEpoch);
    }
    if receipt.freeze_generation != state.scope.freeze_generation {
        return Err(OracleRejection::StaleFreezeGeneration);
    }
    if !nonzero(receipt.domain_bindings_digest) {
        return Err(OracleRejection::InvalidDigest);
    }
    let effects: Vec<_> = state.effects.values().cloned().collect();
    let cohort = joint_effect_cohort_digest(state.key, effects.clone())
        .map_err(|_| OracleRejection::InvalidDigest)?;
    let classification = joint_classification_root(state.key, effects.clone())
        .map_err(|_| OracleRejection::InvalidDigest)?;
    let counts = joint_classification_counts(effects.clone());
    if receipt.effect_cohort_digest != cohort
        || receipt.classification_root != classification
        || receipt.counts != counts
    {
        return Err(OracleRejection::EffectCohortMismatch);
    }
    let has_blocker = effects.iter().any(|effect| {
        matches!(
            effect.classification,
            JointEffectClassification::Registered | JointEffectClassification::UnresolvedTombstone
        )
    });
    match (has_blocker, receipt.disposition) {
        (false, FreezeDisposition::ReadyToCommit) => {}
        (true, FreezeDisposition::Blocked { blocker_digest })
            if blocker_digest == classification =>
        {
            state.blocked_seal = true;
        }
        _ => return Err(OracleRejection::EffectCohortMismatch),
    }
    state.nexus_freeze = Some(reference);
    state.nexus_disposition = Some(receipt.disposition);
    state.nexus_domain_bindings_digest = Some(receipt.domain_bindings_digest);
    state.native_effect_gate_closed = true;
    state.assertions.insert(JointAssertion::EffectCohortRecomputed);
    Ok(())
}

fn apply_destination_prepared(
    state: &mut OracleState,
    trace: &JointRawTrace,
    receipt: &DestinationPreparedReceipt,
    reference: ReceiptRef,
) -> Result<(), OracleRejection> {
    if state.phase != OraclePhase::FrozenUnsealed {
        return Err(OracleRejection::InvalidPhase);
    }
    if !matches!(state.nexus_disposition, Some(FreezeDisposition::ReadyToCommit)) {
        return Err(OracleRejection::ClosureBlocked);
    }
    let intent = required(state.intent)?;
    let visa_freeze = required(state.visa_freeze)?;
    let nexus_freeze = required(state.nexus_freeze)?;
    require_reference(receipt.intent, intent)?;
    require_reference(receipt.visa_freeze, visa_freeze)?;
    require_reference(receipt.nexus_freeze, nexus_freeze)?;
    require_previous(receipt.header.previous_digest, None)?;
    let expected = &trace.prepared_input;
    let mapping_digest =
        joint_mapping_digest(&trace.mapping).map_err(|_| OracleRejection::InvalidDigest)?;
    if receipt.snapshot != expected.snapshot
        || receipt.snapshot.source_journal_position != required(state.source_journal_position)?
        || receipt.journal_position != expected.destination_journal_position
        || receipt.state_digest != expected.destination_state_digest
        || receipt.prepared_destination_digest != expected.prepared_destination_digest
        || receipt.authorities_digest != expected.prepared_authorities_digest
        || receipt.bindings_digest != expected.prepared_bindings_digest
        || receipt.joint_mapping_manifest_digest != mapping_digest
        || receipt.lease_commit_operation != expected.lease_commit_operation
        || receipt.lease_commit_idempotency != expected.lease_commit_idempotency
        || receipt.lease_commit_request_digest != expected.lease_commit_request_digest
    {
        return Err(OracleRejection::ReceiptMismatch);
    }
    state.destination_prepared = Some(reference);
    state.assertions.insert(JointAssertion::DestinationPreparedBound);
    Ok(())
}

fn apply_ownership_prepared(
    state: &mut OracleState,
    trace: &JointRawTrace,
    receipt: &OwnershipPreparedReceipt,
    reference: ReceiptRef,
) -> Result<(), OracleRejection> {
    if state.phase != OraclePhase::FrozenUnsealed {
        return Err(OracleRejection::InvalidPhase);
    }
    if !matches!(state.nexus_disposition, Some(FreezeDisposition::ReadyToCommit)) {
        return Err(OracleRejection::ClosureBlocked);
    }
    let intent = required(state.intent)?;
    let visa_freeze = required(state.visa_freeze)?;
    let nexus_freeze = required(state.nexus_freeze)?;
    let destination = required(state.destination_prepared)?;
    require_reference(receipt.intent, intent)?;
    require_reference(receipt.visa_freeze, visa_freeze)?;
    require_reference(receipt.nexus_freeze, nexus_freeze)?;
    require_reference(receipt.destination_prepared, destination)?;
    require_previous(receipt.header.previous_digest, Some(intent.digest))?;
    let mapping =
        joint_mapping_digest(&trace.mapping).map_err(|_| OracleRejection::InvalidDigest)?;
    let bindings = expected_prepared_bindings(state, trace, mapping)?;
    if receipt.reservation != required(state.reservation)?
        || receipt.bindings != bindings
        || trace.mapping.key != state.key
        || trace.mapping.effect_scope != state.scope
        || trace.mapping.effect_cohort_digest
            != nexus_effect_digest(state).ok_or(OracleRejection::EffectCohortMismatch)?
        || trace.mapping.domain_bindings_manifest_digest
            != nexus_domain_digest(state).ok_or(OracleRejection::ReceiptMismatch)?
        || trace.mapping.ownership_service.service_id != state.issuers.ownership.issuer
        || trace.mapping.ownership_service.service_incarnation
            != state.issuers.ownership.issuer_incarnation
    {
        return Err(OracleRejection::ReceiptMismatch);
    }
    let intent_revision = state.intent_revision.ok_or(OracleRejection::MissingPrerequisite)?;
    if receipt.prepared_revision <= intent_revision {
        return Err(OracleRejection::InvalidRevision);
    }
    state.prepared = Some(reference);
    state.prepared_revision = Some(receipt.prepared_revision);
    state.phase = OraclePhase::PreparedFrozen;
    state.assertions.insert(JointAssertion::PreparedBindingsComplete);
    Ok(())
}

fn apply_abort(
    state: &mut OracleState,
    receipt: &OwnershipAbortReceipt,
    reference: ReceiptRef,
) -> Result<(), OracleRejection> {
    if !matches!(state.decision, OracleDecision::Undecided) {
        return Err(OracleRejection::DecisionConflict);
    }
    if !matches!(
        state.phase,
        OraclePhase::PrepareIntent | OraclePhase::FrozenUnsealed | OraclePhase::PreparedFrozen
    ) {
        return Err(OracleRejection::InvalidPhase);
    }
    let (basis, revision) = match (state.prepared, state.prepared_revision) {
        (Some(prepared), Some(revision)) => (prepared, revision),
        (None, None) => (
            required(state.intent)?,
            state.intent_revision.ok_or(OracleRejection::MissingPrerequisite)?,
        ),
        _ => return Err(OracleRejection::MissingPrerequisite),
    };
    require_reference(receipt.basis, basis)?;
    require_previous(receipt.header.previous_digest, Some(basis.digest))?;
    if receipt.reservation != required(state.reservation)?
        || receipt.basis_revision != revision
        || receipt.decision_sequence <= revision
        || receipt.header.sequence != receipt.decision_sequence
        || !nonzero(receipt.non_equivocation_root)
    {
        return Err(OracleRejection::InvalidRevision);
    }
    state.decision = OracleDecision::Abort(reference);
    state.phase = OraclePhase::AbortDecided;
    state.source_execution = false;
    state.assertions.insert(JointAssertion::SingleTerminalDecision);
    Ok(())
}

fn apply_commit(
    state: &mut OracleState,
    receipt: &OwnershipCommitReceipt,
    reference: ReceiptRef,
) -> Result<(), OracleRejection> {
    if !matches!(state.decision, OracleDecision::Undecided) {
        return Err(OracleRejection::DecisionConflict);
    }
    if state.phase != OraclePhase::PreparedFrozen {
        return Err(OracleRejection::InvalidPhase);
    }
    let prepared = required(state.prepared)?;
    let revision = state.prepared_revision.ok_or(OracleRejection::MissingPrerequisite)?;
    require_reference(receipt.prepared, prepared)?;
    require_previous(receipt.header.previous_digest, Some(prepared.digest))?;
    if receipt.reservation != required(state.reservation)?
        || receipt.prepared_revision != revision
        || receipt.decision_sequence <= revision
        || receipt.header.sequence != receipt.decision_sequence
        || !nonzero(receipt.non_equivocation_root)
    {
        return Err(OracleRejection::InvalidRevision);
    }
    state.decision = OracleDecision::Commit(reference);
    state.phase = OraclePhase::CommitDecided;
    state.source_execution = false;
    state.assertions.insert(JointAssertion::SingleTerminalDecision);
    state.assertions.insert(JointAssertion::SourceFencedAfterCommit);
    Ok(())
}

fn apply_thaw(
    state: &mut OracleState,
    receipt: &NexusThawReceipt,
    reference: ReceiptRef,
) -> Result<(), OracleRejection> {
    if state.phase != OraclePhase::AbortDecided {
        return Err(OracleRejection::InvalidPhase);
    }
    let OracleDecision::Abort(abort) = state.decision else {
        return Err(OracleRejection::DecisionConflict);
    };
    require_reference(receipt.abort, abort)?;
    if receipt.nexus_freeze != required(state.nexus_freeze)? || receipt.thaw_generation == 0 {
        return Err(OracleRejection::ReceiptMismatch);
    }
    require_previous(receipt.header.previous_digest, Some(receipt.nexus_freeze.digest))?;
    state.thaw = Some(reference);
    state.phase = OraclePhase::SourceThawPending;
    state.native_effect_gate_closed = false;
    state.assertions.insert(JointAssertion::AbortAuthorizedThaw);
    Ok(())
}

fn apply_source_resume(
    state: &mut OracleState,
    receipt: &VisaSourceResumeReceipt,
    reference: ReceiptRef,
) -> Result<(), OracleRejection> {
    if state.phase != OraclePhase::SourceThawPending {
        return Err(OracleRejection::InvalidPhase);
    }
    let OracleDecision::Abort(abort) = state.decision else {
        return Err(OracleRejection::DecisionConflict);
    };
    let thaw = required(state.thaw)?;
    require_reference(receipt.abort, abort)?;
    if receipt.thaw != Some(thaw) {
        return Err(OracleRejection::ReceiptMismatch);
    }
    require_previous(receipt.header.previous_digest, Some(required(state.visa_freeze)?.digest))?;
    if receipt.journal_position.0 == 0 || !nonzero(receipt.state_digest) {
        return Err(OracleRejection::InvalidDigest);
    }
    state.source_resume = Some(reference);
    state.source_execution = true;
    state.destination_execution = false;
    state.phase = OraclePhase::SourceActive;
    state.assertions.insert(JointAssertion::AbortAuthorizedThaw);
    Ok(())
}

fn apply_closure_progress(
    state: &mut OracleState,
    receipt: &ClosureProgressReceipt,
    reference: ReceiptRef,
) -> Result<(), OracleRejection> {
    if !matches!(state.phase, OraclePhase::CommitDecided | OraclePhase::ClosurePending) {
        return Err(OracleRejection::InvalidPhase);
    }
    let (commit, nexus_freeze) = commit_and_freeze(state)?;
    require_reference(receipt.commit, commit)?;
    require_reference(receipt.nexus_freeze, nexus_freeze)?;
    let previous = state.closure_progress.map_or(nexus_freeze.digest, |value| value.digest);
    require_previous(receipt.header.previous_digest, Some(previous))?;
    if receipt.closure_revision <= state.closure_revision || !nonzero(receipt.progress_root) {
        return Err(OracleRejection::InvalidRevision);
    }
    state.closure_revision = receipt.closure_revision;
    state.closure_progress = Some(reference);
    state.phase = OraclePhase::ClosurePending;
    Ok(())
}

fn apply_closure(
    state: &mut OracleState,
    receipt: &ClosureReceipt,
    reference: ReceiptRef,
) -> Result<(), OracleRejection> {
    if !matches!(state.phase, OraclePhase::CommitDecided | OraclePhase::ClosurePending) {
        return Err(OracleRejection::InvalidPhase);
    }
    let (commit, nexus_freeze) = commit_and_freeze(state)?;
    require_reference(receipt.commit, commit)?;
    require_reference(receipt.nexus_freeze, nexus_freeze)?;
    let previous = state.closure_progress.map_or(nexus_freeze.digest, |value| value.digest);
    require_previous(receipt.header.previous_digest, Some(previous))?;
    let cohort = joint_effect_cohort_digest(state.key, state.effects.values().cloned())
        .map_err(|_| OracleRejection::InvalidDigest)?;
    if receipt.closure_revision <= state.closure_revision
        || receipt.effect_manifest_digest != cohort
        || receipt.closed_authority_epoch != state.scope.authority_epoch
    {
        return Err(OracleRejection::EffectCohortMismatch);
    }
    state.closure_revision = receipt.closure_revision;
    state.closure = Some(reference);
    state.phase = OraclePhase::SourceClosed;
    state.source_execution = false;
    state.assertions.insert(JointAssertion::CommitAuthorizedClosure);
    Ok(())
}

fn apply_retained_tombstone(
    state: &mut OracleState,
    receipt: &RetainedTombstoneReceipt,
    reference: ReceiptRef,
) -> Result<(), OracleRejection> {
    if !matches!(state.phase, OraclePhase::CommitDecided | OraclePhase::ClosurePending) {
        return Err(OracleRejection::InvalidPhase);
    }
    let (commit, nexus_freeze) = commit_and_freeze(state)?;
    require_reference(receipt.commit, commit)?;
    require_reference(receipt.nexus_freeze, nexus_freeze)?;
    let previous = state.closure_progress.map_or(nexus_freeze.digest, |value| value.digest);
    require_previous(receipt.header.previous_digest, Some(previous))?;
    if receipt.closure_revision <= state.closure_revision
        || receipt.tombstone_count == 0
        || !nonzero(receipt.tombstone_manifest_digest)
    {
        return Err(OracleRejection::InvalidRevision);
    }
    state.closure_revision = receipt.closure_revision;
    state.closure = Some(reference);
    state.phase = OraclePhase::RecoveryRequired;
    state.source_execution = false;
    state.destination_execution = false;
    Ok(())
}

fn apply_source_fence(
    state: &mut OracleState,
    receipt: &VisaSourceFenceReceipt,
    reference: ReceiptRef,
) -> Result<(), OracleRejection> {
    if state.phase != OraclePhase::SourceClosed {
        return Err(OracleRejection::InvalidPhase);
    }
    let OracleDecision::Commit(commit) = state.decision else {
        return Err(OracleRejection::DecisionConflict);
    };
    let closure = required(state.closure)?;
    require_reference(receipt.commit, commit)?;
    require_reference(receipt.closure, closure)?;
    require_previous(receipt.header.previous_digest, Some(required(state.visa_freeze)?.digest))?;
    if receipt.journal_position.0 == 0 || !nonzero(receipt.state_digest) {
        return Err(OracleRejection::InvalidDigest);
    }
    state.source_fence = Some(reference);
    state.source_execution = false;
    state.assertions.insert(JointAssertion::SourceFencedAfterCommit);
    Ok(())
}

fn apply_destination_activation(
    state: &mut OracleState,
    receipt: &VisaDestinationActivationReceipt,
    reference: ReceiptRef,
) -> Result<(), OracleRejection> {
    if state.phase != OraclePhase::DestinationActivationPending || state.source_fence.is_none() {
        return Err(OracleRejection::ClosureBlocked);
    }
    let OracleDecision::Commit(commit) = state.decision else {
        return Err(OracleRejection::DecisionConflict);
    };
    let closure = required(state.closure)?;
    let source_fence = required(state.source_fence)?;
    require_reference(receipt.commit, commit)?;
    require_reference(receipt.closure, closure)?;
    require_reference(receipt.source_fence, source_fence)?;
    require_previous(
        receipt.header.previous_digest,
        Some(required(state.destination_prepared)?.digest),
    )?;
    if state.destination_activation_command != Some(receipt.activation_command)
        || receipt.resume_command.is_zero()
        || receipt.resume_command == receipt.activation_command
        || !nonzero(receipt.activation_attempt_record_digest)
        || receipt.journal_position.0 == 0
        || !nonzero(receipt.state_digest)
    {
        return Err(OracleRejection::InvalidDigest);
    }
    state.destination_activation = Some(reference);
    state.source_execution = false;
    state.destination_execution = true;
    state.phase = OraclePhase::DestinationActive;
    state.assertions.insert(JointAssertion::ClosurePrecededActivation);
    Ok(())
}

fn validate_receipt_header(
    state: &OracleState,
    header: &ReceiptHeader,
    expected: ReceiptIssuerIdentity,
) -> Result<(), OracleRejection> {
    if header.issuer != expected.issuer
        || header.key_id != expected.key_id
        || header.log_id != expected.log_id
    {
        return Err(OracleRejection::IssuerMismatch);
    }
    if header.issuer_incarnation != expected.issuer_incarnation {
        return Err(OracleRejection::StaleIssuerIncarnation);
    }
    if header.sequence == 0
        || header.previous_digest.is_some_and(|digest| !nonzero(digest))
        || [header.issuer, header.issuer_incarnation, header.key_id, header.log_id]
            .into_iter()
            .any(Identity::is_zero)
    {
        return Err(OracleRejection::InvalidReceiptHeader);
    }
    let sequence_key = (header.issuer, header.issuer_incarnation, header.log_id);
    let expected_sequence = state
        .issuer_sequences
        .get(&sequence_key)
        .copied()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or(OracleRejection::InvalidRevision)?;
    if header.sequence != expected_sequence {
        return Err(OracleRejection::StaleSequence);
    }
    Ok(())
}

fn commit_receipt_header(state: &mut OracleState, header: &ReceiptHeader, reference: ReceiptRef) {
    state
        .issuer_sequences
        .insert((header.issuer, header.issuer_incarnation, header.log_id), header.sequence);
    state.accepted_receipts.insert(reference.digest, reference);
}

fn validate_receipt_key(
    expected: JointHandoffKey,
    actual: JointHandoffKey,
) -> Result<(), OracleRejection> {
    if !well_formed_key(actual) {
        return Err(OracleRejection::InvalidHandoffKey);
    }
    if actual.handoff != expected.handoff {
        return Err(OracleRejection::HandoffMismatch);
    }
    if actual.destination != expected.destination {
        return Err(OracleRejection::CompetingDestination);
    }
    if actual.expected_epoch != expected.expected_epoch || actual.next_epoch != expected.next_epoch
    {
        return Err(OracleRejection::StaleEpoch);
    }
    if actual != expected {
        return Err(OracleRejection::HandoffMismatch);
    }
    Ok(())
}

fn issuer_for_kind(issuers: &JointIssuerSet, kind: ReceiptKind) -> ReceiptIssuerIdentity {
    match kind {
        ReceiptKind::PrepareIntent
        | ReceiptKind::OwnershipPrepared
        | ReceiptKind::OwnershipAbort
        | ReceiptKind::OwnershipCommit => issuers.ownership,
        ReceiptKind::VisaFreeze | ReceiptKind::VisaSourceFence | ReceiptKind::VisaSourceResume => {
            issuers.visa_source
        }
        ReceiptKind::DestinationPrepared | ReceiptKind::VisaDestinationActivation => {
            issuers.visa_destination
        }
        ReceiptKind::NexusFreeze
        | ReceiptKind::NexusThaw
        | ReceiptKind::ClosureProgress
        | ReceiptKind::Closure
        | ReceiptKind::RetainedTombstone => issuers.effect_closure,
    }
}

fn commit_and_freeze(state: &OracleState) -> Result<(ReceiptRef, ReceiptRef), OracleRejection> {
    let OracleDecision::Commit(commit) = state.decision else {
        return Err(OracleRejection::DecisionConflict);
    };
    Ok((commit, required(state.nexus_freeze)?))
}

fn nexus_effect_digest(state: &OracleState) -> Option<Digest> {
    state.nexus_freeze.and_then(|reference| {
        state.accepted_receipts.get(&reference.digest).and_then(|_| {
            joint_effect_cohort_digest(state.key, state.effects.values().cloned()).ok()
        })
    })
}

fn expected_prepared_bindings(
    state: &OracleState,
    trace: &JointRawTrace,
    mapping_digest: Digest,
) -> Result<PreparedBindings, OracleRejection> {
    let input = &trace.prepared_input;
    Ok(PreparedBindings {
        prepare_intent_receipt_digest: required(state.intent)?.digest,
        visa_freeze_receipt_digest: required(state.visa_freeze)?.digest,
        effect_freeze_receipt_digest: required(state.nexus_freeze)?.digest,
        snapshot: input.snapshot.snapshot,
        snapshot_integrity_digest: input.snapshot.integrity,
        source_journal_position: required(state.source_journal_position)?,
        source_state_digest: required(state.source_state_digest)?,
        component_digest: input.snapshot.component_digest,
        profile_digest: input.snapshot.profile_digest,
        destination_prepared_receipt_digest: required(state.destination_prepared)?.digest,
        destination_state_digest: input.destination_state_digest,
        prepared_authorities_digest: input.prepared_authorities_digest,
        prepared_bindings_digest: input.prepared_bindings_digest,
        effect_cohort_manifest_digest: nexus_effect_digest(state)
            .ok_or(OracleRejection::EffectCohortMismatch)?,
        joint_mapping_manifest_digest: mapping_digest,
    })
}

fn nexus_domain_digest(state: &OracleState) -> Option<Digest> {
    state.nexus_domain_bindings_digest
}

fn require_previous(
    actual: Option<Digest>,
    expected: Option<Digest>,
) -> Result<(), OracleRejection> {
    if actual == expected { Ok(()) } else { Err(OracleRejection::CausalChainMismatch) }
}

fn require_reference(actual: ReceiptRef, expected: ReceiptRef) -> Result<(), OracleRejection> {
    if actual == expected { Ok(()) } else { Err(OracleRejection::ReceiptMismatch) }
}

fn required<T: Copy>(value: Option<T>) -> Result<T, OracleRejection> {
    value.ok_or(OracleRejection::MissingPrerequisite)
}

fn validate_safety_invariants(
    state: &OracleState,
    trace: &JointRawTrace,
    event_index: u64,
    findings: &mut Vec<JointValidationFinding>,
) {
    if state.source_execution && state.destination_execution {
        finding(
            findings,
            "dual-joint-execution-authority",
            Some(&trace.case_id),
            Some(event_index),
            "source and destination are simultaneously executable",
        );
    }
    if matches!(state.decision, OracleDecision::Commit(_)) && state.source_execution {
        finding(
            findings,
            "source-executable-after-joint-commit",
            Some(&trace.case_id),
            Some(event_index),
            "commit decision did not fence source execution",
        );
    }
    if state.destination_execution
        && (state.phase != OraclePhase::DestinationActive
            || state.closure.is_none()
            || state.source_fence.is_none()
            || !matches!(state.decision, OracleDecision::Commit(_)))
    {
        finding(
            findings,
            "destination-active-without-joint-closure",
            Some(&trace.case_id),
            Some(event_index),
            "destination execution lacks commit, closure, or source-fence proof",
        );
    }
    if matches!(state.decision, OracleDecision::Abort(_)) && state.destination_execution {
        finding(
            findings,
            "destination-active-after-joint-abort",
            Some(&trace.case_id),
            Some(event_index),
            "abort decision coexists with destination execution",
        );
    }
}

fn validate_state_observation(
    raw: &JointRawEvent,
    trace: &JointRawTrace,
    expected_before: &str,
    expected_after: &str,
    findings: &mut Vec<JointValidationFinding>,
) {
    let (before, after) = match &raw.event {
        JointRawEventKind::ReceiptRejected { state_before_sha256, state_after_sha256, .. }
        | JointRawEventKind::ExternalFault { state_before_sha256, state_after_sha256, .. } => {
            (state_before_sha256, state_after_sha256)
        }
        _ => return,
    };
    if !valid_sha256(before)
        || !valid_sha256(after)
        || before != expected_before
        || after != expected_after
    {
        finding(
            findings,
            "joint-state-observation-mismatch",
            Some(&trace.case_id),
            Some(raw.index),
            format!(
                "claimed_before={before}, recomputed_before={expected_before}, claimed_after={after}, recomputed_after={expected_after}"
            ),
        );
    }
}

fn requires_fail_closed_restart(phase: OraclePhase) -> bool {
    !matches!(
        phase,
        OraclePhase::SourceOwned | OraclePhase::PrepareIntent | OraclePhase::SourceActive
    )
}

fn restart_projection_is_fail_closed(state: &OracleState) -> bool {
    match state.phase {
        OraclePhase::SourceOwned | OraclePhase::PrepareIntent | OraclePhase::SourceActive => true,
        OraclePhase::DestinationActive => {
            !state.source_execution
                && state.destination_execution
                && state.source_fence.is_some()
                && state.closure.is_some()
                && matches!(state.decision, OracleDecision::Commit(_))
        }
        OraclePhase::FrozenUnsealed
        | OraclePhase::PreparedFrozen
        | OraclePhase::AbortDecided
        | OraclePhase::SourceThawPending
        | OraclePhase::CommitDecided
        | OraclePhase::ClosurePending
        | OraclePhase::SourceClosed
        | OraclePhase::DestinationActivationPending
        | OraclePhase::RecoveryRequired => !state.source_execution && !state.destination_execution,
    }
}

fn well_formed_key(key: JointHandoffKey) -> bool {
    !key.continuity_unit.identity.is_zero()
        && !key.handoff.is_zero()
        && !key.source.is_zero()
        && !key.destination.is_zero()
        && key.source != key.destination
        && key.expected_epoch.next() == Some(key.next_epoch)
}

fn well_formed_issuer(issuer: ReceiptIssuerIdentity) -> bool {
    [issuer.issuer, issuer.issuer_incarnation, issuer.key_id, issuer.log_id]
        .into_iter()
        .all(|identity| !identity.is_zero())
}

fn well_formed_scope(scope: EffectScopeVersion) -> bool {
    !scope.registry_instance.is_zero()
        && !scope.scope_id.is_zero()
        && scope.scope_generation > 0
        && scope.authority_epoch > 0
        && scope.freeze_generation > 0
}

fn nonzero(digest: Digest) -> bool {
    digest != Digest::ZERO
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_git_sha(value: &str) -> bool {
    value.len() == 40
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn finding(
    findings: &mut Vec<JointValidationFinding>,
    code: &str,
    case_id: Option<&str>,
    event_index: Option<u64>,
    detail: impl Into<String>,
) {
    findings.push(JointValidationFinding {
        code: code.to_owned(),
        case_id: case_id.map(str::to_owned),
        event_index,
        detail: detail.into(),
    });
}
