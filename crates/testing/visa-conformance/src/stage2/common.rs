use std::path::Path;

use serde::Deserialize;

use super::{
    artifacts::{finding, is_sha256, read_and_hash},
    model::{
        STAGE2_ACCEPTED_REGISTRY_SHA256, STAGE2_AUTHORITY_POLICY_CANONICAL_ENCODING,
        STAGE2_AUTHORITY_POLICY_INPUT_SCHEMA_VERSION, STAGE2_COMMON_INPUT_FILE,
        STAGE2_COMMON_INPUT_SCHEMA_VERSION, STAGE2_COMPONENT_STATE_CODEC_NAME,
        STAGE2_COMPONENT_STATE_CODEC_VERSION, STAGE2_WIT_WORLD_NAME, STAGE2_WIT_WORLD_SHA256,
        Stage2AuthorityPolicyInput, Stage2CommonCaseInput, Stage2CommonInputManifest,
        Stage2Runtime, Stage2TranslationProvenance, Stage2ValidationFinding,
    },
    verify::VerifiedCell,
};
use crate::{
    STAGE1_CASE_DEFINITIONS, STAGE1_EVIDENCE_SCHEMA_VERSION, STAGE1_SEMANTIC_TRACE_SCHEMA_VERSION,
    canonical_stage2_sha256, sha256_hex,
};

pub(crate) fn validate_common_input(
    common: &Stage2CommonInputManifest,
    root: &Path,
) -> Vec<Stage2ValidationFinding> {
    let mut findings = Vec::new();
    if common.schema_version != STAGE2_COMMON_INPUT_SCHEMA_VERSION {
        finding(
            &mut findings,
            "unsupported-stage2-common-input-schema",
            format!("found {}", common.schema_version),
        );
    }
    if common.wit_world.world_name != STAGE2_WIT_WORLD_NAME
        || common.wit_world.artifact.sha256 != STAGE2_WIT_WORLD_SHA256
    {
        finding(
            &mut findings,
            "wrong-stage2-wit-world-lock",
            "WIT world name or bytes digest differs from the accepted world lock",
        );
    }
    if common.component_state_codec.name != STAGE2_COMPONENT_STATE_CODEC_NAME
        || common.component_state_codec.version != STAGE2_COMPONENT_STATE_CODEC_VERSION
        || common.stage1_evidence_schema_version != STAGE1_EVIDENCE_SCHEMA_VERSION
        || common.stage1_semantic_trace_schema_version != STAGE1_SEMANTIC_TRACE_SCHEMA_VERSION
    {
        finding(
            &mut findings,
            "wrong-stage2-consumed-contract-version",
            "common input names a different component codec or Stage 1 schema",
        );
    }
    for (label, reference) in [
        ("component", &common.original_component),
        ("profile", &common.profile),
        ("configuration", &common.configuration),
    ] {
        let _ = read_and_hash(root, reference, label, &mut findings);
    }
    if let Some(policy_bytes) =
        read_and_hash(root, &common.authority_policy, "authority policy", &mut findings)
    {
        validate_authority_policy_input(&policy_bytes, common, &mut findings);
    }
    let _ = read_and_hash(root, &common.wit_world.artifact, "WIT world", &mut findings);
    for (label, digest) in [
        ("component", common.original_component.sha256.as_str()),
        ("profile", common.profile_sha256.as_str()),
        ("configuration", common.config_sha256.as_str()),
        ("authority policy", common.authority_policy_sha256.as_str()),
    ] {
        if !is_sha256(digest) {
            finding(
                &mut findings,
                "invalid-stage2-common-input-digest",
                format!("{label} digest is not SHA-256"),
            );
        }
    }
    if common.cases.len() != STAGE1_CASE_DEFINITIONS.len() {
        finding(
            &mut findings,
            "wrong-stage2-common-case-count",
            format!("expected {}, found {}", STAGE1_CASE_DEFINITIONS.len(), common.cases.len()),
        );
    }
    match accepted_registry_sha256(&common.cases) {
        Ok(digest) if digest == STAGE2_ACCEPTED_REGISTRY_SHA256 => {}
        Ok(digest) => finding(
            &mut findings,
            "stage2-accepted-registry-lock-mismatch",
            format!(
                "common case registry digest is {digest}, expected {STAGE2_ACCEPTED_REGISTRY_SHA256}"
            ),
        ),
        Err(source) => finding(&mut findings, source.code, source.detail),
    }
    for (index, definition) in STAGE1_CASE_DEFINITIONS.iter().enumerate() {
        let Some(case) = common.cases.get(index) else {
            continue;
        };
        if case.case_id != definition.id
            || case.class != definition.class
            || case.allowed_outcomes != definition.allowed_outcomes
            || !is_sha256(&case.case_config_sha256)
            || !is_sha256(&case.case_policy_sha256)
            || case.fault_schedule.schedule_id.is_empty()
        {
            finding(
                &mut findings,
                "invalid-stage2-common-case-input",
                format!("case slot {index} does not match compiled registry {}", definition.id),
            );
        }
    }
    findings
}

pub(super) fn accepted_registry_sha256(
    cases: &[Stage2CommonCaseInput],
) -> Result<String, crate::Stage2NormalizationError> {
    canonical_stage2_sha256(&cases)
}

fn validate_authority_policy_input(
    bytes: &[u8],
    common: &Stage2CommonInputManifest,
    findings: &mut Vec<Stage2ValidationFinding>,
) {
    let policy: Stage2AuthorityPolicyInput = match serde_json::from_slice(bytes) {
        Ok(policy) => policy,
        Err(source) => {
            finding(findings, "invalid-stage2-authority-policy-input-json", source.to_string());
            return;
        }
    };
    if policy.schema_version != STAGE2_AUTHORITY_POLICY_INPUT_SCHEMA_VERSION
        || policy.canonical_encoding != STAGE2_AUTHORITY_POLICY_CANONICAL_ENCODING
        || policy.cases.len() != STAGE1_CASE_DEFINITIONS.len()
    {
        finding(
            findings,
            "invalid-stage2-authority-policy-input",
            "policy input has the wrong schema, encoder, or case count",
        );
        return;
    }
    for (index, definition) in STAGE1_CASE_DEFINITIONS.iter().enumerate() {
        let Some(policy_case) = policy.cases.get(index) else {
            continue;
        };
        let Some(common_case) = common.cases.get(index) else {
            continue;
        };
        let decoded = decode_lower_hex(&policy_case.canonical_policy_bytes_hex);
        if policy_case.case_id != definition.id
            || policy_case.case_id != common_case.case_id
            || policy_case.policy_sha256 != common_case.case_policy_sha256
            || !is_sha256(&policy_case.policy_sha256)
            || !decoded.as_ref().is_some_and(|bytes| sha256_hex(bytes) == policy_case.policy_sha256)
        {
            finding(
                findings,
                "inconsistent-stage2-authority-policy-case",
                format!("policy slot {index} is not the canonical input for {}", definition.id),
            );
        }
    }
}

fn decode_lower_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2)
        || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    debug_assert!(remainder.is_empty());
    pairs
        .iter()
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Some((high << 4) | low)
        })
        .collect()
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

pub(super) fn validate_cross_cell_inputs(
    common: &Stage2CommonInputManifest,
    common_sha256: &str,
    cells: &[VerifiedCell],
) -> Vec<Stage2ValidationFinding> {
    let mut findings = Vec::new();
    let Some(baseline) = cells.first() else {
        return findings;
    };
    let mut jco_provenance: Option<&Stage2TranslationProvenance> = None;
    for cell in cells {
        let bundle = &cell.bundle;
        if bundle.provenance.component_sha256 != common.original_component.sha256
            || bundle.provenance.profile_sha256 != common.profile_sha256
            || bundle.provenance.config_sha256 != common.config_sha256
            || bundle.environment.authority_enforcement.policy_sha256
                != common.authority_policy_sha256
            || bundle.provenance.artifacts.component.sha256 != common.original_component.sha256
            || bundle.provenance.artifacts.profile.sha256 != common.profile.sha256
            || bundle.provenance.artifacts.matrix_manifest.sha256 != common.configuration.sha256
        {
            finding(
                &mut findings,
                "stage2-common-input-bundle-mismatch",
                format!(
                    "{} does not consume the common artifacts/digests",
                    cell.descriptor.id.as_str()
                ),
            );
        }
        if bundle.provenance.component_sha256 != baseline.bundle.provenance.component_sha256
            || bundle.provenance.profile_sha256 != baseline.bundle.provenance.profile_sha256
            || bundle.provenance.config_sha256 != baseline.bundle.provenance.config_sha256
            || bundle.provenance.source_sha256 != baseline.bundle.provenance.source_sha256
            || bundle.provenance.toolchain_sha256 != baseline.bundle.provenance.toolchain_sha256
            || bundle.provenance.executable_sha256 != baseline.bundle.provenance.executable_sha256
            || bundle.environment.authority_enforcement.policy_sha256
                != baseline.bundle.environment.authority_enforcement.policy_sha256
        {
            finding(
                &mut findings,
                "stage2-cross-cell-global-input-mismatch",
                format!("{} has different global inputs", cell.descriptor.id.as_str()),
            );
        }
        if bundle.cases.len() != common.cases.len() {
            continue;
        }
        validate_portable_component_codec(cell, &mut findings);
        validate_common_input_identity_binding(cell, common_sha256, &mut findings);
        for (runtime, provenance) in [
            (cell.descriptor.source_runtime, cell.source_translation_provenance.as_ref()),
            (cell.descriptor.destination_runtime, cell.destination_translation_provenance.as_ref()),
        ] {
            if runtime == Stage2Runtime::JcoNode {
                match (jco_provenance, provenance) {
                    (None, Some(observed)) => jco_provenance = Some(observed),
                    (Some(expected), Some(observed)) if expected == observed => {}
                    _ => finding(
                        &mut findings,
                        "stage2-cross-cell-translation-provenance-mismatch",
                        format!(
                            "{} has inconsistent Jco translation provenance",
                            cell.descriptor.id.as_str()
                        ),
                    ),
                }
            } else if provenance.is_some() {
                finding(
                    &mut findings,
                    "stage2-wasmtime-translation-provenance-present",
                    format!(
                        "{} attributes translation provenance to Wasmtime",
                        cell.descriptor.id.as_str()
                    ),
                );
            }
        }
        for ((case, expected), baseline_case) in
            bundle.cases.iter().zip(&common.cases).zip(&baseline.bundle.cases)
        {
            if case.case_id != expected.case_id
                || case.case_config_sha256 != expected.case_config_sha256
                || case.case_policy_sha256 != expected.case_policy_sha256
                || case.fault_schedule != expected.fault_schedule
                || case.case_id != baseline_case.case_id
                || case.case_config_sha256 != baseline_case.case_config_sha256
                || case.case_policy_sha256 != baseline_case.case_policy_sha256
                || case.fault_schedule != baseline_case.fault_schedule
                || case.outcome != baseline_case.outcome
            {
                finding(
                    &mut findings,
                    "stage2-cross-cell-case-input-or-outcome-mismatch",
                    format!(
                        "{} {} differs from common/baseline",
                        cell.descriptor.id.as_str(),
                        case.case_id
                    ),
                );
            }
        }
    }
    findings
}

fn validate_portable_component_codec(
    cell: &VerifiedCell,
    findings: &mut Vec<Stage2ValidationFinding>,
) {
    let mut observed = 0_usize;
    for case in &cell.normalized.cases {
        if let Some(snapshot) = &case.snapshot {
            observed += 1;
            if !snapshot.body.portable_state.starts_with(b"VISACS01") {
                finding(
                    findings,
                    "wrong-stage2-portable-component-codec",
                    format!(
                        "{} {} snapshot does not use VISACS01",
                        cell.descriptor.id.as_str(),
                        case.case_id
                    ),
                );
            }
        }
        for trace in &case.semantic_traces {
            for state in [&trace.base_state, &trace.final_state] {
                if !state.portable_state.is_empty()
                    && !state.portable_state.starts_with(b"VISACS01")
                {
                    finding(
                        findings,
                        "wrong-stage2-portable-component-codec",
                        format!(
                            "{} {} canonical state does not use VISACS01",
                            cell.descriptor.id.as_str(),
                            case.case_id
                        ),
                    );
                }
            }
        }
    }
    if observed == 0 {
        finding(
            findings,
            "missing-stage2-portable-component-state",
            format!("{} has no snapshot portable state", cell.descriptor.id.as_str()),
        );
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommonInputIdentityBoundAssertion {
    name: String,
    detail: CommonInputIdentityBoundDetail,
    case_config_digest: contract_core::Digest,
    case_policy_digest: contract_core::Digest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommonInputIdentityBoundDetail {
    uri: String,
    sha256: String,
}

fn validate_common_input_identity_binding(
    cell: &VerifiedCell,
    common_sha256: &str,
    findings: &mut Vec<Stage2ValidationFinding>,
) {
    let Some(case) = cell.bundle.cases.iter().find(|case| case.case_id == "evidence-verification")
    else {
        finding(
            findings,
            "missing-stage2-common-input-identity-binding-case",
            format!("{} has no evidence-verification case", cell.descriptor.id.as_str()),
        );
        return;
    };
    let expected_assertions_uri = format!("cases/{}/raw/assertions.jsonl", case.case_id);
    let Some(reference) = case
        .artifacts
        .raw_execution
        .iter()
        .find(|reference| reference.uri == expected_assertions_uri)
    else {
        finding(
            findings,
            "missing-stage2-common-input-identity-binding-assertion",
            format!("{} has no evidence-verification assertions", cell.descriptor.id.as_str()),
        );
        return;
    };
    let Some(bytes) = cell.artifacts.bytes(&reference.uri) else {
        finding(
            findings,
            "missing-stage2-captured-common-input-assertion",
            format!("{} {} was not retained", cell.descriptor.id.as_str(), reference.uri),
        );
        return;
    };
    let mut observed = Vec::new();
    for line in bytes.split(|byte| *byte == b'\n').filter(|line| !line.is_empty()) {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(line) else {
            continue;
        };
        if value.get("name").and_then(serde_json::Value::as_str)
            != Some("stage2-common-input-identity-bound")
        {
            continue;
        }
        match serde_json::from_slice::<CommonInputIdentityBoundAssertion>(line) {
            Ok(assertion) => observed.push(assertion),
            Err(source) => finding(
                findings,
                "invalid-stage2-common-input-identity-binding-assertion",
                format!("{}: {source}", cell.descriptor.id.as_str()),
            ),
        }
    }
    let valid = matches!(observed.as_slice(), [assertion]
        if assertion.name == "stage2-common-input-identity-bound"
            && assertion.detail.uri == STAGE2_COMMON_INPUT_FILE
            && assertion.detail.sha256 == common_sha256
            && digest_hex(assertion.case_config_digest) == case.case_config_sha256
            && digest_hex(assertion.case_policy_digest) == case.case_policy_sha256);
    if !valid {
        finding(
            findings,
            "invalid-stage2-common-input-identity-binding-assertion",
            format!(
                "{} must contain exactly one assertion for common input {common_sha256}",
                cell.descriptor.id.as_str()
            ),
        );
    }
}

fn digest_hex(digest: contract_core::Digest) -> String {
    digest.0.iter().map(|byte| format!("{byte:02x}")).collect()
}
