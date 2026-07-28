use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::ffi::OsStrExt,
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use super::model::*;
use crate::{
    STAGE1_CASE_DEFINITIONS, STAGE4_ACCEPTED_COMPONENT_SHA256, STAGE4_COMMON_INPUT_SCHEMA_VERSION,
    STAGE4_TARGET_HELLO_SCHEMA_VERSION, STAGE4_WORKER_PROTOCOL_VERSION, Stage1EvidenceBundle,
    Stage1IsaIdentity, Stage2NormalizedCellV1, artifact_io::SecureArtifactRoot,
    canonical_stage2_json_bytes, parse_stage1_evidence_bundle_json, sha256_hex,
    stage2_normalize::normalize_stage2_cell,
    validate_stage1_evidence_bundle_with_artifact_snapshot,
};

const SSH_URI: &str = "transport/ssh";
const KNOWN_HOSTS_URI: &str = "transport/known_hosts";
const UNAME_PROGRAM: &str = "/usr/bin/uname";
const VIRT_PROGRAM: &str = "/usr/bin/systemd-detect-virt";
const PROVIDER_LOCATOR_PREFIX: &str = "visa-provider+unix-v1:";
const PROVIDER_DATABASE_ID_DOMAIN: &[u8] = b"visa-provider-database-id-v1\0";
const EVIDENCE_VERIFICATION_CASE_ID: &str = "evidence-verification";
// These nested Stage 1 fault runs are not handoff cases; bind their provider
// domains by the exact runner catalog and locator derivation instead.
const SUPPLEMENTAL_PROVIDER_DOMAINS: &[(&str, &str)] = &[
    ("evidence-verification-fault-before-activation-bundle", "supplemental-source-retry"),
    ("evidence-verification-fault-after-activation-bundle", "supplemental-source-recovery"),
    ("evidence-verification-fault-before-journal-write", "supplemental-source-retry"),
    ("evidence-verification-fault-after-journal-write", "supplemental-source-recovery"),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublicationMode {
    Published,
    Staged,
}

struct VerifiedCell {
    cell_id: Stage4NativeCellId,
    bundle: Stage1EvidenceBundle,
    bundle_bytes: Vec<u8>,
    normalized: Stage2NormalizedCellV1,
}

pub fn parse_stage4_native_evidence_bundle(
    bytes: &[u8],
) -> Result<Stage4NativeEvidenceBundle, Stage4NativeEvidenceLoadError> {
    serde_json::from_slice(bytes).map_err(|source| Stage4NativeEvidenceLoadError {
        code: "invalid-stage4-native-evidence-json".to_owned(),
        detail: source.to_string(),
    })
}

pub fn stage4_native_bundle_id_from_matrix_sha256(digest: &str) -> Option<String> {
    is_sha256(digest).then(|| format!("stage4-native-{digest}"))
}

pub fn stage4_native_registry_sha256() -> String {
    #[derive(Serialize)]
    struct ProviderRegistry {
        receipt_schema_version: &'static str,
        provider_host: Stage4NativeHostId,
        backend_identity: &'static str,
        backend_target: crate::Stage4TargetIdentity,
        service_executable_uri: String,
        hx_transport: &'static str,
        ha_transport: &'static str,
        runtime_execution: Stage4NativeProviderRuntimeExecution,
        case_domain_count: usize,
    }

    #[derive(Serialize)]
    struct Registry<'a> {
        endpoints: &'a [Stage4NativeEndpointId],
        hosts: &'a [Stage4NativeHostId],
        cells: &'a [Stage4NativeCellId],
        provider: ProviderRegistry,
        claim: Stage4NativeClaimDefinition,
        claim_guards: Stage4NativeClaimGuards,
        case_ids: Vec<&'static str>,
    }
    let registry = Registry {
        endpoints: STAGE4_NATIVE_ENDPOINT_CATALOG,
        hosts: STAGE4_NATIVE_HOST_CATALOG,
        cells: STAGE4_NATIVE_CELL_CATALOG,
        provider: ProviderRegistry {
            receipt_schema_version: STAGE4_NATIVE_PROVIDER_RECEIPT_SCHEMA_VERSION,
            provider_host: Stage4NativeHostId::HxHost,
            backend_identity: STAGE4_NATIVE_PROVIDER_BACKEND_IDENTITY,
            backend_target: required_stage4_native_provider_backend_target(),
            service_executable_uri: Stage4NativeEndpointId::Hx.worker_uri(),
            hx_transport: "unix-stream",
            ha_transport: "ssh-reverse-stream-local",
            runtime_execution: Stage4NativeProviderRuntimeExecution {
                hx_native: true,
                ha_native: true,
            },
            case_domain_count: STAGE4_NATIVE_EXECUTION_COUNT,
        },
        claim: required_stage4_native_claim(),
        claim_guards: Stage4NativeClaimGuards::required(),
        case_ids: STAGE1_CASE_DEFINITIONS.iter().map(|case| case.id).collect(),
    };
    sha256_hex(&serde_json::to_vec(&registry).expect("static native registry serializes"))
}

pub fn validate_stage4_native_evidence_bundle(
    bundle: &Stage4NativeEvidenceBundle,
    artifact_root: &Path,
) -> Stage4NativeValidationReport {
    validate_impl(bundle, artifact_root, PublicationMode::Published)
}

pub fn gate_stage4_native_evidence_bundle_json_with_artifacts(
    bytes: &[u8],
    artifact_root: &Path,
) -> Stage4NativeEvidenceGateResult {
    let bundle = match parse_stage4_native_evidence_bundle(bytes) {
        Ok(bundle) => bundle,
        Err(error) => {
            return Stage4NativeEvidenceGateResult {
                ok: false,
                load_error: Some(error),
                validation: None,
            };
        }
    };
    let validation = validate_stage4_native_evidence_bundle(&bundle, artifact_root);
    Stage4NativeEvidenceGateResult {
        ok: validation.ok,
        load_error: None,
        validation: Some(validation),
    }
}

pub(crate) fn validate_stage4_native_evidence_bundle_for_publication(
    bundle: &Stage4NativeEvidenceBundle,
    artifact_root: &Path,
) -> Stage4NativeValidationReport {
    validate_impl(bundle, artifact_root, PublicationMode::Staged)
}

fn validate_impl(
    bundle: &Stage4NativeEvidenceBundle,
    artifact_root: &Path,
    mode: PublicationMode,
) -> Stage4NativeValidationReport {
    let mut findings = Vec::new();
    validate_evidence_shape(bundle, &mut findings);
    let root = match SecureArtifactRoot::open(artifact_root) {
        Ok(root) => root,
        Err(source) => {
            finding(&mut findings, "invalid-stage4-native-root", source.to_string());
            return report(findings);
        }
    };
    validate_marker(&root, mode, &mut findings);
    validate_main_bundle(&root, bundle, &mut findings);
    let matrix_bytes =
        read_reference(&root, &bundle.matrix_manifest, "native matrix manifest", &mut findings);
    let matrix = matrix_bytes.as_deref().and_then(|bytes| {
        match serde_json::from_slice::<Stage4NativeMatrixManifest>(bytes) {
            Ok(matrix) => Some(matrix),
            Err(source) => {
                finding(&mut findings, "invalid-stage4-native-matrix-json", source.to_string());
                None
            }
        }
    });
    let Some(matrix) = matrix else {
        validate_exact_artifact_set(artifact_root, bundle, None, &[], mode, &mut findings);
        return report(findings);
    };
    if serde_json::to_vec_pretty(&matrix).ok().as_deref() != matrix_bytes.as_deref() {
        finding(
            &mut findings,
            "noncanonical-stage4-native-matrix",
            "matrix.json differs from the canonical publisher encoding",
        );
    }
    validate_matrix_shape(&matrix, bundle, &mut findings);

    let common_bytes =
        read_reference(&root, &matrix.common_input, "native common input", &mut findings);
    let common = common_bytes.as_deref().and_then(|bytes| {
        match serde_json::from_slice::<crate::Stage4CommonInputIdentity>(bytes) {
            Ok(common) => Some(common),
            Err(source) => {
                finding(&mut findings, "invalid-stage4-native-common-input", source.to_string());
                None
            }
        }
    });
    if let (Some(common), Some(bytes)) = (common.as_ref(), common_bytes.as_deref()) {
        if serde_json::to_vec_pretty(common).ok().as_deref() != Some(bytes) {
            finding(
                &mut findings,
                "noncanonical-stage4-native-common-input",
                "common input differs from the canonical publisher encoding",
            );
        }
        validate_common_shape(common, &mut findings);
    }

    let hosts = validate_hosts(&root, &matrix, &mut findings);
    let endpoints = validate_endpoints(&root, &matrix, &hosts, common.as_ref(), &mut findings);
    validate_provider(&root, &matrix.provider, &endpoints, &mut findings);
    let mut nonces = BTreeSet::new();
    let mut verified = Vec::new();
    let mut loaded = Vec::new();
    for cell in &matrix.cells {
        let expected = cell.cell_id.endpoints();
        if (cell.source_endpoint, cell.destination_endpoint) != expected {
            finding(&mut findings, "invalid-stage4-native-cell-endpoints", cell.cell_id.as_str());
        }
        validate_cell_paths(cell, &mut findings);
        if let Some(source) = endpoints.get(&expected.0) {
            validate_hello(
                &root,
                cell.cell_id,
                crate::Stage4Role::Source,
                &cell.source_hello,
                source,
                &mut nonces,
                &mut findings,
            );
        }
        if let Some(destination) = endpoints.get(&expected.1) {
            validate_hello(
                &root,
                cell.cell_id,
                crate::Stage4Role::Destination,
                &cell.destination_hello,
                destination,
                &mut nonces,
                &mut findings,
            );
        }
        let Some(bundle_bytes) =
            read_reference(&root, &cell.stage1_bundle, "inner Stage 1 bundle", &mut findings)
        else {
            continue;
        };
        let inner = match parse_stage1_evidence_bundle_json(&bundle_bytes) {
            Ok(inner) => inner,
            Err(source) => {
                finding(
                    &mut findings,
                    "invalid-stage4-native-inner-json",
                    format!("{}: {}", cell.cell_id.as_str(), source.detail),
                );
                continue;
            }
        };
        loaded.push((cell.cell_id, inner.clone()));
        let cell_root = artifact_root.join(cell.cell_id.cell_root_uri());
        let (inner_report, snapshot) =
            validate_stage1_evidence_bundle_with_artifact_snapshot(&inner, &cell_root);
        if let Some(snapshot) = snapshot.as_ref() {
            validate_provider_transcript_bindings(
                cell.cell_id,
                &inner,
                snapshot,
                &matrix.execution_artifact_root,
                &matrix.provider.receipt,
                &mut findings,
            );
        }
        if !inner_report.ok {
            for inner_finding in inner_report.findings {
                finding(
                    &mut findings,
                    "stage4-native-inner-verification-failed",
                    format!(
                        "{}: {}: {}",
                        cell.cell_id.as_str(),
                        inner_finding.code,
                        inner_finding.detail
                    ),
                );
            }
            continue;
        }
        let Some(snapshot) = snapshot else {
            finding(
                &mut findings,
                "missing-stage4-native-inner-artifact-snapshot",
                cell.cell_id.as_str(),
            );
            continue;
        };
        if let Some(common) = common.as_ref() {
            let actual = crate::stage4::common_input_from_stage1(&inner);
            if &actual != common {
                finding(&mut findings, "mixed-stage4-native-common-input", cell.cell_id.as_str());
            }
        }
        if let (Some(source), Some(destination)) =
            (endpoints.get(&expected.0), endpoints.get(&expected.1))
        {
            validate_inner_target_environment(
                cell.cell_id,
                &inner,
                source,
                destination,
                &mut findings,
            );
            if inner.provenance.executable_sha256 != source.worker_executable.sha256 {
                finding(
                    &mut findings,
                    "stage4-native-inner-source-executable-mismatch",
                    cell.cell_id.as_str(),
                );
            }
        }
        let normalized = match normalize_stage2_cell(&inner, &snapshot) {
            Ok(normalized) => normalized,
            Err(source) => {
                finding(
                    &mut findings,
                    "stage4-native-normalization-failed",
                    format!("{}: {}", source.code, source.detail),
                );
                continue;
            }
        };
        validate_normalized_cache(
            &root,
            cell.cell_id,
            &cell.normalized_observable_trace,
            &normalized,
            &mut findings,
        );
        verified.push(VerifiedCell {
            cell_id: cell.cell_id,
            bundle: inner,
            bundle_bytes,
            normalized,
        });
    }
    let comparisons = compare_verified(&verified, &mut findings);
    validate_summaries(bundle, &verified, &comparisons, &mut findings);
    validate_exact_artifact_set(artifact_root, bundle, Some(&matrix), &loaded, mode, &mut findings);
    report(findings)
}

fn validate_evidence_shape(
    bundle: &Stage4NativeEvidenceBundle,
    findings: &mut Vec<Stage4NativeValidationFinding>,
) {
    if bundle.schema_version != STAGE4_NATIVE_EVIDENCE_SCHEMA_VERSION {
        finding(findings, "unsupported-stage4-native-schema", &bundle.schema_version);
    }
    if stage4_native_bundle_id_from_matrix_sha256(&bundle.matrix_manifest.sha256).as_deref()
        != Some(&bundle.bundle_id)
    {
        finding(
            findings,
            "invalid-stage4-native-bundle-id",
            "bundle id must derive from the retained matrix digest",
        );
    }
    if bundle.matrix_manifest.uri != STAGE4_NATIVE_MATRIX_FILE {
        finding(findings, "noncanonical-stage4-native-matrix-path", &bundle.matrix_manifest.uri);
    }
    if bundle.completed_execution_count != STAGE4_NATIVE_EXECUTION_COUNT {
        finding(
            findings,
            "incomplete-stage4-native-execution-count",
            bundle.completed_execution_count.to_string(),
        );
    }
    if bundle.claim != required_stage4_native_claim()
        || bundle.claim_guards != Stage4NativeClaimGuards::required()
    {
        finding(
            findings,
            "invalid-stage4-native-claim-boundary",
            "claim and explicit nonclaims must match the compiled profile",
        );
    }
}

fn validate_matrix_shape(
    matrix: &Stage4NativeMatrixManifest,
    bundle: &Stage4NativeEvidenceBundle,
    findings: &mut Vec<Stage4NativeValidationFinding>,
) {
    if matrix.schema_version != STAGE4_NATIVE_MATRIX_SCHEMA_VERSION {
        finding(findings, "unsupported-stage4-native-matrix-schema", &matrix.schema_version);
    }
    if matrix.common_input.uri != STAGE4_NATIVE_COMMON_INPUT_FILE {
        finding(findings, "noncanonical-stage4-native-common-input-path", &matrix.common_input.uri);
    }
    let historical_root = Path::new(&matrix.execution_artifact_root);
    if !historical_root.is_absolute()
        || !historical_root
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
    {
        finding(findings, "invalid-stage4-native-execution-root", &matrix.execution_artifact_root);
    }
    if matrix.registry_sha256 != STAGE4_NATIVE_ACCEPTED_REGISTRY_SHA256
        || stage4_native_registry_sha256() != STAGE4_NATIVE_ACCEPTED_REGISTRY_SHA256
    {
        finding(findings, "invalid-stage4-native-registry-digest", &matrix.registry_sha256);
    }
    if matrix.execution_count != STAGE4_NATIVE_EXECUTION_COUNT
        || matrix.execution_count != bundle.completed_execution_count
    {
        finding(
            findings,
            "inconsistent-stage4-native-execution-count",
            matrix.execution_count.to_string(),
        );
    }
    if matrix.claim != bundle.claim || matrix.claim_guards != bundle.claim_guards {
        finding(
            findings,
            "inconsistent-stage4-native-claim-boundary",
            "matrix and evidence disagree",
        );
    }
    if matrix.hosts.iter().map(|host| host.host_id).collect::<Vec<_>>()
        != STAGE4_NATIVE_HOST_CATALOG
    {
        finding(
            findings,
            "invalid-stage4-native-host-catalog",
            "expected exact ordered Hx-host, Ha-host",
        );
    }
    if matrix.endpoints.iter().map(|endpoint| endpoint.endpoint_id).collect::<Vec<_>>()
        != STAGE4_NATIVE_ENDPOINT_CATALOG
    {
        finding(
            findings,
            "invalid-stage4-native-endpoint-catalog",
            "expected exact ordered Hx, Ha",
        );
    }
    if matrix.cells.iter().map(|cell| cell.cell_id).collect::<Vec<_>>()
        != STAGE4_NATIVE_CELL_CATALOG
    {
        finding(
            findings,
            "invalid-stage4-native-cell-catalog",
            "expected exact ordered Hx/Hx, Hx/Ha, Ha/Hx, Ha/Ha",
        );
    }
}

fn validate_common_shape(
    common: &crate::Stage4CommonInputIdentity,
    findings: &mut Vec<Stage4NativeValidationFinding>,
) {
    if common.schema_version != STAGE4_COMMON_INPUT_SCHEMA_VERSION
        || common.component_sha256 != STAGE4_ACCEPTED_COMPONENT_SHA256
        || common.cases.len() != STAGE4_NATIVE_CASE_COUNT
        || common
            .cases
            .iter()
            .zip(STAGE1_CASE_DEFINITIONS)
            .any(|(actual, expected)| actual.case_id != expected.id)
    {
        finding(
            findings,
            "invalid-stage4-native-common-input-shape",
            "common input must retain the accepted release component and ordered 31 cases",
        );
    }
}

fn validate_hosts<'a>(
    root: &SecureArtifactRoot,
    matrix: &'a Stage4NativeMatrixManifest,
    findings: &mut Vec<Stage4NativeValidationFinding>,
) -> BTreeMap<Stage4NativeHostId, &'a Stage4NativeHostEvidence> {
    let mut result = BTreeMap::new();
    let mut nonces = BTreeSet::new();
    for host in &matrix.hosts {
        if result.insert(host.host_id, host).is_some() {
            finding(findings, "duplicate-stage4-native-host", host.host_id.as_str());
        }
        validate_host(root, host, &mut nonces, findings);
    }
    result
}

fn validate_host(
    root: &SecureArtifactRoot,
    host: &Stage4NativeHostEvidence,
    nonces: &mut BTreeSet<String>,
    findings: &mut Vec<Stage4NativeValidationFinding>,
) {
    let receipt = &host.receipt;
    validate_canonical_reference(
        &host.receipt_artifact,
        &host.host_id.receipt_uri(),
        "host receipt",
        findings,
    );
    validate_typed_artifact(root, &host.receipt_artifact, receipt, "host receipt", findings);
    if receipt.schema_version != STAGE4_NATIVE_HOST_RECEIPT_SCHEMA_VERSION
        || receipt.host_id != host.host_id
    {
        finding(findings, "invalid-stage4-native-host-receipt", host.host_id.as_str());
    }
    if !is_nonce(&receipt.expected_nonce) || !nonces.insert(receipt.expected_nonce.clone()) {
        finding(findings, "invalid-stage4-native-host-nonce", host.host_id.as_str());
    }
    validate_canonical_reference(
        &receipt.raw_observation,
        &host.host_id.observation_uri(),
        "raw host observation",
        findings,
    );
    let raw = read_reference(root, &receipt.raw_observation, "raw host observation", findings)
        .and_then(|bytes| {
            let Some(line) = bytes.strip_suffix(b"\n") else {
                finding(
                    findings,
                    "noncanonical-stage4-native-raw-host-observation",
                    "host observation must end in exactly one newline",
                );
                return None;
            };
            let parsed = serde_json::from_slice::<Stage4NativeRawHostObservation>(line)
                .map_err(|source| {
                    finding(
                        findings,
                        "invalid-stage4-native-raw-host-observation",
                        source.to_string(),
                    );
                })
                .ok()?;
            let canonical = serde_json::to_vec(&parsed).map(|mut encoded| {
                encoded.push(b'\n');
                encoded
            });
            if canonical.as_ref().ok() != Some(&bytes) {
                finding(
                    findings,
                    "noncanonical-stage4-native-raw-host-observation",
                    "host observation must be one canonical JSON line",
                );
            }
            Some(parsed)
        });
    validate_command(root, host.host_id, &receipt.uname, true, findings);
    validate_command(root, host.host_id, &receipt.virtualization, false, findings);
    let expected_machine = match host.host_id {
        Stage4NativeHostId::HxHost => "x86_64",
        Stage4NativeHostId::HaHost => "aarch64",
    };
    if receipt.identity.sysname != "Linux"
        || receipt.identity.machine != expected_machine
        || receipt.identity.kernel_release.is_empty()
    {
        finding(findings, "invalid-stage4-native-host-identity", host.host_id.as_str());
    }
    let expected_uname = format!(
        "{} {} {}\n",
        receipt.identity.sysname, receipt.identity.kernel_release, receipt.identity.machine
    );
    if read_reference(root, &receipt.uname.raw_stdout, "uname stdout", findings).as_deref()
        != Some(expected_uname.as_bytes())
    {
        finding(findings, "stage4-native-uname-identity-mismatch", host.host_id.as_str());
    }
    match (host.host_id, receipt.hardware_model.as_ref()) {
        (Stage4NativeHostId::HxHost, None) => {}
        (Stage4NativeHostId::HaHost, Some(model)) => {
            validate_canonical_reference(
                &model.raw,
                &host.host_id.hardware_model_uri(),
                "hardware model",
                findings,
            );
            let bytes = read_reference(root, &model.raw, "hardware model", findings);
            let parsed = bytes.as_deref().and_then(|bytes| {
                std::str::from_utf8(bytes)
                    .ok()
                    .map(|value| value.trim_matches(['\0', '\n', '\r']).to_owned())
            });
            if model.source_path != "/proc/device-tree/model"
                || model.model.trim().is_empty()
                || !model.model.starts_with("Raspberry Pi Zero 2 W")
                || parsed.as_deref() != Some(&model.model)
            {
                finding(findings, "invalid-stage4-native-hardware-model", host.host_id.as_str());
            }
        }
        _ => finding(
            findings,
            "invalid-stage4-native-hardware-boundary",
            "Hx must not assert a board model and Ha must retain the Raspberry Pi model",
        ),
    }
    if let Some(raw) = raw {
        let model_path = receipt.hardware_model.as_ref().map(|model| model.source_path.clone());
        let model = receipt.hardware_model.as_ref().map(|model| model.model.clone());
        if raw.schema_version != STAGE4_NATIVE_HOST_OBSERVATION_SCHEMA_VERSION
            || raw.nonce != receipt.expected_nonce
            || raw.host_id != host.host_id
            || raw.identity != receipt.identity
            || raw.uname_program_sha256 != receipt.uname.program_sha256
            || raw.uname_program_size != receipt.uname.program_size
            || raw.uname_argv != receipt.uname.argv
            || raw.uname_exit_status != receipt.uname.exit_status
            || raw.uname_stdout.as_bytes()
                != read_reference(root, &receipt.uname.raw_stdout, "uname stdout", findings)
                    .as_deref()
                    .unwrap_or_default()
            || raw.uname_stderr.as_bytes()
                != read_reference(root, &receipt.uname.raw_stderr, "uname stderr", findings)
                    .as_deref()
                    .unwrap_or_default()
            || raw.virtualization_program_sha256 != receipt.virtualization.program_sha256
            || raw.virtualization_program_size != receipt.virtualization.program_size
            || raw.virtualization_argv != receipt.virtualization.argv
            || raw.virtualization_exit_status != receipt.virtualization.exit_status
            || raw.virtualization_stdout.as_bytes()
                != read_reference(
                    root,
                    &receipt.virtualization.raw_stdout,
                    "virtualization stdout",
                    findings,
                )
                .as_deref()
                .unwrap_or_default()
            || raw.virtualization_stderr.as_bytes()
                != read_reference(
                    root,
                    &receipt.virtualization.raw_stderr,
                    "virtualization stderr",
                    findings,
                )
                .as_deref()
                .unwrap_or_default()
            || raw.hardware_model_source_path != model_path
            || raw.hardware_model != model
        {
            finding(findings, "stage4-native-host-observation-mismatch", host.host_id.as_str());
        }
    }
}

fn validate_command(
    root: &SecureArtifactRoot,
    host: Stage4NativeHostId,
    command: &Stage4NativeCommandReceipt,
    uname: bool,
    findings: &mut Vec<Stage4NativeValidationFinding>,
) {
    let (program, argv, stdout_uri, stderr_uri) = if uname {
        (
            UNAME_PROGRAM,
            vec![UNAME_PROGRAM, "-s", "-r", "-m"],
            host.uname_stdout_uri(),
            host.uname_stderr_uri(),
        )
    } else {
        (
            VIRT_PROGRAM,
            vec![VIRT_PROGRAM],
            host.virtualization_stdout_uri(),
            host.virtualization_stderr_uri(),
        )
    };
    if command.program != program
        || command.argv != argv
        || !is_sha256(&command.program_sha256)
        || command.program_size == 0
        || (uname && command.exit_status != 0)
        || (!uname && command.exit_status != 1)
    {
        finding(
            findings,
            "invalid-stage4-native-host-command",
            format!("{} {program}", host.as_str()),
        );
    }
    validate_canonical_reference(&command.raw_stdout, &stdout_uri, "host stdout", findings);
    validate_canonical_reference(&command.raw_stderr, &stderr_uri, "host stderr", findings);
    let stdout = read_reference(root, &command.raw_stdout, "host stdout", findings);
    let stderr = read_reference(root, &command.raw_stderr, "host stderr", findings);
    if stderr.as_deref() != Some(&[]) || (!uname && stdout.as_deref() != Some(b"none\n")) {
        finding(
            findings,
            "stage4-native-host-command-output-mismatch",
            format!("{} {program}", host.as_str()),
        );
    }
}

fn validate_endpoints<'a>(
    root: &SecureArtifactRoot,
    matrix: &'a Stage4NativeMatrixManifest,
    hosts: &BTreeMap<Stage4NativeHostId, &Stage4NativeHostEvidence>,
    common: Option<&crate::Stage4CommonInputIdentity>,
    findings: &mut Vec<Stage4NativeValidationFinding>,
) -> BTreeMap<Stage4NativeEndpointId, &'a Stage4NativeEndpointEvidence> {
    let mut result = BTreeMap::new();
    for endpoint in &matrix.endpoints {
        if result.insert(endpoint.endpoint_id, endpoint).is_some() {
            finding(findings, "duplicate-stage4-native-endpoint", endpoint.endpoint_id.as_str());
        }
        validate_endpoint(root, matrix, endpoint, hosts, findings);
    }
    if let (Some(hx), Some(ha)) =
        (result.get(&Stage4NativeEndpointId::Hx), result.get(&Stage4NativeEndpointId::Ha))
    {
        let lineage_mismatch = hx.build_receipt.build_source_sha256
            != ha.build_receipt.build_source_sha256
            || hx.build_receipt.build_toolchain_sha256 != ha.build_receipt.build_toolchain_sha256
            || common.is_some_and(|common| {
                common.source_sha256 != hx.build_receipt.build_source_sha256
                    || common.toolchain_sha256 != hx.build_receipt.build_toolchain_sha256
            });
        if lineage_mismatch {
            finding(
                findings,
                "mixed-stage4-native-build-lineage",
                "Hx, Ha, and common input must share one source/toolchain identity",
            );
        }
    }
    result
}

fn validate_endpoint(
    root: &SecureArtifactRoot,
    matrix: &Stage4NativeMatrixManifest,
    endpoint: &Stage4NativeEndpointEvidence,
    hosts: &BTreeMap<Stage4NativeHostId, &Stage4NativeHostEvidence>,
    findings: &mut Vec<Stage4NativeValidationFinding>,
) {
    let id = endpoint.endpoint_id;
    if endpoint.host_id != id.host_id() {
        finding(findings, "invalid-stage4-native-endpoint-host", id.as_str());
    }
    if endpoint.target.target_triple != id.target_triple()
        || endpoint.target.architecture != id.architecture()
        || endpoint.target.os != "linux"
        || endpoint.target.abi != "linux-gnu"
        || endpoint.target.endianness != "little"
        || endpoint.target.pointer_width_bits != 64
    {
        finding(findings, "invalid-stage4-native-target", id.as_str());
    }
    if hosts
        .get(&endpoint.host_id)
        .is_none_or(|host| host.receipt.identity.machine != endpoint.target.architecture)
    {
        finding(findings, "stage4-native-target-host-mismatch", id.as_str());
    }
    validate_canonical_reference(&endpoint.worker_executable, &id.worker_uri(), "worker", findings);
    if let Some(bytes) = read_reference(root, &endpoint.worker_executable, "worker", findings) {
        validate_worker_elf(id, &bytes, findings);
    }
    validate_canonical_reference(
        &endpoint.build_receipt_artifact,
        &id.build_receipt_uri(),
        "build receipt",
        findings,
    );
    validate_typed_artifact(
        root,
        &endpoint.build_receipt_artifact,
        &endpoint.build_receipt,
        "build receipt",
        findings,
    );
    let build = &endpoint.build_receipt;
    if build.schema_version != STAGE4_NATIVE_BUILD_RECEIPT_SCHEMA_VERSION
        || build.endpoint_id != id
        || build.target != endpoint.target
        || build.executable_sha256 != endpoint.worker_executable.sha256
        || build.executable_size != endpoint.worker_executable.size
        || !is_sha256(&build.build_source_sha256)
        || !is_sha256(&build.build_toolchain_sha256)
    {
        finding(findings, "invalid-stage4-native-build-receipt", id.as_str());
    }
    validate_canonical_reference(
        &endpoint.launcher_receipt_artifact,
        &id.launcher_receipt_uri(),
        "launcher receipt",
        findings,
    );
    validate_typed_artifact(
        root,
        &endpoint.launcher_receipt_artifact,
        &endpoint.launcher_receipt,
        "launcher receipt",
        findings,
    );
    let launcher = &endpoint.launcher_receipt;
    if launcher.schema_version != STAGE4_NATIVE_LAUNCHER_RECEIPT_SCHEMA_VERSION
        || launcher.endpoint_id != id
        || launcher.host_id != endpoint.host_id
        || launcher.worker_sha256 != endpoint.worker_executable.sha256
        || launcher.worker_size != endpoint.worker_executable.size
        || !launcher.native_execution
        || launcher.emulated_execution
    {
        finding(findings, "invalid-stage4-native-launcher-receipt", id.as_str());
    }
    match (id, &launcher.transport) {
        (Stage4NativeEndpointId::Hx, Stage4NativeLauncherTransport::LocalDirect { argv }) => {
            let expected = Path::new(&matrix.execution_artifact_root).join(id.worker_uri());
            if argv.len() != 1 || Path::new(&argv[0]) != expected {
                finding(findings, "invalid-stage4-native-local-launcher", id.as_str());
            }
        }
        (
            Stage4NativeEndpointId::Ha,
            Stage4NativeLauncherTransport::Ssh {
                ssh_program,
                known_hosts,
                remote_host,
                remote_worker_path,
                argv,
            },
        ) => {
            validate_canonical_reference(ssh_program, SSH_URI, "owned ssh", findings);
            validate_canonical_reference(known_hosts, KNOWN_HOSTS_URI, "known_hosts", findings);
            let ssh_bytes = read_reference(root, ssh_program, "owned ssh", findings);
            let known_hosts_bytes = read_reference(root, known_hosts, "known_hosts", findings);
            let owned_ssh = Path::new(&matrix.execution_artifact_root).join(SSH_URI);
            let owned_known_hosts =
                Path::new(&matrix.execution_artifact_root).join(KNOWN_HOSTS_URI);
            let strict = "StrictHostKeyChecking=yes";
            let identities_only = "IdentitiesOnly=yes";
            let known = format!("UserKnownHostsFile={}", owned_known_hosts.display());
            if ssh_bytes.as_deref().is_none_or(|bytes| bytes.is_empty())
                || known_hosts_bytes.as_deref().is_none_or(|bytes| bytes.is_empty())
                || remote_host.trim().is_empty()
                || !Path::new(remote_worker_path).is_absolute()
                || argv.first().is_none_or(|arg| Path::new(arg) != owned_ssh)
                || !argv.iter().any(|arg| arg == strict)
                || !argv.iter().any(|arg| arg == identities_only)
                || !argv.iter().any(|arg| {
                    arg.strip_prefix("IdentityFile=").is_some_and(|path| !path.is_empty())
                })
                || !argv.iter().any(|arg| arg == &known)
                || !argv.iter().any(|arg| arg == remote_host)
                || argv.last() != Some(remote_worker_path)
                || argv.iter().any(|arg| arg.to_ascii_lowercase().contains("qemu"))
            {
                finding(findings, "invalid-stage4-native-ssh-launcher", id.as_str());
            }
        }
        _ => finding(findings, "invalid-stage4-native-launcher-transport", id.as_str()),
    }
}

fn validate_provider(
    root: &SecureArtifactRoot,
    provider: &Stage4NativeProviderEvidence,
    endpoints: &BTreeMap<Stage4NativeEndpointId, &Stage4NativeEndpointEvidence>,
    findings: &mut Vec<Stage4NativeValidationFinding>,
) {
    validate_canonical_reference(
        &provider.receipt_artifact,
        STAGE4_NATIVE_PROVIDER_RECEIPT_FILE,
        "provider receipt",
        findings,
    );
    validate_typed_artifact(
        root,
        &provider.receipt_artifact,
        &provider.receipt,
        "provider receipt",
        findings,
    );

    let receipt = &provider.receipt;
    if receipt.schema_version != STAGE4_NATIVE_PROVIDER_RECEIPT_SCHEMA_VERSION
        || receipt.provider_host != Stage4NativeHostId::HxHost
        || receipt.backend_identity != STAGE4_NATIVE_PROVIDER_BACKEND_IDENTITY
        || receipt.backend_target != required_stage4_native_provider_backend_target()
    {
        finding(
            findings,
            "invalid-stage4-native-provider-identity",
            "provider must be the Hx-host x86_64 Linux substrate_host::SqliteProvider service",
        );
    }
    let Some(hx) = endpoints.get(&Stage4NativeEndpointId::Hx) else {
        finding(
            findings,
            "missing-stage4-native-provider-service-endpoint",
            Stage4NativeEndpointId::Hx.as_str(),
        );
        return;
    };
    if receipt.backend_target != hx.target
        || receipt.service_executable != hx.worker_executable
        || receipt.service_executable_sha256 != hx.worker_executable.sha256
        || receipt.service_executable_size != hx.worker_executable.size
    {
        finding(
            findings,
            "stage4-native-provider-service-identity-mismatch",
            "provider service must be the retained native Hx worker artifact",
        );
    }
    if !receipt.runtime_execution.hx_native || !receipt.runtime_execution.ha_native {
        finding(
            findings,
            "invalid-stage4-native-provider-runtime-execution",
            "both Hx and Ha runtime endpoints must execute natively",
        );
    }
    match &receipt.transport {
        Stage4NativeProviderTransport::UnixStream {
            local_socket_path,
            ha_transport:
                Stage4NativeProviderHaTransport::SshReverseStreamLocal { remote_socket_path },
        } => {
            if !strict_absolute_normalized_path(local_socket_path)
                || !strict_absolute_normalized_path(remote_socket_path)
                || local_socket_path == remote_socket_path
            {
                finding(
                    findings,
                    "invalid-stage4-native-provider-socket-topology",
                    "provider sockets must be distinct strict absolute normalized paths",
                );
            }
        }
    }

    let expected_domains = STAGE4_NATIVE_CELL_CATALOG.iter().copied().flat_map(|cell_id| {
        STAGE1_CASE_DEFINITIONS
            .iter()
            .map(move |definition| (cell_id, definition.id, cell_id.endpoints()))
    });
    if receipt.case_domains.len() != STAGE4_NATIVE_EXECUTION_COUNT {
        finding(
            findings,
            "invalid-stage4-native-provider-case-domain-catalog",
            format!(
                "expected {} ordered cell x case domains, observed {}",
                STAGE4_NATIVE_EXECUTION_COUNT,
                receipt.case_domains.len()
            ),
        );
    }
    let mut database_ids = BTreeSet::new();
    for (domain, (cell_id, case_id, endpoints)) in receipt.case_domains.iter().zip(expected_domains)
    {
        if domain.cell_id != cell_id
            || domain.case_id != case_id
            || (domain.source_endpoint, domain.destination_endpoint) != endpoints
        {
            finding(
                findings,
                "invalid-stage4-native-provider-case-domain-catalog",
                format!("{} {}", domain.cell_id.as_str(), domain.case_id),
            );
        }
        if !is_sha256(&domain.logical_database_id) {
            finding(
                findings,
                "invalid-stage4-native-provider-database-id",
                format!("{} {}", domain.cell_id.as_str(), domain.case_id),
            );
        } else if !database_ids.insert(domain.logical_database_id.clone()) {
            finding(
                findings,
                "duplicate-stage4-native-provider-database-id",
                &domain.logical_database_id,
            );
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Stage4NativeRawTranscriptStream {
    ParentRequest,
    WorkerResponse,
    WorkerStderr,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stage4NativeRawTranscriptLine {
    worker: String,
    #[serde(rename = "pid")]
    _pid: u32,
    #[serde(rename = "sequence")]
    _sequence: u64,
    stream: Stage4NativeRawTranscriptStream,
    line: String,
}

struct ParsedStage4NativeProviderLocator {
    socket_path: String,
    database_id: String,
}

fn validate_provider_transcript_bindings(
    cell_id: Stage4NativeCellId,
    bundle: &Stage1EvidenceBundle,
    artifacts: &crate::VerifiedStage1Artifacts,
    execution_artifact_root: &str,
    receipt: &Stage4NativeProviderReceipt,
    findings: &mut Vec<Stage4NativeValidationFinding>,
) {
    let (local_socket_path, remote_socket_path) = match &receipt.transport {
        Stage4NativeProviderTransport::UnixStream {
            local_socket_path,
            ha_transport:
                Stage4NativeProviderHaTransport::SshReverseStreamLocal { remote_socket_path },
        } => (local_socket_path.as_str(), remote_socket_path.as_str()),
    };
    let (source_endpoint, destination_endpoint) = cell_id.endpoints();
    for case in &bundle.cases {
        let Some(domain) = receipt
            .case_domains
            .iter()
            .find(|domain| domain.cell_id == cell_id && domain.case_id == case.case_id)
        else {
            finding(
                findings,
                "missing-stage4-native-provider-case-domain",
                format!("{} {}", cell_id.as_str(), case.case_id),
            );
            continue;
        };
        let recomputed_primary_database_id =
            stage4_native_provider_database_id(execution_artifact_root, cell_id, &case.case_id);
        if domain.logical_database_id != recomputed_primary_database_id {
            finding(
                findings,
                "stage4-native-provider-receipt-database-binding-mismatch",
                format!("{} {}", cell_id.as_str(), case.case_id),
            );
        }
        for (role, endpoint, file_name) in [
            (crate::Stage4Role::Source, source_endpoint, "source.jsonl"),
            (crate::Stage4Role::Destination, destination_endpoint, "destination.jsonl"),
        ] {
            let uri = format!("cases/{}/raw/{file_name}", case.case_id);
            let Some(reference) =
                case.artifacts.raw_execution.iter().find(|reference| reference.uri == uri)
            else {
                finding(
                    findings,
                    "missing-stage4-native-provider-transcript",
                    format!("{} {} {file_name}", cell_id.as_str(), case.case_id),
                );
                continue;
            };
            let Some(bytes) = artifacts.bytes(&reference.uri) else {
                finding(
                    findings,
                    "missing-stage4-native-provider-transcript-bytes",
                    format!("{} {}", cell_id.as_str(), reference.uri),
                );
                continue;
            };
            let expected_socket = match endpoint {
                Stage4NativeEndpointId::Hx => local_socket_path,
                Stage4NativeEndpointId::Ha => remote_socket_path,
            };
            validate_provider_transcript_bytes(
                cell_id,
                &case.case_id,
                role,
                bytes,
                expected_socket,
                execution_artifact_root,
                findings,
            );
        }
    }
}

fn validate_provider_transcript_bytes(
    cell_id: Stage4NativeCellId,
    case_id: &str,
    role: crate::Stage4Role,
    bytes: &[u8],
    expected_socket: &str,
    execution_artifact_root: &str,
    findings: &mut Vec<Stage4NativeValidationFinding>,
) {
    let Some(body) = bytes.strip_suffix(b"\n") else {
        finding(
            findings,
            "invalid-stage4-native-provider-transcript",
            format!("{} {} {} has no terminal newline", cell_id.as_str(), case_id, role.as_str()),
        );
        return;
    };
    let mut primary_initialize_count = 0_usize;
    let mut supplemental_bindings = BTreeSet::new();
    for (line_index, raw_line) in body.split(|byte| *byte == b'\n').enumerate() {
        if raw_line.is_empty() {
            finding(
                findings,
                "invalid-stage4-native-provider-transcript",
                format!(
                    "{} {} {} has an empty line at {}",
                    cell_id.as_str(),
                    case_id,
                    role.as_str(),
                    line_index + 1
                ),
            );
            continue;
        }
        let transcript = match serde_json::from_slice::<Stage4NativeRawTranscriptLine>(raw_line) {
            Ok(transcript) => transcript,
            Err(source) => {
                finding(
                    findings,
                    "invalid-stage4-native-provider-transcript",
                    format!(
                        "{} {} {} line {}: {source}",
                        cell_id.as_str(),
                        case_id,
                        role.as_str(),
                        line_index + 1
                    ),
                );
                continue;
            }
        };
        if transcript.stream != Stage4NativeRawTranscriptStream::ParentRequest {
            continue;
        }
        let request = match serde_json::from_str::<serde_json::Value>(&transcript.line) {
            Ok(request) => request,
            Err(source) => {
                finding(
                    findings,
                    "invalid-stage4-native-provider-request-json",
                    format!(
                        "{} {} {} {}: {source}",
                        cell_id.as_str(),
                        case_id,
                        role.as_str(),
                        transcript.worker
                    ),
                );
                continue;
            }
        };
        let Some(command) = request.get("command").and_then(serde_json::Value::as_object) else {
            continue;
        };
        if command.get("kind").and_then(serde_json::Value::as_str) != Some("initialize") {
            continue;
        }
        if command.get("role").and_then(serde_json::Value::as_str) != Some(role.as_str()) {
            finding(
                findings,
                "stage4-native-provider-initialize-role-mismatch",
                format!("{} {} {} {}", cell_id.as_str(), case_id, role.as_str(), transcript.worker),
            );
        }
        let Some(locator_text) = command.get("database_path").and_then(serde_json::Value::as_str)
        else {
            finding(
                findings,
                "invalid-stage4-native-provider-initialize-locator",
                format!(
                    "{} {} {} {} has no locator",
                    cell_id.as_str(),
                    case_id,
                    role.as_str(),
                    transcript.worker
                ),
            );
            continue;
        };
        let locator = match parse_stage4_native_provider_locator(locator_text) {
            Ok(locator) => locator,
            Err(detail) => {
                finding(
                    findings,
                    "invalid-stage4-native-provider-initialize-locator",
                    format!(
                        "{} {} {} {}: {detail}",
                        cell_id.as_str(),
                        case_id,
                        role.as_str(),
                        transcript.worker
                    ),
                );
                continue;
            }
        };
        if locator.socket_path != expected_socket {
            finding(
                findings,
                "stage4-native-provider-socket-binding-mismatch",
                format!("{} {} {} {}", cell_id.as_str(), case_id, role.as_str(), transcript.worker),
            );
        }
        let Some(initialized_case_id) = command
            .get("options")
            .and_then(serde_json::Value::as_object)
            .and_then(|options| options.get("case_id"))
            .and_then(serde_json::Value::as_str)
        else {
            finding(
                findings,
                "invalid-stage4-native-provider-initialize-domain",
                format!(
                    "{} {} {} {} has no options.case_id",
                    cell_id.as_str(),
                    case_id,
                    role.as_str(),
                    transcript.worker
                ),
            );
            continue;
        };
        let supplemental = match classify_stage4_native_provider_domain(
            case_id,
            role,
            &transcript.worker,
            initialized_case_id,
        ) {
            Ok(supplemental) => supplemental,
            Err(detail) => {
                finding(
                    findings,
                    "invalid-stage4-native-provider-initialize-domain",
                    format!(
                        "{} {} {} {}: {detail}",
                        cell_id.as_str(),
                        case_id,
                        role.as_str(),
                        transcript.worker
                    ),
                );
                continue;
            }
        };
        if supplemental {
            if !supplemental_bindings
                .insert((initialized_case_id.to_owned(), transcript.worker.clone()))
            {
                finding(
                    findings,
                    "duplicate-stage4-native-provider-supplemental-initialize",
                    format!("{} {} {}", cell_id.as_str(), case_id, transcript.worker),
                );
            }
        } else {
            primary_initialize_count += 1;
        }
        let expected_database_id = stage4_native_provider_database_id(
            execution_artifact_root,
            cell_id,
            initialized_case_id,
        );
        if locator.database_id != expected_database_id {
            finding(
                findings,
                "stage4-native-provider-database-binding-mismatch",
                format!(
                    "{} {} {} {} domain={initialized_case_id}",
                    cell_id.as_str(),
                    case_id,
                    role.as_str(),
                    transcript.worker
                ),
            );
        }
    }
    if primary_initialize_count == 0 {
        finding(
            findings,
            "missing-stage4-native-provider-initialize-request",
            format!("{} {} {}", cell_id.as_str(), case_id, role.as_str()),
        );
    }
    if case_id == EVIDENCE_VERIFICATION_CASE_ID && role == crate::Stage4Role::Source {
        let expected = expected_supplemental_provider_bindings();
        if supplemental_bindings != expected {
            finding(
                findings,
                "invalid-stage4-native-provider-supplemental-domain-catalog",
                format!(
                    "{} {} expected {} exact supplemental bindings, observed {}",
                    cell_id.as_str(),
                    case_id,
                    expected.len(),
                    supplemental_bindings.len()
                ),
            );
        }
    }
}

fn classify_stage4_native_provider_domain(
    outer_case_id: &str,
    role: crate::Stage4Role,
    worker: &str,
    initialized_case_id: &str,
) -> Result<bool, &'static str> {
    if initialized_case_id == outer_case_id {
        return Ok(false);
    }
    if outer_case_id != EVIDENCE_VERIFICATION_CASE_ID || role != crate::Stage4Role::Source {
        return Err("supplemental domains are source-only evidence-verification inputs");
    }
    let Some((_, continuation_label)) =
        SUPPLEMENTAL_PROVIDER_DOMAINS.iter().find(|(case_id, _)| *case_id == initialized_case_id)
    else {
        return Err("supplemental domain is not one of the four provider fault cases");
    };
    let initial_worker = format!("{initialized_case_id}-supplemental-source");
    let continuation_worker = format!("{initialized_case_id}-{continuation_label}");
    if worker != initial_worker && worker != continuation_worker {
        return Err("supplemental domain is not bound to its exact initial/retry/recovery worker");
    }
    Ok(true)
}

fn expected_supplemental_provider_bindings() -> BTreeSet<(String, String)> {
    SUPPLEMENTAL_PROVIDER_DOMAINS
        .iter()
        .flat_map(|(case_id, continuation_label)| {
            [
                ((*case_id).to_owned(), format!("{case_id}-supplemental-source")),
                ((*case_id).to_owned(), format!("{case_id}-{continuation_label}")),
            ]
        })
        .collect()
}

fn stage4_native_provider_database_id(
    execution_artifact_root: &str,
    cell_id: Stage4NativeCellId,
    initialized_case_id: &str,
) -> String {
    let database_path = Path::new(execution_artifact_root)
        .join(cell_id.cell_root_uri())
        .join(".runner-work")
        .join(format!("{initialized_case_id}.sqlite3"));
    let mut input = Vec::with_capacity(
        PROVIDER_DATABASE_ID_DOMAIN.len() + database_path.as_os_str().as_bytes().len(),
    );
    input.extend_from_slice(PROVIDER_DATABASE_ID_DOMAIN);
    input.extend_from_slice(database_path.as_os_str().as_bytes());
    sha256_hex(&input)
}

fn parse_stage4_native_provider_locator(
    value: &str,
) -> Result<ParsedStage4NativeProviderLocator, &'static str> {
    let remainder = value
        .strip_prefix(PROVIDER_LOCATOR_PREFIX)
        .ok_or("local paths and unknown provider locator schemes are forbidden")?;
    let (socket_hex, database_id) =
        remainder.split_once(':').ok_or("provider locator has no database id")?;
    if database_id.contains(':')
        || socket_hex.is_empty()
        || !socket_hex.len().is_multiple_of(2)
        || !socket_hex.bytes().all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        || !is_sha256(database_id)
    {
        return Err("provider locator is not strict lowercase-hex v1");
    }
    let socket_bytes =
        decode_lower_hex(socket_hex).ok_or("provider locator socket hex is invalid")?;
    let socket_path =
        String::from_utf8(socket_bytes).map_err(|_| "provider locator socket is not UTF-8")?;
    if !strict_absolute_normalized_path(&socket_path) {
        return Err("provider locator socket is not a strict absolute normalized path");
    }
    Ok(ParsedStage4NativeProviderLocator { socket_path, database_id: database_id.to_owned() })
}

fn decode_lower_hex(value: &str) -> Option<Vec<u8>> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = lower_hex_nibble(pair[0])?;
            let low = lower_hex_nibble(pair[1])?;
            Some((high << 4) | low)
        })
        .collect()
}

fn lower_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn validate_worker_elf(
    endpoint: Stage4NativeEndpointId,
    bytes: &[u8],
    findings: &mut Vec<Stage4NativeValidationFinding>,
) {
    let expected = match endpoint {
        Stage4NativeEndpointId::Hx => 62_u16,
        Stage4NativeEndpointId::Ha => 183_u16,
    };
    let actual = bytes
        .get(..20)
        .filter(|header| header.starts_with(b"\x7fELF") && header[4] == 2 && header[5] == 1)
        .map(|header| u16::from_le_bytes([header[18], header[19]]));
    if actual != Some(expected) {
        finding(findings, "stage4-native-worker-elf-isa-mismatch", endpoint.as_str());
    }
}

fn validate_cell_paths(
    cell: &Stage4NativeCellEvidence,
    findings: &mut Vec<Stage4NativeValidationFinding>,
) {
    validate_canonical_reference(
        &cell.stage1_bundle,
        &cell.cell_id.stage1_bundle_uri(),
        "inner Stage 1 bundle",
        findings,
    );
    validate_canonical_reference(
        &cell.normalized_observable_trace,
        &cell.cell_id.normalized_uri(),
        "normalized trace",
        findings,
    );
    for (reference, expected) in [
        (&cell.source_hello.raw_stdout, cell.cell_id.hello_stdout_uri(crate::Stage4Role::Source)),
        (&cell.source_hello.raw_stderr, cell.cell_id.hello_stderr_uri(crate::Stage4Role::Source)),
        (
            &cell.destination_hello.raw_stdout,
            cell.cell_id.hello_stdout_uri(crate::Stage4Role::Destination),
        ),
        (
            &cell.destination_hello.raw_stderr,
            cell.cell_id.hello_stderr_uri(crate::Stage4Role::Destination),
        ),
    ] {
        validate_canonical_reference(reference, &expected, "target hello", findings);
    }
}

fn validate_hello(
    root: &SecureArtifactRoot,
    cell: Stage4NativeCellId,
    role: crate::Stage4Role,
    observation: &crate::Stage4TargetHelloObservation,
    endpoint: &Stage4NativeEndpointEvidence,
    nonces: &mut BTreeSet<String>,
    findings: &mut Vec<Stage4NativeValidationFinding>,
) {
    let hello = &observation.hello;
    if observation.exit_status != 0
        || !is_nonce(&observation.expected_nonce)
        || hello.nonce != observation.expected_nonce
        || !nonces.insert(observation.expected_nonce.clone())
    {
        finding(
            findings,
            "invalid-stage4-native-target-hello-challenge",
            format!("{} {}", cell.as_str(), role.as_str()),
        );
    }
    let target = &endpoint.target;
    let build = &endpoint.build_receipt;
    if hello.schema_version != STAGE4_TARGET_HELLO_SCHEMA_VERSION
        || hello.target_triple != target.target_triple
        || hello.architecture != target.architecture
        || hello.os != target.os
        || hello.abi != target.abi
        || hello.endianness != target.endianness
        || hello.pointer_width_bits != target.pointer_width_bits
        || hello.executable_sha256 != endpoint.worker_executable.sha256
        || hello.executable_size != endpoint.worker_executable.size
        || hello.build_source_sha256 != build.build_source_sha256
        || hello.build_toolchain_sha256 != build.build_toolchain_sha256
        || hello.worker_protocol_version != STAGE4_WORKER_PROTOCOL_VERSION
    {
        finding(
            findings,
            "stage4-native-target-hello-identity-mismatch",
            format!("{} {}", cell.as_str(), role.as_str()),
        );
    }
    let stdout = read_reference(root, &observation.raw_stdout, "target hello stdout", findings);
    let expected = serde_json::to_vec(hello).map(|mut bytes| {
        bytes.push(b'\n');
        bytes
    });
    if stdout.as_ref() != expected.as_ref().ok() {
        finding(
            findings,
            "noncanonical-stage4-native-target-hello",
            format!("{} {}", cell.as_str(), role.as_str()),
        );
    }
    if read_reference(root, &observation.raw_stderr, "target hello stderr", findings).as_deref()
        != Some(&[])
    {
        finding(
            findings,
            "nonempty-stage4-native-target-hello-stderr",
            format!("{} {}", cell.as_str(), role.as_str()),
        );
    }
}

fn validate_inner_target_environment(
    cell: Stage4NativeCellId,
    bundle: &Stage1EvidenceBundle,
    source: &Stage4NativeEndpointEvidence,
    destination: &Stage4NativeEndpointEvidence,
    findings: &mut Vec<Stage4NativeValidationFinding>,
) {
    let source_isa = Stage1IsaIdentity {
        architecture: source.target.architecture.clone(),
        abi: source.target.abi.clone(),
    };
    let destination_isa = Stage1IsaIdentity {
        architecture: destination.target.architecture.clone(),
        abi: destination.target.abi.clone(),
    };
    if bundle.environment.source_isa != source_isa
        || bundle.environment.destination_isa != destination_isa
    {
        finding(findings, "stage4-native-inner-target-environment-mismatch", cell.as_str());
    }
}

fn validate_normalized_cache(
    root: &SecureArtifactRoot,
    cell: Stage4NativeCellId,
    reference: &crate::Stage4ArtifactReference,
    normalized: &Stage2NormalizedCellV1,
    findings: &mut Vec<Stage4NativeValidationFinding>,
) {
    let expected = canonical_stage2_json_bytes(normalized).ok();
    let actual = read_reference(root, reference, "normalized trace", findings);
    if actual != expected {
        finding(findings, "stage4-native-normalized-cache-mismatch", cell.as_str());
    }
}

fn compare_verified(
    cells: &[VerifiedCell],
    findings: &mut Vec<Stage4NativeValidationFinding>,
) -> Vec<Stage4NativeCaseComparison> {
    if cells.iter().map(|cell| cell.cell_id).collect::<Vec<_>>() != STAGE4_NATIVE_CELL_CATALOG {
        finding(
            findings,
            "incomplete-stage4-native-verified-matrix",
            format!("verified {} of four cells", cells.len()),
        );
        return Vec::new();
    }
    let mut comparisons = Vec::with_capacity(STAGE1_CASE_DEFINITIONS.len());
    for (index, definition) in STAGE1_CASE_DEFINITIONS.iter().enumerate() {
        let baseline = cells[0].normalized.cases.get(index);
        if baseline.is_none()
            || baseline.is_some_and(|case| case.case_id != definition.id)
            || cells.iter().any(|cell| cell.normalized.cases.get(index) != baseline)
        {
            finding(findings, "stage4-native-normalized-observable-divergence", definition.id);
            continue;
        }
        let baseline = baseline.expect("checked above");
        let digest = canonical_stage2_json_bytes(baseline)
            .map(|bytes| sha256_hex(&bytes))
            .unwrap_or_default();
        comparisons.push(Stage4NativeCaseComparison {
            case_id: definition.id.to_owned(),
            normalized_case_sha256: digest,
            equal_across_all_cells: true,
        });
    }
    comparisons
}

fn validate_summaries(
    evidence: &Stage4NativeEvidenceBundle,
    verified: &[VerifiedCell],
    comparisons: &[Stage4NativeCaseComparison],
    findings: &mut Vec<Stage4NativeValidationFinding>,
) {
    if evidence.case_comparisons != comparisons || comparisons.len() != STAGE4_NATIVE_CASE_COUNT {
        finding(
            findings,
            "invalid-stage4-native-case-comparisons",
            "summaries differ from independent four-cell recomputation",
        );
    }
    if evidence.inner_verifications.len() != STAGE4_NATIVE_CELL_COUNT
        || evidence.inner_verifications.iter().map(|summary| summary.cell_id).collect::<Vec<_>>()
            != STAGE4_NATIVE_CELL_CATALOG
    {
        finding(
            findings,
            "invalid-stage4-native-inner-summary-catalog",
            "four ordered summaries are required",
        );
        return;
    }
    for (summary, cell) in evidence.inner_verifications.iter().zip(verified) {
        if summary.cell_id != cell.cell_id
            || summary.stage1_bundle_id != cell.bundle.bundle_id
            || summary.stage1_bundle_sha256 != sha256_hex(&cell.bundle_bytes)
            || summary.case_count != STAGE4_NATIVE_CASE_COUNT
            || !summary.independently_verified
        {
            finding(findings, "stage4-native-inner-summary-mismatch", summary.cell_id.as_str());
        }
    }
}

fn validate_typed_artifact<T: Serialize + PartialEq>(
    root: &SecureArtifactRoot,
    reference: &crate::Stage4ArtifactReference,
    expected: &T,
    label: &str,
    findings: &mut Vec<Stage4NativeValidationFinding>,
) {
    let bytes = read_reference(root, reference, label, findings);
    if serde_json::to_vec_pretty(expected).ok().as_deref() != bytes.as_deref() {
        finding(
            findings,
            "stage4-native-typed-artifact-mismatch",
            format!("{label} {}", reference.uri),
        );
    }
}

fn validate_canonical_reference(
    reference: &crate::Stage4ArtifactReference,
    expected: &str,
    label: &str,
    findings: &mut Vec<Stage4NativeValidationFinding>,
) {
    if reference.uri != expected || !is_sha256(&reference.sha256) {
        finding(
            findings,
            "noncanonical-stage4-native-artifact-reference",
            format!("{label}: expected {expected}, observed {}", reference.uri),
        );
    }
}

fn read_reference(
    root: &SecureArtifactRoot,
    reference: &crate::Stage4ArtifactReference,
    label: &str,
    findings: &mut Vec<Stage4NativeValidationFinding>,
) -> Option<Vec<u8>> {
    if !safe_uri(&reference.uri) {
        finding(findings, "invalid-stage4-native-artifact-uri", &reference.uri);
        return None;
    }
    let bytes = match root.read_regular(&reference.uri) {
        Ok(bytes) => bytes,
        Err(source) => {
            finding(
                findings,
                "invalid-stage4-native-artifact",
                format!("{label} {}: {source}", reference.uri),
            );
            return None;
        }
    };
    if reference.size != u64::try_from(bytes.len()).unwrap_or(u64::MAX) {
        finding(findings, "stage4-native-artifact-size-mismatch", &reference.uri);
    }
    if reference.sha256 != sha256_hex(&bytes) {
        finding(findings, "stage4-native-artifact-digest-mismatch", &reference.uri);
    }
    Some(bytes)
}

fn validate_main_bundle(
    root: &SecureArtifactRoot,
    bundle: &Stage4NativeEvidenceBundle,
    findings: &mut Vec<Stage4NativeValidationFinding>,
) {
    match root.read_regular(STAGE4_NATIVE_EVIDENCE_FILE) {
        Ok(bytes) if serde_json::to_vec_pretty(bundle).ok().as_deref() == Some(&bytes) => {}
        Ok(_) => finding(
            findings,
            "noncanonical-stage4-native-evidence",
            "main bundle differs from canonical encoding",
        ),
        Err(source) => {
            finding(findings, "invalid-stage4-native-evidence-artifact", source.to_string())
        }
    }
}

fn validate_marker(
    root: &SecureArtifactRoot,
    mode: PublicationMode,
    findings: &mut Vec<Stage4NativeValidationFinding>,
) {
    let observed = root.read_regular(STAGE4_NATIVE_INCOMPLETE_MARKER_FILE);
    match (mode, observed) {
        (PublicationMode::Published, Err(source))
            if source.kind == crate::artifact_io::SecureArtifactErrorKind::Missing => {}
        (PublicationMode::Published, Ok(_)) => {
            finding(findings, "incomplete-stage4-native-publication", "incomplete marker remains")
        }
        (PublicationMode::Published, Err(source)) => {
            finding(findings, "invalid-stage4-native-publication-marker", source.to_string())
        }
        (PublicationMode::Staged, Ok(bytes))
            if bytes == STAGE4_NATIVE_INCOMPLETE_MARKER_CONTENT => {}
        (PublicationMode::Staged, _) => finding(
            findings,
            "missing-stage4-native-publication-marker",
            "staged validation requires the exact incomplete marker",
        ),
    }
}

fn validate_exact_artifact_set(
    artifact_root: &Path,
    bundle: &Stage4NativeEvidenceBundle,
    matrix: Option<&Stage4NativeMatrixManifest>,
    loaded: &[(Stage4NativeCellId, Stage1EvidenceBundle)],
    mode: PublicationMode,
    findings: &mut Vec<Stage4NativeValidationFinding>,
) {
    let mut expected = BTreeSet::from([STAGE4_NATIVE_EVIDENCE_FILE.to_owned()]);
    insert_ref(&bundle.matrix_manifest, &mut expected);
    if mode == PublicationMode::Staged {
        expected.insert(STAGE4_NATIVE_INCOMPLETE_MARKER_FILE.to_owned());
    }
    if let Some(matrix) = matrix {
        insert_ref(&matrix.common_input, &mut expected);
        insert_ref(&matrix.provider.receipt_artifact, &mut expected);
        insert_ref(&matrix.provider.receipt.service_executable, &mut expected);
        for host in &matrix.hosts {
            insert_ref(&host.receipt_artifact, &mut expected);
            insert_ref(&host.receipt.raw_observation, &mut expected);
            for reference in [
                &host.receipt.uname.raw_stdout,
                &host.receipt.uname.raw_stderr,
                &host.receipt.virtualization.raw_stdout,
                &host.receipt.virtualization.raw_stderr,
            ] {
                insert_ref(reference, &mut expected);
            }
            if let Some(model) = host.receipt.hardware_model.as_ref() {
                insert_ref(&model.raw, &mut expected);
            }
        }
        for endpoint in &matrix.endpoints {
            for reference in [
                &endpoint.worker_executable,
                &endpoint.build_receipt_artifact,
                &endpoint.launcher_receipt_artifact,
            ] {
                insert_ref(reference, &mut expected);
            }
            if let Stage4NativeLauncherTransport::Ssh { ssh_program, known_hosts, .. } =
                &endpoint.launcher_receipt.transport
            {
                insert_ref(ssh_program, &mut expected);
                insert_ref(known_hosts, &mut expected);
            }
        }
        for cell in &matrix.cells {
            for reference in [
                &cell.stage1_bundle,
                &cell.normalized_observable_trace,
                &cell.source_hello.raw_stdout,
                &cell.source_hello.raw_stderr,
                &cell.destination_hello.raw_stdout,
                &cell.destination_hello.raw_stderr,
            ] {
                insert_ref(reference, &mut expected);
            }
        }
    }
    for (cell, stage1) in loaded {
        for definition in STAGE1_CASE_DEFINITIONS {
            expected.insert(format!(
                "{}/cases/{}/manifest.json",
                cell.cell_root_uri(),
                definition.id
            ));
        }
        for uri in stage1_artifact_uris(stage1) {
            expected.insert(format!("{}/{}", cell.cell_root_uri(), uri));
        }
    }
    let mut expected_dirs = BTreeSet::new();
    for uri in &expected {
        let mut parent = Path::new(uri).parent();
        while let Some(path) = parent {
            if path.as_os_str().is_empty() {
                break;
            }
            expected_dirs.insert(path.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/"));
            parent = path.parent();
        }
    }
    let mut observed = BTreeSet::new();
    enumerate(artifact_root, "", &expected, &expected_dirs, &mut observed, findings);
    for missing in expected.difference(&observed) {
        finding(findings, "missing-stage4-native-artifact-entry", missing);
    }
}

fn stage1_artifact_uris(bundle: &Stage1EvidenceBundle) -> Vec<&str> {
    let provenance = &bundle.provenance.artifacts;
    let mut uris = vec![
        provenance.component.uri.as_str(),
        provenance.profile.uri.as_str(),
        provenance.source_manifest.uri.as_str(),
        provenance.toolchain.uri.as_str(),
        provenance.build_source_manifest.uri.as_str(),
        provenance.build_toolchain.uri.as_str(),
        provenance.executable.uri.as_str(),
        provenance.matrix_manifest.uri.as_str(),
    ];
    for case in &bundle.cases {
        if let Some(snapshot) = case.artifacts.snapshot.as_ref() {
            uris.push(snapshot.uri.as_str());
        }
        uris.extend(case.artifacts.semantic_traces.iter().map(|item| item.uri.as_str()));
        uris.extend(case.artifacts.binding_receipts.iter().map(|item| item.artifact.uri.as_str()));
        uris.extend(case.artifacts.raw_execution.iter().map(|item| item.uri.as_str()));
    }
    uris
}

fn enumerate(
    directory: &Path,
    relative: &str,
    expected_files: &BTreeSet<String>,
    expected_dirs: &BTreeSet<String>,
    observed: &mut BTreeSet<String>,
    findings: &mut Vec<Stage4NativeValidationFinding>,
) {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(source) => {
            finding(findings, "unreadable-stage4-native-directory", source.to_string());
            return;
        }
    };
    for entry in entries.flatten() {
        let name = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(_) => {
                finding(findings, "non-utf8-stage4-native-entry", entry.path().display());
                continue;
            }
        };
        let uri = if relative.is_empty() { name } else { format!("{relative}/{name}") };
        let metadata = match fs::symlink_metadata(entry.path()) {
            Ok(metadata) => metadata,
            Err(source) => {
                finding(findings, "unreadable-stage4-native-entry", source.to_string());
                continue;
            }
        };
        if metadata.file_type().is_symlink() {
            finding(findings, "invalid-stage4-native-entry-type", format!("{uri} symlink"));
        } else if metadata.is_dir() {
            if expected_dirs.contains(&uri) {
                enumerate(&entry.path(), &uri, expected_files, expected_dirs, observed, findings);
            } else {
                finding(findings, "unexpected-stage4-native-artifact-entry", &uri);
            }
        } else if metadata.is_file() {
            observed.insert(uri.clone());
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt as _;
                if metadata.nlink() != 1 {
                    finding(findings, "hardlinked-stage4-native-artifact-entry", &uri);
                }
            }
            if !expected_files.contains(&uri) {
                finding(findings, "unexpected-stage4-native-artifact-entry", &uri);
            }
        } else {
            finding(findings, "invalid-stage4-native-entry-type", &uri);
        }
    }
}

fn insert_ref(reference: &crate::Stage4ArtifactReference, expected: &mut BTreeSet<String>) {
    if safe_uri(&reference.uri) {
        expected.insert(reference.uri.clone());
    }
}

fn safe_uri(uri: &str) -> bool {
    let path = Path::new(uri);
    !uri.is_empty()
        && !path.is_absolute()
        && path.components().all(|component| matches!(component, Component::Normal(_)))
}

fn strict_absolute_normalized_path(value: &str) -> bool {
    let path = Path::new(value);
    if !path.is_absolute() || value.as_bytes().contains(&0) {
        return false;
    }
    let mut rebuilt = PathBuf::from("/");
    let mut normal_components = 0;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(part) => {
                normal_components += 1;
                rebuilt.push(part);
            }
            _ => return false,
        }
    }
    normal_components > 0 && rebuilt.to_str() == Some(value)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn is_nonce(value: &str) -> bool {
    is_sha256(value)
}

fn finding(
    findings: &mut Vec<Stage4NativeValidationFinding>,
    code: impl Into<String>,
    detail: impl std::fmt::Display,
) {
    findings.push(Stage4NativeValidationFinding { code: code.into(), detail: detail.to_string() });
}

fn report(findings: Vec<Stage4NativeValidationFinding>) -> Stage4NativeValidationReport {
    Stage4NativeValidationReport { ok: findings.is_empty(), findings }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(label: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "visa-stage4-native-{label}-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn artifact(
        root: &Path,
        uri: impl Into<String>,
        bytes: &[u8],
    ) -> crate::Stage4ArtifactReference {
        let uri = uri.into();
        let path = root.join(&uri);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
        crate::Stage4ArtifactReference { uri, sha256: sha256_hex(bytes), size: bytes.len() as u64 }
    }

    fn provider_fixture(
        root: &Path,
    ) -> (Stage4NativeProviderEvidence, Stage4NativeEndpointEvidence) {
        let target = required_stage4_native_provider_backend_target();
        let worker = crate::Stage4ArtifactReference {
            uri: Stage4NativeEndpointId::Hx.worker_uri(),
            sha256: "a".repeat(64),
            size: 4096,
        };
        let build_receipt = Stage4NativeBuildReceipt {
            schema_version: STAGE4_NATIVE_BUILD_RECEIPT_SCHEMA_VERSION.to_owned(),
            endpoint_id: Stage4NativeEndpointId::Hx,
            target: target.clone(),
            executable_sha256: worker.sha256.clone(),
            executable_size: worker.size,
            build_source_sha256: "b".repeat(64),
            build_toolchain_sha256: "c".repeat(64),
        };
        let launcher_receipt = Stage4NativeLauncherReceipt {
            schema_version: STAGE4_NATIVE_LAUNCHER_RECEIPT_SCHEMA_VERSION.to_owned(),
            endpoint_id: Stage4NativeEndpointId::Hx,
            host_id: Stage4NativeHostId::HxHost,
            worker_sha256: worker.sha256.clone(),
            worker_size: worker.size,
            native_execution: true,
            emulated_execution: false,
            transport: Stage4NativeLauncherTransport::LocalDirect {
                argv: vec!["/tmp/native/targets/Hx/worker".to_owned()],
            },
        };
        let hx = Stage4NativeEndpointEvidence {
            endpoint_id: Stage4NativeEndpointId::Hx,
            host_id: Stage4NativeHostId::HxHost,
            target: target.clone(),
            worker_executable: worker.clone(),
            build_receipt_artifact: crate::Stage4ArtifactReference {
                uri: Stage4NativeEndpointId::Hx.build_receipt_uri(),
                sha256: "d".repeat(64),
                size: 1,
            },
            build_receipt,
            launcher_receipt_artifact: crate::Stage4ArtifactReference {
                uri: Stage4NativeEndpointId::Hx.launcher_receipt_uri(),
                sha256: "e".repeat(64),
                size: 1,
            },
            launcher_receipt,
        };
        let case_domains = STAGE4_NATIVE_CELL_CATALOG
            .iter()
            .copied()
            .flat_map(|cell_id| {
                STAGE1_CASE_DEFINITIONS.iter().map(move |definition| {
                    let (source_endpoint, destination_endpoint) = cell_id.endpoints();
                    Stage4NativeProviderCaseDomain {
                        cell_id,
                        case_id: definition.id.to_owned(),
                        source_endpoint,
                        destination_endpoint,
                        logical_database_id: sha256_hex(
                            format!("{}:{}", cell_id.as_str(), definition.id).as_bytes(),
                        ),
                    }
                })
            })
            .collect();
        let receipt = Stage4NativeProviderReceipt {
            schema_version: STAGE4_NATIVE_PROVIDER_RECEIPT_SCHEMA_VERSION.to_owned(),
            provider_host: Stage4NativeHostId::HxHost,
            backend_identity: STAGE4_NATIVE_PROVIDER_BACKEND_IDENTITY.to_owned(),
            backend_target: target,
            service_executable: worker.clone(),
            service_executable_sha256: worker.sha256,
            service_executable_size: worker.size,
            transport: Stage4NativeProviderTransport::UnixStream {
                local_socket_path: "/tmp/visa-stage4-native/provider.sock".to_owned(),
                ha_transport: Stage4NativeProviderHaTransport::SshReverseStreamLocal {
                    remote_socket_path: "/tmp/visa-stage4-native-ha/provider.sock".to_owned(),
                },
            },
            runtime_execution: Stage4NativeProviderRuntimeExecution {
                hx_native: true,
                ha_native: true,
            },
            case_domains,
        };
        let receipt_bytes = serde_json::to_vec_pretty(&receipt).unwrap();
        let provider = Stage4NativeProviderEvidence {
            receipt_artifact: artifact(root, STAGE4_NATIVE_PROVIDER_RECEIPT_FILE, &receipt_bytes),
            receipt,
        };
        (provider, hx)
    }

    fn retain_provider_receipt(root: &Path, provider: &mut Stage4NativeProviderEvidence) {
        let bytes = serde_json::to_vec_pretty(&provider.receipt).unwrap();
        provider.receipt_artifact = artifact(root, STAGE4_NATIVE_PROVIDER_RECEIPT_FILE, &bytes);
    }

    fn provider_locator(socket: &str, database_id: &str) -> String {
        let socket_hex =
            socket.as_bytes().iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        format!("{PROVIDER_LOCATOR_PREFIX}{socket_hex}:{database_id}")
    }

    fn initialize_transcript(entries: &[(&str, crate::Stage4Role, &str, &str)]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for (index, (worker, role, initialized_case_id, locator)) in entries.iter().enumerate() {
            let request = serde_json::json!({
                "version": crate::STAGE1_WORKER_PROTOCOL_VERSION,
                "id": format!("request-{}", index + 1),
                "command": {
                    "kind": "initialize",
                    "role": role.as_str(),
                    "runtime": "wasmtime",
                    "database_path": locator,
                    "options": {
                        "case_id": initialized_case_id,
                        "namespace_availability": "correct",
                        "authority_policy": "sufficient",
                        "timer_delay_ns": 1
                    },
                    "fault": null
                }
            });
            serde_json::to_writer(
                &mut bytes,
                &serde_json::json!({
                    "worker": worker,
                    "pid": u32::try_from(index + 1).unwrap(),
                    "sequence": 1,
                    "stream": "parent_request",
                    "line": serde_json::to_string(&request).unwrap()
                }),
            )
            .unwrap();
            bytes.push(b'\n');
        }
        bytes
    }

    #[test]
    fn catalog_is_exact_four_direction_native_matrix() {
        assert_eq!(STAGE4_NATIVE_EXECUTION_COUNT, 124);
        assert_eq!(STAGE4_NATIVE_ENDPOINT_CATALOG.len(), 2);
        assert_eq!(STAGE4_NATIVE_HOST_CATALOG.len(), 2);
        assert_eq!(required_stage4_native_claim().required_cells, STAGE4_NATIVE_CELL_CATALOG);
        assert_eq!(stage4_native_registry_sha256(), STAGE4_NATIVE_ACCEPTED_REGISTRY_SHA256);
    }

    #[test]
    fn worker_elf_lock_distinguishes_hx_and_ha() {
        let mut x86 = vec![0_u8; 20];
        x86[..6].copy_from_slice(b"\x7fELF\x02\x01");
        x86[18..20].copy_from_slice(&62_u16.to_le_bytes());
        let mut arm = x86.clone();
        arm[18..20].copy_from_slice(&183_u16.to_le_bytes());
        let mut findings = Vec::new();
        validate_worker_elf(Stage4NativeEndpointId::Hx, &x86, &mut findings);
        validate_worker_elf(Stage4NativeEndpointId::Ha, &arm, &mut findings);
        assert!(findings.is_empty());
        validate_worker_elf(Stage4NativeEndpointId::Ha, &x86, &mut findings);
        assert!(
            findings
                .iter()
                .any(|finding| { finding.code == "stage4-native-worker-elf-isa-mismatch" })
        );
    }

    #[test]
    fn retained_reference_survives_root_relocation() {
        let original = root("relocation-original");
        fs::create_dir_all(original.join("nested")).unwrap();
        let bytes = b"relocatable evidence";
        fs::write(original.join("nested/value"), bytes).unwrap();
        let reference = crate::Stage4ArtifactReference {
            uri: "nested/value".to_owned(),
            sha256: sha256_hex(bytes),
            size: bytes.len() as u64,
        };
        let secure = SecureArtifactRoot::open(&original).unwrap();
        let mut findings = Vec::new();
        assert_eq!(
            read_reference(&secure, &reference, "value", &mut findings),
            Some(bytes.to_vec())
        );
        assert!(findings.is_empty());
        drop(secure);
        let relocated = original
            .with_file_name(format!("{}-moved", original.file_name().unwrap().to_string_lossy()));
        let _ = fs::remove_dir_all(&relocated);
        fs::rename(&original, &relocated).unwrap();
        let secure = SecureArtifactRoot::open(&relocated).unwrap();
        assert_eq!(
            read_reference(&secure, &reference, "value", &mut findings),
            Some(bytes.to_vec())
        );
        assert!(findings.is_empty());
        fs::remove_dir_all(relocated).unwrap();
    }

    #[test]
    fn claim_guards_do_not_imply_second_runtime_or_aot_portability() {
        let guards = Stage4NativeClaimGuards::required();
        assert_eq!(guards.real_aarch64_hardware, Stage4NativeClaimBoundary::Proven);
        assert_eq!(guards.native_cross_isa, Stage4NativeClaimBoundary::Proven);
        assert_eq!(guards.cross_host, Stage4NativeClaimBoundary::Proven);
        assert_eq!(guards.shared_provider_transaction_domain, Stage4NativeClaimBoundary::Proven);
        assert_eq!(guards.provider_substrate_cross_isa, Stage4NativeClaimBoundary::NotClaimed);
        assert_eq!(guards.provider_migration, Stage4NativeClaimBoundary::NotClaimed);
        assert_eq!(guards.second_runtime, Stage4NativeClaimBoundary::NotClaimed);
        assert_eq!(guards.aot_binary_portability, Stage4NativeClaimBoundary::NotClaimed);
    }

    #[test]
    fn provider_receipt_rejects_aliased_socket_and_reused_database_domain() {
        let root_path = root("provider-topology-negative");
        let (mut provider, hx) = provider_fixture(&root_path);
        let secure = SecureArtifactRoot::open(&root_path).unwrap();
        let endpoints = BTreeMap::from([(Stage4NativeEndpointId::Hx, &hx)]);
        let mut findings = Vec::new();
        validate_provider(&secure, &provider, &endpoints, &mut findings);
        assert!(findings.is_empty(), "{findings:?}");

        let Stage4NativeProviderTransport::UnixStream { local_socket_path, .. } =
            &mut provider.receipt.transport;
        *local_socket_path = "/tmp/visa-stage4-native/../provider.sock".to_owned();
        provider.receipt.case_domains[1].logical_database_id =
            provider.receipt.case_domains[0].logical_database_id.clone();
        retain_provider_receipt(&root_path, &mut provider);
        let mut findings = Vec::new();
        validate_provider(&secure, &provider, &endpoints, &mut findings);
        assert!(
            findings
                .iter()
                .any(|finding| finding.code == "invalid-stage4-native-provider-socket-topology")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.code == "duplicate-stage4-native-provider-database-id")
        );
        fs::remove_dir_all(root_path).unwrap();
    }

    #[test]
    fn provider_receipt_rejects_backend_and_service_identity_drift() {
        let root_path = root("provider-identity-negative");
        let (mut provider, hx) = provider_fixture(&root_path);
        provider.receipt.backend_identity = "other::Provider".to_owned();
        provider.receipt.service_executable_sha256 = "f".repeat(64);
        retain_provider_receipt(&root_path, &mut provider);
        let secure = SecureArtifactRoot::open(&root_path).unwrap();
        let endpoints = BTreeMap::from([(Stage4NativeEndpointId::Hx, &hx)]);
        let mut findings = Vec::new();
        validate_provider(&secure, &provider, &endpoints, &mut findings);
        assert!(
            findings
                .iter()
                .any(|finding| finding.code == "invalid-stage4-native-provider-identity")
        );
        assert!(
            findings.iter().any(|finding| {
                finding.code == "stage4-native-provider-service-identity-mismatch"
            })
        );
        fs::remove_dir_all(root_path).unwrap();
    }

    #[test]
    fn provider_transcript_rejects_split_database_id_in_audit_initialize() {
        let execution_root = "/artifacts/native-test";
        let cell_id = Stage4NativeCellId::HxToHx;
        let case_id = STAGE1_CASE_DEFINITIONS[0].id;
        let expected_database_id =
            stage4_native_provider_database_id(execution_root, cell_id, case_id);
        let split_database_id = "b".repeat(64);
        let socket = "/tmp/visa-stage4-native/provider.sock";
        let correct = provider_locator(socket, &expected_database_id);
        let split = provider_locator(socket, &split_database_id);
        let bytes = initialize_transcript(&[
            ("case-source", crate::Stage4Role::Source, case_id, &correct),
            ("case-source-audit", crate::Stage4Role::Source, case_id, &split),
        ]);
        let mut findings = Vec::new();
        validate_provider_transcript_bytes(
            cell_id,
            case_id,
            crate::Stage4Role::Source,
            &bytes,
            socket,
            execution_root,
            &mut findings,
        );
        assert!(
            findings.iter().any(|finding| {
                finding.code == "stage4-native-provider-database-binding-mismatch"
            })
        );
    }

    #[test]
    fn provider_transcript_rejects_wrong_socket_in_restart_initialize() {
        let execution_root = "/artifacts/native-test";
        let cell_id = Stage4NativeCellId::HxToHa;
        let case_id = STAGE1_CASE_DEFINITIONS[0].id;
        let database_id = stage4_native_provider_database_id(execution_root, cell_id, case_id);
        let remote_socket = "/tmp/visa-stage4-native-ha/provider.sock";
        let wrong_socket = "/tmp/visa-stage4-native/provider.sock";
        let correct = provider_locator(remote_socket, &database_id);
        let wrong = provider_locator(wrong_socket, &database_id);
        let bytes = initialize_transcript(&[
            ("case-destination", crate::Stage4Role::Destination, case_id, &correct),
            ("case-destination-restart", crate::Stage4Role::Destination, case_id, &wrong),
        ]);
        let mut findings = Vec::new();
        validate_provider_transcript_bytes(
            cell_id,
            case_id,
            crate::Stage4Role::Destination,
            &bytes,
            remote_socket,
            execution_root,
            &mut findings,
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.code == "stage4-native-provider-socket-binding-mismatch")
        );
    }

    #[test]
    fn provider_transcript_rejects_local_filesystem_database_path() {
        let execution_root = "/artifacts/native-test";
        let case_id = STAGE1_CASE_DEFINITIONS[0].id;
        let socket = "/tmp/visa-stage4-native/provider.sock";
        let bytes = initialize_transcript(&[(
            "case-source",
            crate::Stage4Role::Source,
            case_id,
            "/tmp/case.sqlite3",
        )]);
        let mut findings = Vec::new();
        validate_provider_transcript_bytes(
            Stage4NativeCellId::HxToHx,
            case_id,
            crate::Stage4Role::Source,
            &bytes,
            socket,
            execution_root,
            &mut findings,
        );
        assert!(findings.iter().any(|finding| {
            finding.code == "invalid-stage4-native-provider-initialize-locator"
        }));
    }

    #[test]
    fn provider_transcript_accepts_exact_recomputed_supplemental_fault_domains() {
        let execution_root = "/artifacts/native-test";
        let cell_id = Stage4NativeCellId::HxToHx;
        let socket = "/tmp/visa-stage4-native/provider.sock";
        let primary_id = stage4_native_provider_database_id(
            execution_root,
            cell_id,
            EVIDENCE_VERIFICATION_CASE_ID,
        );
        let supplemental_ids = SUPPLEMENTAL_PROVIDER_DOMAINS
            .iter()
            .map(|(case_id, _)| {
                stage4_native_provider_database_id(execution_root, cell_id, case_id)
            })
            .collect::<Vec<_>>();
        let primary = provider_locator(socket, &primary_id);
        let supplemental = supplemental_ids
            .iter()
            .map(|database_id| provider_locator(socket, database_id))
            .collect::<Vec<_>>();
        let bytes = initialize_transcript(&[
            (
                "evidence-verification-source",
                crate::Stage4Role::Source,
                EVIDENCE_VERIFICATION_CASE_ID,
                &primary,
            ),
            (
                "evidence-verification-fault-before-activation-bundle-supplemental-source",
                crate::Stage4Role::Source,
                SUPPLEMENTAL_PROVIDER_DOMAINS[0].0,
                &supplemental[0],
            ),
            (
                "evidence-verification-fault-before-activation-bundle-supplemental-source-retry",
                crate::Stage4Role::Source,
                SUPPLEMENTAL_PROVIDER_DOMAINS[0].0,
                &supplemental[0],
            ),
            (
                "evidence-verification-fault-after-activation-bundle-supplemental-source",
                crate::Stage4Role::Source,
                SUPPLEMENTAL_PROVIDER_DOMAINS[1].0,
                &supplemental[1],
            ),
            (
                "evidence-verification-fault-after-activation-bundle-supplemental-source-recovery",
                crate::Stage4Role::Source,
                SUPPLEMENTAL_PROVIDER_DOMAINS[1].0,
                &supplemental[1],
            ),
            (
                "evidence-verification-fault-before-journal-write-supplemental-source",
                crate::Stage4Role::Source,
                SUPPLEMENTAL_PROVIDER_DOMAINS[2].0,
                &supplemental[2],
            ),
            (
                "evidence-verification-fault-before-journal-write-supplemental-source-retry",
                crate::Stage4Role::Source,
                SUPPLEMENTAL_PROVIDER_DOMAINS[2].0,
                &supplemental[2],
            ),
            (
                "evidence-verification-fault-after-journal-write-supplemental-source",
                crate::Stage4Role::Source,
                SUPPLEMENTAL_PROVIDER_DOMAINS[3].0,
                &supplemental[3],
            ),
            (
                "evidence-verification-fault-after-journal-write-supplemental-source-recovery",
                crate::Stage4Role::Source,
                SUPPLEMENTAL_PROVIDER_DOMAINS[3].0,
                &supplemental[3],
            ),
        ]);
        let mut findings = Vec::new();
        validate_provider_transcript_bytes(
            cell_id,
            EVIDENCE_VERIFICATION_CASE_ID,
            crate::Stage4Role::Source,
            &bytes,
            socket,
            execution_root,
            &mut findings,
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn provider_transcript_rejects_unregistered_supplemental_domain() {
        let execution_root = "/artifacts/native-test";
        let cell_id = Stage4NativeCellId::HxToHx;
        let socket = "/tmp/visa-stage4-native/provider.sock";
        let primary_id = stage4_native_provider_database_id(
            execution_root,
            cell_id,
            EVIDENCE_VERIFICATION_CASE_ID,
        );
        let unknown_case_id = "evidence-verification-fault-unregistered";
        let unknown_id =
            stage4_native_provider_database_id(execution_root, cell_id, unknown_case_id);
        let primary = provider_locator(socket, &primary_id);
        let unknown = provider_locator(socket, &unknown_id);
        let bytes = initialize_transcript(&[
            (
                "evidence-verification-source",
                crate::Stage4Role::Source,
                EVIDENCE_VERIFICATION_CASE_ID,
                &primary,
            ),
            (
                "evidence-verification-fault-unregistered-supplemental-source",
                crate::Stage4Role::Source,
                unknown_case_id,
                &unknown,
            ),
        ]);
        let mut findings = Vec::new();
        validate_provider_transcript_bytes(
            cell_id,
            EVIDENCE_VERIFICATION_CASE_ID,
            crate::Stage4Role::Source,
            &bytes,
            socket,
            execution_root,
            &mut findings,
        );
        assert!(
            findings.iter().any(|finding| {
                finding.code == "invalid-stage4-native-provider-initialize-domain"
            }),
            "{findings:?}"
        );
    }

    #[test]
    fn ha_host_receipt_recomputes_physical_pi_observation_from_raw_artifacts() {
        let root_path = root("ha-host");
        let host_id = Stage4NativeHostId::HaHost;
        let identity = crate::Stage4HostIdentity {
            sysname: "Linux".to_owned(),
            kernel_release: "6.18.34+rpt-rpi-v8".to_owned(),
            machine: "aarch64".to_owned(),
        };
        let nonce = "a".repeat(64);
        let uname_stdout = "Linux 6.18.34+rpt-rpi-v8 aarch64\n";
        let observation = Stage4NativeRawHostObservation {
            schema_version: STAGE4_NATIVE_HOST_OBSERVATION_SCHEMA_VERSION.to_owned(),
            nonce: nonce.clone(),
            host_id,
            identity: identity.clone(),
            uname_program_sha256: "b".repeat(64),
            uname_program_size: 1,
            uname_argv: [UNAME_PROGRAM, "-s", "-r", "-m"].map(str::to_owned).to_vec(),
            uname_exit_status: 0,
            uname_stdout: uname_stdout.to_owned(),
            uname_stderr: String::new(),
            virtualization_program_sha256: "c".repeat(64),
            virtualization_program_size: 1,
            virtualization_argv: vec![VIRT_PROGRAM.to_owned()],
            virtualization_exit_status: 1,
            virtualization_stdout: "none\n".to_owned(),
            virtualization_stderr: String::new(),
            hardware_model_source_path: Some("/proc/device-tree/model".to_owned()),
            hardware_model: Some("Raspberry Pi Zero 2 W Rev 1.0".to_owned()),
        };
        let mut observation_bytes = serde_json::to_vec(&observation).unwrap();
        observation_bytes.push(b'\n');
        let raw_observation = artifact(&root_path, host_id.observation_uri(), &observation_bytes);
        let uname_stdout_ref =
            artifact(&root_path, host_id.uname_stdout_uri(), uname_stdout.as_bytes());
        let uname_stderr_ref = artifact(&root_path, host_id.uname_stderr_uri(), b"");
        let virt_stdout_ref = artifact(&root_path, host_id.virtualization_stdout_uri(), b"none\n");
        let virt_stderr_ref = artifact(&root_path, host_id.virtualization_stderr_uri(), b"");
        let model_ref =
            artifact(&root_path, host_id.hardware_model_uri(), b"Raspberry Pi Zero 2 W Rev 1.0\0");
        let receipt = Stage4NativeHostReceipt {
            schema_version: STAGE4_NATIVE_HOST_RECEIPT_SCHEMA_VERSION.to_owned(),
            host_id,
            expected_nonce: nonce,
            raw_observation,
            identity,
            uname: Stage4NativeCommandReceipt {
                program: UNAME_PROGRAM.to_owned(),
                program_sha256: "b".repeat(64),
                program_size: 1,
                argv: [UNAME_PROGRAM, "-s", "-r", "-m"].map(str::to_owned).to_vec(),
                exit_status: 0,
                raw_stdout: uname_stdout_ref,
                raw_stderr: uname_stderr_ref,
            },
            virtualization: Stage4NativeCommandReceipt {
                program: VIRT_PROGRAM.to_owned(),
                program_sha256: "c".repeat(64),
                program_size: 1,
                argv: vec![VIRT_PROGRAM.to_owned()],
                exit_status: 1,
                raw_stdout: virt_stdout_ref,
                raw_stderr: virt_stderr_ref,
            },
            hardware_model: Some(Stage4NativeHardwareModelObservation {
                source_path: "/proc/device-tree/model".to_owned(),
                model: "Raspberry Pi Zero 2 W Rev 1.0".to_owned(),
                raw: model_ref,
            }),
        };
        let receipt_bytes = serde_json::to_vec_pretty(&receipt).unwrap();
        let host = Stage4NativeHostEvidence {
            host_id,
            receipt_artifact: artifact(&root_path, host_id.receipt_uri(), &receipt_bytes),
            receipt,
        };
        let secure = SecureArtifactRoot::open(&root_path).unwrap();
        let mut nonces = BTreeSet::new();
        let mut findings = Vec::new();
        validate_host(&secure, &host, &mut nonces, &mut findings);
        assert!(findings.is_empty(), "{findings:?}");

        let mut forged = host;
        forged.receipt.hardware_model.as_mut().unwrap().model = "virtual-arm".to_owned();
        let mut findings = Vec::new();
        validate_host(&secure, &forged, &mut BTreeSet::new(), &mut findings);
        assert!(findings.iter().any(|finding| {
            finding.code == "invalid-stage4-native-hardware-model"
                || finding.code == "stage4-native-host-observation-mismatch"
        }));
        fs::remove_dir_all(root_path).unwrap();
    }

    #[test]
    fn json_gate_reports_load_errors_without_claiming_validation() {
        let root = root("load-error");
        let result = gate_stage4_native_evidence_bundle_json_with_artifacts(b"{}", &root);
        assert!(!result.ok);
        assert!(result.load_error.is_some());
        assert!(result.validation.is_none());
        fs::remove_dir_all(root).unwrap();
    }
}
