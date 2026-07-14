use std::{collections::BTreeSet, fs, path::Path};

use sha2::{Digest as _, Sha256};

use super::model::*;
use crate::artifact_io::{SecureArtifactErrorKind, SecureArtifactRoot};

pub fn stage3_registry_sha256(profile: Stage3Profile) -> String {
    let bytes = serde_json::to_vec(profile.cases()).expect("static Stage 3 registry serializes");
    sha256_hex(&bytes)
}

pub fn parse_stage3_evidence_bundle_json(
    bytes: &[u8],
) -> Result<Stage3EvidenceBundle, Stage3EvidenceLoadError> {
    serde_json::from_slice(bytes).map_err(|source| Stage3EvidenceLoadError {
        code: "invalid-stage3-evidence-json".to_owned(),
        detail: source.to_string(),
    })
}

pub fn gate_stage3_evidence_bundle_json_with_artifacts(
    expected_profile: Stage3Profile,
    bytes: &[u8],
    artifact_root: impl AsRef<Path>,
) -> Stage3EvidenceGateResult {
    let bundle = match parse_stage3_evidence_bundle_json(bytes) {
        Ok(bundle) => bundle,
        Err(load_error) => {
            return Stage3EvidenceGateResult {
                ok: false,
                load_error: Some(load_error),
                validation: None,
            };
        }
    };
    let artifact_root = artifact_root.as_ref();
    let mut validation = validate_stage3_evidence_bundle(expected_profile, &bundle, artifact_root);
    match SecureArtifactRoot::open(artifact_root)
        .and_then(|root| root.read_regular(expected_profile.evidence_file()))
    {
        Ok(on_disk) if on_disk == bytes => {}
        Ok(_) => finding(
            &mut validation.findings,
            "stage3-gate-bundle-bytes-mismatch",
            "the JSON supplied to the gate is not byte-identical to the bundle in the artifact root",
        ),
        Err(source) => {
            finding(&mut validation.findings, "invalid-stage3-bundle-artifact", source.to_string())
        }
    }
    validation.ok = validation.findings.is_empty();
    Stage3EvidenceGateResult { ok: validation.ok, load_error: None, validation: Some(validation) }
}

pub fn validate_stage3_evidence_bundle(
    expected_profile: Stage3Profile,
    bundle: &Stage3EvidenceBundle,
    artifact_root: &Path,
) -> Stage3ValidationReport {
    validate_stage3_evidence_bundle_impl(
        expected_profile,
        bundle,
        artifact_root,
        PublicationMode::Published,
    )
}

/// Private publisher gate. The final bundle is already durably staged, but
/// the incomplete marker must remain present until this exact-set validation
/// succeeds. Removing the marker is the publication commit point.
pub fn validate_stage3_evidence_bundle_for_publication(
    expected_profile: Stage3Profile,
    bundle: &Stage3EvidenceBundle,
    artifact_root: &Path,
) -> Stage3ValidationReport {
    validate_stage3_evidence_bundle_impl(
        expected_profile,
        bundle,
        artifact_root,
        PublicationMode::Staged,
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublicationMode {
    Published,
    Staged,
}

fn validate_stage3_evidence_bundle_impl(
    expected_profile: Stage3Profile,
    bundle: &Stage3EvidenceBundle,
    artifact_root: &Path,
    mode: PublicationMode,
) -> Stage3ValidationReport {
    let mut findings = Vec::new();
    validate_shape(expected_profile, bundle, &mut findings);
    let root = match SecureArtifactRoot::open(artifact_root) {
        Ok(root) => root,
        Err(source) => {
            finding(&mut findings, "invalid-stage3-artifact-root", source.to_string());
            return report(findings);
        }
    };

    validate_publication_marker(&root, mode, &mut findings);
    validate_bundle_artifact(&root, expected_profile, bundle, &mut findings);

    let mut uris = BTreeSet::new();
    for reference in top_level_artifacts(bundle)
        .chain(bundle.cases.iter().flat_map(|case| case.artifacts.iter()))
    {
        if !uris.insert(reference.uri.as_str()) {
            finding(
                &mut findings,
                "duplicate-stage3-artifact-uri",
                format!("artifact URI {} is referenced more than once", reference.uri),
            );
            continue;
        }
        let bytes = match root.read_regular(&reference.uri) {
            Ok(bytes) => bytes,
            Err(source) => {
                finding(
                    &mut findings,
                    "invalid-stage3-artifact",
                    format!("{}: {source}", reference.uri),
                );
                continue;
            }
        };
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != reference.size {
            finding(
                &mut findings,
                "stage3-artifact-size-mismatch",
                format!("{} has an unexpected size", reference.uri),
            );
        }
        if sha256_hex(&bytes) != reference.sha256 {
            finding(
                &mut findings,
                "stage3-artifact-digest-mismatch",
                format!("{} has an unexpected digest", reference.uri),
            );
        }
    }
    validate_exact_artifact_set(artifact_root, expected_profile, bundle, mode, &mut findings);
    report(findings)
}

fn validate_publication_marker(
    root: &SecureArtifactRoot,
    mode: PublicationMode,
    findings: &mut Vec<Stage3ValidationFinding>,
) {
    match (mode, root.read_regular(STAGE3_INCOMPLETE_MARKER_FILE)) {
        (PublicationMode::Published, Ok(_)) => finding(
            findings,
            "incomplete-stage3-publication",
            format!("{STAGE3_INCOMPLETE_MARKER_FILE} is still present"),
        ),
        (PublicationMode::Published, Err(source))
            if source.kind == SecureArtifactErrorKind::Missing => {}
        (PublicationMode::Published, Err(source)) => {
            finding(findings, "unreadable-stage3-publication-marker", source.to_string())
        }
        (PublicationMode::Staged, Ok(bytes)) if bytes == STAGE3_INCOMPLETE_MARKER_CONTENT => {}
        (PublicationMode::Staged, Ok(_)) => finding(
            findings,
            "invalid-stage3-publication-marker",
            "the staged publication marker has unexpected content",
        ),
        (PublicationMode::Staged, Err(source))
            if source.kind == SecureArtifactErrorKind::Missing =>
        {
            finding(
                findings,
                "missing-stage3-publication-marker",
                "staged publication validation requires the incomplete marker",
            )
        }
        (PublicationMode::Staged, Err(source)) => {
            finding(findings, "unreadable-stage3-publication-marker", source.to_string())
        }
    }
}

fn validate_bundle_artifact(
    root: &SecureArtifactRoot,
    expected_profile: Stage3Profile,
    bundle: &Stage3EvidenceBundle,
    findings: &mut Vec<Stage3ValidationFinding>,
) {
    let uri = expected_profile.evidence_file();
    let bytes = match root.read_regular(uri) {
        Ok(bytes) => bytes,
        Err(source) => {
            finding(findings, "invalid-stage3-bundle-artifact", format!("{uri}: {source}"));
            return;
        }
    };
    match serde_json::to_vec_pretty(bundle) {
        Ok(expected) if expected == bytes => {}
        Ok(_) => finding(
            findings,
            "noncanonical-stage3-bundle-artifact",
            format!("{uri} is not the canonical publisher encoding of the supplied bundle"),
        ),
        Err(source) => finding(
            findings,
            "unencodable-stage3-bundle",
            format!("cannot encode the supplied bundle: {source}"),
        ),
    }
    match parse_stage3_evidence_bundle_json(&bytes) {
        Ok(on_disk) if on_disk == *bundle => {}
        Ok(_) => finding(
            findings,
            "stage3-bundle-artifact-mismatch",
            format!("{uri} does not equal the bundle supplied to the verifier"),
        ),
        Err(source) => finding(findings, source.code, source.detail),
    }
}

fn validate_exact_artifact_set(
    artifact_root: &Path,
    expected_profile: Stage3Profile,
    bundle: &Stage3EvidenceBundle,
    mode: PublicationMode,
    findings: &mut Vec<Stage3ValidationFinding>,
) {
    let mut expected_files = BTreeSet::new();
    let mut expected_directories = BTreeSet::new();
    for uri in top_level_artifacts(bundle)
        .chain(bundle.cases.iter().flat_map(|case| case.artifacts.iter()))
        .map(|reference| reference.uri.as_str())
        .chain(std::iter::once(expected_profile.evidence_file()))
        .chain((mode == PublicationMode::Staged).then_some(STAGE3_INCOMPLETE_MARKER_FILE))
    {
        if safe_relative_uri(uri) {
            insert_expected_path(uri, &mut expected_files, &mut expected_directories);
        }
    }
    enumerate_exact_directory(artifact_root, "", &expected_files, &expected_directories, findings);
}

fn insert_expected_path(
    uri: &str,
    expected_files: &mut BTreeSet<String>,
    expected_directories: &mut BTreeSet<String>,
) {
    expected_files.insert(uri.to_owned());
    let mut parent = Path::new(uri).parent();
    while let Some(path) = parent {
        if path.as_os_str().is_empty() {
            break;
        }
        if let Some(path) = path.to_str() {
            expected_directories.insert(path.replace(std::path::MAIN_SEPARATOR, "/"));
        }
        parent = path.parent();
    }
}

fn enumerate_exact_directory(
    directory: &Path,
    relative: &str,
    expected_files: &BTreeSet<String>,
    expected_directories: &BTreeSet<String>,
    findings: &mut Vec<Stage3ValidationFinding>,
) {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(source) => {
            finding(
                findings,
                "unreadable-stage3-artifact-directory",
                format!("cannot enumerate {}: {source}", directory.display()),
            );
            return;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(source) => {
                finding(
                    findings,
                    "unreadable-stage3-artifact-directory-entry",
                    format!("cannot enumerate {}: {source}", directory.display()),
                );
                continue;
            }
        };
        let name = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(_) => {
                finding(
                    findings,
                    "non-utf8-stage3-artifact-entry",
                    format!("{} contains a non-UTF-8 entry", directory.display()),
                );
                continue;
            }
        };
        let uri = if relative.is_empty() { name } else { format!("{relative}/{name}") };
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(source) => {
                finding(
                    findings,
                    "unreadable-stage3-artifact-directory-entry",
                    format!("cannot inspect {}: {source}", entry.path().display()),
                );
                continue;
            }
        };
        if file_type.is_symlink() {
            finding(findings, "invalid-stage3-artifact-entry-type", format!("{uri} is a symlink"));
        } else if file_type.is_dir() {
            if expected_directories.contains(&uri) {
                enumerate_exact_directory(
                    &entry.path(),
                    &uri,
                    expected_files,
                    expected_directories,
                    findings,
                );
            } else {
                finding(
                    findings,
                    "unexpected-stage3-artifact-entry",
                    format!("unmanifested directory {uri}"),
                );
            }
        } else if file_type.is_file() {
            if !expected_files.contains(&uri) {
                finding(
                    findings,
                    "unexpected-stage3-artifact-entry",
                    format!("unmanifested file {uri}"),
                );
            }
        } else {
            finding(
                findings,
                "invalid-stage3-artifact-entry-type",
                format!("{uri} is neither a regular file nor a directory"),
            );
        }
    }
}

fn safe_relative_uri(uri: &str) -> bool {
    let path = Path::new(uri);
    !uri.is_empty()
        && !path.is_absolute()
        && path.components().all(|component| matches!(component, std::path::Component::Normal(_)))
}

fn validate_shape(
    expected_profile: Stage3Profile,
    bundle: &Stage3EvidenceBundle,
    findings: &mut Vec<Stage3ValidationFinding>,
) {
    if bundle.profile != expected_profile {
        finding(findings, "stage3-profile-mismatch", "bundle profile does not match the gate");
    }
    if bundle.schema_version != expected_profile.schema_version() {
        finding(findings, "stage3-schema-mismatch", "unexpected evidence schema version");
    }
    if bundle.claim_id != expected_profile.claim_id() {
        finding(findings, "stage3-claim-mismatch", "unexpected Stage 3 claim ID");
    }
    if bundle.bundle_id.is_empty() || bundle.finished_at_unix_ms < bundle.started_at_unix_ms {
        finding(findings, "invalid-stage3-run-identity", "bundle ID or timestamps are invalid");
    }

    let computed_registry = stage3_registry_sha256(expected_profile);
    if computed_registry != expected_profile.accepted_registry_sha256()
        || bundle.registry_sha256 != expected_profile.accepted_registry_sha256()
    {
        finding(
            findings,
            "stage3-registry-digest-mismatch",
            "bundle and compiled registry must equal the accepted catalog lock",
        );
    }
    validate_runtime(expected_profile, &bundle.runtime, findings);

    let definitions = expected_profile.cases();
    if bundle.cases.len() != definitions.len() {
        finding(
            findings,
            "stage3-case-count-mismatch",
            format!("expected {}, found {}", definitions.len(), bundle.cases.len()),
        );
    }
    for (index, definition) in definitions.iter().enumerate() {
        let Some(case) = bundle.cases.get(index) else { continue };
        if case.case_id != definition.id {
            finding(
                findings,
                "stage3-case-order-mismatch",
                format!("case {index} must be {}", definition.id),
            );
        }
        if case.terminal != definition.terminal {
            finding(
                findings,
                "stage3-terminal-mismatch",
                format!("{} has the wrong terminal disposition", case.case_id),
            );
        }
        if !case.passed {
            finding(findings, "stage3-case-failed", format!("{} did not pass", case.case_id));
        }
        validate_assertions(definition, case, findings);
        validate_case_facts(case, findings);
    }
}

fn validate_runtime(
    profile: Stage3Profile,
    runtime: &Stage3RuntimeScope,
    findings: &mut Vec<Stage3ValidationFinding>,
) {
    let expected_implementation = match profile {
        Stage3Profile::RegularFile => "visa_wasmtime_stage3a",
        Stage3Profile::LogicalRequest => "visa_wasmtime_stage3b",
    };
    for (role, identity) in [("source", &runtime.source), ("destination", &runtime.destination)] {
        if identity.implementation != expected_implementation
            || identity.implementation_version.is_empty()
            || identity.engine != "wasmtime"
            || identity.engine_version.is_empty()
        {
            finding(
                findings,
                "invalid-stage3-runtime-scope",
                format!("{role} is not the declared Wasmtime Stage 3 adapter"),
            );
        }
    }
    if runtime.host_os != "linux"
        || runtime.source_isa != "x86_64"
        || runtime.destination_isa != "x86_64"
        || runtime.substrate != "substrate_host::SqliteProvider"
        || runtime.execution_boundary
            != "same-process-distinct-wasmtime-store-and-provider-instance"
    {
        finding(
            findings,
            "invalid-stage3-target-scope",
            "Stage 3 evidence must remain scoped to Linux/x86_64, the SQLite host provider, and distinct in-process Wasmtime stores/provider instances",
        );
    }
    if runtime.independent_runtime_coverage {
        finding(
            findings,
            "stage3-runtime-overclaim",
            "the first Stage 3 gate cannot claim a qualified independent second runtime",
        );
    }
    if !runtime.unsupported_runtime_implementations.iter().any(|runtime| runtime == "wacogo") {
        finding(
            findings,
            "missing-stage3-runtime-limit",
            "Wacogo Stage 3 support must remain explicitly unsupported until separately qualified",
        );
    }
}

fn validate_assertions(
    definition: &Stage3CaseDefinition,
    case: &Stage3CaseEvidence,
    findings: &mut Vec<Stage3ValidationFinding>,
) {
    let expected = definition.required_assertions.iter().copied().collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    for assertion in &case.assertions {
        if !actual.insert(assertion.name.as_str()) {
            finding(
                findings,
                "duplicate-stage3-assertion",
                format!("{} repeats assertion {}", case.case_id, assertion.name),
            );
        }
        if !assertion.passed {
            finding(
                findings,
                "stage3-assertion-failed",
                format!("{} failed assertion {}", case.case_id, assertion.name),
            );
        }
    }
    if actual != expected {
        finding(
            findings,
            "stage3-assertion-set-mismatch",
            format!("{} does not carry the exact required assertions", case.case_id),
        );
    }
}

fn validate_case_facts(case: &Stage3CaseEvidence, findings: &mut Vec<Stage3ValidationFinding>) {
    for (label, digest) in
        [("before", &case.canonical_before_sha256), ("after", &case.canonical_after_sha256)]
    {
        if !is_lower_hex(digest, 64) {
            finding(
                findings,
                "invalid-stage3-canonical-digest",
                format!("{} has invalid {label} canonical digest", case.case_id),
            );
        }
    }
    if case.source_epoch == 0 {
        finding(
            findings,
            "invalid-stage3-source-epoch",
            format!("{} has a zero source epoch", case.case_id),
        );
    }
    match case.terminal {
        Stage3CaseTerminal::HandoffCommitted => {
            if case.destination_epoch != case.source_epoch.checked_add(1) {
                finding(
                    findings,
                    "invalid-stage3-destination-epoch",
                    format!("{} did not advance exactly one lease epoch", case.case_id),
                );
            }
        }
        Stage3CaseTerminal::HandoffBlocked | Stage3CaseTerminal::ProfileRejected => {
            if case.destination_epoch.is_some() {
                finding(
                    findings,
                    "unexpected-stage3-destination-epoch",
                    format!("{} published a destination epoch", case.case_id),
                );
            }
        }
    }
    if case.profile_operations.iter().any(|operation| !is_lower_hex(operation, 32)) {
        finding(
            findings,
            "invalid-stage3-operation-id",
            format!("{} has a noncanonical operation ID", case.case_id),
        );
    }
    if case.artifacts.is_empty() {
        finding(
            findings,
            "missing-stage3-case-artifacts",
            format!("{} has no retained raw evidence", case.case_id),
        );
    }
}

fn top_level_artifacts(
    bundle: &Stage3EvidenceBundle,
) -> impl Iterator<Item = &Stage3ArtifactReference> {
    [&bundle.component, &bundle.wit_world, &bundle.profile_manifest, &bundle.configuration]
        .into_iter()
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn finding(
    findings: &mut Vec<Stage3ValidationFinding>,
    code: impl Into<String>,
    detail: impl Into<String>,
) {
    findings.push(Stage3ValidationFinding { code: code.into(), detail: detail.into() });
}

fn report(findings: Vec<Stage3ValidationFinding>) -> Stage3ValidationReport {
    Stage3ValidationReport { ok: findings.is_empty(), findings }
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;

    static NEXT_TEST_ROOT: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn registry_locks_match_the_compiled_catalogs() {
        assert_eq!(
            stage3_registry_sha256(Stage3Profile::RegularFile),
            STAGE3A_ACCEPTED_REGISTRY_SHA256
        );
        assert_eq!(
            stage3_registry_sha256(Stage3Profile::LogicalRequest),
            STAGE3B_ACCEPTED_REGISTRY_SHA256
        );
    }

    #[test]
    fn case_catalogs_are_unique_and_nonempty() {
        for profile in [Stage3Profile::RegularFile, Stage3Profile::LogicalRequest] {
            let mut cases = BTreeSet::new();
            for definition in profile.cases() {
                assert!(cases.insert(definition.id));
                assert!(!definition.required_assertions.is_empty());
                let assertions =
                    definition.required_assertions.iter().copied().collect::<BTreeSet<_>>();
                assert_eq!(assertions.len(), definition.required_assertions.len());
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn exact_set_rejects_unmanifested_files_and_directories() {
        let root = test_root("exact-set");
        let bundle = published_test_bundle(&root, Stage3Profile::RegularFile);
        assert!(validate_stage3_evidence_bundle(Stage3Profile::RegularFile, &bundle, &root).ok);

        fs::write(root.join("surprise.bin"), b"not manifest").unwrap();
        let report = validate_stage3_evidence_bundle(Stage3Profile::RegularFile, &bundle, &root);
        assert_has_code(&report, "unexpected-stage3-artifact-entry");
        fs::remove_file(root.join("surprise.bin")).unwrap();

        fs::create_dir(root.join("unexpected-work-tree")).unwrap();
        let report = validate_stage3_evidence_bundle(Stage3Profile::RegularFile, &bundle, &root);
        assert_has_code(&report, "unexpected-stage3-artifact-entry");
        fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn publication_marker_is_a_private_commit_guard() {
        let root = test_root("marker");
        let bundle = published_test_bundle(&root, Stage3Profile::LogicalRequest);
        fs::write(root.join(STAGE3_INCOMPLETE_MARKER_FILE), STAGE3_INCOMPLETE_MARKER_CONTENT)
            .unwrap();

        assert!(
            validate_stage3_evidence_bundle_for_publication(
                Stage3Profile::LogicalRequest,
                &bundle,
                &root,
            )
            .ok
        );
        let public = validate_stage3_evidence_bundle(Stage3Profile::LogicalRequest, &bundle, &root);
        assert_has_code(&public, "incomplete-stage3-publication");

        fs::remove_file(root.join(STAGE3_INCOMPLETE_MARKER_FILE)).unwrap();
        assert!(validate_stage3_evidence_bundle(Stage3Profile::LogicalRequest, &bundle, &root).ok);
        fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gate_requires_input_bytes_to_match_the_root_bundle() {
        let root = test_root("bundle-bytes");
        let bundle = published_test_bundle(&root, Stage3Profile::RegularFile);
        let differently_formatted = serde_json::to_vec(&bundle).unwrap();
        let result = gate_stage3_evidence_bundle_json_with_artifacts(
            Stage3Profile::RegularFile,
            &differently_formatted,
            &root,
        );
        assert!(!result.ok);
        assert_has_code(
            result.validation.as_ref().expect("validation report"),
            "stage3-gate-bundle-bytes-mismatch",
        );
        fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(target_os = "linux")]
    fn published_test_bundle(root: &Path, profile: Stage3Profile) -> Stage3EvidenceBundle {
        fs::create_dir_all(root).unwrap();
        let component = write_test_artifact(root, "inputs/component.wasm", b"component");
        let wit_world = write_test_artifact(root, "inputs/world.wit", b"world");
        let profile_manifest = write_test_artifact(root, "inputs/profile.json", b"profile");
        let configuration = write_test_artifact(root, "inputs/configuration.json", b"config");
        let cases = profile
            .cases()
            .iter()
            .map(|definition| Stage3CaseEvidence {
                case_id: definition.id.to_owned(),
                terminal: definition.terminal,
                passed: true,
                assertions: definition
                    .required_assertions
                    .iter()
                    .map(|name| Stage3Assertion { name: (*name).to_owned(), passed: true })
                    .collect(),
                canonical_before_sha256: "a".repeat(64),
                canonical_after_sha256: "b".repeat(64),
                source_epoch: 1,
                destination_epoch: (definition.terminal == Stage3CaseTerminal::HandoffCommitted)
                    .then_some(2),
                profile_operations: vec!["c".repeat(32)],
                artifacts: vec![write_test_artifact(
                    root,
                    &format!("cases/{}/evidence/trace.json", definition.id),
                    definition.id.as_bytes(),
                )],
            })
            .collect();
        let implementation = match profile {
            Stage3Profile::RegularFile => "visa_wasmtime_stage3a",
            Stage3Profile::LogicalRequest => "visa_wasmtime_stage3b",
        };
        let identity = Stage3RuntimeIdentity {
            implementation: implementation.to_owned(),
            implementation_version: "test".to_owned(),
            engine: "wasmtime".to_owned(),
            engine_version: "test".to_owned(),
        };
        let bundle = Stage3EvidenceBundle {
            schema_version: profile.schema_version().to_owned(),
            profile,
            claim_id: profile.claim_id().to_owned(),
            bundle_id: "stage3-test-bundle".to_owned(),
            started_at_unix_ms: 1,
            finished_at_unix_ms: 2,
            registry_sha256: profile.accepted_registry_sha256().to_owned(),
            component,
            wit_world,
            profile_manifest,
            configuration,
            runtime: Stage3RuntimeScope {
                source: identity.clone(),
                destination: identity,
                host_os: "linux".to_owned(),
                source_isa: "x86_64".to_owned(),
                destination_isa: "x86_64".to_owned(),
                substrate: "substrate_host::SqliteProvider".to_owned(),
                execution_boundary: "same-process-distinct-wasmtime-store-and-provider-instance"
                    .to_owned(),
                independent_runtime_coverage: false,
                unsupported_runtime_implementations: vec!["wacogo".to_owned()],
            },
            cases,
        };
        fs::write(root.join(profile.evidence_file()), serde_json::to_vec_pretty(&bundle).unwrap())
            .unwrap();
        bundle
    }

    #[cfg(target_os = "linux")]
    fn write_test_artifact(root: &Path, uri: &str, bytes: &[u8]) -> Stage3ArtifactReference {
        let path = root.join(uri);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
        Stage3ArtifactReference {
            uri: uri.to_owned(),
            sha256: sha256_hex(bytes),
            size: bytes.len() as u64,
        }
    }

    #[cfg(target_os = "linux")]
    fn test_root(label: &str) -> PathBuf {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let nonce = NEXT_TEST_ROOT.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir()
            .join(format!("visa-stage3-{label}-{}-{now}-{nonce}", std::process::id()))
    }

    #[cfg(target_os = "linux")]
    fn assert_has_code(report: &Stage3ValidationReport, code: &str) {
        assert!(
            report.findings.iter().any(|finding| finding.code == code),
            "missing {code}: {report:#?}"
        );
    }
}
