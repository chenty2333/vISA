use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use contract_core::Digest;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use visa_component_adapter::RuntimeIdentity;
use visa_conformance::{
    STAGE3_INCOMPLETE_MARKER_CONTENT, STAGE3_INCOMPLETE_MARKER_FILE, Stage3ArtifactReference,
    Stage3Assertion, Stage3CaseDefinition, Stage3CaseEvidence, Stage3CaseTerminal,
    Stage3EvidenceBundle, Stage3Profile, Stage3RuntimeIdentity, Stage3RuntimeScope,
    stage3_registry_sha256, validate_stage3_evidence_bundle_for_publication,
};

use crate::component;

static NEXT_STAGE3_TEMP_FILE: AtomicU64 = AtomicU64::new(1);

pub struct Stage3CaseCapture {
    pub definition: &'static Stage3CaseDefinition,
    pub canonical_before: Digest,
    pub canonical_after: Digest,
    pub source_epoch: u64,
    pub destination_epoch: Option<u64>,
    pub profile_operations: Vec<String>,
    pub assertions: Vec<(String, bool)>,
    pub trace: serde_json::Value,
    pub file_before: Vec<u8>,
    pub file_after: Vec<u8>,
}

pub struct Stage3bCaseCapture {
    pub definition: &'static Stage3CaseDefinition,
    pub canonical_before: Digest,
    pub canonical_after: Digest,
    pub source_epoch: u64,
    pub destination_epoch: Option<u64>,
    pub profile_operations: Vec<String>,
    pub assertions: Vec<(String, bool)>,
    pub trace: serde_json::Value,
    pub request: Vec<u8>,
    pub delivered_response: Vec<u8>,
}

impl Stage3CaseCapture {
    pub fn passed(&self) -> bool {
        self.assertions.iter().all(|(_, passed)| *passed)
            && self
                .definition
                .required_assertions
                .iter()
                .copied()
                .eq(self.assertions.iter().map(|(name, _)| name.as_str()))
    }
}

impl Stage3bCaseCapture {
    pub fn passed(&self) -> bool {
        self.assertions.iter().all(|(_, passed)| *passed)
            && self
                .definition
                .required_assertions
                .iter()
                .copied()
                .eq(self.assertions.iter().map(|(name, _)| name.as_str()))
    }
}

pub fn create_incomplete_marker(root: &Path) -> Result<(), String> {
    fs::create_dir_all(root)
        .map_err(|error| format!("cannot create {}: {error}", root.display()))?;
    let entries = fs::read_dir(root)
        .map_err(|error| {
            format!("cannot enumerate Stage 3 artifact root {}: {error}", root.display())
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            format!("cannot enumerate Stage 3 artifact root {}: {error}", root.display())
        })?;
    if !entries.is_empty() {
        let names = entries
            .iter()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect::<BTreeSet<_>>();
        return Err(format!(
            "Stage 3 artifact root {} must be empty (found {})",
            root.display(),
            names.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    publish_atomic(root, STAGE3_INCOMPLETE_MARKER_FILE, STAGE3_INCOMPLETE_MARKER_CONTENT)
}

pub fn publish_stage3a(
    root: &Path,
    started_at_unix_ms: u64,
    finished_at_unix_ms: u64,
    runtime: RuntimeIdentity,
    profile_manifest: &impl Serialize,
    configuration: &impl Serialize,
    captures: &[Stage3CaseCapture],
) -> Result<PathBuf, String> {
    let profile = Stage3Profile::RegularFile;
    if captures.len() != profile.cases().len()
        || !captures
            .iter()
            .zip(profile.cases())
            .all(|(capture, definition)| capture.definition.id == definition.id)
    {
        return Err("Stage 3A captures do not match the accepted registry".to_owned());
    }

    let component = write_artifact(
        root,
        "inputs/stage3-file-component.component.wasm",
        component::stage3a_bytes(),
    )?;
    let wit_world = write_artifact(
        root,
        "inputs/regular-file-continuity.wit",
        include_bytes!("../../../../wit/regular-file-continuity/world.wit"),
    )?;
    let profile_manifest =
        write_json_artifact(root, "inputs/regular-file-profile.json", profile_manifest)?;
    let configuration =
        write_json_artifact(root, "inputs/stage3a-configuration.json", configuration)?;

    let mut cases = Vec::with_capacity(captures.len());
    for capture in captures {
        let prefix = format!("cases/{}/evidence", capture.definition.id);
        let trace = write_json_artifact(root, &format!("{prefix}/trace.json"), &capture.trace)?;
        let before =
            write_artifact(root, &format!("{prefix}/file-before.bin"), &capture.file_before)?;
        let after = write_artifact(root, &format!("{prefix}/file-after.bin"), &capture.file_after)?;
        cases.push(Stage3CaseEvidence {
            case_id: capture.definition.id.to_owned(),
            terminal: capture.definition.terminal,
            passed: capture.passed(),
            assertions: capture
                .assertions
                .iter()
                .map(|(name, passed)| Stage3Assertion { name: name.clone(), passed: *passed })
                .collect(),
            canonical_before_sha256: digest_hex(capture.canonical_before),
            canonical_after_sha256: digest_hex(capture.canonical_after),
            source_epoch: capture.source_epoch,
            destination_epoch: capture.destination_epoch,
            profile_operations: capture.profile_operations.clone(),
            artifacts: vec![trace, before, after],
        });
    }

    let registry_sha256 = stage3_registry_sha256(profile);
    let bundle_fingerprint = serde_json::to_vec(&(
        profile,
        &registry_sha256,
        started_at_unix_ms,
        finished_at_unix_ms,
        &cases,
    ))
    .map_err(|error| format!("cannot encode Stage 3A fingerprint: {error}"))?;
    let bundle = Stage3EvidenceBundle {
        schema_version: profile.schema_version().to_owned(),
        profile,
        claim_id: profile.claim_id().to_owned(),
        bundle_id: format!("stage3a-{}", &sha256_hex(&bundle_fingerprint)[..24]),
        started_at_unix_ms,
        finished_at_unix_ms,
        registry_sha256,
        component,
        wit_world,
        profile_manifest,
        configuration,
        runtime: Stage3RuntimeScope {
            source: runtime_identity(&runtime),
            destination: runtime_identity(&runtime),
            host_os: std::env::consts::OS.to_owned(),
            source_isa: std::env::consts::ARCH.to_owned(),
            destination_isa: std::env::consts::ARCH.to_owned(),
            substrate: "substrate_host::SqliteProvider".to_owned(),
            execution_boundary: "same-process-distinct-wasmtime-store-and-provider-instance"
                .to_owned(),
            independent_runtime_coverage: false,
            unsupported_runtime_implementations: vec!["wacogo".to_owned()],
        },
        cases,
    };

    publish_bundle(root, profile, &bundle, "Stage 3A")
}

pub fn publish_stage3b(
    root: &Path,
    started_at_unix_ms: u64,
    finished_at_unix_ms: u64,
    runtime: RuntimeIdentity,
    profile_manifest: &impl Serialize,
    configuration: &impl Serialize,
    captures: &[Stage3bCaseCapture],
) -> Result<PathBuf, String> {
    let profile = Stage3Profile::LogicalRequest;
    if captures.len() != profile.cases().len()
        || !captures
            .iter()
            .zip(profile.cases())
            .all(|(capture, definition)| capture.definition.id == definition.id)
    {
        return Err("Stage 3B captures do not match the accepted registry".to_owned());
    }

    let component = write_artifact(
        root,
        "inputs/stage3-request-component.component.wasm",
        component::stage3b_bytes(),
    )?;
    let wit_world = write_artifact(
        root,
        "inputs/logical-request-continuity.wit",
        include_bytes!("../../../../wit/logical-request-continuity/world.wit"),
    )?;
    let profile_manifest =
        write_json_artifact(root, "inputs/logical-request-profile.json", profile_manifest)?;
    let configuration =
        write_json_artifact(root, "inputs/stage3b-configuration.json", configuration)?;

    let mut cases = Vec::with_capacity(captures.len());
    for capture in captures {
        let prefix = format!("cases/{}/evidence", capture.definition.id);
        let trace = write_json_artifact(root, &format!("{prefix}/trace.json"), &capture.trace)?;
        let request = write_artifact(root, &format!("{prefix}/request.bin"), &capture.request)?;
        let response = write_artifact(
            root,
            &format!("{prefix}/delivered-response.bin"),
            &capture.delivered_response,
        )?;
        cases.push(Stage3CaseEvidence {
            case_id: capture.definition.id.to_owned(),
            terminal: capture.definition.terminal,
            passed: capture.passed(),
            assertions: capture
                .assertions
                .iter()
                .map(|(name, passed)| Stage3Assertion { name: name.clone(), passed: *passed })
                .collect(),
            canonical_before_sha256: digest_hex(capture.canonical_before),
            canonical_after_sha256: digest_hex(capture.canonical_after),
            source_epoch: capture.source_epoch,
            destination_epoch: capture.destination_epoch,
            profile_operations: capture.profile_operations.clone(),
            artifacts: vec![trace, request, response],
        });
    }

    let registry_sha256 = stage3_registry_sha256(profile);
    let fingerprint = serde_json::to_vec(&(
        profile,
        &registry_sha256,
        started_at_unix_ms,
        finished_at_unix_ms,
        &cases,
    ))
    .map_err(|error| format!("cannot encode Stage 3B fingerprint: {error}"))?;
    let bundle = Stage3EvidenceBundle {
        schema_version: profile.schema_version().to_owned(),
        profile,
        claim_id: profile.claim_id().to_owned(),
        bundle_id: format!("stage3b-{}", &sha256_hex(&fingerprint)[..24]),
        started_at_unix_ms,
        finished_at_unix_ms,
        registry_sha256,
        component,
        wit_world,
        profile_manifest,
        configuration,
        runtime: Stage3RuntimeScope {
            source: runtime_identity(&runtime),
            destination: runtime_identity(&runtime),
            host_os: std::env::consts::OS.to_owned(),
            source_isa: std::env::consts::ARCH.to_owned(),
            destination_isa: std::env::consts::ARCH.to_owned(),
            substrate: "substrate_host::SqliteProvider".to_owned(),
            execution_boundary: "same-process-distinct-wasmtime-store-and-provider-instance"
                .to_owned(),
            independent_runtime_coverage: false,
            unsupported_runtime_implementations: vec!["wacogo".to_owned()],
        },
        cases,
    };

    publish_bundle(root, profile, &bundle, "Stage 3B")
}

fn publish_bundle(
    root: &Path,
    profile: Stage3Profile,
    bundle: &Stage3EvidenceBundle,
    label: &str,
) -> Result<PathBuf, String> {
    let bytes = serde_json::to_vec_pretty(bundle)
        .map_err(|error| format!("cannot encode {label} bundle: {error}"))?;
    publish_atomic(root, profile.evidence_file(), &bytes)?;

    // The marker remains the publication commit guard while the final bundle,
    // its exact file set, and every referenced digest are independently checked.
    let validation = validate_stage3_evidence_bundle_for_publication(profile, bundle, root);
    if !validation.ok {
        let detail = serde_json::to_string_pretty(&validation)
            .unwrap_or_else(|_| format!("{:?}", validation.findings));
        return Err(format!("{label} prepublication verification failed: {detail}"));
    }

    let marker = root.join(STAGE3_INCOMPLETE_MARKER_FILE);
    fs::remove_file(&marker)
        .map_err(|error| format!("cannot remove {}: {error}", marker.display()))?;
    if let Err(error) = sync_directory(root) {
        let _ =
            publish_atomic(root, STAGE3_INCOMPLETE_MARKER_FILE, STAGE3_INCOMPLETE_MARKER_CONTENT);
        return Err(format!("cannot commit {label} publication: {error}"));
    }
    Ok(root.join(profile.evidence_file()))
}

fn write_json_artifact(
    root: &Path,
    uri: &str,
    value: &impl Serialize,
) -> Result<Stage3ArtifactReference, String> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("cannot encode {uri}: {error}"))?;
    write_artifact(root, uri, &bytes)
}

fn write_artifact(root: &Path, uri: &str, bytes: &[u8]) -> Result<Stage3ArtifactReference, String> {
    if uri.starts_with('/')
        || uri
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(format!("unsafe Stage 3 artifact URI {uri:?}"));
    }
    let path = root.join(uri);
    let parent = path.parent().ok_or_else(|| format!("artifact {uri} has no parent"))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    publish_atomic(root, uri, bytes)?;
    Ok(Stage3ArtifactReference {
        uri: uri.to_owned(),
        sha256: sha256_hex(bytes),
        size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
    })
}

fn publish_atomic(root: &Path, uri: &str, bytes: &[u8]) -> Result<(), String> {
    if !safe_relative_uri(uri) {
        return Err(format!("unsafe Stage 3 publication URI {uri:?}"));
    }
    reject_existing_symlink_components(root, uri)?;
    let destination = root.join(uri);
    let parent = destination.parent().ok_or_else(|| format!("artifact {uri} has no parent"))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    reject_existing_symlink_components(root, uri)?;

    let file_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("artifact {uri} has no UTF-8 file name"))?;
    let nonce = NEXT_STAGE3_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(".{file_name}.{}.{}.tmp", std::process::id(), nonce));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| format!("cannot create {}: {error}", temporary.display()))?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&temporary);
        return Err(format!("cannot write {}: {error}", temporary.display()));
    }
    drop(file);

    if let Err(error) = fs::hard_link(&temporary, &destination) {
        let _ = fs::remove_file(&temporary);
        return Err(if error.kind() == std::io::ErrorKind::AlreadyExists {
            format!("Stage 3 publication target already exists: {}", destination.display())
        } else {
            format!("cannot publish {} as {}: {error}", temporary.display(), destination.display())
        });
    }
    if let Err(error) = fs::remove_file(&temporary) {
        return Err(format!("cannot remove {}: {error}", temporary.display()));
    }
    sync_directory(parent)
}

fn safe_relative_uri(uri: &str) -> bool {
    let path = Path::new(uri);
    !uri.is_empty()
        && !path.is_absolute()
        && path.components().all(|component| matches!(component, Component::Normal(_)))
}

fn reject_existing_symlink_components(root: &Path, uri: &str) -> Result<(), String> {
    let mut prefix = root.to_path_buf();
    for component in Path::new(uri).components() {
        let Component::Normal(component) = component else { unreachable!() };
        prefix.push(component);
        match fs::symlink_metadata(&prefix) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!(
                    "Stage 3 publication path contains symlink component {}",
                    prefix.display()
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => {
                return Err(format!("cannot inspect {}: {error}", prefix.display()));
            }
        }
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), String> {
    let directory = fs::File::open(path).map_err(|error| {
        format!("cannot open publication directory {}: {error}", path.display())
    })?;
    directory
        .sync_all()
        .map_err(|error| format!("cannot sync publication directory {}: {error}", path.display()))
}

fn runtime_identity(identity: &RuntimeIdentity) -> Stage3RuntimeIdentity {
    Stage3RuntimeIdentity {
        implementation: identity.implementation.clone(),
        implementation_version: identity.implementation_version.clone(),
        engine: identity.engine.clone(),
        engine_version: identity.engine_version.clone(),
    }
}

fn digest_hex(digest: Digest) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in digest.0 {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn terminal_name(terminal: Stage3CaseTerminal) -> &'static str {
    match terminal {
        Stage3CaseTerminal::HandoffCommitted => "handoff_committed",
        Stage3CaseTerminal::HandoffBlocked => "handoff_blocked",
        Stage3CaseTerminal::ProfileRejected => "profile_rejected",
    }
}
