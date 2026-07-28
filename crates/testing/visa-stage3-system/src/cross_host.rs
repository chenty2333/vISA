use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use contract_core::{
    AuthorityGrant, Digest, EvidenceKind, EvidenceRef, ExtensionSupport, IdempotencyKey, Rights,
    SchemaVersion, SnapshotEnvelope,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use substrate_api::{AuthorityPolicy, AuthorityPort, JournalScope, LeasePort, LeaseRecord};
use substrate_host::SqliteProvider;
use visa_component_adapter::{
    PortableRegularFileState, RegularFileWorkloadPhase, RuntimeIdentity, parse_identity,
};
use visa_profile::{
    REGULAR_FILE_EXTENSION_ID, REGULAR_FILE_EXTENSION_VERSION, RegularFileOperation,
    RegularFileResult, RegularFileState, regular_file_state,
};
use visa_runtime::{
    AuthorityPlan, Coordinator, ProfileAuthorityPlan, SnapshotExpectations, ValidatedSnapshot,
    canonical_digest, validate_snapshot,
};

use crate::{
    component,
    fixture::{
        FixtureIds, INITIAL_LEASE_EPOCH, Stage3aFixture, Stage3aFixtureOptions, derive_identity,
        key_value_rights, profile_rights, stage3a_profile, timer_rights,
    },
    regular_file_runtime::{MatrixRegularFileAdapter, RegularFileRuntimeKind},
};

pub const CROSS_HOST_EVIDENCE_FILE: &str = "stage3a-cross-host-evidence.json";
pub const CROSS_HOST_CELL_ID: &str = "s3a.supporting.cross-host.wasmtime.regular-file";

const CASE_ID: &str = "cross-host-read-write-offset";
const SOURCE_SCHEMA: &str = "visa.stage3a-cross-host-source-bundle.v1";
const HELLO_SCHEMA: &str = "visa.stage3a-cross-host-endpoint-hello.v1";
const TOKEN_SCHEMA: &str = "visa.stage3a-cross-host-activation-token.v1";
const REQUEST_SCHEMA: &str = "visa.stage3a-cross-host-destination-request.v1";
const RECEIPT_SCHEMA: &str = "visa.stage3a-cross-host-destination-receipt.v1";
const EVIDENCE_SCHEMA: &str = "visa.stage3a-cross-host-evidence.v1";
const CLAIM_CLASS: &str = "bounded-supporting-cell";
const INCOMPLETE_MARKER: &str = ".stage3a-cross-host-incomplete";
const INCOMPLETE_CONTENT: &[u8] = b"incomplete\n";
const INITIAL_CONTENT: &[u8] = b"0123456789";
const SOURCE_READ_PREFIX: &[u8] = b"012";
const SOURCE_WRITE: &[u8] = b"XY";
const TRANSFERRED_CONTENT: &[u8] = b"012XY56789";
const DESTINATION_SUFFIX: &[u8] = b"56789";
const HANDOFF_OFFSET: u64 = 5;
const FINAL_OFFSET: u64 = 10;
const MAX_WIRE_BYTES: u64 = 4 * 1024 * 1024;
const NON_CLAIMS: &[&str] = &[
    "distributed-source-fencing",
    "crash-or-reboot-survival",
    "cryptographic-controller-authority",
    "cross-isa-execution",
    "arbitrary-filesystem-objects",
    "production-migration-service",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostIdentity {
    pub endpoint_id_sha256: String,
    pub hostname: String,
    pub os_release: String,
    pub kernel_release: String,
    pub isa: String,
    pub executable_sha256: String,
    pub executable_size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeIdentityEvidence {
    pub implementation: String,
    pub implementation_version: String,
    pub engine: String,
    pub engine_version: String,
}

impl From<RuntimeIdentity> for RuntimeIdentityEvidence {
    fn from(value: RuntimeIdentity) -> Self {
        Self {
            implementation: value.implementation,
            implementation_version: value.implementation_version,
            engine: value.engine,
            engine_version: value.engine_version,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObjectKind {
    SnapshotEnvelope,
    PortableRegularFileState,
    RegularFileImage,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportObject {
    pub kind: ObjectKind,
    pub sha256: String,
    pub size: u64,
    pub bytes: Vec<u8>,
}

impl TransportObject {
    fn new(kind: ObjectKind, bytes: Vec<u8>) -> Result<Self, String> {
        let size = u64::try_from(bytes.len()).map_err(|_| "transport object is too large")?;
        Ok(Self { kind, sha256: sha256_hex(&bytes), size, bytes })
    }

    fn uri(&self) -> String {
        format!("objects/sha256/{}", self.sha256)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBundle {
    pub schema_version: String,
    pub cell_id: String,
    pub case_id: String,
    pub claim_class: String,
    pub started_at_unix_ms: u64,
    pub finished_at_unix_ms: u64,
    pub host: HostIdentity,
    pub runtime: RuntimeIdentityEvidence,
    pub component_sha256: String,
    pub profile_sha256: String,
    pub canonical_after_export_sha256: String,
    pub source_operation_ids: Vec<String>,
    pub source_read_prefix_sha256: String,
    pub handoff_logical_offset: u64,
    pub runtime_shutdown_clean: bool,
    pub source_database_transferred: bool,
    pub objects: Vec<TransportObject>,
    pub explicit_non_claims: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointHello {
    pub schema_version: String,
    pub cell_id: String,
    pub host: HostIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationTokenPayload {
    pub schema_version: String,
    pub cell_id: String,
    pub issued_at_unix_ms: u64,
    pub source_bundle_sha256: String,
    pub source_endpoint_id_sha256: String,
    pub source_executable_sha256: String,
    pub source_process_exit_observed: bool,
    pub source_process_exit_code: i32,
    pub destination_endpoint_id_sha256: String,
    pub destination_executable_sha256: String,
    pub cryptographic_authority: bool,
    pub distributed_fencing_claim: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationToken {
    pub payload: ActivationTokenPayload,
    pub token_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationRequest {
    pub schema_version: String,
    pub source: SourceBundle,
    pub activation: ActivationToken,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedAssertion {
    pub name: String,
    pub passed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationReceipt {
    pub schema_version: String,
    pub cell_id: String,
    pub source_bundle_sha256: String,
    pub activation_token_sha256: String,
    pub started_at_unix_ms: u64,
    pub finished_at_unix_ms: u64,
    pub host: HostIdentity,
    pub runtime: RuntimeIdentityEvidence,
    pub canonical_before_prepare_sha256: String,
    pub canonical_after_read_sha256: String,
    pub destination_epoch: u64,
    pub resumed_logical_offset: u64,
    pub read_suffix_sha256: String,
    pub destination_file_sha256: String,
    pub destination_database_created_after_preflight: bool,
    pub destination_file_root_created_after_preflight: bool,
    pub source_database_transferred: bool,
    pub activation_token_cryptographic: bool,
    pub distributed_fencing_claim: bool,
    pub authority_scope: String,
    pub runtime_shutdown_clean: bool,
    pub assertions: Vec<NamedAssertion>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactReference {
    pub uri: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityBoundary {
    pub source_exit_observed_before_activation_token: bool,
    pub token_is_cryptographic_authority: bool,
    pub source_process_remains_stopped_assumption: bool,
    pub destination_lease_transition_is_local: bool,
    pub distributed_fencing_claim: bool,
    pub statement: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossHostEvidenceBundle {
    pub schema_version: String,
    pub cell_id: String,
    pub claim_class: String,
    pub started_at_unix_ms: u64,
    pub finished_at_unix_ms: u64,
    pub topology: String,
    pub transport: String,
    pub source_bundle_sha256: String,
    pub activation_token_sha256: String,
    pub source: HostIdentity,
    pub destination: HostIdentity,
    pub source_runtime: RuntimeIdentityEvidence,
    pub destination_runtime: RuntimeIdentityEvidence,
    pub authority_boundary: AuthorityBoundary,
    pub assertions: Vec<NamedAssertion>,
    pub artifacts: Vec<ArtifactReference>,
    pub explicit_non_claims: Vec<String>,
}

struct ValidatedSource {
    snapshot: SnapshotEnvelope,
    validated_snapshot: ValidatedSnapshot,
    portable: PortableRegularFileState,
    regular_file: RegularFileState,
    file_image: Vec<u8>,
}

pub fn endpoint_hello() -> Result<EndpointHello, String> {
    Ok(EndpointHello {
        schema_version: HELLO_SCHEMA.to_owned(),
        cell_id: CROSS_HOST_CELL_ID.to_owned(),
        host: host_identity()?,
    })
}

pub fn run_source_role(work_root: &Path) -> Result<SourceBundle, String> {
    ensure_absent(work_root, "source work root")?;
    let started_at_unix_ms = now_unix_ms()?;
    let host = host_identity()?;
    let fixture = Stage3aFixture::create(
        work_root,
        CASE_ID,
        INITIAL_CONTENT,
        Stage3aFixtureOptions::standard(),
    )?;
    let Stage3aFixture { paths, ids, source_state, profile_digest, source, destination, .. } =
        fixture;
    drop(destination);

    let mut coordinator = Coordinator::recover(source_state, source).map_err(runtime_error)?;
    coordinator
        .activate(
            derive_identity(CASE_ID, "activate"),
            ids.source_handoff_authority,
            INITIAL_LEASE_EPOCH,
        )
        .map_err(runtime_error)?;
    let mut source = MatrixRegularFileAdapter::instantiate(
        RegularFileRuntimeKind::Wasmtime,
        component::stage3a_bytes(),
        coordinator,
    )
    .map_err(adapter_error)?;
    source.activate(format!("{CASE_ID}:session")).map_err(adapter_error)?;

    let mut source_operation_ids = Vec::new();
    let read = source
        .execute(
            RegularFileOperation::Read {
                max_bytes: u32::try_from(SOURCE_READ_PREFIX.len())
                    .map_err(|_| "source read bound does not fit u32")?,
            },
            None,
        )
        .map_err(adapter_error)?;
    source_operation_ids.push(read.operation_id.clone());
    if !matches!(
        read.result,
        RegularFileResult::Read { ref bytes, logical_offset, .. }
            if bytes == SOURCE_READ_PREFIX && logical_offset == SOURCE_READ_PREFIX.len() as u64
    ) {
        return Err("source did not read the fixed prefix before handoff".to_owned());
    }
    let write = source
        .execute(
            RegularFileOperation::Write {
                bytes: SOURCE_WRITE.to_vec(),
                durability: visa_profile::FileDurability::Visible,
            },
            Some("cross-host-source-write"),
        )
        .map_err(adapter_error)?;
    source_operation_ids.push(write.operation_id.clone());
    if !matches!(write.result, RegularFileResult::Mutated { logical_offset: HANDOFF_OFFSET, .. }) {
        return Err("source write did not advance to the fixed handoff offset".to_owned());
    }

    source
        .coordinator_mut()
        .begin_quiesce(
            derive_identity(CASE_ID, "source-begin-quiesce"),
            ids.source_handoff_authority,
        )
        .map_err(runtime_error)?;
    let safe_point = source.coordinator_mut().prepare_safe_point().map_err(runtime_error)?;
    let portable = source.freeze().map_err(adapter_error)?;
    source
        .coordinator_mut()
        .commit_safe_point(
            derive_identity(CASE_ID, "source-freeze"),
            portable.as_bytes().to_vec(),
            safe_point,
        )
        .map_err(runtime_error)?;
    let evidence = EvidenceRef {
        identity: derive_identity(CASE_ID, "snapshot-evidence"),
        kind: EvidenceKind::SnapshotIntegrity,
        digest: source.coordinator().state_digest().map_err(runtime_error)?,
    };
    let (_, snapshot) = source
        .coordinator_mut()
        .export_snapshot(
            derive_identity(CASE_ID, "source-export"),
            ids.handoff,
            ids.snapshot,
            evidence,
        )
        .map_err(runtime_error)?;
    let canonical_after_export = source.coordinator().state_digest().map_err(runtime_error)?;
    let regular_file = canonical_regular_file(source.coordinator().state())?;
    let file_image = fs::read(&paths.file_path)
        .map_err(|error| format!("cannot read source file image: {error}"))?;
    validate_fixed_handoff_state(&regular_file, &file_image, &portable)?;
    if snapshot.body.portable_state != portable.as_bytes() {
        return Err("snapshot portable state differs from the frozen component state".to_owned());
    }

    let runtime = RuntimeIdentityEvidence::from(source.runtime_identity());
    source.shutdown().map_err(adapter_error)?;
    let objects = vec![
        TransportObject::new(
            ObjectKind::SnapshotEnvelope,
            serde_json::to_vec(&snapshot)
                .map_err(|error| format!("cannot encode snapshot envelope: {error}"))?,
        )?,
        TransportObject::new(ObjectKind::PortableRegularFileState, portable.into_bytes())?,
        TransportObject::new(ObjectKind::RegularFileImage, file_image)?,
    ];
    let finished_at_unix_ms = now_unix_ms()?;
    Ok(SourceBundle {
        schema_version: SOURCE_SCHEMA.to_owned(),
        cell_id: CROSS_HOST_CELL_ID.to_owned(),
        case_id: CASE_ID.to_owned(),
        claim_class: CLAIM_CLASS.to_owned(),
        started_at_unix_ms,
        finished_at_unix_ms,
        host,
        runtime,
        component_sha256: digest_hex(component::stage3a_digest()),
        profile_sha256: digest_hex(profile_digest),
        canonical_after_export_sha256: digest_hex(canonical_after_export),
        source_operation_ids,
        source_read_prefix_sha256: sha256_hex(SOURCE_READ_PREFIX),
        handoff_logical_offset: HANDOFF_OFFSET,
        runtime_shutdown_clean: true,
        source_database_transferred: false,
        objects,
        explicit_non_claims: non_claims(),
    })
}

pub fn create_activation_token(
    source: &SourceBundle,
    source_bundle_sha256: &str,
    source_exit_code: i32,
    destination: &EndpointHello,
) -> Result<ActivationToken, String> {
    validate_source_bundle(source)?;
    require_sha256(source_bundle_sha256, "source bundle digest")?;
    if source_exit_code != 0 {
        return Err("activation token requires an observed zero source exit status".to_owned());
    }
    validate_hello(destination)?;
    if source.host.endpoint_id_sha256 == destination.host.endpoint_id_sha256 {
        return Err("cross-host cell requires distinct endpoint identities".to_owned());
    }
    if source.host.executable_sha256 != destination.host.executable_sha256 {
        return Err("source and destination executable digests differ".to_owned());
    }
    if source.host.isa != "x86_64" || destination.host.isa != "x86_64" {
        return Err("the bounded supporting cell requires two x86_64 endpoints".to_owned());
    }
    let issued_at_unix_ms = now_unix_ms()?;
    if issued_at_unix_ms < source.finished_at_unix_ms {
        return Err("activation token timestamp precedes source completion".to_owned());
    }
    let payload = ActivationTokenPayload {
        schema_version: TOKEN_SCHEMA.to_owned(),
        cell_id: CROSS_HOST_CELL_ID.to_owned(),
        issued_at_unix_ms,
        source_bundle_sha256: source_bundle_sha256.to_owned(),
        source_endpoint_id_sha256: source.host.endpoint_id_sha256.clone(),
        source_executable_sha256: source.host.executable_sha256.clone(),
        source_process_exit_observed: true,
        source_process_exit_code: 0,
        destination_endpoint_id_sha256: destination.host.endpoint_id_sha256.clone(),
        destination_executable_sha256: destination.host.executable_sha256.clone(),
        cryptographic_authority: false,
        distributed_fencing_claim: false,
    };
    let token_sha256 = sha256_hex(
        &serde_json::to_vec(&payload)
            .map_err(|error| format!("cannot encode activation token payload: {error}"))?,
    );
    Ok(ActivationToken { payload, token_sha256 })
}

pub fn run_destination_role(
    request: &DestinationRequest,
    work_root: &Path,
) -> Result<DestinationReceipt, String> {
    let started_at_unix_ms = now_unix_ms()?;
    let host = host_identity()?;
    run_destination_role_with_host(request, work_root, host, started_at_unix_ms)
}

fn run_destination_role_with_host(
    request: &DestinationRequest,
    work_root: &Path,
    host: HostIdentity,
    started_at_unix_ms: u64,
) -> Result<DestinationReceipt, String> {
    // No filesystem state is created before every wire, digest, identity,
    // snapshot, profile, portable-state, and activation-token check succeeds.
    let validated = validate_destination_request(request, &host)?;
    ensure_absent(work_root, "destination work root")?;
    fs::create_dir_all(work_root)
        .map_err(|error| format!("cannot create destination work root: {error}"))?;
    let file_root = work_root.join("live-file-root");
    fs::create_dir(&file_root)
        .map_err(|error| format!("cannot create destination file root: {error}"))?;
    let file_path = file_root.join("data.bin");
    write_new_file(&file_path, &validated.file_image)?;
    let database = work_root.join("provider.sqlite3");
    let ids = FixtureIds::for_case(CASE_ID);
    let mut provider = SqliteProvider::open(
        &database,
        JournalScope { node: ids.destination_node, component: ids.destination_component.identity },
    )
    .map_err(provider_error)?;
    install_destination_material(
        &mut provider,
        &ids,
        &validated.snapshot,
        &validated.regular_file,
        &file_root,
    )?;

    let mut destination =
        Coordinator::restore(validated.validated_snapshot, provider).map_err(runtime_error)?;
    let canonical_before_prepare = destination.state_digest().map_err(runtime_error)?;
    let (handoff_authority, timer_authority, key_value_authority, file_authority) =
        authority_plans(&ids);
    destination
        .prepare_destination_with_profiles(
            derive_identity(CASE_ID, "destination-prepare"),
            handoff_authority,
            timer_authority,
            key_value_authority,
            &[file_authority],
        )
        .map_err(runtime_error)?;
    destination
        .commit_handoff(
            derive_identity(CASE_ID, "destination-commit-command"),
            derive_identity(CASE_ID, "destination-commit-operation"),
            IdempotencyKey::from_bytes(
                derive_identity(CASE_ID, "destination-commit-idempotency").0,
            ),
        )
        .map_err(runtime_error)?;
    let mut destination = MatrixRegularFileAdapter::instantiate(
        RegularFileRuntimeKind::Wasmtime,
        component::stage3a_bytes(),
        destination,
    )
    .map_err(adapter_error)?;
    destination.restore(&validated.portable).map_err(adapter_error)?;
    destination
        .coordinator_mut()
        .resume_destination(derive_identity(CASE_ID, "destination-resume"))
        .map_err(runtime_error)?;
    let read = destination
        .execute(
            RegularFileOperation::Read {
                max_bytes: u32::try_from(DESTINATION_SUFFIX.len())
                    .map_err(|_| "destination read bound does not fit u32")?,
            },
            None,
        )
        .map_err(adapter_error)?;
    let suffix = match read.result {
        RegularFileResult::Read { bytes, logical_offset, .. } if logical_offset == FINAL_OFFSET => {
            bytes
        }
        _ => return Err("destination read did not advance to the expected final offset".to_owned()),
    };
    let state = canonical_regular_file(destination.coordinator().state())?;
    let file_after = fs::read(&file_path)
        .map_err(|error| format!("cannot read destination file image: {error}"))?;
    let destination_epoch = destination.coordinator().state().ownership.epoch.0;
    let canonical_after_read = destination.coordinator().state_digest().map_err(runtime_error)?;
    let runtime = RuntimeIdentityEvidence::from(destination.runtime_identity());
    destination.shutdown().map_err(adapter_error)?;
    drop(destination);
    let database_exists = fs::metadata(&database).is_ok_and(|metadata| metadata.is_file());
    let suffix_ok = suffix == DESTINATION_SUFFIX;
    let file_ok = file_after == TRANSFERRED_CONTENT
        && canonical_digest(&file_after).map_err(runtime_error)? == state.content_digest;
    let offset_ok = state.logical_offset == FINAL_OFFSET;
    let version_ok = state.version == 2;
    let epoch_ok = destination_epoch == INITIAL_LEASE_EPOCH.0 + 1;
    let assertions = named_assertions([
        ("preflight_completed_before_materialization", true),
        ("fresh_destination_database_created", database_exists),
        ("fresh_destination_file_root_created", file_root.is_dir()),
        ("snapshot_identity_and_integrity_validated", true),
        ("activation_token_bound_to_destination", true),
        ("logical_offset_preserved", offset_ok),
        ("expected_suffix_read_once", suffix_ok),
        ("file_digest_preserved", file_ok),
        ("file_version_preserved", version_ok),
        ("destination_local_epoch_advanced", epoch_ok),
        ("source_database_not_transferred", true),
        ("distributed_fencing_not_claimed", true),
        ("runtime_shutdown_clean", true),
    ]);
    if assertions.iter().any(|assertion| !assertion.passed) {
        return Err("destination supporting-cell assertion failed".to_owned());
    }
    Ok(DestinationReceipt {
        schema_version: RECEIPT_SCHEMA.to_owned(),
        cell_id: CROSS_HOST_CELL_ID.to_owned(),
        source_bundle_sha256: request.activation.payload.source_bundle_sha256.clone(),
        activation_token_sha256: request.activation.token_sha256.clone(),
        started_at_unix_ms,
        finished_at_unix_ms: now_unix_ms()?,
        host,
        runtime,
        canonical_before_prepare_sha256: digest_hex(canonical_before_prepare),
        canonical_after_read_sha256: digest_hex(canonical_after_read),
        destination_epoch,
        resumed_logical_offset: state.logical_offset,
        read_suffix_sha256: sha256_hex(&suffix),
        destination_file_sha256: sha256_hex(&file_after),
        destination_database_created_after_preflight: database_exists,
        destination_file_root_created_after_preflight: file_root.is_dir(),
        source_database_transferred: false,
        activation_token_cryptographic: false,
        distributed_fencing_claim: false,
        authority_scope: "controller-observed-source-exit-plus-destination-local-lease-transition"
            .to_owned(),
        runtime_shutdown_clean: true,
        assertions,
    })
}

pub fn run_controller(
    artifact_root: &Path,
    source_work_root: &Path,
    destination_work_root: &Path,
    destination_launcher: &[OsString],
) -> Result<PathBuf, String> {
    if destination_launcher.is_empty() {
        return Err("destination launcher is empty".to_owned());
    }
    ensure_absent(artifact_root, "cross-host artifact root")?;
    ensure_absent(source_work_root, "source work root")?;
    let started_at_unix_ms = now_unix_ms()?;
    let executable = std::env::current_exe()
        .map_err(|error| format!("cannot resolve cross-host executable: {error}"))?;
    let source_output = Command::new(&executable)
        .arg("source")
        .arg(source_work_root)
        .output()
        .map_err(|error| format!("cannot launch source role: {error}"))?;
    require_success("source role", &source_output)?;
    let source: SourceBundle = parse_compact_json(&source_output.stdout, "source bundle")?;
    validate_source_bundle(&source)?;
    let source_bundle_sha256 = sha256_hex(&source_output.stdout);

    let hello_output = run_launcher(destination_launcher, &[OsStr::new("hello")], None)?;
    require_success("destination hello", &hello_output)?;
    let hello: EndpointHello = parse_compact_json(&hello_output.stdout, "destination hello")?;
    let activation = create_activation_token(&source, &source_bundle_sha256, 0, &hello)?;
    let activation_bytes = serde_json::to_vec(&activation)
        .map_err(|error| format!("cannot encode activation token: {error}"))?;
    let request = DestinationRequest {
        schema_version: REQUEST_SCHEMA.to_owned(),
        source: source.clone(),
        activation: activation.clone(),
    };
    let request_bytes = serde_json::to_vec(&request)
        .map_err(|error| format!("cannot encode destination request: {error}"))?;
    let destination_output = run_launcher(
        destination_launcher,
        &[OsStr::new("destination"), destination_work_root.as_os_str()],
        Some(&request_bytes),
    )?;
    require_success("destination role", &destination_output)?;
    let receipt: DestinationReceipt =
        parse_compact_json(&destination_output.stdout, "destination receipt")?;
    validate_destination_receipt(&source, &activation, &hello, &receipt)?;
    let finished_at_unix_ms = now_unix_ms()?;
    publish_cross_host(
        artifact_root,
        started_at_unix_ms,
        finished_at_unix_ms,
        &source_output.stdout,
        &source,
        &hello_output.stdout,
        &hello,
        &activation_bytes,
        &activation,
        &destination_output.stdout,
        &receipt,
    )
}

pub fn verify_cross_host_publication(artifact_root: &Path) -> Result<(), String> {
    verify_cross_host_publication_mode(artifact_root, false)
}

fn validate_source_bundle(source: &SourceBundle) -> Result<ValidatedSource, String> {
    if source.schema_version != SOURCE_SCHEMA
        || source.cell_id != CROSS_HOST_CELL_ID
        || source.case_id != CASE_ID
        || source.claim_class != CLAIM_CLASS
    {
        return Err("source bundle identity or schema mismatch".to_owned());
    }
    if source.started_at_unix_ms > source.finished_at_unix_ms {
        return Err("source timestamps are reversed".to_owned());
    }
    validate_host_identity(&source.host)?;
    if source.host.isa != "x86_64" {
        return Err("source endpoint is not x86_64".to_owned());
    }
    if source.runtime.implementation != "visa_wasmtime_stage3a" {
        return Err("source runtime is not the bounded Wasmtime Stage 3A adapter".to_owned());
    }
    if source.component_sha256 != digest_hex(component::stage3a_digest()) {
        return Err("source component digest mismatch".to_owned());
    }
    let (_, profile_digest) = stage3a_profile()?;
    if source.profile_sha256 != digest_hex(profile_digest) {
        return Err("source profile digest mismatch".to_owned());
    }
    require_sha256(&source.canonical_after_export_sha256, "source canonical digest")?;
    if source.source_operation_ids.len() != 2
        || source.source_operation_ids.iter().any(|operation| parse_identity(operation).is_none())
    {
        return Err(
            "source operation identity set is not the fixed two-operation workload".to_owned()
        );
    }
    if source.source_operation_ids[0] == source.source_operation_ids[1] {
        return Err("source operation identities are not unique".to_owned());
    }
    if source.source_read_prefix_sha256 != sha256_hex(SOURCE_READ_PREFIX)
        || source.handoff_logical_offset != HANDOFF_OFFSET
        || !source.runtime_shutdown_clean
        || source.source_database_transferred
        || source.explicit_non_claims != non_claims()
    {
        return Err("source workload summary or boundary declaration mismatch".to_owned());
    }
    if source.objects.len() != 3 {
        return Err("source bundle must contain exactly three transport objects".to_owned());
    }
    let expected_kinds = [
        ObjectKind::SnapshotEnvelope,
        ObjectKind::PortableRegularFileState,
        ObjectKind::RegularFileImage,
    ];
    let mut kinds = BTreeSet::new();
    let mut object_digests = BTreeSet::new();
    for object in &source.objects {
        if !kinds.insert(object.kind) || !object_digests.insert(object.sha256.as_str()) {
            return Err("source transport objects are not unique".to_owned());
        }
        validate_transport_object(object)?;
    }
    if kinds != expected_kinds.into_iter().collect() {
        return Err("source transport object kinds do not match the bounded exact set".to_owned());
    }
    let snapshot_object = object(source, ObjectKind::SnapshotEnvelope)?;
    let portable_object = object(source, ObjectKind::PortableRegularFileState)?;
    let file_object = object(source, ObjectKind::RegularFileImage)?;
    let snapshot: SnapshotEnvelope =
        parse_compact_json(&snapshot_object.bytes, "snapshot envelope object")?;
    let portable = PortableRegularFileState::try_from_bytes(portable_object.bytes.clone())
        .map_err(|error| format!("invalid portable regular-file state: {error:?}"))?;
    let file_image = file_object.bytes.clone();
    let ids = FixtureIds::for_case(CASE_ID);
    if snapshot.body.source_node != ids.source_node
        || snapshot.body.component != ids.source_component
        || snapshot.body.snapshot.handoff != ids.handoff
        || snapshot.body.snapshot.snapshot != ids.snapshot
        || snapshot.body.source_lease_epoch != INITIAL_LEASE_EPOCH
        || snapshot.body.component_digest != component::stage3a_digest()
        || snapshot.body.profile_digest != profile_digest
        || snapshot.body.profile_version != SchemaVersion::new(1, 0)
        || snapshot.body.claims.timer.resource != ids.timer
        || snapshot.body.claims.key_value.resource != ids.key_value
        || snapshot.body.claims.key_value.namespace != ids.key_value_namespace
        || snapshot.body.portable_state != portable.as_bytes()
    {
        return Err(
            "snapshot identity, claim, profile, or portable-state binding mismatch".to_owned()
        );
    }
    if snapshot.body.snapshot.evidence.kind != EvidenceKind::SnapshotIntegrity
        || snapshot.body.snapshot.evidence.identity != derive_identity(CASE_ID, "snapshot-evidence")
        || snapshot.body.snapshot.evidence.digest == Digest::ZERO
    {
        return Err("snapshot evidence identity is invalid".to_owned());
    }
    if snapshot.body.extensions.len() != 1
        || snapshot.body.extensions[0].id != REGULAR_FILE_EXTENSION_ID
        || snapshot.body.extensions[0].version != REGULAR_FILE_EXTENSION_VERSION
    {
        return Err("snapshot regular-file extension exact set mismatch".to_owned());
    }
    let regular_file = regular_file_state(&snapshot.body.extensions[0])
        .map_err(|error| format!("invalid snapshot regular-file extension: {error:?}"))?;
    validate_fixed_handoff_state(&regular_file, &file_image, &portable)?;
    validate_source_authorities(&snapshot, &ids)?;
    let validated_snapshot = validate_snapshot(
        &snapshot,
        &SnapshotExpectations {
            component_digest: component::stage3a_digest(),
            profile_digest,
            profile_version: SchemaVersion::new(1, 0),
            supported_extensions: vec![ExtensionSupport {
                id: REGULAR_FILE_EXTENSION_ID,
                version: REGULAR_FILE_EXTENSION_VERSION,
            }],
            destination: ids.destination_node,
        },
    )
    .map_err(runtime_error)?;
    Ok(ValidatedSource { snapshot, validated_snapshot, portable, regular_file, file_image })
}

fn validate_destination_request(
    request: &DestinationRequest,
    destination_host: &HostIdentity,
) -> Result<ValidatedSource, String> {
    if request.schema_version != REQUEST_SCHEMA {
        return Err("destination request schema mismatch".to_owned());
    }
    let validated = validate_source_bundle(&request.source)?;
    validate_activation_token(
        &request.activation,
        &request.source,
        destination_host,
        &compact_sha256(&request.source)?,
    )?;
    Ok(validated)
}

fn validate_activation_token(
    token: &ActivationToken,
    source: &SourceBundle,
    destination_host: &HostIdentity,
    source_bundle_sha256: &str,
) -> Result<(), String> {
    let payload = &token.payload;
    if payload.schema_version != TOKEN_SCHEMA || payload.cell_id != CROSS_HOST_CELL_ID {
        return Err("activation token schema or cell mismatch".to_owned());
    }
    let expected_token_sha256 = sha256_hex(
        &serde_json::to_vec(payload)
            .map_err(|error| format!("cannot re-encode activation token payload: {error}"))?,
    );
    if token.token_sha256 != expected_token_sha256 {
        return Err("activation token digest mismatch".to_owned());
    }
    if payload.source_bundle_sha256 != source_bundle_sha256
        || payload.source_endpoint_id_sha256 != source.host.endpoint_id_sha256
        || payload.source_executable_sha256 != source.host.executable_sha256
        || !payload.source_process_exit_observed
        || payload.source_process_exit_code != 0
        || payload.issued_at_unix_ms < source.finished_at_unix_ms
        || payload.destination_endpoint_id_sha256 != destination_host.endpoint_id_sha256
        || payload.destination_executable_sha256 != destination_host.executable_sha256
        || payload.cryptographic_authority
        || payload.distributed_fencing_claim
    {
        return Err("activation token binding or authority boundary mismatch".to_owned());
    }
    if source.host.endpoint_id_sha256 == destination_host.endpoint_id_sha256 {
        return Err("activation token does not bind a distinct destination endpoint".to_owned());
    }
    if source.host.executable_sha256 != destination_host.executable_sha256 {
        return Err("activation token endpoints do not run the same executable bytes".to_owned());
    }
    Ok(())
}

fn validate_hello(hello: &EndpointHello) -> Result<(), String> {
    if hello.schema_version != HELLO_SCHEMA || hello.cell_id != CROSS_HOST_CELL_ID {
        return Err("destination hello schema or cell mismatch".to_owned());
    }
    validate_host_identity(&hello.host)
}

fn validate_destination_receipt(
    source: &SourceBundle,
    activation: &ActivationToken,
    hello: &EndpointHello,
    receipt: &DestinationReceipt,
) -> Result<(), String> {
    validate_hello(hello)?;
    if receipt.schema_version != RECEIPT_SCHEMA || receipt.cell_id != CROSS_HOST_CELL_ID {
        return Err("destination receipt schema or cell mismatch".to_owned());
    }
    validate_host_identity(&receipt.host)?;
    if receipt.host != hello.host
        || receipt.source_bundle_sha256 != activation.payload.source_bundle_sha256
        || receipt.activation_token_sha256 != activation.token_sha256
        || receipt.started_at_unix_ms > receipt.finished_at_unix_ms
        || receipt.runtime.implementation != "visa_wasmtime_stage3a"
        || receipt.destination_epoch != INITIAL_LEASE_EPOCH.0 + 1
        || receipt.resumed_logical_offset != FINAL_OFFSET
        || receipt.read_suffix_sha256 != sha256_hex(DESTINATION_SUFFIX)
        || receipt.destination_file_sha256 != sha256_hex(TRANSFERRED_CONTENT)
        || !receipt.destination_database_created_after_preflight
        || !receipt.destination_file_root_created_after_preflight
        || receipt.source_database_transferred
        || receipt.activation_token_cryptographic
        || receipt.distributed_fencing_claim
        || receipt.authority_scope
            != "controller-observed-source-exit-plus-destination-local-lease-transition"
        || !receipt.runtime_shutdown_clean
    {
        return Err("destination receipt semantic or boundary mismatch".to_owned());
    }
    require_sha256(&receipt.canonical_before_prepare_sha256, "pre-prepare canonical digest")?;
    require_sha256(&receipt.canonical_after_read_sha256, "post-read canonical digest")?;
    if source.host.endpoint_id_sha256 == receipt.host.endpoint_id_sha256
        || source.host.executable_sha256 != receipt.host.executable_sha256
        || source.host.isa != "x86_64"
        || receipt.host.isa != "x86_64"
    {
        return Err(
            "destination receipt does not establish the bounded two-host x86_64 subject".to_owned()
        );
    }
    validate_required_assertions(&receipt.assertions, destination_assertion_names())
}

fn validate_transport_object(object: &TransportObject) -> Result<(), String> {
    require_sha256(&object.sha256, "transport object digest")?;
    let observed_size =
        u64::try_from(object.bytes.len()).map_err(|_| "transport object size does not fit u64")?;
    if object.size != observed_size || object.size > MAX_WIRE_BYTES {
        return Err("transport object size mismatch or limit exceeded".to_owned());
    }
    if object.sha256 != sha256_hex(&object.bytes) {
        return Err("transport object digest mismatch".to_owned());
    }
    Ok(())
}

fn object(source: &SourceBundle, kind: ObjectKind) -> Result<&TransportObject, String> {
    let mut matching = source.objects.iter().filter(|object| object.kind == kind);
    let object = matching.next().ok_or_else(|| format!("missing transport object {kind:?}"))?;
    if matching.next().is_some() {
        return Err(format!("duplicate transport object {kind:?}"));
    }
    Ok(object)
}

fn validate_fixed_handoff_state(
    state: &RegularFileState,
    file_image: &[u8],
    portable: &PortableRegularFileState,
) -> Result<(), String> {
    let ids = FixtureIds::for_case(CASE_ID);
    if state.claim.resource != ids.file
        || state.claim.namespace != ids.file_namespace
        || state.claim.relative_path != b"data.bin"
        || state.claim.required_rights != profile_rights()
        || state.logical_offset != HANDOFF_OFFSET
        || state.version != 2
        || state.size != TRANSFERRED_CONTENT.len() as u64
        || file_image != TRANSFERRED_CONTENT
        || state.content_digest
            != canonical_digest(&file_image.to_vec())
                .map_err(|error| format!("cannot digest regular-file image: {error:?}"))?
    {
        return Err("regular-file canonical handoff state mismatch".to_owned());
    }
    let decoded = portable
        .decode()
        .map_err(|error| format!("cannot decode portable regular-file state: {error:?}"))?;
    decoded
        .validate_canonical(state)
        .map_err(|error| format!("portable and canonical regular-file states differ: {error:?}"))?;
    if decoded.phase != RegularFileWorkloadPhase::Frozen || decoded.logical_offset != HANDOFF_OFFSET
    {
        return Err("portable regular-file state is not frozen at the handoff offset".to_owned());
    }
    Ok(())
}

fn validate_source_authorities(
    snapshot: &SnapshotEnvelope,
    ids: &FixtureIds,
) -> Result<(), String> {
    let expected = [
        AuthorityGrant::active_root(
            ids.source_handoff_authority,
            ids.source_component,
            ids.source_component,
            Rights::HANDOFF,
        ),
        AuthorityGrant::active_root(
            ids.source_timer_authority,
            ids.source_component,
            ids.timer,
            timer_rights(),
        ),
        AuthorityGrant::active_root(
            ids.source_key_value_authority,
            ids.source_component,
            ids.key_value,
            key_value_rights(),
        ),
        AuthorityGrant::active_root(
            ids.source_file_authority,
            ids.source_component,
            ids.file,
            profile_rights(),
        ),
    ];
    if snapshot.body.authorities.len() != expected.len()
        || expected.iter().any(|authority| !snapshot.body.authorities.contains(authority))
    {
        return Err("snapshot source authority exact set mismatch".to_owned());
    }
    Ok(())
}

fn install_destination_material(
    provider: &mut SqliteProvider,
    ids: &FixtureIds,
    snapshot: &SnapshotEnvelope,
    regular_file: &RegularFileState,
    file_root: &Path,
) -> Result<(), String> {
    for (resource, rights) in [
        (ids.source_component, Rights::HANDOFF),
        (ids.timer, timer_rights()),
        (ids.key_value, key_value_rights()),
        (ids.file, profile_rights()),
    ] {
        provider
            .install_policy(AuthorityPolicy {
                subject: ids.source_component,
                resource,
                allowed_rights: rights,
            })
            .map_err(|error| {
                format!(
                    "install fixed source authority policy projection: {}",
                    provider_error(error)
                )
            })?;
    }
    for (resource, rights) in [
        (ids.destination_component, Rights::HANDOFF),
        (ids.timer, timer_rights()),
        (ids.key_value, key_value_rights()),
        (ids.file, profile_rights()),
    ] {
        provider
            .install_policy(AuthorityPolicy {
                subject: ids.destination_component,
                resource,
                allowed_rights: rights,
            })
            .map_err(|error| {
                format!("install destination authority policy: {}", provider_error(error))
            })?;
    }
    for grant in &snapshot.body.authorities {
        provider.install_grant(grant).map_err(|error| {
            format!("install transported source authority: {}", provider_error(error))
        })?;
    }
    provider.provision_key_value_namespace(ids.key_value, ids.key_value_namespace).map_err(
        |error| format!("provision destination key-value namespace: {}", provider_error(error)),
    )?;
    provider.provision_regular_file(regular_file, file_root).map_err(|error| {
        format!("provision destination regular file: {}", provider_error(error))
    })?;
    for resource in [ids.timer, ids.key_value, ids.file] {
        provider
            .initialize_lease(LeaseRecord {
                resource,
                owner: ids.source_node,
                epoch: INITIAL_LEASE_EPOCH,
            })
            .map_err(|error| {
                format!("initialize destination-local source lease: {}", provider_error(error))
            })?;
    }
    Ok(())
}

fn authority_plans(
    ids: &FixtureIds,
) -> (AuthorityPlan, AuthorityPlan, AuthorityPlan, ProfileAuthorityPlan) {
    (
        AuthorityPlan {
            source_authority: ids.source_handoff_authority,
            destination_authority: ids.destination_handoff_authority,
            attenuated_authority: ids.attenuated_handoff_authority,
        },
        AuthorityPlan {
            source_authority: ids.source_timer_authority,
            destination_authority: ids.destination_timer_authority,
            attenuated_authority: ids.attenuated_timer_authority,
        },
        AuthorityPlan {
            source_authority: ids.source_key_value_authority,
            destination_authority: ids.destination_key_value_authority,
            attenuated_authority: ids.attenuated_key_value_authority,
        },
        ProfileAuthorityPlan {
            profile: REGULAR_FILE_EXTENSION_ID,
            resource: ids.file,
            authority: AuthorityPlan {
                source_authority: ids.source_file_authority,
                destination_authority: ids.destination_file_authority,
                attenuated_authority: ids.attenuated_file_authority,
            },
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn publish_cross_host(
    artifact_root: &Path,
    started_at_unix_ms: u64,
    finished_at_unix_ms: u64,
    source_bytes: &[u8],
    source: &SourceBundle,
    hello_bytes: &[u8],
    hello: &EndpointHello,
    activation_bytes: &[u8],
    activation: &ActivationToken,
    receipt_bytes: &[u8],
    receipt: &DestinationReceipt,
) -> Result<PathBuf, String> {
    ensure_absent(artifact_root, "cross-host artifact root")?;
    fs::create_dir_all(artifact_root)
        .map_err(|error| format!("cannot create cross-host artifact root: {error}"))?;
    write_new_file(&artifact_root.join(INCOMPLETE_MARKER), INCOMPLETE_CONTENT)?;
    let mut artifacts = vec![
        write_artifact(artifact_root, "source/source-bundle.json", source_bytes)?,
        write_artifact(artifact_root, "destination/hello.json", hello_bytes)?,
        write_artifact(artifact_root, "controller/activation-token.json", activation_bytes)?,
        write_artifact(artifact_root, "destination/receipt.json", receipt_bytes)?,
    ];
    for object in &source.objects {
        artifacts.push(write_artifact(artifact_root, &object.uri(), &object.bytes)?);
    }
    artifacts.sort_by(|left, right| left.uri.cmp(&right.uri));
    let assertions = named_assertions([
        (
            "distinct_host_endpoint_identity",
            source.host.endpoint_id_sha256 != hello.host.endpoint_id_sha256,
        ),
        (
            "identical_executable_digest",
            source.host.executable_sha256 == hello.host.executable_sha256,
        ),
        ("two_x86_64_endpoints", source.host.isa == "x86_64" && hello.host.isa == "x86_64"),
        (
            "source_exit_observed_before_activation_token",
            activation.payload.source_process_exit_observed
                && activation.payload.source_process_exit_code == 0
                && activation.payload.issued_at_unix_ms >= source.finished_at_unix_ms,
        ),
        ("source_bundle_content_addressed", source.objects.len() == 3),
        ("destination_preflight_validated", true),
        ("destination_independent_database", !receipt.source_database_transferred),
        (
            "destination_independent_file_root",
            receipt.destination_file_root_created_after_preflight,
        ),
        ("logical_offset_preserved", receipt.resumed_logical_offset == FINAL_OFFSET),
        ("expected_suffix_read_once", receipt.read_suffix_sha256 == sha256_hex(DESTINATION_SUFFIX)),
        (
            "file_digest_preserved",
            receipt.destination_file_sha256 == sha256_hex(TRANSFERRED_CONTENT),
        ),
        ("runtime_shutdown_clean", source.runtime_shutdown_clean && receipt.runtime_shutdown_clean),
        (
            "distributed_fencing_not_claimed",
            !activation.payload.distributed_fencing_claim && !receipt.distributed_fencing_claim,
        ),
    ]);
    if assertions.iter().any(|assertion| !assertion.passed) {
        return Err("cross-host publication assertion failed".to_owned());
    }
    let bundle = CrossHostEvidenceBundle {
        schema_version: EVIDENCE_SCHEMA.to_owned(),
        cell_id: CROSS_HOST_CELL_ID.to_owned(),
        claim_class: CLAIM_CLASS.to_owned(),
        started_at_unix_ms,
        finished_at_unix_ms,
        topology: "controller-source-process-to-external-destination-process".to_owned(),
        transport: "bounded-json-over-launcher-stdio".to_owned(),
        source_bundle_sha256: sha256_hex(source_bytes),
        activation_token_sha256: activation.token_sha256.clone(),
        source: source.host.clone(),
        destination: hello.host.clone(),
        source_runtime: source.runtime.clone(),
        destination_runtime: receipt.runtime.clone(),
        authority_boundary: AuthorityBoundary {
            source_exit_observed_before_activation_token: true,
            token_is_cryptographic_authority: false,
            source_process_remains_stopped_assumption: true,
            destination_lease_transition_is_local: true,
            distributed_fencing_claim: false,
            statement: "The controller observes clean source-process exit before issuing a digest-bound activation token. The token is sequencing evidence, not cryptographic authority; the destination advances only its fresh local ledger, so no distributed source-fencing guarantee is claimed."
                .to_owned(),
        },
        assertions,
        artifacts,
        explicit_non_claims: non_claims(),
    };
    let evidence_bytes = serde_json::to_vec_pretty(&bundle)
        .map_err(|error| format!("cannot encode cross-host evidence: {error}"))?;
    write_new_file(&artifact_root.join(CROSS_HOST_EVIDENCE_FILE), &evidence_bytes)?;
    verify_cross_host_publication_mode(artifact_root, true)?;
    fs::remove_file(artifact_root.join(INCOMPLETE_MARKER))
        .map_err(|error| format!("cannot commit cross-host publication: {error}"))?;
    sync_directory(artifact_root)?;
    verify_cross_host_publication_mode(artifact_root, false)?;
    Ok(artifact_root.join(CROSS_HOST_EVIDENCE_FILE))
}

fn verify_cross_host_publication_mode(artifact_root: &Path, staged: bool) -> Result<(), String> {
    let root_metadata = fs::symlink_metadata(artifact_root)
        .map_err(|error| format!("cannot inspect cross-host artifact root: {error}"))?;
    if !root_metadata.file_type().is_dir() || root_metadata.file_type().is_symlink() {
        return Err("cross-host artifact root is not a real directory".to_owned());
    }
    let marker = artifact_root.join(INCOMPLETE_MARKER);
    match (staged, fs::symlink_metadata(&marker)) {
        (true, Ok(metadata)) if metadata.file_type().is_file() => {
            if fs::read(&marker).map_err(io_error("read incomplete marker"))? != INCOMPLETE_CONTENT
            {
                return Err("cross-host incomplete marker content mismatch".to_owned());
            }
        }
        (true, Ok(_)) => {
            return Err("cross-host incomplete marker is not a regular file".to_owned());
        }
        (true, Err(error)) => {
            return Err(format!("staged cross-host publication lacks marker: {error}"));
        }
        (false, Ok(_)) => return Err("cross-host publication remains incomplete".to_owned()),
        (false, Err(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
        (false, Err(error)) => {
            return Err(format!("cannot inspect cross-host publication marker: {error}"));
        }
    }
    let evidence_path = artifact_root.join(CROSS_HOST_EVIDENCE_FILE);
    let evidence_bytes = read_regular_bounded(&evidence_path, MAX_WIRE_BYTES)?;
    let evidence: CrossHostEvidenceBundle = serde_json::from_slice(&evidence_bytes)
        .map_err(|error| format!("invalid cross-host evidence JSON: {error}"))?;
    let canonical = serde_json::to_vec_pretty(&evidence)
        .map_err(|error| format!("cannot re-encode cross-host evidence: {error}"))?;
    if evidence_bytes != canonical {
        return Err("cross-host evidence is not in canonical publisher encoding".to_owned());
    }
    if evidence.schema_version != EVIDENCE_SCHEMA
        || evidence.cell_id != CROSS_HOST_CELL_ID
        || evidence.claim_class != CLAIM_CLASS
        || evidence.started_at_unix_ms > evidence.finished_at_unix_ms
        || evidence.topology != "controller-source-process-to-external-destination-process"
        || evidence.transport != "bounded-json-over-launcher-stdio"
        || evidence.explicit_non_claims != non_claims()
    {
        return Err("cross-host evidence identity, scope, or timestamp mismatch".to_owned());
    }
    validate_host_identity(&evidence.source)?;
    validate_host_identity(&evidence.destination)?;
    validate_required_assertions(&evidence.assertions, publication_assertion_names())?;
    let boundary = &evidence.authority_boundary;
    if !boundary.source_exit_observed_before_activation_token
        || boundary.token_is_cryptographic_authority
        || !boundary.source_process_remains_stopped_assumption
        || !boundary.destination_lease_transition_is_local
        || boundary.distributed_fencing_claim
        || boundary.statement
            != "The controller observes clean source-process exit before issuing a digest-bound activation token. The token is sequencing evidence, not cryptographic authority; the destination advances only its fresh local ledger, so no distributed source-fencing guarantee is claimed."
    {
        return Err("cross-host authority boundary declaration mismatch".to_owned());
    }
    let files = read_and_validate_artifacts(artifact_root, &evidence.artifacts)?;
    let expected_static = BTreeSet::from([
        "controller/activation-token.json".to_owned(),
        "destination/hello.json".to_owned(),
        "destination/receipt.json".to_owned(),
        "source/source-bundle.json".to_owned(),
    ]);
    let actual_static = files
        .keys()
        .filter(|uri| !uri.starts_with("objects/sha256/"))
        .cloned()
        .collect::<BTreeSet<_>>();
    if actual_static != expected_static {
        return Err("cross-host artifact static exact set mismatch".to_owned());
    }
    let source_bytes = required_artifact(&files, "source/source-bundle.json")?;
    let source: SourceBundle = parse_compact_json(source_bytes, "published source bundle")?;
    validate_source_bundle(&source)?;
    if evidence.source_bundle_sha256 != sha256_hex(source_bytes)
        || evidence.source != source.host
        || evidence.source_runtime != source.runtime
    {
        return Err("cross-host evidence does not bind the published source bundle".to_owned());
    }
    let hello: EndpointHello = parse_compact_json(
        required_artifact(&files, "destination/hello.json")?,
        "published destination hello",
    )?;
    validate_hello(&hello)?;
    let activation: ActivationToken = parse_compact_json(
        required_artifact(&files, "controller/activation-token.json")?,
        "published activation token",
    )?;
    validate_activation_token(&activation, &source, &hello.host, &evidence.source_bundle_sha256)?;
    let receipt: DestinationReceipt = parse_compact_json(
        required_artifact(&files, "destination/receipt.json")?,
        "published destination receipt",
    )?;
    validate_destination_receipt(&source, &activation, &hello, &receipt)?;
    if evidence.activation_token_sha256 != activation.token_sha256
        || evidence.destination != hello.host
        || evidence.destination_runtime != receipt.runtime
    {
        return Err(
            "cross-host evidence does not bind destination hello, token, or receipt".to_owned()
        );
    }
    for object in &source.objects {
        let bytes = required_artifact(&files, &object.uri())?;
        if bytes != object.bytes {
            return Err(format!("published object {} differs from source bundle", object.uri()));
        }
    }
    let object_uris = source.objects.iter().map(TransportObject::uri).collect::<BTreeSet<_>>();
    let published_object_uris = files
        .keys()
        .filter(|uri| uri.starts_with("objects/sha256/"))
        .cloned()
        .collect::<BTreeSet<_>>();
    if object_uris != published_object_uris {
        return Err("published content-addressed object exact set mismatch".to_owned());
    }
    let mut expected_files = files.keys().cloned().collect::<BTreeSet<_>>();
    expected_files.insert(CROSS_HOST_EVIDENCE_FILE.to_owned());
    if staged {
        expected_files.insert(INCOMPLETE_MARKER.to_owned());
    }
    validate_exact_tree(artifact_root, &expected_files)?;
    Ok(())
}

fn read_and_validate_artifacts(
    root: &Path,
    references: &[ArtifactReference],
) -> Result<BTreeMap<String, Vec<u8>>, String> {
    if references.len() != 7 {
        return Err("cross-host artifact reference count mismatch".to_owned());
    }
    let mut files = BTreeMap::new();
    for reference in references {
        validate_relative_uri(&reference.uri)?;
        require_sha256(&reference.sha256, "artifact digest")?;
        let bytes = read_regular_bounded(&root.join(&reference.uri), MAX_WIRE_BYTES)?;
        let size = u64::try_from(bytes.len()).map_err(|_| "artifact size does not fit u64")?;
        if size != reference.size || sha256_hex(&bytes) != reference.sha256 {
            return Err(format!("artifact {} size or digest mismatch", reference.uri));
        }
        if files.insert(reference.uri.clone(), bytes).is_some() {
            return Err(format!("duplicate artifact URI {}", reference.uri));
        }
    }
    Ok(files)
}

fn write_artifact(root: &Path, uri: &str, bytes: &[u8]) -> Result<ArtifactReference, String> {
    validate_relative_uri(uri)?;
    let path = root.join(uri);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!("cannot create artifact directory {}: {error}", parent.display())
        })?;
    }
    write_new_file(&path, bytes)?;
    Ok(ArtifactReference {
        uri: uri.to_owned(),
        sha256: sha256_hex(bytes),
        size: u64::try_from(bytes.len()).map_err(|_| "artifact size does not fit u64")?,
    })
}

fn validate_exact_tree(root: &Path, expected_files: &BTreeSet<String>) -> Result<(), String> {
    let mut observed = BTreeSet::new();
    let mut pending = vec![(root.to_path_buf(), String::new())];
    while let Some((directory, prefix)) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .map_err(|error| format!("cannot enumerate {}: {error}", directory.display()))?
        {
            let entry =
                entry.map_err(|error| format!("cannot enumerate artifact entry: {error}"))?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "artifact tree contains a non-UTF-8 name".to_owned())?;
            let uri = if prefix.is_empty() { name } else { format!("{prefix}/{name}") };
            let file_type = entry
                .file_type()
                .map_err(|error| format!("cannot inspect artifact {uri}: {error}"))?;
            if file_type.is_symlink() {
                return Err(format!("artifact {uri} is a symlink"));
            }
            if file_type.is_dir() {
                pending.push((entry.path(), uri));
            } else if file_type.is_file() {
                observed.insert(uri);
            } else {
                return Err(format!("artifact {uri} is a special file"));
            }
        }
    }
    if &observed != expected_files {
        return Err("cross-host publication exact file set mismatch".to_owned());
    }
    Ok(())
}

pub fn encode_compact<T: Serialize>(value: &T, label: &str) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|error| format!("cannot encode {label}: {error}"))
}

pub fn parse_destination_request_bytes(bytes: &[u8]) -> Result<DestinationRequest, String> {
    if bytes.len() as u64 > MAX_WIRE_BYTES {
        return Err("destination request exceeds the bounded wire limit".to_owned());
    }
    parse_compact_json(bytes, "destination request")
}

pub const fn max_wire_bytes() -> u64 {
    MAX_WIRE_BYTES
}

fn parse_compact_json<T>(bytes: &[u8], label: &str) -> Result<T, String>
where
    T: DeserializeOwned + Serialize,
{
    if bytes.len() as u64 > MAX_WIRE_BYTES {
        return Err(format!("{label} exceeds the bounded wire limit"));
    }
    let value =
        serde_json::from_slice(bytes).map_err(|error| format!("invalid {label} JSON: {error}"))?;
    let canonical =
        serde_json::to_vec(&value).map_err(|error| format!("cannot re-encode {label}: {error}"))?;
    if canonical != bytes {
        return Err(format!("{label} is not in canonical compact encoding"));
    }
    Ok(value)
}

fn compact_sha256<T: Serialize>(value: &T) -> Result<String, String> {
    Ok(sha256_hex(
        &serde_json::to_vec(value)
            .map_err(|error| format!("cannot encode value for digest: {error}"))?,
    ))
}

fn host_identity() -> Result<HostIdentity, String> {
    let machine_id = fs::read_to_string("/etc/machine-id")
        .map_err(|error| format!("cannot read /etc/machine-id: {error}"))?;
    let machine_id = machine_id.trim();
    if machine_id.len() != 32 || !machine_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("/etc/machine-id is not a 32-digit hexadecimal endpoint identity".to_owned());
    }
    let mut endpoint_material = b"visa-stage3a-cross-host-endpoint-v1\0".to_vec();
    endpoint_material.extend_from_slice(machine_id.as_bytes());
    let hostname = read_trimmed(Path::new("/proc/sys/kernel/hostname"), "hostname")?;
    let kernel_release = read_trimmed(Path::new("/proc/sys/kernel/osrelease"), "kernel release")?;
    let os_release_bytes = fs::read_to_string("/etc/os-release")
        .map_err(|error| format!("cannot read /etc/os-release: {error}"))?;
    let os_release = os_release_bytes
        .lines()
        .find_map(|line| line.strip_prefix("PRETTY_NAME="))
        .map(|value| value.trim_matches('"').to_owned())
        .filter(|value| !value.is_empty())
        .ok_or("/etc/os-release lacks PRETTY_NAME")?;
    let executable = std::env::current_exe()
        .map_err(|error| format!("cannot resolve current executable: {error}"))?;
    let (executable_sha256, executable_size) = sha256_file(&executable)?;
    Ok(HostIdentity {
        endpoint_id_sha256: sha256_hex(&endpoint_material),
        hostname,
        os_release,
        kernel_release,
        isa: std::env::consts::ARCH.to_owned(),
        executable_sha256,
        executable_size,
    })
}

fn validate_host_identity(host: &HostIdentity) -> Result<(), String> {
    require_sha256(&host.endpoint_id_sha256, "endpoint identity")?;
    require_sha256(&host.executable_sha256, "executable digest")?;
    if host.hostname.is_empty()
        || host.hostname.len() > 255
        || host.os_release.is_empty()
        || host.kernel_release.is_empty()
        || host.isa.is_empty()
        || host.executable_size == 0
    {
        return Err("host identity contains an empty or invalid field".to_owned());
    }
    Ok(())
}

fn read_trimmed(path: &Path, label: &str) -> Result<String, String> {
    let value = fs::read_to_string(path)
        .map_err(|error| format!("cannot read {label} from {}: {error}", path.display()))?;
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("{label} is empty"));
    }
    Ok(value.to_owned())
}

fn sha256_file(path: &Path) -> Result<(String, u64), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect executable {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err("current executable is not a regular file".to_owned());
    }
    let mut file = File::open(path)
        .map_err(|error| format!("cannot open executable {}: {error}", path.display()))?;
    let mut digest = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("cannot read executable {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        total = total.checked_add(read as u64).ok_or("executable size overflow")?;
    }
    if total != metadata.len() {
        return Err("executable changed while it was hashed".to_owned());
    }
    Ok((hex_bytes(&digest.finalize()), total))
}

fn run_launcher(
    launcher: &[OsString],
    appended_arguments: &[&OsStr],
    input: Option<&[u8]>,
) -> Result<Output, String> {
    let program = launcher.first().ok_or("destination launcher is empty")?;
    let mut command = Command::new(program);
    command.args(&launcher[1..]).args(appended_arguments);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    if input.is_some() {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }
    let mut child =
        command.spawn().map_err(|error| format!("cannot launch destination command: {error}"))?;
    if let Some(input) = input {
        child
            .stdin
            .take()
            .ok_or("destination launcher lacks piped stdin")?
            .write_all(input)
            .map_err(|error| format!("cannot write destination request: {error}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("cannot wait for destination command: {error}"))?;
    if output.stdout.len() as u64 > MAX_WIRE_BYTES || output.stderr.len() as u64 > MAX_WIRE_BYTES {
        return Err("destination command output exceeds the bounded wire limit".to_owned());
    }
    Ok(output)
}

fn require_success(label: &str, output: &Output) -> Result<(), String> {
    if output.status.success() && output.status.code() == Some(0) {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(format!("{label} failed with status {}: {}", output.status, stderr.trim()))
}

fn named_assertions<const N: usize>(items: [(&str, bool); N]) -> Vec<NamedAssertion> {
    items
        .into_iter()
        .map(|(name, passed)| NamedAssertion { name: name.to_owned(), passed })
        .collect()
}

fn destination_assertion_names() -> &'static [&'static str] {
    &[
        "preflight_completed_before_materialization",
        "fresh_destination_database_created",
        "fresh_destination_file_root_created",
        "snapshot_identity_and_integrity_validated",
        "activation_token_bound_to_destination",
        "logical_offset_preserved",
        "expected_suffix_read_once",
        "file_digest_preserved",
        "file_version_preserved",
        "destination_local_epoch_advanced",
        "source_database_not_transferred",
        "distributed_fencing_not_claimed",
        "runtime_shutdown_clean",
    ]
}

fn publication_assertion_names() -> &'static [&'static str] {
    &[
        "distinct_host_endpoint_identity",
        "identical_executable_digest",
        "two_x86_64_endpoints",
        "source_exit_observed_before_activation_token",
        "source_bundle_content_addressed",
        "destination_preflight_validated",
        "destination_independent_database",
        "destination_independent_file_root",
        "logical_offset_preserved",
        "expected_suffix_read_once",
        "file_digest_preserved",
        "runtime_shutdown_clean",
        "distributed_fencing_not_claimed",
    ]
}

fn validate_required_assertions(
    assertions: &[NamedAssertion],
    expected_names: &[&str],
) -> Result<(), String> {
    if assertions.len() != expected_names.len() {
        return Err("assertion exact set length mismatch".to_owned());
    }
    let mut observed = BTreeSet::new();
    for assertion in assertions {
        if !assertion.passed || !observed.insert(assertion.name.as_str()) {
            return Err("assertion failed or was duplicated".to_owned());
        }
    }
    let expected = expected_names.iter().copied().collect::<BTreeSet<_>>();
    if observed != expected {
        return Err("assertion exact set mismatch".to_owned());
    }
    Ok(())
}

fn canonical_regular_file(
    state: &contract_core::CanonicalState,
) -> Result<RegularFileState, String> {
    let mut matching =
        state.extensions.iter().filter(|extension| extension.id == REGULAR_FILE_EXTENSION_ID);
    let extension = matching.next().ok_or("missing regular-file extension")?;
    if matching.next().is_some() {
        return Err("duplicate regular-file extension".to_owned());
    }
    regular_file_state(extension)
        .map_err(|error| format!("invalid regular-file canonical state: {error:?}"))
}

fn ensure_absent(path: &Path, label: &str) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(format!("{label} already exists: {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("cannot inspect {label} {}: {error}", path.display())),
    }
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("cannot write and sync {}: {error}", path.display()))
}

fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| format!("cannot sync directory {}: {error}", path.display()))
}

fn read_regular_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    if metadata.len() > limit {
        return Err(format!("{} exceeds the bounded read limit", path.display()));
    }
    let file =
        File::open(path).map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > limit {
        return Err(format!("{} changed while it was read", path.display()));
    }
    Ok(bytes)
}

fn validate_relative_uri(uri: &str) -> Result<(), String> {
    let path = Path::new(uri);
    if uri.is_empty()
        || path.is_absolute()
        || path.components().any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("unsafe artifact URI {uri}"));
    }
    Ok(())
}

fn required_artifact<'a>(
    files: &'a BTreeMap<String, Vec<u8>>,
    uri: &str,
) -> Result<&'a [u8], String> {
    files.get(uri).map(Vec::as_slice).ok_or_else(|| format!("missing required artifact {uri}"))
}

fn non_claims() -> Vec<String> {
    NON_CLAIMS.iter().map(|item| (*item).to_owned()).collect()
}

fn require_sha256(value: &str, label: &str) -> Result<(), String> {
    if value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(format!("{label} is not a lowercase SHA-256 digest"))
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_bytes(&Sha256::digest(bytes))
}

fn digest_hex(digest: Digest) -> String {
    hex_bytes(&digest.0)
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[(byte >> 4) as usize]));
        output.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    output
}

fn now_unix_ms() -> Result<u64, String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock precedes Unix epoch: {error}"))?;
    u64::try_from(duration.as_millis()).map_err(|_| "timestamp does not fit u64".to_owned())
}

fn runtime_error(error: impl std::fmt::Debug) -> String {
    format!("runtime error: {error:?}")
}

fn adapter_error(error: impl std::fmt::Display) -> String {
    format!("regular-file adapter error: {error}")
}

fn provider_error(error: substrate_api::ProviderError) -> String {
    format!("provider error {:?} (retryable={})", error.kind, error.retryable)
}

fn io_error(action: &'static str) -> impl FnOnce(std::io::Error) -> String {
    move |error| format!("cannot {action}: {error}")
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new(label: &str) -> Self {
            let unique = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("visa-stage3a-cross-host-{label}-{}-{unique}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).expect("temporary parent is created");
            Self(path)
        }

        fn child(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn source_fixture(root: &TempRoot) -> SourceBundle {
        run_source_role(&root.child("source")).expect("source role succeeds")
    }

    fn distinct_destination(source: &SourceBundle, label: &[u8]) -> HostIdentity {
        let mut destination = source.host.clone();
        destination.endpoint_id_sha256 = sha256_hex(label);
        destination.hostname = "bounded-test-destination".to_owned();
        destination
    }

    fn request_for(
        source: &SourceBundle,
        destination: &HostIdentity,
    ) -> (EndpointHello, ActivationToken, DestinationRequest) {
        let hello = EndpointHello {
            schema_version: HELLO_SCHEMA.to_owned(),
            cell_id: CROSS_HOST_CELL_ID.to_owned(),
            host: destination.clone(),
        };
        let source_digest = compact_sha256(source).expect("source digest computes");
        let activation = create_activation_token(source, &source_digest, 0, &hello)
            .expect("activation token is issued");
        let request = DestinationRequest {
            schema_version: REQUEST_SCHEMA.to_owned(),
            source: source.clone(),
            activation: activation.clone(),
        };
        (hello, activation, request)
    }

    #[test]
    fn independent_destination_resumes_at_offset_and_reads_suffix() {
        let root = TempRoot::new("positive");
        let source = source_fixture(&root);
        let destination = distinct_destination(&source, b"positive-destination");
        let (_, _, request) = request_for(&source, &destination);
        let receipt = run_destination_role_with_host(
            &request,
            &root.child("destination"),
            destination,
            now_unix_ms().unwrap(),
        )
        .expect("destination role succeeds");
        assert_eq!(receipt.resumed_logical_offset, FINAL_OFFSET);
        assert_eq!(receipt.read_suffix_sha256, sha256_hex(DESTINATION_SUFFIX));
        assert!(!receipt.source_database_transferred);
        assert!(!receipt.distributed_fencing_claim);
        assert!(receipt.assertions.iter().all(|assertion| assertion.passed));
    }

    #[test]
    fn object_tamper_is_rejected_before_destination_root_exists() {
        let root = TempRoot::new("object-tamper");
        let mut source = source_fixture(&root);
        let destination = distinct_destination(&source, b"object-tamper-destination");
        let (_, activation, _) = request_for(&source, &destination);
        let file = source
            .objects
            .iter_mut()
            .find(|object| object.kind == ObjectKind::RegularFileImage)
            .unwrap();
        file.bytes[0] ^= 1;
        let request =
            DestinationRequest { schema_version: REQUEST_SCHEMA.to_owned(), source, activation };
        let destination_root = root.child("destination");
        let error = run_destination_role_with_host(
            &request,
            &destination_root,
            destination,
            now_unix_ms().unwrap(),
        )
        .expect_err("tampered object is rejected");
        assert!(error.contains("transport object digest mismatch"));
        assert!(!destination_root.exists());
    }

    #[test]
    fn activation_token_rejects_destination_substitution_before_materialization() {
        let root = TempRoot::new("token-substitution");
        let source = source_fixture(&root);
        let destination = distinct_destination(&source, b"intended-destination");
        let (_, _, request) = request_for(&source, &destination);
        let substituted = distinct_destination(&source, b"substituted-destination");
        let destination_root = root.child("destination");
        let error = run_destination_role_with_host(
            &request,
            &destination_root,
            substituted,
            now_unix_ms().unwrap(),
        )
        .expect_err("destination substitution is rejected");
        assert!(error.contains("activation token binding"));
        assert!(!destination_root.exists());
    }

    #[test]
    fn publication_verifier_recomputes_objects_and_rejects_tamper() {
        let root = TempRoot::new("publication");
        let source = source_fixture(&root);
        let destination = distinct_destination(&source, b"publication-destination");
        let (hello, activation, request) = request_for(&source, &destination);
        let receipt = run_destination_role_with_host(
            &request,
            &root.child("destination"),
            destination,
            now_unix_ms().unwrap(),
        )
        .expect("destination role succeeds");
        let source_bytes = encode_compact(&source, "test source").unwrap();
        let hello_bytes = encode_compact(&hello, "test hello").unwrap();
        let activation_bytes = encode_compact(&activation, "test activation").unwrap();
        let receipt_bytes = encode_compact(&receipt, "test receipt").unwrap();
        let artifact_root = root.child("artifact");
        publish_cross_host(
            &artifact_root,
            source.started_at_unix_ms,
            receipt.finished_at_unix_ms,
            &source_bytes,
            &source,
            &hello_bytes,
            &hello,
            &activation_bytes,
            &activation,
            &receipt_bytes,
            &receipt,
        )
        .expect("publication succeeds");
        verify_cross_host_publication(&artifact_root).expect("publication verifies");
        let file_object = object(&source, ObjectKind::RegularFileImage).unwrap();
        fs::write(artifact_root.join(file_object.uri()), b"tampered")
            .expect("test mutates retained object");
        assert!(verify_cross_host_publication(&artifact_root).is_err());
    }
}
