use std::{
    collections::BTreeSet,
    env, fs,
    fs::OpenOptions,
    io::{self, Cursor, Write},
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

use contract_core::{
    Digest as ContractDigest, EffectOutcome, EffectRequest, EntityRef, Identity, LeaseEpoch,
    NodeIdentity, canonical_digest,
};
use joint_handoff_core::{
    OwnershipAbortReceipt, OwnershipCommitReceipt, OwnershipPreparedReceipt, PrepareIntentReceipt,
    ReceiptKind, TypedReceipt, canonical_bytes, canonical_digest as joint_canonical_digest,
    canonical_from_bytes,
};
use rusqlite::{Connection, MAIN_DB};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use visa_conformance::artifact_io::{SecureArtifactFile, SecureArtifactRoot};
use visa_joint_handoff::{JointProjectionLogHead, JointProjectionRecord};
use visa_joint_handoff_system::{
    DESTINATION_DATABASE, JOINT_PROJECTION_DATABASE, LOGICAL_REQUEST_ADMISSION_REPORT,
    LOGICAL_REQUEST_ADMISSION_SCHEMA, LogicalRequestAdmissionExpectations,
    LogicalRequestAdmissionInputs, LogicalRequestAdmissionReport, NexusProcessQualificationInputs,
    OWNERSHIP_DATABASE, OwnershipCommitRequest, OwnershipReserveRequest, OwnershipSealRequest,
    SOURCE_DATABASE, run_logical_request_admission_cell, validate_logical_request_admission_report,
};
use visa_profile::{
    LOGICAL_REQUEST_EXTENSION_ID, LogicalRequestPhase, LogicalRequestState, logical_request_state,
};

const MANIFEST_SCHEMA: &str = "visa.logical-request-admission-artifact.v1";
const EVIDENCE_STATUS: &str = "bounded-same-boot-admission-ordered-logical-request-lost-ack";
const MANIFEST_FILE: &str = "logical-request-admission-manifest.json";
const INCOMPLETE_FILE: &str = "logical-request-admission-incomplete";
const NEXUS_EFFECT_PEER_FILE: &str = "nexus-effect-peer";
const NEXUS_EFFECT_PEER_SCHEMA: &str = "opaque-nexus-effect-peer-bytes-sha256-v1";
const SOURCE_DATABASE_SCHEMA: &str = "sqlite3-substrate-host-source-user-version-5";
const DESTINATION_DATABASE_SCHEMA: &str = "sqlite3-substrate-host-destination-user-version-5";
const OWNERSHIP_DATABASE_SCHEMA: &str = "sqlite3-reference-ownership-user-version-2";
const JOINT_PROJECTION_DATABASE_SCHEMA: &str = "sqlite3-visa-joint-projection-v1-user-version-0";
const SOURCE_DATABASE_USER_VERSION: u32 = 5;
const DESTINATION_DATABASE_USER_VERSION: u32 = 5;
const OWNERSHIP_DATABASE_USER_VERSION: u32 = 2;
const JOINT_PROJECTION_DATABASE_USER_VERSION: u32 = 0;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_REPORT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_DATABASE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_EXECUTABLE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ARTIFACT_SET_BYTES: u64 = 192 * 1024 * 1024;
const EXPECTED_LOGICAL_REQUEST: &[u8] = b"visa-admission-ordered-request-v1";
const EXPECTED_LOGICAL_RESPONSE: &[u8] = b"visa-admission-ordered-response-v1";

type OwnershipHandoffRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
type ProviderOperationRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Run,
    Verify,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Arguments {
    mode: Mode,
    artifact_root: PathBuf,
    execution_executable: Option<PathBuf>,
    expected_manifest_sha256: Option<String>,
    provenance: ArtifactProvenance,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactProvenance {
    visa_revision: String,
    nexus_revision: String,
    nexus_reference_baseline_revision: String,
    nexus_executable_sha256: String,
    neutral_revision: String,
    neutral_tree: String,
    neutral_bundle_sha256: String,
    source_lock_sha256: String,
    nexus_qualification_lock_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactManifest {
    schema: String,
    evidence_status: String,
    report: ArtifactFile,
    source_database: ArtifactFile,
    destination_database: ArtifactFile,
    ownership_database: ArtifactFile,
    joint_projection_database: ArtifactFile,
    nexus_effect_peer: ArtifactFile,
    provenance: ArtifactProvenance,
    expectations: LogicalRequestAdmissionExpectations,
    limitations: ArtifactLimitations,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactFile {
    path: String,
    bytes: u64,
    sha256: String,
    schema: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactLimitations {
    same_boot_only: bool,
    cross_host_claimed: bool,
    host_reboot_recovery_claimed: bool,
    real_ostd_execution_claimed: bool,
    irq_or_smp_claimed: bool,
    retained_tombstone_supported: bool,
    registry_replacement_supported: bool,
    cryptographic_freshness_claimed: bool,
    general_exactly_once_claimed: bool,
    source_to_binary_reproducibility_claimed: bool,
    remote_ci_observed: bool,
    process_pid_path_and_start_ticks_are_normative_provenance: bool,
    artifact_owned_binary_reexecuted_during_verification: bool,
}

impl ArtifactLimitations {
    const fn bounded() -> Self {
        Self {
            same_boot_only: true,
            cross_host_claimed: false,
            host_reboot_recovery_claimed: false,
            real_ostd_execution_claimed: false,
            irq_or_smp_claimed: false,
            retained_tombstone_supported: false,
            registry_replacement_supported: false,
            cryptographic_freshness_claimed: false,
            general_exactly_once_claimed: false,
            source_to_binary_reproducibility_claimed: false,
            remote_ci_observed: false,
            process_pid_path_and_start_ticks_are_normative_provenance: false,
            artifact_owned_binary_reexecuted_during_verification: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ArtifactSet {
    manifest: SecureArtifactFile,
    report: SecureArtifactFile,
    source_database: SecureArtifactFile,
    destination_database: SecureArtifactFile,
    ownership_database: SecureArtifactFile,
    joint_projection_database: SecureArtifactFile,
    nexus_effect_peer: SecureArtifactFile,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredLedgerPhase {
    Prepared,
    Pending,
    UnknownCompletion,
    Completed,
    TimedOut,
    Cancelled,
    Rejected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredResponseMetadata {
    size: u32,
    digest: ContractDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredLogicalLedgerRecord {
    #[serde(default)]
    revision: u64,
    resource: EntityRef,
    operation_id: Identity,
    peer_identity: Vec<u8>,
    credential_reference: Identity,
    request_size: u32,
    request_digest: ContractDigest,
    request: Option<Vec<u8>>,
    phase: StoredLedgerPhase,
    response: Option<Vec<u8>>,
    #[serde(default)]
    response_metadata: Option<StoredResponseMetadata>,
    delivered_cursor: u32,
    rejection: Option<serde_json::Value>,
    cleaned: bool,
}

#[derive(Clone, Copy)]
struct LedgerExpectations<'a> {
    operation: Identity,
    resource: EntityRef,
    peer_identity: &'a [u8],
    credential_reference: Identity,
    request: &'a [u8],
    retained_request: bool,
    response: Option<&'a [u8]>,
    revision: u64,
    phase: StoredLedgerPhase,
    delivered_cursor: u32,
}

#[derive(Clone, Copy)]
struct ProviderOperationBinding<'a> {
    operation: &'a [u8],
    idempotency: &'a [u8],
    request: &'a EffectRequest,
    outcome: &'a EffectOutcome,
    cleaned: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredOwnershipPhase {
    Reserved,
    Prepared,
    AbortDecided,
    CommitDecided,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredOwnership {
    key: joint_handoff_core::JointHandoffKey,
    reservation: Identity,
    state_sequence: u64,
    phase: StoredOwnershipPhase,
    reserve_request_digest: ContractDigest,
    intent: PrepareIntentReceipt,
    seal_request_digest: Option<ContractDigest>,
    prepared: Option<OwnershipPreparedReceipt>,
    abort_request_digest: Option<ContractDigest>,
    abort: Option<OwnershipAbortReceipt>,
    commit_request_digest: Option<ContractDigest>,
    commit: Option<OwnershipCommitReceipt>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredUnitOwnership {
    continuity_unit: EntityRef,
    owner: NodeIdentity,
    epoch: LeaseEpoch,
    active_handoff: Option<Identity>,
    active_reservation: Option<Identity>,
}

fn main() -> ExitCode {
    match run_main() {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Logical-request admission artifact failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn run_main() -> Result<String, String> {
    let mut values = env::args_os();
    let program = values.next().unwrap_or_default();
    let arguments = parse_arguments(&program, &values.collect::<Vec<_>>())?;
    validate_provenance(&arguments.provenance)?;

    match arguments.mode {
        Mode::Run => {
            require(
                arguments.expected_manifest_sha256.is_none(),
                "run mode unexpectedly accepted a manifest digest",
            )?;
            let supplied = arguments
                .execution_executable
                .as_deref()
                .ok_or("run mode omitted the external Nexus executable")?;
            let executable =
                canonical_executable(supplied, &arguments.provenance.nexus_executable_sha256)?;
            let manifest_sha256 =
                publish_artifact(&arguments.artifact_root, &arguments.provenance, &executable)?;
            Ok(format!(
                "Logical-request admission artifact: {} manifest_sha256={manifest_sha256}",
                arguments.artifact_root.display()
            ))
        }
        Mode::Verify => {
            require(
                arguments.execution_executable.is_none(),
                "verify mode unexpectedly accepted an external Nexus executable",
            )?;
            let expected_manifest_sha256 = arguments
                .expected_manifest_sha256
                .as_deref()
                .ok_or("verify mode omitted the external manifest digest")?;
            verify_artifact(
                &arguments.artifact_root,
                expected_manifest_sha256,
                &arguments.provenance,
            )?;
            Ok(format!(
                "Verified logical-request admission artifact: {} manifest_sha256={expected_manifest_sha256}",
                arguments.artifact_root.display()
            ))
        }
    }
}

fn parse_arguments(
    program: &std::ffi::OsStr,
    values: &[std::ffi::OsString],
) -> Result<Arguments, String> {
    match values.first().and_then(|value| value.to_str()) {
        Some("run") if values.len() == 12 => Ok(Arguments {
            mode: Mode::Run,
            artifact_root: PathBuf::from(&values[1]),
            execution_executable: Some(PathBuf::from(&values[3])),
            expected_manifest_sha256: None,
            provenance: ArtifactProvenance {
                visa_revision: utf8(&values[2], "vISA revision")?,
                nexus_executable_sha256: utf8(&values[4], "Nexus executable SHA-256")?,
                nexus_revision: utf8(&values[5], "qualified Nexus revision")?,
                nexus_reference_baseline_revision: utf8(
                    &values[6],
                    "Nexus reference baseline revision",
                )?,
                neutral_revision: utf8(&values[7], "neutral revision")?,
                neutral_tree: utf8(&values[8], "neutral tree")?,
                neutral_bundle_sha256: utf8(&values[9], "neutral bundle SHA-256")?,
                source_lock_sha256: utf8(&values[10], "source-lock SHA-256")?,
                nexus_qualification_lock_sha256: utf8(
                    &values[11],
                    "Nexus qualification-lock SHA-256",
                )?,
            },
        }),
        Some("verify") if values.len() == 12 => Ok(Arguments {
            mode: Mode::Verify,
            artifact_root: PathBuf::from(&values[1]),
            execution_executable: None,
            expected_manifest_sha256: Some(utf8(&values[2], "expected manifest SHA-256")?),
            provenance: ArtifactProvenance {
                visa_revision: utf8(&values[3], "vISA revision")?,
                nexus_executable_sha256: utf8(&values[4], "Nexus executable SHA-256")?,
                nexus_revision: utf8(&values[5], "qualified Nexus revision")?,
                nexus_reference_baseline_revision: utf8(
                    &values[6],
                    "Nexus reference baseline revision",
                )?,
                neutral_revision: utf8(&values[7], "neutral revision")?,
                neutral_tree: utf8(&values[8], "neutral tree")?,
                neutral_bundle_sha256: utf8(&values[9], "neutral bundle SHA-256")?,
                source_lock_sha256: utf8(&values[10], "source-lock SHA-256")?,
                nexus_qualification_lock_sha256: utf8(
                    &values[11],
                    "Nexus qualification-lock SHA-256",
                )?,
            },
        }),
        _ => Err(usage(program)),
    }
}

fn usage(program: &std::ffi::OsStr) -> String {
    format!(
        "usage:\n  {} run <artifact-root> <visa-sha> <external-nexus-effect-peer-bin> <nexus-bin-sha256> <qualified-nexus-sha> <nexus-reference-baseline-sha> <neutral-sha> <neutral-tree> <neutral-bundle-sha256> <source-lock-sha256> <nexus-qualification-lock-sha256>\n  {} verify <artifact-root> <expected-manifest-sha256> <visa-sha> <nexus-bin-sha256> <qualified-nexus-sha> <nexus-reference-baseline-sha> <neutral-sha> <neutral-tree> <neutral-bundle-sha256> <source-lock-sha256> <nexus-qualification-lock-sha256>\nverify securely reads but never executes the artifact-owned ./{} binary",
        PathBuf::from(program).display(),
        PathBuf::from(program).display(),
        NEXUS_EFFECT_PEER_FILE,
    )
}

fn utf8(value: &std::ffi::OsStr, label: &str) -> Result<String, String> {
    value.to_str().map(str::to_owned).ok_or_else(|| format!("{label} is not UTF-8"))
}

fn publish_artifact(
    root: &Path,
    provenance: &ArtifactProvenance,
    execution_executable: &Path,
) -> Result<String, String> {
    verify_executed_visa_checkout(&provenance.visa_revision)?;
    let execution_executable =
        canonical_executable(execution_executable, &provenance.nexus_executable_sha256)?;
    create_artifact_root(root)?;
    let incomplete = root.join(INCOMPLETE_FILE);
    write_new(&incomplete, b"logical-request admission publication incomplete\n")?;

    let publication = (|| {
        let report = run_logical_request_admission_cell(
            root,
            LogicalRequestAdmissionInputs {
                run_identity: derive_run_identity(provenance)?,
                nexus: NexusProcessQualificationInputs {
                    executable: execution_executable.clone(),
                    executable_sha256: provenance.nexus_executable_sha256.clone(),
                    nexus_revision: provenance.nexus_revision.clone(),
                },
            },
        )?;
        let expectations = LogicalRequestAdmissionExpectations {
            run_identity: derive_run_identity(provenance)?,
            nexus_process: report.nexus.process.clone(),
        };
        validate_manifest_expectations(&expectations, provenance)?;
        validate_logical_request_admission_report(&report, &expectations)?;
        require(
            report.nexus.process.executable_path == execution_executable,
            "admission report did not observe the exact run-only external executable path",
        )?;

        let report_raw = read_stable_regular(
            &root.join(LOGICAL_REQUEST_ADMISSION_REPORT),
            "generated admission report",
            MAX_REPORT_BYTES,
        )?;
        require(
            canonical_report_json(&report)? == report_raw,
            "generated admission report differs from the canonical returned evidence",
        )?;
        let source_raw = read_stable_regular(
            &root.join(SOURCE_DATABASE),
            "source database",
            MAX_DATABASE_BYTES,
        )?;
        let destination_raw = read_stable_regular(
            &root.join(DESTINATION_DATABASE),
            "destination database",
            MAX_DATABASE_BYTES,
        )?;
        let ownership_raw = read_stable_regular(
            &root.join(OWNERSHIP_DATABASE),
            "ownership database",
            MAX_DATABASE_BYTES,
        )?;
        let joint_projection_raw = read_stable_regular(
            &root.join(JOINT_PROJECTION_DATABASE),
            "joint projection database",
            MAX_DATABASE_BYTES,
        )?;
        validate_sqlite_bytes(&source_raw, SOURCE_DATABASE_USER_VERSION, "source database")?;
        validate_sqlite_bytes(
            &destination_raw,
            DESTINATION_DATABASE_USER_VERSION,
            "destination database",
        )?;
        validate_sqlite_bytes(
            &ownership_raw,
            OWNERSHIP_DATABASE_USER_VERSION,
            "ownership database",
        )?;
        validate_sqlite_bytes(
            &joint_projection_raw,
            JOINT_PROJECTION_DATABASE_USER_VERSION,
            "joint projection database",
        )?;

        let executable_raw = read_stable_regular(
            &execution_executable,
            "executed external Nexus effect peer",
            MAX_EXECUTABLE_BYTES,
        )?;
        require(
            sha256_hex(&executable_raw) == provenance.nexus_executable_sha256,
            "executed external Nexus effect peer changed before artifact capture",
        )?;
        write_new_executable(root.join(NEXUS_EFFECT_PEER_FILE), &executable_raw)?;

        let secure_root = SecureArtifactRoot::open(root).map_err(secure_error)?;
        require_inventory(&secure_root, &incomplete_inventory(), "incomplete inventory drifted")?;
        let manifest = ArtifactManifest {
            schema: MANIFEST_SCHEMA.to_owned(),
            evidence_status: EVIDENCE_STATUS.to_owned(),
            report: artifact_file(
                LOGICAL_REQUEST_ADMISSION_REPORT,
                LOGICAL_REQUEST_ADMISSION_SCHEMA,
                &report_raw,
            )?,
            source_database: artifact_file(SOURCE_DATABASE, SOURCE_DATABASE_SCHEMA, &source_raw)?,
            destination_database: artifact_file(
                DESTINATION_DATABASE,
                DESTINATION_DATABASE_SCHEMA,
                &destination_raw,
            )?,
            ownership_database: artifact_file(
                OWNERSHIP_DATABASE,
                OWNERSHIP_DATABASE_SCHEMA,
                &ownership_raw,
            )?,
            joint_projection_database: artifact_file(
                JOINT_PROJECTION_DATABASE,
                JOINT_PROJECTION_DATABASE_SCHEMA,
                &joint_projection_raw,
            )?,
            nexus_effect_peer: artifact_file(
                NEXUS_EFFECT_PEER_FILE,
                NEXUS_EFFECT_PEER_SCHEMA,
                &executable_raw,
            )?,
            provenance: provenance.clone(),
            expectations,
            limitations: ArtifactLimitations::bounded(),
        };
        let manifest_raw = canonical_manifest_json(&manifest)?;
        let manifest_sha256 = sha256_hex(&manifest_raw);
        write_new(root.join(MANIFEST_FILE), &manifest_raw)?;

        canonical_executable(&execution_executable, &provenance.nexus_executable_sha256)?;
        verify_executed_visa_checkout(&provenance.visa_revision)?;
        fs::remove_file(&incomplete)
            .map_err(|error| format!("cannot remove {}: {error}", incomplete.display()))?;
        verify_artifact(root, &manifest_sha256, provenance)?;
        Ok(manifest_sha256)
    })();
    if publication.is_err() && !incomplete.exists() {
        let _ = fs::write(&incomplete, b"logical-request admission publication incomplete\n");
    }
    publication
}

fn verify_artifact(
    root: &Path,
    expected_manifest_sha256: &str,
    expected_provenance: &ArtifactProvenance,
) -> Result<(), String> {
    validate_provenance(expected_provenance)?;
    require(
        is_lower_hex(expected_manifest_sha256, 64),
        "expected manifest SHA-256 is not canonical",
    )?;
    verify_executed_visa_checkout(&expected_provenance.visa_revision)?;
    let secure_root = SecureArtifactRoot::open(root).map_err(secure_error)?;
    require_inventory(
        &secure_root,
        &final_inventory(),
        "artifact inventory differs from the strict seven-file publication",
    )?;
    let artifacts = read_artifact_set(&secure_root)?;
    require(
        sha256_hex(&artifacts.manifest.bytes) == expected_manifest_sha256,
        "artifact manifest differs from the externally supplied SHA-256",
    )?;

    let manifest: ArtifactManifest = decode_canonical_manifest(&artifacts.manifest.bytes)?;
    validate_manifest(&manifest, expected_provenance, &artifacts)?;
    let report: LogicalRequestAdmissionReport = decode_canonical_report(&artifacts.report.bytes)?;
    validate_logical_request_admission_report(&report, &manifest.expectations)?;
    validate_report_inventory(&report)?;
    validate_databases(&artifacts, &report)?;
    require(
        sha256_hex(&artifacts.nexus_effect_peer.bytes)
            == expected_provenance.nexus_executable_sha256,
        "artifact-owned Nexus effect peer differs from exact provenance",
    )?;

    let database_identities = [
        (artifacts.source_database.device, artifacts.source_database.inode),
        (artifacts.destination_database.device, artifacts.destination_database.inode),
        (artifacts.ownership_database.device, artifacts.ownership_database.inode),
        (artifacts.joint_projection_database.device, artifacts.joint_projection_database.inode),
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    require(
        database_identities.len() == 4,
        "artifact SQLite files do not have four distinct live identities",
    )?;

    require_inventory(
        &secure_root,
        &final_inventory(),
        "artifact inventory changed during verification",
    )?;
    verify_artifact_set_unchanged(&secure_root, &artifacts)?;
    verify_executed_visa_checkout(&expected_provenance.visa_revision)
}

fn read_artifact_set(root: &SecureArtifactRoot) -> Result<ArtifactSet, String> {
    let mut remaining = MAX_ARTIFACT_SET_BYTES;
    let artifacts = ArtifactSet {
        manifest: secure_read_budgeted(root, MANIFEST_FILE, MAX_MANIFEST_BYTES, &mut remaining)?,
        report: secure_read_budgeted(
            root,
            LOGICAL_REQUEST_ADMISSION_REPORT,
            MAX_REPORT_BYTES,
            &mut remaining,
        )?,
        source_database: secure_read_budgeted(
            root,
            SOURCE_DATABASE,
            MAX_DATABASE_BYTES,
            &mut remaining,
        )?,
        destination_database: secure_read_budgeted(
            root,
            DESTINATION_DATABASE,
            MAX_DATABASE_BYTES,
            &mut remaining,
        )?,
        ownership_database: secure_read_budgeted(
            root,
            OWNERSHIP_DATABASE,
            MAX_DATABASE_BYTES,
            &mut remaining,
        )?,
        joint_projection_database: secure_read_budgeted(
            root,
            JOINT_PROJECTION_DATABASE,
            MAX_DATABASE_BYTES,
            &mut remaining,
        )?,
        nexus_effect_peer: secure_read_budgeted(
            root,
            NEXUS_EFFECT_PEER_FILE,
            MAX_EXECUTABLE_BYTES,
            &mut remaining,
        )?,
    };
    require(
        artifact_set_bytes(&artifacts)? <= MAX_ARTIFACT_SET_BYTES,
        "artifact set exceeds its aggregate byte limit",
    )?;
    Ok(artifacts)
}

fn artifact_set_bytes(artifacts: &ArtifactSet) -> Result<u64, String> {
    [
        &artifacts.manifest,
        &artifacts.report,
        &artifacts.source_database,
        &artifacts.destination_database,
        &artifacts.ownership_database,
        &artifacts.joint_projection_database,
        &artifacts.nexus_effect_peer,
    ]
    .into_iter()
    .try_fold(0_u64, |total, artifact| {
        let length = u64::try_from(artifact.bytes.len())
            .map_err(|_| "artifact byte length does not fit u64".to_owned())?;
        total.checked_add(length).ok_or_else(|| "artifact byte total overflowed".to_owned())
    })
}

fn verify_artifact_set_unchanged(
    root: &SecureArtifactRoot,
    expected: &ArtifactSet,
) -> Result<(), String> {
    for (path, maximum, artifact) in [
        (MANIFEST_FILE, MAX_MANIFEST_BYTES, &expected.manifest),
        (LOGICAL_REQUEST_ADMISSION_REPORT, MAX_REPORT_BYTES, &expected.report),
        (SOURCE_DATABASE, MAX_DATABASE_BYTES, &expected.source_database),
        (DESTINATION_DATABASE, MAX_DATABASE_BYTES, &expected.destination_database),
        (OWNERSHIP_DATABASE, MAX_DATABASE_BYTES, &expected.ownership_database),
        (JOINT_PROJECTION_DATABASE, MAX_DATABASE_BYTES, &expected.joint_projection_database),
        (NEXUS_EFFECT_PEER_FILE, MAX_EXECUTABLE_BYTES, &expected.nexus_effect_peer),
    ] {
        require(
            secure_read(root, path, maximum)? == *artifact,
            "artifact bytes or live file identities changed during verification",
        )?;
    }
    Ok(())
}

fn secure_read(
    root: &SecureArtifactRoot,
    path: &str,
    maximum: u64,
) -> Result<SecureArtifactFile, String> {
    root.read_single_link_regular(path, maximum).map_err(secure_error)
}

fn secure_read_budgeted(
    root: &SecureArtifactRoot,
    path: &str,
    per_file_maximum: u64,
    remaining: &mut u64,
) -> Result<SecureArtifactFile, String> {
    let artifact = secure_read(root, path, per_file_maximum.min(*remaining))?;
    let length = u64::try_from(artifact.bytes.len())
        .map_err(|_| format!("artifact byte length does not fit u64: {path}"))?;
    *remaining = remaining
        .checked_sub(length)
        .ok_or_else(|| "artifact set exceeds its aggregate byte limit".to_owned())?;
    Ok(artifact)
}

fn secure_error(error: visa_conformance::artifact_io::SecureArtifactError) -> String {
    error.to_string()
}

fn final_inventory() -> Vec<String> {
    [
        MANIFEST_FILE,
        LOGICAL_REQUEST_ADMISSION_REPORT,
        SOURCE_DATABASE,
        DESTINATION_DATABASE,
        OWNERSHIP_DATABASE,
        JOINT_PROJECTION_DATABASE,
        NEXUS_EFFECT_PEER_FILE,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn incomplete_inventory() -> Vec<String> {
    [
        INCOMPLETE_FILE,
        LOGICAL_REQUEST_ADMISSION_REPORT,
        SOURCE_DATABASE,
        DESTINATION_DATABASE,
        OWNERSHIP_DATABASE,
        JOINT_PROJECTION_DATABASE,
        NEXUS_EFFECT_PEER_FILE,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn require_inventory(
    root: &SecureArtifactRoot,
    expected: &[String],
    message: &str,
) -> Result<(), String> {
    let mut expected = expected.to_vec();
    expected.sort();
    require(root.inventory().map_err(secure_error)? == expected, message)
}

fn validate_manifest(
    manifest: &ArtifactManifest,
    expected_provenance: &ArtifactProvenance,
    artifacts: &ArtifactSet,
) -> Result<(), String> {
    require(manifest.schema == MANIFEST_SCHEMA, "artifact manifest schema drifted")?;
    require(manifest.evidence_status == EVIDENCE_STATUS, "artifact evidence status drifted")?;
    require(
        manifest.provenance == *expected_provenance,
        "artifact provenance differs from independently supplied expectations",
    )?;
    require(
        manifest.limitations == ArtifactLimitations::bounded(),
        "artifact limitations overclaim the bounded experiment",
    )?;
    validate_manifest_expectations(&manifest.expectations, expected_provenance)?;
    validate_manifest_sizes(manifest)?;
    require(
        file_matches(
            &manifest.report,
            LOGICAL_REQUEST_ADMISSION_REPORT,
            LOGICAL_REQUEST_ADMISSION_SCHEMA,
            &artifacts.report.bytes,
        ) && file_matches(
            &manifest.source_database,
            SOURCE_DATABASE,
            SOURCE_DATABASE_SCHEMA,
            &artifacts.source_database.bytes,
        ) && file_matches(
            &manifest.destination_database,
            DESTINATION_DATABASE,
            DESTINATION_DATABASE_SCHEMA,
            &artifacts.destination_database.bytes,
        ) && file_matches(
            &manifest.ownership_database,
            OWNERSHIP_DATABASE,
            OWNERSHIP_DATABASE_SCHEMA,
            &artifacts.ownership_database.bytes,
        ) && file_matches(
            &manifest.joint_projection_database,
            JOINT_PROJECTION_DATABASE,
            JOINT_PROJECTION_DATABASE_SCHEMA,
            &artifacts.joint_projection_database.bytes,
        ) && file_matches(
            &manifest.nexus_effect_peer,
            NEXUS_EFFECT_PEER_FILE,
            NEXUS_EFFECT_PEER_SCHEMA,
            &artifacts.nexus_effect_peer.bytes,
        ),
        "artifact evidence bytes do not match the exact manifest inventory",
    )
}

fn validate_manifest_sizes(manifest: &ArtifactManifest) -> Result<(), String> {
    let bounded = [
        (&manifest.report, MAX_REPORT_BYTES),
        (&manifest.source_database, MAX_DATABASE_BYTES),
        (&manifest.destination_database, MAX_DATABASE_BYTES),
        (&manifest.ownership_database, MAX_DATABASE_BYTES),
        (&manifest.joint_projection_database, MAX_DATABASE_BYTES),
        (&manifest.nexus_effect_peer, MAX_EXECUTABLE_BYTES),
    ];
    require(
        bounded.iter().all(|(file, maximum)| file.bytes <= *maximum),
        "artifact manifest declares a file above its verifier limit",
    )?;
    let declared = bounded.iter().try_fold(
        u64::try_from(canonical_manifest_json(manifest)?.len())
            .map_err(|_| "manifest byte length does not fit u64".to_owned())?,
        |total, (file, _)| {
            total
                .checked_add(file.bytes)
                .ok_or_else(|| "artifact manifest byte total overflowed".to_owned())
        },
    )?;
    require(
        declared <= MAX_ARTIFACT_SET_BYTES,
        "artifact manifest exceeds the aggregate byte limit",
    )
}

fn validate_manifest_expectations(
    expectations: &LogicalRequestAdmissionExpectations,
    provenance: &ArtifactProvenance,
) -> Result<(), String> {
    let process = &expectations.nexus_process;
    require(
        expectations.run_identity == derive_run_identity(provenance)?
            && process.process_id != 0
            && process.start_time_ticks != 0
            && process.executable_path.is_absolute()
            && !process.executable_path.as_os_str().is_empty()
            && process.executable_sha256 == provenance.nexus_executable_sha256
            && process.nexus_revision == provenance.nexus_revision,
        "artifact expectations do not bind exact run and process provenance",
    )
}

fn validate_report_inventory(report: &LogicalRequestAdmissionReport) -> Result<(), String> {
    require(
        report.databases.source.path == SOURCE_DATABASE
            && report.databases.source.user_version == SOURCE_DATABASE_USER_VERSION
            && report.databases.destination.path == DESTINATION_DATABASE
            && report.databases.destination.user_version == DESTINATION_DATABASE_USER_VERSION
            && report.databases.ownership.path == OWNERSHIP_DATABASE
            && report.databases.ownership.user_version == OWNERSHIP_DATABASE_USER_VERSION
            && report.databases.joint_projection.path == JOINT_PROJECTION_DATABASE
            && report.databases.joint_projection.user_version
                == JOINT_PROJECTION_DATABASE_USER_VERSION,
        "admission report database inventory differs from the exact artifact contract",
    )
}

fn artifact_file(path: &str, schema: &str, raw: &[u8]) -> Result<ArtifactFile, String> {
    Ok(ArtifactFile {
        path: path.to_owned(),
        bytes: u64::try_from(raw.len())
            .map_err(|_| format!("artifact file is too large: {path}"))?,
        sha256: sha256_hex(raw),
        schema: schema.to_owned(),
    })
}

fn file_matches(file: &ArtifactFile, path: &str, schema: &str, raw: &[u8]) -> bool {
    file.path == path
        && file.schema == schema
        && file.bytes == u64::try_from(raw.len()).unwrap_or(u64::MAX)
        && file.sha256 == sha256_hex(raw)
}

fn validate_provenance(value: &ArtifactProvenance) -> Result<(), String> {
    for (label, digest) in [
        ("vISA revision", &value.visa_revision),
        ("qualified Nexus revision", &value.nexus_revision),
        ("Nexus reference baseline revision", &value.nexus_reference_baseline_revision),
        ("neutral revision", &value.neutral_revision),
        ("neutral tree", &value.neutral_tree),
    ] {
        require(is_lower_hex(digest, 40), &format!("{label} is not exact lowercase 40-hex"))?;
    }
    for (label, digest) in [
        ("Nexus executable SHA-256", &value.nexus_executable_sha256),
        ("neutral bundle SHA-256", &value.neutral_bundle_sha256),
        ("source-lock SHA-256", &value.source_lock_sha256),
        ("Nexus qualification-lock SHA-256", &value.nexus_qualification_lock_sha256),
    ] {
        require(is_lower_hex(digest, 64), &format!("{label} is not lowercase SHA-256"))?;
    }
    Ok(())
}

fn derive_run_identity(provenance: &ArtifactProvenance) -> Result<Identity, String> {
    let encoded = serde_json::to_vec(provenance)
        .map_err(|error| format!("cannot encode run identity provenance: {error}"))?;
    let mut digest = Sha256::new();
    digest.update(b"vISA logical-request admission artifact run identity v1\0");
    digest.update(u64::try_from(encoded.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(encoded);
    let digest = digest.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    let identity = Identity::from_bytes(bytes);
    require(!identity.is_zero(), "derived admission artifact run identity was zero")?;
    Ok(identity)
}

fn canonical_manifest_json(value: &ArtifactManifest) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec(value)
        .map_err(|error| format!("cannot encode admission artifact manifest: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn decode_canonical_manifest(raw: &[u8]) -> Result<ArtifactManifest, String> {
    let value = serde_json::from_slice::<ArtifactManifest>(raw)
        .map_err(|error| format!("cannot decode strict admission artifact manifest: {error}"))?;
    require(
        canonical_manifest_json(&value)? == raw,
        "admission artifact manifest is not canonical compact JSON plus one LF",
    )?;
    Ok(value)
}

fn canonical_report_json(value: &LogicalRequestAdmissionReport) -> Result<Vec<u8>, String> {
    serde_json::to_vec_pretty(value)
        .map_err(|error| format!("cannot encode canonical admission report: {error}"))
}

fn decode_canonical_report(raw: &[u8]) -> Result<LogicalRequestAdmissionReport, String> {
    let value = serde_json::from_slice::<LogicalRequestAdmissionReport>(raw)
        .map_err(|error| format!("cannot decode strict admission report: {error}"))?;
    require(
        canonical_report_json(&value)? == raw,
        "admission report is not canonical pretty JSON",
    )?;
    Ok(value)
}

fn validate_sqlite_bytes(
    raw: &[u8],
    expected_user_version: u32,
    label: &str,
) -> Result<(), String> {
    require(
        raw.len() >= 100 && raw.starts_with(b"SQLite format 3\0"),
        &format!("{label} is not a complete SQLite 3 database"),
    )?;
    let user_version = u32::from_be_bytes([raw[60], raw[61], raw[62], raw[63]]);
    require(
        user_version == expected_user_version,
        &format!(
            "{label} user_version drifted: actual={user_version}, expected={expected_user_version}"
        ),
    )
}

fn deserialize_database(raw: &[u8], label: &str) -> Result<Connection, String> {
    let mut connection = Connection::open_in_memory()
        .map_err(|error| format!("cannot open in-memory {label}: {error}"))?;
    connection
        .deserialize_read_exact(MAIN_DB, Cursor::new(raw), raw.len(), true)
        .map_err(|error| format!("cannot deserialize exact {label} bytes: {error}"))?;
    connection
        .execute_batch("PRAGMA query_only = ON;")
        .map_err(|error| format!("cannot make {label} query-only: {error}"))?;
    let query_only: i64 =
        connection.query_row("PRAGMA query_only", [], |row| row.get(0)).map_err(sqlite_error)?;
    require(query_only == 1, &format!("{label} did not remain query-only"))?;
    validate_sqlite_integrity(&connection, label)?;
    Ok(connection)
}

fn validate_databases(
    artifacts: &ArtifactSet,
    report: &LogicalRequestAdmissionReport,
) -> Result<(), String> {
    validate_sqlite_bytes(
        &artifacts.source_database.bytes,
        SOURCE_DATABASE_USER_VERSION,
        "source database",
    )?;
    validate_sqlite_bytes(
        &artifacts.destination_database.bytes,
        DESTINATION_DATABASE_USER_VERSION,
        "destination database",
    )?;
    validate_sqlite_bytes(
        &artifacts.ownership_database.bytes,
        OWNERSHIP_DATABASE_USER_VERSION,
        "ownership database",
    )?;
    validate_sqlite_bytes(
        &artifacts.joint_projection_database.bytes,
        JOINT_PROJECTION_DATABASE_USER_VERSION,
        "joint projection database",
    )?;

    let source = deserialize_database(&artifacts.source_database.bytes, "source database")?;
    let destination =
        deserialize_database(&artifacts.destination_database.bytes, "destination database")?;
    let ownership =
        deserialize_database(&artifacts.ownership_database.bytes, "ownership database")?;
    let projection = deserialize_database(
        &artifacts.joint_projection_database.bytes,
        "joint projection database",
    )?;
    validate_source_database(&source, report)?;
    validate_destination_database(&destination, report)?;
    validate_ownership_database(&ownership, report)?;
    validate_projection_database(&projection, report)
}

fn validate_source_database(
    connection: &Connection,
    report: &LogicalRequestAdmissionReport,
) -> Result<(), String> {
    require(
        query_count(connection, "SELECT COUNT(*) FROM provider_operation")? == 1
            && query_count(connection, "SELECT COUNT(*) FROM logical_request_ledger")? == 1
            && query_count(connection, "SELECT COUNT(*) FROM logical_request_effect")? == 1,
        "source database did not retain exactly one Start operation and logical ledger mapping",
    )?;
    let (operation, idempotency, request_raw, outcome_raw, cleaned): ProviderOperationRow =
        connection
            .query_row(
                "SELECT operation, idempotency_key, request, outcome, cleaned
                 FROM provider_operation",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .map_err(sqlite_error)?;
    let request: EffectRequest = decode_stored_json(&request_raw, "source provider request")?;
    let outcome: EffectOutcome = decode_stored_json(&outcome_raw, "source provider outcome")?;
    validate_provider_operation_binding(
        ProviderOperationBinding {
            operation: &operation,
            idempotency: &idempotency,
            request: &request,
            outcome: &outcome,
            cleaned,
        },
        &report.source.preview,
        &report.source.source_start_outcome,
        "source",
    )?;

    let (effect_operation, logical_operation): (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT effect_operation, logical_operation FROM logical_request_effect",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sqlite_error)?;
    require(
        identity_from_blob(&effect_operation, "source effect operation")?
            == report.source.source_start_effect
            && identity_from_blob(&logical_operation, "source logical operation")?
                == report.source.logical_operation,
        "source logical-request effect mapping differs from the report",
    )?;

    let (ledger_key, ledger_raw): (Vec<u8>, Vec<u8>) = connection
        .query_row("SELECT operation_id, record FROM logical_request_ledger", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .map_err(sqlite_error)?;
    let ledger: StoredLogicalLedgerRecord =
        decode_stored_json(&ledger_raw, "source logical-request ledger")?;
    require(
        report.source.source_ledger_retained_request,
        "source report omitted retained request bytes",
    )?;
    let logical = canonical_logical_state(&report.source.source_start_state)?;
    let expected = ledger_expectations_from_state(
        &logical,
        EXPECTED_LOGICAL_REQUEST,
        true,
        None,
        report.source.source_ledger_revision,
        StoredLedgerPhase::UnknownCompletion,
    )?;
    require(expected.revision == 3, "source ledger revision drifted from the fixed cell")?;
    validate_ledger_binding(&ledger_key, &ledger, expected, "source logical-request ledger")
}

fn validate_destination_database(
    connection: &Connection,
    report: &LogicalRequestAdmissionReport,
) -> Result<(), String> {
    require(
        query_count(connection, "SELECT COUNT(*) FROM provider_operation")? == 2
            && query_count(connection, "SELECT COUNT(*) FROM logical_request_ledger")? == 1
            && query_count(connection, "SELECT COUNT(*) FROM logical_request_effect")? == 1,
        "destination database did not retain exactly LeaseCommit plus Reconcile",
    )?;
    let lease = report
        .runtime
        .destination_activation_state
        .operations
        .last()
        .ok_or("destination activation omitted LeaseCommit")?;
    let reconcile = report
        .runtime
        .destination_terminal_state
        .operations
        .last()
        .ok_or("destination terminal state omitted Reconcile")?;
    let expected = [
        (&lease.request, lease.outcome.as_ref().ok_or("LeaseCommit omitted its outcome")?),
        (
            &reconcile.request,
            reconcile.outcome.as_ref().ok_or("destination Reconcile omitted its outcome")?,
        ),
    ];
    let mut statement = connection
        .prepare(
            "SELECT operation, idempotency_key, request, outcome, cleaned
             FROM provider_operation",
        )
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })
        .map_err(sqlite_error)?;
    let mut observed = Vec::new();
    for row in rows {
        let (operation, idempotency, request_raw, outcome_raw, cleaned) =
            row.map_err(sqlite_error)?;
        let request: EffectRequest =
            decode_stored_json(&request_raw, "destination provider request")?;
        let outcome: EffectOutcome =
            decode_stored_json(&outcome_raw, "destination provider outcome")?;
        validate_provider_operation_binding(
            ProviderOperationBinding {
                operation: &operation,
                idempotency: &idempotency,
                request: &request,
                outcome: &outcome,
                cleaned,
            },
            &request,
            &outcome,
            "destination",
        )?;
        observed.push((request, outcome));
    }
    require(
        expected.iter().all(|(request, outcome)| {
            observed.iter().any(|(actual_request, actual_outcome)| {
                actual_request == *request && actual_outcome == *outcome
            })
        }),
        "destination provider rows do not match LeaseCommit and Reconcile",
    )?;

    let (effect_operation, logical_operation): (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT effect_operation, logical_operation FROM logical_request_effect",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sqlite_error)?;
    require(
        identity_from_blob(&effect_operation, "destination effect operation")?
            == report.destination.reconcile_effect
            && identity_from_blob(&logical_operation, "destination logical operation")?
                == report.source.logical_operation,
        "destination logical-request effect mapping differs from Reconcile",
    )?;

    let (ledger_key, ledger_raw): (Vec<u8>, Vec<u8>) = connection
        .query_row("SELECT operation_id, record FROM logical_request_ledger", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .map_err(sqlite_error)?;
    let ledger: StoredLogicalLedgerRecord =
        decode_stored_json(&ledger_raw, "destination logical-request ledger")?;
    require(
        !report.destination.destination_ledger_retained_request,
        "destination report unexpectedly claims retained request bytes",
    )?;
    let logical = canonical_logical_state(&report.runtime.destination_terminal_state)?;
    let expected = ledger_expectations_from_state(
        &logical,
        EXPECTED_LOGICAL_REQUEST,
        false,
        Some(EXPECTED_LOGICAL_RESPONSE),
        report.destination.destination_ledger_revision,
        StoredLedgerPhase::Completed,
    )?;
    require(expected.revision == 2, "destination ledger revision drifted from the fixed cell")?;
    validate_ledger_binding(&ledger_key, &ledger, expected, "destination logical-request ledger")
}

fn canonical_logical_state(
    state: &contract_core::CanonicalState,
) -> Result<LogicalRequestState, String> {
    let mut matching =
        state.extensions.iter().filter(|extension| extension.id == LOGICAL_REQUEST_EXTENSION_ID);
    let extension = matching.next().ok_or("logical-request extension is absent")?;
    require(matching.next().is_none(), "logical-request extension is duplicated")?;
    logical_request_state(extension).map_err(debug)
}

fn ledger_expectations_from_state<'a>(
    state: &'a LogicalRequestState,
    request: &'a [u8],
    retained_request: bool,
    response: Option<&'a [u8]>,
    revision: u64,
    phase: StoredLedgerPhase,
) -> Result<LedgerExpectations<'a>, String> {
    let request_size =
        u32::try_from(request.len()).map_err(|_| "logical request is too large".to_owned())?;
    let request_digest =
        canonical_digest(request).map_err(|error| format!("logical request digest: {error:?}"))?;
    let response_metadata = response
        .map(|bytes| -> Result<StoredResponseMetadata, String> {
            Ok(StoredResponseMetadata {
                size: u32::try_from(bytes.len())
                    .map_err(|_| "logical response is too large".to_owned())?,
                digest: canonical_digest(bytes)
                    .map_err(|error| format!("logical response digest: {error:?}"))?,
            })
        })
        .transpose()?;
    let state_response = state
        .response
        .map(|metadata| StoredResponseMetadata { size: metadata.size, digest: metadata.digest });
    let phase_matches = matches!(
        (phase, state.phase),
        (StoredLedgerPhase::UnknownCompletion, LogicalRequestPhase::UnknownCompletion)
            | (StoredLedgerPhase::Completed, LogicalRequestPhase::Completed)
    );
    require(
        state.request_size == request_size
            && state.request_digest == request_digest
            && state_response == response_metadata
            && state.rejection.is_none()
            && phase_matches,
        "canonical logical-request state differs from exact ledger expectations",
    )?;
    Ok(LedgerExpectations {
        operation: state.operation_id,
        resource: state.claim.resource,
        peer_identity: &state.claim.peer_identity,
        credential_reference: state.claim.credential_reference,
        request,
        retained_request,
        response,
        revision,
        phase,
        delivered_cursor: state.response_cursor,
    })
}

fn validate_ledger_binding(
    ledger_key: &[u8],
    ledger: &StoredLogicalLedgerRecord,
    expected: LedgerExpectations<'_>,
    label: &str,
) -> Result<(), String> {
    let request_size = u32::try_from(expected.request.len())
        .map_err(|_| format!("{label} request is too large"))?;
    let request_digest = canonical_digest(expected.request)
        .map_err(|error| format!("{label} request digest: {error:?}"))?;
    let response_metadata = expected
        .response
        .map(|bytes| -> Result<StoredResponseMetadata, String> {
            Ok(StoredResponseMetadata {
                size: u32::try_from(bytes.len())
                    .map_err(|_| format!("{label} response is too large"))?,
                digest: canonical_digest(bytes)
                    .map_err(|error| format!("{label} response digest: {error:?}"))?,
            })
        })
        .transpose()?;
    require(
        identity_from_blob(ledger_key, &format!("{label} operation"))? == expected.operation
            && ledger.operation_id == expected.operation
            && ledger.resource == expected.resource
            && ledger.peer_identity == expected.peer_identity
            && ledger.credential_reference == expected.credential_reference
            && ledger.request_size == request_size
            && ledger.request_digest == request_digest
            && ledger.request.as_deref() == expected.retained_request.then_some(expected.request)
            && ledger.phase == expected.phase
            && ledger.response.as_deref() == expected.response
            && ledger.response_metadata == response_metadata
            && ledger.delivered_cursor == expected.delivered_cursor
            && ledger.rejection.is_none()
            && !ledger.cleaned
            && ledger.revision == expected.revision,
        &format!("{label} does not match exact canonical logical-request truth"),
    )
}

fn validate_provider_operation_binding(
    binding: ProviderOperationBinding<'_>,
    expected_request: &EffectRequest,
    expected_outcome: &EffectOutcome,
    label: &str,
) -> Result<(), String> {
    require(
        identity_from_blob(binding.operation, &format!("{label} provider operation"))?
            == expected_request.operation
            && binding.idempotency == expected_request.idempotency_key.0
            && binding.request == expected_request
            && binding.outcome == expected_outcome
            && binding.cleaned == 0,
        &format!("{label} provider row differs from exact request, outcome, or dedup key"),
    )
}

fn validate_ownership_database(
    connection: &Connection,
    report: &LogicalRequestAdmissionReport,
) -> Result<(), String> {
    require(
        query_count(connection, "SELECT COUNT(*) FROM ownership_handoff")? == 1
            && query_count(connection, "SELECT COUNT(*) FROM ownership_unit")? == 1,
        "ownership database did not retain exactly one handoff and continuity unit",
    )?;
    let key = report.ownership.commit.key;
    let (handoff, continuity, generation, expected_epoch, record_raw): OwnershipHandoffRow =
        connection
            .query_row(
                "SELECT handoff_id, continuity_unit, continuity_generation, expected_epoch, record
                 FROM ownership_handoff",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .map_err(sqlite_error)?;
    let stored: StoredOwnership = decode_stored_binary(&record_raw, "ownership handoff record")?;
    validate_stored_ownership_lineage(
        &stored,
        report.nexus.freeze.intent,
        report.nexus.freeze.receipt_ref().map_err(debug)?,
        &report.ownership.prepared,
        &report.ownership.commit,
        &report.ownership.commit_request,
    )?;
    let commit_request_digest = joint_canonical_digest(&report.ownership.commit_request)
        .map_err(|error| format!("ownership commit request digest: {error:?}"))?;
    require(
        identity_from_blob(&handoff, "ownership handoff")? == key.handoff
            && identity_from_blob(&continuity, "ownership continuity unit")?
                == key.continuity_unit.identity
            && u64_from_blob(&generation, "ownership continuity generation")?
                == key.continuity_unit.generation.0
            && u64_from_blob(&expected_epoch, "ownership expected epoch")? == key.expected_epoch.0
            && stored.key == key
            && stored.phase == StoredOwnershipPhase::CommitDecided
            && stored.state_sequence == 3
            && stored.reservation == report.ownership.commit.reservation
            && stored.commit_request_digest == Some(commit_request_digest)
            && stored.abort_request_digest.is_none()
            && stored.abort.is_none(),
        "ownership handoff terminal row does not match the committed report receipt",
    )?;

    let (unit_identity, unit_generation, unit_raw): (Vec<u8>, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT continuity_unit, continuity_generation, record FROM ownership_unit",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(sqlite_error)?;
    let unit: StoredUnitOwnership =
        decode_stored_binary(&unit_raw, "ownership continuity-unit record")?;
    require(
        identity_from_blob(&unit_identity, "ownership unit identity")?
            == key.continuity_unit.identity
            && u64_from_blob(&unit_generation, "ownership unit generation")?
                == key.continuity_unit.generation.0
            && unit.continuity_unit == key.continuity_unit
            && unit.owner == key.destination
            && unit.epoch == key.next_epoch
            && unit.active_handoff.is_none()
            && unit.active_reservation.is_none(),
        "ownership continuity-unit row does not prove terminal destination ownership",
    )
}

fn validate_stored_ownership_lineage(
    stored: &StoredOwnership,
    freeze_intent: joint_handoff_core::ReceiptRef,
    freeze_ref: joint_handoff_core::ReceiptRef,
    prepared: &OwnershipPreparedReceipt,
    commit: &OwnershipCommitReceipt,
    captured_commit_request: &OwnershipCommitRequest,
) -> Result<(), String> {
    let key = commit.key;
    let reserve_request = OwnershipReserveRequest { key, expected_state_sequence: 0 };
    let reserve_request_digest = joint_canonical_digest(&reserve_request)
        .map_err(|error| format!("ownership reserve request digest: {error:?}"))?;
    let intent_ref = stored.intent.receipt_ref().map_err(debug)?;
    let prepared_ref = prepared.receipt_ref().map_err(debug)?;
    let seal_request = OwnershipSealRequest {
        key,
        reservation: stored.reservation,
        intent: intent_ref,
        visa_freeze: prepared.visa_freeze,
        effect_freeze: freeze_ref,
        destination_prepared: prepared.destination_prepared,
        bindings: prepared.bindings,
        expected_state_sequence: 1,
    };
    let seal_request_digest = joint_canonical_digest(&seal_request)
        .map_err(|error| format!("ownership seal request digest: {error:?}"))?;
    let expected_commit_request = OwnershipCommitRequest {
        key,
        reservation: stored.reservation,
        prepared: prepared_ref,
        expected_state_sequence: 2,
    };
    let commit_request_digest = joint_canonical_digest(&expected_commit_request)
        .map_err(|error| format!("ownership commit request digest: {error:?}"))?;
    require(
        stored.key == key
            && stored.reservation == prepared.reservation
            && stored.reservation == commit.reservation
            && stored.intent.header.kind == ReceiptKind::PrepareIntent
            && stored.intent.header.sequence == 1
            && stored.intent.header.previous_digest.is_none()
            && stored.intent.key == key
            && stored.intent.reservation == stored.reservation
            && stored.intent.intent_revision == 1
            && stored.intent.request_digest == reserve_request_digest
            && intent_ref == freeze_intent
            && intent_ref == prepared.intent
            && stored.reserve_request_digest == reserve_request_digest,
        "stored ownership intent does not bind the exact reserve request",
    )?;
    require(
        prepared.key == key
            && freeze_ref.kind == ReceiptKind::NexusFreeze
            && prepared.nexus_freeze == freeze_ref
            && prepared.bindings.prepare_intent_receipt_digest == intent_ref.digest
            && prepared.bindings.visa_freeze_receipt_digest == prepared.visa_freeze.digest
            && prepared.bindings.effect_freeze_receipt_digest == prepared.nexus_freeze.digest
            && prepared.bindings.destination_prepared_receipt_digest
                == prepared.destination_prepared.digest
            && stored.seal_request_digest == Some(seal_request_digest)
            && stored.prepared.as_ref() == Some(prepared),
        "stored ownership Prepared record does not bind the exact seal request",
    )?;
    require(
        commit.key == key
            && commit.prepared == prepared_ref
            && *captured_commit_request == expected_commit_request
            && stored.commit_request_digest == Some(commit_request_digest)
            && stored.commit.as_ref() == Some(commit),
        "stored ownership Commit record does not bind the exact commit request",
    )
}

fn validate_projection_database(
    connection: &Connection,
    report: &LogicalRequestAdmissionReport,
) -> Result<(), String> {
    let expected_records = &report.runtime.joint_projection.canonical_record_bytes;
    require(
        query_count(connection, "SELECT COUNT(*) FROM joint_projection_record")?
            == i64::try_from(expected_records.len()).unwrap_or(i64::MAX)
            && query_count(connection, "SELECT COUNT(*) FROM joint_projection_head")? == 1,
        "joint projection database retained the wrong record or head count",
    )?;
    let mut statement = connection
        .prepare("SELECT sequence, record FROM joint_projection_record ORDER BY sequence")
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)))
        .map_err(sqlite_error)?;
    for (index, row) in rows.enumerate() {
        let (sequence, raw) = row.map_err(sqlite_error)?;
        let expected_sequence = i64::try_from(index).unwrap_or(i64::MAX) + 1;
        let record = JointProjectionRecord::from_canonical_bytes(&raw)
            .map_err(|error| format!("decode joint projection record: {error:?}"))?;
        require(
            sequence == expected_sequence
                && record.sequence == u64::try_from(expected_sequence).unwrap_or(u64::MAX)
                && expected_records.get(index).map(Vec::as_slice) == Some(raw.as_slice()),
            "joint projection database record bytes or sequence differ from the report",
        )?;
    }
    let (singleton, head_raw): (i64, Vec<u8>) = connection
        .query_row("SELECT singleton, head FROM joint_projection_head", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .map_err(sqlite_error)?;
    let head: JointProjectionLogHead = decode_stored_binary(&head_raw, "joint projection head")?;
    require(
        singleton == 1
            && head == report.runtime.joint_projection.head
            && canonical_bytes(&head).map_err(debug)? == head_raw,
        "joint projection database head differs from the report",
    )
}

fn decode_stored_json<T>(raw: &[u8], label: &str) -> Result<T, String>
where
    T: DeserializeOwned + Serialize,
{
    let value = serde_json::from_slice::<T>(raw)
        .map_err(|error| format!("cannot decode {label}: {error}"))?;
    require(
        serde_json::to_vec(&value).map_err(|error| format!("cannot re-encode {label}: {error}"))?
            == raw,
        &format!("{label} is not canonical compact JSON"),
    )?;
    Ok(value)
}

fn decode_stored_binary<T>(raw: &[u8], label: &str) -> Result<T, String>
where
    T: DeserializeOwned + Serialize,
{
    let value = canonical_from_bytes::<T>(raw)
        .map_err(|error| format!("cannot decode canonical {label}: {error:?}"))?;
    require(
        canonical_bytes(&value)
            .map_err(|error| format!("cannot re-encode canonical {label}: {error:?}"))?
            == raw,
        &format!("{label} bytes are not canonical"),
    )?;
    Ok(value)
}

fn identity_from_blob(raw: &[u8], label: &str) -> Result<Identity, String> {
    let bytes: [u8; 16] =
        raw.try_into().map_err(|_| format!("{label} is not a 16-byte identity"))?;
    Ok(Identity::from_bytes(bytes))
}

fn u64_from_blob(raw: &[u8], label: &str) -> Result<u64, String> {
    let bytes: [u8; 8] = raw.try_into().map_err(|_| format!("{label} is not a big-endian u64"))?;
    Ok(u64::from_be_bytes(bytes))
}

fn debug(error: impl std::fmt::Debug) -> String {
    format!("{error:?}")
}

fn validate_sqlite_integrity(connection: &Connection, label: &str) -> Result<(), String> {
    let integrity: String = connection
        .query_row("PRAGMA integrity_check(1)", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    let foreign_key_findings =
        query_count(connection, "SELECT COUNT(*) FROM pragma_foreign_key_check")?;
    require(
        integrity == "ok" && foreign_key_findings == 0,
        &format!("{label} failed SQLite integrity or foreign-key verification"),
    )
}

fn query_count(connection: &Connection, sql: &str) -> Result<i64, String> {
    connection.query_row(sql, [], |row| row.get(0)).map_err(sqlite_error)
}

fn sqlite_error(error: rusqlite::Error) -> String {
    format!("SQLite semantic verification failed: {error}")
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical_executable(path: &Path, expected_sha256: &str) -> Result<PathBuf, String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|error| format!("cannot read current directory: {error}"))?
            .join(path)
    };
    let metadata = fs::symlink_metadata(&absolute).map_err(|error| {
        format!("cannot inspect Nexus executable {}: {error}", absolute.display())
    })?;
    require(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.nlink() == 1,
        "Nexus executable is not a single-link regular non-symlink file",
    )?;
    require(
        metadata.permissions().mode() & 0o111 != 0,
        "Nexus executable has no executable permission bit",
    )?;
    let canonical = fs::canonicalize(&absolute)
        .map_err(|error| format!("cannot canonicalize Nexus executable: {error}"))?;
    require(
        canonical == absolute,
        "Nexus executable path traverses a symlink or is not canonical",
    )?;
    let bytes = read_stable_regular(&canonical, "Nexus executable", MAX_EXECUTABLE_BYTES)?;
    require(
        sha256_hex(&bytes) == expected_sha256,
        "Nexus executable SHA-256 differs from the explicit identity",
    )?;
    Ok(canonical)
}

fn create_artifact_root(root: &Path) -> Result<(), String> {
    match fs::symlink_metadata(root) {
        Ok(_) => return Err(format!("artifact root already exists: {}", root.display())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("cannot inspect artifact root: {error}")),
    }
    let parent = root.parent().ok_or_else(|| "artifact root has no parent".to_owned())?;
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|error| format!("cannot inspect artifact parent {}: {error}", parent.display()))?;
    require(
        parent_metadata.is_dir() && !parent_metadata.file_type().is_symlink(),
        "artifact parent is not a real directory",
    )?;
    fs::create_dir(root)
        .map_err(|error| format!("cannot create artifact root {}: {error}", root.display()))
}

fn read_stable_regular(path: &Path, label: &str, maximum: u64) -> Result<Vec<u8>, String> {
    let before = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {label} {}: {error}", path.display()))?;
    require(
        before.is_file() && !before.file_type().is_symlink() && before.nlink() == 1,
        &format!("{label} is not a single-link regular non-symlink file"),
    )?;
    require(before.len() <= maximum, &format!("{label} exceeds {maximum} bytes"))?;
    let bytes = fs::read(path).map_err(|error| format!("cannot read {label}: {error}"))?;
    let after = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot re-inspect {label}: {error}"))?;
    let before_identity = (
        before.dev(),
        before.ino(),
        before.nlink(),
        before.len(),
        before.mtime(),
        before.mtime_nsec(),
        before.ctime(),
        before.ctime_nsec(),
    );
    let after_identity = (
        after.dev(),
        after.ino(),
        after.nlink(),
        after.len(),
        after.mtime(),
        after.mtime_nsec(),
        after.ctime(),
        after.ctime_nsec(),
    );
    require(
        before_identity == after_identity
            && bytes.len() == usize::try_from(after.len()).unwrap_or(usize::MAX),
        &format!("{label} changed while being read"),
    )?;
    Ok(bytes)
}

fn write_new(path: impl AsRef<Path>, bytes: &[u8]) -> Result<(), String> {
    let path = path.as_ref();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("cannot publish {}: {error}", path.display()))
}

fn write_new_executable(path: impl AsRef<Path>, bytes: &[u8]) -> Result<(), String> {
    let path = path.as_ref();
    write_new(path, bytes)?;
    let mut permissions = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {} after publication: {error}", path.display()))?
        .permissions();
    permissions.set_mode(0o500);
    fs::set_permissions(path, permissions)
        .map_err(|error| format!("cannot mark {} executable: {error}", path.display()))?;
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|error| format!("cannot reopen {} after chmod: {error}", path.display()))?;
    file.sync_all().map_err(|error| format!("cannot sync executable {}: {error}", path.display()))
}

fn verify_executed_visa_checkout(expected_sha: &str) -> Result<(), String> {
    let checkout = visa_checkout()?;
    let toplevel = git_output(&checkout, ["rev-parse", "--show-toplevel"])?;
    require(
        Path::new(toplevel.trim()) == checkout,
        "compiled vISA manifest directory is not its Git toplevel",
    )?;
    let head = git_output(&checkout, ["rev-parse", "--verify", "HEAD"])?;
    require(
        head.trim() == expected_sha,
        &format!(
            "executed vISA checkout HEAD mismatch: actual={}, expected={expected_sha}",
            head.trim()
        ),
    )?;
    let status = git_output(&checkout, ["status", "--porcelain=v1", "--untracked-files=all"])?;
    require(
        status.is_empty(),
        "executed vISA checkout is not clean, including non-ignored untracked files",
    )
}

fn visa_checkout() -> Result<PathBuf, String> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    fs::canonicalize(manifest.join("../../.."))
        .map_err(|error| format!("cannot canonicalize compiled vISA checkout: {error}"))
}

fn git_output<const N: usize>(checkout: &Path, arguments: [&str; N]) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(checkout)
        .args(arguments)
        .output()
        .map_err(|error| format!("cannot execute git: {error}"))?;
    require(
        output.status.success(),
        &format!("git command failed: {}", String::from_utf8_lossy(&output.stderr).trim()),
    )?;
    String::from_utf8(output.stdout).map_err(|_| "git output is not UTF-8".to_owned())
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn require(condition: bool, message: &str) -> Result<(), String> {
    if condition { Ok(()) } else { Err(message.to_owned()) }
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::{OsStr, OsString},
        sync::atomic::{AtomicU64, Ordering},
    };

    use rusqlite::MAIN_DB;

    use super::*;

    static NEXT_TEST: AtomicU64 = AtomicU64::new(1);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let sequence = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "visa-logical-request-admission-artifact-{label}-{}-{sequence}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn provenance() -> ArtifactProvenance {
        ArtifactProvenance {
            visa_revision: "1".repeat(40),
            nexus_revision: "2".repeat(40),
            nexus_reference_baseline_revision: "3".repeat(40),
            nexus_executable_sha256: "4".repeat(64),
            neutral_revision: "5".repeat(40),
            neutral_tree: "6".repeat(40),
            neutral_bundle_sha256: "7".repeat(64),
            source_lock_sha256: "8".repeat(64),
            nexus_qualification_lock_sha256: "9".repeat(64),
        }
    }

    fn expectations() -> LogicalRequestAdmissionExpectations {
        let provenance = provenance();
        LogicalRequestAdmissionExpectations {
            run_identity: derive_run_identity(&provenance).unwrap(),
            nexus_process: visa_joint_handoff_system::ProcessEffectPeerIdentity {
                process_id: 42,
                executable_path: PathBuf::from("/opt/qualified/nexus-effect-peer"),
                executable_sha256: provenance.nexus_executable_sha256,
                nexus_revision: provenance.nexus_revision,
                start_time_ticks: 77,
            },
        }
    }

    fn secure_file(bytes: &[u8], inode: u64) -> SecureArtifactFile {
        SecureArtifactFile { bytes: bytes.to_vec(), device: 1, inode, links: 1 }
    }

    fn artifact_set() -> ArtifactSet {
        ArtifactSet {
            manifest: secure_file(b"manifest", 1),
            report: secure_file(b"report", 2),
            source_database: secure_file(b"source", 3),
            destination_database: secure_file(b"destination", 4),
            ownership_database: secure_file(b"ownership", 5),
            joint_projection_database: secure_file(b"projection", 6),
            nexus_effect_peer: secure_file(b"nexus", 7),
        }
    }

    fn manifest(artifacts: &ArtifactSet) -> ArtifactManifest {
        ArtifactManifest {
            schema: MANIFEST_SCHEMA.to_owned(),
            evidence_status: EVIDENCE_STATUS.to_owned(),
            report: artifact_file(
                LOGICAL_REQUEST_ADMISSION_REPORT,
                LOGICAL_REQUEST_ADMISSION_SCHEMA,
                &artifacts.report.bytes,
            )
            .unwrap(),
            source_database: artifact_file(
                SOURCE_DATABASE,
                SOURCE_DATABASE_SCHEMA,
                &artifacts.source_database.bytes,
            )
            .unwrap(),
            destination_database: artifact_file(
                DESTINATION_DATABASE,
                DESTINATION_DATABASE_SCHEMA,
                &artifacts.destination_database.bytes,
            )
            .unwrap(),
            ownership_database: artifact_file(
                OWNERSHIP_DATABASE,
                OWNERSHIP_DATABASE_SCHEMA,
                &artifacts.ownership_database.bytes,
            )
            .unwrap(),
            joint_projection_database: artifact_file(
                JOINT_PROJECTION_DATABASE,
                JOINT_PROJECTION_DATABASE_SCHEMA,
                &artifacts.joint_projection_database.bytes,
            )
            .unwrap(),
            nexus_effect_peer: artifact_file(
                NEXUS_EFFECT_PEER_FILE,
                NEXUS_EFFECT_PEER_SCHEMA,
                &artifacts.nexus_effect_peer.bytes,
            )
            .unwrap(),
            provenance: provenance(),
            expectations: expectations(),
            limitations: ArtifactLimitations::bounded(),
        }
    }

    fn ledger_fixture(
        retained_request: bool,
        response: Option<&'static [u8]>,
        phase: StoredLedgerPhase,
    ) -> (Vec<u8>, StoredLogicalLedgerRecord, LedgerExpectations<'static>) {
        const PEER: &[u8] = b"expected-peer";
        let operation = Identity::from_u128(101);
        let resource = EntityRef::initial(Identity::from_u128(102));
        let credential_reference = Identity::from_u128(103);
        let request_digest = canonical_digest(EXPECTED_LOGICAL_REQUEST).unwrap();
        let response_metadata = response.map(|bytes| StoredResponseMetadata {
            size: u32::try_from(bytes.len()).unwrap(),
            digest: canonical_digest(bytes).unwrap(),
        });
        let expected = LedgerExpectations {
            operation,
            resource,
            peer_identity: PEER,
            credential_reference,
            request: EXPECTED_LOGICAL_REQUEST,
            retained_request,
            response,
            revision: 2,
            phase,
            delivered_cursor: 0,
        };
        let ledger = StoredLogicalLedgerRecord {
            revision: expected.revision,
            resource,
            operation_id: operation,
            peer_identity: PEER.to_vec(),
            credential_reference,
            request_size: u32::try_from(EXPECTED_LOGICAL_REQUEST.len()).unwrap(),
            request_digest,
            request: retained_request.then(|| EXPECTED_LOGICAL_REQUEST.to_vec()),
            phase,
            response: response.map(<[u8]>::to_vec),
            response_metadata,
            delivered_cursor: 0,
            rejection: None,
            cleaned: false,
        };
        (operation.0.to_vec(), ledger, expected)
    }

    fn provider_request() -> EffectRequest {
        let component = EntityRef::initial(Identity::from_u128(202));
        EffectRequest {
            operation: Identity::from_u128(201),
            idempotency_key: contract_core::IdempotencyKey::from_u128(203),
            causal_parent: None,
            node: NodeIdentity::new(Identity::from_u128(204)),
            subject: component,
            resource: EntityRef::initial(Identity::from_u128(205)),
            authority: EntityRef::initial(Identity::from_u128(206)),
            lease_epoch: LeaseEpoch(1),
            request_digest: ContractDigest::ZERO,
            kind: contract_core::EffectKind::Profile {
                profile: Identity::from_u128(207),
                access: contract_core::ProfileAccess::Write,
                payload: vec![1, 2, 3],
            },
        }
    }

    fn run_values() -> Vec<OsString> {
        vec![
            "run".into(),
            "artifact".into(),
            "1".repeat(40).into(),
            "/opt/nexus-effect-peer".into(),
            "4".repeat(64).into(),
            "2".repeat(40).into(),
            "3".repeat(40).into(),
            "5".repeat(40).into(),
            "6".repeat(40).into(),
            "7".repeat(64).into(),
            "8".repeat(64).into(),
            "9".repeat(64).into(),
        ]
    }

    #[test]
    fn parser_separates_run_executable_from_verify_manifest_anchor() {
        let run = parse_arguments(OsStr::new("runner"), &run_values()).unwrap();
        assert_eq!(run.mode, Mode::Run);
        assert_eq!(run.execution_executable, Some(PathBuf::from("/opt/nexus-effect-peer")));
        assert_eq!(run.expected_manifest_sha256, None);

        let mut verify = run_values();
        verify[0] = "verify".into();
        verify.remove(3);
        verify.insert(2, "a".repeat(64).into());
        let parsed = parse_arguments(OsStr::new("runner"), &verify).unwrap();
        assert_eq!(parsed.mode, Mode::Verify);
        assert_eq!(parsed.execution_executable, None);
        assert_eq!(parsed.expected_manifest_sha256, Some("a".repeat(64)));
        assert_eq!(parsed.provenance, provenance());

        let mut extra_path = verify;
        extra_path.insert(3, "/tmp/forbidden-executable".into());
        assert!(parse_arguments(OsStr::new("runner"), &extra_path).is_err());
    }

    #[test]
    fn manifest_is_canonical_and_unknown_fields_fail_closed() {
        let artifacts = artifact_set();
        let manifest = manifest(&artifacts);
        let raw = canonical_manifest_json(&manifest).unwrap();
        assert_eq!(decode_canonical_manifest(&raw).unwrap(), manifest);

        let mut noncanonical = raw.clone();
        noncanonical.insert(0, b' ');
        assert!(decode_canonical_manifest(&noncanonical).is_err());

        let mut value = serde_json::to_value(&manifest).unwrap();
        value.as_object_mut().unwrap().insert("unknown".to_owned(), serde_json::Value::Bool(true));
        let mut unknown = serde_json::to_vec(&value).unwrap();
        unknown.push(b'\n');
        assert!(decode_canonical_manifest(&unknown).is_err());
    }

    #[test]
    fn manifest_binds_all_six_owned_files_and_external_expectations() {
        let artifacts = artifact_set();
        let baseline = manifest(&artifacts);
        validate_manifest(&baseline, &provenance(), &artifacts).unwrap();

        let mut mutated = baseline.clone();
        mutated.report.path.push('x');
        assert!(validate_manifest(&mutated, &provenance(), &artifacts).is_err());
        let mut mutated = baseline.clone();
        mutated.source_database.schema.push('x');
        assert!(validate_manifest(&mutated, &provenance(), &artifacts).is_err());
        let mut mutated = baseline.clone();
        mutated.destination_database.bytes += 1;
        assert!(validate_manifest(&mutated, &provenance(), &artifacts).is_err());
        let mut mutated = baseline.clone();
        mutated.ownership_database.sha256 = "0".repeat(64);
        assert!(validate_manifest(&mutated, &provenance(), &artifacts).is_err());
        let mut mutated = baseline.clone();
        mutated.joint_projection_database.path = "other.sqlite3".to_owned();
        assert!(validate_manifest(&mutated, &provenance(), &artifacts).is_err());
        let mut mutated = baseline.clone();
        mutated.nexus_effect_peer.schema.push('x');
        assert!(validate_manifest(&mutated, &provenance(), &artifacts).is_err());
        let mut mutated = baseline.clone();
        mutated.expectations.nexus_process.executable_sha256 = "0".repeat(64);
        assert!(validate_manifest(&mutated, &provenance(), &artifacts).is_err());
        let baseline_sha = sha256_hex(&canonical_manifest_json(&baseline).unwrap());
        let mut historical_mutation = baseline;
        historical_mutation.expectations.nexus_process.start_time_ticks += 1;
        assert_ne!(
            sha256_hex(&canonical_manifest_json(&historical_mutation).unwrap()),
            baseline_sha
        );

        let mut oversized = manifest(&artifacts);
        oversized.report.bytes = MAX_REPORT_BYTES;
        oversized.source_database.bytes = MAX_DATABASE_BYTES;
        oversized.destination_database.bytes = MAX_DATABASE_BYTES;
        oversized.ownership_database.bytes = MAX_DATABASE_BYTES;
        oversized.joint_projection_database.bytes = MAX_DATABASE_BYTES;
        oversized.nexus_effect_peer.bytes = MAX_EXECUTABLE_BYTES;
        assert!(validate_manifest_sizes(&oversized).is_err());
    }

    #[test]
    fn secure_seven_file_read_does_not_execute_the_embedded_binary() {
        let root = TestRoot::new("no-exec");
        let sentinel = root.0.with_extension("sentinel");
        let binary = format!("#!/bin/sh\ntouch '{}'\n", sentinel.display());
        for path in final_inventory() {
            let bytes = if path == NEXUS_EFFECT_PEER_FILE { binary.as_bytes() } else { b"fixture" };
            fs::write(root.0.join(path), bytes).unwrap();
        }
        let secure = SecureArtifactRoot::open(&root.0).unwrap();

        require_inventory(&secure, &final_inventory(), "inventory").unwrap();
        let artifacts = read_artifact_set(&secure).unwrap();

        assert_eq!(artifacts.nexus_effect_peer.bytes, binary.as_bytes());
        assert!(!sentinel.exists());
        fs::write(root.0.join("extra"), b"extra").unwrap();
        assert!(require_inventory(&secure, &final_inventory(), "inventory").is_err());
        fs::remove_file(root.0.join("extra")).unwrap();
        fs::remove_file(root.0.join(MANIFEST_FILE)).unwrap();
        assert!(require_inventory(&secure, &final_inventory(), "inventory").is_err());
    }

    #[test]
    fn sqlite_deserialization_is_read_only_and_uses_exact_bytes() {
        let source = Connection::open_in_memory().unwrap();
        source
            .execute_batch(
                "PRAGMA user_version = 5;
                 CREATE TABLE evidence(value INTEGER NOT NULL);
                 INSERT INTO evidence VALUES (7);",
            )
            .unwrap();
        let raw = source.serialize(MAIN_DB).unwrap().to_vec();
        validate_sqlite_bytes(&raw, 5, "fixture").unwrap();
        let exact = deserialize_database(&raw, "fixture").unwrap();
        assert_eq!(
            exact.query_row("SELECT value FROM evidence", [], |row| row.get::<_, i64>(0)).unwrap(),
            7
        );
        assert!(exact.execute("DELETE FROM evidence", []).is_err());

        let mut mutated = raw;
        mutated[60..64].copy_from_slice(&6_u32.to_be_bytes());
        assert!(validate_sqlite_bytes(&mutated, 5, "fixture").is_err());
    }

    #[test]
    fn ledger_binding_rejects_semantically_self_consistent_mutations() {
        let (key, ledger, expected) =
            ledger_fixture(false, Some(EXPECTED_LOGICAL_RESPONSE), StoredLedgerPhase::Completed);
        validate_ledger_binding(&key, &ledger, expected, "fixture").unwrap();

        let mut changed = ledger.clone();
        changed.response = None;
        changed.response_metadata = None;
        assert!(validate_ledger_binding(&key, &changed, expected, "fixture").is_err());
        let mut changed = ledger.clone();
        changed.peer_identity = b"other-peer".to_vec();
        assert!(validate_ledger_binding(&key, &changed, expected, "fixture").is_err());
        let mut changed = ledger.clone();
        changed.credential_reference = Identity::from_u128(999);
        assert!(validate_ledger_binding(&key, &changed, expected, "fixture").is_err());
        let mut changed = ledger;
        changed.delivered_cursor = 1;
        assert!(validate_ledger_binding(&key, &changed, expected, "fixture").is_err());

        let (key, mut source, source_expected) =
            ledger_fixture(true, None, StoredLedgerPhase::UnknownCompletion);
        source.request = Some(b"self-consistent-mutation".to_vec());
        source.request_size = u32::try_from(source.request.as_ref().unwrap().len()).unwrap();
        source.request_digest = canonical_digest(source.request.as_deref().unwrap()).unwrap();
        assert!(validate_ledger_binding(&key, &source, source_expected, "source").is_err());
    }

    #[test]
    fn provider_binding_rejects_independent_idempotency_column_mutation() {
        let request = provider_request();
        let outcome = EffectOutcome::Indeterminate { evidence: None };
        let operation = request.operation.0.to_vec();
        let idempotency = request.idempotency_key.0.to_vec();
        validate_provider_operation_binding(
            ProviderOperationBinding {
                operation: &operation,
                idempotency: &idempotency,
                request: &request,
                outcome: &outcome,
                cleaned: 0,
            },
            &request,
            &outcome,
            "fixture",
        )
        .unwrap();

        let changed = contract_core::IdempotencyKey::from_u128(999).0.to_vec();
        assert!(
            validate_provider_operation_binding(
                ProviderOperationBinding {
                    operation: &operation,
                    idempotency: &changed,
                    request: &request,
                    outcome: &outcome,
                    cleaned: 0,
                },
                &request,
                &outcome,
                "fixture",
            )
            .is_err()
        );
    }
}
