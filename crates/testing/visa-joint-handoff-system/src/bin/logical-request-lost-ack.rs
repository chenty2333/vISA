use std::{
    env, fs,
    fs::OpenOptions,
    io::{self, Write},
    os::unix::{
        ffi::OsStrExt as _,
        fs::{MetadataExt as _, PermissionsExt as _},
    },
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

use contract_core::{
    Digest as ContractDigest, EffectOutcome, EffectRequest, EffectResult, EntityRef, Identity,
    LeaseEpoch, NodeIdentity, canonical_digest,
};
use joint_handoff_core::{
    JointHandoffKey, OwnershipAbortReceipt, OwnershipCommitReceipt, OwnershipPreparedReceipt,
    PrepareIntentReceipt, ReceiptKind, TypedReceipt, canonical_bytes,
    canonical_digest as joint_canonical_digest, canonical_from_bytes,
};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use visa_joint_handoff_system::{
    LOGICAL_REQUEST_DUAL_LOST_ACK_REPORT, LOGICAL_REQUEST_DUAL_LOST_ACK_SCHEMA,
    LOGICAL_REQUEST_OWNERSHIP_DATABASE, LOGICAL_REQUEST_PROVIDER_DATABASE,
    LogicalRequestDualLostAckInputs, LogicalRequestDualLostAckReport,
    NexusProcessQualificationInputs, OwnershipCommitRequest, OwnershipReserveRequest,
    OwnershipSealRequest, run_logical_request_dual_lost_ack_cell,
    validate_logical_request_dual_lost_ack_report,
};

const MANIFEST_SCHEMA: &str = "visa.logical-request-dual-lost-ack-artifact.v2";
const EVIDENCE_STATUS: &str =
    "supplemental-non-normative-same-boot-logical-request-dual-real-lost-ack-observation";
const MANIFEST_FILE: &str = "logical-request-dual-lost-ack-manifest.json";
const INCOMPLETE_FILE: &str = "logical-request-dual-lost-ack-incomplete";
const NEXUS_EFFECT_PEER_FILE: &str = "nexus-effect-peer";
const NEXUS_EFFECT_PEER_SCHEMA: &str = "opaque-nexus-effect-peer-bytes-sha256-v1";
const PROVIDER_DATABASE_SCHEMA: &str = "sqlite3-user-version-5";
const OWNERSHIP_DATABASE_SCHEMA: &str = "sqlite3-user-version-2";
const PROVIDER_DATABASE_USER_VERSION: u32 = 5;
const OWNERSHIP_DATABASE_USER_VERSION: u32 = 2;
const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_REPORT_BYTES: usize = 32 * 1024 * 1024;
const MAX_DATABASE_BYTES: usize = 512 * 1024 * 1024;
const MAX_EXECUTABLE_BYTES: usize = 256 * 1024 * 1024;

type ProviderOperationRow = (Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>, i64);
type OwnershipHandoffRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

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
    provider_database: ArtifactFile,
    ownership_database: ArtifactFile,
    nexus_effect_peer: ArtifactFile,
    provenance: ArtifactProvenance,
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
    host_reboot_recovery_claimed: bool,
    raw_tcp_frame_capture_available: bool,
    source_to_binary_reproducibility_claimed: bool,
    registry_replacement_supported: bool,
    retained_tombstone_supported: bool,
    remote_ci_observed: bool,
    normative_joint_handoff_claim: bool,
    nexus_serialized_external_effect_admission: bool,
    visa_runtime_handoff_executed: bool,
    source_fencing_executed: bool,
    destination_activation_executed: bool,
    observed_executable_path_is_normative_provenance: bool,
    artifact_owned_binary_reexecuted_during_verification: bool,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
enum CapturedLogicalRequestPhase {
    Ready,
    Pending,
    PartialResponse,
    UnknownCompletion,
    Reconciling,
    Replaying,
    Cancelling,
    Completed,
    TimedOut,
    Cancelled,
    Rejected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
enum CapturedLogicalRequestRejection {
    PeerMismatch,
    CredentialDenied,
    UnsafeReplay,
    UnsupportedTransport,
    PolicyDenied,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapturedLogicalRequestObservation {
    phase: CapturedLogicalRequestPhase,
    response: Option<StoredResponseMetadata>,
    rejection: Option<CapturedLogicalRequestRejection>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
enum CapturedLogicalRequestResult {
    Started {
        observation: CapturedLogicalRequestObservation,
    },
    Observed {
        observation: CapturedLogicalRequestObservation,
        bytes: Vec<u8>,
        response_cursor: u32,
    },
    Reconciled {
        observation: CapturedLogicalRequestObservation,
    },
    Cancelled {
        observation: CapturedLogicalRequestObservation,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProviderLedgerExpectations {
    run_identity: Identity,
    operation: Identity,
    resource: EntityRef,
    request_digest: ContractDigest,
    response_metadata: StoredResponseMetadata,
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
    key: JointHandoffKey,
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

impl ArtifactLimitations {
    fn bounded() -> Self {
        Self {
            same_boot_only: true,
            host_reboot_recovery_claimed: false,
            raw_tcp_frame_capture_available: false,
            source_to_binary_reproducibility_claimed: false,
            registry_replacement_supported: false,
            retained_tombstone_supported: false,
            remote_ci_observed: false,
            normative_joint_handoff_claim: false,
            nexus_serialized_external_effect_admission: false,
            visa_runtime_handoff_executed: false,
            source_fencing_executed: false,
            destination_activation_executed: false,
            observed_executable_path_is_normative_provenance: false,
            artifact_owned_binary_reexecuted_during_verification: false,
        }
    }
}

fn main() -> ExitCode {
    match run_main() {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Supplemental logical-request dual-lost-ACK artifact failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn run_main() -> Result<String, String> {
    let mut values = env::args_os();
    let program = values.next().unwrap_or_default();
    let values = values.collect::<Vec<_>>();
    let arguments = parse_arguments(&program, &values)?;
    validate_provenance(&arguments.provenance)?;

    match arguments.mode {
        Mode::Run => {
            let supplied = arguments
                .execution_executable
                .as_deref()
                .ok_or_else(|| "run mode omitted the external Nexus executable".to_owned())?;
            let executable =
                canonical_executable(supplied, &arguments.provenance.nexus_executable_sha256)?;
            publish_artifact(&arguments.artifact_root, &arguments.provenance, &executable)?;
            Ok(format!(
                "Supplemental non-normative logical-request dual-lost-ACK artifact: {}",
                arguments.artifact_root.display()
            ))
        }
        Mode::Verify => {
            require(
                arguments.execution_executable.is_none(),
                "verify mode unexpectedly accepted an external Nexus executable",
            )?;
            verify_artifact(&arguments.artifact_root, &arguments.provenance)?;
            Ok(format!(
                "Verified supplemental non-normative logical-request dual-lost-ACK artifact: {}",
                arguments.artifact_root.display()
            ))
        }
    }
}

fn parse_arguments(
    program: &std::ffi::OsStr,
    values: &[std::ffi::OsString],
) -> Result<Arguments, String> {
    let mode = match values.first().and_then(|value| value.to_str()) {
        Some("run") if values.len() == 12 => Mode::Run,
        Some("verify") if values.len() == 11 => Mode::Verify,
        _ => return Err(usage(program)),
    };
    let (execution_executable, provenance_offset) = match mode {
        Mode::Run => (Some(PathBuf::from(&values[3])), 1),
        Mode::Verify => (None, 0),
    };
    if values.len() <= 10 + provenance_offset {
        return Err(usage(program));
    }
    Ok(Arguments {
        mode,
        artifact_root: PathBuf::from(&values[1]),
        execution_executable,
        provenance: ArtifactProvenance {
            visa_revision: utf8(&values[2], "vISA revision")?,
            nexus_executable_sha256: utf8(
                &values[3 + provenance_offset],
                "Nexus executable SHA-256",
            )?,
            nexus_revision: utf8(&values[4 + provenance_offset], "qualified Nexus revision")?,
            nexus_reference_baseline_revision: utf8(
                &values[5 + provenance_offset],
                "Nexus reference baseline revision",
            )?,
            neutral_revision: utf8(&values[6 + provenance_offset], "neutral revision")?,
            neutral_tree: utf8(&values[7 + provenance_offset], "neutral tree")?,
            neutral_bundle_sha256: utf8(&values[8 + provenance_offset], "neutral bundle SHA-256")?,
            source_lock_sha256: utf8(&values[9 + provenance_offset], "source-lock SHA-256")?,
            nexus_qualification_lock_sha256: utf8(
                &values[10 + provenance_offset],
                "Nexus qualification-lock SHA-256",
            )?,
        },
    })
}

fn usage(program: &std::ffi::OsStr) -> String {
    format!(
        "usage:\n  {} run <artifact-root> <visa-sha> <external-nexus-effect-peer-bin> <nexus-bin-sha256> <qualified-nexus-sha> <nexus-reference-baseline-sha> <neutral-sha> <neutral-tree> <neutral-bundle-sha256> <source-lock-sha256> <nexus-qualification-lock-sha256>\n  {} verify <artifact-root> <visa-sha> <nexus-bin-sha256> <qualified-nexus-sha> <nexus-reference-baseline-sha> <neutral-sha> <neutral-tree> <neutral-bundle-sha256> <source-lock-sha256> <nexus-qualification-lock-sha256>\nverify reads only the artifact-owned ./{} binary; the run-only absolute source path is a historical process observation and is excluded from provenance and run identity",
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
) -> Result<(), String> {
    verify_executed_visa_checkout(&provenance.visa_revision)?;
    let execution_executable =
        canonical_executable(execution_executable, &provenance.nexus_executable_sha256)?;
    create_artifact_root(root)?;
    let incomplete = root.join(INCOMPLETE_FILE);
    write_new(&incomplete, b"logical-request dual-lost-ACK publication incomplete\n")?;

    let publication = (|| {
        let report = run_logical_request_dual_lost_ack_cell(
            root,
            LogicalRequestDualLostAckInputs {
                run_identity: derive_run_identity(provenance)?,
                nexus: NexusProcessQualificationInputs {
                    executable: execution_executable.clone(),
                    executable_sha256: provenance.nexus_executable_sha256.clone(),
                    nexus_revision: provenance.nexus_revision.clone(),
                },
            },
        )?;
        validate_report_provenance(&report, provenance)?;
        validate_execution_observation(&report, &execution_executable)?;

        let generated_report_path = root.join(LOGICAL_REQUEST_DUAL_LOST_ACK_REPORT);
        let generated_report = read_stable_regular(
            &generated_report_path,
            "generated logical-request report",
            MAX_REPORT_BYTES,
        )?;
        let generated_decoded: LogicalRequestDualLostAckReport =
            serde_json::from_slice(&generated_report).map_err(|error| {
                format!("cannot decode generated logical-request report: {error}")
            })?;
        require(
            generated_decoded == report,
            "generated logical-request report differs from the returned evidence",
        )?;
        fs::remove_file(&generated_report_path)
            .map_err(|error| format!("cannot replace generated report: {error}"))?;
        let report_raw = canonical_json(&report, "logical-request dual-lost-ACK report")?;
        write_new(&generated_report_path, &report_raw)?;

        let provider_path = root.join(LOGICAL_REQUEST_PROVIDER_DATABASE);
        let ownership_path = root.join(LOGICAL_REQUEST_OWNERSHIP_DATABASE);
        let provider_raw = read_stable_regular(
            &provider_path,
            "logical-request provider database",
            MAX_DATABASE_BYTES,
        )?;
        let ownership_raw = read_stable_regular(
            &ownership_path,
            "logical-request ownership database",
            MAX_DATABASE_BYTES,
        )?;
        validate_sqlite_bytes(
            &provider_raw,
            PROVIDER_DATABASE_USER_VERSION,
            "logical-request provider database",
        )?;
        validate_sqlite_bytes(
            &ownership_raw,
            OWNERSHIP_DATABASE_USER_VERSION,
            "logical-request ownership database",
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
        let artifact_executable_path = root.join(NEXUS_EFFECT_PEER_FILE);
        write_new_executable(&artifact_executable_path, &executable_raw)?;

        validate_incomplete_inventory(root)?;
        let manifest = ArtifactManifest {
            schema: MANIFEST_SCHEMA.to_owned(),
            evidence_status: EVIDENCE_STATUS.to_owned(),
            report: artifact_file(
                LOGICAL_REQUEST_DUAL_LOST_ACK_REPORT,
                LOGICAL_REQUEST_DUAL_LOST_ACK_SCHEMA,
                &report_raw,
            )?,
            provider_database: artifact_file(
                LOGICAL_REQUEST_PROVIDER_DATABASE,
                PROVIDER_DATABASE_SCHEMA,
                &provider_raw,
            )?,
            ownership_database: artifact_file(
                LOGICAL_REQUEST_OWNERSHIP_DATABASE,
                OWNERSHIP_DATABASE_SCHEMA,
                &ownership_raw,
            )?,
            nexus_effect_peer: artifact_file(
                NEXUS_EFFECT_PEER_FILE,
                NEXUS_EFFECT_PEER_SCHEMA,
                &executable_raw,
            )?,
            provenance: provenance.clone(),
            limitations: ArtifactLimitations::bounded(),
        };
        let manifest_raw = canonical_json(&manifest, "logical-request artifact manifest")?;
        write_new(root.join(MANIFEST_FILE), &manifest_raw)?;

        canonical_executable(&execution_executable, &provenance.nexus_executable_sha256)?;
        verify_executed_visa_checkout(&provenance.visa_revision)?;
        fs::remove_file(&incomplete)
            .map_err(|error| format!("cannot remove {}: {error}", incomplete.display()))?;
        verify_artifact(root, provenance)
    })();
    if publication.is_err() && !incomplete.exists() {
        let _ = fs::write(&incomplete, b"logical-request dual-lost-ACK publication incomplete\n");
    }
    publication
}

fn verify_artifact(root: &Path, expected: &ArtifactProvenance) -> Result<(), String> {
    validate_provenance(expected)?;
    verify_executed_visa_checkout(&expected.visa_revision)?;
    validate_artifact_root(root)?;

    let manifest_raw =
        read_stable_regular(&root.join(MANIFEST_FILE), "artifact manifest", MAX_MANIFEST_BYTES)?;
    let report_raw = read_stable_regular(
        &root.join(LOGICAL_REQUEST_DUAL_LOST_ACK_REPORT),
        "logical-request report",
        MAX_REPORT_BYTES,
    )?;
    let provider_raw = read_stable_regular(
        &root.join(LOGICAL_REQUEST_PROVIDER_DATABASE),
        "logical-request provider database",
        MAX_DATABASE_BYTES,
    )?;
    let ownership_raw = read_stable_regular(
        &root.join(LOGICAL_REQUEST_OWNERSHIP_DATABASE),
        "logical-request ownership database",
        MAX_DATABASE_BYTES,
    )?;
    let executable_raw = read_artifact_executable(root, &expected.nexus_executable_sha256)?;

    let manifest: ArtifactManifest =
        decode_canonical(&manifest_raw, "logical-request artifact manifest")?;
    validate_manifest(
        &manifest,
        expected,
        &report_raw,
        &provider_raw,
        &ownership_raw,
        &executable_raw,
    )?;
    let report: LogicalRequestDualLostAckReport =
        decode_canonical(&report_raw, "logical-request dual-lost-ACK report")?;
    validate_report_provenance(&report, expected)?;
    validate_sqlite_bytes(
        &provider_raw,
        PROVIDER_DATABASE_USER_VERSION,
        "logical-request provider database",
    )?;
    validate_sqlite_bytes(
        &ownership_raw,
        OWNERSHIP_DATABASE_USER_VERSION,
        "logical-request ownership database",
    )?;
    validate_provider_database(&root.join(LOGICAL_REQUEST_PROVIDER_DATABASE), &report)?;
    validate_ownership_database(&root.join(LOGICAL_REQUEST_OWNERSHIP_DATABASE), &report)?;
    validate_artifact_root(root)?;
    require(
        read_stable_regular(
            &root.join(LOGICAL_REQUEST_PROVIDER_DATABASE),
            "logical-request provider database after semantic verification",
            MAX_DATABASE_BYTES,
        )? == provider_raw
            && read_stable_regular(
                &root.join(LOGICAL_REQUEST_OWNERSHIP_DATABASE),
                "logical-request ownership database after semantic verification",
                MAX_DATABASE_BYTES,
            )? == ownership_raw,
        "read-only semantic database verification changed artifact bytes",
    )?;

    require(
        read_artifact_executable(root, &expected.nexus_executable_sha256)? == executable_raw,
        "artifact-owned Nexus effect peer changed during semantic verification",
    )?;
    verify_executed_visa_checkout(&expected.visa_revision)
}

fn validate_manifest(
    manifest: &ArtifactManifest,
    expected: &ArtifactProvenance,
    report_raw: &[u8],
    provider_raw: &[u8],
    ownership_raw: &[u8],
    executable_raw: &[u8],
) -> Result<(), String> {
    require(manifest.schema == MANIFEST_SCHEMA, "artifact manifest schema drifted")?;
    require(manifest.evidence_status == EVIDENCE_STATUS, "artifact evidence status drifted")?;
    require(
        manifest.provenance == *expected,
        "artifact provenance differs from independently supplied expectations",
    )?;
    require(
        manifest.limitations == ArtifactLimitations::bounded(),
        "artifact limitations overclaim the bounded same-boot experiment",
    )?;
    require(
        file_matches(
            &manifest.report,
            LOGICAL_REQUEST_DUAL_LOST_ACK_REPORT,
            LOGICAL_REQUEST_DUAL_LOST_ACK_SCHEMA,
            report_raw,
        ) && file_matches(
            &manifest.provider_database,
            LOGICAL_REQUEST_PROVIDER_DATABASE,
            PROVIDER_DATABASE_SCHEMA,
            provider_raw,
        ) && file_matches(
            &manifest.ownership_database,
            LOGICAL_REQUEST_OWNERSHIP_DATABASE,
            OWNERSHIP_DATABASE_SCHEMA,
            ownership_raw,
        ) && file_matches(
            &manifest.nexus_effect_peer,
            NEXUS_EFFECT_PEER_FILE,
            NEXUS_EFFECT_PEER_SCHEMA,
            executable_raw,
        ),
        "artifact evidence bytes do not match the exact manifest inventory",
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

fn validate_report_provenance(
    report: &LogicalRequestDualLostAckReport,
    expected: &ArtifactProvenance,
) -> Result<(), String> {
    validate_logical_request_dual_lost_ack_report(report)?;
    require(
        report.run_identity == derive_run_identity(expected)?,
        "logical-request report run identity is not derived from exact provenance",
    )?;
    require(
        report.logical_request.provider_database == LOGICAL_REQUEST_PROVIDER_DATABASE
            && report.ownership_commit_ack_loss.database == LOGICAL_REQUEST_OWNERSHIP_DATABASE,
        "logical-request report database inventory drifted",
    )?;
    let process = &report.nexus_terminal_response_loss.process;
    require(
        process.executable_path.is_absolute()
            && !process.executable_path.as_os_str().is_empty()
            && process.executable_sha256 == expected.nexus_executable_sha256
            && process.nexus_revision == expected.nexus_revision,
        "logical-request report Nexus process identity drifted",
    )
}

fn validate_execution_observation(
    report: &LogicalRequestDualLostAckReport,
    execution_executable: &Path,
) -> Result<(), String> {
    require(
        report.nexus_terminal_response_loss.process.executable_path == execution_executable,
        "logical-request report did not observe the exact run-only external executable path",
    )
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
    digest.update(b"vISA logical-request artifact run identity v2\0");
    digest.update(u64::try_from(encoded.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(encoded);
    let digest = digest.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    let identity = Identity::from_bytes(bytes);
    require(!identity.is_zero(), "derived logical-request run identity was zero")?;
    Ok(identity)
}

fn derive_cell_identity(parent: Identity, label: &[u8]) -> Result<Identity, String> {
    let digest = canonical_digest(&(
        b"vISA logical-request dual lost-ack cell v1".as_slice(),
        parent,
        label,
    ))
    .map_err(|error| format!("cannot derive logical-request claim identity: {error:?}"))?;
    require(digest != ContractDigest::ZERO, "derived logical-request claim digest was zero")?;
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.0[..16]);
    let identity = Identity::from_bytes(bytes);
    require(!identity.is_zero(), "derived logical-request claim identity was zero")?;
    Ok(identity)
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

fn validate_provider_database(
    path: &Path,
    report: &LogicalRequestDualLostAckReport,
) -> Result<(), String> {
    let connection = open_read_only_database(path, "logical-request provider database")?;
    validate_sqlite_integrity(&connection, "logical-request provider database")?;
    require(
        query_count(&connection, "SELECT COUNT(*) FROM logical_request_ledger")? == 1
            && query_count(&connection, "SELECT COUNT(*) FROM logical_request_effect")? == 1
            && query_count(&connection, "SELECT COUNT(*) FROM provider_operation")? == 1,
        "provider database did not retain exactly one logical ledger/effect/operation",
    )?;

    let (ledger_key, ledger_raw): (Vec<u8>, Vec<u8>) = connection
        .query_row("SELECT operation_id, record FROM logical_request_ledger", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .map_err(sqlite_error)?;
    let ledger: StoredLogicalLedgerRecord =
        decode_stored_json(&ledger_raw, "logical-request ledger record")?;
    let captured_outcome: EffectOutcome = decode_stored_json(
        report.logical_request.exchange.response_json.as_bytes(),
        "captured provider effect outcome",
    )?;
    let captured_response_metadata = captured_logical_response_metadata(&captured_outcome)?;
    let operation = report.logical_request.operation_id;
    validate_provider_ledger_binding(
        &ledger_key,
        &ledger,
        ProviderLedgerExpectations {
            run_identity: report.run_identity,
            operation,
            resource: report.logical_request.resource,
            request_digest: report.logical_request.request_digest,
            response_metadata: captured_response_metadata,
        },
    )?;

    let (effect_operation, logical_operation): (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT effect_operation, logical_operation FROM logical_request_effect",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sqlite_error)?;
    require(
        identity_from_blob(&effect_operation, "provider effect operation")?
            == report.logical_request.canonical_effect_operation
            && identity_from_blob(&logical_operation, "provider logical operation")? == operation,
        "provider logical_request_effect row does not bind the reported operation pair",
    )?;

    let (stored_operation, idempotency, request_raw, outcome_raw, cleaned): ProviderOperationRow =
        connection
            .query_row(
                "SELECT operation, idempotency_key, request, outcome, cleaned FROM provider_operation",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .map_err(sqlite_error)?;
    let effect_request: EffectRequest =
        decode_stored_json(&request_raw, "provider effect request")?;
    let outcome_raw =
        outcome_raw.ok_or_else(|| "provider operation omitted its terminal outcome".to_owned())?;
    let outcome: EffectOutcome = decode_stored_json(&outcome_raw, "provider effect outcome")?;
    let captured_request: EffectRequest = decode_stored_json(
        report.logical_request.exchange.request_json.as_bytes(),
        "captured provider effect request",
    )?;
    require(
        identity_from_blob(&stored_operation, "provider operation")?
            == report.logical_request.canonical_effect_operation
            && effect_request.operation == report.logical_request.canonical_effect_operation
            && effect_request.resource == report.logical_request.resource
            && effect_request == captured_request
            && idempotency.as_slice() == effect_request.idempotency_key.0
            && cleaned == 0
            && matches!(outcome, EffectOutcome::Succeeded { .. })
            && outcome == captured_outcome
            && canonical_digest(&outcome)
                .map_err(|error| format!("provider outcome digest: {error:?}"))?
                == report.logical_request.outcome_digest,
        "provider operation terminal row does not match the reported outcome",
    )?;
    Ok(())
}

fn validate_provider_ledger_binding(
    ledger_key: &[u8],
    ledger: &StoredLogicalLedgerRecord,
    expected: ProviderLedgerExpectations,
) -> Result<(), String> {
    let request = ledger
        .request
        .as_deref()
        .ok_or_else(|| "completed logical-request ledger omitted request bytes".to_owned())?;
    let response = ledger
        .response
        .as_deref()
        .ok_or_else(|| "completed logical-request ledger omitted response bytes".to_owned())?;
    let response_metadata = ledger
        .response_metadata
        .ok_or_else(|| "completed logical-request ledger omitted response metadata".to_owned())?;
    let actual_request_digest =
        canonical_digest(request).map_err(|error| format!("request digest: {error:?}"))?;
    let actual_response_metadata = StoredResponseMetadata {
        size: u32::try_from(response.len()).unwrap_or(u32::MAX),
        digest: canonical_digest(response)
            .map_err(|error| format!("response digest: {error:?}"))?,
    };
    let expected_peer_identity = b"visa-joint-logical-request-peer-v1".as_slice();
    let expected_credential_reference =
        derive_cell_identity(expected.run_identity, b"credential-reference")?;
    require(
        identity_from_blob(ledger_key, "provider ledger operation")? == expected.operation
            && ledger.operation_id == expected.operation
            && ledger.resource == expected.resource
            && ledger.revision == 3
            && ledger.phase == StoredLedgerPhase::Completed
            && !ledger.cleaned
            && ledger.rejection.is_none()
            && ledger.delivered_cursor == 0
            && ledger.peer_identity == expected_peer_identity
            && ledger.credential_reference == expected_credential_reference
            && ledger.request_size == u32::try_from(request.len()).unwrap_or(u32::MAX)
            && ledger.request_digest == expected.request_digest
            && actual_request_digest == ledger.request_digest
            && response_metadata == expected.response_metadata
            && response_metadata == actual_response_metadata,
        "provider ledger terminal row does not match the logical-request report",
    )
}

fn captured_logical_response_metadata(
    outcome: &EffectOutcome,
) -> Result<StoredResponseMetadata, String> {
    let EffectOutcome::Succeeded { result: EffectResult::Profile { payload, .. }, .. } = outcome
    else {
        return Err("captured provider outcome is not a successful profile result".to_owned());
    };
    let result: CapturedLogicalRequestResult = canonical_from_bytes(payload)
        .map_err(|error| format!("captured logical-request result payload: {error:?}"))?;
    require(
        canonical_bytes(&result)
            .map_err(|error| format!("captured logical-request result payload: {error:?}"))?
            == *payload,
        "captured logical-request result payload is not canonical",
    )?;
    let CapturedLogicalRequestResult::Started { observation } = result else {
        return Err("captured provider outcome is not a logical-request Start result".to_owned());
    };
    require(
        observation.phase == CapturedLogicalRequestPhase::Completed
            && observation.rejection.is_none(),
        "captured provider outcome is not a successful terminal logical response",
    )?;
    observation
        .response
        .ok_or_else(|| "captured provider outcome omitted logical response metadata".to_owned())
}

fn validate_ownership_database(
    path: &Path,
    report: &LogicalRequestDualLostAckReport,
) -> Result<(), String> {
    let connection = open_read_only_database(path, "logical-request ownership database")?;
    validate_sqlite_integrity(&connection, "logical-request ownership database")?;
    require(
        query_count(&connection, "SELECT COUNT(*) FROM ownership_handoff")? == 1
            && query_count(&connection, "SELECT COUNT(*) FROM ownership_unit")? == 1,
        "ownership database did not retain exactly one handoff and continuity unit",
    )?;
    let key = report.binding.ownership_commit.key;

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
    let captured_commit_request: OwnershipCommitRequest = decode_stored_json(
        report.ownership_commit_ack_loss.commit_exchange.request_json.as_bytes(),
        "captured ownership commit request",
    )?;
    let captured_commit_request_digest = joint_canonical_digest(&captured_commit_request)
        .map_err(|error| format!("ownership commit request digest: {error:?}"))?;
    validate_stored_ownership_lineage(
        &stored,
        report.binding.freeze.intent,
        report.binding.freeze.receipt_ref().map_err(|error| {
            format!("reported Nexus freeze reference for ownership record: {error:?}")
        })?,
        &report.binding.ownership_prepared,
        &report.binding.ownership_commit,
        &captured_commit_request,
    )?;
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
            && stored.reservation == report.binding.ownership_commit.reservation
            && stored.commit_request_digest == Some(captured_commit_request_digest)
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
            && unit.owner == report.terminal.ownership_owner
            && unit.epoch == key.next_epoch
            && unit.epoch == report.terminal.ownership_epoch
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
    let intent_ref = stored
        .intent
        .receipt_ref()
        .map_err(|error| format!("stored ownership intent reference: {error:?}"))?;
    let prepared_ref = prepared
        .receipt_ref()
        .map_err(|error| format!("reported ownership prepared reference: {error:?}"))?;
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
            && stored.intent.header.version == joint_handoff_core::JOINT_PROTOCOL_VERSION
            && stored.intent.header.kind == ReceiptKind::PrepareIntent
            && stored.intent.header.issuer == prepared.header.issuer
            && stored.intent.header.issuer_incarnation == prepared.header.issuer_incarnation
            && stored.intent.header.key_id == prepared.header.key_id
            && stored.intent.header.log_id == prepared.header.log_id
            && stored.intent.header.sequence == 1
            && stored.intent.header.previous_digest.is_none()
            && stored.intent.key == key
            && stored.intent.ownership_service == stored.intent.header.issuer
            && stored.intent.service_incarnation == stored.intent.header.issuer_incarnation
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

fn open_read_only_database(path: &Path, label: &str) -> Result<Connection, String> {
    let uri = immutable_sqlite_uri(path);
    let connection = Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|error| format!("cannot open {label} read-only: {error}"))?;
    connection
        .execute_batch("PRAGMA query_only = ON;")
        .map_err(|error| format!("cannot make {label} query-only: {error}"))?;
    let query_only: i64 =
        connection.query_row("PRAGMA query_only", [], |row| row.get(0)).map_err(sqlite_error)?;
    require(query_only == 1, &format!("{label} did not enter query-only mode"))?;
    Ok(connection)
}

fn immutable_sqlite_uri(path: &Path) -> String {
    let mut uri = String::from("file:");
    for byte in path.as_os_str().as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'/' | b'-' | b'.' | b'_' | b'~') {
            uri.push(char::from(*byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut uri, "%{byte:02X}").expect("writing to a String cannot fail");
        }
    }
    uri.push_str("?mode=ro&immutable=1");
    uri
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
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "Nexus executable is not a regular non-symlink file",
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

fn read_artifact_executable(root: &Path, expected_sha256: &str) -> Result<Vec<u8>, String> {
    let path = root.join(NEXUS_EFFECT_PEER_FILE);
    let before = fs::symlink_metadata(&path).map_err(|error| {
        format!("cannot inspect artifact-owned Nexus effect peer {}: {error}", path.display())
    })?;
    require(
        before.is_file() && !before.file_type().is_symlink() && before.nlink() == 1,
        "artifact-owned Nexus effect peer is not a single-link regular non-symlink file",
    )?;
    let bytes =
        read_stable_regular(&path, "artifact-owned Nexus effect peer", MAX_EXECUTABLE_BYTES)?;
    require(
        sha256_hex(&bytes) == expected_sha256,
        "artifact-owned Nexus effect peer SHA-256 differs from exact provenance",
    )?;
    let after = fs::symlink_metadata(&path)
        .map_err(|error| format!("cannot re-inspect artifact-owned Nexus effect peer: {error}"))?;
    require(
        after.is_file()
            && !after.file_type().is_symlink()
            && after.nlink() == 1
            && (before.dev(), before.ino(), before.len())
                == (after.dev(), after.ino(), after.len()),
        "artifact-owned Nexus effect peer identity or link count changed during verification",
    )?;
    Ok(bytes)
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

fn validate_incomplete_inventory(root: &Path) -> Result<(), String> {
    validate_inventory(
        root,
        &[
            INCOMPLETE_FILE,
            LOGICAL_REQUEST_DUAL_LOST_ACK_REPORT,
            LOGICAL_REQUEST_OWNERSHIP_DATABASE,
            LOGICAL_REQUEST_PROVIDER_DATABASE,
            NEXUS_EFFECT_PEER_FILE,
        ],
        "incomplete publication inventory drifted",
    )
}

fn validate_artifact_root(root: &Path) -> Result<(), String> {
    validate_inventory(
        root,
        &[
            MANIFEST_FILE,
            LOGICAL_REQUEST_DUAL_LOST_ACK_REPORT,
            LOGICAL_REQUEST_OWNERSHIP_DATABASE,
            LOGICAL_REQUEST_PROVIDER_DATABASE,
            NEXUS_EFFECT_PEER_FILE,
        ],
        "artifact inventory differs from the strict five-file publication",
    )
}

fn validate_inventory(root: &Path, expected: &[&str], message: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("cannot inspect artifact root {}: {error}", root.display()))?;
    require(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "artifact root is not a real directory",
    )?;
    let mut entries = Vec::new();
    for entry in fs::read_dir(root)
        .map_err(|error| format!("cannot enumerate artifact root {}: {error}", root.display()))?
    {
        let entry = entry.map_err(|error| format!("cannot enumerate artifact entry: {error}"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "artifact contains a non-UTF-8 entry name".to_owned())?;
        let entry_metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("cannot inspect artifact entry {name}: {error}"))?;
        require(
            entry_metadata.is_file() && !entry_metadata.file_type().is_symlink(),
            "artifact contains a non-regular or symlink entry",
        )?;
        entries.push(name);
    }
    entries.sort();
    let mut expected = expected.iter().map(|value| (*value).to_owned()).collect::<Vec<_>>();
    expected.sort();
    require(entries == expected, message)
}

fn read_stable_regular(path: &Path, label: &str, maximum: usize) -> Result<Vec<u8>, String> {
    let before = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {label} {}: {error}", path.display()))?;
    require(
        before.is_file() && !before.file_type().is_symlink(),
        &format!("{label} is not a regular non-symlink file"),
    )?;
    require(
        before.len() <= u64::try_from(maximum).unwrap_or(u64::MAX),
        &format!("{label} exceeds {maximum} bytes"),
    )?;
    let bytes = fs::read(path).map_err(|error| format!("cannot read {label}: {error}"))?;
    let after = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot re-inspect {label}: {error}"))?;
    let before_identity =
        (before.dev(), before.ino(), before.len(), before.mtime(), before.mtime_nsec());
    let after_identity = (after.dev(), after.ino(), after.len(), after.mtime(), after.mtime_nsec());
    require(
        before_identity == after_identity
            && bytes.len() == usize::try_from(after.len()).unwrap_or(usize::MAX),
        &format!("{label} changed while being read"),
    )?;
    Ok(bytes)
}

fn canonical_json<T: Serialize>(value: &T, label: &str) -> Result<Vec<u8>, String> {
    let mut bytes =
        serde_json::to_vec(value).map_err(|error| format!("cannot encode {label}: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn decode_canonical<T>(raw: &[u8], label: &str) -> Result<T, String>
where
    T: DeserializeOwned + Serialize,
{
    let value = serde_json::from_slice::<T>(raw)
        .map_err(|error| format!("cannot decode strict {label}: {error}"))?;
    require(
        canonical_json(&value, label)? == raw,
        &format!("{label} bytes are not canonical compact JSON plus one LF"),
    )?;
    Ok(value)
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
    use std::ffi::{OsStr, OsString};

    use serde_json::Value;

    use super::*;

    fn provenance() -> ArtifactProvenance {
        ArtifactProvenance {
            visa_revision: "1".repeat(40),
            nexus_revision: "2".repeat(40),
            nexus_reference_baseline_revision: "9".repeat(40),
            nexus_executable_sha256: "3".repeat(64),
            neutral_revision: "4".repeat(40),
            neutral_tree: "5".repeat(40),
            neutral_bundle_sha256: "6".repeat(64),
            source_lock_sha256: "7".repeat(64),
            nexus_qualification_lock_sha256: "8".repeat(64),
        }
    }

    fn sqlite(version: u32) -> Vec<u8> {
        let mut raw = vec![0_u8; 100];
        raw[..16].copy_from_slice(b"SQLite format 3\0");
        raw[60..64].copy_from_slice(&version.to_be_bytes());
        raw
    }

    fn manifest(
        report: &[u8],
        provider: &[u8],
        ownership: &[u8],
        executable: &[u8],
    ) -> ArtifactManifest {
        ArtifactManifest {
            schema: MANIFEST_SCHEMA.to_owned(),
            evidence_status: EVIDENCE_STATUS.to_owned(),
            report: artifact_file(
                LOGICAL_REQUEST_DUAL_LOST_ACK_REPORT,
                LOGICAL_REQUEST_DUAL_LOST_ACK_SCHEMA,
                report,
            )
            .unwrap(),
            provider_database: artifact_file(
                LOGICAL_REQUEST_PROVIDER_DATABASE,
                PROVIDER_DATABASE_SCHEMA,
                provider,
            )
            .unwrap(),
            ownership_database: artifact_file(
                LOGICAL_REQUEST_OWNERSHIP_DATABASE,
                OWNERSHIP_DATABASE_SCHEMA,
                ownership,
            )
            .unwrap(),
            nexus_effect_peer: artifact_file(
                NEXUS_EFFECT_PEER_FILE,
                NEXUS_EFFECT_PEER_SCHEMA,
                executable,
            )
            .unwrap(),
            provenance: provenance(),
            limitations: ArtifactLimitations::bounded(),
        }
    }

    fn stored_ownership_lineage_fixture()
    -> (StoredOwnership, OwnershipPreparedReceipt, OwnershipCommitReceipt, OwnershipCommitRequest)
    {
        let key = JointHandoffKey {
            continuity_unit: EntityRef::initial(Identity::from_u128(1)),
            handoff: Identity::from_u128(2),
            source: NodeIdentity::new(Identity::from_u128(3)),
            destination: NodeIdentity::new(Identity::from_u128(4)),
            expected_epoch: LeaseEpoch(1),
            next_epoch: LeaseEpoch(2),
        };
        let issuer = Identity::from_u128(10);
        let issuer_incarnation = Identity::from_u128(11);
        let key_id = Identity::from_u128(12);
        let log_id = Identity::from_u128(13);
        let reserve_request = OwnershipReserveRequest { key, expected_state_sequence: 0 };
        let reserve_request_digest = joint_canonical_digest(&reserve_request).unwrap();
        let reservation = Identity::from_u128(14);
        let intent = PrepareIntentReceipt {
            header: joint_handoff_core::ReceiptHeader {
                version: joint_handoff_core::JOINT_PROTOCOL_VERSION,
                kind: ReceiptKind::PrepareIntent,
                issuer,
                issuer_incarnation,
                key_id,
                log_id,
                sequence: 1,
                previous_digest: None,
            },
            key,
            ownership_service: issuer,
            service_incarnation: issuer_incarnation,
            reservation,
            intent_revision: 1,
            request_digest: reserve_request_digest,
        };
        let intent_ref = intent.receipt_ref().unwrap();
        let reference = |kind: ReceiptKind, seed: u8| joint_handoff_core::ReceiptRef {
            version: joint_handoff_core::JOINT_PROTOCOL_VERSION,
            kind,
            handoff: key.handoff,
            issuer: Identity::from_u128(u128::from(seed) + 20),
            issuer_incarnation: Identity::from_u128(u128::from(seed) + 30),
            key_id: Identity::from_u128(u128::from(seed) + 40),
            log_id: Identity::from_u128(u128::from(seed) + 50),
            sequence: 1,
            digest: ContractDigest::from_bytes([seed; 32]),
        };
        let visa_freeze = reference(ReceiptKind::VisaFreeze, 1);
        let nexus_freeze = reference(ReceiptKind::NexusFreeze, 2);
        let destination_prepared = reference(ReceiptKind::DestinationPrepared, 3);
        let bindings = joint_handoff_core::PreparedBindings {
            prepare_intent_receipt_digest: intent_ref.digest,
            visa_freeze_receipt_digest: visa_freeze.digest,
            effect_freeze_receipt_digest: nexus_freeze.digest,
            snapshot: Identity::from_u128(60),
            snapshot_integrity_digest: ContractDigest::from_bytes([4; 32]),
            source_journal_position: contract_core::JournalPosition(1),
            source_state_digest: ContractDigest::from_bytes([5; 32]),
            component_digest: ContractDigest::from_bytes([6; 32]),
            profile_digest: ContractDigest::from_bytes([7; 32]),
            destination_prepared_receipt_digest: destination_prepared.digest,
            destination_state_digest: ContractDigest::from_bytes([8; 32]),
            prepared_authorities_digest: ContractDigest::from_bytes([9; 32]),
            prepared_bindings_digest: ContractDigest::from_bytes([10; 32]),
            effect_cohort_manifest_digest: ContractDigest::from_bytes([11; 32]),
            joint_mapping_manifest_digest: ContractDigest::from_bytes([12; 32]),
        };
        let prepared = OwnershipPreparedReceipt {
            header: joint_handoff_core::ReceiptHeader {
                version: joint_handoff_core::JOINT_PROTOCOL_VERSION,
                kind: ReceiptKind::OwnershipPrepared,
                issuer,
                issuer_incarnation,
                key_id,
                log_id,
                sequence: 2,
                previous_digest: Some(intent_ref.digest),
            },
            key,
            reservation,
            intent: intent_ref,
            visa_freeze,
            nexus_freeze,
            destination_prepared,
            bindings,
            prepared_revision: 2,
        };
        let prepared_ref = prepared.receipt_ref().unwrap();
        let commit = OwnershipCommitReceipt {
            header: joint_handoff_core::ReceiptHeader {
                version: joint_handoff_core::JOINT_PROTOCOL_VERSION,
                kind: ReceiptKind::OwnershipCommit,
                issuer,
                issuer_incarnation,
                key_id,
                log_id,
                sequence: 3,
                previous_digest: Some(prepared_ref.digest),
            },
            key,
            reservation,
            prepared: prepared_ref,
            prepared_revision: 2,
            decision_sequence: 3,
            non_equivocation_root: ContractDigest::from_bytes([13; 32]),
        };
        let commit_request = OwnershipCommitRequest {
            key,
            reservation,
            prepared: prepared_ref,
            expected_state_sequence: 2,
        };
        let seal_request = OwnershipSealRequest {
            key,
            reservation,
            intent: intent_ref,
            visa_freeze,
            effect_freeze: nexus_freeze,
            destination_prepared,
            bindings,
            expected_state_sequence: 1,
        };
        let stored = StoredOwnership {
            key,
            reservation,
            state_sequence: 3,
            phase: StoredOwnershipPhase::CommitDecided,
            reserve_request_digest,
            intent,
            seal_request_digest: Some(joint_canonical_digest(&seal_request).unwrap()),
            prepared: Some(prepared.clone()),
            abort_request_digest: None,
            abort: None,
            commit_request_digest: Some(joint_canonical_digest(&commit_request).unwrap()),
            commit: Some(commit.clone()),
        };
        (stored, prepared, commit, commit_request)
    }

    #[test]
    fn parser_separates_run_only_path_from_normative_provenance() {
        let run_values = [
            "run",
            "artifact",
            &"1".repeat(40),
            "/tmp/nexus-effect-peer",
            &"3".repeat(64),
            &"2".repeat(40),
            &"9".repeat(40),
            &"4".repeat(40),
            &"5".repeat(40),
            &"6".repeat(64),
            &"7".repeat(64),
            &"8".repeat(64),
        ]
        .into_iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
        let parsed_run = parse_arguments(OsStr::new("runner"), &run_values).unwrap();
        assert_eq!(parsed_run.mode, Mode::Run);
        assert_eq!(parsed_run.execution_executable, Some(PathBuf::from("/tmp/nexus-effect-peer")));
        assert_eq!(parsed_run.provenance, provenance());
        assert!(parse_arguments(OsStr::new("runner"), &run_values[..11]).is_err());

        let mut relocated_run = run_values.clone();
        relocated_run[3] = OsString::from("/elsewhere/nexus-effect-peer");
        let relocated_run = parse_arguments(OsStr::new("runner"), &relocated_run).unwrap();
        assert_eq!(relocated_run.provenance, parsed_run.provenance);
        assert_eq!(
            derive_run_identity(&relocated_run.provenance).unwrap(),
            derive_run_identity(&parsed_run.provenance).unwrap()
        );

        let mut verify_values = run_values.clone();
        verify_values[0] = OsString::from("verify");
        verify_values.remove(3);
        let parsed_verify = parse_arguments(OsStr::new("runner"), &verify_values).unwrap();
        assert_eq!(parsed_verify.mode, Mode::Verify);
        assert_eq!(parsed_verify.execution_executable, None);
        assert_eq!(parsed_verify.provenance, parsed_run.provenance);
        assert!(parse_arguments(OsStr::new("runner"), &run_values[0..11]).is_err());

        let mut invalid = run_values;
        invalid[0] = OsString::from("inspect");
        assert!(parse_arguments(OsStr::new("runner"), &invalid).is_err());
    }

    #[test]
    fn provenance_and_run_identity_are_strict_and_stable() {
        let mut value = provenance();
        assert_eq!(validate_provenance(&value), Ok(()));
        let first = derive_run_identity(&value).unwrap();
        assert_eq!(derive_run_identity(&value).unwrap(), first);
        value.nexus_revision = "a".repeat(40);
        assert_ne!(derive_run_identity(&value).unwrap(), first);
        value.source_lock_sha256 = "A".repeat(64);
        assert!(validate_provenance(&value).is_err());
    }

    #[test]
    fn manifest_is_canonical_and_rejects_unknown_fields() {
        let report = b"{}\n";
        let provider = sqlite(PROVIDER_DATABASE_USER_VERSION);
        let ownership = sqlite(OWNERSHIP_DATABASE_USER_VERSION);
        let executable = b"opaque executable";
        let value = manifest(report, &provider, &ownership, executable);
        let canonical = canonical_json(&value, "manifest").unwrap();
        assert_eq!(decode_canonical::<ArtifactManifest>(&canonical, "manifest").unwrap(), value);

        let mut noncanonical = canonical.clone();
        noncanonical.push(b'\n');
        assert!(decode_canonical::<ArtifactManifest>(&noncanonical, "manifest").is_err());
        let mut unknown: Value = serde_json::from_slice(&canonical).unwrap();
        unknown["unknown"] = Value::Bool(true);
        let unknown = canonical_json(&unknown, "manifest").unwrap();
        assert!(decode_canonical::<ArtifactManifest>(&unknown, "manifest").is_err());
    }

    #[test]
    fn manifest_binds_every_owned_file_field_and_supplemental_limitations() {
        let report = b"{}\n";
        let provider = sqlite(PROVIDER_DATABASE_USER_VERSION);
        let ownership = sqlite(OWNERSHIP_DATABASE_USER_VERSION);
        let executable = b"opaque executable";
        let expected = provenance();
        let mut value = manifest(report, &provider, &ownership, executable);
        assert_eq!(
            validate_manifest(&value, &expected, report, &provider, &ownership, executable,),
            Ok(())
        );
        value.provider_database.sha256 = "0".repeat(64);
        assert!(
            validate_manifest(&value, &expected, report, &provider, &ownership, executable,)
                .is_err()
        );
        for mutation in ["path", "bytes", "sha256", "schema"] {
            let mut value = manifest(report, &provider, &ownership, executable);
            match mutation {
                "path" => value.nexus_effect_peer.path = "elsewhere".to_owned(),
                "bytes" => value.nexus_effect_peer.bytes += 1,
                "sha256" => value.nexus_effect_peer.sha256 = "0".repeat(64),
                "schema" => value.nexus_effect_peer.schema = "opaque".to_owned(),
                _ => unreachable!(),
            }
            assert!(
                validate_manifest(&value, &expected, report, &provider, &ownership, executable,)
                    .is_err(),
                "binary manifest mutation was accepted: {mutation}"
            );
        }
        let mut value = manifest(report, &provider, &ownership, executable);
        value.limitations.remote_ci_observed = true;
        assert!(
            validate_manifest(&value, &expected, report, &provider, &ownership, executable,)
                .is_err()
        );
        let bounded = ArtifactLimitations::bounded();
        assert!(!bounded.normative_joint_handoff_claim);
        assert!(!bounded.nexus_serialized_external_effect_admission);
        assert!(!bounded.visa_runtime_handoff_executed);
        assert!(!bounded.source_fencing_executed);
        assert!(!bounded.destination_activation_executed);
        assert!(!bounded.observed_executable_path_is_normative_provenance);
        assert!(!bounded.artifact_owned_binary_reexecuted_during_verification);
        assert!(!bounded.source_to_binary_reproducibility_claimed);
    }

    #[test]
    fn sqlite_header_binds_each_database_schema_version() {
        let provider = sqlite(PROVIDER_DATABASE_USER_VERSION);
        assert_eq!(
            validate_sqlite_bytes(&provider, PROVIDER_DATABASE_USER_VERSION, "provider"),
            Ok(())
        );
        assert!(
            validate_sqlite_bytes(&provider, OWNERSHIP_DATABASE_USER_VERSION, "ownership").is_err()
        );
        assert!(validate_sqlite_bytes(b"not sqlite", 0, "invalid").is_err());
    }

    #[test]
    fn captured_outcome_exposes_the_exact_terminal_response_metadata() {
        let response_metadata =
            StoredResponseMetadata { size: 23, digest: ContractDigest::from_bytes([7; 32]) };
        let result = CapturedLogicalRequestResult::Started {
            observation: CapturedLogicalRequestObservation {
                phase: CapturedLogicalRequestPhase::Completed,
                response: Some(response_metadata),
                rejection: None,
            },
        };
        let outcome = EffectOutcome::Succeeded {
            result: EffectResult::Profile {
                profile: Identity::from_u128(1),
                payload: canonical_bytes(&result).unwrap(),
            },
            evidence: contract_core::EvidenceRef {
                identity: Identity::from_u128(2),
                kind: contract_core::EvidenceKind::EffectOutcome,
                digest: ContractDigest::from_bytes([8; 32]),
            },
        };
        assert_eq!(captured_logical_response_metadata(&outcome).unwrap(), response_metadata);

        let mut missing = result.clone();
        let CapturedLogicalRequestResult::Started { observation } = &mut missing else {
            unreachable!()
        };
        observation.response = None;
        let mut changed = outcome.clone();
        let EffectOutcome::Succeeded { result: EffectResult::Profile { payload, .. }, .. } =
            &mut changed
        else {
            unreachable!()
        };
        *payload = canonical_bytes(&missing).unwrap();
        assert!(captured_logical_response_metadata(&changed).is_err());

        let mut nonterminal = result;
        let CapturedLogicalRequestResult::Started { observation } = &mut nonterminal else {
            unreachable!()
        };
        observation.phase = CapturedLogicalRequestPhase::Pending;
        let EffectOutcome::Succeeded { result: EffectResult::Profile { payload, .. }, .. } =
            &mut changed
        else {
            unreachable!()
        };
        *payload = canonical_bytes(&nonterminal).unwrap();
        assert!(captured_logical_response_metadata(&changed).is_err());
    }

    #[test]
    fn stored_ownership_lineage_rejects_intent_and_request_digest_mutations() {
        let (stored, prepared, commit, commit_request) = stored_ownership_lineage_fixture();
        assert_eq!(
            validate_stored_ownership_lineage(
                &stored,
                prepared.intent,
                prepared.nexus_freeze,
                &prepared,
                &commit,
                &commit_request,
            ),
            Ok(())
        );

        let mut changed = stored.clone();
        changed.reserve_request_digest = ContractDigest::ZERO;
        assert!(
            validate_stored_ownership_lineage(
                &changed,
                prepared.intent,
                prepared.nexus_freeze,
                &prepared,
                &commit,
                &commit_request,
            )
            .is_err()
        );
        let mut changed = stored.clone();
        changed.intent.request_digest = ContractDigest::ZERO;
        assert!(
            validate_stored_ownership_lineage(
                &changed,
                prepared.intent,
                prepared.nexus_freeze,
                &prepared,
                &commit,
                &commit_request,
            )
            .is_err()
        );
        let mut changed = stored.clone();
        changed.seal_request_digest = Some(ContractDigest::ZERO);
        assert!(
            validate_stored_ownership_lineage(
                &changed,
                prepared.intent,
                prepared.nexus_freeze,
                &prepared,
                &commit,
                &commit_request,
            )
            .is_err()
        );
        let mut changed_prepared = prepared.clone();
        changed_prepared.bindings.source_state_digest = ContractDigest::ZERO;
        assert!(
            validate_stored_ownership_lineage(
                &stored,
                prepared.intent,
                prepared.nexus_freeze,
                &changed_prepared,
                &commit,
                &commit_request,
            )
            .is_err()
        );
        let mut changed_commit_request = commit_request;
        changed_commit_request.expected_state_sequence = 3;
        assert!(
            validate_stored_ownership_lineage(
                &stored,
                prepared.intent,
                prepared.nexus_freeze,
                &prepared,
                &commit,
                &changed_commit_request,
            )
            .is_err()
        );
        let mut changed_freeze_intent = prepared.intent;
        changed_freeze_intent.digest = ContractDigest::ZERO;
        assert!(
            validate_stored_ownership_lineage(
                &stored,
                changed_freeze_intent,
                prepared.nexus_freeze,
                &prepared,
                &commit,
                &commit_request,
            )
            .is_err()
        );
    }

    #[test]
    fn provider_ledger_binding_rejects_claim_and_captured_response_mutations() {
        let run_identity = Identity::from_u128(0x4c52_2d44_422d_5445_5354);
        let operation = Identity::from_u128(10);
        let resource = EntityRef::initial(Identity::from_u128(11));
        let request = b"logical request bytes".to_vec();
        let response = b"captured response bytes".to_vec();
        let request_digest = canonical_digest(request.as_slice()).unwrap();
        let response_metadata = StoredResponseMetadata {
            size: u32::try_from(response.len()).unwrap(),
            digest: canonical_digest(response.as_slice()).unwrap(),
        };
        let expected = ProviderLedgerExpectations {
            run_identity,
            operation,
            resource,
            request_digest,
            response_metadata,
        };
        let ledger_key = operation.0.to_vec();
        let ledger = StoredLogicalLedgerRecord {
            revision: 3,
            resource,
            operation_id: operation,
            peer_identity: b"visa-joint-logical-request-peer-v1".to_vec(),
            credential_reference: derive_cell_identity(run_identity, b"credential-reference")
                .unwrap(),
            request_size: u32::try_from(request.len()).unwrap(),
            request_digest,
            request: Some(request),
            phase: StoredLedgerPhase::Completed,
            response: Some(response),
            response_metadata: Some(response_metadata),
            delivered_cursor: 0,
            rejection: None,
            cleaned: false,
        };
        assert_eq!(validate_provider_ledger_binding(&ledger_key, &ledger, expected), Ok(()));

        let mut changed = ledger.clone();
        changed.peer_identity = b"different-peer".to_vec();
        assert!(validate_provider_ledger_binding(&ledger_key, &changed, expected).is_err());

        let mut changed = ledger.clone();
        changed.credential_reference = Identity::from_u128(12);
        assert!(validate_provider_ledger_binding(&ledger_key, &changed, expected).is_err());

        let mut changed = ledger.clone();
        changed.response.as_mut().unwrap()[0] ^= 1;
        assert!(validate_provider_ledger_binding(&ledger_key, &changed, expected).is_err());

        let mut changed = ledger.clone();
        changed.response_metadata.as_mut().unwrap().digest = ContractDigest::ZERO;
        assert!(validate_provider_ledger_binding(&ledger_key, &changed, expected).is_err());

        let mut changed_expected = expected;
        changed_expected.response_metadata.digest = ContractDigest::ZERO;
        assert!(validate_provider_ledger_binding(&ledger_key, &ledger, changed_expected).is_err());
    }

    #[test]
    fn strict_five_file_inventory_owns_the_executable_bytes() {
        let unique =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let root = std::env::temp_dir()
            .join(format!("visa-logical-request-five-file-{}-{unique}", std::process::id()));
        fs::create_dir(&root).unwrap();
        for name in [
            MANIFEST_FILE,
            LOGICAL_REQUEST_DUAL_LOST_ACK_REPORT,
            LOGICAL_REQUEST_OWNERSHIP_DATABASE,
            LOGICAL_REQUEST_PROVIDER_DATABASE,
        ] {
            fs::write(root.join(name), b"evidence").unwrap();
        }
        let executable = b"owned executable bytes";
        let executable_path = root.join(NEXUS_EFFECT_PEER_FILE);
        write_new_executable(&executable_path, executable).unwrap();
        assert_eq!(validate_artifact_root(&root), Ok(()));
        assert_eq!(read_artifact_executable(&root, &sha256_hex(executable)).unwrap(), executable);

        let mut downloaded_permissions =
            fs::symlink_metadata(&executable_path).unwrap().permissions();
        downloaded_permissions.set_mode(0o644);
        fs::set_permissions(&executable_path, downloaded_permissions).unwrap();
        assert_eq!(read_artifact_executable(&root, &sha256_hex(executable)).unwrap(), executable);

        let hardlink = root.with_extension("hardlink");
        fs::hard_link(&executable_path, &hardlink).unwrap();
        assert!(read_artifact_executable(&root, &sha256_hex(executable)).is_err());
        fs::remove_file(hardlink).unwrap();
        assert_eq!(read_artifact_executable(&root, &sha256_hex(executable)).unwrap(), executable);

        fs::write(&executable_path, b"tampered executable bytes").unwrap();
        assert!(read_artifact_executable(&root, &sha256_hex(executable)).is_err());
        fs::remove_file(&executable_path).unwrap();
        std::os::unix::fs::symlink(root.join(MANIFEST_FILE), &executable_path).unwrap();
        assert!(read_artifact_executable(&root, &sha256_hex(executable)).is_err());

        fs::write(root.join("unexpected"), b"not inventoried").unwrap();
        assert!(validate_artifact_root(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn immutable_read_only_database_does_not_create_wal_sidecars() {
        let path = std::env::temp_dir()
            .join(format!("visa logical%request immutable-{}.sqlite3", std::process::id()));
        let wal = PathBuf::from(format!("{}-wal", path.display()));
        let shm = PathBuf::from(format!("{}-shm", path.display()));
        for candidate in [&path, &wal, &shm] {
            let _ = fs::remove_file(candidate);
        }
        {
            let connection = Connection::open(&path).unwrap();
            connection
                .execute_batch(
                    "PRAGMA journal_mode = WAL;
                     PRAGMA user_version = 5;
                     CREATE TABLE evidence(value INTEGER NOT NULL);
                     INSERT INTO evidence(value) VALUES (1);",
                )
                .unwrap();
        }
        assert!(!wal.exists() && !shm.exists());
        let before = fs::read(&path).unwrap();
        let connection = open_read_only_database(&path, "test database").unwrap();
        assert_eq!(query_count(&connection, "SELECT COUNT(*) FROM evidence").unwrap(), 1);
        drop(connection);
        assert_eq!(fs::read(&path).unwrap(), before);
        assert!(!wal.exists() && !shm.exists());
        fs::remove_file(path).unwrap();
    }
}
