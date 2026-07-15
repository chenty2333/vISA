use serde::{Deserialize, Serialize};

use crate::{
    Stage1AuthorityEnforcementIdentity, Stage1EvidenceKind, Stage1FaultSchedule,
    Stage1ProviderIdentity, Stage1ResourceProfile, Stage1VersionedIdentity,
    Stage2SnapshotTimerStrategy,
};

pub const STAGE4_EVIDENCE_SCHEMA_VERSION: &str = "visa-stage4-evidence-v1";
pub const STAGE4_MATRIX_SCHEMA_VERSION: &str = "visa-stage4-matrix-v1";
pub const STAGE4_COMMON_INPUT_SCHEMA_VERSION: &str = "visa-stage4-common-input-v2";
pub const STAGE4_BUILD_RECEIPT_SCHEMA_VERSION: &str = "visa-stage4-build-receipt-v1";
pub const STAGE4_LAUNCHER_RECEIPT_SCHEMA_VERSION: &str = "visa-stage4-launcher-receipt-v1";
pub const STAGE4_SYSROOT_RECEIPT_SCHEMA_VERSION: &str = "visa-stage4-sysroot-receipt-v1";
pub const STAGE4_SYSROOT_MANIFEST_SCHEMA_VERSION: &str = "visa-stage4-sysroot-manifest-v1";
pub const STAGE4_TARGET_HELLO_SCHEMA_VERSION: &str = "visa-stage4-target-hello-v1";
pub const STAGE4_HOST_RECEIPT_SCHEMA_VERSION: &str = "visa-stage4-host-receipt-v1";
pub const STAGE4_EVIDENCE_FILE: &str = "stage4-evidence.json";
pub const STAGE4_MATRIX_FILE: &str = "matrix.json";
pub const STAGE4_COMMON_INPUT_FILE: &str = "inputs/stage4-common-input.json";
pub const STAGE4_INCOMPLETE_MARKER_FILE: &str = "stage4-incomplete";
pub const STAGE4_INCOMPLETE_MARKER_CONTENT: &[u8] = b"stage4 evidence publication incomplete\n";
pub const STAGE4_HOST_UNAME_STDOUT_FILE: &str = "targets/orchestrator/uname.stdout.txt";
pub const STAGE4_HOST_UNAME_STDERR_FILE: &str = "targets/orchestrator/uname.stderr.log";
pub const STAGE4_CASE_COUNT: usize = 31;
pub const STAGE4_CELL_COUNT: usize = 7;
pub const STAGE4_EXECUTION_COUNT: usize = STAGE4_CASE_COUNT * STAGE4_CELL_COUNT;
pub const STAGE4_WORKER_PROTOCOL_VERSION: u64 = 3;
// Stage 4 cross-builds release workers, so Cargo also builds the embedded
// handoff Component with the release profile. This is intentionally a
// different byte artifact from Strict Stage 2's dev-profile Component even
// though both implement the same locked WIT world and Stage 1 workload.
// Update only after an explicit Stage 4 Component/toolchain review.
pub const STAGE4_ACCEPTED_COMPONENT_SHA256: &str =
    "64ac7689f90a09f2b0a6756cf9087e952e775f81470c57b1c12a988ecee967af";
// Updated only by an explicit endpoint/cell/claim/case registry review.
pub const STAGE4_ACCEPTED_REGISTRY_SHA256: &str =
    "add0099df5d8b8f89c847496ab151347e1b6051810f2beb722f8b0ddc3e23cdf";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Stage4EndpointId {
    #[serde(rename = "Hx")]
    Hx,
    #[serde(rename = "Qx")]
    Qx,
    #[serde(rename = "Qa")]
    Qa,
}

impl Stage4EndpointId {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hx => "Hx",
            Self::Qx => "Qx",
            Self::Qa => "Qa",
        }
    }

    pub const fn architecture(self) -> &'static str {
        match self {
            Self::Hx | Self::Qx => "x86_64",
            Self::Qa => "aarch64",
        }
    }

    pub const fn target_triple(self) -> &'static str {
        match self {
            Self::Hx | Self::Qx => "x86_64-unknown-linux-gnu",
            Self::Qa => "aarch64-unknown-linux-gnu",
        }
    }

    pub const fn required_execution_mode(self) -> Stage4ExecutionMode {
        match self {
            Self::Hx => Stage4ExecutionMode::NativeHost,
            Self::Qx | Self::Qa => Stage4ExecutionMode::UserEmulated,
        }
    }

    pub fn worker_uri(self) -> String {
        format!("targets/{}/worker", self.as_str())
    }

    pub fn build_receipt_uri(self) -> String {
        format!("targets/{}/build-receipt.json", self.as_str())
    }

    pub fn launcher_receipt_uri(self) -> String {
        format!("targets/{}/launcher-receipt.json", self.as_str())
    }

    pub fn sysroot_receipt_uri(self) -> String {
        format!("targets/{}/sysroot-receipt.json", self.as_str())
    }

    pub fn sysroot_manifest_uri(self) -> String {
        format!("targets/{}/sysroot-manifest.json", self.as_str())
    }

    pub fn loader_resolution_stdout_uri(self) -> String {
        format!("targets/{}/loader-resolution.stdout.txt", self.as_str())
    }

    pub fn loader_resolution_stderr_uri(self) -> String {
        format!("targets/{}/loader-resolution.stderr.log", self.as_str())
    }

    pub fn qemu_uri(self) -> String {
        format!("targets/{}/qemu", self.as_str())
    }

    pub fn qemu_version_stdout_uri(self) -> String {
        format!("targets/{}/qemu-version.stdout.txt", self.as_str())
    }

    pub fn qemu_version_stderr_uri(self) -> String {
        format!("targets/{}/qemu-version.stderr.log", self.as_str())
    }
}

pub const STAGE4_ENDPOINT_CATALOG: &[Stage4EndpointId] =
    &[Stage4EndpointId::Hx, Stage4EndpointId::Qx, Stage4EndpointId::Qa];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage4CellId {
    HxToHx,
    HxToQx,
    QxToHx,
    QxToQx,
    QxToQa,
    QaToQx,
    QaToQa,
}

impl Stage4CellId {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HxToHx => "hx-to-hx",
            Self::HxToQx => "hx-to-qx",
            Self::QxToHx => "qx-to-hx",
            Self::QxToQx => "qx-to-qx",
            Self::QxToQa => "qx-to-qa",
            Self::QaToQx => "qa-to-qx",
            Self::QaToQa => "qa-to-qa",
        }
    }

    pub const fn endpoints(self) -> (Stage4EndpointId, Stage4EndpointId) {
        match self {
            Self::HxToHx => (Stage4EndpointId::Hx, Stage4EndpointId::Hx),
            Self::HxToQx => (Stage4EndpointId::Hx, Stage4EndpointId::Qx),
            Self::QxToHx => (Stage4EndpointId::Qx, Stage4EndpointId::Hx),
            Self::QxToQx => (Stage4EndpointId::Qx, Stage4EndpointId::Qx),
            Self::QxToQa => (Stage4EndpointId::Qx, Stage4EndpointId::Qa),
            Self::QaToQx => (Stage4EndpointId::Qa, Stage4EndpointId::Qx),
            Self::QaToQa => (Stage4EndpointId::Qa, Stage4EndpointId::Qa),
        }
    }

    pub fn cell_root_uri(self) -> String {
        format!("cells/{}", self.as_str())
    }

    pub fn stage1_bundle_uri(self) -> String {
        format!("{}/stage1-evidence.json", self.cell_root_uri())
    }

    pub fn normalized_uri(self) -> String {
        format!("normalized/{}.json", self.as_str())
    }

    pub fn hello_stdout_uri(self, role: Stage4Role) -> String {
        format!("{}/hello/{}.stdout.json", self.cell_root_uri(), role.as_str())
    }

    pub fn hello_stderr_uri(self, role: Stage4Role) -> String {
        format!("{}/hello/{}.stderr.log", self.cell_root_uri(), role.as_str())
    }
}

pub const STAGE4_CELL_CATALOG: &[Stage4CellId] = &[
    Stage4CellId::HxToHx,
    Stage4CellId::HxToQx,
    Stage4CellId::QxToHx,
    Stage4CellId::QxToQx,
    Stage4CellId::QxToQa,
    Stage4CellId::QaToQx,
    Stage4CellId::QaToQa,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage4ClaimId {
    NamedTargetSubstrateContinuityV1,
    EmulatedCrossIsaContinuityV1,
}

impl Stage4ClaimId {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NamedTargetSubstrateContinuityV1 => "named-target-substrate-continuity-v1",
            Self::EmulatedCrossIsaContinuityV1 => "emulated-cross-isa-continuity-v1",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4ClaimDefinition {
    pub claim_id: Stage4ClaimId,
    pub required_cells: Vec<Stage4CellId>,
}

pub fn required_stage4_claims() -> Vec<Stage4ClaimDefinition> {
    vec![
        Stage4ClaimDefinition {
            claim_id: Stage4ClaimId::NamedTargetSubstrateContinuityV1,
            required_cells: vec![
                Stage4CellId::HxToHx,
                Stage4CellId::HxToQx,
                Stage4CellId::QxToHx,
                Stage4CellId::QxToQx,
            ],
        },
        Stage4ClaimDefinition {
            claim_id: Stage4ClaimId::EmulatedCrossIsaContinuityV1,
            required_cells: vec![
                Stage4CellId::QxToQx,
                Stage4CellId::QxToQa,
                Stage4CellId::QaToQx,
                Stage4CellId::QaToQa,
            ],
        },
    ]
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4ArtifactReference {
    pub uri: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4TargetIdentity {
    pub target_triple: String,
    pub architecture: String,
    pub os: String,
    pub abi: String,
    pub endianness: String,
    pub pointer_width_bits: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4HostIdentity {
    pub sysname: String,
    pub kernel_release: String,
    pub machine: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4HostReceipt {
    pub schema_version: String,
    pub program: String,
    pub program_sha256: String,
    pub program_size: u64,
    pub argv: Vec<String>,
    pub exit_status: i32,
    pub identity: Stage4HostIdentity,
    pub raw_stdout: Stage4ArtifactReference,
    pub raw_stderr: Stage4ArtifactReference,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage4ExecutionMode {
    NativeHost,
    UserEmulated,
    FullSystem,
    Hardware,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4ExecutionBoundary {
    pub native_host: bool,
    pub user_emulated: bool,
    pub full_system: bool,
    pub hardware: bool,
}

impl Stage4ExecutionBoundary {
    pub const fn for_mode(mode: Stage4ExecutionMode) -> Self {
        Self {
            native_host: matches!(mode, Stage4ExecutionMode::NativeHost),
            user_emulated: matches!(mode, Stage4ExecutionMode::UserEmulated),
            full_system: matches!(mode, Stage4ExecutionMode::FullSystem),
            hardware: matches!(mode, Stage4ExecutionMode::Hardware),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4BuildReceipt {
    pub schema_version: String,
    pub endpoint_id: Stage4EndpointId,
    pub target: Stage4TargetIdentity,
    pub executable_sha256: String,
    pub executable_size: u64,
    pub build_source_sha256: String,
    pub build_toolchain_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4SysrootReceipt {
    pub schema_version: String,
    pub endpoint_id: Stage4EndpointId,
    pub identity: String,
    pub manifest: Stage4ArtifactReference,
    pub loader_resolution_stdout: Stage4ArtifactReference,
    pub loader_resolution_stderr: Stage4ArtifactReference,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4SysrootManifestEntry {
    pub name: String,
    pub version: String,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4SysrootManifest {
    pub schema_version: String,
    pub endpoint_id: Stage4EndpointId,
    pub entries: Vec<Stage4SysrootManifestEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4QemuReceipt {
    pub adapter_family: String,
    pub emulator_name: String,
    pub emulator_version: String,
    pub executable: Stage4ArtifactReference,
    pub version_stdout: Stage4ArtifactReference,
    pub version_stderr: Stage4ArtifactReference,
    pub argv_prefix: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4LauncherReceipt {
    pub schema_version: String,
    pub endpoint_id: Stage4EndpointId,
    pub execution_mode: Stage4ExecutionMode,
    pub boundary: Stage4ExecutionBoundary,
    pub program_sha256: String,
    pub program_size: u64,
    pub argv: Vec<String>,
    pub qemu: Option<Stage4QemuReceipt>,
    pub sysroot: Stage4ArtifactReference,
    pub native_fallback_allowed: bool,
    pub observed_native_fallback: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4EndpointEvidence {
    pub endpoint_id: Stage4EndpointId,
    pub target: Stage4TargetIdentity,
    pub worker_executable: Stage4ArtifactReference,
    pub build_receipt_artifact: Stage4ArtifactReference,
    pub build_receipt: Stage4BuildReceipt,
    pub launcher_receipt_artifact: Stage4ArtifactReference,
    pub launcher_receipt: Stage4LauncherReceipt,
    pub sysroot_receipt_artifact: Stage4ArtifactReference,
    pub sysroot_receipt: Stage4SysrootReceipt,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4TargetHello {
    pub schema_version: String,
    pub nonce: String,
    pub target_triple: String,
    pub architecture: String,
    pub os: String,
    pub abi: String,
    pub endianness: String,
    pub pointer_width_bits: u16,
    pub executable_sha256: String,
    pub executable_size: u64,
    pub build_source_sha256: String,
    pub build_toolchain_sha256: String,
    pub worker_protocol_version: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage4Role {
    Source,
    Destination,
}

impl Stage4Role {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Destination => "destination",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4TargetHelloObservation {
    pub expected_nonce: String,
    pub exit_status: i32,
    pub hello: Stage4TargetHello,
    pub raw_stdout: Stage4ArtifactReference,
    pub raw_stderr: Stage4ArtifactReference,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4CommonCaseInput {
    pub case_id: String,
    pub case_config_sha256: String,
    pub case_policy_sha256: String,
    pub snapshot_timer_strategy: Stage2SnapshotTimerStrategy,
    pub fault_schedule: Stage1FaultSchedule,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4CommonInputIdentity {
    pub schema_version: String,
    pub stage1_schema_version: String,
    pub capability_id: String,
    pub evidence_kind: Stage1EvidenceKind,
    pub component_sha256: String,
    pub wit_world_name: String,
    pub wit_world_sha256: String,
    pub profile_sha256: String,
    pub config_sha256: String,
    pub source_sha256: String,
    pub toolchain_sha256: String,
    pub carrier: Stage1VersionedIdentity,
    pub source_runtime: Stage1VersionedIdentity,
    pub destination_runtime: Stage1VersionedIdentity,
    pub substrate: Stage1VersionedIdentity,
    pub provider: Stage1ProviderIdentity,
    pub authority_enforcement: Stage1AuthorityEnforcementIdentity,
    pub resource_profiles: Vec<Stage1ResourceProfile>,
    pub cases: Vec<Stage4CommonCaseInput>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Stage4CellDisposition {
    Passed {
        stage1_bundle: Stage4ArtifactReference,
        normalized_observable_trace: Stage4ArtifactReference,
        source_hello: Stage4TargetHelloObservation,
        destination_hello: Stage4TargetHelloObservation,
    },
    Failed {
        reason: String,
        diagnostics: Vec<Stage4ArtifactReference>,
    },
    NotRun {
        reason: String,
    },
    Unsupported {
        reason: String,
    },
}

impl Stage4CellDisposition {
    pub const fn is_passed(&self) -> bool {
        matches!(self, Self::Passed { .. })
    }

    pub const fn status(&self) -> Stage4CellStatus {
        match self {
            Self::Passed { .. } => Stage4CellStatus::Passed,
            Self::Failed { .. } => Stage4CellStatus::Failed,
            Self::NotRun { .. } => Stage4CellStatus::NotRun,
            Self::Unsupported { .. } => Stage4CellStatus::Unsupported,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage4CellStatus {
    Passed,
    Failed,
    NotRun,
    Unsupported,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4CellEvidence {
    pub cell_id: Stage4CellId,
    pub source_endpoint: Stage4EndpointId,
    pub destination_endpoint: Stage4EndpointId,
    pub disposition: Stage4CellDisposition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage4ClaimBoundary {
    Proven,
    NotClaimed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4ClaimGuards {
    pub real_aarch64_hardware: Stage4ClaimBoundary,
    pub no_std_reference_kernel: Stage4ClaimBoundary,
    pub real_device_enforcement: Stage4ClaimBoundary,
    pub stage3_resources_cross_target: Stage4ClaimBoundary,
    pub second_stage4_runtime: Stage4ClaimBoundary,
    pub aot_binary_portability: Stage4ClaimBoundary,
    pub cross_host: Stage4ClaimBoundary,
    pub big_endian_or_32_bit: Stage4ClaimBoundary,
    pub hostile_host_or_confidentiality: Stage4ClaimBoundary,
    pub production_or_performance: Stage4ClaimBoundary,
}

impl Stage4ClaimGuards {
    pub const fn required() -> Self {
        Self {
            real_aarch64_hardware: Stage4ClaimBoundary::NotClaimed,
            no_std_reference_kernel: Stage4ClaimBoundary::NotClaimed,
            real_device_enforcement: Stage4ClaimBoundary::NotClaimed,
            stage3_resources_cross_target: Stage4ClaimBoundary::NotClaimed,
            second_stage4_runtime: Stage4ClaimBoundary::NotClaimed,
            aot_binary_portability: Stage4ClaimBoundary::NotClaimed,
            cross_host: Stage4ClaimBoundary::NotClaimed,
            big_endian_or_32_bit: Stage4ClaimBoundary::NotClaimed,
            hostile_host_or_confidentiality: Stage4ClaimBoundary::NotClaimed,
            production_or_performance: Stage4ClaimBoundary::NotClaimed,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage4QualificationStatus {
    Unsupported,
    NotRun,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4QualificationRecord {
    pub qualification_id: String,
    pub status: Stage4QualificationStatus,
    pub reason: String,
}

pub fn required_stage4_qualifications() -> Vec<Stage4QualificationRecord> {
    vec![
        Stage4QualificationRecord {
            qualification_id: "legacy-no-std-reference-kernel".to_owned(),
            status: Stage4QualificationStatus::Unsupported,
            reason: "runtime-not-linked-and-legacy-engine-stub".to_owned(),
        },
        Stage4QualificationRecord {
            qualification_id: "real-aarch64-hardware".to_owned(),
            status: Stage4QualificationStatus::NotRun,
            reason: "qemu-user-qualification-only".to_owned(),
        },
    ]
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4MatrixManifest {
    pub schema_version: String,
    pub common_input: Stage4ArtifactReference,
    pub execution_artifact_root: String,
    pub orchestrator: Stage4TargetIdentity,
    pub orchestrator_host: Stage4HostReceipt,
    pub registry_sha256: String,
    pub endpoints: Vec<Stage4EndpointEvidence>,
    pub claims: Vec<Stage4ClaimDefinition>,
    pub claim_guards: Stage4ClaimGuards,
    pub qualifications: Vec<Stage4QualificationRecord>,
    pub cells: Vec<Stage4CellEvidence>,
    pub execution_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4InnerVerification {
    pub cell_id: Stage4CellId,
    pub disposition: Stage4CellStatus,
    pub stage1_bundle_id: Option<String>,
    pub stage1_bundle_sha256: Option<String>,
    pub case_count: usize,
    pub independently_verified: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4CaseComparison {
    pub case_id: String,
    pub normalized_case_sha256: String,
    pub equal_across_all_cells: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4EvidenceBundle {
    pub schema_version: String,
    pub bundle_id: String,
    pub matrix_manifest: Stage4ArtifactReference,
    pub completed_execution_count: usize,
    pub inner_verifications: Vec<Stage4InnerVerification>,
    pub case_comparisons: Vec<Stage4CaseComparison>,
    pub claims: Vec<Stage4ClaimDefinition>,
    pub claim_guards: Stage4ClaimGuards,
    pub qualifications: Vec<Stage4QualificationRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stage4ValidationFinding {
    pub code: String,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stage4ValidationReport {
    pub ok: bool,
    pub findings: Vec<Stage4ValidationFinding>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stage4EvidenceLoadError {
    pub code: String,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stage4EvidenceGateResult {
    pub ok: bool,
    pub load_error: Option<Stage4EvidenceLoadError>,
    pub validation: Option<Stage4ValidationReport>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Stage4PublicationCellDisposition {
    Passed {
        stage1_bundle: Stage4ArtifactReference,
        source_hello: Stage4TargetHelloObservation,
        destination_hello: Stage4TargetHelloObservation,
    },
    Failed {
        reason: String,
        diagnostics: Vec<Stage4ArtifactReference>,
    },
    NotRun {
        reason: String,
    },
    Unsupported {
        reason: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4PublicationCell {
    pub cell_id: Stage4CellId,
    pub source_endpoint: Stage4EndpointId,
    pub destination_endpoint: Stage4EndpointId,
    pub disposition: Stage4PublicationCellDisposition,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4PublicationInput {
    pub orchestrator: Stage4TargetIdentity,
    pub orchestrator_host: Stage4HostReceipt,
    pub endpoints: Vec<Stage4EndpointEvidence>,
    pub cells: Vec<Stage4PublicationCell>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stage4WriteResult {
    pub bundle_path: String,
    pub matrix_path: String,
    pub completed_execution_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stage4WriteError {
    pub code: String,
    pub detail: String,
}

impl std::fmt::Display for Stage4WriteError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for Stage4WriteError {}
