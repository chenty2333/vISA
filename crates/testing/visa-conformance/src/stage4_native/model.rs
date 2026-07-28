use serde::{Deserialize, Serialize};

use crate::{
    Stage4ArtifactReference, Stage4CommonInputIdentity, Stage4HostIdentity,
    Stage4TargetHelloObservation, Stage4TargetIdentity,
};

pub const STAGE4_NATIVE_EVIDENCE_SCHEMA_VERSION: &str = "visa-stage4-native-evidence-v1";
pub const STAGE4_NATIVE_MATRIX_SCHEMA_VERSION: &str = "visa-stage4-native-matrix-v1";
pub const STAGE4_NATIVE_HOST_RECEIPT_SCHEMA_VERSION: &str = "visa-stage4-native-host-receipt-v1";
pub const STAGE4_NATIVE_HOST_OBSERVATION_SCHEMA_VERSION: &str =
    "visa-stage4-native-host-observation-v1";
pub const STAGE4_NATIVE_BUILD_RECEIPT_SCHEMA_VERSION: &str = "visa-stage4-native-build-receipt-v1";
pub const STAGE4_NATIVE_LAUNCHER_RECEIPT_SCHEMA_VERSION: &str =
    "visa-stage4-native-launcher-receipt-v1";
pub const STAGE4_NATIVE_PROVIDER_RECEIPT_SCHEMA_VERSION: &str =
    "visa-stage4-native-provider-receipt-v1";
pub const STAGE4_NATIVE_EVIDENCE_FILE: &str = "stage4-native-evidence.json";
pub const STAGE4_NATIVE_MATRIX_FILE: &str = "matrix.json";
pub const STAGE4_NATIVE_COMMON_INPUT_FILE: &str = "inputs/stage4-native-common-input.json";
pub const STAGE4_NATIVE_PROVIDER_RECEIPT_FILE: &str = "provider/provider-receipt.json";
pub const STAGE4_NATIVE_PROVIDER_BACKEND_IDENTITY: &str = "substrate_host::SqliteProvider";
pub const STAGE4_NATIVE_INCOMPLETE_MARKER_FILE: &str = "stage4-native-incomplete";
pub const STAGE4_NATIVE_INCOMPLETE_MARKER_CONTENT: &[u8] =
    b"Stage 4 native evidence publication incomplete\n";
pub const STAGE4_NATIVE_CASE_COUNT: usize = 31;
pub const STAGE4_NATIVE_CELL_COUNT: usize = 4;
pub const STAGE4_NATIVE_EXECUTION_COUNT: usize =
    STAGE4_NATIVE_CASE_COUNT * STAGE4_NATIVE_CELL_COUNT;
pub const STAGE4_NATIVE_CLAIM_ID: &str = "native-arm-cross-isa-continuity-v1";
// Resealed only after an explicit endpoint/cell/claim/case registry review.
pub const STAGE4_NATIVE_ACCEPTED_REGISTRY_SHA256: &str =
    "d306c21c404ea83a91eff9c4b73399d210c75b7e1b6c0c4e0788bc68134ba3d6";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Stage4NativeEndpointId {
    #[serde(rename = "Hx")]
    Hx,
    #[serde(rename = "Ha")]
    Ha,
}

impl Stage4NativeEndpointId {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hx => "Hx",
            Self::Ha => "Ha",
        }
    }

    pub const fn architecture(self) -> &'static str {
        match self {
            Self::Hx => "x86_64",
            Self::Ha => "aarch64",
        }
    }

    pub const fn target_triple(self) -> &'static str {
        match self {
            Self::Hx => "x86_64-unknown-linux-gnu",
            Self::Ha => "aarch64-unknown-linux-gnu",
        }
    }

    pub const fn host_id(self) -> Stage4NativeHostId {
        match self {
            Self::Hx => Stage4NativeHostId::HxHost,
            Self::Ha => Stage4NativeHostId::HaHost,
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
}

pub const STAGE4_NATIVE_ENDPOINT_CATALOG: &[Stage4NativeEndpointId] =
    &[Stage4NativeEndpointId::Hx, Stage4NativeEndpointId::Ha];

pub fn required_stage4_native_provider_backend_target() -> Stage4TargetIdentity {
    Stage4TargetIdentity {
        target_triple: Stage4NativeEndpointId::Hx.target_triple().to_owned(),
        architecture: Stage4NativeEndpointId::Hx.architecture().to_owned(),
        os: "linux".to_owned(),
        abi: "linux-gnu".to_owned(),
        endianness: "little".to_owned(),
        pointer_width_bits: 64,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Stage4NativeHostId {
    #[serde(rename = "Hx-host")]
    HxHost,
    #[serde(rename = "Ha-host")]
    HaHost,
}

impl Stage4NativeHostId {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HxHost => "Hx",
            Self::HaHost => "Ha",
        }
    }

    pub fn receipt_uri(self) -> String {
        format!("hosts/{}/host-receipt.json", self.as_str())
    }

    pub fn observation_uri(self) -> String {
        format!("hosts/{}/host-observation.stdout.json", self.as_str())
    }

    pub fn uname_stdout_uri(self) -> String {
        format!("hosts/{}/uname.stdout.txt", self.as_str())
    }

    pub fn uname_stderr_uri(self) -> String {
        format!("hosts/{}/uname.stderr.log", self.as_str())
    }

    pub fn virtualization_stdout_uri(self) -> String {
        format!("hosts/{}/virtualization.stdout.txt", self.as_str())
    }

    pub fn virtualization_stderr_uri(self) -> String {
        format!("hosts/{}/virtualization.stderr.log", self.as_str())
    }

    pub fn hardware_model_uri(self) -> String {
        format!("hosts/{}/hardware-model.raw", self.as_str())
    }
}

pub const STAGE4_NATIVE_HOST_CATALOG: &[Stage4NativeHostId] =
    &[Stage4NativeHostId::HxHost, Stage4NativeHostId::HaHost];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage4NativeCellId {
    HxToHx,
    HxToHa,
    HaToHx,
    HaToHa,
}

impl Stage4NativeCellId {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HxToHx => "hx-to-hx",
            Self::HxToHa => "hx-to-ha",
            Self::HaToHx => "ha-to-hx",
            Self::HaToHa => "ha-to-ha",
        }
    }

    pub const fn endpoints(self) -> (Stage4NativeEndpointId, Stage4NativeEndpointId) {
        match self {
            Self::HxToHx => (Stage4NativeEndpointId::Hx, Stage4NativeEndpointId::Hx),
            Self::HxToHa => (Stage4NativeEndpointId::Hx, Stage4NativeEndpointId::Ha),
            Self::HaToHx => (Stage4NativeEndpointId::Ha, Stage4NativeEndpointId::Hx),
            Self::HaToHa => (Stage4NativeEndpointId::Ha, Stage4NativeEndpointId::Ha),
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

    pub fn hello_stdout_uri(self, role: crate::Stage4Role) -> String {
        format!("{}/hello/{}.stdout.json", self.cell_root_uri(), role.as_str())
    }

    pub fn hello_stderr_uri(self, role: crate::Stage4Role) -> String {
        format!("{}/hello/{}.stderr.log", self.cell_root_uri(), role.as_str())
    }
}

pub const STAGE4_NATIVE_CELL_CATALOG: &[Stage4NativeCellId] = &[
    Stage4NativeCellId::HxToHx,
    Stage4NativeCellId::HxToHa,
    Stage4NativeCellId::HaToHx,
    Stage4NativeCellId::HaToHa,
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4NativeCommandReceipt {
    pub program: String,
    pub program_sha256: String,
    pub program_size: u64,
    pub argv: Vec<String>,
    pub exit_status: i32,
    pub raw_stdout: Stage4ArtifactReference,
    pub raw_stderr: Stage4ArtifactReference,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4NativeHardwareModelObservation {
    pub source_path: String,
    pub model: String,
    pub raw: Stage4ArtifactReference,
}

/// One challenge-bound line emitted by the worker on the observed host. The
/// controller retains this line and separately retains the command/file bytes
/// represented by the typed publication receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4NativeRawHostObservation {
    pub schema_version: String,
    pub nonce: String,
    pub host_id: Stage4NativeHostId,
    pub identity: Stage4HostIdentity,
    pub uname_program_sha256: String,
    pub uname_program_size: u64,
    pub uname_argv: Vec<String>,
    pub uname_exit_status: i32,
    pub uname_stdout: String,
    pub uname_stderr: String,
    pub virtualization_program_sha256: String,
    pub virtualization_program_size: u64,
    pub virtualization_argv: Vec<String>,
    pub virtualization_exit_status: i32,
    pub virtualization_stdout: String,
    pub virtualization_stderr: String,
    pub hardware_model_source_path: Option<String>,
    pub hardware_model: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4NativeHostReceipt {
    pub schema_version: String,
    pub host_id: Stage4NativeHostId,
    pub expected_nonce: String,
    pub raw_observation: Stage4ArtifactReference,
    pub identity: Stage4HostIdentity,
    pub uname: Stage4NativeCommandReceipt,
    pub virtualization: Stage4NativeCommandReceipt,
    pub hardware_model: Option<Stage4NativeHardwareModelObservation>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4NativeHostEvidence {
    pub host_id: Stage4NativeHostId,
    pub receipt_artifact: Stage4ArtifactReference,
    pub receipt: Stage4NativeHostReceipt,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4NativeBuildReceipt {
    pub schema_version: String,
    pub endpoint_id: Stage4NativeEndpointId,
    pub target: Stage4TargetIdentity,
    pub executable_sha256: String,
    pub executable_size: u64,
    pub build_source_sha256: String,
    pub build_toolchain_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Stage4NativeLauncherTransport {
    LocalDirect {
        argv: Vec<String>,
    },
    Ssh {
        ssh_program: Stage4ArtifactReference,
        known_hosts: Stage4ArtifactReference,
        remote_host: String,
        remote_worker_path: String,
        argv: Vec<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4NativeLauncherReceipt {
    pub schema_version: String,
    pub endpoint_id: Stage4NativeEndpointId,
    pub host_id: Stage4NativeHostId,
    pub worker_sha256: String,
    pub worker_size: u64,
    pub native_execution: bool,
    pub emulated_execution: bool,
    pub transport: Stage4NativeLauncherTransport,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4NativeEndpointEvidence {
    pub endpoint_id: Stage4NativeEndpointId,
    pub host_id: Stage4NativeHostId,
    pub target: Stage4TargetIdentity,
    pub worker_executable: Stage4ArtifactReference,
    pub build_receipt_artifact: Stage4ArtifactReference,
    pub build_receipt: Stage4NativeBuildReceipt,
    pub launcher_receipt_artifact: Stage4ArtifactReference,
    pub launcher_receipt: Stage4NativeLauncherReceipt,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Stage4NativeProviderHaTransport {
    SshReverseStreamLocal { remote_socket_path: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Stage4NativeProviderTransport {
    UnixStream { local_socket_path: String, ha_transport: Stage4NativeProviderHaTransport },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4NativeProviderRuntimeExecution {
    pub hx_native: bool,
    pub ha_native: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4NativeProviderCaseDomain {
    pub cell_id: Stage4NativeCellId,
    pub case_id: String,
    pub source_endpoint: Stage4NativeEndpointId,
    pub destination_endpoint: Stage4NativeEndpointId,
    /// One identifier names the transaction domain used by both role endpoints.
    pub logical_database_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4NativeProviderReceipt {
    pub schema_version: String,
    pub provider_host: Stage4NativeHostId,
    pub backend_identity: String,
    pub backend_target: Stage4TargetIdentity,
    pub service_executable: Stage4ArtifactReference,
    pub service_executable_sha256: String,
    pub service_executable_size: u64,
    pub transport: Stage4NativeProviderTransport,
    pub runtime_execution: Stage4NativeProviderRuntimeExecution,
    pub case_domains: Vec<Stage4NativeProviderCaseDomain>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4NativeProviderEvidence {
    pub receipt_artifact: Stage4ArtifactReference,
    pub receipt: Stage4NativeProviderReceipt,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4NativePublicationCell {
    pub cell_id: Stage4NativeCellId,
    pub source_endpoint: Stage4NativeEndpointId,
    pub destination_endpoint: Stage4NativeEndpointId,
    pub stage1_bundle: Stage4ArtifactReference,
    pub source_hello: Stage4TargetHelloObservation,
    pub destination_hello: Stage4TargetHelloObservation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4NativeCellEvidence {
    pub cell_id: Stage4NativeCellId,
    pub source_endpoint: Stage4NativeEndpointId,
    pub destination_endpoint: Stage4NativeEndpointId,
    pub stage1_bundle: Stage4ArtifactReference,
    pub normalized_observable_trace: Stage4ArtifactReference,
    pub source_hello: Stage4TargetHelloObservation,
    pub destination_hello: Stage4TargetHelloObservation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage4NativeClaimBoundary {
    Proven,
    NotClaimed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4NativeClaimGuards {
    pub real_aarch64_hardware: Stage4NativeClaimBoundary,
    pub native_cross_isa: Stage4NativeClaimBoundary,
    pub cross_host: Stage4NativeClaimBoundary,
    pub shared_provider_transaction_domain: Stage4NativeClaimBoundary,
    pub provider_substrate_cross_isa: Stage4NativeClaimBoundary,
    pub provider_migration: Stage4NativeClaimBoundary,
    pub second_runtime: Stage4NativeClaimBoundary,
    pub aot_binary_portability: Stage4NativeClaimBoundary,
    pub stage3_resources_cross_isa: Stage4NativeClaimBoundary,
    pub hostile_host_or_transport: Stage4NativeClaimBoundary,
    pub production_or_performance: Stage4NativeClaimBoundary,
}

impl Stage4NativeClaimGuards {
    pub const fn required() -> Self {
        Self {
            real_aarch64_hardware: Stage4NativeClaimBoundary::Proven,
            native_cross_isa: Stage4NativeClaimBoundary::Proven,
            cross_host: Stage4NativeClaimBoundary::Proven,
            shared_provider_transaction_domain: Stage4NativeClaimBoundary::Proven,
            provider_substrate_cross_isa: Stage4NativeClaimBoundary::NotClaimed,
            provider_migration: Stage4NativeClaimBoundary::NotClaimed,
            second_runtime: Stage4NativeClaimBoundary::NotClaimed,
            aot_binary_portability: Stage4NativeClaimBoundary::NotClaimed,
            stage3_resources_cross_isa: Stage4NativeClaimBoundary::NotClaimed,
            hostile_host_or_transport: Stage4NativeClaimBoundary::NotClaimed,
            production_or_performance: Stage4NativeClaimBoundary::NotClaimed,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4NativeClaimDefinition {
    pub claim_id: String,
    pub required_cells: Vec<Stage4NativeCellId>,
}

pub fn required_stage4_native_claim() -> Stage4NativeClaimDefinition {
    Stage4NativeClaimDefinition {
        claim_id: STAGE4_NATIVE_CLAIM_ID.to_owned(),
        required_cells: STAGE4_NATIVE_CELL_CATALOG.to_vec(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4NativeMatrixManifest {
    pub schema_version: String,
    pub common_input: Stage4ArtifactReference,
    pub execution_artifact_root: String,
    pub registry_sha256: String,
    pub hosts: Vec<Stage4NativeHostEvidence>,
    pub endpoints: Vec<Stage4NativeEndpointEvidence>,
    pub provider: Stage4NativeProviderEvidence,
    pub claim: Stage4NativeClaimDefinition,
    pub claim_guards: Stage4NativeClaimGuards,
    pub cells: Vec<Stage4NativeCellEvidence>,
    pub execution_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4NativeInnerVerification {
    pub cell_id: Stage4NativeCellId,
    pub stage1_bundle_id: String,
    pub stage1_bundle_sha256: String,
    pub case_count: usize,
    pub independently_verified: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4NativeCaseComparison {
    pub case_id: String,
    pub normalized_case_sha256: String,
    pub equal_across_all_cells: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4NativeEvidenceBundle {
    pub schema_version: String,
    pub bundle_id: String,
    pub matrix_manifest: Stage4ArtifactReference,
    pub completed_execution_count: usize,
    pub inner_verifications: Vec<Stage4NativeInnerVerification>,
    pub case_comparisons: Vec<Stage4NativeCaseComparison>,
    pub claim: Stage4NativeClaimDefinition,
    pub claim_guards: Stage4NativeClaimGuards,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage4NativePublicationInput {
    pub hosts: Vec<Stage4NativeHostEvidence>,
    pub endpoints: Vec<Stage4NativeEndpointEvidence>,
    pub provider: Stage4NativeProviderEvidence,
    pub cells: Vec<Stage4NativePublicationCell>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stage4NativeValidationFinding {
    pub code: String,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stage4NativeValidationReport {
    pub ok: bool,
    pub findings: Vec<Stage4NativeValidationFinding>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stage4NativeEvidenceLoadError {
    pub code: String,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stage4NativeEvidenceGateResult {
    pub ok: bool,
    pub load_error: Option<Stage4NativeEvidenceLoadError>,
    pub validation: Option<Stage4NativeValidationReport>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stage4NativeWriteResult {
    pub bundle_path: String,
    pub matrix_path: String,
    pub completed_execution_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stage4NativeWriteError {
    pub code: String,
    pub detail: String,
}

impl std::fmt::Display for Stage4NativeWriteError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for Stage4NativeWriteError {}

#[allow(dead_code)]
fn _common_input_type_lock(_: &Stage4CommonInputIdentity) {}
