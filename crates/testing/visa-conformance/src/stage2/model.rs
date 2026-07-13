use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

use crate::{Stage1CaseClass, Stage1CaseOutcome, Stage1FaultSchedule, Stage1VersionedIdentity};

pub const STAGE2_COMMON_INPUT_SCHEMA_VERSION: &str = "visa-stage2-common-input-v1";
pub const STAGE2_MATRIX_MANIFEST_SCHEMA_VERSION: &str = "visa-stage2-matrix-manifest-v2";
pub const STAGE2_EVIDENCE_SCHEMA_VERSION: &str = "visa-stage2-evidence-v2";
pub const STAGE2_CLAIM_ID: &str = "cross-execution-path-portability";
pub const STAGE2_COMMON_INPUT_FILE: &str = "stage2-common-input.json";
pub const STAGE2_MATRIX_MANIFEST_FILE: &str = "stage2-matrix-manifest.json";
pub const STAGE2_EVIDENCE_FILE: &str = "stage2-evidence.json";
pub const STAGE2_INCOMPLETE_MARKER_FILE: &str = "stage2-incomplete";
pub const STAGE2_EXECUTION_COUNT: usize = 124;
pub const STAGE2_STRICT_CLAIM_ID: &str = "strict-cross-runtime-continuity";
pub const STAGE2_COMPONENT_STATE_CODEC_NAME: &str = "VISACS01";
pub const STAGE2_COMPONENT_STATE_CODEC_VERSION: &str = "visa-component-state-v1";
pub const STAGE2_INSTANTIATION_OBSERVATIONS_SCHEMA_VERSION: &str =
    "visa-stage2-instantiation-observations-v1";
pub const STAGE2_AUTHORITY_POLICY_INPUT_SCHEMA_VERSION: &str =
    "visa-stage2-authority-policy-input-v1";
pub const STAGE2_AUTHORITY_POLICY_CANONICAL_ENCODING: &str = "postcard-1.1.3";
pub const STAGE2_JCO_VERSION: &str = "1.25.2";
pub const STAGE2_JS_COMPONENT_BINDGEN_VERSION: &str = "2.0.11";
pub const STAGE2_COMPONENT_TRANSLATOR_VERSION: &str = "45.0.1";
pub const STAGE2_JCO_TRANSLATION_OPTIONS: &str = concat!(
    "{\"schema\":\"visa-jco-node-transpile-options-v1\",",
    "\"name\":\"handoff-component.component\",",
    "\"no_typescript\":true,\"instantiation_mode\":\"sync\",",
    "\"import_bindings\":\"js\",\"nodejs_compat_disabled\":false,",
    "\"base64_cutoff\":0,\"tla_compat\":false,",
    "\"valid_lifting_optimization\":false,\"tracing\":false,",
    "\"no_namespaced_exports\":true,\"multi_memory\":false,",
    "\"guest\":false,\"strict\":true,\"asmjs\":false}"
);
pub const STAGE2_NODE_VERSION: &str = "24.15.0";
pub const STAGE2_V8_VERSION: &str = "13.6.233.17-node.48";
pub const STAGE2_JCO_NODE_RPC_PROTOCOL_VERSION: u32 = 3;
pub const STAGE2_JCO_NODE_EXECUTION_CARRIER: &str = crate::JCO_NODE_EXECUTION_CARRIER;
pub const STAGE2_ACCEPTED_REGISTRY_SHA256: &str =
    "95e05af67ff122ca4be0a94823340bcf5ad368f05be8946ca0a26a47816ecfd9";
pub const STAGE2_WIT_WORLD_NAME: &str = "visa:continuity/cooperative-handoff@0.1.0";
pub const STAGE2_WIT_WORLD_SHA256: &str =
    "709eb08784d446068bbaed47dbfb1dddd637f957cf5de1f3713d5be0aa7d5920";
pub const STAGE2_WASMTIME_ENVIRONMENT_NAME: &str = "visa_wasmtime adapter with wasmtime";
pub const STAGE2_WASMTIME_ENVIRONMENT_VERSION: &str = "0.2.0+wasmtime.43.0.2";
pub const STAGE2_JCO_NODE_ENVIRONMENT_NAME: &str =
    "visa_jco_node+jco+js-component-bindgen adapter with node+v8";
pub const STAGE2_JCO_NODE_ENVIRONMENT_VERSION: &str =
    "0.2.0/jco-1.25.2/bindgen-2.0.11/translator-45.0.1+node+v8.24.15.0/v8-13.6.233.17-node.48";
pub const STAGE2_WASMTIME_IMPLEMENTATION_VERSION: &str = "0.2.0";
pub const STAGE2_WASMTIME_ENGINE_VERSION: &str = "43.0.2";
pub const STAGE2_JCO_NODE_IMPLEMENTATION_VERSION: &str =
    "0.2.0/jco-1.25.2/bindgen-2.0.11/translator-45.0.1";
pub const STAGE2_WACOGO_ENVIRONMENT_NAME: &str =
    "visa_wacogo adapter with partite-ai/wacogo+wazero";
pub const STAGE2_WACOGO_IMPLEMENTATION_VERSION: &str = "0.1.0";
pub const STAGE2_WACOGO_ENGINE_VERSION: &str = concat!(
    "wacogo-v0.0.0-20260617023329-3de16a61796c+visa-patchset-v1/",
    "wazero-v1.11.1-0.20260418165552-5cb4bb3ec0c1"
);
pub const STAGE2_WACOGO_ENVIRONMENT_VERSION: &str = concat!(
    "0.1.0+partite-ai/wacogo+wazero.",
    "wacogo-v0.0.0-20260617023329-3de16a61796c+visa-patchset-v1/",
    "wazero-v1.11.1-0.20260418165552-5cb4bb3ec0c1"
);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage2Runtime {
    Wasmtime,
    JcoNode,
    Wacogo,
}

impl Stage2Runtime {
    pub const fn selector(self) -> &'static str {
        match self {
            Self::Wasmtime => "wasmtime",
            Self::JcoNode => "jco-node",
            Self::Wacogo => "wacogo",
        }
    }

    pub(super) const fn protocol_selector(self) -> &'static str {
        match self {
            Self::Wasmtime => "wasmtime",
            Self::JcoNode => "jco_node",
            Self::Wacogo => "wacogo",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage2ClaimSet {
    CrossExecutionPathPortability,
    StrictCrossRuntimeContinuity,
}

impl Stage2ClaimSet {
    pub const fn claim_id(self) -> &'static str {
        match self {
            Self::CrossExecutionPathPortability => STAGE2_CLAIM_ID,
            Self::StrictCrossRuntimeContinuity => STAGE2_STRICT_CLAIM_ID,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Stage2CellId(&'static str);

#[allow(non_upper_case_globals)]
impl Stage2CellId {
    pub const WasmtimeToWasmtime: Self = Self("wasmtime-to-wasmtime");
    pub const JcoNodeToJcoNode: Self = Self("jco-node-to-jco-node");
    pub const WasmtimeToJcoNode: Self = Self("wasmtime-to-jco-node");
    pub const JcoNodeToWasmtime: Self = Self("jco-node-to-wasmtime");
    pub const WacogoToWacogo: Self = Self("wacogo-to-wacogo");
    pub const WasmtimeToWacogo: Self = Self("wasmtime-to-wacogo");
    pub const WacogoToWasmtime: Self = Self("wacogo-to-wasmtime");

    pub const fn as_str(self) -> &'static str {
        self.0
    }

    pub fn cell_root(self, stage2_root: &Path) -> PathBuf {
        stage2_root.join("cells").join(self.as_str())
    }

    pub fn stage1_bundle_uri(self) -> String {
        format!("cells/{}/stage1-evidence.json", self.as_str())
    }

    pub fn normalized_uri(self) -> String {
        format!("normalized/{}.json", self.as_str())
    }
}

impl Serialize for Stage2CellId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0)
    }
}

impl<'de> Deserialize<'de> for Stage2CellId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        STAGE2_CELL_CATALOG
            .iter()
            .find(|descriptor| descriptor.id.as_str() == value)
            .map(|descriptor| descriptor.id)
            .ok_or_else(|| D::Error::custom(format!("unknown Stage 2 cell ID {value:?}")))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stage2CellDescriptor {
    pub id: Stage2CellId,
    pub source_runtime: Stage2Runtime,
    pub destination_runtime: Stage2Runtime,
    pub claim_sets: &'static [Stage2ClaimSet],
}

const EXECUTION_AND_STRICT_CLAIMS: &[Stage2ClaimSet] =
    &[Stage2ClaimSet::CrossExecutionPathPortability, Stage2ClaimSet::StrictCrossRuntimeContinuity];
const EXECUTION_CLAIM: &[Stage2ClaimSet] = &[Stage2ClaimSet::CrossExecutionPathPortability];

pub const STAGE2_CELL_CATALOG: &[Stage2CellDescriptor] = &[
    Stage2CellDescriptor {
        id: Stage2CellId::WasmtimeToWasmtime,
        source_runtime: Stage2Runtime::Wasmtime,
        destination_runtime: Stage2Runtime::Wasmtime,
        claim_sets: EXECUTION_AND_STRICT_CLAIMS,
    },
    Stage2CellDescriptor {
        id: Stage2CellId::JcoNodeToJcoNode,
        source_runtime: Stage2Runtime::JcoNode,
        destination_runtime: Stage2Runtime::JcoNode,
        claim_sets: EXECUTION_CLAIM,
    },
    Stage2CellDescriptor {
        id: Stage2CellId::WasmtimeToJcoNode,
        source_runtime: Stage2Runtime::Wasmtime,
        destination_runtime: Stage2Runtime::JcoNode,
        claim_sets: EXECUTION_CLAIM,
    },
    Stage2CellDescriptor {
        id: Stage2CellId::JcoNodeToWasmtime,
        source_runtime: Stage2Runtime::JcoNode,
        destination_runtime: Stage2Runtime::Wasmtime,
        claim_sets: EXECUTION_CLAIM,
    },
    Stage2CellDescriptor {
        id: Stage2CellId::WacogoToWacogo,
        source_runtime: Stage2Runtime::Wacogo,
        destination_runtime: Stage2Runtime::Wacogo,
        claim_sets: &[Stage2ClaimSet::StrictCrossRuntimeContinuity],
    },
    Stage2CellDescriptor {
        id: Stage2CellId::WasmtimeToWacogo,
        source_runtime: Stage2Runtime::Wasmtime,
        destination_runtime: Stage2Runtime::Wacogo,
        claim_sets: &[Stage2ClaimSet::StrictCrossRuntimeContinuity],
    },
    Stage2CellDescriptor {
        id: Stage2CellId::WacogoToWasmtime,
        source_runtime: Stage2Runtime::Wacogo,
        destination_runtime: Stage2Runtime::Wasmtime,
        claim_sets: &[Stage2ClaimSet::StrictCrossRuntimeContinuity],
    },
];

pub fn stage2_cell_descriptor(id: Stage2CellId) -> Option<&'static Stage2CellDescriptor> {
    STAGE2_CELL_CATALOG.iter().find(|descriptor| descriptor.id == id)
}

pub fn stage2_cell_descriptors(
    claim_set: Stage2ClaimSet,
) -> impl Clone + Iterator<Item = &'static Stage2CellDescriptor> {
    STAGE2_CELL_CATALOG.iter().filter(move |descriptor| descriptor.claim_sets.contains(&claim_set))
}

pub fn stage2_cell_ids_match_claim(
    ids: impl IntoIterator<Item = Stage2CellId>,
    claim_set: Stage2ClaimSet,
) -> bool {
    ids.into_iter().eq(stage2_cell_descriptors(claim_set).map(|descriptor| descriptor.id))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2ArtifactReference {
    pub uri: String,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2CommonInputManifest {
    pub schema_version: String,
    pub original_component: Stage2ArtifactReference,
    pub wit_world: Stage2WitWorldInput,
    pub profile: Stage2ArtifactReference,
    pub profile_sha256: String,
    pub configuration: Stage2ArtifactReference,
    pub config_sha256: String,
    pub authority_policy: Stage2ArtifactReference,
    pub authority_policy_sha256: String,
    pub component_state_codec: Stage1VersionedIdentity,
    pub stage1_evidence_schema_version: String,
    pub stage1_semantic_trace_schema_version: String,
    pub cases: Vec<Stage2CommonCaseInput>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2WitWorldInput {
    pub world_name: String,
    pub artifact: Stage2ArtifactReference,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2CommonCaseInput {
    pub case_id: String,
    pub class: Stage1CaseClass,
    pub allowed_outcomes: Vec<Stage1CaseOutcome>,
    pub case_config_sha256: String,
    pub case_policy_sha256: String,
    pub fault_schedule: Stage1FaultSchedule,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2AuthorityPolicyInput {
    pub schema_version: String,
    pub canonical_encoding: String,
    pub cases: Vec<Stage2AuthorityPolicyCaseInput>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2AuthorityPolicyCaseInput {
    pub case_id: String,
    pub policy_sha256: String,
    pub canonical_policy_bytes_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2CellManifest {
    pub cell_id: Stage2CellId,
    pub requested_source: Stage2Runtime,
    pub requested_destination: Stage2Runtime,
    pub observed_source: Stage1VersionedIdentity,
    pub observed_destination: Stage1VersionedIdentity,
    pub source_translation_provenance: Option<Stage2TranslationProvenance>,
    pub destination_translation_provenance: Option<Stage2TranslationProvenance>,
    pub instantiation_observations: Stage2InstantiationObservations,
    pub stage1_bundle: Stage2ArtifactReference,
    pub normalized_observable_trace: Stage2ArtifactReference,
    pub case_count: usize,
    pub no_fallback_observed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Activation facts for each top-level canonical case execution.
///
/// Auxiliary replay, audit, recovery, and fault-injection workers remain part of the raw
/// transcript audit, but their local state views do not redefine the primary case lifecycle.
pub struct Stage2InstantiationObservations {
    pub schema_version: String,
    pub cases: Vec<Stage2CaseInstantiationObservation>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2CaseInstantiationObservation {
    pub case_id: String,
    pub source: Stage2InstantiationObservation,
    pub destination: Stage2InstantiationObservation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Stage2InstantiationObservation {
    Live {
        boundary: Stage2LiveInstantiationBoundary,
    },
    NotInstantiatedByCaseDesign {
        boundary: Stage2NotInstantiatedBoundary,
        reason: Stage2NotInstantiatedReason,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage2LiveInstantiationBoundary {
    BootstrapSource,
    PostCommitResume,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage2NotInstantiatedBoundary {
    BeforeCommit,
    AfterCommitBeforeResume,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage2NotInstantiatedReason {
    SourceRetained,
    RecoveryRequired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2TranslationProvenance {
    pub jco_version: String,
    pub js_component_bindgen_version: String,
    pub translator: String,
    pub translator_version: String,
    pub translation_options: String,
    pub node_executable_path: String,
    pub node_executable_sha256: String,
    pub node_version: String,
    pub v8_version: String,
    pub rpc_protocol_version: u32,
    pub execution_carrier: String,
    pub generated_sha256: String,
    pub driver_sha256: String,
    pub core_module_sha256s: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage2Claim {
    CrossExecutionPathPortability,
    StrictCrossRuntimeContinuity,
    IndependentComponentModelRuntimes,
    CrossRuntimePortabilityUnderCurrentRoadmap,
    CrossIsaPortability,
    TransparentLiveMigration,
    ProductionReadiness,
    Performance,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage2ClaimBoundary {
    NotProven,
    NotClaimed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2ClaimGuards {
    pub strict_component_model_runtime_independence: Stage2ClaimBoundary,
    pub cross_runtime_portability_under_current_roadmap: Stage2ClaimBoundary,
    pub cross_isa_portability: Stage2ClaimBoundary,
    pub transparent_live_migration: Stage2ClaimBoundary,
    pub production_readiness: Stage2ClaimBoundary,
    pub performance: Stage2ClaimBoundary,
}

impl Stage2ClaimGuards {
    pub const fn required() -> Self {
        Self {
            strict_component_model_runtime_independence: Stage2ClaimBoundary::NotProven,
            cross_runtime_portability_under_current_roadmap: Stage2ClaimBoundary::NotClaimed,
            cross_isa_portability: Stage2ClaimBoundary::NotClaimed,
            transparent_live_migration: Stage2ClaimBoundary::NotClaimed,
            production_readiness: Stage2ClaimBoundary::NotClaimed,
            performance: Stage2ClaimBoundary::NotClaimed,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2MatrixManifest {
    pub schema_version: String,
    pub common_input: Stage2ArtifactReference,
    pub registry_sha256: String,
    pub cells: Vec<Stage2CellManifest>,
    pub execution_count: usize,
    pub claims: Vec<Stage2Claim>,
    pub claim_guards: Stage2ClaimGuards,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2InnerVerification {
    pub cell_id: Stage2CellId,
    pub stage1_bundle_id: String,
    pub stage1_bundle_sha256: String,
    pub case_count: usize,
    pub independently_verified: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2CaseComparison {
    pub case_id: String,
    pub normalized_case_sha256: String,
    pub equal_across_all_cells: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2EvidenceBundle {
    pub schema_version: String,
    pub bundle_id: String,
    pub matrix_manifest: Stage2ArtifactReference,
    pub completed_execution_count: usize,
    pub inner_verifications: Vec<Stage2InnerVerification>,
    pub case_comparisons: Vec<Stage2CaseComparison>,
    pub claims: Vec<Stage2Claim>,
    pub claim_guards: Stage2ClaimGuards,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2ValidationFinding {
    pub code: String,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2ValidationReport {
    pub ok: bool,
    pub findings: Vec<Stage2ValidationFinding>,
}

impl Stage2ValidationReport {
    pub(super) fn new(findings: Vec<Stage2ValidationFinding>) -> Self {
        Self { ok: findings.is_empty(), findings }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2EvidenceLoadError {
    pub code: String,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2EvidenceGateResult {
    pub ok: bool,
    pub load_error: Option<Stage2EvidenceLoadError>,
    pub validation: Option<Stage2ValidationReport>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stage2WriteResult {
    pub evidence_path: PathBuf,
    pub manifest_path: PathBuf,
    pub bundle_id: String,
    pub bundle_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stage2WriteError {
    pub code: String,
    pub detail: String,
}

impl std::fmt::Display for Stage2WriteError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for Stage2WriteError {}
