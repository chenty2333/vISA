use serde::{Deserialize, Serialize};

use super::model::{
    Stage2ArtifactReference, Stage2CaseComparison, Stage2CellId, Stage2InnerVerification,
    Stage2InstantiationObservations, Stage2MatrixManifest, Stage2Runtime,
    Stage2TranslationProvenance,
};
use crate::{Stage1ResourceKind, Stage1VersionedIdentity, Stage2Claim, Stage2EvidenceBundle};

pub const STAGE2_STRICT_MATRIX_MANIFEST_SCHEMA_VERSION: &str = "visa-stage2-matrix-manifest-v3";
pub const STAGE2_STRICT_EVIDENCE_SCHEMA_VERSION: &str = "visa-stage2-evidence-v3";
pub const STAGE2_STRICT_COMPONENT_BYTE_LENGTH: usize = 146_486;
pub const STAGE2_STRICT_COMPONENT_SHA256: &str =
    "4d8c99fbe7475aa02983592f55a8cfdc4260753aec75de74e18a19ec47813e3b";
pub const STAGE2_STRICT_CASE_COUNT: usize = 31;
pub const STAGE2_STRICT_CELL_COUNT: usize = 4;
pub const STAGE2_STRICT_EXECUTION_COUNT: usize =
    STAGE2_STRICT_CASE_COUNT * STAGE2_STRICT_CELL_COUNT;

/// The only target operating system covered by the strict v3 claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage2StrictOperatingSystem {
    Linux,
}

/// The only target architecture covered by the strict v3 claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage2StrictArchitecture {
    X86_64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2StrictContentIdentity {
    pub byte_length: usize,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2StrictWitWorldIdentity {
    pub world_name: String,
    pub sha256: String,
}

/// Exact, intentionally narrow scope of the Strict Stage 2 claim.
///
/// The booleans are present in the document so that a retained bundle cannot
/// silently imply either cross-ISA support or Stage 3 resources. The strict
/// verifier compares the complete value with [`Self::required`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2StrictScope {
    pub operating_system: Stage2StrictOperatingSystem,
    pub architecture: Stage2StrictArchitecture,
    pub component: Stage2StrictContentIdentity,
    pub wit_world: Stage2StrictWitWorldIdentity,
    pub external_resources: Vec<Stage1ResourceKind>,
    pub case_count: usize,
    pub cross_isa: bool,
    pub extra_external_resources: bool,
}

impl Stage2StrictScope {
    pub fn required() -> Self {
        Self {
            operating_system: Stage2StrictOperatingSystem::Linux,
            architecture: Stage2StrictArchitecture::X86_64,
            component: Stage2StrictContentIdentity {
                byte_length: STAGE2_STRICT_COMPONENT_BYTE_LENGTH,
                sha256: STAGE2_STRICT_COMPONENT_SHA256.to_owned(),
            },
            wit_world: Stage2StrictWitWorldIdentity {
                world_name: super::model::STAGE2_WIT_WORLD_NAME.to_owned(),
                sha256: super::model::STAGE2_WIT_WORLD_SHA256.to_owned(),
            },
            external_resources: vec![
                Stage1ResourceKind::PausedDurationTimer,
                Stage1ResourceKind::DurableKeyValue,
            ],
            case_count: STAGE2_STRICT_CASE_COUNT,
            cross_isa: false,
            extra_external_resources: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage2StrictClaimBoundary {
    Proven,
    NotClaimed,
}

/// Claim boundaries for v3 strict evidence, separate from the unchanged v2
/// guards whose runtime-independence boundary remains `not-proven`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2StrictClaimGuards {
    pub strict_cross_runtime_continuity: Stage2StrictClaimBoundary,
    pub strict_component_model_runtime_independence: Stage2StrictClaimBoundary,
    pub cross_runtime_portability_under_current_roadmap: Stage2StrictClaimBoundary,
    pub cross_isa_portability: Stage2StrictClaimBoundary,
    pub extra_external_resources: Stage2StrictClaimBoundary,
    pub transparent_live_migration: Stage2StrictClaimBoundary,
    pub production_readiness: Stage2StrictClaimBoundary,
    pub performance: Stage2StrictClaimBoundary,
}

impl Stage2StrictClaimGuards {
    pub const fn required() -> Self {
        Self {
            strict_cross_runtime_continuity: Stage2StrictClaimBoundary::Proven,
            strict_component_model_runtime_independence: Stage2StrictClaimBoundary::Proven,
            cross_runtime_portability_under_current_roadmap: Stage2StrictClaimBoundary::NotClaimed,
            cross_isa_portability: Stage2StrictClaimBoundary::NotClaimed,
            extra_external_resources: Stage2StrictClaimBoundary::NotClaimed,
            transparent_live_migration: Stage2StrictClaimBoundary::NotClaimed,
            production_readiness: Stage2StrictClaimBoundary::NotClaimed,
            performance: Stage2StrictClaimBoundary::NotClaimed,
        }
    }
}

/// Wacogo facts emitted at prepared/live observation boundaries. The same
/// shape is retained in the manifest lineage, permitting exact field-by-field
/// comparison without importing a worker-protocol type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2WacogoRuntimeLineageObservation {
    pub source_lock_schema: String,
    pub source_lock_sha256: String,
    pub derivative_id: String,
    pub upstream_module: String,
    pub upstream_version: String,
    pub upstream_revision: String,
    pub upstream_module_sum: String,
    pub upstream_is_qualified_without_patches: bool,
    pub patchset_id: String,
    pub patchset_sha256: String,
    pub patch_sha256s: Vec<String>,
    pub patched_tree_sha256: String,
    pub sidecar_executable_sha256: String,
    pub sidecar_executable_size: u64,
    pub sidecar_protocol_version: u32,
    pub execution_carrier: String,
    pub wacogo_version: String,
    pub wacogo_revision: String,
    pub wazero_version: String,
    pub go_version: String,
    pub target: String,
    pub main_module: String,
}

/// Public projection of runtime identity and provenance used by strict outer
/// evidence. Its first four fields mirror the shared adapter identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2StrictRuntimeMetadata {
    pub implementation: String,
    pub implementation_version: String,
    pub engine: String,
    pub engine_version: String,
    pub translation_provenance: Option<Stage2TranslationProvenance>,
    pub implementation_lineage: Option<Stage2WacogoRuntimeLineageObservation>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2ComponentModelImplementationLineage {
    pub parser: Stage1VersionedIdentity,
    pub canonical_abi: Stage1VersionedIdentity,
    pub instantiation: Stage1VersionedIdentity,
    pub execution: Stage1VersionedIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "runtime", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Stage2StrictRuntimeLineage {
    Wasmtime {
        expected_metadata: Stage2StrictRuntimeMetadata,
        component_model: Stage2ComponentModelImplementationLineage,
        dependency_lock: Stage2ArtifactReference,
    },
    Wacogo {
        expected_metadata: Stage2StrictRuntimeMetadata,
        component_model: Stage2ComponentModelImplementationLineage,
        source_lock: Stage2ArtifactReference,
        build_receipt: Stage2ArtifactReference,
        sidecar: Stage2ArtifactReference,
    },
}

/// Compact requested -> prepared -> live identity chain for one cell role.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2StrictRuntimeIdentityChain {
    pub requested: Stage2Runtime,
    pub prepared: Stage2StrictRuntimeMetadata,
    pub prepared_observation_count: usize,
    pub live: Stage2StrictRuntimeMetadata,
    pub live_observation_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2StrictCellManifest {
    pub cell_id: Stage2CellId,
    pub source: Stage2StrictRuntimeIdentityChain,
    pub destination: Stage2StrictRuntimeIdentityChain,
    pub instantiation_observations: Stage2InstantiationObservations,
    pub stage1_bundle: Stage2ArtifactReference,
    pub normalized_observable_trace: Stage2ArtifactReference,
    pub case_count: usize,
    pub no_fallback_observed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2StrictMatrixManifest {
    pub schema_version: String,
    pub common_input: Stage2ArtifactReference,
    pub scope: Stage2StrictScope,
    pub registry_sha256: String,
    pub runtime_lineages: Vec<Stage2StrictRuntimeLineage>,
    pub cells: Vec<Stage2StrictCellManifest>,
    pub execution_count: usize,
    pub claims: Vec<Stage2Claim>,
    pub claim_guards: Stage2StrictClaimGuards,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2StrictEvidenceBundle {
    pub schema_version: String,
    pub bundle_id: String,
    pub matrix_manifest: Stage2ArtifactReference,
    pub completed_execution_count: usize,
    pub inner_verifications: Vec<Stage2InnerVerification>,
    pub case_comparisons: Vec<Stage2CaseComparison>,
    pub claims: Vec<Stage2Claim>,
    pub claim_guards: Stage2StrictClaimGuards,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage2MatrixManifestDocumentSchema {
    V2,
    StrictV3,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stage2MatrixManifestDocument {
    V2(Stage2MatrixManifest),
    StrictV3(Stage2StrictMatrixManifest),
}

impl Stage2MatrixManifestDocument {
    pub const fn schema(&self) -> Stage2MatrixManifestDocumentSchema {
        match self {
            Self::V2(_) => Stage2MatrixManifestDocumentSchema::V2,
            Self::StrictV3(_) => Stage2MatrixManifestDocumentSchema::StrictV3,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage2EvidenceDocumentSchema {
    V2,
    StrictV3,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stage2EvidenceDocument {
    V2(Stage2EvidenceBundle),
    StrictV3(Stage2StrictEvidenceBundle),
}

impl Stage2EvidenceDocument {
    pub const fn schema(&self) -> Stage2EvidenceDocumentSchema {
        match self {
            Self::V2(_) => Stage2EvidenceDocumentSchema::V2,
            Self::StrictV3(_) => Stage2EvidenceDocumentSchema::StrictV3,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stage2DocumentParseError {
    pub code: &'static str,
    pub detail: String,
}

impl std::fmt::Display for Stage2DocumentParseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for Stage2DocumentParseError {}

pub fn parse_stage2_matrix_manifest_document_json(
    bytes: &[u8],
) -> Result<Stage2MatrixManifestDocument, Stage2DocumentParseError> {
    let schema_version = document_schema_version(bytes, "matrix manifest")?;
    match schema_version.as_str() {
        super::model::STAGE2_MATRIX_MANIFEST_SCHEMA_VERSION => parse_document(bytes)
            .map(Stage2MatrixManifestDocument::V2)
            .map_err(|source| invalid_document("matrix manifest v2", source)),
        STAGE2_STRICT_MATRIX_MANIFEST_SCHEMA_VERSION => parse_document(bytes)
            .map(Stage2MatrixManifestDocument::StrictV3)
            .map_err(|source| invalid_document("strict matrix manifest v3", source)),
        other => Err(unknown_schema("matrix manifest", other)),
    }
}

pub fn parse_stage2_evidence_document_json(
    bytes: &[u8],
) -> Result<Stage2EvidenceDocument, Stage2DocumentParseError> {
    let schema_version = document_schema_version(bytes, "evidence")?;
    match schema_version.as_str() {
        super::model::STAGE2_EVIDENCE_SCHEMA_VERSION => parse_document(bytes)
            .map(Stage2EvidenceDocument::V2)
            .map_err(|source| invalid_document("evidence v2", source)),
        STAGE2_STRICT_EVIDENCE_SCHEMA_VERSION => parse_document(bytes)
            .map(Stage2EvidenceDocument::StrictV3)
            .map_err(|source| invalid_document("strict evidence v3", source)),
        other => Err(unknown_schema("evidence", other)),
    }
}

fn document_schema_version(bytes: &[u8], kind: &str) -> Result<String, Stage2DocumentParseError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|source| Stage2DocumentParseError {
            code: "invalid-stage2-document-json",
            detail: format!("invalid Stage 2 {kind} JSON: {source}"),
        })?;
    value.get("schema_version").and_then(serde_json::Value::as_str).map(str::to_owned).ok_or_else(
        || Stage2DocumentParseError {
            code: "missing-stage2-document-schema",
            detail: format!("Stage 2 {kind} must have a string schema_version discriminant"),
        },
    )
}

fn parse_document<T>(bytes: &[u8]) -> Result<T, serde_json::Error>
where
    T: for<'de> Deserialize<'de>,
{
    // Parse the original bytes again so duplicate fields are not hidden by the
    // temporary Value used solely to inspect the schema discriminant.
    serde_json::from_slice(bytes)
}

fn invalid_document(kind: &str, source: serde_json::Error) -> Stage2DocumentParseError {
    Stage2DocumentParseError {
        code: "invalid-stage2-versioned-document",
        detail: format!("invalid Stage 2 {kind}: {source}"),
    }
}

fn unknown_schema(kind: &str, schema: &str) -> Stage2DocumentParseError {
    Stage2DocumentParseError {
        code: "unknown-stage2-document-schema",
        detail: format!("unknown Stage 2 {kind} schema_version {schema:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Stage2ClaimBoundary, Stage2ClaimGuards};

    fn artifact(uri: &str) -> Stage2ArtifactReference {
        Stage2ArtifactReference { uri: uri.to_owned(), sha256: "a".repeat(64) }
    }

    fn v2_manifest() -> Stage2MatrixManifest {
        Stage2MatrixManifest {
            schema_version: super::super::model::STAGE2_MATRIX_MANIFEST_SCHEMA_VERSION.to_owned(),
            common_input: artifact("stage2-common-input.json"),
            registry_sha256: "b".repeat(64),
            cells: Vec::new(),
            execution_count: 0,
            claims: vec![Stage2Claim::CrossExecutionPathPortability],
            claim_guards: Stage2ClaimGuards::required(),
        }
    }

    fn strict_manifest() -> Stage2StrictMatrixManifest {
        Stage2StrictMatrixManifest {
            schema_version: STAGE2_STRICT_MATRIX_MANIFEST_SCHEMA_VERSION.to_owned(),
            common_input: artifact("stage2-common-input.json"),
            scope: Stage2StrictScope::required(),
            registry_sha256: "b".repeat(64),
            runtime_lineages: Vec::new(),
            cells: Vec::new(),
            execution_count: STAGE2_STRICT_EXECUTION_COUNT,
            claims: vec![Stage2Claim::StrictCrossRuntimeContinuity],
            claim_guards: Stage2StrictClaimGuards::required(),
        }
    }

    fn v2_evidence() -> Stage2EvidenceBundle {
        Stage2EvidenceBundle {
            schema_version: super::super::model::STAGE2_EVIDENCE_SCHEMA_VERSION.to_owned(),
            bundle_id: "v2".to_owned(),
            matrix_manifest: artifact("stage2-matrix-manifest.json"),
            completed_execution_count: 0,
            inner_verifications: Vec::new(),
            case_comparisons: Vec::new(),
            claims: vec![Stage2Claim::CrossExecutionPathPortability],
            claim_guards: Stage2ClaimGuards::required(),
        }
    }

    fn strict_evidence() -> Stage2StrictEvidenceBundle {
        Stage2StrictEvidenceBundle {
            schema_version: STAGE2_STRICT_EVIDENCE_SCHEMA_VERSION.to_owned(),
            bundle_id: "strict-v3".to_owned(),
            matrix_manifest: artifact("stage2-matrix-manifest.json"),
            completed_execution_count: STAGE2_STRICT_EXECUTION_COUNT,
            inner_verifications: Vec::new(),
            case_comparisons: Vec::new(),
            claims: vec![Stage2Claim::StrictCrossRuntimeContinuity],
            claim_guards: Stage2StrictClaimGuards::required(),
        }
    }

    #[test]
    fn strict_scope_and_guards_are_exact_and_do_not_extend_stage2() {
        let scope = Stage2StrictScope::required();
        assert_eq!(scope.operating_system, Stage2StrictOperatingSystem::Linux);
        assert_eq!(scope.architecture, Stage2StrictArchitecture::X86_64);
        assert_eq!(scope.component.byte_length, 146_486);
        assert_eq!(scope.component.sha256, STAGE2_STRICT_COMPONENT_SHA256);
        assert_eq!(scope.wit_world.world_name, super::super::model::STAGE2_WIT_WORLD_NAME);
        assert_eq!(scope.wit_world.sha256, super::super::model::STAGE2_WIT_WORLD_SHA256);
        assert_eq!(
            scope.external_resources,
            [Stage1ResourceKind::PausedDurationTimer, Stage1ResourceKind::DurableKeyValue]
        );
        assert_eq!(scope.case_count, 31);
        assert!(!scope.cross_isa);
        assert!(!scope.extra_external_resources);

        let guards = Stage2StrictClaimGuards::required();
        assert_eq!(guards.strict_cross_runtime_continuity, Stage2StrictClaimBoundary::Proven);
        assert_eq!(
            guards.strict_component_model_runtime_independence,
            Stage2StrictClaimBoundary::Proven
        );
        assert_eq!(guards.cross_isa_portability, Stage2StrictClaimBoundary::NotClaimed);
        assert_eq!(guards.extra_external_resources, Stage2StrictClaimBoundary::NotClaimed);

        let legacy = Stage2ClaimGuards::required();
        assert_eq!(
            legacy.strict_component_model_runtime_independence,
            Stage2ClaimBoundary::NotProven
        );
    }

    #[test]
    fn versioned_document_parsers_discriminate_v2_and_strict_v3() {
        let v2_manifest = serde_json::to_vec(&v2_manifest()).unwrap();
        let strict_manifest = serde_json::to_vec(&strict_manifest()).unwrap();
        assert_eq!(
            parse_stage2_matrix_manifest_document_json(&v2_manifest).unwrap().schema(),
            Stage2MatrixManifestDocumentSchema::V2
        );
        assert_eq!(
            parse_stage2_matrix_manifest_document_json(&strict_manifest).unwrap().schema(),
            Stage2MatrixManifestDocumentSchema::StrictV3
        );

        let v2_evidence = serde_json::to_vec(&v2_evidence()).unwrap();
        let strict_evidence = serde_json::to_vec(&strict_evidence()).unwrap();
        assert_eq!(
            parse_stage2_evidence_document_json(&v2_evidence).unwrap().schema(),
            Stage2EvidenceDocumentSchema::V2
        );
        assert_eq!(
            parse_stage2_evidence_document_json(&strict_evidence).unwrap().schema(),
            Stage2EvidenceDocumentSchema::StrictV3
        );
    }

    #[test]
    fn versioned_document_parsers_reject_unknown_fields_schemas_and_mixed_shapes() {
        let mut unknown_field = serde_json::to_value(strict_manifest()).unwrap();
        unknown_field["unexpected"] = serde_json::json!(true);
        let error = parse_stage2_matrix_manifest_document_json(
            &serde_json::to_vec(&unknown_field).unwrap(),
        )
        .unwrap_err();
        assert_eq!(error.code, "invalid-stage2-versioned-document");

        let mut unknown_schema = serde_json::to_value(strict_evidence()).unwrap();
        unknown_schema["schema_version"] = serde_json::json!("visa-stage2-evidence-v99");
        let error =
            parse_stage2_evidence_document_json(&serde_json::to_vec(&unknown_schema).unwrap())
                .unwrap_err();
        assert_eq!(error.code, "unknown-stage2-document-schema");

        let mut v2_body_claiming_v3 = serde_json::to_value(v2_manifest()).unwrap();
        v2_body_claiming_v3["schema_version"] =
            serde_json::json!(STAGE2_STRICT_MATRIX_MANIFEST_SCHEMA_VERSION);
        assert!(
            parse_stage2_matrix_manifest_document_json(
                &serde_json::to_vec(&v2_body_claiming_v3).unwrap()
            )
            .is_err()
        );

        let mut v3_body_claiming_v2 = serde_json::to_value(strict_evidence()).unwrap();
        v3_body_claiming_v2["schema_version"] =
            serde_json::json!(super::super::model::STAGE2_EVIDENCE_SCHEMA_VERSION);
        assert!(
            parse_stage2_evidence_document_json(&serde_json::to_vec(&v3_body_claiming_v2).unwrap())
                .is_err()
        );
    }
}
