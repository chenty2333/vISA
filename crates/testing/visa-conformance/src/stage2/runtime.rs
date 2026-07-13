use std::path::Path;

use serde::Deserialize;

use super::{
    artifacts::{finding, is_sha256},
    instantiation::{ObservedCellTranscriptEvidence, audit_runtime_transcripts},
    model::{
        STAGE2_COMPONENT_TRANSLATOR_VERSION, STAGE2_JCO_NODE_ENVIRONMENT_NAME,
        STAGE2_JCO_NODE_ENVIRONMENT_VERSION, STAGE2_JCO_NODE_EXECUTION_CARRIER,
        STAGE2_JCO_NODE_IMPLEMENTATION_VERSION, STAGE2_JCO_NODE_RPC_PROTOCOL_VERSION,
        STAGE2_JCO_TRANSLATION_OPTIONS, STAGE2_JCO_VERSION, STAGE2_JS_COMPONENT_BINDGEN_VERSION,
        STAGE2_NODE_VERSION, STAGE2_V8_VERSION, STAGE2_WACOGO_ENGINE_VERSION,
        STAGE2_WACOGO_ENVIRONMENT_NAME, STAGE2_WACOGO_ENVIRONMENT_VERSION,
        STAGE2_WACOGO_IMPLEMENTATION_VERSION, STAGE2_WASMTIME_ENGINE_VERSION,
        STAGE2_WASMTIME_ENVIRONMENT_NAME, STAGE2_WASMTIME_ENVIRONMENT_VERSION,
        STAGE2_WASMTIME_IMPLEMENTATION_VERSION, Stage2CellDescriptor, Stage2CellId,
        Stage2CellManifest, Stage2Runtime, Stage2TranslationProvenance, Stage2ValidationFinding,
    },
    strict_model::{Stage2StrictRuntimeMetadata, Stage2WacogoRuntimeLineageObservation},
};
use crate::{
    STAGE1_CASE_DEFINITIONS, Stage1Claim, Stage1EvidenceBundle, Stage1EvidenceKind,
    Stage1VersionedIdentity, VerifiedStage1Artifacts,
};

pub(super) fn translation_presence_matches(
    runtime: Stage2Runtime,
    provenance: Option<&Stage2TranslationProvenance>,
) -> bool {
    match (runtime, provenance) {
        (Stage2Runtime::Wasmtime, None) => true,
        (Stage2Runtime::Wacogo, None) => true,
        (Stage2Runtime::JcoNode, Some(provenance)) => {
            provenance.jco_version == STAGE2_JCO_VERSION
                && provenance.js_component_bindgen_version == STAGE2_JS_COMPONENT_BINDGEN_VERSION
                && provenance.translator
                    == "wasmtime-environ component translator (shared by js-component-bindgen)"
                && provenance.translator_version == STAGE2_COMPONENT_TRANSLATOR_VERSION
                && provenance.translation_options == STAGE2_JCO_TRANSLATION_OPTIONS
                && std::path::Path::new(&provenance.node_executable_path).is_absolute()
                && is_sha256(&provenance.node_executable_sha256)
                && provenance.node_version == STAGE2_NODE_VERSION
                && provenance.v8_version == STAGE2_V8_VERSION
                && provenance.rpc_protocol_version == STAGE2_JCO_NODE_RPC_PROTOCOL_VERSION
                && provenance.execution_carrier == STAGE2_JCO_NODE_EXECUTION_CARRIER
                && is_sha256(&provenance.generated_sha256)
                && is_sha256(&provenance.driver_sha256)
                && !provenance.core_module_sha256s.is_empty()
                && provenance.core_module_sha256s.iter().all(|digest| is_sha256(digest))
        }
        _ => false,
    }
}

pub(super) fn validate_inner_cell(
    descriptor: &'static Stage2CellDescriptor,
    manifest: &Stage2CellManifest,
    bundle: &Stage1EvidenceBundle,
    artifacts: &VerifiedStage1Artifacts,
    cell_root: &Path,
    findings: &mut Vec<Stage2ValidationFinding>,
) -> ObservedCellTranscriptEvidence {
    let id = descriptor.id;
    let observed =
        validate_inner_cell_without_manifest(descriptor, bundle, artifacts, cell_root, findings);
    if manifest.observed_source != bundle.environment.source_runtime
        || manifest.observed_destination != bundle.environment.destination_runtime
        || manifest.case_count != bundle.cases.len()
        || manifest.source_translation_provenance != observed.translation_provenance.source
        || manifest.destination_translation_provenance
            != observed.translation_provenance.destination
    {
        finding(
            findings,
            "stage2-cell-observation-mismatch",
            format!("{} outer observations differ from Stage 1", id.as_str()),
        );
    }
    if manifest.instantiation_observations != observed.instantiation_observations {
        finding(
            findings,
            "stage2-cell-instantiation-observation-mismatch",
            format!(
                "{} outer instantiation observations differ from transcript facts",
                id.as_str()
            ),
        );
    }
    observed
}

pub(super) fn validate_inner_cell_without_manifest(
    descriptor: &'static Stage2CellDescriptor,
    bundle: &Stage1EvidenceBundle,
    artifacts: &VerifiedStage1Artifacts,
    cell_root: &Path,
    findings: &mut Vec<Stage2ValidationFinding>,
) -> ObservedCellTranscriptEvidence {
    let id = descriptor.id;
    if bundle.evidence_kind != Stage1EvidenceKind::Execution
        || bundle.claims != [Stage1Claim::CooperativeStatefulComponentHandoff]
        || bundle.cases.len() != STAGE1_CASE_DEFINITIONS.len()
    {
        finding(
            findings,
            "invalid-stage2-inner-stage1-scope",
            format!("{} is not exact 31-case cooperative execution evidence", id.as_str()),
        );
    }
    if !runtime_identity_matches(descriptor.source_runtime, &bundle.environment.source_runtime)
        || !runtime_identity_matches(
            descriptor.destination_runtime,
            &bundle.environment.destination_runtime,
        )
    {
        finding(
            findings,
            "wrong-stage2-runtime-identity",
            format!("{} runtime identities do not match its fixed pair", id.as_str()),
        );
    }
    for case in &bundle.cases {
        if let Err(source) = crate::stage2_normalize::validate_canonical_raw_artifacts(case) {
            finding(findings, source.code, format!("{}: {}", id.as_str(), source.detail));
        }
    }
    audit_runtime_transcripts(descriptor, bundle, artifacts, cell_root, findings)
}

pub(crate) fn runtime_identity_matches(
    runtime: Stage2Runtime,
    identity: &Stage1VersionedIdentity,
) -> bool {
    match runtime {
        Stage2Runtime::Wasmtime => {
            identity.name == STAGE2_WASMTIME_ENVIRONMENT_NAME
                && identity.version == STAGE2_WASMTIME_ENVIRONMENT_VERSION
        }
        Stage2Runtime::JcoNode => {
            identity.name == STAGE2_JCO_NODE_ENVIRONMENT_NAME
                && identity.version == STAGE2_JCO_NODE_ENVIRONMENT_VERSION
        }
        Stage2Runtime::Wacogo => {
            identity.name == STAGE2_WACOGO_ENVIRONMENT_NAME
                && identity.version == STAGE2_WACOGO_ENVIRONMENT_VERSION
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ObservedRuntimeIdentity {
    pub(crate) implementation: String,
    pub(crate) implementation_version: String,
    pub(crate) engine: String,
    pub(crate) engine_version: String,
    pub(crate) translation_provenance: Option<Stage2TranslationProvenance>,
    pub(crate) implementation_lineage: Option<ObservedImplementationLineage>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ObservedImplementationLineage {
    Wacogo {
        source_lock_schema: String,
        source_lock_sha256: String,
        derivative_id: String,
        upstream_module: String,
        upstream_version: String,
        upstream_revision: String,
        upstream_module_sum: String,
        upstream_is_qualified_without_patches: bool,
        patchset_id: String,
        patchset_sha256: String,
        patch_sha256s: Vec<String>,
        patched_tree_sha256: String,
        sidecar_executable_sha256: String,
        sidecar_executable_size: u64,
        sidecar_protocol_version: u32,
        execution_carrier: String,
        wacogo_version: String,
        wacogo_revision: String,
        wazero_version: String,
        go_version: String,
        target: String,
        main_module: String,
    },
}

impl ObservedRuntimeIdentity {
    pub(super) fn strict_metadata(&self) -> Stage2StrictRuntimeMetadata {
        Stage2StrictRuntimeMetadata {
            implementation: self.implementation.clone(),
            implementation_version: self.implementation_version.clone(),
            engine: self.engine.clone(),
            engine_version: self.engine_version.clone(),
            translation_provenance: self.translation_provenance.clone(),
            implementation_lineage: self.implementation_lineage.as_ref().map(|lineage| {
                let ObservedImplementationLineage::Wacogo {
                    source_lock_schema,
                    source_lock_sha256,
                    derivative_id,
                    upstream_module,
                    upstream_version,
                    upstream_revision,
                    upstream_module_sum,
                    upstream_is_qualified_without_patches,
                    patchset_id,
                    patchset_sha256,
                    patch_sha256s,
                    patched_tree_sha256,
                    sidecar_executable_sha256,
                    sidecar_executable_size,
                    sidecar_protocol_version,
                    execution_carrier,
                    wacogo_version,
                    wacogo_revision,
                    wazero_version,
                    go_version,
                    target,
                    main_module,
                } = lineage;
                Stage2WacogoRuntimeLineageObservation {
                    source_lock_schema: source_lock_schema.clone(),
                    source_lock_sha256: source_lock_sha256.clone(),
                    derivative_id: derivative_id.clone(),
                    upstream_module: upstream_module.clone(),
                    upstream_version: upstream_version.clone(),
                    upstream_revision: upstream_revision.clone(),
                    upstream_module_sum: upstream_module_sum.clone(),
                    upstream_is_qualified_without_patches: *upstream_is_qualified_without_patches,
                    patchset_id: patchset_id.clone(),
                    patchset_sha256: patchset_sha256.clone(),
                    patch_sha256s: patch_sha256s.clone(),
                    patched_tree_sha256: patched_tree_sha256.clone(),
                    sidecar_executable_sha256: sidecar_executable_sha256.clone(),
                    sidecar_executable_size: *sidecar_executable_size,
                    sidecar_protocol_version: *sidecar_protocol_version,
                    execution_carrier: execution_carrier.clone(),
                    wacogo_version: wacogo_version.clone(),
                    wacogo_revision: wacogo_revision.clone(),
                    wazero_version: wazero_version.clone(),
                    go_version: go_version.clone(),
                    target: target.clone(),
                    main_module: main_module.clone(),
                }
            }),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct ObservedCellTranslationProvenance {
    pub(super) source: Option<Stage2TranslationProvenance>,
    pub(super) destination: Option<Stage2TranslationProvenance>,
}

pub(super) fn validate_observed_runtime(
    id: Stage2CellId,
    case: &crate::Stage1CaseEvidence,
    role_name: &str,
    expected_runtime: Stage2Runtime,
    value: &serde_json::Value,
    cell_provenance: &mut ObservedCellTranslationProvenance,
    findings: &mut Vec<Stage2ValidationFinding>,
) {
    let runtime = value
        .pointer("/outcome/result/prepared_runtime")
        .filter(|runtime| runtime_metadata_value_is_exact(runtime))
        .cloned()
        .and_then(|runtime| serde_json::from_value::<ObservedRuntimeIdentity>(runtime).ok());
    if !runtime.as_ref().is_some_and(|runtime| {
        observed_runtime_matches(expected_runtime, runtime)
            && translation_provenance_matches(expected_runtime, runtime)
            && implementation_lineage_matches(expected_runtime, runtime)
    }) {
        finding(
            findings,
            "stage2-runtime-observation-fallback",
            format!("{} {} observed a different implementation", id.as_str(), case.case_id),
        );
        return;
    }
    let runtime = runtime.expect("checked Some above");
    let slot = if role_name == "source.jsonl" {
        &mut cell_provenance.source
    } else {
        &mut cell_provenance.destination
    };
    if let Some(previous) = slot.as_ref()
        && runtime.translation_provenance.as_ref() != Some(previous)
    {
        finding(
            findings,
            "inconsistent-stage2-translation-provenance",
            format!("{} {} changed {role_name} translation provenance", id.as_str(), case.case_id),
        );
    } else if slot.is_none() {
        *slot = runtime.translation_provenance;
    }
}

pub(crate) fn observed_runtime_matches(
    runtime: Stage2Runtime,
    observed: &ObservedRuntimeIdentity,
) -> bool {
    match runtime {
        Stage2Runtime::Wasmtime => {
            observed.implementation == "visa_wasmtime"
                && observed.implementation_version == STAGE2_WASMTIME_IMPLEMENTATION_VERSION
                && observed.engine == "wasmtime"
                && observed.engine_version == STAGE2_WASMTIME_ENGINE_VERSION
        }
        Stage2Runtime::JcoNode => {
            observed.implementation == "visa_jco_node+jco+js-component-bindgen"
                && observed.implementation_version == STAGE2_JCO_NODE_IMPLEMENTATION_VERSION
                && observed.engine == "node+v8"
                && observed.engine_version
                    == format!("{STAGE2_NODE_VERSION}/v8-{STAGE2_V8_VERSION}")
        }
        Stage2Runtime::Wacogo => {
            observed.implementation == "visa_wacogo"
                && observed.implementation_version == STAGE2_WACOGO_IMPLEMENTATION_VERSION
                && observed.engine == "partite-ai/wacogo+wazero"
                && observed.engine_version == STAGE2_WACOGO_ENGINE_VERSION
        }
    }
}

pub(crate) fn complete_runtime_metadata_matches(
    runtime: Stage2Runtime,
    observed: &ObservedRuntimeIdentity,
) -> bool {
    observed_runtime_matches(runtime, observed)
        && translation_provenance_matches(runtime, observed)
        && implementation_lineage_matches(runtime, observed)
}

pub(crate) fn runtime_metadata_value_is_exact(value: &serde_json::Value) -> bool {
    const FIELDS: [&str; 6] = [
        "implementation",
        "implementation_version",
        "engine",
        "engine_version",
        "translation_provenance",
        "implementation_lineage",
    ];
    value.as_object().is_some_and(|object| {
        object.len() == FIELDS.len()
            && FIELDS.iter().all(|field| object.contains_key(*field))
            && FIELDS[..4]
                .iter()
                .all(|field| object.get(*field).is_some_and(serde_json::Value::is_string))
            && ["translation_provenance", "implementation_lineage"].iter().all(|field| {
                object.get(*field).is_some_and(|value| value.is_null() || value.is_object())
            })
    })
}

pub(crate) fn translation_provenance_matches(
    runtime: Stage2Runtime,
    observed: &ObservedRuntimeIdentity,
) -> bool {
    match (runtime, observed.translation_provenance.as_ref()) {
        (Stage2Runtime::Wasmtime, None) => true,
        (Stage2Runtime::Wacogo, None) => true,
        (Stage2Runtime::JcoNode, Some(provenance)) => {
            provenance.translator
                == "wasmtime-environ component translator (shared by js-component-bindgen)"
                && provenance.jco_version == STAGE2_JCO_VERSION
                && provenance.js_component_bindgen_version == STAGE2_JS_COMPONENT_BINDGEN_VERSION
                && provenance.translator_version == STAGE2_COMPONENT_TRANSLATOR_VERSION
                && provenance.translation_options == STAGE2_JCO_TRANSLATION_OPTIONS
                && std::path::Path::new(&provenance.node_executable_path).is_absolute()
                && is_sha256(&provenance.node_executable_sha256)
                && provenance.node_version == STAGE2_NODE_VERSION
                && provenance.v8_version == STAGE2_V8_VERSION
                && provenance.rpc_protocol_version == STAGE2_JCO_NODE_RPC_PROTOCOL_VERSION
                && provenance.execution_carrier == STAGE2_JCO_NODE_EXECUTION_CARRIER
                && is_sha256(&provenance.generated_sha256)
                && is_sha256(&provenance.driver_sha256)
                && !provenance.core_module_sha256s.is_empty()
                && provenance.core_module_sha256s.iter().all(|digest| is_sha256(digest))
                && observed.implementation_version.contains(&format!(
                    "/jco-{}/bindgen-{}/translator-{}",
                    provenance.jco_version,
                    provenance.js_component_bindgen_version,
                    provenance.translator_version
                ))
                && observed.engine_version
                    == format!("{}/v8-{}", provenance.node_version, provenance.v8_version)
        }
        _ => false,
    }
}

pub(crate) fn implementation_lineage_matches(
    runtime: Stage2Runtime,
    observed: &ObservedRuntimeIdentity,
) -> bool {
    match (runtime, observed.implementation_lineage.as_ref()) {
        (Stage2Runtime::Wasmtime | Stage2Runtime::JcoNode, None) => true,
        (
            Stage2Runtime::Wacogo,
            Some(ObservedImplementationLineage::Wacogo {
                source_lock_schema,
                source_lock_sha256,
                derivative_id,
                upstream_module,
                upstream_version,
                upstream_revision,
                upstream_module_sum,
                upstream_is_qualified_without_patches,
                patchset_id,
                patchset_sha256,
                patch_sha256s,
                patched_tree_sha256,
                sidecar_executable_sha256,
                sidecar_executable_size,
                sidecar_protocol_version,
                execution_carrier,
                wacogo_version,
                wacogo_revision,
                wazero_version,
                go_version,
                target,
                main_module,
            }),
        ) => {
            source_lock_schema == "visa.wacogo-source-lock.v1"
                && source_lock_sha256
                    == "f8dfe3c290bc4f6f60843316c8824da9a0bfbb30a1f4fb0bf5845a3fb81b2235"
                && derivative_id == "partite-ai-wacogo-3de16a61796c-visa-patchset-v1"
                && upstream_module == "github.com/partite-ai/wacogo"
                && upstream_version == "v0.0.0-20260617023329-3de16a61796c"
                && upstream_revision == "3de16a61796ce02d29795e4a074f37a33e6ebd87"
                && upstream_module_sum == "h1:WAxQQFk9xW0jy0cu1Ql4JaaUJTUMo0GsK5TNn5Nliiw="
                && !upstream_is_qualified_without_patches
                && patchset_id == "visa-wacogo-downstream-v1"
                && patchset_sha256
                    == "a377b3d3f0da455f14097638380a8bab566b2aa0d33a4f25d90326e7a2b211e2"
                && patch_sha256s.iter().map(String::as_str).eq([
                    "c04b82a5ec2a95c45f5f81bdce5b2cbff11e25556865eb19928b48b6f94eed69",
                    "3531ff7a61de7c41f4237d7077a4dd0602bedd15e3067db070fd3e659575a37e",
                    "4b32fe31643aedab8472c42ae38d635abbfc9133093866b5ff1de9dcc4548d0e",
                ])
                && patched_tree_sha256
                    == "813eb9fad2d93d0c2237edf5d55d18316d1cc313ccf033e079c01fd18f653311"
                && sidecar_executable_sha256
                    == "7dd8365e5132fcd32f92ac89d8d1b78b80ec1d285730d8e43b360de6378a0606"
                && *sidecar_executable_size == 6_754_430
                && *sidecar_protocol_version == 1
                && execution_carrier == "owned-component-stdin-frame-v1"
                && wacogo_version == upstream_version
                && wacogo_revision == upstream_revision
                && wazero_version == "v1.11.1-0.20260418165552-5cb4bb3ec0c1"
                && go_version == "go1.26.5"
                && target == "linux/amd64"
                && main_module == "visa.local/wacogo-runtime"
        }
        _ => false,
    }
}
