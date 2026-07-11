use std::path::Path;

use serde::Deserialize;

use super::{
    artifacts::{finding, is_sha256},
    instantiation::{ObservedCellTranscriptEvidence, audit_runtime_transcripts},
    model::{
        STAGE2_COMPONENT_TRANSLATOR_VERSION, STAGE2_JCO_NODE_ENVIRONMENT_NAME,
        STAGE2_JCO_NODE_ENVIRONMENT_VERSION, STAGE2_JCO_NODE_IMPLEMENTATION_VERSION,
        STAGE2_JCO_NODE_RPC_PROTOCOL_VERSION, STAGE2_JCO_TRANSLATION_OPTIONS, STAGE2_JCO_VERSION,
        STAGE2_JS_COMPONENT_BINDGEN_VERSION, STAGE2_NODE_VERSION, STAGE2_V8_VERSION,
        STAGE2_WASMTIME_ENGINE_VERSION, STAGE2_WASMTIME_ENVIRONMENT_NAME,
        STAGE2_WASMTIME_ENVIRONMENT_VERSION, STAGE2_WASMTIME_IMPLEMENTATION_VERSION, Stage2CellId,
        Stage2CellManifest, Stage2Runtime, Stage2TranslationProvenance, Stage2ValidationFinding,
    },
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
                && is_sha256(&provenance.generated_sha256)
                && is_sha256(&provenance.driver_sha256)
                && !provenance.core_module_sha256s.is_empty()
                && provenance.core_module_sha256s.iter().all(|digest| is_sha256(digest))
        }
        _ => false,
    }
}

pub(super) fn validate_inner_cell(
    id: Stage2CellId,
    manifest: &Stage2CellManifest,
    bundle: &Stage1EvidenceBundle,
    artifacts: &VerifiedStage1Artifacts,
    cell_root: &Path,
    findings: &mut Vec<Stage2ValidationFinding>,
) -> ObservedCellTranscriptEvidence {
    let observed = validate_inner_cell_without_manifest(id, bundle, artifacts, cell_root, findings);
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
    id: Stage2CellId,
    bundle: &Stage1EvidenceBundle,
    artifacts: &VerifiedStage1Artifacts,
    cell_root: &Path,
    findings: &mut Vec<Stage2ValidationFinding>,
) -> ObservedCellTranscriptEvidence {
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
    if !runtime_identity_matches(id.source_runtime(), &bundle.environment.source_runtime)
        || !runtime_identity_matches(
            id.destination_runtime(),
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
    audit_runtime_transcripts(id, bundle, artifacts, cell_root, findings)
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
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ObservedRuntimeIdentity {
    pub(crate) implementation: String,
    pub(crate) implementation_version: String,
    pub(crate) engine: String,
    pub(crate) engine_version: String,
    pub(crate) translation_provenance: Option<Stage2TranslationProvenance>,
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
        .pointer("/outcome/result/runtime")
        .cloned()
        .and_then(|runtime| serde_json::from_value::<ObservedRuntimeIdentity>(runtime).ok());
    if !runtime.as_ref().is_some_and(|runtime| {
        observed_runtime_matches(expected_runtime, runtime)
            && translation_provenance_matches(expected_runtime, runtime)
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
    }
}

fn translation_provenance_matches(
    runtime: Stage2Runtime,
    observed: &ObservedRuntimeIdentity,
) -> bool {
    match (runtime, observed.translation_provenance.as_ref()) {
        (Stage2Runtime::Wasmtime, None) => true,
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
