mod artifacts;
mod common;
mod instantiation;
mod model;
mod protocol;
mod runtime;
mod verify;
mod writer;

#[cfg(test)]
pub(crate) use artifacts::{publish_atomic, read_contained};
#[cfg(test)]
pub(crate) use common::validate_common_input;
#[cfg(test)]
pub(crate) use instantiation::{
    audit_runtime_transcript_for_test, audit_runtime_transcript_observation_for_test,
};
pub use model::*;
pub use protocol::{ProtocolCommandKind, ProtocolResultKind};
pub(crate) use protocol::{
    ProtocolRequestProjection, ProtocolResponseProjection, project_request_command,
    project_response, success_result_matches, validate_initialize_worker_binding,
};
pub(crate) use runtime::{
    ObservedRuntimeIdentity, observed_runtime_matches, runtime_identity_matches,
    translation_provenance_matches,
};
pub use verify::{
    gate_stage2_evidence_bundle_json_with_artifacts, parse_stage2_evidence_bundle_json,
    validate_stage2_evidence_artifacts,
};
#[cfg(test)]
pub(crate) use verify::{
    validate_evidence_shape, validate_manifest_shape, validate_normalized_cache,
    validate_stage2_evidence_artifacts_for_publication,
};
pub use writer::{normalize_verified_stage1_bundle_for_stage2, write_stage2_evidence_artifacts};
