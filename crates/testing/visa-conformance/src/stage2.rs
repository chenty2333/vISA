mod artifacts;
mod common;
mod instantiation;
mod model;
mod protocol;
mod runtime;
mod strict_lineage;
mod strict_model;
mod strict_verify;
mod strict_writer;
mod verify;
mod writer;

#[cfg(test)]
pub(crate) use artifacts::{publish_atomic, read_contained};
pub(crate) use common::normalized_case_matches_snapshot_timer_strategy;
#[cfg(test)]
pub(crate) use common::{parse_common_input, validate_common_input};
#[cfg(test)]
pub(crate) use instantiation::{
    audit_runtime_transcript_for_test, audit_runtime_transcript_observation_for_test,
};
pub use model::*;
pub use protocol::{ProtocolCommandKind, ProtocolResultKind};
pub(crate) use protocol::{
    ProtocolRequestProjection, ProtocolResponseProjection, observed_component_instantiated,
    project_request_command, project_response, success_result_matches,
    validate_initialize_worker_binding,
};
pub(crate) use runtime::{
    ObservedRuntimeIdentity, complete_runtime_metadata_matches, implementation_lineage_matches,
    observed_runtime_matches, runtime_identity_matches, runtime_metadata_value_is_exact,
    translation_provenance_matches,
};
pub use strict_lineage::{
    STAGE2_STRICT_CARGO_LOCK_URI, STAGE2_STRICT_LINEAGE_ROOT,
    STAGE2_STRICT_WACOGO_BUILD_RECEIPT_URI, STAGE2_STRICT_WACOGO_SIDECAR_SHA256,
    STAGE2_STRICT_WACOGO_SIDECAR_SIZE, STAGE2_STRICT_WACOGO_SIDECAR_URI,
    STAGE2_STRICT_WACOGO_SOURCE_LOCK_SHA256, STAGE2_STRICT_WACOGO_SOURCE_LOCK_URI,
};
pub use strict_model::*;
pub use strict_verify::{
    gate_stage2_strict_evidence_bundle_json_with_artifacts,
    parse_stage2_strict_evidence_bundle_json, validate_stage2_strict_evidence_artifacts,
};
pub use strict_writer::write_stage2_strict_evidence_artifacts;
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
