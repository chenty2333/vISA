mod error;
mod host;
mod lifecycle;
mod logical_request_state;
mod regular_file_state;
mod state;
mod types;

pub use error::{
    AdapterError, AdapterFailureKind, KvFailure, ResourceBindingError, TimerFailure,
    WorkloadFailure, WorkloadFailureKind,
};
pub use host::{
    AdapterProvider, BindingError, BindingSet, KvBinding, KvWriteResult, ProfileBinding,
    ProfileCallResult, ProfileFailure, TimerArmResult, TimerBinding, identity_string,
    kv_conditional_put, kv_read, parse_identity, profile_execute, profile_observe, timer_arm,
    timer_cancel,
};
pub use lifecycle::{
    CooperativeRuntimeFactory, CooperativeRuntimeInstance, RecoverableInstantiation,
    component_digest, validate_preflight_contract,
};
pub use logical_request_state::{
    LOGICAL_REQUEST_COMPONENT_STATE_ENCODING, LogicalRequestComponentState,
    LogicalRequestStateCodecError, LogicalRequestWorkloadLifecycle, PortableLogicalRequestState,
};
pub use regular_file_state::{
    PortableRegularFileState, REGULAR_FILE_COMPONENT_STATE_ENCODING, RegularFileComponentState,
    RegularFileStateCodecError, RegularFileWorkloadPhase,
};
pub use state::{
    COMPONENT_STATE_ENCODING, ComponentState, ComponentStatus, PortableComponentState,
    StateCodecError, WorkloadPhase,
};
pub use types::{ActivationRequest, ComponentSafePoint, PreflightExpectations, RuntimeIdentity};
