mod error;
mod host;
mod lifecycle;
mod state;
mod types;

pub use error::{
    AdapterError, AdapterFailureKind, KvFailure, ResourceBindingError, TimerFailure,
    WorkloadFailure, WorkloadFailureKind,
};
pub use host::{
    AdapterProvider, BindingError, BindingSet, KvBinding, KvWriteResult, TimerArmResult,
    TimerBinding, identity_string, kv_conditional_put, kv_read, parse_identity, timer_arm,
    timer_cancel,
};
pub use lifecycle::{
    CooperativeRuntimeFactory, CooperativeRuntimeInstance, RecoverableInstantiation,
    component_digest, validate_preflight_contract,
};
pub use state::{
    COMPONENT_STATE_ENCODING, ComponentState, ComponentStatus, PortableComponentState,
    StateCodecError, WorkloadPhase,
};
pub use types::{ActivationRequest, ComponentSafePoint, PreflightExpectations, RuntimeIdentity};
