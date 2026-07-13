//! Process adapter for the pinned downstream wacogo Component Model runtime.
//!
//! The Go sidecar owns only wacogo-local Component instances and resource
//! handles. Canonical state, authority, timer/KV effects, and portable state
//! remain Rust-owned behind [`visa_runtime::Coordinator`]. There is no fallback
//! to Wasmtime or another runtime.

mod adapter;
mod carrier;
mod error;
mod identity;
mod preflight;
mod process;
mod protocol;
mod state;

pub use adapter::{WacogoAdapter, WacogoRuntime};
pub use identity::{
    DERIVATIVE_ID, ENGINE_VERSION, GO_VERSION, MAIN_MODULE, PATCH_SHA256S, PATCHED_TREE_SHA256,
    PATCHSET_ID, PATCHSET_SHA256, SIDECAR_EXECUTABLE_SHA256, SIDECAR_EXECUTABLE_SIZE,
    SOURCE_LOCK_SCHEMA, SOURCE_LOCK_SHA256, TARGET, UPSTREAM_MODULE, UPSTREAM_MODULE_SUM,
    VISA_WACOGO_VERSION, WACOGO_REVISION, WACOGO_VERSION, WAZERO_VERSION, WacogoProvenance,
};
pub use preflight::PreparedWacogoComponent;
pub use visa_component_adapter::{
    ActivationRequest, AdapterError, AdapterFailureKind, AdapterProvider, COMPONENT_STATE_ENCODING,
    ComponentSafePoint, ComponentState, ComponentStatus, KvBinding, KvFailure,
    PortableComponentState, PreflightExpectations, ResourceBindingError, RuntimeIdentity,
    StateCodecError, TimerBinding, TimerFailure, WorkloadFailure, WorkloadFailureKind,
    WorkloadPhase, component_digest,
};
