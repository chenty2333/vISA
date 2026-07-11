//! Wasmtime Component Model adapter for vISA state continuity.
//!
//! Component-owned logical state crosses the adapter as a deterministic byte
//! sequence. Wasmtime resource handles remain local to one store and every
//! imported effect is routed through [`visa_runtime::Coordinator`].

mod adapter;
mod bindings;
mod error;
mod host;
mod state;

pub use adapter::{
    ComponentAdapter, PreparedComponent, VISA_WASMTIME_VERSION, WASMTIME_VERSION, WasmtimeRuntime,
};
pub use host::StoreState;
pub use visa_component_adapter::{
    ActivationRequest, AdapterError, AdapterFailureKind, AdapterProvider, COMPONENT_STATE_ENCODING,
    ComponentSafePoint, ComponentState, ComponentStatus, KvBinding, KvFailure,
    PortableComponentState, PreflightExpectations, ResourceBindingError, RuntimeIdentity,
    StateCodecError, TimerBinding, TimerFailure, WorkloadFailure, WorkloadFailureKind,
    WorkloadPhase, component_digest,
};
