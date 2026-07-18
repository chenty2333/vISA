//! Wasmtime Component Model adapter for vISA state continuity.
//!
//! Component-owned logical state crosses the adapter as a deterministic byte
//! sequence. Wasmtime resource handles remain local to one store and every
//! imported effect is routed through [`visa_runtime::Coordinator`].

mod adapter;
mod bindings;
mod error;
mod host;
pub mod logical_request;
pub mod regular_file;
mod state;

pub use adapter::{
    ComponentAdapter, PreparedComponent, VISA_WASMTIME_VERSION, WASMTIME_VERSION, WasmtimeRuntime,
};
pub use host::StoreState;
pub use logical_request::{
    ContinuityDisposition, DeliveryPolicy, EffectAdmissionProfile,
    LOGICAL_REQUEST_COMPONENT_STATE_ENCODING, LogicalRequestAdapter, LogicalRequestAdapterError,
    LogicalRequestCallResult, LogicalRequestComponentState, LogicalRequestFailure,
    LogicalRequestIdempotency, LogicalRequestObservation, LogicalRequestOperation,
    LogicalRequestPhase, LogicalRequestRejection, LogicalRequestReplay, LogicalRequestResult,
    LogicalRequestState, LogicalRequestStateCodecError, LogicalRequestStoreState,
    LogicalRequestTransport, LogicalRequestWorkloadFailure, LogicalRequestWorkloadLifecycle,
    LogicalResponseMetadata, PortableLogicalRequestState, PreparedLogicalRequestComponent,
    PreparedLogicalRequestStart,
};
pub use regular_file::{
    FileDurability, FileLockState, PortableRegularFileState, PreparedRegularFileComponent,
    REGULAR_FILE_COMPONENT_STATE_ENCODING, RegularFileAdapter, RegularFileAdapterError,
    RegularFileCallResult, RegularFileComponentState, RegularFileFailure, RegularFileOperation,
    RegularFileResult, RegularFileState, RegularFileStateCodecError, RegularFileStoreState,
    RegularFileWorkloadFailure, RegularFileWorkloadPhase,
};
pub use visa_component_adapter::{
    ActivationRequest, AdapterError, AdapterFailureKind, AdapterProvider, COMPONENT_STATE_ENCODING,
    ComponentSafePoint, ComponentState, ComponentStatus, KvBinding, KvFailure,
    PortableComponentState, PreflightExpectations, ResourceBindingError, RuntimeIdentity,
    StateCodecError, TimerBinding, TimerFailure, WorkloadFailure, WorkloadFailureKind,
    WorkloadPhase, component_digest,
};
