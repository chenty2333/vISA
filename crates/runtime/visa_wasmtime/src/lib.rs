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

pub use adapter::{ActivationRequest, ComponentAdapter, ComponentSafePoint, component_digest};
pub use error::{AdapterError, KvFailure, ResourceBindingError, TimerFailure, WorkloadFailure};
pub use host::{AdapterProvider, KvBinding, StoreState, TimerBinding};
pub use state::{
    COMPONENT_STATE_ENCODING, ComponentStatus, PortableComponentState, StateCodecError,
    WorkloadPhase,
};
