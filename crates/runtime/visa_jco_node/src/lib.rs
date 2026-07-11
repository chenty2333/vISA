//! Jco/Node Component Model adapter for vISA state continuity.
//!
//! The selected Component is translated by `js-component-bindgen`, then its
//! core modules are executed by Node/V8.  The canonical coordinator and every
//! authority/effect decision remain in Rust.

mod adapter;
mod error;
mod node;
mod preflight;
mod process;
mod protocol;

pub use adapter::{JcoNodeAdapter, JcoNodeRuntime};
pub use preflight::{
    JCO_NODE_RPC_PROTOCOL_VERSION, JCO_VERSION, JS_COMPONENT_BINDGEN_VERSION,
    JcoTranslationProvenance, NODE_VERSION, NodeRuntimeProvenance, PreparedArtifactKind,
    PreparedArtifactManifestEntry, PreparedJcoComponent, V8_VERSION, VISA_JCO_NODE_VERSION,
    WASMTIME_ENVIRON_VERSION,
};
pub use visa_component_adapter::{
    ActivationRequest, AdapterError, AdapterFailureKind, AdapterProvider, COMPONENT_STATE_ENCODING,
    ComponentSafePoint, ComponentState, ComponentStatus, KvBinding, KvFailure,
    PortableComponentState, PreflightExpectations, ResourceBindingError, RuntimeIdentity,
    StateCodecError, TimerBinding, TimerFailure, WorkloadFailure, WorkloadFailureKind,
    WorkloadPhase, component_digest,
};
