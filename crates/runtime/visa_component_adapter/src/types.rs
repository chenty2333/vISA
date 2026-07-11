use contract_core::Digest;
use visa_runtime::SafePointTimer;

use crate::PortableComponentState;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivationRequest {
    pub session_id: String,
    pub key: String,
    pub initial_value: Vec<u8>,
    pub completion_value: Vec<u8>,
    pub delay_ns: u64,
    pub baseline_idempotency_key: String,
    pub timer_idempotency_key: String,
    pub completion_idempotency_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentSafePoint {
    pub state: PortableComponentState,
    pub timer: SafePointTimer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreflightExpectations {
    pub component_digest: Digest,
    pub profile_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeIdentity {
    pub implementation: String,
    pub implementation_version: String,
    pub engine: String,
    pub engine_version: String,
}

impl RuntimeIdentity {
    pub fn new(
        implementation: impl Into<String>,
        implementation_version: impl Into<String>,
        engine: impl Into<String>,
        engine_version: impl Into<String>,
    ) -> Self {
        Self {
            implementation: implementation.into(),
            implementation_version: implementation_version.into(),
            engine: engine.into(),
            engine_version: engine_version.into(),
        }
    }
}
