//! Real Wasmtime Component frontend for the first vISA continuation path.
//!
//! The component contract is intentionally small and scalar:
//! `increment() -> u64`, `value() -> u64`, `freeze-counter() -> u64`, and
//! `restore-counter(u64)`.  Wasmtime's [`Engine`], [`Component`], [`Store`],
//! and [`Instance`] are kept in opaque host-local types.  Portable state is
//! always the canonical [`visa_core::SnapshotEnvelope`] produced by the
//! selected [`WasiProfile`]; no runtime object is copied into it.

use std::fmt;

use visa_core::{
    AuthorityCommitReceipt, AuthorityId, ContinuationId, ContractError, Digest, ExternalCoordinate,
    LineageAdvance, LineageId, LineagePoint, PortableSnapshot, ProfileRef, SafePointReceipt,
    ScopeId, SnapshotEnvelope, SnapshotId, SourceSemanticCut,
};
use visa_profile::{ContinuityProfile, CounterSessionState, DurableKvProfile};
use wasmtime::component::types::ComponentItem;
use wasmtime::component::{Component, Instance, Linker, Type};
use wasmtime::{Config, Engine, Store};

/// The exact component digest type owned by `visa-core`.
pub type ComponentDigest = Digest;

/// A profile adapter for the scalar counter component.
///
/// The profile owns typed encoding, strict decoding, validation, and logical
/// resource requirements.  The frontend only transports the resulting bytes.
pub trait WasiProfile: Clone + Send + Sync + 'static {
    /// Exact profile identity, including contract and state schema digests.
    fn profile_ref(&self) -> ProfileRef;

    /// Encode the complete typed portable state.
    fn encode_state(&self, state: &CounterSessionState) -> Result<Vec<u8>, ProfileError>;

    /// Strictly decode the complete typed portable state.
    fn decode_state(&self, bytes: &[u8]) -> Result<CounterSessionState, ProfileError>;

    /// Validate decoded state before it reaches a destination guest.
    fn validate_state(&self, state: &CounterSessionState) -> Result<(), ProfileError>;

    /// Describe logical resources needed after restore.
    fn resource_requirements(
        &self,
        state: &CounterSessionState,
    ) -> Result<Vec<visa_core::ResourceRequirement>, ProfileError>;
}

/// The first profile's typed state codec is reusable by this frontend.
pub type CounterProfile = DurableKvProfile;

impl WasiProfile for DurableKvProfile {
    fn profile_ref(&self) -> ProfileRef {
        ContinuityProfile::profile_ref(self)
    }

    fn encode_state(&self, state: &CounterSessionState) -> Result<Vec<u8>, ProfileError> {
        self.state_codec().encode(state).map_err(|error| ProfileError::new(format!("{error:?}")))
    }

    fn decode_state(&self, bytes: &[u8]) -> Result<CounterSessionState, ProfileError> {
        let state = self
            .state_codec()
            .decode(bytes)
            .map_err(|error| ProfileError::new(format!("{error:?}")))?;
        ContinuityProfile::validate_state(self, &state)
            .map_err(|error| ProfileError::new(format!("{error:?}")))?;
        Ok(state)
    }

    fn validate_state(&self, state: &CounterSessionState) -> Result<(), ProfileError> {
        ContinuityProfile::validate_state(self, state)
            .map_err(|error| ProfileError::new(format!("{error:?}")))
    }

    fn resource_requirements(
        &self,
        state: &CounterSessionState,
    ) -> Result<Vec<visa_core::ResourceRequirement>, ProfileError> {
        ContinuityProfile::resource_requirements(self, state)
            .map_err(|error| ProfileError::new(format!("{error:?}")))
    }
}

/// Profile codec/validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileError {
    message: String,
}

impl ProfileError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }
}

impl fmt::Display for ProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ProfileError {}

/// Metadata emitted for a successful cooperative safe point.  The portable
/// snapshot itself remains the core envelope; this is only a runtime-local
/// observation used by the coordinator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SafePointCapture {
    pub dispatch_stopped: bool,
    pub execution_epoch: u64,
    pub safe_point: SafePointReceipt,
}

/// Host-local permission to open business dispatch for one exact runtime
/// instance.  It is deliberately non-serializable and carries no authority
/// by itself; an embedding host constructs it only after validating either an
/// active source binding or an authority commit receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivationGate {
    continuation: ContinuationId,
    snapshot: SnapshotId,
    runtime: ExternalCoordinate,
    execution_epoch: u64,
}

impl ActivationGate {
    #[must_use]
    pub fn from_authority_commit(receipt: &AuthorityCommitReceipt) -> Self {
        Self {
            continuation: receipt.continuation,
            snapshot: receipt.snapshot,
            runtime: receipt.destination.clone(),
            execution_epoch: receipt.execution_epoch,
        }
    }

    /// Construct a source gate after the embedding host has validated and
    /// opened its opaque source binding.
    #[must_use]
    pub fn for_active_source(context: &SnapshotContext, execution_epoch: u64) -> Self {
        Self {
            continuation: context.continuation,
            snapshot: context.snapshot,
            runtime: context.runtime.clone(),
            execution_epoch,
        }
    }
}

/// Inputs needed to seal a core snapshot.  Defaults are deterministic test
/// coordinates; a real coordinator supplies its own exact values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotContext {
    pub snapshot: SnapshotId,
    pub continuation: ContinuationId,
    pub scope: ScopeId,
    pub lineage: LineageAdvance,
    pub runtime: ExternalCoordinate,
    pub cut_sequence: u64,
    pub receipt_digest: Digest,
}

impl Default for SnapshotContext {
    fn default() -> Self {
        Self {
            snapshot: SnapshotId::from_u128(1),
            continuation: ContinuationId::from_u128(1),
            scope: ScopeId::from_u128(1),
            lineage: LineageAdvance {
                parent: LineagePoint {
                    lineage: LineageId::from_u128(1),
                    generation: 0,
                    state_digest: Digest::ZERO,
                },
                successor_generation: 1,
            },
            runtime: ExternalCoordinate {
                authority: AuthorityId::from_u128(1),
                value: b"wasmtime".to_vec(),
            },
            cut_sequence: 0,
            receipt_digest: Digest::ZERO,
        }
    }
}

/// Component identity and profile identity required for exact preflight.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreflightExpectations {
    pub component_digest: ComponentDigest,
    pub profile: ProfileRef,
}

impl PreflightExpectations {
    #[must_use]
    pub fn new(component_digest: ComponentDigest, profile: ProfileRef) -> Self {
        Self { component_digest, profile }
    }
}

/// Compile/type-check a component without creating a Store or running guest
/// code.  The profile is copied into each fresh prepared instance.
pub struct WasiFrontend<P> {
    profile: P,
    expected_component_digest: Option<ComponentDigest>,
}

impl<P: WasiProfile> WasiFrontend<P> {
    #[must_use]
    pub fn new(profile: P) -> Self {
        Self { profile, expected_component_digest: None }
    }

    #[must_use]
    pub const fn with_component_digest(mut self, digest: ComponentDigest) -> Self {
        self.expected_component_digest = Some(digest);
        self
    }

    #[must_use]
    pub fn profile_ref(&self) -> ProfileRef {
        self.profile.profile_ref()
    }

    pub fn preflight(&self, component_bytes: &[u8]) -> Result<PreparedComponent<P>, WasiError> {
        let digest = component_digest(component_bytes);
        self.preflight_with_expectations(
            component_bytes,
            PreflightExpectations::new(
                self.expected_component_digest.unwrap_or(digest),
                self.profile.profile_ref(),
            ),
        )
    }

    pub fn preflight_with_expectations(
        &self,
        component_bytes: &[u8],
        expectations: PreflightExpectations,
    ) -> Result<PreparedComponent<P>, WasiError> {
        let actual_digest = component_digest(component_bytes);
        if actual_digest != expectations.component_digest {
            return Err(WasiError::ComponentDigestMismatch {
                expected: expectations.component_digest,
                actual: actual_digest,
            });
        }
        let actual_profile = self.profile.profile_ref();
        if actual_profile != expectations.profile {
            return Err(WasiError::ProfileRefMismatch {
                expected: Box::new(expectations.profile),
                actual: Box::new(actual_profile),
            });
        }

        let engine = build_engine()?;
        let component = Component::new(&engine, component_bytes)
            .map_err(|error| WasiError::Compile(format!("{error:#}")))?;
        validate_component_contract(&component, &engine)?;
        Ok(PreparedComponent {
            engine,
            component,
            profile: self.profile.clone(),
            component_digest: actual_digest,
        })
    }
}

/// SHA-256 of the exact component bytes.
#[must_use]
pub fn component_digest(bytes: &[u8]) -> ComponentDigest {
    Digest::of_bytes(bytes)
}

fn build_engine() -> Result<Engine, WasiError> {
    let mut config = Config::new();
    config.wasm_component_model(true);
    Engine::new(&config).map_err(|error| WasiError::Engine(error.to_string()))
}

fn validate_component_contract(component: &Component, engine: &Engine) -> Result<(), WasiError> {
    let component_type = component.component_type();
    for (name, expected_params) in [
        ("increment", 0_usize),
        ("value", 0_usize),
        ("freeze-counter", 0_usize),
        ("restore-counter", 1_usize),
    ] {
        let Some(ComponentItem::ComponentFunc(function)) = component_type.get_export(engine, name)
        else {
            return Err(WasiError::InvalidContract(format!("missing function export `{name}`")));
        };
        let mut params = function.params();
        let mut results = function.results();
        let valid = params.len() == expected_params
            && params.all(|(_, ty)| matches!(ty, Type::U64))
            && if name == "restore-counter" {
                results.next().is_none()
            } else {
                matches!(results.next(), Some(Type::U64)) && results.next().is_none()
            };
        if !valid {
            return Err(WasiError::InvalidContract(format!(
                "export `{name}` has the wrong component function type"
            )));
        }
    }
    Ok(())
}

/// Compiled Wasmtime objects.  This type intentionally has no serialization
/// implementation and never appears in a portable snapshot.
pub struct PreparedComponent<P> {
    engine: Engine,
    component: Component,
    profile: P,
    component_digest: ComponentDigest,
}

impl<P> fmt::Debug for PreparedComponent<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedComponent")
            .field("component_digest", &self.component_digest)
            .finish_non_exhaustive()
    }
}

impl<P: WasiProfile> PreparedComponent<P> {
    #[must_use]
    pub const fn component_digest(&self) -> ComponentDigest {
        self.component_digest
    }

    #[must_use]
    pub fn profile_ref(&self) -> ProfileRef {
        self.profile.profile_ref()
    }

    /// Always instantiate a new Store and Instance.
    pub fn instantiate(&self, execution_epoch: u64) -> Result<WasiInstance<P>, WasiError> {
        let mut store = Store::new(&self.engine, HostState { dispatch_open: false });
        let linker = Linker::<HostState>::new(&self.engine);
        let instance = linker
            .instantiate(&mut store, &self.component)
            .map_err(|error| WasiError::Instantiate(error.to_string()))?;
        Ok(WasiInstance {
            store,
            instance,
            profile: self.profile.clone(),
            component_digest: self.component_digest,
            execution_epoch,
            activated: false,
            activation_prepared: false,
            frozen: false,
            context: SnapshotContext::default(),
            safe_point: None,
            staged_counter: None,
            session_key: b"counter".to_vec(),
            last_seen_version: None,
        })
    }

    pub fn instantiate_fresh(&self, execution_epoch: u64) -> Result<WasiInstance<P>, WasiError> {
        self.instantiate(execution_epoch)
    }
}

struct HostState {
    dispatch_open: bool,
}

/// A fresh isolated Wasmtime instance and its local activation state.
pub struct WasiInstance<P> {
    store: Store<HostState>,
    instance: Instance,
    profile: P,
    component_digest: ComponentDigest,
    execution_epoch: u64,
    activated: bool,
    activation_prepared: bool,
    frozen: bool,
    context: SnapshotContext,
    safe_point: Option<SafePointCapture>,
    staged_counter: Option<u64>,
    session_key: Vec<u8>,
    last_seen_version: Option<u64>,
}

impl<P> fmt::Debug for WasiInstance<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WasiInstance")
            .field("component_digest", &self.component_digest)
            .field("execution_epoch", &self.execution_epoch)
            .field("activated", &self.activated)
            .field("frozen", &self.frozen)
            .finish_non_exhaustive()
    }
}

impl<P: WasiProfile> WasiInstance<P> {
    #[must_use]
    pub const fn component_digest(&self) -> ComponentDigest {
        self.component_digest
    }

    #[must_use]
    pub const fn execution_epoch(&self) -> u64 {
        self.execution_epoch
    }

    #[must_use]
    pub const fn is_activated(&self) -> bool {
        self.activated
    }

    #[must_use]
    pub const fn is_frozen(&self) -> bool {
        self.frozen
    }

    /// Replace default test coordinates with coordinator-owned exact values.
    pub fn set_snapshot_context(&mut self, context: SnapshotContext) -> Result<(), WasiError> {
        if self.activated || self.activation_prepared || self.frozen {
            return Err(WasiError::ContextLocked);
        }
        self.context = context;
        Ok(())
    }

    /// Bind the next continuation cut on an already active source. This
    /// changes only portable semantic coordinates; it does not replace the
    /// runtime instance or reopen a frozen dispatch path.
    pub fn begin_continuation(&mut self, context: SnapshotContext) -> Result<(), WasiError> {
        if !self.activated || self.frozen {
            return Err(WasiError::ContextLocked);
        }
        self.context = context;
        self.safe_point = None;
        Ok(())
    }

    #[must_use]
    pub fn safe_point(&self) -> Option<&SafePointCapture> {
        self.safe_point.as_ref()
    }

    /// Update the portable logical session metadata after a synchronous
    /// provider operation. No provider handle or authority is captured.
    pub fn set_portable_session(
        &mut self,
        session_key: Vec<u8>,
        last_seen_version: Option<u64>,
    ) -> Result<(), WasiError> {
        if self.frozen {
            return Err(WasiError::AlreadyFrozen);
        }
        let state =
            CounterSessionState { counter: 0, session_key: session_key.clone(), last_seen_version };
        self.profile.validate_state(&state).map_err(WasiError::ProfileValidation)?;
        self.session_key = session_key;
        self.last_seen_version = last_seen_version;
        Ok(())
    }

    #[must_use]
    pub fn portable_session(&self) -> (&[u8], Option<u64>) {
        (&self.session_key, self.last_seen_version)
    }

    /// Open business dispatch only after the exact authority commit epoch.
    pub fn activate(&mut self, gate: &ActivationGate) -> Result<(), WasiError> {
        self.prepare_activation(gate)?;
        self.enable_activation()
    }

    /// Validate and stage an exact activation while guest business dispatch
    /// remains closed. The host can now acquire its external admission fence.
    pub fn prepare_activation(&mut self, gate: &ActivationGate) -> Result<(), WasiError> {
        if gate.continuation != self.context.continuation
            || gate.snapshot != self.context.snapshot
            || gate.runtime != self.context.runtime
        {
            return Err(WasiError::ActivationGateMismatch);
        }
        if gate.execution_epoch != self.execution_epoch {
            return Err(WasiError::ExecutionEpochMismatch {
                expected: self.execution_epoch,
                actual: gate.execution_epoch,
            });
        }
        self.activation_prepared = true;
        self.activated = false;
        self.store.data_mut().dispatch_open = false;
        Ok(())
    }

    /// Complete a previously validated activation after provider admission.
    pub fn enable_activation(&mut self) -> Result<(), WasiError> {
        if !self.activation_prepared || self.frozen {
            return Err(WasiError::ActivationRequired);
        }
        self.activation_prepared = false;
        self.activated = true;
        self.store.data_mut().dispatch_open = true;
        Ok(())
    }

    pub fn increment(&mut self) -> Result<u64, WasiError> {
        self.require_business_dispatch()?;
        let function = self
            .instance
            .get_typed_func::<(), (u64,)>(&mut self.store, "increment")
            .map_err(|error| WasiError::MissingExport(error.to_string()))?;
        function
            .call(&mut self.store, ())
            .map(|result| result.0)
            .map_err(|error| WasiError::GuestTrap(error.to_string()))
    }

    pub fn value(&mut self) -> Result<u64, WasiError> {
        self.require_business_dispatch()?;
        let function = self
            .instance
            .get_typed_func::<(), (u64,)>(&mut self.store, "value")
            .map_err(|error| WasiError::MissingExport(error.to_string()))?;
        function
            .call(&mut self.store, ())
            .map(|result| result.0)
            .map_err(|error| WasiError::GuestTrap(error.to_string()))
    }

    /// Stop business dispatch and capture guest state at a cooperative safe
    /// point. The embedding host may then atomically close/capture its native
    /// providers before sealing the portable snapshot.
    pub fn begin_freeze(&mut self) -> Result<(), WasiError> {
        if !self.activated {
            return Err(WasiError::NotActivated);
        }
        if self.frozen {
            return Err(WasiError::AlreadyFrozen);
        }
        let function = self
            .instance
            .get_typed_func::<(), (u64,)>(&mut self.store, "freeze-counter")
            .map_err(|error| WasiError::MissingExport(error.to_string()))?;
        self.frozen = true;
        self.store.data_mut().dispatch_open = false;
        let counter = match function.call(&mut self.store, ()) {
            Ok(result) => result.0,
            Err(error) => {
                self.frozen = false;
                self.store.data_mut().dispatch_open = true;
                return Err(WasiError::GuestTrap(error.to_string()));
            }
        };
        self.staged_counter = Some(counter);
        Ok(())
    }

    /// Seal the snapshot after the host has captured logical provider state
    /// and closed the corresponding native dispatch path.
    pub fn complete_freeze(
        &mut self,
        session_key: Vec<u8>,
        last_seen_version: Option<u64>,
    ) -> Result<SnapshotEnvelope, WasiError> {
        let counter = self.staged_counter.ok_or(WasiError::NotFrozen)?;
        let typed_state = CounterSessionState { counter, session_key, last_seen_version };
        self.profile.validate_state(&typed_state).map_err(WasiError::ProfileValidation)?;
        let state = self.profile.encode_state(&typed_state).map_err(WasiError::ProfileEncoding)?;
        let decoded = self.profile.decode_state(&state).map_err(WasiError::ProfileDecoding)?;
        self.profile.validate_state(&decoded).map_err(WasiError::ProfileValidation)?;
        let resources =
            self.profile.resource_requirements(&decoded).map_err(WasiError::ProfileValidation)?;
        let state_digest = Digest::of_bytes(&state);
        let safe_point = SafePointReceipt {
            continuation: self.context.continuation,
            scope: self.context.scope,
            runtime: self.context.runtime.clone(),
            cut_sequence: self.context.cut_sequence,
            portable_state_digest: state_digest,
            receipt_digest: Digest::ZERO,
        }
        .seal()
        .map_err(WasiError::Contract)?;
        let body = PortableSnapshot {
            snapshot: self.context.snapshot,
            continuation: self.context.continuation,
            scope: self.context.scope,
            lineage: self.context.lineage.clone(),
            profile: self.profile.profile_ref(),
            source_cut: SourceSemanticCut {
                runtime: self.context.runtime.clone(),
                cut_sequence: self.context.cut_sequence,
                receipt_digest: safe_point.receipt_digest,
            },
            state,
            state_digest,
            resources,
            effects: Vec::new(),
        };
        let envelope = SnapshotEnvelope::seal(body).map_err(WasiError::Contract)?;
        self.safe_point = Some(SafePointCapture {
            dispatch_stopped: true,
            execution_epoch: self.execution_epoch,
            safe_point,
        });
        self.session_key = typed_state.session_key;
        self.last_seen_version = typed_state.last_seen_version;
        self.staged_counter = None;
        Ok(envelope)
    }

    /// Reopen this still-local source when the host could not establish the
    /// provider half of the safe point. No portable snapshot exists yet.
    pub fn cancel_freeze(&mut self) -> Result<(), WasiError> {
        if !self.frozen || self.safe_point.is_some() {
            return Err(WasiError::NotFrozen);
        }
        self.frozen = false;
        self.staged_counter = None;
        self.store.data_mut().dispatch_open = true;
        Ok(())
    }

    /// Convenience path for frontends without an external provider cut.
    pub fn freeze(&mut self) -> Result<SnapshotEnvelope, WasiError> {
        self.begin_freeze()?;
        self.complete_freeze(self.session_key.clone(), self.last_seen_version)
    }

    /// Verify the core envelope/profile/schema and restore into this fresh
    /// destination.  Activation remains closed until a matching receipt.
    pub fn restore(&mut self, snapshot: &SnapshotEnvelope) -> Result<(), WasiError> {
        snapshot.verify().map_err(WasiError::Contract)?;
        if snapshot.body.continuation != self.context.continuation
            || snapshot.body.snapshot != self.context.snapshot
            || snapshot.body.scope != self.context.scope
            || snapshot.body.lineage != self.context.lineage
        {
            return Err(WasiError::SnapshotContextMismatch);
        }
        let expected_profile = self.profile.profile_ref();
        if snapshot.body.profile != expected_profile {
            return Err(WasiError::ProfileRefMismatch {
                expected: Box::new(expected_profile),
                actual: Box::new(snapshot.body.profile.clone()),
            });
        }
        let state =
            self.profile.decode_state(&snapshot.body.state).map_err(WasiError::ProfileDecoding)?;
        self.profile.validate_state(&state).map_err(WasiError::ProfileValidation)?;
        let function = self
            .instance
            .get_typed_func::<(u64,), ()>(&mut self.store, "restore-counter")
            .map_err(|error| WasiError::MissingExport(error.to_string()))?;
        function
            .call(&mut self.store, (state.counter,))
            .map_err(|error| WasiError::GuestTrap(error.to_string()))?;
        self.session_key = state.session_key;
        self.last_seen_version = state.last_seen_version;
        self.frozen = false;
        self.activated = false;
        self.activation_prepared = false;
        self.safe_point = None;
        self.staged_counter = None;
        self.store.data_mut().dispatch_open = false;
        Ok(())
    }

    fn require_business_dispatch(&self) -> Result<(), WasiError> {
        if self.activated && !self.frozen && self.store.data().dispatch_open {
            Ok(())
        } else {
            Err(WasiError::ActivationRequired)
        }
    }
}

/// Frontend errors.  Core integrity remains represented by `ContractError`.
#[derive(Debug)]
pub enum WasiError {
    Engine(String),
    Compile(String),
    InvalidContract(String),
    Instantiate(String),
    MissingExport(String),
    GuestTrap(String),
    ComponentDigestMismatch { expected: ComponentDigest, actual: ComponentDigest },
    ProfileRefMismatch { expected: Box<ProfileRef>, actual: Box<ProfileRef> },
    ProfileEncoding(ProfileError),
    ProfileDecoding(ProfileError),
    ProfileValidation(ProfileError),
    Contract(ContractError),
    ExecutionEpochMismatch { expected: u64, actual: u64 },
    ActivationGateMismatch,
    SnapshotContextMismatch,
    ContextLocked,
    NotActivated,
    ActivationRequired,
    AlreadyFrozen,
    NotFrozen,
}

impl fmt::Display for WasiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Engine(error) => write!(formatter, "engine creation failed: {error}"),
            Self::Compile(error) => write!(formatter, "component compilation failed: {error}"),
            Self::InvalidContract(error) => {
                write!(formatter, "invalid component contract: {error}")
            }
            Self::Instantiate(error) => {
                write!(formatter, "component instantiation failed: {error}")
            }
            Self::MissingExport(error) => write!(formatter, "required export unavailable: {error}"),
            Self::GuestTrap(error) => write!(formatter, "guest call trapped: {error}"),
            Self::ComponentDigestMismatch { expected, actual } => {
                write!(
                    formatter,
                    "component digest mismatch: expected {expected:?}, got {actual:?}"
                )
            }
            Self::ProfileRefMismatch { expected, actual } => {
                write!(
                    formatter,
                    "profile reference mismatch: expected {expected:?}, got {actual:?}"
                )
            }
            Self::ProfileEncoding(error) => write!(formatter, "profile encoding failed: {error}"),
            Self::ProfileDecoding(error) => write!(formatter, "profile decoding failed: {error}"),
            Self::ProfileValidation(error) => {
                write!(formatter, "profile validation failed: {error}")
            }
            Self::Contract(error) => {
                write!(formatter, "continuation contract rejected operation: {error}")
            }
            Self::ExecutionEpochMismatch { expected, actual } => {
                write!(formatter, "execution epoch mismatch: expected {expected}, got {actual}")
            }
            Self::ActivationGateMismatch => {
                formatter.write_str("activation gate does not bind this continuation target")
            }
            Self::SnapshotContextMismatch => {
                formatter.write_str("snapshot does not bind this continuation context")
            }
            Self::ContextLocked => formatter.write_str("snapshot context is already locked"),
            Self::NotActivated => formatter.write_str("freeze requires an activated instance"),
            Self::ActivationRequired => formatter.write_str("business call requires activation"),
            Self::AlreadyFrozen => formatter.write_str("instance is already frozen"),
            Self::NotFrozen => formatter.write_str("instance has no staged freeze"),
        }
    }
}

impl std::error::Error for WasiError {}

/// SHA-256 component identity helper.
#[must_use]
pub fn component_digest_hex(bytes: &[u8]) -> String {
    Digest::of_bytes(bytes).0.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A stable reusable scalar counter Component.
pub const COUNTER_COMPONENT_WAT: &str = r#"(component
  (core module $counter
    (global $counter (mut i64) (i64.const 0))
    (func $increment (result i64)
      (local $next i64)
      (local.set $next
        (i64.add (global.get $counter) (i64.const 1)))
      (global.set $counter (local.get $next))
      (local.get $next))
    (func $value (result i64) (global.get $counter))
    (func $freeze (result i64) (global.get $counter))
    (func $restore (param i64) (global.set $counter (local.get 0)))
    (export "increment" (func $increment))
    (export "value" (func $value))
    (export "freeze-counter" (func $freeze))
    (export "restore-counter" (func $restore)))
  (core instance $counter (instantiate $counter))
  (alias core export $counter "increment" (core func $increment))
  (alias core export $counter "value" (core func $value))
  (alias core export $counter "freeze-counter" (core func $freeze))
  (alias core export $counter "restore-counter" (core func $restore))
  (func (export "increment") (result u64)
    (canon lift (core func $increment)))
  (func (export "value") (result u64)
    (canon lift (core func $value)))
  (func (export "freeze-counter") (result u64)
    (canon lift (core func $freeze)))
  (func (export "restore-counter") (param "counter" u64)
    (canon lift (core func $restore)))
)"#;

/// Compile the reusable counter WAT to Component bytes.
pub fn counter_component_bytes() -> Result<Vec<u8>, WasiError> {
    wat::parse_str(COUNTER_COMPONENT_WAT).map_err(|error| WasiError::Compile(error.to_string()))
}

/// Return the reusable counter WAT source.
#[must_use]
pub const fn counter_component_wat() -> &'static str {
    COUNTER_COMPONENT_WAT
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prepared() -> PreparedComponent<CounterProfile> {
        let bytes = counter_component_bytes().unwrap();
        WasiFrontend::new(CounterProfile::default()).preflight(&bytes).unwrap()
    }

    fn gate(execution_epoch: u64) -> ActivationGate {
        ActivationGate::for_active_source(&SnapshotContext::default(), execution_epoch)
    }

    #[test]
    fn preflight_rejects_exact_digest_and_profile_mismatch() {
        let bytes = counter_component_bytes().unwrap();
        let digest = component_digest(&bytes);
        let frontend = WasiFrontend::new(CounterProfile::default());
        let error = frontend
            .preflight_with_expectations(
                &bytes,
                PreflightExpectations::new(component_digest(b"wrong"), frontend.profile_ref()),
            )
            .unwrap_err();
        assert!(matches!(error, WasiError::ComponentDigestMismatch { .. }));
        let mut profile = frontend.profile_ref();
        profile.version.major = profile.version.major.saturating_add(1);
        let error = frontend
            .preflight_with_expectations(&bytes, PreflightExpectations::new(digest, profile))
            .unwrap_err();
        assert!(matches!(error, WasiError::ProfileRefMismatch { .. }));
    }

    #[test]
    fn instances_are_isolated_and_activation_is_required() {
        let prepared = prepared();
        let mut first = prepared.instantiate(7).unwrap();
        let mut second = prepared.instantiate(7).unwrap();
        assert!(matches!(first.increment(), Err(WasiError::ActivationRequired)));
        first.activate(&gate(7)).unwrap();
        second.activate(&gate(7)).unwrap();
        assert_eq!(first.increment().unwrap(), 1);
        assert_eq!(first.value().unwrap(), 1);
        assert_eq!(second.value().unwrap(), 0);
    }

    #[test]
    fn freeze_restore_is_monotonic_and_snapshot_has_no_host_token() {
        let prepared = prepared();
        let mut source = prepared.instantiate(7).unwrap();
        source.activate(&gate(7)).unwrap();
        assert_eq!(source.increment().unwrap(), 1);
        assert_eq!(source.increment().unwrap(), 2);
        let snapshot = source.freeze().unwrap();
        assert!(source.increment().is_err());
        assert_eq!(snapshot.body.resources.len(), 1);
        assert_eq!(snapshot.body.resources[0].logical_name, b"counter");
        let mut destination = prepared.instantiate(9).unwrap();
        destination.restore(&snapshot).unwrap();
        assert!(destination.increment().is_err());
        destination.activate(&gate(9)).unwrap();
        assert_eq!(destination.increment().unwrap(), 3);
    }

    #[test]
    fn staged_freeze_can_cancel_or_seal_after_provider_capture() {
        let prepared = prepared();
        let mut source = prepared.instantiate(7).unwrap();
        source.activate(&gate(7)).unwrap();
        assert_eq!(source.increment().unwrap(), 1);

        source.begin_freeze().unwrap();
        assert!(source.increment().is_err());
        source.cancel_freeze().unwrap();
        assert_eq!(source.increment().unwrap(), 2);

        source.begin_freeze().unwrap();
        let snapshot = source.complete_freeze(b"logical-session".to_vec(), Some(11)).unwrap();
        let decoded = CounterProfile::default().state_codec().decode(&snapshot.body.state).unwrap();
        assert_eq!(decoded.counter, 2);
        assert_eq!(decoded.session_key, b"logical-session");
        assert_eq!(decoded.last_seen_version, Some(11));
    }

    #[test]
    fn malformed_state_is_rejected() {
        let prepared = prepared();
        let mut source = prepared.instantiate(7).unwrap();
        source.activate(&gate(7)).unwrap();
        let mut snapshot = source.freeze().unwrap();
        snapshot.body.state.push(1);
        assert!(matches!(destination_restore(&prepared, &snapshot), Err(WasiError::Contract(_))));
    }

    fn destination_restore(
        prepared: &PreparedComponent<CounterProfile>,
        snapshot: &SnapshotEnvelope,
    ) -> Result<(), WasiError> {
        prepared.instantiate(7)?.restore(snapshot)
    }
}
