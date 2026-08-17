//! Real Wasmtime Component frontend for the first vISA continuation path.
//!
//! The component contract is intentionally small and scalar:
//! `increment() -> u64`, `value() -> u64`, `freeze-counter() -> u64`, and
//! `restore-counter(u64)`.  Wasmtime's [`Engine`], [`Component`], [`Store`],
//! and [`Instance`] are kept in opaque host-local types.  Portable state is
//! always the canonical [`visa_core::SnapshotEnvelope`] produced by the
//! selected [`WasiProfile`]; no runtime object is copied into it.
//!
//! [`ProfileRef`] is the portable compatibility boundary.  It identifies the
//! profile contract and state schema, not one particular component binary.
//! [`ComponentDigest`] is instead an embedding-local preflight identity: an
//! embedding may require an exact artifact before preparing an instance, but
//! the digest is intentionally not part of portable snapshot compatibility.

use std::fmt;

use visa_core::{
    AuthorityCommitReceipt, ContinuationId, ContractError, Digest, ExternalCoordinate,
    LineageAdvance, PortableSnapshot, ProfileRef, SafePointReceipt, ScopeId, SnapshotEnvelope,
    SnapshotId, SourceSemanticCut,
};
use visa_profile::{ContinuityProfile, CounterSessionState, DurableKvProfile, PortableStateCodec};
use wasmtime::component::types::ComponentItem;
use wasmtime::component::{Component, Instance, Linker, Type};
use wasmtime::{Config, Engine, Store};

/// The exact component digest type owned by `visa-core`.
pub type ComponentDigest = Digest;

/// A profile adapter for the scalar counter component.
///
/// The profile owns typed encoding, strict decoding, validation, and logical
/// resource requirements.  The frontend only transports the resulting bytes.
pub trait WasiProfile: ContinuityProfile + Clone + Send + Sync + 'static {
    /// Build the associated typed state at the runtime's cooperative cut.
    ///
    /// The scalar counter and session metadata are frontend inputs only; the
    /// profile decides how (or whether) they belong in its portable state.
    fn capture_state(
        &self,
        counter: u64,
        session_key: Vec<u8>,
        last_seen_version: Option<u64>,
    ) -> Result<Self::State, ProfileError>;

    /// Project the profile state back into the scalar runtime contract.
    fn runtime_counter(&self, state: &Self::State) -> u64;

    /// Return frontend session metadata retained for a subsequent capture.
    /// A profile may return empty/default metadata when it does not use it.
    fn session_metadata(&self, state: &Self::State) -> (Vec<u8>, Option<u64>);

    /// Return initial metadata for a fresh instance.  The default is only a
    /// compatibility value for profiles that use the first scalar example;
    /// profiles with different metadata requirements should override it.
    fn initial_session_metadata(&self) -> (Vec<u8>, Option<u64>) {
        (b"counter".to_vec(), None)
    }

    /// Encode the complete typed portable state using the profile's codec.
    fn encode_state(&self, state: &Self::State) -> Result<Vec<u8>, ProfileError> {
        self.state_codec().encode(state).map_err(|error| ProfileError::new(format!("{error:?}")))
    }

    /// Strictly decode and validate one complete typed portable state.
    fn decode_state(&self, bytes: &[u8]) -> Result<Self::State, ProfileError> {
        let state = self
            .state_codec()
            .decode(bytes)
            .map_err(|error| ProfileError::new(format!("{error:?}")))?;
        self.validate_state(&state).map_err(|error| ProfileError::new(format!("{error:?}")))?;
        Ok(state)
    }
}

/// The first profile's typed state codec is reusable by this frontend.
pub type CounterProfile = DurableKvProfile;

impl WasiProfile for DurableKvProfile {
    fn capture_state(
        &self,
        counter: u64,
        session_key: Vec<u8>,
        last_seen_version: Option<u64>,
    ) -> Result<Self::State, ProfileError> {
        let state = CounterSessionState { counter, session_key, last_seen_version };
        ContinuityProfile::validate_state(self, &state)
            .map_err(|error| ProfileError::new(format!("{error:?}")))?;
        Ok(state)
    }

    fn runtime_counter(&self, state: &Self::State) -> u64 {
        state.counter
    }

    fn session_metadata(&self, state: &Self::State) -> (Vec<u8>, Option<u64>) {
        (state.session_key.clone(), state.last_seen_version)
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

    fn from_profile(error: visa_profile::ProfileError) -> Self {
        Self::new(format!("{error:?}"))
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

/// Inputs needed to seal a core snapshot.
///
/// There is intentionally no `Default` implementation: these coordinates are
/// owned by the embedding coordinator and silently substituting test values
/// would permit a runtime to activate or seal against the wrong continuation.
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

/// Embedding-local component identity and portable profile identity required
/// for exact preflight.  The component digest is not a portable profile key.
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
/// code.  The profile is copied into each fresh prepared instance.  Digest
/// expectations are an embedding-local artifact check; they do not narrow the
/// portable [`ProfileRef`] compatibility boundary.
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
        let actual_digest = component_digest(component_bytes);
        self.preflight_validated(
            component_bytes,
            actual_digest,
            PreflightExpectations::new(
                self.expected_component_digest.unwrap_or(actual_digest),
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
        self.preflight_validated(component_bytes, actual_digest, expectations)
    }

    fn preflight_validated(
        &self,
        component_bytes: &[u8],
        actual_digest: ComponentDigest,
        expectations: PreflightExpectations,
    ) -> Result<PreparedComponent<P>, WasiError> {
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
        let linker = Linker::<HostState>::new(&engine);
        Ok(PreparedComponent {
            engine,
            component,
            linker,
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
/// implementation and never appears in a portable snapshot.  Its digest is
/// useful for local preflight/audit decisions, not as portable state identity.
pub struct PreparedComponent<P> {
    engine: Engine,
    component: Component,
    linker: Linker<HostState>,
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
        let (session_key, last_seen_version) = self.profile.initial_session_metadata();
        let mut store = Store::new(&self.engine, HostState { dispatch_open: false });
        let instance = self
            .linker
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
            restored: false,
            context: None,
            safe_point: None,
            staged_counter: None,
            session_key,
            last_seen_version,
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
    restored: bool,
    context: Option<SnapshotContext>,
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
            .field("restored", &self.restored)
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
        // A successful restore binds this instance to the context it used;
        // callers must create a fresh instance for a different snapshot.
        if self.restored || self.activated || self.activation_prepared || self.frozen {
            return Err(WasiError::ContextLocked);
        }
        self.context = Some(context);
        Ok(())
    }

    /// Bind the next continuation cut on an already active source. This
    /// changes only portable semantic coordinates; it does not replace the
    /// runtime instance or reopen a frozen dispatch path.
    pub fn begin_continuation(&mut self, context: SnapshotContext) -> Result<(), WasiError> {
        if !self.activated || self.frozen {
            return Err(WasiError::ContextLocked);
        }
        self.context = Some(context);
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
        self.profile
            .capture_state(0, session_key.clone(), last_seen_version)
            .map_err(WasiError::ProfileValidation)?;
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
        if self.frozen {
            return Err(WasiError::AlreadyFrozen);
        }
        if self.activated {
            return Err(WasiError::AlreadyActivated);
        }
        if self.activation_prepared {
            return Err(WasiError::ActivationAlreadyPrepared);
        }
        let Some(context) = self.context.as_ref() else {
            return Err(WasiError::SnapshotContextRequired);
        };
        if gate.continuation != context.continuation
            || gate.snapshot != context.snapshot
            || gate.runtime != context.runtime
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
        if self.frozen {
            return Err(WasiError::AlreadyFrozen);
        }
        if !self.activation_prepared {
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
        let context = self.context.clone().ok_or(WasiError::SnapshotContextRequired)?;
        let counter = self.staged_counter.ok_or(WasiError::NotFrozen)?;
        let typed_state = self
            .profile
            .capture_state(counter, session_key, last_seen_version)
            .map_err(WasiError::ProfileValidation)?;
        let state = self.profile.encode_state(&typed_state).map_err(WasiError::ProfileEncoding)?;
        let decoded = self.profile.decode_state(&state).map_err(WasiError::ProfileDecoding)?;
        let resources = ContinuityProfile::resource_requirements(&self.profile, &decoded)
            .map_err(|error| WasiError::ProfileValidation(ProfileError::from_profile(error)))?;
        let state_digest = Digest::of_bytes(&state);
        let safe_point = SafePointReceipt {
            continuation: context.continuation,
            scope: context.scope,
            runtime: context.runtime.clone(),
            cut_sequence: context.cut_sequence,
            portable_state_digest: state_digest,
            receipt_digest: Digest::ZERO,
        }
        .seal()
        .map_err(WasiError::Contract)?;
        let body = PortableSnapshot {
            snapshot: context.snapshot,
            continuation: context.continuation,
            scope: context.scope,
            lineage: context.lineage.clone(),
            profile: self.profile.profile_ref(),
            source_cut: SourceSemanticCut {
                runtime: context.runtime.clone(),
                cut_sequence: context.cut_sequence,
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
        (self.session_key, self.last_seen_version) = self.profile.session_metadata(&typed_state);
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
        // Defensive cleanup: activation preparation must never survive a
        // cancelled safe-point attempt, even if a future path stages it
        // before freezing.
        self.activation_prepared = false;
        self.store.data_mut().dispatch_open = true;
        Ok(())
    }

    /// Convenience path for frontends without an external provider cut.
    pub fn freeze(&mut self) -> Result<SnapshotEnvelope, WasiError> {
        self.begin_freeze()?;
        self.complete_freeze(self.session_key.clone(), self.last_seen_version)
    }

    /// Verify the core envelope/profile/schema and restore into a fresh
    /// destination.  A successful restore is one-shot and locks the
    /// instance's snapshot context; activation remains closed until a matching
    /// receipt.
    pub fn restore(&mut self, snapshot: &SnapshotEnvelope) -> Result<(), WasiError> {
        if self.restored
            || self.activated
            || self.activation_prepared
            || self.frozen
            || self.safe_point.is_some()
            || self.staged_counter.is_some()
        {
            return Err(WasiError::RestoreRequiresFresh);
        }
        snapshot.verify().map_err(WasiError::Contract)?;
        let context = self.context.as_ref().ok_or(WasiError::SnapshotContextRequired)?;
        if snapshot.body.continuation != context.continuation
            || snapshot.body.snapshot != context.snapshot
            || snapshot.body.scope != context.scope
            || snapshot.body.lineage != context.lineage
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
        ContinuityProfile::validate_resources(&self.profile, &state, &snapshot.body.resources)
            .map_err(|error| WasiError::ProfileValidation(ProfileError::from_profile(error)))?;
        let function = self
            .instance
            .get_typed_func::<(u64,), ()>(&mut self.store, "restore-counter")
            .map_err(|error| WasiError::MissingExport(error.to_string()))?;
        function
            .call(&mut self.store, (self.profile.runtime_counter(&state),))
            .map_err(|error| WasiError::GuestTrap(error.to_string()))?;
        (self.session_key, self.last_seen_version) = self.profile.session_metadata(&state);
        self.frozen = false;
        self.activated = false;
        self.activation_prepared = false;
        self.safe_point = None;
        self.staged_counter = None;
        self.restored = true;
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
    SnapshotContextRequired,
    ContextLocked,
    NotActivated,
    ActivationRequired,
    AlreadyActivated,
    ActivationAlreadyPrepared,
    AlreadyFrozen,
    NotFrozen,
    RestoreRequiresFresh,
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
            Self::SnapshotContextRequired => {
                formatter.write_str("an explicit snapshot context is required")
            }
            Self::ContextLocked => formatter.write_str("snapshot context is already locked"),
            Self::NotActivated => formatter.write_str("freeze requires an activated instance"),
            Self::ActivationRequired => formatter.write_str("business call requires activation"),
            Self::AlreadyActivated => formatter.write_str("instance is already activated"),
            Self::ActivationAlreadyPrepared => {
                formatter.write_str("activation is already prepared")
            }
            Self::AlreadyFrozen => formatter.write_str("instance is already frozen"),
            Self::NotFrozen => formatter.write_str("instance has no staged freeze"),
            Self::RestoreRequiresFresh => {
                formatter.write_str("restore requires a fresh, unused instance")
            }
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
    use visa_profile::{
        ApplicationRecoveryDecision, CodecError, PortableStateCodec,
        ProfileError as ProfileSdkError,
    };

    fn prepared() -> PreparedComponent<CounterProfile> {
        let bytes = counter_component_bytes().unwrap();
        WasiFrontend::new(CounterProfile::default()).preflight(&bytes).unwrap()
    }

    fn context() -> SnapshotContext {
        SnapshotContext {
            snapshot: SnapshotId::from_u128(1),
            continuation: ContinuationId::from_u128(1),
            scope: ScopeId::from_u128(1),
            lineage: LineageAdvance {
                parent: visa_core::LineagePoint {
                    lineage: visa_core::LineageId::from_u128(1),
                    generation: 0,
                    state_digest: Digest::ZERO,
                },
                successor_generation: 1,
            },
            runtime: ExternalCoordinate {
                authority: visa_core::AuthorityId::from_u128(1),
                value: b"wasmtime".to_vec(),
            },
            cut_sequence: 0,
            receipt_digest: Digest::ZERO,
        }
    }

    fn gate(execution_epoch: u64) -> ActivationGate {
        let context = context();
        ActivationGate::for_active_source(&context, execution_epoch)
    }

    fn activate(instance: &mut WasiInstance<CounterProfile>, execution_epoch: u64) {
        instance.set_snapshot_context(context()).unwrap();
        instance.activate(&gate(execution_epoch)).unwrap();
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
        activate(&mut first, 7);
        activate(&mut second, 7);
        assert_eq!(first.increment().unwrap(), 1);
        assert_eq!(first.value().unwrap(), 1);
        assert_eq!(second.value().unwrap(), 0);
    }

    #[test]
    fn freeze_restore_is_monotonic_and_snapshot_has_no_host_token() {
        let prepared = prepared();
        let mut source = prepared.instantiate(7).unwrap();
        activate(&mut source, 7);
        assert_eq!(source.increment().unwrap(), 1);
        assert_eq!(source.increment().unwrap(), 2);
        let snapshot = source.freeze().unwrap();
        assert!(source.increment().is_err());
        assert_eq!(snapshot.body.resources.len(), 1);
        assert_eq!(snapshot.body.resources[0].logical_name, b"counter");
        let mut destination = prepared.instantiate(9).unwrap();
        destination.set_snapshot_context(context()).unwrap();
        destination.restore(&snapshot).unwrap();
        assert!(destination.increment().is_err());
        destination.activate(&gate(9)).unwrap();
        assert_eq!(destination.increment().unwrap(), 3);
    }

    #[test]
    fn restore_requires_fresh_instance_once_and_locks_context() {
        let prepared = prepared();
        let mut source = prepared.instantiate(7).unwrap();
        activate(&mut source, 7);
        let snapshot = source.freeze().unwrap();

        let mut destination = prepared.instantiate(9).unwrap();
        destination.set_snapshot_context(context()).unwrap();
        destination.restore(&snapshot).unwrap();
        assert!(matches!(destination.restore(&snapshot), Err(WasiError::RestoreRequiresFresh)));
        assert!(matches!(
            destination.set_snapshot_context(context()),
            Err(WasiError::ContextLocked)
        ));

        let mut active = prepared.instantiate(9).unwrap();
        activate(&mut active, 9);
        assert!(matches!(active.restore(&snapshot), Err(WasiError::RestoreRequiresFresh)));
    }

    #[test]
    fn activation_guards_and_cancelled_freeze_clear_staged_defense() {
        let prepared = prepared();
        let mut source = prepared.instantiate(7).unwrap();
        activate(&mut source, 7);
        source.begin_freeze().unwrap();
        assert!(matches!(source.prepare_activation(&gate(7)), Err(WasiError::AlreadyFrozen)));

        // Exercise the cancellation defense even if a future path were to
        // stage activation before entering the freeze state.
        source.activation_prepared = true;
        source.cancel_freeze().unwrap();
        assert!(!source.activation_prepared);
        assert!(matches!(source.enable_activation(), Err(WasiError::ActivationRequired)));
        assert!(matches!(source.prepare_activation(&gate(7)), Err(WasiError::AlreadyActivated)));

        let mut staged = prepared.instantiate(7).unwrap();
        staged.set_snapshot_context(context()).unwrap();
        staged.prepare_activation(&gate(7)).unwrap();
        assert!(matches!(
            staged.prepare_activation(&gate(7)),
            Err(WasiError::ActivationAlreadyPrepared)
        ));
        staged.enable_activation().unwrap();
    }

    #[test]
    fn staged_freeze_can_cancel_or_seal_after_provider_capture() {
        let prepared = prepared();
        let mut source = prepared.instantiate(7).unwrap();
        activate(&mut source, 7);
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
        activate(&mut source, 7);
        let mut snapshot = source.freeze().unwrap();
        snapshot.body.state.push(1);
        assert!(matches!(destination_restore(&prepared, &snapshot), Err(WasiError::Contract(_))));
    }

    fn destination_restore(
        prepared: &PreparedComponent<CounterProfile>,
        snapshot: &SnapshotEnvelope,
    ) -> Result<(), WasiError> {
        let mut destination = prepared.instantiate(7)?;
        destination.set_snapshot_context(context())?;
        destination.restore(snapshot)
    }

    /// A deliberately different typed state and codec.  The frontend should
    /// only know how to obtain/project the scalar runtime value; the marker
    /// and its wire format belong entirely to this profile.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct MarkerState {
        counter: u64,
        marker: Vec<u8>,
    }

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    struct MarkerCodec;

    impl PortableStateCodec<MarkerState> for MarkerCodec {
        fn encode(&self, value: &MarkerState) -> Result<Vec<u8>, CodecError> {
            if value.marker.len() > u8::MAX as usize {
                return Err(CodecError::Oversize {
                    len: value.marker.len(),
                    max: u8::MAX as usize,
                });
            }
            let mut bytes = value.counter.to_le_bytes().to_vec();
            bytes.push(value.marker.len() as u8);
            bytes.extend_from_slice(&value.marker);
            Ok(bytes)
        }

        fn decode(&self, bytes: &[u8]) -> Result<MarkerState, CodecError> {
            if bytes.len() < 9 {
                return Err(CodecError::Deserialize);
            }
            let mut counter = [0; 8];
            counter.copy_from_slice(&bytes[..8]);
            let marker_len = bytes[8] as usize;
            if bytes.len() != 9 + marker_len {
                return if bytes.len() > 9 + marker_len {
                    Err(CodecError::TrailingBytes)
                } else {
                    Err(CodecError::Deserialize)
                };
            }
            Ok(MarkerState { counter: u64::from_le_bytes(counter), marker: bytes[9..].to_vec() })
        }
    }

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    struct MarkerProfile;

    impl ContinuityProfile for MarkerProfile {
        type State = MarkerState;
        type Codec = MarkerCodec;

        fn profile_ref(&self) -> ProfileRef {
            ProfileRef {
                id: visa_core::ProfileId::from_u128(2),
                version: visa_core::ProfileVersion { major: 1, minor: 0 },
                contract_digest: Digest::of_bytes(b"visa-wasi/test-marker/1"),
                state_schema: visa_core::SchemaRef {
                    id: visa_core::SchemaId::from_u128(2),
                    version: 1,
                },
            }
        }

        fn state_codec(&self) -> Self::Codec {
            MarkerCodec
        }

        fn validate_state(&self, state: &Self::State) -> Result<(), ProfileSdkError> {
            if state.marker.is_empty() {
                return Err(ProfileSdkError::EmptySessionKey);
            }
            if state.marker.len() > 32 {
                return Err(ProfileSdkError::SessionKeyTooLong);
            }
            Ok(())
        }

        fn resource_requirements(
            &self,
            state: &Self::State,
        ) -> Result<Vec<visa_core::ResourceRequirement>, ProfileSdkError> {
            self.validate_state(state)?;
            Ok(vec![visa_core::ResourceRequirement {
                id: visa_core::RequirementId::from_u128(2),
                kind: b"marker-resource".to_vec(),
                profile_data: Vec::new(),
                required_rights: visa_core::Rights(1),
                disposition: visa_core::RebindDisposition::Recreate,
                logical_name: state.marker.clone(),
            }])
        }

        fn validate_binding_grant(
            &self,
            requirement: &visa_core::ResourceRequirement,
            grant: &visa_core::BindingGrant,
        ) -> Result<(), ProfileSdkError> {
            if requirement.id != visa_core::RequirementId::from_u128(2)
                || grant.requirement != requirement.id
                || requirement.kind != b"marker-resource"
                || requirement.disposition != visa_core::RebindDisposition::Recreate
                || grant.granted_rights != visa_core::Rights(1)
            {
                return Err(ProfileSdkError::WrongRequirement);
            }
            Ok(())
        }

        fn validate_binding(
            &self,
            state: &Self::State,
            requirement: &visa_core::ResourceRequirement,
            grant: &visa_core::BindingGrant,
        ) -> Result<(), ProfileSdkError> {
            self.validate_state(state)?;
            self.validate_binding_grant(requirement, grant)?;
            if requirement.logical_name != state.marker {
                return Err(ProfileSdkError::WrongLogicalName);
            }
            Ok(())
        }

        fn project_effects(
            &self,
            receipts: &[visa_core::EffectClosureReceipt],
        ) -> ApplicationRecoveryDecision {
            if receipts.is_empty() {
                ApplicationRecoveryDecision::Continue
            } else {
                ApplicationRecoveryDecision::RecoveryRequired
            }
        }
    }

    impl WasiProfile for MarkerProfile {
        fn capture_state(
            &self,
            counter: u64,
            session_key: Vec<u8>,
            _last_seen_version: Option<u64>,
        ) -> Result<Self::State, ProfileError> {
            let state = MarkerState { counter, marker: session_key };
            self.validate_state(&state).map_err(ProfileError::from_profile)?;
            Ok(state)
        }

        fn runtime_counter(&self, state: &Self::State) -> u64 {
            state.counter
        }

        fn session_metadata(&self, state: &Self::State) -> (Vec<u8>, Option<u64>) {
            (state.marker.clone(), None)
        }
    }

    #[test]
    fn custom_profile_state_codec_and_binding_flow_through_frontend() {
        let bytes = counter_component_bytes().unwrap();
        let prepared = WasiFrontend::new(MarkerProfile).preflight(&bytes).unwrap();
        let mut source = prepared.instantiate(7).unwrap();
        source.set_snapshot_context(context()).unwrap();
        source.activate(&gate(7)).unwrap();
        assert_eq!(source.increment().unwrap(), 1);
        source.begin_freeze().unwrap();
        let snapshot = source.complete_freeze(b"marker-v1".to_vec(), Some(99)).unwrap();

        let state = MarkerCodec.decode(&snapshot.body.state).unwrap();
        assert_eq!(state, MarkerState { counter: 1, marker: b"marker-v1".to_vec() });
        assert_eq!(snapshot.body.profile, MarkerProfile.profile_ref());
        let requirement = &snapshot.body.resources[0];
        let grant = visa_core::BindingGrant {
            requirement: requirement.id,
            provider: ExternalCoordinate {
                authority: visa_core::AuthorityId::from_u128(2),
                value: b"provider".to_vec(),
            },
            provider_generation: 1,
            binding: ExternalCoordinate {
                authority: visa_core::AuthorityId::from_u128(2),
                value: b"binding".to_vec(),
            },
            granted_rights: visa_core::Rights(1),
        };
        MarkerProfile.validate_binding(&state, requirement, &grant).unwrap();

        let mut destination = prepared.instantiate(9).unwrap();
        destination.set_snapshot_context(context()).unwrap();
        destination.restore(&snapshot).unwrap();
        destination.activate(&gate(9)).unwrap();
        assert_eq!(destination.increment().unwrap(), 2);
    }
}
