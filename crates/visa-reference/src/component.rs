//! Private Wasmtime Component frontend for the reference Counter/KV vertical.
//!
//! A prepared component and every Store/Instance are host-local. The single
//! Component import is the real durable-KV call used by the guest business
//! operation; its opaque binding handle never enters portable state.

use std::fmt;

use visa_core::{
    ActivationPermitReceipt, ContinuationId, ContractError, Digest, ExternalCoordinate,
    LineageAdvance, OpaqueBytes, PortableSnapshot, ScopeId, SnapshotEnvelope, SnapshotId,
    canonical_digest,
};
use wasmtime::component::types::ComponentItem;
use wasmtime::component::{Component, Instance, Linker, Type};
use wasmtime::{Config, Engine, Store};

use crate::profile::{DurableKvProfile, ProfileError};
use crate::provider::BindingHandle;

const KV_IMPORT: &str = "durable-kv-cas";

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ActivationGate {
    continuation: ContinuationId,
    snapshot: SnapshotId,
    runtime: ExternalCoordinate,
    execution_epoch: u64,
}

impl ActivationGate {
    pub(crate) fn from_activation_permit(receipt: &ActivationPermitReceipt) -> Self {
        Self {
            continuation: receipt.continuation,
            snapshot: receipt.snapshot,
            runtime: receipt.destination.clone(),
            execution_epoch: receipt.execution_epoch,
        }
    }

    pub(crate) fn for_active_source(context: &SnapshotContext, execution_epoch: u64) -> Self {
        Self {
            continuation: context.continuation,
            snapshot: context.snapshot,
            runtime: context.runtime.clone(),
            execution_epoch,
        }
    }
}

pub(crate) struct WasiFrontend;

impl WasiFrontend {
    pub(crate) fn preflight(component_bytes: &[u8]) -> Result<PreparedComponent, WasiError> {
        let engine = build_engine()?;
        let component = Component::new(&engine, component_bytes)
            .map_err(|error| WasiError::Compile(format!("{error:#}")))?;
        validate_component_contract(&component, &engine)?;
        let mut linker = Linker::new(&engine);
        linker
            .root()
            .func_wrap(
                KV_IMPORT,
                |mut store: wasmtime::StoreContextMut<'_, HostState>, (value,): (u64,)| {
                    let state = store.data_mut();
                    if !state.dispatch_open {
                        return Err(wasmtime::Error::msg("durable KV dispatch is closed"));
                    }
                    let entry = state
                        .binding
                        .cas(b"counter", state.last_seen_version, &value.to_be_bytes())
                        .map_err(|error| wasmtime::Error::msg(error.to_string()))?;
                    state.last_seen_version = Some(entry.revision);
                    Ok((entry.revision,))
                },
            )
            .map_err(|error| WasiError::InvalidContract(error.to_string()))?;
        Ok(PreparedComponent { engine, component, linker })
    }
}

fn build_engine() -> Result<Engine, WasiError> {
    let mut config = Config::new();
    config.wasm_component_model(true);
    Engine::new(&config).map_err(|error| WasiError::Engine(error.to_string()))
}

fn validate_component_contract(component: &Component, engine: &Engine) -> Result<(), WasiError> {
    let component_type = component.component_type();
    let mut imports = component_type.imports(engine);
    let Some((name, ComponentItem::ComponentFunc(function))) = imports.next() else {
        return Err(WasiError::InvalidContract(format!("missing function import `{KV_IMPORT}`")));
    };
    if name != KV_IMPORT || imports.next().is_some() {
        return Err(WasiError::UnknownImport(name.to_owned()));
    }
    let mut params = function.params();
    let mut results = function.results();
    if !matches!(params.next(), Some((_, Type::U64)))
        || params.next().is_some()
        || !matches!(results.next(), Some(Type::U64))
        || results.next().is_some()
    {
        return Err(WasiError::InvalidContract(format!(
            "import `{KV_IMPORT}` has the wrong component function type"
        )));
    }
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

pub(crate) struct PreparedComponent {
    engine: Engine,
    component: Component,
    linker: Linker<HostState>,
}

impl PreparedComponent {
    /// A continuation always receives a fresh Store and Component Instance.
    pub(crate) fn instantiate(
        &self,
        execution_epoch: u64,
        binding: BindingHandle,
    ) -> Result<WasiInstance, WasiError> {
        let mut store = Store::new(
            &self.engine,
            HostState { dispatch_open: false, binding, last_seen_version: None },
        );
        let instance = self
            .linker
            .instantiate(&mut store, &self.component)
            .map_err(|error| WasiError::Instantiate(error.to_string()))?;
        Ok(WasiInstance {
            store,
            instance,
            execution_epoch,
            activated: false,
            activation_prepared: false,
            frozen: false,
            restored: false,
            context: None,
            staged_counter: None,
            session_key: b"counter".to_vec(),
        })
    }
}

struct HostState {
    dispatch_open: bool,
    binding: BindingHandle,
    last_seen_version: Option<u64>,
}

pub(crate) struct WasiInstance {
    store: Store<HostState>,
    instance: Instance,
    execution_epoch: u64,
    activated: bool,
    activation_prepared: bool,
    frozen: bool,
    restored: bool,
    context: Option<SnapshotContext>,
    staged_counter: Option<u64>,
    session_key: Vec<u8>,
}

impl WasiInstance {
    pub(crate) fn set_snapshot_context(
        &mut self,
        context: SnapshotContext,
    ) -> Result<(), WasiError> {
        if self.restored || self.activated || self.activation_prepared || self.frozen {
            return Err(WasiError::ContextLocked);
        }
        self.context = Some(context);
        Ok(())
    }

    pub(crate) fn begin_continuation(&mut self, context: SnapshotContext) -> Result<(), WasiError> {
        if !self.activated || self.frozen {
            return Err(WasiError::ContextLocked);
        }
        self.context = Some(context);
        Ok(())
    }

    pub(crate) fn prepare_activation(&mut self, gate: &ActivationGate) -> Result<(), WasiError> {
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
        self.store.data_mut().dispatch_open = false;
        Ok(())
    }

    pub(crate) fn enable_activation(&mut self) -> Result<(), WasiError> {
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

    pub(crate) fn activate(&mut self, gate: &ActivationGate) -> Result<(), WasiError> {
        self.prepare_activation(gate)?;
        self.enable_activation()
    }

    pub(crate) fn increment(&mut self) -> Result<u64, WasiError> {
        self.require_dispatch()?;
        let function = self
            .instance
            .get_typed_func::<(), (u64,)>(&mut self.store, "increment")
            .map_err(|error| WasiError::MissingExport(error.to_string()))?;
        function
            .call(&mut self.store, ())
            .map(|result| result.0)
            .map_err(|error| WasiError::GuestTrap(error.to_string()))
    }

    pub(crate) fn value(&mut self) -> Result<u64, WasiError> {
        self.require_dispatch()?;
        let function = self
            .instance
            .get_typed_func::<(), (u64,)>(&mut self.store, "value")
            .map_err(|error| WasiError::MissingExport(error.to_string()))?;
        function
            .call(&mut self.store, ())
            .map(|result| result.0)
            .map_err(|error| WasiError::GuestTrap(error.to_string()))
    }

    pub(crate) fn last_seen_version(&self) -> Option<u64> {
        self.store.data().last_seen_version
    }

    pub(crate) fn binding(&self) -> &BindingHandle {
        &self.store.data().binding
    }

    pub(crate) fn begin_freeze(&mut self) -> Result<(), WasiError> {
        if !self.activated {
            return Err(WasiError::NotActivated);
        }
        if self.frozen {
            return Err(WasiError::AlreadyFrozen);
        }
        self.frozen = true;
        self.store.data_mut().dispatch_open = false;
        let function = self
            .instance
            .get_typed_func::<(), (u64,)>(&mut self.store, "freeze-counter")
            .map_err(|error| WasiError::MissingExport(error.to_string()))?;
        match function.call(&mut self.store, ()) {
            Ok(counter) => {
                self.staged_counter = Some(counter.0);
                Ok(())
            }
            Err(error) => {
                self.frozen = false;
                self.store.data_mut().dispatch_open = true;
                Err(WasiError::GuestTrap(error.to_string()))
            }
        }
    }

    pub(crate) fn complete_freeze(
        &mut self,
        session_key: Vec<u8>,
        last_seen_version: Option<u64>,
    ) -> Result<SnapshotEnvelope, WasiError> {
        let context = self.context.clone().ok_or(WasiError::SnapshotContextRequired)?;
        let counter = self.staged_counter.ok_or(WasiError::NotFrozen)?;
        let state = DurableKvProfile
            .capture_state(counter, session_key, last_seen_version)
            .map_err(WasiError::Profile)?;
        let bytes = DurableKvProfile.encode_state(&state).map_err(WasiError::Profile)?;
        let decoded = DurableKvProfile.decode_state(&bytes).map_err(WasiError::Profile)?;
        let resources = DurableKvProfile.requirements(&decoded).map_err(WasiError::Profile)?;
        let state_digest = Digest::of_bytes(&bytes);
        let snapshot = SnapshotEnvelope::seal(PortableSnapshot {
            snapshot: context.snapshot,
            continuation: context.continuation,
            scope: context.scope,
            semantic_domain: context.lineage.parent.semantic_domain.clone(),
            lineage: context.lineage,
            profile: DurableKvProfile.profile_ref(),
            source: context.runtime,
            semantic_cut: visa_core::SemanticCut {
                sequence: context.cut_sequence,
                safe_point_digest: canonical_digest(&(
                    b"guest-freeze-counter".as_slice(),
                    counter,
                    context.cut_sequence,
                ))
                .map_err(WasiError::Contract)?,
                admission_digest: canonical_digest(&(
                    b"provider-dispatch-closed".as_slice(),
                    self.store.data().binding.binding_id().as_bytes(),
                    self.store.data().binding.generation(),
                    self.store.data().binding.execution_epoch(),
                    last_seen_version,
                ))
                .map_err(WasiError::Contract)?,
            },
            state: OpaqueBytes(bytes),
            state_digest,
            resources,
            effect_closure: visa_core::EffectClosure::Empty,
        })
        .map_err(WasiError::Contract)?;
        self.session_key = decoded.session_key;
        self.store.data_mut().last_seen_version = decoded.last_seen_version;
        self.staged_counter = None;
        Ok(snapshot)
    }

    pub(crate) fn cancel_freeze(&mut self) -> Result<(), WasiError> {
        if !self.frozen {
            return Err(WasiError::NotFrozen);
        }
        self.frozen = false;
        self.activated = true;
        self.staged_counter = None;
        self.activation_prepared = false;
        self.store.data_mut().dispatch_open = true;
        Ok(())
    }

    pub(crate) fn restore(&mut self, snapshot: &SnapshotEnvelope) -> Result<(), WasiError> {
        if self.restored
            || self.activated
            || self.activation_prepared
            || self.frozen
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
            || snapshot.body.profile != DurableKvProfile.profile_ref()
        {
            return Err(WasiError::SnapshotContextMismatch);
        }
        let state =
            DurableKvProfile.decode_state(&snapshot.body.state.0).map_err(WasiError::Profile)?;
        DurableKvProfile
            .validate_resources(&state, &snapshot.body.resources)
            .map_err(WasiError::Profile)?;
        let function = self
            .instance
            .get_typed_func::<(u64,), ()>(&mut self.store, "restore-counter")
            .map_err(|error| WasiError::MissingExport(error.to_string()))?;
        function
            .call(&mut self.store, (state.counter,))
            .map_err(|error| WasiError::GuestTrap(error.to_string()))?;
        self.session_key = state.session_key;
        self.store.data_mut().last_seen_version = state.last_seen_version;
        self.restored = true;
        self.store.data_mut().dispatch_open = false;
        Ok(())
    }

    fn require_dispatch(&self) -> Result<(), WasiError> {
        if self.activated && !self.frozen && self.store.data().dispatch_open {
            Ok(())
        } else {
            Err(WasiError::ActivationRequired)
        }
    }
}

#[derive(Debug)]
pub(crate) enum WasiError {
    Engine(String),
    Compile(String),
    InvalidContract(String),
    UnknownImport(String),
    Instantiate(String),
    MissingExport(String),
    GuestTrap(String),
    Profile(ProfileError),
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Engine(e) => write!(f, "engine creation failed: {e}"),
            Self::Compile(e) => write!(f, "component compilation failed: {e}"),
            Self::InvalidContract(e) => write!(f, "invalid component contract: {e}"),
            Self::UnknownImport(name) => write!(f, "component import `{name}` is not supported"),
            Self::Instantiate(e) => write!(f, "component instantiation failed: {e}"),
            Self::MissingExport(e) => write!(f, "required export unavailable: {e}"),
            Self::GuestTrap(e) => write!(f, "guest call trapped: {e}"),
            Self::Profile(e) => write!(f, "counter/KV profile rejected state: {e}"),
            Self::Contract(e) => write!(f, "continuation contract rejected operation: {e}"),
            Self::ExecutionEpochMismatch { expected, actual } => {
                write!(f, "execution epoch mismatch: expected {expected}, got {actual}")
            }
            Self::ActivationGateMismatch => {
                f.write_str("activation gate does not bind this continuation target")
            }
            Self::SnapshotContextMismatch => {
                f.write_str("snapshot does not bind this continuation context")
            }
            Self::SnapshotContextRequired => {
                f.write_str("an explicit snapshot context is required")
            }
            Self::ContextLocked => f.write_str("snapshot context is already locked"),
            Self::NotActivated => f.write_str("freeze requires an activated instance"),
            Self::ActivationRequired => f.write_str("business call requires activation"),
            Self::AlreadyActivated => f.write_str("instance is already activated"),
            Self::ActivationAlreadyPrepared => f.write_str("activation is already prepared"),
            Self::AlreadyFrozen => f.write_str("instance is already frozen"),
            Self::NotFrozen => f.write_str("instance has no staged freeze"),
            Self::RestoreRequiresFresh => f.write_str("restore requires a fresh, unused instance"),
        }
    }
}
impl std::error::Error for WasiError {}

const COUNTER_COMPONENT_WAT: &str = r#"(component
  (import "durable-kv-cas" (func $durable-kv-cas (param "value" u64) (result u64)))
  (core func $durable-kv-cas-lowered (canon lower (func $durable-kv-cas)))
  (core instance $host
    (export "cas" (func $durable-kv-cas-lowered)))
  (core module $counter
    (import "host" "cas" (func $cas (param i64) (result i64)))
    (global $counter (mut i64) (i64.const 0))
    (func $increment (result i64)
      (global.set $counter (i64.add (global.get $counter) (i64.const 1)))
      (drop (call $cas (global.get $counter)))
      (global.get $counter))
    (func $value (result i64) (global.get $counter))
    (func $freeze (result i64) (global.get $counter))
    (func $restore (param i64) (global.set $counter (local.get 0)))
    (export "increment" (func $increment)) (export "value" (func $value))
    (export "freeze-counter" (func $freeze)) (export "restore-counter" (func $restore)))
  (core instance $counter (instantiate $counter (with "host" (instance $host))))
  (alias core export $counter "increment" (core func $increment))
  (alias core export $counter "value" (core func $value))
  (alias core export $counter "freeze-counter" (core func $freeze))
  (alias core export $counter "restore-counter" (core func $restore))
  (func (export "increment") (result u64) (canon lift (core func $increment)))
  (func (export "value") (result u64) (canon lift (core func $value)))
  (func (export "freeze-counter") (result u64) (canon lift (core func $freeze)))
  (func (export "restore-counter") (param "counter" u64) (canon lift (core func $restore))))"#;

pub(crate) fn counter_component_bytes() -> Result<Vec<u8>, WasiError> {
    wat::parse_str(COUNTER_COMPONENT_WAT).map_err(|error| WasiError::Compile(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::WasiFrontend;

    #[test]
    fn incompatible_component_contract_is_rejected_at_preflight() {
        let incompatible = wat::parse_str("(component)").expect("valid empty component");
        assert!(WasiFrontend::preflight(&incompatible).is_err());
    }
}
