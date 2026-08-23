//! Runtime-owned half of the one Counter/KV continuation vertical.
//!
//! Exact operation results live in a runtime table. Wasmtime stores, instances,
//! and provider handles remain process-local: a receipt never fakes a live one.

use std::collections::HashMap;
use std::fmt;

use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use visa_coordinator::{Action, ActionRequest, CapturedSnapshot, Observation, RuntimePort};
use visa_core::{
    DestinationRestoreReceipt, Digest, ExternalCoordinate, OpaqueBytes, OperationId,
    RetirementReceipt, RuntimeActivationReceipt, RuntimePreparationReceipt, SnapshotEnvelope,
    SnapshotReceipt, SourceRestorationReceipt, canonical_digest,
};

pub use crate::component::SnapshotContext;

use crate::authority::{Authority, AuthorityError, REFERENCE_AUTHORITY_ID, SourceBinding};
use crate::component::{
    ActivationGate, PreparedComponent, WasiError, WasiFrontend, WasiInstance,
    counter_component_bytes,
};
use crate::db::{ReferenceDatabase, ReferenceDatabaseError, u64_to_sqlite};
use crate::profile::DurableKvProfile;
use crate::provider::{BindingHandle, DurableKvProvider, ProviderError};

#[derive(Debug)]
pub enum RuntimeError {
    Database(ReferenceDatabaseError),
    Authority(AuthorityError),
    Component(String),
    Provider(ProviderError),
    Rejected(String),
    Conflict(String),
    Corrupt(String),
    RetiredCapture,
    MissingSource,
    MissingPreparedInstance,
    NativeStateIndeterminate,
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(error) => write!(formatter, "runtime database error: {error}"),
            Self::Authority(error) => write!(formatter, "runtime authority error: {error}"),
            Self::Component(error) => write!(formatter, "Wasmtime component error: {error}"),
            Self::Provider(error) => write!(formatter, "durable KV provider error: {error}"),
            Self::Rejected(reason) => write!(formatter, "runtime rejected request: {reason}"),
            Self::Conflict(operation) => {
                write!(formatter, "conflicting runtime operation: {operation}")
            }
            Self::Corrupt(reason) => write!(formatter, "corrupt runtime outcome: {reason}"),
            Self::RetiredCapture => formatter.write_str("the durable source capture was retired"),
            Self::MissingSource => {
                formatter.write_str("source instance is unavailable in this process")
            }
            Self::MissingPreparedInstance => {
                formatter.write_str("prepared destination instance is unavailable in this process")
            }
            Self::NativeStateIndeterminate => formatter.write_str(
                "the exact runtime operation is durable but its host-local state is unavailable",
            ),
        }
    }
}
impl std::error::Error for RuntimeError {}
impl From<ReferenceDatabaseError> for RuntimeError {
    fn from(value: ReferenceDatabaseError) -> Self {
        Self::Database(value)
    }
}
impl From<AuthorityError> for RuntimeError {
    fn from(value: AuthorityError) -> Self {
        Self::Authority(value)
    }
}
impl From<rusqlite::Error> for RuntimeError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Database(value.into())
    }
}
impl From<WasiError> for RuntimeError {
    fn from(value: WasiError) -> Self {
        Self::Component(value.to_string())
    }
}
impl From<ProviderError> for RuntimeError {
    fn from(value: ProviderError) -> Self {
        Self::Provider(value)
    }
}

/// The sole reference runtime. Durable records contain receipts, not opaque
/// instance or binding material.
pub struct ReferenceRuntime {
    database: ReferenceDatabase,
    authority: Authority,
    provider: DurableKvProvider,
    prepared: PreparedComponent,
    source: Option<LiveSource>,
    destinations: HashMap<OperationId, PreparedDestination>,
}
struct LiveSource {
    coordinate: ExternalCoordinate,
    instance: WasiInstance,
    frozen_snapshot: Option<SnapshotEnvelope>,
}
struct PreparedDestination {
    instance: WasiInstance,
    snapshot: SnapshotEnvelope,
    destination: ExternalCoordinate,
    restored: bool,
    activated: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuntimeOperationKind {
    Capture,
    PrepareDestination,
    RestoreSource,
    RestoreDestination,
    Activate,
    Retire,
}
impl RuntimeOperationKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Capture => "capture",
            Self::PrepareDestination => "prepare_destination",
            Self::RestoreSource => "restore_source",
            Self::RestoreDestination => "restore_destination",
            Self::Activate => "activate",
            Self::Retire => "retire",
        }
    }
}
enum RuntimeOperationState {
    Applied(Vec<u8>),
    Rejected(String),
    Conflict(String),
    Armed,
    Retired,
    Absent,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct DurableCapture {
    snapshot: SnapshotEnvelope,
    receipt: SnapshotReceipt,
}

impl ReferenceRuntime {
    pub fn profile_ref() -> visa_core::ProfileRef {
        DurableKvProfile.profile_ref()
    }

    pub fn semantic_domain_ref() -> Result<visa_core::SemanticDomainRef, RuntimeError> {
        let bytes = counter_component_bytes()?;
        Ok(DurableKvProfile.semantic_domain(Digest::of_bytes(&bytes)))
    }

    /// Opens a query-only runtime after restart. It deliberately has no source.
    pub fn new(database: ReferenceDatabase, authority: Authority) -> Result<Self, RuntimeError> {
        initialize_runtime_tables(&database)?;
        let bytes = counter_component_bytes()?;
        Ok(Self {
            provider: DurableKvProvider::new(database.clone()),
            database,
            authority,
            prepared: WasiFrontend::preflight(&bytes)?,
            source: None,
            destinations: HashMap::new(),
        })
    }

    /// Starts the unique bootstrap source before its first capture.
    pub fn with_source(
        database: ReferenceDatabase,
        authority: Authority,
        source: SourceBinding,
    ) -> Result<Self, RuntimeError> {
        let mut runtime = Self::new(database, authority)?;
        let coordinate = binding_coordinate(&source.binding_id);
        let handle = runtime.provider.bind_bootstrap_source(&runtime.authority, &source)?;
        let mut instance = runtime.prepared.instantiate(source.execution_epoch, handle)?;
        let context = bootstrap_context(coordinate.clone());
        instance.set_snapshot_context(context.clone())?;
        instance.activate(&ActivationGate::for_active_source(&context, source.execution_epoch))?;
        runtime.source = Some(LiveSource { coordinate, instance, frozen_snapshot: None });
        Ok(runtime)
    }

    /// One reference business call: guest counter plus matching durable KV revision.
    pub fn increment_counter(&mut self) -> Result<(u64, u64), RuntimeError> {
        let source = self.source.as_mut().ok_or(RuntimeError::MissingSource)?;
        let counter = source.instance.increment()?;
        let revision = source.instance.last_seen_version().ok_or_else(|| {
            RuntimeError::Corrupt("guest increment returned without a durable KV revision".into())
        })?;
        Ok((counter, revision))
    }
    pub fn source_value(&mut self) -> Result<u64, RuntimeError> {
        self.source
            .as_mut()
            .ok_or(RuntimeError::MissingSource)?
            .instance
            .value()
            .map_err(Into::into)
    }
    pub fn destination_value(
        &mut self,
        preparation_operation: OperationId,
    ) -> Result<u64, RuntimeError> {
        self.destinations
            .get_mut(&preparation_operation)
            .ok_or(RuntimeError::MissingPreparedInstance)?
            .instance
            .value()
            .map_err(Into::into)
    }
    pub fn increment_destination_counter(
        &mut self,
        preparation_operation: OperationId,
    ) -> Result<(u64, u64), RuntimeError> {
        let destination = self
            .destinations
            .get_mut(&preparation_operation)
            .ok_or(RuntimeError::MissingPreparedInstance)?;
        let counter = destination.instance.increment()?;
        let revision = destination.instance.last_seen_version().ok_or_else(|| {
            RuntimeError::Corrupt("guest increment returned without a durable KV revision".into())
        })?;
        Ok((counter, revision))
    }
    pub fn destination_provider_value(
        &self,
        preparation_operation: OperationId,
    ) -> Result<Option<(Vec<u8>, u64)>, RuntimeError> {
        let destination = self
            .destinations
            .get(&preparation_operation)
            .ok_or(RuntimeError::MissingPreparedInstance)?;
        Ok(self
            .provider
            .get_for_handle(destination.instance.binding(), b"counter")?
            .map(|entry| (entry.value, entry.revision)))
    }
    /// A precise test fault cut: durable arm is present but no snapshot is sealed.
    #[doc(hidden)]
    pub fn arm_capture_without_sealing_for_test(
        &self,
        action: &Action,
    ) -> Result<(), RuntimeError> {
        require_kind(action, RuntimeOperationKind::Capture)?;
        match self.operation(action, RuntimeOperationKind::Capture)? {
            RuntimeOperationState::Absent => self.arm(action, RuntimeOperationKind::Capture),
            RuntimeOperationState::Armed => Ok(()),
            _ => Err(RuntimeError::Conflict(hex(&action.operation.0))),
        }
    }

    fn capture_action(&mut self, action: &Action) -> Result<CapturedSnapshot, RuntimeError> {
        require_kind(action, RuntimeOperationKind::Capture)?;
        match self.operation(action, RuntimeOperationKind::Capture)? {
            RuntimeOperationState::Applied(bytes) => return decode_capture(&bytes),
            RuntimeOperationState::Rejected(reason) => return Err(RuntimeError::Rejected(reason)),
            RuntimeOperationState::Conflict(reason) => return Err(RuntimeError::Conflict(reason)),
            RuntimeOperationState::Armed => {
                return Err(RuntimeError::Rejected(
                    "capture is armed without a sealed snapshot".into(),
                ));
            }
            RuntimeOperationState::Retired => return Err(RuntimeError::RetiredCapture),
            RuntimeOperationState::Absent => self.arm(action, RuntimeOperationKind::Capture)?,
        }
        let ActionRequest::Capture { continuation, scope, source, lineage_parent, profile } =
            &action.request
        else {
            return Err(RuntimeError::Rejected("not a capture action".into()));
        };
        if *profile != DurableKvProfile.profile_ref()
            || lineage_parent.semantic_domain != Self::semantic_domain_ref()?
        {
            return Err(RuntimeError::Rejected(
                "capture profile differs from reference profile".into(),
            ));
        }
        let provider = self.provider.clone();
        let live = self.source.as_mut().ok_or(RuntimeError::MissingSource)?;
        if &live.coordinate != source || live.frozen_snapshot.is_some() {
            return Err(RuntimeError::Rejected("capture source is not current".into()));
        }
        live.instance.begin_continuation(SnapshotContext {
            snapshot: snapshot_id(action.operation),
            continuation: *continuation,
            scope: *scope,
            lineage: visa_core::LineageAdvance {
                parent: lineage_parent.clone(),
                successor_generation: lineage_parent
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| RuntimeError::Rejected("lineage overflow".into()))?,
                successor_digest: Digest::ZERO,
            },
            runtime: source.clone(),
            cut_sequence: lineage_parent.generation,
            receipt_digest: Digest::ZERO,
        })?;
        live.instance.begin_freeze()?;
        let revision = match provider.capture_and_close(live.instance.binding(), b"counter") {
            Ok(entry) => entry.map(|value| value.revision),
            Err(error) => {
                let _ = live.instance.cancel_freeze();
                return Err(error.into());
            }
        };
        let snapshot = live.instance.complete_freeze(b"counter".to_vec(), revision)?;
        debug_assert_eq!(snapshot.body.profile, *profile);
        let receipt = SnapshotReceipt {
            operation: action.operation,
            request_digest: action.request_digest,
            continuation: *continuation,
            scope: *scope,
            snapshot: snapshot.body.snapshot,
            snapshot_digest: snapshot.body_digest,
            lineage: snapshot.body.lineage.clone(),
            profile: snapshot.body.profile.clone(),
            source: snapshot.body.source.clone(),
            semantic_cut: snapshot.body.semantic_cut,
            receipt_digest: Digest::ZERO,
        }
        .seal()
        .map_err(|error| RuntimeError::Rejected(error.to_string()))?;
        let captured = CapturedSnapshot { snapshot: snapshot.clone(), receipt };
        live.frozen_snapshot = Some(captured.snapshot.clone());
        let _ = live;
        self.persist_applied(
            action,
            RuntimeOperationKind::Capture,
            &DurableCapture { snapshot, receipt: captured.receipt.clone() },
        )?;
        Ok(captured)
    }

    fn prepare_destination_action(
        &mut self,
        action: &Action,
    ) -> Result<RuntimePreparationReceipt, RuntimeError> {
        require_kind(action, RuntimeOperationKind::PrepareDestination)?;
        match self.operation(action, RuntimeOperationKind::PrepareDestination)? {
            RuntimeOperationState::Applied(bytes) => {
                let receipt = decode(&bytes)?;
                self.materialize_preparation_action(action)?;
                return Ok(receipt);
            }
            RuntimeOperationState::Rejected(reason) => return Err(RuntimeError::Rejected(reason)),
            RuntimeOperationState::Conflict(reason) => return Err(RuntimeError::Conflict(reason)),
            RuntimeOperationState::Armed => {
                return Err(RuntimeError::NativeStateIndeterminate);
            }
            RuntimeOperationState::Retired => {
                return Err(RuntimeError::Corrupt(
                    "preparation operation is a capture tombstone".into(),
                ));
            }
            RuntimeOperationState::Absent => {
                self.arm(action, RuntimeOperationKind::PrepareDestination)?
            }
        }
        let ActionRequest::PrepareDestination { continuation, snapshot, destination, bindings } =
            &action.request
        else {
            return Err(RuntimeError::Rejected("not a prepare-destination action".into()));
        };
        validate_snapshot(snapshot, *continuation)?;
        bindings.verify().map_err(|error| RuntimeError::Rejected(error.to_string()))?;
        if bindings.continuation != *continuation
            || bindings.snapshot != snapshot.body.snapshot
            || bindings.snapshot_digest != snapshot.body_digest
            || bindings.destination != *destination
        {
            return Err(RuntimeError::Rejected(
                "binding preparation does not match snapshot".into(),
            ));
        }
        self.ensure_prepared(action.operation, snapshot, destination, bindings)?;
        let receipt = RuntimePreparationReceipt {
            operation: action.operation,
            continuation: *continuation,
            snapshot: snapshot.body.snapshot,
            snapshot_digest: snapshot.body_digest,
            destination: destination.clone(),
            binding_receipt_digest: bindings.receipt_digest,
            request_digest: action.request_digest,
            receipt_digest: Digest::ZERO,
        }
        .seal()
        .map_err(|error| RuntimeError::Rejected(error.to_string()))?;
        self.persist_applied(action, RuntimeOperationKind::PrepareDestination, &receipt)?;
        Ok(receipt)
    }

    fn restore_source_action(
        &mut self,
        action: &Action,
    ) -> Result<SourceRestorationReceipt, RuntimeError> {
        require_kind(action, RuntimeOperationKind::RestoreSource)?;
        match self.operation(action, RuntimeOperationKind::RestoreSource)? {
            RuntimeOperationState::Applied(bytes) => return decode(&bytes),
            RuntimeOperationState::Rejected(reason) => return Err(RuntimeError::Rejected(reason)),
            RuntimeOperationState::Conflict(reason) => return Err(RuntimeError::Conflict(reason)),
            RuntimeOperationState::Armed => {
                return Err(RuntimeError::Rejected("source restoration cannot be armed".into()));
            }
            RuntimeOperationState::Retired => {
                return Err(RuntimeError::Corrupt(
                    "source restore operation is a capture tombstone".into(),
                ));
            }
            RuntimeOperationState::Absent => {
                self.arm(action, RuntimeOperationKind::RestoreSource)?
            }
        }
        let ActionRequest::RestoreSource { continuation, source, snapshot } = &action.request
        else {
            return Err(RuntimeError::Rejected("not a restore-source action".into()));
        };
        validate_snapshot(snapshot, *continuation)?;
        let mut live = self.source.take().ok_or(RuntimeError::MissingSource)?;
        let result = (|| {
            if &live.coordinate != source || live.frozen_snapshot.as_ref() != Some(snapshot) {
                return Err(RuntimeError::Rejected(
                    "source restoration is not for the frozen snapshot".into(),
                ));
            }
            reopen_source_dispatch(&self.database, live.instance.binding())?;
            live.instance.cancel_freeze()?;
            let receipt = SourceRestorationReceipt {
                operation: action.operation,
                continuation: *continuation,
                snapshot: snapshot.body.snapshot,
                snapshot_digest: snapshot.body_digest,
                source: source.clone(),
                execution_epoch: live.instance.binding().execution_epoch(),
                request_digest: action.request_digest,
                receipt_digest: Digest::ZERO,
            }
            .seal()
            .map_err(|error| RuntimeError::Rejected(error.to_string()))?;
            self.persist_applied(action, RuntimeOperationKind::RestoreSource, &receipt)?;
            live.frozen_snapshot = None;
            Ok(receipt)
        })();
        self.source = Some(live);
        result
    }

    fn restore_destination_action(
        &mut self,
        action: &Action,
    ) -> Result<DestinationRestoreReceipt, RuntimeError> {
        require_kind(action, RuntimeOperationKind::RestoreDestination)?;
        match self.operation(action, RuntimeOperationKind::RestoreDestination)? {
            RuntimeOperationState::Applied(bytes) => {
                let receipt = decode(&bytes)?;
                self.materialize_restoration_action(action)?;
                return Ok(receipt);
            }
            RuntimeOperationState::Rejected(reason) => return Err(RuntimeError::Rejected(reason)),
            RuntimeOperationState::Conflict(reason) => return Err(RuntimeError::Conflict(reason)),
            RuntimeOperationState::Armed => {
                return Err(RuntimeError::NativeStateIndeterminate);
            }
            RuntimeOperationState::Retired => {
                return Err(RuntimeError::Corrupt(
                    "destination restore operation is a capture tombstone".into(),
                ));
            }
            RuntimeOperationState::Absent => {
                self.arm(action, RuntimeOperationKind::RestoreDestination)?
            }
        }
        let ActionRequest::RestoreDestination {
            continuation,
            destination,
            snapshot,
            preparation,
            bindings,
        } = &action.request
        else {
            return Err(RuntimeError::Rejected("not a restore-destination action".into()));
        };
        validate_snapshot(snapshot, *continuation)?;
        preparation.verify().map_err(|error| RuntimeError::Rejected(error.to_string()))?;
        bindings.verify().map_err(|error| RuntimeError::Rejected(error.to_string()))?;
        if preparation.continuation != *continuation
            || preparation.snapshot != snapshot.body.snapshot
            || preparation.snapshot_digest != snapshot.body_digest
            || preparation.destination != *destination
            || bindings.snapshot != snapshot.body.snapshot
            || bindings.snapshot_digest != snapshot.body_digest
        {
            return Err(RuntimeError::Rejected(
                "destination receipts do not match snapshot".into(),
            ));
        }
        self.ensure_restored(preparation, snapshot, destination, bindings)?;
        let receipt = DestinationRestoreReceipt {
            operation: action.operation,
            continuation: *continuation,
            snapshot: snapshot.body.snapshot,
            snapshot_digest: snapshot.body_digest,
            destination: destination.clone(),
            preparation_receipt_digest: preparation.receipt_digest,
            request_digest: action.request_digest,
            receipt_digest: Digest::ZERO,
        }
        .seal()
        .map_err(|error| RuntimeError::Rejected(error.to_string()))?;
        self.persist_applied(action, RuntimeOperationKind::RestoreDestination, &receipt)?;
        Ok(receipt)
    }

    fn activate_action(
        &mut self,
        action: &Action,
    ) -> Result<RuntimeActivationReceipt, RuntimeError> {
        require_kind(action, RuntimeOperationKind::Activate)?;
        match self.operation(action, RuntimeOperationKind::Activate)? {
            RuntimeOperationState::Applied(bytes) => {
                let receipt = decode(&bytes)?;
                self.materialize_activation_action(action)?;
                return Ok(receipt);
            }
            RuntimeOperationState::Rejected(reason) => return Err(RuntimeError::Rejected(reason)),
            RuntimeOperationState::Conflict(reason) => return Err(RuntimeError::Conflict(reason)),
            RuntimeOperationState::Armed => {
                return Err(RuntimeError::NativeStateIndeterminate);
            }
            RuntimeOperationState::Retired => {
                return Err(RuntimeError::Corrupt(
                    "activation operation is a capture tombstone".into(),
                ));
            }
            RuntimeOperationState::Absent => self.arm(action, RuntimeOperationKind::Activate)?,
        }
        let ActionRequest::Activate { continuation, destination, snapshot, preparation, permit } =
            &action.request
        else {
            return Err(RuntimeError::Rejected("not an activate action".into()));
        };
        validate_snapshot(snapshot, *continuation)?;
        preparation.verify().map_err(|error| RuntimeError::Rejected(error.to_string()))?;
        permit.verify().map_err(|error| RuntimeError::Rejected(error.to_string()))?;
        if preparation.continuation != *continuation
            || preparation.snapshot != snapshot.body.snapshot
            || preparation.snapshot_digest != snapshot.body_digest
            || preparation.destination != *destination
            || permit.continuation != *continuation
            || permit.snapshot != snapshot.body.snapshot
            || permit.snapshot_digest != snapshot.body_digest
            || permit.destination != *destination
        {
            return Err(RuntimeError::Rejected(
                "activation material does not match snapshot".into(),
            ));
        }
        let bindings = self.authority.preparation_by_digest(preparation.binding_receipt_digest)?;
        self.ensure_activated(preparation, snapshot, destination, &bindings, permit)?;
        let receipt = RuntimeActivationReceipt {
            operation: action.operation,
            continuation: *continuation,
            snapshot: snapshot.body.snapshot,
            snapshot_digest: snapshot.body_digest,
            destination: destination.clone(),
            activation_permit_digest: permit.receipt_digest,
            request_digest: action.request_digest,
            receipt_digest: Digest::ZERO,
        }
        .seal()
        .map_err(|error| RuntimeError::Rejected(error.to_string()))?;
        self.persist_applied(action, RuntimeOperationKind::Activate, &receipt)?;
        Ok(receipt)
    }

    fn retire_action(&mut self, action: &Action) -> Result<RetirementReceipt, RuntimeError> {
        require_kind(action, RuntimeOperationKind::Retire)?;
        match self.operation(action, RuntimeOperationKind::Retire)? {
            RuntimeOperationState::Applied(bytes) => return decode(&bytes),
            RuntimeOperationState::Rejected(reason) => return Err(RuntimeError::Rejected(reason)),
            RuntimeOperationState::Conflict(reason) => return Err(RuntimeError::Conflict(reason)),
            RuntimeOperationState::Armed => {
                return Err(RuntimeError::Rejected("retirement cannot be armed".into()));
            }
            RuntimeOperationState::Retired => {
                return Err(RuntimeError::Corrupt(
                    "retirement operation is a capture tombstone".into(),
                ));
            }
            RuntimeOperationState::Absent => {}
        }
        let ActionRequest::Retire {
            continuation,
            snapshot,
            snapshot_digest,
            source,
            runtime_activation,
        } = &action.request
        else {
            return Err(RuntimeError::Rejected("not a retire action".into()));
        };
        runtime_activation.verify().map_err(|error| RuntimeError::Rejected(error.to_string()))?;
        if runtime_activation.continuation != *continuation
            || runtime_activation.snapshot != *snapshot
            || runtime_activation.snapshot_digest != *snapshot_digest
            || runtime_activation.destination.authority != REFERENCE_AUTHORITY_ID
        {
            return Err(RuntimeError::Rejected(
                "retirement activation does not match request".into(),
            ));
        }
        let receipt = RetirementReceipt {
            operation: action.operation,
            continuation: *continuation,
            snapshot: *snapshot,
            snapshot_digest: *snapshot_digest,
            source: source.clone(),
            runtime_activation_receipt_digest: runtime_activation.receipt_digest,
            request_digest: action.request_digest,
            receipt_digest: Digest::ZERO,
        }
        .seal()
        .map_err(|error| RuntimeError::Rejected(error.to_string()))?;
        self.persist_retirement(action, &receipt, *snapshot)?;
        Ok(receipt)
    }

    fn materialize_preparation_action(&mut self, action: &Action) -> Result<(), RuntimeError> {
        let ActionRequest::PrepareDestination { snapshot, destination, bindings, .. } =
            &action.request
        else {
            return Err(RuntimeError::Rejected("not a prepare-destination action".into()));
        };
        self.ensure_prepared(action.operation, snapshot, destination, bindings)
    }

    fn materialize_restoration_action(&mut self, action: &Action) -> Result<(), RuntimeError> {
        let ActionRequest::RestoreDestination {
            destination, snapshot, preparation, bindings, ..
        } = &action.request
        else {
            return Err(RuntimeError::Rejected("not a restore-destination action".into()));
        };
        self.ensure_restored(preparation, snapshot, destination, bindings)
    }

    fn materialize_activation_action(&mut self, action: &Action) -> Result<(), RuntimeError> {
        let ActionRequest::Activate { destination, snapshot, preparation, permit, .. } =
            &action.request
        else {
            return Err(RuntimeError::Rejected("not an activate action".into()));
        };
        let bindings = self.authority.preparation_by_digest(preparation.binding_receipt_digest)?;
        self.ensure_activated(preparation, snapshot, destination, &bindings, permit)
    }

    fn ensure_prepared(
        &mut self,
        operation: OperationId,
        snapshot: &SnapshotEnvelope,
        destination: &ExternalCoordinate,
        bindings: &visa_core::BindingPreparationReceipt,
    ) -> Result<(), RuntimeError> {
        validate_snapshot(snapshot, bindings.continuation)?;
        bindings.verify().map_err(|error| RuntimeError::Rejected(error.to_string()))?;
        if bindings.snapshot != snapshot.body.snapshot
            || bindings.snapshot_digest != snapshot.body_digest
            || bindings.destination != *destination
        {
            return Err(RuntimeError::Rejected(
                "binding preparation does not match destination recipe".into(),
            ));
        }
        if let Some(prepared) = self.destinations.get(&operation) {
            if prepared.snapshot != *snapshot || prepared.destination != *destination {
                return Err(RuntimeError::Conflict(hex(&operation.0)));
            }
            return Ok(());
        }
        let handle = self.provider.bind_destination(&self.authority, &bindings.operation.0)?;
        let mut instance = self.prepared.instantiate(handle.execution_epoch(), handle)?;
        instance.set_snapshot_context(snapshot_context(snapshot, destination.clone()))?;
        self.destinations.insert(
            operation,
            PreparedDestination {
                instance,
                snapshot: snapshot.clone(),
                destination: destination.clone(),
                restored: false,
                activated: false,
            },
        );
        Ok(())
    }

    fn ensure_restored(
        &mut self,
        preparation: &RuntimePreparationReceipt,
        snapshot: &SnapshotEnvelope,
        destination: &ExternalCoordinate,
        bindings: &visa_core::BindingPreparationReceipt,
    ) -> Result<(), RuntimeError> {
        preparation.verify().map_err(|error| RuntimeError::Rejected(error.to_string()))?;
        if preparation.snapshot != snapshot.body.snapshot
            || preparation.snapshot_digest != snapshot.body_digest
            || preparation.destination != *destination
            || preparation.binding_receipt_digest != bindings.receipt_digest
        {
            return Err(RuntimeError::Rejected(
                "runtime preparation does not match restore recipe".into(),
            ));
        }
        self.ensure_prepared(preparation.operation, snapshot, destination, bindings)?;
        validate_resource_bindings(snapshot, bindings)?;
        let prepared = self
            .destinations
            .get_mut(&preparation.operation)
            .ok_or(RuntimeError::MissingPreparedInstance)?;
        if !prepared.restored {
            prepared.instance.restore(snapshot)?;
            prepared.restored = true;
        }
        Ok(())
    }

    fn ensure_activated(
        &mut self,
        preparation: &RuntimePreparationReceipt,
        snapshot: &SnapshotEnvelope,
        destination: &ExternalCoordinate,
        bindings: &visa_core::BindingPreparationReceipt,
        permit: &visa_core::ActivationPermitReceipt,
    ) -> Result<(), RuntimeError> {
        permit.verify().map_err(|error| RuntimeError::Rejected(error.to_string()))?;
        self.ensure_restored(preparation, snapshot, destination, bindings)?;
        let prepared = self
            .destinations
            .get_mut(&preparation.operation)
            .ok_or(RuntimeError::MissingPreparedInstance)?;
        if prepared.instance.binding().execution_epoch() != permit.execution_epoch
            || permit.continuation != preparation.continuation
            || permit.snapshot != snapshot.body.snapshot
            || permit.snapshot_digest != snapshot.body_digest
            || permit.destination != *destination
        {
            return Err(RuntimeError::Rejected(
                "activation permit does not match restored destination".into(),
            ));
        }
        if !prepared.activated {
            self.provider.ensure_live(prepared.instance.binding())?;
            prepared.instance.activate(&ActivationGate::from_activation_permit(permit))?;
            prepared.activated = true;
        }
        Ok(())
    }

    fn operation(
        &self,
        action: &Action,
        kind: RuntimeOperationKind,
    ) -> Result<RuntimeOperationState, RuntimeError> {
        verify_action(action)?;
        let connection = self.database.lock()?;
        let row = connection.query_row(
            "SELECT kind, request_digest, outcome, receipt, rejection FROM visa_runtime_operations WHERE operation_id = ?1",
            params![action.operation.0.to_vec()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, String>(2)?, row.get::<_, Option<Vec<u8>>>(3)?, row.get::<_, Option<String>>(4)?)),
        ).optional()?;
        match row {
            None => Ok(RuntimeOperationState::Absent),
            Some((stored_kind, digest, _, _, _))
                if stored_kind != kind.as_str() || digest != action.request_digest.0 =>
            {
                Ok(RuntimeOperationState::Conflict(hex(&action.operation.0)))
            }
            Some((_, _, outcome, receipt, _)) if outcome == "applied" => {
                receipt.map(RuntimeOperationState::Applied).ok_or_else(|| {
                    RuntimeError::Rejected("applied runtime operation lacks receipt".into())
                })
            }
            Some((_, _, outcome, _, rejection)) if outcome == "rejected" => {
                Ok(RuntimeOperationState::Rejected(
                    rejection.unwrap_or_else(|| "runtime rejected request".into()),
                ))
            }
            Some((_, _, outcome, _, _)) if outcome == "armed" => Ok(RuntimeOperationState::Armed),
            Some((_, _, outcome, _, _)) if outcome == "retired" => {
                Ok(RuntimeOperationState::Retired)
            }
            Some(_) => {
                Err(RuntimeError::Corrupt("unknown durable runtime operation outcome".into()))
            }
        }
    }
    fn arm(&self, action: &Action, kind: RuntimeOperationKind) -> Result<(), RuntimeError> {
        verify_action(action)?;
        let connection = self.database.lock()?;
        connection.execute("INSERT INTO visa_runtime_operations (operation_id, kind, request_digest, outcome) VALUES (?1, ?2, ?3, 'armed')", params![action.operation.0.to_vec(), kind.as_str(), action.request_digest.0.to_vec()])?;
        Ok(())
    }
    fn persist_applied<T: Serialize>(
        &self,
        action: &Action,
        kind: RuntimeOperationKind,
        receipt: &T,
    ) -> Result<(), RuntimeError> {
        let bytes = postcard::to_allocvec(receipt)
            .map_err(|_| RuntimeError::Rejected("runtime receipt encoding failed".into()))?;
        self.persist(action, kind, "applied", Some(&bytes), None)
    }
    fn persist_rejected(
        &self,
        action: &Action,
        kind: RuntimeOperationKind,
        reason: &str,
    ) -> Result<(), RuntimeError> {
        self.persist(action, kind, "rejected", None, Some(reason))
    }
    fn persist(
        &self,
        action: &Action,
        kind: RuntimeOperationKind,
        outcome: &str,
        receipt: Option<&[u8]>,
        rejection: Option<&str>,
    ) -> Result<(), RuntimeError> {
        verify_action(action)?;
        let connection = self.database.lock()?;
        let transaction = connection.unchecked_transaction()?;
        persist_runtime_operation_in(&transaction, action, kind, outcome, receipt, rejection)?;
        transaction.commit()?;
        Ok(())
    }

    fn persist_retirement(
        &self,
        action: &Action,
        receipt: &RetirementReceipt,
        snapshot: visa_core::SnapshotId,
    ) -> Result<(), RuntimeError> {
        verify_action(action)?;
        let bytes = postcard::to_allocvec(receipt)
            .map_err(|_| RuntimeError::Rejected("runtime receipt encoding failed".into()))?;
        let connection = self.database.lock()?;
        let transaction = connection.unchecked_transaction()?;
        persist_runtime_operation_in(
            &transaction,
            action,
            RuntimeOperationKind::Retire,
            "applied",
            Some(&bytes),
            None,
        )?;
        let retired = transaction.execute(
            "UPDATE visa_runtime_operations
             SET outcome = 'retired', receipt = NULL, rejection = NULL
             WHERE operation_id = ?1 AND kind = 'capture' AND outcome = 'applied'",
            params![snapshot.0.to_vec()],
        )?;
        if retired != 1 {
            return Err(RuntimeError::Conflict(hex(&snapshot.0)));
        }
        transaction.commit()?;
        Ok(())
    }
}

fn persist_runtime_operation_in(
    transaction: &rusqlite::Transaction<'_>,
    action: &Action,
    kind: RuntimeOperationKind,
    outcome: &str,
    receipt: Option<&[u8]>,
    rejection: Option<&str>,
) -> Result<(), RuntimeError> {
    let state = transaction.query_row("SELECT kind, request_digest, outcome, receipt, rejection FROM visa_runtime_operations WHERE operation_id = ?1", params![action.operation.0.to_vec()], |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, String>(2)?, row.get::<_, Option<Vec<u8>>>(3)?, row.get::<_, Option<String>>(4)?))).optional()?;
    match state {
        None => {
            transaction.execute("INSERT INTO visa_runtime_operations (operation_id, kind, request_digest, outcome, receipt, rejection) VALUES (?1, ?2, ?3, ?4, ?5, ?6)", params![action.operation.0.to_vec(), kind.as_str(), action.request_digest.0.to_vec(), outcome, receipt, rejection])?;
        }
        Some((stored_kind, digest, stored_outcome, _, _))
            if stored_kind == kind.as_str()
                && digest == action.request_digest.0
                && stored_outcome == "armed" =>
        {
            transaction.execute("UPDATE visa_runtime_operations SET outcome = ?2, receipt = ?3, rejection = ?4 WHERE operation_id = ?1 AND outcome = 'armed'", params![action.operation.0.to_vec(), outcome, receipt, rejection])?;
        }
        Some((stored_kind, digest, stored_outcome, stored_receipt, stored_rejection))
            if stored_kind == kind.as_str()
                && digest == action.request_digest.0
                && stored_outcome == outcome
                && stored_receipt.as_deref() == receipt
                && stored_rejection.as_deref() == rejection => {}
        _ => return Err(RuntimeError::Conflict(hex(&action.operation.0))),
    }
    Ok(())
}

impl RuntimePort for ReferenceRuntime {
    type Error = RuntimeError;
    fn capture(&mut self, action: &Action) -> Observation<CapturedSnapshot, Self::Error> {
        match self.operation(action, RuntimeOperationKind::Capture) {
            Ok(RuntimeOperationState::Applied(bytes)) => {
                decode_capture(&bytes).map_or_else(Observation::Rejected, Observation::Applied)
            }
            Ok(RuntimeOperationState::Rejected(reason)) => {
                Observation::Rejected(RuntimeError::Rejected(reason))
            }
            Ok(RuntimeOperationState::Conflict(reason)) => {
                Observation::Unverifiable(RuntimeError::Conflict(reason))
            }
            Ok(RuntimeOperationState::Retired) => {
                Observation::Unverifiable(RuntimeError::RetiredCapture)
            }
            Ok(RuntimeOperationState::Armed) | Err(RuntimeError::Database(_)) => {
                Observation::Indeterminate
            }
            Ok(RuntimeOperationState::Absent) => {
                let result = self.capture_action(action);
                invoke(self, action, RuntimeOperationKind::Capture, result)
            }
            Err(RuntimeError::Corrupt(reason)) => {
                Observation::Unverifiable(RuntimeError::Corrupt(reason))
            }
            Err(error) => Observation::Rejected(error),
        }
    }
    fn query_capture(&mut self, action: &Action) -> Observation<CapturedSnapshot, Self::Error> {
        query_capture(self.operation(action, RuntimeOperationKind::Capture))
    }
    fn prepare_destination(
        &mut self,
        action: &Action,
    ) -> Observation<RuntimePreparationReceipt, Self::Error> {
        let result = self.prepare_destination_action(action);
        invoke(self, action, RuntimeOperationKind::PrepareDestination, result)
    }
    fn query_prepare_destination(
        &mut self,
        action: &Action,
    ) -> Observation<RuntimePreparationReceipt, Self::Error> {
        match self.operation(action, RuntimeOperationKind::PrepareDestination) {
            Ok(RuntimeOperationState::Applied(_)) => {
                query_materialized(self.prepare_destination_action(action))
            }
            other => query(other),
        }
    }
    fn restore_source(
        &mut self,
        action: &Action,
    ) -> Observation<SourceRestorationReceipt, Self::Error> {
        match self.operation(action, RuntimeOperationKind::RestoreSource) {
            Ok(RuntimeOperationState::Applied(bytes)) => {
                decode(&bytes).map_or_else(Observation::Rejected, Observation::Applied)
            }
            Ok(RuntimeOperationState::Rejected(reason)) => {
                Observation::Rejected(RuntimeError::Rejected(reason))
            }
            Ok(RuntimeOperationState::Conflict(reason)) => {
                Observation::Unverifiable(RuntimeError::Conflict(reason))
            }
            Ok(RuntimeOperationState::Retired) => Observation::Unverifiable(RuntimeError::Corrupt(
                "source restore operation is a capture tombstone".into(),
            )),
            Ok(RuntimeOperationState::Armed) | Err(RuntimeError::Database(_)) => {
                Observation::Indeterminate
            }
            Ok(RuntimeOperationState::Absent) => match self.restore_source_action(action) {
                Ok(receipt) => Observation::Applied(receipt),
                Err(_) => Observation::Indeterminate,
            },
            Err(RuntimeError::Corrupt(reason)) => {
                Observation::Unverifiable(RuntimeError::Corrupt(reason))
            }
            Err(error) => Observation::Rejected(error),
        }
    }
    fn query_restore_source(
        &mut self,
        action: &Action,
    ) -> Observation<SourceRestorationReceipt, Self::Error> {
        query(self.operation(action, RuntimeOperationKind::RestoreSource))
    }
    fn restore_destination(
        &mut self,
        action: &Action,
    ) -> Observation<DestinationRestoreReceipt, Self::Error> {
        let result = self.restore_destination_action(action);
        invoke(self, action, RuntimeOperationKind::RestoreDestination, result)
    }
    fn query_restore_destination(
        &mut self,
        action: &Action,
    ) -> Observation<DestinationRestoreReceipt, Self::Error> {
        match self.operation(action, RuntimeOperationKind::RestoreDestination) {
            Ok(RuntimeOperationState::Applied(_)) => {
                query_materialized(self.restore_destination_action(action))
            }
            other => query(other),
        }
    }
    fn activate(&mut self, action: &Action) -> Observation<RuntimeActivationReceipt, Self::Error> {
        let result = self.activate_action(action);
        invoke(self, action, RuntimeOperationKind::Activate, result)
    }
    fn query_activate(
        &mut self,
        action: &Action,
    ) -> Observation<RuntimeActivationReceipt, Self::Error> {
        match self.operation(action, RuntimeOperationKind::Activate) {
            Ok(RuntimeOperationState::Applied(_)) => {
                query_materialized(self.activate_action(action))
            }
            other => query(other),
        }
    }
    fn retire(&mut self, action: &Action) -> Observation<RetirementReceipt, Self::Error> {
        let result = self.retire_action(action);
        invoke(self, action, RuntimeOperationKind::Retire, result)
    }
    fn query_retire(&mut self, action: &Action) -> Observation<RetirementReceipt, Self::Error> {
        query(self.operation(action, RuntimeOperationKind::Retire))
    }
}

fn initialize_runtime_tables(database: &ReferenceDatabase) -> Result<(), RuntimeError> {
    database.lock()?.execute_batch(
        "CREATE TABLE IF NOT EXISTS visa_runtime_operations (
             operation_id BLOB PRIMARY KEY NOT NULL,
             kind TEXT NOT NULL CHECK(kind IN ('capture', 'prepare_destination', 'restore_source', 'restore_destination', 'activate', 'retire')),
             request_digest BLOB NOT NULL,
             outcome TEXT NOT NULL CHECK(outcome IN ('armed', 'applied', 'rejected', 'retired')),
             receipt BLOB, rejection TEXT
         );",
    )?;
    Ok(())
}
fn verify_action(action: &Action) -> Result<(), RuntimeError> {
    let digest = canonical_digest(&(action.operation, &action.request))
        .map_err(|error| RuntimeError::Rejected(error.to_string()))?;
    if digest == action.request_digest {
        Ok(())
    } else {
        Err(RuntimeError::Conflict(hex(&action.operation.0)))
    }
}
fn require_kind(action: &Action, kind: RuntimeOperationKind) -> Result<(), RuntimeError> {
    verify_action(action)?;
    let actual = match action.request.kind() {
        visa_coordinator::ActionKind::Capture => RuntimeOperationKind::Capture,
        visa_coordinator::ActionKind::PrepareDestination => {
            RuntimeOperationKind::PrepareDestination
        }
        visa_coordinator::ActionKind::RestoreSource => RuntimeOperationKind::RestoreSource,
        visa_coordinator::ActionKind::RestoreDestination => {
            RuntimeOperationKind::RestoreDestination
        }
        visa_coordinator::ActionKind::Activate => RuntimeOperationKind::Activate,
        visa_coordinator::ActionKind::Retire => RuntimeOperationKind::Retire,
        _ => return Err(RuntimeError::Rejected("runtime received authority action".into())),
    };
    if actual == kind {
        Ok(())
    } else {
        Err(RuntimeError::Rejected("runtime action kind mismatch".into()))
    }
}
fn query<T: serde::de::DeserializeOwned>(
    state: Result<RuntimeOperationState, RuntimeError>,
) -> Observation<T, RuntimeError> {
    match state {
        Ok(RuntimeOperationState::Applied(bytes)) => {
            decode(&bytes).map_or_else(Observation::Unverifiable, Observation::Applied)
        }
        Ok(RuntimeOperationState::Rejected(reason)) => {
            Observation::Rejected(RuntimeError::Rejected(reason))
        }
        Ok(RuntimeOperationState::Conflict(reason)) => {
            Observation::Unverifiable(RuntimeError::Conflict(reason))
        }
        Ok(RuntimeOperationState::Armed) => Observation::Indeterminate,
        Ok(RuntimeOperationState::Retired) => {
            Observation::Unverifiable(RuntimeError::RetiredCapture)
        }
        Ok(RuntimeOperationState::Absent) => Observation::Absent,
        Err(RuntimeError::Database(_)) => Observation::Indeterminate,
        Err(
            error @ (RuntimeError::Conflict(_)
            | RuntimeError::Corrupt(_)
            | RuntimeError::RetiredCapture),
        ) => Observation::Unverifiable(error),
        Err(error) => Observation::Rejected(error),
    }
}
fn query_materialized<T>(result: Result<T, RuntimeError>) -> Observation<T, RuntimeError> {
    match result {
        Ok(value) => Observation::Applied(value),
        Err(
            RuntimeError::Database(_)
            | RuntimeError::Authority(AuthorityError::Database(_))
            | RuntimeError::NativeStateIndeterminate,
        ) => Observation::Indeterminate,
        Err(error) => Observation::Unverifiable(error),
    }
}
fn invoke<T>(
    runtime: &ReferenceRuntime,
    action: &Action,
    kind: RuntimeOperationKind,
    result: Result<T, RuntimeError>,
) -> Observation<T, RuntimeError> {
    match result {
        Ok(value) => Observation::Applied(value),
        Err(
            RuntimeError::Database(_)
            | RuntimeError::Authority(AuthorityError::Database(_))
            | RuntimeError::NativeStateIndeterminate,
        ) => Observation::Indeterminate,
        Err(
            error @ (RuntimeError::Conflict(_)
            | RuntimeError::Corrupt(_)
            | RuntimeError::RetiredCapture),
        ) => Observation::Unverifiable(error),
        Err(error) => {
            let reason = error.to_string();
            match runtime.persist_rejected(action, kind, &reason) {
                Ok(()) => Observation::Rejected(error),
                Err(RuntimeError::Database(_)) => Observation::Indeterminate,
                Err(_) => Observation::Unverifiable(error),
            }
        }
    }
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, RuntimeError> {
    postcard::from_bytes(bytes)
        .map_err(|_| RuntimeError::Corrupt("durable runtime receipt cannot be decoded".into()))
}
fn decode_capture(bytes: &[u8]) -> Result<CapturedSnapshot, RuntimeError> {
    let durable: DurableCapture = decode(bytes)?;
    Ok(CapturedSnapshot { snapshot: durable.snapshot, receipt: durable.receipt })
}
fn query_capture(
    state: Result<RuntimeOperationState, RuntimeError>,
) -> Observation<CapturedSnapshot, RuntimeError> {
    match state {
        Ok(RuntimeOperationState::Applied(bytes)) => {
            decode_capture(&bytes).map_or_else(Observation::Unverifiable, Observation::Applied)
        }
        Ok(RuntimeOperationState::Rejected(reason)) => {
            Observation::Rejected(RuntimeError::Rejected(reason))
        }
        Ok(RuntimeOperationState::Conflict(reason)) => {
            Observation::Unverifiable(RuntimeError::Conflict(reason))
        }
        Ok(RuntimeOperationState::Armed) => Observation::Indeterminate,
        Ok(RuntimeOperationState::Retired) => {
            Observation::Unverifiable(RuntimeError::RetiredCapture)
        }
        Ok(RuntimeOperationState::Absent) => Observation::Absent,
        Err(RuntimeError::Database(_)) => Observation::Indeterminate,
        Err(error) => Observation::Unverifiable(error),
    }
}
fn binding_coordinate(binding_id: &str) -> ExternalCoordinate {
    ExternalCoordinate {
        authority: REFERENCE_AUTHORITY_ID,
        value: OpaqueBytes(binding_id.as_bytes().to_vec()),
    }
}
fn bootstrap_context(runtime: ExternalCoordinate) -> SnapshotContext {
    SnapshotContext {
        snapshot: visa_core::SnapshotId::default(),
        continuation: visa_core::ContinuationId::default(),
        scope: visa_core::ScopeId::default(),
        lineage: visa_core::LineageAdvance {
            parent: visa_core::LineagePoint {
                semantic_domain: ReferenceRuntime::semantic_domain_ref()
                    .expect("embedded reference component has a semantic domain"),
                lineage: visa_core::LineageId::default(),
                generation: 0,
                state_digest: Digest::ZERO,
            },
            successor_generation: 1,
            successor_digest: Digest::ZERO,
        },
        runtime,
        cut_sequence: 0,
        receipt_digest: Digest::ZERO,
    }
}
fn snapshot_context(snapshot: &SnapshotEnvelope, runtime: ExternalCoordinate) -> SnapshotContext {
    SnapshotContext {
        snapshot: snapshot.body.snapshot,
        continuation: snapshot.body.continuation,
        scope: snapshot.body.scope,
        lineage: snapshot.body.lineage.clone(),
        runtime,
        cut_sequence: snapshot.body.lineage.successor_generation,
        receipt_digest: snapshot.body_digest,
    }
}
fn snapshot_id(operation: OperationId) -> visa_core::SnapshotId {
    visa_core::SnapshotId(operation.0)
}
fn validate_snapshot(
    snapshot: &SnapshotEnvelope,
    continuation: visa_core::ContinuationId,
) -> Result<(), RuntimeError> {
    snapshot.verify().map_err(|error| RuntimeError::Rejected(error.to_string()))?;
    if snapshot.body.continuation == continuation {
        Ok(())
    } else {
        Err(RuntimeError::Rejected("snapshot continuation mismatch".into()))
    }
}
fn validate_resource_bindings(
    snapshot: &SnapshotEnvelope,
    bindings: &visa_core::BindingPreparationReceipt,
) -> Result<(), RuntimeError> {
    let state = DurableKvProfile
        .decode_state(&snapshot.body.state.0)
        .map_err(|error| RuntimeError::Rejected(error.to_string()))?;
    for requirement in &snapshot.body.resources {
        let grant =
            bindings.grants.iter().find(|grant| grant.requirement == requirement.id).ok_or_else(
                || RuntimeError::Rejected("missing destination binding grant".into()),
            )?;
        DurableKvProfile
            .validate_binding(&state, requirement, grant)
            .map_err(|error| RuntimeError::Rejected(error.to_string()))?;
    }
    Ok(())
}
/// Only reverses the runtime's own pre-commit close. A fenced source cannot reopen.
fn reopen_source_dispatch(
    database: &ReferenceDatabase,
    handle: &BindingHandle,
) -> Result<(), RuntimeError> {
    let changed = database.lock()?.execute(
        "UPDATE visa_authority_bindings SET dispatch_open = 1 WHERE binding_id = ?1 AND generation = ?2 AND epoch = ?3 AND role = 'source' AND active = 1 AND fenced = 0 AND dispatch_open = 0",
        params![handle.binding_id(), u64_to_sqlite(handle.generation(), "binding generation")?, u64_to_sqlite(handle.execution_epoch(), "execution epoch")?],
    )?;
    if changed == 1 {
        Ok(())
    } else {
        Err(RuntimeError::Rejected(
            "source dispatch cannot reopen after its authority fence".into(),
        ))
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
