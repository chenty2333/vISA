//! Runtime-local adapter for the real Wasmtime Component path.

use std::fmt;

use visa_coordinator::{self as coordinator, CallOutcome, QueryOutcome};
use visa_core::{
    ActivationReceipt, AuthorityCommitReceipt as CoreCommitReceipt, Digest, ExternalCoordinate,
    SafePointReceipt, SnapshotEnvelope, SnapshotId, SourceRestorationReceipt,
};
use visa_profile::DurableKvProfile;
use visa_wasi::{ActivationGate, PreparedComponent, SnapshotContext, WasiError, WasiInstance};

use crate::authority::{
    ActivationAdmissionRequest, ActivationAdmissionState, Authority, AuthorityError,
};
use crate::provider::{BindingHandle, DurableKvProvider, KvEntry, ProviderError};

#[derive(Debug)]
pub enum RuntimeError {
    Wasi(WasiError),
    Provider(ProviderError),
    SessionRevisionMismatch { expected: Option<u64>, actual: Option<u64> },
}
impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wasi(e) => write!(f, "WASI runtime error: {e}"),
            Self::Provider(e) => write!(f, "provider runtime error: {e}"),
            Self::SessionRevisionMismatch { expected, actual } => {
                write!(f, "session revision mismatch: expected {expected:?}, actual {actual:?}")
            }
        }
    }
}
impl std::error::Error for RuntimeError {}
impl From<WasiError> for RuntimeError {
    fn from(e: WasiError) -> Self {
        Self::Wasi(e)
    }
}
impl From<ProviderError> for RuntimeError {
    fn from(e: ProviderError) -> Self {
        Self::Provider(e)
    }
}

/// One isolated Wasmtime instance plus one host-local provider handle.
pub struct ReferenceInstance {
    instance: WasiInstance<DurableKvProfile>,
    binding: BindingHandle,
    provider: DurableKvProvider,
}
impl fmt::Debug for ReferenceInstance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReferenceInstance")
            .field("binding_id", &self.binding.binding_id())
            .field("execution_epoch", &self.binding.execution_epoch())
            .finish_non_exhaustive()
    }
}

impl ReferenceInstance {
    /// Construct an activated source using coordinator-owned snapshot
    /// coordinates.  The authority receipt is still only a local activation
    /// gate; no runtime object is carried in the portable envelope.
    pub fn source_with_context(
        prepared: &PreparedComponent<DurableKvProfile>,
        provider: DurableKvProvider,
        binding: BindingHandle,
        context: SnapshotContext,
    ) -> Result<Self, RuntimeError> {
        let mut instance = prepared.instantiate(binding.execution_epoch())?;
        let gate = ActivationGate::for_active_source(&context, binding.execution_epoch());
        instance.set_snapshot_context(context)?;
        instance.activate(&gate)?;
        Ok(Self { instance, binding, provider })
    }

    pub(crate) fn destination_unactivated(
        prepared: &PreparedComponent<DurableKvProfile>,
        provider: DurableKvProvider,
        binding: BindingHandle,
        snapshot: &SnapshotEnvelope,
        receipt: &CoreCommitReceipt,
    ) -> Result<Self, RuntimeError> {
        if receipt.execution_epoch != binding.execution_epoch() {
            return Err(RuntimeError::SessionRevisionMismatch {
                expected: Some(receipt.execution_epoch),
                actual: Some(binding.execution_epoch()),
            });
        }
        let mut instance = prepared.instantiate(binding.execution_epoch())?;
        let context = SnapshotContext {
            snapshot: receipt.snapshot,
            continuation: receipt.continuation,
            scope: snapshot.body.scope,
            lineage: snapshot.body.lineage.clone(),
            runtime: receipt.destination.clone(),
            cut_sequence: snapshot.body.source_cut.cut_sequence,
            receipt_digest: snapshot.body.source_cut.receipt_digest,
        };
        instance.set_snapshot_context(context)?;
        instance.restore(snapshot)?;
        Ok(Self { instance, binding, provider })
    }

    /// Recreate a source after a coordinator/runtime process restart.  The
    /// provider binding is freshly opened from the still-active authority
    /// coordinate; only the portable snapshot crosses the restart boundary.
    pub(crate) fn source_from_snapshot(
        prepared: &PreparedComponent<DurableKvProfile>,
        provider: DurableKvProvider,
        binding: BindingHandle,
        snapshot: &SnapshotEnvelope,
    ) -> Result<Self, RuntimeError> {
        let mut instance = prepared.instantiate(binding.execution_epoch())?;
        instance.set_snapshot_context(SnapshotContext {
            snapshot: snapshot.body.snapshot,
            continuation: snapshot.body.continuation,
            scope: snapshot.body.scope,
            lineage: snapshot.body.lineage.clone(),
            runtime: snapshot.body.source_cut.runtime.clone(),
            cut_sequence: snapshot.body.source_cut.cut_sequence,
            receipt_digest: snapshot.body.source_cut.receipt_digest,
        })?;
        instance.restore(snapshot)?;
        Ok(Self { instance, binding, provider })
    }

    pub(crate) fn prepare_activation_core(
        &mut self,
        receipt: &CoreCommitReceipt,
    ) -> Result<(), RuntimeError> {
        self.instance.prepare_activation(&ActivationGate::from_authority_commit(receipt))?;
        Ok(())
    }

    pub(crate) fn enable_activation(&mut self) -> Result<(), RuntimeError> {
        self.instance.enable_activation()?;
        Ok(())
    }

    pub(crate) fn restore_source(
        &mut self,
        snapshot: &SnapshotEnvelope,
    ) -> Result<(), RuntimeError> {
        self.instance.restore(snapshot)?;
        Ok(())
    }

    pub(crate) fn activate_source(
        &mut self,
        snapshot: &SnapshotEnvelope,
    ) -> Result<(), RuntimeError> {
        let context = SnapshotContext {
            snapshot: snapshot.body.snapshot,
            continuation: snapshot.body.continuation,
            scope: snapshot.body.scope,
            lineage: snapshot.body.lineage.clone(),
            runtime: snapshot.body.source_cut.runtime.clone(),
            cut_sequence: snapshot.body.source_cut.cut_sequence,
            receipt_digest: snapshot.body.source_cut.receipt_digest,
        };
        self.instance.activate(&ActivationGate::for_active_source(
            &context,
            self.binding.execution_epoch(),
        ))?;
        Ok(())
    }

    pub fn increment(&mut self) -> Result<u64, RuntimeError> {
        Ok(self.instance.increment()?)
    }
    pub fn value(&mut self) -> Result<u64, RuntimeError> {
        Ok(self.instance.value()?)
    }
    pub fn binding(&self) -> &BindingHandle {
        &self.binding
    }
    pub(crate) fn safe_point(&self) -> Option<SafePointReceipt> {
        self.instance.safe_point().map(|capture| capture.safe_point.clone())
    }
    pub(crate) fn begin_continuation(
        &mut self,
        context: SnapshotContext,
    ) -> Result<(), RuntimeError> {
        self.instance.begin_continuation(context)?;
        Ok(())
    }
    pub fn set_session(&self, value: &[u8]) -> Result<KvEntry, RuntimeError> {
        let current = self.provider.get_for_handle(&self.binding, b"counter")?;
        Ok(self.provider.cas_for_handle(
            &self.binding,
            b"counter",
            current.as_ref().map(|e| e.revision),
            value,
        )?)
    }
    pub fn session(&self) -> Result<Option<KvEntry>, RuntimeError> {
        Ok(self.provider.get_for_handle(&self.binding, b"counter")?)
    }
    pub fn freeze(&mut self, session_key: &[u8]) -> Result<SnapshotEnvelope, RuntimeError> {
        self.instance.begin_freeze()?;
        let session = match self.provider.capture_and_close(&self.binding, session_key) {
            Ok(session) => session,
            Err(error) => {
                self.instance.cancel_freeze()?;
                return Err(error.into());
            }
        };
        match self
            .instance
            .complete_freeze(session_key.to_vec(), session.map(|entry| entry.revision))
        {
            Ok(snapshot) => Ok(snapshot),
            Err(error) => {
                self.instance.cancel_freeze()?;
                Err(error.into())
            }
        }
    }
}

pub struct WasmtimeVertical {
    pub prepared: PreparedComponent<DurableKvProfile>,
}

/// A coordinator-facing runtime port backed by the real Wasmtime component
/// frontend.  Its associated values are deliberately host-local tokens; only
/// the core snapshot and receipts cross the coordinator's durable boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoordinatorRuntimeError(pub String);

impl fmt::Display for CoordinatorRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for CoordinatorRuntimeError {}

pub struct PreparedDestination {
    snapshot: SnapshotEnvelope,
    destination: ExternalCoordinate,
}

pub struct RestoredDestination {
    instance: ReferenceInstance,
}

pub struct CoordinatorRuntimeAdapter {
    authority: Authority,
    provider: DurableKvProvider,
    pub vertical: WasmtimeVertical,
    source: Option<ReferenceInstance>,
    destination: Option<ReferenceInstance>,
    activation: Option<ActivationReceipt>,
}

impl CoordinatorRuntimeAdapter {
    pub fn new(
        authority: Authority,
        provider: DurableKvProvider,
        vertical: WasmtimeVertical,
    ) -> Self {
        Self { authority, provider, vertical, source: None, destination: None, activation: None }
    }

    /// Install the already-running source owned by the embedding host. The
    /// instance remains host-local and is never written to the record store.
    pub fn install_source(&mut self, source: ReferenceInstance) {
        self.source = Some(source);
    }

    fn error(error: impl fmt::Display) -> CoordinatorRuntimeError {
        CoordinatorRuntimeError(error.to_string())
    }

    fn authority_indeterminate(error: &AuthorityError) -> bool {
        matches!(error, AuthorityError::Database(_) | AuthorityError::Indeterminate)
    }

    fn provider_indeterminate(error: &ProviderError) -> bool {
        matches!(
            error,
            ProviderError::Database(_)
                | ProviderError::Authority(
                    AuthorityError::Database(_) | AuthorityError::Indeterminate
                )
        )
    }

    fn runtime_indeterminate(error: &RuntimeError) -> bool {
        matches!(error, RuntimeError::Provider(error) if Self::provider_indeterminate(error))
    }

    fn source_context(request: &coordinator::FreezeSourceRequest) -> SnapshotContext {
        SnapshotContext {
            snapshot: SnapshotId(request.continuation.0),
            continuation: request.continuation,
            scope: request.scope,
            lineage: request.lineage.clone(),
            // The source binding is an authority coordinate and must never be
            // copied into portable state.  The runtime coordinate identifies
            // the Wasmtime frontend instead.
            runtime: SnapshotContext::default().runtime,
            cut_sequence: 0,
            receipt_digest: Digest::ZERO,
        }
    }

    fn local_binding(coordinate: &ExternalCoordinate) -> Result<String, CoordinatorRuntimeError> {
        if coordinate.authority != visa_core::AuthorityId::from_u128(1) {
            return Err(Self::error("binding belongs to a different authority"));
        }
        String::from_utf8(coordinate.value.clone())
            .map_err(|_| Self::error("binding coordinate is not exact UTF-8"))
    }

    pub fn destination_mut(&mut self) -> Option<&mut ReferenceInstance> {
        self.destination.as_mut()
    }

    pub fn source_mut(&mut self) -> Option<&mut ReferenceInstance> {
        self.source.as_mut()
    }
}

impl coordinator::RuntimePort for CoordinatorRuntimeAdapter {
    type Frozen = ();
    type Prepared = PreparedDestination;
    type Restored = RestoredDestination;
    type ActivationRejection = CoordinatorRuntimeError;
    type Error = CoordinatorRuntimeError;

    fn freeze_source(
        &mut self,
        request: coordinator::FreezeSourceRequest,
    ) -> CallOutcome<coordinator::FrozenRuntime<Self::Frozen>, Self::Error> {
        if request.profile != self.vertical.prepared.profile_ref() {
            return CallOutcome::Rejected(Self::error(
                "source profile does not match prepared component",
            ));
        }
        let binding_id = match Self::local_binding(&request.source) {
            Ok(binding_id) => binding_id,
            Err(error) => return CallOutcome::Rejected(error),
        };
        if self.source.as_ref().is_some_and(|source| source.binding().binding_id() != binding_id) {
            self.source = None;
        }
        if self.source.is_none()
            && self
                .destination
                .as_ref()
                .is_some_and(|destination| destination.binding().binding_id() == binding_id)
        {
            self.source = self.destination.take();
        }
        let Some(source) = self.source.as_mut() else {
            return CallOutcome::Rejected(Self::error(
                "live source is unavailable before the durable snapshot boundary",
            ));
        };
        if let Err(error) = source.begin_continuation(Self::source_context(&request)) {
            return CallOutcome::Rejected(Self::error(error));
        }
        let snapshot = match source.freeze(b"counter") {
            Ok(snapshot) => snapshot,
            Err(error) => {
                if let Err(resume_error) =
                    self.authority.resume_source(source.binding().binding_id())
                {
                    if Self::authority_indeterminate(&resume_error) {
                        return CallOutcome::Indeterminate;
                    }
                    return CallOutcome::Rejected(Self::error(resume_error));
                }
                if Self::runtime_indeterminate(&error) {
                    return CallOutcome::Indeterminate;
                }
                return CallOutcome::Rejected(Self::error(error));
            }
        };
        let Some(safe_point) = source.safe_point() else {
            return CallOutcome::Rejected(Self::error("source did not report a safe point"));
        };
        CallOutcome::Applied(coordinator::FrozenRuntime { snapshot, safe_point, frozen: () })
    }

    fn restore_source(
        &mut self,
        request: coordinator::RestoreSourceRequest,
    ) -> CallOutcome<SourceRestorationReceipt, Self::Error> {
        if self.source.is_none() {
            let binding_id = match Self::local_binding(&request.source) {
                Ok(binding_id) => binding_id,
                Err(error) => return CallOutcome::Rejected(error),
            };
            let binding = match self.provider.bind(&self.authority, &binding_id) {
                Ok(binding) => binding,
                Err(error) if Self::provider_indeterminate(&error) => {
                    return CallOutcome::Indeterminate;
                }
                Err(error) => return CallOutcome::Rejected(Self::error(error)),
            };
            let source = match ReferenceInstance::source_from_snapshot(
                &self.vertical.prepared,
                self.provider.clone(),
                binding,
                &request.snapshot,
            ) {
                Ok(source) => source,
                Err(error) => return CallOutcome::Rejected(Self::error(error)),
            };
            if let Err(error) = self.authority.resume_source(source.binding().binding_id()) {
                if Self::authority_indeterminate(&error) {
                    return CallOutcome::Indeterminate;
                }
                return CallOutcome::Rejected(Self::error(error));
            }
            let mut source = source;
            if let Err(error) = source.activate_source(&request.snapshot) {
                let _ = self.authority.close_source(source.binding().binding_id());
                return CallOutcome::Rejected(Self::error(error));
            }
            let receipt = SourceRestorationReceipt {
                continuation: request.continuation,
                snapshot: request.snapshot.body.snapshot,
                source: request.source,
                execution_epoch: source.binding().execution_epoch(),
                receipt_digest: Digest::ZERO,
            }
            .seal()
            .expect("reference source restoration receipt is encodable");
            self.source = Some(source);
            return CallOutcome::Applied(receipt);
        }
        let source = self.source.as_mut().expect("source was checked above");
        match source.restore_source(&request.snapshot) {
            Ok(()) => {
                if let Err(error) = self.authority.resume_source(source.binding().binding_id()) {
                    if Self::authority_indeterminate(&error) {
                        return CallOutcome::Indeterminate;
                    }
                    return CallOutcome::Rejected(Self::error(error));
                }
                if let Err(error) = source.activate_source(&request.snapshot) {
                    let _ = self.authority.close_source(source.binding().binding_id());
                    return CallOutcome::Rejected(Self::error(error));
                }
                CallOutcome::Applied(
                    SourceRestorationReceipt {
                        continuation: request.continuation,
                        snapshot: request.snapshot.body.snapshot,
                        source: request.source,
                        execution_epoch: source.binding().execution_epoch(),
                        receipt_digest: Digest::ZERO,
                    }
                    .seal()
                    .expect("reference source restoration receipt is encodable"),
                )
            }
            Err(error) => CallOutcome::Rejected(Self::error(error)),
        }
    }

    fn source_restoration_is_live(&self, receipt: &SourceRestorationReceipt) -> bool {
        let Ok(binding_id) = Self::local_binding(&receipt.source) else { return false };
        self.source.as_ref().is_some_and(|source| {
            source.binding().binding_id() == binding_id
                && source.binding().execution_epoch() == receipt.execution_epoch
        })
    }

    fn prepare_destination(
        &mut self,
        request: coordinator::PrepareDestinationRequest,
    ) -> CallOutcome<Self::Prepared, Self::Error> {
        if request.snapshot.body.profile != self.vertical.prepared.profile_ref()
            || request.snapshot.body.resources != request.requirements
        {
            return CallOutcome::Rejected(Self::error(
                "destination profile or requirements mismatch",
            ));
        }
        CallOutcome::Applied(PreparedDestination {
            snapshot: request.snapshot,
            destination: request.destination,
        })
    }

    fn restore_destination(
        &mut self,
        request: coordinator::RestoreDestinationRequest<Self::Prepared>,
    ) -> CallOutcome<Self::Restored, Self::Error> {
        if request.prepared.snapshot != request.snapshot
            || request.prepared.destination != request.destination
        {
            return CallOutcome::Rejected(Self::error("destination preparation token mismatch"));
        }
        let Some(grant) = request.preparation.grants.first() else {
            return CallOutcome::Rejected(Self::error("authority returned no destination grant"));
        };
        let binding_id = match Self::local_binding(&grant.binding) {
            Ok(binding_id) => binding_id,
            Err(error) => return CallOutcome::Rejected(error),
        };
        let binding = match self.provider.bind(&self.authority, &binding_id) {
            Ok(binding) => binding,
            Err(error) if Self::provider_indeterminate(&error) => {
                return CallOutcome::Indeterminate;
            }
            Err(error) => return CallOutcome::Rejected(Self::error(error)),
        };
        match ReferenceInstance::destination_unactivated(
            &self.vertical.prepared,
            self.provider.clone(),
            binding,
            &request.snapshot,
            &request.commit,
        ) {
            Ok(instance) => CallOutcome::Applied(RestoredDestination { instance }),
            Err(error) => CallOutcome::Rejected(Self::error(error)),
        }
    }

    fn activate(
        &mut self,
        request: coordinator::ActivateRequest<Self::Restored>,
    ) -> CallOutcome<ActivationReceipt, Self::ActivationRejection> {
        let mut restored = request.restored.instance;
        if request.commit.continuation != request.continuation
            || request.commit.snapshot != request.snapshot
            || request.commit.destination != request.destination
        {
            return CallOutcome::Rejected(Self::error("activation request does not match commit"));
        }
        if let Err(error) = restored.prepare_activation_core(&request.commit) {
            return CallOutcome::Rejected(Self::error(error));
        }
        let admission = ActivationAdmissionRequest {
            operation: request.operation,
            continuation: request.continuation,
            snapshot: request.snapshot,
            destination: request.destination.clone(),
            destination_binding_id: restored.binding().binding_id().to_owned(),
            commit: request.commit.clone(),
        };
        if let Err(error) = self.authority.open_destination(&admission) {
            return if Self::authority_indeterminate(&error) {
                CallOutcome::Indeterminate
            } else {
                CallOutcome::Rejected(Self::error(error))
            };
        }
        if let Err(error) = restored.enable_activation() {
            return match self.authority.close_destination(&admission) {
                Ok(()) => CallOutcome::Rejected(Self::error(error)),
                Err(_) => CallOutcome::Indeterminate,
            };
        }
        let receipt = ActivationReceipt {
            operation: request.operation,
            continuation: request.continuation,
            snapshot: request.snapshot,
            destination: request.destination,
            authority_commit_digest: request.commit.receipt_digest,
            execution_epoch: request.commit.execution_epoch,
            receipt_digest: Digest::ZERO,
        }
        .seal()
        .expect("reference activation receipt is encodable");
        self.destination = Some(restored);
        self.activation = Some(receipt.clone());
        match self.authority.confirm_destination_activation(&admission) {
            Ok(()) => CallOutcome::Applied(receipt),
            Err(_) => CallOutcome::Indeterminate,
        }
    }

    fn query_activation(
        &mut self,
        request: coordinator::QueryActivationRequest,
    ) -> QueryOutcome<ActivationReceipt, Self::ActivationRejection> {
        let binding_id = match Self::local_binding(&request.binding) {
            Ok(binding_id) => binding_id,
            Err(error) => return QueryOutcome::Rejected(error),
        };
        let admission = ActivationAdmissionRequest {
            operation: request.operation,
            continuation: request.continuation,
            snapshot: request.snapshot,
            destination: request.destination.clone(),
            destination_binding_id: binding_id,
            commit: request.commit.clone(),
        };
        let receipt = ActivationReceipt {
            operation: request.operation,
            continuation: request.continuation,
            snapshot: request.snapshot,
            destination: request.destination,
            authority_commit_digest: request.commit.receipt_digest,
            execution_epoch: request.commit.execution_epoch,
            receipt_digest: Digest::ZERO,
        }
        .seal()
        .expect("reference activation receipt is encodable");
        match self.authority.query_activation_admission(&admission) {
            Ok(ActivationAdmissionState::Activated) => QueryOutcome::Applied(receipt),
            Ok(ActivationAdmissionState::Admitted)
                if self.activation.as_ref() == Some(&receipt) && self.destination.is_some() =>
            {
                match self.authority.confirm_destination_activation(&admission) {
                    Ok(()) => QueryOutcome::Applied(receipt),
                    Err(_) => QueryOutcome::Indeterminate,
                }
            }
            Ok(ActivationAdmissionState::Admitted) => QueryOutcome::Indeterminate,
            Ok(ActivationAdmissionState::Absent) => QueryOutcome::Absent,
            Err(error) if Self::authority_indeterminate(&error) => QueryOutcome::Indeterminate,
            Err(error) => QueryOutcome::Rejected(Self::error(error)),
        }
    }
}

impl WasmtimeVertical {
    pub fn new() -> Result<Self, RuntimeError> {
        let bytes = visa_wasi::counter_component_bytes()?;
        Ok(Self { prepared: visa_wasi::WasiFrontend::new(DurableKvProfile).preflight(&bytes)? })
    }
}
