//! Runtime-local adapter for the real Wasmtime Component path.

use std::fmt;

use rusqlite::{OptionalExtension, params};
use visa_coordinator::{self as coordinator, CallOutcome, QueryOutcome};
use visa_core::{
    ActivationReceipt, AuthorityCommitReceipt as CoreCommitReceipt, BindingGrant, CaptureReceipt,
    Digest, ExternalCoordinate, SafePointReceipt, SnapshotEnvelope, SnapshotId,
    SourceRestorationReceipt, canonical_digest,
};
use visa_profile::{ContinuityProfile, DurableKvProfile};
use visa_wasi::{ActivationGate, PreparedComponent, SnapshotContext, WasiError, WasiInstance};

use crate::authority::{
    ActivationAdmissionRequest, ActivationAdmissionState, Authority, AuthorityError,
};
use crate::provider::{BindingHandle, DurableKvProvider, KvEntry, ProviderError};

const MAX_CAPTURE_FACT_BYTES: usize = 1024 * 1024;

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
        self.provider.ensure_live(&self.binding)?;
        Ok(self.instance.increment()?)
    }
    pub fn value(&mut self) -> Result<u64, RuntimeError> {
        self.provider.ensure_live(&self.binding)?;
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
    pub(crate) fn freeze(&mut self, session_key: &[u8]) -> Result<SnapshotEnvelope, RuntimeError> {
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

/// A sealed capture that has crossed the runtime safe point but has not yet
/// been observed as durable by this adapter.  The source provider dispatch is
/// already closed at this point, so dropping this value would strand the
/// source and make a subsequent exact query incorrectly look retryable.
#[derive(Clone)]
struct PendingCapture {
    request_digest: Digest,
    captured: coordinator::CapturedSnapshot,
}

enum CapturePersistence {
    Persisted(Box<coordinator::CapturedSnapshot>),
    Indeterminate,
    Rejected(CoordinatorRuntimeError),
}

enum CaptureReadError {
    Indeterminate,
    Rejected(CoordinatorRuntimeError),
}

enum DurableCapture {
    Absent,
    Armed,
    Captured(Box<coordinator::CapturedSnapshot>),
}

enum CaptureArming {
    Armed,
    AlreadyArmed,
    AlreadyCaptured,
    Indeterminate,
    Rejected(CoordinatorRuntimeError),
}

pub struct CoordinatorRuntimeAdapter {
    authority: Authority,
    provider: DurableKvProvider,
    pub vertical: WasmtimeVertical,
    source: Option<ReferenceInstance>,
    source_restoration: Option<SourceRestorationReceipt>,
    destination: Option<ReferenceInstance>,
    activation: Option<ActivationReceipt>,
    lose_capture_ack_once: bool,
    fail_capture_persistence_once: bool,
    pending_captures: Vec<PendingCapture>,
    retired_captures: Vec<(visa_core::OperationId, Digest)>,
}

impl CoordinatorRuntimeAdapter {
    pub fn new(
        authority: Authority,
        provider: DurableKvProvider,
        vertical: WasmtimeVertical,
    ) -> Self {
        Self {
            authority,
            provider,
            vertical,
            source: None,
            source_restoration: None,
            destination: None,
            activation: None,
            lose_capture_ack_once: false,
            fail_capture_persistence_once: false,
            pending_captures: Vec::new(),
            retired_captures: Vec::new(),
        }
    }

    /// Install the already-running source owned by the embedding host. The
    /// instance remains host-local and is never written to the record store.
    pub fn install_source(&mut self, source: ReferenceInstance) {
        self.source = Some(source);
        self.source_restoration = None;
    }

    /// Test/reference fault injection after the runtime-owned durable capture
    /// transaction commits but before the coordinator receives its receipt.
    pub fn inject_capture_lost_ack_once(&mut self) {
        self.lose_capture_ack_once = true;
    }

    /// Test/reference fault injection after source capture seals but before
    /// its durable capture row is written. The sealed value remains in this
    /// adapter and the next exact query retries that write without freezing
    /// the source a second time.
    pub fn inject_capture_persistence_failure_once(&mut self) {
        self.fail_capture_persistence_once = true;
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
            runtime: Self::reference_runtime_coordinate(),
            cut_sequence: request.lineage.successor_generation,
            receipt_digest: Digest::ZERO,
        }
    }

    fn reference_runtime_coordinate() -> ExternalCoordinate {
        ExternalCoordinate {
            authority: visa_core::AuthorityId::from_u128(2),
            value: b"reference-wasmtime".to_vec(),
        }
    }

    fn local_binding(coordinate: &ExternalCoordinate) -> Result<String, CoordinatorRuntimeError> {
        if coordinate.authority != visa_core::AuthorityId::from_u128(1) {
            return Err(Self::error("binding belongs to a different authority"));
        }
        String::from_utf8(coordinate.value.clone())
            .map_err(|_| Self::error("binding coordinate is not exact UTF-8"))
    }

    /// In the reference authority a provider coordinate identifies the
    /// provider generation, not the destination binding. Binding coordinates
    /// carry the `destination:{operation}` row id separately.
    fn reference_provider_coordinate(provider_generation: u64) -> ExternalCoordinate {
        ExternalCoordinate {
            authority: visa_core::AuthorityId::from_u128(1),
            value: format!("provider:g{provider_generation}").into_bytes(),
        }
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

    fn capture_durability(&self) -> coordinator::CaptureDurability {
        coordinator::CaptureDurability::AuthorityDurableQueryable
    }

    fn capture(
        &mut self,
        request: coordinator::CaptureRequest,
    ) -> CallOutcome<coordinator::CapturedRuntime<Self::Frozen>, Self::Error> {
        let query = coordinator::QueryCaptureRequest {
            operation: request.operation,
            continuation: request.continuation,
            scope: request.scope,
            source: request.source.clone(),
            profile: request.profile.clone(),
            lineage: request.lineage.clone(),
        };
        let request_digest = match Self::capture_request_digest(
            request.operation,
            request.continuation,
            request.scope,
            &request.source,
            &request.profile,
            &request.lineage,
        ) {
            Ok(digest) => digest,
            Err(error) => return CallOutcome::Rejected(error),
        };
        match self.query_capture(query.clone()) {
            QueryOutcome::Applied(captured) => {
                return CallOutcome::Applied(coordinator::CapturedRuntime {
                    snapshot: captured.snapshot,
                    safe_point: captured.safe_point,
                    receipt: Some(captured.receipt),
                    frozen: (),
                });
            }
            QueryOutcome::Rejected(error) => return CallOutcome::Rejected(error),
            QueryOutcome::Indeterminate => return CallOutcome::Indeterminate,
            QueryOutcome::Absent => {}
        }

        // The operation marker is the runtime authority's durable source
        // fence for this capture. It must commit before freeze_source can
        // close provider dispatch; otherwise a fresh process cannot tell an
        // unstarted capture from one that may already have frozen the source.
        match self.arm_durable_capture(request.operation, request_digest) {
            CaptureArming::Armed => {}
            CaptureArming::AlreadyArmed => return CallOutcome::Indeterminate,
            CaptureArming::AlreadyCaptured => {
                return match self.query_capture(query) {
                    QueryOutcome::Applied(captured) => {
                        CallOutcome::Applied(coordinator::CapturedRuntime {
                            snapshot: captured.snapshot,
                            safe_point: captured.safe_point,
                            receipt: Some(captured.receipt),
                            frozen: (),
                        })
                    }
                    QueryOutcome::Rejected(error) => CallOutcome::Rejected(error),
                    QueryOutcome::Indeterminate | QueryOutcome::Absent => {
                        CallOutcome::Indeterminate
                    }
                };
            }
            CaptureArming::Rejected(error) => return CallOutcome::Rejected(error),
            CaptureArming::Indeterminate => return CallOutcome::Indeterminate,
        }

        let frozen = match self.freeze_source(coordinator::FreezeSourceRequest {
            operation: request.operation,
            continuation: request.continuation,
            scope: request.scope,
            source: request.source.clone(),
            profile: request.profile.clone(),
            lineage: request.lineage.clone(),
        }) {
            CallOutcome::Applied(frozen) => frozen,
            CallOutcome::Rejected(error) => return CallOutcome::Rejected(error),
            CallOutcome::Indeterminate => return CallOutcome::Indeterminate,
        };
        let receipt = match (CaptureReceipt {
            operation: request.operation,
            continuation: request.continuation,
            scope: request.scope,
            snapshot: frozen.snapshot.body.snapshot,
            source: request.source,
            profile: request.profile,
            lineage: request.lineage,
            state_digest: frozen.snapshot.body.state_digest,
            snapshot_digest: frozen.snapshot.body_digest,
            safe_point_digest: frozen.safe_point.receipt_digest,
            receipt_digest: Digest::ZERO,
        })
        .seal()
        {
            Ok(receipt) => receipt,
            Err(error) => return CallOutcome::Rejected(Self::error(format!("{error:?}"))),
        };
        let request_digest = match Self::capture_request_digest(
            receipt.operation,
            receipt.continuation,
            receipt.scope,
            &receipt.source,
            &receipt.profile,
            &receipt.lineage,
        ) {
            Ok(digest) => digest,
            Err(error) => return CallOutcome::Rejected(error),
        };
        let pending = PendingCapture {
            request_digest,
            captured: coordinator::CapturedSnapshot {
                snapshot: frozen.snapshot,
                safe_point: frozen.safe_point,
                receipt,
            },
        };
        if let Err(error) = self.remember_capture(pending.clone()) {
            return CallOutcome::Rejected(error);
        }
        let captured = match self.persist_pending_capture(&pending) {
            CapturePersistence::Persisted(captured) => *captured,
            CapturePersistence::Rejected(error) => return CallOutcome::Rejected(error),
            CapturePersistence::Indeterminate => return CallOutcome::Indeterminate,
        };
        if self.lose_capture_ack_once {
            self.lose_capture_ack_once = false;
            return CallOutcome::Indeterminate;
        }
        self.forget_capture(request.operation);
        CallOutcome::Applied(coordinator::CapturedRuntime {
            snapshot: captured.snapshot,
            safe_point: captured.safe_point,
            receipt: Some(captured.receipt),
            frozen: (),
        })
    }

    fn query_capture(
        &mut self,
        request: coordinator::QueryCaptureRequest,
    ) -> QueryOutcome<coordinator::CapturedSnapshot, Self::Error> {
        let request_digest = match Self::capture_request_digest(
            request.operation,
            request.continuation,
            request.scope,
            &request.source,
            &request.profile,
            &request.lineage,
        ) {
            Ok(digest) => digest,
            Err(error) => return QueryOutcome::Rejected(error),
        };
        match self.read_durable_capture(&request, request_digest) {
            Ok(DurableCapture::Captured(captured)) => {
                self.forget_capture(request.operation);
                QueryOutcome::Applied(*captured)
            }
            Ok(DurableCapture::Absent) => QueryOutcome::Absent,
            Ok(DurableCapture::Armed) => {
                // A process-local sealed value can complete the armed row
                // without freezing a second time. A fresh runtime has no
                // such token and must report the armed/not-captured state as
                // indeterminate, never as absent or retry authority.
                let pending = match self.pending_capture(request.operation, request_digest) {
                    Ok(Some(pending)) => pending,
                    Ok(None) => return QueryOutcome::Indeterminate,
                    Err(error) => return QueryOutcome::Rejected(error),
                };
                match self.persist_pending_capture(&pending) {
                    CapturePersistence::Persisted(captured) => {
                        self.forget_capture(request.operation);
                        QueryOutcome::Applied(*captured)
                    }
                    CapturePersistence::Rejected(error) => QueryOutcome::Rejected(error),
                    CapturePersistence::Indeterminate => QueryOutcome::Indeterminate,
                }
            }
            Err(CaptureReadError::Rejected(error)) => QueryOutcome::Rejected(error),
            Err(CaptureReadError::Indeterminate) => QueryOutcome::Indeterminate,
        }
    }

    fn retire_capture(&mut self, receipt: &CaptureReceipt) -> Result<(), Self::Error> {
        receipt
            .verify()
            .map_err(|error| Self::error(format!("invalid capture retirement receipt: {error}")))?;
        let request_digest = Self::capture_request_digest(
            receipt.operation,
            receipt.continuation,
            receipt.scope,
            &receipt.source,
            &receipt.profile,
            &receipt.lineage,
        )?;
        if self.retired_captures.contains(&(receipt.operation, request_digest)) {
            return Ok(());
        }
        let receipt_bytes = postcard::to_allocvec(receipt)
            .map_err(|error| Self::error(format!("cannot encode capture receipt: {error}")))?;
        let database = self.provider.database();
        let connection = database.lock().map_err(Self::error)?;
        let transaction = connection.unchecked_transaction().map_err(Self::error)?;
        let stored: Option<(Vec<u8>, String, Option<Vec<u8>>)> = transaction
            .query_row(
                "SELECT request_digest, status, receipt FROM visa_runtime_captures
                 WHERE operation_id = ?1",
                params![receipt.operation.0.to_vec()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(Self::error)?;
        let Some((stored_digest, status, stored_receipt)) = stored else {
            self.retired_captures.push((receipt.operation, request_digest));
            return Ok(());
        };
        if stored_digest.as_slice() != request_digest.0
            || status != "captured"
            || stored_receipt.as_deref() != Some(receipt_bytes.as_slice())
        {
            return Err(Self::error("capture retirement does not match durable facts"));
        }
        if transaction
            .execute(
                "DELETE FROM visa_runtime_captures
                 WHERE operation_id = ?1 AND request_digest = ?2 AND status = 'captured'
                   AND receipt = ?3",
                params![receipt.operation.0.to_vec(), request_digest.0.to_vec(), receipt_bytes,],
            )
            .map_err(Self::error)?
            != 1
        {
            return Err(Self::error("capture retirement lost its exact durable row"));
        }
        transaction.commit().map_err(Self::error)?;
        self.forget_capture(receipt.operation);
        self.retired_captures.push((receipt.operation, request_digest));
        Ok(())
    }

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
        self.source_restoration = None;
        if let Err(error) = source.begin_continuation(Self::source_context(&request)) {
            return CallOutcome::Rejected(Self::error(format!("{error:?}")));
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
                return CallOutcome::Rejected(Self::error(format!("{error:?}")));
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
        if request.snapshot.body.source_cut.runtime != Self::reference_runtime_coordinate() {
            return CallOutcome::Rejected(Self::error(
                "source snapshot runtime coordinate does not belong to the reference runtime",
            ));
        }
        if let Some(receipt) = self.source_restoration.clone()
            && receipt.continuation == request.continuation
            && receipt.snapshot == request.snapshot.body.snapshot
            && receipt.source == request.source
            && receipt.snapshot_digest == request.snapshot.body_digest
        {
            return CallOutcome::Applied(receipt);
        }
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
                snapshot_digest: request.snapshot.body_digest,
                source: request.source,
                execution_epoch: source.binding().execution_epoch(),
                receipt_digest: Digest::ZERO,
            }
            .seal()
            .expect("reference source restoration receipt is encodable");
            self.source_restoration = Some(receipt.clone());
            self.source = Some(source);
            return CallOutcome::Applied(receipt);
        }
        let requested_binding = match Self::local_binding(&request.source) {
            Ok(binding_id) => binding_id,
            Err(error) => return CallOutcome::Rejected(error),
        };
        let source = self.source.as_mut().expect("source was checked above");
        if source.binding().binding_id() != requested_binding {
            return CallOutcome::Rejected(Self::error(
                "restore source binding coordinate does not match the live source",
            ));
        }
        // A captured source is frozen and the frontend deliberately forbids
        // restoring over it. Drop that host-local instance and rebuild a
        // fresh source from portable state through the same path used after a
        // process restart. The exact restoration receipt above makes repeats
        // idempotent after this succeeds.
        self.source = None;
        self.restore_source(request)
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
        let profile = DurableKvProfile;
        let state = match profile.state_codec().decode(&request.snapshot.body.state) {
            Ok(state) => state,
            Err(error) => return CallOutcome::Rejected(Self::error(error)),
        };
        if request.preparation.destination != request.destination
            || request.commit.continuation != request.continuation
            || request.commit.snapshot != request.snapshot.body.snapshot
            || request.commit.destination != request.destination
            || request.commit.binding_receipt_digest != request.preparation.receipt_digest
        {
            return CallOutcome::Rejected(Self::error(
                "destination restore request does not match preparation or commit",
            ));
        }
        if let Err(error) = profile.validate_resources(&state, &request.snapshot.body.resources) {
            return CallOutcome::Rejected(Self::error(format!("{error:?}")));
        }
        if request.preparation.grants.len() != request.snapshot.body.resources.len() {
            return CallOutcome::Rejected(Self::error(
                "authority returned a grant set that does not match profile requirements",
            ));
        }
        let mut destination_grant: Option<&BindingGrant> = None;
        for requirement in &request.snapshot.body.resources {
            let mut matches = request
                .preparation
                .grants
                .iter()
                .filter(|grant| grant.requirement == requirement.id);
            let Some(grant) = matches.next() else {
                return CallOutcome::Rejected(Self::error(
                    "authority returned no grant for a profile requirement",
                ));
            };
            if matches.next().is_some() {
                return CallOutcome::Rejected(Self::error(
                    "authority returned multiple grants for a profile requirement",
                ));
            }
            if let Err(error) = profile.validate_binding(&state, requirement, grant) {
                return CallOutcome::Rejected(Self::error(format!("{error:?}")));
            }
            if let Some(selected) = destination_grant
                && (selected.binding != grant.binding
                    || selected.provider != grant.provider
                    || selected.provider_generation != grant.provider_generation)
            {
                return CallOutcome::Rejected(Self::error(
                    "authority grants disagree on the reference destination binding",
                ));
            }
            destination_grant = Some(grant);
        }
        let Some(grant) = destination_grant else {
            return CallOutcome::Rejected(Self::error("authority returned no destination grant"));
        };
        if grant.provider != Self::reference_provider_coordinate(grant.provider_generation) {
            return CallOutcome::Rejected(Self::error(
                "authority grant names an unknown reference provider",
            ));
        }
        let destination_owner = match Self::local_binding(&request.destination) {
            Ok(owner) => owner,
            Err(error) => return CallOutcome::Rejected(error),
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
        if binding.provider_generation() != grant.provider_generation
            || binding.rights().bits() != grant.granted_rights.0
            || binding.execution_epoch() != request.commit.execution_epoch
            || binding.owner() != destination_owner
        {
            return CallOutcome::Rejected(Self::error(
                "authority grant does not match the live provider binding",
            ));
        }
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
            snapshot_digest: request.commit.snapshot_digest,
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
        let Some(binding) = request.binding.as_ref() else {
            return QueryOutcome::Indeterminate;
        };
        let binding_id = match Self::local_binding(binding) {
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
            snapshot_digest: request.commit.snapshot_digest,
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

impl CoordinatorRuntimeAdapter {
    fn remember_capture(&mut self, pending: PendingCapture) -> Result<(), CoordinatorRuntimeError> {
        if let Some(existing) = self.pending_captures.iter().find(|existing| {
            existing.captured.receipt.operation == pending.captured.receipt.operation
        }) {
            if existing.request_digest != pending.request_digest
                || existing.captured != pending.captured
            {
                return Err(Self::error("capture operation request mismatch"));
            }
            return Ok(());
        }
        self.pending_captures.push(pending);
        Ok(())
    }

    fn pending_capture(
        &self,
        operation: visa_core::OperationId,
        request_digest: Digest,
    ) -> Result<Option<PendingCapture>, CoordinatorRuntimeError> {
        let Some(pending) = self
            .pending_captures
            .iter()
            .find(|pending| pending.captured.receipt.operation == operation)
        else {
            return Ok(None);
        };
        if pending.request_digest != request_digest {
            return Err(Self::error("capture operation request mismatch"));
        }
        Ok(Some(pending.clone()))
    }

    fn forget_capture(&mut self, operation: visa_core::OperationId) {
        self.pending_captures.retain(|pending| pending.captured.receipt.operation != operation);
    }

    fn arm_durable_capture(
        &self,
        operation: visa_core::OperationId,
        request_digest: Digest,
    ) -> CaptureArming {
        let database = self.provider.database();
        let armed = database.lock().and_then(|connection| {
            let transaction = connection.unchecked_transaction()?;
            let inserted = transaction.execute(
                "INSERT OR IGNORE INTO visa_runtime_captures
                 (operation_id, request_digest, status)
                 VALUES (?1, ?2, 'armed')",
                params![operation.0.to_vec(), request_digest.0.to_vec()],
            )?;
            let row: (Vec<u8>, String) = transaction.query_row(
                "SELECT request_digest, status FROM visa_runtime_captures
                 WHERE operation_id = ?1",
                params![operation.0.to_vec()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            transaction.commit()?;
            Ok((inserted, row))
        });
        let (inserted, (stored_digest, status)) = match armed {
            Ok(result) => result,
            Err(_) => return CaptureArming::Indeterminate,
        };
        if stored_digest.as_slice() != request_digest.0 {
            return CaptureArming::Rejected(Self::error("capture operation request mismatch"));
        }
        match status.as_str() {
            "armed" if inserted == 1 => CaptureArming::Armed,
            "armed" => CaptureArming::AlreadyArmed,
            "captured" => CaptureArming::AlreadyCaptured,
            _ => CaptureArming::Rejected(Self::error("durable capture has an unknown status")),
        }
    }

    fn read_durable_capture(
        &self,
        request: &coordinator::QueryCaptureRequest,
        request_digest: Digest,
    ) -> Result<DurableCapture, CaptureReadError> {
        type CaptureRow = (Vec<u8>, String, Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>);
        let database = self.provider.database();
        let row: Result<Option<CaptureRow>, _> = database.lock().and_then(|connection| {
            connection
                .query_row(
                    "SELECT request_digest, status, snapshot, safe_point, receipt
                     FROM visa_runtime_captures WHERE operation_id = ?1",
                    params![request.operation.0.to_vec()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
                )
                .optional()
                .map_err(Into::into)
        });
        let Some((stored_digest, status, snapshot, safe_point, receipt)) =
            row.map_err(|_| CaptureReadError::Indeterminate)?
        else {
            return Ok(DurableCapture::Absent);
        };
        if stored_digest.as_slice() != request_digest.0 {
            return Err(CaptureReadError::Rejected(Self::error(
                "capture operation request mismatch",
            )));
        }
        if status == "armed" {
            if snapshot.is_some() || safe_point.is_some() || receipt.is_some() {
                return Err(CaptureReadError::Rejected(Self::error(
                    "armed capture unexpectedly contains sealed facts",
                )));
            }
            return Ok(DurableCapture::Armed);
        }
        if status != "captured" {
            return Err(CaptureReadError::Rejected(Self::error(
                "durable capture has an unknown status",
            )));
        }
        let (Some(snapshot), Some(safe_point), Some(receipt)) = (snapshot, safe_point, receipt)
        else {
            return Err(CaptureReadError::Rejected(Self::error(
                "captured durable capture is missing sealed facts",
            )));
        };
        let snapshot = postcard::from_bytes::<SnapshotEnvelope>(&snapshot)
            .map_err(|_| CaptureReadError::Rejected(Self::error("durable capture is corrupt")))?;
        let safe_point = postcard::from_bytes::<SafePointReceipt>(&safe_point)
            .map_err(|_| CaptureReadError::Rejected(Self::error("durable capture is corrupt")))?;
        let receipt = postcard::from_bytes::<CaptureReceipt>(&receipt)
            .map_err(|_| CaptureReadError::Rejected(Self::error("durable capture is corrupt")))?;
        Self::validate_captured(request, &snapshot, &safe_point, &receipt)
            .map_err(CaptureReadError::Rejected)?;
        Ok(DurableCapture::Captured(Box::new(coordinator::CapturedSnapshot {
            snapshot,
            safe_point,
            receipt,
        })))
    }

    fn validate_captured(
        request: &coordinator::QueryCaptureRequest,
        snapshot: &SnapshotEnvelope,
        safe_point: &SafePointReceipt,
        receipt: &CaptureReceipt,
    ) -> Result<(), CoordinatorRuntimeError> {
        snapshot
            .verify()
            .map_err(|error| Self::error(format!("invalid durable snapshot: {error:?}")))?;
        safe_point
            .verify()
            .map_err(|error| Self::error(format!("invalid durable safe point: {error:?}")))?;
        receipt
            .verify()
            .map_err(|error| Self::error(format!("invalid durable capture receipt: {error:?}")))?;
        if snapshot.body.continuation != request.continuation
            || snapshot.body.scope != request.scope
            || snapshot.body.profile != request.profile
            || snapshot.body.lineage != request.lineage
            || snapshot.body.source_cut.runtime != Self::reference_runtime_coordinate()
            || receipt.operation != request.operation
            || receipt.continuation != request.continuation
            || receipt.scope != request.scope
            || receipt.snapshot != snapshot.body.snapshot
            || receipt.source != request.source
            || receipt.profile != request.profile
            || receipt.lineage != request.lineage
            || receipt.state_digest != snapshot.body.state_digest
            || receipt.snapshot_digest != snapshot.body_digest
            || receipt.safe_point_digest != safe_point.receipt_digest
            || safe_point.continuation != snapshot.body.continuation
            || safe_point.scope != snapshot.body.scope
            || safe_point.runtime != snapshot.body.source_cut.runtime
            || safe_point.cut_sequence != snapshot.body.source_cut.cut_sequence
            || safe_point.portable_state_digest != snapshot.body.state_digest
            || safe_point.receipt_digest != snapshot.body.source_cut.receipt_digest
        {
            return Err(Self::error("durable capture does not match its request"));
        }
        Ok(())
    }

    fn persist_pending_capture(&mut self, pending: &PendingCapture) -> CapturePersistence {
        if self.fail_capture_persistence_once {
            self.fail_capture_persistence_once = false;
            return CapturePersistence::Indeterminate;
        }
        let snapshot_bytes = match postcard::to_allocvec(&pending.captured.snapshot) {
            Ok(bytes) => bytes,
            Err(_) => return CapturePersistence::Indeterminate,
        };
        let safe_point_bytes = match postcard::to_allocvec(&pending.captured.safe_point) {
            Ok(bytes) => bytes,
            Err(_) => return CapturePersistence::Indeterminate,
        };
        let receipt_bytes = match postcard::to_allocvec(&pending.captured.receipt) {
            Ok(bytes) => bytes,
            Err(_) => return CapturePersistence::Indeterminate,
        };
        if snapshot_bytes.len() > MAX_CAPTURE_FACT_BYTES
            || safe_point_bytes.len() > MAX_CAPTURE_FACT_BYTES
            || receipt_bytes.len() > MAX_CAPTURE_FACT_BYTES
        {
            return CapturePersistence::Rejected(Self::error(
                "durable capture fact exceeds the storage limit",
            ));
        }
        let database = self.provider.database();
        let persisted = database.lock().and_then(|connection| {
            let transaction = connection.unchecked_transaction()?;
            transaction.execute(
                "UPDATE visa_runtime_captures
                 SET status = 'captured', snapshot = ?3, safe_point = ?4, receipt = ?5
                 WHERE operation_id = ?1 AND request_digest = ?2 AND status = 'armed'",
                params![
                    pending.captured.receipt.operation.0.to_vec(),
                    pending.request_digest.0.to_vec(),
                    snapshot_bytes,
                    safe_point_bytes,
                    receipt_bytes,
                ],
            )?;
            transaction.commit()?;
            Ok(())
        });
        if persisted.is_err() {
            return CapturePersistence::Indeterminate;
        }
        let receipt = &pending.captured.receipt;
        let request = coordinator::QueryCaptureRequest {
            operation: receipt.operation,
            continuation: receipt.continuation,
            scope: receipt.scope,
            source: receipt.source.clone(),
            profile: receipt.profile.clone(),
            lineage: receipt.lineage.clone(),
        };
        match self.read_durable_capture(&request, pending.request_digest) {
            Ok(DurableCapture::Captured(captured)) if *captured == pending.captured => {
                CapturePersistence::Persisted(captured)
            }
            Ok(DurableCapture::Captured(_)) => CapturePersistence::Rejected(Self::error(
                "durable capture differs from sealed process-local capture",
            )),
            Ok(DurableCapture::Absent | DurableCapture::Armed) => CapturePersistence::Indeterminate,
            Err(CaptureReadError::Indeterminate) => CapturePersistence::Indeterminate,
            Err(CaptureReadError::Rejected(error)) => CapturePersistence::Rejected(error),
        }
    }

    fn capture_request_digest(
        operation: visa_core::OperationId,
        continuation: visa_core::ContinuationId,
        scope: visa_core::ScopeId,
        source: &ExternalCoordinate,
        profile: &visa_core::ProfileRef,
        lineage: &visa_core::LineageAdvance,
    ) -> Result<Digest, CoordinatorRuntimeError> {
        canonical_digest(&(operation, continuation, scope, source, profile, lineage))
            .map_err(Self::error)
    }
}

impl WasmtimeVertical {
    pub fn new() -> Result<Self, RuntimeError> {
        let bytes = visa_wasi::counter_component_bytes()?;
        Ok(Self { prepared: visa_wasi::WasiFrontend::new(DurableKvProfile).preflight(&bytes)? })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use visa_coordinator::{FreezeSourceRequest, RestoreSourceRequest, RuntimePort};
    use visa_core::{ContinuationId, LineageAdvance, LineageId, LineagePoint, ScopeId};

    #[test]
    fn in_process_abort_rebuilds_the_frozen_source_before_restore() {
        let database = crate::db::ReferenceDatabase::in_memory().unwrap();
        let authority = Authority::new(database.clone()).unwrap();
        let source = authority
            .bootstrap(
                "runtime-restore",
                0,
                crate::authority::Rights::READ | crate::authority::Rights::WRITE,
            )
            .unwrap();
        let provider = DurableKvProvider::new(database);
        let binding = provider.bind_bootstrap_source(&authority, &source.binding_id).unwrap();
        let vertical = WasmtimeVertical::new().unwrap();
        let continuation = ContinuationId::from_u128(1);
        let scope = ScopeId::from_u128(2);
        let lineage = LineageAdvance {
            parent: LineagePoint {
                lineage: LineageId::from_u128(3),
                generation: 0,
                state_digest: Digest::ZERO,
            },
            successor_generation: 1,
        };
        let source_coordinate = ExternalCoordinate {
            authority: visa_core::AuthorityId::from_u128(1),
            value: source.binding_id.as_bytes().to_vec(),
        };
        let instance = ReferenceInstance::source_with_context(
            &vertical.prepared,
            provider.clone(),
            binding,
            SnapshotContext {
                snapshot: SnapshotId::from_u128(4),
                continuation,
                scope,
                lineage: lineage.clone(),
                runtime: CoordinatorRuntimeAdapter::reference_runtime_coordinate(),
                cut_sequence: 0,
                receipt_digest: Digest::ZERO,
            },
        )
        .unwrap();
        let mut runtime = CoordinatorRuntimeAdapter::new(authority, provider, vertical);
        runtime.install_source(instance);
        let frozen = match runtime.freeze_source(FreezeSourceRequest {
            operation: visa_core::OperationId::from_u128(5),
            continuation,
            scope,
            source: source_coordinate.clone(),
            profile: DurableKvProfile.profile_ref(),
            lineage,
        }) {
            CallOutcome::Applied(frozen) => frozen,
            _ => panic!("source freeze failed"),
        };
        let restored = runtime.restore_source(RestoreSourceRequest {
            continuation,
            snapshot: frozen.snapshot,
            source: source_coordinate,
        });
        assert!(matches!(restored, CallOutcome::Applied(_)));
        assert_eq!(runtime.source_mut().unwrap().increment().unwrap(), 1);
    }
}
