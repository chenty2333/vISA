use serde::{Deserialize, Serialize};
use visa_core::{
    AbortPreparationReceipt, ActivationPermitReceipt, AuthorityCommitReceipt,
    BindingPreparationReceipt, ContinuationId, ContinuationIntent, ContinuationRecord,
    ContractError, DestinationRestoreReceipt, Digest, Event, ExternalCoordinate, LineagePoint,
    OperationId, Progress, ResourceRequirement, RetirementReceipt, RuntimeActivationReceipt,
    RuntimePreparationReceipt, SnapshotEnvelope, SnapshotId, SnapshotReceipt,
    SourceRestorationReceipt, apply, canonical_digest,
};

use crate::{AuthorityPort, LineageCreate, LineageUpdate, RecordStore, RuntimePort};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowIntent {
    pub continuation: ContinuationIntent,
    pub source: ExternalCoordinate,
    pub destination: ExternalCoordinate,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionKind {
    Capture = 1,
    PrepareBindings = 2,
    PrepareDestination = 3,
    CommitFence = 4,
    AbortBindings = 5,
    RestoreSource = 6,
    RestoreDestination = 7,
    PermitActivation = 8,
    Activate = 9,
    Retire = 10,
}

impl ActionKind {
    fn recovery(self) -> RecoveryRequirement {
        match self {
            Self::Capture => RecoveryRequirement::CaptureUnknown,
            Self::PrepareBindings | Self::PrepareDestination | Self::AbortBindings => {
                RecoveryRequirement::PreparationUnknown
            }
            Self::CommitFence => RecoveryRequirement::CommitUnknown,
            Self::RestoreSource => RecoveryRequirement::SourceRestoreUnknown,
            Self::RestoreDestination => RecoveryRequirement::DestinationRestoreUnknown,
            Self::PermitActivation | Self::Activate => RecoveryRequirement::ActivationUnknown,
            Self::Retire => RecoveryRequirement::RetirementUnknown,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryRequirement {
    CaptureUnknown,
    PreparationUnknown,
    CommitUnknown,
    SourceRestoreUnknown,
    DestinationRestoreUnknown,
    ActivationUnknown,
    RetirementUnknown,
    StoreConflict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionMode {
    Query,
    Invoke,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Action {
    pub operation: OperationId,
    pub request: ActionRequest,
    pub request_digest: Digest,
}

/// Exact portable material required by one port operation. Ports execute from
/// this value alone and never read coordinator storage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionRequest {
    Capture {
        continuation: ContinuationId,
        scope: visa_core::ScopeId,
        source: ExternalCoordinate,
        lineage_parent: LineagePoint,
        profile: visa_core::ProfileRef,
    },
    PrepareBindings {
        continuation: ContinuationId,
        snapshot: SnapshotId,
        snapshot_digest: Digest,
        source: ExternalCoordinate,
        destination: ExternalCoordinate,
        resources: alloc::vec::Vec<ResourceRequirement>,
    },
    PrepareDestination {
        continuation: ContinuationId,
        snapshot: SnapshotEnvelope,
        destination: ExternalCoordinate,
        bindings: BindingPreparationReceipt,
    },
    CommitFence {
        continuation: ContinuationId,
        snapshot: SnapshotId,
        snapshot_digest: Digest,
        source: ExternalCoordinate,
        destination: ExternalCoordinate,
        binding_receipt_digest: Digest,
    },
    AbortBindings {
        continuation: ContinuationId,
        snapshot: SnapshotId,
        snapshot_digest: Digest,
        source: ExternalCoordinate,
        destination: ExternalCoordinate,
        bindings: BindingPreparationReceipt,
    },
    RestoreSource {
        continuation: ContinuationId,
        source: ExternalCoordinate,
        snapshot: SnapshotEnvelope,
    },
    RestoreDestination {
        continuation: ContinuationId,
        destination: ExternalCoordinate,
        snapshot: SnapshotEnvelope,
        preparation: RuntimePreparationReceipt,
        bindings: BindingPreparationReceipt,
    },
    PermitActivation {
        continuation: ContinuationId,
        snapshot: SnapshotId,
        snapshot_digest: Digest,
        destination: ExternalCoordinate,
        commit: AuthorityCommitReceipt,
    },
    Activate {
        continuation: ContinuationId,
        destination: ExternalCoordinate,
        snapshot: SnapshotEnvelope,
        preparation: RuntimePreparationReceipt,
        permit: ActivationPermitReceipt,
    },
    Retire {
        continuation: ContinuationId,
        snapshot: SnapshotId,
        snapshot_digest: Digest,
        source: ExternalCoordinate,
        runtime_activation: RuntimeActivationReceipt,
    },
}

impl ActionRequest {
    #[must_use]
    pub const fn kind(&self) -> ActionKind {
        match self {
            Self::Capture { .. } => ActionKind::Capture,
            Self::PrepareBindings { .. } => ActionKind::PrepareBindings,
            Self::PrepareDestination { .. } => ActionKind::PrepareDestination,
            Self::CommitFence { .. } => ActionKind::CommitFence,
            Self::AbortBindings { .. } => ActionKind::AbortBindings,
            Self::RestoreSource { .. } => ActionKind::RestoreSource,
            Self::RestoreDestination { .. } => ActionKind::RestoreDestination,
            Self::PermitActivation { .. } => ActionKind::PermitActivation,
            Self::Activate { .. } => ActionKind::Activate,
            Self::Retire { .. } => ActionKind::Retire,
        }
    }
}

/// The sole inbound result vocabulary. Error payloads belong to the embedding;
/// they are intentionally not recorded as authority facts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Observation<T, E> {
    Applied(T),
    /// An exact authority durably rejected the operation before applying it.
    Rejected(E),
    /// The claimed exact outcome cannot be trusted (conflict, corruption, or
    /// invalid receipt material) and therefore grants no abort/retry authority.
    Unverifiable(E),
    Absent,
    Indeterminate,
}

/// The sole outbound workflow vocabulary.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Decision {
    Arm(ActionKind),
    Action { mode: ActionMode, action: Action },
    Wait(RecoveryRequirement),
    Complete,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PendingState {
    NeverInvoked,
    InvokePermitted,
    InvokeUnknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingAction {
    pub action: Action,
    pub state: PendingState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkflowStatus {
    Forward,
    RollingBack,
    RolledBack,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowRecord {
    pub core: ContinuationRecord,
    pub source: ExternalCoordinate,
    pub destination: ExternalCoordinate,
    pub recovery: Option<RecoveryRequirement>,
    /// Coordinator-owned rollback lifecycle. Core `Aborted` is reserved for
    /// cancellation before capture; a captured rollback stays `Captured` and
    /// is terminal only after exact destination cleanup and source restore.
    pub status: WorkflowStatus,
    pub pending: Option<PendingAction>,
    pub bindings: Option<BindingPreparationReceipt>,
    pub destination_prepared: Option<RuntimePreparationReceipt>,
    pub commit: Option<AuthorityCommitReceipt>,
    pub destination_restored: Option<DestinationRestoreReceipt>,
    pub activation_permit: Option<ActivationPermitReceipt>,
    pub runtime_activation: Option<RuntimeActivationReceipt>,
    pub bindings_aborted: Option<AbortPreparationReceipt>,
    pub source_restored: Option<SourceRestorationReceipt>,
    pub retired: Option<RetirementReceipt>,
}

impl WorkflowRecord {
    fn snapshot(&self) -> Option<(SnapshotId, Digest)> {
        self.core.snapshot.as_ref().map(|value| (value.body.snapshot, value.body_digest))
    }
}

fn snapshot(record: &WorkflowRecord) -> Result<SnapshotEnvelope, ContractError> {
    record.core.snapshot.clone().ok_or(ContractError::SnapshotMismatch)
}

fn build_request(
    record: &WorkflowRecord,
    kind: ActionKind,
) -> Result<ActionRequest, ContractError> {
    let continuation = record.core.intent.id;
    match kind {
        ActionKind::Capture => Ok(ActionRequest::Capture {
            continuation,
            scope: record.core.intent.scope,
            source: record.source.clone(),
            lineage_parent: record.core.intent.lineage_parent.clone(),
            profile: record.core.intent.profile.clone(),
        }),
        ActionKind::PrepareBindings => {
            let snapshot = snapshot(record)?;
            Ok(ActionRequest::PrepareBindings {
                continuation,
                snapshot: snapshot.body.snapshot,
                snapshot_digest: snapshot.body_digest,
                source: record.source.clone(),
                destination: record.destination.clone(),
                resources: snapshot.body.resources,
            })
        }
        ActionKind::PrepareDestination => Ok(ActionRequest::PrepareDestination {
            continuation,
            snapshot: snapshot(record)?,
            destination: record.destination.clone(),
            bindings: record.bindings.clone().ok_or(ContractError::SnapshotMismatch)?,
        }),
        ActionKind::CommitFence => {
            let snapshot = snapshot(record)?;
            Ok(ActionRequest::CommitFence {
                continuation,
                snapshot: snapshot.body.snapshot,
                snapshot_digest: snapshot.body_digest,
                source: record.source.clone(),
                destination: record.destination.clone(),
                binding_receipt_digest: record
                    .bindings
                    .as_ref()
                    .ok_or(ContractError::SnapshotMismatch)?
                    .receipt_digest,
            })
        }
        ActionKind::AbortBindings => {
            let snapshot = snapshot(record)?;
            Ok(ActionRequest::AbortBindings {
                continuation,
                snapshot: snapshot.body.snapshot,
                snapshot_digest: snapshot.body_digest,
                source: record.source.clone(),
                destination: record.destination.clone(),
                bindings: record.bindings.clone().ok_or(ContractError::SnapshotMismatch)?,
            })
        }
        ActionKind::RestoreSource => Ok(ActionRequest::RestoreSource {
            continuation,
            source: record.source.clone(),
            snapshot: snapshot(record)?,
        }),
        ActionKind::RestoreDestination => Ok(ActionRequest::RestoreDestination {
            continuation,
            destination: record.destination.clone(),
            snapshot: snapshot(record)?,
            preparation: record
                .destination_prepared
                .clone()
                .ok_or(ContractError::SnapshotMismatch)?,
            bindings: record.bindings.clone().ok_or(ContractError::SnapshotMismatch)?,
        }),
        ActionKind::PermitActivation => {
            let snapshot = snapshot(record)?;
            Ok(ActionRequest::PermitActivation {
                continuation,
                snapshot: snapshot.body.snapshot,
                snapshot_digest: snapshot.body_digest,
                destination: record.destination.clone(),
                commit: record.commit.clone().ok_or(ContractError::SnapshotMismatch)?,
            })
        }
        ActionKind::Activate => Ok(ActionRequest::Activate {
            continuation,
            destination: record.destination.clone(),
            snapshot: snapshot(record)?,
            preparation: record
                .destination_prepared
                .clone()
                .ok_or(ContractError::SnapshotMismatch)?,
            permit: record.activation_permit.clone().ok_or(ContractError::SnapshotMismatch)?,
        }),
        ActionKind::Retire => {
            let snapshot = snapshot(record)?;
            Ok(ActionRequest::Retire {
                continuation,
                snapshot: snapshot.body.snapshot,
                snapshot_digest: snapshot.body_digest,
                source: record.source.clone(),
                runtime_activation: record
                    .runtime_activation
                    .clone()
                    .ok_or(ContractError::SnapshotMismatch)?,
            })
        }
    }
}

#[derive(Debug)]
pub enum CoordinatorError<E> {
    Store(E),
    Contract(ContractError),
    MissingRecord,
    PendingMismatch,
    ReceiptMismatch,
    OperationAlreadyArmed,
}

#[derive(Debug)]
pub enum StepError<SE> {
    Coordinator(CoordinatorError<SE>),
}

pub struct Coordinator<S> {
    store: S,
}
impl<S> Coordinator<S> {
    #[must_use]
    pub const fn new(store: S) -> Self {
        Self { store }
    }
    #[must_use]
    pub fn into_store(self) -> S {
        self.store
    }
}

impl<S: RecordStore> Coordinator<S> {
    pub fn begin(&mut self, intent: WorkflowIntent) -> Result<(), CoordinatorError<S::Error>> {
        let core = apply(None, &Event::Begun(intent.continuation.clone()))
            .map_err(CoordinatorError::Contract)?;
        let record = WorkflowRecord {
            core,
            source: intent.source,
            destination: intent.destination,
            recovery: None,
            status: WorkflowStatus::Forward,
            pending: None,
            bindings: None,
            destination_prepared: None,
            commit: None,
            destination_restored: None,
            activation_permit: None,
            runtime_activation: None,
            bindings_aborted: None,
            source_restored: None,
            retired: None,
        };
        self.store
            .create(
                record,
                LineageCreate {
                    parent: intent.continuation.lineage_parent,
                    active_continuation: intent.continuation.id,
                },
            )
            .map_err(CoordinatorError::Store)
    }

    pub fn plan(
        &self,
        continuation: &ContinuationId,
    ) -> Result<Decision, CoordinatorError<S::Error>> {
        let record = self
            .store
            .load(continuation)
            .map_err(CoordinatorError::Store)?
            .ok_or(CoordinatorError::MissingRecord)?;
        Ok(plan_record(&record))
    }

    /// Arms first; the resulting operation is queried before its first invoke.
    pub fn arm(
        &mut self,
        continuation: &ContinuationId,
        operation: OperationId,
    ) -> Result<Action, CoordinatorError<S::Error>> {
        let current = self
            .store
            .load(continuation)
            .map_err(CoordinatorError::Store)?
            .ok_or(CoordinatorError::MissingRecord)?;
        if current.pending.is_some() {
            return Err(CoordinatorError::OperationAlreadyArmed);
        }
        let Decision::Arm(kind) = plan_record(&current) else {
            return Err(CoordinatorError::OperationAlreadyArmed);
        };
        let request = build_request(&current, kind).map_err(CoordinatorError::Contract)?;
        let request_digest =
            canonical_digest(&(operation, &request)).map_err(CoordinatorError::Contract)?;
        let action = Action { operation, request, request_digest };
        let mut next = current.clone();
        next.pending =
            Some(PendingAction { action: action.clone(), state: PendingState::NeverInvoked });
        self.store.cas(&current, next, None).map_err(CoordinatorError::Store)?;
        Ok(action)
    }

    /// Persist that an invoke is now in flight before touching a port. A
    /// restart after this CAS therefore always queries the exact operation.
    pub fn begin_invoke(
        &mut self,
        continuation: &ContinuationId,
        action: &Action,
    ) -> Result<Action, CoordinatorError<S::Error>> {
        let current = self
            .store
            .load(continuation)
            .map_err(CoordinatorError::Store)?
            .ok_or(CoordinatorError::MissingRecord)?;
        let pending = current.pending.as_ref().ok_or(CoordinatorError::PendingMismatch)?;
        if &pending.action != action || pending.state != PendingState::InvokePermitted {
            return Err(CoordinatorError::PendingMismatch);
        }
        let mut next = current.clone();
        next.pending.as_mut().expect("pending").state = PendingState::InvokeUnknown;
        self.store.cas(&current, next, None).map_err(CoordinatorError::Store)?;
        Ok(action.clone())
    }

    fn preparation_probe(
        &self,
        continuation: &ContinuationId,
    ) -> Result<(Action, RuntimePreparationReceipt), CoordinatorError<S::Error>> {
        let record = self
            .store
            .load(continuation)
            .map_err(CoordinatorError::Store)?
            .ok_or(CoordinatorError::MissingRecord)?;
        let expected =
            record.destination_prepared.clone().ok_or(CoordinatorError::ReceiptMismatch)?;
        expected.verify().map_err(CoordinatorError::Contract)?;
        let request = build_request(&record, ActionKind::PrepareDestination)
            .map_err(CoordinatorError::Contract)?;
        let request_digest = canonical_digest(&(expected.operation, &request))
            .map_err(CoordinatorError::Contract)?;
        if request_digest != expected.request_digest {
            return Err(CoordinatorError::ReceiptMismatch);
        }
        Ok((Action { operation: expected.operation, request, request_digest }, expected))
    }

    fn pending_recovery(
        &mut self,
        continuation: &ContinuationId,
        action: &Action,
        requirement: RecoveryRequirement,
    ) -> Result<Decision, CoordinatorError<S::Error>> {
        let current = self
            .store
            .load(continuation)
            .map_err(CoordinatorError::Store)?
            .ok_or(CoordinatorError::MissingRecord)?;
        if current.pending.as_ref().map(|pending| &pending.action) != Some(action) {
            return Err(CoordinatorError::PendingMismatch);
        }
        let next = recovery(current.clone(), requirement).map_err(CoordinatorError::Contract)?;
        self.store.cas(&current, next, None).map_err(CoordinatorError::Store)?;
        Ok(Decision::Wait(requirement))
    }

    fn resolve_preparation_recovery(
        &mut self,
        continuation: &ContinuationId,
        action: &Action,
    ) -> Result<Decision, CoordinatorError<S::Error>> {
        let current = self
            .store
            .load(continuation)
            .map_err(CoordinatorError::Store)?
            .ok_or(CoordinatorError::MissingRecord)?;
        if current.pending.as_ref().map(|pending| &pending.action) != Some(action) {
            return Err(CoordinatorError::PendingMismatch);
        }
        let next =
            resolve_pending_recovery(current.clone(), RecoveryRequirement::PreparationUnknown)
                .map_err(CoordinatorError::Contract)?;
        self.store.cas(&current, next.clone(), None).map_err(CoordinatorError::Store)?;
        Ok(plan_record(&next))
    }

    fn abort_uninvoked_commit(
        &mut self,
        continuation: &ContinuationId,
        action: &Action,
    ) -> Result<Decision, CoordinatorError<S::Error>> {
        let current = self
            .store
            .load(continuation)
            .map_err(CoordinatorError::Store)?
            .ok_or(CoordinatorError::MissingRecord)?;
        if current.pending.as_ref().map(|pending| &pending.action) != Some(action)
            || action.request.kind() != ActionKind::CommitFence
            || current.commit.is_some()
        {
            return Err(CoordinatorError::PendingMismatch);
        }
        let next = aborted(current.clone()).map_err(CoordinatorError::Contract)?;
        self.store.cas(&current, next.clone(), None).map_err(CoordinatorError::Store)?;
        Ok(plan_record(&next))
    }

    pub fn observe<T, E>(
        &mut self,
        continuation: &ContinuationId,
        action: &Action,
        observation: Observation<T, E>,
    ) -> Result<Decision, CoordinatorError<S::Error>>
    where
        T: Into<Receipt>,
    {
        let current = self
            .store
            .load(continuation)
            .map_err(CoordinatorError::Store)?
            .ok_or(CoordinatorError::MissingRecord)?;
        let pending = current.pending.as_ref().ok_or(CoordinatorError::PendingMismatch)?;
        if &pending.action != action {
            return Err(CoordinatorError::PendingMismatch);
        }
        let next = match observation {
            Observation::Applied(value) => {
                let resolved =
                    resolve_pending_recovery(current.clone(), action.request.kind().recovery())
                        .map_err(CoordinatorError::Contract)?;
                let applied = applied(resolved, action, value.into()).map_err(map_apply_error)?;
                if applied.status == WorkflowStatus::RollingBack && applied.commit.is_none() {
                    aborted(applied).map_err(CoordinatorError::Contract)?
                } else if applied.commit.is_some() {
                    WorkflowRecord { status: WorkflowStatus::Forward, ..applied }
                } else {
                    applied
                }
            }
            Observation::Absent
                if pending.state == PendingState::NeverInvoked
                    && current.recovery.is_none()
                    && (current.status == WorkflowStatus::Forward
                        || matches!(
                            action.request.kind(),
                            ActionKind::AbortBindings | ActionKind::RestoreSource
                        )) =>
            {
                let mut next =
                    resolve_pending_recovery(current.clone(), action.request.kind().recovery())
                        .map_err(CoordinatorError::Contract)?;
                next.pending.as_mut().expect("pending").state = PendingState::InvokePermitted;
                next
            }
            Observation::Rejected(_)
                if precommit(action.request.kind())
                    || action.request.kind() == ActionKind::CommitFence =>
            {
                aborted(current.clone()).map_err(CoordinatorError::Contract)?
            }
            Observation::Absent | Observation::Rejected(_) => {
                let mut resolved =
                    resolve_pending_recovery(current.clone(), action.request.kind().recovery())
                        .map_err(CoordinatorError::Contract)?;
                resolved.pending = None;
                if resolved.status == WorkflowStatus::RollingBack && resolved.commit.is_none() {
                    aborted(resolved).map_err(CoordinatorError::Contract)?
                } else {
                    resolved
                }
            }
            Observation::Indeterminate => {
                let mut unknown = recovery(current.clone(), action.request.kind().recovery())
                    .map_err(CoordinatorError::Contract)?;
                unknown.pending.as_mut().expect("pending").state = PendingState::InvokeUnknown;
                unknown
            }
            Observation::Unverifiable(_) => {
                let mut unknown = recovery(current.clone(), action.request.kind().recovery())
                    .map_err(CoordinatorError::Contract)?;
                unknown.pending.as_mut().expect("pending").state = PendingState::InvokeUnknown;
                unknown
            }
        };
        let lineage = lineage_update(&current, &next).map_err(CoordinatorError::Contract)?;
        self.store.cas(&current, next.clone(), lineage).map_err(CoordinatorError::Store)?;
        Ok(plan_record(&next))
    }

    /// Before commit this initiates the same source-restoration tail as a
    /// verified rejection. After commit it deliberately cannot revive source.
    pub fn abort(
        &mut self,
        continuation: &ContinuationId,
    ) -> Result<Decision, CoordinatorError<S::Error>> {
        let current = self
            .store
            .load(continuation)
            .map_err(CoordinatorError::Store)?
            .ok_or(CoordinatorError::MissingRecord)?;
        // A committed fence is irreversible. Operator abort becomes a no-op
        // and the existing destination-side recovery plan remains authoritative.
        if current.commit.is_some() {
            return Ok(plan_record(&current));
        }
        let mut next = current.clone();
        next.status = WorkflowStatus::RollingBack;
        // Never erase a pending exact operation. Even a never-invoked action is
        // queried to a conclusive Absent/Rejected/Applied observation first.
        if next.pending.is_none() && next.recovery.is_none() {
            next = aborted(next).map_err(CoordinatorError::Contract)?;
        }
        let lineage = lineage_update(&current, &next).map_err(CoordinatorError::Contract)?;
        self.store.cas(&current, next.clone(), lineage).map_err(CoordinatorError::Store)?;
        Ok(plan_record(&next))
    }

    /// Thin effect interpreter for the one action vocabulary. It deliberately
    /// does not allocate operation ids: embeddings arm those durably first.
    pub fn step<R: RuntimePort, A: AuthorityPort>(
        &mut self,
        continuation: &ContinuationId,
        runtime: &mut R,
        authority: &mut A,
    ) -> Result<Decision, StepError<S::Error>> {
        let decision = self.plan(continuation).map_err(StepError::Coordinator)?;
        let Decision::Action { mode, action } = decision else {
            return Ok(decision);
        };
        if action.request.kind() == ActionKind::CommitFence {
            let record = self
                .store
                .load(continuation)
                .map_err(CoordinatorError::Store)
                .map_err(StepError::Coordinator)?
                .ok_or(CoordinatorError::MissingRecord)
                .map_err(StepError::Coordinator)?;
            if record.recovery == Some(RecoveryRequirement::PreparationUnknown) {
                let (probe, expected) =
                    self.preparation_probe(continuation).map_err(StepError::Coordinator)?;
                return match runtime.query_prepare_destination(&probe) {
                    Observation::Applied(receipt) if receipt == expected => self
                        .resolve_preparation_recovery(continuation, &action)
                        .map_err(StepError::Coordinator),
                    Observation::Absent | Observation::Rejected(_) => self
                        .abort_uninvoked_commit(continuation, &action)
                        .map_err(StepError::Coordinator),
                    Observation::Applied(_)
                    | Observation::Unverifiable(_)
                    | Observation::Indeterminate => {
                        Ok(Decision::Wait(RecoveryRequirement::PreparationUnknown))
                    }
                };
            }
        }
        let action = if mode == ActionMode::Invoke {
            self.begin_invoke(continuation, &action).map_err(StepError::Coordinator)?
        } else {
            action
        };
        if mode == ActionMode::Invoke && action.request.kind() == ActionKind::CommitFence {
            let (probe, expected) =
                self.preparation_probe(continuation).map_err(StepError::Coordinator)?;
            match runtime.query_prepare_destination(&probe) {
                Observation::Applied(receipt) if receipt == expected => {}
                Observation::Absent | Observation::Rejected(_) => {
                    return self
                        .abort_uninvoked_commit(continuation, &action)
                        .map_err(StepError::Coordinator);
                }
                Observation::Applied(_)
                | Observation::Unverifiable(_)
                | Observation::Indeterminate => {
                    return self
                        .pending_recovery(
                            continuation,
                            &action,
                            RecoveryRequirement::PreparationUnknown,
                        )
                        .map_err(StepError::Coordinator);
                }
            }
        }
        let next = match (mode, action.request.kind()) {
            (ActionMode::Query, ActionKind::Capture) => {
                self.observe(continuation, &action, runtime.query_capture(&action))
            }
            (ActionMode::Invoke, ActionKind::Capture) => {
                self.observe(continuation, &action, runtime.capture(&action))
            }
            (ActionMode::Query, ActionKind::PrepareBindings) => {
                self.observe(continuation, &action, authority.query_prepare_bindings(&action))
            }
            (ActionMode::Invoke, ActionKind::PrepareBindings) => {
                self.observe(continuation, &action, authority.prepare_bindings(&action))
            }
            (ActionMode::Query, ActionKind::PrepareDestination) => {
                self.observe(continuation, &action, runtime.query_prepare_destination(&action))
            }
            (ActionMode::Invoke, ActionKind::PrepareDestination) => {
                self.observe(continuation, &action, runtime.prepare_destination(&action))
            }
            (ActionMode::Query, ActionKind::CommitFence) => {
                self.observe(continuation, &action, authority.query_commit_fence(&action))
            }
            (ActionMode::Invoke, ActionKind::CommitFence) => {
                self.observe(continuation, &action, authority.commit_fence(&action))
            }
            (ActionMode::Query, ActionKind::PermitActivation) => {
                self.observe(continuation, &action, authority.query_permit_activation(&action))
            }
            (ActionMode::Invoke, ActionKind::PermitActivation) => {
                self.observe(continuation, &action, authority.permit_activation(&action))
            }
            (ActionMode::Query, ActionKind::AbortBindings) => {
                self.observe(continuation, &action, authority.query_abort_bindings(&action))
            }
            (ActionMode::Invoke, ActionKind::AbortBindings) => {
                self.observe(continuation, &action, authority.abort_bindings(&action))
            }
            (ActionMode::Query, ActionKind::RestoreSource) => {
                self.observe(continuation, &action, runtime.query_restore_source(&action))
            }
            (ActionMode::Invoke, ActionKind::RestoreSource) => {
                self.observe(continuation, &action, runtime.restore_source(&action))
            }
            (ActionMode::Query, ActionKind::RestoreDestination) => {
                self.observe(continuation, &action, runtime.query_restore_destination(&action))
            }
            (ActionMode::Invoke, ActionKind::RestoreDestination) => {
                self.observe(continuation, &action, runtime.restore_destination(&action))
            }
            (ActionMode::Query, ActionKind::Activate) => {
                self.observe(continuation, &action, runtime.query_activate(&action))
            }
            (ActionMode::Invoke, ActionKind::Activate) => {
                self.observe(continuation, &action, runtime.activate(&action))
            }
            (ActionMode::Query, ActionKind::Retire) => {
                self.observe(continuation, &action, runtime.query_retire(&action))
            }
            (ActionMode::Invoke, ActionKind::Retire) => {
                self.observe(continuation, &action, runtime.retire(&action))
            }
        };
        next.map_err(StepError::Coordinator)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapturedSnapshot {
    pub snapshot: SnapshotEnvelope,
    pub receipt: SnapshotReceipt,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Receipt {
    Capture(CapturedSnapshot),
    Bindings(BindingPreparationReceipt),
    RuntimePreparation(RuntimePreparationReceipt),
    Commit(AuthorityCommitReceipt),
    Abort(AbortPreparationReceipt),
    SourceRestore(SourceRestorationReceipt),
    DestinationRestore(DestinationRestoreReceipt),
    ActivationPermit(ActivationPermitReceipt),
    RuntimeActivation(RuntimeActivationReceipt),
    Retirement(RetirementReceipt),
}
impl From<CapturedSnapshot> for Receipt {
    fn from(value: CapturedSnapshot) -> Self {
        Self::Capture(value)
    }
}
impl From<BindingPreparationReceipt> for Receipt {
    fn from(value: BindingPreparationReceipt) -> Self {
        Self::Bindings(value)
    }
}
impl From<RuntimePreparationReceipt> for Receipt {
    fn from(value: RuntimePreparationReceipt) -> Self {
        Self::RuntimePreparation(value)
    }
}
impl From<AuthorityCommitReceipt> for Receipt {
    fn from(value: AuthorityCommitReceipt) -> Self {
        Self::Commit(value)
    }
}
impl From<AbortPreparationReceipt> for Receipt {
    fn from(value: AbortPreparationReceipt) -> Self {
        Self::Abort(value)
    }
}
impl From<SourceRestorationReceipt> for Receipt {
    fn from(value: SourceRestorationReceipt) -> Self {
        Self::SourceRestore(value)
    }
}
impl From<DestinationRestoreReceipt> for Receipt {
    fn from(value: DestinationRestoreReceipt) -> Self {
        Self::DestinationRestore(value)
    }
}
impl From<ActivationPermitReceipt> for Receipt {
    fn from(value: ActivationPermitReceipt) -> Self {
        Self::ActivationPermit(value)
    }
}
impl From<RuntimeActivationReceipt> for Receipt {
    fn from(value: RuntimeActivationReceipt) -> Self {
        Self::RuntimeActivation(value)
    }
}
impl From<RetirementReceipt> for Receipt {
    fn from(value: RetirementReceipt) -> Self {
        Self::Retirement(value)
    }
}

fn plan_record(record: &WorkflowRecord) -> Decision {
    if let Some(pending) = &record.pending {
        return Decision::Action {
            mode: if pending.state == PendingState::InvokePermitted
                && (record.status == WorkflowStatus::Forward
                    || matches!(
                        pending.action.request.kind(),
                        ActionKind::AbortBindings | ActionKind::RestoreSource
                    ))
            {
                ActionMode::Invoke
            } else {
                ActionMode::Query
            },
            action: pending.action.clone(),
        };
    }
    if let Some(requirement) = record.recovery {
        return Decision::Wait(requirement);
    }
    match record.status {
        WorkflowStatus::RolledBack => return Decision::Complete,
        WorkflowStatus::RollingBack => {
            if record.bindings.is_some() && record.bindings_aborted.is_none() {
                return Decision::Arm(ActionKind::AbortBindings);
            }
            if record.source_restored.is_none() && record.core.snapshot.is_some() {
                return Decision::Arm(ActionKind::RestoreSource);
            }
            return Decision::Complete;
        }
        WorkflowStatus::Forward => {}
    }
    match record.core.phase {
        Progress::Capturing => Decision::Arm(ActionKind::Capture),
        Progress::Captured if record.bindings.is_none() => {
            Decision::Arm(ActionKind::PrepareBindings)
        }
        Progress::Captured if record.destination_prepared.is_none() => {
            Decision::Arm(ActionKind::PrepareDestination)
        }
        Progress::Captured if record.commit.is_none() => Decision::Arm(ActionKind::CommitFence),
        Progress::Captured if record.destination_restored.is_none() => {
            Decision::Arm(ActionKind::RestoreDestination)
        }
        Progress::Captured if record.activation_permit.is_none() => {
            Decision::Arm(ActionKind::PermitActivation)
        }
        Progress::Captured if record.runtime_activation.is_none() => {
            Decision::Arm(ActionKind::Activate)
        }
        Progress::Captured if record.retired.is_none() => Decision::Arm(ActionKind::Retire),
        Progress::Captured => Decision::Complete,
        Progress::Aborted => Decision::Complete,
    }
}

enum ApplyError {
    Contract(ContractError),
    Receipt,
}
fn map_apply_error<E>(error: ApplyError) -> CoordinatorError<E> {
    match error {
        ApplyError::Contract(error) => CoordinatorError::Contract(error),
        ApplyError::Receipt => CoordinatorError::ReceiptMismatch,
    }
}

fn applied(
    mut record: WorkflowRecord,
    action: &Action,
    receipt: Receipt,
) -> Result<WorkflowRecord, ApplyError> {
    match (action.request.kind(), receipt) {
        (ActionKind::Capture, Receipt::Capture(value)) => {
            if value.receipt.operation != action.operation
                || value.receipt.request_digest != action.request_digest
                || value.snapshot.body.source != record.source
            {
                return Err(ApplyError::Receipt);
            }
            record.core = apply(
                Some(&record.core),
                &Event::CaptureRecorded { snapshot: value.snapshot, receipt: value.receipt },
            )
            .map_err(ApplyError::Contract)?;
        }
        (ActionKind::PrepareBindings, Receipt::Bindings(value)) => {
            check_binding(&record, action, &value)?;
            record.bindings = Some(value);
        }
        (ActionKind::PrepareDestination, Receipt::RuntimePreparation(value)) => {
            check_runtime_preparation(&record, action, &value)?;
            record.destination_prepared = Some(value);
        }
        (ActionKind::CommitFence, Receipt::Commit(value)) => {
            check_commit(&record, action, &value)?;
            record.commit = Some(value);
        }
        (ActionKind::RestoreDestination, Receipt::DestinationRestore(value)) => {
            check_destination_restore(&record, action, &value)?;
            record.destination_restored = Some(value);
        }
        (ActionKind::PermitActivation, Receipt::ActivationPermit(value)) => {
            check_activation_permit(&record, action, &value)?;
            record.activation_permit = Some(value);
        }
        (ActionKind::Activate, Receipt::RuntimeActivation(value)) => {
            check_runtime_activation(&record, action, &value)?;
            record.runtime_activation = Some(value);
        }
        (ActionKind::Retire, Receipt::Retirement(value)) => {
            check_retirement(&record, action, &value)?;
            record.retired = Some(value);
        }
        (ActionKind::AbortBindings, Receipt::Abort(value)) => {
            check_abort(&record, action, &value)?;
            record.bindings_aborted = Some(value);
        }
        (ActionKind::RestoreSource, Receipt::SourceRestore(value)) => {
            check_source_restore(&record, action, &value)?;
            record.source_restored = Some(value);
        }
        _ => return Err(ApplyError::Receipt),
    }
    record.pending = None;
    Ok(record)
}

fn check_common(
    record: &WorkflowRecord,
    action: &Action,
    operation: OperationId,
    request_digest: Digest,
    continuation: ContinuationId,
    snapshot: SnapshotId,
    digest: Digest,
) -> Result<(), ApplyError> {
    if record.snapshot() != Some((snapshot, digest))
        || action.operation != operation
        || action.request_digest != request_digest
        || record.core.intent.id != continuation
    {
        Err(ApplyError::Receipt)
    } else {
        Ok(())
    }
}
fn check_binding(
    record: &WorkflowRecord,
    action: &Action,
    value: &BindingPreparationReceipt,
) -> Result<(), ApplyError> {
    value.verify().map_err(ApplyError::Contract)?;
    check_common(
        record,
        action,
        value.operation,
        value.request_digest,
        value.continuation,
        value.snapshot,
        value.snapshot_digest,
    )?;
    if value.destination != record.destination {
        return Err(ApplyError::Receipt);
    }
    let requirements = &record.core.snapshot.as_ref().ok_or(ApplyError::Receipt)?.body.resources;
    if value.grants.len() != requirements.len()
        || requirements.iter().any(|required| {
            !value.grants.iter().any(|grant| {
                grant.requirement == required.id && grant.granted_rights == required.required_rights
            })
        })
    {
        return Err(ApplyError::Receipt);
    }
    Ok(())
}
fn check_runtime_preparation(
    record: &WorkflowRecord,
    action: &Action,
    value: &RuntimePreparationReceipt,
) -> Result<(), ApplyError> {
    value.verify().map_err(ApplyError::Contract)?;
    check_common(
        record,
        action,
        value.operation,
        value.request_digest,
        value.continuation,
        value.snapshot,
        value.snapshot_digest,
    )?;
    if value.destination == record.destination
        && record
            .bindings
            .as_ref()
            .is_some_and(|bindings| bindings.receipt_digest == value.binding_receipt_digest)
    {
        Ok(())
    } else {
        Err(ApplyError::Receipt)
    }
}
fn check_commit(
    record: &WorkflowRecord,
    action: &Action,
    value: &AuthorityCommitReceipt,
) -> Result<(), ApplyError> {
    value.verify().map_err(ApplyError::Contract)?;
    check_common(
        record,
        action,
        value.operation,
        value.request_digest,
        value.continuation,
        value.snapshot,
        value.snapshot_digest,
    )?;
    if value.source == record.source
        && value.destination == record.destination
        && record
            .bindings
            .as_ref()
            .is_some_and(|binding| binding.receipt_digest == value.binding_receipt_digest)
    {
        Ok(())
    } else {
        Err(ApplyError::Receipt)
    }
}
fn check_destination_restore(
    record: &WorkflowRecord,
    action: &Action,
    value: &DestinationRestoreReceipt,
) -> Result<(), ApplyError> {
    value.verify().map_err(ApplyError::Contract)?;
    check_common(
        record,
        action,
        value.operation,
        value.request_digest,
        value.continuation,
        value.snapshot,
        value.snapshot_digest,
    )?;
    if value.destination == record.destination
        && record
            .destination_prepared
            .as_ref()
            .is_some_and(|prep| prep.receipt_digest == value.preparation_receipt_digest)
    {
        Ok(())
    } else {
        Err(ApplyError::Receipt)
    }
}
fn check_activation_permit(
    record: &WorkflowRecord,
    action: &Action,
    value: &ActivationPermitReceipt,
) -> Result<(), ApplyError> {
    value.verify().map_err(ApplyError::Contract)?;
    check_common(
        record,
        action,
        value.operation,
        value.request_digest,
        value.continuation,
        value.snapshot,
        value.snapshot_digest,
    )?;
    if value.destination == record.destination
        && record.commit.as_ref().is_some_and(|commit| {
            commit.receipt_digest == value.authority_commit_digest
                && commit.execution_epoch == value.execution_epoch
        })
    {
        Ok(())
    } else {
        Err(ApplyError::Receipt)
    }
}
fn check_runtime_activation(
    record: &WorkflowRecord,
    action: &Action,
    value: &RuntimeActivationReceipt,
) -> Result<(), ApplyError> {
    value.verify().map_err(ApplyError::Contract)?;
    check_common(
        record,
        action,
        value.operation,
        value.request_digest,
        value.continuation,
        value.snapshot,
        value.snapshot_digest,
    )?;
    if value.destination == record.destination
        && record
            .activation_permit
            .as_ref()
            .is_some_and(|permit| permit.receipt_digest == value.activation_permit_digest)
    {
        Ok(())
    } else {
        Err(ApplyError::Receipt)
    }
}
fn check_retirement(
    record: &WorkflowRecord,
    action: &Action,
    value: &RetirementReceipt,
) -> Result<(), ApplyError> {
    value.verify().map_err(ApplyError::Contract)?;
    check_common(
        record,
        action,
        value.operation,
        value.request_digest,
        value.continuation,
        value.snapshot,
        value.snapshot_digest,
    )?;
    if value.source == record.source
        && record.runtime_activation.as_ref().is_some_and(|activation| {
            activation.receipt_digest == value.runtime_activation_receipt_digest
        })
    {
        Ok(())
    } else {
        Err(ApplyError::Receipt)
    }
}
fn check_abort(
    record: &WorkflowRecord,
    action: &Action,
    value: &AbortPreparationReceipt,
) -> Result<(), ApplyError> {
    value.verify().map_err(ApplyError::Contract)?;
    check_common(
        record,
        action,
        value.operation,
        value.request_digest,
        value.continuation,
        value.snapshot,
        value.snapshot_digest,
    )?;
    if value.source == record.source
        && value.destination == record.destination
        && record
            .bindings
            .as_ref()
            .is_some_and(|binding| binding.receipt_digest == value.preparation_receipt_digest)
    {
        Ok(())
    } else {
        Err(ApplyError::Receipt)
    }
}
fn check_source_restore(
    record: &WorkflowRecord,
    action: &Action,
    value: &SourceRestorationReceipt,
) -> Result<(), ApplyError> {
    value.verify().map_err(ApplyError::Contract)?;
    check_common(
        record,
        action,
        value.operation,
        value.request_digest,
        value.continuation,
        value.snapshot,
        value.snapshot_digest,
    )?;
    if value.source == record.source { Ok(()) } else { Err(ApplyError::Receipt) }
}

fn precommit(kind: ActionKind) -> bool {
    matches!(
        kind,
        ActionKind::Capture | ActionKind::PrepareBindings | ActionKind::PrepareDestination
    )
}
fn aborted(mut record: WorkflowRecord) -> Result<WorkflowRecord, ContractError> {
    record.pending = None;
    record.recovery = None;
    record.status = WorkflowStatus::RollingBack;
    if record.core.phase == Progress::Capturing {
        record.core = apply(Some(&record.core), &Event::Aborted)?;
    }
    if rollback_cleanup_complete(&record) {
        record.status = WorkflowStatus::RolledBack;
    }
    Ok(record)
}

fn rollback_cleanup_complete(record: &WorkflowRecord) -> bool {
    (record.bindings.is_none() || record.bindings_aborted.is_some())
        && (record.core.snapshot.is_none() || record.source_restored.is_some())
}
fn recovery(
    mut record: WorkflowRecord,
    requirement: RecoveryRequirement,
) -> Result<WorkflowRecord, ContractError> {
    match record.recovery {
        None => record.recovery = Some(requirement),
        Some(current) if current == requirement => {}
        Some(_) => return Err(ContractError::InvalidPhase),
    }
    Ok(record)
}

fn resolve_pending_recovery(
    mut record: WorkflowRecord,
    requirement: RecoveryRequirement,
) -> Result<WorkflowRecord, ContractError> {
    if let Some(current) = record.recovery {
        if current != requirement {
            return Err(ContractError::InvalidPhase);
        }
        record.recovery = None;
    }
    Ok(record)
}
fn lineage_update(
    current: &WorkflowRecord,
    next: &WorkflowRecord,
) -> Result<Option<LineageUpdate>, ContractError> {
    let intent = &next.core.intent;
    if current.status != WorkflowStatus::RolledBack && next.status == WorkflowStatus::RolledBack {
        return Ok(Some(LineageUpdate {
            lineage: intent.lineage_parent.lineage,
            expected_head: intent.lineage_parent.clone(),
            successor: intent.lineage_parent.clone(),
            expected_active: intent.id,
            next_active: None,
        }));
    }
    let snapshot = next.core.snapshot.as_ref();
    if current.commit.is_none() && next.commit.is_some() {
        let snapshot = snapshot.ok_or(ContractError::SnapshotMismatch)?;
        return Ok(Some(LineageUpdate {
            lineage: intent.lineage_parent.lineage,
            expected_head: intent.lineage_parent.clone(),
            successor: snapshot.successor_point()?,
            expected_active: intent.id,
            next_active: Some(intent.id),
        }));
    }
    if current.runtime_activation.is_none() && next.runtime_activation.is_some() {
        let snapshot = snapshot.ok_or(ContractError::SnapshotMismatch)?;
        let successor = snapshot.successor_point()?;
        return Ok(Some(LineageUpdate {
            lineage: successor.lineage,
            expected_head: successor.clone(),
            successor,
            expected_active: intent.id,
            next_active: None,
        }));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{collections::BTreeMap, vec, vec::Vec};
    use visa_core::{
        AuthorityId, EffectClosure, LineageId, OpaqueBytes, ProfileId, ProfileRef, ProfileVersion,
        SchemaId, SchemaRef, SemanticDomainId, SemanticDomainRef,
    };

    #[derive(Default)]
    struct Store {
        records: BTreeMap<ContinuationId, WorkflowRecord>,
        heads: BTreeMap<visa_core::LineageId, LineagePoint>,
        active: BTreeMap<visa_core::LineageId, ContinuationId>,
    }
    impl RecordStore for Store {
        type Error = ();
        fn create(&mut self, record: WorkflowRecord, lineage: LineageCreate) -> Result<(), ()> {
            if self.active.contains_key(&lineage.parent.lineage)
                || self
                    .heads
                    .get(&lineage.parent.lineage)
                    .is_some_and(|head| head != &lineage.parent)
            {
                return Err(());
            }
            self.heads.insert(lineage.parent.lineage, lineage.parent.clone());
            self.active.insert(lineage.parent.lineage, lineage.active_continuation);
            self.records.insert(record.core.intent.id, record);
            Ok(())
        }
        fn load(&self, id: &ContinuationId) -> Result<Option<WorkflowRecord>, ()> {
            Ok(self.records.get(id).cloned())
        }
        fn cas(
            &mut self,
            expected: &WorkflowRecord,
            next: WorkflowRecord,
            lineage: Option<LineageUpdate>,
        ) -> Result<(), ()> {
            if self.records.get(&expected.core.intent.id) != Some(expected) {
                return Err(());
            }
            if let Some(update) = lineage {
                if self.heads.get(&update.lineage) != Some(&update.expected_head) {
                    return Err(());
                }
                if self.active.get(&update.lineage) != Some(&update.expected_active) {
                    return Err(());
                }
                self.heads.insert(update.lineage, update.successor);
                match update.next_active {
                    Some(active) => {
                        self.active.insert(update.lineage, active);
                    }
                    None => {
                        self.active.remove(&update.lineage);
                    }
                }
            }
            self.records.insert(next.core.intent.id, next);
            Ok(())
        }
        fn unfinished(&self) -> Result<Vec<ContinuationId>, ()> {
            Ok(self.records.keys().copied().collect())
        }
    }
    fn endpoint(value: u8) -> ExternalCoordinate {
        ExternalCoordinate { authority: AuthorityId::from_u128(9), value: OpaqueBytes(vec![value]) }
    }
    fn intent() -> WorkflowIntent {
        WorkflowIntent {
            continuation: ContinuationIntent {
                id: ContinuationId::from_u128(1),
                scope: visa_core::ScopeId::from_u128(2),
                lineage_parent: LineagePoint {
                    semantic_domain: SemanticDomainRef {
                        id: SemanticDomainId::from_u128(6),
                        contract_digest: Digest::of_bytes(b"test-domain"),
                        artifact_digest: Digest::of_bytes(b"test-artifact"),
                    },
                    lineage: LineageId::from_u128(3),
                    generation: 0,
                    state_digest: Digest::ZERO,
                },
                profile: ProfileRef {
                    id: ProfileId::from_u128(4),
                    version: ProfileVersion { major: 1, minor: 0 },
                    contract_digest: Digest::ZERO,
                    state_schema: SchemaRef { id: SchemaId::from_u128(5), version: 1 },
                },
            },
            source: endpoint(1),
            destination: endpoint(2),
        }
    }

    fn pending_commit(state: PendingState) -> (ContinuationId, WorkflowRecord, Action) {
        let intent = intent();
        let id = intent.continuation.id;
        let action = Action {
            operation: OperationId::from_u128(12),
            request: ActionRequest::CommitFence {
                continuation: id,
                snapshot: SnapshotId::from_u128(11),
                snapshot_digest: Digest::ZERO,
                source: intent.source.clone(),
                destination: intent.destination.clone(),
                binding_receipt_digest: Digest::ZERO,
            },
            request_digest: Digest::ZERO,
        };
        let mut core = apply(None, &Event::Begun(intent.continuation)).unwrap();
        core.phase = Progress::Captured;
        let record = WorkflowRecord {
            core,
            source: intent.source,
            destination: intent.destination,
            recovery: None,
            status: WorkflowStatus::Forward,
            pending: Some(PendingAction { action: action.clone(), state }),
            bindings: None,
            destination_prepared: None,
            commit: None,
            destination_restored: None,
            activation_permit: None,
            runtime_activation: None,
            bindings_aborted: None,
            source_restored: None,
            retired: None,
        };
        (id, record, action)
    }
    fn store_with_record(id: ContinuationId, record: WorkflowRecord) -> Store {
        let parent = record.core.intent.lineage_parent.clone();
        let mut store = Store::default();
        store.heads.insert(parent.lineage, parent);
        store.active.insert(record.core.intent.lineage_parent.lineage, id);
        store.records.insert(id, record);
        store
    }
    #[test]
    fn armed_operation_is_queried_then_only_absence_permits_same_id_invoke() {
        let mut coordinator = Coordinator::new(Store::default());
        let intent = intent();
        let id = intent.continuation.id;
        coordinator.begin(intent).unwrap();
        assert_eq!(coordinator.plan(&id).unwrap(), Decision::Arm(ActionKind::Capture));
        let action = coordinator.arm(&id, OperationId::from_u128(10)).unwrap();
        assert!(matches!(
            &action.request,
            ActionRequest::Capture { continuation, scope, source, lineage_parent, profile }
                if *continuation == id
                    && *scope == visa_core::ScopeId::from_u128(2)
                    && *source == endpoint(1)
                    && lineage_parent.generation == 0
                    && profile.id == ProfileId::from_u128(4)
        ));
        assert_eq!(
            coordinator.plan(&id).unwrap(),
            Decision::Action { mode: ActionMode::Query, action: action.clone() }
        );
        let decision =
            coordinator.observe(&id, &action, Observation::<CapturedSnapshot, ()>::Absent).unwrap();
        assert_eq!(decision, Decision::Action { mode: ActionMode::Invoke, action: action.clone() });
        coordinator.begin_invoke(&id, &action).unwrap();
        assert_eq!(
            coordinator.plan(&id).unwrap(),
            Decision::Action { mode: ActionMode::Query, action: action.clone() }
        );
        assert_eq!(
            coordinator.abort(&id).unwrap(),
            Decision::Action { mode: ActionMode::Query, action: action.clone() }
        );
        let restarted = Coordinator::new(coordinator.into_store());
        assert_eq!(
            restarted.plan(&id).unwrap(),
            Decision::Action { mode: ActionMode::Query, action }
        );
    }

    #[test]
    fn authoritative_absence_resolves_indeterminate_pending_capture() {
        let mut coordinator = Coordinator::new(Store::default());
        let intent = intent();
        let id = intent.continuation.id;
        coordinator.begin(intent).unwrap();
        let action = coordinator.arm(&id, OperationId::from_u128(10)).unwrap();
        coordinator
            .observe(&id, &action, Observation::<CapturedSnapshot, ()>::Indeterminate)
            .unwrap();
        let decision =
            coordinator.observe(&id, &action, Observation::<CapturedSnapshot, ()>::Absent).unwrap();
        assert_eq!(decision, Decision::Arm(ActionKind::Capture));
    }

    #[test]
    fn reconciled_abort_releases_lineage_but_unknown_abort_holds_it() {
        let mut coordinator = Coordinator::new(Store::default());
        let first = intent();
        let id = first.continuation.id;
        let mut second = first.clone();
        second.continuation.id = ContinuationId::from_u128(2);
        coordinator.begin(first).unwrap();
        let action = coordinator.arm(&id, OperationId::from_u128(10)).unwrap();
        coordinator
            .observe(&id, &action, Observation::<CapturedSnapshot, ()>::Indeterminate)
            .unwrap();
        assert!(matches!(coordinator.begin(second.clone()), Err(CoordinatorError::Store(()))));
        assert!(matches!(
            coordinator.abort(&id).unwrap(),
            Decision::Action { mode: ActionMode::Query, .. }
        ));
        assert!(matches!(coordinator.begin(second.clone()), Err(CoordinatorError::Store(()))));
        assert_eq!(
            coordinator.observe(&id, &action, Observation::<CapturedSnapshot, ()>::Absent).unwrap(),
            Decision::Complete
        );
        coordinator.begin(second).unwrap();
    }

    #[test]
    fn authoritative_capture_resolves_indeterminate_pending_capture() {
        let mut coordinator = Coordinator::new(Store::default());
        let intent = intent();
        let id = intent.continuation.id;
        coordinator.begin(intent).unwrap();
        let action = coordinator.arm(&id, OperationId::from_u128(10)).unwrap();
        coordinator
            .observe(&id, &action, Observation::<CapturedSnapshot, ()>::Indeterminate)
            .unwrap();
        let ActionRequest::Capture { continuation, scope, source, lineage_parent, profile } =
            &action.request
        else {
            panic!("capture request")
        };
        let snapshot = visa_core::SnapshotEnvelope::seal(visa_core::PortableSnapshot {
            snapshot: SnapshotId::from_u128(11),
            continuation: *continuation,
            scope: *scope,
            semantic_domain: lineage_parent.semantic_domain.clone(),
            lineage: visa_core::LineageAdvance {
                parent: lineage_parent.clone(),
                successor_generation: 1,
                successor_digest: Digest::ZERO,
            },
            profile: profile.clone(),
            source: source.clone(),
            semantic_cut: visa_core::SemanticCut {
                sequence: 1,
                safe_point_digest: Digest::of_bytes(&[3]),
                admission_digest: Digest::of_bytes(&[4]),
            },
            state: OpaqueBytes(vec![1]),
            state_digest: Digest::ZERO,
            resources: vec![],
            effect_closure: EffectClosure::Empty,
        })
        .unwrap();
        let receipt = SnapshotReceipt {
            operation: action.operation,
            request_digest: action.request_digest,
            continuation: *continuation,
            scope: *scope,
            snapshot: snapshot.body.snapshot,
            snapshot_digest: snapshot.body_digest,
            lineage: snapshot.body.lineage.clone(),
            profile: profile.clone(),
            source: source.clone(),
            semantic_cut: snapshot.body.semantic_cut,
            receipt_digest: Digest::ZERO,
        }
        .seal()
        .unwrap();
        let decision = coordinator
            .observe(
                &id,
                &action,
                Observation::<CapturedSnapshot, ()>::Applied(CapturedSnapshot {
                    snapshot,
                    receipt,
                }),
            )
            .unwrap();
        assert_eq!(decision, Decision::Arm(ActionKind::PrepareBindings));
    }

    #[test]
    fn abort_waits_for_exact_commit_query_when_ack_is_unknown() {
        let (id, record, action) = pending_commit(PendingState::InvokeUnknown);
        let mut coordinator = Coordinator::new(store_with_record(id, record));
        assert_eq!(
            coordinator.abort(&id).unwrap(),
            Decision::Action { mode: ActionMode::Query, action: action.clone() }
        );
        let record = coordinator.into_store().records.remove(&id).unwrap();
        assert_eq!(record.pending.unwrap().action, action);
        assert_eq!(record.core.phase, Progress::Captured);
    }

    #[test]
    fn commit_rejection_proves_precommit_abort_path() {
        let (id, record, action) = pending_commit(PendingState::NeverInvoked);
        let mut coordinator = Coordinator::new(store_with_record(id, record));
        assert_eq!(
            coordinator
                .observe(&id, &action, Observation::<AuthorityCommitReceipt, ()>::Rejected(()))
                .unwrap(),
            Decision::Complete
        );
        let record = coordinator.into_store().records.remove(&id).unwrap();
        assert_eq!(record.core.phase, Progress::Captured);
        assert_eq!(record.status, WorkflowStatus::RolledBack);
    }

    #[test]
    fn exact_commit_absence_permits_abort_cleanup() {
        let (id, record, action) = pending_commit(PendingState::InvokePermitted);
        let mut coordinator = Coordinator::new(store_with_record(id, record));
        assert_eq!(
            coordinator.abort(&id).unwrap(),
            Decision::Action { mode: ActionMode::Query, action: action.clone() }
        );
        assert_eq!(
            coordinator
                .observe(&id, &action, Observation::<AuthorityCommitReceipt, ()>::Absent)
                .unwrap(),
            Decision::Complete
        );
    }
    #[test]
    fn post_commit_unknown_is_recovery_not_abort() {
        let record = WorkflowRecord {
            core: apply(None, &Event::Begun(intent().continuation)).unwrap(),
            source: endpoint(1),
            destination: endpoint(2),
            recovery: None,
            status: WorkflowStatus::Forward,
            pending: None,
            bindings: None,
            destination_prepared: None,
            commit: None,
            destination_restored: None,
            activation_permit: None,
            runtime_activation: None,
            bindings_aborted: None,
            source_restored: None,
            retired: None,
        };
        let next = recovery(record, RecoveryRequirement::ActivationUnknown).unwrap();
        assert_eq!(next.recovery, Some(RecoveryRequirement::ActivationUnknown));
    }

    #[test]
    fn authority_permit_precedes_runtime_activation() {
        let continuation = intent().continuation;
        let destination = endpoint(2);
        let mut core = apply(None, &Event::Begun(continuation.clone())).unwrap();
        core.phase = Progress::Captured;
        let record = WorkflowRecord {
            core,
            source: endpoint(1),
            destination: destination.clone(),
            recovery: None,
            status: WorkflowStatus::Forward,
            pending: None,
            bindings: Some(visa_core::BindingPreparationReceipt {
                operation: OperationId::from_u128(6),
                continuation: continuation.id,
                snapshot: SnapshotId::from_u128(8),
                snapshot_digest: Digest::ZERO,
                destination: destination.clone(),
                grants: vec![],
                request_digest: Digest::ZERO,
                receipt_digest: Digest::ZERO,
            }),
            destination_prepared: Some(visa_core::RuntimePreparationReceipt {
                operation: OperationId::from_u128(7),
                continuation: continuation.id,
                snapshot: SnapshotId::from_u128(8),
                snapshot_digest: Digest::ZERO,
                destination: destination.clone(),
                binding_receipt_digest: Digest::ZERO,
                request_digest: Digest::ZERO,
                receipt_digest: Digest::ZERO,
            }),
            commit: Some(visa_core::AuthorityCommitReceipt {
                operation: OperationId::from_u128(8),
                continuation: continuation.id,
                snapshot: SnapshotId::from_u128(8),
                snapshot_digest: Digest::ZERO,
                source: endpoint(1),
                destination: destination.clone(),
                binding_receipt_digest: Digest::ZERO,
                source_fence_epoch: 0,
                execution_epoch: 1,
                request_digest: Digest::ZERO,
                receipt_digest: Digest::ZERO,
            }),
            destination_restored: Some(visa_core::DestinationRestoreReceipt {
                operation: OperationId::from_u128(9),
                continuation: continuation.id,
                snapshot: SnapshotId::from_u128(8),
                snapshot_digest: Digest::ZERO,
                destination,
                preparation_receipt_digest: Digest::ZERO,
                request_digest: Digest::ZERO,
                receipt_digest: Digest::ZERO,
            }),
            activation_permit: None,
            runtime_activation: None,
            bindings_aborted: None,
            source_restored: None,
            retired: None,
        };
        assert_eq!(plan_record(&record), Decision::Arm(ActionKind::PermitActivation));
    }
}
