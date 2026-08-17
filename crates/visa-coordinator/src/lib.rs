//! Restartable continuity coordination.
//!
//! This crate owns workflow intent and durable operation references.  Portable
//! vocabulary and the pure transition reducer live in [`visa_core`]. Runtime
//! preparation values are associated opaque types and are kept only in the
//! coordinator process.

use std::collections::BTreeMap;

use visa_core::{
    self, AbortPreparationReceipt, ActivationReceipt, AuthorityCommitReceipt,
    BindingPreparationReceipt, ContinuationId, ContinuationIntent, ContinuationPhase,
    ContinuationRecord, ContractError, Digest, Event, ExternalCoordinate, ExternalOperationKind,
    LineagePoint, OperationId, PendingExternal, ProfileRef, Progress, RecoveryCause,
    ResourceRequirement, SafePointReceipt, ScopeId, SnapshotEnvelope, SourceRestorationReceipt,
    apply,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn id(value: u128) -> [u8; 16] {
        value.to_be_bytes()
    }

    fn coordinate(value: u8) -> ExternalCoordinate {
        ExternalCoordinate { authority: visa_core::AuthorityId(id(9)), value: vec![value] }
    }

    fn intent() -> ContinuationIntent {
        ContinuationIntent {
            id: ContinuationId::from_u128(1),
            scope: ScopeId::from_u128(2),
            source: coordinate(1),
            destination: coordinate(2),
            lineage_parent: LineagePoint {
                lineage: visa_core::LineageId::from_u128(3),
                generation: 0,
                state_digest: Digest::ZERO,
            },
            profile: ProfileRef {
                id: visa_core::ProfileId::from_u128(4),
                version: visa_core::ProfileVersion { major: 1, minor: 0 },
                contract_digest: Digest::ZERO,
                state_schema: visa_core::SchemaRef {
                    id: visa_core::SchemaId::from_u128(5),
                    version: 1,
                },
            },
        }
    }

    fn begun() -> ContinuationRecord {
        apply(None, &Event::Begun(intent())).expect("valid begin")
    }

    fn snapshot_for(intent: &ContinuationIntent) -> (SnapshotEnvelope, SafePointReceipt) {
        let state = vec![1, 2, 3];
        let safe = SafePointReceipt {
            continuation: intent.id,
            scope: intent.scope,
            runtime: intent.source.clone(),
            cut_sequence: 1,
            portable_state_digest: Digest::of_bytes(&state),
            receipt_digest: Digest::ZERO,
        }
        .seal()
        .expect("valid safe point");
        let body = visa_core::PortableSnapshot {
            snapshot: visa_core::SnapshotId::from_u128(6),
            continuation: intent.id,
            scope: intent.scope,
            lineage: visa_core::LineageAdvance {
                parent: intent.lineage_parent.clone(),
                successor_generation: intent.lineage_parent.generation + 1,
            },
            profile: intent.profile.clone(),
            source_cut: visa_core::SourceSemanticCut {
                runtime: intent.source.clone(),
                cut_sequence: 1,
                receipt_digest: safe.receipt_digest,
            },
            state,
            state_digest: Digest::ZERO,
            resources: vec![],
            effects: vec![],
        };
        let envelope = SnapshotEnvelope::seal(body).expect("valid snapshot");
        (envelope, safe)
    }

    struct FakeAuthority {
        prepare_calls: usize,
        commit_calls: usize,
        prepare_queries: VecDeque<QueryOutcome<BindingPreparationReceipt, ()>>,
        commit_queries: VecDeque<QueryOutcome<AuthorityCommitReceipt, ()>>,
    }

    impl FakeAuthority {
        fn preparation(request: &PrepareRequest) -> BindingPreparationReceipt {
            BindingPreparationReceipt {
                operation: request.operation,
                continuation: request.binding.continuation,
                snapshot: request.binding.snapshot,
                destination: request.binding.destination.clone(),
                grants: vec![],
                receipt_digest: Digest::ZERO,
            }
            .seal()
            .expect("fake preparation is encodable")
        }

        fn commit(request: &CommitRequest) -> AuthorityCommitReceipt {
            AuthorityCommitReceipt {
                operation: request.operation,
                continuation: request.binding.continuation,
                snapshot: request.binding.snapshot,
                source: request.binding.source.clone(),
                source_fence_epoch: 1,
                destination: request.binding.destination.clone(),
                binding_receipt_digest: request.preparation.receipt_digest,
                execution_epoch: 1,
                receipt_digest: Digest::ZERO,
            }
            .seal()
            .expect("fake commit is encodable")
        }
    }

    impl AuthorityPort for FakeAuthority {
        type PrepareRejection = ();
        type CommitRejection = ();
        type AbortRejection = ();

        fn prepare(
            &mut self,
            request: PrepareRequest,
        ) -> CallOutcome<BindingPreparationReceipt, ()> {
            self.prepare_calls += 1;
            CallOutcome::Applied(Self::preparation(&request))
        }

        fn query_prepare(
            &mut self,
            request: QueryPrepareRequest,
        ) -> QueryOutcome<BindingPreparationReceipt, ()> {
            match self.prepare_queries.pop_front().unwrap_or(QueryOutcome::Indeterminate) {
                QueryOutcome::Applied(mut receipt) => {
                    receipt.operation = request.operation;
                    receipt.continuation = request.binding.continuation;
                    receipt.snapshot = request.binding.snapshot;
                    receipt.destination = request.binding.destination;
                    QueryOutcome::Applied(receipt.seal().expect("fake preparation is encodable"))
                }
                other => other,
            }
        }

        fn commit(&mut self, request: CommitRequest) -> CallOutcome<AuthorityCommitReceipt, ()> {
            self.commit_calls += 1;
            CallOutcome::Applied(Self::commit(&request))
        }

        fn query_commit(
            &mut self,
            request: QueryCommitRequest,
        ) -> QueryOutcome<AuthorityCommitReceipt, ()> {
            match self.commit_queries.pop_front().unwrap_or(QueryOutcome::Indeterminate) {
                QueryOutcome::Applied(mut receipt) => {
                    receipt.operation = request.operation;
                    receipt.continuation = request.binding.continuation;
                    receipt.snapshot = request.binding.snapshot;
                    receipt.source = request.binding.source;
                    receipt.destination = request.binding.destination;
                    receipt.binding_receipt_digest = request.preparation.receipt_digest;
                    QueryOutcome::Applied(receipt.seal().expect("fake commit is encodable"))
                }
                other => other,
            }
        }

        fn abort_preparation(
            &mut self,
            request: AbortPreparationRequest,
        ) -> CallOutcome<AbortPreparationReceipt, ()> {
            CallOutcome::Applied(
                AbortPreparationReceipt {
                    operation: request.operation,
                    continuation: request.binding.continuation,
                    snapshot: request.binding.snapshot,
                    source: request.binding.source,
                    destination: request.binding.destination,
                    preparation_receipt_digest: request.preparation.receipt_digest,
                    receipt_digest: Digest::ZERO,
                }
                .seal()
                .expect("fake abort is encodable"),
            )
        }

        fn query_abort(
            &mut self,
            request: QueryAbortRequest,
        ) -> QueryOutcome<AbortPreparationReceipt, ()> {
            QueryOutcome::Applied(
                AbortPreparationReceipt {
                    operation: request.operation,
                    continuation: request.binding.continuation,
                    snapshot: request.binding.snapshot,
                    source: request.binding.source,
                    destination: request.binding.destination,
                    preparation_receipt_digest: request.preparation.receipt_digest,
                    receipt_digest: Digest::ZERO,
                }
                .seal()
                .expect("fake abort is encodable"),
            )
        }
    }

    struct FakeRuntime {
        snapshot: Option<(SnapshotEnvelope, SafePointReceipt)>,
        freeze_calls: usize,
        prepare_calls: usize,
        restore_calls: usize,
        activate_calls: usize,
        activation_queries: VecDeque<QueryOutcome<ActivationReceipt, ()>>,
        reject_restore: bool,
        reject_source_restore: bool,
        source_live: bool,
    }

    impl RuntimePort for FakeRuntime {
        type Frozen = u8;
        type Prepared = u8;
        type Restored = u8;
        type ActivationRejection = ();
        type Error = ();

        fn freeze_source(
            &mut self,
            _request: FreezeSourceRequest,
        ) -> CallOutcome<FrozenRuntime<Self::Frozen>, ()> {
            self.freeze_calls += 1;
            let Some((snapshot, safe_point)) = self.snapshot.take() else {
                return CallOutcome::Indeterminate;
            };
            CallOutcome::Applied(FrozenRuntime { snapshot, safe_point, frozen: 1 })
        }

        fn restore_source(
            &mut self,
            request: RestoreSourceRequest,
        ) -> CallOutcome<SourceRestorationReceipt, ()> {
            self.restore_calls += 1;
            if self.reject_source_restore {
                return CallOutcome::Rejected(());
            }
            self.source_live = true;
            CallOutcome::Applied(
                SourceRestorationReceipt {
                    continuation: request.continuation,
                    snapshot: request.snapshot.body.snapshot,
                    source: request.source,
                    execution_epoch: 0,
                    receipt_digest: Digest::ZERO,
                }
                .seal()
                .expect("fake restoration is encodable"),
            )
        }

        fn source_restoration_is_live(&self, _receipt: &SourceRestorationReceipt) -> bool {
            self.source_live
        }

        fn prepare_destination(
            &mut self,
            _request: PrepareDestinationRequest,
        ) -> CallOutcome<Self::Prepared, ()> {
            self.prepare_calls += 1;
            CallOutcome::Applied(2)
        }

        fn restore_destination(
            &mut self,
            _request: RestoreDestinationRequest<Self::Prepared>,
        ) -> CallOutcome<Self::Restored, ()> {
            self.restore_calls += 1;
            if self.reject_restore { CallOutcome::Rejected(()) } else { CallOutcome::Applied(3) }
        }

        fn activate(
            &mut self,
            _request: ActivateRequest<Self::Restored>,
        ) -> CallOutcome<ActivationReceipt, ()> {
            self.activate_calls += 1;
            CallOutcome::Indeterminate
        }

        fn query_activation(
            &mut self,
            request: QueryActivationRequest,
        ) -> QueryOutcome<ActivationReceipt, ()> {
            self.activation_queries.pop_front().unwrap_or(QueryOutcome::Applied(
                ActivationReceipt {
                    operation: request.operation,
                    continuation: request.continuation,
                    snapshot: request.snapshot,
                    destination: request.destination,
                    authority_commit_digest: request.commit.receipt_digest,
                    execution_epoch: request.commit.execution_epoch,
                    receipt_digest: Digest::ZERO,
                }
                .seal()
                .expect("fake activation is encodable"),
            ))
        }
    }

    #[derive(Default)]
    struct RejectFirstCasStore {
        inner: InMemoryRecordStore,
        reject_next_cas: bool,
    }

    impl RecordStore for RejectFirstCasStore {
        type Error = InMemoryStoreError;

        fn create(&mut self, request: CreateRecord) -> Result<ContinuationRecord, Self::Error> {
            self.inner.create(request)
        }

        fn load(
            &self,
            continuation: &ContinuationId,
        ) -> Result<Option<ContinuationRecord>, Self::Error> {
            self.inner.load(continuation)
        }

        fn cas(
            &mut self,
            continuation: &ContinuationId,
            expected_revision: u64,
            next: ContinuationRecord,
            lineage: Option<LineageUpdate>,
        ) -> Result<ContinuationRecord, Self::Error> {
            if self.reject_next_cas {
                self.reject_next_cas = false;
                return Err(InMemoryStoreError::CasConflict);
            }
            self.inner.cas(continuation, expected_revision, next, lineage)
        }
    }

    #[test]
    fn in_memory_store_cas_and_lineage_update_are_atomic() {
        let record = begun();
        let id = record.intent.id;
        let lineage = record.intent.lineage_parent.lineage;
        let mut store = InMemoryRecordStore::default();
        store
            .create(CreateRecord {
                record: record.clone(),
                lineage: LineageCreate {
                    parent: record.intent.lineage_parent.clone(),
                    active_continuation: id,
                },
            })
            .expect("create");

        let next = apply(
            Some(record.clone()),
            &Event::RecoveryRequired(RecoveryCause::ExternalOutcomeUnknown {
                authority: visa_core::AuthorityId::default(),
                operation: OperationId::from_u128(7),
            }),
        )
        .expect("valid recovery transition");
        let successor =
            LineagePoint { lineage, generation: 1, state_digest: Digest::of_bytes(b"successor") };
        store
            .cas(
                &id,
                record.revision,
                next,
                Some(LineageUpdate {
                    lineage,
                    expected_head: record.intent.lineage_parent.clone(),
                    new_head: successor.clone(),
                    expected_active: Some(id),
                    active_continuation: None,
                }),
            )
            .expect("atomic cas");

        let fork = store.create(CreateRecord {
            record: {
                let mut value = begun();
                value.intent.id = ContinuationId::from_u128(99);
                value
            },
            lineage: LineageCreate {
                parent: record.intent.lineage_parent,
                active_continuation: ContinuationId::from_u128(99),
            },
        });
        assert_eq!(fork, Err(InMemoryStoreError::LineageFork));

        let mut next_intent = intent();
        next_intent.id = ContinuationId::from_u128(100);
        next_intent.lineage_parent = successor.clone();
        let next_record = apply(None, &Event::Begun(next_intent)).unwrap();
        assert!(
            store
                .create(CreateRecord {
                    record: next_record,
                    lineage: LineageCreate {
                        parent: successor,
                        active_continuation: ContinuationId::from_u128(100),
                    },
                })
                .is_ok()
        );
    }

    #[test]
    fn failed_snapshot_cas_and_failed_rollback_become_recovery_required() {
        let intent = intent();
        let id = intent.id;
        let (snapshot, safe) = snapshot_for(&intent);
        let authority = FakeAuthority {
            prepare_calls: 0,
            commit_calls: 0,
            prepare_queries: VecDeque::new(),
            commit_queries: VecDeque::new(),
        };
        let runtime = FakeRuntime {
            snapshot: Some((snapshot, safe)),
            freeze_calls: 0,
            prepare_calls: 0,
            restore_calls: 0,
            activate_calls: 0,
            activation_queries: VecDeque::new(),
            reject_restore: false,
            reject_source_restore: true,
            source_live: false,
        };
        let store =
            RejectFirstCasStore { inner: InMemoryRecordStore::default(), reject_next_cas: true };
        let mut coordinator = Coordinator::new(store, authority, runtime);
        coordinator.begin(intent).expect("begin");

        assert_eq!(coordinator.drive(&id).expect("capture recovery"), DriveResult::Waiting);
        assert_eq!(coordinator.runtime.restore_calls, 1);
        let record = coordinator.store.load(&id).expect("load").expect("record");
        assert!(record.snapshot.is_none());
        assert!(matches!(
            record.phase,
            ContinuationPhase::RecoveryRequired {
                last_known: Progress::Preparing,
                cause: RecoveryCause::SourceRestorationUnknown,
            }
        ));
    }

    #[test]
    fn recovery_is_pure_and_one_way() {
        let mut record = begun();
        assert_eq!(decide_recovery(&record), RecoveryDecision::Wait);

        record.phase = ContinuationPhase::Progress(Progress::Committed);
        assert_eq!(decide_recovery(&record), RecoveryDecision::DestinationOnly);

        record.phase = ContinuationPhase::RecoveryRequired {
            last_known: Progress::DestinationPrepared,
            cause: RecoveryCause::StoreConflict,
        };
        assert_eq!(decide_recovery(&record), RecoveryDecision::Fatal);

        record.phase = ContinuationPhase::Progress(Progress::Aborted);
        record.snapshot = Some(snapshot_for(&record.intent).0);
        assert_eq!(decide_recovery(&record), RecoveryDecision::RestoreSource);
    }

    #[test]
    fn pending_is_durable_before_prepare_and_lost_ack_is_queried() {
        let operation = OperationId::from_u128(1);
        let intent = intent();
        let (snapshot, safe) = snapshot_for(&intent);
        let preparation = BindingPreparationReceipt {
            operation,
            continuation: intent.id,
            snapshot: snapshot.body.snapshot,
            destination: intent.destination.clone(),
            grants: vec![],
            receipt_digest: Digest::ZERO,
        }
        .seal()
        .unwrap();
        let authority = FakeAuthority {
            prepare_calls: 0,
            commit_calls: 0,
            prepare_queries: VecDeque::from([QueryOutcome::Applied(preparation)]),
            commit_queries: VecDeque::new(),
        };
        let runtime = FakeRuntime {
            snapshot: Some((snapshot, safe)),
            freeze_calls: 0,
            prepare_calls: 0,
            restore_calls: 0,
            activate_calls: 0,
            activation_queries: VecDeque::new(),
            reject_restore: false,
            reject_source_restore: false,
            source_live: false,
        };
        let mut coordinator = Coordinator::new(InMemoryRecordStore::default(), authority, runtime);
        let id = coordinator.begin(intent).expect("begin");
        assert_eq!(coordinator.drive(&id).expect("capture"), DriveResult::DurableBoundary);
        let pending = coordinator.drive(&id).expect("arm");
        let DriveResult::ExternalPending(pending_id) = pending else { panic!("expected pending") };
        assert_eq!(coordinator.authority.prepare_calls, 0);
        assert!(coordinator.store.load(&id).expect("load").unwrap().pending.is_some());

        // The call can be applied even when its acknowledgement is lost; the
        // next durable step queries the exact operation id.
        coordinator.drive(&id).expect("call");
        assert_eq!(coordinator.authority.prepare_calls, 1);
        coordinator.drive(&id).expect("query");
        let record = coordinator.store.load(&id).expect("load").unwrap();
        assert_eq!(record.pending, None);
        assert_eq!(record.binding_preparation.unwrap().operation, pending_id);
    }

    #[test]
    fn authority_absent_retries_the_same_operation_id() {
        let intent = intent();
        let (snapshot, safe) = snapshot_for(&intent);
        let operation = OperationId::from_u128(1);
        let preparation = BindingPreparationReceipt {
            operation,
            continuation: intent.id,
            snapshot: snapshot.body.snapshot,
            destination: intent.destination.clone(),
            grants: vec![],
            receipt_digest: Digest::ZERO,
        }
        .seal()
        .unwrap();
        let authority = FakeAuthority {
            prepare_calls: 0,
            commit_calls: 0,
            prepare_queries: VecDeque::from([
                QueryOutcome::Absent,
                QueryOutcome::Applied(preparation),
            ]),
            commit_queries: VecDeque::new(),
        };
        let runtime = FakeRuntime {
            snapshot: Some((snapshot, safe)),
            freeze_calls: 0,
            prepare_calls: 0,
            restore_calls: 0,
            activate_calls: 0,
            activation_queries: VecDeque::new(),
            reject_restore: false,
            reject_source_restore: false,
            source_live: false,
        };
        let mut coordinator = Coordinator::new(InMemoryRecordStore::default(), authority, runtime);
        let id = coordinator.begin(intent).expect("begin");
        coordinator.drive(&id).expect("capture");
        let DriveResult::ExternalPending(operation) = coordinator.drive(&id).expect("arm") else {
            panic!("expected pending")
        };

        coordinator.drive(&id).expect("first call");
        assert_eq!(coordinator.authority.prepare_calls, 1);
        coordinator.drive(&id).expect("absent query");
        assert_eq!(coordinator.authority.prepare_calls, 1);
        assert_eq!(
            coordinator.store.load(&id).expect("load").unwrap().pending.unwrap().operation,
            operation
        );

        coordinator.drive(&id).expect("same-id retry");
        assert_eq!(coordinator.authority.prepare_calls, 2);
        coordinator.drive(&id).expect("applied query");
        let record = coordinator.store.load(&id).expect("load").unwrap();
        assert_eq!(record.pending, None);
        assert_eq!(record.binding_preparation.unwrap().operation, operation);
    }

    #[test]
    fn indeterminate_query_waits_without_abort_or_operation_id_change() {
        let intent = intent();
        let (snapshot, safe) = snapshot_for(&intent);
        let authority = FakeAuthority {
            prepare_calls: 0,
            commit_calls: 0,
            prepare_queries: VecDeque::from([QueryOutcome::Indeterminate]),
            commit_queries: VecDeque::new(),
        };
        let runtime = FakeRuntime {
            snapshot: Some((snapshot, safe)),
            freeze_calls: 0,
            prepare_calls: 0,
            restore_calls: 0,
            activate_calls: 0,
            activation_queries: VecDeque::new(),
            reject_restore: false,
            reject_source_restore: false,
            source_live: false,
        };
        let mut coordinator = Coordinator::new(InMemoryRecordStore::default(), authority, runtime);
        let id = coordinator.begin(intent).expect("begin");
        coordinator.drive(&id).expect("capture");
        let DriveResult::ExternalPending(operation) = coordinator.drive(&id).expect("arm") else {
            panic!("expected pending")
        };
        coordinator.drive(&id).expect("call");
        assert_eq!(coordinator.drive(&id).expect("unknown"), DriveResult::Waiting);
        let record = coordinator.store.load(&id).expect("load").unwrap();
        let pending = record.pending.expect("pending retained");
        assert!(matches!(record.phase, ContinuationPhase::RecoveryRequired { .. }));
        assert_eq!(pending.operation, operation);
        assert_eq!(coordinator.authority.prepare_calls, 1);
    }

    #[test]
    fn commit_lost_ack_advances_lineage_only_after_exact_query() {
        let intent = intent();
        let (snapshot, safe) = snapshot_for(&intent);
        let preparation = BindingPreparationReceipt {
            operation: OperationId::from_u128(1),
            continuation: intent.id,
            snapshot: snapshot.body.snapshot,
            destination: intent.destination.clone(),
            grants: vec![],
            receipt_digest: Digest::ZERO,
        }
        .seal()
        .unwrap();
        let commit = AuthorityCommitReceipt {
            operation: OperationId::from_u128(2),
            continuation: intent.id,
            snapshot: snapshot.body.snapshot,
            source: intent.source.clone(),
            source_fence_epoch: 1,
            destination: intent.destination.clone(),
            binding_receipt_digest: preparation.receipt_digest,
            execution_epoch: 1,
            receipt_digest: Digest::ZERO,
        }
        .seal()
        .unwrap();
        let authority = FakeAuthority {
            prepare_calls: 0,
            commit_calls: 0,
            prepare_queries: VecDeque::from([QueryOutcome::Applied(preparation)]),
            commit_queries: VecDeque::from([QueryOutcome::Applied(commit)]),
        };
        let runtime = FakeRuntime {
            snapshot: Some((snapshot, safe)),
            freeze_calls: 0,
            prepare_calls: 0,
            restore_calls: 0,
            activate_calls: 0,
            activation_queries: VecDeque::new(),
            reject_restore: false,
            reject_source_restore: false,
            source_live: false,
        };
        let mut coordinator = Coordinator::new(InMemoryRecordStore::default(), authority, runtime);
        let id = coordinator.begin(intent).expect("begin");
        for _ in 0..7 {
            coordinator.drive(&id).expect("progress to committed");
        }
        let record = coordinator.store.load(&id).expect("load").unwrap();
        assert!(record.authority_commit.is_some());
        assert_eq!(record.phase.last_known(), Progress::Committed);
        assert_eq!(coordinator.authority.commit_calls, 1);
    }
}

/// Result of an operation sent to an external authority or runtime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallOutcome<T, R> {
    Applied(T),
    Rejected(R),
    Indeterminate,
}

/// Result of an exact operation query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QueryOutcome<T, R> {
    Applied(T),
    Rejected(R),
    /// Only an authority's `Absent` permits a retry with the same operation id.
    Absent,
    Indeterminate,
}

/// Exact request coordinates copied into every authority request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityBinding {
    pub continuation: ContinuationId,
    pub snapshot: visa_core::SnapshotId,
    pub source: ExternalCoordinate,
    pub destination: ExternalCoordinate,
    pub requirements: Vec<ResourceRequirement>,
    pub preparation_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrepareRequest {
    pub operation: OperationId,
    pub binding: AuthorityBinding,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryPrepareRequest {
    pub operation: OperationId,
    pub binding: AuthorityBinding,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitRequest {
    pub operation: OperationId,
    pub binding: AuthorityBinding,
    pub preparation: BindingPreparationReceipt,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryCommitRequest {
    pub operation: OperationId,
    pub binding: AuthorityBinding,
    pub preparation: BindingPreparationReceipt,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AbortPreparationRequest {
    pub operation: OperationId,
    pub binding: AuthorityBinding,
    pub preparation: BindingPreparationReceipt,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryAbortRequest {
    pub operation: OperationId,
    pub binding: AuthorityBinding,
    pub preparation: BindingPreparationReceipt,
}

/// The authority owns bindings, source fences, and commit facts. Its receipts
/// are the core contract receipts; rejection types remain authority-local.
pub trait AuthorityPort {
    type PrepareRejection: Clone;
    type CommitRejection: Clone;
    type AbortRejection: Clone;

    fn prepare(
        &mut self,
        request: PrepareRequest,
    ) -> CallOutcome<BindingPreparationReceipt, Self::PrepareRejection>;
    fn query_prepare(
        &mut self,
        request: QueryPrepareRequest,
    ) -> QueryOutcome<BindingPreparationReceipt, Self::PrepareRejection>;
    fn commit(
        &mut self,
        request: CommitRequest,
    ) -> CallOutcome<AuthorityCommitReceipt, Self::CommitRejection>;
    fn query_commit(
        &mut self,
        request: QueryCommitRequest,
    ) -> QueryOutcome<AuthorityCommitReceipt, Self::CommitRejection>;
    fn abort_preparation(
        &mut self,
        request: AbortPreparationRequest,
    ) -> CallOutcome<AbortPreparationReceipt, Self::AbortRejection>;
    fn query_abort(
        &mut self,
        request: QueryAbortRequest,
    ) -> QueryOutcome<AbortPreparationReceipt, Self::AbortRejection>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FreezeSourceRequest {
    pub continuation: ContinuationId,
    pub scope: ScopeId,
    pub source: ExternalCoordinate,
    pub profile: ProfileRef,
    pub lineage: visa_core::LineageAdvance,
}

pub struct FrozenRuntime<F> {
    pub snapshot: SnapshotEnvelope,
    pub safe_point: SafePointReceipt,
    pub frozen: F,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreSourceRequest {
    pub continuation: ContinuationId,
    pub snapshot: SnapshotEnvelope,
    pub source: ExternalCoordinate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrepareDestinationRequest {
    pub continuation: ContinuationId,
    pub snapshot: SnapshotEnvelope,
    pub destination: ExternalCoordinate,
    pub requirements: Vec<ResourceRequirement>,
    pub preparation_digest: Digest,
}

pub struct RestoreDestinationRequest<P> {
    pub continuation: ContinuationId,
    pub snapshot: SnapshotEnvelope,
    pub destination: ExternalCoordinate,
    pub preparation: BindingPreparationReceipt,
    pub commit: AuthorityCommitReceipt,
    pub prepared: P,
}

pub struct ActivateRequest<T> {
    pub continuation: ContinuationId,
    pub operation: OperationId,
    pub snapshot: visa_core::SnapshotId,
    pub destination: ExternalCoordinate,
    pub preparation: BindingPreparationReceipt,
    pub commit: AuthorityCommitReceipt,
    pub restored: T,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryActivationRequest {
    pub continuation: ContinuationId,
    pub snapshot: visa_core::SnapshotId,
    pub destination: ExternalCoordinate,
    pub operation: OperationId,
    pub binding: ExternalCoordinate,
    pub commit: AuthorityCommitReceipt,
}

/// Runtime tokens are not serializable and never occur in a core record.
pub trait RuntimePort {
    type Frozen;
    type Prepared;
    type Restored;
    type ActivationRejection: Clone;
    type Error: Clone;

    fn freeze_source(
        &mut self,
        request: FreezeSourceRequest,
    ) -> CallOutcome<FrozenRuntime<Self::Frozen>, Self::Error>;
    fn restore_source(
        &mut self,
        request: RestoreSourceRequest,
    ) -> CallOutcome<SourceRestorationReceipt, Self::Error>;
    fn source_restoration_is_live(&self, receipt: &SourceRestorationReceipt) -> bool;
    fn prepare_destination(
        &mut self,
        request: PrepareDestinationRequest,
    ) -> CallOutcome<Self::Prepared, Self::Error>;
    fn restore_destination(
        &mut self,
        request: RestoreDestinationRequest<Self::Prepared>,
    ) -> CallOutcome<Self::Restored, Self::Error>;
    fn activate(
        &mut self,
        request: ActivateRequest<Self::Restored>,
    ) -> CallOutcome<ActivationReceipt, Self::ActivationRejection>;
    fn query_activation(
        &mut self,
        request: QueryActivationRequest,
    ) -> QueryOutcome<ActivationReceipt, Self::ActivationRejection>;
}

/// A lineage create carries the parent, current head, and active continuation
/// in the same durable transaction as the initial record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineageCreate {
    pub parent: LineagePoint,
    pub active_continuation: ContinuationId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateRecord {
    pub record: ContinuationRecord,
    pub lineage: LineageCreate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineageUpdate {
    pub lineage: visa_core::LineageId,
    pub expected_head: LineagePoint,
    pub new_head: LineagePoint,
    pub expected_active: Option<ContinuationId>,
    pub active_continuation: Option<ContinuationId>,
}

/// `cas` must apply its record write and lineage update atomically.
pub trait RecordStore {
    type Error;

    fn create(&mut self, request: CreateRecord) -> Result<ContinuationRecord, Self::Error>;
    fn load(
        &self,
        continuation: &ContinuationId,
    ) -> Result<Option<ContinuationRecord>, Self::Error>;
    fn cas(
        &mut self,
        continuation: &ContinuationId,
        expected_revision: u64,
        next: ContinuationRecord,
        lineage: Option<LineageUpdate>,
    ) -> Result<ContinuationRecord, Self::Error>;
}

/// Small deterministic store useful for adapters and focused coordinator
/// tests. It models the same atomic record/lineage checks a durable store must
/// provide; it is not a second authority ledger.
#[derive(Clone, Debug, Default)]
pub struct InMemoryRecordStore {
    records: BTreeMap<ContinuationId, ContinuationRecord>,
    lineages: BTreeMap<visa_core::LineageId, InMemoryLineage>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct InMemoryLineage {
    head: LineagePoint,
    active: Option<ContinuationId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InMemoryStoreError {
    AlreadyExists,
    NotFound,
    CasConflict,
    LineageFork,
}

impl RecordStore for InMemoryRecordStore {
    type Error = InMemoryStoreError;

    fn create(&mut self, request: CreateRecord) -> Result<ContinuationRecord, Self::Error> {
        let id = request.record.intent.id;
        if request.record.intent.lineage_parent != request.lineage.parent
            || request.lineage.active_continuation != id
        {
            return Err(InMemoryStoreError::LineageFork);
        }
        if self.records.contains_key(&id) {
            return Err(InMemoryStoreError::AlreadyExists);
        }
        if let Some(lineage) = self.lineages.get(&request.lineage.parent.lineage)
            && (lineage.head != request.lineage.parent || lineage.active.is_some())
        {
            return Err(InMemoryStoreError::LineageFork);
        }
        self.records.insert(id, request.record.clone());
        self.lineages.insert(
            request.lineage.parent.lineage,
            InMemoryLineage {
                head: request.lineage.parent,
                active: Some(request.lineage.active_continuation),
            },
        );
        Ok(request.record)
    }

    fn load(
        &self,
        continuation: &ContinuationId,
    ) -> Result<Option<ContinuationRecord>, Self::Error> {
        Ok(self.records.get(continuation).cloned())
    }

    fn cas(
        &mut self,
        continuation: &ContinuationId,
        expected_revision: u64,
        next: ContinuationRecord,
        lineage: Option<LineageUpdate>,
    ) -> Result<ContinuationRecord, Self::Error> {
        let current = self.records.get(continuation).ok_or(InMemoryStoreError::NotFound)?;
        if current.revision != expected_revision || next.revision != expected_revision + 1 {
            return Err(InMemoryStoreError::CasConflict);
        }
        if let Some(update) = lineage {
            if update.expected_head.lineage != update.lineage
                || update.new_head.lineage != update.lineage
            {
                return Err(InMemoryStoreError::LineageFork);
            }
            let state =
                self.lineages.get_mut(&update.lineage).ok_or(InMemoryStoreError::LineageFork)?;
            if state.head != update.expected_head || state.active != update.expected_active {
                return Err(InMemoryStoreError::LineageFork);
            }
            state.head = update.new_head;
            state.active = update.active_continuation;
        }
        self.records.insert(*continuation, next.clone());
        Ok(next)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryDecision {
    RestoreSource,
    DestinationOnly,
    Wait,
    Fatal,
}

/// Pure recovery decision. No port or store is consulted.
#[must_use]
pub fn decide_recovery(record: &ContinuationRecord) -> RecoveryDecision {
    if matches!(record.phase, ContinuationPhase::Progress(Progress::Aborted)) {
        return if record.snapshot.is_some() && record.source_restoration.is_none() {
            RecoveryDecision::RestoreSource
        } else {
            RecoveryDecision::Wait
        };
    }
    if let ContinuationPhase::RecoveryRequired { cause, .. } = &record.phase {
        return match cause {
            RecoveryCause::StoreConflict | RecoveryCause::ReceiptConflict => {
                RecoveryDecision::Fatal
            }
            RecoveryCause::MissingPreparedRuntime => RecoveryDecision::DestinationOnly,
            RecoveryCause::RuntimeActivationUnknown { .. } if record.authority_commit.is_some() => {
                RecoveryDecision::DestinationOnly
            }
            RecoveryCause::ExternalOutcomeUnknown { .. }
            | RecoveryCause::SourceRestorationUnknown
            | RecoveryCause::RuntimeActivationUnknown { .. }
            | RecoveryCause::UnresolvedEffects => RecoveryDecision::Wait,
        };
    }
    if record.authority_commit.is_some()
        || matches!(record.phase.last_known(), Progress::Committed | Progress::Activated)
    {
        return RecoveryDecision::DestinationOnly;
    }
    RecoveryDecision::Wait
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DriveResult {
    DurableBoundary,
    ExternalPending(OperationId),
    Waiting,
    SourceRestored,
    Activated,
    Aborted,
    Fatal,
}

#[derive(Debug)]
pub enum CoordinatorError<SE> {
    Store(SE),
    Core(ContractError),
    NotFound,
}

struct RuntimeTokens<R: RuntimePort> {
    frozen: Option<R::Frozen>,
    prepared: Option<R::Prepared>,
    restored: Option<R::Restored>,
}

impl<R: RuntimePort> Default for RuntimeTokens<R> {
    fn default() -> Self {
        Self { frozen: None, prepared: None, restored: None }
    }
}

/// The process-local coordinator. Only core records cross the `RecordStore`
/// boundary; all runtime values stay in `tokens`.
pub struct Coordinator<S, A, R>
where
    S: RecordStore,
    A: AuthorityPort,
    R: RuntimePort,
{
    pub store: S,
    pub authority: A,
    pub runtime: R,
    tokens: BTreeMap<ContinuationId, RuntimeTokens<R>>,
    /// Process-local acknowledgement tracking. The durable pending record is
    /// written before the first call; after a call, the next drive queries its
    /// exact operation id instead of issuing a duplicate call.
    called: BTreeMap<(ContinuationId, OperationId), bool>,
}

impl<S, A, R> Coordinator<S, A, R>
where
    S: RecordStore,
    A: AuthorityPort,
    R: RuntimePort,
{
    pub fn new(store: S, authority: A, runtime: R) -> Self {
        Self { store, authority, runtime, tokens: BTreeMap::new(), called: BTreeMap::new() }
    }

    pub fn begin(
        &mut self,
        intent: ContinuationIntent,
    ) -> Result<ContinuationId, CoordinatorError<S::Error>> {
        let record = apply(None, &Event::Begun(intent.clone())).map_err(CoordinatorError::Core)?;
        let id = intent.id;
        self.store
            .create(CreateRecord {
                record,
                lineage: LineageCreate { parent: intent.lineage_parent, active_continuation: id },
            })
            .map_err(CoordinatorError::Store)?;
        self.tokens.insert(id, RuntimeTokens::default());
        Ok(id)
    }

    pub fn drive(
        &mut self,
        id: &ContinuationId,
    ) -> Result<DriveResult, CoordinatorError<S::Error>> {
        let record = self.load(id)?;
        if record.snapshot.as_ref().is_some_and(|snapshot| !snapshot.body.effects.is_empty()) {
            return self.mark_recovery(id, record, RecoveryCause::UnresolvedEffects);
        }
        if record.pending.is_some() {
            return self.progress_pending(id, record);
        }
        match record.phase.last_known() {
            Progress::Preparing => {
                if record.snapshot.is_none() {
                    self.capture(id, record)
                } else {
                    self.arm_authority(id, record, ExternalOperationKind::PrepareBindings)
                }
            }
            Progress::Frozen => {
                if record.binding_preparation.is_none() {
                    self.arm_authority(id, record, ExternalOperationKind::PrepareBindings)
                } else {
                    self.prepare_destination(id, record)
                }
            }
            Progress::DestinationPrepared => self.prepare_destination(id, record),
            Progress::Committed => self.activate(id, record),
            Progress::Activated => Ok(DriveResult::Activated),
            Progress::Aborted => Ok(DriveResult::Aborted),
        }
    }

    pub fn recover(
        &mut self,
        id: &ContinuationId,
    ) -> Result<DriveResult, CoordinatorError<S::Error>> {
        let record = self.load(id)?;
        if record.phase.last_known() == Progress::Aborted && record.snapshot.is_none() {
            return Ok(DriveResult::Aborted);
        }
        if record.phase.last_known() == Progress::Aborted
            && let Some(restoration) = record.source_restoration.as_ref()
        {
            if self.runtime.source_restoration_is_live(restoration) {
                return Ok(DriveResult::SourceRestored);
            }
            return self.mark_recovery(id, record, RecoveryCause::MissingPreparedRuntime);
        }
        if let Some(pending) = &record.pending {
            // A fresh coordinator has no process-local call marker. Recovery
            // must query the exact durable operation before considering a
            // resend; only an authority `Absent` response can clear this
            // query barrier.
            self.called.insert((record.intent.id, pending.operation), true);
            return self.progress_pending(id, record);
        }
        if matches!(
            record.phase,
            ContinuationPhase::Progress(
                Progress::Preparing | Progress::Frozen | Progress::DestinationPrepared
            )
        ) {
            return self.drive(id);
        }
        if record.phase.last_known() == Progress::Activated {
            return self.recover_activated(id, record);
        }
        match decide_recovery(&record) {
            RecoveryDecision::RestoreSource => self.restore_source(id, record),
            RecoveryDecision::DestinationOnly => self.drive(id),
            RecoveryDecision::Wait => Ok(DriveResult::Waiting),
            RecoveryDecision::Fatal => Ok(DriveResult::Fatal),
        }
    }

    pub fn abort(
        &mut self,
        id: &ContinuationId,
    ) -> Result<DriveResult, CoordinatorError<S::Error>> {
        let record = self.load(id)?;
        if record.authority_commit.is_some() || record.phase.last_known() == Progress::Committed {
            return Ok(DriveResult::Fatal);
        }
        if record.pending.is_some() {
            return Ok(DriveResult::Waiting);
        }
        if record.snapshot.is_none()
            && matches!(record.phase, ContinuationPhase::RecoveryRequired { .. })
        {
            // Once the live source is missing, a pre-snapshot record cannot
            // prove that anything was terminated. Keep the recovery
            // requirement instead of manufacturing an aborted outcome.
            return Ok(DriveResult::Waiting);
        }
        if record.binding_preparation.is_none() {
            let lineage = LineageUpdate {
                lineage: record.intent.lineage_parent.lineage,
                expected_head: record.intent.lineage_parent.clone(),
                new_head: record.intent.lineage_parent.clone(),
                expected_active: Some(record.intent.id),
                active_continuation: None,
            };
            self.apply_event(
                record,
                &Event::Aborted {
                    operation: OperationId::from_u128(0),
                    receipt: None,
                    reason: visa_core::AbortReason::OperatorRequested,
                },
                Some(lineage),
            )?;
            return Ok(DriveResult::Aborted);
        }
        self.arm_authority(id, record, ExternalOperationKind::AbortPreparation)
    }

    fn load(&self, id: &ContinuationId) -> Result<ContinuationRecord, CoordinatorError<S::Error>> {
        self.store.load(id).map_err(CoordinatorError::Store)?.ok_or(CoordinatorError::NotFound)
    }

    fn operation_id(record: &ContinuationRecord, kind: ExternalOperationKind) -> OperationId {
        let mut material = Vec::with_capacity(25);
        material.extend_from_slice(&record.intent.id.0);
        material.extend_from_slice(&record.revision.to_be_bytes());
        material.push(match kind {
            ExternalOperationKind::PrepareBindings => 1,
            ExternalOperationKind::CommitAuthority => 2,
            ExternalOperationKind::AbortPreparation => 3,
            ExternalOperationKind::ActivateRuntime => 4,
        });
        let digest = Digest::of_bytes(&material);
        OperationId(digest.0[..16].try_into().expect("digest prefix is sixteen bytes"))
    }

    fn binding(&self, record: &ContinuationRecord) -> Option<AuthorityBinding> {
        let snapshot = record.snapshot.as_ref()?;
        Some(AuthorityBinding {
            continuation: record.intent.id,
            snapshot: snapshot.body.snapshot,
            source: record.intent.source.clone(),
            destination: record.intent.destination.clone(),
            requirements: snapshot.body.resources.clone(),
            preparation_digest: snapshot.body_digest,
        })
    }

    fn cas(
        &mut self,
        current: ContinuationRecord,
        next: ContinuationRecord,
        lineage: Option<LineageUpdate>,
    ) -> Result<ContinuationRecord, CoordinatorError<S::Error>> {
        self.store
            .cas(&current.intent.id, current.revision, next, lineage)
            .map_err(CoordinatorError::Store)
    }

    fn apply_event(
        &mut self,
        current: ContinuationRecord,
        event: &Event,
        lineage: Option<LineageUpdate>,
    ) -> Result<ContinuationRecord, CoordinatorError<S::Error>> {
        let next = apply(Some(current.clone()), event).map_err(CoordinatorError::Core)?;
        self.cas(current, next, lineage)
    }

    fn capture(
        &mut self,
        id: &ContinuationId,
        record: ContinuationRecord,
    ) -> Result<DriveResult, CoordinatorError<S::Error>> {
        let outcome = self.runtime.freeze_source(FreezeSourceRequest {
            continuation: record.intent.id,
            scope: record.intent.scope,
            source: record.intent.source.clone(),
            profile: record.intent.profile.clone(),
            lineage: visa_core::LineageAdvance {
                parent: record.intent.lineage_parent.clone(),
                successor_generation: record
                    .intent
                    .lineage_parent
                    .generation
                    .checked_add(1)
                    .ok_or(CoordinatorError::Core(
                        visa_core::ContractError::InvalidLineageAdvance,
                    ))?,
            },
        });
        match outcome {
            CallOutcome::Applied(frozen) => {
                let token = self.tokens.entry(*id).or_default();
                token.frozen = Some(frozen.frozen);
                let rollback = RestoreSourceRequest {
                    continuation: record.intent.id,
                    snapshot: frozen.snapshot.clone(),
                    source: record.intent.source.clone(),
                };
                if let Err(error) = self.apply_event(
                    record,
                    &Event::SnapshotRecorded {
                        snapshot: frozen.snapshot.clone(),
                        safe_point: frozen.safe_point,
                    },
                    None,
                ) {
                    // A failed CAS can also be a lost store acknowledgement.
                    // Never roll the source back until a fresh read proves
                    // that this exact snapshot did not become durable.
                    let Ok(latest) = self.load(id) else { return Err(error) };
                    if latest.snapshot.as_ref() == Some(&frozen.snapshot) {
                        return Ok(DriveResult::DurableBoundary);
                    }
                    if latest.snapshot.is_some() || latest.phase.last_known() != Progress::Preparing
                    {
                        return self.mark_recovery(id, latest, RecoveryCause::StoreConflict);
                    }
                    match self.runtime.restore_source(rollback) {
                        CallOutcome::Applied(_) => {
                            self.tokens.entry(*id).or_default().frozen = None;
                            return Err(error);
                        }
                        CallOutcome::Rejected(_) | CallOutcome::Indeterminate => {
                            self.tokens.entry(*id).or_default().frozen = None;
                            return self.mark_recovery(
                                id,
                                latest,
                                RecoveryCause::SourceRestorationUnknown,
                            );
                        }
                    }
                }
                Ok(DriveResult::DurableBoundary)
            }
            CallOutcome::Rejected(_) => {
                self.mark_recovery(id, record, RecoveryCause::MissingPreparedRuntime)
            }
            CallOutcome::Indeterminate => self.mark_recovery(
                id,
                record.clone(),
                RecoveryCause::ExternalOutcomeUnknown {
                    authority: record.intent.source.authority,
                    operation: OperationId::from_u128(0),
                },
            ),
        }
    }

    fn arm_authority(
        &mut self,
        id: &ContinuationId,
        record: ContinuationRecord,
        kind: ExternalOperationKind,
    ) -> Result<DriveResult, CoordinatorError<S::Error>> {
        let operation = Self::operation_id(&record, kind);
        let digest = record.snapshot.as_ref().map_or(Digest::ZERO, |s| s.body_digest);
        let pending = PendingExternal { operation, kind, request_digest: digest };
        self.apply_event(record, &Event::ExternalArmed(pending.clone()), None)?;
        let _ = id;
        Ok(DriveResult::ExternalPending(operation))
    }

    fn prepare_destination(
        &mut self,
        id: &ContinuationId,
        record: ContinuationRecord,
    ) -> Result<DriveResult, CoordinatorError<S::Error>> {
        let Some(snapshot) = record.snapshot.clone() else { return Ok(DriveResult::Waiting) };
        if self.tokens.entry(*id).or_default().prepared.is_none() {
            match self.runtime.prepare_destination(PrepareDestinationRequest {
                continuation: record.intent.id,
                snapshot,
                destination: record.intent.destination.clone(),
                requirements: record
                    .snapshot
                    .as_ref()
                    .map_or_else(Vec::new, |s| s.body.resources.clone()),
                preparation_digest: record
                    .snapshot
                    .as_ref()
                    .map_or(Digest::ZERO, |s| s.body_digest),
            }) {
                CallOutcome::Applied(prepared) => {
                    self.tokens.entry(*id).or_default().prepared = Some(prepared)
                }
                CallOutcome::Rejected(_) | CallOutcome::Indeterminate => {
                    return Ok(DriveResult::Waiting);
                }
            }
        }
        self.arm_authority(id, record, ExternalOperationKind::CommitAuthority)
    }

    fn activate(
        &mut self,
        id: &ContinuationId,
        record: ContinuationRecord,
    ) -> Result<DriveResult, CoordinatorError<S::Error>> {
        let Some(snapshot) = record.snapshot.clone() else { return Ok(DriveResult::Waiting) };
        let Some(preparation) = record.binding_preparation.clone() else {
            return Ok(DriveResult::Waiting);
        };
        let Some(commit) = record.authority_commit.clone() else {
            return Ok(DriveResult::Waiting);
        };
        if self.tokens.entry(*id).or_default().prepared.is_none() {
            match self.runtime.prepare_destination(PrepareDestinationRequest {
                continuation: record.intent.id,
                snapshot: snapshot.clone(),
                destination: record.intent.destination.clone(),
                requirements: snapshot.body.resources.clone(),
                preparation_digest: snapshot.body_digest,
            }) {
                CallOutcome::Applied(prepared) => {
                    self.tokens.entry(*id).or_default().prepared = Some(prepared);
                }
                CallOutcome::Rejected(_) | CallOutcome::Indeterminate => {
                    return Ok(DriveResult::Waiting);
                }
            }
        }
        let Some(prepared) = self.tokens.entry(*id).or_default().prepared.take() else {
            return Ok(DriveResult::Waiting);
        };
        match self.runtime.restore_destination(RestoreDestinationRequest {
            continuation: record.intent.id,
            snapshot,
            destination: record.intent.destination.clone(),
            preparation,
            commit,
            prepared,
        }) {
            CallOutcome::Applied(restored) => {
                self.tokens.entry(*id).or_default().restored = Some(restored)
            }
            CallOutcome::Rejected(_) | CallOutcome::Indeterminate => {
                return Ok(DriveResult::Waiting);
            }
        }
        self.arm_authority(id, record, ExternalOperationKind::ActivateRuntime)
    }

    fn progress_pending(
        &mut self,
        id: &ContinuationId,
        record: ContinuationRecord,
    ) -> Result<DriveResult, CoordinatorError<S::Error>> {
        let Some(pending) = record.pending.clone() else { return Ok(DriveResult::Waiting) };
        let key = (record.intent.id, pending.operation);
        let was_called = self.called.get(&key).copied().unwrap_or(false);
        if !was_called {
            self.called.insert(key, true);
            return match pending.kind {
                ExternalOperationKind::PrepareBindings => {
                    let Some(binding) = self.binding(&record) else {
                        return Ok(DriveResult::Waiting);
                    };
                    match self
                        .authority
                        .prepare(PrepareRequest { operation: pending.operation, binding })
                    {
                        CallOutcome::Rejected(_) => {
                            self.called.remove(&(record.intent.id, pending.operation));
                            let record = self.apply_event(
                                record,
                                &Event::ExternalRejected(pending.clone()),
                                None,
                            )?;
                            self.abort_record(record, pending.operation, None)
                        }
                        CallOutcome::Applied(_) | CallOutcome::Indeterminate => {
                            Ok(DriveResult::ExternalPending(pending.operation))
                        }
                    }
                }
                ExternalOperationKind::CommitAuthority => {
                    let Some(binding) = self.binding(&record) else {
                        return Ok(DriveResult::Waiting);
                    };
                    let Some(preparation) = record.binding_preparation.clone() else {
                        return Ok(DriveResult::Waiting);
                    };
                    match self.authority.commit(CommitRequest {
                        operation: pending.operation,
                        binding,
                        preparation,
                    }) {
                        CallOutcome::Rejected(_) => {
                            self.called.remove(&(record.intent.id, pending.operation));
                            let record =
                                self.apply_event(record, &Event::ExternalRejected(pending), None)?;
                            let id = record.intent.id;
                            self.arm_authority(&id, record, ExternalOperationKind::AbortPreparation)
                        }
                        CallOutcome::Applied(_) | CallOutcome::Indeterminate => {
                            Ok(DriveResult::ExternalPending(pending.operation))
                        }
                    }
                }
                ExternalOperationKind::AbortPreparation => {
                    let Some(binding) = self.binding(&record) else {
                        return Ok(DriveResult::Waiting);
                    };
                    let Some(preparation) = record.binding_preparation.clone() else {
                        return Ok(DriveResult::Waiting);
                    };
                    match self.authority.abort_preparation(AbortPreparationRequest {
                        operation: pending.operation,
                        binding,
                        preparation,
                    }) {
                        CallOutcome::Rejected(_) => {
                            self.mark_recovery(id, record, RecoveryCause::ReceiptConflict)
                        }
                        CallOutcome::Applied(_) | CallOutcome::Indeterminate => {
                            Ok(DriveResult::ExternalPending(pending.operation))
                        }
                    }
                }
                ExternalOperationKind::ActivateRuntime => {
                    self.call_activate(id, record, pending.operation)
                }
            };
        }
        match pending.kind {
            ExternalOperationKind::PrepareBindings => self.query_prepare(id, record, pending),
            ExternalOperationKind::CommitAuthority => self.query_commit(id, record, pending),
            ExternalOperationKind::AbortPreparation => self.query_abort(id, record, pending),
            ExternalOperationKind::ActivateRuntime => self.query_activate(id, record, pending),
        }
    }

    fn call_activate(
        &mut self,
        id: &ContinuationId,
        record: ContinuationRecord,
        operation: OperationId,
    ) -> Result<DriveResult, CoordinatorError<S::Error>> {
        let Some(snapshot) = record.snapshot.as_ref() else { return Ok(DriveResult::Waiting) };
        let Some(preparation) = record.binding_preparation.clone() else {
            return Ok(DriveResult::Waiting);
        };
        let Some(commit) = record.authority_commit.clone() else {
            return Ok(DriveResult::Waiting);
        };
        if self.tokens.entry(*id).or_default().restored.is_none() {
            if self.tokens.entry(*id).or_default().prepared.is_none() {
                match self.runtime.prepare_destination(PrepareDestinationRequest {
                    continuation: record.intent.id,
                    snapshot: snapshot.clone(),
                    destination: record.intent.destination.clone(),
                    requirements: snapshot.body.resources.clone(),
                    preparation_digest: snapshot.body_digest,
                }) {
                    CallOutcome::Applied(prepared) => {
                        self.tokens.entry(*id).or_default().prepared = Some(prepared);
                    }
                    CallOutcome::Rejected(_) | CallOutcome::Indeterminate => {
                        return Ok(DriveResult::Waiting);
                    }
                }
            }
            let Some(prepared) = self.tokens.entry(*id).or_default().prepared.take() else {
                return Ok(DriveResult::Waiting);
            };
            match self.runtime.restore_destination(RestoreDestinationRequest {
                continuation: record.intent.id,
                snapshot: snapshot.clone(),
                destination: record.intent.destination.clone(),
                preparation: preparation.clone(),
                commit: commit.clone(),
                prepared,
            }) {
                CallOutcome::Applied(restored) => {
                    self.tokens.entry(*id).or_default().restored = Some(restored);
                }
                CallOutcome::Rejected(_) | CallOutcome::Indeterminate => {
                    return Ok(DriveResult::Waiting);
                }
            }
        }
        let Some(restored) = self.tokens.entry(*id).or_default().restored.take() else {
            return Ok(DriveResult::Waiting);
        };
        match self.runtime.activate(ActivateRequest {
            continuation: record.intent.id,
            operation,
            snapshot: snapshot.body.snapshot,
            destination: record.intent.destination.clone(),
            preparation,
            commit,
            restored,
        }) {
            CallOutcome::Rejected(_) => self.mark_recovery(
                id,
                record,
                RecoveryCause::RuntimeActivationUnknown { operation },
            ),
            CallOutcome::Applied(_) | CallOutcome::Indeterminate => {
                Ok(DriveResult::ExternalPending(operation))
            }
        }
    }

    fn query_prepare(
        &mut self,
        _id: &ContinuationId,
        record: ContinuationRecord,
        pending: PendingExternal,
    ) -> Result<DriveResult, CoordinatorError<S::Error>> {
        let Some(binding) = self.binding(&record) else { return Ok(DriveResult::Waiting) };
        match self
            .authority
            .query_prepare(QueryPrepareRequest { operation: pending.operation, binding })
        {
            QueryOutcome::Applied(receipt) => {
                self.called.remove(&(record.intent.id, pending.operation));
                self.apply_event(record, &Event::BindingPreparationRecorded(receipt), None)?;
                Ok(DriveResult::DurableBoundary)
            }
            QueryOutcome::Rejected(_) => {
                let record =
                    self.apply_event(record, &Event::ExternalRejected(pending.clone()), None)?;
                self.abort_record(record, pending.operation, None)
            }
            QueryOutcome::Absent => {
                self.called.remove(&(record.intent.id, pending.operation));
                Ok(DriveResult::Waiting)
            }
            QueryOutcome::Indeterminate => self.mark_external_unknown(record, pending.operation),
        }
    }

    fn query_commit(
        &mut self,
        _id: &ContinuationId,
        record: ContinuationRecord,
        pending: PendingExternal,
    ) -> Result<DriveResult, CoordinatorError<S::Error>> {
        let Some(binding) = self.binding(&record) else { return Ok(DriveResult::Waiting) };
        let Some(preparation) = record.binding_preparation.clone() else {
            return Ok(DriveResult::Waiting);
        };
        match self.authority.query_commit(QueryCommitRequest {
            operation: pending.operation,
            binding,
            preparation,
        }) {
            QueryOutcome::Applied(receipt) => {
                self.called.remove(&(record.intent.id, pending.operation));
                let snapshot = record
                    .snapshot
                    .as_ref()
                    .ok_or(CoordinatorError::Core(visa_core::ContractError::MissingSnapshot))?;
                let lineage = LineageUpdate {
                    lineage: record.intent.lineage_parent.lineage,
                    expected_head: record.intent.lineage_parent.clone(),
                    new_head: LineagePoint {
                        lineage: snapshot.body.lineage.parent.lineage,
                        generation: snapshot.body.lineage.successor_generation,
                        state_digest: snapshot.body.state_digest,
                    },
                    expected_active: Some(record.intent.id),
                    active_continuation: Some(record.intent.id),
                };
                self.apply_event(record, &Event::AuthorityCommitted(receipt), Some(lineage))?;
                Ok(DriveResult::DurableBoundary)
            }
            QueryOutcome::Rejected(_) => {
                let record = self.apply_event(record, &Event::ExternalRejected(pending), None)?;
                let id = record.intent.id;
                self.arm_authority(&id, record, ExternalOperationKind::AbortPreparation)
            }
            QueryOutcome::Absent => {
                self.called.remove(&(record.intent.id, pending.operation));
                Ok(DriveResult::Waiting)
            }
            QueryOutcome::Indeterminate => self.mark_external_unknown(record, pending.operation),
        }
    }

    fn query_abort(
        &mut self,
        _id: &ContinuationId,
        record: ContinuationRecord,
        pending: PendingExternal,
    ) -> Result<DriveResult, CoordinatorError<S::Error>> {
        let Some(binding) = self.binding(&record) else { return Ok(DriveResult::Waiting) };
        let Some(preparation) = record.binding_preparation.clone() else {
            return Ok(DriveResult::Waiting);
        };
        match self.authority.query_abort(QueryAbortRequest {
            operation: pending.operation,
            binding,
            preparation,
        }) {
            QueryOutcome::Applied(receipt) => {
                self.abort_record(record, pending.operation, Some(receipt))
            }
            QueryOutcome::Rejected(_) => {
                self.mark_recovery(_id, record, RecoveryCause::ReceiptConflict)
            }
            QueryOutcome::Absent => {
                self.called.remove(&(record.intent.id, pending.operation));
                Ok(DriveResult::Waiting)
            }
            QueryOutcome::Indeterminate => self.mark_external_unknown(record, pending.operation),
        }
    }

    fn query_activate(
        &mut self,
        _id: &ContinuationId,
        record: ContinuationRecord,
        pending: PendingExternal,
    ) -> Result<DriveResult, CoordinatorError<S::Error>> {
        let Some(snapshot) = record.snapshot.as_ref() else { return Ok(DriveResult::Waiting) };
        let Some(commit) = record.authority_commit.as_ref() else {
            return Ok(DriveResult::Waiting);
        };
        let Some(binding) = record
            .binding_preparation
            .as_ref()
            .and_then(|preparation| preparation.grants.first())
            .map(|grant| grant.binding.clone())
        else {
            return Ok(DriveResult::Waiting);
        };
        match self.runtime.query_activation(QueryActivationRequest {
            continuation: record.intent.id,
            snapshot: snapshot.body.snapshot,
            destination: record.intent.destination.clone(),
            operation: pending.operation,
            binding,
            commit: commit.clone(),
        }) {
            QueryOutcome::Applied(receipt) => {
                self.called.remove(&(record.intent.id, pending.operation));
                let snapshot = record
                    .snapshot
                    .as_ref()
                    .ok_or(CoordinatorError::Core(visa_core::ContractError::MissingSnapshot))?;
                let head = LineagePoint {
                    lineage: snapshot.body.lineage.parent.lineage,
                    generation: snapshot.body.lineage.successor_generation,
                    state_digest: snapshot.body.state_digest,
                };
                let lineage = LineageUpdate {
                    lineage: head.lineage,
                    expected_head: head.clone(),
                    new_head: head,
                    expected_active: Some(record.intent.id),
                    active_continuation: None,
                };
                self.apply_event(record, &Event::Activated(receipt), Some(lineage))?;
                Ok(DriveResult::Activated)
            }
            QueryOutcome::Absent => {
                self.called.remove(&(record.intent.id, pending.operation));
                Ok(DriveResult::Waiting)
            }
            QueryOutcome::Rejected(_) | QueryOutcome::Indeterminate => self.mark_recovery(
                _id,
                record,
                RecoveryCause::RuntimeActivationUnknown { operation: pending.operation },
            ),
        }
    }

    fn recover_activated(
        &mut self,
        _id: &ContinuationId,
        record: ContinuationRecord,
    ) -> Result<DriveResult, CoordinatorError<S::Error>> {
        let Some(activation) = record.activation.clone() else {
            return Ok(DriveResult::Waiting);
        };
        let Some(snapshot) = record.snapshot.clone() else {
            return Ok(DriveResult::Waiting);
        };
        let Some(commit) = record.authority_commit.clone() else {
            return Ok(DriveResult::Fatal);
        };
        let Some(binding) = record
            .binding_preparation
            .as_ref()
            .and_then(|preparation| preparation.grants.first())
            .map(|grant| grant.binding.clone())
        else {
            return Ok(DriveResult::Fatal);
        };
        match self.runtime.query_activation(QueryActivationRequest {
            continuation: record.intent.id,
            snapshot: snapshot.body.snapshot,
            destination: record.intent.destination.clone(),
            operation: activation.operation,
            binding,
            commit,
        }) {
            QueryOutcome::Applied(receipt) if receipt == activation => Ok(DriveResult::Activated),
            QueryOutcome::Applied(_) | QueryOutcome::Rejected(_) => Ok(DriveResult::Fatal),
            QueryOutcome::Absent | QueryOutcome::Indeterminate => Ok(DriveResult::Waiting),
        }
    }

    fn abort_record(
        &mut self,
        record: ContinuationRecord,
        operation: OperationId,
        receipt: Option<AbortPreparationReceipt>,
    ) -> Result<DriveResult, CoordinatorError<S::Error>> {
        let lineage = LineageUpdate {
            lineage: record.intent.lineage_parent.lineage,
            expected_head: record.intent.lineage_parent.clone(),
            new_head: record.intent.lineage_parent.clone(),
            expected_active: Some(record.intent.id),
            active_continuation: None,
        };
        self.apply_event(
            record,
            &Event::Aborted { operation, receipt, reason: visa_core::AbortReason::Rejected },
            Some(lineage),
        )?;
        Ok(DriveResult::Aborted)
    }

    fn mark_external_unknown(
        &mut self,
        record: ContinuationRecord,
        operation: OperationId,
    ) -> Result<DriveResult, CoordinatorError<S::Error>> {
        let id = record.intent.id;
        self.mark_recovery(
            &id,
            record,
            RecoveryCause::ExternalOutcomeUnknown {
                authority: visa_core::AuthorityId::default(),
                operation,
            },
        )
    }

    fn mark_recovery(
        &mut self,
        id: &ContinuationId,
        record: ContinuationRecord,
        cause: RecoveryCause,
    ) -> Result<DriveResult, CoordinatorError<S::Error>> {
        if matches!(record.phase, ContinuationPhase::RecoveryRequired { .. }) {
            return Ok(DriveResult::Waiting);
        }
        self.apply_event(record, &Event::RecoveryRequired(cause), None)?;
        let _ = id;
        Ok(DriveResult::Waiting)
    }

    fn restore_source(
        &mut self,
        id: &ContinuationId,
        record: ContinuationRecord,
    ) -> Result<DriveResult, CoordinatorError<S::Error>> {
        if record.phase.last_known() != Progress::Aborted {
            return Ok(DriveResult::Waiting);
        }
        let Some(snapshot) = record.snapshot.clone() else { return Ok(DriveResult::Waiting) };
        match self.runtime.restore_source(RestoreSourceRequest {
            continuation: record.intent.id,
            snapshot,
            source: record.intent.source.clone(),
        }) {
            CallOutcome::Applied(receipt) => {
                self.apply_event(record, &Event::SourceRestored(receipt), None)?;
                let _ = id;
                Ok(DriveResult::SourceRestored)
            }
            CallOutcome::Rejected(_) | CallOutcome::Indeterminate => Ok(DriveResult::Waiting),
        }
    }
}

// Keep the dependency explicit in metadata even when this crate is consumed
// through a facade.
#[allow(unused_imports)]
use visa_core as _visa_core;
