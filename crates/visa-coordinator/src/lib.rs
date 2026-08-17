//! Restartable continuity coordination.
//!
//! This crate owns workflow intent and durable operation references.  Portable
//! vocabulary and the pure transition reducer live in [`visa_core`]. Runtime
//! preparation values are associated opaque types and are kept only in the
//! coordinator process.

use std::{collections::BTreeMap, fmt};

use visa_core::{
    self, AbortPreparationReceipt, ActivationReceipt, AuthorityCommitReceipt,
    BindingPreparationReceipt, CaptureReceipt, ContinuationId, ContinuationIntent,
    ContinuationPhase, ContinuationRecord, ContractError, Digest, Event, ExternalCoordinate,
    ExternalOperationKind, LineagePoint, OperationId, PendingExternal, ProfileRef, Progress,
    RecoveryCause, ResourceRequirement, SafePointReceipt, ScopeId, SnapshotEnvelope,
    SourceRestorationReceipt, apply,
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
                snapshot_digest: request.binding.preparation_digest,
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
                snapshot_digest: request.binding.preparation_digest,
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
                    receipt.snapshot_digest = request.binding.preparation_digest;
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
                    receipt.snapshot_digest = request.binding.preparation_digest;
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
                    snapshot_digest: request.binding.preparation_digest,
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
                    snapshot_digest: request.binding.preparation_digest,
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
        capture_durability: CaptureDurability,
        capture_queries: VecDeque<QueryOutcome<CapturedSnapshot, ()>>,
        capture_query_operations: Vec<OperationId>,
        freeze_calls: usize,
        prepare_calls: usize,
        restore_calls: usize,
        activate_calls: usize,
        activation_queries: VecDeque<QueryOutcome<ActivationReceipt, ()>>,
        reject_restore: bool,
        reject_source_restore: bool,
    }

    impl RuntimePort for FakeRuntime {
        type Frozen = u8;
        type Prepared = u8;
        type Restored = u8;
        type ActivationRejection = ();
        type Error = ();

        fn capture_durability(&self) -> CaptureDurability {
            self.capture_durability
        }

        fn capture(
            &mut self,
            request: CaptureRequest,
        ) -> CallOutcome<CapturedRuntime<Self::Frozen>, Self::Error> {
            let outcome = self.freeze_source(FreezeSourceRequest {
                operation: request.operation,
                continuation: request.continuation,
                scope: request.scope,
                source: request.source.clone(),
                profile: request.profile.clone(),
                lineage: request.lineage.clone(),
            });
            match outcome {
                CallOutcome::Applied(frozen) => {
                    let receipt = if self.capture_durability
                        == CaptureDurability::AuthorityDurableQueryable
                    {
                        Some(
                            CaptureReceipt {
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
                            }
                            .seal()
                            .expect("fake capture is encodable"),
                        )
                    } else {
                        None
                    };
                    CallOutcome::Applied(CapturedRuntime {
                        snapshot: frozen.snapshot,
                        safe_point: frozen.safe_point,
                        receipt,
                        frozen: frozen.frozen,
                    })
                }
                CallOutcome::Rejected(error) => CallOutcome::Rejected(error),
                CallOutcome::Indeterminate => CallOutcome::Indeterminate,
            }
        }

        fn query_capture(
            &mut self,
            request: QueryCaptureRequest,
        ) -> QueryOutcome<CapturedSnapshot, Self::Error> {
            self.capture_query_operations.push(request.operation);
            self.capture_queries.pop_front().unwrap_or(QueryOutcome::Indeterminate)
        }

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
            CallOutcome::Applied(
                SourceRestorationReceipt {
                    continuation: request.continuation,
                    snapshot: request.snapshot.body.snapshot,
                    snapshot_digest: request.snapshot.body_digest,
                    source: request.source,
                    execution_epoch: 0,
                    receipt_digest: Digest::ZERO,
                }
                .seal()
                .expect("fake restoration is encodable"),
            )
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
                    snapshot_digest: request.commit.snapshot_digest,
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
        reject_on_call: Option<usize>,
        cas_calls: usize,
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
            expected: &ContinuationRecord,
            next: ContinuationRecord,
            lineage: Option<LineageUpdate>,
        ) -> Result<ContinuationRecord, Self::Error> {
            self.cas_calls += 1;
            if self.reject_on_call == Some(self.cas_calls) {
                return Err(InMemoryStoreError::CasConflict);
            }
            self.inner.cas(continuation, expected, next, lineage)
        }

        fn discover_unfinished(&self) -> Result<Vec<ContinuationId>, Self::Error> {
            self.inner.discover_unfinished()
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
                &record,
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
            capture_durability: CaptureDurability::ProcessLocal,
            capture_queries: VecDeque::new(),
            capture_query_operations: Vec::new(),
            freeze_calls: 0,
            prepare_calls: 0,
            restore_calls: 0,
            activate_calls: 0,
            activation_queries: VecDeque::new(),
            reject_restore: false,
            reject_source_restore: true,
        };
        let store = RejectFirstCasStore {
            inner: InMemoryRecordStore::default(),
            reject_on_call: Some(2),
            cas_calls: 0,
        };
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
    fn failed_post_abort_source_restore_is_durably_recovery_required() {
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
            capture_durability: CaptureDurability::ProcessLocal,
            capture_queries: VecDeque::new(),
            capture_query_operations: Vec::new(),
            freeze_calls: 0,
            prepare_calls: 0,
            restore_calls: 0,
            activate_calls: 0,
            activation_queries: VecDeque::new(),
            reject_restore: false,
            reject_source_restore: true,
        };
        let mut coordinator = Coordinator::new(InMemoryRecordStore::default(), authority, runtime);
        coordinator.begin(intent).expect("begin");
        assert_eq!(coordinator.drive(&id).expect("capture"), DriveResult::DurableBoundary);
        assert_eq!(coordinator.abort(&id).expect("abort"), DriveResult::Aborted);

        let outcome = coordinator.recover_with_diagnostics(&id).expect("restore failure");
        assert_eq!(outcome.result, DriveResult::Waiting);
        assert_eq!(outcome.diagnostic.stage, CoordinatorStage::SourceRestore);
        assert_eq!(
            outcome.diagnostic.recovery_cause,
            Some(RecoveryCause::SourceRestorationUnknown)
        );
        assert_eq!(outcome.diagnostic.retry_hint, Some(RetryHint::do_not_retry()));
        let record = coordinator.store.load(&id).expect("load").expect("record");
        assert!(matches!(
            record.phase,
            ContinuationPhase::RecoveryRequired {
                last_known: Progress::Aborted,
                cause: RecoveryCause::SourceRestorationUnknown,
            }
        ));
        assert_eq!(coordinator.runtime.restore_calls, 1);
        assert_eq!(coordinator.recover(&id).expect("fail closed"), DriveResult::Waiting);
        assert_eq!(coordinator.runtime.restore_calls, 1);
    }

    #[test]
    fn lost_source_restoration_record_ack_does_not_replay_snapshot() {
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
            capture_durability: CaptureDurability::ProcessLocal,
            capture_queries: VecDeque::new(),
            capture_query_operations: Vec::new(),
            freeze_calls: 0,
            prepare_calls: 0,
            restore_calls: 0,
            activate_calls: 0,
            activation_queries: VecDeque::new(),
            reject_restore: false,
            reject_source_restore: false,
        };
        let store = RejectFirstCasStore {
            inner: InMemoryRecordStore::default(),
            // capture arm, snapshot, and abort are the first three CAS calls;
            // fail the acknowledgement of the applied source restoration.
            reject_on_call: Some(4),
            cas_calls: 0,
        };
        let mut coordinator = Coordinator::new(store, authority, runtime);
        coordinator.begin(intent).expect("begin");
        assert_eq!(coordinator.drive(&id).expect("capture"), DriveResult::DurableBoundary);
        assert_eq!(coordinator.abort(&id).expect("abort"), DriveResult::Aborted);

        assert_eq!(
            coordinator.recover(&id).expect("lost record acknowledgement"),
            DriveResult::Waiting
        );
        let record = coordinator.store.load(&id).expect("load").expect("record");
        assert!(record.source_restoration.is_none());
        assert!(matches!(
            record.phase,
            ContinuationPhase::RecoveryRequired {
                last_known: Progress::Aborted,
                cause: RecoveryCause::SourceRestorationUnknown,
            }
        ));
        assert_eq!(coordinator.runtime.restore_calls, 1);

        assert_eq!(coordinator.recover(&id).expect("fail closed"), DriveResult::Waiting);
        assert_eq!(coordinator.runtime.restore_calls, 1);
    }

    #[test]
    fn durable_capture_query_retries_after_capture_record_cas_conflict_without_recapture() {
        let intent = intent();
        let (snapshot, safe) = snapshot_for(&intent);
        let authority = FakeAuthority {
            prepare_calls: 0,
            commit_calls: 0,
            prepare_queries: VecDeque::new(),
            commit_queries: VecDeque::new(),
        };
        let runtime = FakeRuntime {
            // The initial call is indeterminate; the durable capture becomes
            // observable only through the exact query below.
            snapshot: None,
            capture_durability: CaptureDurability::AuthorityDurableQueryable,
            capture_queries: VecDeque::new(),
            capture_query_operations: Vec::new(),
            freeze_calls: 0,
            prepare_calls: 0,
            restore_calls: 0,
            activate_calls: 0,
            activation_queries: VecDeque::new(),
            reject_restore: false,
            reject_source_restore: false,
        };
        let store = RejectFirstCasStore {
            inner: InMemoryRecordStore::default(),
            // begin has no CAS; drive arms the operation and records the
            // initial recovery requirement before the first query.
            reject_on_call: Some(3),
            cas_calls: 0,
        };
        let mut coordinator = Coordinator::new(store, authority, runtime);
        let id = coordinator.begin(intent.clone()).expect("begin");

        assert_eq!(coordinator.drive(&id).expect("indeterminate capture"), DriveResult::Waiting);
        let pending = coordinator
            .store
            .load(&id)
            .expect("load")
            .expect("record")
            .pending
            .expect("capture operation remains pending");
        let receipt = CaptureReceipt {
            operation: pending.operation,
            continuation: intent.id,
            scope: intent.scope,
            snapshot: snapshot.body.snapshot,
            source: intent.source.clone(),
            profile: intent.profile.clone(),
            lineage: snapshot.body.lineage.clone(),
            state_digest: snapshot.body.state_digest,
            snapshot_digest: snapshot.body_digest,
            safe_point_digest: safe.receipt_digest,
            receipt_digest: Digest::ZERO,
        }
        .seal()
        .expect("capture receipt");
        let captured = CapturedSnapshot { snapshot, safe_point: safe, receipt };
        coordinator.runtime.capture_queries = VecDeque::from([
            QueryOutcome::Applied(captured.clone()),
            QueryOutcome::Applied(captured),
        ]);

        assert!(matches!(
            coordinator.drive(&id),
            Err(CoordinatorError::Store(InMemoryStoreError::CasConflict))
        ));
        let after_failed_query = coordinator.store.load(&id).expect("load").expect("record");
        assert!(after_failed_query.snapshot.is_none());
        assert_eq!(
            after_failed_query.pending.as_ref().map(|value| value.operation),
            Some(pending.operation)
        );
        assert_eq!(coordinator.runtime.capture_query_operations, vec![pending.operation]);
        assert_eq!(coordinator.runtime.freeze_calls, 1);
        assert_eq!(coordinator.read_control_counts().external_call, 1);

        assert_eq!(
            coordinator.recover(&id).expect("retry durable query"),
            DriveResult::DurableBoundary
        );
        assert_eq!(
            coordinator.runtime.capture_query_operations,
            vec![pending.operation, pending.operation]
        );
        assert_eq!(coordinator.runtime.freeze_calls, 1);
        assert_eq!(coordinator.read_control_counts().external_call, 1);
        let record = coordinator.store.load(&id).expect("load").expect("record");
        assert!(record.snapshot.is_some());
        assert!(record.pending.is_none());
    }

    #[test]
    fn durable_capture_query_conflict_is_fatal_and_preserves_exact_operation() {
        let intent = intent();
        let authority = FakeAuthority {
            prepare_calls: 0,
            commit_calls: 0,
            prepare_queries: VecDeque::new(),
            commit_queries: VecDeque::new(),
        };
        let runtime = FakeRuntime {
            snapshot: None,
            capture_durability: CaptureDurability::AuthorityDurableQueryable,
            capture_queries: VecDeque::new(),
            capture_query_operations: Vec::new(),
            freeze_calls: 0,
            prepare_calls: 0,
            restore_calls: 0,
            activate_calls: 0,
            activation_queries: VecDeque::new(),
            reject_restore: false,
            reject_source_restore: false,
        };
        let mut coordinator = Coordinator::new(InMemoryRecordStore::default(), authority, runtime);
        let id = coordinator.begin(intent).expect("begin");

        assert_eq!(coordinator.drive(&id).expect("indeterminate capture"), DriveResult::Waiting);
        let pending = coordinator
            .store
            .load(&id)
            .expect("load")
            .expect("record")
            .pending
            .expect("capture operation remains pending");
        coordinator.runtime.capture_queries = VecDeque::from([QueryOutcome::Rejected(())]);

        assert_eq!(
            coordinator.recover(&id).expect("conflicting exact query"),
            DriveResult::Waiting
        );
        let record = coordinator.store.load(&id).expect("load").expect("record");
        assert_eq!(record.pending.as_ref().map(|value| value.operation), Some(pending.operation));
        assert!(matches!(
            record.phase,
            ContinuationPhase::RecoveryRequired {
                cause: RecoveryCause::CaptureReceiptMismatch { operation },
                ..
            } if operation == pending.operation
        ));
        assert_eq!(coordinator.runtime.capture_query_operations, vec![pending.operation]);
        assert_eq!(coordinator.runtime.freeze_calls, 1);
        let outcome = coordinator.read_step_outcome().expect("diagnostic");
        assert!(matches!(
            outcome.diagnostic.recovery_cause,
            Some(RecoveryCause::CaptureReceiptMismatch { operation })
                if operation == pending.operation
        ));
        assert_eq!(outcome.diagnostic.retry_hint, Some(RetryHint::do_not_retry()));

        assert_eq!(coordinator.recover(&id).expect("fatal recovery"), DriveResult::Fatal);
        assert_eq!(coordinator.drive(&id).expect("fatal drive"), DriveResult::Fatal);
        assert_eq!(coordinator.runtime.capture_query_operations, vec![pending.operation]);
    }

    #[test]
    fn process_local_capture_indeterminate_records_dual_crash_risk_and_diagnostic() {
        let intent = intent();
        let authority = FakeAuthority {
            prepare_calls: 0,
            commit_calls: 0,
            prepare_queries: VecDeque::new(),
            commit_queries: VecDeque::new(),
        };
        let runtime = FakeRuntime {
            snapshot: None,
            capture_durability: CaptureDurability::ProcessLocal,
            capture_queries: VecDeque::new(),
            capture_query_operations: Vec::new(),
            freeze_calls: 0,
            prepare_calls: 0,
            restore_calls: 0,
            activate_calls: 0,
            activation_queries: VecDeque::new(),
            reject_restore: false,
            reject_source_restore: false,
        };
        let mut coordinator = Coordinator::new(InMemoryRecordStore::default(), authority, runtime);
        let id = coordinator.begin(intent).expect("begin");

        let outcome = coordinator.drive_with_diagnostics(&id).expect("capture outcome");
        assert_eq!(outcome.result, DriveResult::Waiting);
        assert_eq!(coordinator.runtime.freeze_calls, 1);
        let record = coordinator.store.load(&id).expect("load").expect("record");
        let operation = record.pending.as_ref().expect("capture pending").operation;
        assert!(matches!(
            record.phase,
            ContinuationPhase::RecoveryRequired {
                cause: RecoveryCause::ProcessLocalCaptureDualCrashRisk { operation: found },
                ..
            } if found == operation
        ));
        assert_eq!(outcome.diagnostic.stage, CoordinatorStage::Capture);
        assert_eq!(outcome.diagnostic.operation, Some(operation));
        assert_eq!(outcome.diagnostic.capture_capability, CaptureDurability::ProcessLocal);
        assert!(matches!(
            outcome.diagnostic.recovery_cause,
            Some(RecoveryCause::ProcessLocalCaptureDualCrashRisk { operation: found })
                if found == operation
        ));
        assert_eq!(outcome.diagnostic.retry_hint, Some(RetryHint::retry(BackoffClass::Medium)));
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
    fn recovery_barrier_does_not_replay_last_known_progress() {
        let intent = intent();
        let (snapshot, safe) = snapshot_for(&intent);
        let mut record = begun();
        record.phase = ContinuationPhase::RecoveryRequired {
            last_known: Progress::Preparing,
            cause: RecoveryCause::CaptureRejected { operation: OperationId::from_u128(7) },
        };
        let id = record.intent.id;
        let mut store = InMemoryRecordStore::default();
        store
            .create(CreateRecord {
                lineage: LineageCreate {
                    parent: record.intent.lineage_parent.clone(),
                    active_continuation: id,
                },
                record,
            })
            .expect("record");
        let runtime = FakeRuntime {
            snapshot: Some((snapshot, safe)),
            capture_durability: CaptureDurability::ProcessLocal,
            capture_queries: VecDeque::new(),
            capture_query_operations: Vec::new(),
            freeze_calls: 0,
            prepare_calls: 0,
            restore_calls: 0,
            activate_calls: 0,
            activation_queries: VecDeque::new(),
            reject_restore: false,
            reject_source_restore: false,
        };
        let authority = FakeAuthority {
            prepare_calls: 0,
            commit_calls: 0,
            prepare_queries: VecDeque::new(),
            commit_queries: VecDeque::new(),
        };
        let mut coordinator = Coordinator::new(store, authority, runtime);

        assert_eq!(coordinator.drive(&id).expect("barrier"), DriveResult::Waiting);
        assert_eq!(coordinator.runtime.freeze_calls, 0);
        assert!(matches!(
            coordinator.store.load(&id).expect("load").unwrap().phase,
            ContinuationPhase::RecoveryRequired { .. }
        ));
    }

    #[test]
    fn abort_is_idempotent_after_durable_abort() {
        let mut record = begun();
        record.phase = ContinuationPhase::Progress(Progress::Aborted);
        let id = record.intent.id;
        let revision = record.revision;
        let mut store = InMemoryRecordStore::default();
        store
            .create(CreateRecord {
                lineage: LineageCreate {
                    parent: record.intent.lineage_parent.clone(),
                    active_continuation: id,
                },
                record,
            })
            .expect("record");
        let authority = FakeAuthority {
            prepare_calls: 0,
            commit_calls: 0,
            prepare_queries: VecDeque::new(),
            commit_queries: VecDeque::new(),
        };
        let runtime = FakeRuntime {
            snapshot: None,
            capture_durability: CaptureDurability::ProcessLocal,
            capture_queries: VecDeque::new(),
            capture_query_operations: Vec::new(),
            freeze_calls: 0,
            prepare_calls: 0,
            restore_calls: 0,
            activate_calls: 0,
            activation_queries: VecDeque::new(),
            reject_restore: false,
            reject_source_restore: false,
        };
        let mut coordinator = Coordinator::new(store, authority, runtime);

        assert_eq!(coordinator.abort(&id).expect("first abort"), DriveResult::Aborted);
        assert_eq!(coordinator.abort(&id).expect("second abort"), DriveResult::Aborted);
        assert_eq!(coordinator.store.load(&id).unwrap().unwrap().revision, revision);
    }

    #[test]
    fn applied_prepare_query_keeps_barrier_when_record_cas_fails() {
        let intent = intent();
        let (snapshot, safe) = snapshot_for(&intent);
        let preparation = BindingPreparationReceipt {
            operation: OperationId::from_u128(1),
            continuation: intent.id,
            snapshot: snapshot.body.snapshot,
            snapshot_digest: snapshot.body_digest,
            destination: intent.destination.clone(),
            grants: vec![],
            receipt_digest: Digest::ZERO,
        }
        .seal()
        .expect("preparation");
        let authority = FakeAuthority {
            prepare_calls: 0,
            commit_calls: 0,
            prepare_queries: VecDeque::from([
                QueryOutcome::Applied(preparation.clone()),
                QueryOutcome::Applied(preparation),
            ]),
            commit_queries: VecDeque::new(),
        };
        let runtime = FakeRuntime {
            snapshot: Some((snapshot, safe)),
            capture_durability: CaptureDurability::ProcessLocal,
            capture_queries: VecDeque::new(),
            capture_query_operations: Vec::new(),
            freeze_calls: 0,
            prepare_calls: 0,
            restore_calls: 0,
            activate_calls: 0,
            activation_queries: VecDeque::new(),
            reject_restore: false,
            reject_source_restore: false,
        };
        let store = RejectFirstCasStore {
            inner: InMemoryRecordStore::default(),
            // capture arm, capture record, and prepare arm succeed; the
            // exact query's record CAS is the first rejected write.
            reject_on_call: Some(4),
            cas_calls: 0,
        };
        let mut coordinator = Coordinator::new(store, authority, runtime);
        let id = coordinator.begin(intent).expect("begin");
        coordinator.drive(&id).expect("capture");
        coordinator.drive(&id).expect("arm prepare");
        coordinator.drive(&id).expect("prepare call");
        assert!(matches!(
            coordinator.drive(&id),
            Err(CoordinatorError::Store(InMemoryStoreError::CasConflict))
        ));
        let operation = coordinator.store.load(&id).unwrap().unwrap().pending.unwrap().operation;
        assert!(coordinator.called.get(&(id, operation)).copied().unwrap_or(false));
        coordinator.store.reject_on_call = None;
        assert_eq!(
            coordinator.drive(&id).expect("retry exact query"),
            DriveResult::DurableBoundary
        );
        assert!(!coordinator.called.contains_key(&(id, operation)));
        assert!(coordinator.store.load(&id).unwrap().unwrap().binding_preparation.is_some());
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
            snapshot_digest: snapshot.body_digest,
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
            capture_durability: CaptureDurability::ProcessLocal,
            capture_queries: VecDeque::new(),
            capture_query_operations: Vec::new(),
            freeze_calls: 0,
            prepare_calls: 0,
            restore_calls: 0,
            activate_calls: 0,
            activation_queries: VecDeque::new(),
            reject_restore: false,
            reject_source_restore: false,
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
            snapshot_digest: snapshot.body_digest,
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
            capture_durability: CaptureDurability::ProcessLocal,
            capture_queries: VecDeque::new(),
            capture_query_operations: Vec::new(),
            freeze_calls: 0,
            prepare_calls: 0,
            restore_calls: 0,
            activate_calls: 0,
            activation_queries: VecDeque::new(),
            reject_restore: false,
            reject_source_restore: false,
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
            capture_durability: CaptureDurability::ProcessLocal,
            capture_queries: VecDeque::new(),
            capture_query_operations: Vec::new(),
            freeze_calls: 0,
            prepare_calls: 0,
            restore_calls: 0,
            activate_calls: 0,
            activation_queries: VecDeque::new(),
            reject_restore: false,
            reject_source_restore: false,
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
            snapshot_digest: snapshot.body_digest,
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
            snapshot_digest: snapshot.body_digest,
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
            capture_durability: CaptureDurability::ProcessLocal,
            capture_queries: VecDeque::new(),
            capture_query_operations: Vec::new(),
            freeze_calls: 0,
            prepare_calls: 0,
            restore_calls: 0,
            activate_calls: 0,
            activation_queries: VecDeque::new(),
            reject_restore: false,
            reject_source_restore: false,
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

    #[test]
    fn unfinished_discovery_uses_only_activated_and_source_restored_aborted_terminals() {
        let mut activated = begun();
        activated.intent.id = ContinuationId::from_u128(10);
        activated.intent.lineage_parent.lineage = visa_core::LineageId::from_u128(10);
        activated.phase = ContinuationPhase::Progress(Progress::Activated);

        let mut restored_aborted = begun();
        restored_aborted.intent.id = ContinuationId::from_u128(11);
        restored_aborted.intent.lineage_parent.lineage = visa_core::LineageId::from_u128(11);
        restored_aborted.phase = ContinuationPhase::Progress(Progress::Aborted);
        restored_aborted.source_restoration = Some(SourceRestorationReceipt {
            continuation: restored_aborted.intent.id,
            snapshot: visa_core::SnapshotId::from_u128(12),
            snapshot_digest: Digest::ZERO,
            source: restored_aborted.intent.source.clone(),
            execution_epoch: 1,
            receipt_digest: Digest::ZERO,
        });

        let mut aborted_needing_restore = begun();
        aborted_needing_restore.intent.id = ContinuationId::from_u128(12);
        aborted_needing_restore.intent.lineage_parent.lineage = visa_core::LineageId::from_u128(12);
        aborted_needing_restore.phase = ContinuationPhase::Progress(Progress::Aborted);
        aborted_needing_restore.snapshot = Some(snapshot_for(&aborted_needing_restore.intent).0);

        let mut aborted_before_capture = begun();
        aborted_before_capture.intent.id = ContinuationId::from_u128(13);
        aborted_before_capture.intent.lineage_parent.lineage = visa_core::LineageId::from_u128(13);
        aborted_before_capture.phase = ContinuationPhase::Progress(Progress::Aborted);

        let mut store = InMemoryRecordStore::default();
        for record in [activated, restored_aborted, aborted_needing_restore, aborted_before_capture]
        {
            let id = record.intent.id;
            store
                .create(CreateRecord {
                    lineage: LineageCreate {
                        parent: record.intent.lineage_parent.clone(),
                        active_continuation: id,
                    },
                    record,
                })
                .expect("record");
        }
        assert_eq!(
            store.discover_unfinished().expect("discovery"),
            vec![ContinuationId::from_u128(12)]
        );
    }

    #[test]
    fn activated_recovery_uses_durable_receipt_without_runtime_query() {
        let mut activated = begun();
        activated.intent.id = ContinuationId::from_u128(14);
        activated.intent.lineage_parent.lineage = visa_core::LineageId::from_u128(14);
        let (snapshot, _) = snapshot_for(&activated.intent);
        activated.snapshot = Some(snapshot.clone());
        activated.activation = Some(
            ActivationReceipt {
                operation: OperationId::from_u128(15),
                continuation: activated.intent.id,
                snapshot: snapshot.body.snapshot,
                snapshot_digest: snapshot.body_digest,
                destination: activated.intent.destination.clone(),
                authority_commit_digest: Digest::ZERO,
                execution_epoch: 1,
                receipt_digest: Digest::ZERO,
            }
            .seal()
            .expect("activation receipt"),
        );
        activated.phase = ContinuationPhase::Progress(Progress::Activated);

        let runtime = FakeRuntime {
            snapshot: None,
            capture_durability: CaptureDurability::ProcessLocal,
            capture_queries: VecDeque::new(),
            capture_query_operations: Vec::new(),
            freeze_calls: 0,
            prepare_calls: 0,
            restore_calls: 0,
            activate_calls: 0,
            // Even an indeterminate authority/runtime query must not make a
            // durable Activated record waiting or rediscoverable.
            activation_queries: VecDeque::from([QueryOutcome::Indeterminate]),
            reject_restore: false,
            reject_source_restore: false,
        };
        let id = activated.intent.id;
        let mut store = InMemoryRecordStore::default();
        store
            .create(CreateRecord {
                lineage: LineageCreate {
                    parent: activated.intent.lineage_parent.clone(),
                    active_continuation: id,
                },
                record: activated,
            })
            .expect("activated record");
        let authority = FakeAuthority {
            prepare_calls: 0,
            commit_calls: 0,
            prepare_queries: VecDeque::new(),
            commit_queries: VecDeque::new(),
        };
        let mut coordinator = Coordinator::new(store, authority, runtime);

        assert_eq!(coordinator.recover(&id).expect("recover"), DriveResult::Activated);
        assert_eq!(coordinator.runtime.activation_queries.len(), 1);
        assert_eq!(coordinator.read_control_counts().query, 0);
        assert!(coordinator.discover_unfinished().expect("discovery").is_empty());
    }

    #[test]
    fn indeterminate_step_publishes_stage_operation_capability_cause_and_retry_hint() {
        let intent = intent();
        let destination_authority = intent.destination.authority;
        let (snapshot, safe) = snapshot_for(&intent);
        let authority = FakeAuthority {
            prepare_calls: 0,
            commit_calls: 0,
            prepare_queries: VecDeque::from([QueryOutcome::Indeterminate]),
            commit_queries: VecDeque::new(),
        };
        let runtime = FakeRuntime {
            snapshot: Some((snapshot, safe)),
            capture_durability: CaptureDurability::ProcessLocal,
            capture_queries: VecDeque::new(),
            capture_query_operations: Vec::new(),
            freeze_calls: 0,
            prepare_calls: 0,
            restore_calls: 0,
            activate_calls: 0,
            activation_queries: VecDeque::new(),
            reject_restore: false,
            reject_source_restore: false,
        };
        let mut coordinator = Coordinator::new(InMemoryRecordStore::default(), authority, runtime);
        let id = coordinator.begin(intent).expect("begin");
        coordinator.drive(&id).expect("capture");
        let DriveResult::ExternalPending(operation) = coordinator.drive(&id).expect("arm") else {
            panic!("expected pending")
        };
        coordinator.drive(&id).expect("call");
        coordinator.drive(&id).expect("query");
        let outcome = coordinator.read_step_outcome().expect("step outcome");
        assert_eq!(outcome.result, DriveResult::Waiting);
        assert_eq!(outcome.diagnostic.stage, CoordinatorStage::Prepare);
        assert_eq!(outcome.diagnostic.operation, Some(operation));
        assert_eq!(outcome.diagnostic.capture_capability, CaptureDurability::ProcessLocal);
        assert!(matches!(
            outcome.diagnostic.recovery_cause,
            Some(RecoveryCause::ExternalOutcomeUnknown {
                authority,
                operation: found,
            }) if found == operation && authority == destination_authority
        ));
        assert_eq!(outcome.diagnostic.retry_hint, Some(RetryHint::retry(BackoffClass::Long)));
    }

    #[test]
    fn control_counts_cover_drive_load_reducer_arm_calls_and_queries() {
        let intent = intent();
        let (snapshot, safe) = snapshot_for(&intent);
        let authority = FakeAuthority {
            prepare_calls: 0,
            commit_calls: 0,
            prepare_queries: VecDeque::new(),
            commit_queries: VecDeque::new(),
        };
        let runtime = FakeRuntime {
            snapshot: Some((snapshot, safe)),
            capture_durability: CaptureDurability::ProcessLocal,
            capture_queries: VecDeque::new(),
            capture_query_operations: Vec::new(),
            freeze_calls: 0,
            prepare_calls: 0,
            restore_calls: 0,
            activate_calls: 0,
            activation_queries: VecDeque::new(),
            reject_restore: false,
            reject_source_restore: false,
        };
        let mut coordinator = Coordinator::new(InMemoryRecordStore::default(), authority, runtime);
        let id = coordinator.begin(intent).expect("begin");
        assert_eq!(coordinator.drive(&id).expect("capture"), DriveResult::DurableBoundary);
        let counts = coordinator.read_control_counts();
        assert_eq!(counts.drive, 1);
        assert_eq!(counts.load, 2);
        assert_eq!(counts.cas, 2);
        assert_eq!(counts.reducer, 3);
        assert_eq!(counts.arm, 1);
        assert_eq!(counts.external_call, 1);
        assert_eq!(counts.query, 0);
        assert_eq!(counts.capture, 1);
        assert_eq!(counts.prepare, 0);
        assert_eq!(counts.commit, 0);
        assert_eq!(counts.abort, 0);
        assert_eq!(counts.activation, 0);
        assert_eq!(coordinator.take_control_counts(), counts);
        assert_eq!(coordinator.read_control_counts(), CoordinatorControlCounts::default());
    }

    #[test]
    fn postcommit_runtime_unknowns_resume_destination_recovery() {
        let mut record = begun();
        record.authority_commit = Some(AuthorityCommitReceipt {
            operation: OperationId::from_u128(90),
            continuation: record.intent.id,
            snapshot: visa_core::SnapshotId::from_u128(91),
            snapshot_digest: Digest::of_bytes(b"snapshot"),
            source: record.intent.source.clone(),
            source_fence_epoch: 1,
            destination: record.intent.destination.clone(),
            binding_receipt_digest: Digest::of_bytes(b"binding"),
            execution_epoch: 1,
            receipt_digest: Digest::of_bytes(b"commit"),
        });
        for cause in [
            RecoveryCause::RuntimePreparationUnknown { operation: OperationId::from_u128(92) },
            RecoveryCause::RuntimeRestoreUnknown { operation: OperationId::from_u128(93) },
        ] {
            record.phase = ContinuationPhase::RecoveryRequired {
                last_known: Progress::Committed,
                cause: cause.clone(),
            };
            assert_eq!(decide_recovery(&record), RecoveryDecision::DestinationOnly);
            let operation = match cause {
                RecoveryCause::RuntimePreparationUnknown { operation }
                | RecoveryCause::RuntimeRestoreUnknown { operation } => operation,
                _ => unreachable!(),
            };
            record.pending = Some(PendingExternal {
                operation,
                kind: ExternalOperationKind::ActivateRuntime,
                request_digest: Digest::of_bytes(b"activation"),
            });
            assert!(recovery_allows_pending_query(&record));
            record.pending = None;
        }
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
    pub operation: OperationId,
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

/// Explicit runtime capture durability.  `ProcessLocal` is useful for
/// cooperative runtimes, but it cannot recover a capture after both the
/// coordinator and source process disappear.  `AuthorityDurableQueryable`
/// requires an exact operation query after an acknowledgement is lost.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureDurability {
    ProcessLocal,
    AuthorityDurableQueryable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureRequest {
    pub operation: OperationId,
    pub continuation: ContinuationId,
    pub scope: ScopeId,
    pub source: ExternalCoordinate,
    pub profile: ProfileRef,
    pub lineage: visa_core::LineageAdvance,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryCaptureRequest {
    pub operation: OperationId,
    pub continuation: ContinuationId,
    pub scope: ScopeId,
    pub source: ExternalCoordinate,
    pub profile: ProfileRef,
    pub lineage: visa_core::LineageAdvance,
}

/// A capture returned while the source runtime is still held by this
/// coordinator process.  A durable runtime supplies `receipt`; a process-local
/// runtime deliberately leaves it absent.
pub struct CapturedRuntime<F> {
    pub snapshot: SnapshotEnvelope,
    pub safe_point: SafePointReceipt,
    pub receipt: Option<CaptureReceipt>,
    pub frozen: F,
}

/// The durable/queryable portion of a capture returned by an exact query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapturedSnapshot {
    pub snapshot: SnapshotEnvelope,
    pub safe_point: SafePointReceipt,
    pub receipt: CaptureReceipt,
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
    /// The authority may commit an activation without issuing any concrete
    /// grants (for example, when the runtime needs no resource rebinding).
    /// In that case there is no binding coordinate that can be queried.
    pub binding: Option<ExternalCoordinate>,
    pub commit: AuthorityCommitReceipt,
}

/// Runtime tokens are not serializable and never occur in a core record.
pub trait RuntimePort {
    type Frozen;
    type Prepared;
    type Restored;
    type ActivationRejection: Clone;
    type Error: Clone;

    /// The capability is part of the runtime contract, rather than an
    /// assumption hidden in coordinator recovery. Existing runtimes default
    /// to process-local capture until they implement the durable protocol.
    fn capture_durability(&self) -> CaptureDurability {
        CaptureDurability::ProcessLocal
    }

    /// Capture using the stable operation identity already stored in the
    /// continuation record. The default adapts the original process-local
    /// freeze API, preserving existing embeddings while making their weaker
    /// durability explicit.
    fn capture(
        &mut self,
        request: CaptureRequest,
    ) -> CallOutcome<CapturedRuntime<Self::Frozen>, Self::Error> {
        let operation = request.operation;
        match self.freeze_source(FreezeSourceRequest {
            operation,
            continuation: request.continuation,
            scope: request.scope,
            source: request.source,
            profile: request.profile,
            lineage: request.lineage,
        }) {
            CallOutcome::Applied(frozen) => CallOutcome::Applied(CapturedRuntime {
                snapshot: frozen.snapshot,
                safe_point: frozen.safe_point,
                receipt: None,
                frozen: frozen.frozen,
            }),
            CallOutcome::Rejected(error) => CallOutcome::Rejected(error),
            CallOutcome::Indeterminate => CallOutcome::Indeterminate,
        }
    }

    /// Query the exact durable capture operation. Process-local runtimes leave
    /// the default indeterminate, which is surfaced as dual-crash recovery.
    fn query_capture(
        &mut self,
        _request: QueryCaptureRequest,
    ) -> QueryOutcome<CapturedSnapshot, Self::Error> {
        QueryOutcome::Indeterminate
    }

    /// Best-effort cleanup for a durable capture row after its exact receipt
    /// has been persisted in the continuation record. Cleanup is deliberately
    /// outside the correctness boundary: a failure leaves the row queryable,
    /// and a later drive/restart may retry this idempotent operation.
    fn retire_capture(&mut self, _receipt: &CaptureReceipt) -> Result<(), Self::Error> {
        Ok(())
    }

    fn freeze_source(
        &mut self,
        request: FreezeSourceRequest,
    ) -> CallOutcome<FrozenRuntime<Self::Frozen>, Self::Error>;
    /// Restore the exact aborted source cut. Implementations must make an
    /// exact duplicate request idempotent: it may return the same restoration
    /// fact, but must never replay the snapshot over a source that has already
    /// resumed execution. The coordinator stops with
    /// `SourceRestorationUnknown` if its durable acknowledgement is lost.
    fn restore_source(
        &mut self,
        request: RestoreSourceRequest,
    ) -> CallOutcome<SourceRestorationReceipt, Self::Error>;
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
        expected: &ContinuationRecord,
        next: ContinuationRecord,
        lineage: Option<LineageUpdate>,
    ) -> Result<ContinuationRecord, Self::Error>;

    /// Discover records that still need coordinator work after a process
    /// restart. Stores should implement this against their durable index;
    /// failures are surfaced to the embedding rather than treated as an
    /// empty result.
    fn discover_unfinished(&self) -> Result<Vec<ContinuationId>, Self::Error>;
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
        expected: &ContinuationRecord,
        next: ContinuationRecord,
        lineage: Option<LineageUpdate>,
    ) -> Result<ContinuationRecord, Self::Error> {
        let current = self.records.get(continuation).ok_or(InMemoryStoreError::NotFound)?;
        if current != expected || expected.revision.checked_add(1) != Some(next.revision) {
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

    fn discover_unfinished(&self) -> Result<Vec<ContinuationId>, Self::Error> {
        Ok(self
            .records
            .iter()
            .filter_map(|(id, record)| (!record_is_terminal(record)).then_some(*id))
            .collect())
    }
}

/// Activated continuations are complete. An aborted continuation needs source
/// restoration only when it had already captured a snapshot; an abort before
/// capture has no frozen source state to restore.
#[must_use]
pub fn record_is_terminal(record: &ContinuationRecord) -> bool {
    matches!(record.phase, ContinuationPhase::Progress(Progress::Activated))
        || (matches!(record.phase, ContinuationPhase::Progress(Progress::Aborted))
            && (record.snapshot.is_none() || record.source_restoration.is_some()))
}

fn stage_for_operation(kind: ExternalOperationKind) -> CoordinatorStage {
    match kind {
        ExternalOperationKind::CaptureSource => CoordinatorStage::Capture,
        ExternalOperationKind::PrepareBindings => CoordinatorStage::Prepare,
        ExternalOperationKind::CommitAuthority => CoordinatorStage::Commit,
        ExternalOperationKind::AbortPreparation => CoordinatorStage::Abort,
        ExternalOperationKind::ActivateRuntime => CoordinatorStage::Activation,
    }
}

fn operation_for_pending(record: &ContinuationRecord, kind: ExternalOperationKind) -> OperationId {
    record
        .pending
        .as_ref()
        .filter(|pending| pending.kind == kind)
        .map_or_else(|| OperationId::from_u128(0), |pending| pending.operation)
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
            RecoveryCause::RuntimePreparationUnknown { .. }
            | RecoveryCause::RuntimeRestoreUnknown { .. }
                if record.authority_commit.is_some() =>
            {
                RecoveryDecision::DestinationOnly
            }
            RecoveryCause::ExternalOutcomeUnknown { .. }
            | RecoveryCause::CaptureOutcomeUnknown { .. }
            | RecoveryCause::CaptureDurabilityUnavailable { .. }
            | RecoveryCause::ProcessLocalCaptureDualCrashRisk { .. }
            | RecoveryCause::CaptureRejected { .. }
            | RecoveryCause::SourceRestorationUnknown
            | RecoveryCause::RuntimePreparationUnknown { .. }
            | RecoveryCause::RuntimeRestoreUnknown { .. }
            | RecoveryCause::RuntimeActivationUnknown { .. }
            | RecoveryCause::UnresolvedEffects => RecoveryDecision::Wait,
            RecoveryCause::CaptureReceiptMismatch { .. } => RecoveryDecision::Fatal,
        };
    }
    if record.authority_commit.is_some()
        || matches!(record.phase.last_known(), Progress::Committed | Progress::Activated)
    {
        return RecoveryDecision::DestinationOnly;
    }
    RecoveryDecision::Wait
}

fn recovery_allows_pending_query(record: &ContinuationRecord) -> bool {
    let ContinuationPhase::RecoveryRequired { cause, .. } = &record.phase else {
        return true;
    };
    matches!(
        cause,
        RecoveryCause::ExternalOutcomeUnknown { .. }
            | RecoveryCause::CaptureOutcomeUnknown { .. }
            | RecoveryCause::ProcessLocalCaptureDualCrashRisk { .. }
            | RecoveryCause::RuntimePreparationUnknown { .. }
            | RecoveryCause::RuntimeRestoreUnknown { .. }
            | RecoveryCause::RuntimeActivationUnknown { .. }
    )
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

/// The control-path stage that produced a process-local diagnostic.  These
/// values are coordinator vocabulary only; they do not become part of a core
/// record or an authority receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoordinatorStage {
    Capture,
    Prepare,
    Commit,
    Abort,
    Activation,
    SourceRestore,
    Recovery,
    Store,
    Reducer,
}

/// A scheduler-facing backoff class.  It is deliberately qualitative: an
/// embedding chooses the actual delay and may use a different scheduling
/// policy without changing the continuation's semantic outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackoffClass {
    Immediate,
    Short,
    Medium,
    Long,
}

/// Explicit retry guidance for an indeterminate control-path result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetryHint {
    pub retryable: bool,
    pub backoff: BackoffClass,
}

impl RetryHint {
    #[must_use]
    pub const fn retry(backoff: BackoffClass) -> Self {
        Self { retryable: true, backoff }
    }

    #[must_use]
    pub const fn do_not_retry() -> Self {
        Self { retryable: false, backoff: BackoffClass::Long }
    }
}

/// The process-local semantic outcome of the most recent coordinator step.
/// A rejection's rendered reason, when available, lives only here and is
/// never sent through `visa_core::Event`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepOutcome {
    Applied,
    Rejected,
    Indeterminate,
    Waiting,
    DurableBoundary,
    SourceRestored,
    Activated,
    Aborted,
    Fatal,
    Error,
}

impl StepOutcome {
    #[must_use]
    fn from_result(result: &DriveResult) -> Self {
        match result {
            DriveResult::DurableBoundary => Self::DurableBoundary,
            DriveResult::ExternalPending(_) => Self::Applied,
            DriveResult::Waiting => Self::Waiting,
            DriveResult::SourceRestored => Self::SourceRestored,
            DriveResult::Activated => Self::Activated,
            DriveResult::Aborted => Self::Aborted,
            DriveResult::Fatal => Self::Fatal,
        }
    }
}

/// Structured, process-local information for an embedding or scheduler.
/// `rejection` is intentionally an opaque diagnostic string: it is not a
/// persisted fact and is absent when a port does not expose a useful debug
/// representation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepDiagnostic {
    pub continuation: ContinuationId,
    pub stage: CoordinatorStage,
    pub operation: Option<OperationId>,
    pub capture_capability: CaptureDurability,
    pub recovery_cause: Option<RecoveryCause>,
    pub outcome: StepOutcome,
    pub rejection: Option<String>,
    pub retry_hint: Option<RetryHint>,
}

/// Result and diagnostics returned by the opt-in embedding API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoordinatorStepOutcome {
    pub result: DriveResult,
    pub diagnostic: StepDiagnostic,
}

/// Deterministic counts for coordinator control-path work.  They are
/// process-local measurements and reset only through `take_control_counts`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CoordinatorControlCounts {
    pub drive: u64,
    pub recover: u64,
    pub load: u64,
    pub cas: u64,
    pub reducer: u64,
    pub arm: u64,
    pub external_call: u64,
    pub query: u64,
    pub capture: u64,
    pub prepare: u64,
    pub commit: u64,
    pub abort: u64,
    pub activation: u64,
}

impl CoordinatorControlCounts {
    fn count_operation(&mut self, kind: ExternalOperationKind) {
        match kind {
            ExternalOperationKind::CaptureSource => self.capture += 1,
            ExternalOperationKind::PrepareBindings => self.prepare += 1,
            ExternalOperationKind::CommitAuthority => self.commit += 1,
            ExternalOperationKind::AbortPreparation => self.abort += 1,
            ExternalOperationKind::ActivateRuntime => self.activation += 1,
        }
    }
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
    control_counts: CoordinatorControlCounts,
    pending_diagnostic: Option<StepDiagnostic>,
    last_step_outcome: Option<CoordinatorStepOutcome>,
}

impl<S, A, R> Coordinator<S, A, R>
where
    S: RecordStore,
    A: AuthorityPort,
    R: RuntimePort,
    A::PrepareRejection: fmt::Debug,
    A::CommitRejection: fmt::Debug,
    A::AbortRejection: fmt::Debug,
    R::ActivationRejection: fmt::Debug,
    R::Error: fmt::Debug,
{
    pub fn new(store: S, authority: A, runtime: R) -> Self {
        Self {
            store,
            authority,
            runtime,
            tokens: BTreeMap::new(),
            called: BTreeMap::new(),
            control_counts: CoordinatorControlCounts::default(),
            pending_diagnostic: None,
            last_step_outcome: None,
        }
    }

    /// Return the current process-local control-path counters without
    /// resetting them.
    #[must_use]
    pub const fn read_control_counts(&self) -> CoordinatorControlCounts {
        self.control_counts
    }

    /// Return and reset process-local control-path counters.
    pub fn take_control_counts(&mut self) -> CoordinatorControlCounts {
        std::mem::take(&mut self.control_counts)
    }

    /// Discover all non-terminal continuations known by the backing store.
    /// The result is sorted by stores such as `InMemoryRecordStore`; the
    /// coordinator does not infer completion from missing records.
    pub fn discover_unfinished(&self) -> Result<Vec<ContinuationId>, CoordinatorError<S::Error>> {
        self.store.discover_unfinished().map_err(CoordinatorError::Store)
    }

    /// Read the most recently published process-local step outcome.
    #[must_use]
    pub fn read_step_outcome(&self) -> Option<&CoordinatorStepOutcome> {
        self.last_step_outcome.as_ref()
    }

    /// Take the most recently published process-local step outcome.
    pub fn take_step_outcome(&mut self) -> Option<CoordinatorStepOutcome> {
        self.last_step_outcome.take()
    }

    /// Read only the diagnostic portion of the most recent step outcome.
    #[must_use]
    pub fn read_step_diagnostic(&self) -> Option<&StepDiagnostic> {
        self.last_step_outcome.as_ref().map(|outcome| &outcome.diagnostic)
    }

    /// Take only the diagnostic portion of the most recent step outcome.
    pub fn take_step_diagnostic(&mut self) -> Option<StepDiagnostic> {
        self.last_step_outcome.take().map(|outcome| outcome.diagnostic)
    }

    /// Drive once and return the structured process-local outcome.
    pub fn drive_with_diagnostics(
        &mut self,
        id: &ContinuationId,
    ) -> Result<CoordinatorStepOutcome, CoordinatorError<S::Error>> {
        self.drive(id)?;
        Ok(self.last_step_outcome.clone().expect("drive publishes a step outcome"))
    }

    /// Recover once and return the structured process-local outcome.
    pub fn recover_with_diagnostics(
        &mut self,
        id: &ContinuationId,
    ) -> Result<CoordinatorStepOutcome, CoordinatorError<S::Error>> {
        self.recover(id)?;
        Ok(self.last_step_outcome.clone().expect("recover publishes a step outcome"))
    }

    /// Abort once and return the structured process-local outcome.
    pub fn abort_with_diagnostics(
        &mut self,
        id: &ContinuationId,
    ) -> Result<CoordinatorStepOutcome, CoordinatorError<S::Error>> {
        self.abort(id)?;
        Ok(self.last_step_outcome.clone().expect("abort publishes a step outcome"))
    }

    fn begin_step(&mut self) {
        self.pending_diagnostic = None;
    }

    fn finish_step(
        &mut self,
        id: &ContinuationId,
        result: &Result<DriveResult, CoordinatorError<S::Error>>,
    ) {
        let (drive_result, outcome) = match result {
            Ok(result) => (result.clone(), StepOutcome::from_result(result)),
            Err(_) => (DriveResult::Waiting, StepOutcome::Error),
        };
        let had_diagnostic = self.pending_diagnostic.is_some();
        let diagnostic = self.pending_diagnostic.take().unwrap_or_else(|| StepDiagnostic {
            continuation: *id,
            stage: CoordinatorStage::Recovery,
            operation: None,
            capture_capability: self.runtime.capture_durability(),
            recovery_cause: None,
            outcome: outcome.clone(),
            rejection: None,
            retry_hint: None,
        });
        let mut diagnostic = diagnostic;
        if !had_diagnostic {
            diagnostic.outcome = outcome;
        }
        self.last_step_outcome = Some(CoordinatorStepOutcome { result: drive_result, diagnostic });
    }

    fn note_rejected<T: fmt::Debug>(
        &mut self,
        record: &ContinuationRecord,
        kind: ExternalOperationKind,
        rejection: &T,
    ) {
        self.pending_diagnostic = Some(StepDiagnostic {
            continuation: record.intent.id,
            stage: stage_for_operation(kind),
            operation: Some(operation_for_pending(record, kind)),
            capture_capability: self.runtime.capture_durability(),
            recovery_cause: None,
            outcome: StepOutcome::Rejected,
            rejection: Some(format!("{rejection:?}")),
            retry_hint: Some(RetryHint::do_not_retry()),
        });
    }

    fn note_indeterminate(
        &mut self,
        record: &ContinuationRecord,
        kind: ExternalOperationKind,
        retry_backoff: BackoffClass,
    ) {
        self.pending_diagnostic = Some(StepDiagnostic {
            continuation: record.intent.id,
            stage: stage_for_operation(kind),
            operation: Some(operation_for_pending(record, kind)),
            capture_capability: self.runtime.capture_durability(),
            recovery_cause: None,
            outcome: StepOutcome::Indeterminate,
            rejection: None,
            retry_hint: Some(RetryHint::retry(retry_backoff)),
        });
    }

    fn note_runtime_rejected<T: fmt::Debug>(
        &mut self,
        record: &ContinuationRecord,
        stage: CoordinatorStage,
        operation: Option<OperationId>,
        rejection: &T,
    ) {
        self.pending_diagnostic = Some(StepDiagnostic {
            continuation: record.intent.id,
            stage,
            operation,
            capture_capability: self.runtime.capture_durability(),
            recovery_cause: None,
            outcome: StepOutcome::Rejected,
            rejection: Some(format!("{rejection:?}")),
            retry_hint: Some(RetryHint::do_not_retry()),
        });
    }

    fn note_runtime_indeterminate(
        &mut self,
        record: &ContinuationRecord,
        stage: CoordinatorStage,
        operation: Option<OperationId>,
        backoff: BackoffClass,
    ) {
        self.pending_diagnostic = Some(StepDiagnostic {
            continuation: record.intent.id,
            stage,
            operation,
            capture_capability: self.runtime.capture_durability(),
            recovery_cause: None,
            outcome: StepOutcome::Indeterminate,
            rejection: None,
            retry_hint: Some(RetryHint::retry(backoff)),
        });
    }

    fn count_external_call(&mut self, kind: ExternalOperationKind) {
        self.control_counts.external_call += 1;
        self.control_counts.count_operation(kind);
    }

    fn count_query(&mut self, kind: ExternalOperationKind) {
        self.control_counts.query += 1;
        self.control_counts.count_operation(kind);
    }

    pub fn begin(
        &mut self,
        intent: ContinuationIntent,
    ) -> Result<ContinuationId, CoordinatorError<S::Error>> {
        self.control_counts.reducer += 1;
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
        self.control_counts.drive += 1;
        self.begin_step();
        let result = self.drive_inner(id);
        self.finish_step(id, &result);
        result
    }

    fn drive_inner(
        &mut self,
        id: &ContinuationId,
    ) -> Result<DriveResult, CoordinatorError<S::Error>> {
        let record = self.load(id)?;
        self.retire_capture_if_durable(&record);
        if matches!(record.phase, ContinuationPhase::RecoveryRequired { .. }) {
            // A recovery requirement is a barrier. In particular, do not
            // reinterpret a failed capture/authority query as permission to
            // dispatch the last-known progress again. Only a decision which
            // explicitly names a destination/source action may cross it.
            let decision = decide_recovery(&record);
            if decision == RecoveryDecision::Fatal {
                return Ok(DriveResult::Fatal);
            }
            if record.pending.is_some() && recovery_allows_pending_query(&record) {
                return self.progress_pending(id, record);
            }
            return match decision {
                RecoveryDecision::Wait => Ok(DriveResult::Waiting),
                RecoveryDecision::RestoreSource => self.restore_source(id, record),
                RecoveryDecision::DestinationOnly => self.drive_destination_recovery(id, record),
                RecoveryDecision::Fatal => Ok(DriveResult::Fatal),
            };
        }
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

    fn drive_destination_recovery(
        &mut self,
        id: &ContinuationId,
        record: ContinuationRecord,
    ) -> Result<DriveResult, CoordinatorError<S::Error>> {
        // Destination-only recovery is deliberately narrow. It can resume
        // preparation/activation only after an authority commit is durable;
        // all other last-known phases remain behind the recovery barrier.
        if record.activation.is_some() || record.phase.last_known() == Progress::Activated {
            return Ok(DriveResult::Activated);
        }
        if record.authority_commit.is_some() {
            return self.activate(id, record);
        }
        Ok(DriveResult::Waiting)
    }

    pub fn recover(
        &mut self,
        id: &ContinuationId,
    ) -> Result<DriveResult, CoordinatorError<S::Error>> {
        self.control_counts.recover += 1;
        self.begin_step();
        let result = self.recover_inner(id);
        self.finish_step(id, &result);
        result
    }

    fn recover_inner(
        &mut self,
        id: &ContinuationId,
    ) -> Result<DriveResult, CoordinatorError<S::Error>> {
        let record = self.load(id)?;
        self.retire_capture_if_durable(&record);
        if matches!(record.phase, ContinuationPhase::RecoveryRequired { .. }) {
            let decision = decide_recovery(&record);
            if decision == RecoveryDecision::Fatal {
                return Ok(DriveResult::Fatal);
            }
            if recovery_allows_pending_query(&record)
                && let Some(pending) = &record.pending
            {
                // A fresh coordinator has no process-local call marker.
                // Recovery must query the exact durable operation before any
                // resend; only an authority `Absent` response clears it.
                self.called.insert((record.intent.id, pending.operation), true);
                return self.progress_pending(id, record);
            }
            return match decision {
                RecoveryDecision::Wait => Ok(DriveResult::Waiting),
                RecoveryDecision::RestoreSource => self.restore_source(id, record),
                RecoveryDecision::DestinationOnly => self.drive_destination_recovery(id, record),
                RecoveryDecision::Fatal => Ok(DriveResult::Fatal),
            };
        }
        if record.phase.last_known() == Progress::Aborted && record.snapshot.is_none() {
            return Ok(DriveResult::Aborted);
        }
        // Event::Activated is the durable terminal transition. Its receipt
        // was validated before it was persisted, so recovery must not consult
        // a process-local destination runtime again (or turn an authority
        // query outage into a new obligation).
        if record.phase.last_known() == Progress::Activated {
            return Ok(DriveResult::Activated);
        }
        if record.phase.last_known() == Progress::Aborted && record.source_restoration.is_some() {
            // SourceRestored is terminal once its exact receipt is durable.
            // A later process must not turn a missing process-local liveness
            // probe into a second restoration obligation.
            return Ok(DriveResult::SourceRestored);
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
        match decide_recovery(&record) {
            RecoveryDecision::RestoreSource => self.restore_source(id, record),
            RecoveryDecision::DestinationOnly => self.drive_destination_recovery(id, record),
            RecoveryDecision::Wait => Ok(DriveResult::Waiting),
            RecoveryDecision::Fatal => Ok(DriveResult::Fatal),
        }
    }

    pub fn abort(
        &mut self,
        id: &ContinuationId,
    ) -> Result<DriveResult, CoordinatorError<S::Error>> {
        self.begin_step();
        let result = self.abort_inner(id);
        self.finish_step(id, &result);
        result
    }

    fn abort_inner(
        &mut self,
        id: &ContinuationId,
    ) -> Result<DriveResult, CoordinatorError<S::Error>> {
        let record = self.load(id)?;
        self.retire_capture_if_durable(&record);
        if matches!(record.phase, ContinuationPhase::Progress(Progress::Aborted)) {
            // Abort is an idempotent observation once the durable terminal
            // event exists; it must not manufacture another receipt or CAS.
            return Ok(DriveResult::Aborted);
        }
        if matches!(record.phase, ContinuationPhase::RecoveryRequired { .. }) {
            return match decide_recovery(&record) {
                RecoveryDecision::Fatal | RecoveryDecision::DestinationOnly => {
                    Ok(DriveResult::Fatal)
                }
                RecoveryDecision::RestoreSource | RecoveryDecision::Wait => {
                    Ok(DriveResult::Waiting)
                }
            };
        }
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

    fn load(
        &mut self,
        id: &ContinuationId,
    ) -> Result<ContinuationRecord, CoordinatorError<S::Error>> {
        self.control_counts.load += 1;
        self.store.load(id).map_err(CoordinatorError::Store)?.ok_or(CoordinatorError::NotFound)
    }

    fn retire_capture_if_durable(&mut self, record: &ContinuationRecord) {
        if let Some(receipt) = record.capture_receipt.as_ref() {
            // The receipt was read from durable storage, so cleanup is now
            // safe. A failed cleanup is intentionally ignored; the next
            // drive/restart repeats this idempotent best-effort operation.
            let _ = self.runtime.retire_capture(receipt);
        }
    }

    fn operation_id(record: &ContinuationRecord, kind: ExternalOperationKind) -> OperationId {
        let mut material = Vec::with_capacity(25);
        material.extend_from_slice(&record.intent.id.0);
        material.extend_from_slice(&record.revision.to_be_bytes());
        material.push(match kind {
            ExternalOperationKind::CaptureSource => 0,
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
        self.control_counts.cas += 1;
        self.store.cas(&current.intent.id, &current, next, lineage).map_err(CoordinatorError::Store)
    }

    fn apply_event(
        &mut self,
        current: ContinuationRecord,
        event: &Event,
        lineage: Option<LineageUpdate>,
    ) -> Result<ContinuationRecord, CoordinatorError<S::Error>> {
        self.control_counts.reducer += 1;
        let next = apply(Some(current.clone()), event).map_err(CoordinatorError::Core)?;
        self.cas(current, next, lineage)
    }

    fn capture(
        &mut self,
        id: &ContinuationId,
        mut record: ContinuationRecord,
    ) -> Result<DriveResult, CoordinatorError<S::Error>> {
        if record.pending.is_none() {
            self.arm_authority(id, record, ExternalOperationKind::CaptureSource)?;
            record = self.load(id)?;
        }
        if let Some(pending) = &record.pending {
            self.called.insert((record.intent.id, pending.operation), true);
        }
        self.call_capture(id, record)
    }

    fn capture_request(
        record: &ContinuationRecord,
        operation: OperationId,
    ) -> Result<CaptureRequest, CoordinatorError<S::Error>> {
        let successor_generation = record
            .intent
            .lineage_parent
            .generation
            .checked_add(1)
            .ok_or(CoordinatorError::Core(ContractError::InvalidLineageAdvance))?;
        Ok(CaptureRequest {
            operation,
            continuation: record.intent.id,
            scope: record.intent.scope,
            source: record.intent.source.clone(),
            profile: record.intent.profile.clone(),
            lineage: visa_core::LineageAdvance {
                parent: record.intent.lineage_parent.clone(),
                successor_generation,
            },
        })
    }

    fn query_capture_request(
        record: &ContinuationRecord,
        operation: OperationId,
    ) -> Result<QueryCaptureRequest, CoordinatorError<S::Error>> {
        let request = Self::capture_request(record, operation)?;
        Ok(QueryCaptureRequest {
            operation: request.operation,
            continuation: request.continuation,
            scope: request.scope,
            source: request.source,
            profile: request.profile,
            lineage: request.lineage,
        })
    }

    fn call_capture(
        &mut self,
        id: &ContinuationId,
        record: ContinuationRecord,
    ) -> Result<DriveResult, CoordinatorError<S::Error>> {
        let Some(pending) = record.pending.clone() else { return Ok(DriveResult::Waiting) };
        if pending.kind != ExternalOperationKind::CaptureSource {
            return Ok(DriveResult::Waiting);
        }
        let request = Self::capture_request(&record, pending.operation)?;
        self.count_external_call(ExternalOperationKind::CaptureSource);
        match self.runtime.capture(request) {
            CallOutcome::Applied(captured) => {
                let CapturedRuntime { snapshot, safe_point, receipt, frozen } = captured;
                let token = self.tokens.entry(*id).or_default();
                token.frozen = Some(frozen);
                if self.runtime.capture_durability() == CaptureDurability::AuthorityDurableQueryable
                    && receipt.is_none()
                {
                    return self.mark_recovery(
                        id,
                        record,
                        RecoveryCause::CaptureDurabilityUnavailable {
                            operation: pending.operation,
                        },
                    );
                }
                self.record_captured(id, record, snapshot, safe_point, receipt)
            }
            CallOutcome::Rejected(error) => {
                self.note_rejected(&record, ExternalOperationKind::CaptureSource, &error);
                self.called.remove(&(record.intent.id, pending.operation));
                let record =
                    self.apply_event(record, &Event::ExternalRejected(pending.clone()), None)?;
                self.mark_recovery(
                    id,
                    record,
                    RecoveryCause::CaptureRejected { operation: pending.operation },
                )
            }
            CallOutcome::Indeterminate => {
                self.note_indeterminate(
                    &record,
                    ExternalOperationKind::CaptureSource,
                    BackoffClass::Medium,
                );
                let cause = if self.runtime.capture_durability()
                    == CaptureDurability::AuthorityDurableQueryable
                {
                    RecoveryCause::CaptureOutcomeUnknown { operation: pending.operation }
                } else {
                    RecoveryCause::ProcessLocalCaptureDualCrashRisk { operation: pending.operation }
                };
                self.mark_recovery(id, record, cause)
            }
        }
    }

    fn record_captured(
        &mut self,
        id: &ContinuationId,
        record: ContinuationRecord,
        snapshot: SnapshotEnvelope,
        safe_point: SafePointReceipt,
        receipt: Option<CaptureReceipt>,
    ) -> Result<DriveResult, CoordinatorError<S::Error>> {
        let durable_receipt = receipt.clone();
        let event = match receipt {
            Some(receipt) => Event::CaptureRecorded {
                snapshot: snapshot.clone(),
                safe_point: safe_point.clone(),
                receipt,
            },
            None => Event::SnapshotRecorded {
                snapshot: snapshot.clone(),
                safe_point: safe_point.clone(),
            },
        };
        if let Err(error) = self.apply_event(record.clone(), &event, None) {
            // A lost store acknowledgement is not permission to thaw. A
            // durable capture remains queryable; a process-local capture can
            // only be rolled back while this process still owns its token.
            let latest = self.load(id)?;
            let exact_capture_persisted = latest.snapshot.as_ref() == Some(&snapshot)
                && latest.capture_receipt.as_ref() == durable_receipt.as_ref();
            if exact_capture_persisted {
                if let Some(receipt) = durable_receipt.as_ref() {
                    // `latest` is the proof that the exact receipt became
                    // durable despite the lost CAS acknowledgement.
                    let _ = self.runtime.retire_capture(receipt);
                }
                if let Some(pending) = record.pending.as_ref() {
                    self.called.remove(&(record.intent.id, pending.operation));
                }
                return Ok(DriveResult::DurableBoundary);
            }
            if self.runtime.capture_durability() == CaptureDurability::AuthorityDurableQueryable {
                let operation = record
                    .pending
                    .as_ref()
                    .map_or(OperationId::from_u128(0), |pending| pending.operation);
                return match self.mark_recovery(
                    id,
                    latest,
                    RecoveryCause::CaptureOutcomeUnknown { operation },
                ) {
                    Ok(result) => Ok(result),
                    Err(_) => Err(error),
                };
            }
            if latest.snapshot.is_some() || latest.phase.last_known() != Progress::Preparing {
                return self.mark_recovery(id, latest, RecoveryCause::StoreConflict);
            }
            let rollback = RestoreSourceRequest {
                continuation: record.intent.id,
                snapshot,
                source: record.intent.source.clone(),
            };
            self.control_counts.external_call += 1;
            self.control_counts.capture += 1;
            match self.runtime.restore_source(rollback) {
                CallOutcome::Applied(_) => {
                    self.tokens.entry(*id).or_default().frozen = None;
                    let latest = self.load(id)?;
                    if let Some(pending) = latest.pending.clone()
                        && pending.kind == ExternalOperationKind::CaptureSource
                    {
                        let _ = self.apply_event(latest, &Event::ExternalRejected(pending), None);
                    }
                    Err(error)
                }
                CallOutcome::Rejected(error) => {
                    self.note_runtime_rejected(
                        &record,
                        CoordinatorStage::SourceRestore,
                        record.pending.as_ref().map(|pending| pending.operation),
                        &error,
                    );
                    self.tokens.entry(*id).or_default().frozen = None;
                    let latest = self.load(id)?;
                    self.mark_recovery(id, latest, RecoveryCause::SourceRestorationUnknown)
                }
                CallOutcome::Indeterminate => {
                    self.note_runtime_indeterminate(
                        &record,
                        CoordinatorStage::SourceRestore,
                        record.pending.as_ref().map(|pending| pending.operation),
                        BackoffClass::Long,
                    );
                    self.tokens.entry(*id).or_default().frozen = None;
                    let latest = self.load(id)?;
                    self.mark_recovery(id, latest, RecoveryCause::SourceRestorationUnknown)
                }
            }
        } else {
            if let Some(receipt) = durable_receipt.as_ref() {
                let _ = self.runtime.retire_capture(receipt);
            }
            if let Some(pending) = record.pending.as_ref() {
                self.called.remove(&(record.intent.id, pending.operation));
            }
            Ok(DriveResult::DurableBoundary)
        }
    }

    fn arm_authority(
        &mut self,
        id: &ContinuationId,
        record: ContinuationRecord,
        kind: ExternalOperationKind,
    ) -> Result<DriveResult, CoordinatorError<S::Error>> {
        self.control_counts.arm += 1;
        let operation = Self::operation_id(&record, kind);
        let digest = if kind == ExternalOperationKind::CaptureSource {
            let request = Self::capture_request(&record, operation)?;
            visa_core::canonical_digest(&(
                request.operation,
                request.continuation,
                request.scope,
                &request.source,
                &request.profile,
                &request.lineage,
            ))
            .map_err(CoordinatorError::Core)?
        } else {
            record.snapshot.as_ref().map_or(Digest::ZERO, |s| s.body_digest)
        };
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
            let preparation_operation =
                Self::operation_id(&record, ExternalOperationKind::CommitAuthority);
            self.control_counts.external_call += 1;
            self.control_counts.prepare += 1;
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
                CallOutcome::Rejected(error) => {
                    self.note_runtime_rejected(&record, CoordinatorStage::Prepare, None, &error);
                    return Ok(DriveResult::Waiting);
                }
                CallOutcome::Indeterminate => {
                    self.note_runtime_indeterminate(
                        &record,
                        CoordinatorStage::Prepare,
                        Some(preparation_operation),
                        BackoffClass::Medium,
                    );
                    return self.mark_recovery(
                        id,
                        record,
                        RecoveryCause::RuntimePreparationUnknown {
                            operation: preparation_operation,
                        },
                    );
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
        let activation_operation =
            Self::operation_id(&record, ExternalOperationKind::ActivateRuntime);
        if self.tokens.entry(*id).or_default().restored.is_none()
            && self.tokens.entry(*id).or_default().prepared.is_none()
        {
            self.control_counts.external_call += 1;
            self.control_counts.prepare += 1;
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
                CallOutcome::Rejected(error) => {
                    self.note_runtime_rejected(&record, CoordinatorStage::Prepare, None, &error);
                    return Ok(DriveResult::Waiting);
                }
                CallOutcome::Indeterminate => {
                    self.note_runtime_indeterminate(
                        &record,
                        CoordinatorStage::Prepare,
                        Some(activation_operation),
                        BackoffClass::Medium,
                    );
                    return self.mark_recovery(
                        id,
                        record,
                        RecoveryCause::RuntimePreparationUnknown {
                            operation: activation_operation,
                        },
                    );
                }
            }
        }
        if self.tokens.entry(*id).or_default().restored.is_none() {
            let Some(prepared) = self.tokens.entry(*id).or_default().prepared.take() else {
                return Ok(DriveResult::Waiting);
            };
            self.control_counts.external_call += 1;
            self.control_counts.activation += 1;
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
                CallOutcome::Rejected(error) => {
                    self.note_runtime_rejected(
                        &record,
                        CoordinatorStage::Activation,
                        Some(activation_operation),
                        &error,
                    );
                    return Ok(DriveResult::Waiting);
                }
                CallOutcome::Indeterminate => {
                    self.note_runtime_indeterminate(
                        &record,
                        CoordinatorStage::Activation,
                        Some(activation_operation),
                        BackoffClass::Medium,
                    );
                    return self.mark_recovery(
                        id,
                        record,
                        RecoveryCause::RuntimeRestoreUnknown { operation: activation_operation },
                    );
                }
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
            // Activation has a runtime preparation/restore sequence before
            // the actual activate call. Its marker must not suppress that
            // call after either prerequisite returns indeterminate.
            if pending.kind != ExternalOperationKind::ActivateRuntime {
                self.called.insert(key, true);
            }
            return match pending.kind {
                ExternalOperationKind::CaptureSource => self.call_capture(id, record),
                ExternalOperationKind::PrepareBindings => {
                    let Some(binding) = self.binding(&record) else {
                        return Ok(DriveResult::Waiting);
                    };
                    self.count_external_call(ExternalOperationKind::PrepareBindings);
                    match self
                        .authority
                        .prepare(PrepareRequest { operation: pending.operation, binding })
                    {
                        CallOutcome::Rejected(error) => {
                            self.note_rejected(
                                &record,
                                ExternalOperationKind::PrepareBindings,
                                &error,
                            );
                            self.called.remove(&(record.intent.id, pending.operation));
                            let record = self.apply_event(
                                record,
                                &Event::ExternalRejected(pending.clone()),
                                None,
                            )?;
                            self.abort_record(record, pending.operation, None)
                        }
                        CallOutcome::Applied(_) => {
                            Ok(DriveResult::ExternalPending(pending.operation))
                        }
                        CallOutcome::Indeterminate => {
                            self.note_indeterminate(
                                &record,
                                ExternalOperationKind::PrepareBindings,
                                BackoffClass::Medium,
                            );
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
                    self.count_external_call(ExternalOperationKind::CommitAuthority);
                    match self.authority.commit(CommitRequest {
                        operation: pending.operation,
                        binding,
                        preparation,
                    }) {
                        CallOutcome::Rejected(error) => {
                            self.note_rejected(
                                &record,
                                ExternalOperationKind::CommitAuthority,
                                &error,
                            );
                            self.called.remove(&(record.intent.id, pending.operation));
                            let record =
                                self.apply_event(record, &Event::ExternalRejected(pending), None)?;
                            let id = record.intent.id;
                            self.arm_authority(&id, record, ExternalOperationKind::AbortPreparation)
                        }
                        CallOutcome::Applied(_) => {
                            Ok(DriveResult::ExternalPending(pending.operation))
                        }
                        CallOutcome::Indeterminate => {
                            self.note_indeterminate(
                                &record,
                                ExternalOperationKind::CommitAuthority,
                                BackoffClass::Medium,
                            );
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
                    self.count_external_call(ExternalOperationKind::AbortPreparation);
                    match self.authority.abort_preparation(AbortPreparationRequest {
                        operation: pending.operation,
                        binding,
                        preparation,
                    }) {
                        CallOutcome::Rejected(error) => {
                            self.note_rejected(
                                &record,
                                ExternalOperationKind::AbortPreparation,
                                &error,
                            );
                            self.mark_recovery(id, record, RecoveryCause::ReceiptConflict)
                        }
                        CallOutcome::Applied(_) => {
                            Ok(DriveResult::ExternalPending(pending.operation))
                        }
                        CallOutcome::Indeterminate => {
                            self.note_indeterminate(
                                &record,
                                ExternalOperationKind::AbortPreparation,
                                BackoffClass::Long,
                            );
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
            ExternalOperationKind::CaptureSource => self.query_capture(id, record, pending),
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
                self.control_counts.external_call += 1;
                self.control_counts.prepare += 1;
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
                    CallOutcome::Rejected(error) => {
                        self.note_runtime_rejected(
                            &record,
                            CoordinatorStage::Prepare,
                            Some(operation),
                            &error,
                        );
                        return Ok(DriveResult::Waiting);
                    }
                    CallOutcome::Indeterminate => {
                        self.note_runtime_indeterminate(
                            &record,
                            CoordinatorStage::Prepare,
                            Some(operation),
                            BackoffClass::Medium,
                        );
                        return self.mark_recovery(
                            id,
                            record,
                            RecoveryCause::RuntimePreparationUnknown { operation },
                        );
                    }
                }
            }
            let Some(prepared) = self.tokens.entry(*id).or_default().prepared.take() else {
                return Ok(DriveResult::Waiting);
            };
            self.control_counts.external_call += 1;
            self.control_counts.activation += 1;
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
                CallOutcome::Rejected(error) => {
                    self.note_runtime_rejected(
                        &record,
                        CoordinatorStage::Activation,
                        Some(operation),
                        &error,
                    );
                    return Ok(DriveResult::Waiting);
                }
                CallOutcome::Indeterminate => {
                    self.note_runtime_indeterminate(
                        &record,
                        CoordinatorStage::Activation,
                        Some(operation),
                        BackoffClass::Medium,
                    );
                    return self.mark_recovery(
                        id,
                        record,
                        RecoveryCause::RuntimeRestoreUnknown { operation },
                    );
                }
            }
        }
        let Some(restored) = self.tokens.entry(*id).or_default().restored.take() else {
            return Ok(DriveResult::Waiting);
        };
        // The marker is intentionally set at the last possible point. A
        // failed/indeterminate prepare or restore above has not called
        // activate, so the next drive may still perform this exact call.
        self.called.insert((record.intent.id, operation), true);
        self.count_external_call(ExternalOperationKind::ActivateRuntime);
        match self.runtime.activate(ActivateRequest {
            continuation: record.intent.id,
            operation,
            snapshot: snapshot.body.snapshot,
            destination: record.intent.destination.clone(),
            preparation,
            commit,
            restored,
        }) {
            CallOutcome::Rejected(error) => {
                self.note_runtime_rejected(
                    &record,
                    CoordinatorStage::Activation,
                    Some(operation),
                    &error,
                );
                self.mark_recovery(
                    id,
                    record,
                    RecoveryCause::RuntimeActivationUnknown { operation },
                )
            }
            CallOutcome::Applied(_) => Ok(DriveResult::ExternalPending(operation)),
            CallOutcome::Indeterminate => {
                self.note_runtime_indeterminate(
                    &record,
                    CoordinatorStage::Activation,
                    Some(operation),
                    BackoffClass::Long,
                );
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
        self.count_query(ExternalOperationKind::PrepareBindings);
        match self
            .authority
            .query_prepare(QueryPrepareRequest { operation: pending.operation, binding })
        {
            QueryOutcome::Applied(receipt) => {
                let continuation = record.intent.id;
                let result =
                    self.apply_event(record, &Event::BindingPreparationRecorded(receipt), None);
                if result.is_ok() {
                    self.called.remove(&(continuation, pending.operation));
                }
                result?;
                Ok(DriveResult::DurableBoundary)
            }
            QueryOutcome::Rejected(error) => {
                self.note_rejected(&record, ExternalOperationKind::PrepareBindings, &error);
                let record =
                    self.apply_event(record, &Event::ExternalRejected(pending.clone()), None)?;
                self.abort_record(record, pending.operation, None)
            }
            QueryOutcome::Absent => {
                self.called.remove(&(record.intent.id, pending.operation));
                Ok(DriveResult::Waiting)
            }
            QueryOutcome::Indeterminate => {
                self.note_indeterminate(
                    &record,
                    ExternalOperationKind::PrepareBindings,
                    BackoffClass::Long,
                );
                self.mark_external_unknown(record, pending.operation)
            }
        }
    }

    fn query_capture(
        &mut self,
        id: &ContinuationId,
        record: ContinuationRecord,
        pending: PendingExternal,
    ) -> Result<DriveResult, CoordinatorError<S::Error>> {
        let request = Self::query_capture_request(&record, pending.operation)?;
        self.count_query(ExternalOperationKind::CaptureSource);
        match self.runtime.query_capture(request) {
            QueryOutcome::Applied(captured) => {
                let continuation = record.intent.id;
                let receipt = captured.receipt.clone();
                let event = Event::CaptureRecorded {
                    snapshot: captured.snapshot,
                    safe_point: captured.safe_point,
                    receipt: captured.receipt,
                };
                match self.apply_event(record, &event, None) {
                    Ok(_) => {
                        let _ = self.runtime.retire_capture(&receipt);
                        self.called.remove(&(continuation, pending.operation));
                        Ok(DriveResult::DurableBoundary)
                    }
                    Err(CoordinatorError::Core(
                        ContractError::CaptureMismatch | ContractError::ReceiptDigestMismatch,
                    )) => {
                        let latest = self.load(id)?;
                        self.mark_recovery(
                            id,
                            latest,
                            RecoveryCause::CaptureReceiptMismatch { operation: pending.operation },
                        )
                    }
                    Err(error) => Err(error),
                }
            }
            QueryOutcome::Rejected(error) => {
                self.note_rejected(&record, ExternalOperationKind::CaptureSource, &error);
                self.mark_recovery(
                    id,
                    record,
                    RecoveryCause::CaptureReceiptMismatch { operation: pending.operation },
                )
            }
            QueryOutcome::Absent => {
                self.called.remove(&(record.intent.id, pending.operation));
                Ok(DriveResult::Waiting)
            }
            QueryOutcome::Indeterminate => {
                self.note_indeterminate(
                    &record,
                    ExternalOperationKind::CaptureSource,
                    BackoffClass::Long,
                );
                let cause = if self.runtime.capture_durability()
                    == CaptureDurability::AuthorityDurableQueryable
                {
                    RecoveryCause::CaptureOutcomeUnknown { operation: pending.operation }
                } else {
                    RecoveryCause::ProcessLocalCaptureDualCrashRisk { operation: pending.operation }
                };
                self.mark_recovery(id, record, cause)
            }
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
        self.count_query(ExternalOperationKind::CommitAuthority);
        match self.authority.query_commit(QueryCommitRequest {
            operation: pending.operation,
            binding,
            preparation,
        }) {
            QueryOutcome::Applied(receipt) => {
                let continuation = record.intent.id;
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
                let result =
                    self.apply_event(record, &Event::AuthorityCommitted(receipt), Some(lineage));
                if result.is_ok() {
                    self.called.remove(&(continuation, pending.operation));
                }
                result?;
                Ok(DriveResult::DurableBoundary)
            }
            QueryOutcome::Rejected(error) => {
                self.note_rejected(&record, ExternalOperationKind::CommitAuthority, &error);
                let record = self.apply_event(record, &Event::ExternalRejected(pending), None)?;
                let id = record.intent.id;
                self.arm_authority(&id, record, ExternalOperationKind::AbortPreparation)
            }
            QueryOutcome::Absent => {
                self.called.remove(&(record.intent.id, pending.operation));
                Ok(DriveResult::Waiting)
            }
            QueryOutcome::Indeterminate => {
                self.note_indeterminate(
                    &record,
                    ExternalOperationKind::CommitAuthority,
                    BackoffClass::Long,
                );
                self.mark_external_unknown(record, pending.operation)
            }
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
        self.count_query(ExternalOperationKind::AbortPreparation);
        match self.authority.query_abort(QueryAbortRequest {
            operation: pending.operation,
            binding,
            preparation,
        }) {
            QueryOutcome::Applied(receipt) => {
                let continuation = record.intent.id;
                let result = self.abort_record(record, pending.operation, Some(receipt));
                if result.is_ok() {
                    self.called.remove(&(continuation, pending.operation));
                }
                result
            }
            QueryOutcome::Rejected(error) => {
                self.note_rejected(&record, ExternalOperationKind::AbortPreparation, &error);
                self.mark_recovery(_id, record, RecoveryCause::ReceiptConflict)
            }
            QueryOutcome::Absent => {
                self.called.remove(&(record.intent.id, pending.operation));
                Ok(DriveResult::Waiting)
            }
            QueryOutcome::Indeterminate => {
                self.note_indeterminate(
                    &record,
                    ExternalOperationKind::AbortPreparation,
                    BackoffClass::Long,
                );
                self.mark_external_unknown(record, pending.operation)
            }
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
        let binding = record
            .binding_preparation
            .as_ref()
            .and_then(|preparation| preparation.grants.first())
            .map(|grant| grant.binding.clone());
        self.count_query(ExternalOperationKind::ActivateRuntime);
        match self.runtime.query_activation(QueryActivationRequest {
            continuation: record.intent.id,
            snapshot: snapshot.body.snapshot,
            destination: record.intent.destination.clone(),
            operation: pending.operation,
            binding,
            commit: commit.clone(),
        }) {
            QueryOutcome::Applied(receipt) => {
                let continuation = record.intent.id;
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
                let result = self.apply_event(record, &Event::Activated(receipt), Some(lineage));
                if result.is_ok() {
                    self.called.remove(&(continuation, pending.operation));
                }
                result?;
                Ok(DriveResult::Activated)
            }
            QueryOutcome::Absent => {
                self.called.remove(&(record.intent.id, pending.operation));
                Ok(DriveResult::Waiting)
            }
            QueryOutcome::Rejected(error) => {
                self.note_runtime_rejected(
                    &record,
                    CoordinatorStage::Activation,
                    Some(pending.operation),
                    &error,
                );
                self.mark_recovery(
                    _id,
                    record,
                    RecoveryCause::RuntimeActivationUnknown { operation: pending.operation },
                )
            }
            QueryOutcome::Indeterminate => {
                self.note_runtime_indeterminate(
                    &record,
                    CoordinatorStage::Activation,
                    Some(pending.operation),
                    BackoffClass::Long,
                );
                self.mark_recovery(
                    _id,
                    record,
                    RecoveryCause::RuntimeActivationUnknown { operation: pending.operation },
                )
            }
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
        let authority = record.intent.destination.authority;
        self.mark_recovery(
            &id,
            record,
            RecoveryCause::ExternalOutcomeUnknown {
                // Prepare/commit/abort outcomes belong to the destination
                // authority represented by the durable intent coordinate.
                // Never substitute AuthorityId::default(): it would make an
                // unknown result unreconcilable by the actual authority.
                authority,
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
        let retry_hint = match &cause {
            RecoveryCause::StoreConflict
            | RecoveryCause::ReceiptConflict
            | RecoveryCause::CaptureReceiptMismatch { .. }
            | RecoveryCause::SourceRestorationUnknown
            | RecoveryCause::RuntimePreparationUnknown { .. }
            | RecoveryCause::RuntimeRestoreUnknown { .. } => RetryHint::do_not_retry(),
            _ => RetryHint::retry(BackoffClass::Long),
        };
        if let Some(diagnostic) = self.pending_diagnostic.as_mut() {
            diagnostic.recovery_cause = Some(cause.clone());
            if matches!(
                cause,
                RecoveryCause::SourceRestorationUnknown
                    | RecoveryCause::RuntimePreparationUnknown { .. }
                    | RecoveryCause::RuntimeRestoreUnknown { .. }
            ) || diagnostic.retry_hint.is_none()
            {
                diagnostic.retry_hint = Some(retry_hint);
            }
        } else {
            let (stage, operation) =
                record.pending.as_ref().map_or((CoordinatorStage::Recovery, None), |pending| {
                    (stage_for_operation(pending.kind), Some(pending.operation))
                });
            self.pending_diagnostic = Some(StepDiagnostic {
                continuation: *id,
                stage,
                operation,
                capture_capability: self.runtime.capture_durability(),
                recovery_cause: Some(cause.clone()),
                outcome: StepOutcome::Waiting,
                rejection: None,
                retry_hint: Some(retry_hint),
            });
        }
        if matches!(
            &record.phase,
            ContinuationPhase::RecoveryRequired { cause: current, .. } if current == &cause
        ) {
            return Ok(DriveResult::Waiting);
        }
        self.apply_event(record, &Event::RecoveryRequired(cause), None)?;
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
        self.control_counts.external_call += 1;
        self.control_counts.capture += 1;
        match self.runtime.restore_source(RestoreSourceRequest {
            continuation: record.intent.id,
            snapshot,
            source: record.intent.source.clone(),
        }) {
            CallOutcome::Applied(receipt) => {
                let event = Event::SourceRestored(receipt.clone());
                match self.apply_event(record, &event, None) {
                    Ok(_) => Ok(DriveResult::SourceRestored),
                    Err(error) => {
                        // Reconcile a lost store acknowledgement before making
                        // any recovery decision. If the receipt is not already
                        // durable, preserve the aborted source cut as an
                        // explicit non-retryable recovery requirement; blindly
                        // replaying the snapshot could overwrite resumed work.
                        let latest = self.load(id)?;
                        if latest.source_restoration.as_ref() == Some(&receipt) {
                            return Ok(DriveResult::SourceRestored);
                        }
                        match self.mark_recovery(
                            id,
                            latest,
                            RecoveryCause::SourceRestorationUnknown,
                        ) {
                            Ok(result) => Ok(result),
                            Err(_) => Err(error),
                        }
                    }
                }
            }
            CallOutcome::Rejected(error) => {
                self.note_runtime_rejected(&record, CoordinatorStage::SourceRestore, None, &error);
                self.mark_recovery(id, record, RecoveryCause::SourceRestorationUnknown)
            }
            CallOutcome::Indeterminate => {
                self.note_runtime_indeterminate(
                    &record,
                    CoordinatorStage::SourceRestore,
                    None,
                    BackoffClass::Long,
                );
                self.mark_recovery(id, record, RecoveryCause::SourceRestorationUnknown)
            }
        }
    }
}

// Keep the dependency explicit in metadata even when this crate is consumed
// through a facade.
#[allow(unused_imports)]
use visa_core as _visa_core;
