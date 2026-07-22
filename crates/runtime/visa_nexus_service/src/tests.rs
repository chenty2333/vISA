use std::{
    cell::{Cell, RefCell},
    os::unix::fs::PermissionsExt,
};

use tempfile::TempDir;
use visa_local_rpc::{
    common::{
        AgentBinding, AgentRole, BootId, CanonicalPayload, CohortId, IdempotencyId,
        LogicalIncarnation, OperationId, PRODUCT_VERSION, PayloadSchema, ProcessNonce,
        RegistryInstanceId, RequestId, RuntimeSessionId, ServiceIncarnation, Sha256Digest,
    },
    nexus_adapter as wire,
};

use crate::{
    AdapterBinding, AdapterIdentity, NativeCommitInput, NativeCommitReceipt, NativeCommitRejection,
    NativeCommitResult, NativePeer, NativePeerError, NexusAdapterStore, NexusServiceError,
    PreparedNativeCommit, StoreBootstrap, StoreLimits,
};

struct FakePeer {
    registry: RegistryInstanceId,
    fail_once: Cell<bool>,
    prepare_calls: Cell<u32>,
    commit_calls: Cell<u32>,
    receipt_sequence: Cell<u64>,
    rejection: Option<wire::Rejection>,
    receipt_registry_override: Option<RegistryInstanceId>,
    receipt_request_digest_override: Option<Sha256Digest>,
    provider_revision_override: Option<u64>,
    receipt_sequence_override: Option<u64>,
    last_prepared: RefCell<Option<PreparedNativeCommit>>,
}

impl FakePeer {
    fn new(registry: RegistryInstanceId) -> Self {
        Self {
            registry,
            fail_once: Cell::new(false),
            prepare_calls: Cell::new(0),
            commit_calls: Cell::new(0),
            receipt_sequence: Cell::new(0),
            rejection: None,
            receipt_registry_override: None,
            receipt_request_digest_override: None,
            provider_revision_override: None,
            receipt_sequence_override: None,
            last_prepared: RefCell::new(None),
        }
    }

    fn unavailable_once(self) -> Self {
        self.fail_once.set(true);
        self
    }

    fn rejecting(mut self, rejection: wire::Rejection) -> Self {
        self.rejection = Some(rejection);
        self
    }

    fn with_registry_override(mut self, registry: RegistryInstanceId) -> Self {
        self.receipt_registry_override = Some(registry);
        self
    }

    fn with_request_digest_override(mut self, digest: Sha256Digest) -> Self {
        self.receipt_request_digest_override = Some(digest);
        self
    }

    fn with_provider_revision(mut self, revision: u64) -> Self {
        self.provider_revision_override = Some(revision);
        self
    }

    fn with_receipt_sequence(mut self, sequence: u64) -> Self {
        self.receipt_sequence_override = Some(sequence);
        self
    }
}

impl NativePeer for FakePeer {
    fn prepare_commit(
        &self,
        input: &NativeCommitInput,
    ) -> Result<PreparedNativeCommit, NativePeerError> {
        self.prepare_calls.set(self.prepare_calls.get() + 1);
        let input_bytes = postcard::to_allocvec(input).map_err(|_| NativePeerError::Integrity)?;
        let mut request_bytes = b"native-v1/commit/".to_vec();
        request_bytes.extend_from_slice(&input_bytes);
        let prepared = PreparedNativeCommit {
            native_request_id: input.native_request_id,
            input_digest: Sha256Digest::of(&input_bytes),
            request_digest: Sha256Digest::of(&request_bytes),
            request_bytes,
        };
        *self.last_prepared.borrow_mut() = Some(prepared.clone());
        Ok(prepared)
    }

    fn commit(
        &mut self,
        prepared: &PreparedNativeCommit,
    ) -> Result<NativeCommitResult, NativePeerError> {
        self.commit_calls.set(self.commit_calls.get() + 1);
        *self.last_prepared.borrow_mut() = Some(prepared.clone());
        if self.fail_once.replace(false) {
            return Err(NativePeerError::Unavailable);
        }
        if let Some(rejection) = self.rejection.clone() {
            return Ok(NativeCommitResult::Rejected(NativeCommitRejection {
                native_request_id: prepared.native_request_id,
                request_digest: prepared.request_digest,
                rejection,
            }));
        }
        let receipt_sequence =
            self.receipt_sequence_override.unwrap_or_else(|| self.receipt_sequence.get() + 1);
        self.receipt_sequence.set(receipt_sequence);
        Ok(NativeCommitResult::Committed(NativeCommitReceipt {
            native_request_id: prepared.native_request_id,
            registry_instance: self.receipt_registry_override.unwrap_or(self.registry),
            provider_revision: self.provider_revision_override.unwrap_or(3),
            request_digest: self.receipt_request_digest_override.unwrap_or(prepared.request_digest),
            receipt_digest: Sha256Digest::of(
                &[prepared.request_digest.0.as_slice(), b"receipt"].concat(),
            ),
            receipt_sequence,
        }))
    }
}

fn fixture() -> (TempDir, StoreBootstrap, AgentBinding, Vec<u8>) {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let binding = AdapterBinding {
        cohort: CohortId::from_u128(1),
        boot: BootId::from_u128(2),
        runtime_session: RuntimeSessionId::from_u128(3),
    };
    let identity = AdapterIdentity {
        service_incarnation: ServiceIncarnation::from_u128(4),
        registry_instance: RegistryInstanceId::from_u128(5),
        provider_identity_digest: Sha256Digest::of(b"fake-provider"),
    };
    let caller = AgentBinding {
        product_version: PRODUCT_VERSION,
        cohort: binding.cohort,
        boot: binding.boot,
        runtime_session: binding.runtime_session,
        role: AgentRole::Source,
        logical_incarnation: LogicalIncarnation::from_u128(6),
        process_nonce: ProcessNonce::from_u128(7),
        process_generation: 1,
    };
    let effect = wire::EffectIdentity {
        operation: OperationId::from_u128(8),
        idempotency: IdempotencyId::from_u128(9),
    };
    let request = wire::Request::new(
        RequestId::from_u128(10),
        caller,
        wire::Operation::CommitAndAuthorizeDispatch(wire::DispatchCommitRequest {
            effect,
            expected_provider_revision: 2,
            expected_projection_digest: Sha256Digest::of(b"projection"),
            invocation: CanonicalPayload::new(
                PayloadSchema { id: wire::COMMIT_SCHEMA, major: 1, minor: 0 },
                b"invoke".to_vec(),
            )
            .unwrap(),
        }),
    );
    let request_bytes = wire::encode_request(&request).unwrap();
    let bootstrap = StoreBootstrap {
        binding,
        identity,
        process_nonce: ProcessNonce::from_u128(11),
        create_new: true,
        limits: StoreLimits::development_default(),
    };
    (directory, bootstrap, caller, request_bytes)
}

fn database_path(directory: &TempDir) -> std::path::PathBuf {
    directory.path().join("nexus.sqlite3")
}

#[test]
fn commit_grant_is_exactly_replayed() {
    let (directory, bootstrap, caller, request_bytes) = fixture();
    let mut store = NexusAdapterStore::open(database_path(&directory), bootstrap).unwrap();
    let mut peer = FakePeer::new(bootstrap.identity.registry_instance);

    let first = store.execute_exact(caller, &request_bytes, &mut peer).unwrap();
    let second = store.execute_exact(caller, &request_bytes, &mut peer).unwrap();
    assert_eq!(first, second);
    assert_eq!(peer.prepare_calls.get(), 1);
    assert_eq!(peer.commit_calls.get(), 1);

    let request = wire::decode_request(&request_bytes).unwrap();
    let response = wire::decode_response_for(&request, &first).unwrap();
    let wire::Outcome::Success(wire::Success::DispatchAuthorized(grant)) = response.outcome else {
        panic!("expected dispatch grant");
    };
    assert_eq!(grant.grant_sequence, 1);
    assert_eq!(grant.registry_instance, bootstrap.identity.registry_instance);
}

#[test]
fn pending_native_commit_reuses_exact_prepared_bytes_after_reopen() {
    let (directory, mut bootstrap, caller, request_bytes) = fixture();
    let database = database_path(&directory);
    let mut store = NexusAdapterStore::open(&database, bootstrap).unwrap();
    let mut first_peer = FakePeer::new(bootstrap.identity.registry_instance).unavailable_once();
    assert_eq!(
        store.execute_exact(caller, &request_bytes, &mut first_peer),
        Err(NexusServiceError::NativeUnavailable)
    );
    let prepared = first_peer.last_prepared.borrow().clone().unwrap();
    drop(store);

    bootstrap.create_new = false;
    bootstrap.process_nonce = ProcessNonce::from_u128(12);
    let mut store = NexusAdapterStore::open(&database, bootstrap).unwrap();
    let mut second_peer = FakePeer::new(bootstrap.identity.registry_instance);
    let response_bytes = store.execute_exact(caller, &request_bytes, &mut second_peer).unwrap();
    assert_eq!(second_peer.prepare_calls.get(), 0);
    assert_eq!(second_peer.commit_calls.get(), 1);
    assert_eq!(second_peer.last_prepared.borrow().as_ref(), Some(&prepared));
    let request = wire::decode_request(&request_bytes).unwrap();
    wire::decode_response_for(&request, &response_bytes).unwrap();
}

#[test]
fn caller_binding_and_projection_substitution_fail_closed() {
    let (directory, bootstrap, caller, request_bytes) = fixture();
    let mut store = NexusAdapterStore::open(database_path(&directory), bootstrap).unwrap();
    let mut peer = FakePeer::new(bootstrap.identity.registry_instance);
    store.execute_exact(caller, &request_bytes, &mut peer).unwrap();

    let mut substituted = caller;
    substituted.logical_incarnation = LogicalIncarnation::from_u128(99);
    assert_eq!(
        store.execute_exact(substituted, &request_bytes, &mut peer),
        Err(NexusServiceError::InvalidRequest)
    );

    let mut request = wire::decode_request(&request_bytes).unwrap();
    let wire::Operation::CommitAndAuthorizeDispatch(ref mut commit) = request.operation else {
        unreachable!();
    };
    commit.expected_projection_digest = Sha256Digest::of(b"substituted-projection");
    request.request_id = RequestId::from_u128(101);
    let substituted_bytes = wire::encode_request(&request).unwrap();
    let response_bytes = store.execute_exact(caller, &substituted_bytes, &mut peer).unwrap();
    let response = wire::decode_response_for(&request, &response_bytes).unwrap();
    assert!(matches!(response.outcome, wire::Outcome::Rejected(wire::Rejection::Conflict)));
    assert_eq!(peer.prepare_calls.get(), 1);
    assert_eq!(peer.commit_calls.get(), 1);
}

#[test]
fn grant_query_survives_store_reopen() {
    let (directory, mut bootstrap, caller, request_bytes) = fixture();
    let database = database_path(&directory);
    let mut store = NexusAdapterStore::open(&database, bootstrap).unwrap();
    let mut peer = FakePeer::new(bootstrap.identity.registry_instance);
    let response_bytes = store.execute_exact(caller, &request_bytes, &mut peer).unwrap();
    let request = wire::decode_request(&request_bytes).unwrap();
    let response = wire::decode_response_for(&request, &response_bytes).unwrap();
    let grant = match response.outcome {
        wire::Outcome::Success(wire::Success::DispatchAuthorized(grant)) => grant,
        _ => panic!("expected grant"),
    };
    drop(store);

    bootstrap.create_new = false;
    bootstrap.process_nonce = ProcessNonce::from_u128(13);
    let mut store = NexusAdapterStore::open(&database, bootstrap).unwrap();
    let query = wire::Request::new(
        RequestId::from_u128(14),
        caller,
        wire::Operation::Query(wire::QueryRequest::Grant(grant.grant)),
    );
    let query_bytes = wire::encode_request(&query).unwrap();
    let query_response = store.execute_exact(caller, &query_bytes, &mut peer).unwrap();
    let query_response = wire::decode_response_for(&query, &query_response).unwrap();
    assert!(matches!(
        query_response.outcome,
        wire::Outcome::Success(wire::Success::Query(wire::QueryResult::Grant(_)))
    ));
}

fn commit_request_bytes(
    base: &[u8],
    request_id: u128,
    operation: u128,
    idempotency: u128,
    projection: &[u8],
) -> Vec<u8> {
    let mut request = wire::decode_request(base).unwrap();
    request.request_id = RequestId::from_u128(request_id);
    let wire::Operation::CommitAndAuthorizeDispatch(ref mut commit) = request.operation else {
        panic!("fixture must be a commit request");
    };
    commit.effect.operation = OperationId::from_u128(operation);
    commit.effect.idempotency = IdempotencyId::from_u128(idempotency);
    commit.expected_projection_digest = Sha256Digest::of(projection);
    wire::encode_request(&request).unwrap()
}

fn effect_query(
    caller: AgentBinding,
    request_id: u128,
    operation: u128,
    idempotency: u128,
) -> wire::Request {
    wire::Request::new(
        RequestId::from_u128(request_id),
        caller,
        wire::Operation::Query(wire::QueryRequest::Effect(wire::EffectIdentity {
            operation: OperationId::from_u128(operation),
            idempotency: IdempotencyId::from_u128(idempotency),
        })),
    )
}

#[test]
fn descriptor_exposes_the_frozen_native_request_bound() {
    let (directory, bootstrap, caller, _) = fixture();
    let mut store = NexusAdapterStore::open(database_path(&directory), bootstrap).unwrap();
    let request = wire::Request::new(RequestId::from_u128(20), caller, wire::Operation::Descriptor);
    let request_bytes = wire::encode_request(&request).unwrap();
    let mut peer = FakePeer::new(bootstrap.identity.registry_instance);
    let response_bytes = store.execute_exact(caller, &request_bytes, &mut peer).unwrap();
    let response = wire::decode_response_for(&request, &response_bytes).unwrap();
    let wire::Outcome::Success(wire::Success::Descriptor(descriptor)) = response.outcome else {
        panic!("expected descriptor");
    };
    assert_eq!(descriptor.maximum_native_request_bytes, 65_536);
    assert_eq!(peer.commit_calls.get(), 0);
}

#[test]
fn request_id_reuse_with_different_bytes_is_rejected_before_peer_call() {
    let (directory, bootstrap, caller, request_bytes) = fixture();
    let mut store = NexusAdapterStore::open(database_path(&directory), bootstrap).unwrap();
    let mut peer = FakePeer::new(bootstrap.identity.registry_instance);
    store.execute_exact(caller, &request_bytes, &mut peer).unwrap();
    let changed = commit_request_bytes(&request_bytes, 10, 8, 9, b"different");
    assert_eq!(
        store.execute_exact(caller, &changed, &mut peer),
        Err(NexusServiceError::RequestIdConflict)
    );
    assert_eq!(peer.prepare_calls.get(), 1);
    assert_eq!(peer.commit_calls.get(), 1);
}

#[test]
fn caller_generation_regression_is_rejected_before_peer_call() {
    let (directory, bootstrap, caller, request_bytes) = fixture();
    let mut store = NexusAdapterStore::open(database_path(&directory), bootstrap).unwrap();
    let mut peer = FakePeer::new(bootstrap.identity.registry_instance);
    store.execute_exact(caller, &request_bytes, &mut peer).unwrap();
    let mut stale = caller;
    stale.process_nonce = ProcessNonce::from_u128(99);
    let mut changed_request =
        wire::decode_request(&commit_request_bytes(&request_bytes, 11, 18, 19, b"new-effect"))
            .unwrap();
    changed_request.caller = stale;
    let changed = wire::encode_request(&changed_request).unwrap();
    assert_eq!(
        store.execute_exact(stale, &changed, &mut peer),
        Err(NexusServiceError::CallerBindingConflict)
    );
    assert_eq!(peer.commit_calls.get(), 1);
}

#[test]
fn caller_generation_outside_sqlite_domain_is_rejected_before_peer_call() {
    let (directory, bootstrap, caller, _) = fixture();
    let mut store = NexusAdapterStore::open(database_path(&directory), bootstrap).unwrap();
    let mut oversized = caller;
    oversized.process_generation = i64::MAX as u64 + 1;
    let request =
        wire::Request::new(RequestId::from_u128(15), oversized, wire::Operation::Descriptor);
    let request_bytes = wire::encode_request(&request).unwrap();
    let mut peer = FakePeer::new(bootstrap.identity.registry_instance);
    assert_eq!(
        store.execute_exact(oversized, &request_bytes, &mut peer),
        Err(NexusServiceError::InvalidRequest)
    );
    assert_eq!(peer.prepare_calls.get(), 0);
    assert_eq!(peer.commit_calls.get(), 0);
}

#[test]
fn provider_revision_boundary_is_checked_before_native_effect() {
    let (directory, mut bootstrap, caller, request_bytes) = fixture();
    let database = database_path(&directory);
    let mut store = NexusAdapterStore::open(&database, bootstrap).unwrap();
    let mut boundary_request = wire::decode_request(&request_bytes).unwrap();
    let wire::Operation::CommitAndAuthorizeDispatch(ref mut commit) = boundary_request.operation
    else {
        unreachable!();
    };
    commit.expected_provider_revision = i64::MAX as u64 - 1;
    let boundary_bytes = wire::encode_request(&boundary_request).unwrap();
    let mut peer =
        FakePeer::new(bootstrap.identity.registry_instance).with_provider_revision(i64::MAX as u64);
    store.execute_exact(caller, &boundary_bytes, &mut peer).unwrap();
    assert_eq!(peer.prepare_calls.get(), 1);
    assert_eq!(peer.commit_calls.get(), 1);
    drop(store);

    bootstrap.create_new = false;
    bootstrap.process_nonce = ProcessNonce::from_u128(16);
    let mut store = NexusAdapterStore::open(&database, bootstrap).unwrap();
    let mut oversized_request = wire::decode_request(&request_bytes).unwrap();
    oversized_request.request_id = RequestId::from_u128(17);
    let wire::Operation::CommitAndAuthorizeDispatch(ref mut commit) = oversized_request.operation
    else {
        unreachable!();
    };
    commit.effect.operation = OperationId::from_u128(18);
    commit.effect.idempotency = IdempotencyId::from_u128(19);
    commit.expected_provider_revision = i64::MAX as u64;
    let oversized_bytes = wire::encode_request(&oversized_request).unwrap();
    assert_eq!(
        store.execute_exact(caller, &oversized_bytes, &mut peer),
        Err(NexusServiceError::InvalidRequest)
    );
    assert_eq!(peer.prepare_calls.get(), 1);
    assert_eq!(peer.commit_calls.get(), 1);
}

#[test]
fn native_commit_is_not_called_without_terminal_response_reservation() {
    let (directory, mut bootstrap, caller, request_bytes) = fixture();
    bootstrap.limits = StoreLimits {
        max_exchanges: 64,
        max_exchange_bytes: 2 * visa_local_rpc::MAX_INNER_REQUEST_BYTES as u64,
    };
    let mut store = NexusAdapterStore::open(database_path(&directory), bootstrap).unwrap();
    let commit_len = u64::try_from(request_bytes.len()).unwrap();
    let mut crossed_reservation_boundary = false;
    let mut peer = FakePeer::new(bootstrap.identity.registry_instance);
    for index in 0..32_u128 {
        let request = wire::Request::new(
            RequestId::from_u128(1_000 + index),
            caller,
            wire::Operation::Register(wire::EffectInvocation {
                effect: wire::EffectIdentity {
                    operation: OperationId::from_u128(2_000 + index),
                    idempotency: IdempotencyId::from_u128(3_000 + index),
                },
                expected_provider_revision: 0,
                invocation: CanonicalPayload::new(
                    PayloadSchema { id: wire::REGISTER_SCHEMA, major: 1, minor: 0 },
                    vec![b'x'; 65_536],
                )
                .unwrap(),
            }),
        );
        let bytes = wire::encode_request(&request).unwrap();
        store.execute_exact(caller, &bytes, &mut peer).unwrap();
        let retained: i64 = store
            .connection
            .query_row(
                "SELECT coalesce(sum(length(request_bytes) + length(response_bytes)), 0)
                 FROM rpc_exchange",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let admitted = u64::try_from(retained)
            .unwrap()
            .checked_add(commit_len)
            .and_then(|value| value.checked_add(visa_local_rpc::MAX_INNER_RESPONSE_BYTES as u64))
            .unwrap();
        if admitted > bootstrap.limits.max_exchange_bytes {
            crossed_reservation_boundary = true;
            break;
        }
    }
    assert!(crossed_reservation_boundary);
    assert_eq!(
        store.execute_exact(caller, &request_bytes, &mut peer),
        Err(NexusServiceError::Capacity)
    );
    assert_eq!(peer.prepare_calls.get(), 1);
    assert_eq!(peer.commit_calls.get(), 0);
    let pending: i64 = store
        .connection
        .query_row("SELECT count(*) FROM native_exchange", [], |row| row.get(0))
        .unwrap();
    assert_eq!(pending, 0);
}

#[test]
fn invalid_native_request_digest_leaves_pending_for_reconcile() {
    let (directory, bootstrap, caller, request_bytes) = fixture();
    let mut store = NexusAdapterStore::open(database_path(&directory), bootstrap).unwrap();
    let mut bad_peer = FakePeer::new(bootstrap.identity.registry_instance)
        .with_request_digest_override(Sha256Digest::of(b"wrong-native-request"));
    assert_eq!(
        store.execute_exact(caller, &request_bytes, &mut bad_peer),
        Err(NexusServiceError::Integrity)
    );
    let mut good_peer = FakePeer::new(bootstrap.identity.registry_instance);
    assert_eq!(store.reconcile_pending(&mut good_peer).unwrap(), 1);
}

#[test]
fn invalid_native_receipt_leaves_pending_for_adapter_reconcile() {
    let (directory, bootstrap, caller, request_bytes) = fixture();
    let database = database_path(&directory);
    let mut store = NexusAdapterStore::open(&database, bootstrap).unwrap();
    let mut bad_peer = FakePeer::new(bootstrap.identity.registry_instance)
        .with_registry_override(RegistryInstanceId::from_u128(99));
    assert_eq!(
        store.execute_exact(caller, &request_bytes, &mut bad_peer),
        Err(NexusServiceError::Integrity)
    );
    assert_eq!(bad_peer.commit_calls.get(), 1);
    let mut good_peer = FakePeer::new(bootstrap.identity.registry_instance);
    assert_eq!(store.reconcile_pending(&mut good_peer).unwrap(), 1);
    assert_eq!(good_peer.prepare_calls.get(), 0);
    assert_eq!(good_peer.commit_calls.get(), 1);
}

#[test]
fn native_rejection_is_bound_and_survives_reopen() {
    let (directory, mut bootstrap, caller, request_bytes) = fixture();
    let database = database_path(&directory);
    let mut store = NexusAdapterStore::open(&database, bootstrap).unwrap();
    let mut peer = FakePeer::new(bootstrap.identity.registry_instance)
        .rejecting(wire::Rejection::StaleProviderRevision { expected: 2, actual: 3 });
    let first = store.execute_exact(caller, &request_bytes, &mut peer).unwrap();
    let request = wire::decode_request(&request_bytes).unwrap();
    let response = wire::decode_response_for(&request, &first).unwrap();
    assert!(matches!(
        response.outcome,
        wire::Outcome::Rejected(wire::Rejection::StaleProviderRevision { .. })
    ));
    drop(store);
    bootstrap.create_new = false;
    bootstrap.process_nonce = ProcessNonce::from_u128(12);
    let mut reopened = NexusAdapterStore::open(&database, bootstrap).unwrap();
    let replay = reopened.execute_exact(caller, &request_bytes, &mut peer).unwrap();
    assert_eq!(replay, first);
    assert_eq!(peer.commit_calls.get(), 1);
}

#[test]
fn adapter_reconciles_pending_after_agent_generation_changes() {
    let (directory, mut bootstrap, caller, request_bytes) = fixture();
    let database = database_path(&directory);
    let mut store = NexusAdapterStore::open(&database, bootstrap).unwrap();
    let mut unavailable = FakePeer::new(bootstrap.identity.registry_instance).unavailable_once();
    assert_eq!(
        store.execute_exact(caller, &request_bytes, &mut unavailable),
        Err(NexusServiceError::NativeUnavailable)
    );
    drop(store);
    bootstrap.create_new = false;
    bootstrap.process_nonce = ProcessNonce::from_u128(12);
    let mut store = NexusAdapterStore::open(&database, bootstrap).unwrap();
    let mut restarted_caller = caller;
    restarted_caller.process_nonce = ProcessNonce::from_u128(13);
    restarted_caller.process_generation = 2;
    let query = effect_query(restarted_caller, 30, 8, 9);
    let query_bytes = wire::encode_request(&query).unwrap();
    let before = store.execute_exact(restarted_caller, &query_bytes, &mut unavailable).unwrap();
    let before = wire::decode_response_for(&query, &before).unwrap();
    let wire::Outcome::Unknown(unknown) = before.outcome else {
        panic!("pending native effect must remain explicitly unknown");
    };
    assert_eq!(
        unknown.query,
        wire::QueryRequest::Effect(wire::EffectIdentity {
            operation: OperationId::from_u128(8),
            idempotency: IdempotencyId::from_u128(9),
        })
    );
    assert_eq!(unknown.last_known_provider_revision, 2);
    let mut peer = FakePeer::new(bootstrap.identity.registry_instance);
    assert_eq!(store.reconcile_pending(&mut peer).unwrap(), 1);
    let after_query = effect_query(restarted_caller, 31, 8, 9);
    let after = store
        .execute_exact(restarted_caller, &wire::encode_request(&after_query).unwrap(), &mut peer)
        .unwrap();
    let after = wire::decode_response_for(&after_query, &after).unwrap();
    let wire::Outcome::Success(wire::Success::Query(wire::QueryResult::Effect(state))) =
        after.outcome
    else {
        panic!("expected committed effect state");
    };
    assert_eq!(state.phase, wire::EffectPhase::Committed);
}

#[test]
fn two_grants_reopen_with_receipt_sequences_without_hash_order_assumption() {
    let (directory, mut bootstrap, caller, request_bytes) = fixture();
    let database = database_path(&directory);
    let mut store = NexusAdapterStore::open(&database, bootstrap).unwrap();
    let mut peer = FakePeer::new(bootstrap.identity.registry_instance);
    store.execute_exact(caller, &request_bytes, &mut peer).unwrap();
    let second = commit_request_bytes(&request_bytes, 40, 41, 42, b"second");
    store.execute_exact(caller, &second, &mut peer).unwrap();
    assert_eq!(peer.commit_calls.get(), 2);
    drop(store);
    bootstrap.create_new = false;
    bootstrap.process_nonce = ProcessNonce::from_u128(12);
    let _reopened = NexusAdapterStore::open(&database, bootstrap).unwrap();
}

#[test]
fn duplicate_native_receipt_sequence_fails_live_and_remains_pending() {
    let (directory, mut bootstrap, caller, request_bytes) = fixture();
    let database = database_path(&directory);
    let mut store = NexusAdapterStore::open(&database, bootstrap).unwrap();
    let mut first_peer =
        FakePeer::new(bootstrap.identity.registry_instance).with_receipt_sequence(1);
    store.execute_exact(caller, &request_bytes, &mut first_peer).unwrap();

    let second = commit_request_bytes(&request_bytes, 50, 51, 52, b"second-sequence");
    let mut duplicate_peer =
        FakePeer::new(bootstrap.identity.registry_instance).with_receipt_sequence(1);
    assert_eq!(
        store.execute_exact(caller, &second, &mut duplicate_peer),
        Err(NexusServiceError::Integrity)
    );
    assert_eq!(duplicate_peer.commit_calls.get(), 1);
    drop(store);

    bootstrap.create_new = false;
    bootstrap.process_nonce = ProcessNonce::from_u128(53);
    let mut store = NexusAdapterStore::open(&database, bootstrap).unwrap();
    let query = effect_query(caller, 54, 51, 52);
    let query_bytes = wire::encode_request(&query).unwrap();
    let response = store.execute_exact(caller, &query_bytes, &mut duplicate_peer).unwrap();
    let response = wire::decode_response_for(&query, &response).unwrap();
    assert!(matches!(response.outcome, wire::Outcome::Unknown(_)));

    let mut replay_peer =
        FakePeer::new(bootstrap.identity.registry_instance).with_receipt_sequence(1);
    assert_eq!(store.reconcile_pending(&mut replay_peer), Err(NexusServiceError::Integrity));
    assert_eq!(replay_peer.prepare_calls.get(), 0);
    assert_eq!(replay_peer.commit_calls.get(), 1);
    let pending: i64 = store
        .connection
        .query_row("SELECT count(*) FROM native_exchange WHERE phase = 0", [], |row| row.get(0))
        .unwrap();
    assert_eq!(pending, 1);
}
