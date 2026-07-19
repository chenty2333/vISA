use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
};

use joint_handoff_core::{
    ClassificationCounts, DestinationPreparedReceipt, Digest, FreezeDisposition, IdempotencyKey,
    Identity, JointIssuerSet, JournalPosition, NexusFreezeReceipt, PrepareIntentReceipt,
    PreparedBindings, ReceiptHeader, ReceiptIssuerIdentity, ReceiptKind, SnapshotBinding,
    TypedReceipt, VisaFreezeReceipt, canonical_from_bytes,
};
use rusqlite::Connection;
use tempfile::TempDir;
use visa_local_rpc::{
    common::{
        AgentBinding, AgentRole, AuthorityServiceBinding, BootId, CohortId, ContinuityUnitId,
        EntityRefWire, HandoffId, IssuerId, IssuerKeyId, IssuerLogId, JointHandoffKeyWire,
        LogicalIncarnation, NodeId, PRODUCT_VERSION, ProcessNonce, RequestId, RuntimeSessionId,
        ServiceIncarnation,
    },
    ownership as wire,
};

use super::*;

struct TestFixture {
    _root: TempDir,
    database_path: PathBuf,
    binding: StoreBinding,
    identity: OwnershipServiceIdentity,
    caller: AgentBinding,
    limits: StoreLimits,
}

impl TestFixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("private temporary directory");
        let binding = StoreBinding {
            cohort: CohortId::from_u128(1),
            boot: BootId::from_u128(2),
            runtime_session: RuntimeSessionId::from_u128(3),
        };
        let identity = OwnershipServiceIdentity {
            service_incarnation: ServiceIncarnation::from_u128(10),
            issuer: IssuerId::from_u128(11),
            key_id: IssuerKeyId::from_u128(12),
            log_namespace: IssuerLogId::from_u128(13),
        };
        let caller = AgentBinding {
            product_version: PRODUCT_VERSION,
            cohort: binding.cohort,
            boot: binding.boot,
            runtime_session: binding.runtime_session,
            role: AgentRole::Source,
            logical_incarnation: LogicalIncarnation::from_u128(14),
            process_nonce: ProcessNonce::from_u128(15),
            process_generation: 1,
        };
        Self {
            database_path: root.path().join("ownership.sqlite"),
            _root: root,
            binding,
            identity,
            caller,
            limits: StoreLimits::development_default(),
        }
    }

    fn bootstrap(
        &self,
        create_identity: Option<OwnershipServiceIdentity>,
        process_nonce: u128,
    ) -> StoreBootstrap {
        StoreBootstrap {
            binding: self.binding,
            create_identity,
            process_nonce: ProcessNonce::from_u128(process_nonce),
            limits: self.limits,
        }
    }

    fn authenticator(&self) -> PinnedLocalReceiptAuthenticator {
        self.authenticator_with_visa_source(300)
    }

    fn authenticator_with_visa_source(&self, visa_source: u128) -> PinnedLocalReceiptAuthenticator {
        PinnedLocalReceiptAuthenticator::new(JointIssuerSet {
            ownership: ReceiptIssuerIdentity {
                issuer: Identity::from_bytes(self.identity.issuer.0),
                issuer_incarnation: Identity::from_bytes(self.identity.service_incarnation.0),
                key_id: Identity::from_bytes(self.identity.key_id.0),
                log_id: Identity::from_bytes(self.identity.log_namespace.0),
            },
            visa_source: issuer(visa_source),
            visa_destination: issuer(500),
            effect_closure: issuer(400),
        })
        .expect("fixed local receipt policy")
    }

    fn create(&self, process_nonce: u128) -> AuthorityStore {
        AuthorityStore::open(
            &self.database_path,
            self.bootstrap(Some(self.identity), process_nonce),
            self.authenticator(),
        )
        .expect("create ownership store")
    }

    fn reopen(&self, process_nonce: u128) -> AuthorityStore {
        AuthorityStore::open(
            &self.database_path,
            self.bootstrap(None, process_nonce),
            self.authenticator(),
        )
        .expect("reopen ownership store")
    }
}

fn key(handoff: u128, source: u128, destination: u128, expected_epoch: u64) -> JointHandoffKeyWire {
    JointHandoffKeyWire {
        continuity_unit: EntityRefWire {
            identity: ContinuityUnitId::from_u128(100),
            generation: 0,
        },
        handoff: HandoffId::from_u128(handoff),
        source: NodeId::from_u128(source),
        destination: NodeId::from_u128(destination),
        expected_epoch,
        next_epoch: expected_epoch + 1,
    }
}

fn initialize_operation(key: JointHandoffKeyWire) -> wire::Operation {
    wire::Operation::InitializeUnit(wire::InitializeUnitRequest {
        continuity_unit: key.continuity_unit,
        owner: key.source,
        epoch: key.expected_epoch,
    })
}

fn reserve_operation(key: JointHandoffKeyWire) -> wire::Operation {
    wire::Operation::Reserve(wire::DecisionProposal {
        key,
        expected_state_sequence: 0,
        proposal: encode_reserve_proposal(&ReserveProposalV1::default()).expect("reserve proposal"),
    })
}

fn request(
    caller: AgentBinding,
    request_id: u128,
    operation: wire::Operation,
) -> (wire::Request, Vec<u8>) {
    let request = wire::Request::new(RequestId::from_u128(request_id), caller, operation);
    let bytes = wire::encode_request(&request).expect("canonical request");
    (request, bytes)
}

fn execute(
    store: &mut AuthorityStore,
    caller: AgentBinding,
    request_id: u128,
    operation: wire::Operation,
) -> (wire::Request, wire::Response, Vec<u8>) {
    let (request, request_bytes) = request(caller, request_id, operation);
    let response_bytes =
        store.execute_exact(caller, &request_bytes).expect("execute ownership request");
    let response =
        wire::decode_response_for(&request, &response_bytes).expect("paired ownership response");
    (request, response, response_bytes)
}

fn rewrite_first_response_server(
    database_path: &PathBuf,
    mutate: impl FnOnce(&mut AuthorityServiceBinding),
) {
    let connection = Connection::open(database_path).expect("open database for response fault");
    let (request_bytes, response_bytes): (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT request_bytes, response_bytes FROM rpc_exchange WHERE completion_order = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("stored exchange");
    let request = wire::decode_request(&request_bytes).expect("stored request");
    let mut response =
        wire::decode_response_for(&request, &response_bytes).expect("stored response");
    mutate(&mut response.server);
    let substituted =
        wire::encode_response_for(&request, &response).expect("substituted valid response");
    let substituted_digest = response.digest().expect("substituted response digest");
    connection
        .execute(
            "UPDATE rpc_exchange SET response_bytes = ?1, response_digest = ?2
             WHERE completion_order = 1",
            rusqlite::params![substituted, substituted_digest.0.as_slice()],
        )
        .expect("substitute response server binding");
}

fn receipt_from_outcome(outcome: &wire::Outcome) -> visa_local_rpc::common::ReceiptArtifact {
    match outcome {
        wire::Outcome::Success(
            wire::Success::Reserved(value)
            | wire::Success::Prepared(value)
            | wire::Success::Aborted(value)
            | wire::Success::Committed(value),
        ) => value.clone(),
        other => panic!("expected receipt success, got {other:?}"),
    }
}

fn digest(value: u8) -> Digest {
    Digest::from_bytes([value; 32])
}

fn issuer(base: u128) -> ReceiptIssuerIdentity {
    ReceiptIssuerIdentity {
        issuer: Identity::from_u128(base),
        issuer_incarnation: Identity::from_u128(base + 1),
        key_id: Identity::from_u128(base + 2),
        log_id: Identity::from_u128(base + 3),
    }
}

fn header(kind: ReceiptKind, issuer: ReceiptIssuerIdentity) -> ReceiptHeader {
    ReceiptHeader {
        version: joint_handoff_core::JOINT_PROTOCOL_VERSION,
        kind,
        issuer: issuer.issuer,
        issuer_incarnation: issuer.issuer_incarnation,
        key_id: issuer.key_id,
        log_id: issuer.log_id,
        sequence: 1,
        previous_digest: None,
    }
}

struct SealEvidence {
    proposal: SealProposalV1,
}

fn seal_evidence(
    intent_artifact: &visa_local_rpc::common::ReceiptArtifact,
    disposition: FreezeDisposition,
    unresolved: u64,
) -> SealEvidence {
    let intent: PrepareIntentReceipt =
        canonical_from_bytes(&intent_artifact.payload.bytes).expect("typed prepare intent");
    let key = intent.key;
    let intent_ref = intent.receipt_ref().expect("intent reference");
    let visa_issuer = issuer(300);
    let effect_issuer = issuer(400);
    let destination_issuer = issuer(500);
    let visa = VisaFreezeReceipt {
        header: header(ReceiptKind::VisaFreeze, visa_issuer),
        key,
        intent: intent_ref,
        journal_position: JournalPosition(20),
        state_digest: digest(20),
        portable_state_digest: digest(21),
    };
    let visa_ref = visa.receipt_ref().expect("visa freeze reference");
    let nexus = NexusFreezeReceipt {
        header: header(ReceiptKind::NexusFreeze, effect_issuer),
        key,
        intent: intent_ref,
        registry_instance: Identity::from_u128(401),
        scope_id: Identity::from_u128(402),
        scope_generation: 1,
        authority_epoch: 1,
        freeze_generation: 1,
        domain_bindings_digest: digest(22),
        effect_cohort_digest: digest(23),
        classification_root: digest(24),
        counts: ClassificationCounts {
            registered: 1,
            committed: u64::from(unresolved == 0),
            aborted: 0,
            unresolved,
            tombstones: 0,
        },
        disposition,
    };
    let nexus_ref = nexus.receipt_ref().expect("Nexus freeze reference");
    let destination = DestinationPreparedReceipt {
        header: header(ReceiptKind::DestinationPrepared, destination_issuer),
        key,
        intent: intent_ref,
        visa_freeze: visa_ref,
        nexus_freeze: nexus_ref,
        snapshot: SnapshotBinding {
            snapshot: Identity::from_u128(600),
            integrity: digest(25),
            body_digest: digest(26),
            source_journal_position: visa.journal_position,
            component_digest: digest(27),
            profile_digest: digest(28),
        },
        journal_position: JournalPosition(21),
        state_digest: digest(29),
        prepared_destination_digest: digest(30),
        authorities_digest: digest(31),
        bindings_digest: digest(32),
        joint_mapping_manifest_digest: digest(33),
        lease_commit_operation: Identity::from_u128(601),
        lease_commit_idempotency: IdempotencyKey::from_bytes(602_u128.to_be_bytes()),
        lease_commit_request_digest: digest(34),
    };
    let destination_ref = destination.receipt_ref().expect("destination reference");
    let bindings = PreparedBindings {
        prepare_intent_receipt_digest: intent_ref.digest,
        visa_freeze_receipt_digest: visa_ref.digest,
        effect_freeze_receipt_digest: nexus_ref.digest,
        snapshot: destination.snapshot.snapshot,
        snapshot_integrity_digest: destination.snapshot.integrity,
        source_journal_position: visa.journal_position,
        source_state_digest: visa.state_digest,
        component_digest: destination.snapshot.component_digest,
        profile_digest: destination.snapshot.profile_digest,
        destination_prepared_receipt_digest: destination_ref.digest,
        destination_state_digest: destination.state_digest,
        prepared_authorities_digest: destination.authorities_digest,
        prepared_bindings_digest: destination.bindings_digest,
        effect_cohort_manifest_digest: nexus.effect_cohort_digest,
        joint_mapping_manifest_digest: destination.joint_mapping_manifest_digest,
    };
    SealEvidence {
        proposal: SealProposalV1 {
            version: joint_handoff_core::JOINT_PROTOCOL_VERSION,
            reservation: intent.reservation,
            intent: intent_artifact.clone(),
            visa_freeze: receipt_artifact(&visa).expect("visa artifact"),
            nexus_freeze: receipt_artifact(&nexus).expect("Nexus artifact"),
            destination_prepared: receipt_artifact(&destination).expect("destination artifact"),
            bindings,
        },
    }
}

fn reserve(
    store: &mut AuthorityStore,
    caller: AgentBinding,
    key: JointHandoffKeyWire,
    request_id: u128,
) -> visa_local_rpc::common::ReceiptArtifact {
    let (_, response, _) = execute(store, caller, request_id, reserve_operation(key));
    receipt_from_outcome(&response.outcome)
}

fn complete_handoff(
    store: &mut AuthorityStore,
    caller: AgentBinding,
    key: JointHandoffKeyWire,
    request_id_base: u128,
) -> (Vec<u8>, Vec<u8>, visa_local_rpc::common::ReceiptArtifact) {
    let intent = reserve(store, caller, key, request_id_base);
    let evidence = seal_evidence(&intent, FreezeDisposition::ReadyToCommit, 0);
    let seal_operation = wire::Operation::Seal(wire::DecisionProposal {
        key,
        expected_state_sequence: 1,
        proposal: encode_seal_proposal(&evidence.proposal).expect("seal proposal"),
    });
    let (_, prepared_response, _) = execute(store, caller, request_id_base + 1, seal_operation);
    let prepared = receipt_from_outcome(&prepared_response.outcome);
    let commit_operation = wire::Operation::Commit(wire::DecisionProposal {
        key,
        expected_state_sequence: 2,
        proposal: encode_commit_proposal(&CommitProposalV1 {
            version: joint_handoff_core::JOINT_PROTOCOL_VERSION,
            reservation: evidence.proposal.reservation,
            prepared,
        })
        .expect("commit proposal"),
    });
    let (commit_request, commit_request_bytes) =
        request(caller, request_id_base + 2, commit_operation);
    let commit_response_bytes =
        store.execute_exact(caller, &commit_request_bytes).expect("commit handoff");
    let commit_response = wire::decode_response_for(&commit_request, &commit_response_bytes)
        .expect("paired commit response");
    let committed = receipt_from_outcome(&commit_response.outcome);
    (commit_request_bytes, commit_response_bytes, committed)
}

#[test]
fn proposal_codecs_are_strict_and_versioned() {
    let value = ReserveProposalV1::default();
    let encoded = encode_reserve_proposal(&value).expect("encode reserve proposal");
    assert_eq!(decode_reserve_proposal(&encoded), Ok(value));

    let mut wrong_schema = encoded.clone();
    wrong_schema.schema.id = wire::SEAL_PROPOSAL_SCHEMA;
    assert_eq!(decode_reserve_proposal(&wrong_schema), Err(ProposalCodecError::WrongSchema));

    let mut trailing_bytes = encoded.bytes.clone();
    trailing_bytes.push(0);
    let trailing = visa_local_rpc::common::CanonicalPayload::new(encoded.schema, trailing_bytes)
        .expect("well-formed carrier");
    assert_eq!(decode_reserve_proposal(&trailing), Err(ProposalCodecError::TrailingBytes));
    assert_eq!(
        crate::proposal::require_supported_version(joint_handoff_core::JointProtocolVersion::new(
            1, 1
        )),
        Err(ProposalCodecError::Invalid)
    );
}

#[test]
fn store_is_private_durable_single_writer_and_exactly_bound() {
    let fixture = TestFixture::new();
    assert!(matches!(
        AuthorityStore::open(
            &fixture.database_path,
            fixture.bootstrap(None, 19),
            fixture.authenticator()
        ),
        Err(OwnershipServiceError::StoreMismatch)
    ));
    assert!(!fixture.database_path.exists());

    let wrong_ownership_policy = PinnedLocalReceiptAuthenticator::new(JointIssuerSet {
        ownership: issuer(900),
        visa_source: issuer(300),
        visa_destination: issuer(500),
        effect_closure: issuer(400),
    })
    .expect("wrong but well-formed policy");
    assert!(matches!(
        AuthorityStore::open(
            &fixture.database_path,
            fixture.bootstrap(Some(fixture.identity), 20),
            wrong_ownership_policy
        ),
        Err(OwnershipServiceError::StoreMismatch)
    ));
    assert!(!fixture.database_path.exists());

    let store = fixture.create(20);
    let report = store.durability_report().expect("durability report");
    assert_eq!(report.journal_mode, "wal");
    assert_eq!(report.synchronous, 2);
    assert_eq!(report.foreign_keys, 1);
    assert_eq!(report.trusted_schema, 0);
    assert_eq!(report.page_size, 4096);
    assert_eq!(report.max_page_count, (fixture.limits.max_database_bytes / 4096) as i64);
    assert!(!report.sqlite_version.is_empty());
    assert!(!report.sqlite_source_id.is_empty());
    assert_eq!(
        fs::metadata(&fixture.database_path).expect("database metadata").permissions().mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(fixture.database_path.parent().expect("database parent"))
            .expect("parent metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );

    assert!(matches!(
        AuthorityStore::open(
            &fixture.database_path,
            fixture.bootstrap(None, 21),
            fixture.authenticator()
        ),
        Err(OwnershipServiceError::StoreBusy)
    ));
    drop(store);

    let mut mismatched = fixture.bootstrap(None, 21);
    mismatched.binding.boot = BootId::from_u128(99);
    assert!(matches!(
        AuthorityStore::open(&fixture.database_path, mismatched, fixture.authenticator()),
        Err(OwnershipServiceError::StoreMismatch)
    ));
    assert!(matches!(
        AuthorityStore::open(
            &fixture.database_path,
            fixture.bootstrap(None, 21),
            fixture.authenticator_with_visa_source(800)
        ),
        Err(OwnershipServiceError::StoreMismatch)
    ));
    let mut mismatched_limits = fixture.bootstrap(None, 21);
    mismatched_limits.limits.max_exchanges -= 1;
    assert!(matches!(
        AuthorityStore::open(&fixture.database_path, mismatched_limits, fixture.authenticator()),
        Err(OwnershipServiceError::StoreMismatch)
    ));
    let reopened = fixture.reopen(21);
    assert_eq!(reopened.server_binding().process_generation, 2);
    assert_eq!(reopened.identity(), fixture.identity);
    drop(reopened);

    assert!(matches!(
        AuthorityStore::open(
            &fixture.database_path,
            fixture.bootstrap(None, 21),
            fixture.authenticator()
        ),
        Err(OwnershipServiceError::StoreMismatch)
    ));
    let reopened = fixture.reopen(22);
    assert_eq!(reopened.server_binding().process_generation, 3);
}

#[test]
fn first_create_ignores_old_orphans_and_publishes_only_a_complete_database() {
    let fixture = TestFixture::new();
    let stale =
        crate::store::initialization_path(&fixture.database_path, ProcessNonce::from_u128(19));
    fs::write(&stale, b"interrupted initialization").expect("create stale initialization file");
    fs::set_permissions(&stale, fs::Permissions::from_mode(0o600))
        .expect("make stale initialization file private");

    let current =
        crate::store::initialization_path(&fixture.database_path, ProcessNonce::from_u128(20));
    let store = fixture.create(20);
    assert!(fixture.database_path.exists());
    assert_eq!(fs::read(&stale).expect("retain old orphan"), b"interrupted initialization");
    let current_prefix =
        current.file_name().expect("initialization file name").to_string_lossy().into_owned();
    let current_leftovers =
        fs::read_dir(fixture.database_path.parent().expect("database parent directory"))
            .expect("list database parent")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(&current_prefix))
            .collect::<Vec<_>>();
    assert!(
        current_leftovers.is_empty(),
        "unexpected initialization leftovers: {current_leftovers:?}"
    );
    drop(store);

    let reopened = fixture.reopen(21);
    assert_eq!(reopened.server_binding().process_generation, 2);
}

#[test]
fn published_generation_zero_store_converges_to_the_first_process_generation() {
    let fixture = TestFixture::new();
    crate::store::initialize_and_publish_database(
        &fixture.database_path,
        fixture.bootstrap(Some(fixture.identity), 20),
        &fixture.authenticator(),
    )
    .expect("publish complete generation-zero store");

    let connection = Connection::open(&fixture.database_path).expect("inspect published store");
    let (generation, nonce): (i64, Vec<u8>) = connection
        .query_row(
            "SELECT process_generation, last_process_nonce FROM store_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("published generation-zero metadata");
    let process_instances: i64 = connection
        .query_row("SELECT count(*) FROM process_instance", [], |row| row.get(0))
        .expect("published process history");
    assert_eq!(generation, 0);
    assert_eq!(nonce, vec![0_u8; 16]);
    assert_eq!(process_instances, 0);
    drop(connection);

    let reopened = fixture.reopen(21);
    assert_eq!(reopened.server_binding().process_generation, 1);
    assert_eq!(reopened.server_binding().process_nonce, ProcessNonce::from_u128(21));
}

#[test]
fn first_create_never_replaces_an_existing_partial_final_path() {
    let fixture = TestFixture::new();
    fs::write(&fixture.database_path, b"partial final database")
        .expect("create interrupted final database");
    fs::set_permissions(&fixture.database_path, fs::Permissions::from_mode(0o600))
        .expect("make interrupted final database private");
    let before = fs::metadata(&fixture.database_path).expect("partial final metadata");

    assert!(matches!(
        AuthorityStore::open(
            &fixture.database_path,
            fixture.bootstrap(Some(fixture.identity), 20),
            fixture.authenticator(),
        ),
        Err(OwnershipServiceError::StoreMismatch)
    ));
    let after = fs::metadata(&fixture.database_path).expect("retained final metadata");
    assert_eq!(after.ino(), before.ino());
    assert_eq!(
        fs::read(&fixture.database_path).expect("retained final bytes"),
        b"partial final database"
    );
    assert!(
        !crate::store::initialization_path(&fixture.database_path, ProcessNonce::from_u128(20),)
            .exists()
    );

    assert!(matches!(
        AuthorityStore::open(
            &fixture.database_path,
            fixture.bootstrap(None, 21),
            fixture.authenticator(),
        ),
        Err(OwnershipServiceError::StoreMismatch)
    ));
    let after_reopen = fs::metadata(&fixture.database_path).expect("rejected final metadata");
    assert_eq!(after_reopen.ino(), before.ino());
    assert_eq!(
        fs::read(&fixture.database_path).expect("unmodified rejected final bytes"),
        b"partial final database"
    );
}

#[test]
fn first_create_never_removes_a_preexisting_same_nonce_initialization_path() {
    let fixture = TestFixture::new();
    let preexisting =
        crate::store::initialization_path(&fixture.database_path, ProcessNonce::from_u128(20));
    fs::write(&preexisting, b"preexisting same-nonce file")
        .expect("create same-nonce initialization path");
    fs::set_permissions(&preexisting, fs::Permissions::from_mode(0o600))
        .expect("make same-nonce initialization path private");
    let before = fs::metadata(&preexisting).expect("same-nonce metadata");

    assert!(matches!(
        AuthorityStore::open(
            &fixture.database_path,
            fixture.bootstrap(Some(fixture.identity), 20),
            fixture.authenticator(),
        ),
        Err(OwnershipServiceError::StoreMismatch)
    ));
    let after = fs::metadata(&preexisting).expect("retained same-nonce metadata");
    assert_eq!(after.ino(), before.ino());
    assert_eq!(
        fs::read(&preexisting).expect("retained same-nonce bytes"),
        b"preexisting same-nonce file"
    );
    assert!(!fixture.database_path.exists());
}

#[test]
fn first_create_never_consumes_or_removes_preexisting_sqlite_sidecars() {
    for suffix in ["-wal", "-shm", "-journal"] {
        let fixture = TestFixture::new();
        let temporary =
            crate::store::initialization_path(&fixture.database_path, ProcessNonce::from_u128(20));
        let sidecar = crate::store::sqlite_sidecar_path(&temporary, suffix);
        fs::write(&sidecar, b"preexisting temporary sidecar").expect("create temporary sidecar");
        fs::set_permissions(&sidecar, fs::Permissions::from_mode(0o600))
            .expect("make temporary sidecar private");
        let before = fs::metadata(&sidecar).expect("temporary sidecar metadata");

        assert!(matches!(
            AuthorityStore::open(
                &fixture.database_path,
                fixture.bootstrap(Some(fixture.identity), 20),
                fixture.authenticator(),
            ),
            Err(OwnershipServiceError::StoreMismatch)
        ));
        let after = fs::metadata(&sidecar).expect("retained temporary sidecar metadata");
        assert_eq!(after.ino(), before.ino());
        assert_eq!(
            fs::read(&sidecar).expect("retained temporary sidecar bytes"),
            b"preexisting temporary sidecar"
        );
        assert!(!temporary.exists());
        assert!(!fixture.database_path.exists());
    }

    for suffix in ["-wal", "-shm", "-journal"] {
        let fixture = TestFixture::new();
        let sidecar = crate::store::sqlite_sidecar_path(&fixture.database_path, suffix);
        fs::write(&sidecar, b"preexisting final sidecar").expect("create final sidecar");
        fs::set_permissions(&sidecar, fs::Permissions::from_mode(0o600))
            .expect("make final sidecar private");
        let before = fs::metadata(&sidecar).expect("final sidecar metadata");

        assert!(matches!(
            AuthorityStore::open(
                &fixture.database_path,
                fixture.bootstrap(Some(fixture.identity), 20),
                fixture.authenticator(),
            ),
            Err(OwnershipServiceError::StoreMismatch)
        ));
        let after = fs::metadata(&sidecar).expect("retained final sidecar metadata");
        assert_eq!(after.ino(), before.ino());
        assert_eq!(
            fs::read(&sidecar).expect("retained final sidecar bytes"),
            b"preexisting final sidecar"
        );
        assert!(!fixture.database_path.exists());
    }
}

#[test]
fn insecure_parent_file_mode_and_hardlink_fail_closed() {
    let insecure_parent = TestFixture::new();
    fs::set_permissions(
        insecure_parent.database_path.parent().expect("database parent"),
        fs::Permissions::from_mode(0o755),
    )
    .expect("weaken parent mode");
    assert!(matches!(
        AuthorityStore::open(
            &insecure_parent.database_path,
            insecure_parent.bootstrap(Some(insecure_parent.identity), 20),
            insecure_parent.authenticator()
        ),
        Err(OwnershipServiceError::StoreMismatch)
    ));

    let fixture = TestFixture::new();
    drop(fixture.create(20));
    fs::set_permissions(&fixture.database_path, fs::Permissions::from_mode(0o644))
        .expect("weaken database mode");
    assert!(matches!(
        AuthorityStore::open(
            &fixture.database_path,
            fixture.bootstrap(None, 21),
            fixture.authenticator()
        ),
        Err(OwnershipServiceError::StoreMismatch)
    ));

    fs::set_permissions(&fixture.database_path, fs::Permissions::from_mode(0o600))
        .expect("restore database mode");
    let alias =
        fixture.database_path.parent().expect("database parent").join("ownership-hardlink.sqlite");
    fs::hard_link(&fixture.database_path, &alias).expect("create database hardlink");
    assert!(matches!(
        AuthorityStore::open(
            &fixture.database_path,
            fixture.bootstrap(None, 21),
            fixture.authenticator()
        ),
        Err(OwnershipServiceError::StoreMismatch)
    ));
    fs::remove_file(alias).expect("remove database hardlink");
}

#[test]
fn exact_replay_survives_restart_and_changed_bytes_conflict() {
    let fixture = TestFixture::new();
    let mut store = fixture.create(20);
    let key = key(200, 201, 202, 7);
    let (initialize, initialize_bytes) = request(fixture.caller, 1, initialize_operation(key));
    let first = store.execute_exact(fixture.caller, &initialize_bytes).expect("initialize");
    assert_eq!(
        store.execute_exact(fixture.caller, &initialize_bytes).expect("exact in-process replay"),
        first
    );

    let (_, changed_bytes) = request(
        fixture.caller,
        1,
        wire::Operation::Query(wire::QueryRequest::Unit(key.continuity_unit)),
    );
    assert_eq!(
        store.execute_exact(fixture.caller, &changed_bytes),
        Err(OwnershipServiceError::RequestIdConflict)
    );
    let original_response =
        wire::decode_response_for(&initialize, &first).expect("original response");
    let original_server = original_response.server;
    drop(store);

    let mut reopened = fixture.reopen(21);
    assert_ne!(reopened.server_binding(), original_server);
    let replayed =
        reopened.execute_exact(fixture.caller, &initialize_bytes).expect("restart replay");
    assert_eq!(replayed, first);
    let replayed_response =
        wire::decode_response_for(&initialize, &replayed).expect("replayed response");
    assert_eq!(replayed_response.server, original_server);
}

#[test]
fn admitted_caller_must_equal_the_request_and_store_binding() {
    let fixture = TestFixture::new();
    let mut store = fixture.create(20);
    let key = key(200, 201, 202, 7);
    let (_, request_bytes) = request(fixture.caller, 1, initialize_operation(key));

    let mut substituted_process = fixture.caller;
    substituted_process.process_nonce = ProcessNonce::from_u128(99);
    assert_eq!(
        store.execute_exact(substituted_process, &request_bytes),
        Err(OwnershipServiceError::InvalidRequest)
    );

    let mut foreign_caller = fixture.caller;
    foreign_caller.cohort = CohortId::from_u128(99);
    let (_, foreign_bytes) = request(foreign_caller, 2, initialize_operation(key));
    assert_eq!(
        store.execute_exact(foreign_caller, &foreign_bytes),
        Err(OwnershipServiceError::InvalidRequest)
    );
    drop(store);

    let connection = Connection::open(&fixture.database_path).expect("inspect database");
    let exchanges: i64 = connection
        .query_row("SELECT count(*) FROM rpc_exchange", [], |row| row.get(0))
        .expect("exchange count");
    assert_eq!(exchanges, 0);
}

#[test]
fn semantic_retry_under_new_rpc_id_reuses_receipt_but_pairs_new_response() {
    let fixture = TestFixture::new();
    let mut store = fixture.create(20);
    let key = key(200, 201, 202, 7);
    execute(&mut store, fixture.caller, 1, initialize_operation(key));
    let operation = reserve_operation(key);
    let (_, first, first_bytes) = execute(&mut store, fixture.caller, 2, operation.clone());
    let (_, second, second_bytes) = execute(&mut store, fixture.caller, 3, operation);
    assert_eq!(receipt_from_outcome(&first.outcome), receipt_from_outcome(&second.outcome));
    assert_ne!(first.request_id, second.request_id);
    assert_ne!(first_bytes, second_bytes);
}

#[test]
fn seal_rejects_untrusted_blocked_and_mismatched_evidence_without_mutation() {
    let fixture = TestFixture::new();
    let mut store = fixture.create(20);
    let key = key(200, 201, 202, 7);
    execute(&mut store, fixture.caller, 1, initialize_operation(key));
    let intent = reserve(&mut store, fixture.caller, key, 2);
    let valid = seal_evidence(&intent, FreezeDisposition::ReadyToCommit, 0);
    let operation = |proposal: &SealProposalV1| {
        wire::Operation::Seal(wire::DecisionProposal {
            key,
            expected_state_sequence: 1,
            proposal: encode_seal_proposal(proposal).expect("seal proposal"),
        })
    };

    let mut untrusted = valid.proposal.clone();
    let mut untrusted_visa: VisaFreezeReceipt =
        canonical_from_bytes(&untrusted.visa_freeze.payload.bytes).expect("typed Visa receipt");
    let untrusted_issuer = issuer(700);
    untrusted_visa.header.issuer = untrusted_issuer.issuer;
    untrusted_visa.header.issuer_incarnation = untrusted_issuer.issuer_incarnation;
    untrusted_visa.header.key_id = untrusted_issuer.key_id;
    untrusted_visa.header.log_id = untrusted_issuer.log_id;
    untrusted.visa_freeze = receipt_artifact(&untrusted_visa).expect("untrusted Visa artifact");
    let (_, denied, denied_bytes) = execute(&mut store, fixture.caller, 3, operation(&untrusted));
    assert_eq!(denied.outcome, wire::Outcome::Rejected(wire::Rejection::InvalidRequest));
    let (_, denied_request_bytes) = request(fixture.caller, 3, operation(&untrusted));
    assert_eq!(
        store
            .execute_exact(fixture.caller, &denied_request_bytes)
            .expect("replay rejected response"),
        denied_bytes
    );

    let blocked =
        seal_evidence(&intent, FreezeDisposition::Blocked { blocker_digest: digest(99) }, 1);
    let (_, blocked_response, _) =
        execute(&mut store, fixture.caller, 4, operation(&blocked.proposal));
    assert_eq!(blocked_response.outcome, wire::Outcome::Rejected(wire::Rejection::InvalidRequest));

    let mut invalid_body = valid.proposal.clone();
    let mut invalid_nexus: NexusFreezeReceipt =
        canonical_from_bytes(&invalid_body.nexus_freeze.payload.bytes)
            .expect("typed Nexus receipt");
    invalid_nexus.registry_instance = Identity::ZERO;
    invalid_body.nexus_freeze =
        receipt_artifact(&invalid_nexus).expect("invalid-body Nexus artifact");
    let (_, invalid_body_response, _) =
        execute(&mut store, fixture.caller, 5, operation(&invalid_body));
    assert_eq!(
        invalid_body_response.outcome,
        wire::Outcome::Rejected(wire::Rejection::InvalidRequest)
    );

    let mut mismatched = valid.proposal.clone();
    mismatched.bindings.profile_digest = digest(98);
    let (_, mismatch_response, _) = execute(&mut store, fixture.caller, 6, operation(&mismatched));
    assert_eq!(mismatch_response.outcome, wire::Outcome::Rejected(wire::Rejection::InvalidRequest));

    let (_, query_response, _) = execute(
        &mut store,
        fixture.caller,
        7,
        wire::Operation::Query(wire::QueryRequest::Handoff(key.handoff)),
    );
    assert!(matches!(
        query_response.outcome,
        wire::Outcome::Success(wire::Success::Query(wire::QueryResult::Reserved(_)))
    ));

    let (_, prepared, _) = execute(&mut store, fixture.caller, 8, operation(&valid.proposal));
    assert!(matches!(prepared.outcome, wire::Outcome::Success(wire::Success::Prepared(_))));
}

#[test]
fn commit_is_terminal_replays_after_restart_and_updates_owner() {
    let fixture = TestFixture::new();
    let mut store = fixture.create(20);
    let key = key(200, 201, 202, 7);
    execute(&mut store, fixture.caller, 1, initialize_operation(key));
    let (commit_request_bytes, commit_response_bytes, committed) =
        complete_handoff(&mut store, fixture.caller, key, 10);
    let committed_receipt: joint_handoff_core::OwnershipCommitReceipt =
        canonical_from_bytes(&committed.payload.bytes).expect("typed commit receipt");

    let abort = wire::Operation::Abort(wire::DecisionProposal {
        key,
        expected_state_sequence: 3,
        proposal: encode_abort_proposal(&AbortProposalV1 {
            version: joint_handoff_core::JOINT_PROTOCOL_VERSION,
            reservation: committed_receipt.reservation,
            basis: committed.clone(),
        })
        .expect("abort proposal"),
    });
    let (_, abort_response, _) = execute(&mut store, fixture.caller, 20, abort);
    assert!(matches!(
        abort_response.outcome,
        wire::Outcome::Rejected(wire::Rejection::ExistingCommit(ref receipt))
            if receipt == &committed
    ));

    let (_, unit_response, _) = execute(
        &mut store,
        fixture.caller,
        21,
        wire::Operation::Query(wire::QueryRequest::Unit(key.continuity_unit)),
    );
    assert!(matches!(
        unit_response.outcome,
        wire::Outcome::Success(wire::Success::Query(wire::QueryResult::Unit(value)))
            if value.owner == key.destination
                && value.epoch == key.next_epoch
                && value.active_handoff.is_none()
    ));
    drop(store);

    let mut reopened = fixture.reopen(21);
    assert_eq!(
        reopened
            .execute_exact(fixture.caller, &commit_request_bytes)
            .expect("exact terminal replay"),
        commit_response_bytes
    );
}

#[test]
fn abort_from_reserved_is_terminal_and_non_equivocating() {
    let fixture = TestFixture::new();
    let mut store = fixture.create(20);
    let key = key(200, 201, 202, 7);
    execute(&mut store, fixture.caller, 1, initialize_operation(key));
    let intent = reserve(&mut store, fixture.caller, key, 2);
    let typed_intent: PrepareIntentReceipt =
        canonical_from_bytes(&intent.payload.bytes).expect("typed intent");
    let abort_operation = wire::Operation::Abort(wire::DecisionProposal {
        key,
        expected_state_sequence: 1,
        proposal: encode_abort_proposal(&AbortProposalV1 {
            version: joint_handoff_core::JOINT_PROTOCOL_VERSION,
            reservation: typed_intent.reservation,
            basis: intent.clone(),
        })
        .expect("abort proposal"),
    });
    let (_, aborted_response, _) = execute(&mut store, fixture.caller, 3, abort_operation);
    let aborted = receipt_from_outcome(&aborted_response.outcome);

    let commit_operation = wire::Operation::Commit(wire::DecisionProposal {
        key,
        expected_state_sequence: 2,
        proposal: encode_commit_proposal(&CommitProposalV1 {
            version: joint_handoff_core::JOINT_PROTOCOL_VERSION,
            reservation: typed_intent.reservation,
            prepared: intent,
        })
        .expect("commit proposal"),
    });
    let (_, commit_response, _) = execute(&mut store, fixture.caller, 4, commit_operation);
    assert!(matches!(
        commit_response.outcome,
        wire::Outcome::Rejected(wire::Rejection::ExistingAbort(ref receipt))
            if receipt == &aborted
    ));

    let (_, unit_response, _) = execute(
        &mut store,
        fixture.caller,
        5,
        wire::Operation::Query(wire::QueryRequest::Unit(key.continuity_unit)),
    );
    assert!(matches!(
        unit_response.outcome,
        wire::Outcome::Success(wire::Success::Query(wire::QueryResult::Unit(value)))
            if value.owner == key.source
                && value.epoch == key.expected_epoch
                && value.active_handoff.is_none()
    ));
    drop(store);
    drop(fixture.reopen(21));
}

#[test]
fn two_committed_epochs_survive_restart_history_audit() {
    let fixture = TestFixture::new();
    let mut store = fixture.create(20);
    let first = key(200, 201, 202, 7);
    execute(&mut store, fixture.caller, 1, initialize_operation(first));
    complete_handoff(&mut store, fixture.caller, first, 10);
    let second = key(300, 202, 203, 8);
    complete_handoff(&mut store, fixture.caller, second, 20);
    drop(store);

    let mut reopened = fixture.reopen(21);
    let (_, response, _) = execute(
        &mut reopened,
        fixture.caller,
        30,
        wire::Operation::Query(wire::QueryRequest::Unit(second.continuity_unit)),
    );
    assert!(matches!(
        response.outcome,
        wire::Outcome::Success(wire::Success::Query(wire::QueryResult::Unit(value)))
            if value.owner == second.destination && value.epoch == second.next_epoch
    ));
}

#[test]
fn capacity_failure_rolls_back_authority_mutation() {
    let mut fixture = TestFixture::new();
    fixture.limits.max_exchanges = 1;
    let mut store = fixture.create(20);
    let key = key(200, 201, 202, 7);
    execute(&mut store, fixture.caller, 1, initialize_operation(key));
    let (_, reserve_bytes) = request(fixture.caller, 2, reserve_operation(key));
    assert_eq!(
        store.execute_exact(fixture.caller, &reserve_bytes),
        Err(OwnershipServiceError::Capacity)
    );
    drop(store);
    let connection = Connection::open(&fixture.database_path).expect("inspect database");
    let handoffs: i64 = connection
        .query_row("SELECT count(*) FROM ownership_handoff", [], |row| row.get(0))
        .expect("handoff count");
    assert_eq!(handoffs, 0);
}

#[test]
fn corrupted_replay_and_unexpected_schema_objects_fail_closed() {
    let fixture = TestFixture::new();
    let mut store = fixture.create(20);
    let key = key(200, 201, 202, 7);
    execute(&mut store, fixture.caller, 1, initialize_operation(key));
    drop(store);
    let connection = Connection::open(&fixture.database_path).expect("open database for fault");
    connection
        .execute(
            "UPDATE rpc_exchange SET response_bytes = zeroblob(length(response_bytes))
             WHERE request_id = ?1",
            [RequestId::from_u128(1).0.as_slice()],
        )
        .expect("corrupt stored response");
    drop(connection);
    assert!(matches!(
        AuthorityStore::open(
            &fixture.database_path,
            fixture.bootstrap(None, 21),
            fixture.authenticator()
        ),
        Err(OwnershipServiceError::Integrity)
    ));

    let clean = TestFixture::new();
    drop(clean.create(20));
    let connection = Connection::open(&clean.database_path).expect("open schema");
    connection
        .execute_batch("CREATE VIEW unexpected_authority_view AS SELECT 1 AS value;")
        .expect("add unexpected schema object");
    drop(connection);
    assert!(matches!(
        AuthorityStore::open(
            &clean.database_path,
            clean.bootstrap(None, 21),
            clean.authenticator()
        ),
        Err(OwnershipServiceError::Integrity)
    ));

    let weakened = TestFixture::new();
    drop(weakened.create(20));
    let connection = Connection::open(&weakened.database_path).expect("open schema for fault");
    connection
        .execute_batch(
            "PRAGMA writable_schema = ON;
             UPDATE sqlite_schema
             SET sql = replace(sql, ') STRICT', ')')
             WHERE name = 'rpc_exchange';
             PRAGMA writable_schema = OFF;",
        )
        .expect("weaken strict table schema");
    drop(connection);
    assert!(matches!(
        AuthorityStore::open(
            &weakened.database_path,
            weakened.bootstrap(None, 21),
            weakened.authenticator()
        ),
        Err(OwnershipServiceError::Integrity)
    ));
}

#[test]
fn replay_completion_order_is_gap_free() {
    let fixture = TestFixture::new();
    let mut store = fixture.create(20);
    let key = key(200, 201, 202, 7);
    execute(&mut store, fixture.caller, 1, initialize_operation(key));
    execute(
        &mut store,
        fixture.caller,
        2,
        wire::Operation::Query(wire::QueryRequest::Unit(key.continuity_unit)),
    );
    drop(store);

    let connection = Connection::open(&fixture.database_path).expect("open database for fault");
    connection
        .execute("UPDATE rpc_exchange SET completion_order = 3 WHERE completion_order = 2", [])
        .expect("create completion gap");
    drop(connection);
    assert!(matches!(
        AuthorityStore::open(
            &fixture.database_path,
            fixture.bootstrap(None, 21),
            fixture.authenticator()
        ),
        Err(OwnershipServiceError::Integrity)
    ));
}

#[test]
fn replay_ledger_must_reconstruct_the_exact_authority_projection() {
    let fixture = TestFixture::new();
    let mut store = fixture.create(20);
    let key = key(200, 201, 202, 7);
    execute(&mut store, fixture.caller, 1, initialize_operation(key));
    reserve(&mut store, fixture.caller, key, 2);
    drop(store);

    let connection = Connection::open(&fixture.database_path).expect("open database for fault");
    connection.execute("DELETE FROM rpc_exchange", []).expect("remove exact replay ledger");
    drop(connection);
    assert!(matches!(
        AuthorityStore::open(
            &fixture.database_path,
            fixture.bootstrap(None, 21),
            fixture.authenticator()
        ),
        Err(OwnershipServiceError::Integrity)
    ));
}

#[test]
fn replay_responses_remain_bound_to_the_persisted_service_incarnation() {
    let fixture = TestFixture::new();
    let mut store = fixture.create(20);
    let key = key(200, 201, 202, 7);
    execute(&mut store, fixture.caller, 1, initialize_operation(key));
    drop(store);

    rewrite_first_response_server(&fixture.database_path, |server| {
        server.service_incarnation = ServiceIncarnation::from_u128(999);
    });
    assert!(matches!(
        AuthorityStore::open(
            &fixture.database_path,
            fixture.bootstrap(None, 21),
            fixture.authenticator()
        ),
        Err(OwnershipServiceError::Integrity)
    ));
}

#[test]
fn replay_responses_remain_bound_to_the_exact_process_history() {
    let changed_nonce = TestFixture::new();
    let mut store = changed_nonce.create(20);
    let key = key(200, 201, 202, 7);
    execute(&mut store, changed_nonce.caller, 1, initialize_operation(key));
    drop(store);
    rewrite_first_response_server(&changed_nonce.database_path, |server| {
        server.process_nonce = ProcessNonce::from_u128(999);
    });
    assert!(matches!(
        AuthorityStore::open(
            &changed_nonce.database_path,
            changed_nonce.bootstrap(None, 21),
            changed_nonce.authenticator()
        ),
        Err(OwnershipServiceError::Integrity)
    ));

    let changed_existing_pair = TestFixture::new();
    let mut store = changed_existing_pair.create(20);
    execute(&mut store, changed_existing_pair.caller, 1, initialize_operation(key));
    drop(store);
    drop(changed_existing_pair.reopen(21));
    rewrite_first_response_server(&changed_existing_pair.database_path, |server| {
        server.process_generation = 2;
        server.process_nonce = ProcessNonce::from_u128(21);
    });
    assert!(matches!(
        AuthorityStore::open(
            &changed_existing_pair.database_path,
            changed_existing_pair.bootstrap(None, 22),
            changed_existing_pair.authenticator()
        ),
        Err(OwnershipServiceError::Integrity)
    ));
}

#[test]
fn process_history_retains_zero_request_generations_without_gaps() {
    let retained = TestFixture::new();
    drop(retained.create(20));
    drop(retained.reopen(21));
    let mut third_process = retained.reopen(22);
    let key = key(200, 201, 202, 7);
    execute(&mut third_process, retained.caller, 1, initialize_operation(key));
    drop(third_process);
    drop(retained.reopen(23));

    let fixture = TestFixture::new();
    drop(fixture.create(20));
    drop(fixture.reopen(21));
    drop(fixture.reopen(22));

    let connection = Connection::open(&fixture.database_path).expect("open process history");
    connection
        .execute("DELETE FROM process_instance WHERE process_generation = 2", [])
        .expect("remove zero-request process generation");
    drop(connection);
    assert!(matches!(
        AuthorityStore::open(
            &fixture.database_path,
            fixture.bootstrap(None, 23),
            fixture.authenticator()
        ),
        Err(OwnershipServiceError::Integrity)
    ));
}
