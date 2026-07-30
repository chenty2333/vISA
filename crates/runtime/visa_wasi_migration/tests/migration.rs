use std::{
    cell::{Cell, RefCell},
    fs,
    path::Path,
    rc::Rc,
};

use serde::Serialize;
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;
use visa_wasi_migration::{
    BuildIdentity, CanonicalCommitProof, CanonicalFenceProof, CanonicalProofVerifier,
    CanonicalRecovery, CanonicalSourceRetainedProof, ComputeControl, Driver, DriverRecord,
    DriverRecordStore, FileDriverRecordStore, FileRoles, MigrationError, MigrationIntent,
    MigrationManifest, Phase, PlatformIdentity, ProviderMode, ProviderProjection,
    ProviderProjectionStatus,
};
use visa_wasi_protocol::{BarrierToken, ClientId, OwnerId, SessionId};

const SESSION: SessionId = SessionId([1; 16]);
const OWNER: OwnerId = OwnerId([2; 16]);
const HANDOFF: [u8; 16] = [3; 16];
const CHECKPOINT_BARRIER: BarrierToken = BarrierToken([7; 16]);
const SOURCE_CLIENT: ClientId = ClientId([4; 16]);
const DESTINATION_CLIENT: ClientId = ClientId([5; 16]);
const SOURCE_RESTORE_CLIENT: ClientId = ClientId([6; 16]);
const SOURCE_EPOCH: u64 = 11;
const DESTINATION_EPOCH: u64 = 12;

type Log = Rc<RefCell<Vec<&'static str>>>;
type CommitMutation = Box<dyn Fn(&mut CanonicalCommitProof)>;

struct FailingStore {
    inner: FileDriverRecordStore,
    fail_generation: Rc<Cell<Option<u64>>>,
}

impl DriverRecordStore for FailingStore {
    fn load(&mut self) -> Result<Option<DriverRecord>, MigrationError> {
        self.inner.load()
    }

    fn save(&mut self, record: &DriverRecord) -> Result<(), MigrationError> {
        if self.fail_generation.get() == Some(record.generation) {
            self.fail_generation.set(None);
            return Err(MigrationError::Durability("injected record fsync failure".to_owned()));
        }
        self.inner.save(record)
    }
}

#[derive(Clone)]
struct FakeCompute {
    log: Log,
}

impl ComputeControl for FakeCompute {
    fn confirm_source_exit(&mut self, _: &MigrationIntent) -> Result<(), MigrationError> {
        self.log.borrow_mut().push("compute-exit");
        Ok(())
    }

    fn restore_destination(&mut self, _: &MigrationManifest) -> Result<(), MigrationError> {
        self.log.borrow_mut().push("compute-restore");
        Ok(())
    }

    fn restore_source(&mut self, _: &MigrationIntent) -> Result<(), MigrationError> {
        self.log.borrow_mut().push("source-compute-restore");
        Ok(())
    }
}

#[derive(Clone)]
struct FakeProvider {
    log: Log,
    session: SessionId,
}

impl FakeProvider {
    fn status(&self, mode: ProviderMode, authority_epoch: u64) -> ProviderProjectionStatus {
        ProviderProjectionStatus { session: self.session, mode, authority_epoch }
    }
}

impl ProviderProjection for FakeProvider {
    fn freeze_source(
        &mut self,
        _: &MigrationIntent,
    ) -> Result<ProviderProjectionStatus, MigrationError> {
        self.log.borrow_mut().push("provider-freeze");
        Ok(self.status(ProviderMode::Frozen, SOURCE_EPOCH))
    }

    fn export_source_capsule(&mut self, _: &MigrationIntent) -> Result<(), MigrationError> {
        self.log.borrow_mut().push("provider-export");
        Ok(())
    }

    fn restore_destination_prepared(
        &mut self,
        _: &MigrationManifest,
    ) -> Result<ProviderProjectionStatus, MigrationError> {
        self.log.borrow_mut().push("provider-prepare");
        Ok(self.status(ProviderMode::Prepared, SOURCE_EPOCH))
    }

    fn fence_source(
        &mut self,
        _: &MigrationManifest,
    ) -> Result<ProviderProjectionStatus, MigrationError> {
        self.log.borrow_mut().push("provider-fence");
        Ok(self.status(ProviderMode::Fenced, SOURCE_EPOCH))
    }

    fn activate_destination(
        &mut self,
        _: &MigrationManifest,
    ) -> Result<ProviderProjectionStatus, MigrationError> {
        self.log.borrow_mut().push("provider-activate");
        Ok(self.status(ProviderMode::Active, DESTINATION_EPOCH))
    }

    fn resume_source(
        &mut self,
        _: &MigrationIntent,
    ) -> Result<ProviderProjectionStatus, MigrationError> {
        self.log.borrow_mut().push("provider-resume");
        Ok(self.status(ProviderMode::Active, SOURCE_EPOCH))
    }
}

#[derive(Clone)]
struct ReceiptVerifier {
    log: Log,
    canonical: Rc<RefCell<CanonicalRecovery>>,
}

impl CanonicalProofVerifier for ReceiptVerifier {
    fn verify_ownership_commit(
        &self,
        manifest: &MigrationManifest,
        proof: &CanonicalCommitProof,
        artifact_root: &Path,
    ) -> Result<(), MigrationError> {
        self.log.borrow_mut().push("verify-commit");
        let canonical_receipt = proof.verify_binding(manifest, artifact_root)?;
        if fs::read(canonical_receipt).map_err(MigrationError::Io)? != b"canonical commit" {
            return Err(MigrationError::Proof("commit receipt was not canonical"));
        }
        let mut canonical = self.canonical.borrow_mut();
        match &*canonical {
            CanonicalRecovery::Uncommitted => {
                *canonical = CanonicalRecovery::OwnershipCommitted(Box::new(proof.clone()));
                Ok(())
            }
            CanonicalRecovery::OwnershipCommitted(existing) if **existing == *proof => Ok(()),
            CanonicalRecovery::SourceFenced { commit, .. } if **commit == *proof => Ok(()),
            CanonicalRecovery::SourceRetained(_) => Err(MigrationError::Proof(
                "source-retained authority decision already won terminal CAS",
            )),
            _ => Err(MigrationError::Proof("conflicting canonical ownership commit")),
        }
    }

    fn verify_source_fence(
        &self,
        manifest: &MigrationManifest,
        commit: &CanonicalCommitProof,
        fence: &CanonicalFenceProof,
        artifact_root: &Path,
    ) -> Result<(), MigrationError> {
        self.log.borrow_mut().push("verify-fence");
        let canonical_receipt = fence.verify_binding(manifest, commit, artifact_root)?;
        if fs::read(canonical_receipt).map_err(MigrationError::Io)? != b"canonical fence" {
            return Err(MigrationError::Proof("fence receipt was not canonical"));
        }
        let mut canonical = self.canonical.borrow_mut();
        match &*canonical {
            CanonicalRecovery::OwnershipCommitted(existing) if **existing == *commit => {
                *canonical = CanonicalRecovery::SourceFenced {
                    commit: Box::new(commit.clone()),
                    fence: Box::new(fence.clone()),
                };
                Ok(())
            }
            CanonicalRecovery::SourceFenced { commit: existing_commit, fence: existing_fence }
                if **existing_commit == *commit && **existing_fence == *fence =>
            {
                Ok(())
            }
            CanonicalRecovery::SourceRetained(_) => Err(MigrationError::Proof(
                "source-retained authority decision excludes source fencing",
            )),
            _ => Err(MigrationError::Proof("conflicting canonical source fence")),
        }
    }

    fn claim_source_retained(
        &self,
        manifest: &MigrationManifest,
        root: &Path,
    ) -> Result<CanonicalSourceRetainedProof, MigrationError> {
        self.log.borrow_mut().push("claim-source-retained");
        let proof = CanonicalSourceRetainedProof::bind_receipt(
            manifest,
            root,
            "proofs/source-retained.receipt",
        )?;
        let mut canonical = self.canonical.borrow_mut();
        match &*canonical {
            CanonicalRecovery::Uncommitted => {
                *canonical = CanonicalRecovery::SourceRetained(Box::new(proof.clone()));
                Ok(proof)
            }
            CanonicalRecovery::SourceRetained(existing) if **existing == proof => Ok(proof),
            CanonicalRecovery::OwnershipCommitted(_) | CanonicalRecovery::SourceFenced { .. } => {
                Err(MigrationError::Proof("canonical ownership commit excludes source retention"))
            }
            _ => Err(MigrationError::Proof("conflicting source-retained proof")),
        }
    }

    fn recover_canonical_state(
        &self,
        _: &MigrationManifest,
        _: &Path,
    ) -> Result<CanonicalRecovery, MigrationError> {
        self.log.borrow_mut().push("recover-authority");
        Ok(self.canonical.borrow().clone())
    }
}

struct Fixture {
    temporary: TempDir,
    intent: MigrationIntent,
}

#[derive(Serialize)]
struct TestCapsuleManifest {
    schema: &'static str,
    session_hex: String,
    source_epoch: u64,
    destination_epoch: u64,
    handoff_hex: String,
    state_file: &'static str,
    state_size: u64,
    state_sha256: String,
}

impl Fixture {
    fn new(state_seed: u8) -> Self {
        Self::with_capsule_schema(state_seed, "visa-wasi-filesystem-capsule-v2")
    }

    fn with_capsule_schema(state_seed: u8, capsule_schema: &'static str) -> Self {
        let temporary = tempfile::tempdir().expect("temporary root");
        fs::create_dir(temporary.path().join("artifacts")).expect("artifact directory");
        fs::create_dir(temporary.path().join("capsule")).expect("capsule directory");
        fs::create_dir(temporary.path().join("proofs")).expect("proof directory");
        fs::write(temporary.path().join("artifacts/application.wasm"), b"stock application")
            .expect("application");
        let checkpoint = (0..(400 * 1024)).map(|index| (index % 251) as u8).collect::<Vec<_>>();
        fs::write(temporary.path().join("artifacts/checkpoint.bin"), checkpoint)
            .expect("checkpoint");
        let state = vec![state_seed; 150_001];
        fs::write(temporary.path().join("capsule/state.sqlite"), &state).expect("state");
        let capsule = TestCapsuleManifest {
            schema: capsule_schema,
            session_hex: hex(&SESSION.0),
            source_epoch: SOURCE_EPOCH,
            destination_epoch: DESTINATION_EPOCH,
            handoff_hex: hex(&HANDOFF),
            state_file: "state.sqlite",
            state_size: state.len() as u64,
            state_sha256: sha256(&state),
        };
        fs::write(
            temporary.path().join("capsule/manifest.json"),
            serde_json::to_vec_pretty(&capsule).expect("capsule manifest"),
        )
        .expect("capsule manifest file");
        fs::write(temporary.path().join("proofs/commit.receipt"), b"canonical commit")
            .expect("commit receipt");
        fs::write(temporary.path().join("proofs/fence.receipt"), b"canonical fence")
            .expect("fence receipt");
        fs::write(
            temporary.path().join("proofs/source-retained.receipt"),
            b"canonical source retained",
        )
        .expect("source-retained receipt");
        Self { temporary, intent: intent() }
    }

    fn root(&self) -> &Path {
        self.temporary.path()
    }

    fn record_path(&self) -> std::path::PathBuf {
        self.temporary.path().join("driver/record.json")
    }
}

fn intent() -> MigrationIntent {
    MigrationIntent {
        files: FileRoles {
            application: "artifacts/application.wasm".to_owned(),
            compute_checkpoint: "artifacts/checkpoint.bin".to_owned(),
            resource_capsule_manifest: "capsule/manifest.json".to_owned(),
            resource_capsule_state: "capsule/state.sqlite".to_owned(),
        },
        session: SESSION,
        stable_owner: OWNER,
        handoff: HANDOFF,
        checkpoint_barrier: CHECKPOINT_BARRIER,
        source_epoch: SOURCE_EPOCH,
        destination_epoch: DESTINATION_EPOCH,
        source_client: SOURCE_CLIENT,
        source_restore_client: SOURCE_RESTORE_CLIENT,
        destination_client: DESTINATION_CLIENT,
        application_build: BuildIdentity {
            source_revision: "0123456789abcdef".to_owned(),
            toolchain: "wasi-sdk-29".to_owned(),
            build_configuration_sha256: sha256(b"build"),
        },
        source_platform: platform("source"),
        destination_platform: platform("destination"),
    }
}

fn platform(label: &str) -> PlatformIdentity {
    PlatformIdentity {
        operating_system: "linux".to_owned(),
        architecture: "x86_64".to_owned(),
        abi: "wasm32-wasi-preview1".to_owned(),
        runtime_name: "carrier".to_owned(),
        runtime_version: label.to_owned(),
        runtime_build_sha256: sha256(label.as_bytes()),
    }
}

type TestDriver = Driver<FakeCompute, FakeProvider, ReceiptVerifier, FileDriverRecordStore>;

fn driver(fixture: &Fixture) -> TestDriver {
    let log = Rc::new(RefCell::new(Vec::new()));
    let canonical = Rc::new(RefCell::new(CanonicalRecovery::Uncommitted));
    Driver::new(
        fixture.intent.clone(),
        FakeCompute { log: Rc::clone(&log) },
        FakeProvider { log: Rc::clone(&log), session: SESSION },
        ReceiptVerifier { log, canonical },
        FileDriverRecordStore::acquire(fixture.record_path()).expect("record store"),
    )
    .expect("valid driver")
}

fn prepared_driver(fixture: &Fixture) -> TestDriver {
    let mut driver = driver(fixture);
    driver.confirm_source_compute_exit().expect("exit");
    driver.freeze_source().expect("freeze");
    driver.export_source_capsule().expect("export");
    driver.seal_manifest(fixture.root()).expect("seal");
    driver.restore_destination_prepared().expect("prepare");
    driver
}

fn commit_proof(driver: &TestDriver, root: &Path) -> CanonicalCommitProof {
    CanonicalCommitProof::bind_receipt(
        driver.manifest().expect("manifest"),
        root,
        "proofs/commit.receipt",
    )
    .expect("commit proof")
}

fn fence_proof(
    driver: &TestDriver,
    commit: &CanonicalCommitProof,
    root: &Path,
) -> CanonicalFenceProof {
    CanonicalFenceProof::bind_receipt(
        driver.manifest().expect("manifest"),
        commit,
        root,
        "proofs/fence.receipt",
    )
    .expect("fence proof")
}

#[test]
fn native_restore_processes_have_pairwise_distinct_client_identities() {
    let fixture = Fixture::new(7);
    let manifest = MigrationManifest::seal(&fixture.intent, fixture.root()).expect("manifest");
    assert_eq!(manifest.clients.source_restore_client_hex, hex(&SOURCE_RESTORE_CLIENT.0));

    for duplicate in [SOURCE_CLIENT, DESTINATION_CLIENT] {
        let mut changed = fixture.intent.clone();
        changed.source_restore_client = duplicate;
        assert!(matches!(
            MigrationManifest::seal(&changed, fixture.root()),
            Err(MigrationError::Invalid(
                "source, source-restore, and destination clients must be distinct"
            ))
        ));
    }
}

#[test]
fn complete_flow_obeys_the_canonical_fence_before_activation_order() {
    let fixture = Fixture::new(7);
    let mut driver = prepared_driver(&fixture);
    let commit = commit_proof(&driver, fixture.root());
    driver.record_ownership_commit(commit.clone(), fixture.root()).expect("commit");
    driver.record_ownership_commit(commit.clone(), fixture.root()).expect("duplicate commit");
    let fence = fence_proof(&driver, &commit, fixture.root());
    driver.fence_source(fence.clone(), fixture.root()).expect("fence");
    driver.fence_source(fence, fixture.root()).expect("duplicate fence");
    driver.activate_destination().expect("activate");
    driver.activate_destination().expect("duplicate activate");
    driver.restore_compute().expect("restore");
    driver.restore_compute().expect("duplicate restore");
    assert_eq!(driver.phase(), Phase::ComputeRestored);

    let (compute, _, _, _) = driver.into_parts();
    assert_eq!(
        compute.log.borrow().as_slice(),
        [
            "compute-exit",
            "provider-freeze",
            "provider-export",
            "provider-prepare",
            "verify-commit",
            "verify-fence",
            "provider-fence",
            "provider-activate",
            "compute-restore",
        ]
    );
}

#[test]
fn checkpoint_digest_tamper_is_rejected_independently() {
    let fixture = Fixture::new(8);
    let manifest = MigrationManifest::seal(&fixture.intent, fixture.root()).expect("seal");
    fs::write(fixture.root().join("artifacts/checkpoint.bin"), b"forged checkpoint")
        .expect("tamper");
    assert!(matches!(
        manifest.verify_at(fixture.root()),
        Err(MigrationError::Integrity("bound file content differs"))
    ));
}

#[test]
fn provider_manifest_and_database_cross_pair_swap_is_rejected() {
    let fixture = Fixture::new(9);
    fs::write(fixture.root().join("capsule/state.sqlite"), vec![10_u8; 150_001])
        .expect("swap state");
    assert!(matches!(
        MigrationManifest::seal(&fixture.intent, fixture.root()),
        Err(MigrationError::Integrity("provider capsule binding differs from migration manifest"))
    ));
}

#[test]
fn legacy_v1_provider_capsule_is_rejected() {
    let fixture = Fixture::with_capsule_schema(10, "visa-wasi-filesystem-capsule-v1");
    assert!(matches!(
        MigrationManifest::seal(&fixture.intent, fixture.root()),
        Err(MigrationError::Integrity("provider capsule binding differs from migration manifest"))
    ));
}

#[test]
fn commit_rejects_wrong_session_owner_handoff_and_epoch() {
    let mut mutations: Vec<CommitMutation> = vec![
        Box::new(|proof| proof.session_hex = hex(&[21; 16])),
        Box::new(|proof| proof.stable_owner_hex = hex(&[22; 16])),
        Box::new(|proof| proof.handoff_hex = hex(&[23; 16])),
        Box::new(|proof| proof.destination_epoch += 1),
    ];
    for mutate in mutations.drain(..) {
        let fixture = Fixture::new(11);
        let mut driver = prepared_driver(&fixture);
        let mut proof = commit_proof(&driver, fixture.root());
        mutate(&mut proof);
        assert!(matches!(
            driver.record_ownership_commit(proof, fixture.root()),
            Err(MigrationError::Proof("ownership commit proof binding differs"))
        ));
        assert_eq!(driver.phase(), Phase::DestinationPrepared);
    }
}

#[test]
fn activation_before_commit_or_fence_is_fail_closed() {
    let fixture = Fixture::new(12);
    let mut driver = prepared_driver(&fixture);
    assert!(matches!(driver.activate_destination(), Err(MigrationError::Transition { .. })));
    let commit = commit_proof(&driver, fixture.root());
    driver.record_ownership_commit(commit, fixture.root()).expect("commit");
    assert!(matches!(driver.activate_destination(), Err(MigrationError::Transition { .. })));
    assert_eq!(driver.phase(), Phase::OwnershipCommitted);
}

#[test]
fn fence_is_bound_to_the_exact_commit_and_rejects_pair_swap() {
    let fixture = Fixture::new(13);
    let mut driver = prepared_driver(&fixture);
    let commit = commit_proof(&driver, fixture.root());
    let fence = fence_proof(&driver, &commit, fixture.root());
    driver.record_ownership_commit(commit.clone(), fixture.root()).expect("commit");
    let mut swapped_commit = commit;
    swapped_commit.canonical_receipt.sha256 = sha256(b"different");
    assert!(matches!(
        fence.verify_binding(driver.manifest().expect("manifest"), &swapped_commit, fixture.root()),
        Err(MigrationError::Proof("source fence proof binding differs"))
    ));
}

#[test]
fn canonical_receipt_digest_tamper_is_rejected_before_authenticity_verification() {
    let fixture = Fixture::new(18);
    let mut driver = prepared_driver(&fixture);
    let proof = commit_proof(&driver, fixture.root());
    fs::write(fixture.root().join("proofs/commit.receipt"), b"forged receipt").expect("tamper");
    assert!(matches!(
        driver.record_ownership_commit(proof, fixture.root()),
        Err(MigrationError::Integrity("bound file content differs"))
    ));
    assert_eq!(driver.phase(), Phase::DestinationPrepared);
}

#[test]
fn duplicate_steps_and_precommit_resume_are_idempotent() {
    let fixture = Fixture::new(14);
    let mut driver = driver(&fixture);
    driver.confirm_source_compute_exit().expect("exit");
    driver.confirm_source_compute_exit().expect("duplicate exit");
    driver.freeze_source().expect("freeze");
    driver.freeze_source().expect("duplicate freeze");
    driver.export_source_capsule().expect("export");
    driver.export_source_capsule().expect("duplicate export");
    driver.seal_manifest(fixture.root()).expect("seal");
    driver.restore_destination_prepared().expect("prepare");
    driver.resume_source(fixture.root()).expect("resume");
    driver.resume_source(fixture.root()).expect("duplicate resume");
    assert_eq!(driver.phase(), Phase::SourceResumed);
    let (compute, _, _, _) = driver.into_parts();
    assert_eq!(
        compute.log.borrow().as_slice(),
        [
            "compute-exit",
            "provider-freeze",
            "provider-export",
            "provider-prepare",
            "claim-source-retained",
            "provider-resume",
            "source-compute-restore"
        ]
    );
}

#[test]
fn resume_after_canonical_commit_is_rejected() {
    let fixture = Fixture::new(15);
    let mut driver = prepared_driver(&fixture);
    let commit = commit_proof(&driver, fixture.root());
    driver.record_ownership_commit(commit, fixture.root()).expect("commit");
    assert!(matches!(driver.resume_source(fixture.root()), Err(MigrationError::Proof(_))));
}

#[test]
fn wrong_provider_session_does_not_advance_the_driver() {
    let fixture = Fixture::new(16);
    let log = Rc::new(RefCell::new(Vec::new()));
    let canonical = Rc::new(RefCell::new(CanonicalRecovery::Uncommitted));
    let mut driver = Driver::new(
        fixture.intent.clone(),
        FakeCompute { log: Rc::clone(&log) },
        FakeProvider { log, session: SessionId([99; 16]) },
        ReceiptVerifier { log: Rc::new(RefCell::new(Vec::new())), canonical },
        FileDriverRecordStore::acquire(fixture.record_path()).expect("record store"),
    )
    .expect("driver");
    driver.confirm_source_compute_exit().expect("exit");
    assert!(matches!(
        driver.freeze_source(),
        Err(MigrationError::Integrity("provider projection returned the wrong session"))
    ));
    assert_eq!(driver.phase(), Phase::SourceComputeExited);
}

#[test]
fn semantic_paths_and_noncanonical_manifest_encodings_are_rejected() {
    let fixture = Fixture::new(17);
    let mut absolute = fixture.intent.clone();
    absolute.files.application =
        fixture.root().join("artifacts/application.wasm").display().to_string();
    assert!(matches!(
        absolute.validate(),
        Err(MigrationError::Invalid("non-canonical semantic path"))
    ));

    let manifest = MigrationManifest::seal(&fixture.intent, fixture.root()).expect("manifest");
    let canonical = manifest.canonical_bytes().expect("canonical");
    assert_eq!(MigrationManifest::decode_canonical(&canonical).expect("decode"), manifest);
    let pretty = serde_json::to_vec_pretty(&manifest).expect("pretty");
    assert!(matches!(
        MigrationManifest::decode_canonical(&pretty),
        Err(MigrationError::Integrity("migration manifest is not canonical RFC 8785 JSON"))
    ));
}

#[test]
fn restart_replays_provider_resume_then_restores_source_compute() {
    restart_abort_after_failed_completion_save(14, 2, 1);
}

#[test]
fn restart_recovers_source_retention_after_the_terminal_cas_save_is_lost() {
    let fixture = Fixture::new(30);
    let log = Rc::new(RefCell::new(Vec::new()));
    let canonical = Rc::new(RefCell::new(CanonicalRecovery::Uncommitted));
    let fail_generation = Rc::new(Cell::new(Some(12)));
    let mut driver = Driver::new(
        fixture.intent.clone(),
        FakeCompute { log: Rc::clone(&log) },
        FakeProvider { log: Rc::clone(&log), session: SESSION },
        ReceiptVerifier { log: Rc::clone(&log), canonical: Rc::clone(&canonical) },
        FailingStore {
            inner: FileDriverRecordStore::acquire(fixture.record_path()).expect("record store"),
            fail_generation: Rc::clone(&fail_generation),
        },
    )
    .expect("driver");
    driver.confirm_source_compute_exit().expect("exit");
    driver.freeze_source().expect("freeze");
    driver.export_source_capsule().expect("export");
    driver.seal_manifest(fixture.root()).expect("seal");
    driver.restore_destination_prepared().expect("prepare");

    assert!(matches!(driver.resume_source(fixture.root()), Err(MigrationError::Durability(_))));
    assert_eq!(driver.phase(), Phase::DestinationPrepared);
    assert_eq!(
        driver.record().pending_action,
        Some(visa_wasi_migration::DriverAction::ClaimSourceRetained)
    );
    assert!(matches!(&*canonical.borrow(), CanonicalRecovery::SourceRetained(_)));
    drop(driver);

    let mut recovered = Driver::recover(
        FakeCompute { log: Rc::clone(&log) },
        FakeProvider { log: Rc::clone(&log), session: SESSION },
        ReceiptVerifier { log: Rc::clone(&log), canonical },
        FailingStore {
            inner: FileDriverRecordStore::acquire(fixture.record_path()).expect("reopen store"),
            fail_generation,
        },
        fixture.root(),
    )
    .expect("recover terminal source retention");
    assert_eq!(recovered.phase(), Phase::SourceRetained);
    recovered.resume_source(fixture.root()).expect("finish source resume");
    assert_eq!(recovered.phase(), Phase::SourceResumed);
    let events = log.borrow();
    assert_eq!(events.iter().filter(|event| **event == "claim-source-retained").count(), 1);
    assert_eq!(events.iter().filter(|event| **event == "provider-resume").count(), 1);
    assert_eq!(events.iter().filter(|event| **event == "source-compute-restore").count(), 1);
}

#[test]
fn restart_projects_a_commit_that_won_against_a_pending_source_retention() {
    let fixture = Fixture::new(29);
    let log = Rc::new(RefCell::new(Vec::new()));
    let canonical = Rc::new(RefCell::new(CanonicalRecovery::Uncommitted));
    let mut driver = Driver::new(
        fixture.intent.clone(),
        FakeCompute { log: Rc::clone(&log) },
        FakeProvider { log: Rc::clone(&log), session: SESSION },
        ReceiptVerifier { log: Rc::clone(&log), canonical: Rc::clone(&canonical) },
        FileDriverRecordStore::acquire(fixture.record_path()).expect("record store"),
    )
    .expect("driver");
    driver.confirm_source_compute_exit().expect("exit");
    driver.freeze_source().expect("freeze");
    driver.export_source_capsule().expect("export");
    driver.seal_manifest(fixture.root()).expect("seal");
    driver.restore_destination_prepared().expect("prepare");
    let commit = commit_proof(&driver, fixture.root());
    *canonical.borrow_mut() = CanonicalRecovery::OwnershipCommitted(Box::new(commit.clone()));

    assert!(matches!(
        driver.resume_source(fixture.root()),
        Err(MigrationError::Proof("canonical ownership commit excludes source retention"))
    ));
    assert_eq!(driver.phase(), Phase::DestinationPrepared);
    assert_eq!(
        driver.record().pending_action,
        Some(visa_wasi_migration::DriverAction::ClaimSourceRetained)
    );
    drop(driver);

    let recovered = Driver::recover(
        FakeCompute { log: Rc::clone(&log) },
        FakeProvider { log: Rc::clone(&log), session: SESSION },
        ReceiptVerifier { log: Rc::clone(&log), canonical },
        FileDriverRecordStore::acquire(fixture.record_path()).expect("reopen store"),
        fixture.root(),
    )
    .expect("recover winning commit");
    assert_eq!(recovered.phase(), Phase::OwnershipCommitted);
    assert!(recovered.record().pending_action.is_none());
    assert_eq!(
        recovered
            .record()
            .ownership_commit_proof
            .as_ref()
            .expect("stored commit")
            .digest()
            .unwrap(),
        commit.digest().unwrap()
    );
    let events = log.borrow();
    assert_eq!(events.iter().filter(|event| **event == "provider-resume").count(), 0);
    assert_eq!(events.iter().filter(|event| **event == "source-compute-restore").count(), 0);
}

#[test]
fn restart_replays_source_compute_restore_after_lost_completion_save() {
    restart_abort_after_failed_completion_save(16, 1, 2);
}

fn restart_abort_after_failed_completion_save(
    failed_generation: u64,
    expected_provider_resumes: usize,
    expected_compute_restores: usize,
) {
    let fixture = Fixture::new(u8::try_from(failed_generation).expect("seed"));
    let log = Rc::new(RefCell::new(Vec::new()));
    let canonical = Rc::new(RefCell::new(CanonicalRecovery::Uncommitted));
    let fail_generation = Rc::new(Cell::new(Some(failed_generation)));
    let store = FailingStore {
        inner: FileDriverRecordStore::acquire(fixture.record_path()).expect("record store"),
        fail_generation: Rc::clone(&fail_generation),
    };
    let mut driver = Driver::new(
        fixture.intent.clone(),
        FakeCompute { log: Rc::clone(&log) },
        FakeProvider { log: Rc::clone(&log), session: SESSION },
        ReceiptVerifier { log: Rc::clone(&log), canonical: Rc::clone(&canonical) },
        store,
    )
    .expect("driver");
    driver.confirm_source_compute_exit().expect("exit");
    driver.freeze_source().expect("freeze");
    driver.export_source_capsule().expect("export");
    driver.seal_manifest(fixture.root()).expect("seal");
    driver.restore_destination_prepared().expect("prepare");
    assert!(matches!(driver.resume_source(fixture.root()), Err(MigrationError::Durability(_))));
    drop(driver);

    let recovered = Driver::recover(
        FakeCompute { log: Rc::clone(&log) },
        FakeProvider { log: Rc::clone(&log), session: SESSION },
        ReceiptVerifier { log: Rc::clone(&log), canonical },
        FailingStore {
            inner: FileDriverRecordStore::acquire(fixture.record_path()).expect("reopen store"),
            fail_generation,
        },
        fixture.root(),
    )
    .expect("recover");
    assert_eq!(recovered.phase(), Phase::SourceResumed);
    let events = log.borrow();
    assert_eq!(
        events.iter().filter(|event| **event == "provider-resume").count(),
        expected_provider_resumes
    );
    assert_eq!(
        events.iter().filter(|event| **event == "source-compute-restore").count(),
        expected_compute_restores
    );
}

#[test]
fn restart_reconciles_a_canonical_commit_missing_from_the_local_record() {
    let fixture = Fixture::new(31);
    let log = Rc::new(RefCell::new(Vec::new()));
    let canonical = Rc::new(RefCell::new(CanonicalRecovery::Uncommitted));
    let mut driver = Driver::new(
        fixture.intent.clone(),
        FakeCompute { log: Rc::clone(&log) },
        FakeProvider { log: Rc::clone(&log), session: SESSION },
        ReceiptVerifier { log: Rc::clone(&log), canonical: Rc::clone(&canonical) },
        FileDriverRecordStore::acquire(fixture.record_path()).expect("record store"),
    )
    .expect("driver");
    driver.confirm_source_compute_exit().expect("exit");
    driver.freeze_source().expect("freeze");
    driver.export_source_capsule().expect("export");
    driver.seal_manifest(fixture.root()).expect("seal");
    driver.restore_destination_prepared().expect("prepare");
    let commit = CanonicalCommitProof::bind_receipt(
        driver.manifest().expect("manifest"),
        fixture.root(),
        "proofs/commit.receipt",
    )
    .expect("commit");
    *canonical.borrow_mut() = CanonicalRecovery::OwnershipCommitted(Box::new(commit.clone()));
    drop(driver);

    let mut recovered = Driver::recover(
        FakeCompute { log: Rc::clone(&log) },
        FakeProvider { log: Rc::clone(&log), session: SESSION },
        ReceiptVerifier { log, canonical },
        FileDriverRecordStore::acquire(fixture.record_path()).expect("reopen store"),
        fixture.root(),
    )
    .expect("recover");
    assert_eq!(recovered.phase(), Phase::OwnershipCommitted);
    assert_eq!(
        recovered
            .record()
            .ownership_commit_proof
            .as_ref()
            .expect("stored commit")
            .digest()
            .unwrap(),
        commit.digest().unwrap()
    );
    assert!(matches!(recovered.resume_source(fixture.root()), Err(MigrationError::Proof(_))));
}

#[test]
fn restart_projects_a_canonical_fence_missing_from_the_local_record() {
    let fixture = Fixture::new(32);
    let log = Rc::new(RefCell::new(Vec::new()));
    let canonical = Rc::new(RefCell::new(CanonicalRecovery::Uncommitted));
    let mut driver = Driver::new(
        fixture.intent.clone(),
        FakeCompute { log: Rc::clone(&log) },
        FakeProvider { log: Rc::clone(&log), session: SESSION },
        ReceiptVerifier { log: Rc::clone(&log), canonical: Rc::clone(&canonical) },
        FileDriverRecordStore::acquire(fixture.record_path()).expect("record store"),
    )
    .expect("driver");
    driver.confirm_source_compute_exit().expect("exit");
    driver.freeze_source().expect("freeze");
    driver.export_source_capsule().expect("export");
    driver.seal_manifest(fixture.root()).expect("seal");
    driver.restore_destination_prepared().expect("prepare");
    let commit = CanonicalCommitProof::bind_receipt(
        driver.manifest().expect("manifest"),
        fixture.root(),
        "proofs/commit.receipt",
    )
    .expect("commit");
    let fence = CanonicalFenceProof::bind_receipt(
        driver.manifest().expect("manifest"),
        &commit,
        fixture.root(),
        "proofs/fence.receipt",
    )
    .expect("fence");
    *canonical.borrow_mut() = CanonicalRecovery::SourceFenced {
        commit: Box::new(commit.clone()),
        fence: Box::new(fence.clone()),
    };
    drop(driver);

    let recovered = Driver::recover(
        FakeCompute { log: Rc::clone(&log) },
        FakeProvider { log: Rc::clone(&log), session: SESSION },
        ReceiptVerifier { log: Rc::clone(&log), canonical },
        FileDriverRecordStore::acquire(fixture.record_path()).expect("reopen store"),
        fixture.root(),
    )
    .expect("recover");
    assert_eq!(recovered.phase(), Phase::SourceFenced);
    assert_eq!(
        recovered.record().source_fence_proof.as_ref().expect("stored fence").digest().unwrap(),
        fence.digest().unwrap()
    );
    assert_eq!(log.borrow().iter().filter(|event| **event == "provider-fence").count(), 1);
}

#[test]
fn restart_rejects_a_noncanonical_driver_record() {
    let fixture = Fixture::new(33);
    let driver = driver(&fixture);
    let record = driver.record().clone();
    drop(driver);
    fs::write(fixture.record_path(), serde_json::to_vec_pretty(&record).expect("pretty record"))
        .expect("replace record bytes");
    let log = Rc::new(RefCell::new(Vec::new()));
    let result = Driver::recover(
        FakeCompute { log: Rc::clone(&log) },
        FakeProvider { log: Rc::clone(&log), session: SESSION },
        ReceiptVerifier { log, canonical: Rc::new(RefCell::new(CanonicalRecovery::Uncommitted)) },
        FileDriverRecordStore::acquire(fixture.record_path()).expect("reopen store"),
        fixture.root(),
    );
    assert!(matches!(
        result,
        Err(MigrationError::Integrity("driver record is not canonical RFC 8785 JSON"))
    ));
}

fn sha256(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}
