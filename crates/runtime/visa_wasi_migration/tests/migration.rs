use std::{cell::RefCell, fs, path::Path, rc::Rc};

use serde::Serialize;
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;
use visa_wasi_migration::{
    BuildIdentity, CanonicalCommitProof, CanonicalFenceProof, CanonicalProofVerifier,
    ComputeControl, Driver, FileRoles, MigrationError, MigrationIntent, MigrationManifest, Phase,
    PlatformIdentity, ProviderMode, ProviderProjection, ProviderProjectionStatus,
};
use visa_wasi_protocol::{ClientId, OwnerId, SessionId};

const SESSION: SessionId = SessionId([1; 16]);
const OWNER: OwnerId = OwnerId([2; 16]);
const HANDOFF: [u8; 16] = [3; 16];
const SOURCE_CLIENT: ClientId = ClientId([4; 16]);
const DESTINATION_CLIENT: ClientId = ClientId([5; 16]);
const SOURCE_EPOCH: u64 = 11;
const DESTINATION_EPOCH: u64 = 12;

type Log = Rc<RefCell<Vec<&'static str>>>;
type CommitMutation = Box<dyn Fn(&mut CanonicalCommitProof)>;

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
}

impl CanonicalProofVerifier for ReceiptVerifier {
    fn verify_ownership_commit(
        &self,
        _: &MigrationManifest,
        _: &CanonicalCommitProof,
        canonical_receipt: &Path,
    ) -> Result<(), MigrationError> {
        self.log.borrow_mut().push("verify-commit");
        if fs::read(canonical_receipt).map_err(MigrationError::Io)? == b"canonical commit" {
            Ok(())
        } else {
            Err(MigrationError::Proof("commit receipt was not canonical"))
        }
    }

    fn verify_source_fence(
        &self,
        _: &MigrationManifest,
        _: &CanonicalCommitProof,
        _: &CanonicalFenceProof,
        canonical_receipt: &Path,
    ) -> Result<(), MigrationError> {
        self.log.borrow_mut().push("verify-fence");
        if fs::read(canonical_receipt).map_err(MigrationError::Io)? == b"canonical fence" {
            Ok(())
        } else {
            Err(MigrationError::Proof("fence receipt was not canonical"))
        }
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
        Self { temporary, intent: intent() }
    }

    fn root(&self) -> &Path {
        self.temporary.path()
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
        source_epoch: SOURCE_EPOCH,
        destination_epoch: DESTINATION_EPOCH,
        source_client: SOURCE_CLIENT,
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

fn driver(fixture: &Fixture) -> Driver<FakeCompute, FakeProvider, ReceiptVerifier> {
    let log = Rc::new(RefCell::new(Vec::new()));
    Driver::new(
        fixture.intent.clone(),
        FakeCompute { log: Rc::clone(&log) },
        FakeProvider { log: Rc::clone(&log), session: SESSION },
        ReceiptVerifier { log },
    )
    .expect("valid driver")
}

fn prepared_driver(fixture: &Fixture) -> Driver<FakeCompute, FakeProvider, ReceiptVerifier> {
    let mut driver = driver(fixture);
    driver.confirm_source_compute_exit().expect("exit");
    driver.freeze_source().expect("freeze");
    driver.export_source_capsule().expect("export");
    driver.seal_manifest(fixture.root()).expect("seal");
    driver.restore_destination_prepared().expect("prepare");
    driver
}

fn commit_proof(
    driver: &Driver<FakeCompute, FakeProvider, ReceiptVerifier>,
    root: &Path,
) -> CanonicalCommitProof {
    CanonicalCommitProof::bind_receipt(
        driver.manifest().expect("manifest"),
        root,
        "proofs/commit.receipt",
    )
    .expect("commit proof")
}

fn fence_proof(
    driver: &Driver<FakeCompute, FakeProvider, ReceiptVerifier>,
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

    let (compute, _, _) = driver.into_parts();
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
    driver.resume_source().expect("resume");
    driver.resume_source().expect("duplicate resume");
    assert_eq!(driver.phase(), Phase::SourceResumed);
    let (compute, _, _) = driver.into_parts();
    assert_eq!(
        compute.log.borrow().as_slice(),
        [
            "compute-exit",
            "provider-freeze",
            "provider-export",
            "provider-prepare",
            "provider-resume"
        ]
    );
}

#[test]
fn resume_after_canonical_commit_is_rejected() {
    let fixture = Fixture::new(15);
    let mut driver = prepared_driver(&fixture);
    let commit = commit_proof(&driver, fixture.root());
    driver.record_ownership_commit(commit, fixture.root()).expect("commit");
    assert!(matches!(driver.resume_source(), Err(MigrationError::Transition { .. })));
}

#[test]
fn wrong_provider_session_does_not_advance_the_driver() {
    let fixture = Fixture::new(16);
    let log = Rc::new(RefCell::new(Vec::new()));
    let mut driver = Driver::new(
        fixture.intent.clone(),
        FakeCompute { log: Rc::clone(&log) },
        FakeProvider { log, session: SessionId([99; 16]) },
        ReceiptVerifier { log: Rc::new(RefCell::new(Vec::new())) },
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
