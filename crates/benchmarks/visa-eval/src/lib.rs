//! Performance measurement harness for the production continuity spine.
//!
//! Four measures answer four separate questions and share nothing but the
//! fixture and the sample sink:
//!
//! * `steady_state` — what one durable effect costs on the real coordinator,
//!   against a same-SQLite baseline that performs the same transactions.
//! * `handoff_phases` — where the time inside one composite handoff goes.
//! * `snapshot_size` — how large the portable snapshot is, field by field.
//! * `restart_baseline` — what a full journal replay costs against a lossy
//!   read-the-last-value restart.
//!
//! The harness measures the real crates. Nothing here reimplements coordinator
//! or provider behaviour; the baselines are deliberately separate code paths
//! that do less work, and every place they do less is reported.

use std::path::{Path, PathBuf};

use contract_core::{
    CanonicalState, Digest, EvidenceKind, EvidenceRef, ExtensionSupport, Identity, NodeIdentity,
    SchemaVersion,
};
use substrate_host::{LoopbackLogicalPeer, LoopbackLogicalPeerBehavior, SqliteProvider};
use visa_composite_cell::{
    adapter::{CompositeAdapter, CompositeAdapterError},
    cell::{BASELINE_KEY, INITIAL_FILE_CONTENT, REQUEST_BODY},
    component,
    fixture::{
        CompositeFixture, CompositeFixtureIds, CompositeFixturePaths, DEFAULT_CREDENTIAL_MATERIAL,
        DEFAULT_PEER_IDENTITY, INITIAL_LEASE_EPOCH, derive_identity,
    },
    state::TimerKvComponentState,
};
use visa_profile::{
    LOGICAL_REQUEST_EXTENSION_ID, LOGICAL_REQUEST_EXTENSION_VERSION, REGULAR_FILE_EXTENSION_ID,
    REGULAR_FILE_EXTENSION_VERSION,
};
use visa_runtime::{AuthorityPlan, Coordinator, ProfileAuthorityPlan, SnapshotExpectations};

pub mod output;
pub mod phases;
pub mod restart;
pub mod snapshot_size;
pub mod steady_state;

/// Timer duration used wherever a timer must be pending but must not fire
/// during the measurement.
pub const LONG_TIMER_NANOS: u64 = 60_000_000_000;

/// Which measures a single invocation should run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Measure {
    SteadyState,
    HandoffPhases,
    SnapshotSize,
    RestartBaseline,
}

impl Measure {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SteadyState => "steady-state",
            Self::HandoffPhases => "handoff-phases",
            Self::SnapshotSize => "snapshot-size",
            Self::RestartBaseline => "restart-baseline",
        }
    }

    #[must_use]
    pub const fn all() -> [Self; 4] {
        [Self::SteadyState, Self::HandoffPhases, Self::SnapshotSize, Self::RestartBaseline]
    }
}

/// Parameters shared by every measure.
#[derive(Clone, Debug)]
pub struct EvalOptions {
    /// Where samples, the environment receipt, and per-run working
    /// directories are written.
    pub out: PathBuf,
    /// Iterations per run for the iteration-shaped measures.
    pub iters: u64,
    /// Discarded iterations before the first recorded sample.
    pub warmup: u64,
    /// Independent runs. Each run gets a fresh working directory.
    pub runs: u32,
    /// Effect counts used as the independent variable for the handoff and
    /// restart measures.
    pub effects_before_handoff: Vec<u64>,
}

impl Default for EvalOptions {
    fn default() -> Self {
        Self {
            out: PathBuf::from("target/visa-eval"),
            iters: 2_000,
            warmup: 100,
            runs: 30,
            effects_before_handoff: vec![10, 100, 1_000],
        }
    }
}

impl EvalOptions {
    /// Working directory for one run of one measure. Callers create a fresh
    /// one per run so no provider database is ever reused.
    #[must_use]
    pub fn run_root(&self, measure: &str, run: u32) -> PathBuf {
        self.out.join("work").join(measure).join(format!("run-{run:04}"))
    }
}

/// Start the loopback peer the logical-request claim binds to. The fixture
/// records the peer address, so the peer must outlive every provider that was
/// provisioned against it.
pub fn spawn_peer() -> Result<LoopbackLogicalPeer, String> {
    LoopbackLogicalPeer::spawn(
        DEFAULT_PEER_IDENTITY.to_vec(),
        DEFAULT_CREDENTIAL_MATERIAL.to_vec(),
        LoopbackLogicalPeerBehavior::Echo,
    )
    .map_err(|error| format!("cannot start loopback peer: {error:?}"))
}

/// Build the four-resource composite fixture used by every measure.
pub fn create_fixture(
    artifact_root: &Path,
    case_id: &str,
    peer: &LoopbackLogicalPeer,
) -> Result<CompositeFixture, String> {
    std::fs::create_dir_all(artifact_root)
        .map_err(|error| format!("cannot create {}: {error}", artifact_root.display()))?;
    CompositeFixture::create(artifact_root, case_id, INITIAL_FILE_CONTENT, REQUEST_BODY, peer)
}

/// A compiled composite component ready to be placed under a store.
pub type PreparedComponent =
    visa_composite_cell::adapter::PreparedCompositeComponent<SqliteProvider>;

/// An activated source cell: canonical state recovered, lease taken, component
/// instantiated, and the guest holding all four resource handles. Both the
/// handoff-phase measure and the restart measure start from here.
pub struct SourceCell {
    pub adapter: CompositeAdapter<SqliteProvider>,
    pub ids: CompositeFixtureIds,
    pub paths: CompositeFixturePaths,
    pub profile_digest: Digest,
    pub handoff_authority: AuthorityPlan,
    pub timer_authority: AuthorityPlan,
    pub key_value_authority: AuthorityPlan,
    pub file_authority: ProfileAuthorityPlan,
    pub request_authority: ProfileAuthorityPlan,
    pub destination: SqliteProvider,
    pub session: String,
    /// The dormant state the source recovered from. The restart measure needs
    /// it again to replay the journal from the beginning.
    pub initial_state: CanonicalState,
}

/// Activate the source side of one composite cell. Nothing here is timed; the
/// measures time the work they add on top.
pub fn activate_source(fixture: CompositeFixture, case: &str) -> Result<SourceCell, String> {
    let CompositeFixture {
        paths,
        ids,
        source_state,
        profile_digest,
        handoff_authority,
        timer_authority,
        key_value_authority,
        file_authority,
        request_authority,
        source,
        destination,
        ..
    } = fixture;

    let initial_state = source_state.clone();
    let mut coordinator = Coordinator::recover(source_state, source).map_err(runtime_error)?;
    coordinator
        .activate(derive(case, "activate"), ids.source_handoff_authority, INITIAL_LEASE_EPOCH)
        .map_err(runtime_error)?;
    let mut adapter = CompositeAdapter::instantiate(component::composite_bytes(), coordinator)
        .map_err(adapter_error)?;
    let session = format!("{case}:session");
    adapter.activate(session.clone(), timer_kv_state(case, None, 0)).map_err(adapter_error)?;

    Ok(SourceCell {
        adapter,
        ids,
        paths,
        profile_digest,
        handoff_authority,
        timer_authority,
        key_value_authority,
        file_authority,
        request_authority,
        destination,
        session,
        initial_state,
    })
}

/// Guest-side timer/key-value record. A fresh activation passes `None` and
/// version zero; a guest being rebuilt after a restart has to name the arm
/// operation and the key-value version the coordinator recovered, because the
/// adapter refuses a guest record that disagrees with canonical truth.
#[must_use]
pub fn timer_kv_state(
    case: &str,
    timer_operation: Option<String>,
    expected_version: u64,
) -> TimerKvComponentState {
    TimerKvComponentState {
        key: BASELINE_KEY.to_owned(),
        expected_version,
        completion_value: b"visa-eval-completed".to_vec(),
        timer_operation_id: timer_operation,
        timer_idempotency_key: format!("{case}-timer"),
        completion_idempotency_key: format!("{case}-completion"),
        timer_completed: false,
    }
}

/// Deterministic identity for one labelled step of one case.
#[must_use]
pub fn derive(case_id: &str, label: &str) -> Identity {
    derive_identity(case_id, label)
}

/// Evidence reference for a harness-issued command. The digest is derived from
/// the same label as the identity, so a retained sample can be traced back to
/// the step that produced it.
#[must_use]
pub fn derive_evidence(case_id: &str, label: &str, kind: EvidenceKind) -> EvidenceRef {
    let identity = derive_identity(case_id, label);
    let mut digest = [0_u8; 32];
    digest[..16].copy_from_slice(&identity.0);
    digest[16..].copy_from_slice(&derive_identity(case_id, &format!("{label}-digest")).0);
    EvidenceRef { identity, kind, digest: Digest::from_bytes(digest) }
}

/// Snapshot acceptance criteria the composite destination applies. Identical to
/// the composite cell's own expectations; both extensions are mandatory because
/// the fixture publishes a profile that carries them in a fixed order.
#[must_use]
pub fn expectations(profile_digest: Digest, destination: NodeIdentity) -> SnapshotExpectations {
    SnapshotExpectations {
        component_digest: component::composite_digest(),
        profile_digest,
        profile_version: SchemaVersion::new(1, 0),
        supported_extensions: vec![
            ExtensionSupport {
                id: REGULAR_FILE_EXTENSION_ID,
                version: REGULAR_FILE_EXTENSION_VERSION,
            },
            ExtensionSupport {
                id: LOGICAL_REQUEST_EXTENSION_ID,
                version: LOGICAL_REQUEST_EXTENSION_VERSION,
            },
        ],
        destination,
    }
}

/// Evidence reference bound into an export, digested over the live canonical
/// state so the exported snapshot names the state it was taken from.
pub fn snapshot_evidence(
    case: &str,
    coordinator: &Coordinator<SqliteProvider>,
) -> Result<EvidenceRef, String> {
    Ok(EvidenceRef {
        identity: derive(case, "snapshot-evidence"),
        kind: EvidenceKind::SnapshotIntegrity,
        digest: coordinator.state_digest().map_err(runtime_error)?,
    })
}

/// Case identifier for one run. Restricted to the lowercase-and-dash alphabet
/// the fixture accepts.
#[must_use]
pub fn case_id(measure: &str, run: u32) -> String {
    format!("{}-run-{run:04}", measure.replace('_', "-"))
}

pub(crate) fn runtime_error(error: visa_runtime::RuntimeError) -> String {
    format!("runtime error: {error:?}")
}

pub(crate) fn provider_error(error: substrate_api::ProviderError) -> String {
    format!("provider error {:?} (retryable={})", error.kind, error.retryable)
}

pub(crate) fn adapter_error(error: CompositeAdapterError) -> String {
    format!("composite adapter error: {error}")
}

pub(crate) fn nanos(elapsed: std::time::Duration) -> u64 {
    u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
}
