use std::{fmt, path::Path};

use serde::{Deserialize, Serialize};
use visa_wasi_protocol::SessionId;

use crate::{
    CanonicalCommitProof, CanonicalFenceProof, CanonicalSourceRetainedProof, DriverRecordStore,
    MigrationIntent, MigrationManifest,
};

pub const DRIVER_RECORD_SCHEMA: &str = "visa-wasi-migration-driver-record-v4";

#[derive(Debug)]
pub enum MigrationError {
    Invalid(&'static str),
    Integrity(&'static str),
    Proof(&'static str),
    Transition { expected: &'static str, actual: Phase },
    External(String),
    Durability(String),
    Codec(String),
    Io(std::io::Error),
}

impl fmt::Display for MigrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "invalid migration input: {message}"),
            Self::Integrity(message) => write!(formatter, "migration integrity failure: {message}"),
            Self::Proof(message) => write!(formatter, "canonical proof rejected: {message}"),
            Self::Transition { expected, actual } => {
                write!(formatter, "migration transition requires {expected}, found {actual:?}")
            }
            Self::External(message) => write!(formatter, "migration operation failed: {message}"),
            Self::Durability(message) => {
                write!(formatter, "migration durability operation failed: {message}")
            }
            Self::Codec(message) => write!(formatter, "migration encoding failed: {message}"),
            Self::Io(error) => write!(formatter, "migration filesystem failure: {error}"),
        }
    }
}

impl std::error::Error for MigrationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderMode {
    Active,
    Frozen,
    Prepared,
    Fenced,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderProjectionStatus {
    pub session: SessionId,
    pub mode: ProviderMode,
    pub authority_epoch: u64,
}

/// Compute operations are keyed by the migration intent and must be
/// idempotent. The driver deliberately replays an action whose completion was
/// not durably recorded before a crash.
pub trait ComputeControl {
    fn confirm_source_exit(&mut self, intent: &MigrationIntent) -> Result<(), MigrationError>;
    fn restore_destination(&mut self, manifest: &MigrationManifest) -> Result<(), MigrationError>;
    fn restore_source(&mut self, intent: &MigrationIntent) -> Result<(), MigrationError>;
}

/// Projection operations are keyed by the session, handoff, and epoch in the
/// supplied intent/manifest and must be idempotent under exact replay.
pub trait ProviderProjection {
    fn freeze_source(
        &mut self,
        intent: &MigrationIntent,
    ) -> Result<ProviderProjectionStatus, MigrationError>;

    fn export_source_capsule(&mut self, intent: &MigrationIntent) -> Result<(), MigrationError>;

    fn restore_destination_prepared(
        &mut self,
        manifest: &MigrationManifest,
    ) -> Result<ProviderProjectionStatus, MigrationError>;

    fn fence_source(
        &mut self,
        manifest: &MigrationManifest,
    ) -> Result<ProviderProjectionStatus, MigrationError>;

    fn activate_destination(
        &mut self,
        manifest: &MigrationManifest,
    ) -> Result<ProviderProjectionStatus, MigrationError>;

    fn resume_source(
        &mut self,
        intent: &MigrationIntent,
    ) -> Result<ProviderProjectionStatus, MigrationError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CanonicalRecovery {
    Uncommitted,
    SourceRetained(Box<CanonicalSourceRetainedProof>),
    OwnershipCommitted(Box<CanonicalCommitProof>),
    SourceFenced { commit: Box<CanonicalCommitProof>, fence: Box<CanonicalFenceProof> },
}

/// Authenticity and canonical-state verification is intentionally outside this
/// crate. Implementations receive the artifact root so they independently
/// rebind proof receipts, and query the authority during restart; trusting a
/// caller's prior receipt check or returning only locally cached proof state
/// defeats reconciliation.
pub trait CanonicalProofVerifier {
    fn verify_ownership_commit(
        &self,
        manifest: &MigrationManifest,
        proof: &CanonicalCommitProof,
        artifact_root: &Path,
    ) -> Result<(), MigrationError>;

    fn verify_source_fence(
        &self,
        manifest: &MigrationManifest,
        commit: &CanonicalCommitProof,
        fence: &CanonicalFenceProof,
        artifact_root: &Path,
    ) -> Result<(), MigrationError>;

    /// Atomically win the canonical pre-commit terminal decision for the
    /// source. This must be mutually exclusive with ownership commit.
    fn claim_source_retained(
        &self,
        manifest: &MigrationManifest,
        artifact_root: &Path,
    ) -> Result<CanonicalSourceRetainedProof, MigrationError>;

    fn recover_canonical_state(
        &self,
        manifest: &MigrationManifest,
        artifact_root: &Path,
    ) -> Result<CanonicalRecovery, MigrationError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Initialized,
    SourceComputeExited,
    SourceFrozen,
    CapsuleExported,
    ManifestSealed,
    DestinationPrepared,
    SourceRetained,
    OwnershipCommitted,
    SourceFenced,
    DestinationActivated,
    ComputeRestored,
    SourceProviderResumed,
    SourceResumed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriverAction {
    ConfirmSourceComputeExit,
    FreezeSource,
    ExportSourceCapsule,
    PrepareDestination,
    FenceSource,
    ActivateDestination,
    RestoreDestinationCompute,
    ClaimSourceRetained,
    ResumeSourceProvider,
    RestoreSourceCompute,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriverRecord {
    pub schema: String,
    pub generation: u64,
    pub phase: Phase,
    pub pending_action: Option<DriverAction>,
    pub intent: MigrationIntent,
    pub migration_manifest: Option<MigrationManifest>,
    pub source_retained_proof: Option<CanonicalSourceRetainedProof>,
    pub ownership_commit_proof: Option<CanonicalCommitProof>,
    pub source_fence_proof: Option<CanonicalFenceProof>,
}

impl DriverRecord {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, MigrationError> {
        self.validate_structure()?;
        serde_json_canonicalizer::to_vec(self)
            .map_err(|error| MigrationError::Codec(error.to_string()))
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, MigrationError> {
        let record: Self = serde_json::from_slice(bytes)
            .map_err(|error| MigrationError::Codec(error.to_string()))?;
        if record.canonical_bytes()? != bytes {
            return Err(MigrationError::Integrity("driver record is not canonical RFC 8785 JSON"));
        }
        Ok(record)
    }

    pub fn verify_at(&self, root: &Path) -> Result<(), MigrationError> {
        self.validate_structure()?;
        if let Some(manifest) = &self.migration_manifest {
            let expected = MigrationManifest::seal(&self.intent, root)?;
            if *manifest != expected {
                return Err(MigrationError::Integrity(
                    "stored manifest is not bound to the recorded migration intent",
                ));
            }
        }
        if let Some(commit) = &self.ownership_commit_proof {
            let manifest = self.manifest()?;
            commit.verify_binding(manifest, root)?;
        }
        if let Some(source_retained) = &self.source_retained_proof {
            let manifest = self.manifest()?;
            source_retained.verify_binding(manifest, root)?;
        }
        if let Some(fence) = &self.source_fence_proof {
            let manifest = self.manifest()?;
            let commit = self.commit()?;
            fence.verify_binding(manifest, commit, root)?;
        }
        Ok(())
    }

    fn validate_structure(&self) -> Result<(), MigrationError> {
        if self.schema != DRIVER_RECORD_SCHEMA {
            return Err(MigrationError::Invalid("unsupported migration driver record schema"));
        }
        if self.generation == 0 {
            return Err(MigrationError::Invalid("zero driver record generation"));
        }
        self.intent.validate()?;

        let has_manifest = self.migration_manifest.is_some();
        let has_source_retained = self.source_retained_proof.is_some();
        let has_commit = self.ownership_commit_proof.is_some();
        let has_fence = self.source_fence_proof.is_some();
        let artifacts_valid = match self.phase {
            Phase::Initialized
            | Phase::SourceComputeExited
            | Phase::SourceFrozen
            | Phase::CapsuleExported => {
                !has_manifest && !has_source_retained && !has_commit && !has_fence
            }
            Phase::ManifestSealed | Phase::DestinationPrepared => {
                has_manifest && !has_source_retained && !has_commit && !has_fence
            }
            Phase::SourceRetained => {
                has_manifest && has_source_retained && !has_commit && !has_fence
            }
            Phase::OwnershipCommitted => {
                has_manifest
                    && !has_source_retained
                    && has_commit
                    && (!has_fence || self.pending_action == Some(DriverAction::FenceSource))
            }
            Phase::SourceFenced | Phase::DestinationActivated | Phase::ComputeRestored => {
                has_manifest && !has_source_retained && has_commit && has_fence
            }
            Phase::SourceProviderResumed | Phase::SourceResumed => {
                !has_commit
                    && !has_fence
                    && ((!has_manifest && !has_source_retained)
                        || (has_manifest && has_source_retained))
            }
        };
        if !artifacts_valid {
            return Err(MigrationError::Integrity(
                "driver phase and retained migration artifacts disagree",
            ));
        }
        if let Some(action) = self.pending_action {
            let valid = match action {
                DriverAction::ConfirmSourceComputeExit => self.phase == Phase::Initialized,
                DriverAction::FreezeSource => self.phase == Phase::SourceComputeExited,
                DriverAction::ExportSourceCapsule => self.phase == Phase::SourceFrozen,
                DriverAction::PrepareDestination => self.phase == Phase::ManifestSealed,
                DriverAction::FenceSource => self.phase == Phase::OwnershipCommitted && has_fence,
                DriverAction::ActivateDestination => self.phase == Phase::SourceFenced,
                DriverAction::RestoreDestinationCompute => {
                    self.phase == Phase::DestinationActivated
                }
                DriverAction::ClaimSourceRetained => {
                    matches!(self.phase, Phase::ManifestSealed | Phase::DestinationPrepared)
                        && !has_source_retained
                }
                DriverAction::ResumeSourceProvider => {
                    is_early_abortable_phase(self.phase) || self.phase == Phase::SourceRetained
                }
                DriverAction::RestoreSourceCompute => self.phase == Phase::SourceProviderResumed,
            };
            if !valid {
                return Err(MigrationError::Integrity(
                    "pending driver action does not match its durable phase",
                ));
            }
        }
        Ok(())
    }

    fn manifest(&self) -> Result<&MigrationManifest, MigrationError> {
        self.migration_manifest
            .as_ref()
            .ok_or(MigrationError::Integrity("migration manifest missing"))
    }

    fn commit(&self) -> Result<&CanonicalCommitProof, MigrationError> {
        self.ownership_commit_proof
            .as_ref()
            .ok_or(MigrationError::Integrity("ownership commit proof missing"))
    }
}

pub struct Driver<C, P, V, S> {
    record: DriverRecord,
    compute: C,
    provider: P,
    verifier: V,
    store: S,
}

impl<C, P, V, S> Driver<C, P, V, S>
where
    C: ComputeControl,
    P: ProviderProjection,
    V: CanonicalProofVerifier,
    S: DriverRecordStore,
{
    pub fn new(
        intent: MigrationIntent,
        compute: C,
        provider: P,
        verifier: V,
        mut store: S,
    ) -> Result<Self, MigrationError> {
        intent.validate()?;
        if store.load()?.is_some() {
            return Err(MigrationError::Integrity("migration driver record already exists"));
        }
        let record = DriverRecord {
            schema: DRIVER_RECORD_SCHEMA.to_owned(),
            generation: 1,
            phase: Phase::Initialized,
            pending_action: None,
            intent,
            migration_manifest: None,
            source_retained_proof: None,
            ownership_commit_proof: None,
            source_fence_proof: None,
        };
        store.save(&record)?;
        Ok(Self { record, compute, provider, verifier, store })
    }

    pub fn recover(
        compute: C,
        provider: P,
        verifier: V,
        mut store: S,
        artifact_root: &Path,
    ) -> Result<Self, MigrationError> {
        let record =
            store.load()?.ok_or(MigrationError::Integrity("migration driver record is missing"))?;
        record.verify_at(artifact_root)?;
        let mut driver = Self { record, compute, provider, verifier, store };
        driver.reconcile_canonical_authority(artifact_root)?;
        driver.reconcile_pending_action(artifact_root)?;
        if driver.record.phase == Phase::SourceProviderResumed {
            driver.restore_source_compute()?;
        }
        Ok(driver)
    }

    pub const fn phase(&self) -> Phase {
        self.record.phase
    }

    pub const fn record(&self) -> &DriverRecord {
        &self.record
    }

    pub const fn manifest(&self) -> Option<&MigrationManifest> {
        self.record.migration_manifest.as_ref()
    }

    pub fn confirm_source_compute_exit(&mut self) -> Result<(), MigrationError> {
        if self.record.phase == Phase::SourceComputeExited && self.record.pending_action.is_none() {
            return Ok(());
        }
        self.require_phase(Phase::Initialized, "initialized state")?;
        self.begin_action(DriverAction::ConfirmSourceComputeExit)?;
        self.compute.confirm_source_exit(&self.record.intent)?;
        self.complete_action(DriverAction::ConfirmSourceComputeExit, Phase::SourceComputeExited)
    }

    pub fn freeze_source(&mut self) -> Result<(), MigrationError> {
        if self.record.phase == Phase::SourceFrozen && self.record.pending_action.is_none() {
            return Ok(());
        }
        self.require_phase(Phase::SourceComputeExited, "source compute exit")?;
        self.begin_action(DriverAction::FreezeSource)?;
        let status = self.provider.freeze_source(&self.record.intent)?;
        expect_status(
            status,
            self.record.intent.session,
            ProviderMode::Frozen,
            self.record.intent.source_epoch,
        )?;
        self.complete_action(DriverAction::FreezeSource, Phase::SourceFrozen)
    }

    pub fn export_source_capsule(&mut self) -> Result<(), MigrationError> {
        if self.record.phase == Phase::CapsuleExported && self.record.pending_action.is_none() {
            return Ok(());
        }
        self.require_phase(Phase::SourceFrozen, "frozen source provider")?;
        self.begin_action(DriverAction::ExportSourceCapsule)?;
        self.provider.export_source_capsule(&self.record.intent)?;
        self.complete_action(DriverAction::ExportSourceCapsule, Phase::CapsuleExported)
    }

    pub fn seal_manifest(&mut self, root: &Path) -> Result<&MigrationManifest, MigrationError> {
        if self.record.phase == Phase::ManifestSealed && self.record.pending_action.is_none() {
            return self.record.manifest();
        }
        self.require_phase(Phase::CapsuleExported, "exported resource capsule")?;
        self.require_no_pending()?;
        let manifest = MigrationManifest::seal(&self.record.intent, root)?;
        let mut next = self.record.clone();
        next.migration_manifest = Some(manifest);
        next.phase = Phase::ManifestSealed;
        self.persist(next)?;
        self.record.manifest()
    }

    pub fn restore_destination_prepared(&mut self) -> Result<(), MigrationError> {
        if self.record.phase == Phase::DestinationPrepared && self.record.pending_action.is_none() {
            return Ok(());
        }
        self.require_phase(Phase::ManifestSealed, "sealed migration manifest")?;
        self.begin_action(DriverAction::PrepareDestination)?;
        let manifest = self.record.manifest()?.clone();
        let status = self.provider.restore_destination_prepared(&manifest)?;
        expect_status(
            status,
            self.record.intent.session,
            ProviderMode::Prepared,
            self.record.intent.source_epoch,
        )?;
        self.complete_action(DriverAction::PrepareDestination, Phase::DestinationPrepared)
    }

    pub fn record_ownership_commit(
        &mut self,
        proof: CanonicalCommitProof,
        root: &Path,
    ) -> Result<(), MigrationError> {
        if self.record.phase == Phase::OwnershipCommitted && self.record.pending_action.is_none() {
            let existing = self.record.commit()?;
            if existing.digest()? == proof.digest()? {
                return Ok(());
            }
            return Err(MigrationError::Proof("different ownership commit supplied after commit"));
        }
        self.require_phase(Phase::DestinationPrepared, "prepared destination resource provider")?;
        self.require_no_pending()?;
        let manifest = self.record.manifest()?;
        self.verifier.verify_ownership_commit(manifest, &proof, root)?;
        let mut next = self.record.clone();
        next.ownership_commit_proof = Some(proof);
        next.phase = Phase::OwnershipCommitted;
        self.persist(next)
    }

    pub fn fence_source(
        &mut self,
        proof: CanonicalFenceProof,
        root: &Path,
    ) -> Result<(), MigrationError> {
        if self.record.phase == Phase::SourceFenced && self.record.pending_action.is_none() {
            let existing = self
                .record
                .source_fence_proof
                .as_ref()
                .ok_or(MigrationError::Integrity("recorded fence proof missing"))?;
            if existing.digest()? == proof.digest()? {
                return Ok(());
            }
            return Err(MigrationError::Proof("different source fence supplied after fencing"));
        }
        self.require_phase(Phase::OwnershipCommitted, "canonical ownership commit proof")?;
        let manifest = self.record.manifest()?.clone();
        let commit = self.record.commit()?.clone();
        self.verifier.verify_source_fence(&manifest, &commit, &proof, root)?;

        if self.record.pending_action.is_none() {
            let mut next = self.record.clone();
            next.source_fence_proof = Some(proof.clone());
            next.pending_action = Some(DriverAction::FenceSource);
            self.persist(next)?;
        } else if self.record.pending_action != Some(DriverAction::FenceSource)
            || self
                .record
                .source_fence_proof
                .as_ref()
                .map(CanonicalFenceProof::digest)
                .transpose()?
                != Some(proof.digest()?)
        {
            return Err(MigrationError::Integrity("different driver action is already pending"));
        }

        let status = self.provider.fence_source(&manifest)?;
        expect_status(
            status,
            self.record.intent.session,
            ProviderMode::Fenced,
            self.record.intent.source_epoch,
        )?;
        self.complete_action(DriverAction::FenceSource, Phase::SourceFenced)
    }

    pub fn activate_destination(&mut self) -> Result<(), MigrationError> {
        if self.record.phase == Phase::DestinationActivated && self.record.pending_action.is_none()
        {
            return Ok(());
        }
        self.require_phase(
            Phase::SourceFenced,
            "canonical commit and canonical source fence proofs",
        )?;
        self.begin_action(DriverAction::ActivateDestination)?;
        let manifest = self.record.manifest()?.clone();
        let status = self.provider.activate_destination(&manifest)?;
        expect_status(
            status,
            self.record.intent.session,
            ProviderMode::Active,
            self.record.intent.destination_epoch,
        )?;
        self.complete_action(DriverAction::ActivateDestination, Phase::DestinationActivated)
    }

    pub fn restore_compute(&mut self) -> Result<(), MigrationError> {
        if self.record.phase == Phase::ComputeRestored && self.record.pending_action.is_none() {
            return Ok(());
        }
        self.require_phase(Phase::DestinationActivated, "active destination resource projection")?;
        self.begin_action(DriverAction::RestoreDestinationCompute)?;
        let manifest = self.record.manifest()?.clone();
        self.compute.restore_destination(&manifest)?;
        self.complete_action(DriverAction::RestoreDestinationCompute, Phase::ComputeRestored)
    }

    /// Abort before canonical ownership commit. Both the source provider and
    /// the source compute checkpoint are restored. A crash after either side
    /// effect is reconciled from the durable pending action on reopen.
    pub fn resume_source(&mut self, artifact_root: &Path) -> Result<(), MigrationError> {
        if self.record.phase == Phase::SourceResumed && self.record.pending_action.is_none() {
            return Ok(());
        }
        if self.record.ownership_commit_proof.is_some() {
            return Err(MigrationError::Proof(
                "source cannot resume after canonical ownership commit",
            ));
        }
        if self.record.phase == Phase::SourceProviderResumed {
            return self.restore_source_compute();
        }
        if self.record.phase == Phase::SourceComputeExited {
            self.require_no_pending()?;
            let mut next = self.record.clone();
            next.phase = Phase::SourceProviderResumed;
            self.persist(next)?;
            return self.restore_source_compute();
        }
        if matches!(self.record.phase, Phase::ManifestSealed | Phase::DestinationPrepared) {
            self.retain_source(artifact_root)?;
        }
        if !is_early_abortable_phase(self.record.phase)
            && self.record.phase != Phase::SourceRetained
        {
            return Err(MigrationError::Transition {
                expected: "a pre-commit source whose compute has exited",
                actual: self.record.phase,
            });
        }
        self.begin_action(DriverAction::ResumeSourceProvider)?;
        let status = self.provider.resume_source(&self.record.intent)?;
        expect_status(
            status,
            self.record.intent.session,
            ProviderMode::Active,
            self.record.intent.source_epoch,
        )?;
        self.complete_action(DriverAction::ResumeSourceProvider, Phase::SourceProviderResumed)?;
        self.restore_source_compute()
    }

    pub fn into_parts(self) -> (C, P, V, S) {
        (self.compute, self.provider, self.verifier, self.store)
    }

    fn restore_source_compute(&mut self) -> Result<(), MigrationError> {
        if self.record.migration_manifest.is_some() && self.record.source_retained_proof.is_none() {
            return Err(MigrationError::Proof(
                "source compute restore requires the terminal source-retained proof",
            ));
        }
        self.require_phase(Phase::SourceProviderResumed, "active source resource projection")?;
        self.begin_action(DriverAction::RestoreSourceCompute)?;
        self.compute.restore_source(&self.record.intent)?;
        self.complete_action(DriverAction::RestoreSourceCompute, Phase::SourceResumed)
    }

    fn reconcile_canonical_authority(&mut self, root: &Path) -> Result<(), MigrationError> {
        let Some(manifest) = self.record.migration_manifest.clone() else {
            return Ok(());
        };
        let canonical = self.verifier.recover_canonical_state(&manifest, root)?;
        match canonical {
            CanonicalRecovery::Uncommitted => {
                if self.record.source_retained_proof.is_some()
                    || self.record.ownership_commit_proof.is_some()
                    || self.record.source_fence_proof.is_some()
                {
                    return Err(MigrationError::Integrity(
                        "local commit proof is absent from canonical authority state",
                    ));
                }
            }
            CanonicalRecovery::SourceRetained(proof) => {
                if self.record.ownership_commit_proof.is_some()
                    || self.record.source_fence_proof.is_some()
                {
                    return Err(MigrationError::Integrity(
                        "canonical source-retained decision conflicts with local commit proofs",
                    ));
                }
                self.reconcile_source_retained_record(*proof, root)?;
            }
            CanonicalRecovery::OwnershipCommitted(commit) => {
                if self.record.source_retained_proof.is_some() {
                    return Err(MigrationError::Integrity(
                        "canonical ownership commit conflicts with local source-retained proof",
                    ));
                }
                self.verify_commit(&manifest, &commit, root)?;
                if self.record.source_fence_proof.is_some() {
                    return Err(MigrationError::Integrity(
                        "local fence proof is absent from canonical authority state",
                    ));
                }
                self.reconcile_commit_record(*commit)?;
            }
            CanonicalRecovery::SourceFenced { commit, fence } => {
                if self.record.source_retained_proof.is_some() {
                    return Err(MigrationError::Integrity(
                        "canonical source fence conflicts with local source-retained proof",
                    ));
                }
                self.verify_commit(&manifest, &commit, root)?;
                self.verify_fence(&manifest, &commit, &fence, root)?;
                self.reconcile_commit_record(*commit)?;
                self.reconcile_fence_record(*fence)?;
            }
        }
        Ok(())
    }

    fn retain_source(&mut self, root: &Path) -> Result<(), MigrationError> {
        if self.record.phase == Phase::SourceRetained && self.record.pending_action.is_none() {
            return Ok(());
        }
        self.require_phase_one_of(
            &[Phase::ManifestSealed, Phase::DestinationPrepared],
            "a manifest-bound pre-commit source",
        )?;
        self.begin_action(DriverAction::ClaimSourceRetained)?;
        let manifest = self.record.manifest()?.clone();
        let proof = self.verifier.claim_source_retained(&manifest, root)?;
        proof.verify_binding(&manifest, root)?;
        self.complete_source_retained(proof)
    }

    fn complete_source_retained(
        &mut self,
        proof: CanonicalSourceRetainedProof,
    ) -> Result<(), MigrationError> {
        if self.record.pending_action != Some(DriverAction::ClaimSourceRetained) {
            return Err(MigrationError::Integrity(
                "source-retained proof arrived without a pending authority action",
            ));
        }
        let mut next = self.record.clone();
        next.source_retained_proof = Some(proof);
        next.phase = Phase::SourceRetained;
        next.pending_action = None;
        self.persist(next)
    }

    fn reconcile_source_retained_record(
        &mut self,
        proof: CanonicalSourceRetainedProof,
        root: &Path,
    ) -> Result<(), MigrationError> {
        let manifest = self.record.manifest()?.clone();
        proof.verify_binding(&manifest, root)?;
        if let Some(existing) = &self.record.source_retained_proof {
            if existing.digest()? != proof.digest()? {
                return Err(MigrationError::Proof(
                    "durable and canonical source-retained proofs differ",
                ));
            }
            return Ok(());
        }
        if !matches!(self.record.phase, Phase::ManifestSealed | Phase::DestinationPrepared)
            || !matches!(self.record.pending_action, None | Some(DriverAction::ClaimSourceRetained))
        {
            return Err(MigrationError::Integrity(
                "canonical source retention arose from an incompatible local phase",
            ));
        }
        let mut next = self.record.clone();
        next.source_retained_proof = Some(proof);
        next.phase = Phase::SourceRetained;
        next.pending_action = None;
        self.persist(next)
    }

    fn reconcile_commit_record(
        &mut self,
        commit: CanonicalCommitProof,
    ) -> Result<(), MigrationError> {
        if let Some(existing) = &self.record.ownership_commit_proof {
            if existing.digest()? != commit.digest()? {
                return Err(MigrationError::Proof(
                    "durable and canonical ownership commits differ",
                ));
            }
            return Ok(());
        }
        if self.record.phase != Phase::DestinationPrepared
            || !matches!(self.record.pending_action, None | Some(DriverAction::ClaimSourceRetained))
        {
            return Err(MigrationError::Integrity(
                "canonical ownership committed from an incompatible local phase",
            ));
        }
        let mut next = self.record.clone();
        next.ownership_commit_proof = Some(commit);
        next.phase = Phase::OwnershipCommitted;
        next.pending_action = None;
        self.persist(next)
    }

    fn reconcile_fence_record(&mut self, fence: CanonicalFenceProof) -> Result<(), MigrationError> {
        if let Some(existing) = &self.record.source_fence_proof {
            if existing.digest()? != fence.digest()? {
                return Err(MigrationError::Proof("durable and canonical source fences differ"));
            }
            return Ok(());
        }
        if self.record.phase != Phase::OwnershipCommitted || self.record.pending_action.is_some() {
            return Err(MigrationError::Integrity(
                "canonical source fence reached from an incompatible local phase",
            ));
        }
        let mut next = self.record.clone();
        next.source_fence_proof = Some(fence);
        next.pending_action = Some(DriverAction::FenceSource);
        self.persist(next)
    }

    fn verify_commit(
        &self,
        manifest: &MigrationManifest,
        commit: &CanonicalCommitProof,
        root: &Path,
    ) -> Result<(), MigrationError> {
        self.verifier.verify_ownership_commit(manifest, commit, root)
    }

    fn verify_fence(
        &self,
        manifest: &MigrationManifest,
        commit: &CanonicalCommitProof,
        fence: &CanonicalFenceProof,
        root: &Path,
    ) -> Result<(), MigrationError> {
        self.verifier.verify_source_fence(manifest, commit, fence, root)
    }

    fn reconcile_pending_action(&mut self, root: &Path) -> Result<(), MigrationError> {
        let Some(action) = self.record.pending_action else {
            return Ok(());
        };
        match action {
            DriverAction::ConfirmSourceComputeExit => {
                self.compute.confirm_source_exit(&self.record.intent)?;
                self.complete_action(action, Phase::SourceComputeExited)
            }
            DriverAction::FreezeSource => {
                let status = self.provider.freeze_source(&self.record.intent)?;
                expect_status(
                    status,
                    self.record.intent.session,
                    ProviderMode::Frozen,
                    self.record.intent.source_epoch,
                )?;
                self.complete_action(action, Phase::SourceFrozen)
            }
            DriverAction::ExportSourceCapsule => {
                self.provider.export_source_capsule(&self.record.intent)?;
                self.complete_action(action, Phase::CapsuleExported)
            }
            DriverAction::PrepareDestination => {
                let manifest = self.record.manifest()?.clone();
                let status = self.provider.restore_destination_prepared(&manifest)?;
                expect_status(
                    status,
                    self.record.intent.session,
                    ProviderMode::Prepared,
                    self.record.intent.source_epoch,
                )?;
                self.complete_action(action, Phase::DestinationPrepared)
            }
            DriverAction::FenceSource => {
                let manifest = self.record.manifest()?.clone();
                let status = self.provider.fence_source(&manifest)?;
                expect_status(
                    status,
                    self.record.intent.session,
                    ProviderMode::Fenced,
                    self.record.intent.source_epoch,
                )?;
                self.complete_action(action, Phase::SourceFenced)
            }
            DriverAction::ActivateDestination => {
                let manifest = self.record.manifest()?.clone();
                let status = self.provider.activate_destination(&manifest)?;
                expect_status(
                    status,
                    self.record.intent.session,
                    ProviderMode::Active,
                    self.record.intent.destination_epoch,
                )?;
                self.complete_action(action, Phase::DestinationActivated)
            }
            DriverAction::RestoreDestinationCompute => {
                let manifest = self.record.manifest()?.clone();
                self.compute.restore_destination(&manifest)?;
                self.complete_action(action, Phase::ComputeRestored)
            }
            DriverAction::ClaimSourceRetained => {
                let manifest = self.record.manifest()?.clone();
                let proof = self.verifier.claim_source_retained(&manifest, root)?;
                proof.verify_binding(&manifest, root)?;
                self.complete_source_retained(proof)
            }
            DriverAction::ResumeSourceProvider => {
                if self.record.migration_manifest.is_some()
                    && self.record.source_retained_proof.is_none()
                {
                    return Err(MigrationError::Proof(
                        "source provider resume requires the terminal source-retained proof",
                    ));
                }
                let status = self.provider.resume_source(&self.record.intent)?;
                expect_status(
                    status,
                    self.record.intent.session,
                    ProviderMode::Active,
                    self.record.intent.source_epoch,
                )?;
                self.complete_action(action, Phase::SourceProviderResumed)
            }
            DriverAction::RestoreSourceCompute => {
                self.compute.restore_source(&self.record.intent)?;
                self.complete_action(action, Phase::SourceResumed)
            }
        }
    }

    fn begin_action(&mut self, action: DriverAction) -> Result<(), MigrationError> {
        match self.record.pending_action {
            Some(existing) if existing == action => Ok(()),
            Some(_) => Err(MigrationError::Integrity("different driver action is already pending")),
            None => {
                let mut next = self.record.clone();
                next.pending_action = Some(action);
                self.persist(next)
            }
        }
    }

    fn complete_action(
        &mut self,
        action: DriverAction,
        phase: Phase,
    ) -> Result<(), MigrationError> {
        if self.record.pending_action != Some(action) {
            return Err(MigrationError::Integrity("completed driver action was not pending"));
        }
        let mut next = self.record.clone();
        next.pending_action = None;
        next.phase = phase;
        self.persist(next)
    }

    fn persist(&mut self, mut next: DriverRecord) -> Result<(), MigrationError> {
        next.generation = self
            .record
            .generation
            .checked_add(1)
            .ok_or(MigrationError::Integrity("driver record generation overflow"))?;
        next.validate_structure()?;
        self.store.save(&next)?;
        self.record = next;
        Ok(())
    }

    fn require_no_pending(&self) -> Result<(), MigrationError> {
        if self.record.pending_action.is_none() {
            Ok(())
        } else {
            Err(MigrationError::Integrity("driver action completion is still pending"))
        }
    }

    fn require_phase(
        &self,
        expected: Phase,
        expected_label: &'static str,
    ) -> Result<(), MigrationError> {
        if self.record.phase == expected {
            Ok(())
        } else {
            Err(MigrationError::Transition { expected: expected_label, actual: self.record.phase })
        }
    }

    fn require_phase_one_of(
        &self,
        expected: &[Phase],
        expected_label: &'static str,
    ) -> Result<(), MigrationError> {
        if expected.contains(&self.record.phase) {
            Ok(())
        } else {
            Err(MigrationError::Transition { expected: expected_label, actual: self.record.phase })
        }
    }
}

fn is_early_abortable_phase(phase: Phase) -> bool {
    matches!(phase, Phase::SourceFrozen | Phase::CapsuleExported)
}

fn expect_status(
    actual: ProviderProjectionStatus,
    session: SessionId,
    mode: ProviderMode,
    authority_epoch: u64,
) -> Result<(), MigrationError> {
    if actual.session != session {
        return Err(MigrationError::Integrity("provider projection returned the wrong session"));
    }
    if actual.mode != mode || actual.authority_epoch != authority_epoch {
        return Err(MigrationError::Integrity(
            "provider projection returned the wrong mode or epoch",
        ));
    }
    Ok(())
}
