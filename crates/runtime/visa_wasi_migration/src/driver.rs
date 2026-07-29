use std::{fmt, path::Path};

use serde::{Deserialize, Serialize};
use visa_wasi_protocol::SessionId;

use crate::{
    CanonicalCommitProof, CanonicalFenceProof, ManifestDigest, MigrationIntent, MigrationManifest,
    ProofDigest,
};

#[derive(Debug)]
pub enum MigrationError {
    Invalid(&'static str),
    Integrity(&'static str),
    Proof(&'static str),
    Transition { expected: &'static str, actual: Phase },
    External(String),
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

pub trait ComputeControl {
    /// Confirm that the source process has completely exited and cannot issue a
    /// resource hostcall while the provider is frozen.
    fn confirm_source_exit(&mut self, intent: &MigrationIntent) -> Result<(), MigrationError>;

    /// Restore compute only after the destination resource projection is active.
    fn restore_destination(&mut self, manifest: &MigrationManifest) -> Result<(), MigrationError>;
}

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

/// Authenticity and canonical-state verification is intentionally outside this
/// crate. Implementations must verify the receipt bytes against the canonical
/// ownership service, not merely compare the digest recorded in the proof.
pub trait CanonicalProofVerifier {
    fn verify_ownership_commit(
        &self,
        manifest: &MigrationManifest,
        proof: &CanonicalCommitProof,
        canonical_receipt: &Path,
    ) -> Result<(), MigrationError>;

    fn verify_source_fence(
        &self,
        manifest: &MigrationManifest,
        commit: &CanonicalCommitProof,
        fence: &CanonicalFenceProof,
        canonical_receipt: &Path,
    ) -> Result<(), MigrationError>;
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
    OwnershipCommitted,
    SourceFenced,
    DestinationActivated,
    ComputeRestored,
    SourceResumed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriverRecord {
    pub phase: Phase,
    pub migration_manifest_sha256: Option<String>,
    pub ownership_commit_proof_sha256: Option<String>,
    pub source_fence_proof_sha256: Option<String>,
}

impl DriverRecord {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, MigrationError> {
        serde_json_canonicalizer::to_vec(self)
            .map_err(|error| MigrationError::Codec(error.to_string()))
    }
}

pub struct Driver<C, P, V> {
    intent: MigrationIntent,
    manifest: Option<MigrationManifest>,
    commit: Option<CanonicalCommitProof>,
    fence: Option<CanonicalFenceProof>,
    record: DriverRecord,
    compute: C,
    provider: P,
    verifier: V,
}

impl<C, P, V> Driver<C, P, V>
where
    C: ComputeControl,
    P: ProviderProjection,
    V: CanonicalProofVerifier,
{
    pub fn new(
        intent: MigrationIntent,
        compute: C,
        provider: P,
        verifier: V,
    ) -> Result<Self, MigrationError> {
        intent.validate()?;
        Ok(Self {
            intent,
            manifest: None,
            commit: None,
            fence: None,
            record: DriverRecord {
                phase: Phase::Initialized,
                migration_manifest_sha256: None,
                ownership_commit_proof_sha256: None,
                source_fence_proof_sha256: None,
            },
            compute,
            provider,
            verifier,
        })
    }

    pub const fn phase(&self) -> Phase {
        self.record.phase
    }

    pub const fn record(&self) -> &DriverRecord {
        &self.record
    }

    pub const fn manifest(&self) -> Option<&MigrationManifest> {
        self.manifest.as_ref()
    }

    pub fn confirm_source_compute_exit(&mut self) -> Result<(), MigrationError> {
        if self.record.phase == Phase::SourceComputeExited {
            return Ok(());
        }
        self.require_phase(Phase::Initialized, "initialized state")?;
        self.compute.confirm_source_exit(&self.intent)?;
        self.record.phase = Phase::SourceComputeExited;
        Ok(())
    }

    pub fn freeze_source(&mut self) -> Result<(), MigrationError> {
        if self.record.phase == Phase::SourceFrozen {
            return Ok(());
        }
        self.require_phase(Phase::SourceComputeExited, "source compute exit")?;
        let status = self.provider.freeze_source(&self.intent)?;
        expect_status(status, self.intent.session, ProviderMode::Frozen, self.intent.source_epoch)?;
        self.record.phase = Phase::SourceFrozen;
        Ok(())
    }

    pub fn export_source_capsule(&mut self) -> Result<(), MigrationError> {
        if self.record.phase == Phase::CapsuleExported {
            return Ok(());
        }
        self.require_phase(Phase::SourceFrozen, "frozen source provider")?;
        self.provider.export_source_capsule(&self.intent)?;
        self.record.phase = Phase::CapsuleExported;
        Ok(())
    }

    pub fn seal_manifest(&mut self, root: &Path) -> Result<&MigrationManifest, MigrationError> {
        if self.record.phase == Phase::ManifestSealed {
            return self
                .manifest
                .as_ref()
                .ok_or(MigrationError::Integrity("sealed manifest missing"));
        }
        self.require_phase(Phase::CapsuleExported, "exported resource capsule")?;
        let manifest = MigrationManifest::seal(&self.intent, root)?;
        let digest = manifest.digest()?;
        self.record.migration_manifest_sha256 = Some(hex_manifest(digest));
        self.manifest = Some(manifest);
        self.record.phase = Phase::ManifestSealed;
        self.manifest.as_ref().ok_or(MigrationError::Integrity("sealed manifest missing"))
    }

    pub fn restore_destination_prepared(&mut self) -> Result<(), MigrationError> {
        if self.record.phase == Phase::DestinationPrepared {
            return Ok(());
        }
        self.require_phase(Phase::ManifestSealed, "sealed migration manifest")?;
        let manifest = self.manifest_ref()?.clone();
        let status = self.provider.restore_destination_prepared(&manifest)?;
        expect_status(
            status,
            self.intent.session,
            ProviderMode::Prepared,
            self.intent.source_epoch,
        )?;
        self.record.phase = Phase::DestinationPrepared;
        Ok(())
    }

    pub fn record_ownership_commit(
        &mut self,
        proof: CanonicalCommitProof,
        root: &Path,
    ) -> Result<(), MigrationError> {
        if self.record.phase == Phase::OwnershipCommitted {
            let existing = self
                .commit
                .as_ref()
                .ok_or(MigrationError::Integrity("recorded commit proof missing"))?;
            if existing.digest()? == proof.digest()? {
                return Ok(());
            }
            return Err(MigrationError::Proof("different ownership commit supplied after commit"));
        }
        self.require_phase(Phase::DestinationPrepared, "prepared destination resource provider")?;
        let manifest = self.manifest_ref()?;
        let receipt = proof.verify_binding(manifest, root)?;
        self.verifier.verify_ownership_commit(manifest, &proof, &receipt)?;
        self.record.ownership_commit_proof_sha256 = Some(hex_proof(proof.digest()?));
        self.commit = Some(proof);
        self.record.phase = Phase::OwnershipCommitted;
        Ok(())
    }

    pub fn fence_source(
        &mut self,
        proof: CanonicalFenceProof,
        root: &Path,
    ) -> Result<(), MigrationError> {
        if self.record.phase == Phase::SourceFenced {
            let existing = self
                .fence
                .as_ref()
                .ok_or(MigrationError::Integrity("recorded fence proof missing"))?;
            if existing.digest()? == proof.digest()? {
                return Ok(());
            }
            return Err(MigrationError::Proof("different source fence supplied after fencing"));
        }
        self.require_phase(Phase::OwnershipCommitted, "canonical ownership commit proof")?;
        let manifest = self.manifest_ref()?.clone();
        let commit = self
            .commit
            .as_ref()
            .ok_or(MigrationError::Integrity("ownership commit proof missing"))?;
        let receipt = proof.verify_binding(&manifest, commit, root)?;
        self.verifier.verify_source_fence(&manifest, commit, &proof, &receipt)?;
        let status = self.provider.fence_source(&manifest)?;
        expect_status(status, self.intent.session, ProviderMode::Fenced, self.intent.source_epoch)?;
        self.record.source_fence_proof_sha256 = Some(hex_proof(proof.digest()?));
        self.fence = Some(proof);
        self.record.phase = Phase::SourceFenced;
        Ok(())
    }

    pub fn activate_destination(&mut self) -> Result<(), MigrationError> {
        if self.record.phase == Phase::DestinationActivated {
            return Ok(());
        }
        self.require_phase(
            Phase::SourceFenced,
            "canonical commit and canonical source fence proofs",
        )?;
        if self.commit.is_none() || self.fence.is_none() {
            return Err(MigrationError::Integrity("activation proof state is incomplete"));
        }
        let manifest = self.manifest_ref()?.clone();
        let status = self.provider.activate_destination(&manifest)?;
        expect_status(
            status,
            self.intent.session,
            ProviderMode::Active,
            self.intent.destination_epoch,
        )?;
        self.record.phase = Phase::DestinationActivated;
        Ok(())
    }

    pub fn restore_compute(&mut self) -> Result<(), MigrationError> {
        if self.record.phase == Phase::ComputeRestored {
            return Ok(());
        }
        self.require_phase(Phase::DestinationActivated, "active destination resource projection")?;
        let manifest = self.manifest_ref()?.clone();
        self.compute.restore_destination(&manifest)?;
        self.record.phase = Phase::ComputeRestored;
        Ok(())
    }

    /// Abort before canonical ownership commit and return the source provider to
    /// its original epoch. Repeating the same resume is a no-op.
    pub fn resume_source(&mut self) -> Result<(), MigrationError> {
        if self.record.phase == Phase::SourceResumed {
            return Ok(());
        }
        if !matches!(
            self.record.phase,
            Phase::SourceFrozen
                | Phase::CapsuleExported
                | Phase::ManifestSealed
                | Phase::DestinationPrepared
        ) {
            return Err(MigrationError::Transition {
                expected: "a frozen pre-commit source",
                actual: self.record.phase,
            });
        }
        if self.commit.is_some() || self.record.ownership_commit_proof_sha256.is_some() {
            return Err(MigrationError::Proof(
                "source cannot resume after canonical ownership commit",
            ));
        }
        let status = self.provider.resume_source(&self.intent)?;
        expect_status(status, self.intent.session, ProviderMode::Active, self.intent.source_epoch)?;
        self.record.phase = Phase::SourceResumed;
        Ok(())
    }

    pub fn into_parts(self) -> (C, P, V) {
        (self.compute, self.provider, self.verifier)
    }

    fn manifest_ref(&self) -> Result<&MigrationManifest, MigrationError> {
        self.manifest.as_ref().ok_or(MigrationError::Integrity("migration manifest missing"))
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

fn hex_manifest(digest: ManifestDigest) -> String {
    crate::manifest::hex(&digest.0)
}

fn hex_proof(digest: ProofDigest) -> String {
    crate::manifest::hex(&digest.0)
}
