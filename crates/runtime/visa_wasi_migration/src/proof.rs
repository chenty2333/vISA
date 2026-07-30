use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    BoundFile, ManifestDigest, MigrationError, MigrationManifest,
    manifest::{hash_file, resolve_file, validate_semantic_path, validate_sha256},
};

pub const COMMIT_PROOF_SCHEMA: &str = "visa-canonical-ownership-commit-proof-v1";
pub const FENCE_PROOF_SCHEMA: &str = "visa-canonical-source-fence-proof-v1";
pub const SOURCE_RETAINED_PROOF_SCHEMA: &str = "visa-canonical-source-retained-proof-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofDigest(pub [u8; 32]);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalCommitProof {
    pub schema: String,
    pub migration_manifest_sha256: String,
    pub session_hex: String,
    pub stable_owner_hex: String,
    pub handoff_hex: String,
    pub source_epoch: u64,
    pub destination_epoch: u64,
    pub canonical_receipt: BoundFile,
}

impl CanonicalCommitProof {
    pub fn bind_receipt(
        manifest: &MigrationManifest,
        root: &Path,
        receipt_semantic_path: &str,
    ) -> Result<Self, MigrationError> {
        let canonical_receipt = bind_receipt(root, receipt_semantic_path)?;
        Ok(Self {
            schema: COMMIT_PROOF_SCHEMA.to_owned(),
            migration_manifest_sha256: manifest.digest()?.to_string(),
            session_hex: manifest.session_hex.clone(),
            stable_owner_hex: manifest.stable_owner_hex.clone(),
            handoff_hex: manifest.handoff_hex.clone(),
            source_epoch: manifest.source_epoch,
            destination_epoch: manifest.destination_epoch,
            canonical_receipt,
        })
    }

    pub fn verify_binding(
        &self,
        manifest: &MigrationManifest,
        root: &Path,
    ) -> Result<PathBuf, MigrationError> {
        if self.schema != COMMIT_PROOF_SCHEMA
            || self.migration_manifest_sha256 != manifest.digest()?.to_string()
            || self.session_hex != manifest.session_hex
            || self.stable_owner_hex != manifest.stable_owner_hex
            || self.handoff_hex != manifest.handoff_hex
            || self.source_epoch != manifest.source_epoch
            || self.destination_epoch != manifest.destination_epoch
        {
            return Err(MigrationError::Proof("ownership commit proof binding differs"));
        }
        self.canonical_receipt.verify_at(root)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, MigrationError> {
        validate_sha256(&self.migration_manifest_sha256, "commit manifest sha256")?;
        validate_semantic_path(&self.canonical_receipt.semantic_path)?;
        serde_json_canonicalizer::to_vec(self)
            .map_err(|error| MigrationError::Codec(error.to_string()))
    }

    pub fn digest(&self) -> Result<ProofDigest, MigrationError> {
        Ok(ProofDigest(Sha256::digest(self.canonical_bytes()?).into()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalSourceRetainedProof {
    pub schema: String,
    pub migration_manifest_sha256: String,
    pub session_hex: String,
    pub stable_owner_hex: String,
    pub handoff_hex: String,
    pub source_epoch: u64,
    pub destination_epoch: u64,
    pub canonical_receipt: BoundFile,
}

impl CanonicalSourceRetainedProof {
    pub fn bind_receipt(
        manifest: &MigrationManifest,
        root: &Path,
        receipt_semantic_path: &str,
    ) -> Result<Self, MigrationError> {
        let canonical_receipt = bind_receipt(root, receipt_semantic_path)?;
        Ok(Self {
            schema: SOURCE_RETAINED_PROOF_SCHEMA.to_owned(),
            migration_manifest_sha256: manifest.digest()?.to_string(),
            session_hex: manifest.session_hex.clone(),
            stable_owner_hex: manifest.stable_owner_hex.clone(),
            handoff_hex: manifest.handoff_hex.clone(),
            source_epoch: manifest.source_epoch,
            destination_epoch: manifest.destination_epoch,
            canonical_receipt,
        })
    }

    pub fn verify_binding(
        &self,
        manifest: &MigrationManifest,
        root: &Path,
    ) -> Result<PathBuf, MigrationError> {
        if self.schema != SOURCE_RETAINED_PROOF_SCHEMA
            || self.migration_manifest_sha256 != manifest.digest()?.to_string()
            || self.session_hex != manifest.session_hex
            || self.stable_owner_hex != manifest.stable_owner_hex
            || self.handoff_hex != manifest.handoff_hex
            || self.source_epoch != manifest.source_epoch
            || self.destination_epoch != manifest.destination_epoch
        {
            return Err(MigrationError::Proof("source-retained proof binding differs"));
        }
        self.canonical_receipt.verify_at(root)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, MigrationError> {
        validate_sha256(&self.migration_manifest_sha256, "source-retained manifest sha256")?;
        validate_semantic_path(&self.canonical_receipt.semantic_path)?;
        serde_json_canonicalizer::to_vec(self)
            .map_err(|error| MigrationError::Codec(error.to_string()))
    }

    pub fn digest(&self) -> Result<ProofDigest, MigrationError> {
        Ok(ProofDigest(Sha256::digest(self.canonical_bytes()?).into()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalFenceProof {
    pub schema: String,
    pub migration_manifest_sha256: String,
    pub ownership_commit_proof_sha256: String,
    pub session_hex: String,
    pub stable_owner_hex: String,
    pub handoff_hex: String,
    pub source_epoch: u64,
    pub destination_epoch: u64,
    pub canonical_receipt: BoundFile,
}

impl CanonicalFenceProof {
    pub fn bind_receipt(
        manifest: &MigrationManifest,
        commit: &CanonicalCommitProof,
        root: &Path,
        receipt_semantic_path: &str,
    ) -> Result<Self, MigrationError> {
        commit.verify_binding(manifest, root)?;
        let canonical_receipt = bind_receipt(root, receipt_semantic_path)?;
        Ok(Self {
            schema: FENCE_PROOF_SCHEMA.to_owned(),
            migration_manifest_sha256: manifest.digest()?.to_string(),
            ownership_commit_proof_sha256: hex_digest(commit.digest()?),
            session_hex: manifest.session_hex.clone(),
            stable_owner_hex: manifest.stable_owner_hex.clone(),
            handoff_hex: manifest.handoff_hex.clone(),
            source_epoch: manifest.source_epoch,
            destination_epoch: manifest.destination_epoch,
            canonical_receipt,
        })
    }

    pub fn verify_binding(
        &self,
        manifest: &MigrationManifest,
        commit: &CanonicalCommitProof,
        root: &Path,
    ) -> Result<PathBuf, MigrationError> {
        if self.schema != FENCE_PROOF_SCHEMA
            || self.migration_manifest_sha256 != manifest.digest()?.to_string()
            || self.ownership_commit_proof_sha256 != hex_digest(commit.digest()?)
            || self.session_hex != manifest.session_hex
            || self.stable_owner_hex != manifest.stable_owner_hex
            || self.handoff_hex != manifest.handoff_hex
            || self.source_epoch != manifest.source_epoch
            || self.destination_epoch != manifest.destination_epoch
        {
            return Err(MigrationError::Proof("source fence proof binding differs"));
        }
        self.canonical_receipt.verify_at(root)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, MigrationError> {
        validate_sha256(&self.migration_manifest_sha256, "fence manifest sha256")?;
        validate_sha256(&self.ownership_commit_proof_sha256, "ownership commit proof sha256")?;
        validate_semantic_path(&self.canonical_receipt.semantic_path)?;
        serde_json_canonicalizer::to_vec(self)
            .map_err(|error| MigrationError::Codec(error.to_string()))
    }

    pub fn digest(&self) -> Result<ProofDigest, MigrationError> {
        Ok(ProofDigest(Sha256::digest(self.canonical_bytes()?).into()))
    }
}

fn bind_receipt(root: &Path, semantic_path: &str) -> Result<BoundFile, MigrationError> {
    validate_semantic_path(semantic_path)?;
    let path = resolve_file(root, semantic_path)?;
    let (size, sha256) = hash_file(&path)?;
    Ok(BoundFile { semantic_path: semantic_path.to_owned(), size, sha256 })
}

fn hex_digest(digest: ProofDigest) -> String {
    crate::manifest::hex(&digest.0)
}

impl From<ManifestDigest> for ProofDigest {
    fn from(value: ManifestDigest) -> Self {
        Self(value.0)
    }
}
