use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use rustix::{
    fs::{
        AtFlags, FileType, FlockOperation, Mode, OFlags, flock, fstat, fsync, open, openat,
        renameat, unlinkat,
    },
    process::geteuid,
};
use serde::{Deserialize, Serialize};
use visa_durable_sqlite::sync_file;

use crate::{
    CanonicalCommitProof, CanonicalFenceProof, CanonicalProofVerifier, CanonicalRecovery,
    CanonicalSourceRetainedProof, MigrationError, MigrationManifest,
};

pub const CANONICAL_AUTHORITY_STATE_SCHEMA: &str = "visa-wasi-canonical-authority-state-v2";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalAuthorityDecision {
    Uncommitted,
    SourceRetained,
    OwnershipCommitted,
    SourceFenced,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalAuthorityState {
    pub schema: String,
    pub generation: u64,
    pub migration_manifest_sha256: String,
    pub decision: CanonicalAuthorityDecision,
    pub source_retained_proof: Option<CanonicalSourceRetainedProof>,
    pub ownership_commit_proof: Option<CanonicalCommitProof>,
    pub source_fence_proof: Option<CanonicalFenceProof>,
}

/// File-backed adapter for one canonical ownership decision.
///
/// All terminal writers use the same lifetime-held file lock. A transition
/// compares the state under that lock, publishes one fsynced replacement, and
/// never permits `SourceRetained` or `OwnershipCommitted` to return to
/// `Uncommitted`. The lock is part of this bounded file-authority adapter's TCB;
/// an external authority service must provide the equivalent CAS operation.
pub struct CanonicalAuthorityFileVerifier {
    state_path: PathBuf,
    source_retained_receipt: String,
}

impl CanonicalAuthorityFileVerifier {
    pub fn new(state_path: impl Into<PathBuf>, source_retained_receipt: impl Into<String>) -> Self {
        Self {
            state_path: state_path.into(),
            source_retained_receipt: source_retained_receipt.into(),
        }
    }

    pub fn state_path(&self) -> &Path {
        &self.state_path
    }

    pub fn initialize(&self, manifest: &MigrationManifest) -> Result<(), MigrationError> {
        let authority = AuthorityLock::acquire(&self.state_path)?;
        if authority.try_read_state()?.is_some() {
            self.load(&authority, manifest, None)?;
            return authority.sync_directory();
        }
        let state = CanonicalAuthorityState {
            schema: CANONICAL_AUTHORITY_STATE_SCHEMA.to_owned(),
            generation: 1,
            migration_manifest_sha256: manifest.digest()?.to_string(),
            decision: CanonicalAuthorityDecision::Uncommitted,
            source_retained_proof: None,
            ownership_commit_proof: None,
            source_fence_proof: None,
        };
        authority.write_state(&state)
    }

    pub fn publish_ownership_commit(
        &self,
        manifest: &MigrationManifest,
        proof: &CanonicalCommitProof,
        artifact_root: &Path,
    ) -> Result<(), MigrationError> {
        let authority = AuthorityLock::acquire(&self.state_path)?;
        proof.verify_binding(manifest, artifact_root)?;
        let mut state = self.load(&authority, manifest, Some(artifact_root))?;
        match state.decision {
            CanonicalAuthorityDecision::Uncommitted => {
                state.advance_generation()?;
                state.decision = CanonicalAuthorityDecision::OwnershipCommitted;
                state.ownership_commit_proof = Some(proof.clone());
                proof.verify_binding(manifest, artifact_root)?;
                authority.write_state(&state)
            }
            CanonicalAuthorityDecision::OwnershipCommitted
                if state.ownership_commit_proof.as_ref() == Some(proof) =>
            {
                authority.sync_directory()
            }
            CanonicalAuthorityDecision::SourceFenced
                if state.ownership_commit_proof.as_ref() == Some(proof) =>
            {
                authority.sync_directory()
            }
            CanonicalAuthorityDecision::SourceRetained => Err(MigrationError::Proof(
                "source-retained authority decision already won terminal CAS",
            )),
            _ => Err(MigrationError::Proof(
                "canonical authority contains a conflicting ownership commit",
            )),
        }
    }

    pub fn publish_source_fence(
        &self,
        manifest: &MigrationManifest,
        commit: &CanonicalCommitProof,
        fence: &CanonicalFenceProof,
        artifact_root: &Path,
    ) -> Result<(), MigrationError> {
        let authority = AuthorityLock::acquire(&self.state_path)?;
        commit.verify_binding(manifest, artifact_root)?;
        fence.verify_binding(manifest, commit, artifact_root)?;
        let mut state = self.load(&authority, manifest, Some(artifact_root))?;
        match state.decision {
            CanonicalAuthorityDecision::OwnershipCommitted
                if state.ownership_commit_proof.as_ref() == Some(commit) =>
            {
                state.advance_generation()?;
                state.decision = CanonicalAuthorityDecision::SourceFenced;
                state.source_fence_proof = Some(fence.clone());
                commit.verify_binding(manifest, artifact_root)?;
                fence.verify_binding(manifest, commit, artifact_root)?;
                authority.write_state(&state)
            }
            CanonicalAuthorityDecision::SourceFenced
                if state.ownership_commit_proof.as_ref() == Some(commit)
                    && state.source_fence_proof.as_ref() == Some(fence) =>
            {
                authority.sync_directory()
            }
            CanonicalAuthorityDecision::SourceRetained => Err(MigrationError::Proof(
                "source-retained authority decision excludes source fencing",
            )),
            _ => Err(MigrationError::Proof(
                "source fence does not extend the canonical ownership commit",
            )),
        }
    }

    fn claim_source_retained_inner(
        &self,
        manifest: &MigrationManifest,
        artifact_root: &Path,
    ) -> Result<CanonicalSourceRetainedProof, MigrationError> {
        let authority = AuthorityLock::acquire(&self.state_path)?;
        let proof = CanonicalSourceRetainedProof::bind_receipt(
            manifest,
            artifact_root,
            &self.source_retained_receipt,
        )?;
        let mut state = self.load(&authority, manifest, Some(artifact_root))?;
        match state.decision {
            CanonicalAuthorityDecision::Uncommitted => {
                state.advance_generation()?;
                state.decision = CanonicalAuthorityDecision::SourceRetained;
                state.source_retained_proof = Some(proof.clone());
                proof.verify_binding(manifest, artifact_root)?;
                authority.write_state(&state)?;
                Ok(proof)
            }
            CanonicalAuthorityDecision::SourceRetained
                if state.source_retained_proof.as_ref() == Some(&proof) =>
            {
                authority.sync_directory()?;
                Ok(proof)
            }
            CanonicalAuthorityDecision::OwnershipCommitted
            | CanonicalAuthorityDecision::SourceFenced => {
                Err(MigrationError::Proof("canonical ownership commit excludes source retention"))
            }
            _ => Err(MigrationError::Proof(
                "canonical authority contains a conflicting source-retained proof",
            )),
        }
    }

    fn load(
        &self,
        authority: &AuthorityLock,
        manifest: &MigrationManifest,
        artifact_root: Option<&Path>,
    ) -> Result<CanonicalAuthorityState, MigrationError> {
        let bytes = authority.read_state()?;
        let state: CanonicalAuthorityState = serde_json::from_slice(&bytes)
            .map_err(|error| MigrationError::Codec(error.to_string()))?;
        let mut canonical = serde_json_canonicalizer::to_vec(&state)
            .map_err(|error| MigrationError::Codec(error.to_string()))?;
        canonical.push(b'\n');
        if canonical != bytes {
            return Err(MigrationError::Integrity(
                "canonical authority state is not canonical RFC 8785 JSON",
            ));
        }
        state.validate(manifest, artifact_root)?;
        Ok(state)
    }
}

impl CanonicalAuthorityState {
    fn advance_generation(&mut self) -> Result<(), MigrationError> {
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(MigrationError::Integrity("canonical authority generation overflow"))?;
        Ok(())
    }

    fn validate(
        &self,
        manifest: &MigrationManifest,
        artifact_root: Option<&Path>,
    ) -> Result<(), MigrationError> {
        if self.schema != CANONICAL_AUTHORITY_STATE_SCHEMA
            || self.generation == 0
            || self.migration_manifest_sha256 != manifest.digest()?.to_string()
        {
            return Err(MigrationError::Proof(
                "canonical authority state differs from the migration manifest",
            ));
        }
        match self.decision {
            CanonicalAuthorityDecision::Uncommitted => {
                if self.source_retained_proof.is_some()
                    || self.ownership_commit_proof.is_some()
                    || self.source_fence_proof.is_some()
                {
                    return Err(MigrationError::Proof(
                        "uncommitted authority state contains canonical proofs",
                    ));
                }
            }
            CanonicalAuthorityDecision::SourceRetained => {
                let proof = self.source_retained_proof.as_ref().ok_or(MigrationError::Proof(
                    "source-retained authority state omits its terminal proof",
                ))?;
                if self.ownership_commit_proof.is_some() || self.source_fence_proof.is_some() {
                    return Err(MigrationError::Proof(
                        "source-retained authority state contains commit-side proofs",
                    ));
                }
                if let Some(root) = artifact_root {
                    proof.verify_binding(manifest, root)?;
                }
            }
            CanonicalAuthorityDecision::OwnershipCommitted => {
                let commit = self.ownership_commit_proof.as_ref().ok_or(MigrationError::Proof(
                    "committed authority state omits its commit proof",
                ))?;
                if self.source_retained_proof.is_some() || self.source_fence_proof.is_some() {
                    return Err(MigrationError::Proof(
                        "ownership-committed authority state contains incompatible proofs",
                    ));
                }
                if let Some(root) = artifact_root {
                    commit.verify_binding(manifest, root)?;
                }
            }
            CanonicalAuthorityDecision::SourceFenced => {
                let commit = self.ownership_commit_proof.as_ref().ok_or(MigrationError::Proof(
                    "source-fenced authority state omits its commit proof",
                ))?;
                let fence = self.source_fence_proof.as_ref().ok_or(MigrationError::Proof(
                    "source-fenced authority state omits its fence proof",
                ))?;
                if self.source_retained_proof.is_some() {
                    return Err(MigrationError::Proof(
                        "source-fenced authority state contains a source-retained proof",
                    ));
                }
                if let Some(root) = artifact_root {
                    commit.verify_binding(manifest, root)?;
                    fence.verify_binding(manifest, commit, root)?;
                }
            }
        }
        Ok(())
    }
}

impl CanonicalProofVerifier for CanonicalAuthorityFileVerifier {
    fn verify_ownership_commit(
        &self,
        manifest: &MigrationManifest,
        proof: &CanonicalCommitProof,
        artifact_root: &Path,
    ) -> Result<(), MigrationError> {
        let authority = AuthorityLock::acquire(&self.state_path)?;
        proof.verify_binding(manifest, artifact_root)?;
        let state = self.load(&authority, manifest, Some(artifact_root))?;
        if !matches!(
            state.decision,
            CanonicalAuthorityDecision::OwnershipCommitted
                | CanonicalAuthorityDecision::SourceFenced
        ) || state.ownership_commit_proof.as_ref() != Some(proof)
        {
            return Err(MigrationError::Proof(
                "ownership commit is absent from canonical authority state",
            ));
        }
        Ok(())
    }

    fn verify_source_fence(
        &self,
        manifest: &MigrationManifest,
        commit: &CanonicalCommitProof,
        fence: &CanonicalFenceProof,
        artifact_root: &Path,
    ) -> Result<(), MigrationError> {
        let authority = AuthorityLock::acquire(&self.state_path)?;
        commit.verify_binding(manifest, artifact_root)?;
        fence.verify_binding(manifest, commit, artifact_root)?;
        let state = self.load(&authority, manifest, Some(artifact_root))?;
        if state.decision != CanonicalAuthorityDecision::SourceFenced
            || state.ownership_commit_proof.as_ref() != Some(commit)
            || state.source_fence_proof.as_ref() != Some(fence)
        {
            return Err(MigrationError::Proof(
                "source fence is absent from canonical authority state",
            ));
        }
        Ok(())
    }

    fn claim_source_retained(
        &self,
        manifest: &MigrationManifest,
        artifact_root: &Path,
    ) -> Result<CanonicalSourceRetainedProof, MigrationError> {
        self.claim_source_retained_inner(manifest, artifact_root)
    }

    fn recover_canonical_state(
        &self,
        manifest: &MigrationManifest,
        artifact_root: &Path,
    ) -> Result<CanonicalRecovery, MigrationError> {
        let authority = AuthorityLock::acquire(&self.state_path)?;
        let state = self.load(&authority, manifest, Some(artifact_root))?;
        match state.decision {
            CanonicalAuthorityDecision::Uncommitted => Ok(CanonicalRecovery::Uncommitted),
            CanonicalAuthorityDecision::SourceRetained => Ok(CanonicalRecovery::SourceRetained(
                Box::new(state.source_retained_proof.expect("validated source-retained proof")),
            )),
            CanonicalAuthorityDecision::OwnershipCommitted => {
                Ok(CanonicalRecovery::OwnershipCommitted(Box::new(
                    state.ownership_commit_proof.expect("validated commit proof"),
                )))
            }
            CanonicalAuthorityDecision::SourceFenced => Ok(CanonicalRecovery::SourceFenced {
                commit: Box::new(state.ownership_commit_proof.expect("validated commit proof")),
                fence: Box::new(state.source_fence_proof.expect("validated fence proof")),
            }),
        }
    }
}

struct AuthorityLock {
    directory: File,
    state_name: OsString,
    temporary_name: OsString,
    _file: File,
}

impl AuthorityLock {
    fn acquire(state_path: &Path) -> Result<Self, MigrationError> {
        let parent = state_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .ok_or(MigrationError::Invalid("canonical authority state has no parent directory"))?;
        let state_name = state_path
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or(MigrationError::Invalid("canonical authority state has no file name"))?
            .to_owned();
        let directory = open(
            parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| MigrationError::Io(io_error(error)))?;
        validate_private_directory(&directory)?;
        let lock_name = suffixed_name(&state_name, ".lock");
        let descriptor = openat(
            &directory,
            &lock_name,
            OFlags::CREATE | OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|error| MigrationError::Io(io_error(error)))?;
        validate_private_regular(&descriptor)?;
        flock(&descriptor, FlockOperation::LockExclusive)
            .map_err(|error| MigrationError::Io(io_error(error)))?;
        validate_private_directory(&directory)?;
        validate_private_regular(&descriptor)?;
        let authority = Self {
            directory: directory.into(),
            temporary_name: suffixed_name(&state_name, ".next"),
            state_name,
            _file: descriptor.into(),
        };
        authority.sync_directory()?;
        Ok(authority)
    }

    fn write_state(&self, state: &CanonicalAuthorityState) -> Result<(), MigrationError> {
        let mut bytes = serde_json_canonicalizer::to_vec(state)
            .map_err(|error| MigrationError::Codec(error.to_string()))?;
        bytes.push(b'\n');
        if self.try_read(&self.temporary_name)?.is_some() {
            unlinkat(&self.directory, &self.temporary_name, AtFlags::empty())
                .map_err(|error| MigrationError::Io(io_error(error)))?;
            self.sync_directory()?;
        }
        let descriptor = openat(
            &self.directory,
            &self.temporary_name,
            OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|error| MigrationError::Io(io_error(error)))?;
        let mut temporary = File::from(descriptor);
        let result = (|| {
            validate_private_regular(&temporary)?;
            temporary.write_all(&bytes).map_err(MigrationError::Io)?;
            temporary.flush().map_err(MigrationError::Io)?;
            sync_file(&temporary).map_err(|error| MigrationError::Durability(error.to_string()))?;
            validate_private_regular(&temporary)?;
            if self.try_read_state()?.is_some() {
                // The opened state was validated before the replacing rename.
            }
            validate_private_directory(&self.directory)?;
            renameat(&self.directory, &self.temporary_name, &self.directory, &self.state_name)
                .map_err(|error| MigrationError::Io(io_error(error)))?;
            self.sync_directory()
        })();
        if result.is_err() {
            let _ = unlinkat(&self.directory, &self.temporary_name, AtFlags::empty());
        }
        result
    }

    fn read_state(&self) -> Result<Vec<u8>, MigrationError> {
        self.try_read_state()?.ok_or_else(|| {
            MigrationError::External("canonical authority state is missing".to_owned())
        })
    }

    fn try_read_state(&self) -> Result<Option<Vec<u8>>, MigrationError> {
        self.try_read(&self.state_name)
    }

    fn try_read(&self, name: &OsStr) -> Result<Option<Vec<u8>>, MigrationError> {
        let descriptor = match openat(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
            Err(error) => return Err(MigrationError::Io(io_error(error))),
        };
        validate_private_regular(&descriptor)?;
        let mut file = File::from(descriptor);
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(MigrationError::Io)?;
        validate_private_regular(&file)?;
        Ok(Some(bytes))
    }

    fn sync_directory(&self) -> Result<(), MigrationError> {
        validate_private_directory(&self.directory)?;
        fsync(&self.directory)
            .map_err(|error| MigrationError::Durability(io_error(error).to_string()))?;
        validate_private_directory(&self.directory)
    }
}

fn validate_private_directory(fd: &impl std::os::fd::AsFd) -> Result<(), MigrationError> {
    let stat = fstat(fd).map_err(|error| MigrationError::Io(io_error(error)))?;
    let permissions = Mode::from_raw_mode(stat.st_mode) & (Mode::RWXU | Mode::RWXG | Mode::RWXO);
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != geteuid().as_raw()
        || permissions != Mode::RWXU
    {
        return Err(MigrationError::Integrity(
            "canonical authority parent is not a private owner directory",
        ));
    }
    Ok(())
}

fn validate_private_regular(fd: &impl std::os::fd::AsFd) -> Result<(), MigrationError> {
    let stat = fstat(fd).map_err(|error| MigrationError::Io(io_error(error)))?;
    let permissions = Mode::from_raw_mode(stat.st_mode) & (Mode::RWXU | Mode::RWXG | Mode::RWXO);
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != geteuid().as_raw()
        || stat.st_nlink != 1
        || permissions != Mode::RUSR | Mode::WUSR
    {
        return Err(MigrationError::Integrity(
            "canonical authority object is not a private, singly-linked regular file",
        ));
    }
    Ok(())
}

fn suffixed_name(name: &OsStr, suffix: &str) -> OsString {
    let mut value = name.to_owned();
    value.push(suffix);
    value
}

fn io_error(error: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error.raw_os_error())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        sync::{Arc, Barrier},
        thread,
    };

    use tempfile::TempDir;

    use super::*;
    use crate::{BoundFile, BuildIdentity, ClientLineage, MANIFEST_SCHEMA, PlatformIdentity};

    #[test]
    fn authority_decision_requires_an_explicit_initialized_state() {
        let temporary = TempDir::new().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let manifest = manifest();
        let path = temporary.path().join("authority.json");
        let verifier = CanonicalAuthorityFileVerifier::new(&path, "authority/source-retained.json");
        assert!(verifier.recover_canonical_state(&manifest, temporary.path()).is_err());
        verifier.initialize(&manifest).unwrap();
        assert_eq!(
            verifier.recover_canonical_state(&manifest, temporary.path()).unwrap(),
            CanonicalRecovery::Uncommitted
        );
        verifier.initialize(&manifest).unwrap();
    }

    #[test]
    fn authority_rejects_non_private_parent_before_any_path_write_and_on_retry() {
        let temporary = TempDir::new().unwrap();
        let root = temporary.path();
        fs::set_permissions(root, fs::Permissions::from_mode(0o755)).unwrap();
        let manifest = manifest();
        let path = root.join("authority.json");
        let verifier = CanonicalAuthorityFileVerifier::new(&path, "authority/source-retained.json");

        assert!(matches!(verifier.initialize(&manifest), Err(MigrationError::Integrity(_))));
        assert!(!path.exists());
        assert!(!root.join("authority.json.lock").exists());

        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        verifier.initialize(&manifest).unwrap();
        fs::set_permissions(root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(verifier.initialize(&manifest), Err(MigrationError::Integrity(_))));
    }

    #[test]
    fn terminal_cas_allows_exactly_one_source_retained_or_commit_winner() {
        let temporary = TempDir::new().unwrap();
        let root = temporary.path();
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(root.join("authority")).unwrap();
        write_receipt(&root.join("authority/source-retained.json"), b"source retained\n");
        write_receipt(&root.join("authority/commit.json"), b"ownership committed\n");
        let manifest = manifest();
        let state_path = root.join("authority-state.json");
        CanonicalAuthorityFileVerifier::new(&state_path, "authority/source-retained.json")
            .initialize(&manifest)
            .unwrap();
        let commit =
            CanonicalCommitProof::bind_receipt(&manifest, root, "authority/commit.json").unwrap();
        let barrier = Arc::new(Barrier::new(2));

        let abort_thread = {
            let barrier = Arc::clone(&barrier);
            let state_path = state_path.clone();
            let manifest = manifest.clone();
            let root = root.to_path_buf();
            thread::spawn(move || {
                let verifier = CanonicalAuthorityFileVerifier::new(
                    state_path,
                    "authority/source-retained.json",
                );
                barrier.wait();
                verifier.claim_source_retained(&manifest, &root)
            })
        };
        let commit_thread = {
            let barrier = Arc::clone(&barrier);
            let state_path = state_path.clone();
            let manifest = manifest.clone();
            let root = root.to_path_buf();
            let commit = commit.clone();
            thread::spawn(move || {
                let verifier = CanonicalAuthorityFileVerifier::new(
                    state_path,
                    "authority/source-retained.json",
                );
                barrier.wait();
                verifier.publish_ownership_commit(&manifest, &commit, &root)
            })
        };

        let abort_result = abort_thread.join().unwrap();
        let commit_result = commit_thread.join().unwrap();
        assert_ne!(abort_result.is_ok(), commit_result.is_ok());
        let verifier =
            CanonicalAuthorityFileVerifier::new(&state_path, "authority/source-retained.json");
        match verifier.recover_canonical_state(&manifest, root).unwrap() {
            CanonicalRecovery::SourceRetained(proof) => {
                assert!(abort_result.is_ok());
                assert!(matches!(
                    verifier.publish_ownership_commit(&manifest, &commit, root),
                    Err(MigrationError::Proof(
                        "source-retained authority decision already won terminal CAS"
                    ))
                ));
                proof.verify_binding(&manifest, root).unwrap();
            }
            CanonicalRecovery::OwnershipCommitted(observed) => {
                assert!(commit_result.is_ok());
                assert_eq!(*observed, commit);
                assert!(verifier.claim_source_retained(&manifest, root).is_err());
            }
            other => panic!("unexpected terminal authority state: {other:?}"),
        }
    }

    #[test]
    fn file_verifier_rebinds_embedded_commit_proof_to_manifest_and_receipt() {
        let temporary = TempDir::new().unwrap();
        let root = temporary.path();
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(root.join("authority")).unwrap();
        write_receipt(&root.join("authority/commit.json"), b"ownership committed\n");
        let manifest = manifest();
        let state_path = root.join("authority-state.json");
        let verifier =
            CanonicalAuthorityFileVerifier::new(&state_path, "authority/source-retained.json");
        verifier.initialize(&manifest).unwrap();
        let commit =
            CanonicalCommitProof::bind_receipt(&manifest, root, "authority/commit.json").unwrap();
        verifier.publish_ownership_commit(&manifest, &commit, root).unwrap();

        let mut forged = commit;
        forged.session_hex = "ff".repeat(16);
        let state = CanonicalAuthorityState {
            schema: CANONICAL_AUTHORITY_STATE_SCHEMA.to_owned(),
            generation: 2,
            migration_manifest_sha256: manifest.digest().unwrap().to_string(),
            decision: CanonicalAuthorityDecision::OwnershipCommitted,
            source_retained_proof: None,
            ownership_commit_proof: Some(forged.clone()),
            source_fence_proof: None,
        };
        let mut bytes = serde_json_canonicalizer::to_vec(&state).unwrap();
        bytes.push(b'\n');
        fs::write(&state_path, bytes).unwrap();
        fs::set_permissions(&state_path, fs::Permissions::from_mode(0o600)).unwrap();

        assert!(matches!(
            verifier.verify_ownership_commit(&manifest, &forged, root),
            Err(MigrationError::Proof("ownership commit proof binding differs"))
        ));
    }

    fn write_receipt(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn manifest() -> MigrationManifest {
        let bound = |semantic_path: &str, byte: u8| BoundFile {
            semantic_path: semantic_path.to_owned(),
            size: 1,
            sha256: format!("{byte:02x}").repeat(32),
        };
        MigrationManifest {
            schema: MANIFEST_SCHEMA.to_owned(),
            application: bound("application.aot", 1),
            compute_checkpoint: bound("checkpoint.pb", 2),
            resource_capsule_manifest: bound("capsule/manifest.json", 3),
            resource_capsule_state: bound("capsule/state.sqlite", 4),
            session_hex: "11".repeat(16),
            stable_owner_hex: "22".repeat(16),
            handoff_hex: "33".repeat(16),
            checkpoint_barrier_hex: "44".repeat(16),
            source_epoch: 1,
            destination_epoch: 2,
            clients: ClientLineage {
                source_client_hex: "55".repeat(16),
                source_restore_client_hex: "66".repeat(16),
                destination_client_hex: "77".repeat(16),
            },
            application_build: BuildIdentity {
                source_revision: "revision".to_owned(),
                toolchain: "toolchain".to_owned(),
                build_configuration_sha256: "88".repeat(32),
            },
            source_platform: platform("99"),
            destination_platform: platform("aa"),
        }
    }

    fn platform(digest_byte: &str) -> PlatformIdentity {
        PlatformIdentity {
            operating_system: "linux".to_owned(),
            architecture: "x86_64".to_owned(),
            abi: "wasi-preview1".to_owned(),
            runtime_name: "wanco".to_owned(),
            runtime_version: "locked".to_owned(),
            runtime_build_sha256: digest_byte.repeat(32),
        }
    }
}
