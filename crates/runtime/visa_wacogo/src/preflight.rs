use std::{
    env,
    ffi::OsString,
    fmt,
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
};

use contract_core::Digest;
use rustix::{
    fs::{MemfdFlags, SealFlags, fcntl_add_seals, fcntl_get_seals, memfd_create},
    io::Errno,
};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use visa_component_adapter::{
    AdapterError, PreflightExpectations, RuntimeIdentity, validate_preflight_contract,
};
use visa_profile::{CooperativeHandoffProfile, ProviderSupport};

use crate::{
    carrier::PreparedComponentBytes,
    identity::{WacogoProvenance, static_identity},
    process::PreparedProcess,
    state::decode_canonical_hex,
};

const SOURCE_LOCK: &str = include_str!("../../../../third_party/wacogo/source-lock.json");

pub struct PreparedWacogoComponent {
    pub(crate) process: PreparedProcess,
    pub(crate) component: PreparedComponentBytes,
    pub(crate) component_digest: Digest,
    pub(crate) profile_digest: Digest,
    pub(crate) identity: RuntimeIdentity,
    pub(crate) provenance: WacogoProvenance,
}

impl fmt::Debug for PreparedWacogoComponent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedWacogoComponent")
            .field("component_digest", &self.component_digest)
            .field("profile_digest", &self.profile_digest)
            .field("identity", &self.identity)
            .field("provenance", &self.provenance)
            .finish_non_exhaustive()
    }
}

impl PreparedWacogoComponent {
    pub const fn component_digest(&self) -> Digest {
        self.component_digest
    }

    pub const fn profile_digest(&self) -> Digest {
        self.profile_digest
    }

    pub fn runtime_identity(&self) -> &RuntimeIdentity {
        &self.identity
    }

    pub fn provenance(&self) -> &WacogoProvenance {
        &self.provenance
    }

    /// Explicitly close a prepared, non-instantiated sidecar through the
    /// production shutdown protocol. Ordinary `Drop` remains the failure and
    /// unwind fallback and terminates the child without claiming graceful exit.
    pub fn shutdown(self) -> Result<(), AdapterError> {
        self.process.shutdown()
    }
}

pub(crate) fn preflight(
    component_bytes: &[u8],
    profile: &CooperativeHandoffProfile,
    support: &ProviderSupport,
    expectations: PreflightExpectations,
) -> Result<PreparedWacogoComponent, AdapterError> {
    let component_digest =
        validate_preflight_contract(component_bytes, profile, support, expectations)?;
    let component = PreparedComponentBytes::capture(component_bytes, component_digest)?;
    let captured_component_digest = component.digest();
    let executable = open_verified_sidecar()?;
    let process = PreparedProcess::spawn(&executable.sealed_file, &component)?;
    let identity = static_identity();
    let provenance = process.runtime().provenance(
        executable.path_text.clone(),
        executable.digest,
        executable.size,
    );
    Ok(PreparedWacogoComponent {
        process,
        component,
        component_digest: captured_component_digest,
        profile_digest: expectations.profile_digest,
        identity,
        provenance,
    })
}

#[derive(Debug)]
struct VerifiedExecutable {
    sealed_file: File,
    path_text: String,
    digest: Digest,
    size: u64,
}

fn open_verified_sidecar() -> Result<VerifiedExecutable, AdapterError> {
    let configured = env::var_os("VISA_WACOGO_BIN").ok_or_else(|| {
        AdapterError::UnsupportedRuntimeFeature(
            "VISA_WACOGO_BIN must name the pinned production wacogo sidecar".into(),
        )
    })?;
    validate_embedded_source_lock()?;
    let expected = sidecar_binary_lock(SOURCE_LOCK)?;
    open_verified_sidecar_at(configured, &expected)
}

fn open_verified_sidecar_at(
    configured: OsString,
    expected: &SidecarBinary,
) -> Result<VerifiedExecutable, AdapterError> {
    let path = PathBuf::from(configured);
    let path_text = path
        .to_str()
        .ok_or_else(|| {
            AdapterError::UnsupportedRuntimeFeature(
                "VISA_WACOGO_BIN is not a valid UTF-8 path".into(),
            )
        })?
        .to_owned();
    let path_metadata = fs::symlink_metadata(&path).map_err(|error| {
        AdapterError::UnsupportedRuntimeFeature(format!(
            "inspecting wacogo sidecar {}: {error}",
            path.display()
        ))
    })?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(AdapterError::UnsupportedRuntimeFeature(format!(
            "wacogo sidecar must be a non-symlink regular file: {}",
            path.display()
        )));
    }
    let file = File::open(&path).map_err(|error| {
        AdapterError::UnsupportedRuntimeFeature(format!(
            "opening wacogo sidecar {}: {error}",
            path.display()
        ))
    })?;
    let metadata = file.metadata().map_err(|error| {
        AdapterError::UnsupportedRuntimeFeature(format!(
            "inspecting opened wacogo sidecar {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_file() || metadata.len() != expected.size {
        return Err(AdapterError::UnsupportedRuntimeFeature(format!(
            "wacogo sidecar size mismatch: expected {}, found {}",
            expected.size,
            metadata.len()
        )));
    }
    let (sealed_file, digest) = copy_verify_and_seal(file, expected)?;
    Ok(VerifiedExecutable { sealed_file, path_text, digest, size: expected.size })
}

fn validate_embedded_source_lock() -> Result<(), AdapterError> {
    let observed = hex::encode(Sha256::digest(SOURCE_LOCK.as_bytes()));
    if observed != crate::identity::SOURCE_LOCK_SHA256 {
        return Err(AdapterError::UnsupportedRuntimeFeature(format!(
            "embedded wacogo source-lock digest mismatch: expected {}, found {observed}",
            crate::identity::SOURCE_LOCK_SHA256
        )));
    }
    let lock: EmbeddedSourceLock = serde_json::from_str(SOURCE_LOCK).map_err(|error| {
        AdapterError::UnsupportedRuntimeFeature(format!(
            "decoding embedded third_party/wacogo/source-lock.json: {error}"
        ))
    })?;
    if lock.schema != crate::identity::SOURCE_LOCK_SCHEMA {
        return Err(AdapterError::UnsupportedRuntimeFeature(format!(
            "embedded wacogo source-lock schema mismatch: expected {}, found {}",
            crate::identity::SOURCE_LOCK_SCHEMA,
            lock.schema
        )));
    }
    Ok(())
}

fn copy_verify_and_seal(
    mut source: File,
    expected: &SidecarBinary,
) -> Result<(File, Digest), AdapterError> {
    source.seek(SeekFrom::Start(0)).map_err(|error| {
        AdapterError::UnsupportedRuntimeFeature(format!(
            "seeking configured wacogo sidecar before staging: {error}"
        ))
    })?;
    let mut staged = executable_memfd()?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut copied = 0_u64;
    loop {
        let count = source.read(&mut buffer).map_err(|error| {
            AdapterError::UnsupportedRuntimeFeature(format!(
                "reading configured wacogo sidecar while staging: {error}"
            ))
        })?;
        if count == 0 {
            break;
        }
        copied = copied.checked_add(count as u64).ok_or_else(|| {
            AdapterError::UnsupportedRuntimeFeature(
                "wacogo sidecar size overflow while staging".into(),
            )
        })?;
        if copied > expected.size {
            return Err(AdapterError::UnsupportedRuntimeFeature(format!(
                "wacogo sidecar size changed while staging: expected {}, found more than {}",
                expected.size, expected.size
            )));
        }
        staged.write_all(&buffer[..count]).map_err(|error| {
            AdapterError::UnsupportedRuntimeFeature(format!(
                "copying wacogo sidecar into executable memfd: {error}"
            ))
        })?;
        hasher.update(&buffer[..count]);
    }
    if copied != expected.size {
        return Err(AdapterError::UnsupportedRuntimeFeature(format!(
            "wacogo sidecar size changed while staging: expected {}, found {copied}",
            expected.size
        )));
    }
    let staged_size = staged.metadata().map_err(|error| {
        AdapterError::UnsupportedRuntimeFeature(format!(
            "inspecting staged wacogo executable memfd: {error}"
        ))
    })?;
    if staged_size.len() != copied {
        return Err(AdapterError::UnsupportedRuntimeFeature(format!(
            "staged wacogo executable size mismatch: copied {copied}, found {}",
            staged_size.len()
        )));
    }
    let digest = Digest::from_bytes(hasher.finalize().into());
    if digest != expected.digest {
        return Err(AdapterError::UnsupportedRuntimeFeature(format!(
            "wacogo sidecar digest mismatch: expected {}, found {}",
            expected.sha256,
            hex::encode(digest.0)
        )));
    }
    staged.seek(SeekFrom::Start(0)).map_err(|error| {
        AdapterError::UnsupportedRuntimeFeature(format!(
            "rewinding staged wacogo executable memfd: {error}"
        ))
    })?;
    seal_executable(&staged)?;
    Ok((staged, digest))
}

fn executable_memfd() -> Result<File, AdapterError> {
    let base_flags = MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING;
    let fd = match memfd_create("visa-wacogo-runtime", base_flags | MemfdFlags::EXEC) {
        Ok(fd) => fd,
        // MFD_EXEC was added in Linux 6.3; older kernels return EINVAL and
        // retain the legacy behavior where memfds are executable by default.
        Err(Errno::INVAL) => memfd_create("visa-wacogo-runtime", base_flags).map_err(|error| {
            AdapterError::UnsupportedRuntimeFeature(format!(
                "creating executable wacogo memfd after an MFD_EXEC compatibility retry: {error}"
            ))
        })?,
        Err(error) => {
            return Err(AdapterError::UnsupportedRuntimeFeature(format!(
                "creating executable wacogo memfd: {error}"
            )));
        }
    };
    Ok(File::from(fd))
}

fn required_executable_seals() -> SealFlags {
    SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL
}

fn seal_executable(file: &File) -> Result<(), AdapterError> {
    let required = required_executable_seals();
    fcntl_add_seals(file, required).map_err(|error| {
        AdapterError::UnsupportedRuntimeFeature(format!(
            "sealing staged wacogo executable memfd: {error}"
        ))
    })?;
    let observed = fcntl_get_seals(file).map_err(|error| {
        AdapterError::UnsupportedRuntimeFeature(format!(
            "reading staged wacogo executable memfd seals: {error}"
        ))
    })?;
    if !observed.contains(required) {
        return Err(AdapterError::UnsupportedRuntimeFeature(format!(
            "staged wacogo executable memfd is missing required seals: required {required:?}, found {observed:?}"
        )));
    }
    Ok(())
}

#[derive(Deserialize)]
struct SourceLock {
    production_artifacts: Option<ProductionArtifacts>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct EmbeddedSourceLock {
    schema: String,
    derivative: serde_json::Value,
    upstream: serde_json::Value,
    patchset: serde_json::Value,
    build_toolchain: serde_json::Value,
    build_policy: serde_json::Value,
    production_artifacts: serde_json::Value,
    redistribution_files: serde_json::Value,
}

#[derive(Deserialize)]
struct ProductionArtifacts {
    sidecar: SidecarArtifact,
}

#[derive(Deserialize)]
struct SidecarArtifact {
    binary: SidecarBinaryRecord,
}

#[derive(Deserialize)]
struct SidecarBinaryRecord {
    #[allow(dead_code)]
    file: String,
    size: u64,
    sha256: String,
}

#[derive(Debug)]
struct SidecarBinary {
    size: u64,
    sha256: String,
    digest: Digest,
}

fn sidecar_binary_lock(source: &str) -> Result<SidecarBinary, AdapterError> {
    let source: SourceLock = serde_json::from_str(source).map_err(|error| {
        AdapterError::UnsupportedRuntimeFeature(format!(
            "decoding third_party/wacogo/source-lock.json: {error}"
        ))
    })?;
    let binary = source
        .production_artifacts
        .ok_or_else(|| {
            AdapterError::UnsupportedRuntimeFeature(
                "wacogo source lock has no production_artifacts.sidecar identity".into(),
            )
        })?
        .sidecar
        .binary;
    let bytes = decode_canonical_hex(&binary.sha256).map_err(|detail| {
        AdapterError::UnsupportedRuntimeFeature(format!(
            "wacogo source-lock sidecar SHA-256 is invalid: {detail}"
        ))
    })?;
    let digest_bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        AdapterError::UnsupportedRuntimeFeature(
            "wacogo source-lock sidecar SHA-256 must contain 32 bytes".into(),
        )
    })?;
    Ok(SidecarBinary {
        size: binary.size,
        sha256: binary.sha256,
        digest: Digest::from_bytes(digest_bytes),
    })
}

#[cfg(test)]
mod tests {
    use std::{
        fs::OpenOptions,
        os::unix::fs::symlink,
        path::Path,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    static NEXT_TEST_FILE: AtomicU64 = AtomicU64::new(0);

    struct TestFile {
        path: PathBuf,
    }

    impl TestFile {
        fn create(bytes: &[u8]) -> Self {
            loop {
                let sequence = NEXT_TEST_FILE.fetch_add(1, Ordering::Relaxed);
                let path = env::temp_dir()
                    .join(format!("visa-wacogo-preflight-{}-{sequence}", std::process::id()));
                match OpenOptions::new().write(true).create_new(true).open(&path) {
                    Ok(mut file) => {
                        file.write_all(bytes).unwrap();
                        return Self { path };
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("creating test sidecar {}: {error}", path.display()),
                }
            }
        }

        fn symlink_to(target: &Path) -> Self {
            loop {
                let sequence = NEXT_TEST_FILE.fetch_add(1, Ordering::Relaxed);
                let path = env::temp_dir()
                    .join(format!("visa-wacogo-preflight-link-{}-{sequence}", std::process::id()));
                match symlink(target, &path) {
                    Ok(()) => return Self { path },
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => {
                        panic!("creating test sidecar symlink {}: {error}", path.display())
                    }
                }
            }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    fn expected_binary(bytes: &[u8]) -> SidecarBinary {
        let digest = Digest::from_bytes(Sha256::digest(bytes).into());
        SidecarBinary { size: bytes.len() as u64, sha256: hex::encode(digest.0), digest }
    }

    fn read_staged(file: &File) -> Vec<u8> {
        let mut file = file.try_clone().unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        bytes
    }

    #[test]
    fn production_binary_lock_requires_exact_size_and_lowercase_sha256() {
        let source = format!(
            r#"{{"production_artifacts":{{"sidecar":{{"binary":{{"file":"sidecar","size":7,"sha256":"{}"}}}}}}}}"#,
            "ab".repeat(32)
        );
        let lock = sidecar_binary_lock(&source).unwrap();
        assert_eq!(lock.size, 7);
        assert_eq!(lock.digest.0, [0xab; 32]);

        for invalid in ["AB".repeat(32), "a".repeat(63), "gg".repeat(32)] {
            let source = format!(
                r#"{{"production_artifacts":{{"sidecar":{{"binary":{{"file":"sidecar","size":7,"sha256":"{invalid}"}}}}}}}}"#
            );
            assert!(sidecar_binary_lock(&source).is_err());
        }
    }

    #[test]
    fn embedded_source_lock_digest_and_production_sidecar_identity_are_exact() {
        validate_embedded_source_lock().unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(SOURCE_LOCK.as_bytes())),
            crate::identity::SOURCE_LOCK_SHA256
        );
        let binary = sidecar_binary_lock(SOURCE_LOCK).unwrap();
        assert_eq!(binary.size, crate::identity::SIDECAR_EXECUTABLE_SIZE);
        assert_eq!(binary.sha256, crate::identity::SIDECAR_EXECUTABLE_SHA256);
    }

    #[test]
    fn missing_production_artifact_fails_closed_without_fallback() {
        let error = sidecar_binary_lock(r#"{"schema":"visa.wacogo-source-lock.v1"}"#)
            .expect_err("a source-only lock cannot select an executable");
        assert_eq!(
            error.kind(),
            visa_component_adapter::AdapterFailureKind::UnsupportedRuntimeFeature
        );
    }

    #[test]
    fn staged_executable_has_all_immutable_seals() {
        let bytes = b"trusted wacogo executable bytes";
        let configured = TestFile::create(bytes);
        let expected = expected_binary(bytes);
        let verified =
            open_verified_sidecar_at(configured.path().as_os_str().to_owned(), &expected).unwrap();

        let seals = fcntl_get_seals(&verified.sealed_file).unwrap();
        assert!(seals.contains(required_executable_seals()));
        let mut staged = verified.sealed_file.try_clone().unwrap();
        staged.seek(SeekFrom::Start(0)).unwrap();
        assert!(staged.write_all(b"!").is_err());
        assert!(staged.set_len(bytes.len() as u64 + 1).is_err());
        assert!(staged.set_len(bytes.len() as u64 - 1).is_err());
        assert!(fcntl_add_seals(&staged, SealFlags::FUTURE_WRITE).is_err());
    }

    #[test]
    fn modifying_and_replacing_configured_file_cannot_change_staged_bytes() {
        let bytes = b"trusted wacogo executable bytes";
        let configured = TestFile::create(bytes);
        let expected = expected_binary(bytes);
        let verified =
            open_verified_sidecar_at(configured.path().as_os_str().to_owned(), &expected).unwrap();

        fs::write(configured.path(), b"same inode was modified").unwrap();
        assert_eq!(read_staged(&verified.sealed_file), bytes);

        let replacement = TestFile::create(b"pathname now names a replacement inode");
        fs::rename(replacement.path(), configured.path()).unwrap();
        assert_eq!(read_staged(&verified.sealed_file), bytes);
        assert_eq!(verified.path_text, configured.path().to_str().unwrap());
        assert_eq!(verified.digest, expected.digest);
    }

    #[test]
    fn configured_sidecar_rejects_incorrect_size_and_digest() {
        let bytes = b"trusted wacogo executable bytes";
        let configured = TestFile::create(bytes);

        let mut wrong_size = expected_binary(bytes);
        wrong_size.size += 1;
        let size_error =
            open_verified_sidecar_at(configured.path().as_os_str().to_owned(), &wrong_size)
                .expect_err("an incorrect locked size must fail closed");
        assert_eq!(
            size_error.kind(),
            visa_component_adapter::AdapterFailureKind::UnsupportedRuntimeFeature
        );

        let mut wrong_digest = expected_binary(bytes);
        wrong_digest.digest = Digest::from_bytes([0x5a; 32]);
        wrong_digest.sha256 = hex::encode(wrong_digest.digest.0);
        let digest_error =
            open_verified_sidecar_at(configured.path().as_os_str().to_owned(), &wrong_digest)
                .expect_err("an incorrect locked digest must fail closed");
        assert_eq!(
            digest_error.kind(),
            visa_component_adapter::AdapterFailureKind::UnsupportedRuntimeFeature
        );
    }

    #[test]
    fn configured_sidecar_symlink_fails_closed_without_opening_a_fallback_path() {
        let bytes = b"trusted wacogo executable bytes";
        let target = TestFile::create(bytes);
        let configured = TestFile::symlink_to(target.path());
        let error = open_verified_sidecar_at(
            configured.path().as_os_str().to_owned(),
            &expected_binary(bytes),
        )
        .expect_err("a configured symlink must not be followed");
        assert_eq!(
            error.kind(),
            visa_component_adapter::AdapterFailureKind::UnsupportedRuntimeFeature
        );
        assert!(
            matches!(error, AdapterError::UnsupportedRuntimeFeature(detail) if detail.contains("non-symlink regular file"))
        );
    }
}
