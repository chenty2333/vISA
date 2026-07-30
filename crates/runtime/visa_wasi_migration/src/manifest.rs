use std::{
    collections::BTreeSet,
    fmt,
    fs::{self, File},
    io::{BufReader, Read},
    os::unix::fs::OpenOptionsExt,
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use visa_wasi_protocol::{BarrierToken, ClientId, OwnerId, SessionId};

use crate::MigrationError;

pub const MANIFEST_SCHEMA: &str = "visa-transparent-wasi-migration-v3";
pub const APPLICATION_ROLE: &str = "application";
pub const CHECKPOINT_ROLE: &str = "compute-checkpoint";
pub const CAPSULE_MANIFEST_ROLE: &str = "resource-capsule-manifest";
pub const CAPSULE_STATE_ROLE: &str = "resource-capsule-state";

const PROVIDER_CAPSULE_SCHEMA: &str = "visa-wasi-filesystem-capsule-v2";
const STREAM_BUFFER_BYTES: usize = 128 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManifestDigest(pub [u8; 32]);

impl fmt::Display for ManifestDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex(&self.0))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundFile {
    pub semantic_path: String,
    pub size: u64,
    pub sha256: String,
}

impl BoundFile {
    pub fn verify_at(&self, root: &Path) -> Result<PathBuf, MigrationError> {
        validate_semantic_path(&self.semantic_path)?;
        validate_sha256(&self.sha256, "file sha256")?;
        let path = resolve_file(root, &self.semantic_path)?;
        let (size, digest) = hash_file(&path)?;
        if size != self.size || digest != self.sha256 {
            return Err(MigrationError::Integrity("bound file content differs"));
        }
        Ok(path)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRoles {
    pub application: String,
    pub compute_checkpoint: String,
    pub resource_capsule_manifest: String,
    pub resource_capsule_state: String,
}

impl FileRoles {
    fn validate(&self) -> Result<(), MigrationError> {
        let values = [
            &self.application,
            &self.compute_checkpoint,
            &self.resource_capsule_manifest,
            &self.resource_capsule_state,
        ];
        for value in values {
            validate_semantic_path(value)?;
        }
        let unique = values.into_iter().collect::<BTreeSet<_>>();
        if unique.len() != 4 {
            return Err(MigrationError::Invalid("semantic file roles are not unique"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildIdentity {
    pub source_revision: String,
    pub toolchain: String,
    pub build_configuration_sha256: String,
}

impl BuildIdentity {
    fn validate(&self) -> Result<(), MigrationError> {
        require_text(&self.source_revision, "source revision")?;
        require_text(&self.toolchain, "toolchain")?;
        validate_sha256(&self.build_configuration_sha256, "build configuration sha256")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformIdentity {
    pub operating_system: String,
    pub architecture: String,
    pub abi: String,
    pub runtime_name: String,
    pub runtime_version: String,
    pub runtime_build_sha256: String,
}

impl PlatformIdentity {
    fn validate(&self) -> Result<(), MigrationError> {
        require_text(&self.operating_system, "operating system")?;
        require_text(&self.architecture, "architecture")?;
        require_text(&self.abi, "ABI")?;
        require_text(&self.runtime_name, "runtime name")?;
        require_text(&self.runtime_version, "runtime version")?;
        validate_sha256(&self.runtime_build_sha256, "runtime build sha256")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientLineage {
    pub source_client_hex: String,
    pub source_restore_client_hex: String,
    pub destination_client_hex: String,
}

impl ClientLineage {
    fn validate(&self) -> Result<(), MigrationError> {
        validate_identity_hex(&self.source_client_hex, 16, "source client")?;
        validate_identity_hex(&self.source_restore_client_hex, 16, "source restore client")?;
        validate_identity_hex(&self.destination_client_hex, 16, "destination client")?;
        let clients = [
            self.source_client_hex.as_str(),
            self.source_restore_client_hex.as_str(),
            self.destination_client_hex.as_str(),
        ];
        if clients.into_iter().collect::<BTreeSet<_>>().len() != 3 {
            return Err(MigrationError::Invalid(
                "source, source-restore, and destination clients must be distinct",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationIntent {
    pub files: FileRoles,
    pub session: SessionId,
    pub stable_owner: OwnerId,
    pub handoff: [u8; 16],
    /// Exact post-hostcall barrier whose checkpoint release made the resource
    /// projection eligible for freeze.
    pub checkpoint_barrier: BarrierToken,
    pub source_epoch: u64,
    pub destination_epoch: u64,
    pub source_client: ClientId,
    /// Fresh native-process identity used only when a pre-commit abort restores
    /// the source checkpoint. Native bridge request counters are not guest
    /// checkpoint state, so reusing `source_client` would alias old sequences.
    pub source_restore_client: ClientId,
    pub destination_client: ClientId,
    pub application_build: BuildIdentity,
    pub source_platform: PlatformIdentity,
    pub destination_platform: PlatformIdentity,
}

impl MigrationIntent {
    pub fn validate(&self) -> Result<(), MigrationError> {
        self.files.validate()?;
        if self.session.is_zero() {
            return Err(MigrationError::Invalid("zero session identity"));
        }
        if self.stable_owner.is_zero() {
            return Err(MigrationError::Invalid("zero stable owner identity"));
        }
        if self.handoff == [0; 16] {
            return Err(MigrationError::Invalid("zero handoff identity"));
        }
        if self.checkpoint_barrier.is_zero() {
            return Err(MigrationError::Invalid("zero checkpoint barrier identity"));
        }
        if self.source_client.is_zero()
            || self.source_restore_client.is_zero()
            || self.destination_client.is_zero()
        {
            return Err(MigrationError::Invalid("zero client identity"));
        }
        if [self.source_client, self.source_restore_client, self.destination_client]
            .into_iter()
            .collect::<BTreeSet<_>>()
            .len()
            != 3
        {
            return Err(MigrationError::Invalid(
                "source, source-restore, and destination clients must be distinct",
            ));
        }
        if self.source_epoch == 0
            || self.destination_epoch
                != self
                    .source_epoch
                    .checked_add(1)
                    .ok_or(MigrationError::Invalid("authority epoch overflow"))?
        {
            return Err(MigrationError::Invalid(
                "destination epoch must immediately follow source epoch",
            ));
        }
        self.application_build.validate()?;
        self.source_platform.validate()?;
        self.destination_platform.validate()
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, MigrationError> {
        self.validate()?;
        serde_json_canonicalizer::to_vec(self)
            .map_err(|error| MigrationError::Codec(error.to_string()))
    }

    pub fn digest(&self) -> Result<ManifestDigest, MigrationError> {
        Ok(ManifestDigest(Sha256::digest(self.canonical_bytes()?).into()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationManifest {
    pub schema: String,
    pub application: BoundFile,
    pub compute_checkpoint: BoundFile,
    pub resource_capsule_manifest: BoundFile,
    pub resource_capsule_state: BoundFile,
    pub session_hex: String,
    pub stable_owner_hex: String,
    pub handoff_hex: String,
    pub checkpoint_barrier_hex: String,
    pub source_epoch: u64,
    pub destination_epoch: u64,
    pub clients: ClientLineage,
    pub application_build: BuildIdentity,
    pub source_platform: PlatformIdentity,
    pub destination_platform: PlatformIdentity,
}

impl MigrationManifest {
    pub fn seal(intent: &MigrationIntent, root: &Path) -> Result<Self, MigrationError> {
        intent.validate()?;
        let manifest = Self {
            schema: MANIFEST_SCHEMA.to_owned(),
            application: bind_file(root, &intent.files.application)?,
            compute_checkpoint: bind_file(root, &intent.files.compute_checkpoint)?,
            resource_capsule_manifest: bind_file(root, &intent.files.resource_capsule_manifest)?,
            resource_capsule_state: bind_file(root, &intent.files.resource_capsule_state)?,
            session_hex: hex(&intent.session.0),
            stable_owner_hex: hex(&intent.stable_owner.0),
            handoff_hex: hex(&intent.handoff),
            checkpoint_barrier_hex: hex(&intent.checkpoint_barrier.0),
            source_epoch: intent.source_epoch,
            destination_epoch: intent.destination_epoch,
            clients: ClientLineage {
                source_client_hex: hex(&intent.source_client.0),
                source_restore_client_hex: hex(&intent.source_restore_client.0),
                destination_client_hex: hex(&intent.destination_client.0),
            },
            application_build: intent.application_build.clone(),
            source_platform: intent.source_platform.clone(),
            destination_platform: intent.destination_platform.clone(),
        };
        manifest.verify_at(root)?;
        Ok(manifest)
    }

    pub fn verify_at(&self, root: &Path) -> Result<(), MigrationError> {
        self.validate_structure()?;
        self.application.verify_at(root)?;
        self.compute_checkpoint.verify_at(root)?;
        let capsule_manifest_path = self.resource_capsule_manifest.verify_at(root)?;
        self.resource_capsule_state.verify_at(root)?;
        self.verify_provider_capsule(root, &capsule_manifest_path)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, MigrationError> {
        self.validate_structure()?;
        serde_json_canonicalizer::to_vec(self)
            .map_err(|error| MigrationError::Codec(error.to_string()))
    }

    pub fn digest(&self) -> Result<ManifestDigest, MigrationError> {
        let bytes = self.canonical_bytes()?;
        Ok(ManifestDigest(Sha256::digest(bytes).into()))
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, MigrationError> {
        let manifest: Self = serde_json::from_slice(bytes)
            .map_err(|error| MigrationError::Codec(error.to_string()))?;
        if manifest.canonical_bytes()? != bytes {
            return Err(MigrationError::Integrity(
                "migration manifest is not canonical RFC 8785 JSON",
            ));
        }
        Ok(manifest)
    }

    pub fn write_new(&self, path: &Path) -> Result<(), MigrationError> {
        let bytes = self.canonical_bytes()?;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = options.open(path).map_err(MigrationError::Io)?;
        use std::io::Write as _;
        file.write_all(&bytes).map_err(MigrationError::Io)?;
        file.sync_all().map_err(MigrationError::Io)?;
        let parent = path
            .parent()
            .filter(|value| !value.as_os_str().is_empty())
            .ok_or(MigrationError::Invalid("manifest path has no parent"))?;
        File::open(parent).and_then(|directory| directory.sync_all()).map_err(MigrationError::Io)
    }

    fn validate_structure(&self) -> Result<(), MigrationError> {
        if self.schema != MANIFEST_SCHEMA {
            return Err(MigrationError::Invalid("unsupported migration manifest schema"));
        }
        let files = [
            &self.application,
            &self.compute_checkpoint,
            &self.resource_capsule_manifest,
            &self.resource_capsule_state,
        ];
        let mut paths = BTreeSet::new();
        for file in files {
            validate_semantic_path(&file.semantic_path)?;
            validate_sha256(&file.sha256, "file sha256")?;
            if !paths.insert(&file.semantic_path) {
                return Err(MigrationError::Invalid("semantic file roles are not unique"));
            }
        }
        validate_identity_hex(&self.session_hex, 16, "session")?;
        validate_identity_hex(&self.stable_owner_hex, 16, "stable owner")?;
        validate_identity_hex(&self.handoff_hex, 16, "handoff")?;
        validate_identity_hex(&self.checkpoint_barrier_hex, 16, "checkpoint barrier")?;
        self.clients.validate()?;
        if self.source_epoch == 0
            || self.destination_epoch
                != self
                    .source_epoch
                    .checked_add(1)
                    .ok_or(MigrationError::Invalid("authority epoch overflow"))?
        {
            return Err(MigrationError::Invalid(
                "destination epoch must immediately follow source epoch",
            ));
        }
        self.application_build.validate()?;
        self.source_platform.validate()?;
        self.destination_platform.validate()
    }

    fn verify_provider_capsule(
        &self,
        root: &Path,
        capsule_manifest_path: &Path,
    ) -> Result<(), MigrationError> {
        let bytes = fs::read(capsule_manifest_path).map_err(MigrationError::Io)?;
        let descriptor: ProviderCapsuleDescriptor = serde_json::from_slice(&bytes)
            .map_err(|error| MigrationError::Codec(error.to_string()))?;
        let canonical = serde_json::to_vec_pretty(&descriptor)
            .map_err(|error| MigrationError::Codec(error.to_string()))?;
        if canonical != bytes {
            return Err(MigrationError::Integrity(
                "provider capsule manifest is not its canonical encoding",
            ));
        }
        descriptor.validate()?;
        if descriptor.schema != PROVIDER_CAPSULE_SCHEMA
            || descriptor.session_hex != self.session_hex
            || descriptor.handoff_hex != self.handoff_hex
            || descriptor.source_epoch != self.source_epoch
            || descriptor.destination_epoch != self.destination_epoch
            || descriptor.state_size != self.resource_capsule_state.size
            || descriptor.state_sha256 != self.resource_capsule_state.sha256
        {
            return Err(MigrationError::Integrity(
                "provider capsule binding differs from migration manifest",
            ));
        }
        let provider_manifest_semantic = Path::new(&self.resource_capsule_manifest.semantic_path);
        let expected_state_semantic = provider_manifest_semantic
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .join(&descriptor.state_file);
        if expected_state_semantic != Path::new(&self.resource_capsule_state.semantic_path) {
            return Err(MigrationError::Integrity(
                "provider capsule state role resolves to a different file",
            ));
        }
        let expected_state = resolve_file(root, &self.resource_capsule_state.semantic_path)?;
        let described_state = capsule_manifest_path
            .parent()
            .ok_or(MigrationError::Invalid("capsule manifest has no parent"))?
            .join(&descriptor.state_file);
        if fs::canonicalize(&described_state).map_err(MigrationError::Io)?
            != fs::canonicalize(&expected_state).map_err(MigrationError::Io)?
        {
            return Err(MigrationError::Integrity(
                "provider capsule manifest points outside the bound state role",
            ));
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderCapsuleDescriptor {
    schema: String,
    session_hex: String,
    source_epoch: u64,
    destination_epoch: u64,
    handoff_hex: String,
    state_file: String,
    state_size: u64,
    state_sha256: String,
}

impl ProviderCapsuleDescriptor {
    fn validate(&self) -> Result<(), MigrationError> {
        validate_identity_hex(&self.session_hex, 16, "capsule session")?;
        validate_identity_hex(&self.handoff_hex, 16, "capsule handoff")?;
        validate_semantic_path(&self.state_file)?;
        if Path::new(&self.state_file).components().count() != 1 {
            return Err(MigrationError::Invalid(
                "provider state file must be a direct bundle child",
            ));
        }
        validate_sha256(&self.state_sha256, "capsule state sha256")
    }
}

fn bind_file(root: &Path, semantic_path: &str) -> Result<BoundFile, MigrationError> {
    validate_semantic_path(semantic_path)?;
    let path = resolve_file(root, semantic_path)?;
    let (size, sha256) = hash_file(&path)?;
    Ok(BoundFile { semantic_path: semantic_path.to_owned(), size, sha256 })
}

pub(crate) fn resolve_file(root: &Path, semantic_path: &str) -> Result<PathBuf, MigrationError> {
    validate_semantic_path(semantic_path)?;
    let root = fs::canonicalize(root).map_err(MigrationError::Io)?;
    let candidate = root.join(semantic_path);
    let metadata = fs::symlink_metadata(&candidate).map_err(MigrationError::Io)?;
    if !metadata.file_type().is_file() {
        return Err(MigrationError::Invalid("bound artifact is not a regular file"));
    }
    let canonical = fs::canonicalize(&candidate).map_err(MigrationError::Io)?;
    if !canonical.starts_with(&root) {
        return Err(MigrationError::Invalid("bound artifact escapes its root"));
    }
    Ok(canonical)
}

pub(crate) fn hash_file(path: &Path) -> Result<(u64, String), MigrationError> {
    let file = File::open(path).map_err(MigrationError::Io)?;
    let mut reader = BufReader::with_capacity(STREAM_BUFFER_BYTES, file);
    let mut buffer = [0_u8; STREAM_BUFFER_BYTES];
    let mut size = 0_u64;
    let mut digest = Sha256::new();
    loop {
        let read = reader.read(&mut buffer).map_err(MigrationError::Io)?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(
                u64::try_from(read)
                    .map_err(|_| MigrationError::Invalid("file size conversion overflow"))?,
            )
            .ok_or(MigrationError::Invalid("file size overflow"))?;
        digest.update(&buffer[..read]);
    }
    Ok((size, hex(&digest.finalize())))
}

pub(crate) fn validate_semantic_path(value: &str) -> Result<(), MigrationError> {
    if value.is_empty()
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains('\\')
        || value.bytes().any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(MigrationError::Invalid("non-canonical semantic path"));
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path.components().any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(MigrationError::Invalid("non-canonical semantic path"));
    }
    Ok(())
}

pub(crate) fn validate_sha256(value: &str, label: &'static str) -> Result<(), MigrationError> {
    if value.len() != 64
        || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(MigrationError::Invalid(label));
    }
    Ok(())
}

fn validate_identity_hex(
    value: &str,
    bytes: usize,
    label: &'static str,
) -> Result<(), MigrationError> {
    if value.len() != bytes * 2
        || value.bytes().all(|byte| byte == b'0')
        || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(MigrationError::Invalid(label));
    }
    Ok(())
}

fn require_text(value: &str, label: &'static str) -> Result<(), MigrationError> {
    if value.is_empty()
        || value.trim() != value
        || value.bytes().any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(MigrationError::Invalid(label));
    }
    Ok(())
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}
