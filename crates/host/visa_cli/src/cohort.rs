use std::{
    env,
    ffi::OsString,
    fs::{self, File},
    io::{self, Read},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

use rustix::{
    fs::{FileType, Mode, OFlags, fstat, open},
    process::geteuid,
    rand::{GetRandomFlags, getrandom},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json_canonicalizer::to_vec as to_jcs_vec;
use visa_agent_store::{AgentStoreError, StableAgentIdentity, publish_new};
use visa_durable_sqlite::{StoreLock, publish_private_noreplace};
use visa_local_rpc::common::{
    AgentRole, BootId, CohortId, LogicalIncarnation, PRODUCT_VERSION, ProcessNonce,
    RuntimeSessionId,
};

const RUNTIME_SCHEMA: &str = "visa.runtime-session.v1";
const MANIFEST_SCHEMA: &str = "visa.launch-manifest.v1";
const MARKER_PREFIX: &str = "visa.agent-store-initialized.v1";
const MAX_SMALL_FILE_BYTES: u64 = 1024 * 1024;

/// User-owned roots used by the local cohort preparation operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CohortRoots {
    pub runtime_root: PathBuf,
    pub state_root: PathBuf,
}

impl CohortRoots {
    pub fn new(runtime_root: PathBuf, state_root: PathBuf) -> Result<Self, String> {
        validate_root_path(&runtime_root, "runtime root")?;
        validate_root_path(&state_root, "state root")?;
        verify_directory(&runtime_root, true)
            .map_err(|error| format!("XDG_RUNTIME_DIR is not a private user directory: {error}"))?;
        verify_directory_if_present(&state_root, false)
            .map_err(|error| format!("state root is not a usable user directory: {error}"))?;
        Ok(Self { runtime_root, state_root })
    }

    pub fn from_environment() -> Result<Self, crate::CliError> {
        let runtime_root = env::var_os("XDG_RUNTIME_DIR").ok_or_else(|| {
            crate::CliError::Configuration("XDG_RUNTIME_DIR is required".to_owned())
        })?;
        let state_root = env::var_os("XDG_STATE_HOME")
            .or_else(|| {
                env::var_os("HOME")
                    .map(|home| PathBuf::from(home).join(".local/state").into_os_string())
            })
            .ok_or_else(|| {
                crate::CliError::Configuration("XDG_STATE_HOME or HOME is required".to_owned())
            })?;
        Self::new(PathBuf::from(runtime_root), PathBuf::from(state_root))
            .map_err(crate::CliError::Configuration)
    }

    fn runtime_base(&self) -> PathBuf {
        self.runtime_root.join("visa/0.1")
    }

    fn state_base(&self) -> PathBuf {
        self.state_root.join("visa/0.1")
    }
}

fn validate_root_path(path: &Path, label: &str) -> Result<(), String> {
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(component, std::path::Component::CurDir | std::path::Component::ParentDir)
        })
    {
        return Err(format!("{label} must be an absolute normalized path"));
    }
    if path.to_str().is_none() {
        return Err(format!("{label} must be valid UTF-8"));
    }
    match fs::symlink_metadata(path) {
        Ok(_) => {
            let canonical = fs::canonicalize(path)
                .map_err(|error| format!("cannot canonicalize {label}: {error}"))?;
            if canonical != path {
                return Err(format!("{label} must not contain symlink aliases"));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("cannot inspect {label}: {error}")),
    }
    Ok(())
}

/// The exact local manifest coordinates used by both persistent and active
/// launch records. Logical agent incarnation is intentionally not a manifest
/// field; it lives in the role store projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchManifest {
    pub schema: String,
    pub product_version: ProductVersionDocument,
    pub cohort_id: String,
    pub boot_id: String,
    pub runtime_session_id: String,
    pub state_path: String,
    pub runtime_path: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductVersionDocument {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeSessionDocument {
    schema: String,
    boot_id: String,
    runtime_session_id: String,
}

/// Result of the local preparation phase. `activation_pending` stays true
/// until a separate user-bus systemd layer completes StartUnit/health checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CohortPlan {
    pub cohort_id: CohortId,
    pub boot: BootId,
    pub runtime_session: RuntimeSessionId,
    pub state_path: PathBuf,
    pub runtime_path: PathBuf,
    pub manifest_path: PathBuf,
    pub active_manifest_path: PathBuf,
    pub source_identity: StableAgentIdentity,
    pub destination_identity: StableAgentIdentity,
    pub activation_pending: bool,
}

/// Local cohort coordinator. It owns no authority database and never emits a
/// receipt; its lease only serializes controller filesystem/activation work.
#[derive(Clone, Debug)]
pub struct CohortManager {
    roots: CohortRoots,
    boot: BootId,
    expected_runtime_session: Option<RuntimeSessionId>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct RolePreflight {
    database_present: bool,
    marker_present: bool,
}

impl RolePreflight {
    const fn complete(self) -> bool {
        self.database_present && self.marker_present
    }

    const fn any_present(self) -> bool {
        self.database_present || self.marker_present
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CohortPreflight {
    active_manifest: Option<LaunchManifest>,
    source: RolePreflight,
    destination: RolePreflight,
}

#[derive(Clone, Copy, Debug)]
struct RoleSpec<'a> {
    role: AgentRole,
    database_name: &'a str,
    marker_name: &'a str,
    cohort_id: CohortId,
    runtime_session: RuntimeSessionId,
}

impl CohortManager {
    pub fn from_environment() -> Result<Self, crate::CliError> {
        let roots = CohortRoots::from_environment()?;
        let boot = read_boot_id().map_err(crate::CliError::Temporary)?;
        Ok(Self { roots, boot, expected_runtime_session: None })
    }

    pub fn new(
        roots: CohortRoots,
        boot: BootId,
        runtime_session: RuntimeSessionId,
    ) -> Result<Self, String> {
        if boot == BootId::ZERO || runtime_session == RuntimeSessionId::ZERO {
            return Err("boot and runtime-session identities must be nonzero".to_owned());
        }
        Ok(Self { roots, boot, expected_runtime_session: Some(runtime_session) })
    }

    /// Execute the exact local preparation order from the release contract.
    pub fn create(&self, cohort_id: CohortId) -> Result<CohortPlan, crate::CliError> {
        if cohort_id == CohortId::ZERO {
            return Err(crate::CliError::Data("cohort id must be nonzero".to_owned()));
        }
        let encoded_cohort = encode_hex(cohort_id.0);
        let runtime_base = self.roots.runtime_base();
        let state_base = self.roots.state_base();
        let state_path = state_base.join("cohorts").join(&encoded_cohort);
        let runtime_path = runtime_base.join("cohorts").join(&encoded_cohort);
        let manifest_path = state_path.join("launch.json");
        let active_manifest_path = runtime_base.join("active-cohort.json");

        // The runtime root is required to exist before this first product
        // mutation. The flat lease itself is deliberately outside visa/0.1.
        verify_directory(&self.roots.runtime_root, true)
            .map_err(|error| crate::CliError::Configuration(error.to_string()))?;
        let _controller_lease =
            StoreLock::acquire(self.roots.runtime_root.join("visa-0.1-controller.lock"))
                .map_err(map_durable_error)?;

        // A missing runtime/session identity with retained cohort state is an
        // audit-only runtime-loss case. Do this read-only preflight before
        // creating any replacement runtime directories or files.
        let runtime_base_present = inspect_private_directory(&runtime_base, true)?;
        let state_path_present = inspect_private_directory(&state_path, true)?;
        let runtime_path_present = inspect_private_directory(&runtime_path, true)?;
        let active_manifest_present =
            path_present(&active_manifest_path).map_err(map_storage_error)?;
        let session_path = runtime_base.join("runtime-session.json");
        let session_present = path_present(&session_path).map_err(map_storage_error)?;
        if (!runtime_base_present || !session_present)
            && (state_path_present || runtime_path_present || active_manifest_present)
        {
            return Err(crate::CliError::Conflict(
                "runtime identity is missing while durable cohort state remains; audit-only"
                    .to_owned(),
            ));
        }

        // Only after the runtime-loss check may the controller create its
        // versioned directories and read/create the session identity.
        verify_or_create_directory(&runtime_base, true).map_err(map_io_error)?;
        let runtime_session =
            read_or_create_runtime_session(&runtime_base, self.boot, self.expected_runtime_session)
                .map_err(map_storage_error)?;
        if self.expected_runtime_session.is_some_and(|expected| expected != runtime_session) {
            return Err(crate::CliError::Conflict(
                "runtime-session identity changed during cohort preparation".to_owned(),
            ));
        }
        verify_or_create_directory(&state_base, false).map_err(map_io_error)?;

        let manifest = LaunchManifest {
            schema: MANIFEST_SCHEMA.to_owned(),
            product_version: ProductVersionDocument {
                major: PRODUCT_VERSION.major,
                minor: PRODUCT_VERSION.minor,
                patch: PRODUCT_VERSION.patch,
            },
            cohort_id: encoded_cohort,
            boot_id: encode_hex(self.boot.0),
            runtime_session_id: encode_hex(runtime_session.0),
            state_path: path_to_manifest_string(&state_path)?,
            runtime_path: path_to_manifest_string(&runtime_path)?,
        };
        let preflight = self.preflight(
            &state_path,
            &runtime_path,
            &manifest_path,
            &active_manifest_path,
            manifest.clone(),
        )?;

        ensure_private_directory(&state_base.join("cohorts")).map_err(map_io_error)?;
        ensure_private_directory(&state_path).map_err(map_io_error)?;
        ensure_private_directory(&runtime_base.join("cohorts")).map_err(map_io_error)?;
        ensure_private_directory(&runtime_path).map_err(map_io_error)?;

        // Persistent manifest precedes role-store initialization by contract.
        write_or_match_json(&manifest_path, &manifest).map_err(map_storage_error)?;
        let source_identity = self.prepare_role_store(
            &state_path,
            RoleSpec {
                role: AgentRole::Source,
                database_name: "source-agent.sqlite",
                marker_name: "source-agent.initialized",
                cohort_id,
                runtime_session,
            },
            preflight.source,
            preflight.active_manifest.is_some(),
        )?;
        let destination_identity = self.prepare_role_store(
            &state_path,
            RoleSpec {
                role: AgentRole::Destination,
                database_name: "destination-agent.sqlite",
                marker_name: "destination-agent.initialized",
                cohort_id,
                runtime_session,
            },
            preflight.destination,
            preflight.active_manifest.is_some(),
        )?;

        // Active manifest is the last local mutation. It is never an authority
        // receipt and can only be exact-retried.
        write_or_match_json(&active_manifest_path, &manifest).map_err(map_storage_error)?;
        Ok(CohortPlan {
            cohort_id,
            boot: self.boot,
            runtime_session,
            state_path,
            runtime_path,
            manifest_path,
            active_manifest_path,
            source_identity,
            destination_identity,
            activation_pending: true,
        })
    }

    fn preflight(
        &self,
        state_path: &Path,
        runtime_path: &Path,
        manifest_path: &Path,
        active_manifest_path: &Path,
        manifest: LaunchManifest,
    ) -> Result<CohortPreflight, crate::CliError> {
        let state_path_present = inspect_private_directory(state_path, true)?;
        let runtime_path_present = inspect_private_directory(runtime_path, true)?;
        if runtime_path_present && !state_path_present {
            return Err(crate::CliError::Conflict(
                "runtime cohort directory exists without durable state".to_owned(),
            ));
        }

        let source =
            inspect_role_preflight(state_path, "source-agent.sqlite", "source-agent.initialized")?;
        let destination = inspect_role_preflight(
            state_path,
            "destination-agent.sqlite",
            "destination-agent.initialized",
        )?;
        let persistent_manifest =
            read_optional_exact_json::<LaunchManifest>(manifest_path).map_err(map_storage_error)?;
        let active_manifest = read_optional_exact_json::<LaunchManifest>(active_manifest_path)
            .map_err(map_storage_error)?;

        if persistent_manifest.is_none() && (source.any_present() || destination.any_present()) {
            return Err(crate::CliError::Conflict(
                "role store exists without a persistent launch manifest".to_owned(),
            ));
        }
        if persistent_manifest.as_ref().is_some_and(|existing| existing != &manifest) {
            return Err(crate::CliError::Conflict(
                "existing persistent launch manifest differs from the exact retry".to_owned(),
            ));
        }
        if active_manifest.as_ref().is_some_and(|existing| existing != &manifest) {
            return Err(crate::CliError::Conflict(
                "a different active cohort manifest already exists".to_owned(),
            ));
        }
        if active_manifest.is_some()
            && (persistent_manifest.is_none() || !source.complete() || !destination.complete())
        {
            return Err(crate::CliError::Conflict(
                "active cohort has incomplete durable role state".to_owned(),
            ));
        }
        Ok(CohortPreflight { active_manifest, source, destination })
    }

    fn prepare_role_store(
        &self,
        state_path: &Path,
        spec: RoleSpec<'_>,
        preflight: RolePreflight,
        active_manifest_present: bool,
    ) -> Result<StableAgentIdentity, crate::CliError> {
        let database_path = state_path.join(spec.database_name);
        let marker_path = state_path.join(spec.marker_name);
        let identity = if preflight.database_present {
            let audit = visa_agent_store::inspect_existing_read_only(&database_path)
                .map_err(map_agent_error)?;
            let expected = audit.stable_identity;
            if expected.product_version != PRODUCT_VERSION
                || expected.cohort != spec.cohort_id
                || expected.boot != self.boot
                || expected.runtime_session != spec.runtime_session
                || expected.role != spec.role
            {
                return Err(crate::CliError::Conflict(format!(
                    "{0:?} agent store identity does not match the launch manifest",
                    spec.role
                )));
            }
            expected
        } else {
            if preflight.marker_present || active_manifest_present {
                return Err(crate::CliError::Conflict(format!(
                    "{0:?} agent store is missing after initialization",
                    spec.role
                )));
            }
            let identity = StableAgentIdentity {
                product_version: PRODUCT_VERSION,
                cohort: spec.cohort_id,
                boot: self.boot,
                runtime_session: spec.runtime_session,
                role: spec.role,
                logical_incarnation: LogicalIncarnation::from_bytes(
                    random_bytes()
                        .map_err(|error| crate::CliError::Temporary(error.to_string()))?,
                ),
            };
            publish_new(
                &database_path,
                identity,
                ProcessNonce::from_bytes(
                    random_bytes()
                        .map_err(|error| crate::CliError::Temporary(error.to_string()))?,
                ),
            )
            .map_err(map_agent_error)?;
            visa_agent_store::inspect_existing_read_only(&database_path)
                .map_err(map_agent_error)?;
            identity
        };
        if preflight.marker_present {
            verify_marker(&marker_path, spec.role).map_err(map_storage_error)?;
        } else {
            write_marker(&marker_path, spec.role).map_err(map_storage_error)?;
        }
        Ok(identity)
    }
}

fn inspect_private_directory(path: &Path, require_private: bool) -> Result<bool, crate::CliError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            verify_directory_metadata(&metadata, require_private).map(|_| true).map_err(|error| {
                crate::CliError::Conflict(format!(
                    "insecure or substituted directory {}: {error}",
                    path.display()
                ))
            })
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(crate::CliError::Temporary(error.to_string())),
    }
}

fn path_present(path: &Path) -> Result<bool, StorageError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(StorageError::Io(error.to_string())),
    }
}

fn inspect_role_preflight(
    state_path: &Path,
    database_name: &str,
    marker_name: &str,
) -> Result<RolePreflight, crate::CliError> {
    if !path_present(state_path).map_err(map_storage_error)? {
        return Ok(RolePreflight::default());
    }
    Ok(RolePreflight {
        database_present: path_present(&state_path.join(database_name))
            .map_err(map_storage_error)?,
        marker_present: path_present(&state_path.join(marker_name)).map_err(map_storage_error)?,
    })
}

fn path_to_manifest_string(path: &Path) -> Result<String, crate::CliError> {
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(component, std::path::Component::CurDir | std::path::Component::ParentDir)
        })
    {
        return Err(crate::CliError::Configuration(format!(
            "manifest path is not an absolute normalized path: {}",
            path.display()
        )));
    }
    path.to_str().map(str::to_owned).ok_or_else(|| {
        crate::CliError::Configuration("manifest paths must be valid UTF-8".to_owned())
    })
}

fn read_boot_id() -> Result<BootId, String> {
    let value = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|error| format!("cannot read boot id: {error}"))?;
    let boot = parse_fixed_hex::<16>(value.trim()).map(BootId::from_bytes)?;
    if boot == BootId::ZERO {
        return Err("kernel boot id must be nonzero".to_owned());
    }
    Ok(boot)
}

fn read_or_create_runtime_session(
    runtime_base: &Path,
    expected_boot: BootId,
    requested_session: Option<RuntimeSessionId>,
) -> Result<RuntimeSessionId, StorageError> {
    verify_or_create_directory(runtime_base, true)
        .map_err(|error| StorageError::Io(error.to_string()))?;
    let path = runtime_base.join("runtime-session.json");
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            let document: RuntimeSessionDocument = read_exact_json(&path)?;
            if document.schema != RUNTIME_SCHEMA {
                return Err(StorageError::Conflict("runtime-session schema mismatch".to_owned()));
            }
            let boot = parse_fixed_hex::<16>(&document.boot_id)
                .map(BootId::from_bytes)
                .map_err(StorageError::Conflict)?;
            let session = parse_fixed_hex::<16>(&document.runtime_session_id)
                .map(RuntimeSessionId::from_bytes)
                .map_err(StorageError::Conflict)?;
            if boot != expected_boot || session == RuntimeSessionId::ZERO {
                return Err(StorageError::Conflict(
                    "runtime-session boot or identity mismatch".to_owned(),
                ));
            }
            Ok(session)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let session = match requested_session {
                Some(session) if session != RuntimeSessionId::ZERO => session,
                Some(_) => {
                    return Err(StorageError::Conflict(
                        "requested runtime-session identity is zero".to_owned(),
                    ));
                }
                None => RuntimeSessionId::from_bytes(
                    random_bytes().map_err(|error| StorageError::Io(error.to_string()))?,
                ),
            };
            let document = RuntimeSessionDocument {
                schema: RUNTIME_SCHEMA.to_owned(),
                boot_id: encode_hex(expected_boot.0),
                runtime_session_id: encode_hex(session.0),
            };
            write_or_match_json(&path, &document)?;
            Ok(session)
        }
        Err(error) => Err(StorageError::Io(error.to_string())),
    }
}

fn write_marker(path: &Path, role: AgentRole) -> Result<(), StorageError> {
    let bytes = marker_bytes(role);
    match create_private_file(path, &bytes) {
        Ok(()) => Ok(()),
        Err(StorageError::AlreadyExists) => {
            let existing = read_private_bytes(path)?;
            if existing == bytes {
                Ok(())
            } else {
                Err(StorageError::Conflict("agent-store initialization marker mismatch".to_owned()))
            }
        }
        Err(error) => Err(error),
    }
}

fn verify_marker(path: &Path, role: AgentRole) -> Result<(), StorageError> {
    let expected = marker_bytes(role);
    let existing = read_private_bytes(path)?;
    if existing == expected {
        Ok(())
    } else {
        Err(StorageError::Conflict("agent-store initialization marker mismatch".to_owned()))
    }
}

fn marker_bytes(role: AgentRole) -> Vec<u8> {
    format!("{MARKER_PREFIX}:{role:?}\n").into_bytes()
}

fn write_or_match_json<T>(path: &Path, value: &T) -> Result<(), StorageError>
where
    T: Serialize,
{
    let bytes = to_jcs_vec(value).map_err(|error| StorageError::Json(error.to_string()))?;
    match create_private_file(path, &bytes) {
        Ok(()) => Ok(()),
        Err(StorageError::AlreadyExists) => {
            let existing = read_private_bytes(path)?;
            if existing == bytes {
                Ok(())
            } else {
                Err(StorageError::Conflict(format!(
                    "existing manifest {} differs from the exact retry",
                    path.display()
                )))
            }
        }
        Err(error) => Err(error),
    }
}

fn read_exact_json<T>(path: &Path) -> Result<T, StorageError>
where
    T: DeserializeOwned + Serialize,
{
    let bytes = read_private_bytes(path)?;
    let value = serde_json::from_slice::<T>(&bytes)
        .map_err(|error| StorageError::Json(error.to_string()))?;
    let canonical = to_jcs_vec(&value).map_err(|error| StorageError::Json(error.to_string()))?;
    if canonical != bytes {
        return Err(StorageError::Conflict(format!(
            "{} is not exact canonical JSON",
            path.display()
        )));
    }
    Ok(value)
}

fn read_optional_exact_json<T>(path: &Path) -> Result<Option<T>, StorageError>
where
    T: DeserializeOwned + Serialize,
{
    match fs::symlink_metadata(path) {
        Ok(_) => read_exact_json(path).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(StorageError::Io(error.to_string())),
    }
}

fn create_private_file(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
    if bytes.len() > MAX_SMALL_FILE_BYTES as usize {
        return Err(StorageError::TooLarge);
    }
    let nonce = random_bytes().map_err(|error| StorageError::Io(error.to_string()))?;
    publish_private_noreplace(path, bytes, nonce).map_err(|error| match error {
        visa_durable_sqlite::DurableStoreError::AlreadyExists => StorageError::AlreadyExists,
        visa_durable_sqlite::DurableStoreError::InvalidPath
        | visa_durable_sqlite::DurableStoreError::Missing
        | visa_durable_sqlite::DurableStoreError::Insecure
        | visa_durable_sqlite::DurableStoreError::SidecarExists
        | visa_durable_sqlite::DurableStoreError::NotSqlite
        | visa_durable_sqlite::DurableStoreError::Integrity => {
            StorageError::Conflict(error.to_string())
        }
        visa_durable_sqlite::DurableStoreError::Busy
        | visa_durable_sqlite::DurableStoreError::Io(_)
        | visa_durable_sqlite::DurableStoreError::Sqlite(_) => StorageError::Io(error.to_string()),
    })
}

fn read_private_bytes(path: &Path) -> Result<Vec<u8>, StorageError> {
    let descriptor = open(path, OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW, Mode::empty())
        .map_err(|error| match error {
            rustix::io::Errno::NOENT => StorageError::Missing,
            rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR => StorageError::Conflict(format!(
                "refusing symlink or non-directory parent for {}",
                path.display()
            )),
            other => StorageError::Io(other.to_string()),
        })?;
    let stat = fstat(&descriptor).map_err(|error| StorageError::Io(error.to_string()))?;
    let mode = Mode::from_raw_mode(stat.st_mode) & (Mode::RWXU | Mode::RWXG | Mode::RWXO);
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != geteuid().as_raw()
        || stat.st_nlink != 1
        || mode != Mode::RUSR | Mode::WUSR
        || stat.st_size < 0
        || stat.st_size as u64 > MAX_SMALL_FILE_BYTES
    {
        return Err(StorageError::Conflict(format!("insecure file {}", path.display())));
    }
    let mut file: File = descriptor.into();
    let mut bytes = Vec::with_capacity(stat.st_size as usize);
    file.read_to_end(&mut bytes).map_err(|error| StorageError::Io(error.to_string()))?;
    let final_stat = fstat(&file).map_err(|error| StorageError::Io(error.to_string()))?;
    if final_stat.st_size != bytes.len() as i64 {
        return Err(StorageError::Conflict(format!("file {} changed during read", path.display())));
    }
    Ok(bytes)
}

fn ensure_private_directory(path: &Path) -> Result<(), io::Error> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => verify_directory_metadata(&metadata, true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            let metadata = fs::symlink_metadata(path)?;
            verify_directory_metadata(&metadata, true)
        }
        Err(error) => Err(error),
    }
}

fn verify_or_create_directory(path: &Path, require_private: bool) -> Result<(), io::Error> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => verify_directory_metadata(&metadata, require_private),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path)?;
            if require_private {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            }
            let metadata = fs::symlink_metadata(path)?;
            verify_directory_metadata(&metadata, require_private)
        }
        Err(error) => Err(error),
    }
}

fn verify_directory_if_present(path: &Path, require_private: bool) -> Result<(), io::Error> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => verify_directory_metadata(&metadata, require_private),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn verify_directory(path: &Path, require_private: bool) -> Result<(), io::Error> {
    let metadata = fs::symlink_metadata(path)?;
    verify_directory_metadata(&metadata, require_private)
}

fn verify_directory_metadata(
    metadata: &fs::Metadata,
    require_private: bool,
) -> Result<(), io::Error> {
    let mode = metadata.mode() & 0o777;
    if !metadata.file_type().is_dir()
        || metadata.uid() != geteuid().as_raw()
        || (require_private && mode != 0o700)
        || (!require_private && mode & 0o022 != 0)
    {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "directory is not private"));
    }
    Ok(())
}

fn random_bytes() -> Result<[u8; 16], io::Error> {
    loop {
        let mut bytes = [0_u8; 16];
        let mut filled = 0;
        while filled < bytes.len() {
            let count = getrandom(&mut bytes[filled..], GetRandomFlags::empty())?;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "getrandom returned no bytes",
                ));
            }
            filled += count;
        }
        if bytes != [0; 16] {
            return Ok(bytes);
        }
    }
}

fn encode_hex(bytes: [u8; 16]) -> String {
    let mut output = String::with_capacity(32);
    for byte in bytes {
        output.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
        output.push(char::from(b"0123456789abcdef"[(byte & 0x0f) as usize]));
    }
    output
}

pub(crate) fn parse_cohort_id(value: &OsString) -> Result<CohortId, String> {
    let value = value.to_str().ok_or_else(|| "cohort id is not UTF-8".to_owned())?;
    parse_fixed_hex::<16>(value).map(CohortId::from_bytes)
}

fn parse_fixed_hex<const N: usize>(value: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(format!("expected exactly {} lowercase hexadecimal characters", N * 2));
    }
    let mut output = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(output)
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("invalid lowercase hexadecimal digit".to_owned()),
    }
}

fn map_agent_error(error: AgentStoreError) -> crate::CliError {
    match error {
        AgentStoreError::InvalidRequest => {
            crate::CliError::Data("invalid agent store identity".to_owned())
        }
        AgentStoreError::StoreBusy => crate::CliError::Temporary("agent store is busy".to_owned()),
        AgentStoreError::StoreMismatch => {
            crate::CliError::Conflict("agent store identity or path mismatch".to_owned())
        }
        AgentStoreError::Integrity => {
            crate::CliError::Integrity("agent store integrity audit failed".to_owned())
        }
        AgentStoreError::Storage => crate::CliError::Temporary("agent store I/O failed".to_owned()),
    }
}

fn map_storage_error(error: StorageError) -> crate::CliError {
    match error {
        StorageError::Conflict(message) => crate::CliError::Conflict(message),
        StorageError::AlreadyExists => crate::CliError::Conflict("file already exists".to_owned()),
        StorageError::Missing => {
            crate::CliError::Conflict("required durable file is missing".to_owned())
        }
        StorageError::TooLarge => {
            crate::CliError::Integrity("durable file exceeds the fixed size bound".to_owned())
        }
        StorageError::Json(message) => crate::CliError::Integrity(message),
        StorageError::Io(message) => crate::CliError::Temporary(message),
    }
}

fn map_io_error(error: io::Error) -> crate::CliError {
    map_storage_error(StorageError::Io(error.to_string()))
}

fn map_durable_error(error: visa_durable_sqlite::DurableStoreError) -> crate::CliError {
    match error {
        visa_durable_sqlite::DurableStoreError::Busy => {
            crate::CliError::Temporary("controller operation is already in progress".to_owned())
        }
        visa_durable_sqlite::DurableStoreError::InvalidPath
        | visa_durable_sqlite::DurableStoreError::Missing
        | visa_durable_sqlite::DurableStoreError::Insecure
        | visa_durable_sqlite::DurableStoreError::SidecarExists
        | visa_durable_sqlite::DurableStoreError::AlreadyExists => {
            crate::CliError::Configuration(error.to_string())
        }
        visa_durable_sqlite::DurableStoreError::NotSqlite
        | visa_durable_sqlite::DurableStoreError::Integrity => {
            crate::CliError::Integrity(error.to_string())
        }
        visa_durable_sqlite::DurableStoreError::Io(_)
        | visa_durable_sqlite::DurableStoreError::Sqlite(_) => {
            crate::CliError::Temporary(error.to_string())
        }
    }
}

#[derive(Debug)]
enum StorageError {
    Conflict(String),
    AlreadyExists,
    Missing,
    TooLarge,
    Json(String),
    Io(String),
}

impl From<io::Error> for StorageError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.to_string())
    }
}
