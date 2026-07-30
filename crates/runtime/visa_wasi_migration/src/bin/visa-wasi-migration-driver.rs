use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use visa_wasi_migration::{
    BuildIdentity, CanonicalAuthorityFileVerifier, CanonicalCommitProof,
    DestinationProviderProcess, Driver, DriverRecord, FileDriverRecordStore, FileIdentity,
    FileRoles, MigrationError, MigrationIntent, MigrationManifest, PlatformIdentity,
    ProviderEndpoint, ProviderProcessProjection, ProviderProjection, ProviderProjectionStatus,
    WancoProcessControl, WancoRestoreCommand, run_wanco_supervisor,
};
use visa_wasi_protocol::{
    AdminCapability, BarrierToken, ClientId, GuestCapability, OwnerId, SessionId,
};

const ADAPTER_SCHEMA: &str = "visa-wasi-real-migration-adapter-v2";
const ADAPTER_BINDING_SCHEMA: &str = "visa-wasi-adapter-binding-v2";
const CRASH_MARKER_SCHEMA: &str = "visa-wasi-coordinator-crash-marker-v1";
const INJECTED_CRASH_EXIT_STATUS: i32 = 75;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IntentDocument {
    files: FileRoles,
    session_hex: String,
    stable_owner_hex: String,
    handoff_hex: String,
    checkpoint_barrier_hex: String,
    source_epoch: u64,
    destination_epoch: u64,
    source_client_hex: String,
    source_restore_client_hex: String,
    destination_client_hex: String,
    application_build: BuildIdentity,
    source_platform: PlatformIdentity,
    destination_platform: PlatformIdentity,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterDocument {
    schema: String,
    canonical_authority: CanonicalAuthorityDocument,
    source_provider: EndpointDocument,
    destination_provider: Option<DestinationProviderDocument>,
    source_exit_receipt: PathBuf,
    source_restore: RestoreCommandDocument,
    destination_restore: Option<RestoreCommandDocument>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalAuthorityDocument {
    state: PathBuf,
    source_retained_receipt: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointDocument {
    socket: PathBuf,
    admin_capability_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DestinationProviderDocument {
    host_binary: PathBuf,
    bundle: PathBuf,
    database: PathBuf,
    restore_receipt: PathBuf,
    socket: PathBuf,
    admin_capability_hex: String,
    guest_capability_hex: String,
    stdout: PathBuf,
    stderr: PathBuf,
    startup_timeout_seconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreCommandDocument {
    argv: Vec<String>,
    cwd: PathBuf,
    stdout: PathBuf,
    stderr: PathBuf,
    completion_receipt: PathBuf,
    supervisor_binary: PathBuf,
    supervisor_spec: PathBuf,
    supervisor_started_receipt: PathBuf,
    supervisor_lock: PathBuf,
    application_argument: String,
    checkpoint_argument: String,
    client_hex: String,
    authority_epoch: u64,
    timeout_seconds: u64,
    cleanup_argv: Vec<String>,
}

#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AdapterBinding {
    schema: String,
    adapter: FileIdentity,
}

struct AdapterParts {
    compute: WancoProcessControl,
    provider: CrashAfterResume,
    verifier: CanonicalAuthorityFileVerifier,
}

struct CrashAfterResume {
    inner: ProviderProcessProjection,
    marker: Option<PathBuf>,
}

impl ProviderProjection for CrashAfterResume {
    fn freeze_source(
        &mut self,
        intent: &MigrationIntent,
    ) -> Result<ProviderProjectionStatus, MigrationError> {
        self.inner.freeze_source(intent)
    }

    fn export_source_capsule(&mut self, intent: &MigrationIntent) -> Result<(), MigrationError> {
        self.inner.export_source_capsule(intent)
    }

    fn restore_destination_prepared(
        &mut self,
        manifest: &MigrationManifest,
    ) -> Result<ProviderProjectionStatus, MigrationError> {
        self.inner.restore_destination_prepared(manifest)
    }

    fn fence_source(
        &mut self,
        manifest: &MigrationManifest,
    ) -> Result<ProviderProjectionStatus, MigrationError> {
        self.inner.fence_source(manifest)
    }

    fn activate_destination(
        &mut self,
        manifest: &MigrationManifest,
    ) -> Result<ProviderProjectionStatus, MigrationError> {
        self.inner.activate_destination(manifest)
    }

    fn resume_source(
        &mut self,
        intent: &MigrationIntent,
    ) -> Result<ProviderProjectionStatus, MigrationError> {
        let status = self.inner.resume_source(intent)?;
        if let Some(marker) = self.marker.take() {
            let document = CrashMarker {
                schema: CRASH_MARKER_SCHEMA,
                injected_after: "resume_source_provider",
                session_hex: hex(&status.session.0),
                authority_epoch: status.authority_epoch,
            };
            if let Err(error) = write_new_canonical(&marker, &document) {
                eprintln!("visa-wasi-migration-driver: cannot persist crash marker: {error}");
                std::process::exit(74);
            }
            // The Driver has already fsynced pending_action=resume_source_provider,
            // while its completion transition has not run yet.
            std::process::exit(INJECTED_CRASH_EXIT_STATUS);
        }
        Ok(status)
    }
}

#[derive(Serialize)]
struct CrashMarker<'a> {
    schema: &'a str,
    injected_after: &'a str,
    session_hex: String,
    authority_epoch: u64,
}

fn usage() -> ! {
    eprintln!(
        "usage:\n  \
visa-wasi-migration-driver init-precommit <artifact-root> <intent-json> <record-json> <adapter-json>\n  \
visa-wasi-migration-driver authority-init <artifact-root> <record-json> <adapter-json>\n  \
visa-wasi-migration-driver authority-commit <artifact-root> <record-json> <adapter-json> \
    <commit-proof-json>\n  \
visa-wasi-migration-driver recover-abort <artifact-root> <record-json> <adapter-json> \
    [--inject-exit-after-provider-resume <marker-json>]"
    );
    std::process::exit(64);
}

fn load_intent(path: &Path) -> Result<MigrationIntent, String> {
    let document: IntentDocument = read_json(path, "migration intent")?;
    let intent = MigrationIntent {
        files: document.files,
        session: SessionId(parse_hex(&document.session_hex, "session")?),
        stable_owner: OwnerId(parse_hex(&document.stable_owner_hex, "stable owner")?),
        handoff: parse_hex(&document.handoff_hex, "handoff")?,
        checkpoint_barrier: BarrierToken(parse_hex(
            &document.checkpoint_barrier_hex,
            "checkpoint barrier",
        )?),
        source_epoch: document.source_epoch,
        destination_epoch: document.destination_epoch,
        source_client: ClientId(parse_hex(&document.source_client_hex, "source client")?),
        source_restore_client: ClientId(parse_hex(
            &document.source_restore_client_hex,
            "source restore client",
        )?),
        destination_client: ClientId(parse_hex(
            &document.destination_client_hex,
            "destination client",
        )?),
        application_build: document.application_build,
        source_platform: document.source_platform,
        destination_platform: document.destination_platform,
    };
    intent.validate().map_err(|error| error.to_string())?;
    Ok(intent)
}

fn load_adapters(
    root: &Path,
    path: &Path,
    crash_marker: Option<PathBuf>,
) -> Result<AdapterParts, String> {
    let document: AdapterDocument = read_json(path, "migration adapter configuration")?;
    if document.schema != ADAPTER_SCHEMA {
        return Err("unsupported migration adapter configuration schema".to_owned());
    }
    let verifier = CanonicalAuthorityFileVerifier::new(
        resolve(root, document.canonical_authority.state),
        document.canonical_authority.source_retained_receipt,
    );
    let source = ProviderEndpoint {
        socket: resolve(root, document.source_provider.socket),
        capability: AdminCapability(parse_hex(
            &document.source_provider.admin_capability_hex,
            "source admin capability",
        )?),
    };
    let destination =
        document.destination_provider.map(|value| destination_provider(root, value)).transpose()?;
    let source_restore = restore_command(root, document.source_restore)?;
    let destination_restore =
        document.destination_restore.map(|value| restore_command(root, value)).transpose()?;
    Ok(AdapterParts {
        compute: WancoProcessControl::new(
            root,
            resolve(root, document.source_exit_receipt),
            source_restore,
            destination_restore,
        ),
        provider: CrashAfterResume {
            inner: ProviderProcessProjection::new(root, source, destination),
            marker: crash_marker,
        },
        verifier,
    })
}

fn destination_provider(
    root: &Path,
    value: DestinationProviderDocument,
) -> Result<DestinationProviderProcess, String> {
    if value.startup_timeout_seconds == 0 {
        return Err("destination provider startup timeout must be nonzero".to_owned());
    }
    Ok(DestinationProviderProcess {
        host_binary: resolve(root, value.host_binary),
        bundle: resolve(root, value.bundle),
        database: resolve(root, value.database),
        restore_receipt: resolve(root, value.restore_receipt),
        endpoint: ProviderEndpoint {
            socket: resolve(root, value.socket),
            capability: AdminCapability(parse_hex(
                &value.admin_capability_hex,
                "destination admin capability",
            )?),
        },
        guest_capability: GuestCapability(parse_hex(
            &value.guest_capability_hex,
            "destination guest capability",
        )?),
        stdout: resolve(root, value.stdout),
        stderr: resolve(root, value.stderr),
        startup_timeout: Duration::from_secs(value.startup_timeout_seconds),
    })
}

fn restore_command(
    root: &Path,
    value: RestoreCommandDocument,
) -> Result<WancoRestoreCommand, String> {
    if value.argv.is_empty() || value.timeout_seconds == 0 {
        return Err("Wanco restore command or timeout is empty".to_owned());
    }
    if value.cleanup_argv.is_empty() {
        return Err("Wanco cleanup command is empty".to_owned());
    }
    Ok(WancoRestoreCommand {
        argv: value.argv,
        cwd: resolve(root, value.cwd),
        stdout: resolve(root, value.stdout),
        stderr: resolve(root, value.stderr),
        completion_receipt: resolve(root, value.completion_receipt),
        supervisor_binary: resolve(root, value.supervisor_binary),
        supervisor_spec: resolve(root, value.supervisor_spec),
        supervisor_started_receipt: resolve(root, value.supervisor_started_receipt),
        supervisor_lock: resolve(root, value.supervisor_lock),
        application_argument: value.application_argument,
        checkpoint_argument: value.checkpoint_argument,
        client: ClientId(parse_hex(&value.client_hex, "Wanco process client")?),
        authority_epoch: value.authority_epoch,
        timeout: Duration::from_secs(value.timeout_seconds),
        cleanup_argv: value.cleanup_argv,
    })
}

fn init_precommit(args: &[String]) -> Result<(), String> {
    if args.len() != 6 {
        usage();
    }
    let root = absolute(&args[2])?;
    let intent = load_intent(Path::new(&args[3]))?;
    let record = PathBuf::from(&args[4]);
    let adapter_path = Path::new(&args[5]);
    let adapters = load_adapters(&root, adapter_path, None)?;
    bind_adapter_configuration(&record, adapter_path, true)?;
    let store = FileDriverRecordStore::acquire(&record).map_err(|error| error.to_string())?;
    let mut driver =
        Driver::new(intent, adapters.compute, adapters.provider, adapters.verifier, store)
            .map_err(|error| error.to_string())?;
    driver.confirm_source_compute_exit().map_err(|error| error.to_string())?;
    driver.freeze_source().map_err(|error| error.to_string())?;
    driver.export_source_capsule().map_err(|error| error.to_string())?;
    driver.seal_manifest(&root).map_err(|error| error.to_string())?;
    print_record(driver.record())
}

fn recover_abort(args: &[String]) -> Result<(), String> {
    if args.len() != 5 && args.len() != 7 {
        usage();
    }
    let root = absolute(&args[2])?;
    let crash_marker = if args.len() == 7 {
        if args[5] != "--inject-exit-after-provider-resume" {
            usage();
        }
        Some(PathBuf::from(&args[6]))
    } else {
        None
    };
    let record = PathBuf::from(&args[3]);
    let adapter_path = Path::new(&args[4]);
    bind_adapter_configuration(&record, adapter_path, false)?;
    let adapters = load_adapters(&root, adapter_path, crash_marker)?;
    let store = FileDriverRecordStore::acquire(&record).map_err(|error| error.to_string())?;
    let mut driver =
        Driver::recover(adapters.compute, adapters.provider, adapters.verifier, store, &root)
            .map_err(|error| error.to_string())?;
    driver.resume_source(&root).map_err(|error| error.to_string())?;
    print_record(driver.record())
}

fn authority_init(args: &[String]) -> Result<(), String> {
    if args.len() != 5 {
        usage();
    }
    let root = absolute(&args[2])?;
    let record_path = Path::new(&args[3]);
    let adapter_path = Path::new(&args[4]);
    ensure_adapter_configuration_binding(record_path, adapter_path)?;
    let record = load_driver_record(record_path, &root)?;
    let manifest = record
        .migration_manifest
        .as_ref()
        .ok_or_else(|| "authority initialization requires a sealed manifest".to_owned())?;
    let adapters = load_adapters(&root, adapter_path, None)?;
    adapters.verifier.initialize(manifest).map_err(|error| error.to_string())
}

fn authority_commit(args: &[String]) -> Result<(), String> {
    if args.len() != 6 {
        usage();
    }
    let root = absolute(&args[2])?;
    let record_path = Path::new(&args[3]);
    let adapter_path = Path::new(&args[4]);
    bind_adapter_configuration(record_path, adapter_path, false)?;
    let record = load_driver_record(record_path, &root)?;
    let manifest = record
        .migration_manifest
        .as_ref()
        .ok_or_else(|| "authority commit requires a sealed manifest".to_owned())?;
    let proof: CanonicalCommitProof = read_json(Path::new(&args[5]), "ownership commit proof")?;
    let adapters = load_adapters(&root, adapter_path, None)?;
    adapters
        .verifier
        .publish_ownership_commit(manifest, &proof, &root)
        .map_err(|error| error.to_string())
}

fn load_driver_record(path: &Path, root: &Path) -> Result<DriverRecord, String> {
    let bytes = fs::read(path).map_err(|error| format!("cannot read migration record: {error}"))?;
    let record = DriverRecord::decode_canonical(&bytes).map_err(|error| error.to_string())?;
    record.verify_at(root).map_err(|error| error.to_string())?;
    Ok(record)
}

fn print_record(record: &visa_wasi_migration::DriverRecord) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(record)
        .map_err(|error| format!("cannot encode migration driver status: {error}"))?;
    std::io::stdout()
        .write_all(&bytes)
        .and_then(|()| std::io::stdout().write_all(b"\n"))
        .map_err(|error| format!("cannot write migration driver status: {error}"))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path, label: &str) -> Result<T, String> {
    let bytes = fs::read(path).map_err(|error| format!("cannot read {label}: {error}"))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("cannot decode {label}: {error}"))
}

fn bind_adapter_configuration(record: &Path, adapter: &Path, create: bool) -> Result<(), String> {
    let expected = AdapterBinding {
        schema: ADAPTER_BINDING_SCHEMA.to_owned(),
        adapter: file_identity(adapter, "migration adapter configuration")?,
    };
    let path = adapter_binding_path(record);
    if path.exists() {
        let bytes = fs::read(&path)
            .map_err(|error| format!("cannot read migration adapter binding: {error}"))?;
        let actual: AdapterBinding = serde_json::from_slice(&bytes)
            .map_err(|error| format!("cannot decode migration adapter binding: {error}"))?;
        let mut canonical = serde_json_canonicalizer::to_vec(&actual)
            .map_err(|error| format!("cannot canonicalize migration adapter binding: {error}"))?;
        canonical.push(b'\n');
        if canonical != bytes || actual != expected {
            return Err(
                "migration adapter configuration differs from the durable binding".to_owned()
            );
        }
        return Ok(());
    }
    if !create {
        return Err("migration adapter binding is missing during recovery".to_owned());
    }
    write_new_canonical(&path, &expected)
}

fn ensure_adapter_configuration_binding(record: &Path, adapter: &Path) -> Result<(), String> {
    let path = adapter_binding_path(record);
    match fs::symlink_metadata(&path) {
        Ok(_) => bind_adapter_configuration(record, adapter, false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            bind_adapter_configuration(record, adapter, true)
        }
        Err(error) => Err(format!("cannot inspect migration adapter binding: {error}")),
    }
}

fn adapter_binding_path(record: &Path) -> PathBuf {
    let mut path = record.as_os_str().to_os_string();
    path.push(".adapter-binding.json");
    PathBuf::from(path)
}

fn file_identity(path: &Path, label: &str) -> Result<FileIdentity, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("cannot inspect {label}: {error}"))?;
    if !metadata.file_type().is_file() {
        return Err(format!("{label} is not a regular file"));
    }
    let mut file = File::open(path).map_err(|error| format!("cannot open {label}: {error}"))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let read =
            file.read(&mut buffer).map_err(|error| format!("cannot read {label}: {error}"))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(FileIdentity { sha256: hex(&digest.finalize()), size: metadata.len() })
}

fn write_new_canonical<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .ok_or_else(|| "crash marker path has no parent".to_owned())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("cannot create crash marker parent: {error}"))?;
    let mut bytes = serde_json_canonicalizer::to_vec(value)
        .map_err(|error| format!("cannot encode crash marker: {error}"))?;
    bytes.push(b'\n');
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file =
        options.open(path).map_err(|error| format!("cannot create crash marker: {error}"))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("cannot sync crash marker: {error}"))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("cannot sync crash marker parent: {error}"))
}

fn absolute(value: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(format!("path must be absolute: {}", path.display()));
    }
    Ok(path)
}

fn cleanup_docker_container(args: &[String]) -> Result<(), String> {
    if args.len() != 4 || args[3].is_empty() {
        return Err(
            "cleanup-docker-container requires a Docker binary and container name".to_owned()
        );
    }
    let status = Command::new(&args[2])
        .args(["container", "rm", "--force", &args[3]])
        .status()
        .map_err(|error| format!("cannot run Docker container cleanup: {error}"))?;
    if status.success() {
        return Ok(());
    }
    let inspection = Command::new(&args[2])
        .args(["container", "inspect", &args[3]])
        .output()
        .map_err(|error| format!("cannot inspect container after cleanup failure: {error}"))?;
    let diagnostic = String::from_utf8_lossy(&inspection.stderr);
    if !inspection.status.success()
        && (diagnostic.contains("No such container") || diagnostic.contains("No such object"))
    {
        return Ok(());
    }
    Err(format!("Docker cleanup did not remove container {}: {}", args[3], diagnostic.trim()))
}

fn resolve(root: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() { path } else { root.join(path) }
}

fn parse_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2 || value != value.to_ascii_lowercase() {
        return Err(format!("{label} must be lowercase {N}-byte hexadecimal"));
    }
    let mut bytes = [0; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair).map_err(|_| format!("{label} is not hexadecimal"))?;
        bytes[index] =
            u8::from_str_radix(pair, 16).map_err(|_| format!("{label} is not hexadecimal"))?;
    }
    if bytes == [0; N] {
        return Err(format!("{label} must not be zero"));
    }
    Ok(bytes)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    result
}

fn run() -> Result<(), String> {
    let args = std::env::args().collect::<Vec<_>>();
    match args.get(1).map(String::as_str) {
        Some("init-precommit") => init_precommit(&args),
        Some("authority-init") => authority_init(&args),
        Some("authority-commit") => authority_commit(&args),
        Some("recover-abort") => recover_abort(&args),
        Some("supervise-wanco") if args.len() == 3 => {
            run_wanco_supervisor(Path::new(&args[2])).map_err(|error| error.to_string())
        }
        Some("cleanup-docker-container") => cleanup_docker_container(&args),
        _ => usage(),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("visa-wasi-migration-driver: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn recovery_rejects_a_different_adapter_configuration() {
        let temporary = TempDir::new().unwrap();
        let adapter = temporary.path().join("adapter.json");
        let record = temporary.path().join("record.json");
        fs::write(&adapter, b"first adapter").unwrap();
        bind_adapter_configuration(&record, &adapter, true).unwrap();
        bind_adapter_configuration(&record, &adapter, false).unwrap();

        fs::write(&adapter, b"different adapter").unwrap();
        assert_eq!(
            bind_adapter_configuration(&record, &adapter, false).unwrap_err(),
            "migration adapter configuration differs from the durable binding"
        );
    }
}
