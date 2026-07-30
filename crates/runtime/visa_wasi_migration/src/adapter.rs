use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::Shutdown,
    os::unix::{fs::OpenOptionsExt, net::UnixStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use visa_wasi_protocol::{
    AdminCapability, AdminOperation, AdminRequest, AdminResponse, ClientId, GuestCapability,
    MAX_FRAME_BYTES, PROTOCOL_VERSION, ProviderMode as WireProviderMode, WireRequest, WireResponse,
    decode_response, encode_request,
};

use crate::{
    ComputeControl, MigrationError, MigrationIntent, MigrationManifest, ProviderMode,
    ProviderProjection, ProviderProjectionStatus,
    supervisor::{SupervisedCommand, execute_or_reconcile},
};

pub const WANCO_SOURCE_EXIT_SCHEMA: &str = "visa-wanco-source-exit-v1";
pub const WANCO_RESTORE_COMPLETION_SCHEMA: &str = "visa-wanco-restore-completion-v1";
pub const DESTINATION_PROVIDER_RESTORE_SCHEMA: &str = "visa-wasi-destination-provider-restore-v1";

const PROVIDER_IO_TIMEOUT: Duration = Duration::from_secs(10);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(25);

#[derive(Clone, Debug)]
pub struct ProviderEndpoint {
    pub socket: PathBuf,
    pub capability: AdminCapability,
}

#[derive(Clone, Debug)]
pub struct DestinationProviderProcess {
    pub host_binary: PathBuf,
    pub bundle: PathBuf,
    pub database: PathBuf,
    pub restore_receipt: PathBuf,
    pub endpoint: ProviderEndpoint,
    pub guest_capability: GuestCapability,
    pub stdout: PathBuf,
    pub stderr: PathBuf,
    pub startup_timeout: Duration,
}

/// A provider projection backed by the production AF_UNIX protocol. Source
/// operations are sent directly to the live provider. When destination process
/// configuration is supplied, a missing destination is restored from the
/// exported capsule and served by `visa_wasi_host` before its status is read.
pub struct ProviderProcessProjection {
    artifact_root: PathBuf,
    source: ProviderEndpoint,
    destination: Option<DestinationProviderProcess>,
    destination_child: Option<Child>,
}

impl ProviderProcessProjection {
    pub fn new(
        artifact_root: impl Into<PathBuf>,
        source: ProviderEndpoint,
        destination: Option<DestinationProviderProcess>,
    ) -> Self {
        Self { artifact_root: artifact_root.into(), source, destination, destination_child: None }
    }

    pub fn source_status(&self) -> Result<ProviderProjectionStatus, MigrationError> {
        endpoint_status(&self.source)
    }

    pub fn destination_status(&self) -> Result<ProviderProjectionStatus, MigrationError> {
        let destination = self.destination.as_ref().ok_or_else(|| {
            MigrationError::External("destination provider process is not configured".to_owned())
        })?;
        endpoint_status(&destination.endpoint)
    }

    fn source_operation(
        &self,
        operation: AdminOperation,
    ) -> Result<ProviderProjectionStatus, MigrationError> {
        operation_status(&self.source, operation)
    }

    fn destination_operation(
        &self,
        operation: AdminOperation,
    ) -> Result<ProviderProjectionStatus, MigrationError> {
        let destination = self.destination.as_ref().ok_or_else(|| {
            MigrationError::External("destination provider process is not configured".to_owned())
        })?;
        operation_status(&destination.endpoint, operation)
    }

    fn ensure_destination_running(
        &mut self,
        manifest: &MigrationManifest,
    ) -> Result<ProviderProjectionStatus, MigrationError> {
        manifest.verify_at(&self.artifact_root)?;
        let destination = self.destination.as_ref().ok_or_else(|| {
            MigrationError::External("destination provider process is not configured".to_owned())
        })?;
        let capsule_manifest =
            self.artifact_root.join(&manifest.resource_capsule_manifest.semantic_path);
        let expected_bundle = capsule_manifest
            .parent()
            .ok_or(MigrationError::Invalid("resource capsule manifest path has no parent"))?;
        if expected_bundle != destination.bundle {
            return Err(MigrationError::Integrity(
                "destination provider bundle differs from the migration manifest",
            ));
        }

        if let Ok(status) = endpoint_status(&destination.endpoint) {
            verify_destination_restore_receipt(destination, manifest, false)?;
            validate_prepared_destination(&status, manifest)?;
            return Ok(status);
        }
        if destination.endpoint.socket.exists() {
            return Err(MigrationError::External(format!(
                "destination provider socket exists but is not serving: {}",
                destination.endpoint.socket.display()
            )));
        }
        if !destination.database.exists() {
            if destination.restore_receipt.exists() {
                return Err(MigrationError::Integrity(
                    "destination restore receipt exists without its database",
                ));
            }
            run_host_restore(destination, manifest)?;
        } else {
            verify_destination_restore_receipt(destination, manifest, true)?;
        }

        let stdout = append_file(&destination.stdout)?;
        let stderr = append_file(&destination.stderr)?;
        let child = Command::new(&destination.host_binary)
            .arg("serve")
            .arg(&destination.database)
            .arg(&destination.endpoint.socket)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .map_err(|error| {
                MigrationError::External(format!("cannot start destination provider: {error}"))
            })?;
        self.destination_child = Some(child);

        let deadline = Instant::now() + destination.startup_timeout;
        loop {
            if let Ok(status) = endpoint_status(&destination.endpoint) {
                verify_destination_restore_receipt(destination, manifest, false)?;
                validate_prepared_destination(&status, manifest)?;
                return Ok(status);
            }
            if let Some(status) = self
                .destination_child
                .as_mut()
                .expect("destination child was just installed")
                .try_wait()
                .map_err(MigrationError::Io)?
            {
                return Err(MigrationError::External(format!(
                    "destination provider exited during startup with {status}"
                )));
            }
            if Instant::now() >= deadline {
                return Err(MigrationError::External(format!(
                    "destination provider did not publish {}",
                    destination.endpoint.socket.display()
                )));
            }
            thread::sleep(PROCESS_POLL_INTERVAL);
        }
    }
}

impl ProviderProjection for ProviderProcessProjection {
    fn freeze_source(
        &mut self,
        intent: &MigrationIntent,
    ) -> Result<ProviderProjectionStatus, MigrationError> {
        self.source_operation(AdminOperation::Freeze {
            barrier: intent.checkpoint_barrier,
            handoff: intent.handoff,
            destination_epoch: intent.destination_epoch,
        })
    }

    fn export_source_capsule(&mut self, intent: &MigrationIntent) -> Result<(), MigrationError> {
        let manifest_path = self.artifact_root.join(&intent.files.resource_capsule_manifest);
        let state_path = self.artifact_root.join(&intent.files.resource_capsule_state);
        let bundle = manifest_path
            .parent()
            .ok_or(MigrationError::Invalid("resource capsule manifest path has no parent"))?;
        if state_path.parent() != Some(bundle) {
            return Err(MigrationError::Invalid(
                "resource capsule files must share one bundle directory",
            ));
        }
        self.source_operation(AdminOperation::Export {
            bundle: path_text(bundle, "resource capsule bundle")?,
        })?;
        Ok(())
    }

    fn restore_destination_prepared(
        &mut self,
        manifest: &MigrationManifest,
    ) -> Result<ProviderProjectionStatus, MigrationError> {
        self.ensure_destination_running(manifest)
    }

    fn fence_source(
        &mut self,
        manifest: &MigrationManifest,
    ) -> Result<ProviderProjectionStatus, MigrationError> {
        self.source_operation(AdminOperation::Fence {
            handoff: parse_hex(&manifest.handoff_hex, "manifest handoff")?,
            committed_epoch: manifest.destination_epoch,
        })
    }

    fn activate_destination(
        &mut self,
        manifest: &MigrationManifest,
    ) -> Result<ProviderProjectionStatus, MigrationError> {
        self.destination_operation(AdminOperation::Activate {
            handoff: parse_hex(&manifest.handoff_hex, "manifest handoff")?,
            authority_epoch: manifest.destination_epoch,
        })
    }

    fn resume_source(
        &mut self,
        intent: &MigrationIntent,
    ) -> Result<ProviderProjectionStatus, MigrationError> {
        self.source_operation(AdminOperation::Resume {
            handoff: intent.handoff,
            authority_epoch: intent.source_epoch,
        })
    }
}

#[derive(Clone, Debug)]
pub struct WancoRestoreCommand {
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    pub stdout: PathBuf,
    pub stderr: PathBuf,
    pub completion_receipt: PathBuf,
    pub supervisor_binary: PathBuf,
    pub supervisor_spec: PathBuf,
    pub supervisor_started_receipt: PathBuf,
    pub supervisor_lock: PathBuf,
    pub application_argument: String,
    pub checkpoint_argument: String,
    pub client: ClientId,
    pub authority_epoch: u64,
    pub timeout: Duration,
    pub cleanup_argv: Vec<String>,
}

#[derive(Clone, Copy)]
struct WancoProcessIdentity<'a> {
    session: &'a [u8; 16],
    stable_owner: &'a [u8; 16],
}

/// Real Wanco compute control. Source exit is accepted only from a durable
/// receipt bound to the nonempty checkpoint. Restore commands are executed
/// without a shell and publish their own durable completion receipt before the
/// migration driver can mark the action complete. A driver replay therefore
/// observes the same successful Wanco invocation instead of launching a second
/// native process.
pub struct WancoProcessControl {
    artifact_root: PathBuf,
    source_exit_receipt: PathBuf,
    source_restore: WancoRestoreCommand,
    destination_restore: Option<WancoRestoreCommand>,
}

impl WancoProcessControl {
    pub fn new(
        artifact_root: impl Into<PathBuf>,
        source_exit_receipt: impl Into<PathBuf>,
        source_restore: WancoRestoreCommand,
        destination_restore: Option<WancoRestoreCommand>,
    ) -> Self {
        Self {
            artifact_root: artifact_root.into(),
            source_exit_receipt: source_exit_receipt.into(),
            source_restore,
            destination_restore,
        }
    }

    fn run_restore(
        &self,
        operation: &'static str,
        command: &WancoRestoreCommand,
        identity: WancoProcessIdentity<'_>,
        application_path: &Path,
        checkpoint_path: &Path,
        binding_digest: String,
    ) -> Result<(), MigrationError> {
        validate_restore_command(command, identity, application_path, checkpoint_path)?;
        let fingerprint = command_fingerprint(operation, command, &binding_digest)?;
        execute_or_reconcile(SupervisedCommand {
            operation,
            supervisor_binary: &command.supervisor_binary,
            spec_path: &command.supervisor_spec,
            started_receipt: &command.supervisor_started_receipt,
            completion_receipt: &command.completion_receipt,
            lock_path: &command.supervisor_lock,
            fingerprint: &fingerprint,
            argv: &command.argv,
            cwd: &command.cwd,
            stdout: &command.stdout,
            stderr: &command.stderr,
            timeout: command.timeout,
            cleanup_argv: &command.cleanup_argv,
        })
    }
}

impl ComputeControl for WancoProcessControl {
    fn confirm_source_exit(&mut self, intent: &MigrationIntent) -> Result<(), MigrationError> {
        let checkpoint = self.artifact_root.join(&intent.files.compute_checkpoint);
        let expected = file_identity(&checkpoint)?;
        let receipt: WancoSourceExit = read_canonical_receipt(&self.source_exit_receipt)?;
        if receipt.schema != WANCO_SOURCE_EXIT_SCHEMA
            || receipt.exit_status != 0
            || receipt.checkpoint != expected
        {
            return Err(MigrationError::Integrity(
                "Wanco source-exit receipt does not bind a successful checkpoint",
            ));
        }
        Ok(())
    }

    fn restore_destination(&mut self, manifest: &MigrationManifest) -> Result<(), MigrationError> {
        manifest.verify_at(&self.artifact_root)?;
        let command = self.destination_restore.as_ref().ok_or_else(|| {
            MigrationError::External("destination Wanco restore is not configured".to_owned())
        })?;
        let expected_client: [u8; 16] =
            parse_hex(&manifest.clients.destination_client_hex, "destination client")?;
        let session = parse_hex(&manifest.session_hex, "manifest session")?;
        let stable_owner = parse_hex(&manifest.stable_owner_hex, "manifest stable owner")?;
        if command.client.0 != expected_client
            || command.authority_epoch != manifest.destination_epoch
        {
            return Err(MigrationError::Integrity(
                "destination Wanco command has the wrong process identity or epoch",
            ));
        }
        let application = self.artifact_root.join(&manifest.application.semantic_path);
        let checkpoint = self.artifact_root.join(&manifest.compute_checkpoint.semantic_path);
        self.run_restore(
            "restore_destination",
            command,
            WancoProcessIdentity { session: &session, stable_owner: &stable_owner },
            &application,
            &checkpoint,
            manifest.digest()?.to_string(),
        )
    }

    fn restore_source(&mut self, intent: &MigrationIntent) -> Result<(), MigrationError> {
        if self.source_restore.client != intent.source_restore_client
            || self.source_restore.authority_epoch != intent.source_epoch
        {
            return Err(MigrationError::Integrity(
                "source Wanco command has the wrong process identity or epoch",
            ));
        }
        let manifest = MigrationManifest::seal(intent, &self.artifact_root)?;
        let application = self.artifact_root.join(&intent.files.application);
        let checkpoint = self.artifact_root.join(&intent.files.compute_checkpoint);
        self.run_restore(
            "restore_source",
            &self.source_restore,
            WancoProcessIdentity {
                session: &intent.session.0,
                stable_owner: &intent.stable_owner.0,
            },
            &application,
            &checkpoint,
            manifest.digest()?.to_string(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DestinationProviderRestoreReceipt {
    schema: String,
    migration_manifest_sha256: String,
    database: FileIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WancoSourceExit {
    pub schema: String,
    pub exit_status: i32,
    pub checkpoint: FileIdentity,
}

fn endpoint_status(
    endpoint: &ProviderEndpoint,
) -> Result<ProviderProjectionStatus, MigrationError> {
    operation_status(endpoint, AdminOperation::Status)
}

fn operation_status(
    endpoint: &ProviderEndpoint,
    operation: AdminOperation,
) -> Result<ProviderProjectionStatus, MigrationError> {
    let response = exchange_admin(endpoint, operation)?;
    if !response.ok {
        return Err(MigrationError::External(format!(
            "provider rejected projection: {}",
            response.message
        )));
    }
    let status = response.status.ok_or_else(|| {
        MigrationError::External("provider response omitted projection status".to_owned())
    })?;
    Ok(ProviderProjectionStatus {
        session: status.session,
        mode: match status.mode {
            WireProviderMode::Active => ProviderMode::Active,
            WireProviderMode::Frozen => ProviderMode::Frozen,
            WireProviderMode::Prepared => ProviderMode::Prepared,
            WireProviderMode::Fenced => ProviderMode::Fenced,
        },
        authority_epoch: status.authority_epoch,
    })
}

fn exchange_admin(
    endpoint: &ProviderEndpoint,
    operation: AdminOperation,
) -> Result<AdminResponse, MigrationError> {
    let request = WireRequest::Admin(AdminRequest {
        version: PROTOCOL_VERSION,
        capability: endpoint.capability,
        operation,
    });
    let bytes =
        encode_request(&request).map_err(|error| MigrationError::Codec(error.to_string()))?;
    let mut stream = UnixStream::connect(&endpoint.socket).map_err(|error| {
        MigrationError::External(format!(
            "cannot connect to provider {}: {error}",
            endpoint.socket.display()
        ))
    })?;
    stream.set_read_timeout(Some(PROVIDER_IO_TIMEOUT)).map_err(MigrationError::Io)?;
    stream.set_write_timeout(Some(PROVIDER_IO_TIMEOUT)).map_err(MigrationError::Io)?;
    write_frame(&mut stream, &bytes)?;
    let response = read_frame(&mut stream)?;
    let _ = stream.shutdown(Shutdown::Both);
    match decode_response(&response).map_err(|error| MigrationError::Codec(error.to_string()))? {
        WireResponse::Admin(response) if response.version.is_supported() => Ok(response),
        WireResponse::Admin(_) => Err(MigrationError::External(
            "provider returned an unsupported protocol version".to_owned(),
        )),
        _ => {
            Err(MigrationError::External("provider returned the wrong response family".to_owned()))
        }
    }
}

fn write_frame(stream: &mut UnixStream, bytes: &[u8]) -> Result<(), MigrationError> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(MigrationError::Invalid("provider wire frame length"));
    }
    let length = u32::try_from(bytes.len())
        .map_err(|_| MigrationError::Invalid("provider wire frame length"))?;
    stream.write_all(&length.to_be_bytes()).map_err(MigrationError::Io)?;
    stream.write_all(bytes).map_err(MigrationError::Io)?;
    stream.flush().map_err(MigrationError::Io)
}

fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, MigrationError> {
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length).map_err(MigrationError::Io)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(MigrationError::Invalid("provider wire frame length"));
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).map_err(MigrationError::Io)?;
    Ok(bytes)
}

fn run_host_restore(
    destination: &DestinationProviderProcess,
    manifest: &MigrationManifest,
) -> Result<(), MigrationError> {
    let stdout = append_file(&destination.stdout)?;
    let stderr = append_file(&destination.stderr)?;
    let mut child = Command::new(&destination.host_binary)
        .arg("restore")
        .arg(&destination.bundle)
        .arg(&destination.database)
        .arg(hex(&destination.endpoint.capability.0))
        .arg(hex(&destination.guest_capability.0))
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .map_err(|error| {
            MigrationError::External(format!("cannot run destination provider restore: {error}"))
        })?;
    let deadline = Instant::now() + destination.startup_timeout;
    loop {
        if let Some(status) = child.try_wait().map_err(MigrationError::Io)? {
            if !status.success() {
                return Err(MigrationError::External(format!(
                    "destination provider restore failed with {status}"
                )));
            }
            File::open(&destination.database)
                .and_then(|file| file.sync_all())
                .map_err(MigrationError::Io)?;
            let receipt = DestinationProviderRestoreReceipt {
                schema: DESTINATION_PROVIDER_RESTORE_SCHEMA.to_owned(),
                migration_manifest_sha256: manifest.digest()?.to_string(),
                database: file_identity(&destination.database)?,
            };
            return write_canonical_receipt(&destination.restore_receipt, &receipt);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(MigrationError::External(format!(
                "destination provider restore timed out after {} seconds",
                destination.startup_timeout.as_secs()
            )));
        }
        thread::sleep(PROCESS_POLL_INTERVAL);
    }
}

fn verify_destination_restore_receipt(
    destination: &DestinationProviderProcess,
    manifest: &MigrationManifest,
    verify_database_identity: bool,
) -> Result<(), MigrationError> {
    let receipt: DestinationProviderRestoreReceipt =
        read_canonical_receipt(&destination.restore_receipt)?;
    if receipt.schema != DESTINATION_PROVIDER_RESTORE_SCHEMA
        || receipt.migration_manifest_sha256 != manifest.digest()?.to_string()
        || (verify_database_identity && receipt.database != file_identity(&destination.database)?)
    {
        return Err(MigrationError::Integrity(
            "destination provider restore receipt differs from the migration manifest or database",
        ));
    }
    Ok(())
}

fn validate_prepared_destination(
    status: &ProviderProjectionStatus,
    manifest: &MigrationManifest,
) -> Result<(), MigrationError> {
    let expected_session = parse_hex(&manifest.session_hex, "manifest session")?;
    if status.session.0 != expected_session
        || status.mode != ProviderMode::Prepared
        || status.authority_epoch != manifest.source_epoch
    {
        return Err(MigrationError::Integrity(
            "destination provider is not the manifest-bound prepared projection",
        ));
    }
    Ok(())
}

fn validate_restore_command(
    command: &WancoRestoreCommand,
    identity: WancoProcessIdentity<'_>,
    application_path: &Path,
    checkpoint_path: &Path,
) -> Result<(), MigrationError> {
    if command.argv.is_empty() || command.timeout.is_zero() {
        return Err(MigrationError::Invalid("incomplete Wanco restore command"));
    }
    let restore_position = command
        .argv
        .windows(2)
        .position(|pair| pair[0] == "--restore" && pair[1] == command.checkpoint_argument)
        .ok_or(MigrationError::Invalid(
            "Wanco restore command does not bind its checkpoint argument",
        ))?;
    let guest_delimiter =
        command.argv.iter().position(|argument| argument == "--").ok_or(
            MigrationError::Invalid("Wanco restore command has no guest argument delimiter"),
        )?;
    if restore_position >= guest_delimiter {
        return Err(MigrationError::Invalid(
            "Wanco restore checkpoint must precede the guest argument delimiter",
        ));
    }
    let application_position =
        command.argv.iter().position(|argument| argument == &command.application_argument).ok_or(
            MigrationError::Invalid("Wanco restore command does not bind its application argument"),
        )?;
    if application_position >= restore_position {
        return Err(MigrationError::Invalid(
            "Wanco restore application must precede its checkpoint argument",
        ));
    }
    let identity_arguments = [
        format!("VISA_WASI_SESSION_ID={}", hex(identity.session)),
        format!("VISA_WASI_OWNER_ID={}", hex(identity.stable_owner)),
        format!("VISA_WASI_CLIENT_ID={}", hex(&command.client.0)),
        format!("VISA_WASI_AUTHORITY_EPOCH={}", command.authority_epoch),
    ];
    if identity_arguments.iter().any(|required| {
        command
            .argv
            .iter()
            .position(|argument| argument == required)
            .is_none_or(|position| position >= guest_delimiter)
    }) {
        return Err(MigrationError::Invalid(
            "Wanco restore command does not bind its process identity before guest arguments",
        ));
    }
    let application_metadata =
        fs::symlink_metadata(application_path).map_err(MigrationError::Io)?;
    if !application_metadata.file_type().is_file() || application_metadata.len() == 0 {
        return Err(MigrationError::Integrity(
            "Wanco restore application is not a nonempty regular file",
        ));
    }
    let metadata = fs::symlink_metadata(checkpoint_path).map_err(MigrationError::Io)?;
    if !metadata.file_type().is_file() || metadata.len() == 0 {
        return Err(MigrationError::Integrity(
            "Wanco restore checkpoint is not a nonempty regular file",
        ));
    }
    Ok(())
}

fn command_fingerprint(
    operation: &str,
    command: &WancoRestoreCommand,
    binding_digest: &str,
) -> Result<String, MigrationError> {
    #[derive(Serialize)]
    struct Fingerprint<'a> {
        operation: &'a str,
        argv: &'a [String],
        cwd: &'a Path,
        application_argument: &'a str,
        checkpoint_argument: &'a str,
        client: &'a [u8; 16],
        authority_epoch: u64,
        binding_digest: &'a str,
    }
    let bytes = serde_json_canonicalizer::to_vec(&Fingerprint {
        operation,
        argv: &command.argv,
        cwd: &command.cwd,
        application_argument: &command.application_argument,
        checkpoint_argument: &command.checkpoint_argument,
        client: &command.client.0,
        authority_epoch: command.authority_epoch,
        binding_digest,
    })
    .map_err(|error| MigrationError::Codec(error.to_string()))?;
    Ok(hex(&Sha256::digest(bytes)))
}

fn file_identity(path: &Path) -> Result<FileIdentity, MigrationError> {
    let metadata = fs::symlink_metadata(path).map_err(MigrationError::Io)?;
    if !metadata.file_type().is_file() {
        return Err(MigrationError::Integrity("evidence path is not a regular file"));
    }
    let mut file = File::open(path).map_err(MigrationError::Io)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(MigrationError::Io)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(FileIdentity { sha256: hex(&digest.finalize()), size: metadata.len() })
}

fn read_canonical_receipt<T>(path: &Path) -> Result<T, MigrationError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let bytes = fs::read(path).map_err(MigrationError::Io)?;
    let value: T =
        serde_json::from_slice(&bytes).map_err(|error| MigrationError::Codec(error.to_string()))?;
    let mut canonical = serde_json_canonicalizer::to_vec(&value)
        .map_err(|error| MigrationError::Codec(error.to_string()))?;
    canonical.push(b'\n');
    if canonical != bytes {
        return Err(MigrationError::Integrity("adapter receipt is not canonical RFC 8785 JSON"));
    }
    Ok(value)
}

fn write_canonical_receipt<T: Serialize>(path: &Path, value: &T) -> Result<(), MigrationError> {
    let mut bytes = serde_json_canonicalizer::to_vec(value)
        .map_err(|error| MigrationError::Codec(error.to_string()))?;
    bytes.push(b'\n');
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .ok_or(MigrationError::Invalid("adapter receipt path has no parent"))?;
    fs::create_dir_all(parent).map_err(MigrationError::Io)?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().and_then(|value| value.to_str()).unwrap_or("receipt"),
        std::process::id()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(&temporary).map_err(MigrationError::Io)?;
    let result = (|| {
        file.write_all(&bytes).map_err(MigrationError::Io)?;
        file.sync_all().map_err(MigrationError::Io)?;
        fs::rename(&temporary, path).map_err(MigrationError::Io)?;
        File::open(parent).and_then(|directory| directory.sync_all()).map_err(MigrationError::Io)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn append_file(path: &Path) -> Result<File, MigrationError> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .ok_or(MigrationError::Invalid("provider log path has no parent"))?;
    fs::create_dir_all(parent).map_err(MigrationError::Io)?;
    let mut options = OpenOptions::new();
    options.write(true).create(true).append(true).mode(0o600);
    options.open(path).map_err(MigrationError::Io)
}

fn path_text(path: &Path, label: &str) -> Result<String, MigrationError> {
    path.to_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| MigrationError::External(format!("{label} is not UTF-8")))
}

fn parse_hex<const N: usize>(value: &str, label: &'static str) -> Result<[u8; N], MigrationError> {
    if value.len() != N * 2 {
        return Err(MigrationError::Invalid(label));
    }
    let mut bytes = [0; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair).map_err(|_| MigrationError::Invalid(label))?;
        bytes[index] = u8::from_str_radix(pair, 16).map_err(|_| MigrationError::Invalid(label))?;
    }
    if bytes == [0; N] {
        return Err(MigrationError::Invalid(label));
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

#[cfg(test)]
mod tests {
    use std::{
        os::unix::{fs::PermissionsExt, net::UnixListener},
        sync::mpsc,
    };

    use tempfile::TempDir;
    use visa_wasi_protocol::{
        AdminResponse, BarrierPhase, BarrierToken, ClientId, EffectId, OwnerId, ProviderStatus,
        SessionId, WireRequest, WireResponse, decode_request, encode_response,
    };

    use super::*;
    use crate::{BuildIdentity, FileRoles, PlatformIdentity};

    const SESSION: SessionId = SessionId([1; 16]);
    const OWNER: OwnerId = OwnerId([2; 16]);
    const SOURCE_CLIENT: ClientId = ClientId([3; 16]);
    const SOURCE_RESTORE_CLIENT: ClientId = ClientId([4; 16]);
    const DESTINATION_CLIENT: ClientId = ClientId([5; 16]);

    #[test]
    fn provider_adapter_sends_the_exact_freeze_protocol_operation() {
        let temporary = TempDir::new().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let socket = temporary.path().join("provider.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let capability = AdminCapability([9; 32]);
        let (sender, receiver) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let frame = read_frame(&mut stream).unwrap();
            let request = decode_request(&frame).unwrap();
            sender.send(request.clone()).unwrap();
            let response = WireResponse::Admin(AdminResponse {
                version: PROTOCOL_VERSION,
                ok: true,
                message: "source frozen".to_owned(),
                status: Some(status(WireProviderMode::Frozen)),
                snapshot: None,
            });
            write_frame(&mut stream, &encode_response(&response).unwrap()).unwrap();
        });
        let mut provider = ProviderProcessProjection::new(
            temporary.path(),
            ProviderEndpoint { socket, capability },
            None,
        );
        let intent = intent();
        let observed = provider.freeze_source(&intent).unwrap();
        assert_eq!(observed.mode, ProviderMode::Frozen);
        assert!(matches!(
            receiver.recv().unwrap(),
            WireRequest::Admin(AdminRequest {
                capability: observed_capability,
                operation: AdminOperation::Freeze {
                    barrier,
                    handoff,
                    destination_epoch: 2,
                },
                ..
            }) if observed_capability == capability
                && barrier == intent.checkpoint_barrier
                && handoff == intent.handoff
        ));
        server.join().unwrap();
    }

    #[test]
    fn wanco_replay_and_destination_receipt_bind_real_process_artifacts() {
        let _process_fixture = crate::supervisor::PROCESS_FIXTURE_LOCK.lock().unwrap();
        let temporary = TempDir::new().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(temporary.path().join("application.aot"), b"application").unwrap();
        let checkpoint = temporary.path().join("checkpoint.pb");
        fs::write(&checkpoint, b"checkpoint").unwrap();
        let capsule = temporary.path().join("capsule");
        fs::create_dir(&capsule).unwrap();
        let state = capsule.join("state.sqlite");
        fs::write(&state, b"state").unwrap();
        let descriptor = TestCapsuleDescriptor {
            schema: "visa-wasi-filesystem-capsule-v2",
            session_hex: hex(&SESSION.0),
            source_epoch: 1,
            destination_epoch: 2,
            handoff_hex: hex(&[6; 16]),
            state_file: "state.sqlite",
            state_size: 5,
            state_sha256: file_identity(&state).unwrap().sha256,
        };
        fs::write(capsule.join("manifest.json"), serde_json::to_vec_pretty(&descriptor).unwrap())
            .unwrap();
        let marker = temporary.path().join("launched");
        let stdout = temporary.path().join("restore.stdout");
        let stderr = temporary.path().join("restore.stderr");
        let completion = temporary.path().join("restore.json");
        let supervisor_spec = temporary.path().join("supervisor-spec.json");
        let supervisor_started = temporary.path().join("supervisor-started.json");
        let supervisor_lock = temporary.path().join("supervisor.lock");
        let source_exit = temporary.path().join("source-exit.json");
        let checkpoint_identity = file_identity(&checkpoint).unwrap();
        write_canonical_receipt(
            &source_exit,
            &WancoSourceExit {
                schema: WANCO_SOURCE_EXIT_SCHEMA.to_owned(),
                exit_status: 0,
                checkpoint: checkpoint_identity,
            },
        )
        .unwrap();
        let command = WancoRestoreCommand {
            argv: vec![
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                "printf x >> \"$1\"".to_owned(),
                "visa-test".to_owned(),
                marker.display().to_string(),
                format!("VISA_WASI_SESSION_ID={}", hex(&SESSION.0)),
                format!("VISA_WASI_OWNER_ID={}", hex(&OWNER.0)),
                format!("VISA_WASI_CLIENT_ID={}", hex(&SOURCE_RESTORE_CLIENT.0)),
                "VISA_WASI_AUTHORITY_EPOCH=1".to_owned(),
                "--restore".to_owned(),
                checkpoint.display().to_string(),
                "--".to_owned(),
            ],
            cwd: temporary.path().to_path_buf(),
            stdout,
            stderr,
            completion_receipt: completion,
            supervisor_binary: PathBuf::from("/not-used-in-unit-test"),
            supervisor_spec,
            supervisor_started_receipt: supervisor_started,
            supervisor_lock,
            application_argument: "/bin/sh".to_owned(),
            checkpoint_argument: checkpoint.display().to_string(),
            client: SOURCE_RESTORE_CLIENT,
            authority_epoch: 1,
            timeout: Duration::from_secs(5),
            cleanup_argv: vec!["/bin/true".to_owned()],
        };
        let mut unbound_application = command.clone();
        unbound_application.application_argument = "/missing/application.aot".to_owned();
        assert!(matches!(
            validate_restore_command(
                &unbound_application,
                WancoProcessIdentity { session: &SESSION.0, stable_owner: &OWNER.0 },
                &temporary.path().join("application.aot"),
                &checkpoint
            ),
            Err(MigrationError::Invalid(
                "Wanco restore command does not bind its application argument"
            ))
        ));
        let mut checkpoint_after_guest_delimiter = command.clone();
        checkpoint_after_guest_delimiter.argv.swap(9, 11);
        checkpoint_after_guest_delimiter.argv.swap(10, 11);
        assert!(matches!(
            validate_restore_command(
                &checkpoint_after_guest_delimiter,
                WancoProcessIdentity { session: &SESSION.0, stable_owner: &OWNER.0 },
                &temporary.path().join("application.aot"),
                &checkpoint,
            ),
            Err(MigrationError::Invalid(
                "Wanco restore checkpoint must precede the guest argument delimiter"
            ))
        ));
        let intent = intent();
        let manifest = MigrationManifest::seal(&intent, temporary.path()).unwrap();
        let destination_database = temporary.path().join("destination.sqlite");
        let destination_receipt = temporary.path().join("destination-restore.json");
        let host_binary = temporary.path().join("test-host");
        fs::write(
            &host_binary,
            b"#!/bin/sh\nset -eu\ntest \"$1\" = restore\nprintf 'prepared database' > \"$3\"\n",
        )
        .unwrap();
        fs::set_permissions(&host_binary, fs::Permissions::from_mode(0o700)).unwrap();
        let destination = DestinationProviderProcess {
            host_binary,
            bundle: capsule.clone(),
            database: destination_database.clone(),
            restore_receipt: destination_receipt.clone(),
            endpoint: ProviderEndpoint {
                socket: temporary.path().join("destination.sock"),
                capability: AdminCapability([9; 32]),
            },
            guest_capability: GuestCapability([8; 32]),
            stdout: temporary.path().join("destination.stdout"),
            stderr: temporary.path().join("destination.stderr"),
            startup_timeout: Duration::from_secs(1),
        };
        run_host_restore(&destination, &manifest).unwrap();
        verify_destination_restore_receipt(&destination, &manifest, true).unwrap();
        fs::write(&destination_database, b"different database").unwrap();
        assert!(matches!(
            verify_destination_restore_receipt(&destination, &manifest, true),
            Err(MigrationError::Integrity(
                "destination provider restore receipt differs from the migration manifest or database"
            ))
        ));
        let fingerprint = command_fingerprint(
            "restore_source",
            &command,
            &manifest.digest().unwrap().to_string(),
        )
        .unwrap();
        crate::supervisor::execute_in_process(SupervisedCommand {
            operation: "restore_source",
            supervisor_binary: &command.supervisor_binary,
            spec_path: &command.supervisor_spec,
            started_receipt: &command.supervisor_started_receipt,
            completion_receipt: &command.completion_receipt,
            lock_path: &command.supervisor_lock,
            fingerprint: &fingerprint,
            argv: &command.argv,
            cwd: &command.cwd,
            stdout: &command.stdout,
            stderr: &command.stderr,
            timeout: command.timeout,
            cleanup_argv: &command.cleanup_argv,
        })
        .unwrap();
        let mut first =
            WancoProcessControl::new(temporary.path(), &source_exit, command.clone(), None);
        first.confirm_source_exit(&intent).unwrap();
        first.restore_source(&intent).unwrap();
        assert_eq!(fs::read(&marker).unwrap(), b"x");

        let mut recovered = WancoProcessControl::new(temporary.path(), source_exit, command, None);
        recovered.restore_source(&intent).unwrap();
        assert_eq!(fs::read(&marker).unwrap(), b"x");
    }

    fn intent() -> MigrationIntent {
        MigrationIntent {
            files: FileRoles {
                application: "application.aot".to_owned(),
                compute_checkpoint: "checkpoint.pb".to_owned(),
                resource_capsule_manifest: "capsule/manifest.json".to_owned(),
                resource_capsule_state: "capsule/state.sqlite".to_owned(),
            },
            session: SESSION,
            stable_owner: OWNER,
            handoff: [6; 16],
            checkpoint_barrier: BarrierToken([7; 16]),
            source_epoch: 1,
            destination_epoch: 2,
            source_client: SOURCE_CLIENT,
            source_restore_client: SOURCE_RESTORE_CLIENT,
            destination_client: DESTINATION_CLIENT,
            application_build: BuildIdentity {
                source_revision: "revision".to_owned(),
                toolchain: "toolchain".to_owned(),
                build_configuration_sha256: "11".repeat(32),
            },
            source_platform: platform(),
            destination_platform: platform(),
        }
    }

    fn platform() -> PlatformIdentity {
        PlatformIdentity {
            operating_system: "linux".to_owned(),
            architecture: "x86_64".to_owned(),
            abi: "wanco-aot-preview1".to_owned(),
            runtime_name: "Wanco".to_owned(),
            runtime_version: "test".to_owned(),
            runtime_build_sha256: "22".repeat(32),
        }
    }

    fn status(mode: WireProviderMode) -> ProviderStatus {
        ProviderStatus {
            session: SESSION,
            mode,
            authority_epoch: 1,
            barrier: BarrierPhase::CheckpointReleased,
            barrier_remaining: None,
            barrier_effect: Some(EffectId([8; 16])),
            open_descriptors: 1,
            objects: 1,
            paths: 1,
            locks: 0,
            effects: 1,
            completed_requests: 1,
            bytes_read: 0,
            bytes_written: 0,
        }
    }

    #[derive(Serialize)]
    struct TestCapsuleDescriptor<'a> {
        schema: &'a str,
        session_hex: String,
        source_epoch: u64,
        destination_epoch: u64,
        handoff_hex: String,
        state_file: &'a str,
        state_size: u64,
        state_sha256: String,
    }
}
