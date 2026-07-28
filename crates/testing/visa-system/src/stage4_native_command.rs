use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    process::{Child, Command, ExitCode, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use sha2::{Digest as _, Sha256};
use visa_conformance::{
    STAGE1_CASE_DEFINITIONS, STAGE4_ACCEPTED_COMPONENT_SHA256,
    STAGE4_NATIVE_BUILD_RECEIPT_SCHEMA_VERSION, STAGE4_NATIVE_CELL_CATALOG,
    STAGE4_NATIVE_HOST_OBSERVATION_SCHEMA_VERSION, STAGE4_NATIVE_HOST_RECEIPT_SCHEMA_VERSION,
    STAGE4_NATIVE_LAUNCHER_RECEIPT_SCHEMA_VERSION, STAGE4_NATIVE_PROVIDER_BACKEND_IDENTITY,
    STAGE4_NATIVE_PROVIDER_RECEIPT_FILE, STAGE4_NATIVE_PROVIDER_RECEIPT_SCHEMA_VERSION,
    STAGE4_WORKER_PROTOCOL_VERSION, Stage4ArtifactReference, Stage4HostIdentity,
    Stage4NativeBuildReceipt, Stage4NativeCellId, Stage4NativeCommandReceipt,
    Stage4NativeEndpointEvidence, Stage4NativeEndpointId, Stage4NativeHardwareModelObservation,
    Stage4NativeHostEvidence, Stage4NativeHostId, Stage4NativeHostReceipt,
    Stage4NativeLauncherReceipt, Stage4NativeLauncherTransport, Stage4NativeProviderCaseDomain,
    Stage4NativeProviderEvidence, Stage4NativeProviderHaTransport, Stage4NativeProviderReceipt,
    Stage4NativeProviderRuntimeExecution, Stage4NativeProviderTransport,
    Stage4NativePublicationCell, Stage4NativePublicationInput, Stage4NativeRawHostObservation,
    Stage4Role, Stage4TargetHello, Stage4TargetHelloObservation, Stage4TargetIdentity,
    begin_stage4_native_evidence_publication, required_stage4_native_provider_backend_target,
    stage4_native_artifact_reference_for_file, write_stage4_native_evidence_artifacts,
};
use visa_system::{
    build_info, component,
    provider_rpc::{ProviderLocator, ProviderServer, probe as probe_provider},
    runner::{RoleLaunchers, TargetHelloObservation, WorkerLauncher},
    target::{TargetEndianness, TargetHelloV1, observe_target, validate_target_nonce},
};

use super::{current_executable, run_evidence_cell_with_launchers};

const UNAME_PATH: &str = "/usr/bin/uname";
const VIRTUALIZATION_PATH: &str = "/usr/bin/systemd-detect-virt";
const HARDWARE_MODEL_PATH: &str = "/proc/device-tree/model";
const SSH_URI: &str = "transport/ssh";
const KNOWN_HOSTS_URI: &str = "transport/known_hosts";
const RAW_STREAM_LIMIT: usize = 1024 * 1024;
static NEXT_HOST_NONCE: AtomicU64 = AtomicU64::new(1);

type CommandResult<T> = Result<T, (u8, String)>;

#[derive(Clone)]
struct OwnedFile {
    path: PathBuf,
    sha256: String,
    size: u64,
}

impl OwnedFile {
    fn reference(&self, uri: impl Into<String>) -> Stage4ArtifactReference {
        Stage4ArtifactReference { uri: uri.into(), sha256: self.sha256.clone(), size: self.size }
    }

    fn verify_unchanged(&self, label: &str) -> CommandResult<()> {
        let observed = regular_file_identity(&self.path, label)?;
        if observed.sha256 != self.sha256 || observed.size != self.size {
            return command_error(1, format!("{label} changed during the native matrix run"));
        }
        Ok(())
    }
}

struct PreparedEndpoint {
    launcher: WorkerLauncher,
    provenance_executable: PathBuf,
    evidence: Stage4NativeEndpointEvidence,
}

#[derive(Clone)]
struct SshTransport {
    launcher: WorkerLauncher,
    ssh: OwnedFile,
    known_hosts: OwnedFile,
    remote_host: String,
    remote_worker: String,
    identity_file: PathBuf,
    prefix: Vec<OsString>,
}

struct ProviderRuntime {
    server: Option<ProviderServer>,
    tunnel: Option<Child>,
    database_root: PathBuf,
    local_socket: PathBuf,
    remote_socket: PathBuf,
    cleanup_transport: SshTransport,
    remote_cleanup_pending: bool,
}

impl ProviderRuntime {
    fn local_socket(&self) -> &Path {
        &self.local_socket
    }

    fn remote_socket(&self) -> &Path {
        &self.remote_socket
    }

    fn shutdown(mut self) -> CommandResult<()> {
        let remote_cleanup =
            remove_remote_provider_socket(&self.cleanup_transport, &self.remote_socket);
        if remote_cleanup.is_ok() {
            self.remote_cleanup_pending = false;
        }
        let tunnel_cleanup = self.stop_tunnel();
        let server_cleanup = self.stop_server();
        let database_cleanup = remove_provider_database_root(&self.database_root);
        remote_cleanup?;
        tunnel_cleanup?;
        server_cleanup?;
        database_cleanup
    }

    fn stop_tunnel(&mut self) -> CommandResult<()> {
        let Some(mut child) = self.tunnel.take() else {
            return Ok(());
        };
        if child
            .try_wait()
            .map_err(|source| (1, format!("cannot inspect native provider tunnel: {source}")))?
            .is_none()
        {
            child
                .kill()
                .map_err(|source| (1, format!("cannot stop native provider tunnel: {source}")))?;
        }
        child
            .wait()
            .map_err(|source| (1, format!("cannot reap native provider tunnel: {source}")))?;
        Ok(())
    }

    fn stop_server(&mut self) -> CommandResult<()> {
        let Some(server) = self.server.take() else {
            return Ok(());
        };
        server
            .shutdown()
            .map_err(|source| (1, format!("cannot stop native provider service: {source}")))
    }
}

impl Drop for ProviderRuntime {
    fn drop(&mut self) {
        if self.remote_cleanup_pending {
            let _ = remove_remote_provider_socket(&self.cleanup_transport, &self.remote_socket);
        }
        let _ = self.stop_tunnel();
        let _ = self.stop_server();
        let _ = remove_provider_database_root(&self.database_root);
    }
}

pub(super) fn run_stage4_native_command(
    requested_root: &Path,
    aarch64_worker: &Path,
    ssh_program: &Path,
    known_hosts: &Path,
    identity_file: &Path,
    remote_host: &OsStr,
    remote_worker: &Path,
) -> CommandResult<ExitCode> {
    validate_remote_host(remote_host)?;
    validate_remote_worker(remote_worker)?;
    begin_stage4_native_evidence_publication(requested_root)
        .map_err(|source| (1, format!("cannot begin Stage 4 native publication: {source}")))?;
    let root = requested_root
        .canonicalize()
        .map_err(|source| (1, format!("cannot resolve Stage 4 native artifact root: {source}")))?;
    execute_native_matrix(
        &root,
        aarch64_worker,
        ssh_program,
        known_hosts,
        identity_file,
        remote_host,
        remote_worker,
    )?;
    Ok(ExitCode::SUCCESS)
}

pub(super) fn run_stage4_native_host_observation(
    nonce: &str,
    host_id: Stage4NativeHostId,
) -> CommandResult<ExitCode> {
    validate_target_nonce(nonce).map_err(|source| (64, source.to_string()))?;
    let observation = observe_native_host(nonce, host_id)?;
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();
    serde_json::to_writer(&mut writer, &observation)
        .map_err(|source| (2, format!("cannot encode native host observation: {source}")))?;
    writer
        .write_all(b"\n")
        .and_then(|()| writer.flush())
        .map_err(|source| (2, format!("cannot write native host observation: {source}")))?;
    Ok(ExitCode::SUCCESS)
}

fn execute_native_matrix(
    root: &Path,
    aarch64_worker_input: &Path,
    ssh_program_input: &Path,
    known_hosts_input: &Path,
    identity_file_input: &Path,
    remote_host: &OsStr,
    remote_worker: &Path,
) -> CommandResult<()> {
    validate_component_identity()?;
    let current = current_executable()?;
    let orchestrator = observe_target(&"0".repeat(64))
        .map_err(|source| (1, format!("cannot observe native orchestrator target: {source}")))?;
    validate_target(Stage4NativeEndpointId::Hx, &orchestrator)?;

    let hx_worker = copy_owned_file(
        root,
        &current,
        &Stage4NativeEndpointId::Hx.worker_uri(),
        0o555,
        "native Hx worker",
    )?;
    let ha_worker = copy_owned_file(
        root,
        aarch64_worker_input,
        &Stage4NativeEndpointId::Ha.worker_uri(),
        0o555,
        "native Ha worker",
    )?;
    require_elf_machine(&hx_worker.path, Stage4NativeEndpointId::Hx)?;
    require_elf_machine(&ha_worker.path, Stage4NativeEndpointId::Ha)?;

    let ssh = copy_owned_file(root, ssh_program_input, SSH_URI, 0o555, "SSH client")?;
    let known_hosts =
        copy_owned_file(root, known_hosts_input, KNOWN_HOSTS_URI, 0o444, "pinned SSH known_hosts")?;
    let ssh_transport = prepare_ssh_transport(
        root,
        ssh,
        known_hosts,
        identity_file_input,
        remote_host,
        remote_worker,
    )?;

    let hx_probe_launcher = WorkerLauncher::direct(&hx_worker.path);
    let hx_preflight = hx_probe_launcher
        .probe_target()
        .map_err(|source| (1, format!("Hx target preflight failed: {source}")))?;
    validate_hello(Stage4NativeEndpointId::Hx, &hx_preflight.hello, &hx_worker)?;
    let ha_preflight = ssh_transport
        .launcher
        .probe_target()
        .map_err(|source| (1, format!("Ha target preflight failed: {source}")))?;
    validate_hello(Stage4NativeEndpointId::Ha, &ha_preflight.hello, &ha_worker)?;
    require_clean_observation("Hx target preflight", &hx_preflight)?;
    require_clean_observation("Ha target preflight", &ha_preflight)?;
    require_shared_build_lineage(&hx_preflight.hello, &ha_preflight.hello)?;

    let hosts = vec![
        retain_host_observation(
            root,
            Stage4NativeHostId::HxHost,
            run_host_observation_direct(&hx_worker.path, Stage4NativeHostId::HxHost)?,
        )?,
        retain_host_observation(
            root,
            Stage4NativeHostId::HaHost,
            run_host_observation_ssh(&ssh_transport, Stage4NativeHostId::HaHost)?,
        )?,
    ];

    let provider_runtime = start_provider_runtime(root, &ssh_transport)?;
    let hx_launcher = hx_probe_launcher.with_provider_socket(provider_runtime.local_socket());
    let ha_launcher =
        ssh_transport.launcher.clone().with_provider_socket(provider_runtime.remote_socket());

    let hx = prepare_endpoint_evidence(
        root,
        Stage4NativeEndpointId::Hx,
        hx_worker.clone(),
        hx_launcher,
        &hx_preflight.hello,
        Stage4NativeLauncherTransport::LocalDirect {
            argv: vec![path_text(&hx_worker.path, "owned Hx worker")?],
        },
    )?;
    let ha_argv = std::iter::once(path_text(&ssh_transport.ssh.path, "owned SSH client")?)
        .chain(os_strings_text(&ssh_transport.prefix, "SSH launcher prefix")?)
        .collect();
    let ha = prepare_endpoint_evidence(
        root,
        Stage4NativeEndpointId::Ha,
        ha_worker.clone(),
        ha_launcher,
        &ha_preflight.hello,
        Stage4NativeLauncherTransport::Ssh {
            ssh_program: ssh_transport.ssh.reference(SSH_URI),
            known_hosts: ssh_transport.known_hosts.reference(KNOWN_HOSTS_URI),
            remote_host: ssh_transport.remote_host.clone(),
            remote_worker_path: ssh_transport.remote_worker.clone(),
            argv: ha_argv,
        },
    )?;
    let endpoints =
        BTreeMap::from([(Stage4NativeEndpointId::Hx, hx), (Stage4NativeEndpointId::Ha, ha)]);
    let provider = prepare_provider_evidence(
        root,
        &hx_worker,
        provider_runtime.local_socket(),
        provider_runtime.remote_socket(),
        &endpoints,
    )?;

    let mut cells = Vec::with_capacity(STAGE4_NATIVE_CELL_CATALOG.len());
    for cell_id in STAGE4_NATIVE_CELL_CATALOG.iter().copied() {
        cells.push(run_native_cell(root, cell_id, &endpoints)?);
    }
    provider_runtime.shutdown()?;

    hx_worker.verify_unchanged("owned Hx worker")?;
    ha_worker.verify_unchanged("owned Ha worker")?;
    ssh_transport.ssh.verify_unchanged("owned SSH client")?;
    ssh_transport.known_hosts.verify_unchanged("owned SSH known_hosts")?;

    let input = Stage4NativePublicationInput {
        hosts,
        endpoints: [Stage4NativeEndpointId::Hx, Stage4NativeEndpointId::Ha]
            .into_iter()
            .map(|id| endpoints[&id].evidence.clone())
            .collect(),
        provider,
        cells,
    };
    let result = write_stage4_native_evidence_artifacts(root, &input)
        .map_err(|source| (1, format!("Stage 4 native publication failed: {source}")))?;
    println!("Stage 4 native evidence bundle: {}", result.bundle_path);
    println!("Stage 4 native matrix manifest: {}", result.matrix_path);
    println!("Stage 4 native artifact root: {}", root.display());
    println!("Stage 4 native cases: 124/124 (31 cases x 4 cells)");
    Ok(())
}

fn prepare_ssh_transport(
    root: &Path,
    ssh: OwnedFile,
    known_hosts: OwnedFile,
    identity_file: &Path,
    remote_host: &OsStr,
    remote_worker: &Path,
) -> CommandResult<SshTransport> {
    let remote_host = remote_host
        .to_str()
        .ok_or_else(|| (64, "remote host must be valid UTF-8".to_owned()))?
        .to_owned();
    let remote_worker = remote_worker
        .to_str()
        .ok_or_else(|| (64, "remote worker path must be valid UTF-8".to_owned()))?
        .to_owned();
    let identity_file = validate_ssh_identity_file(identity_file)?;
    let known_hosts_path = root.join(KNOWN_HOSTS_URI);
    let mut prefix = ssh_connection_options(&known_hosts_path, &identity_file, true);
    prefix.extend([OsString::from(remote_host.clone()), OsString::from(remote_worker.clone())]);
    let launcher = WorkerLauncher::new(&ssh.path, prefix.clone());
    Ok(SshTransport {
        launcher,
        ssh,
        known_hosts,
        remote_host,
        remote_worker,
        identity_file,
        prefix,
    })
}

fn ssh_connection_options(
    known_hosts: &Path,
    identity_file: &Path,
    clear_forwardings: bool,
) -> Vec<OsString> {
    let mut options = vec![
        OsString::from("-T"),
        OsString::from("-F"),
        OsString::from("/dev/null"),
        OsString::from("-o"),
        OsString::from("BatchMode=yes"),
        OsString::from("-o"),
        OsString::from("IdentitiesOnly=yes"),
        OsString::from("-o"),
        OsString::from(format!("IdentityFile={}", identity_file.display())),
        OsString::from("-o"),
        OsString::from("ConnectTimeout=15"),
        OsString::from("-o"),
        OsString::from("ForwardAgent=no"),
        OsString::from("-o"),
        OsString::from("ForwardX11=no"),
        OsString::from("-o"),
        OsString::from("LogLevel=ERROR"),
        OsString::from("-o"),
        OsString::from("StrictHostKeyChecking=yes"),
        OsString::from("-o"),
        OsString::from("GlobalKnownHostsFile=/dev/null"),
        OsString::from("-o"),
        OsString::from(format!("UserKnownHostsFile={}", known_hosts.display())),
        OsString::from("-o"),
        OsString::from("ControlMaster=no"),
        OsString::from("-o"),
        OsString::from("ServerAliveInterval=15"),
        OsString::from("-o"),
        OsString::from("ServerAliveCountMax=3"),
    ];
    if clear_forwardings {
        options.extend([OsString::from("-o"), OsString::from("ClearAllForwardings=yes")]);
    }
    options
}

fn start_provider_runtime(root: &Path, transport: &SshTransport) -> CommandResult<ProviderRuntime> {
    let database_root = root.join(".provider-runtime");
    if fs::symlink_metadata(&database_root).is_ok() {
        return command_error(1, "native provider runtime root already exists");
    }
    let nonce = fresh_host_nonce()?;
    let local_socket = PathBuf::from(format!("/tmp/visa-provider-{nonce}.sock"));
    let remote_worker = Path::new(&transport.remote_worker);
    let remote_parent = remote_worker
        .parent()
        .ok_or_else(|| (64, "remote native worker has no parent directory".to_owned()))?;
    let remote_socket = remote_parent.join("provider.sock");
    validate_remote_worker(&remote_socket)?;

    let server = ProviderServer::start(&database_root, &local_socket)
        .map_err(|source| (1, format!("cannot start native provider service: {source}")))?;
    let local_probe = ProviderLocator::new(&local_socket, "0".repeat(64))
        .map_err(|source| (1, format!("cannot construct local provider probe: {source}")))?;
    probe_provider(local_probe.as_str())
        .map_err(|source| (1, format!("local native provider probe failed: {source}")))?;
    let mut runtime = ProviderRuntime {
        server: Some(server),
        tunnel: None,
        database_root,
        local_socket,
        remote_socket,
        cleanup_transport: transport.clone(),
        remote_cleanup_pending: true,
    };
    runtime.tunnel =
        Some(spawn_provider_tunnel(transport, &runtime.local_socket, &runtime.remote_socket)?);
    wait_for_remote_provider(transport, &mut runtime)?;
    Ok(runtime)
}

fn spawn_provider_tunnel(
    transport: &SshTransport,
    local_socket: &Path,
    remote_socket: &Path,
) -> CommandResult<Child> {
    let local = path_text(local_socket, "local provider socket")?;
    let remote = path_text(remote_socket, "remote provider socket")?;
    if local.contains(':') || remote.contains(':') {
        return command_error(64, "provider socket paths cannot contain ':'");
    }
    let forward = format!("{remote}:{local}");
    let mut command = Command::new(&transport.ssh.path);
    command
        .args(ssh_connection_options(&transport.known_hosts.path, &transport.identity_file, false))
        .args([
            OsString::from("-o"),
            OsString::from("ExitOnForwardFailure=yes"),
            OsString::from("-o"),
            OsString::from("StreamLocalBindUnlink=yes"),
            OsString::from("-N"),
            OsString::from("-R"),
            OsString::from(forward),
            OsString::from(transport.remote_host.clone()),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    command
        .spawn()
        .map_err(|source| (1, format!("cannot start native provider SSH tunnel: {source}")))
}

fn wait_for_remote_provider(
    transport: &SshTransport,
    runtime: &mut ProviderRuntime,
) -> CommandResult<()> {
    let locator = ProviderLocator::new(&runtime.remote_socket, "0".repeat(64))
        .map_err(|source| (1, format!("cannot construct remote provider probe: {source}")))?;
    let mut last_detail = "remote provider tunnel was not ready".to_owned();
    for _ in 0..20 {
        let tunnel = runtime
            .tunnel
            .as_mut()
            .ok_or_else(|| (1, "native provider tunnel is unavailable".to_owned()))?;
        if let Some(status) = tunnel
            .try_wait()
            .map_err(|source| (1, format!("cannot inspect native provider tunnel: {source}")))?
        {
            return command_error(
                1,
                format!("native provider tunnel exited before readiness: {status}"),
            );
        }
        let output = Command::new(&transport.ssh.path)
            .args(&transport.prefix)
            .arg("stage4-native-provider-probe")
            .arg(locator.as_str())
            .stdin(Stdio::null())
            .output()
            .map_err(|source| (1, format!("cannot run remote provider probe: {source}")))?;
        if output.status.code() == Some(0) && output.stdout.is_empty() && output.stderr.is_empty() {
            return Ok(());
        }
        last_detail = format!(
            "status={:?}, stdout={:?}, stderr={:?}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        thread::sleep(Duration::from_millis(100));
    }
    command_error(1, format!("remote native provider probe failed: {last_detail}"))
}

fn remove_remote_provider_socket(
    transport: &SshTransport,
    remote_socket: &Path,
) -> CommandResult<()> {
    let output = Command::new(&transport.ssh.path)
        .args(ssh_connection_options(&transport.known_hosts.path, &transport.identity_file, true))
        .arg(&transport.remote_host)
        .args([OsStr::new("/usr/bin/rm"), OsStr::new("-f"), OsStr::new("--")])
        .arg(remote_socket)
        .stdin(Stdio::null())
        .output()
        .map_err(|source| (1, format!("cannot clean remote provider socket: {source}")))?;
    if output.status.code() != Some(0) || !output.stdout.is_empty() || !output.stderr.is_empty() {
        return command_error(1, "remote provider socket cleanup was not a clean success");
    }
    Ok(())
}

fn remove_provider_database_root(path: &Path) -> CommandResult<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return command_error(
                1,
                format!("cannot inspect native provider runtime {}: {source}", path.display()),
            );
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return command_error(1, "refusing unsafe native provider runtime cleanup");
    }
    fs::remove_dir_all(path)
        .map_err(|source| (1, format!("cannot remove native provider runtime: {source}")))
}

fn prepare_provider_evidence(
    root: &Path,
    hx_worker: &OwnedFile,
    local_socket: &Path,
    remote_socket: &Path,
    endpoints: &BTreeMap<Stage4NativeEndpointId, PreparedEndpoint>,
) -> CommandResult<Stage4NativeProviderEvidence> {
    let mut case_domains =
        Vec::with_capacity(STAGE4_NATIVE_CELL_CATALOG.len() * STAGE1_CASE_DEFINITIONS.len());
    let mut database_ids = BTreeSet::new();
    for cell_id in STAGE4_NATIVE_CELL_CATALOG.iter().copied() {
        let (source_id, destination_id) = cell_id.endpoints();
        let source = &endpoints[&source_id];
        let destination = &endpoints[&destination_id];
        for definition in STAGE1_CASE_DEFINITIONS {
            let database_path = root
                .join(cell_id.cell_root_uri())
                .join(".runner-work")
                .join(format!("{}.sqlite3", definition.id));
            let source_locator = ProviderLocator::parse(
                &source.launcher.database_locator(&database_path).map_err(|source| {
                    (1, format!("cannot route native source provider: {source}"))
                })?,
            )
            .map_err(|source| (1, format!("invalid native source provider locator: {source}")))?;
            let destination_locator = ProviderLocator::parse(
                &destination.launcher.database_locator(&database_path).map_err(|source| {
                    (1, format!("cannot route native destination provider: {source}"))
                })?,
            )
            .map_err(|source| {
                (1, format!("invalid native destination provider locator: {source}"))
            })?;
            if source_locator.database_id() != destination_locator.database_id()
                || source_locator.socket_path()
                    != endpoint_provider_socket(source_id, local_socket, remote_socket)
                || destination_locator.socket_path()
                    != endpoint_provider_socket(destination_id, local_socket, remote_socket)
                || !database_ids.insert(source_locator.database_id().to_owned())
            {
                return command_error(
                    1,
                    "native provider routing does not define one unique shared transaction domain per case",
                );
            }
            case_domains.push(Stage4NativeProviderCaseDomain {
                cell_id,
                case_id: definition.id.to_owned(),
                source_endpoint: source_id,
                destination_endpoint: destination_id,
                logical_database_id: source_locator.database_id().to_owned(),
            });
        }
    }
    let receipt = Stage4NativeProviderReceipt {
        schema_version: STAGE4_NATIVE_PROVIDER_RECEIPT_SCHEMA_VERSION.to_owned(),
        provider_host: Stage4NativeHostId::HxHost,
        backend_identity: STAGE4_NATIVE_PROVIDER_BACKEND_IDENTITY.to_owned(),
        backend_target: required_stage4_native_provider_backend_target(),
        service_executable: hx_worker.reference(Stage4NativeEndpointId::Hx.worker_uri()),
        service_executable_sha256: hx_worker.sha256.clone(),
        service_executable_size: hx_worker.size,
        transport: Stage4NativeProviderTransport::UnixStream {
            local_socket_path: path_text(local_socket, "local provider socket")?,
            ha_transport: Stage4NativeProviderHaTransport::SshReverseStreamLocal {
                remote_socket_path: path_text(remote_socket, "remote provider socket")?,
            },
        },
        runtime_execution: Stage4NativeProviderRuntimeExecution {
            hx_native: true,
            ha_native: true,
        },
        case_domains,
    };
    let receipt_artifact = publish_json(root, STAGE4_NATIVE_PROVIDER_RECEIPT_FILE, &receipt)?;
    Ok(Stage4NativeProviderEvidence { receipt_artifact, receipt })
}

const fn endpoint_provider_socket<'a>(
    endpoint: Stage4NativeEndpointId,
    local_socket: &'a Path,
    remote_socket: &'a Path,
) -> &'a Path {
    match endpoint {
        Stage4NativeEndpointId::Hx => local_socket,
        Stage4NativeEndpointId::Ha => remote_socket,
    }
}

fn prepare_endpoint_evidence(
    root: &Path,
    id: Stage4NativeEndpointId,
    worker: OwnedFile,
    launcher: WorkerLauncher,
    hello: &TargetHelloV1,
    transport: Stage4NativeLauncherTransport,
) -> CommandResult<PreparedEndpoint> {
    let target = target_identity(hello);
    let build_receipt = Stage4NativeBuildReceipt {
        schema_version: STAGE4_NATIVE_BUILD_RECEIPT_SCHEMA_VERSION.to_owned(),
        endpoint_id: id,
        target: target.clone(),
        executable_sha256: worker.sha256.clone(),
        executable_size: worker.size,
        build_source_sha256: hello.build_source_sha256.clone(),
        build_toolchain_sha256: hello.build_toolchain_sha256.clone(),
    };
    let build_receipt_artifact = publish_json(root, &id.build_receipt_uri(), &build_receipt)?;
    let launcher_receipt = Stage4NativeLauncherReceipt {
        schema_version: STAGE4_NATIVE_LAUNCHER_RECEIPT_SCHEMA_VERSION.to_owned(),
        endpoint_id: id,
        host_id: id.host_id(),
        worker_sha256: worker.sha256.clone(),
        worker_size: worker.size,
        native_execution: true,
        emulated_execution: false,
        transport,
    };
    let launcher_receipt_artifact =
        publish_json(root, &id.launcher_receipt_uri(), &launcher_receipt)?;
    Ok(PreparedEndpoint {
        launcher,
        provenance_executable: worker.path.clone(),
        evidence: Stage4NativeEndpointEvidence {
            endpoint_id: id,
            host_id: id.host_id(),
            target,
            worker_executable: worker.reference(id.worker_uri()),
            build_receipt_artifact,
            build_receipt,
            launcher_receipt_artifact,
            launcher_receipt,
        },
    })
}

fn run_native_cell(
    root: &Path,
    cell_id: Stage4NativeCellId,
    endpoints: &BTreeMap<Stage4NativeEndpointId, PreparedEndpoint>,
) -> CommandResult<Stage4NativePublicationCell> {
    let (source_id, destination_id) = cell_id.endpoints();
    let source = endpoints
        .get(&source_id)
        .ok_or_else(|| (1, format!("missing native source endpoint {}", source_id.as_str())))?;
    let destination = endpoints.get(&destination_id).ok_or_else(|| {
        (1, format!("missing native destination endpoint {}", destination_id.as_str()))
    })?;
    let cell_root = root.join(cell_id.cell_root_uri());
    fs::create_dir_all(&cell_root).map_err(|source| {
        (1, format!("cannot create native cell root {}: {source}", cell_root.display()))
    })?;
    let output = run_evidence_cell_with_launchers(
        &cell_root,
        &source.provenance_executable,
        RoleLaunchers::new(source.launcher.clone(), destination.launcher.clone()),
    )?;
    remove_runner_work(&cell_root)?;
    validate_hello(
        source_id,
        &output.source_target.hello,
        &file_from_reference(root, &source.evidence.worker_executable)?,
    )?;
    validate_hello(
        destination_id,
        &output.destination_target.hello,
        &file_from_reference(root, &destination.evidence.worker_executable)?,
    )?;
    let source_hello = retain_hello(root, cell_id, Stage4Role::Source, &output.source_target)?;
    let destination_hello =
        retain_hello(root, cell_id, Stage4Role::Destination, &output.destination_target)?;
    let stage1_bundle =
        stage4_native_artifact_reference_for_file(root, &cell_id.stage1_bundle_uri())
            .map_err(|source| (1, format!("cannot retain native Stage 1 bundle: {source}")))?;
    Ok(Stage4NativePublicationCell {
        cell_id,
        source_endpoint: source_id,
        destination_endpoint: destination_id,
        stage1_bundle,
        source_hello,
        destination_hello,
    })
}

fn run_host_observation_direct(
    worker: &Path,
    host_id: Stage4NativeHostId,
) -> CommandResult<Vec<u8>> {
    let nonce = fresh_host_nonce()?;
    let output = Command::new(worker)
        .arg("stage4-native-host")
        .arg(&nonce)
        .arg(host_id.as_str())
        .output()
        .map_err(|source| (1, format!("cannot run local native host observation: {source}")))?;
    require_host_observation_output("local native host observation", output, &nonce, host_id)
}

fn run_host_observation_ssh(
    transport: &SshTransport,
    host_id: Stage4NativeHostId,
) -> CommandResult<Vec<u8>> {
    let nonce = fresh_host_nonce()?;
    let mut command = Command::new(&transport.ssh.path);
    command.args(&transport.prefix);
    command.arg("stage4-native-host").arg(&nonce).arg(host_id.as_str());
    let output = command
        .output()
        .map_err(|source| (1, format!("cannot run remote native host observation: {source}")))?;
    require_host_observation_output("remote native host observation", output, &nonce, host_id)
}

fn require_host_observation_output(
    label: &str,
    output: std::process::Output,
    nonce: &str,
    host_id: Stage4NativeHostId,
) -> CommandResult<Vec<u8>> {
    if output.status.code() != Some(0) || !output.stderr.is_empty() {
        return command_error(1, format!("{label} was not a clean successful execution"));
    }
    if output.stdout.len() > RAW_STREAM_LIMIT {
        return command_error(1, format!("{label} output exceeds the native evidence limit"));
    }
    let payload = single_json_line(&output.stdout, label)?;
    let observation: Stage4NativeRawHostObservation = serde_json::from_slice(payload)
        .map_err(|source| (1, format!("cannot parse {label}: {source}")))?;
    if observation.schema_version != STAGE4_NATIVE_HOST_OBSERVATION_SCHEMA_VERSION
        || observation.nonce != nonce
        || observation.host_id != host_id
    {
        return command_error(1, format!("{label} challenge or identity mismatch"));
    }
    let canonical = serde_json::to_vec(&observation)
        .map_err(|source| (1, format!("cannot re-encode {label}: {source}")))?;
    if payload != canonical {
        return command_error(1, format!("{label} is not canonical one-line JSON"));
    }
    Ok(output.stdout)
}

fn retain_host_observation(
    root: &Path,
    host_id: Stage4NativeHostId,
    raw_bytes: Vec<u8>,
) -> CommandResult<Stage4NativeHostEvidence> {
    let payload = single_json_line(&raw_bytes, "native host observation")?;
    let observation: Stage4NativeRawHostObservation =
        serde_json::from_slice(payload).map_err(|source| {
            (1, format!("cannot parse retained native host observation: {source}"))
        })?;
    validate_raw_host_observation(&observation)?;
    let raw_observation = publish_bytes(root, &host_id.observation_uri(), &raw_bytes)?;
    let uname_stdout =
        publish_bytes(root, &host_id.uname_stdout_uri(), observation.uname_stdout.as_bytes())?;
    let uname_stderr =
        publish_bytes(root, &host_id.uname_stderr_uri(), observation.uname_stderr.as_bytes())?;
    let virtualization_stdout = publish_bytes(
        root,
        &host_id.virtualization_stdout_uri(),
        observation.virtualization_stdout.as_bytes(),
    )?;
    let virtualization_stderr = publish_bytes(
        root,
        &host_id.virtualization_stderr_uri(),
        observation.virtualization_stderr.as_bytes(),
    )?;
    let hardware_model = match (
        observation.hardware_model_source_path.as_deref(),
        observation.hardware_model.as_deref(),
    ) {
        (Some(source_path), Some(model)) => {
            let mut raw = model.as_bytes().to_vec();
            raw.push(0);
            Some(Stage4NativeHardwareModelObservation {
                source_path: source_path.to_owned(),
                model: model.to_owned(),
                raw: publish_bytes(root, &host_id.hardware_model_uri(), &raw)?,
            })
        }
        (None, None) => None,
        _ => return command_error(1, "native hardware model observation is incomplete"),
    };
    let receipt = Stage4NativeHostReceipt {
        schema_version: STAGE4_NATIVE_HOST_RECEIPT_SCHEMA_VERSION.to_owned(),
        host_id,
        expected_nonce: observation.nonce.clone(),
        raw_observation,
        identity: observation.identity.clone(),
        uname: Stage4NativeCommandReceipt {
            program: UNAME_PATH.to_owned(),
            program_sha256: observation.uname_program_sha256.clone(),
            program_size: observation.uname_program_size,
            argv: observation.uname_argv.clone(),
            exit_status: observation.uname_exit_status,
            raw_stdout: uname_stdout,
            raw_stderr: uname_stderr,
        },
        virtualization: Stage4NativeCommandReceipt {
            program: VIRTUALIZATION_PATH.to_owned(),
            program_sha256: observation.virtualization_program_sha256.clone(),
            program_size: observation.virtualization_program_size,
            argv: observation.virtualization_argv.clone(),
            exit_status: observation.virtualization_exit_status,
            raw_stdout: virtualization_stdout,
            raw_stderr: virtualization_stderr,
        },
        hardware_model,
    };
    let receipt_artifact = publish_json(root, &host_id.receipt_uri(), &receipt)?;
    Ok(Stage4NativeHostEvidence { host_id, receipt_artifact, receipt })
}

fn observe_native_host(
    nonce: &str,
    host_id: Stage4NativeHostId,
) -> CommandResult<Stage4NativeRawHostObservation> {
    let uname_program = regular_file_identity(Path::new(UNAME_PATH), "uname executable")?;
    let uname = Command::new(UNAME_PATH)
        .args(["-s", "-r", "-m"])
        .env_clear()
        .env("LC_ALL", "C")
        .output()
        .map_err(|source| (64, format!("cannot observe uname identity: {source}")))?;
    let uname_stdout = utf8_output(&uname.stdout, "uname stdout")?;
    let uname_stderr = utf8_output(&uname.stderr, "uname stderr")?;
    let identity = parse_uname_identity(&uname_stdout)?;

    let virtualization_program =
        regular_file_identity(Path::new(VIRTUALIZATION_PATH), "virtualization detector")?;
    let virtualization = Command::new(VIRTUALIZATION_PATH)
        .env_clear()
        .env("LC_ALL", "C")
        .output()
        .map_err(|source| (64, format!("cannot run virtualization detector: {source}")))?;
    let virtualization_stdout = utf8_output(&virtualization.stdout, "virtualization stdout")?;
    let virtualization_stderr = utf8_output(&virtualization.stderr, "virtualization stderr")?;

    let (hardware_model_source_path, hardware_model) = match host_id {
        Stage4NativeHostId::HxHost => (None, None),
        Stage4NativeHostId::HaHost => {
            let bytes = fs::read(HARDWARE_MODEL_PATH).map_err(|source| {
                (64, format!("cannot read native hardware model {HARDWARE_MODEL_PATH}: {source}"))
            })?;
            let model = bytes
                .strip_suffix(&[0])
                .ok_or_else(|| (64, "device-tree hardware model lacks trailing NUL".to_owned()))?;
            let model = std::str::from_utf8(model)
                .map_err(|source| (64, format!("hardware model is not UTF-8: {source}")))?;
            if model.is_empty() || model.contains('\0') || model.contains('\n') {
                return command_error(64, "hardware model is empty or noncanonical");
            }
            (Some(HARDWARE_MODEL_PATH.to_owned()), Some(model.to_owned()))
        }
    };

    let observation = Stage4NativeRawHostObservation {
        schema_version: STAGE4_NATIVE_HOST_OBSERVATION_SCHEMA_VERSION.to_owned(),
        nonce: nonce.to_owned(),
        host_id,
        identity,
        uname_program_sha256: uname_program.sha256,
        uname_program_size: uname_program.size,
        uname_argv: [UNAME_PATH, "-s", "-r", "-m"].map(str::to_owned).to_vec(),
        uname_exit_status: uname.status.code().unwrap_or(-1),
        uname_stdout,
        uname_stderr,
        virtualization_program_sha256: virtualization_program.sha256,
        virtualization_program_size: virtualization_program.size,
        virtualization_argv: vec![VIRTUALIZATION_PATH.to_owned()],
        virtualization_exit_status: virtualization.status.code().unwrap_or(-1),
        virtualization_stdout,
        virtualization_stderr,
        hardware_model_source_path,
        hardware_model,
    };
    validate_raw_host_observation(&observation)?;
    Ok(observation)
}

fn validate_raw_host_observation(
    observation: &Stage4NativeRawHostObservation,
) -> CommandResult<()> {
    validate_target_nonce(&observation.nonce).map_err(|source| (64, source.to_string()))?;
    let expected_machine = match observation.host_id {
        Stage4NativeHostId::HxHost => "x86_64",
        Stage4NativeHostId::HaHost => "aarch64",
    };
    if observation.identity.sysname != "Linux"
        || observation.identity.machine != expected_machine
        || observation.identity.kernel_release.is_empty()
        || observation.uname_exit_status != 0
        || !observation.uname_stderr.is_empty()
        || observation.virtualization_exit_status != 1
        || observation.virtualization_stdout != "none\n"
        || !observation.virtualization_stderr.is_empty()
    {
        return command_error(64, "native host observation does not establish physical Linux");
    }
    match observation.host_id {
        Stage4NativeHostId::HxHost
            if observation.hardware_model.is_some()
                || observation.hardware_model_source_path.is_some() =>
        {
            return command_error(64, "Hx host unexpectedly reports an ARM hardware model");
        }
        Stage4NativeHostId::HaHost
            if observation.hardware_model.as_deref().is_none_or(str::is_empty)
                || observation.hardware_model_source_path.as_deref()
                    != Some(HARDWARE_MODEL_PATH) =>
        {
            return command_error(64, "Ha host lacks its physical device-tree model");
        }
        _ => {}
    }
    Ok(())
}

fn validate_component_identity() -> CommandResult<()> {
    let observed = format!("{:x}", Sha256::digest(component::bytes()));
    if observed != STAGE4_ACCEPTED_COMPONENT_SHA256 {
        return command_error(
            1,
            format!(
                "native Stage 4 component identity mismatch: expected {STAGE4_ACCEPTED_COMPONENT_SHA256}, observed {observed}"
            ),
        );
    }
    Ok(())
}

fn require_shared_build_lineage(hx: &TargetHelloV1, ha: &TargetHelloV1) -> CommandResult<()> {
    if hx.build_source_sha256 != ha.build_source_sha256
        || hx.build_toolchain_sha256 != ha.build_toolchain_sha256
        || hx.build_source_sha256 != build_info::SOURCE_SHA256
        || hx.build_toolchain_sha256 != build_info::TOOLCHAIN_SHA256
    {
        return command_error(1, "native endpoints do not share the orchestrator build lineage");
    }
    Ok(())
}

fn validate_hello(
    id: Stage4NativeEndpointId,
    hello: &TargetHelloV1,
    worker: &OwnedFile,
) -> CommandResult<()> {
    validate_target(id, hello)?;
    if hello.worker_protocol_version != STAGE4_WORKER_PROTOCOL_VERSION
        || hello.executable_sha256 != worker.sha256
        || hello.executable_size != worker.size
    {
        return command_error(
            1,
            format!("{} target hello disagrees with retained worker bytes", id.as_str()),
        );
    }
    Ok(())
}

fn validate_target(id: Stage4NativeEndpointId, hello: &TargetHelloV1) -> CommandResult<()> {
    let target = target_identity(hello);
    if target.target_triple != id.target_triple()
        || target.architecture != id.architecture()
        || target.os != "linux"
        || target.abi != "linux-gnu"
        || target.endianness != "little"
        || target.pointer_width_bits != 64
    {
        return command_error(
            64,
            format!("{} does not match the native Stage 4 target: {target:?}", id.as_str()),
        );
    }
    Ok(())
}

fn require_clean_observation(
    label: &str,
    observation: &TargetHelloObservation,
) -> CommandResult<()> {
    if observation.exit_code != 0 || !observation.stderr.is_empty() {
        return command_error(1, format!("{label} wrote stderr or exited unsuccessfully"));
    }
    Ok(())
}

fn retain_hello(
    root: &Path,
    cell: Stage4NativeCellId,
    role: Stage4Role,
    observed: &TargetHelloObservation,
) -> CommandResult<Stage4TargetHelloObservation> {
    require_clean_observation("native target hello", observed)?;
    Ok(Stage4TargetHelloObservation {
        expected_nonce: observed.hello.nonce.clone(),
        exit_status: observed.exit_code,
        hello: stage4_hello(&observed.hello),
        raw_stdout: publish_bytes(root, &cell.hello_stdout_uri(role), &observed.stdout)?,
        raw_stderr: publish_bytes(root, &cell.hello_stderr_uri(role), &observed.stderr)?,
    })
}

fn stage4_hello(hello: &TargetHelloV1) -> Stage4TargetHello {
    Stage4TargetHello {
        schema_version: hello.schema_version.clone(),
        nonce: hello.nonce.clone(),
        target_triple: hello.target_triple.clone(),
        architecture: hello.architecture.clone(),
        os: hello.os.clone(),
        abi: hello.abi.clone(),
        endianness: match hello.endianness {
            TargetEndianness::Little => "little",
            TargetEndianness::Big => "big",
        }
        .to_owned(),
        pointer_width_bits: hello.pointer_width_bits,
        executable_sha256: hello.executable_sha256.clone(),
        executable_size: hello.executable_size,
        build_source_sha256: hello.build_source_sha256.clone(),
        build_toolchain_sha256: hello.build_toolchain_sha256.clone(),
        worker_protocol_version: hello.worker_protocol_version,
    }
}

fn target_identity(hello: &TargetHelloV1) -> Stage4TargetIdentity {
    Stage4TargetIdentity {
        target_triple: hello.target_triple.clone(),
        architecture: hello.architecture.clone(),
        os: hello.os.clone(),
        abi: hello.abi.clone(),
        endianness: match hello.endianness {
            TargetEndianness::Little => "little",
            TargetEndianness::Big => "big",
        }
        .to_owned(),
        pointer_width_bits: hello.pointer_width_bits,
    }
}

fn parse_uname_identity(stdout: &str) -> CommandResult<Stage4HostIdentity> {
    if !stdout.ends_with('\n') || stdout.lines().count() != 1 {
        return command_error(64, "uname output must be one newline-terminated line");
    }
    let fields = stdout.split_whitespace().collect::<Vec<_>>();
    let [sysname, kernel_release, machine] = fields.as_slice() else {
        return command_error(64, "uname output must contain sysname, release, and machine");
    };
    let identity = Stage4HostIdentity {
        sysname: (*sysname).to_owned(),
        kernel_release: (*kernel_release).to_owned(),
        machine: (*machine).to_owned(),
    };
    if format!("{} {} {}\n", identity.sysname, identity.kernel_release, identity.machine) != stdout
    {
        return command_error(64, "uname output is not canonical");
    }
    Ok(identity)
}

fn fresh_host_nonce() -> CommandResult<String> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|source| (1, format!("cannot generate host nonce: {source}")))?;
    let sequence = NEXT_HOST_NONCE.fetch_add(1, Ordering::Relaxed);
    let mut digest = Sha256::new();
    digest.update(elapsed.as_nanos().to_le_bytes());
    digest.update(std::process::id().to_le_bytes());
    digest.update(sequence.to_le_bytes());
    Ok(format!("{:x}", digest.finalize()))
}

fn single_json_line<'a>(bytes: &'a [u8], label: &str) -> CommandResult<&'a [u8]> {
    let Some(payload) = bytes.strip_suffix(b"\n") else {
        return command_error(1, format!("{label} lacks its final newline"));
    };
    if payload.is_empty() || payload.contains(&b'\n') || payload.contains(&b'\r') {
        return command_error(1, format!("{label} is not one JSON line"));
    }
    Ok(payload)
}

fn utf8_output(bytes: &[u8], label: &str) -> CommandResult<String> {
    if bytes.len() > RAW_STREAM_LIMIT {
        return command_error(64, format!("{label} exceeds the native evidence limit"));
    }
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|source| (64, format!("{label} is not UTF-8: {source}")))
}

fn copy_owned_file(
    root: &Path,
    source: &Path,
    uri: &str,
    mode: u32,
    label: &str,
) -> CommandResult<OwnedFile> {
    let before = regular_file_identity(source, label)?;
    let destination = checked_artifact_path(root, uri)?;
    let parent = destination
        .parent()
        .ok_or_else(|| (1, format!("native artifact URI has no parent: {uri}")))?;
    fs::create_dir_all(parent).map_err(|source| {
        (1, format!("cannot create native artifact directory {}: {source}", parent.display()))
    })?;
    fs::copy(source, &destination).map_err(|source| {
        (1, format!("cannot copy {label} to {}: {source}", destination.display()))
    })?;
    fs::set_permissions(&destination, fs::Permissions::from_mode(mode)).map_err(|source| {
        (1, format!("cannot set native artifact mode {}: {source}", destination.display()))
    })?;
    File::open(&destination).and_then(|file| file.sync_all()).map_err(|source| {
        (1, format!("cannot sync native artifact {}: {source}", destination.display()))
    })?;
    let copied = regular_file_identity(&destination, label)?;
    let after = regular_file_identity(source, label)?;
    if before.sha256 != copied.sha256
        || before.size != copied.size
        || before.sha256 != after.sha256
        || before.size != after.size
    {
        return command_error(1, format!("{label} changed while acquiring owned bytes"));
    }
    let metadata = fs::symlink_metadata(&destination)
        .map_err(|source| (1, format!("cannot inspect owned {label}: {source}")))?;
    if metadata.nlink() != 1 || metadata.permissions().mode() & 0o777 != mode {
        return command_error(1, format!("owned {label} has an unsafe mode or link count"));
    }
    Ok(copied)
}

fn regular_file_identity(path: &Path, label: &str) -> CommandResult<OwnedFile> {
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|source| (64, format!("cannot inspect {label} {}: {source}", path.display())))?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return command_error(64, format!("{label} is not a regular non-symlink file"));
    }
    let mut file = File::open(path)
        .map_err(|source| (64, format!("cannot open {label} {}: {source}", path.display())))?;
    let before = file
        .metadata()
        .map_err(|source| (64, format!("cannot inspect opened {label}: {source}")))?;
    let mut digest = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| (64, format!("cannot hash {label}: {source}")))?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(u64::try_from(read).map_err(|_| (64, "file size overflow".to_owned()))?)
            .ok_or_else(|| (64, "file size overflow".to_owned()))?;
        digest.update(&buffer[..read]);
    }
    let after = file
        .metadata()
        .map_err(|source| (64, format!("cannot reinspect opened {label}: {source}")))?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.len() != size
        || path_metadata.dev() != after.dev()
        || path_metadata.ino() != after.ino()
    {
        return command_error(64, format!("{label} changed while hashing"));
    }
    Ok(OwnedFile { path: path.to_path_buf(), sha256: format!("{:x}", digest.finalize()), size })
}

fn file_from_reference(
    root: &Path,
    reference: &Stage4ArtifactReference,
) -> CommandResult<OwnedFile> {
    let observed = regular_file_identity(&root.join(&reference.uri), "native worker artifact")?;
    if observed.sha256 != reference.sha256 || observed.size != reference.size {
        return command_error(1, "native worker reference disagrees with retained bytes");
    }
    Ok(observed)
}

fn require_elf_machine(path: &Path, id: Stage4NativeEndpointId) -> CommandResult<()> {
    let mut header = [0_u8; 20];
    File::open(path)
        .and_then(|mut file| file.read_exact(&mut header))
        .map_err(|source| (64, format!("cannot read native worker ELF header: {source}")))?;
    let expected = match id {
        Stage4NativeEndpointId::Hx => 62_u16,
        Stage4NativeEndpointId::Ha => 183_u16,
    };
    let observed = header
        .starts_with(b"\x7fELF")
        .then_some(())
        .filter(|()| header[4] == 2 && header[5] == 1)
        .map(|()| u16::from_le_bytes([header[18], header[19]]));
    if observed != Some(expected) {
        return command_error(
            64,
            format!("{} worker is not ELF64 machine {expected}", id.as_str()),
        );
    }
    Ok(())
}

fn publish_json<T: Serialize>(
    root: &Path,
    uri: &str,
    value: &T,
) -> CommandResult<Stage4ArtifactReference> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|source| (1, format!("cannot encode native artifact {uri}: {source}")))?;
    publish_bytes(root, uri, &bytes)
}

fn publish_bytes(root: &Path, uri: &str, bytes: &[u8]) -> CommandResult<Stage4ArtifactReference> {
    let path = checked_artifact_path(root, uri)?;
    let parent =
        path.parent().ok_or_else(|| (1, format!("native artifact URI has no parent: {uri}")))?;
    fs::create_dir_all(parent).map_err(|source| {
        (1, format!("cannot create native artifact directory {}: {source}", parent.display()))
    })?;
    let mut file =
        OpenOptions::new().create_new(true).write(true).open(&path).map_err(|source| {
            (1, format!("cannot create native artifact {}: {source}", path.display()))
        })?;
    file.write_all(bytes).and_then(|()| file.sync_all()).map_err(|source| {
        (1, format!("cannot sync native artifact {}: {source}", path.display()))
    })?;
    Ok(Stage4ArtifactReference {
        uri: uri.to_owned(),
        sha256: format!("{:x}", Sha256::digest(bytes)),
        size: u64::try_from(bytes.len()).map_err(|_| (1, "artifact size overflow".to_owned()))?,
    })
}

fn checked_artifact_path(root: &Path, uri: &str) -> CommandResult<PathBuf> {
    let path = Path::new(uri);
    if uri.is_empty()
        || path.is_absolute()
        || path.components().any(|component| !matches!(component, Component::Normal(_)))
    {
        return command_error(1, format!("unsafe native artifact URI {uri:?}"));
    }
    Ok(root.join(path))
}

fn remove_runner_work(cell_root: &Path) -> CommandResult<()> {
    let path = cell_root.join(".runner-work");
    let metadata = fs::symlink_metadata(&path).map_err(|source| {
        (1, format!("cannot inspect native runner work {}: {source}", path.display()))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return command_error(1, format!("refusing unsafe native runner work {}", path.display()));
    }
    fs::remove_dir_all(&path)
        .map_err(|source| (1, format!("cannot remove native runner work: {source}")))
}

fn validate_remote_host(remote_host: &OsStr) -> CommandResult<()> {
    let text =
        remote_host.to_str().ok_or_else(|| (64, "remote host must be valid UTF-8".to_owned()))?;
    if text.is_empty()
        || text.starts_with('-')
        || text.chars().any(|character| {
            !character.is_ascii_alphanumeric() && !matches!(character, '@' | '.' | ':' | '_' | '-')
        })
    {
        return command_error(64, "remote host contains unsupported characters");
    }
    Ok(())
}

fn validate_ssh_identity_file(path: &Path) -> CommandResult<PathBuf> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| (64, format!("cannot inspect SSH identity file: {source}")))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
    {
        return command_error(
            64,
            "SSH identity must be a single-link regular file inaccessible to group and other users",
        );
    }
    path.canonicalize()
        .map_err(|source| (64, format!("cannot resolve SSH identity file: {source}")))
}

fn validate_remote_worker(path: &Path) -> CommandResult<()> {
    if !path.is_absolute()
        || path.components().any(|component| match component {
            Component::RootDir => false,
            Component::Normal(value) => value.to_str().is_none_or(|value| {
                value.is_empty()
                    || value.chars().any(|character| {
                        !character.is_ascii_alphanumeric() && !matches!(character, '.' | '_' | '-')
                    })
            }),
            _ => true,
        })
    {
        return command_error(64, "remote worker path is not an absolute shell-safe path");
    }
    Ok(())
}

fn os_strings_text(values: &[OsString], label: &str) -> CommandResult<Vec<String>> {
    values
        .iter()
        .map(|value| {
            value
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| (64, format!("{label} contains non-UTF-8 data")))
        })
        .collect()
}

fn path_text(path: &Path, label: &str) -> CommandResult<String> {
    path.to_str().map(str::to_owned).ok_or_else(|| (64, format!("{label} path is not UTF-8")))
}

fn command_error<T>(code: u8, detail: impl Into<String>) -> CommandResult<T> {
    Err((code, detail.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_endpoint_inputs_are_shell_safe() {
        assert!(validate_remote_host(OsStr::new("pi@10.12.194.1")).is_ok());
        assert!(validate_remote_host(OsStr::new("-oProxyCommand=bad")).is_err());
        assert!(validate_remote_worker(Path::new("/opt/visa/visa-system")).is_ok());
        assert!(validate_remote_worker(Path::new("/tmp/visa system")).is_err());
        assert!(validate_remote_worker(Path::new("relative/visa-system")).is_err());
    }

    #[test]
    fn host_observation_requires_physical_aarch64_model() {
        let mut observation = Stage4NativeRawHostObservation {
            schema_version: STAGE4_NATIVE_HOST_OBSERVATION_SCHEMA_VERSION.to_owned(),
            nonce: "0".repeat(64),
            host_id: Stage4NativeHostId::HaHost,
            identity: Stage4HostIdentity {
                sysname: "Linux".to_owned(),
                kernel_release: "6.18.0".to_owned(),
                machine: "aarch64".to_owned(),
            },
            uname_program_sha256: "1".repeat(64),
            uname_program_size: 1,
            uname_argv: [UNAME_PATH, "-s", "-r", "-m"].map(str::to_owned).to_vec(),
            uname_exit_status: 0,
            uname_stdout: "Linux 6.18.0 aarch64\n".to_owned(),
            uname_stderr: String::new(),
            virtualization_program_sha256: "2".repeat(64),
            virtualization_program_size: 1,
            virtualization_argv: vec![VIRTUALIZATION_PATH.to_owned()],
            virtualization_exit_status: 1,
            virtualization_stdout: "none\n".to_owned(),
            virtualization_stderr: String::new(),
            hardware_model_source_path: Some(HARDWARE_MODEL_PATH.to_owned()),
            hardware_model: Some("Raspberry Pi Zero 2 W Rev 1.0".to_owned()),
        };
        assert!(validate_raw_host_observation(&observation).is_ok());
        observation.hardware_model = None;
        assert!(validate_raw_host_observation(&observation).is_err());
    }
}
