use std::{
    collections::BTreeMap,
    env,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

use serde::Serialize;
use sha2::{Digest as _, Sha256};
use visa_conformance::{
    STAGE4_BUILD_RECEIPT_SCHEMA_VERSION, STAGE4_CELL_CATALOG, STAGE4_HOST_RECEIPT_SCHEMA_VERSION,
    STAGE4_HOST_UNAME_STDERR_FILE, STAGE4_HOST_UNAME_STDOUT_FILE,
    STAGE4_LAUNCHER_RECEIPT_SCHEMA_VERSION, STAGE4_SYSROOT_MANIFEST_SCHEMA_VERSION,
    STAGE4_SYSROOT_RECEIPT_SCHEMA_VERSION, STAGE4_TARGET_HELLO_SCHEMA_VERSION,
    STAGE4_WORKER_PROTOCOL_VERSION, Stage4ArtifactReference, Stage4BuildReceipt, Stage4CellId,
    Stage4EndpointEvidence, Stage4EndpointId, Stage4ExecutionBoundary, Stage4HostIdentity,
    Stage4HostReceipt, Stage4LauncherReceipt, Stage4PublicationCell,
    Stage4PublicationCellDisposition, Stage4PublicationInput, Stage4QemuReceipt, Stage4Role,
    Stage4SysrootManifest, Stage4SysrootManifestEntry, Stage4SysrootReceipt, Stage4TargetHello,
    Stage4TargetHelloObservation, Stage4TargetIdentity, begin_stage4_evidence_publication,
    write_stage4_evidence_artifacts,
};
use visa_system::{
    build_info,
    runner::{RoleLaunchers, TargetHelloObservation, WorkerLauncher},
    target::{TargetEndianness, TargetHelloV1, observe_target},
};

use super::{current_executable, run_evidence_cell_with_launchers, usable_artifact_root};

const STATUS_FILE: &str = "stage4-status.json";
const STATUS_SCHEMA: &str = "visa-stage4-run-status-v1";
const X86_WORKER_ENV: &str = "VISA_STAGE4_X86_64_WORKER";
const AARCH64_WORKER_ENV: &str = "VISA_STAGE4_AARCH64_WORKER";
const QEMU_X86_ENV: &str = "VISA_STAGE4_QEMU_X86_64";
const QEMU_AARCH64_ENV: &str = "VISA_STAGE4_QEMU_AARCH64";
const QX_SYSROOT_ENV: &str = "VISA_STAGE4_QX_SYSROOT";
const QA_SYSROOT_ENV: &str = "VISA_STAGE4_QA_SYSROOT";
const MAX_QEMU_VERSION_BYTES: usize = 1024 * 1024;
const UNAME_PATH: &str = "/usr/bin/uname";
const UNAME_ARGS: &[&str] = &["-s", "-r", "-m"];

type CommandResult<T> = Result<T, (u8, String)>;

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Stage4RunStatus<'a> {
    schema_version: &'static str,
    status: &'a str,
    phase: &'a str,
    completed_cells: usize,
    required_cells: usize,
    error: Option<&'a str>,
}

struct Stage4Inputs {
    x86_worker: PathBuf,
    aarch64_worker: PathBuf,
    qemu_x86: PathBuf,
    qemu_aarch64: PathBuf,
    qx_sysroot: PathBuf,
    qa_sysroot: PathBuf,
}

struct PreparedEndpoint {
    launcher: WorkerLauncher,
    worker_path: PathBuf,
    evidence: Stage4EndpointEvidence,
    owned_executables: Vec<OwnedExecutable>,
    sysroot_dependencies: Vec<SysrootDependency>,
}

#[derive(Clone)]
struct OwnedExecutable {
    path: PathBuf,
    sha256: String,
    size: u64,
}

struct QemuVersionEvidence {
    version: String,
    stdout: Stage4ArtifactReference,
    stderr: Stage4ArtifactReference,
}

struct PreparedQemu {
    executable: OwnedExecutable,
    emulator_name: &'static str,
    version: QemuVersionEvidence,
}

struct LoaderResolutionEvidence {
    manifest: Stage4SysrootManifest,
    stdout: Stage4ArtifactReference,
    stderr: Stage4ArtifactReference,
    dependencies: Vec<SysrootDependency>,
}

struct SysrootDependency {
    sysroot: PathBuf,
    guest_name: String,
    resolved_path: PathBuf,
    sha256: String,
    size: u64,
}

pub(super) fn run_stage4_command(requested_root: &Path) -> CommandResult<ExitCode> {
    let root = initialize_stage4_root(requested_root)?;
    write_status(&root, "running", "input-qualification", 0, None)?;

    match execute_stage4(&root) {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err((code, detail)) => {
            let status_detail = format!("Stage 4 failed: {detail}");
            if let Err((_, status_error)) =
                write_status(&root, "failed", "failed", completed_cell_count(&root), Some(&detail))
            {
                return Err((
                    code,
                    format!(
                        "{status_detail}; additionally could not retain failure status: {status_error}"
                    ),
                ));
            }
            Err((code, status_detail))
        }
    }
}

fn execute_stage4(root: &Path) -> CommandResult<()> {
    reject_ambient_execution_environment()?;
    let inputs = Stage4Inputs::from_environment()?;
    let current_exe = current_executable()?;
    let current_identity = regular_file_identity(&current_exe, "current visa-system executable")?;
    let supplied_x86 = regular_file_identity(&inputs.x86_worker, X86_WORKER_ENV)?;
    if current_identity.sha256 != supplied_x86.sha256 || current_identity.size != supplied_x86.size
    {
        return command_error(
            64,
            format!(
                "{X86_WORKER_ENV} does not identify the currently executing x86-64 visa-system bytes"
            ),
        );
    }

    let orchestrator_hello = observe_target(&"0".repeat(64)).map_err(|source| {
        (1, format!("cannot observe the independent Stage 4 orchestrator target: {source}"))
    })?;
    let orchestrator = target_identity(&orchestrator_hello);
    require_named_target(Stage4EndpointId::Hx, &orchestrator)?;
    let orchestrator_host = retain_orchestrator_host(root)?;

    let hx =
        prepare_endpoint(root, Stage4EndpointId::Hx, &inputs.x86_worker, None, Path::new("/"))?;
    let qx = prepare_endpoint(
        root,
        Stage4EndpointId::Qx,
        &inputs.x86_worker,
        Some((&inputs.qemu_x86, "qemu-x86_64")),
        &inputs.qx_sysroot,
    )?;
    let qa = prepare_endpoint(
        root,
        Stage4EndpointId::Qa,
        &inputs.aarch64_worker,
        Some((&inputs.qemu_aarch64, "qemu-aarch64")),
        &inputs.qa_sysroot,
    )?;

    if hx.evidence.target != orchestrator {
        return command_error(
            1,
            "native Hx target identity differs from the independently observed orchestrator",
        );
    }
    if hx.evidence.worker_executable.sha256 != qx.evidence.worker_executable.sha256
        || hx.evidence.worker_executable.size != qx.evidence.worker_executable.size
    {
        return command_error(1, "Hx and Qx did not retain identical x86-64 worker bytes");
    }
    let build_source = &hx.evidence.build_receipt.build_source_sha256;
    let build_toolchain = &hx.evidence.build_receipt.build_toolchain_sha256;
    for endpoint in [&hx, &qx, &qa] {
        if endpoint.evidence.build_receipt.build_source_sha256 != *build_source
            || endpoint.evidence.build_receipt.build_toolchain_sha256 != *build_toolchain
        {
            return command_error(
                1,
                "Stage 4 endpoint workers do not share one build source and toolchain identity",
            );
        }
    }
    if build_source != build_info::SOURCE_SHA256 || build_toolchain != build_info::TOOLCHAIN_SHA256
    {
        return command_error(
            1,
            "Stage 4 endpoint build lineage differs from the orchestrator and inner Stage 1 source lineage",
        );
    }

    let endpoints = BTreeMap::from([
        (Stage4EndpointId::Hx, hx),
        (Stage4EndpointId::Qx, qx),
        (Stage4EndpointId::Qa, qa),
    ]);
    let mut publication_cells = Vec::with_capacity(STAGE4_CELL_CATALOG.len());
    for (index, cell_id) in STAGE4_CELL_CATALOG.iter().copied().enumerate() {
        write_status(root, "running", cell_id.as_str(), index, None)?;
        publication_cells.push(run_cell(root, cell_id, &endpoints)?);
    }

    for endpoint in endpoints.values() {
        for executable in &endpoint.owned_executables {
            executable.verify_unchanged()?;
        }
        for dependency in &endpoint.sysroot_dependencies {
            dependency.verify_unchanged()?;
        }
    }

    let input = Stage4PublicationInput {
        orchestrator,
        orchestrator_host,
        endpoints: [Stage4EndpointId::Hx, Stage4EndpointId::Qx, Stage4EndpointId::Qa]
            .into_iter()
            .map(|id| endpoints[&id].evidence.clone())
            .collect(),
        cells: publication_cells,
    };
    remove_status(root)?;
    let result = write_stage4_evidence_artifacts(root, &input)
        .map_err(|source| (1, format!("Stage 4 evidence publication failed: {source}")))?;

    println!("Stage 4 evidence bundle: {}", result.bundle_path);
    println!("Stage 4 matrix manifest: {}", result.matrix_path);
    println!("Stage 4 artifact root: {}", root.display());
    println!("Stage 4 cases: 217/217 (31 cases x 7 cells)");
    Ok(())
}

fn run_cell(
    root: &Path,
    cell_id: Stage4CellId,
    endpoints: &BTreeMap<Stage4EndpointId, PreparedEndpoint>,
) -> CommandResult<Stage4PublicationCell> {
    let (source_id, destination_id) = cell_id.endpoints();
    let source = endpoints
        .get(&source_id)
        .ok_or_else(|| (1, format!("missing source endpoint {}", source_id.as_str())))?;
    let destination = endpoints
        .get(&destination_id)
        .ok_or_else(|| (1, format!("missing destination endpoint {}", destination_id.as_str())))?;
    let cell_root = root.join(cell_id.cell_root_uri());
    fs::create_dir_all(&cell_root).map_err(|source| {
        (1, format!("cannot create Stage 4 cell root {}: {source}", cell_root.display()))
    })?;
    let output = run_evidence_cell_with_launchers(
        &cell_root,
        &source.worker_path,
        RoleLaunchers::new(source.launcher.clone(), destination.launcher.clone()),
    )?;
    remove_runner_work(&cell_root)?;
    validate_endpoint_hello(
        source_id,
        &output.source_target.hello,
        &source.evidence.worker_executable,
    )?;
    validate_endpoint_hello(
        destination_id,
        &output.destination_target.hello,
        &destination.evidence.worker_executable,
    )?;

    let source_hello = retain_hello(root, cell_id, Stage4Role::Source, &output.source_target)?;
    let destination_hello =
        retain_hello(root, cell_id, Stage4Role::Destination, &output.destination_target)?;
    let stage1_bundle = artifact_reference(root, &cell_id.stage1_bundle_uri())?;

    Ok(Stage4PublicationCell {
        cell_id,
        source_endpoint: source_id,
        destination_endpoint: destination_id,
        disposition: Stage4PublicationCellDisposition::Passed {
            stage1_bundle,
            source_hello,
            destination_hello,
        },
    })
}

fn prepare_endpoint(
    root: &Path,
    id: Stage4EndpointId,
    worker_input: &Path,
    qemu_input: Option<(&Path, &str)>,
    sysroot_input: &Path,
) -> CommandResult<PreparedEndpoint> {
    let sysroot = canonical_directory(sysroot_input, &format!("{} sysroot", id.as_str()))?;
    let worker_uri = id.worker_uri();
    let worker = copy_owned_executable(root, worker_input, &worker_uri, "target worker")?;
    require_elf_machine(&worker.path, id)?;
    let worker_reference = worker.reference(worker_uri);

    let prepared_qemu = match qemu_input {
        None => None,
        Some((qemu_input, emulator_name)) => {
            require_input_basename(qemu_input, emulator_name)?;
            let executable =
                copy_owned_executable(root, qemu_input, &id.qemu_uri(), emulator_name)?;
            let version = retain_qemu_version(root, id, emulator_name, &executable.path)?;
            Some(PreparedQemu {
                executable,
                emulator_name: match id {
                    Stage4EndpointId::Qx => "qemu-x86_64",
                    Stage4EndpointId::Qa => "qemu-aarch64",
                    Stage4EndpointId::Hx => {
                        return command_error(1, "Hx cannot have a QEMU launcher");
                    }
                },
                version,
            })
        }
    };
    let loader_resolution = retain_loader_resolution(
        root,
        id,
        &worker.path,
        &sysroot,
        prepared_qemu.as_ref().map(|qemu| &qemu.executable),
    )?;
    let sysroot_manifest_artifact =
        publish_json(root, &id.sysroot_manifest_uri(), &loader_resolution.manifest)?;
    let sysroot_receipt = Stage4SysrootReceipt {
        schema_version: STAGE4_SYSROOT_RECEIPT_SCHEMA_VERSION.to_owned(),
        endpoint_id: id,
        identity: path_text(&sysroot, "sysroot")?,
        manifest: sysroot_manifest_artifact,
        loader_resolution_stdout: loader_resolution.stdout,
        loader_resolution_stderr: loader_resolution.stderr,
    };
    let sysroot_receipt_artifact = publish_json(root, &id.sysroot_receipt_uri(), &sysroot_receipt)?;
    let sysroot_dependencies = loader_resolution.dependencies;

    let (launcher, qemu_receipt, program_identity, argv, mut owned_executables) =
        match prepared_qemu {
            None => {
                let launcher = WorkerLauncher::direct(&worker.path);
                let argv = vec![path_text(&worker.path, "owned Hx worker")?];
                (launcher, None, worker.clone(), argv, vec![worker.clone()])
            }
            Some(qemu) => {
                let prefix = emulated_launcher_prefix(&sysroot, &worker.path);
                let launcher = WorkerLauncher::new(&qemu.executable.path, prefix.clone());
                let prefix_text = os_strings_text(&prefix, "QEMU argv prefix")?;
                let mut argv = vec![path_text(&qemu.executable.path, "owned QEMU")?];
                argv.extend(prefix_text.clone());
                let receipt = Stage4QemuReceipt {
                    adapter_family: "qemu-user".to_owned(),
                    emulator_name: qemu.emulator_name.to_owned(),
                    emulator_version: qemu.version.version,
                    executable: qemu.executable.reference(id.qemu_uri()),
                    version_stdout: qemu.version.stdout,
                    version_stderr: qemu.version.stderr,
                    argv_prefix: prefix_text,
                };
                (
                    launcher,
                    Some(receipt),
                    qemu.executable.clone(),
                    argv,
                    vec![worker.clone(), qemu.executable],
                )
            }
        };

    let preflight = launcher
        .probe_target()
        .map_err(|source| (1, format!("{} target preflight failed: {source}", id.as_str())))?;
    validate_endpoint_hello(id, &preflight.hello, &worker_reference)?;
    if !preflight.stderr.is_empty() || preflight.exit_code != 0 {
        return command_error(
            1,
            format!("{} target preflight produced stderr or a nonzero exit", id.as_str()),
        );
    }
    let target = target_identity(&preflight.hello);
    let build_receipt = Stage4BuildReceipt {
        schema_version: STAGE4_BUILD_RECEIPT_SCHEMA_VERSION.to_owned(),
        endpoint_id: id,
        target: target.clone(),
        executable_sha256: worker.sha256.clone(),
        executable_size: worker.size,
        build_source_sha256: preflight.hello.build_source_sha256.clone(),
        build_toolchain_sha256: preflight.hello.build_toolchain_sha256.clone(),
    };
    let build_receipt_artifact = publish_json(root, &id.build_receipt_uri(), &build_receipt)?;
    let launcher_receipt = launcher_receipt(
        id,
        &program_identity,
        argv,
        qemu_receipt,
        sysroot_receipt_artifact.clone(),
    );
    let launcher_receipt_artifact =
        publish_json(root, &id.launcher_receipt_uri(), &launcher_receipt)?;
    owned_executables.sort_by(|left, right| left.path.cmp(&right.path));

    Ok(PreparedEndpoint {
        launcher,
        worker_path: worker.path,
        evidence: Stage4EndpointEvidence {
            endpoint_id: id,
            target,
            worker_executable: worker_reference,
            build_receipt_artifact,
            build_receipt,
            launcher_receipt_artifact,
            launcher_receipt,
            sysroot_receipt_artifact,
            sysroot_receipt,
        },
        owned_executables,
        sysroot_dependencies,
    })
}

fn emulated_launcher_prefix(sysroot: &Path, worker: &Path) -> Vec<OsString> {
    vec![
        OsString::from("-cpu"),
        OsString::from("max"),
        OsString::from("-L"),
        sysroot.as_os_str().to_owned(),
        worker.as_os_str().to_owned(),
    ]
}

fn launcher_receipt(
    id: Stage4EndpointId,
    program: &OwnedExecutable,
    argv: Vec<String>,
    qemu: Option<Stage4QemuReceipt>,
    sysroot: Stage4ArtifactReference,
) -> Stage4LauncherReceipt {
    Stage4LauncherReceipt {
        schema_version: STAGE4_LAUNCHER_RECEIPT_SCHEMA_VERSION.to_owned(),
        endpoint_id: id,
        execution_mode: id.required_execution_mode(),
        boundary: Stage4ExecutionBoundary::for_mode(id.required_execution_mode()),
        program_sha256: program.sha256.clone(),
        program_size: program.size,
        argv,
        qemu,
        sysroot,
        native_fallback_allowed: false,
        observed_native_fallback: false,
    }
}

impl Stage4Inputs {
    fn from_environment() -> CommandResult<Self> {
        Ok(Self {
            x86_worker: required_file_env(X86_WORKER_ENV)?,
            aarch64_worker: required_file_env(AARCH64_WORKER_ENV)?,
            qemu_x86: required_file_env(QEMU_X86_ENV)?,
            qemu_aarch64: required_file_env(QEMU_AARCH64_ENV)?,
            qx_sysroot: required_directory_env(QX_SYSROOT_ENV)?,
            qa_sysroot: required_directory_env(QA_SYSROOT_ENV)?,
        })
    }
}

fn reject_ambient_execution_environment() -> CommandResult<()> {
    const FORBIDDEN: &[&str] = &[
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "LD_DEBUG",
        "LD_DEBUG_OUTPUT",
        "LD_PROFILE",
        "LD_PROFILE_OUTPUT",
        "LD_BIND_NOW",
        "LD_ASSUME_KERNEL",
        "GLIBC_TUNABLES",
        "QEMU_LD_PREFIX",
        "QEMU_CPU",
        "QEMU_SET_ENV",
        "QEMU_UNSET_ENV",
        "QEMU_GUEST_BASE",
        "QEMU_RESERVED_VA",
        "QEMU_STACK_SIZE",
        "QEMU_LOG",
        "QEMU_LOG_FILENAME",
        "QEMU_STRACE",
        "QEMU_PLUGIN",
    ];
    let present = FORBIDDEN
        .iter()
        .copied()
        .filter(|name| env::var_os(name).is_some_and(|value| !value.is_empty()))
        .collect::<Vec<_>>();
    if !present.is_empty() {
        return command_error(
            64,
            format!("Stage 4 refuses ambient loader or emulator controls: {}", present.join(", ")),
        );
    }
    Ok(())
}

impl OwnedExecutable {
    fn reference(&self, uri: String) -> Stage4ArtifactReference {
        Stage4ArtifactReference { uri, sha256: self.sha256.clone(), size: self.size }
    }

    fn verify_unchanged(&self) -> CommandResult<()> {
        let observed = single_link_file_identity(&self.path, "owned Stage 4 executable")?;
        if observed.sha256 != self.sha256 || observed.size != self.size {
            return command_error(
                1,
                format!(
                    "owned Stage 4 executable changed during execution: {}",
                    self.path.display()
                ),
            );
        }
        require_owned_executable_mode(&self.path)?;
        Ok(())
    }
}

impl SysrootDependency {
    fn verify_unchanged(&self) -> CommandResult<()> {
        let resolved =
            resolve_sysroot_path(&self.sysroot, &self.guest_name, "retained sysroot dependency")?;
        if resolved != self.resolved_path {
            return command_error(
                1,
                format!(
                    "sysroot dependency {} was retargeted during Stage 4 execution",
                    self.guest_name
                ),
            );
        }
        let observed = regular_file_identity(&resolved, "retained sysroot dependency")?;
        if observed.sha256 != self.sha256 || observed.size != self.size {
            return command_error(
                1,
                format!("sysroot dependency {} changed during Stage 4 execution", self.guest_name),
            );
        }
        Ok(())
    }
}

fn initialize_stage4_root(requested: &Path) -> CommandResult<PathBuf> {
    let metadata = fs::symlink_metadata(requested).map_err(|source| {
        (2, format!("cannot inspect Stage 4 artifact root {}: {source}", requested.display()))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return command_error(
            2,
            format!(
                "Stage 4 artifact root must be a non-symlink directory: {}",
                requested.display()
            ),
        );
    }
    let root = usable_artifact_root(requested)?;
    let mut entries = fs::read_dir(&root).map_err(|source| {
        (2, format!("cannot read Stage 4 artifact root {}: {source}", root.display()))
    })?;
    if entries
        .next()
        .transpose()
        .map_err(|source| {
            (2, format!("cannot inspect Stage 4 artifact root {}: {source}", root.display()))
        })?
        .is_some()
    {
        return command_error(
            2,
            format!("Stage 4 artifact root must be empty: {}", root.display()),
        );
    }
    begin_stage4_evidence_publication(&root)
        .map_err(|source| (1, format!("cannot begin Stage 4 publication: {source}")))?;
    Ok(root)
}

fn write_status(
    root: &Path,
    status: &str,
    phase: &str,
    completed_cells: usize,
    error: Option<&str>,
) -> CommandResult<()> {
    let value = Stage4RunStatus {
        schema_version: STATUS_SCHEMA,
        status,
        phase,
        completed_cells,
        required_cells: STAGE4_CELL_CATALOG.len(),
        error,
    };
    let bytes = serde_json::to_vec_pretty(&value)
        .map_err(|source| (1, format!("cannot encode Stage 4 run status: {source}")))?;
    let path = root.join(STATUS_FILE);
    if fs::symlink_metadata(&path)
        .is_ok_and(|metadata| metadata.file_type().is_symlink() || !metadata.is_file())
    {
        return command_error(1, format!("unsafe Stage 4 status path: {}", path.display()));
    }
    let mut file = OpenOptions::new().create(true).truncate(true).write(true).open(&path).map_err(
        |source| (1, format!("cannot write Stage 4 status {}: {source}", path.display())),
    )?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| (1, format!("cannot sync Stage 4 status {}: {source}", path.display())))
}

fn remove_status(root: &Path) -> CommandResult<()> {
    let path = root.join(STATUS_FILE);
    let metadata = fs::symlink_metadata(&path).map_err(|source| {
        (1, format!("cannot inspect Stage 4 status {}: {source}", path.display()))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return command_error(1, format!("unsafe Stage 4 status path: {}", path.display()));
    }
    fs::remove_file(&path)
        .map_err(|source| (1, format!("cannot remove Stage 4 status {}: {source}", path.display())))
}

fn completed_cell_count(root: &Path) -> usize {
    STAGE4_CELL_CATALOG.iter().filter(|cell| root.join(cell.stage1_bundle_uri()).is_file()).count()
}

fn required_file_env(name: &str) -> CommandResult<PathBuf> {
    let path = required_env_path(name)?;
    regular_file_identity(&path, name)?;
    path.canonicalize()
        .map_err(|source| (64, format!("cannot resolve {name} {}: {source}", path.display())))
}

fn required_directory_env(name: &str) -> CommandResult<PathBuf> {
    let path = required_env_path(name)?;
    canonical_directory(&path, name)
}

fn required_env_path(name: &str) -> CommandResult<PathBuf> {
    let value = env::var_os(name)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| (64, format!("stage4 requires {name}")))?;
    Ok(PathBuf::from(value))
}

fn canonical_directory(path: &Path, label: &str) -> CommandResult<PathBuf> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| (64, format!("cannot inspect {label} {}: {source}", path.display())))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return command_error(
            64,
            format!("{label} must be a non-symlink directory: {}", path.display()),
        );
    }
    path.canonicalize()
        .map_err(|source| (64, format!("cannot resolve {label} {}: {source}", path.display())))
}

fn regular_file_identity(path: &Path, label: &str) -> CommandResult<OwnedExecutable> {
    // Cargo may hard-link its top-level executable to target/*/deps. Ambient inputs are
    // therefore accepted as regular, non-symlink files and stabilized by a before/copy/after
    // identity check. They are never used as target workers or QEMU carriers after acquisition.
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|source| (64, format!("cannot inspect {label} {}: {source}", path.display())))?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_file()
        || path_metadata.len() == 0
    {
        return command_error(
            64,
            format!("{label} must be a nonempty regular non-symlink file: {}", path.display()),
        );
    }
    let mut file = File::open(path)
        .map_err(|source| (64, format!("cannot open {label} {}: {source}", path.display())))?;
    let before = file.metadata().map_err(|source| {
        (64, format!("cannot inspect opened {label} {}: {source}", path.display()))
    })?;
    if path_metadata.dev() != before.dev()
        || path_metadata.ino() != before.ino()
        || path_metadata.len() != before.len()
        || path_metadata.nlink() != before.nlink()
    {
        return command_error(
            64,
            format!("{label} path changed while it was opened: {}", path.display()),
        );
    }
    let mut digest = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| (64, format!("cannot hash {label} {}: {source}", path.display())))?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(u64::try_from(read).unwrap_or(u64::MAX))
            .ok_or_else(|| (64, format!("{label} size overflow")))?;
        digest.update(&buffer[..read]);
    }
    let after = file.metadata().map_err(|source| {
        (64, format!("cannot reinspect opened {label} {}: {source}", path.display()))
    })?;
    let final_path = fs::symlink_metadata(path).map_err(|source| {
        (64, format!("cannot reinspect {label} path {}: {source}", path.display()))
    })?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.len() != size
        || before.nlink() != after.nlink()
        || final_path.file_type().is_symlink()
        || !final_path.is_file()
        || after.dev() != final_path.dev()
        || after.ino() != final_path.ino()
        || after.len() != final_path.len()
        || after.nlink() != final_path.nlink()
    {
        return command_error(64, format!("{label} changed while hashing: {}", path.display()));
    }
    Ok(OwnedExecutable {
        path: path.to_path_buf(),
        sha256: format!("{:x}", digest.finalize()),
        size,
    })
}

fn single_link_file_identity(path: &Path, label: &str) -> CommandResult<OwnedExecutable> {
    let identity = regular_file_identity(path, label)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| (64, format!("cannot inspect {label} {}: {source}", path.display())))?;
    if metadata.nlink() != 1 {
        return command_error(
            64,
            format!("{label} must have exactly one link: {}", path.display()),
        );
    }
    Ok(identity)
}

fn require_owned_executable_mode(path: &Path) -> CommandResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|source| {
        (64, format!("cannot inspect owned executable {}: {source}", path.display()))
    })?;
    if metadata.permissions().mode() & 0o777 != 0o555 {
        return command_error(
            64,
            format!("owned executable mode changed from 0555: {}", path.display()),
        );
    }
    Ok(())
}

fn copy_owned_executable(
    root: &Path,
    source: &Path,
    uri: &str,
    label: &str,
) -> CommandResult<OwnedExecutable> {
    // The execution trust boundary starts at this owned copy: every target hello, worker
    // session, loader probe, and QEMU invocation uses these nlink=1, mode-0555 bytes.
    let before = regular_file_identity(source, label)?;
    let destination = root.join(uri);
    let parent = destination
        .parent()
        .ok_or_else(|| (1, format!("owned executable URI has no parent: {uri}")))?;
    fs::create_dir_all(parent).map_err(|source| {
        (1, format!("cannot create owned executable directory {}: {source}", parent.display()))
    })?;
    if fs::symlink_metadata(&destination).is_ok() {
        return command_error(
            1,
            format!("owned executable already exists: {}", destination.display()),
        );
    }
    fs::copy(source, &destination).map_err(|source| {
        (1, format!("cannot copy {label} to {}: {source}", destination.display()))
    })?;
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o555)).map_err(|source| {
        (1, format!("cannot lock owned executable {}: {source}", destination.display()))
    })?;
    File::open(&destination).and_then(|file| file.sync_all()).map_err(|source| {
        (1, format!("cannot sync owned executable {}: {source}", destination.display()))
    })?;
    let copied = single_link_file_identity(&destination, "owned Stage 4 executable")?;
    require_owned_executable_mode(&destination)?;
    let after = regular_file_identity(source, label)?;
    if copied.sha256 != before.sha256
        || copied.size != before.size
        || after.sha256 != before.sha256
        || after.size != before.size
    {
        return command_error(1, format!("{label} changed while acquiring owned bytes"));
    }
    Ok(copied)
}

fn require_elf_machine(path: &Path, endpoint: Stage4EndpointId) -> CommandResult<()> {
    let mut header = [0_u8; 20];
    File::open(path)
        .and_then(|mut file| file.read_exact(&mut header))
        .map_err(|source| (64, format!("cannot read ELF header {}: {source}", path.display())))?;
    let expected = match endpoint {
        Stage4EndpointId::Hx | Stage4EndpointId::Qx => 62_u16,
        Stage4EndpointId::Qa => 183_u16,
    };
    let observed = header
        .starts_with(b"\x7fELF")
        .then_some(())
        .filter(|()| header[4] == 2 && header[5] == 1)
        .map(|()| u16::from_le_bytes([header[18], header[19]]));
    if observed != Some(expected) {
        return command_error(
            64,
            format!(
                "{} worker is not the required ELF64 little-endian machine {expected}: {}",
                endpoint.as_str(),
                path.display()
            ),
        );
    }
    Ok(())
}

fn retain_loader_resolution(
    root: &Path,
    endpoint: Stage4EndpointId,
    worker: &Path,
    sysroot: &Path,
    qemu: Option<&OwnedExecutable>,
) -> CommandResult<LoaderResolutionEvidence> {
    let interpreter = read_elf_interpreter(worker)?;
    let loader = resolve_sysroot_path(sysroot, &interpreter, "ELF interpreter")?;
    let mut command = match qemu {
        Some(qemu) => {
            let mut command = Command::new(&qemu.path);
            command.arg("-cpu").arg("max").arg("-L").arg(sysroot).arg(&loader);
            command
        }
        None => Command::new(&loader),
    };
    let output = command.arg("--list").arg(worker).output().map_err(|source| {
        (
            64,
            format!(
                "cannot execute {} target loader dependency resolution: {source}",
                endpoint.as_str()
            ),
        )
    })?;
    if output.status.code() != Some(0) {
        return command_error(
            64,
            format!(
                "{} target loader dependency resolution failed with {:?}",
                endpoint.as_str(),
                output.status.code()
            ),
        );
    }
    if output.stdout.len() > MAX_QEMU_VERSION_BYTES || output.stderr.len() > MAX_QEMU_VERSION_BYTES
    {
        return command_error(
            64,
            format!("{} target loader dependency output is too large", endpoint.as_str()),
        );
    }
    if !output.stderr.is_empty() {
        return command_error(
            64,
            format!("{} target loader dependency resolution wrote stderr", endpoint.as_str()),
        );
    }
    let stdout_text = std::str::from_utf8(&output.stdout).map_err(|source| {
        (64, format!("{} target loader output is not UTF-8: {source}", endpoint.as_str()))
    })?;
    let (manifest, dependencies) = loader_manifest_from_output(endpoint, sysroot, stdout_text)?;
    let stdout = publish_bytes(root, &endpoint.loader_resolution_stdout_uri(), &output.stdout)?;
    let stderr = publish_bytes(root, &endpoint.loader_resolution_stderr_uri(), &output.stderr)?;
    Ok(LoaderResolutionEvidence { manifest, stdout, stderr, dependencies })
}

fn loader_manifest_from_output(
    endpoint: Stage4EndpointId,
    sysroot: &Path,
    stdout: &str,
) -> CommandResult<(Stage4SysrootManifest, Vec<SysrootDependency>)> {
    let mut libraries = BTreeMap::<String, SysrootDependency>::new();
    for line in stdout.lines() {
        let Some(observed) = loader_path_from_line(line)? else { continue };
        let (name, resolved) = resolve_loader_observation(sysroot, observed)?;
        let identity = regular_file_identity(&resolved, "resolved target library")?;
        let dependency = SysrootDependency {
            sysroot: sysroot.to_path_buf(),
            guest_name: name.clone(),
            resolved_path: resolved,
            sha256: identity.sha256,
            size: identity.size,
        };
        match libraries.get(&name) {
            Some(existing)
                if existing.sha256 != dependency.sha256 || existing.size != dependency.size =>
            {
                return command_error(
                    64,
                    format!("target loader resolved {name} to conflicting bytes"),
                );
            }
            Some(_) => continue,
            None => {
                libraries.insert(name, dependency);
            }
        }
    }
    let entries = libraries
        .values()
        .map(|dependency| Stage4SysrootManifestEntry {
            name: dependency.guest_name.clone(),
            version: "target-loader-list-v1".to_owned(),
            sha256: dependency.sha256.clone(),
        })
        .collect::<Vec<_>>();
    let has_loader = entries.iter().any(|entry| {
        let name = entry.name.to_ascii_lowercase();
        name.contains("ld-linux") || name.contains("ld.so")
    });
    let has_libc = entries.iter().any(|entry| entry.name.to_ascii_lowercase().contains("libc.so"));
    if entries.len() < 2 || !has_loader || !has_libc {
        return command_error(
            64,
            format!(
                "{} loader resolution did not identify both the target loader and libc",
                endpoint.as_str()
            ),
        );
    }
    if entries.iter().any(|entry| !stdout.contains(&entry.name)) {
        return command_error(
            64,
            format!("{} normalized loader entry is absent from raw output", endpoint.as_str()),
        );
    }
    Ok((
        Stage4SysrootManifest {
            schema_version: STAGE4_SYSROOT_MANIFEST_SCHEMA_VERSION.to_owned(),
            endpoint_id: endpoint,
            entries,
        },
        libraries.into_values().collect(),
    ))
}

fn loader_path_from_line(line: &str) -> CommandResult<Option<&str>> {
    let line = line.trim();
    if line.is_empty() || line.contains("linux-vdso") || line.contains("linux-gate") {
        return Ok(None);
    }
    let candidate = match line.split_once("=>") {
        Some((_, resolution)) => {
            let resolution = resolution.trim();
            if resolution.starts_with("not found") {
                return command_error(
                    64,
                    format!("target loader dependency is unresolved: {line}"),
                );
            }
            resolution.split_whitespace().next().unwrap_or_default()
        }
        None => line.split_whitespace().next().unwrap_or_default(),
    };
    if !candidate.starts_with('/') {
        return command_error(64, format!("cannot parse target loader output line: {line:?}"));
    }
    Ok(Some(candidate))
}

fn resolve_loader_observation(sysroot: &Path, observed: &str) -> CommandResult<(String, PathBuf)> {
    let observed_path = Path::new(observed);
    let name = if sysroot != Path::new("/") && observed_path.starts_with(sysroot) {
        let relative = observed_path
            .strip_prefix(sysroot)
            .map_err(|source| (64, format!("cannot normalize loader path {observed}: {source}")))?;
        format!("/{}", relative.display())
    } else {
        observed.to_owned()
    };
    let resolved = resolve_sysroot_path(sysroot, &name, "loader-resolved library")?;
    Ok((name, resolved))
}

fn resolve_sysroot_path(sysroot: &Path, guest_path: &str, label: &str) -> CommandResult<PathBuf> {
    let relative = guest_path
        .strip_prefix('/')
        .ok_or_else(|| (64, format!("{label} must be an absolute guest path: {guest_path}")))?;
    let candidate = sysroot.join(relative);
    let resolved = candidate
        .canonicalize()
        .map_err(|source| (64, format!("sysroot cannot resolve {label} {guest_path}: {source}")))?;
    if !resolved.starts_with(sysroot) {
        return command_error(64, format!("{label} escapes the locked sysroot: {guest_path}"));
    }
    Ok(resolved)
}

fn read_elf_interpreter(path: &Path) -> CommandResult<String> {
    let bytes = fs::read(path)
        .map_err(|source| (64, format!("cannot read worker ELF {}: {source}", path.display())))?;
    if bytes.len() < 64 || !bytes.starts_with(b"\x7fELF") || bytes[4] != 2 || bytes[5] != 1 {
        return command_error(64, format!("worker is not ELF64 little-endian: {}", path.display()));
    }
    let program_offset = read_u64(&bytes, 32)?;
    let entry_size = usize::from(read_u16(&bytes, 54)?);
    let entry_count = usize::from(read_u16(&bytes, 56)?);
    let program_offset = usize::try_from(program_offset)
        .map_err(|_| (64, "ELF program-header offset does not fit memory".to_owned()))?;
    if entry_size < 56 {
        return command_error(64, "ELF program-header entry is too small");
    }
    for index in 0..entry_count {
        let entry = program_offset
            .checked_add(
                index
                    .checked_mul(entry_size)
                    .ok_or_else(|| (64, "ELF program-header index overflow".to_owned()))?,
            )
            .ok_or_else(|| (64, "ELF program-header offset overflow".to_owned()))?;
        if read_u32(&bytes, entry)? != 3 {
            continue;
        }
        let offset = usize::try_from(read_u64(&bytes, entry + 8)?)
            .map_err(|_| (64, "ELF interpreter offset does not fit memory".to_owned()))?;
        let length = usize::try_from(read_u64(&bytes, entry + 32)?)
            .map_err(|_| (64, "ELF interpreter size does not fit memory".to_owned()))?;
        let end = offset
            .checked_add(length)
            .ok_or_else(|| (64, "ELF interpreter range overflow".to_owned()))?;
        let raw = bytes
            .get(offset..end)
            .ok_or_else(|| (64, "ELF interpreter range is outside the file".to_owned()))?;
        let raw = raw
            .strip_suffix(&[0])
            .ok_or_else(|| (64, "ELF interpreter is not NUL terminated".to_owned()))?;
        let interpreter = std::str::from_utf8(raw)
            .map_err(|source| (64, format!("ELF interpreter is not UTF-8: {source}")))?;
        if interpreter.is_empty() || interpreter.contains('\0') {
            return command_error(64, "ELF interpreter is empty or contains embedded NUL");
        }
        return Ok(interpreter.to_owned());
    }
    command_error(64, format!("worker has no PT_INTERP entry: {}", path.display()))
}

fn read_u16(bytes: &[u8], offset: usize) -> CommandResult<u16> {
    let raw =
        bytes.get(offset..offset + 2).ok_or_else(|| (64, "truncated ELF u16 field".to_owned()))?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> CommandResult<u32> {
    let raw =
        bytes.get(offset..offset + 4).ok_or_else(|| (64, "truncated ELF u32 field".to_owned()))?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> CommandResult<u64> {
    let raw =
        bytes.get(offset..offset + 8).ok_or_else(|| (64, "truncated ELF u64 field".to_owned()))?;
    Ok(u64::from_le_bytes(raw.try_into().expect("eight-byte slice")))
}

fn retain_qemu_version(
    root: &Path,
    id: Stage4EndpointId,
    emulator_name: &str,
    qemu: &Path,
) -> CommandResult<QemuVersionEvidence> {
    let output = Command::new(qemu)
        .arg("--version")
        .output()
        .map_err(|source| (64, format!("cannot run owned {emulator_name} --version: {source}")))?;
    if output.status.code() != Some(0) {
        return command_error(64, format!("owned {emulator_name} --version failed"));
    }
    if output.stdout.len() > MAX_QEMU_VERSION_BYTES || output.stderr.len() > MAX_QEMU_VERSION_BYTES
    {
        return command_error(64, format!("owned {emulator_name} --version output is too large"));
    }
    if !output.stderr.is_empty() {
        return command_error(64, format!("owned {emulator_name} --version wrote stderr"));
    }
    let first_line = std::str::from_utf8(&output.stdout)
        .map_err(|source| (64, format!("owned {emulator_name} version is not UTF-8: {source}")))?
        .lines()
        .next()
        .ok_or_else(|| (64, format!("owned {emulator_name} emitted no version line")))?;
    let version = parse_qemu_version_line(first_line, emulator_name)?;
    let stdout = publish_bytes(root, &id.qemu_version_stdout_uri(), &output.stdout)?;
    let stderr = publish_bytes(root, &id.qemu_version_stderr_uri(), &output.stderr)?;
    Ok(QemuVersionEvidence { version, stdout, stderr })
}

fn retain_orchestrator_host(root: &Path) -> CommandResult<Stage4HostReceipt> {
    let uname = Path::new(UNAME_PATH);
    let before = regular_file_identity(uname, "host uname executable")?;
    let output = Command::new(uname)
        .args(UNAME_ARGS)
        .env_clear()
        .env("LC_ALL", "C")
        .output()
        .map_err(|source| (64, format!("cannot observe Stage 4 host identity: {source}")))?;
    let after = regular_file_identity(uname, "host uname executable")?;
    if before.sha256 != after.sha256 || before.size != after.size {
        return command_error(64, "host uname executable changed during observation");
    }
    if output.status.code() != Some(0) {
        return command_error(64, "host uname observation failed");
    }
    if output.stdout.len() > MAX_QEMU_VERSION_BYTES || output.stderr.len() > MAX_QEMU_VERSION_BYTES
    {
        return command_error(64, "host uname observation output is too large");
    }
    if !output.stderr.is_empty() {
        return command_error(64, "host uname observation wrote stderr");
    }
    let identity = parse_uname_identity(&output.stdout)?;
    if identity.sysname != "Linux" || identity.machine != "x86_64" {
        return command_error(
            64,
            format!(
                "Stage 4 requires a native x86_64 Linux orchestrator host, observed {identity:?}"
            ),
        );
    }
    let raw_stdout = publish_bytes(root, STAGE4_HOST_UNAME_STDOUT_FILE, &output.stdout)?;
    let raw_stderr = publish_bytes(root, STAGE4_HOST_UNAME_STDERR_FILE, &output.stderr)?;
    Ok(Stage4HostReceipt {
        schema_version: STAGE4_HOST_RECEIPT_SCHEMA_VERSION.to_owned(),
        program: UNAME_PATH.to_owned(),
        program_sha256: before.sha256,
        program_size: before.size,
        argv: std::iter::once(UNAME_PATH.to_owned())
            .chain(UNAME_ARGS.iter().map(|argument| (*argument).to_owned()))
            .collect(),
        exit_status: output.status.code().expect("successful uname has an exit code"),
        identity,
        raw_stdout,
        raw_stderr,
    })
}

fn parse_uname_identity(stdout: &[u8]) -> CommandResult<Stage4HostIdentity> {
    let stdout = std::str::from_utf8(stdout)
        .map_err(|source| (64, format!("host uname output is not UTF-8: {source}")))?;
    if !stdout.ends_with('\n') || stdout.lines().count() != 1 {
        return command_error(64, "host uname output must contain one newline-terminated line");
    }
    let fields = stdout.split_whitespace().collect::<Vec<_>>();
    let [sysname, kernel_release, machine] = fields.as_slice() else {
        return command_error(64, "host uname output must contain sysname, release, and machine");
    };
    let identity = Stage4HostIdentity {
        sysname: (*sysname).to_owned(),
        kernel_release: (*kernel_release).to_owned(),
        machine: (*machine).to_owned(),
    };
    if format!("{} {} {}\n", identity.sysname, identity.kernel_release, identity.machine).as_bytes()
        != stdout.as_bytes()
    {
        return command_error(64, "host uname output is not canonical");
    }
    Ok(identity)
}

fn parse_qemu_version_line(line: &str, emulator_name: &str) -> CommandResult<String> {
    if !line.starts_with(emulator_name) {
        return command_error(
            64,
            format!("QEMU version line does not identify {emulator_name}: {line:?}"),
        );
    }
    let (_, suffix) = line
        .split_once(" version ")
        .ok_or_else(|| (64, format!("QEMU version line lacks a version token: {line:?}")))?;
    let version = suffix.split_whitespace().next().unwrap_or_default();
    if version.is_empty() {
        return command_error(64, format!("QEMU version line has an empty version: {line:?}"));
    }
    Ok(version.to_owned())
}

fn validate_endpoint_hello(
    id: Stage4EndpointId,
    hello: &TargetHelloV1,
    worker: &Stage4ArtifactReference,
) -> CommandResult<()> {
    let target = target_identity(hello);
    require_named_target(id, &target)?;
    if hello.schema_version != STAGE4_TARGET_HELLO_SCHEMA_VERSION
        || hello.worker_protocol_version != STAGE4_WORKER_PROTOCOL_VERSION
        || hello.executable_sha256 != worker.sha256
        || hello.executable_size != worker.size
    {
        return command_error(
            1,
            format!(
                "{} target hello disagrees with retained worker bytes or protocol",
                id.as_str()
            ),
        );
    }
    Ok(())
}

fn require_named_target(id: Stage4EndpointId, target: &Stage4TargetIdentity) -> CommandResult<()> {
    if target.target_triple != id.target_triple()
        || target.architecture != id.architecture()
        || target.os != "linux"
        || target.abi != "linux-gnu"
        || target.endianness != "little"
        || target.pointer_width_bits != 64
    {
        return command_error(
            64,
            format!("{} does not match the locked Stage 4 Linux target: {target:?}", id.as_str()),
        );
    }
    Ok(())
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

fn retain_hello(
    root: &Path,
    cell: Stage4CellId,
    role: Stage4Role,
    observed: &TargetHelloObservation,
) -> CommandResult<Stage4TargetHelloObservation> {
    if observed.exit_code != 0 || !observed.stderr.is_empty() {
        return command_error(
            1,
            format!("{} {} target hello was not clean", cell.as_str(), role.as_str()),
        );
    }
    let stdout = publish_bytes(root, &cell.hello_stdout_uri(role), &observed.stdout)?;
    let stderr = publish_bytes(root, &cell.hello_stderr_uri(role), &observed.stderr)?;
    Ok(Stage4TargetHelloObservation {
        expected_nonce: observed.hello.nonce.clone(),
        exit_status: observed.exit_code,
        hello: stage4_hello(&observed.hello),
        raw_stdout: stdout,
        raw_stderr: stderr,
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

fn remove_runner_work(cell_root: &Path) -> CommandResult<()> {
    let path = cell_root.join(".runner-work");
    let metadata = fs::symlink_metadata(&path).map_err(|source| {
        (1, format!("cannot inspect Stage 1 runner work directory {}: {source}", path.display()))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return command_error(
            1,
            format!("refusing to remove unsafe Stage 1 runner work path {}", path.display()),
        );
    }
    fs::remove_dir_all(&path).map_err(|source| {
        (1, format!("cannot remove Stage 1 runner work directory {}: {source}", path.display()))
    })
}

fn publish_json<T: Serialize>(
    root: &Path,
    uri: &str,
    value: &T,
) -> CommandResult<Stage4ArtifactReference> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|source| (1, format!("cannot encode Stage 4 artifact {uri}: {source}")))?;
    publish_bytes(root, uri, &bytes)
}

fn publish_bytes(root: &Path, uri: &str, bytes: &[u8]) -> CommandResult<Stage4ArtifactReference> {
    if uri.is_empty()
        || Path::new(uri).is_absolute()
        || uri.split('/').any(|part| part.is_empty() || part == "." || part == "..")
    {
        return command_error(1, format!("unsafe Stage 4 artifact URI {uri:?}"));
    }
    let path = root.join(uri);
    let parent = path.parent().ok_or_else(|| (1, format!("artifact URI has no parent: {uri}")))?;
    fs::create_dir_all(parent).map_err(|source| {
        (1, format!("cannot create Stage 4 artifact directory {}: {source}", parent.display()))
    })?;
    let mut file =
        OpenOptions::new().create_new(true).write(true).open(&path).map_err(|source| {
            (1, format!("cannot create Stage 4 artifact {}: {source}", path.display()))
        })?;
    file.write_all(bytes).and_then(|()| file.sync_all()).map_err(|source| {
        (1, format!("cannot sync Stage 4 artifact {}: {source}", path.display()))
    })?;
    Ok(Stage4ArtifactReference {
        uri: uri.to_owned(),
        sha256: format!("{:x}", Sha256::digest(bytes)),
        size: u64::try_from(bytes.len()).map_err(|_| (1, "artifact size overflow".to_owned()))?,
    })
}

fn artifact_reference(root: &Path, uri: &str) -> CommandResult<Stage4ArtifactReference> {
    let identity = single_link_file_identity(&root.join(uri), "retained Stage 4 artifact")?;
    Ok(identity.reference(uri.to_owned()))
}

fn require_input_basename(path: &Path, expected: &str) -> CommandResult<()> {
    if path.file_name().and_then(|name| name.to_str()) != Some(expected) {
        return command_error(
            64,
            format!("QEMU input must be named {expected}: {}", path.display()),
        );
    }
    Ok(())
}

fn path_text(path: &Path, label: &str) -> CommandResult<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| (64, format!("{label} path is not valid UTF-8: {}", path.display())))
}

fn os_strings_text(values: &[OsString], label: &str) -> CommandResult<Vec<String>> {
    values
        .iter()
        .map(|value| {
            value
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| (64, format!("{label} contains non-UTF-8 text")))
        })
        .collect()
}

fn command_error<T>(code: u8, detail: impl Into<String>) -> CommandResult<T> {
    Err((code, detail.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uname_parser_requires_one_canonical_identity_line() {
        assert_eq!(
            parse_uname_identity(b"Linux 6.12.0-test x86_64\n").unwrap(),
            Stage4HostIdentity {
                sysname: "Linux".to_owned(),
                kernel_release: "6.12.0-test".to_owned(),
                machine: "x86_64".to_owned(),
            }
        );
        for rejected in [
            b"Linux 6.12.0-test x86_64".as_slice(),
            b"Linux  6.12.0-test x86_64\n".as_slice(),
            b"Linux 6.12.0-test x86_64 extra\n".as_slice(),
            b"Linux 6.12.0-test x86_64\nsecond\n".as_slice(),
        ] {
            assert!(parse_uname_identity(rejected).is_err());
        }
    }

    #[test]
    fn qemu_version_parser_requires_the_named_adapter_and_nonempty_version() {
        assert_eq!(
            parse_qemu_version_line("qemu-aarch64 version 10.0.2 (Debian)", "qemu-aarch64")
                .unwrap(),
            "10.0.2"
        );
        assert!(parse_qemu_version_line("QEMU emulator version 10", "qemu-aarch64").is_err());
        assert!(parse_qemu_version_line("qemu-aarch64 version ", "qemu-aarch64").is_err());
    }

    #[test]
    fn elf_parser_reads_machine_and_interpreter_without_executing_the_file() {
        let mut bytes = vec![0_u8; 256];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[18..20].copy_from_slice(&183_u16.to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&3_u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&160_u64.to_le_bytes());
        let interpreter = b"/lib/ld-linux-aarch64.so.1\0";
        bytes[96..104].copy_from_slice(&(interpreter.len() as u64).to_le_bytes());
        bytes[160..160 + interpreter.len()].copy_from_slice(interpreter);

        let root = env::temp_dir().join(format!(
            "visa-stage4-elf-test-{}-{}",
            std::process::id(),
            Sha256::digest(&bytes)[0]
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let file = root.join("worker");
        fs::write(&file, bytes).unwrap();
        assert_eq!(read_elf_interpreter(&file).unwrap(), "/lib/ld-linux-aarch64.so.1");
        require_elf_machine(&file, Stage4EndpointId::Qa).unwrap();
        assert!(require_elf_machine(&file, Stage4EndpointId::Qx).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn artifact_publisher_rejects_traversal_and_retains_digest_and_size() {
        let root =
            env::temp_dir().join(format!("visa-stage4-artifact-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        assert!(publish_bytes(&root, "../escape", b"bad").is_err());
        let reference = publish_bytes(&root, "targets/Hx/receipt", b"owned").unwrap();
        assert_eq!(reference.size, 5);
        assert_eq!(reference.sha256, format!("{:x}", Sha256::digest(b"owned")));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn launcher_receipt_binds_the_actual_program_and_disallows_fallback() {
        let qemu = OwnedExecutable {
            path: PathBuf::from("/owned/qemu-aarch64"),
            sha256: "a".repeat(64),
            size: 17,
        };
        let sysroot = Stage4ArtifactReference {
            uri: "targets/Qa/sysroot-receipt.json".to_owned(),
            sha256: "b".repeat(64),
            size: 23,
        };
        let receipt = launcher_receipt(
            Stage4EndpointId::Qa,
            &qemu,
            vec![
                "/owned/qemu-aarch64".to_owned(),
                "-cpu".to_owned(),
                "max".to_owned(),
                "-L".to_owned(),
                "/sysroot".to_owned(),
                "/owned/worker".to_owned(),
            ],
            Some(Stage4QemuReceipt {
                adapter_family: "qemu-user".to_owned(),
                emulator_name: "qemu-aarch64".to_owned(),
                emulator_version: "10.0.2".to_owned(),
                executable: qemu.reference("targets/Qa/qemu".to_owned()),
                version_stdout: Stage4ArtifactReference {
                    uri: "targets/Qa/qemu-version.stdout.txt".to_owned(),
                    sha256: "c".repeat(64),
                    size: 1,
                },
                version_stderr: Stage4ArtifactReference {
                    uri: "targets/Qa/qemu-version.stderr.log".to_owned(),
                    sha256: "d".repeat(64),
                    size: 0,
                },
                argv_prefix: vec![
                    "-cpu".to_owned(),
                    "max".to_owned(),
                    "-L".to_owned(),
                    "/sysroot".to_owned(),
                    "/owned/worker".to_owned(),
                ],
            }),
            sysroot,
        );

        assert_eq!(receipt.program_sha256, "a".repeat(64));
        assert_eq!(receipt.program_size, 17);
        assert_eq!(receipt.argv[0], "/owned/qemu-aarch64");
        assert_eq!(receipt.argv[1..], receipt.qemu.as_ref().unwrap().argv_prefix);
        assert_eq!(receipt.execution_mode, Stage4EndpointId::Qa.required_execution_mode());
        assert!(!receipt.native_fallback_allowed);
        assert!(!receipt.observed_native_fallback);
    }

    #[test]
    fn emulated_launcher_prefix_fixes_cpu_sysroot_and_owned_worker_order() {
        assert_eq!(
            os_strings_text(
                &emulated_launcher_prefix(
                    Path::new("/usr/aarch64-linux-gnu"),
                    Path::new("/evidence/targets/Qa/worker")
                ),
                "test prefix"
            )
            .unwrap(),
            ["-cpu", "max", "-L", "/usr/aarch64-linux-gnu", "/evidence/targets/Qa/worker",]
        );
    }

    #[test]
    fn loader_manifest_hashes_sorted_dependencies_and_detects_symlink_retarget() {
        let root = env::temp_dir().join(format!("visa-stage4-loader-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let lib = root.join("lib");
        fs::create_dir_all(&lib).unwrap();
        fs::write(lib.join("ld-linux-aarch64.so.1"), b"loader").unwrap();
        fs::write(lib.join("libc-a.so.6"), b"libc-a").unwrap();
        fs::write(lib.join("libc-b.so.6"), b"libc-b").unwrap();
        std::os::unix::fs::symlink("libc-a.so.6", lib.join("libc.so.6")).unwrap();
        let stdout = concat!(
            "linux-vdso.so.1 (0x00000000)\n",
            "libc.so.6 => /lib/libc.so.6 (0x00000001)\n",
            "/lib/ld-linux-aarch64.so.1 (0x00000002)\n",
        );

        let (manifest, dependencies) =
            loader_manifest_from_output(Stage4EndpointId::Qa, &root, stdout).unwrap();
        assert_eq!(manifest.entries.len(), 2);
        assert!(manifest.entries.windows(2).all(|pair| pair[0].name < pair[1].name));
        for dependency in &dependencies {
            dependency.verify_unchanged().unwrap();
        }

        fs::remove_file(lib.join("libc.so.6")).unwrap();
        std::os::unix::fs::symlink("libc-b.so.6", lib.join("libc.so.6")).unwrap();
        assert!(
            dependencies
                .iter()
                .find(|dependency| dependency.guest_name == "/lib/libc.so.6")
                .unwrap()
                .verify_unchanged()
                .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }
}
