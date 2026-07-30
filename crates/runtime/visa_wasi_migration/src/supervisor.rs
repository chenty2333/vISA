use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::{
        fs::OpenOptionsExt,
        process::{CommandExt, ExitStatusExt},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use rustix::process::{Signal, set_parent_process_death_signal};
use serde::{Deserialize, Serialize};
use visa_durable_sqlite::StoreLock;

use crate::{FileIdentity, MigrationError, WANCO_RESTORE_COMPLETION_SCHEMA};

pub const WANCO_SUPERVISOR_SPEC_SCHEMA: &str = "visa-wanco-supervisor-spec-v1";
pub const WANCO_SUPERVISOR_STARTED_SCHEMA: &str = "visa-wanco-supervisor-started-v1";

const POLL_INTERVAL: Duration = Duration::from_millis(25);
const COORDINATOR_GRACE: Duration = Duration::from_secs(10);
const TIMEOUT_EXIT_STATUS: i32 = 124;

#[cfg(test)]
pub(crate) static PROCESS_FIXTURE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub(crate) struct SupervisedCommand<'a> {
    pub operation: &'a str,
    pub supervisor_binary: &'a Path,
    pub spec_path: &'a Path,
    pub started_receipt: &'a Path,
    pub completion_receipt: &'a Path,
    pub lock_path: &'a Path,
    pub fingerprint: &'a str,
    pub argv: &'a [String],
    pub cwd: &'a Path,
    pub stdout: &'a Path,
    pub stderr: &'a Path,
    pub timeout: Duration,
    pub cleanup_argv: &'a [String],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SupervisorSpec {
    schema: String,
    operation: String,
    command_fingerprint: String,
    argv: Vec<String>,
    cwd: PathBuf,
    stdout: PathBuf,
    stderr: PathBuf,
    started_receipt: PathBuf,
    completion_receipt: PathBuf,
    lock_path: PathBuf,
    timeout_millis: u64,
    cleanup_argv: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SupervisorStarted {
    schema: String,
    command_fingerprint: String,
    attempt: u64,
    supervisor_pid: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SupervisorCompletion {
    schema: String,
    operation: String,
    command_fingerprint: String,
    attempt: u64,
    exit_status: i32,
    stdout: FileIdentity,
    stderr: FileIdentity,
}

pub(crate) fn execute_or_reconcile(command: SupervisedCommand<'_>) -> Result<(), MigrationError> {
    let spec = spec_from_command(&command)?;
    ensure_spec(command.spec_path, &spec)?;
    if command.completion_receipt.exists() {
        return verify_completion(&spec);
    }

    let mut supervisor = Command::new(command.supervisor_binary)
        .arg("supervise-wanco")
        .arg(command.spec_path)
        .current_dir(command.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| {
            MigrationError::External(format!("cannot start Wanco supervisor: {error}"))
        })?;
    let deadline = Instant::now() + command.timeout + COORDINATOR_GRACE;
    loop {
        if command.completion_receipt.exists() {
            let result = verify_completion(&spec);
            let _ = supervisor.try_wait();
            return result;
        }
        let _ = supervisor.try_wait().map_err(MigrationError::Io)?;
        if Instant::now() >= deadline {
            return Err(MigrationError::External(
                "Wanco supervisor did not publish a terminal receipt before the deadline"
                    .to_owned(),
            ));
        }
        thread::sleep(POLL_INTERVAL);
    }
}

#[cfg(test)]
pub(crate) fn execute_in_process(command: SupervisedCommand<'_>) -> Result<(), MigrationError> {
    let spec = spec_from_command(&command)?;
    ensure_spec(command.spec_path, &spec)?;
    run_wanco_supervisor(command.spec_path)?;
    verify_completion(&spec)
}

pub fn run_wanco_supervisor(spec_path: &Path) -> Result<(), MigrationError> {
    let spec: SupervisorSpec = read_canonical(spec_path)?;
    validate_spec(&spec)?;
    // A terminal receipt is immutable and fully rebound to the command and
    // output bytes by `verify_completion`. Completed retries therefore do not
    // contend with a live or briefly inherited supervisor lock.
    if spec.completion_receipt.exists() {
        return verify_completion(&spec);
    }
    let _lock = StoreLock::acquire(&spec.lock_path)
        .map_err(|error| MigrationError::Durability(error.to_string()))?;
    // Another supervisor may have completed between the unlocked check and
    // this acquisition.
    if spec.completion_receipt.exists() {
        return verify_completion(&spec);
    }

    let previous = if spec.started_receipt.exists() {
        let started: SupervisorStarted = read_canonical(&spec.started_receipt)?;
        if started.schema != WANCO_SUPERVISOR_STARTED_SCHEMA
            || started.command_fingerprint != spec.command_fingerprint
            || started.attempt == 0
        {
            return Err(MigrationError::Integrity(
                "Wanco supervisor started receipt differs from its command",
            ));
        }
        run_cleanup(&spec)?;
        remove_attempt_output(&spec.stdout)?;
        remove_attempt_output(&spec.stderr)?;
        started.attempt
    } else {
        0
    };
    let attempt = previous
        .checked_add(1)
        .ok_or(MigrationError::Integrity("Wanco supervisor attempt counter overflowed"))?;
    let started = SupervisorStarted {
        schema: WANCO_SUPERVISOR_STARTED_SCHEMA.to_owned(),
        command_fingerprint: spec.command_fingerprint.clone(),
        attempt,
        supervisor_pid: std::process::id(),
    };
    write_canonical(&spec.started_receipt, &started)?;

    let stdout = create_output(&spec.stdout)?;
    let stderr = create_output(&spec.stderr)?;
    let mut child_command = Command::new(&spec.argv[0]);
    child_command
        .args(&spec.argv[1..])
        .current_dir(&spec.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    // The exact cleanup command remains the cross-runtime backstop (for
    // example `docker rm --force`). PDEATHSIG also prevents an ordinary native
    // child from surviving a supervisor crash.
    unsafe {
        child_command.pre_exec(|| {
            set_parent_process_death_signal(Some(Signal::KILL))
                .map_err(|error| std::io::Error::from_raw_os_error(error.raw_os_error()))
        });
    }
    let mut child = child_command.spawn().map_err(|error| {
        MigrationError::External(format!("cannot start supervised Wanco command: {error}"))
    })?;
    let deadline = Instant::now() + Duration::from_millis(spec.timeout_millis);
    let exit_status = loop {
        if let Some(status) = child.try_wait().map_err(MigrationError::Io)? {
            break normalized_exit_status(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            run_cleanup(&spec)?;
            break TIMEOUT_EXIT_STATUS;
        }
        thread::sleep(POLL_INTERVAL);
    };
    if exit_status != 0 && exit_status != TIMEOUT_EXIT_STATUS {
        run_cleanup(&spec)?;
    }
    File::open(&spec.stdout).and_then(|file| file.sync_all()).map_err(MigrationError::Io)?;
    File::open(&spec.stderr).and_then(|file| file.sync_all()).map_err(MigrationError::Io)?;
    let completion = SupervisorCompletion {
        schema: WANCO_RESTORE_COMPLETION_SCHEMA.to_owned(),
        operation: spec.operation.clone(),
        command_fingerprint: spec.command_fingerprint.clone(),
        attempt,
        exit_status,
        stdout: file_identity(&spec.stdout)?,
        stderr: file_identity(&spec.stderr)?,
    };
    write_canonical(&spec.completion_receipt, &completion)
}

fn spec_from_command(command: &SupervisedCommand<'_>) -> Result<SupervisorSpec, MigrationError> {
    let timeout_millis = u64::try_from(command.timeout.as_millis())
        .map_err(|_| MigrationError::Invalid("Wanco supervisor timeout is too large"))?;
    let spec = SupervisorSpec {
        schema: WANCO_SUPERVISOR_SPEC_SCHEMA.to_owned(),
        operation: command.operation.to_owned(),
        command_fingerprint: command.fingerprint.to_owned(),
        argv: command.argv.to_vec(),
        cwd: command.cwd.to_path_buf(),
        stdout: command.stdout.to_path_buf(),
        stderr: command.stderr.to_path_buf(),
        started_receipt: command.started_receipt.to_path_buf(),
        completion_receipt: command.completion_receipt.to_path_buf(),
        lock_path: command.lock_path.to_path_buf(),
        timeout_millis,
        cleanup_argv: command.cleanup_argv.to_vec(),
    };
    validate_spec(&spec)?;
    Ok(spec)
}

fn validate_spec(spec: &SupervisorSpec) -> Result<(), MigrationError> {
    if spec.schema != WANCO_SUPERVISOR_SPEC_SCHEMA
        || spec.argv.is_empty()
        || !matches!(spec.operation.as_str(), "restore_source" | "restore_destination")
        || spec.cleanup_argv.is_empty()
        || spec.timeout_millis == 0
        || spec.command_fingerprint.len() != 64
        || !spec.command_fingerprint.bytes().all(|value| value.is_ascii_hexdigit())
    {
        return Err(MigrationError::Invalid("invalid Wanco supervisor specification"));
    }
    let paths = [
        &spec.cwd,
        &spec.stdout,
        &spec.stderr,
        &spec.started_receipt,
        &spec.completion_receipt,
        &spec.lock_path,
    ];
    if paths.iter().any(|path| !path.is_absolute())
        || spec.stdout == spec.stderr
        || spec.started_receipt == spec.completion_receipt
    {
        return Err(MigrationError::Invalid("invalid Wanco supervisor paths"));
    }
    Ok(())
}

fn ensure_spec(path: &Path, expected: &SupervisorSpec) -> Result<(), MigrationError> {
    if path.exists() {
        let actual: SupervisorSpec = read_canonical(path)?;
        if actual != *expected {
            return Err(MigrationError::Integrity(
                "Wanco supervisor specification changed during replay",
            ));
        }
        return Ok(());
    }
    write_canonical(path, expected)
}

fn verify_completion(spec: &SupervisorSpec) -> Result<(), MigrationError> {
    let started: SupervisorStarted = read_canonical(&spec.started_receipt)?;
    let completion: SupervisorCompletion = read_canonical(&spec.completion_receipt)?;
    if started.schema != WANCO_SUPERVISOR_STARTED_SCHEMA
        || started.command_fingerprint != spec.command_fingerprint
        || completion.schema != WANCO_RESTORE_COMPLETION_SCHEMA
        || completion.operation != spec.operation
        || completion.command_fingerprint != spec.command_fingerprint
        || completion.attempt != started.attempt
        || completion.exit_status < 0
        || completion.stdout != file_identity(&spec.stdout)?
        || completion.stderr != file_identity(&spec.stderr)?
    {
        return Err(MigrationError::Integrity(
            "Wanco supervisor completion receipt differs from its command or outputs",
        ));
    }
    if completion.exit_status != 0 {
        return Err(MigrationError::External(format!(
            "Wanco restore exited with status {}",
            completion.exit_status
        )));
    }
    Ok(())
}

fn run_cleanup(spec: &SupervisorSpec) -> Result<(), MigrationError> {
    let (program, arguments) = spec
        .cleanup_argv
        .split_first()
        .ok_or(MigrationError::Invalid("Wanco supervisor cleanup command is empty"))?;
    let status = Command::new(program)
        .args(arguments)
        .current_dir(&spec.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| {
            MigrationError::External(format!("cannot run Wanco supervisor cleanup: {error}"))
        })?;
    if !status.success() {
        return Err(MigrationError::External(format!(
            "Wanco supervisor cleanup failed with {status}"
        )));
    }
    Ok(())
}

fn remove_attempt_output(path: &Path) -> Result<(), MigrationError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            fs::remove_file(path).map_err(MigrationError::Io)
        }
        Ok(_) => Err(MigrationError::Integrity("Wanco supervisor output is not a regular file")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(MigrationError::Io(error)),
    }
}

fn create_output(path: &Path) -> Result<File, MigrationError> {
    let parent = private_parent(path)?;
    fs::create_dir_all(parent).map_err(MigrationError::Io)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    options.open(path).map_err(MigrationError::Io)
}

fn file_identity(path: &Path) -> Result<FileIdentity, MigrationError> {
    let metadata = fs::symlink_metadata(path).map_err(MigrationError::Io)?;
    if !metadata.file_type().is_file() {
        return Err(MigrationError::Integrity("Wanco supervisor evidence is not a regular file"));
    }
    let bytes = fs::read(path).map_err(MigrationError::Io)?;
    use sha2::{Digest as _, Sha256};
    Ok(FileIdentity { sha256: hex(&Sha256::digest(&bytes)), size: metadata.len() })
}

fn read_canonical<T>(path: &Path) -> Result<T, MigrationError>
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
        return Err(MigrationError::Integrity(
            "Wanco supervisor document is not canonical RFC 8785 JSON",
        ));
    }
    Ok(value)
}

fn write_canonical<T: Serialize>(path: &Path, value: &T) -> Result<(), MigrationError> {
    let parent = private_parent(path)?;
    fs::create_dir_all(parent).map_err(MigrationError::Io)?;
    let mut bytes = serde_json_canonicalizer::to_vec(value)
        .map_err(|error| MigrationError::Codec(error.to_string()))?;
    bytes.push(b'\n');
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().and_then(|value| value.to_str()).unwrap_or("supervisor"),
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

fn private_parent(path: &Path) -> Result<&Path, MigrationError> {
    path.parent()
        .filter(|value| !value.as_os_str().is_empty())
        .ok_or(MigrationError::Invalid("Wanco supervisor path has no parent"))
}

fn normalized_exit_status(status: std::process::ExitStatus) -> i32 {
    status.code().unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
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
    use std::os::unix::fs::PermissionsExt;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn stale_started_attempt_is_cleaned_restarted_and_then_reused() {
        let _process_fixture = PROCESS_FIXTURE_LOCK.lock().unwrap();
        let temporary = TempDir::new().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let marker = temporary.path().join("marker");
        let spec_path = temporary.path().join("spec.json");
        let started_path = temporary.path().join("started.json");
        let completion_path = temporary.path().join("completion.json");
        let lock_path = temporary.path().join("supervisor.lock");
        let stdout_path = temporary.path().join("stdout");
        let stderr_path = temporary.path().join("stderr");
        let fingerprint = "ab".repeat(32);
        let cleanup = vec!["/bin/true".to_owned()];
        let command = vec![
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            "printf x >> \"$1\"".to_owned(),
            "visa-test".to_owned(),
            marker.display().to_string(),
        ];
        let request = SupervisedCommand {
            operation: "restore_source",
            supervisor_binary: Path::new("/not-used"),
            spec_path: &spec_path,
            started_receipt: &started_path,
            completion_receipt: &completion_path,
            lock_path: &lock_path,
            fingerprint: &fingerprint,
            argv: &command,
            cwd: temporary.path(),
            stdout: &stdout_path,
            stderr: &stderr_path,
            timeout: Duration::from_secs(5),
            cleanup_argv: &cleanup,
        };
        let spec = spec_from_command(&request).unwrap();
        ensure_spec(request.spec_path, &spec).unwrap();
        write_canonical(
            &started_path,
            &SupervisorStarted {
                schema: WANCO_SUPERVISOR_STARTED_SCHEMA.to_owned(),
                command_fingerprint: fingerprint.clone(),
                attempt: 1,
                supervisor_pid: 1,
            },
        )
        .unwrap();
        fs::write(&stdout_path, b"stale").unwrap();
        fs::write(&stderr_path, b"stale").unwrap();
        run_wanco_supervisor(request.spec_path).unwrap();
        verify_completion(&spec).unwrap();
        run_wanco_supervisor(request.spec_path).unwrap();
        assert_eq!(fs::read(marker).unwrap(), b"x");
        let started: SupervisorStarted = read_canonical(&started_path).unwrap();
        assert_eq!(started.attempt, 2);
    }
}
