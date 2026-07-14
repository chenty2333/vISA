use std::{
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use sha2::{Digest as _, Sha256};

use crate::{
    protocol::WorkerRole,
    target::{TargetHelloV1, validate_target_nonce},
};

const MAX_TARGET_HELLO_STREAM_BYTES: usize = 1024 * 1024;
static NEXT_TARGET_NONCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerLauncher {
    program: PathBuf,
    prefix_args: Vec<OsString>,
    env_overrides: Vec<(OsString, OsString)>,
}

impl WorkerLauncher {
    pub fn direct(executable: impl AsRef<Path>) -> Self {
        Self::new(executable, std::iter::empty::<OsString>())
    }

    pub fn new(
        program: impl AsRef<Path>,
        prefix_args: impl IntoIterator<Item = impl Into<OsString>>,
    ) -> Self {
        Self {
            program: program.as_ref().to_path_buf(),
            prefix_args: prefix_args.into_iter().map(Into::into).collect(),
            env_overrides: Vec::new(),
        }
    }

    pub fn with_env_override(
        mut self,
        name: impl Into<OsString>,
        value: impl Into<OsString>,
    ) -> Self {
        let name = name.into();
        let value = value.into();
        if let Some((_, existing)) =
            self.env_overrides.iter_mut().find(|(existing, _)| existing == &name)
        {
            *existing = value;
        } else {
            self.env_overrides.push((name, value));
        }
        self
    }

    pub fn program(&self) -> &Path {
        &self.program
    }

    pub fn prefix_args(&self) -> &[OsString] {
        &self.prefix_args
    }

    pub fn env_overrides(&self) -> &[(OsString, OsString)] {
        &self.env_overrides
    }

    pub fn probe_target(&self) -> Result<TargetHelloObservation, WorkerLauncherError> {
        let nonce = fresh_target_nonce()?;
        self.probe_target_with_nonce(&nonce)
    }

    pub fn probe_target_with_nonce(
        &self,
        nonce: &str,
    ) -> Result<TargetHelloObservation, WorkerLauncherError> {
        validate_target_nonce(nonce)
            .map_err(|source| WorkerLauncherError::InvalidNonce { detail: source.to_string() })?;
        let mut command = self.command_with_tail([OsStr::new("target-hello"), OsStr::new(nonce)]);
        command.stdin(Stdio::null());
        let output = command.output().map_err(|source| WorkerLauncherError::Io {
            operation: "spawn target hello",
            source,
        })?;
        if output.stdout.len() > MAX_TARGET_HELLO_STREAM_BYTES
            || output.stderr.len() > MAX_TARGET_HELLO_STREAM_BYTES
        {
            return Err(WorkerLauncherError::OutputTooLarge {
                limit: MAX_TARGET_HELLO_STREAM_BYTES,
            });
        }
        if output.status.code() != Some(0) {
            return Err(WorkerLauncherError::UnexpectedExit {
                status: match output.status.code() {
                    Some(code) => format!("code {code}"),
                    None => "terminated by signal".to_owned(),
                },
            });
        }
        let payload = single_json_line(&output.stdout)?;
        let hello: TargetHelloV1 = serde_json::from_slice(payload)
            .map_err(|source| WorkerLauncherError::InvalidJson { detail: source.to_string() })?;
        hello
            .validate_for_nonce(nonce)
            .map_err(|source| WorkerLauncherError::InvalidHello { detail: source.to_string() })?;
        let canonical = serde_json::to_vec(&hello)
            .map_err(|source| WorkerLauncherError::InvalidJson { detail: source.to_string() })?;
        if payload != canonical {
            return Err(WorkerLauncherError::InvalidOutput {
                detail: "target hello JSON is not the canonical one-line struct encoding"
                    .to_owned(),
            });
        }
        Ok(TargetHelloObservation {
            hello,
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: 0,
        })
    }

    pub(crate) fn worker_command(&self) -> Command {
        self.command_with_tail([OsStr::new("worker")])
    }

    fn command_with_tail<const N: usize>(&self, tail: [&OsStr; N]) -> Command {
        let mut command = Command::new(&self.program);
        command.args(&self.prefix_args).args(tail);
        for (name, value) in &self.env_overrides {
            command.env(name, value);
        }
        command
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleLaunchers {
    source: WorkerLauncher,
    destination: WorkerLauncher,
}

impl RoleLaunchers {
    pub const fn new(source: WorkerLauncher, destination: WorkerLauncher) -> Self {
        Self { source, destination }
    }

    pub const fn source(&self) -> &WorkerLauncher {
        &self.source
    }

    pub const fn destination(&self) -> &WorkerLauncher {
        &self.destination
    }

    pub(crate) const fn for_role(&self, role: WorkerRole) -> &WorkerLauncher {
        match role {
            WorkerRole::Source => &self.source,
            WorkerRole::Destination => &self.destination,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetHelloObservation {
    pub hello: TargetHelloV1,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: i32,
}

#[derive(Debug)]
pub enum WorkerLauncherError {
    Io { operation: &'static str, source: std::io::Error },
    Clock { detail: String },
    InvalidNonce { detail: String },
    UnexpectedExit { status: String },
    OutputTooLarge { limit: usize },
    InvalidOutput { detail: String },
    InvalidJson { detail: String },
    InvalidHello { detail: String },
}

impl std::fmt::Display for WorkerLauncherError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { operation, source } => write!(formatter, "{operation}: {source}"),
            Self::Clock { detail } => write!(formatter, "generate target nonce: {detail}"),
            Self::InvalidNonce { detail } => write!(formatter, "invalid target nonce: {detail}"),
            Self::UnexpectedExit { status } => write!(formatter, "target hello exited as {status}"),
            Self::OutputTooLarge { limit } => {
                write!(formatter, "target hello output exceeds {limit} bytes")
            }
            Self::InvalidOutput { detail } => {
                write!(formatter, "invalid target hello output: {detail}")
            }
            Self::InvalidJson { detail } => {
                write!(formatter, "invalid target hello JSON: {detail}")
            }
            Self::InvalidHello { detail } => write!(formatter, "invalid target hello: {detail}"),
        }
    }
}

impl std::error::Error for WorkerLauncherError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn fresh_target_nonce() -> Result<String, WorkerLauncherError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|source| WorkerLauncherError::Clock { detail: source.to_string() })?;
    let sequence = NEXT_TARGET_NONCE.fetch_add(1, Ordering::Relaxed);
    let mut digest = Sha256::new();
    digest.update(elapsed.as_nanos().to_le_bytes());
    digest.update(std::process::id().to_le_bytes());
    digest.update(sequence.to_le_bytes());
    Ok(format!("{:x}", digest.finalize()))
}

fn single_json_line(stdout: &[u8]) -> Result<&[u8], WorkerLauncherError> {
    if stdout.is_empty() || !stdout.ends_with(b"\n") {
        return Err(WorkerLauncherError::InvalidOutput {
            detail: "stdout must contain one newline-terminated JSON line".to_owned(),
        });
    }
    let payload = &stdout[..stdout.len() - 1];
    if payload.is_empty() || payload.contains(&b'\n') || payload.contains(&b'\r') {
        return Err(WorkerLauncherError::InvalidOutput {
            detail: "stdout must contain exactly one JSON line with no carriage return".to_owned(),
        });
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn launcher_orders_prefix_before_the_worker_mode_and_applies_overrides() {
        let launcher = WorkerLauncher::new(
            "/usr/bin/qemu-aarch64",
            ["-L", "/usr/aarch64-linux-gnu", "/owned/visa-system-aarch64"],
        )
        .with_env_override("VISA_TEST_TARGET", "qa");
        let command = launcher.worker_command();

        assert_eq!(command.get_program(), OsStr::new("/usr/bin/qemu-aarch64"));
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            [
                OsStr::new("-L"),
                OsStr::new("/usr/aarch64-linux-gnu"),
                OsStr::new("/owned/visa-system-aarch64"),
                OsStr::new("worker"),
            ]
        );
        assert!(command.get_envs().any(|(name, value)| {
            name == OsStr::new("VISA_TEST_TARGET") && value == Some(OsStr::new("qa"))
        }));
    }

    #[test]
    fn role_launchers_select_the_same_launcher_for_all_workers_of_a_role() {
        let source = WorkerLauncher::direct("/source-worker");
        let destination = WorkerLauncher::direct("/destination-worker");
        let launchers = RoleLaunchers::new(source.clone(), destination.clone());

        assert_eq!(launchers.for_role(WorkerRole::Source), &source);
        assert_eq!(launchers.for_role(WorkerRole::Destination), &destination);
    }

    #[test]
    fn probe_requires_exactly_one_canonical_nonce_bound_json_line() {
        let script = r#"
nonce="$2"
printf 'qemu-probe-stderr\n' >&2
printf '{"schema_version":"visa-stage4-target-hello-v1","nonce":"%s","target_triple":"aarch64-unknown-linux-gnu","architecture":"aarch64","os":"linux","abi":"linux-gnu","endianness":"little","pointer_width_bits":64,"executable_sha256":"%064d","executable_size":1,"build_source_sha256":"%064d","build_toolchain_sha256":"%064d","worker_protocol_version":3}\n' "$nonce" 0 0 0
"#;
        let launcher = WorkerLauncher::new("/bin/sh", ["-c", script, "probe"]);
        let observation = launcher.probe_target_with_nonce(NONCE).unwrap();

        assert_eq!(observation.hello.nonce, NONCE);
        assert_eq!(observation.hello.architecture, "aarch64");
        assert_eq!(observation.exit_code, 0);
        assert_eq!(observation.stderr, b"qemu-probe-stderr\n");
    }

    #[test]
    fn generated_target_nonces_are_fresh_and_strictly_valid() {
        let first = fresh_target_nonce().unwrap();
        let second = fresh_target_nonce().unwrap();

        assert_ne!(first, second);
        validate_target_nonce(&first).unwrap();
        validate_target_nonce(&second).unwrap();
    }

    #[test]
    fn probe_rejects_extra_stdout_and_nonzero_exit() {
        let valid = r#"
nonce="$2"
printf '{"schema_version":"visa-stage4-target-hello-v1","nonce":"%s","target_triple":"x86_64-unknown-linux-gnu","architecture":"x86_64","os":"linux","abi":"linux-gnu","endianness":"little","pointer_width_bits":64,"executable_sha256":"%064d","executable_size":1,"build_source_sha256":"%064d","build_toolchain_sha256":"%064d","worker_protocol_version":3}\nextra\n' "$nonce" 0 0 0
"#;
        let extra =
            WorkerLauncher::new("/bin/sh", ["-c", valid, "probe"]).probe_target_with_nonce(NONCE);
        assert!(matches!(extra, Err(WorkerLauncherError::InvalidOutput { .. })));

        let failed = WorkerLauncher::new("/bin/sh", ["-c", "exit 9", "probe"])
            .probe_target_with_nonce(NONCE);
        assert!(matches!(failed, Err(WorkerLauncherError::UnexpectedExit { .. })));
    }
}
