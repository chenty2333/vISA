use std::{
    fmt,
    fs::File,
    io::{self, BufRead, BufReader, BufWriter, Write},
    path::Path,
    process::{Child, ChildStdin, Command, ExitStatus, Stdio},
    sync::{
        Arc, Mutex,
        mpsc::{self, Receiver, RecvTimeoutError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

use crate::protocol::{
    CrashMode, PROTOCOL_VERSION, RequestEnvelope, ResponseEnvelope, ResponseOutcome,
    RuntimeIdentityView, WorkerCommand, WorkerError, WorkerResult,
};

const EXIT_POLL_INTERVAL: Duration = Duration::from_millis(5);
const DROP_GRACE_PERIOD: Duration = Duration::from_millis(100);
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptStream {
    ParentRequest,
    WorkerResponse,
    WorkerStderr,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptLine {
    pub sequence: u64,
    pub stream: TranscriptStream,
    pub line: String,
}

#[derive(Debug)]
pub enum WorkerClientError {
    Io { context: &'static str, source: io::Error },
    Json { context: &'static str, detail: String },
    Timeout { operation: String, timeout: Duration },
    Protocol { detail: String },
    RequestIdMismatch { expected: String, actual: String },
    WorkerRejected { request_id: String, error: WorkerError },
    UnexpectedExit { operation: String, status: String },
    ExitCodeMismatch { expected: i32, status: String },
    Closed,
}

impl fmt::Display for WorkerClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { context, source } => write!(formatter, "{context}: {source}"),
            Self::Json { context, detail } => write!(formatter, "{context}: {detail}"),
            Self::Timeout { operation, timeout } => {
                write!(formatter, "{operation} timed out after {timeout:?}")
            }
            Self::Protocol { detail } => write!(formatter, "worker protocol error: {detail}"),
            Self::RequestIdMismatch { expected, actual } => write!(
                formatter,
                "worker response id {actual:?} does not match request id {expected:?}"
            ),
            Self::WorkerRejected { request_id, error } => write!(
                formatter,
                "worker rejected request {request_id:?}: {:?}: {}",
                error.code, error.message
            ),
            Self::UnexpectedExit { operation, status } => {
                write!(formatter, "worker exited during {operation}: {status}")
            }
            Self::ExitCodeMismatch { expected, status } => {
                write!(formatter, "worker exited as {status}, expected code {expected}")
            }
            Self::Closed => formatter.write_str("worker client is closed"),
        }
    }
}

impl std::error::Error for WorkerClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

enum ReaderEvent {
    Line(String),
    Eof,
    Error(String),
}

pub struct WorkerClient {
    label: String,
    child: Child,
    stdin: Option<BufWriter<ChildStdin>>,
    stdout: Receiver<ReaderEvent>,
    stdout_thread: Option<JoinHandle<()>>,
    stderr_thread: Option<JoinHandle<()>>,
    transcript: Arc<Mutex<Vec<TranscriptLine>>>,
    next_request: u64,
    default_timeout: Duration,
    usable: bool,
    runtime_identity: Option<RuntimeIdentityView>,
}

impl WorkerClient {
    /// Spawn the current vISA system executable in worker mode.
    pub fn spawn(
        executable: impl AsRef<Path>,
        label: impl Into<String>,
        default_timeout: Duration,
    ) -> Result<Self, WorkerClientError> {
        let mut command = Command::new(executable.as_ref());
        command.arg("worker");
        Self::spawn_command(command, label.into(), default_timeout)
    }

    pub fn spawn_current(
        label: impl Into<String>,
        default_timeout: Duration,
    ) -> Result<Self, WorkerClientError> {
        let executable = std::env::current_exe().map_err(|source| WorkerClientError::Io {
            context: "resolve current visa-system executable",
            source,
        })?;
        Self::spawn(executable, label, default_timeout)
    }

    fn spawn_command(
        mut command: Command,
        label: String,
        default_timeout: Duration,
    ) -> Result<Self, WorkerClientError> {
        if default_timeout.is_zero() {
            return Err(WorkerClientError::Protocol {
                detail: "worker timeout must be positive".to_owned(),
            });
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| WorkerClientError::Io {
                context: "spawn visa-system worker",
                source,
            })?;
        let stdin = child.stdin.take().ok_or_else(|| WorkerClientError::Protocol {
            detail: "spawned worker has no stdin pipe".to_owned(),
        })?;
        let stdout = child.stdout.take().ok_or_else(|| WorkerClientError::Protocol {
            detail: "spawned worker has no stdout pipe".to_owned(),
        })?;
        let stderr = child.stderr.take().ok_or_else(|| WorkerClientError::Protocol {
            detail: "spawned worker has no stderr pipe".to_owned(),
        })?;
        let transcript = Arc::new(Mutex::new(Vec::new()));
        let (sender, receiver) = mpsc::channel();
        let stdout_transcript = Arc::clone(&transcript);
        let stdout_thread = thread::Builder::new()
            .name(format!("visa-worker-{label}-stdout"))
            .spawn(move || {
                let mut reader = BufReader::new(stdout);
                loop {
                    let mut line = String::new();
                    match reader.read_line(&mut line) {
                        Ok(0) => {
                            let _ = sender.send(ReaderEvent::Eof);
                            break;
                        }
                        Ok(_) => {
                            trim_line_ending(&mut line);
                            record_line(
                                &stdout_transcript,
                                TranscriptStream::WorkerResponse,
                                line.clone(),
                            );
                            if sender.send(ReaderEvent::Line(line)).is_err() {
                                break;
                            }
                        }
                        Err(error) => {
                            let _ = sender.send(ReaderEvent::Error(error.to_string()));
                            break;
                        }
                    }
                }
            })
            .map_err(|source| WorkerClientError::Io {
                context: "spawn worker stdout reader",
                source,
            })?;
        let stderr_transcript = Arc::clone(&transcript);
        let stderr_thread = thread::Builder::new()
            .name(format!("visa-worker-{label}-stderr"))
            .spawn(move || {
                let mut reader = BufReader::new(stderr);
                loop {
                    let mut line = String::new();
                    match reader.read_line(&mut line) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            trim_line_ending(&mut line);
                            record_line(&stderr_transcript, TranscriptStream::WorkerStderr, line);
                        }
                    }
                }
            })
            .map_err(|source| WorkerClientError::Io {
                context: "spawn worker stderr reader",
                source,
            })?;

        Ok(Self {
            label,
            child,
            stdin: Some(BufWriter::new(stdin)),
            stdout: receiver,
            stdout_thread: Some(stdout_thread),
            stderr_thread: Some(stderr_thread),
            transcript,
            next_request: 1,
            default_timeout,
            usable: true,
            runtime_identity: None,
        })
    }

    pub(super) fn set_runtime_identity(&mut self, identity: RuntimeIdentityView) {
        self.runtime_identity = Some(identity);
    }

    pub(super) fn runtime_identity(&self) -> Option<&RuntimeIdentityView> {
        self.runtime_identity.as_ref()
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub const fn is_usable(&self) -> bool {
        self.usable
    }

    pub fn request(
        &mut self,
        command: WorkerCommand,
    ) -> Result<ResponseEnvelope, WorkerClientError> {
        self.request_with_timeout(command, self.default_timeout)
    }

    pub fn request_with_timeout(
        &mut self,
        command: WorkerCommand,
        timeout: Duration,
    ) -> Result<ResponseEnvelope, WorkerClientError> {
        let request_id = self.send(command)?;
        self.receive(&request_id, timeout)
    }

    pub fn request_success(
        &mut self,
        command: WorkerCommand,
    ) -> Result<WorkerResult, WorkerClientError> {
        let timeout = self.default_timeout;
        self.request_success_with_timeout(command, timeout)
    }

    pub fn request_success_with_timeout(
        &mut self,
        command: WorkerCommand,
        timeout: Duration,
    ) -> Result<WorkerResult, WorkerClientError> {
        let response = self.request_with_timeout(command, timeout)?;
        match response.outcome {
            ResponseOutcome::Success { result } => Ok(*result),
            ResponseOutcome::Error { error } => {
                Err(WorkerClientError::WorkerRejected { request_id: response.id, error })
            }
        }
    }

    pub fn crash_and_expect_exit(
        &mut self,
        mode: CrashMode,
        exit_code: i32,
        timeout: Duration,
    ) -> Result<(), WorkerClientError> {
        let command = WorkerCommand::Crash { mode, exit_code };
        match mode {
            CrashMode::AfterResponse => {
                let response = self.request_with_timeout(command, timeout)?;
                match response.outcome {
                    ResponseOutcome::Success { result }
                        if matches!(result.as_ref(), WorkerResult::Ack) => {}
                    ResponseOutcome::Success { result } => {
                        return Err(WorkerClientError::Protocol {
                            detail: format!(
                                "crash acknowledgement returned unexpected result {result:?}"
                            ),
                        });
                    }
                    ResponseOutcome::Error { error } => {
                        return Err(WorkerClientError::WorkerRejected {
                            request_id: response.id,
                            error,
                        });
                    }
                }
            }
            CrashMode::Immediate => {
                let _ = self.send(command)?;
            }
        }
        self.expect_exit(exit_code, timeout)?;
        if mode == CrashMode::Immediate {
            self.ensure_no_response_after_immediate_exit(timeout)?;
        }
        Ok(())
    }

    pub fn expect_exit(
        &mut self,
        expected_code: i32,
        timeout: Duration,
    ) -> Result<ExitStatus, WorkerClientError> {
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
            WorkerClientError::Protocol { detail: "exit timeout overflowed Instant".to_owned() }
        })?;
        loop {
            match self
                .child
                .try_wait()
                .map_err(|source| WorkerClientError::Io { context: "poll worker exit", source })?
            {
                Some(status) => {
                    self.usable = false;
                    self.stdin.take();
                    if status.code() != Some(expected_code) {
                        return Err(WorkerClientError::ExitCodeMismatch {
                            expected: expected_code,
                            status: exit_status_text(status),
                        });
                    }
                    return Ok(status);
                }
                None if Instant::now() < deadline => thread::sleep(EXIT_POLL_INTERVAL),
                None => {
                    return Err(WorkerClientError::Timeout {
                        operation: format!("wait for worker {} to exit", self.label),
                        timeout,
                    });
                }
            }
        }
    }

    pub fn transcript(&self) -> Result<Vec<TranscriptLine>, WorkerClientError> {
        self.transcript.lock().map(|lines| lines.clone()).map_err(|_| WorkerClientError::Protocol {
            detail: "worker transcript lock is poisoned".to_owned(),
        })
    }

    pub fn write_transcript_json_lines(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<(), WorkerClientError> {
        let file = File::create(path).map_err(|source| WorkerClientError::Io {
            context: "create worker transcript",
            source,
        })?;
        let mut writer = BufWriter::new(file);
        for line in self.transcript()? {
            serde_json::to_writer(&mut writer, &line).map_err(|error| WorkerClientError::Json {
                context: "encode worker transcript line",
                detail: error.to_string(),
            })?;
            writer.write_all(b"\n").map_err(|source| WorkerClientError::Io {
                context: "write worker transcript",
                source,
            })?;
        }
        writer
            .flush()
            .map_err(|source| WorkerClientError::Io { context: "flush worker transcript", source })
    }

    fn send(&mut self, command: WorkerCommand) -> Result<String, WorkerClientError> {
        if !self.usable {
            return Err(WorkerClientError::Closed);
        }
        if let Some(status) = self.child.try_wait().map_err(|source| WorkerClientError::Io {
            context: "check worker before request",
            source,
        })? {
            self.usable = false;
            return Err(WorkerClientError::UnexpectedExit {
                operation: "send request".to_owned(),
                status: exit_status_text(status),
            });
        }
        let request_id = format!("{}-{:06}", self.label, self.next_request);
        self.next_request = self.next_request.checked_add(1).ok_or_else(|| {
            WorkerClientError::Protocol { detail: "worker request sequence exhausted".to_owned() }
        })?;
        let request = RequestEnvelope::new(request_id.clone(), command);
        let line = serde_json::to_string(&request).map_err(|error| WorkerClientError::Json {
            context: "encode worker request",
            detail: error.to_string(),
        })?;
        record_line(&self.transcript, TranscriptStream::ParentRequest, line.clone());
        let stdin = self.stdin.as_mut().ok_or(WorkerClientError::Closed)?;
        stdin
            .write_all(line.as_bytes())
            .and_then(|()| stdin.write_all(b"\n"))
            .and_then(|()| stdin.flush())
            .map_err(|source| WorkerClientError::Io { context: "write worker request", source })?;
        Ok(request_id)
    }

    fn receive(
        &mut self,
        request_id: &str,
        timeout: Duration,
    ) -> Result<ResponseEnvelope, WorkerClientError> {
        if timeout.is_zero() {
            self.usable = false;
            return Err(WorkerClientError::Timeout {
                operation: format!("receive response for {request_id}"),
                timeout,
            });
        }
        let event = match self.stdout.recv_timeout(timeout) {
            Ok(event) => event,
            Err(RecvTimeoutError::Timeout) => {
                self.usable = false;
                return Err(WorkerClientError::Timeout {
                    operation: format!("receive response for {request_id}"),
                    timeout,
                });
            }
            Err(RecvTimeoutError::Disconnected) => {
                self.usable = false;
                return Err(self.unexpected_output_end(request_id));
            }
        };
        let line = match event {
            ReaderEvent::Line(line) => line,
            ReaderEvent::Eof => {
                self.usable = false;
                return Err(self.unexpected_output_end(request_id));
            }
            ReaderEvent::Error(detail) => {
                self.usable = false;
                return Err(WorkerClientError::Protocol {
                    detail: format!("read worker response for {request_id}: {detail}"),
                });
            }
        };
        if line.len() > MAX_RESPONSE_BYTES {
            self.usable = false;
            return Err(WorkerClientError::Protocol {
                detail: format!("worker response exceeds {MAX_RESPONSE_BYTES} bytes"),
            });
        }
        let response: ResponseEnvelope = serde_json::from_str(&line).map_err(|error| {
            WorkerClientError::Json { context: "decode worker response", detail: error.to_string() }
        })?;
        if response.version != PROTOCOL_VERSION {
            self.usable = false;
            return Err(WorkerClientError::Protocol {
                detail: format!(
                    "worker response uses protocol version {}, expected {}",
                    response.version, PROTOCOL_VERSION
                ),
            });
        }
        if response.id != request_id {
            self.usable = false;
            return Err(WorkerClientError::RequestIdMismatch {
                expected: request_id.to_owned(),
                actual: response.id,
            });
        }
        Ok(response)
    }

    fn unexpected_output_end(&mut self, operation: &str) -> WorkerClientError {
        match self.child.try_wait() {
            Ok(Some(status)) => WorkerClientError::UnexpectedExit {
                operation: operation.to_owned(),
                status: exit_status_text(status),
            },
            Ok(None) => WorkerClientError::Protocol {
                detail: format!(
                    "worker stdout closed while process remained alive during {operation}"
                ),
            },
            Err(source) => {
                WorkerClientError::Io { context: "inspect worker after stdout closed", source }
            }
        }
    }

    fn ensure_no_response_after_immediate_exit(
        &mut self,
        timeout: Duration,
    ) -> Result<(), WorkerClientError> {
        match self.stdout.recv_timeout(timeout.min(DROP_GRACE_PERIOD)) {
            Ok(ReaderEvent::Eof) | Err(RecvTimeoutError::Disconnected) => Ok(()),
            Ok(ReaderEvent::Line(line)) => Err(WorkerClientError::Protocol {
                detail: format!("immediate crash unexpectedly produced response {line:?}"),
            }),
            Ok(ReaderEvent::Error(detail)) => Err(WorkerClientError::Protocol {
                detail: format!("read immediate crash output: {detail}"),
            }),
            Err(RecvTimeoutError::Timeout) => Err(WorkerClientError::Timeout {
                operation: "confirm silent immediate crash".to_owned(),
                timeout: timeout.min(DROP_GRACE_PERIOD),
            }),
        }
    }

    fn stop_for_drop(&mut self) {
        self.usable = false;
        self.stdin.take();
        let deadline = Instant::now() + DROP_GRACE_PERIOD;
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => thread::sleep(EXIT_POLL_INTERVAL),
                Ok(None) | Err(_) => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    break;
                }
            }
        }
        if let Some(thread) = self.stdout_thread.take() {
            let _ = thread.join();
        }
        if let Some(thread) = self.stderr_thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for WorkerClient {
    fn drop(&mut self) {
        self.stop_for_drop();
    }
}

fn record_line(
    transcript: &Arc<Mutex<Vec<TranscriptLine>>>,
    stream: TranscriptStream,
    line: String,
) {
    if let Ok(mut transcript) = transcript.lock() {
        let sequence = transcript.len() as u64 + 1;
        transcript.push(TranscriptLine { sequence, stream, line });
    }
}

fn trim_line_ending(line: &mut String) {
    let length = line.trim_end_matches(&['\r', '\n'][..]).len();
    line.truncate(length);
}

pub(super) fn exit_status_text(status: ExitStatus) -> String {
    match status.code() {
        Some(code) => format!("code {code}"),
        None => "terminated by signal".to_owned(),
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    const RESPONSE_SCRIPT: &str = r#"
IFS= read -r line
id=$(printf '%s\n' "$line" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
printf '{"version":2,"id":"%s","outcome":{"status":"success","result":{"kind":"ack"}}}\n' "$id"
"#;

    #[test]
    fn worker_client_matches_request_ids_and_records_json_lines() {
        let mut client = shell_client(RESPONSE_SCRIPT, Duration::from_secs(1));
        assert_eq!(client.request_success(WorkerCommand::Read).unwrap(), WorkerResult::Ack);
        client.expect_exit(0, Duration::from_secs(1)).unwrap();

        let transcript = client.transcript().unwrap();
        assert_eq!(transcript.len(), 2);
        assert_eq!(transcript[0].stream, TranscriptStream::ParentRequest);
        assert_eq!(transcript[1].stream, TranscriptStream::WorkerResponse);
        let request: RequestEnvelope = serde_json::from_str(&transcript[0].line).unwrap();
        let response: ResponseEnvelope = serde_json::from_str(&transcript[1].line).unwrap();
        assert_eq!(request.id, response.id);
        assert_eq!(transcript[0].sequence, 1);
        assert_eq!(transcript[1].sequence, 2);
    }

    #[test]
    fn worker_client_rejects_a_mismatched_response_id() {
        let script = r#"
IFS= read -r line
printf '{"version":2,"id":"wrong","outcome":{"status":"success","result":{"kind":"ack"}}}\n'
"#;
        let mut client = shell_client(script, Duration::from_secs(1));
        assert!(matches!(
            client.request(WorkerCommand::Read),
            Err(WorkerClientError::RequestIdMismatch { .. })
        ));
    }

    #[test]
    fn worker_client_times_out_and_becomes_unusable() {
        let script = "IFS= read -r line\nexec sleep 30\n";
        let mut client = shell_client(script, Duration::from_millis(25));
        assert!(matches!(
            client.request(WorkerCommand::Read),
            Err(WorkerClientError::Timeout { .. })
        ));
        assert!(matches!(client.request(WorkerCommand::Read), Err(WorkerClientError::Closed)));
    }

    #[test]
    fn explicit_request_timeout_can_exceed_the_steady_state_default() {
        let script = format!("sleep 0.05\n{RESPONSE_SCRIPT}");
        let mut client = shell_client(&script, Duration::from_millis(5));

        assert_eq!(
            client
                .request_success_with_timeout(WorkerCommand::Read, Duration::from_secs(1))
                .unwrap(),
            WorkerResult::Ack
        );
    }

    #[test]
    fn worker_client_checks_immediate_crash_exit_without_a_response() {
        let script = "IFS= read -r line\nexit 23\n";
        let mut client = shell_client(script, Duration::from_secs(1));
        client.crash_and_expect_exit(CrashMode::Immediate, 23, Duration::from_secs(1)).unwrap();
        assert_eq!(
            client
                .transcript()
                .unwrap()
                .iter()
                .filter(|line| line.stream == TranscriptStream::WorkerResponse)
                .count(),
            0
        );
    }

    #[cfg(unix)]
    #[test]
    fn worker_client_shutdown_terminates_and_reaps_the_child() {
        let mut command = Command::new("/bin/sleep");
        command.arg("30");
        let mut client =
            WorkerClient::spawn_command(command, "drop".to_owned(), Duration::from_secs(1))
                .unwrap();
        let started = Instant::now();

        client.stop_for_drop();

        assert!(client.child.try_wait().unwrap().is_some());
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(client.stdin.is_none());
        assert!(client.stdout_thread.is_none());
        assert!(client.stderr_thread.is_none());
    }

    fn shell_client(script: &str, timeout: Duration) -> WorkerClient {
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg(script);
        WorkerClient::spawn_command(command, "test".to_owned(), timeout).unwrap()
    }
}
