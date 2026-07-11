use std::{
    collections::BTreeSet,
    fmt,
    fs::{self, File},
    io::{self, BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, ExitStatus, Stdio},
    sync::{
        Arc, Mutex,
        mpsc::{self, Receiver, RecvTimeoutError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use visa_conformance::{
    STAGE1_CASE_DEFINITIONS, STAGE1_SEMANTIC_TRACE_SCHEMA_VERSION, Stage1CaseClass,
    Stage1CaseDefinition, Stage1CaseOutcome, Stage1ExpectedOwnership, Stage1FaultInjection,
    Stage1FaultSchedule, Stage1JournalScope, Stage1OwnershipStatus, Stage1PerformanceMetric,
    Stage1SemanticTraceArtifact, Stage1TraceRole, stage1_expected_ownership,
};
use visa_runtime::canonical_digest;

use crate::{
    evidence::{
        BindingReceiptArtifact, CaseAuthorityRecord, CaseExecutionRecord, PerformanceMeasurement,
    },
    fixture::{
        AuthorityPolicyMode, FixtureOptions, FixtureSpec, NamespaceAvailability, derive_identity,
    },
    protocol::{
        CrashMode, DestinationSupportMode, FaultObservationView, FaultPointSpec, LeaseRecordView,
        PROTOCOL_VERSION, RequestEnvelope, RequiredAuthority, ResponseEnvelope, ResponseOutcome,
        SafePointTimerView, SnapshotExpectationOverrides, StateView, TimerPollView, WorkerCommand,
        WorkerError, WorkerErrorCode, WorkerResult, WorkerRole, WorkloadPhaseView,
    },
};

const EXIT_POLL_INTERVAL: Duration = Duration::from_millis(5);
const DROP_GRACE_PERIOD: Duration = Duration::from_millis(100);
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const WORKER_TIMEOUT: Duration = Duration::from_secs(10);
const TIMER_MARGIN: Duration = Duration::from_millis(20);

#[derive(Clone, Copy, Debug, Serialize)]
struct FaultCoverageManifestEntry {
    point: FaultPointSpec,
    case_id: &'static str,
    role: &'static str,
    trigger: &'static str,
    expected: &'static str,
}

const STAGE1_PROVIDER_FAULT_COVERAGE: &[FaultCoverageManifestEntry] = &[
    FaultCoverageManifestEntry {
        point: FaultPointSpec::BeforeJournalWrite,
        case_id: "evidence-verification",
        role: "supplemental-source",
        trigger: "first component effect journal intent",
        expected: "write rejected before persistence; restart retries from durable activation",
    },
    FaultCoverageManifestEntry {
        point: FaultPointSpec::AfterJournalWrite,
        case_id: "evidence-verification",
        role: "supplemental-source",
        trigger: "first component effect journal intent",
        expected: "lost acknowledgement reconciled against the durable journal",
    },
    FaultCoverageManifestEntry {
        point: FaultPointSpec::BeforeActivationBundle,
        case_id: "evidence-verification",
        role: "supplemental-source",
        trigger: "source activation bundle",
        expected: "activation and initial leases remain absent before retry",
    },
    FaultCoverageManifestEntry {
        point: FaultPointSpec::AfterActivationBundle,
        case_id: "evidence-verification",
        role: "supplemental-source",
        trigger: "source activation bundle",
        expected: "lost acknowledgement reconciled against journal and both leases",
    },
    FaultCoverageManifestEntry {
        point: FaultPointSpec::BeforeCommitBundle,
        case_id: "durable-journal-or-commit-write-fails",
        role: "destination",
        trigger: "handoff commit bundle",
        expected: "commit rejected and source resumed under the old epoch",
    },
    FaultCoverageManifestEntry {
        point: FaultPointSpec::AfterCommitBundle,
        case_id: "commit-acknowledgement-lost",
        role: "destination",
        trigger: "handoff commit bundle",
        expected: "lost acknowledgement reconciled to durable destination ownership",
    },
    FaultCoverageManifestEntry {
        point: FaultPointSpec::AfterKvCommit,
        case_id: "kv-unknown-outcome",
        role: "source",
        trigger: "key-value compare-and-set",
        expected: "operation identity reconciles the committed provider outcome",
    },
];

#[derive(Clone, Debug)]
pub struct Stage1RunOutput {
    pub records: Vec<CaseExecutionRecord>,
    pub started_at_unix_ms: u64,
    pub finished_at_unix_ms: u64,
    pub source_digest: contract_core::Digest,
    pub toolchain_digest: contract_core::Digest,
    pub config_digest: contract_core::Digest,
    pub policy_digest: contract_core::Digest,
    pub source_manifest_path: PathBuf,
    pub toolchain_provenance_path: PathBuf,
    pub matrix_manifest_path: PathBuf,
}

#[derive(Debug)]
pub enum RunnerError {
    Io { operation: &'static str, path: PathBuf, source: io::Error },
    Json { context: String, detail: String },
    Worker { case_id: String, role: &'static str, source: WorkerClientError },
    Assertion { case_id: String, detail: String },
    Fixture { case_id: String, detail: String },
    Registry { detail: String },
    Clock,
}

impl fmt::Display for RunnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, path, source } => {
                write!(formatter, "{operation} {}: {source}", path.display())
            }
            Self::Json { context, detail } => write!(formatter, "{context}: {detail}"),
            Self::Worker { case_id, role, source } => {
                write!(formatter, "{case_id} {role} worker: {source}")
            }
            Self::Assertion { case_id, detail } => {
                write!(formatter, "{case_id} assertion failed: {detail}")
            }
            Self::Fixture { case_id, detail } => {
                write!(formatter, "{case_id} fixture failed: {detail}")
            }
            Self::Registry { detail } => write!(formatter, "Stage 1 registry: {detail}"),
            Self::Clock => formatter.write_str("system clock is before the Unix epoch"),
        }
    }
}

impl std::error::Error for RunnerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Worker { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CaseKind {
    TimerPositive,
    TimerPaused,
    TimerCompleted,
    TimerCancelled,
    AuthorityNarrower,
    KvDuplicate,
    RepeatedValidationPrepare,
    JournalReplay,
    StaleSource,
    EvidenceVerification,
    Performance,
    SafePointUnreachable,
    UnsupportedLiveResource,
    KvUnknown,
    CorruptSnapshot,
    IncompatibleVersion,
    ProfileMismatch,
    MissingAuthority,
    RevokedCapability,
    BroaderAuthority,
    MissingNamespace,
    TimerUnsupported,
    CrashBeforeCommit,
    DuplicatePrepare,
    LostCommitAck,
    SourceCommitRace,
    CrashAfterCommit,
    DuplicateRestore,
    RepeatedCleanup,
    DurableWriteFailure,
    ReportFailure,
}

fn case_kind(case_id: &str) -> Option<CaseKind> {
    Some(match case_id {
        "timer-positive-duration-at-freeze" => CaseKind::TimerPositive,
        "timer-paused-during-long-handoff" => CaseKind::TimerPaused,
        "timer-completes-during-quiescence" => CaseKind::TimerCompleted,
        "timer-cancelled-during-quiescence" => CaseKind::TimerCancelled,
        "authority-sufficient-narrower" => CaseKind::AuthorityNarrower,
        "kv-duplicate-idempotent-request" => CaseKind::KvDuplicate,
        "handoff-repeated-validation-prepare" => CaseKind::RepeatedValidationPrepare,
        "journal-replay" => CaseKind::JournalReplay,
        "source-post-commit-stale-attempt" => CaseKind::StaleSource,
        "evidence-verification" => CaseKind::EvidenceVerification,
        "performance-observations" => CaseKind::Performance,
        "safe-point-unreachable" => CaseKind::SafePointUnreachable,
        "unsupported-live-resource-or-borrow" => CaseKind::UnsupportedLiveResource,
        "kv-unknown-outcome" => CaseKind::KvUnknown,
        "corrupt-snapshot-or-component-digest" => CaseKind::CorruptSnapshot,
        "incompatible-snapshot-or-profile-version" => CaseKind::IncompatibleVersion,
        "unknown-extension-or-profile-mismatch" => CaseKind::ProfileMismatch,
        "destination-authority-missing-or-insufficient" => CaseKind::MissingAuthority,
        "required-capability-revoked" => CaseKind::RevokedCapability,
        "adapter-broader-authority" => CaseKind::BroaderAuthority,
        "kv-binding-wrong-or-missing" => CaseKind::MissingNamespace,
        "timer-semantics-unsupported" => CaseKind::TimerUnsupported,
        "destination-crash-before-commit" => CaseKind::CrashBeforeCommit,
        "prepare-message-duplicate-or-lost" => CaseKind::DuplicatePrepare,
        "commit-acknowledgement-lost" => CaseKind::LostCommitAck,
        "source-races-with-commit" => CaseKind::SourceCommitRace,
        "destination-crash-after-commit" => CaseKind::CrashAfterCommit,
        "duplicate-restore-or-stale-snapshot" => CaseKind::DuplicateRestore,
        "repeated-cancel-abort-cleanup" => CaseKind::RepeatedCleanup,
        "durable-journal-or-commit-write-fails" => CaseKind::DurableWriteFailure,
        "report-generation-fails-after-commit" => CaseKind::ReportFailure,
        _ => return None,
    })
}

#[derive(Clone, Debug, Serialize)]
struct CasePlan {
    case_id: String,
    options: FixtureOptions,
    source_fault: Option<FaultPointSpec>,
    destination_fault: Option<FaultPointSpec>,
    destination_support: DestinationSupportMode,
    scenario: String,
}

impl CasePlan {
    fn new(definition: &Stage1CaseDefinition) -> Result<Self, RunnerError> {
        let kind = case_kind(definition.id).ok_or_else(|| RunnerError::Registry {
            detail: format!("{} has no executable scenario", definition.id),
        })?;
        let mut options = FixtureOptions::new(definition.id);
        let mut source_fault = None;
        let mut destination_fault = None;
        let mut destination_support = DestinationSupportMode::Compatible;
        match kind {
            CaseKind::KvUnknown => source_fault = Some(FaultPointSpec::AfterKvCommit),
            CaseKind::MissingAuthority => {
                options.authority_policy = AuthorityPolicyMode::Missing;
            }
            CaseKind::BroaderAuthority => {
                options.authority_policy = AuthorityPolicyMode::Broader;
            }
            CaseKind::MissingNamespace => {
                options.namespace_availability = NamespaceAvailability::Missing;
            }
            CaseKind::TimerUnsupported => {
                destination_support = DestinationSupportMode::TimerSemanticsUnsupported;
            }
            CaseKind::LostCommitAck => {
                destination_fault = Some(FaultPointSpec::AfterCommitBundle);
            }
            CaseKind::DurableWriteFailure => {
                destination_fault = Some(FaultPointSpec::BeforeCommitBundle);
            }
            _ => {}
        }
        Ok(Self {
            case_id: definition.id.to_owned(),
            options,
            source_fault,
            destination_fault,
            destination_support,
            scenario: format!("{kind:?}"),
        })
    }
}

#[derive(Clone, Debug, Serialize)]
struct MatrixEntry {
    case_id: String,
    options: FixtureOptions,
    config_digest: contract_core::Digest,
    policy_digest: contract_core::Digest,
    source_fault: Option<FaultPointSpec>,
    destination_fault: Option<FaultPointSpec>,
    destination_support: DestinationSupportMode,
    scenario: String,
}

#[derive(Clone, Debug, Serialize)]
struct MatrixManifest {
    schema: &'static str,
    entries: Vec<MatrixEntry>,
    provider_fault_coverage: Vec<FaultCoverageManifestEntry>,
}

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
        })
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
        let response = self.request(command)?;
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

fn exit_status_text(status: ExitStatus) -> String {
    match status.code() {
        Some(code) => format!("code {code}"),
        None => "terminated by signal".to_owned(),
    }
}

pub fn run_stage1(
    executable: impl AsRef<Path>,
    output_root: impl AsRef<Path>,
) -> Result<Stage1RunOutput, RunnerError> {
    let executable = executable.as_ref().to_path_buf();
    let output_root = output_root.as_ref();
    fs::create_dir_all(output_root)
        .map_err(|source| runner_io("create Stage 1 output root", output_root, source))?;
    let started_at_unix_ms = unix_time_ms()?;
    let provenance_root = output_root.join("provenance");
    fs::create_dir_all(&provenance_root)
        .map_err(|source| runner_io("create provenance directory", &provenance_root, source))?;

    let workspace_root = workspace_root()?;
    let (source_digest, source_manifest) = source_provenance(&workspace_root)?;
    let source_manifest_path = provenance_root.join("source-manifest.json");
    write_pretty_json(&source_manifest_path, &source_manifest)?;
    let (toolchain_digest, toolchain_raw) = toolchain_provenance()?;
    let toolchain_provenance_path = provenance_root.join("toolchain.txt");
    fs::write(&toolchain_provenance_path, &toolchain_raw).map_err(|source| {
        runner_io("write toolchain provenance", &toolchain_provenance_path, source)
    })?;

    let mut plans = Vec::with_capacity(STAGE1_CASE_DEFINITIONS.len());
    let mut matrix_entries = Vec::with_capacity(STAGE1_CASE_DEFINITIONS.len());
    let mut seen = BTreeSet::new();
    for definition in STAGE1_CASE_DEFINITIONS {
        if !seen.insert(definition.id) {
            return Err(RunnerError::Registry {
                detail: format!("duplicate case id {}", definition.id),
            });
        }
        let plan = CasePlan::new(definition)?;
        let fixture = FixtureSpec::with_options(plan.options.clone()).map_err(|error| {
            RunnerError::Fixture { case_id: definition.id.to_owned(), detail: error.to_string() }
        })?;
        matrix_entries.push(MatrixEntry {
            case_id: plan.case_id.clone(),
            options: plan.options.clone(),
            config_digest: fixture.config_digest().map_err(|error| RunnerError::Fixture {
                case_id: definition.id.to_owned(),
                detail: error.to_string(),
            })?,
            policy_digest: fixture.policy_digest().map_err(|error| RunnerError::Fixture {
                case_id: definition.id.to_owned(),
                detail: error.to_string(),
            })?,
            source_fault: plan.source_fault,
            destination_fault: plan.destination_fault,
            destination_support: plan.destination_support,
            scenario: plan.scenario.clone(),
        });
        plans.push(plan);
    }
    let config_projection = matrix_entries
        .iter()
        .map(|entry| {
            (
                entry.case_id.as_str(),
                &entry.options,
                entry.config_digest,
                entry.source_fault,
                entry.destination_fault,
                entry.destination_support,
                entry.scenario.as_str(),
            )
        })
        .collect::<Vec<_>>();
    let policy_projection = matrix_entries
        .iter()
        .map(|entry| {
            (
                entry.case_id.as_str(),
                entry.policy_digest,
                entry.options.authority_policy,
                entry.destination_support,
                entry.scenario.as_str(),
            )
        })
        .collect::<Vec<_>>();
    let provider_fault_coverage = STAGE1_PROVIDER_FAULT_COVERAGE.to_vec();
    let config_digest =
        canonical_digest(&(config_projection, &provider_fault_coverage)).map_err(|_| {
            RunnerError::Registry { detail: "cannot encode Stage 1 config matrix".to_owned() }
        })?;
    let policy_digest = canonical_digest(&policy_projection).map_err(|_| {
        RunnerError::Registry { detail: "cannot encode Stage 1 policy matrix".to_owned() }
    })?;
    let matrix_manifest = MatrixManifest {
        schema: "visa-stage1-matrix-provenance-v1",
        entries: matrix_entries,
        provider_fault_coverage,
    };
    let matrix_manifest_path = provenance_root.join("matrix.json");
    write_pretty_json(&matrix_manifest_path, &matrix_manifest)?;

    let work_root = output_root.join(".runner-work");
    fs::create_dir_all(&work_root)
        .map_err(|source| runner_io("create runner work directory", &work_root, source))?;
    let mut records = Vec::with_capacity(STAGE1_CASE_DEFINITIONS.len());
    for (definition, plan) in STAGE1_CASE_DEFINITIONS.iter().zip(plans) {
        let mut harness = CaseHarness::new(&executable, &work_root, definition, plan)?;
        let outcome = execute_case(&mut harness)?;
        records.push(harness.finish(outcome)?);
    }
    let toolchain_text = String::from_utf8(toolchain_raw).map_err(|error| RunnerError::Json {
        context: "decode toolchain provenance as UTF-8".to_owned(),
        detail: error.to_string(),
    })?;
    let provenance_assertion = serde_json::json!({
        "name": "stage1-provenance-inputs",
        "algorithms": {
            "source_digest": "sha-256 over compact deterministic source_manifest JSON bytes",
            "toolchain_digest": "sha-256 over toolchain_raw UTF-8 bytes",
            "config_digest": "sha-256 over postcard-1.1.3 config matrix and provider fault coverage projection",
            "policy_digest": "sha-256 over postcard-1.1.3 policy matrix projection"
        },
        "source_manifest": source_manifest,
        "toolchain_raw": toolchain_text,
        "matrix_manifest": matrix_manifest,
        "digests": {
            "source": digest_hex(source_digest),
            "toolchain": digest_hex(toolchain_digest),
            "config": digest_hex(config_digest),
            "policy": digest_hex(policy_digest)
        }
    });
    let evidence_record = records
        .iter_mut()
        .find(|record| record.case_id == "evidence-verification")
        .ok_or_else(|| RunnerError::Registry {
            detail: "evidence-verification execution record is missing".to_owned(),
        })?;
    serde_json::to_writer(&mut evidence_record.raw_assertions_json, &provenance_assertion)
        .map_err(|error| RunnerError::Json {
            context: "encode provenance assertion".to_owned(),
            detail: error.to_string(),
        })?;
    evidence_record.raw_assertions_json.push(b'\n');
    let finished_at_unix_ms = unix_time_ms()?;
    Ok(Stage1RunOutput {
        records,
        started_at_unix_ms,
        finished_at_unix_ms,
        source_digest,
        toolchain_digest,
        config_digest,
        policy_digest,
        source_manifest_path,
        toolchain_provenance_path,
        matrix_manifest_path,
    })
}

#[derive(Serialize)]
struct SourceManifest {
    schema: &'static str,
    files: Vec<SourceFileManifest>,
}

#[derive(Serialize)]
struct SourceFileManifest {
    path: String,
    bytes: u64,
    sha256: String,
}

fn source_provenance(
    workspace_root: &Path,
) -> Result<(contract_core::Digest, SourceManifest), RunnerError> {
    const ROOTS: &[&str] = &[
        "Cargo.toml",
        "Cargo.lock",
        "wit/cooperative-handoff",
        "crates/core/contract_core",
        "crates/core/semantic_core",
        "crates/core/visa_profile",
        "crates/backend/substrate_api",
        "crates/backend/substrate_host",
        "crates/runtime/visa_runtime",
        "crates/runtime/visa_wasmtime",
        "crates/testing/handoff-component",
        "crates/testing/visa-conformance",
        "crates/testing/visa-system",
        "scripts/check-dependency-direction.py",
        "scripts/ci-gate.sh",
        "scripts/run-report-gates.sh",
        "scripts/check-conformance-report.sh",
    ];
    let mut paths = Vec::new();
    for relative in ROOTS {
        collect_source_files(&workspace_root.join(relative), &mut paths)?;
    }
    paths.sort_by_key(|path| {
        path.strip_prefix(workspace_root).unwrap_or(path).to_string_lossy().into_owned()
    });
    paths.dedup();
    let mut files = Vec::with_capacity(paths.len());
    for path in paths {
        let relative = path.strip_prefix(workspace_root).map_err(|_| RunnerError::Registry {
            detail: format!("source path {} escaped workspace", path.display()),
        })?;
        let relative = relative.to_string_lossy().replace('\u{5c}', "/");
        let bytes = fs::read(&path)
            .map_err(|source| runner_io("read source provenance input", &path, source))?;
        files.push(SourceFileManifest {
            path: relative,
            bytes: bytes.len() as u64,
            sha256: sha256_hex(&bytes),
        });
    }
    let manifest = SourceManifest { schema: "visa-stage1-source-manifest-v1", files };
    let canonical_json = serde_json::to_vec(&manifest).map_err(|error| RunnerError::Json {
        context: "encode deterministic source manifest".to_owned(),
        detail: error.to_string(),
    })?;
    Ok((sha256_digest(&canonical_json), manifest))
}

fn collect_source_files(path: &Path, files: &mut Vec<PathBuf>) -> Result<(), RunnerError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| runner_io("inspect source provenance input", path, source))?;
    if metadata.file_type().is_symlink() {
        return Err(RunnerError::Registry {
            detail: format!("source provenance path {} is a symlink", path.display()),
        });
    }
    if metadata.is_file() {
        files.push(path.to_path_buf());
        return Ok(());
    }
    let mut entries = fs::read_dir(path)
        .map_err(|source| runner_io("read source provenance directory", path, source))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| runner_io("read source provenance entry", path, source))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        collect_source_files(&entry.path(), files)?;
    }
    Ok(())
}

fn toolchain_provenance() -> Result<(contract_core::Digest, Vec<u8>), RunnerError> {
    let mut raw = Vec::new();
    for (program, argument) in [("rustc", "-vV"), ("cargo", "-V")] {
        let output = Command::new(program)
            .arg(argument)
            .output()
            .map_err(|source| runner_io("run toolchain provenance command", program, source))?;
        raw.extend_from_slice(format!("$ {program} {argument}\n").as_bytes());
        raw.extend_from_slice(&output.stdout);
        raw.extend_from_slice(&output.stderr);
        if !output.status.success() {
            return Err(RunnerError::Registry {
                detail: format!(
                    "{program} {argument} exited as {}",
                    exit_status_text(output.status)
                ),
            });
        }
    }
    Ok((sha256_digest(&raw), raw))
}

fn workspace_root() -> Result<PathBuf, RunnerError> {
    Path::new(env!("CARGO_MANIFEST_DIR")).ancestors().nth(3).map(Path::to_path_buf).ok_or_else(
        || RunnerError::Registry {
            detail: "cannot resolve workspace root from CARGO_MANIFEST_DIR".to_owned(),
        },
    )
}

fn write_pretty_json(path: &Path, value: &impl Serialize) -> Result<(), RunnerError> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| RunnerError::Json {
        context: format!("encode {}", path.display()),
        detail: error.to_string(),
    })?;
    bytes.push(b'\n');
    fs::write(path, bytes).map_err(|source| runner_io("write JSON artifact", path, source))
}

fn unix_time_ms() -> Result<u64, RunnerError> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| RunnerError::Clock)?;
    u64::try_from(duration.as_millis()).map_err(|_| RunnerError::Clock)
}

fn sha256_digest(bytes: &[u8]) -> contract_core::Digest {
    contract_core::Digest::from_bytes(Sha256::digest(bytes).into())
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn runner_io(operation: &'static str, path: impl AsRef<Path>, source: io::Error) -> RunnerError {
    RunnerError::Io { operation, path: path.as_ref().to_path_buf(), source }
}

#[derive(Clone)]
struct SnapshotTransfer {
    envelope: Option<contract_core::SnapshotEnvelope>,
    component_state: Vec<u8>,
    timer: SafePointTimerView,
}

#[derive(Clone)]
struct DumpData {
    canonical_state: contract_core::CanonicalState,
    state_digest: contract_core::Digest,
    journal: Vec<contract_core::JournalEntry>,
    leases: Vec<LeaseRecordView>,
    binding_receipts: Vec<contract_core::BindingReceipt>,
    fault_observation: Option<FaultObservationView>,
    key_value_entry: Option<contract_core::VersionedValue>,
    component_instantiated: bool,
    component: Option<crate::protocol::ComponentStatusView>,
    portable_component_state: Option<Vec<u8>>,
}

impl DumpData {
    fn from_result(case_id: &str, result: WorkerResult) -> Result<Self, RunnerError> {
        let WorkerResult::Dump {
            canonical_state,
            state_digest,
            journal,
            leases,
            binding_receipts,
            fault_observation,
            key_value_entry,
            component_instantiated,
            component,
            portable_component_state,
            ..
        } = result
        else {
            return Err(RunnerError::Assertion {
                case_id: case_id.to_owned(),
                detail: format!("Dump returned {result:?}"),
            });
        };
        Ok(Self {
            canonical_state: *canonical_state,
            state_digest,
            journal,
            leases,
            binding_receipts,
            fault_observation,
            key_value_entry,
            component_instantiated,
            component,
            portable_component_state,
        })
    }
}

#[derive(Serialize)]
struct AssertionObservation {
    name: String,
    detail: String,
    case_config_digest: contract_core::Digest,
    case_policy_digest: contract_core::Digest,
}

struct ArchivedTranscript {
    label: String,
    pid: u32,
    lines: Vec<TranscriptLine>,
}

#[derive(Serialize)]
struct RawTranscriptLine<'a> {
    worker: &'a str,
    pid: u32,
    sequence: u64,
    stream: TranscriptStream,
    line: &'a str,
}

struct CaseDatabase(PathBuf);

impl CaseDatabase {
    fn new(work_root: &Path, case_id: &str) -> Result<Self, RunnerError> {
        let path = work_root.join(format!("{case_id}.sqlite3"));
        remove_database_files(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for CaseDatabase {
    fn drop(&mut self) {
        let _ = remove_database_files(&self.0);
    }
}

struct CaseHarness {
    definition: &'static Stage1CaseDefinition,
    plan: CasePlan,
    fixture: FixtureSpec,
    executable: PathBuf,
    work_root: PathBuf,
    database: CaseDatabase,
    source: Option<WorkerClient>,
    destination: Option<WorkerClient>,
    source_transcripts: Vec<ArchivedTranscript>,
    destination_transcripts: Vec<ArchivedTranscript>,
    snapshot: Option<SnapshotTransfer>,
    destination_base: Option<DumpData>,
    latest_source: Option<StateView>,
    latest_destination: Option<StateView>,
    assertions: Vec<AssertionObservation>,
    performance: Vec<PerformanceMeasurement>,
    measure_performance: bool,
    handoff_started: Option<Instant>,
    config_digest: contract_core::Digest,
    policy_digest: contract_core::Digest,
}

impl CaseHarness {
    fn new(
        executable: &Path,
        work_root: &Path,
        definition: &'static Stage1CaseDefinition,
        plan: CasePlan,
    ) -> Result<Self, RunnerError> {
        let fixture = FixtureSpec::with_options(plan.options.clone()).map_err(|error| {
            RunnerError::Fixture { case_id: definition.id.to_owned(), detail: error.to_string() }
        })?;
        let config_digest = fixture.config_digest().map_err(|error| RunnerError::Fixture {
            case_id: definition.id.to_owned(),
            detail: error.to_string(),
        })?;
        let policy_digest = fixture.policy_digest().map_err(|error| RunnerError::Fixture {
            case_id: definition.id.to_owned(),
            detail: error.to_string(),
        })?;
        let database = CaseDatabase::new(work_root, definition.id)?;
        let source = spawn_initialized(
            executable,
            definition.id,
            "source",
            WorkerRole::Source,
            database.path(),
            &plan.options,
            plan.source_fault,
        )?;
        let destination = spawn_initialized(
            executable,
            definition.id,
            "destination",
            WorkerRole::Destination,
            database.path(),
            &plan.options,
            plan.destination_fault,
        )?;
        let mut harness = Self {
            definition,
            plan,
            fixture,
            executable: executable.to_path_buf(),
            work_root: work_root.to_path_buf(),
            database,
            source: Some(source),
            destination: Some(destination),
            source_transcripts: Vec::new(),
            destination_transcripts: Vec::new(),
            snapshot: None,
            destination_base: None,
            latest_source: None,
            latest_destination: None,
            assertions: Vec::new(),
            performance: Vec::new(),
            measure_performance: case_kind(definition.id) == Some(CaseKind::Performance),
            handoff_started: None,
            config_digest,
            policy_digest,
        };
        let source_pid = harness.source().pid();
        let destination_pid = harness.destination().pid();
        harness.observe(
            "independent-worker-pids",
            source_pid != destination_pid,
            format!("source={source_pid}, destination={destination_pid}"),
        )?;
        harness.observe("case-config-digest", true, digest_hex(config_digest))?;
        harness.observe("case-policy-digest", true, digest_hex(policy_digest))?;
        Ok(harness)
    }

    fn source(&self) -> &WorkerClient {
        self.source.as_ref().expect("source worker is present")
    }

    fn source_mut(&mut self) -> &mut WorkerClient {
        self.source.as_mut().expect("source worker is present")
    }

    fn destination(&self) -> &WorkerClient {
        self.destination.as_ref().expect("destination worker is present")
    }

    fn destination_mut(&mut self) -> &mut WorkerClient {
        self.destination.as_mut().expect("destination worker is present")
    }

    fn source_success(&mut self, command: WorkerCommand) -> Result<WorkerResult, RunnerError> {
        self.source_mut()
            .request_success(command)
            .map_err(|source| self.worker_error("source", source))
    }

    fn destination_success(&mut self, command: WorkerCommand) -> Result<WorkerResult, RunnerError> {
        self.destination_mut()
            .request_success(command)
            .map_err(|source| self.worker_error("destination", source))
    }

    fn source_rejection(&mut self, command: WorkerCommand) -> Result<WorkerError, RunnerError> {
        let response = self
            .source_mut()
            .request(command)
            .map_err(|source| self.worker_error("source", source))?;
        self.rejection("source", response)
    }

    fn destination_rejection(
        &mut self,
        command: WorkerCommand,
    ) -> Result<WorkerError, RunnerError> {
        let response = self
            .destination_mut()
            .request(command)
            .map_err(|source| self.worker_error("destination", source))?;
        self.rejection("destination", response)
    }

    fn rejection(
        &self,
        role: &'static str,
        response: ResponseEnvelope,
    ) -> Result<WorkerError, RunnerError> {
        match response.outcome {
            ResponseOutcome::Error { error } => Ok(error),
            ResponseOutcome::Success { result } => Err(RunnerError::Assertion {
                case_id: self.definition.id.to_owned(),
                detail: format!("{role} command unexpectedly succeeded with {result:?}"),
            }),
        }
    }

    fn worker_error(&self, role: &'static str, source: WorkerClientError) -> RunnerError {
        RunnerError::Worker { case_id: self.definition.id.to_owned(), role, source }
    }

    fn observe(
        &mut self,
        name: impl Into<String>,
        passed: bool,
        detail: impl Into<String>,
    ) -> Result<(), RunnerError> {
        let base_name = name.into();
        let name = if self.assertions.iter().any(|assertion| assertion.name == base_name) {
            let mut occurrence = 2;
            loop {
                let candidate = format!("{base_name}-occurrence-{occurrence}");
                if !self.assertions.iter().any(|assertion| assertion.name == candidate) {
                    break candidate;
                }
                occurrence += 1;
            }
        } else {
            base_name
        };
        let detail = detail.into();
        if !passed {
            return Err(RunnerError::Assertion {
                case_id: self.definition.id.to_owned(),
                detail: format!("{name}: {detail}"),
            });
        }
        self.assertions.push(AssertionObservation {
            name,
            detail,
            case_config_digest: self.config_digest,
            case_policy_digest: self.policy_digest,
        });
        Ok(())
    }

    fn bootstrap(&mut self) -> Result<StateView, RunnerError> {
        let result = self.source_success(WorkerCommand::BootstrapSource)?;
        let view = state_result(self.definition.id, result)?;
        self.observe(
            "source-running",
            view.canonical_phase == contract_core::HandoffPhase::Running,
            format!("phase={:?}", view.canonical_phase),
        )?;
        self.latest_source = Some(view.clone());
        Ok(view)
    }

    fn begin_quiesce(&mut self) -> Result<StateView, RunnerError> {
        self.handoff_started.get_or_insert_with(Instant::now);
        let result = self.source_success(WorkerCommand::BeginQuiesce)?;
        let view = state_result(self.definition.id, result)?;
        self.observe(
            "source-quiescing",
            view.canonical_phase == contract_core::HandoffPhase::Quiescing,
            format!("phase={:?}", view.canonical_phase),
        )?;
        self.latest_source = Some(view.clone());
        Ok(view)
    }

    fn freeze(&mut self) -> Result<SnapshotTransfer, RunnerError> {
        let result = self.source_success(WorkerCommand::FreezeSource)?;
        let WorkerResult::SafePoint { component_state, timer, view } = result else {
            return Err(RunnerError::Assertion {
                case_id: self.definition.id.to_owned(),
                detail: format!("FreezeSource returned {result:?}"),
            });
        };
        self.observe(
            "source-frozen",
            view.canonical_phase == contract_core::HandoffPhase::Frozen,
            format!("phase={:?}, timer={timer:?}", view.canonical_phase),
        )?;
        self.latest_source = Some(view);
        Ok(SnapshotTransfer { envelope: None, component_state, timer })
    }

    fn export(&mut self, mut transfer: SnapshotTransfer) -> Result<SnapshotTransfer, RunnerError> {
        let result = self.source_success(WorkerCommand::ExportSourceSnapshot)?;
        let WorkerResult::Snapshot { envelope, component_state, view } = result else {
            return Err(RunnerError::Assertion {
                case_id: self.definition.id.to_owned(),
                detail: format!("ExportSourceSnapshot returned {result:?}"),
            });
        };
        self.observe(
            "snapshot-component-state",
            component_state == transfer.component_state
                && envelope.body.portable_state == transfer.component_state,
            format!(
                "worker={} bytes, envelope={} bytes",
                component_state.len(),
                envelope.body.portable_state.len()
            ),
        )?;
        self.latest_source = Some(view);
        transfer.envelope = Some(*envelope);
        self.snapshot = Some(transfer.clone());
        Ok(transfer)
    }

    fn bootstrap_snapshot(&mut self) -> Result<SnapshotTransfer, RunnerError> {
        self.bootstrap()?;
        self.begin_quiesce()?;
        let transfer = self.freeze()?;
        self.export(transfer)
    }

    fn validate_destination(
        &mut self,
        envelope: contract_core::SnapshotEnvelope,
        expectations: SnapshotExpectationOverrides,
        support: DestinationSupportMode,
    ) -> Result<WorkerResult, RunnerError> {
        self.destination_success(WorkerCommand::ValidateDestination {
            envelope,
            expectations,
            support,
        })
    }

    fn load_destination(
        &mut self,
        allowed_phases: &[contract_core::HandoffPhase],
    ) -> Result<StateView, RunnerError> {
        let transfer = self.snapshot.clone().ok_or_else(|| RunnerError::Assertion {
            case_id: self.definition.id.to_owned(),
            detail: "destination load requires a snapshot".to_owned(),
        })?;
        let result = self.destination_success(WorkerCommand::LoadDestination {
            envelope: transfer.envelope.ok_or_else(|| RunnerError::Assertion {
                case_id: self.definition.id.to_owned(),
                detail: "destination load requires an exported envelope".to_owned(),
            })?,
            component_state: transfer.component_state,
        })?;
        let view = state_result(self.definition.id, result)?;
        self.observe(
            "destination-load-replays-allowed-phase",
            allowed_phases.contains(&view.canonical_phase),
            format!("phase={:?}", view.canonical_phase),
        )?;
        self.latest_destination = Some(view.clone());
        let dump = self.dump_destination()?;
        if self.destination_base.is_none() {
            self.destination_base = Some(dump.clone());
        }
        let owner = dump.canonical_state.ownership.owner;
        let epoch = dump.canonical_state.ownership.epoch;
        self.observe(
            "destination-load-does-not-self-activate-or-change-leases",
            !view.component_instantiated
                && !dump.component_instantiated
                && dump.component.is_none()
                && owner.is_some()
                && dump
                    .leases
                    .iter()
                    .all(|lease| Some(lease.owner) == owner && lease.epoch == epoch),
            format!(
                "component_instantiated={}/{}, component={:?}, ownership={:?}, leases={:?}",
                view.component_instantiated,
                dump.component_instantiated,
                dump.component,
                dump.canonical_state.ownership,
                dump.leases
            ),
        )?;
        Ok(view)
    }

    fn prepare_destination(&mut self) -> Result<StateView, RunnerError> {
        let result = self.destination_success(WorkerCommand::PrepareDestination)?;
        let view = state_result(self.definition.id, result)?;
        self.observe(
            "destination-prepared-inactive",
            view.canonical_phase == contract_core::HandoffPhase::DestinationPrepared
                && !view.component_instantiated,
            format!(
                "phase={:?}, component_instantiated={}",
                view.canonical_phase, view.component_instantiated
            ),
        )?;
        self.latest_destination = Some(view.clone());
        Ok(view)
    }

    fn commit_destination(&mut self) -> Result<StateView, RunnerError> {
        let result = self.destination_success(WorkerCommand::CommitDestination)?;
        let view = state_result(self.definition.id, result)?;
        self.observe(
            "destination-committed",
            view.canonical_phase == contract_core::HandoffPhase::Committed
                && !view.component_instantiated,
            format!(
                "phase={:?}, component_instantiated={}",
                view.canonical_phase, view.component_instantiated
            ),
        )?;
        self.latest_destination = Some(view.clone());
        Ok(view)
    }

    fn resume_destination(&mut self) -> Result<StateView, RunnerError> {
        let result = self.destination_success(WorkerCommand::ResumeDestination)?;
        let view = state_result(self.definition.id, result)?;
        self.observe(
            "destination-running",
            view.canonical_phase == contract_core::HandoffPhase::Running
                && view.component_instantiated,
            format!(
                "phase={:?}, component_instantiated={}",
                view.canonical_phase, view.component_instantiated
            ),
        )?;
        if self.measure_performance
            && let Some(started) = self.handoff_started.take()
        {
            self.performance.push(PerformanceMeasurement {
                metric: Stage1PerformanceMetric::HandoffInterruption,
                samples: vec![elapsed_nanos(started)],
            });
        }
        self.latest_destination = Some(view.clone());
        Ok(view)
    }

    fn normal_commit(&mut self) -> Result<(), RunnerError> {
        self.load_destination(&[contract_core::HandoffPhase::Exported])?;
        self.prepare_destination()?;
        self.commit_destination()?;
        self.resume_destination()?;
        Ok(())
    }

    fn pending_timer(
        &self,
    ) -> Result<(contract_core::LogicalDurationNanos, contract_core::Identity), RunnerError> {
        let timer = self
            .snapshot
            .as_ref()
            .ok_or_else(|| RunnerError::Assertion {
                case_id: self.definition.id.to_owned(),
                detail: "pending timer requires a snapshot".to_owned(),
            })?
            .timer;
        match timer {
            SafePointTimerView::Pending { remaining, arm_operation } => {
                Ok((remaining, arm_operation))
            }
            other => Err(RunnerError::Assertion {
                case_id: self.definition.id.to_owned(),
                detail: format!("expected pending safe-point timer, got {other:?}"),
            }),
        }
    }

    fn deliver_pending_timer(&mut self) -> Result<(), RunnerError> {
        let (remaining, _) = self.pending_timer()?;
        let result = self.destination_success(WorkerCommand::PollTimer { deliver: false })?;
        let (poll, delivered, _) = timer_result(self.definition.id, result)?;
        self.observe(
            "destination-timer-rearmed",
            matches!(poll, TimerPollView::Pending { remaining, .. } if remaining.0 > 0)
                && !delivered,
            format!("poll={poll:?}, delivered={delivered}"),
        )?;
        thread::sleep(Duration::from_nanos(remaining.0) + TIMER_MARGIN);
        for _ in 0..3 {
            let result = self.destination_success(WorkerCommand::PollTimer { deliver: true })?;
            let (poll, delivered, view) = timer_result(self.definition.id, result)?;
            match poll {
                TimerPollView::Fired { .. } => {
                    self.observe(
                        "single-timer-delivery",
                        delivered
                            && view.component.as_ref().is_some_and(|component| {
                                component.phase == WorkloadPhaseView::Completed
                                    && component.expected_version == 2
                            }),
                        format!("delivered={delivered}, component={:?}", view.component),
                    )?;
                    self.latest_destination = Some(view);
                    let repeat =
                        self.destination_success(WorkerCommand::PollTimer { deliver: true })?;
                    let (repeat_poll, repeat_delivered, _) =
                        timer_result(self.definition.id, repeat)?;
                    self.observe(
                        "timer-expiry-not-duplicated",
                        repeat_poll == TimerPollView::Completed && !repeat_delivered,
                        format!("poll={repeat_poll:?}, delivered={repeat_delivered}"),
                    )?;
                    return Ok(());
                }
                TimerPollView::Pending { remaining, .. } => {
                    thread::sleep(Duration::from_nanos(remaining.0) + TIMER_MARGIN);
                }
                other => {
                    return Err(RunnerError::Assertion {
                        case_id: self.definition.id.to_owned(),
                        detail: format!("destination timer produced {other:?}"),
                    });
                }
            }
        }
        Err(RunnerError::Assertion {
            case_id: self.definition.id.to_owned(),
            detail: "destination timer remained pending".to_owned(),
        })
    }

    fn dump_source(&mut self) -> Result<DumpData, RunnerError> {
        let result = self.source_success(WorkerCommand::Dump)?;
        DumpData::from_result(self.definition.id, result)
    }

    fn dump_destination(&mut self) -> Result<DumpData, RunnerError> {
        let result = self.destination_success(WorkerCommand::Dump)?;
        DumpData::from_result(self.definition.id, result)
    }

    fn archive_source(&mut self) -> Result<(), RunnerError> {
        if let Some(client) = self.source.take() {
            self.source_transcripts.push(archive_client(&client)?);
            drop(client);
        }
        Ok(())
    }

    fn archive_destination(&mut self) -> Result<(), RunnerError> {
        if let Some(client) = self.destination.take() {
            self.destination_transcripts.push(archive_client(&client)?);
            drop(client);
        }
        Ok(())
    }

    fn restart_destination(&mut self, label: &str) -> Result<(), RunnerError> {
        self.archive_destination()?;
        self.destination = Some(spawn_initialized(
            &self.executable,
            self.definition.id,
            label,
            WorkerRole::Destination,
            self.database.path(),
            &self.plan.options,
            None,
        )?);
        Ok(())
    }

    fn finish(mut self, outcome: Stage1CaseOutcome) -> Result<CaseExecutionRecord, RunnerError> {
        if !self.definition.allowed_outcomes.contains(&outcome) {
            return Err(RunnerError::Assertion {
                case_id: self.definition.id.to_owned(),
                detail: format!("scenario produced disallowed outcome {outcome:?}"),
            });
        }
        let expected_ownership = stage1_expected_ownership(outcome);
        let live_source = if self.source.as_ref().is_some_and(WorkerClient::is_usable) {
            Some(self.dump_source()?)
        } else {
            None
        };
        let live_destination = if self.latest_destination.is_some()
            && self.destination.as_ref().is_some_and(WorkerClient::is_usable)
        {
            Some(self.dump_destination()?)
        } else {
            None
        };

        let source_replay = match expected_ownership {
            Stage1ExpectedOwnership::SourceRetained
                if outcome == Stage1CaseOutcome::RevocationRejectedNoResurrection =>
            {
                let live = live_source.clone().ok_or_else(|| RunnerError::Assertion {
                    case_id: self.definition.id.to_owned(),
                    detail: "revocation outcome has no live exported source state".to_owned(),
                })?;
                let audit_label = format!("{}-source-audit", self.definition.id);
                let mut source_audit =
                    WorkerClient::spawn(&self.executable, audit_label, WORKER_TIMEOUT)
                        .map_err(|source| self.worker_error("source-audit", source))?;
                let initialization = source_audit
                    .request(WorkerCommand::Initialize {
                        role: WorkerRole::Source,
                        database_path: self.database.path().to_string_lossy().into_owned(),
                        options: self.plan.options.clone(),
                        fault: None,
                    })
                    .map_err(|source| self.worker_error("source-audit", source))?;
                self.source_transcripts.push(archive_client(&source_audit)?);
                drop(source_audit);
                self.observe(
                    "source-recovery-requires-reauthorization",
                    matches!(
                        initialization.outcome,
                        ResponseOutcome::Error { ref error }
                            if error.code == WorkerErrorCode::Provider
                                && error.provider_kind.as_deref() == Some("Revoked")
                    ),
                    format!("response={initialization:?}"),
                )?;
                // Executable recovery must not recreate the revoked timer binding. The typed
                // source trace below remains the independent, pure canonical replay proof.
                live
            }
            Stage1ExpectedOwnership::SourceRetained => {
                let mut source_audit = spawn_initialized(
                    &self.executable,
                    self.definition.id,
                    "source-audit",
                    WorkerRole::Source,
                    self.database.path(),
                    &self.plan.options,
                    None,
                )?;
                let source_probe = source_audit
                    .request(WorkerCommand::StaleSourceKvProbe)
                    .map_err(|source| self.worker_error("source-audit", source))?;
                self.observe(
                    "source-lease-remains-admitted",
                    matches!(
                        source_probe.outcome,
                        ResponseOutcome::Success { ref result }
                            if matches!(result.as_ref(), WorkerResult::State { .. })
                    ),
                    format!("response={source_probe:?}"),
                )?;
                let replay = DumpData::from_result(
                    self.definition.id,
                    source_audit
                        .request_success(WorkerCommand::Dump)
                        .map_err(|source| self.worker_error("source-audit", source))?,
                )?;
                self.source_transcripts.push(archive_client(&source_audit)?);
                drop(source_audit);
                replay
            }
            Stage1ExpectedOwnership::DestinationCommitted
            | Stage1ExpectedOwnership::DestinationRecoveryRequired => {
                let source_probe = self
                    .source_mut()
                    .request(WorkerCommand::StaleSourceKvProbe)
                    .map_err(|source| self.worker_error("source", source))?;
                self.observe(
                    "source-lease-is-fenced",
                    matches!(
                        source_probe.outcome,
                        ResponseOutcome::Error { ref error }
                            if error.code == WorkerErrorCode::Provider
                                && error.provider_kind.as_deref() == Some("StaleEpoch")
                    ),
                    format!("response={source_probe:?}"),
                )?;

                let audit_label = format!("{}-source-audit", self.definition.id);
                let mut source_audit =
                    WorkerClient::spawn(&self.executable, audit_label, WORKER_TIMEOUT)
                        .map_err(|source| self.worker_error("source-audit", source))?;
                let initialization = source_audit
                    .request(WorkerCommand::Initialize {
                        role: WorkerRole::Source,
                        database_path: self.database.path().to_string_lossy().into_owned(),
                        options: self.plan.options.clone(),
                        fault: None,
                    })
                    .map_err(|source| self.worker_error("source-audit", source))?;
                let (restart_error, restart_stage) = match initialization.outcome {
                    ResponseOutcome::Error { error } => (error, "recovery"),
                    ResponseOutcome::Success { result }
                        if matches!(
                            result.as_ref(),
                            WorkerResult::Initialized {
                                role: WorkerRole::Source,
                                case_id
                            } if case_id == self.definition.id
                        ) =>
                    {
                        let probe = source_audit
                            .request(WorkerCommand::AdversarialStaleKvWriteProbe)
                            .map_err(|source| self.worker_error("source-audit", source))?;
                        match probe.outcome {
                            ResponseOutcome::Error { error } => (error, "provider-write"),
                            ResponseOutcome::Success { result } => {
                                return Err(RunnerError::Assertion {
                                    case_id: self.definition.id.to_owned(),
                                    detail: format!(
                                        "restarted source wrote under its stale lease: {result:?}"
                                    ),
                                });
                            }
                        }
                    }
                    ResponseOutcome::Success { result } => {
                        return Err(RunnerError::Assertion {
                            case_id: self.definition.id.to_owned(),
                            detail: format!("source audit initialization returned {result:?}"),
                        });
                    }
                };
                self.source_transcripts.push(archive_client(&source_audit)?);
                drop(source_audit);
                self.observe(
                    "source-restart-old-lease-is-fenced",
                    restart_error.code == WorkerErrorCode::Provider
                        && restart_error.provider_kind.as_deref() == Some("StaleEpoch"),
                    format!("stage={restart_stage}, error={restart_error:?}"),
                )?;
                live_source.clone().ok_or_else(|| RunnerError::Assertion {
                    case_id: self.definition.id.to_owned(),
                    detail: "committed outcome has no live source state for evidence".to_owned(),
                })?
            }
        };

        let (final_dump, replay_dump) = match expected_ownership {
            Stage1ExpectedOwnership::SourceRetained => {
                if outcome != Stage1CaseOutcome::RevocationRejectedNoResurrection
                    && let Some(live) = &live_source
                {
                    self.observe(
                        "source-journal-replay-digest",
                        live.state_digest == source_replay.state_digest,
                        format!(
                            "live={:?}, replay={:?}",
                            live.state_digest, source_replay.state_digest
                        ),
                    )?;
                }
                (
                    live_source.clone().unwrap_or_else(|| source_replay.clone()),
                    source_replay.clone(),
                )
            }
            Stage1ExpectedOwnership::DestinationCommitted
            | Stage1ExpectedOwnership::DestinationRecoveryRequired => {
                let transfer = self.snapshot.clone().ok_or_else(|| RunnerError::Assertion {
                    case_id: self.definition.id.to_owned(),
                    detail: "committed outcome has no snapshot".to_owned(),
                })?;
                let mut destination_audit = spawn_initialized(
                    &self.executable,
                    self.definition.id,
                    "destination-audit",
                    WorkerRole::Destination,
                    self.database.path(),
                    &self.plan.options,
                    None,
                )?;
                destination_audit
                    .request_success(WorkerCommand::LoadDestination {
                        envelope: transfer.envelope.ok_or_else(|| RunnerError::Assertion {
                            case_id: self.definition.id.to_owned(),
                            detail: "committed outcome has no exported envelope".to_owned(),
                        })?,
                        component_state: transfer.component_state,
                    })
                    .map_err(|source| self.worker_error("destination-audit", source))?;
                let destination_replay = DumpData::from_result(
                    self.definition.id,
                    destination_audit
                        .request_success(WorkerCommand::Dump)
                        .map_err(|source| self.worker_error("destination-audit", source))?,
                )?;
                self.destination_transcripts.push(archive_client(&destination_audit)?);
                drop(destination_audit);
                let final_destination =
                    live_destination.clone().unwrap_or_else(|| destination_replay.clone());
                self.observe(
                    "destination-journal-replay-digest",
                    final_destination.state_digest == destination_replay.state_digest,
                    format!(
                        "live={:?}, replay={:?}",
                        final_destination.state_digest, destination_replay.state_digest
                    ),
                )?;
                (final_destination, destination_replay)
            }
        };

        if let Some(transfer) = &self.snapshot {
            let expected_portable = transfer.component_state.as_slice();
            let envelope_matches = transfer.envelope.as_ref().is_some_and(|envelope| {
                envelope.body.portable_state.as_slice() == expected_portable
            });
            let source_portable =
                live_source.as_ref().unwrap_or(&source_replay).portable_component_state.as_deref();
            let destination_portable =
                if expected_ownership == Stage1ExpectedOwnership::SourceRetained {
                    live_destination
                        .as_ref()
                        .or(self.destination_base.as_ref())
                        .and_then(|dump| dump.portable_component_state.as_deref())
                } else {
                    final_dump.portable_component_state.as_deref()
                };
            let portable_matches = envelope_matches
                && source_portable == Some(expected_portable)
                && destination_portable.is_none_or(|bytes| bytes == expected_portable);
            let expected_bytes = expected_portable.len();
            let source_bytes = source_portable.map(<[u8]>::len);
            let destination_bytes = destination_portable.map(<[u8]>::len);
            self.observe(
                "snapshot-portable-state-matches-worker-dumps",
                portable_matches,
                format!(
                    "snapshot_bytes={}, source_bytes={:?}, destination_bytes={:?}",
                    expected_bytes, source_bytes, destination_bytes
                ),
            )?;
        }

        let (owner, epoch, ownership, destination_epoch, source_fenced) = match expected_ownership {
            Stage1ExpectedOwnership::SourceRetained => (
                self.fixture.ids.source_node,
                self.fixture.activation.initial_lease_epoch,
                Stage1OwnershipStatus::SourceActive,
                None,
                false,
            ),
            Stage1ExpectedOwnership::DestinationCommitted => (
                self.fixture.ids.destination_node,
                self.fixture.activation.initial_lease_epoch.next().ok_or_else(|| {
                    RunnerError::Assertion {
                        case_id: self.definition.id.to_owned(),
                        detail: "destination lease epoch overflowed".to_owned(),
                    }
                })?,
                Stage1OwnershipStatus::DestinationActive,
                self.fixture.activation.initial_lease_epoch.next(),
                true,
            ),
            Stage1ExpectedOwnership::DestinationRecoveryRequired => (
                self.fixture.ids.destination_node,
                self.fixture.activation.initial_lease_epoch.next().ok_or_else(|| {
                    RunnerError::Assertion {
                        case_id: self.definition.id.to_owned(),
                        detail: "destination lease epoch overflowed".to_owned(),
                    }
                })?,
                Stage1OwnershipStatus::DestinationRecoveryRequired,
                self.fixture.activation.initial_lease_epoch.next(),
                true,
            ),
        };
        self.observe(
            "global-resource-leases-select-one-owner",
            final_dump.leases.len() == 2
                && final_dump
                    .leases
                    .iter()
                    .all(|lease| lease.owner == owner && lease.epoch == epoch),
            format!("leases={:?}", final_dump.leases),
        )?;
        if expected_ownership != Stage1ExpectedOwnership::SourceRetained {
            self.observe(
                "committed-bindings-cover-profile",
                binding_for_claim(&final_dump, self.fixture.ids.timer_resource).is_some()
                    && binding_for_claim(&final_dump, self.fixture.ids.key_value_resource)
                        .is_some(),
                format!("receipts={:?}", final_dump.binding_receipts),
            )?;
        }

        self.archive_source()?;
        self.archive_destination()?;
        let raw_source_json = transcript_json_lines(&self.source_transcripts)?;
        let raw_destination_json = transcript_json_lines(&self.destination_transcripts)?;
        let source_final = live_source.as_ref().unwrap_or(&source_replay);
        let destination_final = if expected_ownership == Stage1ExpectedOwnership::SourceRetained {
            live_destination.as_ref()
        } else {
            Some(&replay_dump)
        };
        let semantic_traces = semantic_traces(
            self.definition.id,
            &self.fixture,
            self.snapshot.as_ref(),
            source_final,
            self.destination_base.as_ref(),
            destination_final,
            expected_ownership,
        )?;
        let timer_binding_receipt = receipt_artifact(&final_dump, self.fixture.ids.timer_resource)?;
        let key_value_binding_receipt =
            receipt_artifact(&final_dump, self.fixture.ids.key_value_resource)?;
        let snapshot_bytes = self
            .snapshot
            .as_ref()
            .and_then(|transfer| transfer.envelope.as_ref())
            .map(|envelope| {
                serde_json::to_vec(envelope).map_err(|error| RunnerError::Json {
                    context: format!("encode {} snapshot", self.definition.id),
                    detail: error.to_string(),
                })
            })
            .transpose()?;
        let observed_source_grants =
            live_source.as_ref().unwrap_or(&source_replay).canonical_state.authorities.as_slice();
        let observed_destination_grants =
            if expected_ownership == Stage1ExpectedOwnership::SourceRetained {
                &[][..]
            } else {
                final_dump.canonical_state.authorities.as_slice()
            };
        let source_authority_root =
            canonical_digest(observed_source_grants).map_err(|_| RunnerError::Fixture {
                case_id: self.definition.id.to_owned(),
                detail: "cannot digest observed source authority grants".to_owned(),
            })?;
        let destination_authority_root =
            canonical_digest(observed_destination_grants).map_err(|_| RunnerError::Fixture {
                case_id: self.definition.id.to_owned(),
                detail: "cannot digest observed destination authority grants".to_owned(),
            })?;
        self.observe(
            "authority-roots-derived-from-observed-grants",
            !observed_source_grants.is_empty()
                && if expected_ownership == Stage1ExpectedOwnership::SourceRetained {
                    observed_destination_grants.is_empty()
                } else {
                    !observed_destination_grants.is_empty()
                },
            format!(
                "source_grants={}, destination_grants={}, source_root={}, destination_root={}",
                observed_source_grants.len(),
                observed_destination_grants.len(),
                digest_hex(source_authority_root),
                digest_hex(destination_authority_root)
            ),
        )?;
        let raw_assertions_json = assertions_json_lines(&self.assertions)?;
        let fault_schedule = fault_schedule(self.definition, &self.plan);
        Ok(CaseExecutionRecord {
            case_id: self.definition.id.to_owned(),
            case_config_digest: self.config_digest,
            case_policy_digest: self.policy_digest,
            execution_id: derive_identity(self.definition.id, "execution"),
            handoff_id: self.fixture.ids.handoff,
            snapshot_id: self.fixture.ids.snapshot,
            outcome,
            exit_status: 0,
            fault_schedule,
            authority: CaseAuthorityRecord {
                source_authority_root,
                destination_authority_root,
                source_lease_epoch: self.fixture.activation.initial_lease_epoch,
                destination_lease_epoch: destination_epoch,
                fencing_epoch: epoch,
                ownership,
                source_fenced,
            },
            snapshot_bytes,
            semantic_traces,
            timer_binding_receipt,
            key_value_binding_receipt,
            raw_source_json,
            raw_destination_json,
            raw_assertions_json,
            state_digest: final_dump.state_digest,
            replay_state_digest: replay_dump.state_digest,
            performance: self.performance,
        })
    }
}

fn execute_case(harness: &mut CaseHarness) -> Result<Stage1CaseOutcome, RunnerError> {
    use Stage1CaseOutcome::{
        AuthorityRejectedBeforeExecution, BindingRejectedNoSubstitution,
        CancelledTimerCleanedNotRecreated, CleanupIdempotentNoResurrection,
        CompletedTimerNotRecreated, DuplicateActivationRejected, DuplicateKvAppliedOnce,
        DuplicatePrepareInactive, DurableDestinationOwnerSelected, DurableWriteAbortedBeforeCommit,
        EvidenceIdentityVerified, EvidenceRegeneratedWithoutStateChange, ExcessAuthorityAttenuated,
        FreezeRejectedNoSnapshot, PreCommitPreparationRetried, PrepareIdempotentInactive,
        ProfileRejectedWithoutDowngrade, RawPerformanceRecorded, ReplayDigestMatched,
        RestoredWithNarrowerAuthority, RevocationRejectedNoResurrection,
        SafePointRejectedSourceRetained, SingleLeaseEpochAccepted, SnapshotRejectedBeforeBindings,
        SourceFencedRecoveryRequired, StaleSourceRejected, TimerPausedThenResumed,
        TimerRecreatedSingleExpiry, TimerSemanticsRejected, UnknownKvReconciled,
        VersionRejectedBeforeBindings,
    };
    match case_kind(harness.definition.id).expect("case registry was checked") {
        CaseKind::TimerPositive => {
            run_pending_handoff(harness, false)?;
            Ok(TimerRecreatedSingleExpiry)
        }
        CaseKind::TimerPaused => {
            run_pending_handoff(harness, true)?;
            Ok(TimerPausedThenResumed)
        }
        CaseKind::TimerCompleted => {
            run_completed_timer_handoff(harness)?;
            Ok(CompletedTimerNotRecreated)
        }
        CaseKind::TimerCancelled => {
            run_cancelled_timer_handoff(harness)?;
            Ok(CancelledTimerCleanedNotRecreated)
        }
        CaseKind::AuthorityNarrower => {
            run_pending_handoff(harness, false)?;
            assert_narrow_destination_authority(harness)?;
            Ok(RestoredWithNarrowerAuthority)
        }
        CaseKind::KvDuplicate => {
            run_pending_handoff(harness, false)?;
            assert_duplicate_kv_replay(harness)?;
            Ok(DuplicateKvAppliedOnce)
        }
        CaseKind::RepeatedValidationPrepare => {
            run_repeated_validation_prepare(harness)?;
            Ok(PrepareIdempotentInactive)
        }
        CaseKind::JournalReplay => {
            run_pending_handoff(harness, false)?;
            Ok(ReplayDigestMatched)
        }
        CaseKind::StaleSource => {
            run_pending_handoff(harness, false)?;
            assert_post_commit_source_rejected(harness)?;
            Ok(StaleSourceRejected)
        }
        CaseKind::EvidenceVerification => {
            run_pending_handoff(harness, false)?;
            assert_evidence_identities(harness)?;
            run_supplemental_fault_coverage(harness)?;
            Ok(EvidenceIdentityVerified)
        }
        CaseKind::Performance => {
            run_performance_case(harness)?;
            Ok(RawPerformanceRecorded)
        }
        CaseKind::SafePointUnreachable => {
            run_safe_point_unavailable(harness)?;
            Ok(SafePointRejectedSourceRetained)
        }
        CaseKind::UnsupportedLiveResource => {
            run_live_resource_rejection(harness)?;
            Ok(FreezeRejectedNoSnapshot)
        }
        CaseKind::KvUnknown => {
            run_unknown_kv_reconciliation(harness)?;
            Ok(UnknownKvReconciled)
        }
        CaseKind::CorruptSnapshot => {
            run_snapshot_validation_rejection(harness, ValidationFailure::CorruptSnapshot)?;
            Ok(SnapshotRejectedBeforeBindings)
        }
        CaseKind::IncompatibleVersion => {
            run_snapshot_validation_rejection(harness, ValidationFailure::Version)?;
            Ok(VersionRejectedBeforeBindings)
        }
        CaseKind::ProfileMismatch => {
            run_snapshot_validation_rejection(harness, ValidationFailure::Profile)?;
            Ok(ProfileRejectedWithoutDowngrade)
        }
        CaseKind::MissingAuthority => {
            run_prepare_rejection(harness, "Denied")?;
            Ok(AuthorityRejectedBeforeExecution)
        }
        CaseKind::RevokedCapability => {
            run_revoked_capability(harness)?;
            Ok(RevocationRejectedNoResurrection)
        }
        CaseKind::BroaderAuthority => {
            run_pending_handoff(harness, false)?;
            assert_broader_policy_input(harness)?;
            assert_narrow_destination_authority(harness)?;
            Ok(ExcessAuthorityAttenuated)
        }
        CaseKind::MissingNamespace => {
            run_prepare_rejection(harness, "NotFound")?;
            Ok(BindingRejectedNoSubstitution)
        }
        CaseKind::TimerUnsupported => {
            run_snapshot_validation_rejection(harness, ValidationFailure::TimerSupport)?;
            Ok(TimerSemanticsRejected)
        }
        CaseKind::CrashBeforeCommit => {
            run_crash_before_commit(harness)?;
            Ok(PreCommitPreparationRetried)
        }
        CaseKind::DuplicatePrepare => {
            run_duplicate_prepare(harness)?;
            Ok(DuplicatePrepareInactive)
        }
        CaseKind::LostCommitAck => {
            run_pending_handoff(harness, false)?;
            let dump = harness.dump_destination()?;
            harness.observe(
                "lost-commit-ack-reconciled",
                harness.latest_destination.as_ref().is_some_and(|view| {
                    view.canonical_phase == contract_core::HandoffPhase::Running
                }) && fault_fired(&dump, FaultPointSpec::AfterCommitBundle),
                format!(
                    "AfterCommitBundle resolved to durable destination truth; fault={:?}",
                    dump.fault_observation
                ),
            )?;
            Ok(DurableDestinationOwnerSelected)
        }
        CaseKind::SourceCommitRace => {
            run_source_commit_race(harness)?;
            Ok(SingleLeaseEpochAccepted)
        }
        CaseKind::CrashAfterCommit => {
            run_crash_after_commit(harness)?;
            Ok(SourceFencedRecoveryRequired)
        }
        CaseKind::DuplicateRestore => {
            run_duplicate_restore(harness)?;
            Ok(DuplicateActivationRejected)
        }
        CaseKind::RepeatedCleanup => {
            run_repeated_cleanup(harness)?;
            Ok(CleanupIdempotentNoResurrection)
        }
        CaseKind::DurableWriteFailure => {
            run_durable_write_failure(harness)?;
            Ok(DurableWriteAbortedBeforeCommit)
        }
        CaseKind::ReportFailure => {
            run_report_failure(harness)?;
            Ok(EvidenceRegeneratedWithoutStateChange)
        }
    }
}

fn run_pending_handoff(harness: &mut CaseHarness, long_pause: bool) -> Result<(), RunnerError> {
    let transfer = harness.bootstrap_snapshot()?;
    let SafePointTimerView::Pending { remaining, .. } = transfer.timer else {
        return Err(RunnerError::Assertion {
            case_id: harness.definition.id.to_owned(),
            detail: format!("pending handoff froze timer as {:?}", transfer.timer),
        });
    };
    if long_pause {
        thread::sleep(Duration::from_nanos(remaining.0) + TIMER_MARGIN);
        let source =
            state_result(harness.definition.id, harness.source_success(WorkerCommand::Read)?)?;
        harness.observe(
            "frozen-time-does-not-expire",
            source.canonical_phase == contract_core::HandoffPhase::Exported,
            format!("phase={:?}, slept_ns={}", source.canonical_phase, remaining.0),
        )?;
    }
    let envelope = snapshot_envelope(harness)?;
    harness.validate_destination(
        envelope,
        SnapshotExpectationOverrides::default(),
        DestinationSupportMode::Compatible,
    )?;
    harness.normal_commit()?;
    harness.deliver_pending_timer()
}

fn run_completed_timer_handoff(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    harness.bootstrap()?;
    harness.begin_quiesce()?;
    thread::sleep(Duration::from_nanos(harness.fixture.activation.delay_ns) + TIMER_MARGIN);
    let transfer = harness.freeze()?;
    harness.observe(
        "quiescing-completion-captured",
        matches!(transfer.timer, SafePointTimerView::Completed { .. }),
        format!("timer={:?}", transfer.timer),
    )?;
    harness.export(transfer)?;
    harness.normal_commit()?;
    let result = harness.destination_success(WorkerCommand::PollTimer { deliver: true })?;
    let (poll, delivered, view) = timer_result(harness.definition.id, result)?;
    harness.observe(
        "completed-timer-not-recreated",
        poll == TimerPollView::Completed
            && !delivered
            && view.component.as_ref().is_some_and(|component| {
                component.phase == WorkloadPhaseView::Completed && component.expected_version == 2
            }),
        format!("poll={poll:?}, delivered={delivered}, component={:?}", view.component),
    )
}

fn run_cancelled_timer_handoff(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    harness.bootstrap()?;
    harness.begin_quiesce()?;
    harness.source_success(WorkerCommand::CancelPending)?;
    let transfer = harness.freeze()?;
    harness.observe(
        "cancelled-timer-captured",
        transfer.timer == SafePointTimerView::Cancelled,
        format!("timer={:?}", transfer.timer),
    )?;
    harness.export(transfer)?;
    let first_cleanup = state_result(
        harness.definition.id,
        harness.source_success(WorkerCommand::CleanupPendingTimer)?,
    )?;
    let second_cleanup = state_result(
        harness.definition.id,
        harness.source_success(WorkerCommand::CleanupPendingTimer)?,
    )?;
    harness.observe(
        "timer-cleanup-idempotent",
        first_cleanup.state_digest == second_cleanup.state_digest
            && first_cleanup.journal_position == second_cleanup.journal_position,
        format!(
            "first={:?}/{:?}, second={:?}/{:?}",
            first_cleanup.journal_position,
            first_cleanup.state_digest,
            second_cleanup.journal_position,
            second_cleanup.state_digest
        ),
    )?;
    harness.normal_commit()?;
    let result = harness.destination_success(WorkerCommand::PollTimer { deliver: true })?;
    let (poll, delivered, _) = timer_result(harness.definition.id, result)?;
    harness.observe(
        "cancelled-timer-not-recreated",
        matches!(poll, TimerPollView::Cancelled | TimerPollView::Cleaned) && !delivered,
        format!("poll={poll:?}, delivered={delivered}"),
    )
}

fn assert_narrow_destination_authority(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    let dump = harness.dump_destination()?;
    let prepared = dump.canonical_state.prepared_destination.as_ref().ok_or_else(|| {
        RunnerError::Assertion {
            case_id: harness.definition.id.to_owned(),
            detail: "destination has no prepared authority set".to_owned(),
        }
    })?;
    let subject = harness.fixture.ids.destination_component;
    let expected_grants = [
        contract_core::AuthorityGrant {
            authority: harness.fixture.handoff_authority.destination_authority,
            parent: Some(harness.fixture.handoff_authority.source_authority),
            subject,
            resource: subject,
            rights: contract_core::Rights::HANDOFF,
            status: contract_core::AuthorityStatus::Active,
        },
        contract_core::AuthorityGrant {
            authority: harness.fixture.timer_authority.destination_authority,
            parent: Some(harness.fixture.timer_authority.source_authority),
            subject,
            resource: harness.fixture.ids.timer_resource,
            rights: harness.fixture.claims.timer.required_rights,
            status: contract_core::AuthorityStatus::Active,
        },
        contract_core::AuthorityGrant {
            authority: harness.fixture.key_value_authority.destination_authority,
            parent: Some(harness.fixture.key_value_authority.source_authority),
            subject,
            resource: harness.fixture.ids.key_value_resource,
            rights: harness.fixture.claims.key_value.required_rights,
            status: contract_core::AuthorityStatus::Active,
        },
    ];
    let prepared_resources =
        prepared.authorities.iter().map(|grant| grant.resource).collect::<BTreeSet<_>>();
    let prepared_exact = prepared.authorities.len() == expected_grants.len()
        && prepared_resources.len() == expected_grants.len()
        && expected_grants.iter().all(|expected| prepared.authorities.contains(expected));
    let mut expected_canonical = snapshot_envelope(harness)?.body.authorities;
    expected_canonical.extend(expected_grants.iter().cloned());
    let canonical_exact = dump.canonical_state.authorities.len() == expected_canonical.len()
        && expected_canonical
            .iter()
            .all(|expected| dump.canonical_state.authorities.contains(expected));
    let expected_bindings = [
        (
            harness.fixture.ids.timer_resource,
            harness.fixture.timer_authority.destination_authority,
            harness.fixture.claims.timer.required_rights,
        ),
        (
            harness.fixture.ids.key_value_resource,
            harness.fixture.key_value_authority.destination_authority,
            harness.fixture.claims.key_value.required_rights,
        ),
    ];
    let binding_claims =
        prepared.bindings.iter().map(|receipt| receipt.claim).collect::<BTreeSet<_>>();
    let bindings_exact = prepared.bindings.len() == expected_bindings.len()
        && binding_claims.len() == expected_bindings.len()
        && expected_bindings.iter().all(|(claim, authority, rights)| {
            prepared.bindings.iter().any(|receipt| {
                receipt.handoff == harness.fixture.ids.handoff
                    && receipt.snapshot == harness.fixture.ids.snapshot
                    && receipt.claim == *claim
                    && receipt.node == harness.fixture.ids.destination_node
                    && receipt.authority == *authority
                    && receipt.exposed_rights == *rights
                    && receipt.lease_epoch == prepared.next_epoch
            })
        });
    harness.observe(
        "destination-authority-is-exactly-profiled",
        prepared_exact && canonical_exact && bindings_exact,
        format!(
            "prepared_grants={:?}, canonical_grants={:?}, bindings={:?}",
            prepared.authorities, dump.canonical_state.authorities, prepared.bindings
        ),
    )
}

fn assert_broader_policy_input(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    let expected = [
        (harness.fixture.ids.destination_component, contract_core::Rights::HANDOFF),
        (harness.fixture.ids.timer_resource, harness.fixture.claims.timer.required_rights),
        (harness.fixture.ids.key_value_resource, harness.fixture.claims.key_value.required_rights),
    ];
    let policies = &harness.fixture.policy_digest_input.destination_policies;
    let policy_is_strictly_broader = harness.plan.options.authority_policy
        == AuthorityPolicyMode::Broader
        && policies.len() == expected.len()
        && expected.iter().all(|(resource, required)| {
            policies.iter().any(|policy| {
                policy.subject == harness.fixture.ids.destination_component
                    && policy.resource == *resource
                    && policy.allowed_rights.contains(*required)
                    && policy.allowed_rights != *required
            })
        });
    harness.observe(
        "broader-policy-is-attenuated-at-destination-boundary",
        policy_is_strictly_broader,
        format!("mode={:?}, policies={policies:?}", harness.plan.options.authority_policy),
    )
}

fn assert_duplicate_kv_replay(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    let result = harness.destination_success(WorkerCommand::DuplicateCompletionKvProbe)?;
    let WorkerResult::EffectProbe { outcome, replayed, view, .. } = result else {
        return Err(RunnerError::Assertion {
            case_id: harness.definition.id.to_owned(),
            detail: format!("duplicate KV probe returned {result:?}"),
        });
    };
    let applied_once = matches!(
        outcome,
        Some(contract_core::EffectOutcome::Succeeded {
            result: contract_core::EffectResult::KeyValue { version: 2, applied: true },
            ..
        })
    );
    harness.observe(
        "duplicate-kv-replayed-once",
        replayed
            && applied_once
            && view.component.is_some_and(|component| component.expected_version == 2),
        format!("replayed={replayed}, outcome={outcome:?}"),
    )
}

fn run_repeated_validation_prepare(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    harness.bootstrap_snapshot()?;
    let envelope = snapshot_envelope(harness)?;
    harness.validate_destination(
        envelope.clone(),
        SnapshotExpectationOverrides::default(),
        DestinationSupportMode::Compatible,
    )?;
    harness.validate_destination(
        envelope,
        SnapshotExpectationOverrides::default(),
        DestinationSupportMode::Compatible,
    )?;
    harness.load_destination(&[contract_core::HandoffPhase::Exported])?;
    let first = harness.prepare_destination()?;
    let second = harness.prepare_destination()?;
    harness.observe(
        "validation-and-prepare-idempotent",
        first.state_digest == second.state_digest
            && first.journal_position == second.journal_position
            && second.canonical_phase == contract_core::HandoffPhase::DestinationPrepared,
        format!(
            "first={:?}/{:?}, second={:?}/{:?}",
            first.journal_position,
            first.state_digest,
            second.journal_position,
            second.state_digest
        ),
    )?;
    abort_precommit_to_source(harness, "repeated-prepare-aborts-to-source")
}

fn assert_post_commit_source_rejected(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    let before = harness.dump_source()?.key_value_entry;
    let error = harness.source_rejection(WorkerCommand::AdversarialStaleKvWriteProbe)?;
    let after = harness.dump_source()?.key_value_entry;
    harness.observe(
        "post-commit-adversarial-source-write-fenced",
        error.code == WorkerErrorCode::Provider
            && error.provider_kind.as_deref() == Some("StaleEpoch")
            && before == after,
        format!("error={error:?}, before={before:?}, after={after:?}"),
    )
}

fn assert_evidence_identities(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    let source = harness.dump_source()?;
    let destination = harness.dump_destination()?;
    let envelope = snapshot_envelope(harness)?;
    let snapshot = &envelope.body.snapshot;
    let receipts_match = destination.binding_receipts.iter().all(|receipt| {
        receipt.handoff == harness.fixture.ids.handoff
            && receipt.snapshot == harness.fixture.ids.snapshot
            && receipt.node == harness.fixture.ids.destination_node
    });
    harness.observe(
        "evidence-identities-cross-check",
        snapshot.handoff == harness.fixture.ids.handoff
            && snapshot.snapshot == harness.fixture.ids.snapshot
            && source.canonical_state.exported_snapshot.as_ref() == Some(snapshot)
            && receipts_match,
        format!("snapshot={snapshot:?}, receipts={:?}", destination.binding_receipts),
    )
}

fn run_supplemental_fault_coverage(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    run_before_activation_fault(harness)?;
    run_after_activation_fault(harness)?;
    run_before_journal_fault(harness)?;
    run_after_journal_fault(harness)?;

    let points = STAGE1_PROVIDER_FAULT_COVERAGE
        .iter()
        .map(|entry| format!("{:?}", entry.point))
        .collect::<BTreeSet<_>>();
    harness.observe(
        "all-provider-fault-points-have-system-scenarios",
        STAGE1_PROVIDER_FAULT_COVERAGE.len() == 7 && points.len() == 7,
        format!("coverage={STAGE1_PROVIDER_FAULT_COVERAGE:?}"),
    )
}

fn run_before_activation_fault(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    let (case_id, fixture, database, mut source) = supplemental_source_worker(
        harness,
        "fault-before-activation-bundle",
        FaultPointSpec::BeforeActivationBundle,
    )?;
    let initial = supplemental_dump(&case_id, &mut source)?;
    let response = source
        .request(WorkerCommand::BootstrapSource)
        .map_err(|source| harness.worker_error("supplemental-source", source))?;
    let error = supplemental_rejection(harness, &case_id, response)?;
    let rejected = supplemental_dump(&case_id, &mut source)?;
    harness.observe(
        "before-activation-bundle-rolls-back-atomically",
        error.code == WorkerErrorCode::Provider
            && error.provider_kind.as_deref() == Some("Unavailable")
            && rejected.canonical_state.phase == contract_core::HandoffPhase::Dormant
            && rejected.state_digest == initial.state_digest
            && rejected.journal.is_empty()
            && rejected.leases.is_empty()
            && fault_fired(&rejected, FaultPointSpec::BeforeActivationBundle),
        format!(
            "error={error:?}, phase={:?}, journal={}, leases={:?}, fault={:?}",
            rejected.canonical_state.phase,
            rejected.journal.len(),
            rejected.leases,
            rejected.fault_observation
        ),
    )?;
    archive_supplemental_source(harness, source)?;

    let mut recovered = spawn_initialized(
        &harness.executable,
        &case_id,
        "supplemental-source-retry",
        WorkerRole::Source,
        database.path(),
        &fixture.options,
        None,
    )?;
    let replay = supplemental_dump(&case_id, &mut recovered)?;
    let running = state_result(
        &case_id,
        recovered
            .request_success(WorkerCommand::BootstrapSource)
            .map_err(|source| harness.worker_error("supplemental-source", source))?,
    )?;
    let committed = supplemental_dump(&case_id, &mut recovered)?;
    harness.observe(
        "before-activation-bundle-retries-from-durable-dormant-state",
        replay.state_digest == rejected.state_digest
            && running.canonical_phase == contract_core::HandoffPhase::Running
            && committed.leases.len() == 2
            && committed.leases.iter().all(|lease| {
                lease.owner == fixture.ids.source_node
                    && lease.epoch == fixture.activation.initial_lease_epoch
            }),
        format!(
            "replay={:?}, running={:?}, leases={:?}",
            replay.state_digest, running.canonical_phase, committed.leases
        ),
    )?;
    archive_supplemental_source(harness, recovered)
}

fn run_after_activation_fault(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    let (case_id, fixture, database, mut source) = supplemental_source_worker(
        harness,
        "fault-after-activation-bundle",
        FaultPointSpec::AfterActivationBundle,
    )?;
    let running = state_result(
        &case_id,
        source
            .request_success(WorkerCommand::BootstrapSource)
            .map_err(|source| harness.worker_error("supplemental-source", source))?,
    )?;
    let committed = supplemental_dump(&case_id, &mut source)?;
    archive_supplemental_source(harness, source)?;

    let mut recovered = spawn_initialized(
        &harness.executable,
        &case_id,
        "supplemental-source-recovery",
        WorkerRole::Source,
        database.path(),
        &fixture.options,
        None,
    )?;
    let replay = supplemental_dump(&case_id, &mut recovered)?;
    harness.observe(
        "after-activation-bundle-lost-ack-is-reconciled",
        running.canonical_phase == contract_core::HandoffPhase::Running
            && committed.leases.len() == 2
            && committed.leases.iter().all(|lease| {
                lease.owner == fixture.ids.source_node
                    && lease.epoch == fixture.activation.initial_lease_epoch
            })
            && committed.state_digest == replay.state_digest
            && committed.journal == replay.journal
            && fault_fired(&committed, FaultPointSpec::AfterActivationBundle),
        format!(
            "phase={:?}, live={:?}, replay={:?}, leases={:?}, fault={:?}",
            running.canonical_phase,
            committed.state_digest,
            replay.state_digest,
            committed.leases,
            committed.fault_observation
        ),
    )?;
    archive_supplemental_source(harness, recovered)
}

fn run_before_journal_fault(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    let (case_id, fixture, database, mut source) = supplemental_source_worker(
        harness,
        "fault-before-journal-write",
        FaultPointSpec::BeforeJournalWrite,
    )?;
    let response = source
        .request(WorkerCommand::BootstrapSource)
        .map_err(|source| harness.worker_error("supplemental-source", source))?;
    let error = supplemental_rejection(harness, &case_id, response)?;
    let rejected = supplemental_dump(&case_id, &mut source)?;
    let only_activation = rejected.journal.len() == 1
        && matches!(&rejected.journal[0].event.kind, contract_core::EventKind::Activated { .. });
    let explicit_unavailable = (error.code == WorkerErrorCode::Provider
        && error.provider_kind.as_deref() == Some("Unavailable"))
        || (error.code == WorkerErrorCode::Adapter
            && error.message.contains("KeyValue(Unavailable)"));
    harness.observe(
        "before-journal-write-leaves-no-partial-effect-entry",
        explicit_unavailable
            && rejected.canonical_state.phase == contract_core::HandoffPhase::Running
            && only_activation
            && rejected.leases.len() == 2
            && rejected.leases.iter().all(|lease| {
                lease.owner == fixture.ids.source_node
                    && lease.epoch == fixture.activation.initial_lease_epoch
            })
            && fault_fired(&rejected, FaultPointSpec::BeforeJournalWrite),
        format!(
            "error={error:?}, phase={:?}, journal={:?}, leases={:?}, fault={:?}",
            rejected.canonical_state.phase,
            rejected.journal,
            rejected.leases,
            rejected.fault_observation
        ),
    )?;
    archive_supplemental_source(harness, source)?;

    let mut recovered = spawn_initialized(
        &harness.executable,
        &case_id,
        "supplemental-source-retry",
        WorkerRole::Source,
        database.path(),
        &fixture.options,
        None,
    )?;
    let replay = supplemental_dump(&case_id, &mut recovered)?;
    let retried = state_result(
        &case_id,
        recovered
            .request_success(WorkerCommand::BootstrapSource)
            .map_err(|source| harness.worker_error("supplemental-source", source))?,
    )?;
    let completed = supplemental_dump(&case_id, &mut recovered)?;
    harness.observe(
        "before-journal-write-retry-starts-at-durable-cursor",
        replay.state_digest == rejected.state_digest
            && replay.journal == rejected.journal
            && retried.canonical_phase == contract_core::HandoffPhase::Running
            && completed.journal.len() > replay.journal.len()
            && retried.component.as_ref().is_some_and(|component| {
                component.phase == WorkloadPhaseView::Armed && component.expected_version == 1
            }),
        format!(
            "replay_entries={}, completed_entries={}, component={:?}",
            replay.journal.len(),
            completed.journal.len(),
            retried.component
        ),
    )?;
    archive_supplemental_source(harness, recovered)
}

fn run_after_journal_fault(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    let (case_id, fixture, database, mut source) = supplemental_source_worker(
        harness,
        "fault-after-journal-write",
        FaultPointSpec::AfterJournalWrite,
    )?;
    let running = state_result(
        &case_id,
        source
            .request_success(WorkerCommand::BootstrapSource)
            .map_err(|source| harness.worker_error("supplemental-source", source))?,
    )?;
    let committed = supplemental_dump(&case_id, &mut source)?;
    archive_supplemental_source(harness, source)?;

    let mut recovered = spawn_initialized(
        &harness.executable,
        &case_id,
        "supplemental-source-recovery",
        WorkerRole::Source,
        database.path(),
        &fixture.options,
        None,
    )?;
    let replay = supplemental_dump(&case_id, &mut recovered)?;
    let positions = replay.journal.iter().map(|entry| entry.position).collect::<BTreeSet<_>>();
    harness.observe(
        "after-journal-write-lost-ack-is-reconciled",
        running.canonical_phase == contract_core::HandoffPhase::Running
            && running.component.as_ref().is_some_and(|component| {
                component.phase == WorkloadPhaseView::Armed && component.expected_version == 1
            })
            && committed.state_digest == replay.state_digest
            && committed.journal == replay.journal
            && committed.leases.len() == 2
            && committed.leases.iter().all(|lease| {
                lease.owner == fixture.ids.source_node
                    && lease.epoch == fixture.activation.initial_lease_epoch
            })
            && positions.len() == replay.journal.len()
            && fault_fired(&committed, FaultPointSpec::AfterJournalWrite),
        format!(
            "live={:?}, replay={:?}, entries={}, unique_positions={}, fault={:?}",
            committed.state_digest,
            replay.state_digest,
            replay.journal.len(),
            positions.len(),
            committed.fault_observation
        ),
    )?;
    archive_supplemental_source(harness, recovered)
}

fn supplemental_source_worker(
    harness: &CaseHarness,
    suffix: &str,
    fault: FaultPointSpec,
) -> Result<(String, FixtureSpec, CaseDatabase, WorkerClient), RunnerError> {
    let case_id = format!("{}-{suffix}", harness.definition.id);
    let options = FixtureOptions::new(case_id.clone());
    let fixture = FixtureSpec::with_options(options).map_err(|error| RunnerError::Fixture {
        case_id: case_id.clone(),
        detail: error.to_string(),
    })?;
    let database = CaseDatabase::new(&harness.work_root, &case_id)?;
    let source = spawn_initialized(
        &harness.executable,
        &case_id,
        "supplemental-source",
        WorkerRole::Source,
        database.path(),
        &fixture.options,
        Some(fault),
    )?;
    Ok((case_id, fixture, database, source))
}

fn supplemental_dump(case_id: &str, source: &mut WorkerClient) -> Result<DumpData, RunnerError> {
    let result = source.request_success(WorkerCommand::Dump).map_err(|source| {
        RunnerError::Worker { case_id: case_id.to_owned(), role: "supplemental-source", source }
    })?;
    DumpData::from_result(case_id, result)
}

fn fault_fired(dump: &DumpData, point: FaultPointSpec) -> bool {
    dump.fault_observation == Some(FaultObservationView { point, count: 1 })
}

fn supplemental_rejection(
    harness: &CaseHarness,
    case_id: &str,
    response: ResponseEnvelope,
) -> Result<WorkerError, RunnerError> {
    match response.outcome {
        ResponseOutcome::Error { error } => Ok(error),
        ResponseOutcome::Success { result } => Err(RunnerError::Assertion {
            case_id: harness.definition.id.to_owned(),
            detail: format!("supplemental case {case_id} unexpectedly succeeded with {result:?}"),
        }),
    }
}

fn archive_supplemental_source(
    harness: &mut CaseHarness,
    source: WorkerClient,
) -> Result<(), RunnerError> {
    harness.source_transcripts.push(archive_client(&source)?);
    drop(source);
    Ok(())
}

fn run_performance_case(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    harness.bootstrap()?;
    let mut steady = Vec::new();
    for _ in 0..5 {
        let started = Instant::now();
        harness.source_success(WorkerCommand::Read)?;
        steady.push(elapsed_nanos(started));
    }
    harness.performance.push(PerformanceMeasurement {
        metric: Stage1PerformanceMetric::SteadyStateCost,
        samples: steady,
    });
    harness.begin_quiesce()?;
    let transfer = harness.freeze()?;
    let transfer = harness.export(transfer)?;
    let snapshot_size = serde_json::to_vec(
        transfer.envelope.as_ref().expect("export populated the snapshot envelope"),
    )
    .map_err(|error| RunnerError::Json {
        context: format!("encode {} snapshot size", harness.definition.id),
        detail: error.to_string(),
    })?
    .len() as u64;
    harness.performance.push(PerformanceMeasurement {
        metric: Stage1PerformanceMetric::SnapshotSize,
        samples: vec![snapshot_size],
    });
    harness.normal_commit()?;
    harness.deliver_pending_timer()?;
    harness.observe(
        "raw-performance-samples-recorded",
        harness.performance.len() == 3
            && harness.performance.iter().all(|measurement| !measurement.samples.is_empty()),
        format!("measurements={:?}", harness.performance),
    )
}

fn run_safe_point_unavailable(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    harness.bootstrap()?;
    harness.begin_quiesce()?;
    let error = harness.source_rejection(WorkerCommand::FreezeSource)?;
    let timed_out =
        state_result(harness.definition.id, harness.source_success(WorkerCommand::Read)?)?;
    harness.observe(
        "safe-point-unavailable-is-explicit",
        error.code == WorkerErrorCode::Adapter
            && error.message.contains("SafePointUnavailable")
            && timed_out.canonical_phase == contract_core::HandoffPhase::Quiescing
            && timed_out.component_instantiated
            && timed_out.component.as_ref().is_some_and(|component| {
                component.phase == WorkloadPhaseView::Armed && component.expected_version == 1
            }),
        format!("error={error:?}, state={timed_out:?}"),
    )?;
    harness.source_success(WorkerCommand::AbortSource)?;
    let resumed =
        state_result(harness.definition.id, harness.source_success(WorkerCommand::ThawSource)?)?;
    let continued =
        state_result(harness.definition.id, harness.source_success(WorkerCommand::Read)?)?;
    let dump = harness.dump_source()?;
    harness.observe(
        "safe-point-unavailable-retains-source",
        resumed.canonical_phase == contract_core::HandoffPhase::Running
            && continued.canonical_phase == contract_core::HandoffPhase::Running
            && continued.component_instantiated
            && continued.component.as_ref().is_some_and(|component| {
                component.phase == WorkloadPhaseView::Armed && component.expected_version == 1
            })
            && dump.canonical_state.phase == contract_core::HandoffPhase::Running
            && dump.canonical_state.ownership.owner == Some(harness.fixture.ids.source_node)
            && dump.canonical_state.exported_snapshot.is_none(),
        format!(
            "resumed={:?}, continued={continued:?}, ownership={:?}",
            resumed.canonical_phase, dump.canonical_state.ownership
        ),
    )
}

fn run_live_resource_rejection(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    harness.bootstrap()?;
    harness.begin_quiesce()?;
    harness.source_success(WorkerCommand::InjectUnsupportedLiveResource)?;
    let error = harness.source_rejection(WorkerCommand::FreezeSource)?;
    harness.observe(
        "live-resource-freeze-rejected",
        error.code == WorkerErrorCode::Adapter && error.message.contains("live resource"),
        format!("error={error:?}"),
    )?;
    let export = harness.source_rejection(WorkerCommand::ExportSourceSnapshot)?;
    harness.observe(
        "rejected-freeze-exports-no-snapshot",
        export.code == WorkerErrorCode::InvalidState,
        format!("error={export:?}"),
    )?;
    harness.source_success(WorkerCommand::ClearUnsupportedLiveResource)?;
    let rolled_back =
        state_result(harness.definition.id, harness.source_success(WorkerCommand::Read)?)?;
    harness.source_success(WorkerCommand::AbortSource)?;
    let resumed =
        state_result(harness.definition.id, harness.source_success(WorkerCommand::ThawSource)?)?;
    let continued =
        state_result(harness.definition.id, harness.source_success(WorkerCommand::Read)?)?;
    let dump = harness.dump_source()?;
    harness.observe(
        "live-resource-rejection-retains-source",
        resumed.canonical_phase == contract_core::HandoffPhase::Running
            && dump.canonical_state.phase == contract_core::HandoffPhase::Running
            && dump.canonical_state.ownership.owner == Some(harness.fixture.ids.source_node)
            && dump.canonical_state.exported_snapshot.is_none(),
        format!(
            "resumed={:?}, canonical={:?}, ownership={:?}",
            resumed.canonical_phase, dump.canonical_state.phase, dump.canonical_state.ownership
        ),
    )?;
    harness.observe(
        "live-resource-rejection-rolls-back-guest",
        [rolled_back.component.as_ref(), continued.component.as_ref()].into_iter().all(
            |component| {
                component.is_some_and(|component| {
                    component.phase == WorkloadPhaseView::Armed && component.expected_version == 1
                })
            },
        ),
        format!(
            "after_rejection={:?}, after_resume={:?}",
            rolled_back.component, continued.component
        ),
    )
}

fn run_unknown_kv_reconciliation(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    harness.bootstrap()?;
    let dump = harness.dump_source()?;
    let reconciled = dump
        .journal
        .iter()
        .any(|entry| matches!(entry.event.kind, contract_core::EventKind::EffectReconciled { .. }));
    harness.observe(
        "unknown-kv-outcome-reconciled",
        reconciled
            && dump.canonical_state.key_value.last_version == Some(1)
            && fault_fired(&dump, FaultPointSpec::AfterKvCommit),
        format!(
            "reconciled={reconciled}, version={:?}, fault={:?}",
            dump.canonical_state.key_value.last_version, dump.fault_observation
        ),
    )?;
    harness.begin_quiesce()?;
    let transfer = harness.freeze()?;
    harness.export(transfer)?;
    harness.normal_commit()?;
    harness.deliver_pending_timer()
}

#[derive(Clone, Copy)]
enum ValidationFailure {
    CorruptSnapshot,
    Version,
    Profile,
    TimerSupport,
}

fn run_snapshot_validation_rejection(
    harness: &mut CaseHarness,
    failure: ValidationFailure,
) -> Result<(), RunnerError> {
    harness.bootstrap_snapshot()?;
    let mut envelope = snapshot_envelope(harness)?;
    let mut expectations = SnapshotExpectationOverrides::default();
    let mut support = DestinationSupportMode::Compatible;
    match failure {
        ValidationFailure::CorruptSnapshot => {
            envelope.integrity = contract_core::Digest::from_bytes([0xa5; 32]);
        }
        ValidationFailure::Version => {
            expectations.profile_version = Some(contract_core::SchemaVersion::new(u16::MAX, 0));
        }
        ValidationFailure::Profile => {
            expectations.profile_digest = Some(contract_core::Digest::from_bytes([0x5a; 32]));
        }
        ValidationFailure::TimerSupport => {
            support = DestinationSupportMode::TimerSemanticsUnsupported;
        }
    }
    let error = harness.destination_rejection(WorkerCommand::ValidateDestination {
        envelope,
        expectations,
        support,
    })?;
    harness.observe(
        "destination-validation-rejected-before-bindings",
        matches!(error.code, WorkerErrorCode::Runtime | WorkerErrorCode::Adapter),
        format!("error={error:?}"),
    )?;
    let source = harness.dump_source()?;
    harness.observe(
        "validation-rejection-retains-source",
        source.canonical_state.ownership.owner == Some(harness.fixture.ids.source_node),
        format!("ownership={:?}", source.canonical_state.ownership),
    )?;
    abort_precommit_to_source(harness, "validation-rejection-aborts-to-source")
}

fn run_prepare_rejection(
    harness: &mut CaseHarness,
    expected_provider: &str,
) -> Result<(), RunnerError> {
    harness.bootstrap_snapshot()?;
    harness.load_destination(&[contract_core::HandoffPhase::Exported])?;
    let error = harness.destination_rejection(WorkerCommand::PrepareDestination)?;
    harness.observe(
        "destination-prepare-rejected",
        error.code == WorkerErrorCode::Provider
            && error.provider_kind.as_deref() == Some(expected_provider),
        format!("error={error:?}"),
    )?;
    let dump = harness.dump_destination()?;
    harness.observe(
        "prepare-rejection-created-no-bindings",
        dump.canonical_state.phase == contract_core::HandoffPhase::Exported
            && !dump.component_instantiated
            && dump.component.is_none()
            && dump.binding_receipts.is_empty(),
        format!(
            "phase={:?}, component_instantiated={}, receipts={}",
            dump.canonical_state.phase,
            dump.component_instantiated,
            dump.binding_receipts.len()
        ),
    )?;
    abort_precommit_to_source(harness, "prepare-rejection-aborts-to-source")
}

fn run_revoked_capability(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    harness.bootstrap()?;
    harness.source_success(WorkerCommand::RevokeRequiredAuthority {
        authority: RequiredAuthority::Timer,
    })?;
    harness.begin_quiesce()?;
    let transfer = harness.freeze()?;
    harness.export(transfer)?;
    harness.load_destination(&[contract_core::HandoffPhase::Exported])?;
    let error = harness.destination_rejection(WorkerCommand::PrepareDestination)?;
    let dump = harness.dump_destination()?;
    harness.observe(
        "revoked-capability-not-resurrected",
        error.code == WorkerErrorCode::Provider
            && error.provider_kind.as_deref() == Some("Revoked")
            && !dump.component_instantiated
            && dump.component.is_none()
            && dump.binding_receipts.is_empty(),
        format!(
            "error={error:?}, component_instantiated={}, receipts={:?}",
            dump.component_instantiated, dump.binding_receipts
        ),
    )
}

fn run_crash_before_commit(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    harness.bootstrap_snapshot()?;
    harness.load_destination(&[contract_core::HandoffPhase::Exported])?;
    harness.prepare_destination()?;
    harness
        .destination_mut()
        .crash_and_expect_exit(CrashMode::Immediate, 42, WORKER_TIMEOUT)
        .map_err(|source| harness.worker_error("destination", source))?;
    harness.restart_destination("destination-recovery-before-commit")?;
    harness.load_destination(&[contract_core::HandoffPhase::DestinationPrepared])?;
    let repeated = harness.prepare_destination()?;
    let dump = harness.dump_destination()?;
    harness.observe(
        "precommit-crash-retries-inactive-preparation",
        repeated.canonical_phase == contract_core::HandoffPhase::DestinationPrepared
            && dump.leases.iter().all(|lease| lease.owner == harness.fixture.ids.source_node),
        format!("phase={:?}, leases={:?}", repeated.canonical_phase, dump.leases),
    )?;
    abort_precommit_to_source(harness, "precommit-crash-retry-aborts-to-source")
}

fn run_duplicate_prepare(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    harness.bootstrap_snapshot()?;
    harness.load_destination(&[contract_core::HandoffPhase::Exported])?;
    let first = harness.prepare_destination()?;
    let second = harness.prepare_destination()?;
    let dump = harness.dump_destination()?;
    harness.observe(
        "duplicate-prepare-remains-inactive",
        first.state_digest == second.state_digest
            && first.journal_position == second.journal_position
            && dump.leases.iter().all(|lease| lease.owner == harness.fixture.ids.source_node),
        format!("first={first:?}, second={second:?}, leases={:?}", dump.leases),
    )?;
    abort_precommit_to_source(harness, "duplicate-prepare-aborts-to-source")
}

fn run_source_commit_race(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    harness.bootstrap_snapshot()?;
    harness.load_destination(&[contract_core::HandoffPhase::Exported])?;
    harness.prepare_destination()?;
    let mut destination = harness.destination.take().expect("destination worker is present");
    let commit = thread::spawn(move || {
        let result = destination.request_success(WorkerCommand::CommitDestination);
        (destination, result)
    });
    let source_response = harness.source_mut().request(WorkerCommand::StaleSourceKvProbe);
    let (destination, commit_result) = commit.join().map_err(|_| RunnerError::Assertion {
        case_id: harness.definition.id.to_owned(),
        detail: "destination commit thread panicked".to_owned(),
    })?;
    harness.destination = Some(destination);
    let commit_view = state_result(
        harness.definition.id,
        commit_result.map_err(|source| harness.worker_error("destination", source))?,
    )?;
    let source_precommit_admitted =
        match source_response.map_err(|source| harness.worker_error("source", source))? {
            ResponseEnvelope { outcome: ResponseOutcome::Success { result }, .. } => {
                matches!(result.as_ref(), WorkerResult::State { .. })
            }
            ResponseEnvelope { outcome: ResponseOutcome::Error { error }, .. } => {
                harness.observe(
                    "racing-source-lease-probe-lost-to-commit",
                    error.code == WorkerErrorCode::Provider
                        && error.provider_kind.as_deref() == Some("StaleEpoch"),
                    format!("stale_source_kv_probe_error={error:?}"),
                )?;
                false
            }
        };
    harness.latest_destination = Some(commit_view.clone());
    harness.observe(
        "commit-race-selected-destination-epoch",
        commit_view.canonical_phase == contract_core::HandoffPhase::Committed,
        format!(
            "phase={:?}, source_precommit_admitted={source_precommit_admitted}",
            commit_view.canonical_phase
        ),
    )?;
    assert_post_commit_source_rejected(harness)?;
    harness.resume_destination()?;
    Ok(())
}

fn run_crash_after_commit(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    harness.bootstrap_snapshot()?;
    harness.load_destination(&[contract_core::HandoffPhase::Exported])?;
    harness.prepare_destination()?;
    let committed = harness.commit_destination()?;
    harness
        .destination_mut()
        .crash_and_expect_exit(CrashMode::Immediate, 43, WORKER_TIMEOUT)
        .map_err(|source| harness.worker_error("destination", source))?;
    assert_post_commit_source_rejected(harness)?;
    harness.restart_destination("destination-recovery-after-commit")?;
    let recovered = harness.load_destination(&[contract_core::HandoffPhase::Committed])?;
    harness.observe(
        "postcommit-crash-requires-destination-recovery",
        recovered.canonical_phase == contract_core::HandoffPhase::Committed
            && recovered.state_digest == committed.state_digest,
        format!("committed={:?}, recovered={:?}", committed.state_digest, recovered.state_digest),
    )
}

fn run_duplicate_restore(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    run_pending_handoff(harness, false)?;
    let expected = harness
        .latest_destination
        .as_ref()
        .expect("normal handoff records destination state")
        .state_digest;
    harness.restart_destination("duplicate-destination")?;
    let replayed = harness.load_destination(&[contract_core::HandoffPhase::Running])?;
    let error = harness.destination_rejection(WorkerCommand::ResumeDestination)?;
    harness.observe(
        "duplicate-restore-cannot-reactivate",
        replayed.state_digest == expected && error.code == WorkerErrorCode::InvalidState,
        format!("replayed={:?}, error={error:?}", replayed.state_digest),
    )
}

fn run_repeated_cleanup(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    harness.bootstrap()?;
    harness.begin_quiesce()?;
    harness.source_success(WorkerCommand::CancelPending)?;
    let transfer = harness.freeze()?;
    harness.export(transfer)?;
    let first_cleanup = state_result(
        harness.definition.id,
        harness.source_success(WorkerCommand::CleanupPendingTimer)?,
    )?;
    let second_cleanup = state_result(
        harness.definition.id,
        harness.source_success(WorkerCommand::CleanupPendingTimer)?,
    )?;
    harness.observe(
        "cancel-cleanup-idempotent-after-export",
        first_cleanup.state_digest == second_cleanup.state_digest
            && first_cleanup.journal_position == second_cleanup.journal_position,
        format!("first={first_cleanup:?}, second={second_cleanup:?}"),
    )?;
    let first_abort =
        state_result(harness.definition.id, harness.source_success(WorkerCommand::AbortSource)?)?;
    let second_abort =
        state_result(harness.definition.id, harness.source_success(WorkerCommand::AbortSource)?)?;
    harness.observe(
        "abort-cleanup-idempotent",
        first_abort.state_digest == second_abort.state_digest
            && first_abort.journal_position == second_abort.journal_position,
        format!("first={first_abort:?}, second={second_abort:?}"),
    )?;
    let resumed =
        state_result(harness.definition.id, harness.source_success(WorkerCommand::ThawSource)?)?;
    let dump = harness.dump_source()?;
    harness.observe(
        "cleanup-does-not-resurrect-timer-or-destination",
        resumed.canonical_phase == contract_core::HandoffPhase::Running
            && dump.canonical_state.ownership.owner == Some(harness.fixture.ids.source_node)
            && matches!(
                dump.canonical_state.timer.status,
                contract_core::TimerStatus::Cancelled | contract_core::TimerStatus::Cleaned
            ),
        format!(
            "phase={:?}, owner={:?}, timer={:?}",
            resumed.canonical_phase,
            dump.canonical_state.ownership.owner,
            dump.canonical_state.timer.status
        ),
    )
}

fn run_durable_write_failure(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    harness.bootstrap_snapshot()?;
    harness.load_destination(&[contract_core::HandoffPhase::Exported])?;
    harness.prepare_destination()?;
    let error = harness.destination_rejection(WorkerCommand::CommitDestination)?;
    harness.observe(
        "failed-durable-commit-not-reported",
        error.code == WorkerErrorCode::Provider
            && error.provider_kind.as_deref() == Some("Unavailable"),
        format!("error={error:?}"),
    )?;
    let destination =
        state_result(harness.definition.id, harness.destination_success(WorkerCommand::Read)?)?;
    let destination_dump = harness.dump_destination()?;
    harness.observe(
        "failed-commit-remains-precommit",
        destination.canonical_phase == contract_core::HandoffPhase::DestinationPrepared
            && !destination.component_instantiated
            && fault_fired(&destination_dump, FaultPointSpec::BeforeCommitBundle),
        format!(
            "phase={:?}, component_instantiated={}, fault={:?}",
            destination.canonical_phase,
            destination.component_instantiated,
            destination_dump.fault_observation
        ),
    )?;
    abort_precommit_to_source(harness, "failed-commit-aborts-to-source")
}

fn abort_precommit_to_source(
    harness: &mut CaseHarness,
    observation: &'static str,
) -> Result<(), RunnerError> {
    harness.archive_destination()?;
    let aborted =
        state_result(harness.definition.id, harness.source_success(WorkerCommand::AbortSource)?)?;
    let resumed =
        state_result(harness.definition.id, harness.source_success(WorkerCommand::ThawSource)?)?;
    let dump = harness.dump_source()?;
    let component_resumed = dump.component.as_ref().is_some_and(|component| {
        component.phase == WorkloadPhaseView::Armed && component.expected_version == 1
    });
    let source_lease_epoch = harness.fixture.activation.initial_lease_epoch;
    harness.observe(
        observation,
        aborted.canonical_phase == contract_core::HandoffPhase::Aborted
            && resumed.canonical_phase == contract_core::HandoffPhase::Running
            && dump.canonical_state.phase == contract_core::HandoffPhase::Running
            && dump.canonical_state.activation.role == contract_core::ActivationRole::Source
            && dump.canonical_state.activation.status == contract_core::ActivationStatus::Active
            && dump.canonical_state.ownership.owner == Some(harness.fixture.ids.source_node)
            && dump.canonical_state.ownership.epoch == source_lease_epoch
            && dump.canonical_state.exported_snapshot.is_none()
            && dump.canonical_state.prepared_destination.is_none()
            && dump.binding_receipts.is_empty()
            && dump.leases.iter().all(|lease| {
                lease.owner == harness.fixture.ids.source_node && lease.epoch == source_lease_epoch
            })
            && component_resumed,
        format!(
            "aborted={:?}, resumed={:?}, canonical={:?}, activation={:?}, ownership={:?}, leases={:?}, receipts={:?}, component={:?}",
            aborted.canonical_phase,
            resumed.canonical_phase,
            dump.canonical_state.phase,
            dump.canonical_state.activation,
            dump.canonical_state.ownership,
            dump.leases,
            dump.binding_receipts,
            dump.component,
        ),
    )
}

fn run_report_failure(harness: &mut CaseHarness) -> Result<(), RunnerError> {
    run_pending_handoff(harness, false)
}

fn snapshot_envelope(
    harness: &CaseHarness,
) -> Result<contract_core::SnapshotEnvelope, RunnerError> {
    harness.snapshot.as_ref().and_then(|transfer| transfer.envelope.clone()).ok_or_else(|| {
        RunnerError::Assertion {
            case_id: harness.definition.id.to_owned(),
            detail: "case has no exported snapshot envelope".to_owned(),
        }
    })
}

fn binding_for_claim(
    dump: &DumpData,
    claim: contract_core::EntityRef,
) -> Option<&contract_core::BindingReceipt> {
    dump.binding_receipts.iter().find(|receipt| receipt.claim == claim)
}

fn receipt_artifact(
    dump: &DumpData,
    claim: contract_core::EntityRef,
) -> Result<Option<BindingReceiptArtifact>, RunnerError> {
    binding_for_claim(dump, claim)
        .map(|receipt| {
            Ok(BindingReceiptArtifact {
                receipt_id: receipt.binding.identity,
                bytes: serde_json::to_vec(receipt).map_err(|error| RunnerError::Json {
                    context: "encode binding receipt".to_owned(),
                    detail: error.to_string(),
                })?,
            })
        })
        .transpose()
}

fn transcript_json_lines(transcripts: &[ArchivedTranscript]) -> Result<Vec<u8>, RunnerError> {
    let mut bytes = Vec::new();
    for transcript in transcripts {
        for line in &transcript.lines {
            serde_json::to_writer(
                &mut bytes,
                &RawTranscriptLine {
                    worker: &transcript.label,
                    pid: transcript.pid,
                    sequence: line.sequence,
                    stream: line.stream,
                    line: &line.line,
                },
            )
            .map_err(|error| RunnerError::Json {
                context: "encode raw worker transcript".to_owned(),
                detail: error.to_string(),
            })?;
            bytes.push(b'\n');
        }
    }
    Ok(bytes)
}

fn assertions_json_lines(assertions: &[AssertionObservation]) -> Result<Vec<u8>, RunnerError> {
    let mut bytes = Vec::new();
    for assertion in assertions {
        serde_json::to_writer(&mut bytes, assertion).map_err(|error| RunnerError::Json {
            context: "encode raw case assertion".to_owned(),
            detail: error.to_string(),
        })?;
        bytes.push(b'\n');
    }
    Ok(bytes)
}

fn semantic_traces(
    case_id: &str,
    fixture: &FixtureSpec,
    snapshot: Option<&SnapshotTransfer>,
    source_final: &DumpData,
    destination_base: Option<&DumpData>,
    destination_final: Option<&DumpData>,
    expected_ownership: Stage1ExpectedOwnership,
) -> Result<Vec<Stage1SemanticTraceArtifact>, RunnerError> {
    let source_claimed = expected_ownership == Stage1ExpectedOwnership::SourceRetained;
    let mut traces = vec![Stage1SemanticTraceArtifact {
        schema_version: STAGE1_SEMANTIC_TRACE_SCHEMA_VERSION.to_owned(),
        role: Stage1TraceRole::Source,
        scope: Stage1JournalScope {
            node: fixture.config_digest_input.source_scope.node,
            component: fixture.config_digest_input.source_scope.component,
        },
        base_cursor: contract_core::JournalPosition::ORIGIN,
        base_state: fixture.source_state.clone(),
        entries: source_final.journal.clone(),
        final_state: source_final.canonical_state.clone(),
        claimed_final: source_claimed,
    }];

    match (destination_base, destination_final) {
        (Some(base), Some(final_dump)) => {
            let base_cursor = snapshot
                .and_then(|transfer| transfer.envelope.as_ref())
                .map(|envelope| envelope.body.snapshot.journal_position)
                .ok_or_else(|| RunnerError::Assertion {
                    case_id: case_id.to_owned(),
                    detail: "destination trace has no snapshot cursor".to_owned(),
                })?;
            traces.push(Stage1SemanticTraceArtifact {
                schema_version: STAGE1_SEMANTIC_TRACE_SCHEMA_VERSION.to_owned(),
                role: Stage1TraceRole::Destination,
                scope: Stage1JournalScope {
                    node: fixture.config_digest_input.destination_scope.node,
                    component: fixture.config_digest_input.destination_scope.component,
                },
                base_cursor,
                base_state: base.canonical_state.clone(),
                entries: final_dump.journal.clone(),
                final_state: final_dump.canonical_state.clone(),
                claimed_final: !source_claimed,
            });
        }
        (None, None) if source_claimed => {}
        (Some(_), None) if source_claimed => {}
        (None, Some(_)) => {
            return Err(RunnerError::Assertion {
                case_id: case_id.to_owned(),
                detail: "destination trace has a final state but no pre-prepare base".to_owned(),
            });
        }
        _ => {
            return Err(RunnerError::Assertion {
                case_id: case_id.to_owned(),
                detail: "destination-owned outcome has no complete destination trace".to_owned(),
            });
        }
    }

    if traces.iter().filter(|trace| trace.claimed_final).count() != 1 {
        return Err(RunnerError::Assertion {
            case_id: case_id.to_owned(),
            detail: "semantic traces must identify exactly one claimed final branch".to_owned(),
        });
    }
    Ok(traces)
}

fn fault_schedule(definition: &Stage1CaseDefinition, plan: &CasePlan) -> Stage1FaultSchedule {
    match definition.class {
        Stage1CaseClass::Acceptance => {
            Stage1FaultSchedule { schedule_id: "none".to_owned(), injections: Vec::new() }
        }
        Stage1CaseClass::FailureRecovery => Stage1FaultSchedule {
            schedule_id: format!("execute-{}", definition.id),
            injections: vec![Stage1FaultInjection {
                transition: definition.id.to_owned(),
                action: format!(
                    "scenario={};source_fault={:?};destination_fault={:?};support={:?}",
                    plan.scenario,
                    plan.source_fault,
                    plan.destination_fault,
                    plan.destination_support
                ),
            }],
        },
    }
}

fn spawn_initialized(
    executable: &Path,
    case_id: &str,
    label: &str,
    role: WorkerRole,
    database: &Path,
    options: &FixtureOptions,
    fault: Option<FaultPointSpec>,
) -> Result<WorkerClient, RunnerError> {
    let worker_label = format!("{case_id}-{label}");
    let mut client =
        WorkerClient::spawn(executable, &worker_label, WORKER_TIMEOUT).map_err(|source| {
            RunnerError::Worker { case_id: case_id.to_owned(), role: role_label(role), source }
        })?;
    let result = client
        .request_success(WorkerCommand::Initialize {
            role,
            database_path: database.to_string_lossy().into_owned(),
            options: options.clone(),
            fault,
        })
        .map_err(|source| RunnerError::Worker {
            case_id: case_id.to_owned(),
            role: role_label(role),
            source,
        })?;
    match result {
        WorkerResult::Initialized { role: actual_role, case_id: actual_case }
            if actual_role == role && actual_case == case_id =>
        {
            Ok(client)
        }
        other => Err(RunnerError::Assertion {
            case_id: case_id.to_owned(),
            detail: format!("{label} initialization returned {other:?}"),
        }),
    }
}

const fn role_label(role: WorkerRole) -> &'static str {
    match role {
        WorkerRole::Source => "source",
        WorkerRole::Destination => "destination",
    }
}

fn state_result(case_id: &str, result: WorkerResult) -> Result<StateView, RunnerError> {
    match result {
        WorkerResult::State { view } => Ok(view),
        other => Err(RunnerError::Assertion {
            case_id: case_id.to_owned(),
            detail: format!("expected state result, got {other:?}"),
        }),
    }
}

fn timer_result(
    case_id: &str,
    result: WorkerResult,
) -> Result<(TimerPollView, bool, StateView), RunnerError> {
    match result {
        WorkerResult::Timer { poll, delivered, view } => Ok((poll, delivered, view)),
        other => Err(RunnerError::Assertion {
            case_id: case_id.to_owned(),
            detail: format!("expected timer result, got {other:?}"),
        }),
    }
}

fn archive_client(client: &WorkerClient) -> Result<ArchivedTranscript, RunnerError> {
    Ok(ArchivedTranscript {
        label: client.label().to_owned(),
        pid: client.pid(),
        lines: client.transcript().map_err(|source| RunnerError::Worker {
            case_id: client.label().to_owned(),
            role: "transcript",
            source,
        })?,
    })
}

fn remove_database_files(path: &Path) -> Result<(), RunnerError> {
    for candidate in [
        path.to_path_buf(),
        PathBuf::from(format!("{}-wal", path.display())),
        PathBuf::from(format!("{}-shm", path.display())),
    ] {
        match fs::remove_file(&candidate) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(runner_io("remove previous SQLite file", candidate, source)),
        }
    }
    Ok(())
}

fn elapsed_nanos(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

fn digest_hex(digest: contract_core::Digest) -> String {
    digest.0.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const RESPONSE_SCRIPT: &str = r#"
IFS= read -r line
id=$(printf '%s\n' "$line" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
printf '{"version":1,"id":"%s","outcome":{"status":"success","result":{"kind":"ack"}}}\n' "$id"
"#;

    #[test]
    fn every_stage1_case_has_one_executable_fixture_plan() {
        assert_eq!(STAGE1_CASE_DEFINITIONS.len(), 31);

        let mut case_ids = BTreeSet::new();
        for definition in STAGE1_CASE_DEFINITIONS {
            assert!(case_ids.insert(definition.id), "duplicate case id {}", definition.id);
            assert!(case_kind(definition.id).is_some(), "missing runner for {}", definition.id);

            let plan = CasePlan::new(definition).expect("registered cases have executable plans");
            let fixture = FixtureSpec::with_options(plan.options)
                .expect("registered case plans produce deterministic fixtures");
            fixture.config_digest().expect("fixture config is canonically encodable");
            fixture.policy_digest().expect("fixture policy is canonically encodable");
        }
    }

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
printf '{"version":1,"id":"wrong","outcome":{"status":"success","result":{"kind":"ack"}}}\n'
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
