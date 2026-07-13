use std::{
    fmt, io,
    path::{Path, PathBuf},
    time::Duration,
};

use crate::{evidence::CaseExecutionRecord, protocol::RuntimeIdentityView};

const WORKER_TIMEOUT: Duration = Duration::from_secs(10);
// JcoNode initialization and destination activation include owned-graph and
// carrier verification plus, where applicable, Node/V8 startup. Keep their liveness
// budget distinct from steady-state worker command handling.
const WORKER_STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const TIMER_MARGIN: Duration = Duration::from_millis(20);

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
    pub source_runtime: RuntimeIdentityView,
    pub destination_runtime: RuntimeIdentityView,
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

mod registry;
mod worker_client;

pub use worker_client::{TranscriptLine, TranscriptStream, WorkerClient, WorkerClientError};

mod stage1;

pub use stage1::{run_stage1, run_stage1_with_runtimes};
mod stage2;

pub use stage2::{
    Stage2CellPlan, Stage2RunOutput, Stage2RunnerError, Stage2StrictLineageSources,
    run_stage2_matrix, run_stage2_strict_matrix,
};
mod provenance;

fn runner_io(operation: &'static str, path: impl AsRef<Path>, source: io::Error) -> RunnerError {
    RunnerError::Io { operation, path: path.as_ref().to_path_buf(), source }
}

mod artifacts;
mod finalize;
mod harness;
mod scenarios;
mod support;
