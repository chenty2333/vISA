use std::{
    fs, io,
    path::{Path, PathBuf},
    time::Instant,
};

use super::{
    RunnerError, WORKER_STARTUP_TIMEOUT, WORKER_TIMEOUT, WorkerClient, harness::ArchivedTranscript,
    runner_io,
};
use crate::{
    fixture::FixtureOptions,
    protocol::{
        FaultPointSpec, RuntimeImplementation, StateView, TimerPollView, WorkerCommand,
        WorkerResult, WorkerRole,
    },
};

pub(super) struct WorkerInitialization<'a> {
    label: &'a str,
    role: WorkerRole,
    runtime: RuntimeImplementation,
    database: &'a Path,
    options: &'a FixtureOptions,
    fault: Option<FaultPointSpec>,
}

impl<'a> WorkerInitialization<'a> {
    pub(super) const fn new(
        label: &'a str,
        role: WorkerRole,
        runtime: RuntimeImplementation,
        database: &'a Path,
        options: &'a FixtureOptions,
    ) -> Self {
        Self { label, role, runtime, database, options, fault: None }
    }

    pub(super) const fn with_fault(mut self, fault: Option<FaultPointSpec>) -> Self {
        self.fault = fault;
        self
    }
}

pub(super) fn spawn_initialized(
    executable: &Path,
    case_id: &str,
    initialization: WorkerInitialization<'_>,
) -> Result<WorkerClient, RunnerError> {
    let WorkerInitialization { label, role, runtime, database, options, fault } = initialization;
    let worker_label = format!("{case_id}-{label}");
    let mut client =
        WorkerClient::spawn(executable, &worker_label, WORKER_TIMEOUT).map_err(|source| {
            RunnerError::Worker { case_id: case_id.to_owned(), role: role_label(role), source }
        })?;
    let result = client
        .request_success_with_timeout(
            WorkerCommand::Initialize {
                role,
                runtime,
                database_path: database.to_string_lossy().into_owned(),
                options: options.clone(),
                fault,
            },
            WORKER_STARTUP_TIMEOUT,
        )
        .map_err(|source| RunnerError::Worker {
            case_id: case_id.to_owned(),
            role: role_label(role),
            source,
        })?;
    match result {
        WorkerResult::Initialized {
            role: actual_role,
            case_id: actual_case,
            runtime: observed_runtime,
        } if actual_role == role
            && actual_case == case_id
            && runtime_identity_matches(runtime, &observed_runtime) =>
        {
            client.set_runtime_identity(observed_runtime);
            Ok(client)
        }
        other => Err(RunnerError::Assertion {
            case_id: case_id.to_owned(),
            detail: format!("{label} initialization returned {other:?}"),
        }),
    }
}

fn runtime_identity_matches(
    requested: RuntimeImplementation,
    observed: &crate::protocol::RuntimeIdentityView,
) -> bool {
    match requested {
        RuntimeImplementation::Wasmtime => {
            observed.implementation == "visa_wasmtime"
                && observed.engine == "wasmtime"
                && observed.translation_provenance.is_none()
        }
        RuntimeImplementation::JcoNode => {
            observed.implementation.starts_with("visa_jco_node+")
                && observed.engine == "node+v8"
                && observed.translation_provenance.as_ref().is_some_and(|provenance| {
                    provenance.execution_carrier == visa_jco_node::JCO_NODE_EXECUTION_CARRIER
                })
        }
    }
}

const fn role_label(role: WorkerRole) -> &'static str {
    match role {
        WorkerRole::Source => "source",
        WorkerRole::Destination => "destination",
    }
}

pub(super) fn state_result(case_id: &str, result: WorkerResult) -> Result<StateView, RunnerError> {
    match result {
        WorkerResult::State { view } => Ok(view),
        other => Err(RunnerError::Assertion {
            case_id: case_id.to_owned(),
            detail: format!("expected state result, got {other:?}"),
        }),
    }
}

pub(super) fn timer_result(
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

pub(super) fn archive_client(client: &WorkerClient) -> Result<ArchivedTranscript, RunnerError> {
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

pub(super) fn remove_database_files(path: &Path) -> Result<(), RunnerError> {
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

pub(super) fn elapsed_nanos(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

pub(super) fn digest_hex(digest: contract_core::Digest) -> String {
    digest.0.iter().map(|byte| format!("{byte:02x}")).collect()
}
