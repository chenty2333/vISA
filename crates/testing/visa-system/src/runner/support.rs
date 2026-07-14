use std::{
    fs, io,
    path::{Path, PathBuf},
    time::Instant,
};

use super::{
    RoleLaunchers, RunnerError, WORKER_STARTUP_TIMEOUT, WORKER_TIMEOUT, WorkerClient,
    harness::ArchivedTranscript, runner_io,
};
use crate::{
    fixture::FixtureOptions,
    protocol::{
        FaultPointSpec, ImplementationLineageView, RuntimeImplementation, StateView, TimerPollView,
        WorkerCommand, WorkerResult, WorkerRole,
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
    launchers: &RoleLaunchers,
    case_id: &str,
    initialization: WorkerInitialization<'_>,
) -> Result<WorkerClient, RunnerError> {
    let WorkerInitialization { label, role, runtime, database, options, fault } = initialization;
    let worker_label = format!("{case_id}-{label}");
    let mut client =
        WorkerClient::spawn_with_launcher(launchers.for_role(role), &worker_label, WORKER_TIMEOUT)
            .map_err(|source| RunnerError::Worker {
                case_id: case_id.to_owned(),
                role: role_label(role),
                source,
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
            prepared_runtime,
            live_runtime,
        } if actual_role == role
            && actual_case == case_id
            && runtime_identity_matches(runtime, &prepared_runtime)
            && match role {
                WorkerRole::Source => live_runtime.as_ref() == Some(&prepared_runtime),
                WorkerRole::Destination => live_runtime.is_none(),
            } =>
        {
            client.set_runtime_identity(*prepared_runtime);
            Ok(client)
        }
        other => Err(RunnerError::Assertion {
            case_id: case_id.to_owned(),
            detail: format!("{label} initialization returned {other:?}"),
        }),
    }
}

pub(super) fn spawn_uninitialized_for_role(
    launchers: &RoleLaunchers,
    case_id: &str,
    label: &str,
    role: WorkerRole,
) -> Result<WorkerClient, RunnerError> {
    let worker_label = format!("{case_id}-{label}");
    WorkerClient::spawn_with_launcher(launchers.for_role(role), worker_label, WORKER_TIMEOUT)
        .map_err(|source| RunnerError::Worker {
            case_id: case_id.to_owned(),
            role: role_label(role),
            source,
        })
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
                && observed.implementation_lineage.is_none()
        }
        RuntimeImplementation::JcoNode => {
            observed.implementation.starts_with("visa_jco_node+")
                && observed.engine == "node+v8"
                && observed.translation_provenance.as_ref().is_some_and(|provenance| {
                    provenance.execution_carrier == visa_jco_node::JCO_NODE_EXECUTION_CARRIER
                })
                && observed.implementation_lineage.is_none()
        }
        RuntimeImplementation::Wacogo => observed.implementation == "visa_wacogo"
            && observed.engine == "partite-ai/wacogo+wazero"
            && observed.translation_provenance.is_none()
            && observed.implementation_lineage.as_ref().is_some_and(|lineage| {
                matches!(
                    lineage,
                    ImplementationLineageView::Wacogo {
                        source_lock_schema,
                        source_lock_sha256,
                        derivative_id,
                        upstream_module,
                        upstream_version,
                        upstream_revision,
                        upstream_module_sum,
                        upstream_is_qualified_without_patches: false,
                        patchset_id,
                        patchset_sha256,
                        patch_sha256s,
                        patched_tree_sha256,
                        sidecar_executable_sha256,
                        sidecar_executable_size,
                        sidecar_protocol_version,
                        execution_carrier,
                        wacogo_version,
                        wacogo_revision,
                        wazero_version,
                        go_version,
                        target,
                        main_module,
                    } if source_lock_schema == visa_wacogo::SOURCE_LOCK_SCHEMA
                        && source_lock_sha256 == visa_wacogo::SOURCE_LOCK_SHA256
                        && derivative_id == visa_wacogo::DERIVATIVE_ID
                        && upstream_module == visa_wacogo::UPSTREAM_MODULE
                        && upstream_version == visa_wacogo::WACOGO_VERSION
                        && upstream_revision == visa_wacogo::WACOGO_REVISION
                        && upstream_module_sum == visa_wacogo::UPSTREAM_MODULE_SUM
                        && patchset_id == visa_wacogo::PATCHSET_ID
                        && patchset_sha256 == visa_wacogo::PATCHSET_SHA256
                        && patch_sha256s.iter().map(String::as_str).eq(visa_wacogo::PATCH_SHA256S)
                        && patched_tree_sha256 == visa_wacogo::PATCHED_TREE_SHA256
                        && sidecar_executable_sha256 == visa_wacogo::SIDECAR_EXECUTABLE_SHA256
                        && *sidecar_executable_size == visa_wacogo::SIDECAR_EXECUTABLE_SIZE
                        && *sidecar_protocol_version == 1
                        && execution_carrier == "owned-component-stdin-frame-v1"
                        && wacogo_version == visa_wacogo::WACOGO_VERSION
                        && wacogo_revision == visa_wacogo::WACOGO_REVISION
                        && wazero_version == visa_wacogo::WAZERO_VERSION
                        && go_version == visa_wacogo::GO_VERSION
                        && target == visa_wacogo::TARGET
                        && main_module == visa_wacogo::MAIN_MODULE
                )
            }),
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
