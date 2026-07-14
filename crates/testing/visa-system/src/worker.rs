use std::io::{self, BufRead, Write};

use contract_core::{
    EffectKind, EffectRequest, EvidenceKind, EvidenceRef, HandoffPhase, IdempotencyKey, Identity,
    Replay, SchemaVersion, TimerDisposition,
};
use substrate_api::{JournalPort, KvPort, LeasePort};
use substrate_host::SqliteProvider;
use visa_profile::ProviderSupport;
use visa_runtime::{
    CommandReceipt, Coordinator, RuntimeError, SafePointTimer, SnapshotExpectations, TimerPoll,
    canonical_digest, validate_snapshot,
};
#[cfg(test)]
use visa_wasmtime::ComponentAdapter;
use visa_wasmtime::{
    AdapterError, AdapterFailureKind, ComponentStatus, PortableComponentState,
    PreflightExpectations, WorkloadFailureKind, WorkloadPhase,
};

use crate::{
    fixture::{FixtureError, FixtureSpec, OpenProviders, derive_identity},
    protocol::{
        AdapterFailureKindView, ComponentStatusView, CrashMode, DestinationSupportMode,
        FaultObservationView, INVALID_REQUEST_ID, ImplementationLineageView, LeaseRecordView,
        PROTOCOL_VERSION, RequestEnvelope, RequiredAuthority, ResponseEnvelope,
        RuntimeIdentityView, RuntimeImplementation, SafePointTimerView,
        SnapshotExpectationOverrides, StateView, TimerPollView, TranslationProvenanceView,
        WorkerCommand, WorkerError, WorkerErrorCode, WorkerResult, WorkerRole,
        WorkloadFailureKindView, WorkloadPhaseView,
    },
};

mod runtime_registry;

use runtime_registry::{
    Adapter, PreparedAdapter, RuntimeMetadata, instantiate_prepared_adapter, preflight_adapter,
};

const MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunExit {
    EndOfInput,
    Requested(i32),
}

#[derive(Debug)]
pub struct WorkerTurn {
    pub response: Option<ResponseEnvelope>,
    pub exit: Option<i32>,
}

struct SourceWorker {
    adapter: Adapter,
    portable_state: Option<PortableComponentState>,
}

struct DestinationPending {
    provider: Option<SqliteProvider>,
    prepared: Option<PreparedAdapter>,
    runtime: RuntimeImplementation,
}

impl DestinationPending {
    fn teardown_prepared(&mut self) -> Result<(), AdapterError> {
        if let Some(mut prepared) = self.prepared.take() {
            prepared.teardown()?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct PendingTimerDelivery {
    arm_operation: Identity,
    evidence: EvidenceRef,
}

struct DestinationWorker {
    coordinator: Option<Coordinator<SqliteProvider>>,
    adapter: Option<Adapter>,
    prepared: Option<PreparedAdapter>,
    portable_state: PortableComponentState,
    remaining_duration_ns: u64,
    pending_timer_delivery: Option<PendingTimerDelivery>,
}

impl DestinationWorker {
    fn coordinator(&self) -> Result<&Coordinator<SqliteProvider>, WorkerError> {
        if let Some(adapter) = &self.adapter {
            Ok(adapter.coordinator())
        } else {
            self.coordinator
                .as_ref()
                .ok_or_else(|| invalid_state("destination coordinator is unavailable"))
        }
    }

    fn coordinator_mut(&mut self) -> Result<&mut Coordinator<SqliteProvider>, WorkerError> {
        if let Some(adapter) = &mut self.adapter {
            Ok(adapter.coordinator_mut())
        } else {
            self.coordinator
                .as_mut()
                .ok_or_else(|| invalid_state("destination coordinator is unavailable"))
        }
    }

    fn adapter_mut(&mut self) -> Result<&mut Adapter, WorkerError> {
        self.adapter
            .as_mut()
            .ok_or_else(|| invalid_state("destination component has not been instantiated"))
    }

    const fn component_instantiated(&self) -> bool {
        self.adapter.is_some()
    }
}

enum WorkerState {
    Uninitialized,
    Source(Box<SourceWorker>),
    DestinationPending(Box<DestinationPending>),
    Destination(Box<DestinationWorker>),
}

pub struct Worker {
    fixture: Option<FixtureSpec>,
    database_path: Option<String>,
    state: WorkerState,
}

impl Worker {
    pub const fn new() -> Self {
        Self { fixture: None, database_path: None, state: WorkerState::Uninitialized }
    }

    pub fn handle(&mut self, request: RequestEnvelope) -> WorkerTurn {
        if request.version != PROTOCOL_VERSION {
            return WorkerTurn {
                response: Some(ResponseEnvelope::error(
                    request.id,
                    WorkerError::new(
                        WorkerErrorCode::Protocol,
                        format!("unsupported protocol version {}", request.version),
                    ),
                )),
                exit: None,
            };
        }
        let id = request.id;
        match request.command {
            WorkerCommand::Crash { mode: CrashMode::Immediate, exit_code } => {
                WorkerTurn { response: None, exit: Some(exit_code) }
            }
            WorkerCommand::Crash { mode: CrashMode::AfterResponse, exit_code } => WorkerTurn {
                response: Some(ResponseEnvelope::success(id, WorkerResult::Ack)),
                exit: Some(exit_code),
            },
            command => {
                let response = match self.execute(command) {
                    Ok(result) => ResponseEnvelope::success(id, result),
                    Err(error) => ResponseEnvelope::error(id, error),
                };
                WorkerTurn { response: Some(response), exit: None }
            }
        }
    }

    fn execute(&mut self, command: WorkerCommand) -> Result<WorkerResult, WorkerError> {
        match command {
            WorkerCommand::Initialize { role, runtime, database_path, options, fault } => {
                self.initialize(role, runtime, &database_path, options, fault)
            }
            WorkerCommand::BootstrapSource => self.bootstrap_source(),
            WorkerCommand::Read => self.state_result(),
            WorkerCommand::BeginQuiesce => self.begin_quiesce(),
            WorkerCommand::FreezeSource => self.freeze_source(),
            WorkerCommand::ExportSourceSnapshot => self.export_source_snapshot(),
            WorkerCommand::AbortSource => self.abort_source(),
            WorkerCommand::ThawSource => self.thaw_source(),
            WorkerCommand::CancelPending => self.cancel_pending(),
            WorkerCommand::CleanupPendingTimer => self.cleanup_pending_timer(),
            WorkerCommand::InjectUnsupportedLiveResource => self.inject_unsupported_live_resource(),
            WorkerCommand::ClearUnsupportedLiveResource => self.clear_unsupported_live_resource(),
            WorkerCommand::RevokeRequiredAuthority { authority } => {
                self.revoke_required_authority(authority)
            }
            WorkerCommand::StaleSourceKvProbe => self.stale_source_kv_probe(),
            WorkerCommand::AdversarialStaleKvWriteProbe => self.adversarial_stale_kv_write_probe(),
            WorkerCommand::DuplicateCompletionKvProbe => self.duplicate_completion_kv_probe(),
            WorkerCommand::ValidateDestination { envelope, expectations, support } => {
                self.validate_destination(&envelope, &expectations, support)
            }
            WorkerCommand::LoadDestination { envelope, component_state } => {
                self.load_destination(envelope, component_state)
            }
            WorkerCommand::PrepareDestination => self.prepare_destination(),
            WorkerCommand::CommitDestination => self.commit_destination(),
            WorkerCommand::ResumeDestination => self.resume_destination(),
            WorkerCommand::PollTimer { deliver } => self.poll_timer(deliver),
            WorkerCommand::Dump => self.dump(),
            WorkerCommand::Crash { .. } => unreachable!("crash commands are handled separately"),
        }
    }

    fn initialize(
        &mut self,
        role: WorkerRole,
        runtime: RuntimeImplementation,
        database_path: &str,
        options: crate::fixture::FixtureOptions,
        fault: Option<crate::protocol::FaultPointSpec>,
    ) -> Result<WorkerResult, WorkerError> {
        if !matches!(self.state, WorkerState::Uninitialized) {
            return Err(invalid_state("worker is already initialized"));
        }
        if database_path.is_empty() {
            return Err(WorkerError::new(
                WorkerErrorCode::Protocol,
                "database path must not be empty",
            ));
        }

        let fixture = FixtureSpec::with_options(options).map_err(fixture_error)?;
        let OpenProviders { mut source, mut destination } =
            fixture.open_providers(database_path).map_err(fixture_error)?;
        let fault = fault.map(Into::into);
        let (state, prepared_runtime, live_runtime) = match role {
            WorkerRole::Source => {
                if let Some(fault) = fault {
                    source.inject_failure_once(fault);
                }
                let coordinator = Coordinator::recover(fixture.source_state.clone(), source)
                    .map_err(runtime_error)?;
                let portable_state = if coordinator.state().portable_state.is_empty() {
                    None
                } else {
                    Some(
                        PortableComponentState::try_from_bytes(
                            coordinator.state().portable_state.clone(),
                        )
                        .map_err(|error| {
                            WorkerError::new(
                                WorkerErrorCode::Adapter,
                                format!("invalid recovered component state: {error:?}"),
                            )
                        })?,
                    )
                };
                let prepared = preflight_adapter(
                    runtime,
                    crate::component::bytes(),
                    &fixture.profile,
                    &provider_support(&fixture, DestinationSupportMode::Compatible),
                    PreflightExpectations {
                        component_digest: fixture.component_digest,
                        profile_digest: fixture.profile_digest,
                    },
                )
                .map_err(adapter_error)?;
                let prepared_runtime = prepared.runtime_metadata();
                let adapter = instantiate_prepared_adapter(prepared, coordinator)
                    .map_err(|failure| adapter_error(failure.error))?;
                let live_runtime = adapter.runtime_metadata();
                if prepared_runtime != live_runtime {
                    return Err(adapter_error(AdapterError::UnsupportedRuntimeFeature(
                        "source prepared/live runtime metadata drift escaped the registry".into(),
                    )));
                }
                (
                    WorkerState::Source(Box::new(SourceWorker { adapter, portable_state })),
                    prepared_runtime,
                    Some(live_runtime),
                )
            }
            WorkerRole::Destination => {
                if let Some(fault) = fault {
                    destination.inject_failure_once(fault);
                }
                let prepared = preflight_adapter(
                    runtime,
                    crate::component::bytes(),
                    &fixture.profile,
                    &provider_support(&fixture, DestinationSupportMode::Compatible),
                    PreflightExpectations {
                        component_digest: fixture.component_digest,
                        profile_digest: fixture.profile_digest,
                    },
                )
                .map_err(adapter_error)?;
                let prepared_runtime = prepared.runtime_metadata();
                (
                    WorkerState::DestinationPending(Box::new(DestinationPending {
                        provider: Some(destination),
                        prepared: Some(prepared),
                        runtime,
                    })),
                    prepared_runtime,
                    None,
                )
            }
        };
        let case_id = fixture.options.case_id.clone();
        self.fixture = Some(fixture);
        self.database_path = Some(database_path.to_owned());
        self.state = state;
        Ok(WorkerResult::Initialized {
            role,
            case_id,
            prepared_runtime: Box::new(runtime_identity_view(prepared_runtime)),
            live_runtime: live_runtime.map(runtime_identity_view).map(Box::new),
        })
    }

    fn bootstrap_source(&mut self) -> Result<WorkerResult, WorkerError> {
        let fixture = self.fixture()?.clone();
        let source = self.source_mut()?;
        let phase = source.adapter.coordinator().state().phase;
        if phase == HandoffPhase::Dormant {
            source
                .adapter
                .coordinator_mut()
                .activate(
                    fixture.activation.command,
                    fixture.activation.source_authority,
                    fixture.activation.initial_lease_epoch,
                )
                .map_err(runtime_error)?;
        } else if phase != HandoffPhase::Running {
            return Err(invalid_state(format!("source cannot bootstrap from phase {phase:?}")));
        }
        if source.adapter.status().map_err(adapter_error)?.is_none() {
            if let Some(portable) = source.portable_state.clone() {
                source.adapter.thaw(&portable).map_err(adapter_error)?;
            } else {
                source
                    .adapter
                    .activate(&fixture.activation.to_wasmtime())
                    .map_err(adapter_error)?;
            }
        }
        self.state_result()
    }

    fn begin_quiesce(&mut self) -> Result<WorkerResult, WorkerError> {
        let fixture = self.fixture()?;
        let command = derive_identity(&fixture.options.case_id, "source-begin-quiesce");
        let authority = fixture.ids.source_handoff_authority;
        self.source_mut()?
            .adapter
            .coordinator_mut()
            .begin_quiesce(command, authority)
            .map_err(runtime_error)?;
        self.state_result()
    }

    fn freeze_source(&mut self) -> Result<WorkerResult, WorkerError> {
        let case_id = self.fixture()?.options.case_id.clone();
        let source = self.source_mut()?;
        let safe_point = source
            .adapter
            .safe_point(derive_identity(&case_id, "source-freeze"))
            .map_err(adapter_error)?;
        let component_state = safe_point.state.as_bytes().to_vec();
        let timer = safe_point_timer_view(safe_point.timer);
        source.portable_state = Some(safe_point.state);
        let view = state_view(WorkerRole::Source, &mut source.adapter)?;
        Ok(WorkerResult::SafePoint { component_state, timer, view })
    }

    fn export_source_snapshot(&mut self) -> Result<WorkerResult, WorkerError> {
        let fixture = self.fixture()?.clone();
        let source = self.source_mut()?;
        let component_state = source
            .portable_state
            .as_ref()
            .ok_or_else(|| invalid_state("source has not reached a safe point"))?
            .as_bytes()
            .to_vec();
        let evidence = EvidenceRef {
            identity: derive_identity(&fixture.options.case_id, "snapshot-evidence"),
            kind: EvidenceKind::SnapshotIntegrity,
            digest: source.adapter.coordinator().state_digest().map_err(runtime_error)?,
        };
        let (_, envelope) = source
            .adapter
            .coordinator_mut()
            .export_snapshot(
                derive_identity(&fixture.options.case_id, "source-export"),
                fixture.ids.handoff,
                fixture.ids.snapshot,
                evidence,
            )
            .map_err(runtime_error)?;
        let view = state_view(WorkerRole::Source, &mut source.adapter)?;
        Ok(WorkerResult::Snapshot { envelope: Box::new(envelope), component_state, view })
    }

    fn abort_source(&mut self) -> Result<WorkerResult, WorkerError> {
        let case_id = self.fixture()?.options.case_id.clone();
        self.source_mut()?
            .adapter
            .coordinator_mut()
            .abort_handoff(derive_identity(&case_id, "source-abort"), None, None)
            .map_err(runtime_error)?;
        self.state_result()
    }

    fn thaw_source(&mut self) -> Result<WorkerResult, WorkerError> {
        let case_id = self.fixture()?.options.case_id.clone();
        let source = self.source_mut()?;
        source
            .adapter
            .coordinator_mut()
            .resume_source(derive_identity(&case_id, "source-resume"))
            .map_err(runtime_error)?;
        if source.adapter.status().map_err(adapter_error)?.is_none() {
            let portable = source
                .portable_state
                .clone()
                .ok_or_else(|| invalid_state("source has no portable component state"))?;
            source.adapter.thaw(&portable).map_err(adapter_error)?;
        }
        self.state_result()
    }

    fn cancel_pending(&mut self) -> Result<WorkerResult, WorkerError> {
        match &mut self.state {
            WorkerState::Source(source) => {
                source.adapter.cancel_pending().map_err(adapter_error)?;
            }
            WorkerState::Destination(destination) => {
                destination.adapter_mut()?.cancel_pending().map_err(adapter_error)?;
            }
            _ => return Err(invalid_state("no active component can cancel a pending timer")),
        }
        self.state_result()
    }

    fn cleanup_pending_timer(&mut self) -> Result<WorkerResult, WorkerError> {
        let case_id = self.fixture()?.options.case_id.clone();
        let source = self.source_mut()?;
        let operation = source
            .adapter
            .coordinator()
            .state()
            .operations
            .iter()
            .rev()
            .find(|record| {
                matches!(record.request.kind, EffectKind::TimerCancel { .. })
                    && record.outcome.is_some()
            })
            .ok_or_else(|| invalid_state("no resolved timer cancellation can be cleaned"))?
            .request
            .operation;
        let evidence_identity = derive_identity(&case_id, "source-timer-cleanup-evidence");
        let evidence = EvidenceRef {
            identity: evidence_identity,
            kind: EvidenceKind::Cleanup,
            digest: canonical_digest(&(operation, evidence_identity, EvidenceKind::Cleanup))
                .map_err(|_| {
                    WorkerError::new(
                        WorkerErrorCode::Runtime,
                        "encoding timer cleanup evidence failed",
                    )
                })?,
        };
        source
            .adapter
            .coordinator_mut()
            .cleanup_operation(
                derive_identity(&case_id, "source-timer-cleanup"),
                operation,
                evidence,
            )
            .map_err(runtime_error)?;
        self.state_result()
    }

    fn inject_unsupported_live_resource(&mut self) -> Result<WorkerResult, WorkerError> {
        match &mut self.state {
            WorkerState::Source(source) => {
                source.adapter.inject_unsupported_live_resource().map_err(adapter_error)?;
            }
            WorkerState::Destination(destination) => {
                destination
                    .adapter_mut()?
                    .inject_unsupported_live_resource()
                    .map_err(adapter_error)?;
            }
            _ => return Err(invalid_state("worker has no component resource table")),
        }
        self.state_result()
    }

    fn clear_unsupported_live_resource(&mut self) -> Result<WorkerResult, WorkerError> {
        match &mut self.state {
            WorkerState::Source(source) => {
                source.adapter.clear_unsupported_live_resource().map_err(adapter_error)?;
            }
            WorkerState::Destination(destination) => {
                destination
                    .adapter_mut()?
                    .clear_unsupported_live_resource()
                    .map_err(adapter_error)?;
            }
            _ => return Err(invalid_state("worker has no component resource table")),
        }
        self.state_result()
    }

    fn revoke_required_authority(
        &mut self,
        required: RequiredAuthority,
    ) -> Result<WorkerResult, WorkerError> {
        let fixture = self.fixture()?.clone();
        let (label, authority) = match required {
            RequiredAuthority::Handoff => {
                ("source-revoke-handoff-authority", fixture.ids.source_handoff_authority)
            }
            RequiredAuthority::Timer => {
                ("source-revoke-timer-authority", fixture.ids.source_timer_authority)
            }
            RequiredAuthority::KeyValue => {
                ("source-revoke-key-value-authority", fixture.ids.source_key_value_authority)
            }
        };
        self.source_mut()?
            .adapter
            .coordinator_mut()
            .revoke_authority(derive_identity(&fixture.options.case_id, label), authority)
            .map_err(runtime_error)?;
        self.state_result()
    }

    fn stale_source_kv_probe(&mut self) -> Result<WorkerResult, WorkerError> {
        let source = self.source_mut()?;
        let state = source.adapter.coordinator().state();
        source
            .adapter
            .coordinator()
            .provider()
            .check_lease(
                state.key_value.claim.resource,
                state.activation.node,
                state.ownership.epoch,
            )
            .map_err(|error| {
                WorkerError::provider("stale source key-value lease was rejected", error)
            })?;
        self.state_result()
    }

    fn adversarial_stale_kv_write_probe(&mut self) -> Result<WorkerResult, WorkerError> {
        let fixture = self.fixture()?.clone();
        let database_path = self
            .database_path
            .clone()
            .ok_or_else(|| invalid_state("worker database path is unavailable"))?;
        let source = self.source_mut()?;
        let state = source.adapter.coordinator().state();
        let kind = EffectKind::KeyValueCompareAndSet {
            key: fixture.activation.key.as_bytes().to_vec(),
            expected_version: state.key_value.last_version,
            value: b"adversarial-stale-source-write".to_vec(),
        };
        let request = EffectRequest {
            operation: derive_identity(&fixture.options.case_id, "adversarial-stale-kv-operation"),
            idempotency_key: IdempotencyKey::from_bytes(
                derive_identity(&fixture.options.case_id, "adversarial-stale-kv-idempotency").0,
            ),
            causal_parent: None,
            node: state.activation.node,
            subject: state.component,
            resource: state.key_value.claim.resource,
            authority: fixture.ids.source_key_value_authority,
            lease_epoch: state.ownership.epoch,
            request_digest: canonical_digest(&kind).map_err(|_| {
                WorkerError::new(
                    WorkerErrorCode::Runtime,
                    "encoding adversarial key-value request failed",
                )
            })?,
            kind,
        };
        let mut provider = SqliteProvider::open(
            database_path,
            fixture.config_digest_input.source_scope.to_runtime(),
        )
        .map_err(|error| {
            WorkerError::provider("opening adversarial source provider failed", error)
        })?;
        match provider.compare_and_set(&request) {
            Err(error) => Err(WorkerError::provider(
                "adversarial stale source key-value write was rejected",
                error,
            )),
            Ok(outcome) => Err(WorkerError::new(
                WorkerErrorCode::Runtime,
                format!("adversarial stale source key-value write was accepted: {outcome:?}"),
            )),
        }
    }

    fn duplicate_completion_kv_probe(&mut self) -> Result<WorkerResult, WorkerError> {
        let completion_value = self.fixture()?.activation.completion_value.clone();
        let case_id = self.fixture()?.options.case_id.clone();
        let destination = self.destination_mut()?;
        let request = destination
            .coordinator()?
            .state()
            .operations
            .iter()
            .rev()
            .find(|record| {
                matches!(
                    &record.request.kind,
                    EffectKind::KeyValueCompareAndSet { value, .. }
                        if value == &completion_value && record.outcome.is_some()
                )
            })
            .ok_or_else(|| invalid_state("completion key-value effect has not committed"))?
            .request
            .clone();
        let operation = request.operation;
        let receipt = destination
            .adapter_mut()?
            .coordinator_mut()
            .effect(derive_identity(&case_id, "duplicate-completion-kv-probe"), request)
            .map_err(runtime_error)?;
        let (outcome, replayed) = match receipt {
            CommandReceipt::Effect(receipt) => (Some(receipt.outcome), false),
            CommandReceipt::Replayed(Replay::Operation(record)) => (record.outcome, true),
            CommandReceipt::Replayed(_) => (None, true),
            CommandReceipt::Committed(_) => (None, false),
        };
        let view = destination_state_view(destination)?;
        Ok(WorkerResult::EffectProbe { operation, outcome, replayed, view })
    }

    fn validate_destination(
        &mut self,
        envelope: &contract_core::SnapshotEnvelope,
        overrides: &SnapshotExpectationOverrides,
        support_mode: DestinationSupportMode,
    ) -> Result<WorkerResult, WorkerError> {
        let fixture = self.fixture()?.clone();
        let expectations = snapshot_expectations(&fixture, overrides);
        let (runtime, slot) = match &mut self.state {
            WorkerState::DestinationPending(destination) => {
                destination.teardown_prepared().map_err(adapter_error)?;
                (destination.runtime, &mut destination.prepared)
            }
            _ => return Err(invalid_state("worker is not waiting for destination validation")),
        };
        validate_snapshot(envelope, &expectations).map_err(runtime_error)?;
        let support = provider_support(&fixture, support_mode);
        let prepared = preflight_adapter(
            runtime,
            crate::component::bytes(),
            &fixture.profile,
            &support,
            PreflightExpectations {
                component_digest: expectations.component_digest,
                profile_digest: expectations.profile_digest,
            },
        )
        .map_err(adapter_error)?;
        let runtime = runtime_identity_view(prepared.runtime_metadata());
        *slot = Some(prepared);
        Ok(WorkerResult::Prepared { runtime: Box::new(runtime) })
    }

    fn load_destination(
        &mut self,
        envelope: contract_core::SnapshotEnvelope,
        component_state: Vec<u8>,
    ) -> Result<WorkerResult, WorkerError> {
        let fixture = self.fixture()?.clone();
        if envelope.body.portable_state != component_state {
            return Err(WorkerError::new(
                WorkerErrorCode::Runtime,
                "component state does not match the snapshot body",
            ));
        }
        let portable =
            PortableComponentState::try_from_bytes(component_state).map_err(|error| {
                WorkerError::new(
                    WorkerErrorCode::Adapter,
                    format!("invalid portable component state: {error:?}"),
                )
            })?;
        let expectations =
            snapshot_expectations(&fixture, &SnapshotExpectationOverrides::default());
        let validated = validate_snapshot(&envelope, &expectations).map_err(runtime_error)?;
        let (provider, prepared) = match &mut self.state {
            WorkerState::DestinationPending(destination) => {
                if destination.provider.is_none() {
                    return Err(invalid_state("destination provider is unavailable"));
                }
                if destination.prepared.is_none() {
                    return Err(invalid_state("destination runtime preflight is unavailable"));
                }
                (
                    destination.provider.take().expect("provider presence was checked"),
                    destination.prepared.take().expect("preflight presence was checked"),
                )
            }
            _ => return Err(invalid_state("worker is not waiting for a destination snapshot")),
        };
        let coordinator = Coordinator::restore(validated, provider).map_err(runtime_error)?;
        let remaining_duration_ns = match envelope.body.timer {
            TimerDisposition::Pending { remaining, .. } => remaining.0,
            _ => 0,
        };
        self.state = WorkerState::Destination(Box::new(DestinationWorker {
            coordinator: Some(coordinator),
            adapter: None,
            prepared: Some(prepared),
            portable_state: portable,
            remaining_duration_ns,
            pending_timer_delivery: None,
        }));
        self.state_result()
    }

    fn prepare_destination(&mut self) -> Result<WorkerResult, WorkerError> {
        let fixture = self.fixture()?.clone();
        self.destination_mut()?
            .coordinator_mut()?
            .prepare_destination(
                derive_identity(&fixture.options.case_id, "destination-prepare"),
                fixture.handoff_authority.to_runtime(),
                fixture.timer_authority.to_runtime(),
                fixture.key_value_authority.to_runtime(),
            )
            .map_err(runtime_error)?;
        self.state_result()
    }

    fn commit_destination(&mut self) -> Result<WorkerResult, WorkerError> {
        let case_id = self.fixture()?.options.case_id.clone();
        let idempotency_key = IdempotencyKey::from_bytes(
            derive_identity(&case_id, "destination-commit-idempotency").0,
        );
        self.destination_mut()?
            .coordinator_mut()?
            .commit_handoff(
                derive_identity(&case_id, "destination-commit-command"),
                derive_identity(&case_id, "destination-commit-operation"),
                idempotency_key,
            )
            .map_err(runtime_error)?;
        self.state_result()
    }

    fn resume_destination(&mut self) -> Result<WorkerResult, WorkerError> {
        let fixture = self.fixture()?.clone();
        let case_id = fixture.options.case_id.clone();
        let destination = self.destination_mut()?;
        let phase = destination.coordinator()?.state().phase;
        if phase != HandoffPhase::Committed {
            return Err(invalid_state(format!(
                "destination component can instantiate only after commit, found {phase:?}"
            )));
        }
        if destination.adapter.is_none() {
            let coordinator = destination
                .coordinator
                .take()
                .ok_or_else(|| invalid_state("destination coordinator is unavailable"))?;
            let prepared = destination
                .prepared
                .take()
                .ok_or_else(|| invalid_state("destination runtime preflight is unavailable"))?;
            match instantiate_prepared_adapter(prepared, coordinator) {
                Ok(adapter) => destination.adapter = Some(adapter),
                Err(failure) => {
                    destination.coordinator = Some(failure.coordinator);
                    return Err(adapter_error(failure.error));
                }
            }
        }
        let should_restore = destination.adapter_mut()?.status().map_err(adapter_error)?.is_none();
        if should_restore {
            let portable_state = destination.portable_state.clone();
            let remaining_duration_ns = destination.remaining_duration_ns;
            destination
                .adapter_mut()?
                .restore(&portable_state, remaining_duration_ns)
                .map_err(adapter_error)?;
        }
        destination
            .adapter_mut()?
            .coordinator_mut()
            .resume_destination(derive_identity(&case_id, "destination-resume"))
            .map_err(runtime_error)?;
        self.state_result()
    }

    fn poll_timer(&mut self, deliver: bool) -> Result<WorkerResult, WorkerError> {
        let destination = self.destination_mut()?;
        if let Some(pending) = destination.pending_timer_delivery {
            let poll = TimerPollView::Fired {
                arm_operation: pending.arm_operation,
                evidence: pending.evidence,
            };
            let delivered = if deliver {
                destination
                    .adapter_mut()?
                    .timer_fired(pending.arm_operation)
                    .map_err(adapter_error)?;
                destination.pending_timer_delivery = None;
                true
            } else {
                false
            };
            let view = destination_state_view(destination)?;
            return Ok(WorkerResult::Timer { poll, delivered, view });
        }

        let polled =
            destination.adapter_mut()?.coordinator_mut().poll_timer().map_err(runtime_error)?;
        if let TimerPoll::Fired { arm_operation, evidence, .. } = &polled {
            destination.pending_timer_delivery =
                Some(PendingTimerDelivery { arm_operation: *arm_operation, evidence: *evidence });
        }
        let poll = timer_poll_view(&polled);
        let delivered = if deliver {
            if let Some(pending) = destination.pending_timer_delivery {
                destination
                    .adapter_mut()?
                    .timer_fired(pending.arm_operation)
                    .map_err(adapter_error)?;
                destination.pending_timer_delivery = None;
                true
            } else {
                false
            }
        } else {
            false
        };
        let view = destination_state_view(destination)?;
        Ok(WorkerResult::Timer { poll, delivered, view })
    }

    fn dump(&mut self) -> Result<WorkerResult, WorkerError> {
        let key = self.fixture()?.activation.key.as_bytes().to_vec();
        let (
            coordinator,
            component_instantiated,
            live_runtime,
            component,
            portable_component_state,
        ) = match &mut self.state {
            WorkerState::Source(source) => {
                let component =
                    source.adapter.status().map_err(adapter_error)?.map(component_status_view);
                (
                    source.adapter.coordinator(),
                    true,
                    Some(runtime_identity_view(source.adapter.runtime_metadata())),
                    component,
                    source.portable_state.as_ref().map(|state| state.as_bytes().to_vec()),
                )
            }
            WorkerState::Destination(destination) => {
                let component = destination
                    .adapter
                    .as_mut()
                    .map(|adapter| adapter.status().map_err(adapter_error))
                    .transpose()?
                    .flatten()
                    .map(component_status_view);
                (
                    destination.coordinator()?,
                    destination.component_instantiated(),
                    destination
                        .adapter
                        .as_ref()
                        .map(Adapter::runtime_metadata)
                        .map(runtime_identity_view),
                    component,
                    Some(destination.portable_state.as_bytes().to_vec()),
                )
            }
            _ => return Err(invalid_state("worker has no canonical state to dump")),
        };
        let canonical_state = coordinator.state().clone();
        let state_digest = coordinator.state_digest().map_err(runtime_error)?;
        let journal = coordinator
            .provider()
            .replay_from(None)
            .map_err(|error| WorkerError::provider("replaying scoped journal failed", error))?;
        let mut leases = Vec::new();
        for resource in
            [canonical_state.timer.claim.resource, canonical_state.key_value.claim.resource]
        {
            if let Some(lease) = coordinator
                .provider()
                .current_lease(resource)
                .map_err(|error| WorkerError::provider("reading current lease failed", error))?
            {
                leases.push(LeaseRecordView {
                    resource: lease.resource,
                    owner: lease.owner,
                    epoch: lease.epoch,
                });
            }
        }
        let mut authority_grants = canonical_state.authorities.clone();
        if let Some(prepared) = &canonical_state.prepared_destination {
            authority_grants.extend(prepared.authorities.clone());
        }
        let binding_receipts = canonical_state
            .prepared_destination
            .as_ref()
            .map(|prepared| prepared.bindings.clone())
            .unwrap_or_default();
        let fault_observation = coordinator.provider().fault_observation().map(|observation| {
            FaultObservationView { point: observation.point.into(), count: observation.count }
        });
        let key_value_entry = coordinator
            .provider()
            .inspect_key_value(canonical_state.key_value.claim.resource, &key)
            .map_err(|error| {
                WorkerError::provider("reading observed key-value entry failed", error)
            })?;
        Ok(WorkerResult::Dump {
            canonical_state: Box::new(canonical_state),
            state_digest,
            journal,
            leases,
            authority_grants,
            binding_receipts,
            fault_observation,
            key_value_entry,
            component_instantiated,
            live_runtime,
            component,
            portable_component_state,
        })
    }

    fn state_result(&mut self) -> Result<WorkerResult, WorkerError> {
        let view = match &mut self.state {
            WorkerState::Source(source) => state_view(WorkerRole::Source, &mut source.adapter)?,
            WorkerState::Destination(destination) => destination_state_view(destination)?,
            WorkerState::DestinationPending(_) => {
                return Err(invalid_state("destination snapshot has not been loaded"));
            }
            WorkerState::Uninitialized => return Err(invalid_state("worker is not initialized")),
        };
        Ok(WorkerResult::State { view })
    }

    fn fixture(&self) -> Result<&FixtureSpec, WorkerError> {
        self.fixture.as_ref().ok_or_else(|| invalid_state("worker is not initialized"))
    }

    fn source_mut(&mut self) -> Result<&mut SourceWorker, WorkerError> {
        match &mut self.state {
            WorkerState::Source(source) => Ok(source),
            _ => Err(invalid_state("command requires a source worker")),
        }
    }

    fn destination_mut(&mut self) -> Result<&mut DestinationWorker, WorkerError> {
        match &mut self.state {
            WorkerState::Destination(destination) => Ok(destination),
            _ => Err(invalid_state("command requires a loaded destination worker")),
        }
    }

    fn teardown_normal(&mut self) -> Result<(), WorkerError> {
        match &mut self.state {
            WorkerState::Source(source) => source.adapter.teardown().map_err(adapter_error),
            WorkerState::DestinationPending(destination) => {
                destination.teardown_prepared().map_err(adapter_error)
            }
            WorkerState::Destination(destination) => {
                let live = destination.adapter.as_mut().map_or(Ok(()), Adapter::teardown);
                let prepared =
                    destination.prepared.as_mut().map_or(Ok(()), PreparedAdapter::teardown);
                live.and(prepared).map_err(adapter_error)
            }
            WorkerState::Uninitialized => Ok(()),
        }
    }
}

impl Default for Worker {
    fn default() -> Self {
        Self::new()
    }
}

pub fn run_json_lines<R, W>(mut reader: R, mut writer: W) -> io::Result<RunExit>
where
    R: BufRead,
    W: Write,
{
    let mut worker = Worker::new();
    run_json_lines_with_worker(&mut worker, &mut reader, &mut writer)
}

fn run_json_lines_with_worker<R, W>(
    worker: &mut Worker,
    mut reader: R,
    mut writer: W,
) -> io::Result<RunExit>
where
    R: BufRead,
    W: Write,
{
    let mut line = Vec::new();
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            worker.teardown_normal().map_err(|error| {
                io::Error::other(format!("normal worker EOF teardown failed: {error:?}"))
            })?;
            return Ok(RunExit::EndOfInput);
        }
        if line.last() == Some(&b'\n') {
            line.pop();
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let response = if line.len() > MAX_REQUEST_BYTES {
            ResponseEnvelope::error(
                request_id_from_bytes(&line),
                WorkerError::new(WorkerErrorCode::Protocol, "request exceeds protocol limit"),
            )
        } else {
            match std::str::from_utf8(&line) {
                Ok(line) => match serde_json::from_str::<RequestEnvelope>(line) {
                    Ok(request) if request.version == PROTOCOL_VERSION => {
                        let turn = worker.handle(request);
                        if let Some(response) = turn.response {
                            write_response(&mut writer, &response)?;
                        }
                        if let Some(exit_code) = turn.exit {
                            return Ok(RunExit::Requested(exit_code));
                        }
                        continue;
                    }
                    Ok(request) => ResponseEnvelope::error(
                        request.id,
                        WorkerError::new(
                            WorkerErrorCode::Protocol,
                            format!("unsupported protocol version {}", request.version),
                        ),
                    ),
                    Err(error) => ResponseEnvelope::error(
                        request_id_from_malformed_line(line),
                        WorkerError::new(
                            WorkerErrorCode::Protocol,
                            format!("invalid request: {error}"),
                        ),
                    ),
                },
                Err(error) => ResponseEnvelope::error(
                    INVALID_REQUEST_ID,
                    WorkerError::new(
                        WorkerErrorCode::Protocol,
                        format!("request is not valid UTF-8: {error}"),
                    ),
                ),
            }
        };
        write_response(&mut writer, &response)?;
    }
}

pub fn run_stdio() -> io::Result<RunExit> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    run_json_lines(stdin.lock(), stdout.lock())
}

fn write_response(writer: &mut impl Write, response: &ResponseEnvelope) -> io::Result<()> {
    serde_json::to_writer(&mut *writer, response).map_err(io::Error::other)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

fn request_id_from_malformed_line(line: &str) -> String {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .and_then(|value| value.get("id").and_then(|id| id.as_str()).map(str::to_owned))
        .unwrap_or_else(|| INVALID_REQUEST_ID.to_owned())
}

fn request_id_from_bytes(line: &[u8]) -> String {
    std::str::from_utf8(line)
        .map(request_id_from_malformed_line)
        .unwrap_or_else(|_| INVALID_REQUEST_ID.to_owned())
}

fn runtime_identity_view(metadata: RuntimeMetadata) -> RuntimeIdentityView {
    let RuntimeMetadata { identity, translation_provenance, implementation_lineage } = metadata;
    RuntimeIdentityView {
        implementation: identity.implementation,
        implementation_version: identity.implementation_version,
        engine: identity.engine,
        engine_version: identity.engine_version,
        translation_provenance: translation_provenance.map(|provenance| {
            TranslationProvenanceView {
                jco_version: provenance.runtime.jco_version,
                js_component_bindgen_version: provenance.runtime.js_component_bindgen_version,
                translator: provenance.runtime.translator,
                translator_version: provenance.runtime.translator_version,
                translation_options: provenance.runtime.translation_options,
                node_executable_path: provenance.runtime.node_executable_path,
                node_executable_sha256: digest_hex(provenance.runtime.node_executable_digest),
                node_version: provenance.runtime.node_version,
                v8_version: provenance.runtime.v8_version,
                rpc_protocol_version: provenance.runtime.rpc_protocol_version,
                execution_carrier: provenance.runtime.execution_carrier,
                generated_sha256: digest_hex(provenance.generated_digest),
                driver_sha256: digest_hex(provenance.driver_digest),
                core_module_sha256s: provenance
                    .core_module_digests
                    .into_iter()
                    .map(digest_hex)
                    .collect(),
            }
        }),
        implementation_lineage: implementation_lineage.map(|provenance| {
            ImplementationLineageView::Wacogo {
                source_lock_schema: provenance.source_lock_schema,
                source_lock_sha256: provenance.source_lock_sha256,
                derivative_id: provenance.derivative_id,
                upstream_module: provenance.upstream_module,
                upstream_version: provenance.wacogo_version.clone(),
                upstream_revision: provenance.wacogo_revision.clone(),
                upstream_module_sum: provenance.upstream_module_sum,
                upstream_is_qualified_without_patches: provenance
                    .upstream_is_qualified_without_patches,
                patchset_id: provenance.patchset_id,
                patchset_sha256: provenance.patchset_sha256,
                patch_sha256s: provenance.patch_sha256s,
                patched_tree_sha256: provenance.patched_tree_sha256,
                sidecar_executable_sha256: digest_hex(provenance.executable_digest),
                sidecar_executable_size: provenance.executable_size,
                sidecar_protocol_version: provenance.protocol_version,
                execution_carrier: provenance.execution_carrier,
                wacogo_version: provenance.wacogo_version,
                wacogo_revision: provenance.wacogo_revision,
                wazero_version: provenance.wazero_version,
                go_version: provenance.go_version,
                target: provenance.target,
                main_module: provenance.main_module,
            }
        }),
    }
}

fn digest_hex(digest: contract_core::Digest) -> String {
    digest.0.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn snapshot_expectations(
    fixture: &FixtureSpec,
    overrides: &SnapshotExpectationOverrides,
) -> SnapshotExpectations {
    SnapshotExpectations {
        component_digest: overrides.component_digest.unwrap_or(fixture.component_digest),
        profile_digest: overrides.profile_digest.unwrap_or(fixture.profile_digest),
        profile_version: overrides.profile_version.unwrap_or_else(|| {
            SchemaVersion::new(fixture.profile.version.major, fixture.profile.version.minor)
        }),
        supported_extensions: overrides
            .supported_extensions
            .clone()
            .unwrap_or_else(|| fixture.profile.required_extensions.clone()),
        destination: overrides.destination.unwrap_or(fixture.ids.destination_node),
    }
}

fn provider_support(fixture: &FixtureSpec, mode: DestinationSupportMode) -> ProviderSupport {
    let mut support =
        ProviderSupport::cooperative_handoff_v1(fixture.profile.required_extensions.clone());
    if mode == DestinationSupportMode::TimerSemanticsUnsupported {
        support.timer_cancellation = false;
    }
    support
}

fn state_view(role: WorkerRole, adapter: &mut Adapter) -> Result<StateView, WorkerError> {
    let component = adapter.status().map_err(adapter_error)?.map(component_status_view);
    let coordinator = adapter.coordinator();
    Ok(StateView {
        role,
        canonical_phase: coordinator.state().phase,
        journal_position: coordinator.journal_position(),
        state_digest: coordinator.state_digest().map_err(runtime_error)?,
        component_instantiated: true,
        live_runtime: Some(runtime_identity_view(adapter.runtime_metadata())),
        component,
    })
}

fn destination_state_view(destination: &mut DestinationWorker) -> Result<StateView, WorkerError> {
    let component = destination
        .adapter
        .as_mut()
        .map(|adapter| adapter.status().map_err(adapter_error))
        .transpose()?
        .flatten()
        .map(component_status_view);
    let component_instantiated = destination.component_instantiated();
    let live_runtime =
        destination.adapter.as_ref().map(Adapter::runtime_metadata).map(runtime_identity_view);
    let coordinator = destination.coordinator()?;
    Ok(StateView {
        role: WorkerRole::Destination,
        canonical_phase: coordinator.state().phase,
        journal_position: coordinator.journal_position(),
        state_digest: coordinator.state_digest().map_err(runtime_error)?,
        component_instantiated,
        live_runtime,
        component,
    })
}

fn component_status_view(status: ComponentStatus) -> ComponentStatusView {
    ComponentStatusView {
        session_id: status.session_id,
        key: status.key,
        expected_version: status.expected_version,
        completion_value: status.completion_value,
        timer_operation_id: status.timer_operation_id,
        timer_idempotency_key: status.timer_idempotency_key,
        completion_idempotency_key: status.completion_idempotency_key,
        phase: match status.phase {
            WorkloadPhase::Armed => WorkloadPhaseView::Armed,
            WorkloadPhase::Frozen => WorkloadPhaseView::Frozen,
            WorkloadPhase::Completed => WorkloadPhaseView::Completed,
            WorkloadPhase::Cancelled => WorkloadPhaseView::Cancelled,
        },
    }
}

const fn safe_point_timer_view(timer: SafePointTimer) -> SafePointTimerView {
    match timer {
        SafePointTimer::Idle => SafePointTimerView::Idle,
        SafePointTimer::Pending { remaining, arm_operation } => {
            SafePointTimerView::Pending { remaining, arm_operation }
        }
        SafePointTimer::Completed { arm_operation } => {
            SafePointTimerView::Completed { arm_operation }
        }
        SafePointTimer::Cancelled => SafePointTimerView::Cancelled,
        SafePointTimer::Cleaned => SafePointTimerView::Cleaned,
    }
}

fn timer_poll_view(poll: &TimerPoll) -> TimerPollView {
    match poll {
        TimerPoll::Idle => TimerPollView::Idle,
        TimerPoll::Pending { arm_operation, remaining } => {
            TimerPollView::Pending { arm_operation: *arm_operation, remaining: *remaining }
        }
        TimerPoll::Fired { arm_operation, evidence, .. } => {
            TimerPollView::Fired { arm_operation: *arm_operation, evidence: *evidence }
        }
        TimerPoll::Completed => TimerPollView::Completed,
        TimerPoll::Cancelled => TimerPollView::Cancelled,
        TimerPoll::CancelledObserved { arm_operation, evidence } => {
            TimerPollView::CancelledObserved { arm_operation: *arm_operation, evidence: *evidence }
        }
        TimerPoll::Cleaned => TimerPollView::Cleaned,
        TimerPoll::Absent { arm_operation } => {
            TimerPollView::Absent { arm_operation: *arm_operation }
        }
        TimerPoll::Frozen(disposition) => TimerPollView::Frozen { disposition: *disposition },
    }
}

fn invalid_state(message: impl Into<String>) -> WorkerError {
    WorkerError::new(WorkerErrorCode::InvalidState, message)
}

fn fixture_error(error: FixtureError) -> WorkerError {
    match error {
        FixtureError::CanonicalEncoding => {
            WorkerError::new(WorkerErrorCode::Fixture, error.to_string())
        }
        FixtureError::Provider(provider) => WorkerError::provider(error.to_string(), provider),
    }
}

fn runtime_error(error: RuntimeError) -> WorkerError {
    let message = format!("runtime coordinator failed: {error:?}");
    match error {
        RuntimeError::Provider(provider)
        | RuntimeError::PreparationCleanupFailed(provider)
        | RuntimeError::SafePointRollbackFailed { error: provider, .. } => {
            WorkerError::provider(message, provider)
        }
        _ => WorkerError::new(WorkerErrorCode::Runtime, message),
    }
}

fn adapter_error(error: AdapterError) -> WorkerError {
    let adapter_kind = Some(adapter_failure_kind_view(error.kind()));
    let workload_kind = error.workload_kind().map(workload_failure_kind_view);
    match error {
        AdapterError::Coordinator(runtime) => {
            let mut error = runtime_error(runtime);
            error.adapter_kind = adapter_kind;
            error.workload_kind = workload_kind;
            error
        }
        other => {
            let mut error = WorkerError::new(WorkerErrorCode::Adapter, other.to_string());
            error.adapter_kind = adapter_kind;
            error.workload_kind = workload_kind;
            error
        }
    }
}

const fn adapter_failure_kind_view(kind: AdapterFailureKind) -> AdapterFailureKindView {
    match kind {
        AdapterFailureKind::IncompatibleProfile => AdapterFailureKindView::IncompatibleProfile,
        AdapterFailureKind::ProfileEncoding => AdapterFailureKindView::ProfileEncoding,
        AdapterFailureKind::ProfileDigestMismatch => AdapterFailureKindView::ProfileDigestMismatch,
        AdapterFailureKind::ComponentDigestMismatch => {
            AdapterFailureKindView::ComponentDigestMismatch
        }
        AdapterFailureKind::Engine => AdapterFailureKindView::Engine,
        AdapterFailureKind::InvalidComponent => AdapterFailureKindView::InvalidComponent,
        AdapterFailureKind::Link => AdapterFailureKindView::Link,
        AdapterFailureKind::UnsupportedRuntimeFeature => {
            AdapterFailureKindView::UnsupportedRuntimeFeature
        }
        AdapterFailureKind::Instantiation => AdapterFailureKindView::Instantiation,
        AdapterFailureKind::GuestTrap => AdapterFailureKindView::GuestTrap,
        AdapterFailureKind::Workload => AdapterFailureKindView::Workload,
        AdapterFailureKind::ResourceBinding => AdapterFailureKindView::ResourceBinding,
        AdapterFailureKind::LiveResourcesAtSafePoint => {
            AdapterFailureKindView::LiveResourcesAtSafePoint
        }
        AdapterFailureKind::SafePointStateMismatch => {
            AdapterFailureKindView::SafePointStateMismatch
        }
        AdapterFailureKind::PortableStateMismatch => AdapterFailureKindView::PortableStateMismatch,
        AdapterFailureKind::PortableState => AdapterFailureKindView::PortableState,
        AdapterFailureKind::Coordinator => AdapterFailureKindView::Coordinator,
        AdapterFailureKind::SafePointRollback => AdapterFailureKindView::SafePointRollback,
        AdapterFailureKind::SafePointGuestRollback => {
            AdapterFailureKindView::SafePointGuestRollback
        }
    }
}

const fn workload_failure_kind_view(kind: WorkloadFailureKind) -> WorkloadFailureKindView {
    match kind {
        WorkloadFailureKind::AlreadyActive => WorkloadFailureKindView::AlreadyActive,
        WorkloadFailureKind::InvalidState => WorkloadFailureKindView::InvalidState,
        WorkloadFailureKind::WrongTimer => WorkloadFailureKindView::WrongTimer,
        WorkloadFailureKind::SafePointUnavailable => WorkloadFailureKindView::SafePointUnavailable,
        WorkloadFailureKind::KeyValueDenied => WorkloadFailureKindView::KeyValueDenied,
        WorkloadFailureKind::KeyValueConflict => WorkloadFailureKindView::KeyValueConflict,
        WorkloadFailureKind::KeyValueStaleBinding => WorkloadFailureKindView::KeyValueStaleBinding,
        WorkloadFailureKind::KeyValueIndeterminate => {
            WorkloadFailureKindView::KeyValueIndeterminate
        }
        WorkloadFailureKind::KeyValueUnavailable => WorkloadFailureKindView::KeyValueUnavailable,
        WorkloadFailureKind::TimerDenied => WorkloadFailureKindView::TimerDenied,
        WorkloadFailureKind::TimerStaleBinding => WorkloadFailureKindView::TimerStaleBinding,
        WorkloadFailureKind::TimerNotPending => WorkloadFailureKindView::TimerNotPending,
        WorkloadFailureKind::TimerUnavailable => WorkloadFailureKindView::TimerUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::Cursor,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
        thread,
        time::Duration,
    };

    use contract_core::{CleanupStatus, HandoffPhase};

    use super::*;
    use crate::{
        fixture::FixtureOptions,
        protocol::{ResponseOutcome, WorkerResult},
    };

    static NEXT_DATABASE: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn malformed_request_is_structured_and_the_loop_continues() {
        let crash = serde_json::to_string(&RequestEnvelope::new(
            "stop",
            WorkerCommand::Crash { mode: CrashMode::AfterResponse, exit_code: 17 },
        ))
        .unwrap();
        let input = format!("{{\"id\":\"malformed\"}}\n{crash}\n");
        let mut output = Vec::new();
        assert_eq!(
            run_json_lines(Cursor::new(input), &mut output).unwrap(),
            RunExit::Requested(17)
        );

        let responses = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<ResponseEnvelope>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0].id, "malformed");
        assert!(matches!(
            &responses[0].outcome,
            ResponseOutcome::Error { error }
                if error.code == WorkerErrorCode::Protocol
        ));
        assert!(matches!(
            responses[1].outcome,
            ResponseOutcome::Success { ref result } if matches!(result.as_ref(), WorkerResult::Ack)
        ));
    }

    #[test]
    fn immediate_crash_has_no_response() {
        let request = serde_json::to_string(&RequestEnvelope::new(
            "crash-now",
            WorkerCommand::Crash { mode: CrashMode::Immediate, exit_code: 23 },
        ))
        .unwrap();
        let mut output = Vec::new();
        assert_eq!(
            run_json_lines(Cursor::new(format!("{request}\n")), &mut output).unwrap(),
            RunExit::Requested(23)
        );
        assert!(output.is_empty());
    }

    #[test]
    fn wasmtime_preflight_is_repeatable_and_rejects_invalid_artifacts_structurally() {
        let fixture = FixtureSpec::new("wasmtime-preflight").unwrap();
        let support = provider_support(&fixture, DestinationSupportMode::Compatible);
        let expectations = PreflightExpectations {
            component_digest: fixture.component_digest,
            profile_digest: fixture.profile_digest,
        };
        let first = ComponentAdapter::<SqliteProvider>::preflight(
            crate::component::bytes(),
            &fixture.profile,
            &support,
            expectations,
        )
        .unwrap();
        let second = ComponentAdapter::<SqliteProvider>::preflight(
            crate::component::bytes(),
            &fixture.profile,
            &support,
            expectations,
        )
        .unwrap();
        drop((first, second));

        let invalid = ComponentAdapter::<SqliteProvider>::preflight(
            b"not-a-component",
            &fixture.profile,
            &support,
            PreflightExpectations {
                component_digest: visa_wasmtime::component_digest(b"not-a-component"),
                profile_digest: fixture.profile_digest,
            },
        )
        .expect_err("invalid Component Model bytes must fail before instantiation");
        assert_eq!(invalid.kind(), AdapterFailureKind::InvalidComponent);

        let digest_mismatch = ComponentAdapter::<SqliteProvider>::preflight(
            crate::component::bytes(),
            &fixture.profile,
            &support,
            PreflightExpectations {
                component_digest: contract_core::Digest::ZERO,
                profile_digest: fixture.profile_digest,
            },
        )
        .expect_err("a stale prepared-artifact identity must be rejected");
        assert_eq!(digest_mismatch.kind(), AdapterFailureKind::ComponentDigestMismatch);
    }

    #[test]
    fn destination_load_requires_the_non_executing_preflight_token() {
        let database = TestDatabase::new("missing-preflight");
        let options = FixtureOptions::new("missing-preflight");
        let mut source = Worker::new();
        initialize(&mut source, WorkerRole::Source, database.path(), options.clone());
        invoke(&mut source, WorkerCommand::BootstrapSource).unwrap();
        invoke(&mut source, WorkerCommand::BeginQuiesce).unwrap();
        invoke(&mut source, WorkerCommand::FreezeSource).unwrap();
        let (envelope, component_state) =
            match invoke(&mut source, WorkerCommand::ExportSourceSnapshot).unwrap() {
                WorkerResult::Snapshot { envelope, component_state, .. } => {
                    (*envelope, component_state)
                }
                other => panic!("expected source snapshot, got {other:?}"),
            };

        let mut destination = Worker::new();
        initialize(&mut destination, WorkerRole::Destination, database.path(), options);
        let WorkerState::DestinationPending(pending) = &mut destination.state else {
            panic!("destination must still be pending")
        };
        pending.prepared = None;
        let rejection =
            invoke(&mut destination, WorkerCommand::LoadDestination { envelope, component_state })
                .expect_err("destination load cannot bypass runtime preflight");
        assert_eq!(rejection.code, WorkerErrorCode::InvalidState);
        let WorkerState::DestinationPending(pending) = &destination.state else {
            panic!("rejected load must leave the destination pending")
        };
        assert!(pending.provider.is_some());
    }

    #[test]
    fn source_worker_reaches_and_dumps_a_real_snapshot() {
        let database = TestDatabase::new("source-worker");
        let options = FixtureOptions::new("source-worker");
        let mut source = Worker::new();
        initialize(&mut source, WorkerRole::Source, database.path(), options);
        expect_state(
            invoke(&mut source, WorkerCommand::BootstrapSource).unwrap(),
            HandoffPhase::Running,
        );
        expect_state(
            invoke(&mut source, WorkerCommand::BeginQuiesce).unwrap(),
            HandoffPhase::Quiescing,
        );
        let frozen = invoke(&mut source, WorkerCommand::FreezeSource).unwrap();
        assert!(matches!(
            frozen,
            WorkerResult::SafePoint {
                timer: SafePointTimerView::Pending { .. },
                ref view,
                ..
            } if view.canonical_phase == HandoffPhase::Frozen
        ));
        let snapshot = invoke(&mut source, WorkerCommand::ExportSourceSnapshot).unwrap();
        assert!(matches!(
            snapshot,
            WorkerResult::Snapshot { ref envelope, ref component_state, ref view }
                if envelope.body.portable_state == *component_state
                    && view.canonical_phase == HandoffPhase::Exported
        ));
        let dump = invoke(&mut source, WorkerCommand::Dump).unwrap();
        assert!(matches!(
            dump,
            WorkerResult::Dump {
                ref canonical_state,
                ref journal,
                ref leases,
                portable_component_state: Some(ref state),
                ..
            } if canonical_state.phase == HandoffPhase::Exported
                && !journal.is_empty()
                && leases.len() == 2
                && *state == canonical_state.portable_state
        ));
    }

    #[test]
    fn cancelled_timer_cleanup_is_canonical_and_idempotent() {
        let database = TestDatabase::new("timer-cleanup");
        let options = FixtureOptions::new("timer-cleanup");
        let mut source = Worker::new();
        initialize(&mut source, WorkerRole::Source, database.path(), options);
        invoke(&mut source, WorkerCommand::BootstrapSource).unwrap();
        invoke(&mut source, WorkerCommand::CancelPending).unwrap();
        invoke(&mut source, WorkerCommand::BeginQuiesce).unwrap();
        assert!(matches!(
            invoke(&mut source, WorkerCommand::FreezeSource).unwrap(),
            WorkerResult::SafePoint { timer: SafePointTimerView::Cancelled, .. }
        ));

        let first = invoke(&mut source, WorkerCommand::CleanupPendingTimer).unwrap();
        let WorkerResult::State { view: first_view } = first else {
            panic!("timer cleanup must return canonical state");
        };
        let second = invoke(&mut source, WorkerCommand::CleanupPendingTimer).unwrap();
        let WorkerResult::State { view: second_view } = second else {
            panic!("repeated timer cleanup must return canonical state");
        };
        assert_eq!(second_view.journal_position, first_view.journal_position);
        assert_eq!(second_view.state_digest, first_view.state_digest);

        let WorkerResult::Dump { canonical_state, .. } =
            invoke(&mut source, WorkerCommand::Dump).unwrap()
        else {
            panic!("cleanup state must be dumpable");
        };
        let cancel = canonical_state
            .operations
            .iter()
            .find(|record| matches!(record.request.kind, EffectKind::TimerCancel { .. }))
            .expect("timer cancellation remains in canonical operations");
        assert_eq!(cancel.cleanup, CleanupStatus::Cleaned);
    }

    #[test]
    fn real_workers_handoff_complete_once_and_fence_the_source() {
        let database = TestDatabase::new("worker-handoff");
        let options = FixtureOptions::new("worker-handoff");
        let mut source = Worker::new();
        initialize(&mut source, WorkerRole::Source, database.path(), options.clone());
        invoke(&mut source, WorkerCommand::BootstrapSource).unwrap();
        invoke(&mut source, WorkerCommand::BeginQuiesce).unwrap();
        let (remaining, source_arm) =
            match invoke(&mut source, WorkerCommand::FreezeSource).unwrap() {
                WorkerResult::SafePoint {
                    timer: SafePointTimerView::Pending { remaining, arm_operation },
                    ..
                } => (remaining, arm_operation),
                other => panic!("expected pending source timer, got {other:?}"),
            };
        assert!(remaining.0 > 0);
        let (envelope, component_state) =
            match invoke(&mut source, WorkerCommand::ExportSourceSnapshot).unwrap() {
                WorkerResult::Snapshot { envelope, component_state, .. } => {
                    (*envelope, component_state)
                }
                other => panic!("expected source snapshot, got {other:?}"),
            };

        let mut destination = Worker::new();
        initialize(&mut destination, WorkerRole::Destination, database.path(), options);
        for (result, phase) in [
            (
                invoke(
                    &mut destination,
                    WorkerCommand::LoadDestination { envelope: envelope.clone(), component_state },
                )
                .unwrap(),
                HandoffPhase::Exported,
            ),
            (
                invoke(&mut destination, WorkerCommand::PrepareDestination).unwrap(),
                HandoffPhase::DestinationPrepared,
            ),
            (
                invoke(&mut destination, WorkerCommand::CommitDestination).unwrap(),
                HandoffPhase::Committed,
            ),
        ] {
            assert!(matches!(
                result,
                WorkerResult::State {
                    view: StateView {
                        canonical_phase,
                        component_instantiated: false,
                        component: None,
                        ..
                    }
                } if canonical_phase == phase
            ));
        }

        let stale = invoke(&mut source, WorkerCommand::StaleSourceKvProbe).unwrap_err();
        assert_eq!(stale.code, WorkerErrorCode::Provider);
        assert_eq!(stale.provider_kind.as_deref(), Some("StaleEpoch"));
        let before = invoke(&mut destination, WorkerCommand::Dump).unwrap();
        let WorkerResult::Dump { key_value_entry: before, .. } = before else {
            panic!("destination KV state must be dumpable before the adversarial probe");
        };
        let adversarial =
            invoke(&mut source, WorkerCommand::AdversarialStaleKvWriteProbe).unwrap_err();
        assert_eq!(adversarial.code, WorkerErrorCode::Provider);
        assert_eq!(adversarial.provider_kind.as_deref(), Some("StaleEpoch"));
        let after = invoke(&mut destination, WorkerCommand::Dump).unwrap();
        let WorkerResult::Dump { key_value_entry: after, .. } = after else {
            panic!("destination KV state must be dumpable after the adversarial probe");
        };
        assert_eq!(after, before, "a fenced source cannot mutate provider KV state");

        let destination_arm =
            match invoke(&mut destination, WorkerCommand::ResumeDestination).unwrap() {
                WorkerResult::State {
                    view:
                        StateView {
                            canonical_phase: HandoffPhase::Running,
                            component_instantiated: true,
                            component:
                                Some(ComponentStatusView {
                                    phase: WorkloadPhaseView::Armed,
                                    expected_version: 1,
                                    timer_operation_id,
                                    ..
                                }),
                            ..
                        },
                } => visa_component_adapter::parse_identity(&timer_operation_id)
                    .expect("destination timer operation identity must be canonical hex"),
                other => panic!("expected an armed destination component, got {other:?}"),
            };
        assert_ne!(destination_arm, source_arm);

        thread::sleep(Duration::from_nanos(remaining.0) + Duration::from_millis(20));
        let observed_evidence =
            match invoke(&mut destination, WorkerCommand::PollTimer { deliver: false }).unwrap() {
                WorkerResult::Timer {
                    poll: TimerPollView::Fired { arm_operation, evidence },
                    delivered: false,
                    view:
                        StateView {
                            component:
                                Some(ComponentStatusView {
                                    phase: WorkloadPhaseView::Armed,
                                    expected_version: 1,
                                    ..
                                }),
                            ..
                        },
                } => {
                    assert_eq!(arm_operation, destination_arm);
                    evidence
                }
                other => panic!("expected a retained non-delivering timer expiry, got {other:?}"),
            };
        let completed =
            invoke(&mut destination, WorkerCommand::PollTimer { deliver: true }).unwrap();
        assert!(matches!(
            &completed,
            WorkerResult::Timer {
                poll: TimerPollView::Fired { arm_operation, evidence },
                delivered: true,
                view: StateView {
                    component: Some(ComponentStatusView {
                        phase: WorkloadPhaseView::Completed,
                        expected_version: 2,
                        timer_operation_id,
                        ..
                    }),
                    ..
                },
                ..
            } if *arm_operation == destination_arm
                && *evidence == observed_evidence
                && visa_component_adapter::parse_identity(timer_operation_id)
                    == Some(destination_arm)
        ));
        assert!(matches!(
            invoke(&mut destination, WorkerCommand::PollTimer { deliver: true }).unwrap(),
            WorkerResult::Timer { poll: TimerPollView::Completed, delivered: false, .. }
        ));

        let duplicate = invoke(&mut destination, WorkerCommand::DuplicateCompletionKvProbe)
            .expect("the same completion operation is replayable");
        assert!(matches!(
            duplicate,
            WorkerResult::EffectProbe {
                replayed: true,
                view: StateView {
                    component: Some(ComponentStatusView {
                        phase: WorkloadPhaseView::Completed,
                        expected_version: 2,
                        ..
                    }),
                    ..
                },
                ..
            }
        ));
        let dump = invoke(&mut destination, WorkerCommand::Dump).unwrap();
        assert!(matches!(
            dump,
            WorkerResult::Dump {
                ref canonical_state,
                ref leases,
                ref binding_receipts,
                ..
            } if canonical_state.phase == HandoffPhase::Running
                && canonical_state.key_value.last_version == Some(2)
                && leases.len() == 2
                && leases.iter().all(|lease| lease.owner == canonical_state.activation.node)
                && binding_receipts.len() == 2
        ));

        let mut validation_worker = Worker::new();
        initialize(
            &mut validation_worker,
            WorkerRole::Destination,
            database.path(),
            FixtureOptions::new("worker-handoff"),
        );
        invoke(
            &mut validation_worker,
            WorkerCommand::ValidateDestination {
                envelope,
                expectations: SnapshotExpectationOverrides::default(),
                support: DestinationSupportMode::TimerSemanticsUnsupported,
            },
        )
        .expect_err("unsupported timer semantics reject before destination effects");
    }

    #[test]
    fn jco_node_workers_execute_the_same_component_handoff_path() {
        let database = TestDatabase::new("jco-node-worker-handoff");
        let options = FixtureOptions::new("jco-node-worker-handoff");
        let mut source = Worker::new();
        let source_runtime = initialize_with_runtime(
            &mut source,
            WorkerRole::Source,
            RuntimeImplementation::JcoNode,
            database.path(),
            options.clone(),
        );
        let source_translation = source_runtime
            .translation_provenance
            .as_ref()
            .expect("Jco source initialization reports translation provenance");
        assert_eq!(source_translation.jco_version, visa_jco_node::JCO_VERSION);
        assert_eq!(source_translation.translator_version, visa_jco_node::WASMTIME_ENVIRON_VERSION);
        assert_eq!(source_translation.node_version, visa_jco_node::NODE_VERSION);
        assert_eq!(source_translation.v8_version, visa_jco_node::V8_VERSION);
        assert_eq!(source_translation.execution_carrier, visa_jco_node::JCO_NODE_EXECUTION_CARRIER);
        assert_eq!(source_translation.generated_sha256.len(), 64);
        assert_eq!(source_translation.driver_sha256.len(), 64);
        assert!(!source_translation.core_module_sha256s.is_empty());
        invoke(&mut source, WorkerCommand::BootstrapSource).unwrap();
        invoke(&mut source, WorkerCommand::BeginQuiesce).unwrap();
        let safe_point = invoke(&mut source, WorkerCommand::FreezeSource).unwrap();
        assert!(matches!(
            safe_point,
            WorkerResult::SafePoint { timer: SafePointTimerView::Pending { .. }, .. }
        ));
        let (envelope, component_state) =
            match invoke(&mut source, WorkerCommand::ExportSourceSnapshot).unwrap() {
                WorkerResult::Snapshot { envelope, component_state, .. } => {
                    (*envelope, component_state)
                }
                other => panic!("expected Jco/Node source snapshot, got {other:?}"),
            };

        let mut destination = Worker::new();
        let destination_runtime = initialize_with_runtime(
            &mut destination,
            WorkerRole::Destination,
            RuntimeImplementation::JcoNode,
            database.path(),
            options,
        );
        assert_eq!(source_runtime, destination_runtime);
        invoke(
            &mut destination,
            WorkerCommand::ValidateDestination {
                envelope: envelope.clone(),
                expectations: SnapshotExpectationOverrides::default(),
                support: DestinationSupportMode::Compatible,
            },
        )
        .unwrap();
        invoke(&mut destination, WorkerCommand::LoadDestination { envelope, component_state })
            .unwrap();
        invoke(&mut destination, WorkerCommand::PrepareDestination).unwrap();
        invoke(&mut destination, WorkerCommand::CommitDestination).unwrap();
        let resumed = invoke(&mut destination, WorkerCommand::ResumeDestination).unwrap();
        assert!(matches!(
            resumed,
            WorkerResult::State {
                view: StateView {
                    canonical_phase: HandoffPhase::Running,
                    component: Some(ComponentStatusView {
                        phase: WorkloadPhaseView::Armed,
                        expected_version: 1,
                        ..
                    }),
                    ..
                }
            }
        ));
        let completed = poll_until_delivered(&mut destination);
        assert!(matches!(
            completed,
            WorkerResult::Timer {
                delivered: true,
                view: StateView {
                    component: Some(ComponentStatusView {
                        phase: WorkloadPhaseView::Completed,
                        expected_version: 2,
                        ..
                    }),
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    #[ignore = "requires VISA_WACOGO_BIN pointing to the pinned production sidecar"]
    fn real_wacogo_worker_failures_do_not_fallback_and_the_worker_continues() {
        assert!(
            std::env::var_os("VISA_WACOGO_BIN").is_some(),
            "set VISA_WACOGO_BIN before explicitly running this live focused test"
        );
        let database = TestDatabase::new("wacogo-focused-failures");
        let options = FixtureOptions::new("wacogo-focused-failures");
        let mut source = Worker::new();
        let source_runtime = initialize_with_runtime(
            &mut source,
            WorkerRole::Source,
            RuntimeImplementation::Wacogo,
            database.path(),
            options.clone(),
        );
        assert_wacogo_runtime_metadata(&source_runtime);
        invoke(&mut source, WorkerCommand::BootstrapSource).unwrap();
        invoke(&mut source, WorkerCommand::BeginQuiesce).unwrap();
        invoke(&mut source, WorkerCommand::InjectUnsupportedLiveResource).unwrap();
        let freeze_error = invoke(&mut source, WorkerCommand::FreezeSource)
            .expect_err("a Wacogo-local live resource must reject the safe point");
        assert_eq!(freeze_error.code, WorkerErrorCode::Adapter);
        assert_eq!(
            freeze_error.adapter_kind,
            Some(AdapterFailureKindView::LiveResourcesAtSafePoint)
        );
        let WorkerResult::State { view } = invoke(&mut source, WorkerCommand::Read).unwrap() else {
            panic!("the Wacogo worker must remain readable after safe-point rejection")
        };
        assert_eq!(view.live_runtime.as_ref(), Some(&source_runtime));
        invoke(&mut source, WorkerCommand::ClearUnsupportedLiveResource).unwrap();
        invoke(&mut source, WorkerCommand::FreezeSource).unwrap();
        let (envelope, component_state) =
            match invoke(&mut source, WorkerCommand::ExportSourceSnapshot).unwrap() {
                WorkerResult::Snapshot { envelope, component_state, .. } => {
                    (*envelope, component_state)
                }
                other => panic!("expected Wacogo source snapshot, got {other:?}"),
            };

        let mut destination = Worker::new();
        let destination_runtime = initialize_with_runtime(
            &mut destination,
            WorkerRole::Destination,
            RuntimeImplementation::Wacogo,
            database.path(),
            options,
        );
        assert_eq!(destination_runtime, source_runtime);
        let replacement_error = invoke(
            &mut destination,
            WorkerCommand::ValidateDestination {
                envelope: envelope.clone(),
                expectations: SnapshotExpectationOverrides::default(),
                support: DestinationSupportMode::TimerSemanticsUnsupported,
            },
        )
        .expect_err("Wacogo replacement preflight must reject unsupported timer semantics");
        assert_eq!(replacement_error.code, WorkerErrorCode::Adapter);
        assert_eq!(
            replacement_error.adapter_kind,
            Some(AdapterFailureKindView::IncompatibleProfile)
        );
        let WorkerState::DestinationPending(pending) = &destination.state else {
            panic!("replacement preflight rejection must leave the Wacogo destination pending")
        };
        assert!(pending.provider.is_some());
        assert!(pending.prepared.is_none());
        assert_eq!(pending.runtime, RuntimeImplementation::Wacogo);

        let replacement = invoke(
            &mut destination,
            WorkerCommand::ValidateDestination {
                envelope: envelope.clone(),
                expectations: SnapshotExpectationOverrides::default(),
                support: DestinationSupportMode::Compatible,
            },
        )
        .expect("the same Wacogo worker must accept a corrected replacement preflight");
        let WorkerResult::Prepared { runtime: replacement_runtime } = replacement else {
            panic!("replacement validation must return prepared runtime metadata")
        };
        assert_eq!(*replacement_runtime, destination_runtime);
        invoke(&mut destination, WorkerCommand::LoadDestination { envelope, component_state })
            .unwrap();
        invoke(&mut destination, WorkerCommand::PrepareDestination).unwrap();
        let WorkerResult::State { view: committed } =
            invoke(&mut destination, WorkerCommand::CommitDestination).unwrap()
        else {
            panic!("Wacogo commit must return state")
        };
        assert!(!committed.component_instantiated);
        assert!(committed.live_runtime.is_none());
        let WorkerResult::State { view: resumed } =
            invoke(&mut destination, WorkerCommand::ResumeDestination).unwrap()
        else {
            panic!("Wacogo resume must return state")
        };
        assert!(resumed.component_instantiated);
        assert_eq!(resumed.live_runtime.as_ref(), Some(&destination_runtime));

        for worker in [&mut source, &mut destination] {
            assert_eq!(
                run_json_lines_with_worker(worker, Cursor::new(Vec::<u8>::new()), Vec::new())
                    .unwrap(),
                RunExit::EndOfInput
            );
            worker.teardown_normal().unwrap();
        }
        let WorkerState::Source(source_state) = &source.state else {
            panic!("Wacogo source state changed during EOF teardown")
        };
        assert!(source_state.adapter.is_consumed());
        let WorkerState::Destination(destination_state) = &destination.state else {
            panic!("Wacogo destination state changed during EOF teardown")
        };
        assert!(destination_state.adapter.as_ref().is_some_and(Adapter::is_consumed));

        let pending_database = TestDatabase::new("wacogo-pending-eof");
        let mut pending = Worker::new();
        initialize_with_runtime(
            &mut pending,
            WorkerRole::Destination,
            RuntimeImplementation::Wacogo,
            pending_database.path(),
            FixtureOptions::new("wacogo-pending-eof"),
        );
        assert_eq!(
            run_json_lines_with_worker(&mut pending, Cursor::new(Vec::<u8>::new()), Vec::new())
                .unwrap(),
            RunExit::EndOfInput
        );
        pending.teardown_normal().unwrap();
        let WorkerState::DestinationPending(pending_state) = &pending.state else {
            panic!("Wacogo pending state changed during EOF teardown")
        };
        assert!(pending_state.prepared.is_none());
    }

    fn assert_wacogo_runtime_metadata(runtime: &RuntimeIdentityView) {
        assert_eq!(runtime.implementation, "visa_wacogo");
        assert_eq!(runtime.engine, "partite-ai/wacogo+wazero");
        assert!(runtime.translation_provenance.is_none());
        let Some(ImplementationLineageView::Wacogo {
            source_lock_sha256,
            sidecar_executable_sha256,
            sidecar_executable_size,
            ..
        }) = runtime.implementation_lineage.as_ref()
        else {
            panic!("Wacogo metadata must carry structured implementation lineage")
        };
        assert_eq!(source_lock_sha256, visa_wacogo::SOURCE_LOCK_SHA256);
        assert_eq!(sidecar_executable_sha256, visa_wacogo::SIDECAR_EXECUTABLE_SHA256);
        assert_eq!(*sidecar_executable_size, visa_wacogo::SIDECAR_EXECUTABLE_SIZE);
    }

    #[test]
    fn real_guest_safe_point_rejection_rolls_back_and_source_continues() {
        let database = TestDatabase::new("safe-point-rejection");
        let options = FixtureOptions::new("safe-point-unreachable");
        let mut source = Worker::new();
        initialize(&mut source, WorkerRole::Source, database.path(), options);
        invoke(&mut source, WorkerCommand::BootstrapSource).unwrap();
        invoke(&mut source, WorkerCommand::BeginQuiesce).unwrap();

        let rejection = invoke(&mut source, WorkerCommand::FreezeSource)
            .expect_err("the real guest must explicitly reject its safe point");
        assert_eq!(rejection.code, WorkerErrorCode::Adapter);
        assert_eq!(rejection.adapter_kind, Some(AdapterFailureKindView::Workload));
        assert_eq!(rejection.workload_kind, Some(WorkloadFailureKindView::SafePointUnavailable));
        assert!(matches!(
            invoke(&mut source, WorkerCommand::Read).unwrap(),
            WorkerResult::State {
                view: StateView {
                    canonical_phase: HandoffPhase::Quiescing,
                    component_instantiated: true,
                    component: Some(ComponentStatusView {
                        phase: WorkloadPhaseView::Armed,
                        expected_version: 1,
                        ..
                    }),
                    ..
                }
            }
        ));

        invoke(&mut source, WorkerCommand::AbortSource).unwrap();
        assert!(matches!(
            invoke(&mut source, WorkerCommand::ThawSource).unwrap(),
            WorkerResult::State {
                view: StateView {
                    canonical_phase: HandoffPhase::Running,
                    component: Some(ComponentStatusView {
                        phase: WorkloadPhaseView::Armed,
                        expected_version: 1,
                        ..
                    }),
                    ..
                }
            }
        ));
    }

    #[test]
    fn unsupported_live_resource_remains_local_while_source_guest_rolls_back() {
        let database = TestDatabase::new("unsupported-live-resource");
        let options = FixtureOptions::new("unsupported-live-resource-or-borrow");
        let mut source = Worker::new();
        initialize(&mut source, WorkerRole::Source, database.path(), options);
        invoke(&mut source, WorkerCommand::BootstrapSource).unwrap();
        invoke(&mut source, WorkerCommand::BeginQuiesce).unwrap();
        invoke(&mut source, WorkerCommand::InjectUnsupportedLiveResource).unwrap();

        let rejection = invoke(&mut source, WorkerCommand::FreezeSource)
            .expect_err("a live unsupported handle must reject the safe point");
        assert_eq!(rejection.code, WorkerErrorCode::Adapter);
        assert_eq!(rejection.adapter_kind, Some(AdapterFailureKindView::LiveResourcesAtSafePoint));
        assert!(matches!(
            invoke(&mut source, WorkerCommand::Read).unwrap(),
            WorkerResult::State {
                view: StateView {
                    canonical_phase: HandoffPhase::Quiescing,
                    component: Some(ComponentStatusView {
                        phase: WorkloadPhaseView::Armed,
                        expected_version: 1,
                        ..
                    }),
                    ..
                }
            }
        ));

        invoke(&mut source, WorkerCommand::ClearUnsupportedLiveResource).unwrap();
        invoke(&mut source, WorkerCommand::AbortSource).unwrap();
        assert!(matches!(
            invoke(&mut source, WorkerCommand::ThawSource).unwrap(),
            WorkerResult::State {
                view: StateView {
                    canonical_phase: HandoffPhase::Running,
                    component: Some(ComponentStatusView {
                        phase: WorkloadPhaseView::Armed,
                        expected_version: 1,
                        ..
                    }),
                    ..
                }
            }
        ));
    }

    fn poll_until_delivered(worker: &mut Worker) -> WorkerResult {
        for _ in 0..5 {
            let result = invoke(worker, WorkerCommand::PollTimer { deliver: true }).unwrap();
            match &result {
                WorkerResult::Timer { poll: TimerPollView::Pending { remaining, .. }, .. } => {
                    thread::sleep(Duration::from_nanos(remaining.0) + Duration::from_millis(5));
                }
                WorkerResult::Timer {
                    poll: TimerPollView::Fired { .. }, delivered: true, ..
                } => {
                    return result;
                }
                other => panic!("destination timer did not become deliverable: {other:?}"),
            }
        }
        panic!("destination timer remained pending")
    }

    fn initialize(worker: &mut Worker, role: WorkerRole, path: &Path, options: FixtureOptions) {
        initialize_with_runtime(worker, role, RuntimeImplementation::Wasmtime, path, options);
    }

    fn initialize_with_runtime(
        worker: &mut Worker,
        role: WorkerRole,
        runtime: RuntimeImplementation,
        path: &Path,
        options: FixtureOptions,
    ) -> RuntimeIdentityView {
        let result = invoke(
            worker,
            WorkerCommand::Initialize {
                role,
                runtime,
                database_path: path.to_string_lossy().into_owned(),
                options,
                fault: None,
            },
        )
        .unwrap();
        match result {
            WorkerResult::Initialized { role: actual, prepared_runtime, live_runtime, .. }
                if actual == role
                    && match role {
                        WorkerRole::Source => live_runtime.as_ref() == Some(&prepared_runtime),
                        WorkerRole::Destination => live_runtime.is_none(),
                    } =>
            {
                *prepared_runtime
            }
            other => panic!("expected initialized {role:?}, got {other:?}"),
        }
    }

    fn expect_state(result: WorkerResult, phase: HandoffPhase) {
        assert!(matches!(result, WorkerResult::State { view } if view.canonical_phase == phase));
    }

    fn invoke(worker: &mut Worker, command: WorkerCommand) -> Result<WorkerResult, WorkerError> {
        let turn = worker.handle(RequestEnvelope::new("test-request", command));
        assert_eq!(turn.exit, None);
        match turn.response.expect("non-crash command responds").outcome {
            ResponseOutcome::Success { result } => Ok(*result),
            ResponseOutcome::Error { error } => Err(error),
        }
    }

    struct TestDatabase(PathBuf);

    impl TestDatabase {
        fn new(label: &str) -> Self {
            let sequence = NEXT_DATABASE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "visa-system-worker-{label}-{}-{sequence}.sqlite3",
                std::process::id()
            ));
            remove_database_files(&path);
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            remove_database_files(&self.0);
        }
    }

    fn remove_database_files(path: &Path) {
        let _ = fs::remove_file(path);
        for suffix in ["-wal", "-shm"] {
            let mut sidecar = path.as_os_str().to_owned();
            sidecar.push(suffix);
            let _ = fs::remove_file(PathBuf::from(sidecar));
        }
    }
}
