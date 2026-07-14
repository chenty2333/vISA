use std::{
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use serde::Serialize;
use visa_conformance::{Stage1CaseDefinition, Stage1CaseOutcome, Stage1PerformanceMetric};

use super::{
    RoleLaunchers, RunnerError, TIMER_MARGIN, TranscriptLine, TranscriptStream,
    WORKER_STARTUP_TIMEOUT, WorkerClient, WorkerClientError,
    registry::{CaseKind, CasePlan, case_kind},
    support::{
        WorkerInitialization, archive_client, digest_hex, elapsed_nanos, remove_database_files,
        spawn_initialized, state_result, timer_result,
    },
};
use crate::{
    evidence::{CaseExecutionRecord, PerformanceMeasurement},
    fixture::FixtureSpec,
    protocol::{
        DestinationSupportMode, FaultObservationView, LeaseRecordView, ResponseEnvelope,
        ResponseOutcome, SafePointTimerView, SnapshotExpectationOverrides, StateView,
        TimerPollView, WorkerCommand, WorkerError, WorkerResult, WorkerRole, WorkloadPhaseView,
    },
};

#[derive(Clone)]
pub(super) struct SnapshotTransfer {
    pub(super) envelope: Option<contract_core::SnapshotEnvelope>,
    pub(super) component_state: Vec<u8>,
    pub(super) timer: SafePointTimerView,
}

#[derive(Clone)]
pub(super) struct DumpData {
    pub(super) canonical_state: contract_core::CanonicalState,
    pub(super) state_digest: contract_core::Digest,
    pub(super) journal: Vec<contract_core::JournalEntry>,
    pub(super) leases: Vec<LeaseRecordView>,
    pub(super) binding_receipts: Vec<contract_core::BindingReceipt>,
    pub(super) fault_observation: Option<FaultObservationView>,
    pub(super) key_value_entry: Option<contract_core::VersionedValue>,
    pub(super) component_instantiated: bool,
    pub(super) component: Option<crate::protocol::ComponentStatusView>,
    pub(super) portable_component_state: Option<Vec<u8>>,
}

impl DumpData {
    pub(super) fn from_result(case_id: &str, result: WorkerResult) -> Result<Self, RunnerError> {
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
pub(super) struct AssertionObservation {
    pub(super) name: String,
    pub(super) detail: String,
    pub(super) case_config_digest: contract_core::Digest,
    pub(super) case_policy_digest: contract_core::Digest,
}

pub(super) struct ArchivedTranscript {
    pub(super) label: String,
    pub(super) pid: u32,
    pub(super) lines: Vec<TranscriptLine>,
}

#[derive(Serialize)]
pub(super) struct RawTranscriptLine<'a> {
    pub(super) worker: &'a str,
    pub(super) pid: u32,
    pub(super) sequence: u64,
    pub(super) stream: TranscriptStream,
    pub(super) line: &'a str,
}

pub(super) struct CaseDatabase(PathBuf);

impl CaseDatabase {
    pub(super) fn new(work_root: &Path, case_id: &str) -> Result<Self, RunnerError> {
        let path = work_root.join(format!("{case_id}.sqlite3"));
        remove_database_files(&path)?;
        Ok(Self(path))
    }

    pub(super) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for CaseDatabase {
    fn drop(&mut self) {
        let _ = remove_database_files(&self.0);
    }
}

pub(super) struct CaseHarness {
    pub(super) definition: &'static Stage1CaseDefinition,
    pub(super) plan: CasePlan,
    pub(super) fixture: FixtureSpec,
    pub(super) launchers: RoleLaunchers,
    pub(super) source_runtime: crate::protocol::RuntimeImplementation,
    pub(super) destination_runtime: crate::protocol::RuntimeImplementation,
    pub(super) work_root: PathBuf,
    pub(super) database: CaseDatabase,
    pub(super) source: Option<WorkerClient>,
    pub(super) destination: Option<WorkerClient>,
    pub(super) source_transcripts: Vec<ArchivedTranscript>,
    pub(super) destination_transcripts: Vec<ArchivedTranscript>,
    pub(super) snapshot: Option<SnapshotTransfer>,
    pub(super) destination_base: Option<DumpData>,
    pub(super) latest_source: Option<StateView>,
    pub(super) latest_destination: Option<StateView>,
    pub(super) assertions: Vec<AssertionObservation>,
    pub(super) performance: Vec<PerformanceMeasurement>,
    pub(super) measure_performance: bool,
    pub(super) handoff_started: Option<Instant>,
    pub(super) config_digest: contract_core::Digest,
    pub(super) policy_digest: contract_core::Digest,
}

impl CaseHarness {
    pub(super) fn new(
        launchers: &RoleLaunchers,
        work_root: &Path,
        definition: &'static Stage1CaseDefinition,
        plan: CasePlan,
        source_runtime: crate::protocol::RuntimeImplementation,
        destination_runtime: crate::protocol::RuntimeImplementation,
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
            launchers,
            definition.id,
            WorkerInitialization::new(
                "source",
                WorkerRole::Source,
                source_runtime,
                database.path(),
                &plan.options,
            )
            .with_fault(plan.source_fault),
        )?;
        let destination = spawn_initialized(
            launchers,
            definition.id,
            WorkerInitialization::new(
                "destination",
                WorkerRole::Destination,
                destination_runtime,
                database.path(),
                &plan.options,
            )
            .with_fault(plan.destination_fault),
        )?;
        let mut harness = Self {
            definition,
            plan,
            fixture,
            launchers: launchers.clone(),
            source_runtime,
            destination_runtime,
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

    pub(super) fn source(&self) -> &WorkerClient {
        self.source.as_ref().expect("source worker is present")
    }

    pub(super) fn source_mut(&mut self) -> &mut WorkerClient {
        self.source.as_mut().expect("source worker is present")
    }

    pub(super) fn destination(&self) -> &WorkerClient {
        self.destination.as_ref().expect("destination worker is present")
    }

    pub(super) fn destination_mut(&mut self) -> &mut WorkerClient {
        self.destination.as_mut().expect("destination worker is present")
    }

    pub(super) fn source_success(
        &mut self,
        command: WorkerCommand,
    ) -> Result<WorkerResult, RunnerError> {
        self.source_mut()
            .request_success(command)
            .map_err(|source| self.worker_error("source", source))
    }

    pub(super) fn destination_success(
        &mut self,
        command: WorkerCommand,
    ) -> Result<WorkerResult, RunnerError> {
        self.destination_mut()
            .request_success(command)
            .map_err(|source| self.worker_error("destination", source))
    }

    pub(super) fn destination_startup_success(
        &mut self,
        command: WorkerCommand,
    ) -> Result<WorkerResult, RunnerError> {
        self.destination_mut()
            .request_success_with_timeout(command, WORKER_STARTUP_TIMEOUT)
            .map_err(|source| self.worker_error("destination", source))
    }

    pub(super) fn source_rejection(
        &mut self,
        command: WorkerCommand,
    ) -> Result<WorkerError, RunnerError> {
        let response = self
            .source_mut()
            .request(command)
            .map_err(|source| self.worker_error("source", source))?;
        self.rejection("source", response)
    }

    pub(super) fn destination_rejection(
        &mut self,
        command: WorkerCommand,
    ) -> Result<WorkerError, RunnerError> {
        let response = self
            .destination_mut()
            .request(command)
            .map_err(|source| self.worker_error("destination", source))?;
        self.rejection("destination", response)
    }

    pub(super) fn destination_startup_rejection(
        &mut self,
        command: WorkerCommand,
    ) -> Result<WorkerError, RunnerError> {
        let response = self
            .destination_mut()
            .request_with_timeout(command, WORKER_STARTUP_TIMEOUT)
            .map_err(|source| self.worker_error("destination", source))?;
        self.rejection("destination", response)
    }

    pub(super) fn rejection(
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

    pub(super) fn worker_error(
        &self,
        role: &'static str,
        source: WorkerClientError,
    ) -> RunnerError {
        RunnerError::Worker { case_id: self.definition.id.to_owned(), role, source }
    }

    pub(super) fn observe(
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

    pub(super) fn bootstrap(&mut self) -> Result<StateView, RunnerError> {
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

    pub(super) fn begin_quiesce(&mut self) -> Result<StateView, RunnerError> {
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

    pub(super) fn freeze(&mut self) -> Result<SnapshotTransfer, RunnerError> {
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

    pub(super) fn export(
        &mut self,
        mut transfer: SnapshotTransfer,
    ) -> Result<SnapshotTransfer, RunnerError> {
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

    pub(super) fn bootstrap_snapshot(&mut self) -> Result<SnapshotTransfer, RunnerError> {
        self.bootstrap()?;
        self.begin_quiesce()?;
        let transfer = self.freeze()?;
        self.export(transfer)
    }

    pub(super) fn validate_destination(
        &mut self,
        envelope: contract_core::SnapshotEnvelope,
        expectations: SnapshotExpectationOverrides,
        support: DestinationSupportMode,
    ) -> Result<WorkerResult, RunnerError> {
        self.destination_startup_success(WorkerCommand::ValidateDestination {
            envelope,
            expectations,
            support,
        })
    }

    pub(super) fn load_destination(
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

    pub(super) fn prepare_destination(&mut self) -> Result<StateView, RunnerError> {
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

    pub(super) fn commit_destination(&mut self) -> Result<StateView, RunnerError> {
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

    pub(super) fn resume_destination(&mut self) -> Result<StateView, RunnerError> {
        let result = self.destination_startup_success(WorkerCommand::ResumeDestination)?;
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

    pub(super) fn normal_commit(&mut self) -> Result<(), RunnerError> {
        self.load_destination(&[contract_core::HandoffPhase::Exported])?;
        self.prepare_destination()?;
        self.commit_destination()?;
        self.resume_destination()?;
        Ok(())
    }

    pub(super) fn pending_timer(
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

    pub(super) fn deliver_pending_timer(&mut self) -> Result<(), RunnerError> {
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

    pub(super) fn dump_source(&mut self) -> Result<DumpData, RunnerError> {
        let result = self.source_success(WorkerCommand::Dump)?;
        DumpData::from_result(self.definition.id, result)
    }

    pub(super) fn dump_destination(&mut self) -> Result<DumpData, RunnerError> {
        let result = self.destination_success(WorkerCommand::Dump)?;
        DumpData::from_result(self.definition.id, result)
    }

    pub(super) fn archive_source(&mut self) -> Result<(), RunnerError> {
        if let Some(client) = self.source.take() {
            self.source_transcripts.push(archive_client(&client)?);
            drop(client);
        }
        Ok(())
    }

    pub(super) fn archive_destination(&mut self) -> Result<(), RunnerError> {
        if let Some(client) = self.destination.take() {
            self.destination_transcripts.push(archive_client(&client)?);
            drop(client);
        }
        Ok(())
    }

    pub(super) fn restart_destination(&mut self, label: &str) -> Result<(), RunnerError> {
        self.archive_destination()?;
        self.destination = Some(spawn_initialized(
            &self.launchers,
            self.definition.id,
            WorkerInitialization::new(
                label,
                WorkerRole::Destination,
                self.destination_runtime,
                self.database.path(),
                &self.plan.options,
            ),
        )?);
        Ok(())
    }

    pub(super) fn finish(
        self,
        outcome: Stage1CaseOutcome,
    ) -> Result<CaseExecutionRecord, RunnerError> {
        super::finalize::finalize_case(self, outcome)
    }
}
