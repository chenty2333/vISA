use visa_conformance::{
    Stage1CaseOutcome, Stage1ExpectedOwnership, Stage1OwnershipStatus, stage1_expected_ownership,
};
use visa_runtime::canonical_digest;

use super::{
    RunnerError, WORKER_STARTUP_TIMEOUT, WorkerClient,
    artifacts::{
        assertions_json_lines, binding_for_claim, receipt_artifact, semantic_traces,
        transcript_json_lines,
    },
    harness::{CaseHarness, DumpData},
    registry::fault_schedule,
    support::{
        WorkerInitialization, archive_client, digest_hex, spawn_initialized,
        spawn_uninitialized_for_role,
    },
};
use crate::{
    evidence::{CaseAuthorityRecord, CaseExecutionRecord},
    fixture::derive_identity,
    protocol::{ResponseOutcome, WorkerCommand, WorkerErrorCode, WorkerResult, WorkerRole},
};

pub(super) fn finalize_case(
    mut harness: CaseHarness,
    outcome: Stage1CaseOutcome,
) -> Result<CaseExecutionRecord, RunnerError> {
    if !harness.definition.allowed_outcomes.contains(&outcome) {
        return Err(RunnerError::Assertion {
            case_id: harness.definition.id.to_owned(),
            detail: format!("scenario produced disallowed outcome {outcome:?}"),
        });
    }
    let expected_ownership = stage1_expected_ownership(outcome);
    let live_source = if harness.source.as_ref().is_some_and(WorkerClient::is_usable) {
        Some(harness.dump_source()?)
    } else {
        None
    };
    let live_destination = if harness.latest_destination.is_some()
        && harness.destination.as_ref().is_some_and(WorkerClient::is_usable)
    {
        Some(harness.dump_destination()?)
    } else {
        None
    };

    let source_replay = match expected_ownership {
        Stage1ExpectedOwnership::SourceRetained
            if outcome == Stage1CaseOutcome::RevocationRejectedNoResurrection =>
        {
            let live = live_source.clone().ok_or_else(|| RunnerError::Assertion {
                case_id: harness.definition.id.to_owned(),
                detail: "revocation outcome has no live exported source state".to_owned(),
            })?;
            let destination_base =
                harness.destination_base.as_ref().ok_or_else(|| RunnerError::Assertion {
                    case_id: harness.definition.id.to_owned(),
                    detail: "revocation outcome has no destination baseline dump".to_owned(),
                })?;
            let destination_final =
                live_destination.as_ref().ok_or_else(|| RunnerError::Assertion {
                    case_id: harness.definition.id.to_owned(),
                    detail: "revocation outcome has no final destination dump".to_owned(),
                })?;
            let destination_preserved = destination_final.canonical_state
                == destination_base.canonical_state
                && destination_final.state_digest == destination_base.state_digest
                && destination_final.journal == destination_base.journal
                && destination_final.leases == destination_base.leases
                && destination_final.authority_grants == destination_base.authority_grants
                && destination_final.binding_receipts == destination_base.binding_receipts
                && destination_final.fault_observation == destination_base.fault_observation
                && destination_final.key_value_entry == destination_base.key_value_entry
                && destination_final.portable_component_state
                    == destination_base.portable_component_state
                && destination_final.canonical_state.phase == contract_core::HandoffPhase::Exported
                && !destination_final.component_instantiated
                && destination_final.component.is_none()
                && destination_final.binding_receipts.is_empty();
            harness.observe(
                "revoked-capability-not-resurrected",
                destination_preserved,
                format!(
                    "base_digest={:?}, final_digest={:?}, phase={:?}, component_instantiated={}, component={:?}, receipts={:?}",
                    destination_base.state_digest,
                    destination_final.state_digest,
                    destination_final.canonical_state.phase,
                    destination_final.component_instantiated,
                    destination_final.component,
                    destination_final.binding_receipts,
                ),
            )?;
            let mut source_audit = spawn_uninitialized_for_role(
                &harness.launchers,
                harness.definition.id,
                "source-audit",
                WorkerRole::Source,
            )?;
            let initialization = source_audit
                .request_with_timeout(
                    WorkerCommand::Initialize {
                        role: WorkerRole::Source,
                        runtime: harness.source_runtime,
                        database_path: harness.database.path().to_string_lossy().into_owned(),
                        options: harness.plan.options.clone(),
                        fault: None,
                    },
                    WORKER_STARTUP_TIMEOUT,
                )
                .map_err(|source| harness.worker_error("source-audit", source))?;
            let snapshot_timer =
                harness.snapshot.as_ref().map(|snapshot| snapshot.timer).ok_or_else(|| {
                    RunnerError::Assertion {
                        case_id: harness.definition.id.to_owned(),
                        detail: "revocation outcome has no locked source snapshot".to_owned(),
                    }
                })?;
            let mut recovery_detail = format!("response={initialization:?}");
            let recovery_preserved_revocation = match (snapshot_timer, &initialization.outcome) {
                (
                    crate::protocol::SafePointTimerView::Completed { .. },
                    ResponseOutcome::Success { result },
                ) if matches!(
                    result.as_ref(),
                    WorkerResult::Initialized {
                        role: WorkerRole::Source,
                        case_id,
                        ..
                    } if case_id == harness.definition.id
                ) =>
                {
                    let recovered = DumpData::from_result(
                        harness.definition.id,
                        source_audit
                            .request_success(WorkerCommand::Dump)
                            .map_err(|source| harness.worker_error("source-audit", source))?,
                    )?;
                    recovery_detail = format!(
                        "response={initialization:?}, live_digest={:?}, recovered_digest={:?}, timer={:?}, component_instantiated={}, component={:?}",
                        live.state_digest,
                        recovered.state_digest,
                        recovered.canonical_state.timer.status,
                        recovered.component_instantiated,
                        recovered.component,
                    );
                    recovered.canonical_state == live.canonical_state
                        && recovered.state_digest == live.state_digest
                        && recovered.journal == live.journal
                        && recovered.leases == live.leases
                        && recovered.authority_grants == live.authority_grants
                        && recovered.binding_receipts == live.binding_receipts
                        && recovered.fault_observation == live.fault_observation
                        && recovered.key_value_entry == live.key_value_entry
                        && recovered.portable_component_state == live.portable_component_state
                        && recovered.canonical_state.timer.status
                            == contract_core::TimerStatus::Frozen(
                                contract_core::TimerDisposition::Completed,
                            )
                        && recovered.component.is_none()
                }
                _ => false,
            };
            harness.source_transcripts.push(archive_client(&source_audit)?);
            drop(source_audit);
            harness.observe(
                "source-recovery-does-not-resurrect-revoked-timer",
                recovery_preserved_revocation,
                recovery_detail,
            )?;
            // Executable recovery must not recreate the revoked timer binding. The typed
            // source trace below remains the independent, pure canonical replay proof.
            live
        }
        Stage1ExpectedOwnership::SourceRetained => {
            let mut source_audit = spawn_initialized(
                &harness.launchers,
                harness.definition.id,
                WorkerInitialization::new(
                    "source-audit",
                    WorkerRole::Source,
                    harness.source_runtime,
                    harness.database.path(),
                    &harness.plan.options,
                ),
            )?;
            let source_probe = source_audit
                .request(WorkerCommand::StaleSourceKvProbe)
                .map_err(|source| harness.worker_error("source-audit", source))?;
            harness.observe(
                "source-lease-remains-admitted",
                matches!(
                    source_probe.outcome,
                    ResponseOutcome::Success { ref result }
                        if matches!(result.as_ref(), WorkerResult::State { .. })
                ),
                format!("response={source_probe:?}"),
            )?;
            let replay = DumpData::from_result(
                harness.definition.id,
                source_audit
                    .request_success(WorkerCommand::Dump)
                    .map_err(|source| harness.worker_error("source-audit", source))?,
            )?;
            harness.source_transcripts.push(archive_client(&source_audit)?);
            drop(source_audit);
            replay
        }
        Stage1ExpectedOwnership::DestinationCommitted
        | Stage1ExpectedOwnership::DestinationRecoveryRequired => {
            let source_probe = harness
                .source_mut()
                .request(WorkerCommand::StaleSourceKvProbe)
                .map_err(|source| harness.worker_error("source", source))?;
            harness.observe(
                "source-lease-is-fenced",
                matches!(
                    source_probe.outcome,
                    ResponseOutcome::Error { ref error }
                        if error.code == WorkerErrorCode::Provider
                            && error.provider_kind.as_deref() == Some("StaleEpoch")
                ),
                format!("response={source_probe:?}"),
            )?;

            let mut source_audit = spawn_uninitialized_for_role(
                &harness.launchers,
                harness.definition.id,
                "source-audit",
                WorkerRole::Source,
            )?;
            let initialization = source_audit
                .request_with_timeout(
                    WorkerCommand::Initialize {
                        role: WorkerRole::Source,
                        runtime: harness.source_runtime,
                        database_path: harness.database.path().to_string_lossy().into_owned(),
                        options: harness.plan.options.clone(),
                        fault: None,
                    },
                    WORKER_STARTUP_TIMEOUT,
                )
                .map_err(|source| harness.worker_error("source-audit", source))?;
            let (restart_error, restart_stage) = match initialization.outcome {
                ResponseOutcome::Error { error } => (error, "recovery"),
                ResponseOutcome::Success { result }
                    if matches!(
                        result.as_ref(),
                        WorkerResult::Initialized {
                            role: WorkerRole::Source,
                            case_id,
                            ..
                        } if case_id == harness.definition.id
                    ) =>
                {
                    let probe = source_audit
                        .request(WorkerCommand::AdversarialStaleKvWriteProbe)
                        .map_err(|source| harness.worker_error("source-audit", source))?;
                    match probe.outcome {
                        ResponseOutcome::Error { error } => (error, "provider-write"),
                        ResponseOutcome::Success { result } => {
                            return Err(RunnerError::Assertion {
                                case_id: harness.definition.id.to_owned(),
                                detail: format!(
                                    "restarted source wrote under its stale lease: {result:?}"
                                ),
                            });
                        }
                    }
                }
                ResponseOutcome::Success { result } => {
                    return Err(RunnerError::Assertion {
                        case_id: harness.definition.id.to_owned(),
                        detail: format!("source audit initialization returned {result:?}"),
                    });
                }
            };
            harness.source_transcripts.push(archive_client(&source_audit)?);
            drop(source_audit);
            harness.observe(
                "source-restart-old-lease-is-fenced",
                restart_error.code == WorkerErrorCode::Provider
                    && restart_error.provider_kind.as_deref() == Some("StaleEpoch"),
                format!("stage={restart_stage}, error={restart_error:?}"),
            )?;
            live_source.clone().ok_or_else(|| RunnerError::Assertion {
                case_id: harness.definition.id.to_owned(),
                detail: "committed outcome has no live source state for evidence".to_owned(),
            })?
        }
    };

    let (final_dump, replay_dump) = match expected_ownership {
        Stage1ExpectedOwnership::SourceRetained => {
            if outcome != Stage1CaseOutcome::RevocationRejectedNoResurrection
                && let Some(live) = &live_source
            {
                harness.observe(
                    "source-journal-replay-digest",
                    live.state_digest == source_replay.state_digest,
                    format!(
                        "live={:?}, replay={:?}",
                        live.state_digest, source_replay.state_digest
                    ),
                )?;
            }
            (live_source.clone().unwrap_or_else(|| source_replay.clone()), source_replay.clone())
        }
        Stage1ExpectedOwnership::DestinationCommitted
        | Stage1ExpectedOwnership::DestinationRecoveryRequired => {
            let transfer = harness.snapshot.clone().ok_or_else(|| RunnerError::Assertion {
                case_id: harness.definition.id.to_owned(),
                detail: "committed outcome has no snapshot".to_owned(),
            })?;
            let mut destination_audit = spawn_initialized(
                &harness.launchers,
                harness.definition.id,
                WorkerInitialization::new(
                    "destination-audit",
                    WorkerRole::Destination,
                    harness.destination_runtime,
                    harness.database.path(),
                    &harness.plan.options,
                ),
            )?;
            destination_audit
                .request_success(WorkerCommand::LoadDestination {
                    envelope: transfer.envelope.ok_or_else(|| RunnerError::Assertion {
                        case_id: harness.definition.id.to_owned(),
                        detail: "committed outcome has no exported envelope".to_owned(),
                    })?,
                    component_state: transfer.component_state,
                })
                .map_err(|source| harness.worker_error("destination-audit", source))?;
            let destination_replay = DumpData::from_result(
                harness.definition.id,
                destination_audit
                    .request_success(WorkerCommand::Dump)
                    .map_err(|source| harness.worker_error("destination-audit", source))?,
            )?;
            harness.destination_transcripts.push(archive_client(&destination_audit)?);
            drop(destination_audit);
            let final_destination =
                live_destination.clone().unwrap_or_else(|| destination_replay.clone());
            harness.observe(
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

    if let Some(transfer) = &harness.snapshot {
        let expected_portable = transfer.component_state.as_slice();
        let envelope_matches = transfer
            .envelope
            .as_ref()
            .is_some_and(|envelope| envelope.body.portable_state.as_slice() == expected_portable);
        let source_portable =
            live_source.as_ref().unwrap_or(&source_replay).portable_component_state.as_deref();
        let destination_portable = if expected_ownership == Stage1ExpectedOwnership::SourceRetained
        {
            live_destination
                .as_ref()
                .or(harness.destination_base.as_ref())
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
        harness.observe(
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
            harness.fixture.ids.source_node,
            harness.fixture.activation.initial_lease_epoch,
            Stage1OwnershipStatus::SourceActive,
            None,
            false,
        ),
        Stage1ExpectedOwnership::DestinationCommitted => (
            harness.fixture.ids.destination_node,
            harness.fixture.activation.initial_lease_epoch.next().ok_or_else(|| {
                RunnerError::Assertion {
                    case_id: harness.definition.id.to_owned(),
                    detail: "destination lease epoch overflowed".to_owned(),
                }
            })?,
            Stage1OwnershipStatus::DestinationActive,
            harness.fixture.activation.initial_lease_epoch.next(),
            true,
        ),
        Stage1ExpectedOwnership::DestinationRecoveryRequired => (
            harness.fixture.ids.destination_node,
            harness.fixture.activation.initial_lease_epoch.next().ok_or_else(|| {
                RunnerError::Assertion {
                    case_id: harness.definition.id.to_owned(),
                    detail: "destination lease epoch overflowed".to_owned(),
                }
            })?,
            Stage1OwnershipStatus::DestinationRecoveryRequired,
            harness.fixture.activation.initial_lease_epoch.next(),
            true,
        ),
    };
    harness.observe(
        "global-resource-leases-select-one-owner",
        final_dump.leases.len() == 2
            && final_dump.leases.iter().all(|lease| lease.owner == owner && lease.epoch == epoch),
        format!("leases={:?}", final_dump.leases),
    )?;
    if expected_ownership != Stage1ExpectedOwnership::SourceRetained {
        harness.observe(
            "committed-bindings-cover-profile",
            binding_for_claim(&final_dump, harness.fixture.ids.timer_resource).is_some()
                && binding_for_claim(&final_dump, harness.fixture.ids.key_value_resource).is_some(),
            format!("receipts={:?}", final_dump.binding_receipts),
        )?;
    }

    harness.archive_source()?;
    harness.archive_destination()?;
    let raw_source_json = transcript_json_lines(&harness.source_transcripts)?;
    let raw_destination_json = transcript_json_lines(&harness.destination_transcripts)?;
    let source_final = live_source.as_ref().unwrap_or(&source_replay);
    let destination_final = if expected_ownership == Stage1ExpectedOwnership::SourceRetained {
        live_destination.as_ref()
    } else {
        Some(&replay_dump)
    };
    let semantic_traces = semantic_traces(
        harness.definition.id,
        &harness.fixture,
        harness.snapshot.as_ref(),
        source_final,
        harness.destination_base.as_ref(),
        destination_final,
        expected_ownership,
    )?;
    let timer_binding_receipt = receipt_artifact(&final_dump, harness.fixture.ids.timer_resource)?;
    let key_value_binding_receipt =
        receipt_artifact(&final_dump, harness.fixture.ids.key_value_resource)?;
    let snapshot_bytes = harness
        .snapshot
        .as_ref()
        .and_then(|transfer| transfer.envelope.as_ref())
        .map(|envelope| {
            serde_json::to_vec(envelope).map_err(|error| RunnerError::Json {
                context: format!("encode {} snapshot", harness.definition.id),
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
            case_id: harness.definition.id.to_owned(),
            detail: "cannot digest observed source authority grants".to_owned(),
        })?;
    let destination_authority_root =
        canonical_digest(observed_destination_grants).map_err(|_| RunnerError::Fixture {
            case_id: harness.definition.id.to_owned(),
            detail: "cannot digest observed destination authority grants".to_owned(),
        })?;
    harness.observe(
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
    let raw_assertions_json = assertions_json_lines(&harness.assertions)?;
    let fault_schedule = fault_schedule(harness.definition, &harness.plan);
    Ok(CaseExecutionRecord {
        case_id: harness.definition.id.to_owned(),
        case_config_digest: harness.config_digest,
        case_policy_digest: harness.policy_digest,
        execution_id: derive_identity(harness.definition.id, "execution"),
        handoff_id: harness.fixture.ids.handoff,
        snapshot_id: harness.fixture.ids.snapshot,
        outcome,
        exit_status: 0,
        fault_schedule,
        authority: CaseAuthorityRecord {
            source_authority_root,
            destination_authority_root,
            source_lease_epoch: harness.fixture.activation.initial_lease_epoch,
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
        performance: harness.performance,
    })
}
