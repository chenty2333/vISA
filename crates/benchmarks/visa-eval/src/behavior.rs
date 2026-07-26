//! Independent B-route behavior-defect generator.
//!
//! Each case gets a fresh composite fixture and arms exactly one one-shot
//! hook. The report records the observed divergence or fail-closed response;
//! it is a working artifact, not a Stage 1 claim or a replacement for the
//! existing 31-case matrix.

use std::path::Path;

use contract_core::{
    AuthorityGrant, AuthorityStatus, Command, CommandKind, Digest, EffectKind, EffectRequest,
    EntityRef, EvidenceKind, HandoffPhase, IdempotencyKey, Identity, ProfileAccess, Rights,
    TimerStatus, canonical_digest,
};
use serde::Serialize;
use serde_json::{Value, json};
use substrate_api::{JournalPort, TimerPort};
use substrate_host::{FaultPoint as HostFaultPoint, LoopbackLogicalPeer, SqliteProvider};
use visa_component_adapter::{
    BindingSet, ProfileBinding, ProfileFailure, faults as adapter_faults, kv_conditional_put,
    profile_execute, timer_arm, timer_cancel,
};
use visa_composite_cell::{
    cell::REQUEST_BODY,
    fixture::{CompositeFixture, CompositeFixtureIds, INITIAL_LEASE_EPOCH},
};
use visa_profile::{
    LOGICAL_REQUEST_EXTENSION_ID, LogicalRequestOperation, encode_logical_request_operation,
};
use visa_runtime::{Coordinator, faults as runtime_faults};

use crate::{
    EvalOptions, create_fixture, derive, derive_evidence, runtime_error, snapshot_evidence,
    spawn_peer,
};

pub const REPORT_SCHEMA: &str = "visa-behavior-defect-report-v1";

#[derive(Debug, Serialize)]
struct BehaviorReport {
    schema: &'static str,
    route: &'static str,
    canonical_impact: &'static str,
    cases: Vec<BehaviorCase>,
    summary: BehaviorSummary,
}

#[derive(Debug, Serialize)]
struct BehaviorCase {
    id: &'static str,
    layer: &'static str,
    fault_point: &'static str,
    fired: bool,
    divergence_or_failure_observed: bool,
    result: String,
    details: Value,
}

#[derive(Debug, Serialize)]
struct BehaviorSummary {
    cases: usize,
    fired: usize,
    observed: usize,
}

pub fn run(options: &EvalOptions) -> Result<(), String> {
    let work_root = options.out.join(format!("behavior-defects-work-{}", std::process::id()));
    std::fs::create_dir_all(&work_root)
        .map_err(|error| format!("cannot create {}: {error}", work_root.display()))?;

    let cases = vec![
        defer_profile_authorization(&work_root)?,
        skip_authority_attenuation(&work_root)?,
        skip_authority_revocation(&work_root)?,
        skip_journal_append(&work_root)?,
        drop_timer_cancel(&work_root)?,
        duplicate_cleanup_apply(&work_root)?,
        remap_profile_error(&work_root)?,
        runtime_skip_external_source_fence(&work_root)?,
        provider_skip_source_fence(&work_root)?,
    ];
    let summary = BehaviorSummary {
        cases: cases.len(),
        fired: cases.iter().filter(|case| case.fired).count(),
        observed: cases.iter().filter(|case| case.divergence_or_failure_observed).count(),
    };
    let report = BehaviorReport {
        schema: REPORT_SCHEMA,
        route: "B: independent generation-side behavior injection",
        canonical_impact: "none: feature-gated controls and an evaluation-only report",
        cases,
        summary,
    };
    let path = options.out.join("behavior-defects.json");
    let bytes = serde_json::to_vec_pretty(&report)
        .map_err(|error| format!("cannot encode {}: {error}", path.display()))?;
    std::fs::write(&path, bytes)
        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    println!("behavior-defect report: {}", path.display());
    Ok(())
}

fn defer_profile_authorization(root: &Path) -> Result<BehaviorCase, String> {
    let case = "behavior-defer-profile-authorization";
    let (_peer, ids, coordinator, _profile_digest) = activated_source(root, case)?;
    let state = coordinator.state().clone();
    let payload = encode_logical_request_operation(&LogicalRequestOperation::Start {
        request: REQUEST_BODY.to_vec(),
    })
    .map_err(|error| format!("cannot encode profile request: {error:?}"))?;
    let kind = EffectKind::Profile {
        profile: LOGICAL_REQUEST_EXTENSION_ID,
        access: ProfileAccess::Write,
        payload,
    };
    let request = EffectRequest {
        operation: derive(case, "operation"),
        idempotency_key: IdempotencyKey::from_bytes(derive(case, "idempotency").0),
        causal_parent: None,
        node: ids.source_node,
        subject: ids.source_component,
        resource: ids.request,
        // The KV authority is intentionally bound to the wrong resource.
        authority: ids.source_key_value_authority,
        lease_epoch: state.ownership.epoch,
        request_digest: canonical_digest(&kind)
            .map_err(|error| format!("cannot digest profile request: {error:?}"))?,
        kind,
    };
    let command = Command::new(derive(case, "command"), CommandKind::RequestEffect(request));
    let baseline = semantic_core::preflight(&state, &command);
    semantic_core::faults::inject_once(
        semantic_core::faults::FaultPoint::DeferProfileAuthorization,
    );
    let injected = semantic_core::preflight(&state, &command);
    let observed = matches!(injected, contract_core::Decision::Execute { .. });
    Ok(BehaviorCase {
        id: case,
        layer: "semantic_core",
        fault_point: "DeferProfileAuthorization",
        fired: semantic_core::faults::observation().is_some_and(|observation| {
            observation.point == semantic_core::faults::FaultPoint::DeferProfileAuthorization
        }),
        divergence_or_failure_observed: matches!(baseline, contract_core::Decision::Reject(_))
            && observed,
        result: format!(
            "baseline_rejected={}; injected_execute={observed}",
            matches!(baseline, contract_core::Decision::Reject(_))
        ),
        details: json!({"wrong_authority": true, "injected_decision_is_execute": observed}),
    })
}

fn skip_authority_attenuation(root: &Path) -> Result<BehaviorCase, String> {
    let case = "behavior-skip-authority-attenuation";
    let (_peer, ids, coordinator, _profile_digest) = activated_source(root, case)?;
    let state = coordinator.state().clone();
    let parent = ids.source_key_value_authority;
    let parent_grant = state
        .authorities
        .iter()
        .find(|grant| grant.authority == parent)
        .cloned()
        .ok_or("source KV authority is missing")?;
    let derived = AuthorityGrant {
        authority: ids.attenuated_key_value_authority,
        parent: Some(parent),
        subject: parent_grant.subject,
        resource: parent_grant.resource,
        rights: Rights::KV_READ,
        status: AuthorityStatus::Active,
    };
    let command = Command::new(
        derive(case, "command"),
        CommandKind::AttenuateAuthority { parent, derived: derived.clone() },
    );
    let event = committed_event(semantic_core::preflight(&state, &command))?;
    let normal = semantic_core::apply(&state, &event)
        .map_err(|error| format!("normal attenuation failed: {error:?}"))?
        .into_state();
    semantic_core::faults::inject_once(semantic_core::faults::FaultPoint::SkipAuthorityAttenuation);
    let injected = semantic_core::apply(&state, &event)
        .map_err(|error| format!("injected attenuation failed: {error:?}"))?
        .into_state();
    let diverged = normal != injected;
    Ok(BehaviorCase {
        id: case,
        layer: "semantic_core",
        fault_point: "SkipAuthorityAttenuation",
        fired: semantic_core::faults::observation().is_some_and(|observation| {
            observation.point == semantic_core::faults::FaultPoint::SkipAuthorityAttenuation
        }),
        divergence_or_failure_observed: diverged,
        result: format!(
            "normal_derived={}; injected_derived={}",
            has_grant(&normal, derived.authority),
            has_grant(&injected, derived.authority)
        ),
        details: json!({"normal_contains_derived": has_grant(&normal, derived.authority), "injected_contains_derived": has_grant(&injected, derived.authority)}),
    })
}

fn skip_authority_revocation(root: &Path) -> Result<BehaviorCase, String> {
    let case = "behavior-skip-authority-revocation";
    let (_peer, ids, coordinator, _profile_digest) = activated_source(root, case)?;
    let state = coordinator.state().clone();
    let authority = ids.source_key_value_authority;
    let command = Command::new(derive(case, "command"), CommandKind::RevokeAuthority { authority });
    let event = committed_event(semantic_core::preflight(&state, &command))?;
    let normal = semantic_core::apply(&state, &event)
        .map_err(|error| format!("normal revocation failed: {error:?}"))?
        .into_state();
    semantic_core::faults::inject_once(semantic_core::faults::FaultPoint::SkipAuthorityRevocation);
    let injected = semantic_core::apply(&state, &event)
        .map_err(|error| format!("injected revocation failed: {error:?}"))?
        .into_state();
    let normal_status = authority_status(&normal, authority);
    let injected_status = authority_status(&injected, authority);
    Ok(BehaviorCase {
        id: case,
        layer: "semantic_core",
        fault_point: "SkipAuthorityRevocation",
        fired: semantic_core::faults::observation().is_some_and(|observation| {
            observation.point == semantic_core::faults::FaultPoint::SkipAuthorityRevocation
        }),
        divergence_or_failure_observed: normal_status != injected_status,
        result: format!("normal={normal_status:?}; injected={injected_status:?}"),
        details: json!({"normal_status": format!("{normal_status:?}"), "injected_status": format!("{injected_status:?}")}),
    })
}

fn skip_journal_append(root: &Path) -> Result<BehaviorCase, String> {
    let case = "behavior-skip-journal-append";
    let (_peer, ids, mut coordinator, _profile_digest) = activated_source(root, case)?;
    let bindings = BindingSet::for_state(coordinator.state())
        .map_err(|error| format!("cannot bind KV: {error:?}"))?;
    let before = coordinator.journal_position().0;
    coordinator.provider_mut().inject_failure_once(HostFaultPoint::SkipJournalAppend);
    let result = kv_conditional_put(
        &mut coordinator,
        &bindings.key_value,
        "behavior-skip-journal".to_owned(),
        "behavior".to_owned(),
        None,
        b"injected".to_vec(),
    );
    let after = coordinator.journal_position().0;
    let entries = coordinator
        .provider()
        .replay_from(None)
        .map_err(|error| format!("cannot inspect journal: {error:?}"))?;
    let durable_last = entries.last().map_or(0, |entry| entry.position.0);
    let observation = coordinator.provider().fault_observation();
    let diverged = after > durable_last;
    Ok(BehaviorCase {
        id: case,
        layer: "substrate_host",
        fault_point: "SkipJournalAppend",
        fired: observation
            .is_some_and(|observation| observation.point == HostFaultPoint::SkipJournalAppend),
        divergence_or_failure_observed: diverged,
        result: format!(
            "operation_error={}; local_position={after}; durable_position={durable_last}",
            result.is_err()
        ),
        details: json!({"source_node": format!("{:?}", ids.source_node), "position_before": before, "position_after": after, "durable_last": durable_last}),
    })
}

fn drop_timer_cancel(root: &Path) -> Result<BehaviorCase, String> {
    let case = "behavior-drop-timer-cancel";
    let (_peer, _ids, mut coordinator, _profile_digest) = activated_source(root, case)?;
    let bindings = BindingSet::for_state(coordinator.state())
        .map_err(|error| format!("cannot bind timer: {error:?}"))?;
    let armed =
        timer_arm(&mut coordinator, &bindings.timer, "behavior-timer".to_owned(), 60_000_000_000)
            .map_err(|error| format!("timer arm failed: {error:?}"))?;
    coordinator.provider_mut().inject_failure_once(HostFaultPoint::DropTimerCancel);
    let result = timer_cancel(&mut coordinator, &bindings.timer, armed.operation_id.clone());
    let observed = coordinator
        .provider_mut()
        .observe(parse_identity(&armed.operation_id).ok_or("invalid timer operation identity")?)
        .map_err(|error| format!("cannot observe timer: {error:?}"))?;
    let canonical_cancelled = coordinator.state().timer.status == TimerStatus::Cancelled;
    let diverged =
        canonical_cancelled && matches!(observed, substrate_api::TimerObservation::Pending(_));
    let fired = coordinator
        .provider()
        .fault_observation()
        .is_some_and(|observation| observation.point == HostFaultPoint::DropTimerCancel);
    Ok(BehaviorCase {
        id: case,
        layer: "substrate_host",
        fault_point: "DropTimerCancel",
        fired,
        divergence_or_failure_observed: diverged,
        result: format!(
            "operation_ok={}; canonical={:?}; provider={observed:?}",
            result.is_ok(),
            coordinator.state().timer.status
        ),
        details: json!({"canonical_cancelled": canonical_cancelled, "provider_observation": format!("{observed:?}")}),
    })
}

fn duplicate_cleanup_apply(root: &Path) -> Result<BehaviorCase, String> {
    let case = "behavior-duplicate-cleanup-apply";
    let (_peer, _ids, mut coordinator, _profile_digest) = activated_source(root, case)?;
    let bindings = BindingSet::for_state(coordinator.state())
        .map_err(|error| format!("cannot bind KV: {error:?}"))?;
    let write = kv_conditional_put(
        &mut coordinator,
        &bindings.key_value,
        "behavior-cleanup".to_owned(),
        "cleanup".to_owned(),
        None,
        b"value".to_vec(),
    )
    .map_err(|error| format!("cleanup fixture write failed: {error:?}"))?;
    let operation =
        parse_identity(&write.operation_id).ok_or("invalid cleanup operation identity")?;
    coordinator.provider_mut().inject_failure_once(HostFaultPoint::DuplicateCleanupApply);
    let result = coordinator.cleanup_operation(
        derive(case, "command"),
        operation,
        derive_evidence(case, "cleanup", EvidenceKind::Cleanup),
    );
    let observation = coordinator.provider().operation(operation);
    let cleaned = observation.as_ref().ok().and_then(Option::as_ref).is_some_and(|observation| {
        observation.record.cleanup == contract_core::CleanupStatus::Cleaned
    });
    let fired = coordinator
        .provider()
        .fault_observation()
        .is_some_and(|observation| observation.point == HostFaultPoint::DuplicateCleanupApply);
    Ok(BehaviorCase {
        id: case,
        layer: "substrate_host",
        fault_point: "DuplicateCleanupApply",
        fired,
        divergence_or_failure_observed: cleaned && result.is_ok(),
        result: format!("operation_ok={}; provider_cleaned={cleaned}", result.is_ok()),
        details: json!({"duplicate_is_idempotently_absorbed": cleaned && result.is_ok()}),
    })
}

fn remap_profile_error(root: &Path) -> Result<BehaviorCase, String> {
    let case = "behavior-remap-profile-error";
    let (_peer, _ids, mut coordinator, _profile_digest) = activated_source(root, case)?;
    let binding = ProfileBinding::for_state(coordinator.state(), LOGICAL_REQUEST_EXTENSION_ID)
        .map_err(|error| format!("cannot bind logical request profile: {error:?}"))?;
    let payload = encode_logical_request_operation(&LogicalRequestOperation::Start {
        request: REQUEST_BODY.to_vec(),
    })
    .map_err(|error| format!("cannot encode profile operation: {error:?}"))?;
    adapter_faults::inject_once(adapter_faults::FaultPoint::RemapProfileError);
    coordinator.provider_mut().inject_failure_once(HostFaultPoint::SkipJournalAppend);
    let result = profile_execute(
        &mut coordinator,
        &binding,
        ProfileAccess::Write,
        b"behavior-profile",
        payload,
    );
    let fired = adapter_faults::observation().is_some_and(|observation| {
        observation.point == adapter_faults::FaultPoint::RemapProfileError
    });
    let remapped = result == Err(ProfileFailure::Conflict);
    Ok(BehaviorCase {
        id: case,
        layer: "visa_component_adapter",
        fault_point: "RemapProfileError",
        fired,
        divergence_or_failure_observed: remapped,
        result: format!("{result:?}"),
        details: json!({"remapped_to_conflict": remapped}),
    })
}

fn runtime_skip_external_source_fence(root: &Path) -> Result<BehaviorCase, String> {
    let case = "behavior-runtime-skip-external-source-fence";
    let (_peer, ids, mut coordinator, _profile_digest) = exported_source(root, case)?;
    runtime_faults::inject_once(runtime_faults::FaultPoint::SkipExternalSourceFence);
    let result = coordinator.project_external_source_fence(
        derive(case, "command"),
        derive(case, "operation"),
        ids.destination_node,
        INITIAL_LEASE_EPOCH.next().ok_or("lease epoch exhausted")?,
        derive_evidence(case, "decision", EvidenceKind::AuthorityDecision),
        derive_evidence(case, "closure", EvidenceKind::SourceFence),
    );
    let durable_commit = has_durable_handoff_commit(&coordinator)?;
    let local_committed = coordinator.state().phase == HandoffPhase::Committed;
    let fired = runtime_faults::observation().is_some_and(|observation| {
        observation.point == runtime_faults::FaultPoint::SkipExternalSourceFence
    });
    Ok(BehaviorCase {
        id: case,
        layer: "visa_runtime",
        fault_point: "SkipExternalSourceFence",
        fired,
        divergence_or_failure_observed: local_committed && !durable_commit,
        result: format!(
            "operation_ok={}; local_committed={local_committed}; durable_commit={durable_commit}",
            result.is_ok()
        ),
        details: json!({"local_committed": local_committed, "durable_commit": durable_commit}),
    })
}

fn provider_skip_source_fence(root: &Path) -> Result<BehaviorCase, String> {
    let case = "behavior-provider-skip-source-fence";
    let (_peer, ids, mut coordinator, _profile_digest) = exported_source(root, case)?;
    coordinator.provider_mut().inject_failure_once(HostFaultPoint::SkipSourceFence);
    let result = coordinator.project_external_source_fence(
        derive(case, "command"),
        derive(case, "operation"),
        ids.destination_node,
        INITIAL_LEASE_EPOCH.next().ok_or("lease epoch exhausted")?,
        derive_evidence(case, "decision", EvidenceKind::AuthorityDecision),
        derive_evidence(case, "closure", EvidenceKind::SourceFence),
    );
    let local_committed = coordinator.state().phase == HandoffPhase::Committed;
    let fired = coordinator
        .provider()
        .fault_observation()
        .is_some_and(|observation| observation.point == HostFaultPoint::SkipSourceFence);
    Ok(BehaviorCase {
        id: case,
        layer: "substrate_host",
        fault_point: "SkipSourceFence",
        fired,
        divergence_or_failure_observed: result.is_err() && local_committed,
        result: format!(
            "operation_error={}; local_committed_after_error={local_committed}",
            result.is_err()
        ),
        details: json!({"fail_closed_error": result.is_err(), "local_state_mutated_before_error": local_committed}),
    })
}

fn activated_source(
    root: &Path,
    case: &str,
) -> Result<(LoopbackLogicalPeer, CompositeFixtureIds, Coordinator<SqliteProvider>, Digest), String>
{
    let peer = spawn_peer()?;
    let fixture = create_fixture(root, case, &peer)?;
    let CompositeFixture { ids, source_state, profile_digest, source, destination, .. } = fixture;
    drop(destination);
    let mut coordinator = Coordinator::recover(source_state, source).map_err(runtime_error)?;
    coordinator
        .activate(derive(case, "activate"), ids.source_handoff_authority, INITIAL_LEASE_EPOCH)
        .map_err(runtime_error)?;
    Ok((peer, ids, coordinator, profile_digest))
}

fn exported_source(
    root: &Path,
    case: &str,
) -> Result<(LoopbackLogicalPeer, CompositeFixtureIds, Coordinator<SqliteProvider>, Digest), String>
{
    let (peer, ids, mut coordinator, profile_digest) = activated_source(root, case)?;
    coordinator
        .begin_quiesce(derive(case, "quiesce"), ids.source_handoff_authority)
        .map_err(runtime_error)?;
    let safe_point = coordinator.prepare_safe_point().map_err(runtime_error)?;
    coordinator
        .commit_safe_point(derive(case, "freeze"), vec![0], safe_point)
        .map_err(runtime_error)?;
    coordinator
        .export_snapshot(
            derive(case, "export"),
            ids.handoff,
            ids.snapshot,
            snapshot_evidence(case, &coordinator)?,
        )
        .map_err(runtime_error)?;
    Ok((peer, ids, coordinator, profile_digest))
}

fn has_durable_handoff_commit(coordinator: &Coordinator<SqliteProvider>) -> Result<bool, String> {
    Ok(coordinator
        .provider()
        .replay_from(None)
        .map_err(|error| format!("cannot inspect source journal: {error:?}"))?
        .iter()
        .any(|entry| matches!(entry.event.kind, contract_core::EventKind::HandoffCommitted { .. })))
}

fn committed_event(decision: contract_core::Decision) -> Result<contract_core::Event, String> {
    match decision {
        contract_core::Decision::Commit(event) => Ok(event),
        other => Err(format!("expected committed event, got {other:?}")),
    }
}

fn has_grant(state: &contract_core::CanonicalState, authority: EntityRef) -> bool {
    state.authorities.iter().any(|grant| grant.authority == authority)
}

fn authority_status(
    state: &contract_core::CanonicalState,
    authority: EntityRef,
) -> Option<AuthorityStatus> {
    state
        .authorities
        .iter()
        .find(|grant| grant.authority.identity == authority.identity)
        .map(|grant| grant.status)
}

fn parse_identity(value: &str) -> Option<Identity> {
    visa_component_adapter::parse_identity(value)
}
