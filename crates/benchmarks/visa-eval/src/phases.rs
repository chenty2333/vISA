//! (b) Where the time inside one composite handoff goes.
//!
//! The driver reproduces the composite cell's own sequence and wraps each
//! segment in its own `Instant`. It stops at `resume_destination`: everything
//! after that point is destination workload, not handoff cost. The timer is
//! armed for a minute so the safe point always observes it pending and no
//! phase ever waits on a firing.

use std::{fs, path::Path, time::Instant};

use contract_core::IdempotencyKey;
use visa_composite_cell::{
    adapter::CompositeAdapter, bindings::visa::request_continuity::logical_request::RequestPhase,
    cell::REQUEST_BODY, component,
};
use visa_profile::FileDurability;
use visa_runtime::{Coordinator, SafePointTimer, validate_snapshot};

use crate::{
    EvalOptions, LONG_TIMER_NANOS, activate_source, adapter_error, case_id, counterbalanced_values,
    create_fixture, derive, expectations,
    output::{Sample, SampleSink},
    runtime_error, snapshot_evidence, spawn_peer,
};

pub const MEASURE: &str = "handoff-phases";
/// Response drain attempts before the loopback request is declared stuck.
const DRAIN_ATTEMPTS: usize = 16;

pub fn run(options: &EvalOptions, sink: &mut SampleSink) -> Result<(), String> {
    for run in 0..options.runs {
        for effects in counterbalanced_values(&options.effects_before_handoff, run) {
            let root = options.run_root(MEASURE, run).join(format!("effects-{effects}"));
            one_handoff(&root, run, effects, sink)?;
        }
    }
    Ok(())
}

/// One complete source-to-destination handoff, phase by phase. A fresh
/// artifact directory and a fresh loopback peer per run keep runs independent.
fn one_handoff(
    root: &Path,
    run: u32,
    effects_before_handoff: u64,
    sink: &mut SampleSink,
) -> Result<(), String> {
    let case = case_id(&format!("handoff-{effects_before_handoff}"), run);
    let peer = spawn_peer()?;
    let fixture = create_fixture(root, &case, &peer)?;
    let cell = activate_source(fixture, &case)?;
    let mut adapter = cell.adapter;
    let ids = cell.ids;

    // ---- workload the handoff has to carry -------------------------------
    for index in 0..effects_before_handoff {
        adapter
            .kv_put(&format!("{case}-pre-{index}"), &index.to_be_bytes())
            .map_err(adapter_error)?;
    }
    let timer_arm_operation = adapter.timer_arm(LONG_TIMER_NANOS).map_err(adapter_error)?;
    adapter.file_append("append-src", b"!", FileDurability::Data).map_err(adapter_error)?;
    drain_request(&mut adapter)?;

    let handoff_started = Instant::now();

    // ---- quiesce ---------------------------------------------------------
    let started = Instant::now();
    adapter
        .coordinator_mut()
        .begin_quiesce(derive(&case, "source-begin-quiesce"), ids.source_handoff_authority)
        .map_err(runtime_error)?;
    let begin_quiesce = started.elapsed();

    let started = Instant::now();
    let safe_point = adapter.coordinator_mut().prepare_safe_point().map_err(runtime_error)?;
    let prepare_safe_point = started.elapsed();
    let safe_point_remaining_ns = match safe_point.timer() {
        SafePointTimer::Pending { remaining, .. } => Some(remaining.0),
        other => {
            return Err(format!(
                "safe point did not observe the armed timer as pending: {other:?} \
                 (arm operation {timer_arm_operation})"
            ));
        }
    };

    let started = Instant::now();
    let portable = adapter.freeze().map_err(adapter_error)?;
    let freeze = started.elapsed();

    let started = Instant::now();
    adapter
        .coordinator_mut()
        .commit_safe_point(derive(&case, "source-freeze"), portable.as_bytes().to_vec(), safe_point)
        .map_err(runtime_error)?;
    let commit_safe_point = started.elapsed();

    // ---- export and validate --------------------------------------------
    let evidence = snapshot_evidence(&case, adapter.coordinator())?;
    let started = Instant::now();
    let (_, snapshot) = adapter
        .coordinator_mut()
        .export_snapshot(derive(&case, "source-export"), ids.handoff, ids.snapshot, evidence)
        .map_err(runtime_error)?;
    let export = started.elapsed();

    let started = Instant::now();
    let validated =
        validate_snapshot(&snapshot, &expectations(cell.profile_digest, ids.destination_node))
            .map_err(runtime_error)?;
    let validate = started.elapsed();

    // ---- rebind the coordinator, reauthorize, commit ---------------------
    let started = Instant::now();
    let mut destination_coordinator =
        Coordinator::restore(validated, cell.destination).map_err(runtime_error)?;
    let coordinator_restore = started.elapsed();

    let started = Instant::now();
    destination_coordinator
        .prepare_destination_with_profiles(
            derive(&case, "destination-prepare"),
            cell.handoff_authority,
            cell.timer_authority,
            cell.key_value_authority,
            &[cell.file_authority, cell.request_authority],
        )
        .map_err(runtime_error)?;
    let reauthorize = started.elapsed();

    let started = Instant::now();
    destination_coordinator
        .commit_handoff(
            derive(&case, "destination-commit-command"),
            derive(&case, "destination-commit-operation"),
            IdempotencyKey::from_bytes(derive(&case, "destination-commit-idempotency").0),
        )
        .map_err(runtime_error)?;
    let commit = started.elapsed();

    // ---- rebind the guest and resume ------------------------------------
    let started = Instant::now();
    let mut destination_adapter =
        CompositeAdapter::instantiate(component::composite_bytes(), destination_coordinator)
            .map_err(adapter_error)?;
    let instantiate = started.elapsed();

    let started = Instant::now();
    destination_adapter.restore(&portable, safe_point_remaining_ns).map_err(adapter_error)?;
    let adapter_restore = started.elapsed();

    let started = Instant::now();
    destination_adapter
        .coordinator_mut()
        .resume_destination(derive(&case, "destination-resume"))
        .map_err(runtime_error)?;
    let resume = started.elapsed();
    let handoff_total = handoff_started.elapsed();

    let quiesce_total = begin_quiesce + prepare_safe_point + freeze + commit_safe_point;
    let phases = [
        ("quiesce-begin", begin_quiesce),
        ("quiesce-prepare-safe-point", prepare_safe_point),
        ("quiesce-freeze", freeze),
        ("quiesce-commit-safe-point", commit_safe_point),
        ("quiesce-total", quiesce_total),
        ("export-snapshot", export),
        ("validate-snapshot", validate),
        ("rebind-coordinator-restore", coordinator_restore),
        ("reauthorize-prepare-destination", reauthorize),
        ("commit-handoff", commit),
        ("rebind-adapter-instantiate", instantiate),
        ("rebind-adapter-restore", adapter_restore),
        ("resume-destination", resume),
        ("handoff-total", handoff_total),
    ];
    for (phase, elapsed) in phases {
        sink.record(
            Sample::new(MEASURE, "composite-cell", phase)
                .config("effects_before_handoff", effects_before_handoff)
                .at(run, 0)
                .nanos(crate::nanos(elapsed)),
        )?;
    }
    // The frozen portable record is what the destination has to accept, so its
    // size belongs next to the phase timings that carry it.
    sink.record(
        Sample::new(MEASURE, "composite-cell", "portable-state")
            .config("effects_before_handoff", effects_before_handoff)
            .at(run, 0)
            .bytes(portable.as_bytes().len() as u64),
    )?;

    drop(destination_adapter);
    drop(adapter);
    drop(peer);
    // Working directories are large and numerous; only the samples are needed.
    let _ = fs::remove_dir_all(root);
    Ok(())
}

/// Start the logical request and drain its response, exactly as the composite
/// cell does. Export validation refuses a request that is still in flight, so
/// this has to complete before the safe point.
pub fn drain_request(
    adapter: &mut CompositeAdapter<substrate_host::SqliteProvider>,
) -> Result<(), String> {
    let started = adapter.request_start(REQUEST_BODY).map_err(adapter_error)?;
    let mut response_len = 0_usize;
    let mut phase = started.phase;
    let mut expected = started.response.as_ref().map(|response| response.size as usize);
    for _ in 0..DRAIN_ATTEMPTS {
        if phase == RequestPhase::Completed && expected == Some(response_len) {
            return Ok(());
        }
        let observed = adapter.request_observe(64).map_err(adapter_error)?;
        let progressed = !observed.bytes.is_empty();
        response_len += observed.bytes.len();
        phase = observed.observation.phase;
        if let Some(response) = &observed.observation.response {
            expected = Some(response.size as usize);
        }
        if !progressed {
            break;
        }
    }
    if phase == RequestPhase::Completed && expected == Some(response_len) {
        return Ok(());
    }
    Err(format!(
        "logical request did not complete: phase {phase:?}, drained {response_len} of {expected:?}"
    ))
}
