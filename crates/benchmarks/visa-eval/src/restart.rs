//! (d) What a crash restart costs, replay against read-the-last-value.
//!
//! The source runs `N` effects and arms a timer, then everything holding the
//! database is dropped without a clean shutdown. Two arms then bring the cell
//! back:
//!
//! * `coordinator-replay` reopens the provider, replays the whole journal
//!   through `Coordinator::recover`, compiles and instantiates the component,
//!   and rebuilds the guest record from canonical truth.
//! * `raw-sqlite` reopens a plain connection, reads the last committed value
//!   out of `kv_entry`, compiles the component, and re-arms the timer from an
//!   in-memory deadline.
//!
//! The second arm is lossy by construction and is not a proposal. What it does
//! not reconstruct is listed in [`LOSSY_NOTES`], and the phase labels are kept
//! aligned so the shared component-compilation cost can be subtracted from
//! both.

use std::{
    path::Path,
    time::{Duration, Instant},
};

use contract_core::{LogicalDurationNanos, TimerStatus};
use rusqlite::{Connection, OptionalExtension, params};
use substrate_api::JournalScope;
use substrate_host::SqliteProvider;
use visa_component_adapter::identity_string;
use visa_composite_cell::{adapter::CompositeAdapter, component};
use visa_runtime::Coordinator;

use crate::{
    EvalOptions, LONG_TIMER_NANOS, activate_source, adapter_error, case_id, counterbalanced_values,
    create_fixture, nanos,
    output::{Sample, SampleSink},
    provider_error, runtime_error, spawn_peer, timer_kv_state,
};

pub const MEASURE: &str = "restart-baseline";

/// What the raw-SQLite arm does not rebuild. Reported as a footnote wherever
/// the two arms are compared.
pub const LOSSY_NOTES: &[&str] = &[
    "in-flight logical request phase, response cursor, and peer binding",
    "timer remaining-duration semantics: the deadline is re-derived, not resumed",
    "the idempotency ledger, so a replayed client request would execute twice",
    "regular-file version, content digest, and lock disposition",
    "authority grants, lease ownership, and the fencing epoch",
];

pub fn run(options: &EvalOptions, sink: &mut SampleSink) -> Result<(), String> {
    for run in 0..options.runs {
        for effects in counterbalanced_values(&options.effects_before_handoff, run) {
            let root = options.run_root(MEASURE, run).join(format!("effects-{effects}"));
            one_restart(&root, run, effects, sink)?;
        }
    }
    Ok(())
}

/// State the restart arms need after the source is gone. Nothing here is
/// recovered state; it is the addressing information an operator would have.
struct RestartTarget {
    database: std::path::PathBuf,
    scope: JournalScope,
    key_value_resource: contract_core::EntityRef,
    guest_key: Vec<u8>,
    timer_remaining: LogicalDurationNanos,
}

struct PreparedRestart {
    initial_state: contract_core::CanonicalState,
    target: RestartTarget,
}

fn one_restart(root: &Path, run: u32, effects: u64, sink: &mut SampleSink) -> Result<(), String> {
    let case = case_id(&format!("restart-{effects}"), run);
    let production_root = root.join("coordinator-replay");
    let raw_root = root.join("raw-sqlite");
    // Build two identical workloads in separate provider databases. The
    // measured arms therefore cannot share SQLite page-cache state or rows.
    let (production, raw) = if run.is_multiple_of(2) {
        let production = prepare_restart(&production_root, &case, effects)?;
        let raw = prepare_restart(&raw_root, &case, effects)?;
        (production, raw)
    } else {
        let raw = prepare_restart(&raw_root, &case, effects)?;
        let production = prepare_restart(&production_root, &case, effects)?;
        (production, raw)
    };

    // Alternate the measured arm order as well as the preparation order.
    if run.is_multiple_of(2) {
        coordinator_replay_arm(
            &case,
            &production.initial_state,
            &production.target,
            run,
            effects,
            sink,
        )?;
        raw_sqlite_arm(&raw.target, run, effects, sink)?;
    } else {
        raw_sqlite_arm(&raw.target, run, effects, sink)?;
        coordinator_replay_arm(
            &case,
            &production.initial_state,
            &production.target,
            run,
            effects,
            sink,
        )?;
    }
    Ok(())
}

fn prepare_restart(root: &Path, case: &str, effects: u64) -> Result<PreparedRestart, String> {
    let peer = spawn_peer()?;
    let fixture = create_fixture(root, case, &peer)?;
    let cell = activate_source(fixture, case)?;
    let ids = cell.ids;
    let initial_state = cell.initial_state;
    let database = cell.paths.database.clone();
    let mut adapter = cell.adapter;

    for index in 0..effects {
        adapter
            .kv_put(&format!("{case}-pre-{index}"), &index.to_be_bytes())
            .map_err(adapter_error)?;
    }
    adapter.timer_arm(LONG_TIMER_NANOS).map_err(adapter_error)?;
    let timer_remaining = match adapter.coordinator().state().timer.status {
        TimerStatus::Armed { remaining } => remaining,
        other => return Err(format!("timer did not arm before the restart: {other:?}")),
    };
    let target = RestartTarget {
        database,
        scope: JournalScope { node: ids.source_node, component: ids.source_component.identity },
        key_value_resource: ids.key_value,
        guest_key: visa_composite_cell::cell::BASELINE_KEY.as_bytes().to_vec(),
        timer_remaining,
    };

    // Simulated kill: the store, coordinator, and SQLite connection go away
    // without a clean shutdown path before either measured arm starts.
    drop(adapter);
    drop(peer);
    Ok(PreparedRestart { initial_state, target })
}

/// The production path: reopen, replay every journal entry, compile, instantiate,
/// and rebuild the guest record from canonical state.
fn coordinator_replay_arm(
    case: &str,
    initial_state: &contract_core::CanonicalState,
    target: &RestartTarget,
    run: u32,
    effects: u64,
    sink: &mut SampleSink,
) -> Result<(), String> {
    let total_started = Instant::now();

    let started = Instant::now();
    let provider = SqliteProvider::open(&target.database, target.scope).map_err(provider_error)?;
    let open = started.elapsed();

    let started = Instant::now();
    let coordinator =
        Coordinator::recover(initial_state.clone(), provider).map_err(runtime_error)?;
    let replay = started.elapsed();
    let operations = coordinator.state().operations.len() as u64;
    let key_value_version = coordinator.state().key_value.last_version.unwrap_or(0);
    let canonical_arm = coordinator
        .state()
        .timer
        .active_operation
        .map(identity_string)
        .ok_or("recovered state lost the armed timer operation")?;

    let started = Instant::now();
    let prepared =
        CompositeAdapter::preflight(component::composite_bytes(), component::composite_digest())
            .map_err(adapter_error)?;
    let compile = started.elapsed();

    let started = Instant::now();
    let mut adapter = CompositeAdapter::instantiate_prepared_recoverable(prepared, coordinator)
        .map_err(|failure| adapter_error(failure.0))?;
    let instantiate = started.elapsed();

    let started = Instant::now();
    adapter
        .activate(
            format!("{case}:session"),
            timer_kv_state(case, Some(canonical_arm), key_value_version),
        )
        .map_err(adapter_error)?;
    let guest_rebuild = started.elapsed();
    let total = total_started.elapsed();

    for (phase, elapsed) in [
        ("open-provider", open),
        ("journal-replay", replay),
        ("component-compile", compile),
        ("store-instantiate", instantiate),
        ("guest-rebuild", guest_rebuild),
        ("total", total),
    ] {
        sink.record(
            Sample::new(MEASURE, "coordinator-replay", phase)
                .config("effects_before_restart", effects)
                .at(run, 0)
                .nanos(nanos(elapsed)),
        )?;
    }
    sink.record(
        Sample::new(MEASURE, "coordinator-replay", "count-operation-records")
            .config("effects_before_restart", effects)
            .at(run, 0)
            .bytes(operations),
    )?;
    drop(adapter);
    Ok(())
}

/// The lossy baseline: one plain connection, one row read, the same component
/// compilation, and a timer deadline reconstructed in memory. It has no
/// canonical state, so it cannot instantiate a store — that phase is absent
/// from this arm rather than estimated, and the production arm reports it
/// separately so the gap can be read directly off the table.
fn raw_sqlite_arm(
    target: &RestartTarget,
    run: u32,
    effects: u64,
    sink: &mut SampleSink,
) -> Result<(), String> {
    let total_started = Instant::now();

    let started = Instant::now();
    let connection = open_plain(&target.database)?;
    let open = started.elapsed();

    let started = Instant::now();
    let restored: Option<(Vec<u8>, i64)> = connection
        .query_row(
            "SELECT value, version FROM kv_entry
             WHERE resource_id = ?1 AND resource_generation = ?2 AND key = ?3",
            params![
                target.key_value_resource.identity.0.as_slice(),
                &target.key_value_resource.generation.0.to_be_bytes()[..],
                &target.guest_key[..]
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| format!("cannot read kv_entry: {error}"))?;
    let read = started.elapsed();
    if restored.is_none() {
        return Err("raw restart found no key-value row to restore from".to_owned());
    }

    let started = Instant::now();
    let _prepared: crate::PreparedComponent =
        CompositeAdapter::preflight(component::composite_bytes(), component::composite_digest())
            .map_err(adapter_error)?;
    let compile = started.elapsed();

    let started = Instant::now();
    let _deadline = Instant::now()
        .checked_add(Duration::from_nanos(target.timer_remaining.0))
        .ok_or("timer deadline is not representable")?;
    let rearm = started.elapsed();
    let total = total_started.elapsed();

    for (phase, elapsed) in [
        ("open-provider", open),
        ("read-last-value", read),
        ("component-compile", compile),
        ("timer-rearm", rearm),
        ("total", total),
    ] {
        sink.record(
            Sample::new(MEASURE, "raw-sqlite", phase)
                .config("effects_before_restart", effects)
                .at(run, 0)
                .nanos(nanos(elapsed)),
        )?;
    }
    Ok(())
}

/// A connection configured exactly as the provider configures its own, so the
/// open cost is comparable between the arms.
fn open_plain(database: &Path) -> Result<Connection, String> {
    let connection = Connection::open(database)
        .map_err(|error| format!("cannot open {}: {error}", database.display()))?;
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(|error| format!("cannot set busy timeout: {error}"))?;
    connection
        .execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA foreign_keys = ON;",
        )
        .map_err(|error| format!("cannot configure connection: {error}"))?;
    Ok(connection)
}
