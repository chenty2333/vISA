//! (a) Steady-state cost of one durable effect on the real coordinator.
//!
//! Two coordinator arms drive the production path with no Wasm in the loop:
//! a key-value compare-and-set, and a timer arm/cancel/cleanup cycle. Two
//! baseline arms perform the same number of SQLite transactions through a
//! separate connection configured exactly like the provider's, writing blobs
//! the size of a real journal entry. The difference between the arms is the
//! coordinator's own cost: two full-state postcard encodings plus SHA-256 per
//! journal entry, the reducer, and the operation ledger.

use std::{path::Path, time::Instant};

use contract_core::{
    EffectKind, EffectOutcome, EffectRequest, EffectResult, EvidenceKind, IdempotencyKey, Identity,
    LogicalDurationNanos, canonical_digest,
};
use rusqlite::{Connection, TransactionBehavior, params};
use visa_composite_cell::fixture::INITIAL_LEASE_EPOCH;
use visa_runtime::{CommandReceipt, Coordinator};

use crate::{
    EvalOptions, case_id, create_fixture, derive, derive_evidence,
    output::{Sample, SampleSink},
    runtime_error, spawn_peer,
};

pub const MEASURE: &str = "steady-state";
/// Key the compare-and-set arm rewrites every iteration.
const STEADY_KEY: &[u8] = b"steady-state";
/// Fallback blob size if no journal entry could be measured.
const FALLBACK_ENTRY_BYTES: usize = 512;

pub fn run(options: &EvalOptions, sink: &mut SampleSink) -> Result<(), String> {
    for run in 0..options.runs {
        let entry_bytes = coordinator_arms(options, sink, run)?;
        sink.record(
            Sample::new(MEASURE, "journal-entry", "postcard-length")
                .at(run, 0)
                .bytes(entry_bytes as u64),
        )?;
        for transactions in [1_u64, 3] {
            baseline_arm(options, sink, run, transactions, entry_bytes)?;
        }
    }
    Ok(())
}

/// Both coordinator arms, each on its own fixture so one arm's operation
/// ledger cannot inflate the other's. Returns the median encoded length of the
/// journal entries the key-value arm actually produced.
fn coordinator_arms(
    options: &EvalOptions,
    sink: &mut SampleSink,
    run: u32,
) -> Result<usize, String> {
    let entry_bytes = key_value_arm(options, sink, run)?;
    timer_arm(options, sink, run)?;
    Ok(entry_bytes)
}

fn key_value_arm(options: &EvalOptions, sink: &mut SampleSink, run: u32) -> Result<usize, String> {
    let root = options.run_root(MEASURE, run).join("kv");
    let case = case_id("steady-kv", run);
    let peer = spawn_peer()?;
    let fixture = create_fixture(&root, &case, &peer)?;
    let ids = fixture.ids;
    let database = fixture.paths.database.clone();

    let mut coordinator =
        Coordinator::recover(fixture.source_state, fixture.source).map_err(runtime_error)?;
    coordinator
        .activate(derive(&case, "activate"), ids.source_handoff_authority, INITIAL_LEASE_EPOCH)
        .map_err(runtime_error)?;

    let mut expected_version = None;
    for iteration in 0..(options.warmup + options.iters) {
        let label = format!("kv-{iteration}");
        let operation = derive(&case, &label);
        let kind = EffectKind::KeyValueCompareAndSet {
            key: STEADY_KEY.to_vec(),
            expected_version,
            value: iteration.to_be_bytes().to_vec(),
        };
        let request = EffectRequest {
            operation,
            idempotency_key: IdempotencyKey::from_bytes(operation.0),
            causal_parent: None,
            node: ids.source_node,
            subject: ids.source_component,
            resource: ids.key_value,
            authority: ids.source_key_value_authority,
            lease_epoch: INITIAL_LEASE_EPOCH,
            request_digest: canonical_digest(&kind)
                .map_err(|error| format!("cannot digest effect: {error:?}"))?,
            kind,
        };
        let started = Instant::now();
        let receipt = coordinator
            .effect(derive(&case, &format!("kv-command-{iteration}")), request)
            .map_err(runtime_error)?;
        let elapsed = started.elapsed();
        expected_version = Some(applied_version(&receipt, operation)?);
        if iteration >= options.warmup {
            sink.record(
                Sample::new(MEASURE, "coordinator", "kv-compare-and-set")
                    .config("effect", "key_value_compare_and_set")
                    .at(run, iteration - options.warmup)
                    .nanos(nanos(elapsed)),
            )?;
        }
    }
    drop(coordinator);
    drop(peer);
    median_journal_entry_bytes(&database)
}

fn timer_arm(options: &EvalOptions, sink: &mut SampleSink, run: u32) -> Result<(), String> {
    let root = options.run_root(MEASURE, run).join("timer");
    let case = case_id("steady-timer", run);
    let peer = spawn_peer()?;
    let fixture = create_fixture(&root, &case, &peer)?;
    let ids = fixture.ids;
    let timer_ids = TimerIds {
        node: ids.source_node,
        subject: ids.source_component,
        resource: ids.timer,
        authority: ids.source_timer_authority,
    };

    let mut coordinator =
        Coordinator::recover(fixture.source_state, fixture.source).map_err(runtime_error)?;
    coordinator
        .activate(derive(&case, "activate"), ids.source_handoff_authority, INITIAL_LEASE_EPOCH)
        .map_err(runtime_error)?;

    for iteration in 0..(options.warmup + options.iters) {
        let arm_operation = derive(&case, &format!("timer-arm-{iteration}"));
        // A one-hour duration keeps the timer pending for the whole cycle, so
        // the cancel path is measured and the firing path never runs.
        let arm_kind = EffectKind::TimerArm { remaining: LogicalDurationNanos(3_600_000_000_000) };
        let arm_request = timer_request(&timer_ids, arm_operation, arm_kind)?;
        let started = Instant::now();
        let receipt = coordinator
            .effect(derive(&case, &format!("timer-arm-command-{iteration}")), arm_request)
            .map_err(runtime_error)?;
        let arm_elapsed = started.elapsed();
        require_effect(&receipt, arm_operation)?;

        let cancel_operation = derive(&case, &format!("timer-cancel-{iteration}"));
        let cancel_kind = EffectKind::TimerCancel { target_operation: arm_operation };
        let cancel_request = timer_request(&timer_ids, cancel_operation, cancel_kind)?;
        let started = Instant::now();
        let receipt = coordinator
            .effect(derive(&case, &format!("timer-cancel-command-{iteration}")), cancel_request)
            .map_err(runtime_error)?;
        let cancel_elapsed = started.elapsed();
        require_effect(&receipt, cancel_operation)?;

        // The canonical timer only returns to an armable state once the arm
        // operation is cleaned, so the cycle cost includes this third command.
        let started = Instant::now();
        coordinator
            .cleanup_operation(
                derive(&case, &format!("timer-cleanup-command-{iteration}")),
                arm_operation,
                derive_evidence(
                    &case,
                    &format!("timer-cleanup-{iteration}"),
                    EvidenceKind::Cleanup,
                ),
            )
            .map_err(runtime_error)?;
        let cleanup_elapsed = started.elapsed();

        if iteration >= options.warmup {
            let index = iteration - options.warmup;
            for (phase, elapsed) in [
                ("timer-arm", arm_elapsed),
                ("timer-cancel", cancel_elapsed),
                ("timer-arm-cleanup", cleanup_elapsed),
                ("timer-cycle", arm_elapsed + cancel_elapsed + cleanup_elapsed),
            ] {
                sink.record(
                    Sample::new(MEASURE, "coordinator", phase)
                        .config("effect", "timer_arm_cancel")
                        .at(run, index)
                        .nanos(nanos(elapsed)),
                )?;
            }
        }
    }
    drop(coordinator);
    drop(peer);
    Ok(())
}

/// The subset of fixture identifiers a timer effect request needs.
struct TimerIds {
    node: contract_core::NodeIdentity,
    subject: contract_core::EntityRef,
    resource: contract_core::EntityRef,
    authority: contract_core::EntityRef,
}

fn timer_request(
    ids: &TimerIds,
    operation: Identity,
    kind: EffectKind,
) -> Result<EffectRequest, String> {
    Ok(EffectRequest {
        operation,
        idempotency_key: IdempotencyKey::from_bytes(operation.0),
        causal_parent: None,
        node: ids.node,
        subject: ids.subject,
        resource: ids.resource,
        authority: ids.authority,
        lease_epoch: INITIAL_LEASE_EPOCH,
        request_digest: canonical_digest(&kind)
            .map_err(|error| format!("cannot digest effect: {error:?}"))?,
        kind,
    })
}

/// The baseline: the same SQLite version, the same durability settings, the
/// same `TransactionBehavior::Immediate`, the same `WITHOUT ROWID` composite
/// primary key, and blobs the size of a real journal entry. It carries no
/// canonical state, so it performs no encoding and no hashing.
fn baseline_arm(
    options: &EvalOptions,
    sink: &mut SampleSink,
    run: u32,
    transactions: u64,
    entry_bytes: usize,
) -> Result<(), String> {
    let root = options.run_root(MEASURE, run).join(format!("baseline-{transactions}txn"));
    std::fs::create_dir_all(&root)
        .map_err(|error| format!("cannot create {}: {error}", root.display()))?;
    let database = root.join("baseline.sqlite3");
    let mut connection = open_baseline(&database)?;
    let blob = vec![0x5A_u8; entry_bytes];

    for iteration in 0..(options.warmup + options.iters) {
        let started = Instant::now();
        for slot in 0..transactions {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|error| format!("cannot begin baseline transaction: {error}"))?;
            transaction
                .execute(
                    "INSERT INTO baseline_entry(scope_id, position, entry) VALUES (?1, ?2, ?3)",
                    params![
                        &[run as u8; 16][..],
                        &(iteration * transactions + slot).to_be_bytes()[..],
                        &blob[..]
                    ],
                )
                .map_err(|error| format!("cannot insert baseline row: {error}"))?;
            transaction
                .commit()
                .map_err(|error| format!("cannot commit baseline transaction: {error}"))?;
        }
        let elapsed = started.elapsed();
        if iteration >= options.warmup {
            sink.record(
                Sample::new(MEASURE, "sqlite-baseline", "insert-cycle")
                    .config("transactions_per_iteration", transactions)
                    .config("blob_bytes", entry_bytes as u64)
                    .at(run, iteration - options.warmup)
                    .nanos(nanos(elapsed)),
            )?;
        }
    }
    Ok(())
}

fn open_baseline(database: &Path) -> Result<Connection, String> {
    let connection = Connection::open(database)
        .map_err(|error| format!("cannot open {}: {error}", database.display()))?;
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|error| format!("cannot set baseline busy timeout: {error}"))?;
    connection
        .execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS baseline_entry (
                 scope_id BLOB NOT NULL CHECK (length(scope_id) = 16),
                 position BLOB NOT NULL CHECK (length(position) = 8),
                 entry BLOB NOT NULL,
                 PRIMARY KEY(scope_id, position)
             ) WITHOUT ROWID;",
        )
        .map_err(|error| format!("cannot configure baseline database: {error}"))?;
    Ok(connection)
}

/// Median encoded length of the journal entries the coordinator wrote. Entry
/// length is what the baseline blob has to match; canonical state size does
/// not enter the entry because the entry carries digests, not state.
fn median_journal_entry_bytes(database: &Path) -> Result<usize, String> {
    let connection = Connection::open(database)
        .map_err(|error| format!("cannot reopen {}: {error}", database.display()))?;
    let mut statement = connection
        .prepare("SELECT length(entry) FROM canonical_journal ORDER BY length(entry)")
        .map_err(|error| format!("cannot query journal entry lengths: {error}"))?;
    let lengths = statement
        .query_map([], |row| row.get::<_, i64>(0))
        .map_err(|error| format!("cannot read journal entry lengths: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot read journal entry lengths: {error}"))?;
    if lengths.is_empty() {
        return Ok(FALLBACK_ENTRY_BYTES);
    }
    let median = lengths[lengths.len() / 2];
    usize::try_from(median).map_err(|_| "journal entry length is not representable".to_owned())
}

fn applied_version(receipt: &CommandReceipt, operation: Identity) -> Result<u64, String> {
    let outcome = require_effect(receipt, operation)?;
    match outcome {
        EffectOutcome::Succeeded {
            result: EffectResult::KeyValue { version, applied }, ..
        } if *applied => Ok(*version),
        other => Err(format!("unexpected key-value outcome for {operation:?}: {other:?}")),
    }
}

/// A replayed receipt would mean the harness reused an identity and measured
/// an in-memory lookup instead of a durable effect.
fn require_effect(receipt: &CommandReceipt, operation: Identity) -> Result<&EffectOutcome, String> {
    match receipt {
        CommandReceipt::Effect(effect) => match &effect.outcome {
            EffectOutcome::Succeeded { .. } => Ok(&effect.outcome),
            other => Err(format!("effect {operation:?} did not succeed: {other:?}")),
        },
        CommandReceipt::Replayed(replay) => {
            Err(format!("effect {operation:?} was replayed, not executed: {replay:?}"))
        }
        CommandReceipt::Committed(_) => {
            Err(format!("effect {operation:?} produced a command receipt"))
        }
    }
}

fn nanos(elapsed: std::time::Duration) -> u64 {
    u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
}
