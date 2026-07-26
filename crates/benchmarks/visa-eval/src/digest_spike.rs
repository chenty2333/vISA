//! Independent journal-replay digest-cost spike.
//!
//! This module intentionally does not change `contract_core`, the reducer, or
//! the production replay path. The current path computes the canonical state
//! digest for every replay boundary; the prototype keeps a fixed non-operation
//! base digest and an operation Merkle tree. The roots are not contract
//! compatible and are compared only as performance prototypes.

use std::{hint::black_box, time::Instant};

use contract_core::{
    CanonicalState, DeliveryPolicy, Digest, EffectKind, EffectRequest, EntityRef, Generation,
    IdempotencyKey, Identity, KeyValueClaim, LeaseEpoch, NodeIdentity, OperationRecord,
    ResourceClaims, Rights, SchemaVersion, TimerClaim, TimerClock, canonical_digest,
};
use sha2::{Digest as _, Sha256};
use visa_runtime::{canonical_bytes, state_digest};

use crate::{
    EvalOptions, nanos,
    output::{Sample, SampleSink},
};

pub const MEASURE: &str = "digest-cost";

/// A local fixed-capacity Merkle tree used only by this spike. Appending and
/// replacing a leaf update one root-to-leaf path; growth beyond the declared
/// capacity is rejected so the measured operation is never silently rebuilt.
#[derive(Clone, Debug)]
pub struct IncrementalStateDigest {
    base: Digest,
    capacity: usize,
    length: usize,
    tree: Vec<Digest>,
}

impl IncrementalStateDigest {
    pub fn new(base: Digest, capacity: usize) -> Self {
        let capacity = capacity.max(1).next_power_of_two();
        Self { base, capacity, length: 0, tree: vec![Digest::ZERO; capacity * 2] }
    }

    pub fn push(&mut self, record: &OperationRecord) -> Result<Digest, String> {
        if self.length == self.capacity {
            return Err("incremental digest prototype capacity exhausted".to_owned());
        }
        let index = self.length;
        self.length += 1;
        self.replace(index, record)
    }

    pub fn replace(&mut self, index: usize, record: &OperationRecord) -> Result<Digest, String> {
        if index >= self.length {
            return Err(format!("cannot replace non-existent operation index {index}"));
        }
        let leaf = canonical_digest(record)
            .map_err(|error| format!("cannot digest operation leaf: {error:?}"))?;
        let mut slot = self.capacity + index;
        self.tree[slot] = leaf;
        while slot > 1 {
            slot /= 2;
            self.tree[slot] = hash_pair(self.tree[slot * 2], self.tree[slot * 2 + 1]);
        }
        Ok(self.root())
    }

    #[must_use]
    pub fn root(&self) -> Digest {
        let mut hasher = Sha256::new();
        hasher.update(b"visa-incremental-state-digest-spike-v1");
        hasher.update(self.base.0);
        hasher.update((self.length as u64).to_be_bytes());
        hasher.update(self.tree[1].0);
        Digest::from_bytes(hasher.finalize().into())
    }
}

fn hash_pair(left: Digest, right: Digest) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"visa-incremental-state-digest-node-v1");
    hasher.update(left.0);
    hasher.update(right.0);
    Digest::from_bytes(hasher.finalize().into())
}

pub fn run(options: &EvalOptions, sink: &mut SampleSink) -> Result<(), String> {
    for run in 0..options.runs {
        for &count in &options.digest_operations {
            let count = usize::try_from(count)
                .map_err(|_| format!("digest operation count {count} is too large"))?;
            let records = (0..count).map(operation_record).collect::<Result<Vec<_>, _>>()?;
            let (full_elapsed, full_state_bytes, full_root) = full_replay(&records)?;
            let (incremental_elapsed, incremental_root) = incremental_replay(&records)?;

            sink.record(
                Sample::new(MEASURE, "full-state-digest", "replay-total")
                    .config("operations", count as u64)
                    .at(run, 0)
                    .nanos(nanos(full_elapsed)),
            )?;
            sink.record(
                Sample::new(MEASURE, "incremental-merkle-prototype", "replay-total")
                    .config("operations", count as u64)
                    .at(run, 0)
                    .nanos(nanos(incremental_elapsed)),
            )?;
            sink.record(
                Sample::new(MEASURE, "full-state-digest", "final-state-bytes")
                    .config("operations", count as u64)
                    .at(run, 0)
                    .bytes(full_state_bytes as u64),
            )?;
            sink.record(
                Sample::new(MEASURE, "digest-roots", "intentionally-non-equivalent")
                    .config("operations", count as u64)
                    .config("full_root_prefix", hex_prefix(full_root))
                    .config("prototype_root_prefix", hex_prefix(incremental_root))
                    .at(run, 0)
                    .bytes(0),
            )?;
        }
    }
    Ok(())
}

fn full_replay(
    records: &[OperationRecord],
) -> Result<(std::time::Duration, usize, Digest), String> {
    let mut state = empty_state();
    let started = Instant::now();
    for record in records {
        state.operations.push(record.clone());
        // The production replay validates both input and output boundaries.
        black_box(
            state_digest(&state).map_err(|error| format!("full state digest failed: {error:?}"))?,
        );
        black_box(
            state_digest(&state).map_err(|error| format!("full state digest failed: {error:?}"))?,
        );
    }
    let elapsed = started.elapsed();
    let bytes = canonical_bytes(&state)
        .map_err(|error| format!("canonical state encoding failed: {error:?}"))?
        .len();
    let root =
        state_digest(&state).map_err(|error| format!("full state digest failed: {error:?}"))?;
    Ok((elapsed, bytes, root))
}

fn incremental_replay(
    records: &[OperationRecord],
) -> Result<(std::time::Duration, Digest), String> {
    let state = empty_state();
    let base = canonical_digest(&state)
        .map_err(|error| format!("prototype base digest failed: {error:?}"))?;
    let mut digest = IncrementalStateDigest::new(base, records.len());
    let started = Instant::now();
    for record in records {
        black_box(digest.push(record)?);
    }
    Ok((started.elapsed(), digest.root()))
}

fn empty_state() -> CanonicalState {
    let component = EntityRef::new(Identity::from_u128(0x100), Generation::INITIAL);
    let node = NodeIdentity::new(Identity::from_u128(0x101));
    CanonicalState::dormant(
        component,
        node,
        Digest::from_bytes([1; 32]),
        Digest::from_bytes([2; 32]),
        SchemaVersion::new(1, 0),
        ResourceClaims {
            timer: TimerClaim {
                resource: EntityRef::new(Identity::from_u128(0x102), Generation::INITIAL),
                clock: TimerClock::PausedMonotonicDuration,
                required_rights: Rights::TIMER_ARM,
            },
            key_value: KeyValueClaim {
                resource: EntityRef::new(Identity::from_u128(0x103), Generation::INITIAL),
                namespace: Identity::from_u128(0x104),
                required_rights: Rights::KV_WRITE,
                delivery: DeliveryPolicy::Deduplicated,
            },
        },
        Vec::new(),
    )
}

fn operation_record(index: usize) -> Result<OperationRecord, String> {
    let operation = Identity::from_u128(0x10_000 + index as u128);
    let kind = EffectKind::KeyValueCompareAndSet {
        key: format!("digest-key-{index}").into_bytes(),
        expected_version: if index > 0 { Some(index as u64 - 1) } else { None },
        value: (index as u64).to_be_bytes().to_vec(),
    };
    let request = EffectRequest {
        operation,
        idempotency_key: IdempotencyKey::from_bytes(operation.0),
        causal_parent: None,
        node: NodeIdentity::new(Identity::from_u128(0x101)),
        subject: EntityRef::new(Identity::from_u128(0x100), Generation::INITIAL),
        resource: EntityRef::new(Identity::from_u128(0x103), Generation::INITIAL),
        authority: EntityRef::new(Identity::from_u128(0x105), Generation::INITIAL),
        lease_epoch: LeaseEpoch::INITIAL,
        request_digest: canonical_digest(&kind)
            .map_err(|error| format!("operation request digest failed: {error:?}"))?,
        kind,
    };
    Ok(OperationRecord::prepared(request))
}

fn hex_prefix(digest: Digest) -> String {
    digest.0[..4].iter().map(|byte| format!("{byte:02x}")).collect()
}
