extern crate std;

use alloc::vec;

use contract_core::{
    ActivationStatus, AuthorityGrant, AuthorityStatus, BindingReceipt, CONTRACT_VERSION,
    CanonicalState, Command, CommandKind, Decision, DeliveryPolicy, Digest, EffectKind,
    EffectOutcome, EffectRequest, EffectResult, EntityRef, Event, EventKind, EvidenceKind,
    EvidenceRef, ExtensionSupport, Generation, HandoffPhase, IdempotencyKey, Identity,
    JournalEntry, JournalPosition, KeyValueClaim, LeaseEpoch, LogicalDurationNanos, NodeIdentity,
    Ownership, PreparationCleanup, PreparedDestination, Rejection, Replay, ResourceClaims, Rights,
    SnapshotEnvelope, SnapshotRecord, TimerClaim, TimerClock, TimerDisposition, TimerStatus,
    VersionedValue,
};

use super::*;

mod authority;
mod effect;
mod handoff;
mod replay;
mod support;

use support::*;
