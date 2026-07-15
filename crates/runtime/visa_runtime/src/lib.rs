//! Authoritative coordinator for vISA state continuity.

#![no_std]

extern crate alloc;

mod codec;
mod coordinator;

pub use codec::{
    CANONICAL_ENCODING, DIGEST_ALGORITHM, EncodeError, canonical_bytes, canonical_digest,
    snapshot_integrity, state_digest,
};
pub use coordinator::{
    AbortReceipt, AuthorityPlan, CommandReceipt, Coordinator, DestinationResumePreview,
    EffectReceipt, ProfileAuthorityPlan, RuntimeError, SafePoint, SafePointTimer,
    SnapshotExpectations, SourceResumeReceipt, TimerPoll, ValidatedSnapshot, validate_snapshot,
};

#[cfg(test)]
mod tests;
