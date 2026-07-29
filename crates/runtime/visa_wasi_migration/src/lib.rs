//! Carrier-neutral binding and fail-closed orchestration for transparent WASI
//! migrations.
//!
//! This crate deliberately does not decide ownership. A caller supplies an
//! implementation of [`CanonicalProofVerifier`] backed by the canonical
//! ownership service. The resource provider operations performed here are
//! projections of that decision, never a second authority.

mod driver;
mod manifest;
mod proof;

pub use driver::{
    CanonicalProofVerifier, ComputeControl, Driver, DriverRecord, MigrationError, Phase,
    ProviderMode, ProviderProjection, ProviderProjectionStatus,
};
pub use manifest::{
    APPLICATION_ROLE, BoundFile, BuildIdentity, CAPSULE_MANIFEST_ROLE, CAPSULE_STATE_ROLE,
    CHECKPOINT_ROLE, ClientLineage, FileRoles, MANIFEST_SCHEMA, ManifestDigest, MigrationIntent,
    MigrationManifest, PlatformIdentity,
};
pub use proof::{
    COMMIT_PROOF_SCHEMA, CanonicalCommitProof, CanonicalFenceProof, FENCE_PROOF_SCHEMA, ProofDigest,
};
