//! Carrier-neutral binding and fail-closed orchestration for transparent WASI
//! migrations.
//!
//! This crate deliberately does not decide ownership. A caller supplies an
//! implementation of [`CanonicalProofVerifier`] backed by the canonical
//! ownership service. The resource provider operations performed here are
//! projections of that decision, never a second authority.

mod adapter;
mod authority;
mod driver;
mod manifest;
mod proof;
mod store;
mod supervisor;

pub use adapter::{
    DESTINATION_PROVIDER_RESTORE_SCHEMA, DestinationProviderProcess, FileIdentity,
    ProviderEndpoint, ProviderProcessProjection, WANCO_RESTORE_COMPLETION_SCHEMA,
    WANCO_SOURCE_EXIT_SCHEMA, WancoProcessControl, WancoRestoreCommand, WancoSourceExit,
};
pub use authority::{
    CANONICAL_AUTHORITY_STATE_SCHEMA, CanonicalAuthorityDecision, CanonicalAuthorityFileVerifier,
    CanonicalAuthorityState,
};
pub use driver::{
    CanonicalProofVerifier, CanonicalRecovery, ComputeControl, DRIVER_RECORD_SCHEMA, Driver,
    DriverAction, DriverRecord, MigrationError, Phase, ProviderMode, ProviderProjection,
    ProviderProjectionStatus,
};
pub use manifest::{
    APPLICATION_ROLE, BoundFile, BuildIdentity, CAPSULE_MANIFEST_ROLE, CAPSULE_STATE_ROLE,
    CHECKPOINT_ROLE, ClientLineage, FileRoles, MANIFEST_SCHEMA, ManifestDigest, MigrationIntent,
    MigrationManifest, PlatformIdentity,
};
pub use proof::{
    COMMIT_PROOF_SCHEMA, CanonicalCommitProof, CanonicalFenceProof, CanonicalSourceRetainedProof,
    FENCE_PROOF_SCHEMA, ProofDigest, SOURCE_RETAINED_PROOF_SCHEMA,
};
pub use store::{DriverRecordStore, FileDriverRecordStore};
pub use supervisor::{
    WANCO_SUPERVISOR_SPEC_SCHEMA, WANCO_SUPERVISOR_STARTED_SCHEMA, run_wanco_supervisor,
};
