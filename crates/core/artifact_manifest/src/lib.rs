//! Manifest record types for Semantic Virtual ISA artifacts, bundles, views, and
//! migration packages.
//!
//! These structs are the interchange layer for artifact identity, package roots,
//! profile facts, semantic snapshots, and evidence reports. They are data
//! schemas, not runtime policy and not substrate authority.

mod artifact_bundle;
mod boundary;
mod semantic_snapshot;
mod target_runtime;
mod views_events;

pub use artifact_bundle::*;
pub use boundary::*;
pub use semantic_snapshot::*;
pub use target_runtime::*;
pub use views_events::*;
