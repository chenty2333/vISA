//! A deliberately small, durable reference authority/provider.
//!
//! This crate is an executable boundary model, not a replacement for
//! TheKernel.  The authority owns bindings and execution fences, the provider
//! owns durable values, and [`store::RecordStore`] owns continuation lineage.
//! They may share one SQLite file, but they use separate tables and separate
//! Rust APIs so that a local projection cannot become a second authority.

#![deny(unsafe_code)]

mod db;

pub mod adapters;
pub mod authority;
pub mod provider;
pub mod runtime;
pub mod store;

pub use authority::{
    Authority, AuthorityError, BindingId, BindingRole, BindingView, CommitRequest, OperationQuery,
    PrepareRequest, SourceBinding,
};
pub use db::{ReferenceDatabase, ReferenceDatabaseError};
// Canonical portable/coordinator vocabulary is always sourced from core.  The
// authority module's string row keys remain implementation details of the
// SQLite adapter and are intentionally not re-exported as contract types.
pub use visa_core::{AuthorityCommitReceipt, BindingPreparationReceipt, OperationId, Rights};
