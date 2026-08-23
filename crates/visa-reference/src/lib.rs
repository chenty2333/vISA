//! A deliberately small, durable reference authority/provider.
//!
//! This crate is an executable boundary model, not a replacement for
//! TheKernel.  The authority owns bindings and execution fences, the provider
//! owns durable values, and [`store::RecordStore`] owns continuation lineage.
//! They may share one SQLite file, but they use separate tables and separate
//! Rust APIs so that a local projection cannot become a second authority.

#![deny(unsafe_code)]

mod component;
mod db;
mod profile;

pub mod authority;
#[allow(dead_code)] // BindingHandle intentionally keeps the grant snapshot opaque.
pub mod provider;
pub mod runtime;
pub mod store;

pub use authority::{
    Authority, AuthorityError, BindingId, BindingRole, BindingView, SourceBinding,
};
pub use db::{ReferenceDatabase, ReferenceDatabaseError};
pub use runtime::{ReferenceRuntime, RuntimeError};
