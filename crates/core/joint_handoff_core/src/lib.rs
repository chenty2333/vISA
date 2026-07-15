//! Versioned composition protocol for vISA ownership handoff and effect closure.
//!
//! This crate owns only the joint protocol vocabulary and its pure reducer. It
//! does not replace vISA canonical state, an ownership service, Nexus closure,
//! receipt signature verification, or durable storage.

#![no_std]

extern crate alloc;

mod codec;
mod reducer;
mod types;

pub use codec::{
    DecodeError, EncodeError, JOINT_CANONICAL_ENCODING, JOINT_DIGEST_ALGORITHM, canonical_bytes,
    canonical_digest, canonical_from_bytes, receipt_digest, receipt_request_binding,
    receipt_request_digest, receipt_request_parameters_digest,
};
pub use reducer::{apply, preflight};
pub use types::*;

#[cfg(test)]
mod tests;
