//! Frozen local process-boundary contracts for the vISA 0.1 product.
//!
//! The three RPC families deliberately share only mechanical primitives. Their
//! request, response, error, replay, schema, service-name, object-path, and
//! interface namespaces remain distinct.

pub mod agent_control;
pub mod common;
pub mod nexus_adapter;
pub mod ownership;
pub mod schema;

mod codec;

pub use codec::{
    CANONICAL_ENCODING, DecodeError, EncodeError, MAX_INNER_REQUEST_BYTES,
    MAX_INNER_RESPONSE_BYTES, MAX_REPLAY_RECORD_BYTES,
};
pub use common::{Sha256Digest, WireValidation, WireValidationError};
