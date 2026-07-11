//! Historical in-memory semantic-model comparison oracle.
//!
//! Stage 1 production uses the narrow `semantic_core` reducer. This oracle implements the pre-reset contract-visible state:
//! ObjectRefs, generations, capabilities, waits, traps, cleanup, events, stable
//! views, and domain stores behind the `SemanticGraph` facade.
//!
//! It is not a Linux compatibility layer, not a substrate implementation, and
//! not the target-runtime wire ABI. Frontend personalities and hardware ports
//! must normalize their behavior into this ledger before it becomes semantic
//! truth.

#![no_std]
#![allow(
    clippy::collapsible_if,
    clippy::option_as_ref_deref,
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::vec_init_then_push
)]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod activation;
mod artifact;
mod boundary;
mod capability;
mod contract_graph;
mod event_log;
mod graph;
mod guest_memory;
mod handles;
mod ids;
mod memory_boundary;
mod migration;
pub mod object_table;
mod records;
mod runtime_mode;
pub mod target_executor;
mod taxonomy;

pub use activation::*;
pub use artifact::*;
pub use boundary::*;
pub use capability::*;
pub use contract_graph::*;
pub use event_log::*;
pub use graph::*;
pub use guest_memory::*;
pub use handles::*;
pub use ids::*;
pub use memory_boundary::*;
pub use migration::*;
pub use records::*;
pub use runtime_mode::*;
pub(crate) use target_executor::*;
pub use taxonomy::*;

#[cfg(test)]
mod tests;
