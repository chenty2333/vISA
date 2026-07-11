//! Historical broad substrate-authority comparison oracle.
//!
//! Stage 1 production uses the narrow continuity ports in `substrate_api`.
//!
//! This crate defines small Rust traits and capability reports for what a target
//! can enforce: console, timer, event queue, guest memory, DMW, code publish,
//! DMA, MMIO, IRQ, snapshot, logging, allocation, and extraction.
//!
//! Trait availability is not permission. Artifacts still pass through profile
//! compatibility, capability checks, generation checks, and contract-visible
//! event recording before machine authority is used.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod adapters;
#[cfg(any(test, feature = "conformance"))]
pub mod conformance;
mod profiles;
mod traits;
mod types;

pub use adapters::*;
pub use profiles::*;
pub use traits::*;
pub use types::*;

#[cfg(test)]
mod tests;
