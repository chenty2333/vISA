//! Pure canonical reducer for vISA state continuity.

#![no_std]

extern crate alloc;

pub mod faults;
mod reducer;
mod replay;
mod restore;

pub use reducer::{ApplyResult, apply, preflight};
pub use replay::{ReplayError, replay, replay_from};
pub use restore::restore;

#[cfg(test)]
mod tests;
