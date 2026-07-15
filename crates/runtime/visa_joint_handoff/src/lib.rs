//! Fail-closed vISA runtime projection for the joint handoff protocol.
//!
//! This wrapper does not decide ownership or implement native effect closure.
//! It consumes an opaque state advanced only by authenticated native receipts
//! and makes only the corresponding local vISA projection available.

#![no_std]

extern crate alloc;

mod durable;
mod durable_projection;
mod projection;
mod verified;

pub use durable::*;
pub use durable_projection::*;
pub use projection::*;
pub use verified::*;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod durable_tests;
