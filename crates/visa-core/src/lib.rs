//! Portable continuation contracts and their pure state reducer.
#![no_std]

extern crate alloc;

mod contract;
mod reducer;

pub use contract::*;
pub use reducer::*;
