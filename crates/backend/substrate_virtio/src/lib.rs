#![no_std]

#[cfg(any(test, feature = "host-tap"))]
extern crate std;

pub mod block;
pub mod net;
