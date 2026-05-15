#![no_std]

extern crate alloc;
#[cfg(any(test, feature = "host-tap"))]
extern crate std;

pub mod block;
pub mod net;
pub mod page_table;
