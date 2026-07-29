//! Wanco ABI bridge for the migratable vISA WASI filesystem personality.
//!
//! This library exports the complete standard Preview1 symbol surface used by
//! Wanco. A stock WASI application therefore needs neither source patches nor
//! migration callbacks: Wanco links this static library in place of its
//! process-local `libwanco_wasi`.
//!
//! File descriptors 0, 1, and 2 are deliberately node-local standard streams.
//! Descriptor 3 is the vISA root preopen and every descriptor above it is
//! provider-owned. The bridge contains no recoverable filesystem or lock state.

mod abi;
mod memory;
mod transport;

use core::ffi::c_char;

/// Native execution environment passed by Wanco to every imported function.
///
/// `memory_size_pages` is a count of 64-KiB WebAssembly pages, not a byte
/// length. The layout is kept byte-for-byte compatible with Wanco's `aot.h`.
#[repr(C)]
pub struct ExecEnv {
    memory_base: *mut u8,
    memory_size_pages: i32,
    migration_state: i32,
    argc: i32,
    argv: *mut *mut c_char,
}

pub use abi::*;
