use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use target_abi::{
    OBJECT_KIND_CODE_OBJECT_V1, ObjectRefRaw, PcRangeEntryV1, PcRangeRuntimeEntryV1,
    TrapAttributionV1, TrapKindV1, TrapMapEntryV1, classify_trap_pc,
};

use super::*;

pub const TARGET_ARTIFACT_GENERATION_V1: Generation = 1;

mod activation;
mod artifact;
mod cleanup;
mod executor;
mod object;
mod store;

pub use activation::*;
pub use artifact::*;
pub use cleanup::*;
pub use executor::*;
pub use object::*;
pub use store::*;

#[cfg(test)]
mod tests;
