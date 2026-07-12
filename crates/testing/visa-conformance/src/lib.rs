mod artifact_io;
mod stage1;
mod stage1_artifacts;
mod stage2;
mod stage2_normalize;

pub const JCO_NODE_EXECUTION_CARRIER: &str = "owned-bytes-stdin-frame-v1";

pub use stage1::*;
pub use stage2::*;
pub use stage2_normalize::*;

#[cfg(test)]
mod stage1_tests;

#[cfg(test)]
mod stage2_tests;
