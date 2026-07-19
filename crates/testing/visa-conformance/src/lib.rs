pub mod artifact_io;
mod effect_closure;
mod effect_closure_replay;
mod joint_handoff;
pub mod local_rpc;
mod stage1;
mod stage1_artifacts;
mod stage2;
mod stage2_normalize;
mod stage3;
mod stage4;

pub const JCO_NODE_EXECUTION_CARRIER: &str = "owned-bytes-stdin-frame-v1";

pub use effect_closure::*;
pub use effect_closure_replay::*;
pub use joint_handoff::*;
pub use stage1::*;
pub use stage2::*;
pub use stage2_normalize::*;
pub use stage3::*;
pub use stage4::*;

#[cfg(test)]
mod stage1_tests;

#[cfg(test)]
mod stage2_tests;
