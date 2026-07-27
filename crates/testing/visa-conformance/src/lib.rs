pub mod artifact_io;
#[cfg(any(test, feature = "defect-corpus"))]
pub mod defect_corpus;
mod effect_closure;
mod effect_closure_replay;
pub mod evidence_matrix;
mod joint_handoff;
pub mod local_rpc;
mod stage1;
mod stage1_artifacts;
#[cfg(any(test, feature = "defect-corpus"))]
pub mod stage1_mutations;
mod stage2;
mod stage2_normalize;
mod stage3;
mod stage3a_cross;
mod stage4;

pub const JCO_NODE_EXECUTION_CARRIER: &str = "owned-bytes-stdin-frame-v1";

pub use effect_closure::*;
pub use effect_closure_replay::*;
pub use evidence_matrix::*;
pub use joint_handoff::*;
pub use stage1::*;
pub use stage2::*;
pub use stage2_normalize::*;
pub use stage3::*;
pub use stage3a_cross::*;
pub use stage4::*;

#[cfg(test)]
mod defect_corpus_tests;

#[cfg(test)]
mod stage1_tests;

#[cfg(test)]
mod stage2_tests;
