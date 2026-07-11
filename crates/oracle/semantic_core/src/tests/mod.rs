use alloc::{format, string::ToString, vec, vec::Vec};

use super::*;

mod core_io;
#[allow(unused_imports)]
use core_io::*;
mod network_core;
#[allow(unused_imports)]
use network_core::*;
mod network_tail;
#[allow(unused_imports)]
use network_tail::*;
mod block_core;
#[allow(unused_imports)]
use block_core::*;
mod block_tail;
#[allow(unused_imports)]
use block_tail::*;
mod smp_runtime;
#[allow(unused_imports)]
use smp_runtime::*;
mod preemptive_simd;
#[allow(unused_imports)]
use preemptive_simd::*;
mod display_runtime;
#[allow(unused_imports)]
use display_runtime::*;
mod integrated_runtime;
#[allow(unused_imports)]
use integrated_runtime::*;

fn test_substrate_boundary() -> SubstrateBoundarySnapshot {
    SubstrateBoundarySnapshot {
        timer_epoch: 0,
        pending_irq_causes: 0,
        pending_dma_completions: 0,
        active_dmw_lease_count: 0,
        active_mmio_authority_count: 0,
        active_dma_authority_count: 0,
        active_irq_authority_count: 0,
        active_packet_device_authority_count: 0,
        active_virtio_queue_authority_count: 0,
        pending_network_inputs: 0,
        random_epoch: 0,
        scheduler_decision_cursor: 0,
        cow_epoch: 0,
        background_copy_pages: 0,
        native_state_policy: "rebuild".to_string(),
    }
}

fn test_artifact_profile() -> ArtifactProfile {
    ArtifactProfile {
        artifact_profile: "test".to_string(),
        target_arch: "target-native".to_string(),
        machine_abi_version: "machine".to_string(),
        supervisor_abi_version: "supervisor".to_string(),
        wasm_feature_profile: "wasm32".to_string(),
        memory64: false,
        multi_memory: false,
        dmw_layout: "dmw".to_string(),
        network_contract_version: "network".to_string(),
        compiler_engine: "wasmtime".to_string(),
        compiler_execution_mode: "precompiled-core-module".to_string(),
        artifact_format: "target-artifact-image-v1".to_string(),
        runtime_executor_abi: "visa-runtime-only-executor-v0".to_string(),
    }
}
