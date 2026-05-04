use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use super::*;

#[derive(Clone, Debug)]
pub struct SemanticGraph {
    domains: SemanticDomains,
    event_log: EventLog,
    command_results: Vec<CommandResult>,
}

mod activation_migration;
mod authority;
mod block_benchmark;
mod block_completion_object;
mod block_device_object;
mod block_dma_buffer;
mod block_driver_cleanup;
mod block_page_object;
mod block_pending_io_policy;
mod block_range_object;
mod block_read_path;
mod block_recovery_benchmark;
mod block_request_generation_audit;
mod block_request_object;
mod block_request_queue;
mod block_wait;
mod block_write_path;
mod boundary;
mod buffer_cache_object;
mod capability;
mod cleanup;
mod command;
mod context;
mod cross_scheduler;
mod descriptor_object;
mod device_capability;
mod device_object;
mod directory_object;
mod display_capability;
mod display_cleanup;
mod display_event_log;
mod display_object;
mod display_panic_last_frame;
mod display_snapshot_barrier;
mod dma_buffer_object;
mod domains;
mod driver_store_binding;
mod endpoint_object;
mod ext4_adapter_object;
mod fake_block_backend_object;
mod fake_net_backend_object;
mod fat_adapter_object;
mod file_handle_capability;
mod file_object;
mod framebuffer_benchmark;
mod framebuffer_dirty_region;
mod framebuffer_flush_region;
mod framebuffer_mapping;
mod framebuffer_object;
mod framebuffer_window_lease;
mod framebuffer_write;
mod fs_wait;
mod hart;
mod hart_event;
mod integrated_code_publish_smp_workload;
mod integrated_disk_preempt_fault;
mod integrated_display_panic;
mod integrated_display_scheduler_load;
mod integrated_network_disk_io;
mod integrated_osctl_trace_replay;
mod integrated_simd_migration;
mod integrated_smp_network_fault;
mod integrated_smp_preemption_cleanup;
mod integrated_snapshot_io_lease_barrier;
mod interface;
mod io_cleanup;
mod io_fault_injection;
mod io_validator;
mod io_wait;
mod ipi;
mod irq_event;
mod irq_line_object;
mod latency;
mod mmio_region_object;
mod network;
mod network_backpressure;
mod network_benchmark;
mod network_driver_cleanup;
mod network_fault_injection;
mod network_generation_audit;
mod network_recovery_benchmark;
mod network_rx_interrupt;
mod network_rx_wait;
mod network_stack_adapter;
mod network_tx_completion;
mod network_tx_gate;
mod packet_buffer_object;
mod packet_descriptor_object;
mod packet_device_object;
mod packet_queue_object;
mod query;
mod queue_object;
mod remote;
mod remote_park;
mod resource;
mod scheduler;
mod simd_benchmark;
mod simd_context_switch_benchmark;
mod simd_fault_injection;
mod smp_cleanup_quiescence;
mod smp_code_publish;
mod smp_safe_point;
mod smp_scaling;
mod smp_snapshot_barrier;
mod smp_stress;
mod snapshot;
mod socket_object;
mod socket_operation;
mod socket_wait;
mod stop_the_world;
mod store;
mod substrate;
mod target_feature_set;
mod task;
mod timer;
mod transaction;
mod vector_state;
mod virtio_blk_backend_object;
mod virtio_net_backend_object;
mod wait;

pub use command::*;
use domains::SemanticDomains;

impl SemanticGraph {
    pub fn new() -> Self {
        Self::with_runtime_mode(RuntimeMode::Research)
    }
    pub fn with_runtime_mode(runtime_mode: RuntimeMode) -> Self {
        Self {
            domains: SemanticDomains::new(),
            event_log: EventLog::with_runtime_mode(runtime_mode),
            command_results: Vec::new(),
        }
    }
    pub fn runtime_mode(&self) -> RuntimeMode {
        self.event_log.runtime_mode()
    }
}

impl Default for SemanticGraph {
    fn default() -> Self {
        Self::new()
    }
}
