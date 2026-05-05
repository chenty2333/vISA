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

impl SemanticGraph {
    pub fn snapshot(&self) -> ContractGraphSnapshot {
        self.snapshot_with(ContractGraphSnapshotInputs::default())
    }

    pub fn snapshot_with(&self, inputs: ContractGraphSnapshotInputs<'_>) -> ContractGraphSnapshot {
        let d = &self.domains;
        ContractGraphSnapshot {
            claimed_evidence_level: inputs.claimed_evidence_level,
            artifacts: inputs.artifacts.to_vec(),
            code_objects: inputs.code_objects.to_vec(),
            // simd domain
            target_feature_sets: d.simd.target_feature_sets.clone(),
            vector_states: d.simd.vector_states.clone(),
            simd_fault_injections: d.simd.simd_fault_injections.clone(),
            simd_benchmarks: d.simd.simd_benchmarks.clone(),
            simd_context_switch_benchmarks: d.simd.simd_context_switch_benchmarks.clone(),
            // display domain
            framebuffer_objects: d.display.framebuffer_objects.clone(),
            display_objects: d.display.display_objects.clone(),
            display_capabilities: d.display.display_capabilities.clone(),
            framebuffer_window_leases: d.display.framebuffer_window_leases.clone(),
            framebuffer_mappings: d.display.framebuffer_mappings.clone(),
            framebuffer_writes: d.display.framebuffer_writes.clone(),
            framebuffer_flush_regions: d.display.framebuffer_flush_regions.clone(),
            framebuffer_dirty_regions: d.display.framebuffer_dirty_regions.clone(),
            display_event_logs: d.display.display_event_logs.clone(),
            display_cleanups: d.display.display_cleanups.clone(),
            display_snapshot_barriers: d.display.display_snapshot_barriers.clone(),
            display_panic_last_frames: d.display.display_panic_last_frames.clone(),
            framebuffer_benchmarks: d.display.framebuffer_benchmarks.clone(),
            // integrated domain
            integrated_display_scheduler_loads: d
                .integrated
                .integrated_display_scheduler_loads
                .clone(),
            integrated_snapshot_io_lease_barriers: d
                .integrated
                .integrated_snapshot_io_lease_barriers
                .clone(),
            integrated_code_publish_smp_workloads: d
                .integrated
                .integrated_code_publish_smp_workloads
                .clone(),
            integrated_display_panics: d.integrated.integrated_display_panics.clone(),
            integrated_osctl_trace_replays: d.integrated.integrated_osctl_trace_replays.clone(),
            integrated_smp_preemption_cleanups: d
                .integrated
                .integrated_smp_preemption_cleanups
                .clone(),
            integrated_smp_network_faults: d.integrated.integrated_smp_network_faults.clone(),
            integrated_disk_preempt_faults: d.integrated.integrated_disk_preempt_faults.clone(),
            integrated_simd_migrations: d.integrated.integrated_simd_migrations.clone(),
            integrated_network_disk_ios: d.integrated.integrated_network_disk_ios.clone(),
            // network domain
            network_benchmarks: d.network.network_benchmarks.clone(),
            network_driver_cleanups: d.network.network_driver_cleanups.clone(),
            packet_device_objects: d.network.packet_device_objects.clone(),
            network_stack_adapters: d.network.network_stack_adapters.clone(),
            socket_objects: d.network.socket_objects.clone(),
            virtio_net_backends: d.network.virtio_net_backends.clone(),
            // device domain
            device_objects: d.device.device_objects.clone(),
            // block domain
            fake_block_backends: d.block.fake_block_backends.clone(),
            block_benchmarks: d.block.block_benchmarks.clone(),
            io_cleanups: d.io.io_cleanups.clone(),
            block_pending_io_policies: d.block.block_pending_io_policies.clone(),
            block_waits: d.block.block_waits.clone(),
            block_request_objects: d.block.block_request_objects.clone(),
            block_device_objects: d.block.block_device_objects.clone(),
            block_range_objects: d.block.block_range_objects.clone(),
            block_request_queues: d.block.block_request_queues.clone(),
            block_dma_buffers: d.block.block_dma_buffers.clone(),
            // scheduler domain
            harts: d.scheduler.harts.clone(),
            tasks: d.scheduler.tasks.clone(),
            runtime_activations: d.scheduler.runtime_activations.clone(),
            runnable_queues: d.scheduler.runnable_queues.clone(),
            scheduler_decisions: d.scheduler.scheduler_decisions.clone(),
            activation_contexts: d.scheduler.activation_contexts.clone(),
            activation_migrations: d.scheduler.activation_migrations.clone(),
            smp_safe_points: d.scheduler.smp_safe_points.clone(),
            stop_the_world_rendezvous: d.scheduler.stop_the_world_rendezvous.clone(),
            smp_code_publish_barriers: d.scheduler.smp_code_publish_barriers.clone(),
            saved_contexts: d.scheduler.saved_contexts.clone(),
            timer_interrupts: d.scheduler.timer_interrupts.clone(),
            remote_preempts: d.scheduler.remote_preempts.clone(),
            activation_cleanups: d.scheduler.activation_cleanups.clone(),
            smp_cleanup_quiescence: d.scheduler.smp_cleanup_quiescence.clone(),
            smp_snapshot_barriers: d.scheduler.smp_snapshot_barriers.clone(),
            smp_stress_runs: d.scheduler.smp_stress_runs.clone(),
            preemptions: d.scheduler.preemptions.clone(),
            activation_resumes: d.scheduler.activation_resumes.clone(),
            // lifecycle + wait domains
            stores: d.lifecycle.stores.clone(),
            waits: d.wait.waits.clone(),
            // executor-side records
            activations: inputs.activations.to_vec(),
            traps: inputs.traps.to_vec(),
            hostcalls: inputs.hostcalls.to_vec(),
            capabilities: {
                let mut caps = self.capabilities().records().to_vec();
                for cap in inputs.capabilities {
                    if !caps.iter().any(|existing| {
                        existing.id == cap.id && existing.generation == cap.generation
                    }) {
                        caps.push(cap.clone());
                    }
                }
                caps
            },
            cleanup_transactions: inputs.cleanup_transactions.to_vec(),
            tombstones: inputs.tombstones.to_vec(),
            external_objects: inputs.external_objects.to_vec(),
            explicit_edges: inputs.explicit_edges.to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_preserves_graph_own_capabilities() {
        let mut graph = SemanticGraph::new();
        graph.ensure_task(1, FrontendKind::Supervisor, "test");
        let store = graph.register_store("pkg", "art", "role", "restartable");
        graph
            .domains
            .capability
            .capabilities
            .grant_manifest_binding(
                "pkg",
                "test.console",
                &["write"],
                "activation",
                CapabilityClass::ServiceImport,
                Some(store),
                Some(1),
                None,
                "test",
            )
            .unwrap();

        let snapshot = graph.snapshot();
        assert!(
            !snapshot.capabilities.is_empty(),
            "snapshot must include graph-owned capability records"
        );
    }

    #[test]
    fn snapshot_with_merges_inputs_into_graph_capabilities() {
        let mut graph = SemanticGraph::new();
        graph.ensure_task(1, FrontendKind::Supervisor, "test");
        let store = graph.register_store("pkg", "art", "role", "restartable");
        graph
            .domains
            .capability
            .capabilities
            .grant_manifest_binding(
                "pkg",
                "g.obj",
                &["use"],
                "activation",
                CapabilityClass::ServiceImport,
                Some(store),
                Some(1),
                None,
                "test",
            )
            .unwrap();
        let graph_cap = graph.capabilities().records().first().cloned().unwrap();

        let mut extra = graph_cap.clone();
        extra.id = 99;
        extra.generation = 99;
        extra.object = "extra.obj".into();
        let inputs =
            ContractGraphSnapshotInputs { capabilities: &[extra.clone()], ..Default::default() };

        let snapshot = graph.snapshot_with(inputs);
        assert_eq!(snapshot.capabilities.len(), 2);
        assert!(snapshot.capabilities.contains(&graph_cap));
        assert!(snapshot.capabilities.contains(&extra));
    }

    #[test]
    fn snapshot_does_not_duplicate_capabilities_by_id_and_generation() {
        let mut graph = SemanticGraph::new();
        graph.ensure_task(1, FrontendKind::Supervisor, "test");
        let store = graph.register_store("pkg", "art", "role", "restartable");
        graph
            .domains
            .capability
            .capabilities
            .grant_manifest_binding(
                "pkg",
                "g.obj",
                &["use"],
                "activation",
                CapabilityClass::ServiceImport,
                Some(store),
                Some(1),
                None,
                "test",
            )
            .unwrap();
        let graph_cap = graph.capabilities().records().first().cloned().unwrap();

        let inputs = ContractGraphSnapshotInputs {
            capabilities: core::slice::from_ref(&graph_cap),
            ..Default::default()
        };

        let snapshot = graph.snapshot_with(inputs);
        assert_eq!(snapshot.capabilities.len(), 1);
    }
}
