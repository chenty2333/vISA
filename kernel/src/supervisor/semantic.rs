use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use semantic_core::{
    ArtifactProfile, FailureEffect, FrontendKind, GuestStateSnapshot, MigrationPackage, ResourceId,
    ResourceKind, SemanticGraph, SemanticWaitKind, SubstrateBoundarySnapshot, TaskState,
};
use supervisor_catalog::SUPERVISOR_WASM_MODULES;

use super::events::Event;
use super::runtime::PrototypeRuntime;
use super::types::{FdResource, WaitKind, WaitRestartClass, WaitToken};

pub(super) fn bootstrap_graph() -> SemanticGraph {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(1, FrontendKind::Supervisor, "bootstrap");
    graph.set_task_state(1, TaskState::Running);

    for spec in SUPERVISOR_WASM_MODULES {
        graph.register_fault_domain(spec.package, spec.role.as_str());
        for capability in spec.capabilities {
            graph.grant_capability(
                spec.package,
                capability.name,
                capability.rights,
                capability.lifetime,
            );
        }
    }

    graph
}

pub(super) fn fd_resource_kind(resource: &FdResource) -> ResourceKind {
    match resource {
        FdResource::ServiceNode { .. } => ResourceKind::Fd,
        FdResource::EpollInstance { .. } => ResourceKind::Epoll,
    }
}

pub(super) fn fd_resource_label(resource: &FdResource) -> String {
    match resource {
        FdResource::ServiceNode { path, .. } => {
            let path = core::str::from_utf8(path).unwrap_or("<non-utf8>");
            format!("fd:{path}")
        }
        FdResource::EpollInstance { epoll_id } => format!("epoll:{epoll_id}"),
    }
}

impl<'engine> PrototypeRuntime<'engine> {
    pub(crate) fn semantic_debug_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        lines.push(format!(
            "semantic graph: tasks={} resources={} waits={} capabilities={} fault_domains={} events={}",
            self.semantic.task_count(),
            self.semantic.resource_count(),
            self.semantic.wait_count(),
            self.semantic.capability_count(),
            self.semantic.fault_domain_count(),
            self.semantic.event_count()
        ));
        lines.push("event log tail:".to_string());
        for event in self.semantic.event_log_tail(16) {
            lines.push(event.summary());
        }
        lines
    }

    pub(super) fn record_wait_token(&mut self, token: WaitToken) {
        self.semantic.record_wait_created(
            token.id,
            token.owner_task,
            semantic_wait_kind(token.kind),
            token.generation,
        );
    }

    pub(super) fn record_scheduler_event(&mut self, event: Event) {
        match event {
            Event::WaitReady(wait) => self.semantic.record_wait_resolved(wait, "ready"),
            Event::WaitCancelled(wait, errno) => self.semantic.record_wait_cancelled(wait, errno),
            Event::WaitRestart(wait, class) => self
                .semantic
                .record_wait_restarted(wait, wait_restart_class_name(class)),
        }
    }

    pub(crate) fn record_window_lease_created(
        &mut self,
        slot_index: usize,
        generation: u64,
        activation_id: u64,
        ptr: u64,
        len: usize,
        writable: bool,
    ) -> ResourceId {
        let label = format!(
            "dmw:slot={} activation={} ptr=0x{:x} len={} writable={}",
            slot_index, activation_id, ptr, len, writable
        );
        self.semantic.record_window_lease_created(
            Some(self.scheduler.current_task()),
            &label,
            generation,
        )
    }

    pub(crate) fn record_window_lease_destroyed(&mut self, lease: ResourceId, generation: u64) {
        self.semantic
            .record_window_lease_destroyed(lease, generation);
    }

    pub(crate) fn create_migration_package(&mut self) -> Result<MigrationPackage, &'static str> {
        let barrier = self.next_snapshot_barrier;
        self.next_snapshot_barrier += 1;
        self.semantic.record_snapshot_barrier_enter(barrier);

        let active_dmw_leases = crate::substrate::dmw::active_lease_count() as u32;
        if active_dmw_leases != 0 {
            self.semantic
                .record_failure_effect(FailureEffect::CompleteWithErrno(vmos_abi::ERR_EFAULT));
            return Err("snapshot barrier observed active DMW leases");
        }
        crate::substrate::dmw::assert_quiescent()?;

        self.semantic.record_snapshot_barrier_exit(barrier);
        let package = self.semantic.migration_package(
            "vmos-demo-migration-v0",
            host_arch(),
            "aarch64-demo-target",
            artifact_profile(),
            GuestStateSnapshot::riscv64_placeholder(),
            SubstrateBoundarySnapshot {
                timer_epoch: crate::interrupts::tick_count(),
                pending_irq_causes: 0,
                pending_dma_completions: 0,
                active_dmw_lease_count: active_dmw_leases,
                native_state_policy:
                    "rebuild page tables, DMW slots, IRQ registrations, stores, and code cache on target"
                        .to_string(),
            },
            barrier,
            true,
        );
        package
            .validate_portability()
            .map_err(|_| "migration package failed portability validation")?;
        Ok(package)
    }
}

fn semantic_wait_kind(kind: WaitKind) -> SemanticWaitKind {
    match kind {
        WaitKind::Timer => SemanticWaitKind::Timer,
        WaitKind::Futex => SemanticWaitKind::Futex,
        WaitKind::Epoll => SemanticWaitKind::Epoll,
    }
}

fn wait_restart_class_name(class: WaitRestartClass) -> &'static str {
    match class {
        WaitRestartClass::DriverRestart => "driver-restart",
    }
}

fn artifact_profile() -> ArtifactProfile {
    ArtifactProfile {
        artifact_profile: "target-native-runtime".to_string(),
        target_arch: "target-native".to_string(),
        machine_abi_version: "vmos-machine-abi-v0".to_string(),
        supervisor_abi_version: "vmos-supervisor-abi-v0".to_string(),
        wasm_feature_profile: "wasm32-core-mvp-single-memory".to_string(),
        memory64: false,
        multi_memory: false,
        dmw_layout: "logical-activation-leases-v0".to_string(),
        compiler_engine: "wasmtime".to_string(),
        compiler_execution_mode: "precompiled-core-module".to_string(),
        artifact_format: "cwasm".to_string(),
    }
}

fn host_arch() -> &'static str {
    if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else if cfg!(target_arch = "riscv64") {
        "riscv64"
    } else {
        "unknown"
    }
}
