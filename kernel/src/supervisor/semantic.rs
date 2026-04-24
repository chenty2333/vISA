use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use semantic_core::{
    ArtifactProfile, FailureEffect, FrontendKind, GenerationCheckError, GuestStateSnapshot,
    MigrationPackage, ResourceHandle, ResourceKind, SemanticGraph, SemanticWaitKind,
    SubstrateBoundarySnapshot, TaskState, WaitHandle,
};
use supervisor_catalog::{
    DMW_LAYOUT, MACHINE_ABI_VERSION, RUNTIME_ONLY_EXECUTOR_ABI, SUPERVISOR_ABI_VERSION,
    SUPERVISOR_ARTIFACT_FORMAT, SUPERVISOR_COMPILER_ENGINE, SUPERVISOR_EXECUTION_MODE,
    WASM_FEATURE_PROFILE,
};

use super::artifacts::ArtifactLoadPlan;
use super::authority::{AuthorityPlane, SubstrateAuthorityClass, SubstrateAuthoritySpec};
use super::events::Event;
use super::runtime::PrototypeRuntime;
use super::types::{FdResource, WaitKind, WaitRestartClass, WaitToken};

pub(super) fn bootstrap_graph(
    load_plan: &ArtifactLoadPlan,
    authority: &AuthorityPlane,
) -> Result<SemanticGraph, &'static str> {
    let mut graph = SemanticGraph::with_runtime_mode(load_plan.runtime_mode);
    graph.ensure_task(1, FrontendKind::Supervisor, "bootstrap");
    graph.set_task_state(1, TaskState::Running);

    for blueprint in load_plan.stores() {
        graph.register_store(
            blueprint.package,
            blueprint.artifact_name,
            blueprint.role,
            blueprint.fault_policy,
        );
        for capability in blueprint.capabilities {
            graph.grant_capability(
                blueprint.package,
                capability.name,
                capability.rights,
                capability.lifetime,
            );
        }
    }
    authority.bind_substrate_authority(
        &mut graph,
        SubstrateAuthoritySpec {
            class: SubstrateAuthorityClass::DmwWindow,
            subject: "linux_elf_frontend",
            object: "dmw.window",
            operations: &["acquire"],
            lifetime: "activation",
            label: "dmw:window-plane",
            owner_store: None,
        },
    )?;
    graph.grant_capability(
        "snapshot_manager",
        "snapshot.barrier",
        &["enter"],
        "activation",
    );
    graph.grant_capability(
        "fault_manager",
        "fault-domain.procfs_service",
        &["restart"],
        "fault-recovery",
    );
    graph.grant_capability(
        "fault_manager",
        "fault-domain.driver_virtio_net",
        &["restart"],
        "fault-recovery",
    );

    Ok(graph)
}

pub(super) fn fd_resource_kind(resource: &FdResource) -> ResourceKind {
    match resource {
        FdResource::ServiceNode { .. } => ResourceKind::Fd,
        FdResource::EpollInstance { .. } => ResourceKind::Epoll,
        FdResource::Socket { .. } => ResourceKind::NetSocket,
    }
}

pub(super) fn fd_resource_label(resource: &FdResource) -> String {
    match resource {
        FdResource::ServiceNode { path, .. } => {
            let path = core::str::from_utf8(path).unwrap_or("<non-utf8>");
            format!("fd:{path}")
        }
        FdResource::EpollInstance { epoll_id } => format!("epoll:{epoll_id}"),
        FdResource::Socket { socket_id, .. } => format!("socket:net:{socket_id}"),
    }
}

impl<'engine> PrototypeRuntime<'engine> {
    pub(crate) fn semantic_debug_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        lines.push(format!(
            "semantic graph: mode={} event_policy={} tasks={} resources={} authority={}/{} waits={} capabilities={} fault_domains={} events={}",
            self.semantic.runtime_mode().as_str(),
            self.semantic.runtime_mode().event_log_policy(),
            self.semantic.task_count(),
            self.semantic.resource_count(),
            self.semantic.active_authority_count(),
            self.semantic.authority_count(),
            self.semantic.wait_count(),
            self.semantic.capability_count(),
            self.semantic.fault_domain_count(),
            self.semantic.event_count()
        ));
        lines.push(format!(
            "store graph: stores={} live_resources={} transactions={} active_transactions={} fastpath={}/{}",
            self.semantic.store_count(),
            self.semantic.live_resource_count(),
            self.semantic.transaction_count(),
            self.semantic.active_transaction_count(),
            self.semantic.active_fast_path_plan_count(),
            self.semantic.fast_path_plan_count()
        ));
        let profile = self.artifacts.profile();
        lines.push(format!(
            "artifact registry: profile={} runtime_mode={} artifacts={} contract={} world={} engine={} mode={} format={} runtime_executor={} network={}",
            self.artifacts.artifact_profile(),
            self.artifacts.runtime_mode().as_str(),
            self.artifacts.artifacts().len(),
            profile.contract_version,
            profile.supervisor_world,
            profile.compiler_engine,
            profile.execution_mode,
            profile.artifact_format,
            profile.runtime_executor_abi,
            profile.network_contract
        ));
        lines.push(self.executor_plan.summary_line());
        lines.push(self.substrate_authority_line());
        lines.push(format!(
            "runtime stores: records={} first_role={} first_policy={} first_owner={} first_cleanup={} first_executor={} first_hostcalls={} first_manifest_source={} first_signature={}",
            self.store_manager.records().len(),
            self.store_manager
                .records()
                .first()
                .map(|record| record.role)
                .unwrap_or("none"),
            self.store_manager
                .records()
                .first()
                .map(|record| record.fault_policy)
                .unwrap_or("none"),
            self.store_manager
                .records()
                .first()
                .map(|record| record.capability_owner)
                .unwrap_or("none"),
            self.store_manager
                .records()
                .first()
                .map(|record| record.cleanup_policy)
                .unwrap_or("none"),
            self.store_manager
                .records()
                .first()
                .map(|record| record.executor_state.as_str())
                .unwrap_or("none"),
            self.store_manager
                .records()
                .first()
                .map(|record| record.executor_hostcalls.state.as_str())
                .unwrap_or("none"),
            self.store_manager
                .records()
                .first()
                .map(|record| record.manifest_binding.source)
                .unwrap_or("none"),
            self.store_manager
                .records()
                .first()
                .map(|record| record.manifest_binding.signature_profile)
                .unwrap_or("none")
        ));
        lines.push(self.capability_owner_line("driver_virtio_net"));
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

    pub(crate) fn validate_resource_handle(
        &mut self,
        handle: ResourceHandle,
    ) -> Result<(), GenerationCheckError> {
        self.semantic.validate_resource_handle(handle)
    }

    pub(crate) fn validate_wait_token(
        &mut self,
        token: WaitToken,
    ) -> Result<(), GenerationCheckError> {
        self.semantic
            .validate_wait_handle(WaitHandle::new(token.id, token.generation))
    }

    pub(crate) fn record_window_lease_created(
        &mut self,
        slot_index: usize,
        generation: u64,
        activation_id: u64,
        ptr: u64,
        len: usize,
        writable: bool,
    ) -> ResourceHandle {
        let label = format!(
            "dmw:slot={} activation={} ptr=0x{:x} len={} writable={}",
            slot_index, activation_id, ptr, len, writable
        );
        let resource = self.semantic.record_window_lease_created(
            Some(self.scheduler.current_task()),
            &label,
            generation,
        );
        self.semantic
            .resource_handle(resource)
            .expect("fresh DMW lease should have a semantic resource handle")
    }

    pub(crate) fn record_window_lease_destroyed(&mut self, lease: ResourceHandle, generation: u64) {
        self.semantic
            .record_window_lease_destroyed(lease.id, generation);
    }

    pub(crate) fn create_migration_package(&mut self) -> Result<MigrationPackage, &'static str> {
        self.require_capability("snapshot_manager", "snapshot.barrier", "enter")
            .map_err(|_| "snapshot barrier capability denied")?;
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
        if self.semantic.active_transaction_count() != 0 {
            self.semantic
                .record_failure_effect(FailureEffect::CompleteWithErrno(vmos_abi::ERR_EAGAIN));
            return Err("snapshot barrier observed active semantic transactions");
        }

        let pending_waits = u32::try_from(self.semantic.pending_wait_count())
            .map_err(|_| "pending wait count overflowed snapshot ABI")?;
        let active_transactions = u32::try_from(self.semantic.active_transaction_count())
            .map_err(|_| "active transaction count overflowed snapshot ABI")?;
        let _network_socket_count = self
            .net_core
            .socket_count()
            .map_err(|_| "net_core socket_count failed at snapshot barrier")?;
        let _linux_socket_count = self
            .linux_socket
            .socket_count()
            .map_err(|_| "linux_socket_service socket_count failed at snapshot barrier")?;
        let network_rx_queue_bytes = self
            .net_core
            .queued_rx_bytes()
            .map_err(|_| "net_core queued_rx_bytes failed at snapshot barrier")?;
        let pending_dma = 0;
        self.replay_snapshot
            .validate_barrier(
                pending_waits,
                active_transactions,
                active_dmw_leases,
                pending_dma,
            )
            .map_err(|_| "replay_snapshot rejected snapshot barrier")?;

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
                pending_network_inputs: u32::from(network_rx_queue_bytes > 0),
                random_epoch: 0,
                scheduler_decision_cursor: self.semantic.event_count() as u64,
                cow_epoch: 1,
                background_copy_pages: 0,
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
        machine_abi_version: MACHINE_ABI_VERSION.to_string(),
        supervisor_abi_version: SUPERVISOR_ABI_VERSION.to_string(),
        wasm_feature_profile: WASM_FEATURE_PROFILE.to_string(),
        memory64: false,
        multi_memory: false,
        dmw_layout: DMW_LAYOUT.to_string(),
        network_contract_version: service_core::net_contract::NETWORK_CONTRACT_VERSION.to_string(),
        compiler_engine: SUPERVISOR_COMPILER_ENGINE.to_string(),
        compiler_execution_mode: SUPERVISOR_EXECUTION_MODE.to_string(),
        artifact_format: SUPERVISOR_ARTIFACT_FORMAT.to_string(),
        runtime_executor_abi: RUNTIME_ONLY_EXECUTOR_ABI.to_string(),
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
