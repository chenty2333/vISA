use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use semantic_core::{
    ArtifactProfile, CapabilityDenyReason, FailureEffect, FrontendKind, GenerationCheckError,
    GuestStateSnapshot, HostcallClass, MigrationPackage, ResourceHandle, ResourceKind,
    SemanticGraph, SemanticWaitKind, StoreId, StoreState, SubstrateBoundarySnapshot, TaskState,
    WaitHandle,
};
use supervisor_catalog::SUPERVISOR_WASM_MODULES;
use vmos_abi::PlanKind;

use super::events::Event;
use super::runtime::PrototypeRuntime;
use super::types::{FdResource, WaitKind, WaitRestartClass, WaitToken};

pub(super) fn bootstrap_graph() -> SemanticGraph {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(1, FrontendKind::Supervisor, "bootstrap");
    graph.set_task_state(1, TaskState::Running);

    for spec in SUPERVISOR_WASM_MODULES {
        let store = graph.register_store(
            spec.package,
            spec.artifact_name,
            spec.role.as_str(),
            spec.fault_policy.as_str(),
        );
        graph.set_store_state(store, StoreState::Instantiating);
        graph.set_store_state(store, StoreState::Running);
        for capability in spec.capabilities {
            graph.grant_capability(
                spec.package,
                capability.name,
                capability.rights,
                capability.lifetime,
            );
        }
    }
    graph.grant_capability(
        "linux_elf_frontend",
        "dmw.window",
        &["acquire"],
        "activation",
    );
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
        lines.push(format!(
            "store graph: stores={} live_resources={}",
            self.semantic.store_count(),
            self.semantic.live_resource_count()
        ));
        lines.push("event log tail:".to_string());
        for event in self.semantic.event_log_tail(16) {
            lines.push(event.summary());
        }
        lines
    }

    pub(crate) fn store_lifecycle_line(&self, package: &str) -> Option<String> {
        let store = self
            .semantic
            .stores()
            .iter()
            .find(|store| store.package == package)?;
        Some(format!(
            "store {} state={} generation={} restarts={} resource={}",
            store.package,
            store.state.as_str(),
            store.generation,
            store.restart_count,
            store
                .resource
                .map(|resource| resource.to_string())
                .unwrap_or_else(|| "none".to_string())
        ))
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

    pub(super) fn record_hostcall_plan(&mut self, label: &str, kind: PlanKind) {
        let (class, subject, object, operation) = hostcall_metadata(kind);
        self.semantic
            .record_hostcall(label, class, subject, object, operation);
    }

    pub(crate) fn require_capability(
        &mut self,
        subject: &str,
        object: &str,
        operation: &str,
    ) -> Result<(), CapabilityDenyReason> {
        self.semantic
            .check_capability(subject, object, operation)
            .map(|_| ())
    }

    pub(crate) fn require_capability_generation(
        &mut self,
        subject: &str,
        object: &str,
        operation: &str,
        expected_generation: u64,
    ) -> Result<(), CapabilityDenyReason> {
        self.semantic
            .check_capability_generation(subject, object, operation, expected_generation)
            .map(|_| ())
    }

    pub(crate) fn capability_generation(&self, subject: &str, object: &str) -> Option<u64> {
        self.semantic.capability_generation(subject, object)
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

    pub(crate) fn store_id(&self, package: &str) -> Option<StoreId> {
        self.semantic.store_id(package)
    }

    pub(crate) fn record_store_trap(&mut self, store: StoreId, trap: &str) {
        self.semantic.record_store_trap(store, trap);
    }

    pub(crate) fn set_store_state(&mut self, store: StoreId, state: StoreState) {
        self.semantic.set_store_state(store, state);
    }

    pub(crate) fn drop_store_instance(&mut self, store: StoreId) {
        self.semantic.drop_store_instance(store);
    }

    pub(crate) fn rebind_store_instance(&mut self, store: StoreId) -> Result<(), &'static str> {
        self.semantic
            .rebind_store_instance(store)
            .map(|_| ())
            .ok_or("store to rebind was not present")
    }

    pub(crate) fn revoke_capability_for_demo(
        &mut self,
        subject: &str,
        object: &str,
    ) -> Result<(), &'static str> {
        self.semantic
            .revoke_capability_by_subject_object(subject, object)
            .map(|_| ())
            .ok_or("capability to revoke was not present")
    }

    pub(crate) fn grant_capability_for_demo(
        &mut self,
        subject: &str,
        object: &str,
        operations: &[&str],
        lifetime: &str,
    ) {
        self.semantic
            .grant_capability(subject, object, operations, lifetime);
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

fn hostcall_metadata(kind: PlanKind) -> (HostcallClass, &'static str, &'static str, &'static str) {
    match kind {
        PlanKind::GetCwd | PlanKind::Uname => (
            HostcallClass::PureQuery,
            "linux_syscall",
            "process.metadata",
            "query",
        ),
        PlanKind::Write => (
            HostcallClass::ImmediatePrivilegedOp,
            "linux_syscall",
            "console.write",
            "write",
        ),
        PlanKind::OpenAt => (
            HostcallClass::ImmediatePrivilegedOp,
            "vfs_service",
            "vfs.namespace",
            "lookup",
        ),
        PlanKind::Read => (
            HostcallClass::ImmediatePrivilegedOp,
            "vfs_service",
            "vfs.namespace",
            "read",
        ),
        PlanKind::Close => (
            HostcallClass::ImmediatePrivilegedOp,
            "linux_syscall",
            "fd.table",
            "close",
        ),
        PlanKind::GetDents64 => (
            HostcallClass::ImmediatePrivilegedOp,
            "vfs_service",
            "vfs.namespace",
            "list",
        ),
        PlanKind::ReadLinkAt => (
            HostcallClass::ImmediatePrivilegedOp,
            "vfs_service",
            "vfs.namespace",
            "readlink",
        ),
        PlanKind::Sleep => (
            HostcallClass::AsyncOp,
            "linux_syscall",
            "timer.sleep",
            "arm",
        ),
        PlanKind::FutexWait => (
            HostcallClass::AsyncOp,
            "futex_service",
            "futex.waitset",
            "wait",
        ),
        PlanKind::FutexWake => (
            HostcallClass::ImmediatePrivilegedOp,
            "futex_service",
            "futex.waitset",
            "wake",
        ),
        PlanKind::EpollCreate1 => (
            HostcallClass::ImmediatePrivilegedOp,
            "epoll_service",
            "epoll.instance",
            "create",
        ),
        PlanKind::EpollCtl => (
            HostcallClass::ImmediatePrivilegedOp,
            "epoll_service",
            "epoll.instance",
            "ctl",
        ),
        PlanKind::EpollWait | PlanKind::EpollReady => (
            HostcallClass::AsyncOp,
            "epoll_service",
            "epoll.instance",
            "wait",
        ),
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
