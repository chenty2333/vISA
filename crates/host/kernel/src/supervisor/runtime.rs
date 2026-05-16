use alloc::{boxed::Box, collections::BTreeMap, vec, vec::Vec};
use core::ptr::null_mut;

use net_stack_adapter::{SmoltcpAdapterConfig, SmoltcpPacketStack};
use semantic_core::{FrontendKind, GuestMemoryManager, ResourceHandle, SemanticGraph, TaskState};
use service_core::seccomp::{
    AUDIT_ARCH_X86_64, SeccompData, SeccompDecision, SeccompFilterChain, SeccompFilterProgram,
};
use vmos_abi::{SYS_EXIT, SYS_EXIT_GROUP, SYS_READ, SYS_RT_SIGRETURN, SYS_WRITE};

use super::{
    artifacts::ArtifactRegistry,
    authority::AuthorityPlane,
    engine::RuntimeOnlyExecutor,
    events::Event,
    guest_memory::GuestMemoryProjection,
    linux::LinuxFrontend,
    net::{NetStackSocketBinding, NetworkPlane},
    pulse::PulseDevice,
    scheduler::Scheduler,
    semantic::bootstrap_graph,
    services::{
        ConsoleService, DevfsService, DriverVirtioNetService, EpollService, FutexService,
        LinuxSocketService, NetCoreService, ProcfsService, ReplaySnapshotService, VfsService,
        WasmApp,
    },
    store_manager::StoreManager,
    types::{
        EventFdState, FdEntry, InjectedFault, Pid, PipeState, ProcessRuntimeState,
        ProcessRuntimeStateKind, RLIMIT_NOFILE, Rlimit, RuntimeClockAdjustmentState, SeccompMode,
        ServiceCallError, SigAction, SocketPairState, TaskId, ThreadRuntimeState,
        ThreadRuntimeStateKind, Tid,
    },
    wait::WaitRegistry,
};
use crate::interrupts;

static mut ACTIVE_RUNTIME: *mut PrototypeRuntime<'static> = null_mut();

fn default_process_rlimits() -> [Rlimit; 16] {
    let mut limits = [Rlimit::default(); 16];
    limits[RLIMIT_NOFILE] = Rlimit { cur: 1024, max: 1024 };
    limits
}

pub(crate) fn runtime() -> Result<&'static mut PrototypeRuntime<'static>, &'static str> {
    unsafe {
        if ACTIVE_RUNTIME.is_null() {
            let engine = Box::leak(Box::new(RuntimeOnlyExecutor::default()));
            crate::kdebug!("runtime-only supervisor executor ready");
            let runtime = Box::leak(Box::new(PrototypeRuntime::new(engine)?));
            crate::kdebug!("prototype2 runtime ready");
            ACTIVE_RUNTIME = runtime as *mut _;
        }

        Ok(&mut *ACTIVE_RUNTIME)
    }
}

pub(crate) struct PrototypeRuntime<'engine> {
    pub(super) artifacts: ArtifactRegistry,
    pub(super) authority: AuthorityPlane,
    pub(super) console: ConsoleService,
    pub(super) vfs: VfsService,
    pub(super) engine: &'engine RuntimeOnlyExecutor,
    pub(super) executor_plan: super::engine::ExecutorLoadPlan,
    pub(super) procfs: Option<ProcfsService>,
    pub(super) devfs: DevfsService,
    pub(super) epoll: EpollService,
    pub(super) futex: FutexService,
    pub(super) net_core: NetCoreService,
    pub(super) linux_socket: LinuxSocketService,
    pub(super) net_stack: SmoltcpPacketStack,
    pub(super) net_stack_sockets: Vec<NetStackSocketBinding>,
    pub(super) net_driver: DriverVirtioNetService,
    pub(super) replay_snapshot: ReplaySnapshotService,
    pub(super) linux: LinuxFrontend,
    pub(super) app: WasmApp,
    pub(crate) processes: Vec<ProcessRuntimeState>,
    pub(crate) threads: Vec<ThreadRuntimeState>,
    pub(super) next_pid: Pid,
    pub(super) next_tid: Tid,
    pub(super) fd_table: Vec<Option<FdEntry>>,
    pub(super) fd_handles: Vec<Option<ResourceHandle>>,
    pub(super) hidden_fd_table_refs: Vec<Vec<Option<FdEntry>>>,
    pub(super) pipes: Vec<PipeState>,
    pub(super) next_pipe_id: u64,
    pub(super) socketpairs: Vec<SocketPairState>,
    pub(super) next_socketpair_id: u64,
    pub(super) eventfds: Vec<EventFdState>,
    pub(super) next_eventfd_id: u64,
    pub(super) fault: Option<InjectedFault>,
    pub(super) scheduler: Scheduler,
    pub(super) futex_pi_boosts: BTreeMap<TaskId, BTreeMap<u64, u32>>,
    pub(super) waits: WaitRegistry,
    pub(super) pulse: PulseDevice,
    pub(super) net: NetworkPlane,
    pub(super) store_manager: StoreManager,
    pub(super) guest_memory: GuestMemoryProjection,
    pub(super) restart_count: u64,
    pub(super) semantic: SemanticGraph,
    pub(super) next_snapshot_barrier: u64,
    pub(super) realtime_epoch_ns: u64,
    pub(super) realtime_epoch_tick: u64,
    pub(super) clock_adj: RuntimeClockAdjustmentState,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct FutexPiHandoff {
    pub(crate) wait_id: u64,
    pub(crate) next_owner_task: TaskId,
    pub(crate) next_owner_tid: Tid,
    pub(crate) remaining_waiter_priority: u32,
    pub(crate) has_more_waiters: bool,
}

impl<'engine> PrototypeRuntime<'engine> {
    pub(super) fn new(engine: &'engine RuntimeOnlyExecutor) -> Result<Self, &'static str> {
        crate::kdebug!("validating supervisor artifact registry");
        let artifacts =
            ArtifactRegistry::from_embedded_manifest_plan().map_err(|err| err.message())?;
        let load_plan = artifacts.load_plan();
        let executor_plan = engine.prepare_load_plan(&load_plan).map_err(|err| err.message())?;
        let plan_profile = load_plan.profile;
        crate::kdebug!(
            "artifact load plan profile={} runtime_mode={} engine={} mode={} runtime={}",
            load_plan.artifact_profile,
            load_plan.runtime_mode.as_str(),
            plan_profile.compiler_engine,
            plan_profile.execution_mode,
            plan_profile.runtime_executor_abi
        );
        crate::kdebug!("{}", executor_plan.summary_line());
        let authority = AuthorityPlane::new();
        crate::kdebug!("bootstrapping semantic graph");
        let mut semantic = bootstrap_graph(&load_plan, &authority)?;
        super::boundary::publish_boot_boundaries(&mut semantic, &load_plan, &executor_plan);
        let store_manager =
            StoreManager::from_load_plan(&load_plan, &executor_plan, &mut semantic)?;
        crate::kdebug!("bootstrapping network plane");
        let net = NetworkPlane::new(&authority, &mut semantic)?;
        crate::kdebug!("instantiating console_service");
        let console = ConsoleService::new(engine)?;
        crate::kdebug!("instantiating vfs_service");
        let vfs = VfsService::new(engine)?;
        crate::kdebug!("instantiating procfs_service");
        let procfs = ProcfsService::new(engine)?;
        crate::kdebug!("instantiating devfs_service");
        let devfs = DevfsService::new(engine)?;
        crate::kdebug!("instantiating epoll_service");
        let epoll = EpollService::new(engine)?;
        crate::kdebug!("instantiating futex_service");
        let futex = FutexService::new(engine)?;
        crate::kdebug!("instantiating net_core");
        let net_core = NetCoreService::new(engine)?;
        crate::kdebug!("instantiating linux_socket_service");
        let linux_socket = LinuxSocketService::new(engine)?;
        crate::kdebug!("instantiating smoltcp packet stack");
        let net_stack = SmoltcpPacketStack::new(SmoltcpAdapterConfig::default_vmos())?;
        crate::kdebug!("instantiating driver_virtio_net");
        let net_driver = DriverVirtioNetService::new(engine)?;
        crate::kdebug!("instantiating replay_snapshot");
        let replay_snapshot = ReplaySnapshotService::new(engine)?;
        crate::kdebug!("instantiating linux_syscall");
        let linux = LinuxFrontend::new(engine)?;
        crate::kdebug!("instantiating wasm_app");
        let app = WasmApp::new(engine)?;
        let guest_memory_store = store_manager
            .records()
            .first()
            .ok_or("store manager was empty while bootstrapping guest memory projection")?
            .store;
        let guest_memory_owner = semantic
            .stores()
            .iter()
            .find(|store| store.id == guest_memory_store)
            .ok_or("semantic store was missing while bootstrapping guest memory projection")?
            .object_ref();
        crate::kdebug!("bootstrapping guest memory projection");
        let mut guest_memory_manager = GuestMemoryManager::new();
        let guest_memory_aspace = guest_memory_manager.create_address_space(guest_memory_owner);
        let guest_memory = GuestMemoryProjection::new(guest_memory_manager, guest_memory_aspace);
        Ok(Self {
            artifacts,
            authority,
            console,
            vfs,
            engine,
            executor_plan,
            procfs: Some(procfs),
            devfs,
            epoll,
            futex,
            net_core,
            linux_socket,
            net_stack,
            net_stack_sockets: Vec::new(),
            net_driver,
            replay_snapshot,
            linux,
            app,
            processes: {
                let mut procs = Vec::new();
                // Bootstrap init process (pid=1)
                procs.push(ProcessRuntimeState {
                    pid: 1,
                    ppid: 0,
                    pgid: 1,
                    sid: 1,
                    tgid: 1,
                    exit_signal: None,
                    state: ProcessRuntimeStateKind::Running,
                    exit_code: None,
                    sigactions: [SigAction::default(); 64],
                    rlimits: default_process_rlimits(),
                });
                procs
            },
            threads: {
                let mut thrds = Vec::new();
                // Bootstrap thread (tid=1, task_id=1) for init process
                thrds.push(ThreadRuntimeState {
                    tid: 1,
                    task_id: 1,
                    pid: 1,
                    state: ThreadRuntimeStateKind::Running,
                    clear_child_tid: None,
                    robust_list: None,
                    sigaltstack: Default::default(),
                    sigmask: 0,
                    sigsuspend_restore_mask: None,
                    pending_signals: Vec::new(),
                    seccomp: SeccompMode::Disabled,
                    no_new_privs: false,
                });
                thrds
            },
            next_pid: 2,
            next_tid: 2,
            fd_table: vec![None, None, None],
            fd_handles: vec![None, None, None],
            hidden_fd_table_refs: Vec::new(),
            pipes: Vec::new(),
            next_pipe_id: 1,
            socketpairs: Vec::new(),
            next_socketpair_id: 1,
            eventfds: Vec::new(),
            next_eventfd_id: 1,
            fault: None,
            scheduler: Scheduler::new(),
            futex_pi_boosts: BTreeMap::new(),
            waits: WaitRegistry::new(),
            pulse: PulseDevice::new(interrupts::tick_count()),
            net,
            store_manager,
            guest_memory,
            restart_count: 0,
            semantic,
            next_snapshot_barrier: 1,
            realtime_epoch_ns: 1_000_000_000,
            realtime_epoch_tick: interrupts::tick_count(),
            clock_adj: RuntimeClockAdjustmentState::default(),
        })
    }

    pub(crate) fn allocate_task(&mut self) -> TaskId {
        let task = self.scheduler.allocate_task();
        self.semantic.ensure_task(task, FrontendKind::LinuxElf, "linux-elf-task");
        task
    }

    /// Allocate a new process (fork-style). Returns the new PID.
    pub(crate) fn allocate_process(&mut self, ppid: Pid, pgid: Pid, sid: Pid) -> Pid {
        let pid = self.next_pid;
        self.next_pid = pid.wrapping_add(1);
        self.processes.push(ProcessRuntimeState {
            pid,
            ppid,
            pgid,
            sid,
            tgid: pid as Tid,
            exit_signal: None,
            state: ProcessRuntimeStateKind::Running,
            exit_code: None,
            sigactions: [SigAction::default(); 64],
            rlimits: default_process_rlimits(),
        });
        pid
    }

    /// Allocate a new thread within a process. Returns the new TID.
    pub(crate) fn allocate_thread(&mut self, task_id: TaskId, pid: Pid) -> Tid {
        let tid = self.next_tid;
        self.next_tid = tid.wrapping_add(1);
        self.threads.push(ThreadRuntimeState {
            tid,
            task_id,
            pid,
            state: ThreadRuntimeStateKind::Running,
            clear_child_tid: None,
            robust_list: None,
            sigaltstack: Default::default(),
            sigmask: 0,
            sigsuspend_restore_mask: None,
            pending_signals: Vec::new(),
            seccomp: SeccompMode::Disabled,
            no_new_privs: false,
        });
        tid
    }

    pub(crate) fn query_thread(&self, tid: Tid) -> Option<&ThreadRuntimeState> {
        self.threads.iter().find(|t| t.tid == tid)
    }

    pub(crate) fn query_process(&self, pid: Pid) -> Option<&ProcessRuntimeState> {
        self.processes.iter().find(|p| p.pid == pid)
    }

    pub(crate) fn current_pid(&self) -> Pid {
        let task_id = self.scheduler.current_task();
        self.threads.iter().find(|t| t.task_id == task_id).map(|t| t.pid).unwrap_or(1)
    }

    pub(crate) fn current_tid(&self) -> Tid {
        let task_id = self.scheduler.current_task();
        self.threads.iter().find(|t| t.task_id == task_id).map(|t| t.tid).unwrap_or(1)
    }

    pub(crate) fn current_task_id(&self) -> TaskId {
        self.scheduler.current_task()
    }

    pub(crate) fn current_task_priority(&self) -> u32 {
        self.scheduler.task_priority(self.scheduler.current_task())
    }

    pub(crate) fn task_priority(&self, task: TaskId) -> u32 {
        self.scheduler.task_priority(task)
    }

    pub(crate) fn task_id_for_tid(&self, tid: Tid) -> Option<TaskId> {
        self.threads.iter().find(|thread| thread.tid == tid).map(|thread| thread.task_id)
    }

    pub(crate) fn tid_for_task_id(&self, task: TaskId) -> Option<Tid> {
        self.threads.iter().find(|thread| thread.task_id == task).map(|thread| thread.tid)
    }

    pub(crate) fn boost_task_priority(&mut self, task: TaskId, priority: u32) -> bool {
        self.scheduler.boost_priority(task, priority)
    }

    pub(crate) fn restore_task_priority(&mut self, task: TaskId) -> bool {
        self.scheduler.restore_priority(task)
    }

    pub(crate) fn register_futex_pi_boost(
        &mut self,
        owner_task: TaskId,
        futex_key: u64,
        priority: u32,
    ) -> bool {
        let owner_boosts = self.futex_pi_boosts.entry(owner_task).or_default();
        let entry = owner_boosts.entry(futex_key).or_insert(0);
        if priority > *entry {
            *entry = priority;
        }
        self.apply_futex_pi_boost(owner_task)
    }

    pub(crate) fn release_futex_pi_boost(&mut self, owner_task: TaskId, futex_key: u64) -> bool {
        let remove_owner = if let Some(owner_boosts) = self.futex_pi_boosts.get_mut(&owner_task) {
            owner_boosts.remove(&futex_key);
            owner_boosts.is_empty()
        } else {
            false
        };
        if remove_owner {
            self.futex_pi_boosts.remove(&owner_task);
        }
        self.apply_futex_pi_boost(owner_task)
    }

    pub(crate) fn refresh_futex_pi_boost(&mut self, owner_task: TaskId, futex_key: u64) -> bool {
        let priority = match self.futex.max_priority(futex_key) {
            Ok(priority) => priority,
            Err(err) => {
                crate::kwarn!(
                    "futex pi max_priority query failed for key {}: {:?}",
                    futex_key,
                    err
                );
                0
            }
        };
        let remove_owner = if let Some(owner_boosts) = self.futex_pi_boosts.get_mut(&owner_task) {
            if priority == 0 {
                owner_boosts.remove(&futex_key);
            } else {
                owner_boosts.insert(futex_key, priority);
            }
            owner_boosts.is_empty()
        } else {
            false
        };
        if remove_owner {
            self.futex_pi_boosts.remove(&owner_task);
        }
        self.apply_futex_pi_boost(owner_task)
    }

    pub(crate) fn adopt_futex_pi_after_wait(
        &mut self,
        futex_key: u64,
        old_owner_task: Option<TaskId>,
    ) {
        if let Some(old_owner_task) = old_owner_task {
            self.release_futex_pi_boost(old_owner_task, futex_key);
        }
        let new_owner_task = self.scheduler.current_task();
        let remaining_priority = match self.futex.max_priority(futex_key) {
            Ok(priority) => priority,
            Err(err) => {
                crate::kwarn!(
                    "futex pi remaining priority query failed for key {}: {:?}",
                    futex_key,
                    err
                );
                0
            }
        };
        if remaining_priority > 0 {
            self.register_futex_pi_boost(new_owner_task, futex_key, remaining_priority);
        } else {
            self.release_futex_pi_boost(new_owner_task, futex_key);
        }
    }

    pub(crate) fn release_all_futex_pi_boosts_for_task(&mut self, task: TaskId) -> bool {
        let had_boosts = self.futex_pi_boosts.remove(&task).is_some();
        self.scheduler.restore_priority(task) || had_boosts
    }

    pub(crate) fn prepare_futex_pi_handoff(
        &mut self,
        futex_key: u64,
    ) -> Result<Option<FutexPiHandoff>, ServiceCallError> {
        let Some(wait_id) = self.futex.peek_waiter(futex_key)? else {
            return Ok(None);
        };
        let Some(next_owner_task) = self.waits.owner_task_for_wait_id(wait_id) else {
            return Err(ServiceCallError::Invalid("futex pi waiter has no pending wait token"));
        };
        let Some(next_owner_tid) = self.tid_for_task_id(next_owner_task) else {
            return Err(ServiceCallError::Invalid("futex pi waiter has no runtime thread"));
        };
        let waiter_count = self.futex.waiter_count(futex_key)?;
        let remaining_waiter_priority = self.futex.max_priority_excluding(futex_key, wait_id)?;
        Ok(Some(FutexPiHandoff {
            wait_id,
            next_owner_task,
            next_owner_tid,
            remaining_waiter_priority,
            has_more_waiters: waiter_count > 1,
        }))
    }

    pub(crate) fn requeue_futex_pi_waiters(
        &mut self,
        src_key: u64,
        dst_key: u64,
        count: u32,
    ) -> Result<u32, ServiceCallError> {
        self.futex.requeue_pi(src_key, count, dst_key)
    }

    pub(crate) fn complete_futex_pi_handoff(
        &mut self,
        futex_key: u64,
        old_owner_task: TaskId,
        handoff: FutexPiHandoff,
    ) -> Result<(), ServiceCallError> {
        let wait_ids = self.futex.wake(futex_key, 1)?;
        if wait_ids.as_slice() != [handoff.wait_id] {
            return Err(ServiceCallError::Invalid("futex pi handoff woke a different waiter"));
        }
        self.scheduler.push_event(Event::WaitReady(handoff.wait_id));
        self.release_futex_pi_boost(old_owner_task, futex_key);
        if handoff.remaining_waiter_priority > 0 {
            self.register_futex_pi_boost(
                handoff.next_owner_task,
                futex_key,
                handoff.remaining_waiter_priority,
            );
        } else {
            self.release_futex_pi_boost(handoff.next_owner_task, futex_key);
        }
        self.drain_event_queue();
        Ok(())
    }

    pub(crate) fn complete_futex_pi_ownerless_handoff(
        &mut self,
        futex_key: u64,
        handoff: FutexPiHandoff,
    ) -> Result<(), ServiceCallError> {
        let wait_ids = self.futex.wake(futex_key, 1)?;
        if wait_ids.as_slice() != [handoff.wait_id] {
            return Err(ServiceCallError::Invalid("futex pi handoff woke a different waiter"));
        }
        self.scheduler.push_event(Event::WaitReady(handoff.wait_id));
        if handoff.remaining_waiter_priority > 0 {
            self.register_futex_pi_boost(
                handoff.next_owner_task,
                futex_key,
                handoff.remaining_waiter_priority,
            );
        } else {
            self.release_futex_pi_boost(handoff.next_owner_task, futex_key);
        }
        self.drain_event_queue();
        Ok(())
    }

    fn apply_futex_pi_boost(&mut self, owner_task: TaskId) -> bool {
        let priority = self
            .futex_pi_boosts
            .get(&owner_task)
            .and_then(|entries| entries.values().copied().max())
            .unwrap_or(0);
        if priority == 0 {
            self.scheduler.restore_priority(owner_task)
        } else {
            self.scheduler.boost_priority(owner_task, priority)
        }
    }

    pub(crate) fn get_rlimit(&self, pid: Pid, resource: usize) -> Rlimit {
        self.processes
            .iter()
            .find(|p| p.pid == pid)
            .and_then(|p| p.rlimits.get(resource).copied())
            .unwrap_or_default()
    }

    pub(crate) fn set_rlimit(&mut self, pid: Pid, resource: usize, rlim: Rlimit) -> bool {
        if let Some(proc) = self.processes.iter_mut().find(|p| p.pid == pid) {
            if resource < 16 {
                proc.rlimits[resource] = rlim;
                return true;
            }
        }
        false
    }

    pub(crate) fn set_seccomp_strict(&mut self, tid: Tid) -> Result<(), i32> {
        let Some(thread) = self.threads.iter_mut().find(|thread| thread.tid == tid) else {
            return Err(vmos_abi::ERR_ESRCH);
        };
        match thread.seccomp {
            SeccompMode::Disabled | SeccompMode::Strict => {
                thread.seccomp = SeccompMode::Strict;
                Ok(())
            }
            SeccompMode::Filter(_) => Err(vmos_abi::ERR_EINVAL),
        }
    }

    pub(crate) fn set_seccomp_filter(
        &mut self,
        tid: Tid,
        program: SeccompFilterProgram,
        privileged: bool,
    ) -> Result<(), i32> {
        let Some(thread) = self.threads.iter_mut().find(|thread| thread.tid == tid) else {
            return Err(vmos_abi::ERR_ESRCH);
        };
        if !thread.no_new_privs && !privileged {
            return Err(vmos_abi::ERR_EACCES);
        }
        match &mut thread.seccomp {
            SeccompMode::Disabled => {}
            SeccompMode::Filter(chain) => {
                chain.push(program);
                return Ok(());
            }
            SeccompMode::Strict => return Err(vmos_abi::ERR_EINVAL),
        }
        thread.seccomp = SeccompMode::Filter(SeccompFilterChain::new(program));
        Ok(())
    }

    pub(crate) fn set_no_new_privs(&mut self, tid: Tid, enabled: bool) -> bool {
        if !enabled {
            return false;
        }
        if let Some(thread) = self.threads.iter_mut().find(|thread| thread.tid == tid) {
            thread.no_new_privs = true;
            return true;
        }
        false
    }

    pub(crate) fn no_new_privs(&self, tid: Tid) -> bool {
        self.threads
            .iter()
            .find(|thread| thread.tid == tid)
            .map(|thread| thread.no_new_privs)
            .unwrap_or(false)
    }

    pub(crate) fn seccomp_mode(&self, tid: Tid) -> Option<u64> {
        self.threads.iter().find(|thread| thread.tid == tid).map(|thread| match thread.seccomp {
            SeccompMode::Disabled => 0,
            SeccompMode::Strict => 1,
            SeccompMode::Filter(_) => 2,
        })
    }

    pub(crate) fn check_seccomp_syscall(
        &self,
        tid: Tid,
        syscall: u64,
        instruction_pointer: u64,
        args: [u64; 6],
    ) -> SeccompDecision {
        match self.threads.iter().find(|thread| thread.tid == tid).map(|thread| &thread.seccomp) {
            None | Some(SeccompMode::Disabled) => SeccompDecision::Allow,
            Some(SeccompMode::Strict) => {
                if matches!(
                    syscall,
                    SYS_READ | SYS_WRITE | SYS_EXIT | SYS_EXIT_GROUP | SYS_RT_SIGRETURN
                ) {
                    SeccompDecision::Allow
                } else {
                    SeccompDecision::Kill { signal: 9 }
                }
            }
            Some(SeccompMode::Filter(program)) => {
                let syscall_nr = syscall.min(u32::MAX as u64) as u32;
                match program.evaluate(SeccompData {
                    nr: syscall_nr,
                    arch: AUDIT_ARCH_X86_64,
                    instruction_pointer,
                    args,
                }) {
                    Ok(decision) => decision,
                    Err(_) => SeccompDecision::Kill { signal: 31 },
                }
            }
        }
    }

    pub(crate) fn set_current_task(&mut self, task: TaskId) {
        self.scheduler.set_current_task(task);
        let should_mark_running = match self.threads.iter().find(|thread| thread.task_id == task) {
            Some(thread) => thread.state == ThreadRuntimeStateKind::Running,
            None => true,
        };
        if should_mark_running {
            self.semantic.set_task_state(task, TaskState::Running);
        }
    }

    pub(crate) fn record_guest_memory_region(
        &mut self,
        start: u64,
        len: u64,
        readable: bool,
        writable: bool,
        executable: bool,
    ) {
        self.guest_memory.record_region(start, len, readable, writable, executable);
    }

    pub(crate) fn record_guest_memory_unmap(&mut self, start: u64, len: u64) {
        self.guest_memory.remove_region(start, len);
    }

    pub(crate) fn record_guest_memory_cow_break(&mut self, page_addr: u64) {
        self.guest_memory.record_cow_break(page_addr);
    }

    pub(crate) fn bootstrap_task(&self) -> TaskId {
        self.scheduler.bootstrap_task()
    }

    pub(crate) fn bind_bootstrap_linux_task(&mut self) -> TaskId {
        let task = self.scheduler.bootstrap_task();
        self.semantic.ensure_task(task, FrontendKind::LinuxElf, "linux-elf-init");
        self.set_current_task(task);
        task
    }

    pub(crate) fn runtime_realtime_now_ns(&self, tick_count: u64, timer_hz: u64) -> u64 {
        let elapsed_ticks = tick_count.saturating_sub(self.realtime_epoch_tick);
        let elapsed_ns = elapsed_ticks.saturating_mul(1_000_000_000) / timer_hz.max(1);
        let correction = (elapsed_ns as i128)
            .saturating_mul(self.clock_adj.freq_scaled_ppm as i128)
            / 65_536
            / 1_000_000;
        let adjusted_elapsed = elapsed_ns as i128 + correction;
        if adjusted_elapsed >= 0 {
            self.realtime_epoch_ns.saturating_add(adjusted_elapsed as u64)
        } else {
            self.realtime_epoch_ns.saturating_sub((-adjusted_elapsed) as u64)
        }
    }

    pub(crate) fn set_runtime_realtime_ns(&mut self, now_ns: u64, tick_count: u64) {
        self.realtime_epoch_ns = now_ns;
        self.realtime_epoch_tick = tick_count;
    }

    pub(crate) fn adjust_runtime_realtime_ns(
        &mut self,
        delta_ns: i128,
        tick_count: u64,
        timer_hz: u64,
    ) {
        let now_ns = self.runtime_realtime_now_ns(tick_count, timer_hz);
        let adjusted = if delta_ns >= 0 {
            now_ns.saturating_add(delta_ns as u64)
        } else {
            now_ns.saturating_sub((-delta_ns) as u64)
        };
        self.set_runtime_realtime_ns(adjusted, tick_count);
    }
}
