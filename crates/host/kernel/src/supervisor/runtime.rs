use alloc::{boxed::Box, vec, vec::Vec};
use core::ptr::null_mut;

use semantic_core::{FrontendKind, ResourceHandle, SemanticGraph, TaskState};

use super::{
    artifacts::ArtifactRegistry,
    authority::AuthorityPlane,
    engine::RuntimeOnlyExecutor,
    linux::LinuxFrontend,
    net::NetworkPlane,
    pulse::PulseDevice,
    scheduler::Scheduler,
    semantic::bootstrap_graph,
    services::{
        ConsoleService, DevfsService, DriverVirtioNetService, EpollService, FutexService,
        LinuxSocketService, NetCoreService, ProcfsService, ReplaySnapshotService, VfsService,
        WasmApp,
    },
    store_manager::StoreManager,
    types::{EventFdState, FdEntry, InjectedFault, PipeState, SocketPairState, TaskId},
    wait::WaitRegistry,
};
use crate::interrupts;

static mut ACTIVE_RUNTIME: *mut PrototypeRuntime<'static> = null_mut();

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
    pub(super) net_driver: DriverVirtioNetService,
    pub(super) replay_snapshot: ReplaySnapshotService,
    pub(super) linux: LinuxFrontend,
    pub(super) app: WasmApp,
    pub(super) fd_table: Vec<Option<FdEntry>>,
    pub(super) fd_handles: Vec<Option<ResourceHandle>>,
    pub(super) pipes: Vec<PipeState>,
    pub(super) next_pipe_id: u64,
    pub(super) socketpairs: Vec<SocketPairState>,
    pub(super) next_socketpair_id: u64,
    pub(super) eventfds: Vec<EventFdState>,
    pub(super) next_eventfd_id: u64,
    pub(super) synthetic_listener_connects: u32,
    pub(super) fault: Option<InjectedFault>,
    pub(super) scheduler: Scheduler,
    pub(super) waits: WaitRegistry,
    pub(super) pulse: PulseDevice,
    pub(super) net: NetworkPlane,
    pub(super) store_manager: StoreManager,
    pub(super) restart_count: u64,
    pub(super) semantic: SemanticGraph,
    pub(super) next_snapshot_barrier: u64,
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
        crate::kdebug!("instantiating driver_virtio_net");
        let net_driver = DriverVirtioNetService::new(engine)?;
        crate::kdebug!("instantiating replay_snapshot");
        let replay_snapshot = ReplaySnapshotService::new(engine)?;
        crate::kdebug!("instantiating linux_syscall");
        let linux = LinuxFrontend::new(engine)?;
        crate::kdebug!("instantiating wasm_app");
        let app = WasmApp::new(engine)?;
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
            net_driver,
            replay_snapshot,
            linux,
            app,
            fd_table: vec![None, None, None],
            fd_handles: vec![None, None, None],
            pipes: Vec::new(),
            next_pipe_id: 1,
            socketpairs: Vec::new(),
            next_socketpair_id: 1,
            eventfds: Vec::new(),
            next_eventfd_id: 1,
            synthetic_listener_connects: 0,
            fault: None,
            scheduler: Scheduler::new(),
            waits: WaitRegistry::new(),
            pulse: PulseDevice::new(interrupts::tick_count()),
            net,
            store_manager,
            restart_count: 0,
            semantic,
            next_snapshot_barrier: 1,
        })
    }

    pub(crate) fn allocate_task(&mut self) -> TaskId {
        let task = self.scheduler.allocate_task();
        self.semantic.ensure_task(task, FrontendKind::LinuxElf, "linux-elf-task");
        task
    }

    pub(crate) fn set_current_task(&mut self, task: TaskId) {
        self.scheduler.set_current_task(task);
        self.semantic.set_task_state(task, TaskState::Running);
    }

    pub(crate) fn bootstrap_task(&self) -> TaskId {
        self.scheduler.bootstrap_task()
    }
}
