use alloc::vec::Vec;

use semantic_core::ResourceId;
use vmos_abi::{NodeKind, RestartClass, ServiceRoute};

pub(crate) type TaskId = u32;
// ProcessId / ThreadId from semantic_core (u64) — use for semantic records
// Supervisor runtime uses u32 pid/tid for performance
pub(crate) type Pid = u32;
pub(crate) type Tid = u32;

#[derive(Clone, Debug)]
pub(crate) struct ProcessRuntimeState {
    pub(crate) pid: Pid,
    pub(crate) ppid: Pid,
    pub(crate) pgid: Pid,
    pub(crate) sid: Pid,
    pub(crate) tgid: Tid,
    pub(crate) exit_signal: Option<u8>,
    pub(crate) state: ProcessRuntimeStateKind,
    pub(crate) exit_code: Option<i32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ProcessRuntimeStateKind {
    Running,
    Zombie,
    Dead,
}

#[derive(Clone, Debug)]
pub(crate) struct ThreadRuntimeState {
    pub(crate) tid: Tid,
    pub(crate) task_id: TaskId,
    pub(crate) pid: Pid,
    pub(crate) state: ThreadRuntimeStateKind,
    pub(crate) clear_child_tid: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ThreadRuntimeStateKind {
    Running,
    Blocked,
    Stopped,
    Dead,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InjectedFault {
    ProcfsRead,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WaitKind {
    Timer,
    Futex,
    Epoll,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WaitToken {
    pub(crate) id: u64,
    pub(crate) owner_task: TaskId,
    pub(crate) kind: WaitKind,
    pub(crate) generation: u64,
}

#[derive(Clone, Debug)]
pub(crate) enum FdResource {
    ServiceNode { route: ServiceRoute, node: NodeKind, path: Vec<u8> },
    EpollInstance { epoll_id: u32 },
    Socket { socket_id: u64, ready_key: u64 },
    PipeEnd { pipe_id: u64, readable: bool, writable: bool },
    SocketPairEnd { pair_id: u64, endpoint: u8 },
    EventFd { eventfd_id: u64 },
}

#[derive(Clone, Debug)]
pub(crate) struct FdEntry {
    pub(crate) resource: FdResource,
    pub(crate) cursor: usize,
    pub(crate) fd_flags: u32,
    pub(crate) status_flags: u32,
    pub(crate) cursor_group: Option<ResourceId>,
}

#[derive(Debug)]
pub(crate) struct PipeState {
    pub(crate) id: u64,
    pub(crate) buffer: Vec<u8>,
    pub(crate) capacity: usize,
    pub(crate) read_open: bool,
    pub(crate) write_open: bool,
}

#[derive(Debug)]
pub(crate) struct SocketPairState {
    pub(crate) id: u64,
    pub(crate) a_to_b: Vec<u8>,
    pub(crate) b_to_a: Vec<u8>,
    pub(crate) capacity: usize,
    pub(crate) open_a: bool,
    pub(crate) open_b: bool,
}

#[derive(Debug)]
pub(crate) struct EventFdState {
    pub(crate) id: u64,
    pub(crate) counter: u64,
    pub(crate) semaphore: bool,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct LookupInfo {
    pub(crate) route: ServiceRoute,
    pub(crate) node: NodeKind,
}

pub(crate) type WaitRestartClass = RestartClass;

#[derive(Debug)]
pub(crate) enum ServiceCallError {
    Trap(&'static str),
    Errno(i32),
    Invalid(&'static str),
}
