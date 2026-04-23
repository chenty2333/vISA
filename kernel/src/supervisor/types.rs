use alloc::vec::Vec;

use vmos_abi::{NodeKind, RestartClass, ServiceRoute};

pub(crate) type TaskId = u32;

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
    ServiceNode {
        route: ServiceRoute,
        node: NodeKind,
        path: Vec<u8>,
    },
    EpollInstance {
        epoll_id: u32,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct FdEntry {
    pub(crate) resource: FdResource,
    pub(crate) cursor: usize,
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
