use alloc::vec::Vec;

use vmos_abi::{NodeKind, ServiceRoute};

pub(crate) type TaskId = u32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InjectedFault {
    ProcfsRead,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WaitKind {
    Timer,
    Futex,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WaitToken {
    pub(crate) id: u64,
    pub(crate) owner_task: TaskId,
    pub(crate) kind: WaitKind,
    pub(crate) generation: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct FdEntry {
    pub(crate) route: ServiceRoute,
    pub(crate) node: NodeKind,
    pub(crate) path: Vec<u8>,
    pub(crate) cursor: usize,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct LookupInfo {
    pub(crate) route: ServiceRoute,
    pub(crate) node: NodeKind,
}

#[derive(Debug)]
pub(crate) enum ServiceCallError {
    Trap(&'static str),
    Errno(i32),
    Invalid(&'static str),
}
