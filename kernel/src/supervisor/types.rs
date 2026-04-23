use alloc::vec::Vec;

use vmos_abi::{NodeKind, ServiceRoute};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InjectedFault {
    ProcfsRead,
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
