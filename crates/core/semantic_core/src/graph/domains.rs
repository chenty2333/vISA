use alloc::vec::Vec;

use super::*;

#[derive(Clone, Debug)]
pub(crate) struct SemanticDomains {
    pub(crate) capability: CapabilityDomain,
    pub(crate) wait: WaitDomain,
    pub(crate) io: IoDomain,
    #[allow(dead_code)]
    pub(crate) memory: MemoryDomain,
}

impl SemanticDomains {
    pub(crate) fn new() -> Self {
        Self {
            capability: CapabilityDomain::new(),
            wait: WaitDomain::new(),
            io: IoDomain::new(),
            memory: MemoryDomain::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CapabilityDomain {
    pub(crate) capabilities: CapabilityLedger,
}

impl CapabilityDomain {
    fn new() -> Self {
        Self { capabilities: CapabilityLedger::new() }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct WaitDomain {
    pub(crate) waits: Vec<WaitRecord>,
}

impl WaitDomain {
    fn new() -> Self {
        Self { waits: Vec::new() }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct IoDomain {
    pub(crate) io_waits: Vec<IoWaitRecord>,
    pub(crate) io_cleanups: Vec<IoCleanupRecord>,
    pub(crate) io_fault_injections: Vec<IoFaultInjectionRecord>,
    pub(crate) io_validation_reports: Vec<IoValidationReportRecord>,
}

impl IoDomain {
    fn new() -> Self {
        Self {
            io_waits: Vec::new(),
            io_cleanups: Vec::new(),
            io_fault_injections: Vec::new(),
            io_validation_reports: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct MemoryDomain;

impl MemoryDomain {
    fn new() -> Self {
        Self
    }
}
