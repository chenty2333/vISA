use semantic_core::{FaultClass, TrapClass};
use visa_abi::{ERR_EFAULT, ERR_EIO, ERR_EPERM};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ClassifiedFault {
    pub(super) trap: TrapClass,
    pub(super) class: FaultClass,
    pub(super) errno: i32,
    pub(super) recoverable: bool,
}

pub(super) fn classify_service_trap(package: &str, detail: &str) -> ClassifiedFault {
    let trap = if detail.contains("WindowViolation") {
        TrapClass::WindowViolationTrap
    } else if package == "console_service" || package.starts_with("driver_") {
        TrapClass::DriverTrap
    } else {
        TrapClass::ServiceTrap
    };
    let class = trap.fault_class();
    ClassifiedFault {
        trap,
        class,
        errno: errno_for_trap(trap),
        recoverable: matches!(class, FaultClass::Service | FaultClass::Driver),
    }
}

pub(super) fn errno_for_trap(trap: TrapClass) -> i32 {
    match trap {
        TrapClass::WindowViolationTrap => ERR_EFAULT,
        TrapClass::CapabilityDenied => ERR_EPERM,
        _ => ERR_EIO,
    }
}
