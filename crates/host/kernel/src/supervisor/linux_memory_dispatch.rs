use vmos_abi::ERR_ENOSYS;

use super::{
    linux::{LinuxCallResult, LinuxPlan},
    runtime::PrototypeRuntime,
};

impl<'engine> PrototypeRuntime<'engine> {
    pub(super) fn plan_mmap(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let addr = plan.args[0];
        let len = plan.args[1];
        let prot = plan.args[2];
        let (readable, writable, executable) = prot_user_region_permissions(prot);
        self.record_guest_memory_region(addr, len, readable, writable, executable);
        Ok(LinuxCallResult::Ret(0))
    }

    pub(super) fn plan_munmap(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        self.record_guest_memory_unmap(plan.args[0], plan.args[1]);
        Ok(LinuxCallResult::Ret(0))
    }

    pub(super) fn plan_poll(&mut self, _plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        Ok(LinuxCallResult::Ret(-(ERR_ENOSYS as i64)))
    }
}

fn prot_user_region_permissions(prot: u64) -> (bool, bool, bool) {
    const PROT_READ: u64 = 0x1;
    const PROT_WRITE: u64 = 0x2;
    const PROT_EXEC: u64 = 0x4;

    let writable = prot & PROT_WRITE != 0;
    let readable = writable || prot & PROT_READ != 0;
    let executable = prot & PROT_EXEC != 0;
    (readable, writable, executable)
}
