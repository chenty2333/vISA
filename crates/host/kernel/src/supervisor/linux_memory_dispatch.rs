use vmos_abi::ERR_ENOSYS;

use super::{
    linux::{LinuxCallResult, LinuxPlan},
    runtime::PrototypeRuntime,
};

impl<'engine> PrototypeRuntime<'engine> {
    pub(super) fn plan_mmap(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let _addr = plan.args[0];
        let _len = plan.args[1];
        let _prot = plan.args[2];
        let _flags = plan.args[3];
        // Semantic VMA recording will be added when GuestMemoryManager
        // is integrated into the supervisor runtime path.
        // For now, mmap succeeds (bridge.rs handles the actual mapping).
        Ok(LinuxCallResult::Ret(0))
    }

    pub(super) fn plan_munmap(
        &mut self,
        _plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        Ok(LinuxCallResult::Ret(0))
    }

    pub(super) fn plan_poll(&mut self, _plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        Ok(LinuxCallResult::Ret(-(ERR_ENOSYS as i64)))
    }
}
