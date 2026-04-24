use vmos_abi::{ERR_ENOSYS, ERR_EOPNOTSUPP};

use super::linux::{LinuxCallResult, LinuxPlan};
use super::runtime::PrototypeRuntime;

impl<'engine> PrototypeRuntime<'engine> {
    pub(super) fn plan_mmap(&mut self, _plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        Ok(LinuxCallResult::Ret(-(ERR_EOPNOTSUPP as i64)))
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
