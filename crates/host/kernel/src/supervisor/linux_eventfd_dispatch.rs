use vmos_abi::ERR_EINVAL;

use super::{
    linux::{LinuxCallResult, LinuxPlan},
    runtime::PrototypeRuntime,
};

impl<'engine> PrototypeRuntime<'engine> {
    pub(super) fn plan_eventfd(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        let flags = match u32::try_from(plan.args[1]) {
            Ok(flags) => flags,
            Err(_) => return Ok(errno_ret(ERR_EINVAL)),
        };
        match self.create_eventfd(plan.args[0], flags) {
            Ok(fd) => Ok(LinuxCallResult::Ret(fd as i64)),
            Err(errno) => Ok(errno_ret(errno)),
        }
    }
}

fn errno_ret(errno: i32) -> LinuxCallResult {
    LinuxCallResult::Ret(-(errno as i64))
}
