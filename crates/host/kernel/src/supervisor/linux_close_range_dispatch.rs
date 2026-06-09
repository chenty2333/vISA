use visa_abi::ERR_EINVAL;

use super::{
    linux::{LinuxCallResult, LinuxPlan},
    runtime::PrototypeRuntime,
};

impl<'engine> PrototypeRuntime<'engine> {
    pub(super) fn plan_close_range(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        const CLOSE_RANGE_UNSHARE: u64 = 1 << 1;
        const CLOSE_RANGE_CLOEXEC: u64 = 1 << 2;

        let first = match u32::try_from(plan.args[0]) {
            Ok(first) => first,
            Err(_) => return Ok(errno_ret(ERR_EINVAL)),
        };
        let last = u32::try_from(plan.args[1]).unwrap_or(u32::MAX);
        let flags = plan.args[2];
        if flags & !(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC) != 0 {
            return Ok(errno_ret(ERR_EINVAL));
        }

        let result = if flags & CLOSE_RANGE_CLOEXEC != 0 {
            self.set_fd_flags_range(first, last, 1)
        } else {
            self.close_fd_range(first, last)
        };
        match result {
            Ok(()) => Ok(LinuxCallResult::Ret(0)),
            Err(errno) => Ok(errno_ret(errno)),
        }
    }
}

fn errno_ret(errno: i32) -> LinuxCallResult {
    LinuxCallResult::Ret(-(errno as i64))
}
