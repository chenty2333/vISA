use vmos_abi::{ERR_EBADF, ERR_EINVAL};

use super::{
    linux::{LinuxCallResult, LinuxPlan},
    runtime::PrototypeRuntime,
};

impl<'engine> PrototypeRuntime<'engine> {
    pub(super) fn plan_dup(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        const MODE_DUP: u64 = 0;
        const MODE_DUP2: u64 = 1;
        const MODE_DUP3: u64 = 2;
        const O_CLOEXEC: u64 = 0o2000000;
        const FD_CLOEXEC: u32 = 1;

        let old_fd = match u32::try_from(plan.args[0]) {
            Ok(fd) => fd,
            Err(_) => return Ok(errno_ret(ERR_EBADF)),
        };
        let ret = match plan.args[3] {
            MODE_DUP => {
                if plan.args[2] != 0 {
                    return Ok(errno_ret(ERR_EINVAL));
                }
                self.dup_fd(old_fd)
            }
            MODE_DUP2 => {
                if plan.args[2] != 0 {
                    return Ok(errno_ret(ERR_EINVAL));
                }
                let new_fd = match u32::try_from(plan.args[1]) {
                    Ok(fd) => fd,
                    Err(_) => return Ok(errno_ret(ERR_EBADF)),
                };
                self.dup_fd_to(old_fd, new_fd, true)
            }
            MODE_DUP3 => {
                if plan.args[2] & !O_CLOEXEC != 0 {
                    return Ok(errno_ret(ERR_EINVAL));
                }
                let new_fd = match u32::try_from(plan.args[1]) {
                    Ok(fd) => fd,
                    Err(_) => return Ok(errno_ret(ERR_EBADF)),
                };
                self.dup_fd_to(old_fd, new_fd, false).and_then(|fd| {
                    if plan.args[2] & O_CLOEXEC != 0 {
                        self.set_fd_flags(fd, FD_CLOEXEC)?;
                    }
                    Ok(fd)
                })
            }
            _ => return Ok(errno_ret(ERR_EINVAL)),
        };
        match ret {
            Ok(fd) => Ok(LinuxCallResult::Ret(fd as i64)),
            Err(errno) => Ok(errno_ret(errno)),
        }
    }
}

fn errno_ret(errno: i32) -> LinuxCallResult {
    LinuxCallResult::Ret(-(errno as i64))
}
