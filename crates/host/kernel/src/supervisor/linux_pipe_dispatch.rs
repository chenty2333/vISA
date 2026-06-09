use visa_abi::{ERR_EFAULT, ERR_EINVAL};

use super::{
    linux::{LinuxCallResult, LinuxPlan},
    runtime::PrototypeRuntime,
};

impl<'engine> PrototypeRuntime<'engine> {
    pub(super) fn plan_pipe(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let fds_ptr = match u32::try_from(plan.args[0]) {
            Ok(ptr) if ptr != 0 => ptr,
            _ => return Ok(errno_ret(ERR_EFAULT)),
        };
        let flags = match u32::try_from(plan.args[1]) {
            Ok(flags) => flags,
            Err(_) => return Ok(errno_ret(ERR_EINVAL)),
        };
        if self.linux.read_bytes(fds_ptr, 8).is_err() {
            return Ok(errno_ret(ERR_EFAULT));
        }

        match self.create_pipe_pair_with_flags(flags) {
            Ok((read_fd, write_fd)) => {
                let mut encoded = [0u8; 8];
                encoded[..4].copy_from_slice(&(read_fd as i32).to_le_bytes());
                encoded[4..].copy_from_slice(&(write_fd as i32).to_le_bytes());
                if self.linux.write_bytes(fds_ptr, &encoded).is_err() {
                    return Ok(errno_ret(ERR_EFAULT));
                }
                Ok(LinuxCallResult::Ret(0))
            }
            Err(errno) => Ok(errno_ret(errno)),
        }
    }
}

fn errno_ret(errno: i32) -> LinuxCallResult {
    LinuxCallResult::Ret(-(errno as i64))
}
