use visa_abi::{
    AF_UNIX, ERR_EAFNOSUPPORT, ERR_EFAULT, ERR_EINVAL, ERR_EPROTONOSUPPORT, SOCK_STREAM,
};

use super::{
    linux::{LinuxCallResult, LinuxPlan},
    runtime::PrototypeRuntime,
};

impl<'engine> PrototypeRuntime<'engine> {
    pub(super) fn plan_socketpair(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        const SOCK_CLOEXEC: u64 = 0o2000000;
        const SOCK_NONBLOCK: u64 = 0o0004000;

        let domain = match u32::try_from(plan.args[0]) {
            Ok(domain) => domain,
            Err(_) => return Ok(errno_ret(ERR_EINVAL)),
        };
        let ty = plan.args[1];
        let protocol = match u32::try_from(plan.args[2]) {
            Ok(protocol) => protocol,
            Err(_) => return Ok(errno_ret(ERR_EINVAL)),
        };
        if domain != AF_UNIX || ty & !(SOCK_CLOEXEC | SOCK_NONBLOCK | SOCK_STREAM as u64) != 0 {
            return Ok(errno_ret(ERR_EAFNOSUPPORT));
        }
        if ty & SOCK_STREAM as u64 == 0 || protocol != 0 {
            return Ok(errno_ret(ERR_EPROTONOSUPPORT));
        }
        let sv_ptr = match u32::try_from(plan.args[3]) {
            Ok(ptr) if ptr != 0 => ptr,
            _ => return Ok(errno_ret(ERR_EFAULT)),
        };
        if self.linux.read_bytes(sv_ptr, 8).is_err() {
            return Ok(errno_ret(ERR_EFAULT));
        }

        let flags = u32::try_from(ty & (SOCK_CLOEXEC | SOCK_NONBLOCK))
            .map_err(|_| "socketpair flags overflowed")?;
        match self.create_socketpair_with_flags(flags) {
            Ok((fd_a, fd_b)) => {
                let mut encoded = [0u8; 8];
                encoded[..4].copy_from_slice(&(fd_a as i32).to_le_bytes());
                encoded[4..].copy_from_slice(&(fd_b as i32).to_le_bytes());
                if self.linux.write_bytes(sv_ptr, &encoded).is_err() {
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
