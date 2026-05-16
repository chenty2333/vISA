use service_core::seccomp::{
    SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO, SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_KILL_THREAD,
    SECCOMP_RET_LOG, SECCOMP_RET_TRAP, SeccompDecision,
};
use vmos_abi::{ERR_EFAULT, ERR_EINVAL, ERR_ENOSYS, ERR_EOPNOTSUPP};

use super::{
    linux::{LinuxCallResult, LinuxPlan},
    runtime::PrototypeRuntime,
};

const SECCOMP_SET_MODE_STRICT: u64 = 0;
const SECCOMP_SET_MODE_FILTER: u64 = 1;
const SECCOMP_GET_ACTION_AVAIL: u64 = 2;

impl<'engine> PrototypeRuntime<'engine> {
    pub(super) fn apply_generic_seccomp_decision(
        &mut self,
        syscall: u64,
        decision: SeccompDecision,
    ) -> Option<LinuxCallResult> {
        match decision {
            SeccompDecision::Allow => None,
            SeccompDecision::Log { data } => {
                crate::kinfo!(
                    "generic seccomp log syscall={} tid={} data={}",
                    syscall,
                    self.current_tid(),
                    data
                );
                None
            }
            SeccompDecision::Errno(errno) => Some(errno_ret(errno as i32)),
            SeccompDecision::Trap { .. } | SeccompDecision::Trace | SeccompDecision::UserNotif => {
                Some(errno_ret(ERR_ENOSYS))
            }
            SeccompDecision::Kill { signal } => {
                crate::kwarn!("generic seccomp killed syscall {}", syscall);
                Some(LinuxCallResult::Exit(128 + signal as i32))
            }
        }
    }

    pub(super) fn plan_seccomp(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        let operation = plan.args[0];
        let flags = plan.args[1];
        let args_ptr = plan.args[2];

        if flags != 0 {
            return Ok(errno_ret(ERR_EINVAL));
        }

        match operation {
            SECCOMP_SET_MODE_STRICT => {
                if args_ptr != 0 {
                    return Ok(errno_ret(ERR_EINVAL));
                }
                match self.set_seccomp_strict(self.current_tid()) {
                    Ok(()) => Ok(LinuxCallResult::Ret(0)),
                    Err(errno) => Ok(errno_ret(errno)),
                }
            }
            SECCOMP_SET_MODE_FILTER => Ok(errno_ret(ERR_ENOSYS)),
            SECCOMP_GET_ACTION_AVAIL => self.seccomp_get_action_avail(args_ptr),
            _ => Ok(errno_ret(ERR_EINVAL)),
        }
    }

    fn seccomp_get_action_avail(&mut self, args_ptr: u64) -> Result<LinuxCallResult, &'static str> {
        let ptr = match u32::try_from(args_ptr) {
            Ok(ptr) if ptr != 0 => ptr,
            _ => return Ok(errno_ret(ERR_EFAULT)),
        };
        let bytes = match self.linux.read_bytes(ptr, 4) {
            Ok(bytes) => bytes,
            Err(_) => return Ok(errno_ret(ERR_EFAULT)),
        };
        let action =
            u32::from_le_bytes(bytes[..4].try_into().map_err(|_| "seccomp action read failed")?);
        if is_supported_seccomp_action(action) {
            Ok(LinuxCallResult::Ret(0))
        } else {
            Ok(errno_ret(ERR_EOPNOTSUPP))
        }
    }
}

fn is_supported_seccomp_action(action: u32) -> bool {
    matches!(
        action,
        SECCOMP_RET_KILL_PROCESS
            | SECCOMP_RET_KILL_THREAD
            | SECCOMP_RET_TRAP
            | SECCOMP_RET_ERRNO
            | SECCOMP_RET_LOG
            | SECCOMP_RET_ALLOW
    )
}

fn errno_ret(errno: i32) -> LinuxCallResult {
    LinuxCallResult::Ret(-(errno as i64))
}
