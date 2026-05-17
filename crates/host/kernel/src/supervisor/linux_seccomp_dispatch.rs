use alloc::vec::Vec;

use service_core::seccomp::{
    SECCOMP_FILTER_FLAG_LOG, SECCOMP_FILTER_FLAG_TSYNC, SeccompDecision, SeccompFilterProgram,
    SeccompInstruction, linux_seccomp_notif_sizes_bytes, seccomp_action_available_without_listener,
};
use vmos_abi::{ERR_EFAULT, ERR_EINVAL, ERR_ENOSYS, ERR_EOPNOTSUPP, ERR_ESRCH};

use super::{
    linux::{LinuxCallResult, LinuxPlan},
    runtime::PrototypeRuntime,
};

const SECCOMP_SET_MODE_STRICT: u64 = 0;
const SECCOMP_SET_MODE_FILTER: u64 = 1;
const SECCOMP_GET_ACTION_AVAIL: u64 = 2;
const SECCOMP_GET_NOTIF_SIZES: u64 = 3;
const SECCOMP_MODE_STRICT: u64 = 1;
const SECCOMP_MODE_FILTER: u64 = 2;

const PR_GET_DUMPABLE: u64 = 3;
const PR_SET_DUMPABLE: u64 = 4;
const PR_GET_SECCOMP: u64 = 21;
const PR_SET_SECCOMP: u64 = 22;
const PR_SET_NO_NEW_PRIVS: u64 = 38;
const PR_GET_NO_NEW_PRIVS: u64 = 39;

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

        match operation {
            SECCOMP_SET_MODE_STRICT => {
                if flags != 0 {
                    return Ok(errno_ret(ERR_EINVAL));
                }
                if args_ptr != 0 {
                    return Ok(errno_ret(ERR_EINVAL));
                }
                self.install_generic_seccomp_mode(SECCOMP_MODE_STRICT, args_ptr, flags)
            }
            SECCOMP_SET_MODE_FILTER => {
                self.install_generic_seccomp_mode(SECCOMP_MODE_FILTER, args_ptr, flags)
            }
            SECCOMP_GET_ACTION_AVAIL => {
                if flags != 0 {
                    return Ok(errno_ret(ERR_EINVAL));
                }
                self.seccomp_get_action_avail(args_ptr)
            }
            SECCOMP_GET_NOTIF_SIZES => {
                if flags != 0 {
                    return Ok(errno_ret(ERR_EINVAL));
                }
                self.seccomp_get_notif_sizes(args_ptr)
            }
            _ => Ok(errno_ret(ERR_EINVAL)),
        }
    }

    pub(super) fn plan_prctl(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let option = plan.args[0];
        let arg2 = plan.args[1];
        let arg3 = plan.args[2];
        let arg4 = plan.args[3];
        let arg5 = plan.args[4];

        match option {
            PR_GET_DUMPABLE => {
                if arg2 != 0 || arg3 != 0 || arg4 != 0 || arg5 != 0 {
                    return Ok(errno_ret(ERR_EINVAL));
                }
                match self.process_dumpable(self.current_pid()) {
                    Ok(dumpable) => Ok(LinuxCallResult::Ret(dumpable as i64)),
                    Err(errno) => Ok(errno_ret(errno)),
                }
            }
            PR_SET_DUMPABLE => {
                if arg2 > 1 || arg3 != 0 || arg4 != 0 || arg5 != 0 {
                    return Ok(errno_ret(ERR_EINVAL));
                }
                match self.set_process_dumpable(self.current_pid(), arg2 != 0) {
                    Ok(()) => Ok(LinuxCallResult::Ret(0)),
                    Err(errno) => Ok(errno_ret(errno)),
                }
            }
            PR_SET_NO_NEW_PRIVS => {
                if arg2 != 1 || arg3 != 0 || arg4 != 0 || arg5 != 0 {
                    return Ok(errno_ret(ERR_EINVAL));
                }
                if self.set_no_new_privs(self.current_tid(), true) {
                    Ok(LinuxCallResult::Ret(0))
                } else {
                    Ok(errno_ret(ERR_ESRCH))
                }
            }
            PR_GET_NO_NEW_PRIVS => {
                if arg2 != 0 || arg3 != 0 || arg4 != 0 || arg5 != 0 {
                    return Ok(errno_ret(ERR_EINVAL));
                }
                Ok(LinuxCallResult::Ret(self.no_new_privs(self.current_tid()) as i64))
            }
            PR_GET_SECCOMP => {
                if arg2 != 0 || arg3 != 0 || arg4 != 0 || arg5 != 0 {
                    return Ok(errno_ret(ERR_EINVAL));
                }
                match self.seccomp_mode(self.current_tid()) {
                    Some(mode) => Ok(LinuxCallResult::Ret(mode as i64)),
                    None => Ok(errno_ret(ERR_ESRCH)),
                }
            }
            PR_SET_SECCOMP => {
                if arg4 != 0 || arg5 != 0 {
                    return Ok(errno_ret(ERR_EINVAL));
                }
                self.install_generic_seccomp_mode(arg2, arg3, 0)
            }
            _ => Ok(errno_ret(ERR_EINVAL)),
        }
    }

    fn install_generic_seccomp_mode(
        &mut self,
        mode: u64,
        arg: u64,
        flags: u64,
    ) -> Result<LinuxCallResult, &'static str> {
        match mode {
            SECCOMP_MODE_STRICT => {
                if flags != 0 || arg != 0 {
                    return Ok(errno_ret(ERR_EINVAL));
                }
                match self.set_seccomp_strict(self.current_tid()) {
                    Ok(()) => Ok(LinuxCallResult::Ret(0)),
                    Err(errno) => Ok(errno_ret(errno)),
                }
            }
            SECCOMP_MODE_FILTER => {
                let supported_flags = SECCOMP_FILTER_FLAG_LOG | SECCOMP_FILTER_FLAG_TSYNC;
                if flags & !supported_flags != 0 {
                    return Ok(errno_ret(ERR_EINVAL));
                }
                let program = match self.read_generic_seccomp_filter_program(arg) {
                    Ok(program) => program,
                    Err(errno) => return Ok(errno_ret(errno)),
                };
                match self.set_seccomp_filter(
                    self.current_tid(),
                    program,
                    false,
                    flags & SECCOMP_FILTER_FLAG_TSYNC != 0,
                    flags & SECCOMP_FILTER_FLAG_LOG != 0,
                ) {
                    Ok(()) => Ok(LinuxCallResult::Ret(0)),
                    Err(errno) => Ok(errno_ret(errno)),
                }
            }
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

    fn seccomp_get_notif_sizes(&mut self, args_ptr: u64) -> Result<LinuxCallResult, &'static str> {
        let ptr = match u32::try_from(args_ptr) {
            Ok(ptr) if ptr != 0 => ptr,
            _ => return Ok(errno_ret(ERR_EFAULT)),
        };
        if self.linux.write_bytes(ptr, &linux_seccomp_notif_sizes_bytes()).is_err() {
            return Ok(errno_ret(ERR_EFAULT));
        }
        Ok(LinuxCallResult::Ret(0))
    }

    fn read_generic_seccomp_filter_program(
        &mut self,
        args_ptr: u64,
    ) -> Result<SeccompFilterProgram, i32> {
        const SOCK_FPROG_SIZE: usize = 16;
        const SOCK_FILTER_SIZE: usize = 8;
        const MAX_FILTER_INSTRUCTIONS: usize = 4096;

        let ptr = u32::try_from(args_ptr).map_err(|_| ERR_EFAULT)?;
        if ptr == 0 {
            return Err(ERR_EFAULT);
        }
        let fprog = self.linux.read_bytes(ptr, SOCK_FPROG_SIZE as u32).map_err(|_| ERR_EFAULT)?;
        let len = u16::from_le_bytes(fprog[0..2].try_into().map_err(|_| ERR_EINVAL)?) as usize;
        let filter_ptr = u64::from_le_bytes(fprog[8..16].try_into().map_err(|_| ERR_EINVAL)?);
        if len == 0 || len > MAX_FILTER_INSTRUCTIONS {
            return Err(ERR_EINVAL);
        }
        let filter_ptr = u32::try_from(filter_ptr).map_err(|_| ERR_EFAULT)?;
        if filter_ptr == 0 {
            return Err(ERR_EFAULT);
        }
        let byte_len = len.checked_mul(SOCK_FILTER_SIZE).ok_or(ERR_EINVAL)?;
        let byte_len_u32 = u32::try_from(byte_len).map_err(|_| ERR_EINVAL)?;
        let raw_filter = self.linux.read_bytes(filter_ptr, byte_len_u32).map_err(|_| ERR_EFAULT)?;
        let mut instructions = Vec::with_capacity(len);
        for chunk in raw_filter.chunks_exact(SOCK_FILTER_SIZE) {
            instructions.push(SeccompInstruction::new(
                u16::from_le_bytes(chunk[0..2].try_into().map_err(|_| ERR_EINVAL)?),
                chunk[2],
                chunk[3],
                u32::from_le_bytes(chunk[4..8].try_into().map_err(|_| ERR_EINVAL)?),
            ));
        }
        SeccompFilterProgram::new(instructions).map_err(|_| ERR_EINVAL)
    }
}

fn is_supported_seccomp_action(action: u32) -> bool {
    seccomp_action_available_without_listener(action)
}

fn errno_ret(errno: i32) -> LinuxCallResult {
    LinuxCallResult::Ret(-(errno as i64))
}
