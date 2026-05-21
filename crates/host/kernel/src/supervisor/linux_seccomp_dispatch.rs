use alloc::vec::Vec;

use service_core::seccomp::{
    SECCOMP_FILTER_FLAG_LOG, SECCOMP_FILTER_FLAG_NEW_LISTENER, SECCOMP_FILTER_FLAG_TSYNC,
    SeccompDecision, SeccompFilterProgram, SeccompInstruction, linux_seccomp_notif_sizes_bytes,
    seccomp_action_available_without_listener,
};
use vmos_abi::{ERR_EFAULT, ERR_EINVAL, ERR_EMFILE, ERR_ENOSYS, ERR_EOPNOTSUPP, ERR_ESRCH};

use super::{
    linux::{LinuxCallResult, LinuxPlan},
    runtime::PrototypeRuntime,
    types::{CAP_SYS_ADMIN, FdEntry, FdResource},
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
                let supported_flags = SECCOMP_FILTER_FLAG_LOG
                    | SECCOMP_FILTER_FLAG_NEW_LISTENER
                    | SECCOMP_FILTER_FLAG_TSYNC;
                if flags & !supported_flags != 0 {
                    return Ok(errno_ret(ERR_EINVAL));
                }
                if flags & SECCOMP_FILTER_FLAG_NEW_LISTENER != 0 && !self.can_allocate_fds(1) {
                    return Ok(errno_ret(ERR_EMFILE));
                }
                let program = match self.read_generic_seccomp_filter_program(arg) {
                    Ok(program) => program,
                    Err(errno) => return Ok(errno_ret(errno)),
                };
                match self.set_seccomp_filter(
                    self.current_tid(),
                    program,
                    self.current_access_state().cap_effective & CAP_SYS_ADMIN != 0,
                    flags & SECCOMP_FILTER_FLAG_TSYNC != 0,
                    flags & SECCOMP_FILTER_FLAG_LOG != 0,
                ) {
                    Ok(()) if flags & SECCOMP_FILTER_FLAG_NEW_LISTENER != 0 => {
                        match self.create_seccomp_listener_fd() {
                            Ok(fd) => Ok(LinuxCallResult::Ret(fd as i64)),
                            Err(errno) => Ok(errno_ret(errno)),
                        }
                    }
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

    pub(crate) fn create_seccomp_listener_fd(&mut self) -> Result<u32, i32> {
        const FD_CLOEXEC: u32 = 1;
        let listener_id = self.next_seccomp_listener_id;
        self.next_seccomp_listener_id = self.next_seccomp_listener_id.saturating_add(1);
        self.alloc_fd(FdEntry {
            resource: FdResource::SeccompListener { listener_id },
            cursor: 0,
            fd_flags: FD_CLOEXEC,
            status_flags: 0,
            cursor_group: None,
        })
    }
}

fn is_supported_seccomp_action(action: u32) -> bool {
    seccomp_action_available_without_listener(action)
}

fn errno_ret(errno: i32) -> LinuxCallResult {
    LinuxCallResult::Ret(-(errno as i64))
}

#[cfg(test)]
mod tests {
    use service_core::seccomp::SECCOMP_RET_ALLOW;
    use vmos_abi::ERR_EACCES;

    use super::*;
    use crate::supervisor::engine::RuntimeOnlyExecutor;

    fn test_runtime() -> PrototypeRuntime<'static> {
        let engine = Box::leak(Box::new(RuntimeOnlyExecutor::default()));
        PrototypeRuntime::new(engine).expect("test runtime")
    }

    fn expect_ret(result: LinuxCallResult) -> i64 {
        match result {
            LinuxCallResult::Ret(ret) => ret,
            other => panic!("expected Ret, got {other:?}"),
        }
    }

    fn set_current_effective_caps(runtime: &mut PrototypeRuntime<'_>, caps: u64) {
        let pid = runtime.current_pid();
        let process =
            runtime.processes.iter_mut().find(|process| process.pid == pid).expect("process");
        process.access.cap_permitted = caps;
        process.access.cap_effective = caps;
    }

    fn write_allow_filter(runtime: &mut PrototypeRuntime<'_>) -> u32 {
        const BPF_RET_K: u16 = 0x06;
        let mut seccomp_args = [0u8; 24];
        let (fprog_ptr, _) = runtime.linux.write_arg_bytes(&seccomp_args).expect("seccomp buffer");
        let filter_ptr = fprog_ptr + 16;

        seccomp_args[0..2].copy_from_slice(&1u16.to_le_bytes());
        seccomp_args[8..16].copy_from_slice(&(filter_ptr as u64).to_le_bytes());
        seccomp_args[16..18].copy_from_slice(&BPF_RET_K.to_le_bytes());
        seccomp_args[20..24].copy_from_slice(&SECCOMP_RET_ALLOW.to_le_bytes());
        runtime.linux.write_bytes(fprog_ptr, &seccomp_args).expect("seccomp buffer write");
        fprog_ptr
    }

    #[test]
    fn generic_seccomp_filter_cap_sys_admin_bypasses_no_new_privs_requirement() {
        let mut denied_runtime = test_runtime();
        set_current_effective_caps(&mut denied_runtime, 0);
        let denied_fprog = write_allow_filter(&mut denied_runtime);
        let denied = denied_runtime
            .install_generic_seccomp_mode(SECCOMP_MODE_FILTER, denied_fprog as u64, 0)
            .expect("denied seccomp install");
        assert_eq!(expect_ret(denied), -(ERR_EACCES as i64));
        assert_eq!(denied_runtime.seccomp_mode(denied_runtime.current_tid()), Some(0));

        let mut privileged_runtime = test_runtime();
        set_current_effective_caps(&mut privileged_runtime, CAP_SYS_ADMIN);
        let privileged_fprog = write_allow_filter(&mut privileged_runtime);
        let allowed = privileged_runtime
            .install_generic_seccomp_mode(SECCOMP_MODE_FILTER, privileged_fprog as u64, 0)
            .expect("privileged seccomp install");
        assert_eq!(expect_ret(allowed), 0);
        assert!(!privileged_runtime.no_new_privs(privileged_runtime.current_tid()));
        assert_eq!(
            privileged_runtime.seccomp_mode(privileged_runtime.current_tid()),
            Some(SECCOMP_MODE_FILTER)
        );
    }

    #[test]
    fn generic_seccomp_new_listener_returns_cloexec_listener_fd() {
        const FD_CLOEXEC: u32 = 1;

        let mut runtime = test_runtime();
        runtime.set_no_new_privs(runtime.current_tid(), true);
        let fprog = write_allow_filter(&mut runtime);
        let result = runtime
            .install_generic_seccomp_mode(
                SECCOMP_MODE_FILTER,
                fprog as u64,
                SECCOMP_FILTER_FLAG_NEW_LISTENER,
            )
            .expect("listener seccomp install");
        let fd = expect_ret(result);
        assert!(fd >= 3);
        assert_eq!(runtime.seccomp_mode(runtime.current_tid()), Some(SECCOMP_MODE_FILTER));

        let entry = runtime.fd_entry(fd as u32).expect("listener fd");
        assert_eq!(entry.fd_flags, FD_CLOEXEC);
        assert_eq!(entry.status_flags, 0);
        assert!(matches!(entry.resource, FdResource::SeccompListener { listener_id: 1 }));
    }
}
