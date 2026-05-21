use alloc::vec::Vec;

use semantic_core::CredentialTransitionKind;
use service_core::seccomp::{
    SECCOMP_FILTER_FLAG_LOG, SECCOMP_FILTER_FLAG_NEW_LISTENER, SECCOMP_FILTER_FLAG_TSYNC,
    SeccompDecision, SeccompFilterProgram, SeccompInstruction, linux_seccomp_notif_sizes_bytes,
    seccomp_action_available_without_listener,
};
use vmos_abi::{
    ERR_EFAULT, ERR_EINVAL, ERR_EMFILE, ERR_ENOSYS, ERR_EOPNOTSUPP, ERR_EPERM, ERR_ESRCH,
};

use super::{
    linux::{LinuxCallResult, LinuxPlan},
    process::{
        access_clear_ambient_capabilities, access_drop_bounding_capability,
        access_lower_ambient_capability, access_raise_ambient_capability, access_set_keepcaps,
        access_set_securebits,
    },
    runtime::PrototypeRuntime,
    types::{CAP_SETPCAP, CAP_SYS_ADMIN, FdEntry, FdResource, LINUX_KNOWN_CAPS},
};

const SECCOMP_SET_MODE_STRICT: u64 = 0;
const SECCOMP_SET_MODE_FILTER: u64 = 1;
const SECCOMP_GET_ACTION_AVAIL: u64 = 2;
const SECCOMP_GET_NOTIF_SIZES: u64 = 3;
const SECCOMP_MODE_STRICT: u64 = 1;
const SECCOMP_MODE_FILTER: u64 = 2;

const PR_GET_DUMPABLE: u64 = 3;
const PR_SET_DUMPABLE: u64 = 4;
const PR_GET_KEEPCAPS: u64 = 7;
const PR_SET_KEEPCAPS: u64 = 8;
const PR_GET_SECCOMP: u64 = 21;
const PR_SET_SECCOMP: u64 = 22;
const PR_CAPBSET_READ: u64 = 23;
const PR_CAPBSET_DROP: u64 = 24;
const PR_GET_SECUREBITS: u64 = 27;
const PR_SET_SECUREBITS: u64 = 28;
const PR_SET_NO_NEW_PRIVS: u64 = 38;
const PR_GET_NO_NEW_PRIVS: u64 = 39;
const PR_CAP_AMBIENT: u64 = 47;
const PR_CAP_AMBIENT_IS_SET: u64 = 1;
const PR_CAP_AMBIENT_RAISE: u64 = 2;
const PR_CAP_AMBIENT_LOWER: u64 = 3;
const PR_CAP_AMBIENT_CLEAR_ALL: u64 = 4;

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
            PR_GET_KEEPCAPS => {
                if arg2 != 0 || arg3 != 0 || arg4 != 0 || arg5 != 0 {
                    return Ok(errno_ret(ERR_EINVAL));
                }
                let keepcaps =
                    self.current_access_state().securebits & super::types::SECBIT_KEEP_CAPS != 0;
                Ok(LinuxCallResult::Ret(keepcaps as i64))
            }
            PR_SET_KEEPCAPS => self.generic_prctl_set_keepcaps(arg2, arg3, arg4, arg5),
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
            PR_CAPBSET_READ => self.generic_prctl_capbset_read(arg2, arg3, arg4, arg5),
            PR_CAPBSET_DROP => self.generic_prctl_capbset_drop(arg2, arg3, arg4, arg5),
            PR_GET_SECUREBITS => {
                if arg2 != 0 || arg3 != 0 || arg4 != 0 || arg5 != 0 {
                    return Ok(errno_ret(ERR_EINVAL));
                }
                Ok(LinuxCallResult::Ret(self.current_access_state().securebits as i64))
            }
            PR_SET_SECUREBITS => self.generic_prctl_set_securebits(arg2, arg3, arg4, arg5),
            PR_CAP_AMBIENT => self.generic_prctl_cap_ambient(arg2, arg3, arg4, arg5),
            _ => Ok(errno_ret(ERR_EINVAL)),
        }
    }

    fn generic_prctl_set_keepcaps(
        &mut self,
        value: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
    ) -> Result<LinuxCallResult, &'static str> {
        if value > 1 || arg3 != 0 || arg4 != 0 || arg5 != 0 {
            return Ok(errno_ret(ERR_EINVAL));
        }
        let before = self.current_access_state();
        let Some(after) = access_set_keepcaps(before.clone(), value != 0) else {
            return Ok(errno_ret(ERR_EPERM));
        };
        if before.securebits == after.securebits {
            return Ok(LinuxCallResult::Ret(0));
        }
        self.apply_current_credential_transition(
            after,
            CredentialTransitionKind::CapSet {
                bounding: false,
                inheritable: false,
                permitted: false,
                effective: false,
                ambient: false,
                securebits: true,
            },
        )
    }

    fn generic_prctl_set_securebits(
        &mut self,
        bits: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
    ) -> Result<LinuxCallResult, &'static str> {
        if bits > u32::MAX as u64 || arg3 != 0 || arg4 != 0 || arg5 != 0 {
            return Ok(errno_ret(ERR_EINVAL));
        }
        if self.current_access_state().cap_effective & CAP_SETPCAP == 0 {
            return Ok(errno_ret(ERR_EPERM));
        }
        let before = self.current_access_state();
        let Some(after) = access_set_securebits(before.clone(), bits as u32) else {
            return Ok(errno_ret(ERR_EPERM));
        };
        if before.securebits == after.securebits {
            return Ok(LinuxCallResult::Ret(0));
        }
        self.apply_current_credential_transition(
            after,
            CredentialTransitionKind::CapSet {
                bounding: false,
                inheritable: false,
                permitted: false,
                effective: false,
                ambient: false,
                securebits: true,
            },
        )
    }

    fn generic_prctl_capbset_read(
        &mut self,
        cap: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
    ) -> Result<LinuxCallResult, &'static str> {
        if arg3 != 0 || arg4 != 0 || arg5 != 0 {
            return Ok(errno_ret(ERR_EINVAL));
        }
        let capability = match capability_bit_from_prctl_arg(cap) {
            Ok(capability) => capability,
            Err(errno) => return Ok(errno_ret(errno)),
        };
        Ok(LinuxCallResult::Ret(
            (self.current_access_state().cap_bounding & capability != 0) as i64,
        ))
    }

    fn generic_prctl_capbset_drop(
        &mut self,
        cap: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
    ) -> Result<LinuxCallResult, &'static str> {
        if arg3 != 0 || arg4 != 0 || arg5 != 0 {
            return Ok(errno_ret(ERR_EINVAL));
        }
        let capability = match capability_bit_from_prctl_arg(cap) {
            Ok(capability) => capability,
            Err(errno) => return Ok(errno_ret(errno)),
        };
        let before = self.current_access_state();
        let Some(after) = access_drop_bounding_capability(before.clone(), capability) else {
            return Ok(errno_ret(ERR_EPERM));
        };
        if before.cap_bounding == after.cap_bounding {
            return Ok(LinuxCallResult::Ret(0));
        }
        self.apply_current_credential_transition(
            after,
            CredentialTransitionKind::CapSet {
                bounding: true,
                inheritable: false,
                permitted: false,
                effective: false,
                ambient: false,
                securebits: false,
            },
        )
    }

    fn generic_prctl_cap_ambient(
        &mut self,
        op: u64,
        cap: u64,
        arg4: u64,
        arg5: u64,
    ) -> Result<LinuxCallResult, &'static str> {
        match op {
            PR_CAP_AMBIENT_IS_SET => {
                if arg4 != 0 || arg5 != 0 {
                    return Ok(errno_ret(ERR_EINVAL));
                }
                let capability = match capability_bit_from_prctl_arg(cap) {
                    Ok(capability) => capability,
                    Err(errno) => return Ok(errno_ret(errno)),
                };
                Ok(LinuxCallResult::Ret(
                    (self.current_access_state().cap_ambient & capability != 0) as i64,
                ))
            }
            PR_CAP_AMBIENT_RAISE => {
                if arg4 != 0 || arg5 != 0 {
                    return Ok(errno_ret(ERR_EINVAL));
                }
                let capability = match capability_bit_from_prctl_arg(cap) {
                    Ok(capability) => capability,
                    Err(errno) => return Ok(errno_ret(errno)),
                };
                let before = self.current_access_state();
                let Some(after) = access_raise_ambient_capability(before.clone(), capability)
                else {
                    return Ok(errno_ret(ERR_EPERM));
                };
                self.apply_ambient_transition_if_changed(before, after)
            }
            PR_CAP_AMBIENT_LOWER => {
                if arg4 != 0 || arg5 != 0 {
                    return Ok(errno_ret(ERR_EINVAL));
                }
                let capability = match capability_bit_from_prctl_arg(cap) {
                    Ok(capability) => capability,
                    Err(errno) => return Ok(errno_ret(errno)),
                };
                let before = self.current_access_state();
                let after = access_lower_ambient_capability(before.clone(), capability);
                self.apply_ambient_transition_if_changed(before, after)
            }
            PR_CAP_AMBIENT_CLEAR_ALL => {
                if cap != 0 || arg4 != 0 || arg5 != 0 {
                    return Ok(errno_ret(ERR_EINVAL));
                }
                let before = self.current_access_state();
                let after = access_clear_ambient_capabilities(before.clone());
                self.apply_ambient_transition_if_changed(before, after)
            }
            _ => Ok(errno_ret(ERR_EINVAL)),
        }
    }

    fn apply_ambient_transition_if_changed(
        &mut self,
        before: super::types::ProcessAccessState,
        after: super::types::ProcessAccessState,
    ) -> Result<LinuxCallResult, &'static str> {
        if before.cap_ambient == after.cap_ambient {
            return Ok(LinuxCallResult::Ret(0));
        }
        self.apply_current_credential_transition(
            after,
            CredentialTransitionKind::CapSet {
                bounding: false,
                inheritable: false,
                permitted: false,
                effective: false,
                ambient: true,
                securebits: false,
            },
        )
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

fn capability_bit_from_prctl_arg(cap: u64) -> Result<u64, i32> {
    if cap >= u64::BITS as u64 {
        return Err(ERR_EINVAL);
    }
    let capability = 1u64 << cap;
    if capability & LINUX_KNOWN_CAPS == 0 {
        return Err(ERR_EINVAL);
    }
    Ok(capability)
}

fn errno_ret(errno: i32) -> LinuxCallResult {
    LinuxCallResult::Ret(-(errno as i64))
}

#[cfg(test)]
mod tests {
    use service_core::seccomp::SECCOMP_RET_ALLOW;
    use vmos_abi::{ERR_EACCES, SYS_PRCTL, SyscallContext};

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

    fn cap_arg(capability: u64) -> u64 {
        capability.trailing_zeros() as u64
    }

    fn dispatch_prctl(
        runtime: &mut PrototypeRuntime<'_>,
        args: [u64; 5],
    ) -> Result<LinuxCallResult, &'static str> {
        runtime.dispatch_linux_syscall_raw(
            "test_prctl",
            SyscallContext::new(SYS_PRCTL, [args[0], args[1], args[2], args[3], args[4], 0]),
        )
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

    #[test]
    fn generic_prctl_capability_state_tracks_bounding_securebits_and_ambient() {
        let mut runtime = test_runtime();
        let cap_sys_time = cap_arg(super::super::types::CAP_SYS_TIME);

        let read = dispatch_prctl(&mut runtime, [PR_CAPBSET_READ, cap_sys_time, 0, 0, 0])
            .expect("capbset read");
        assert_eq!(expect_ret(read), 1);

        let drop = dispatch_prctl(&mut runtime, [PR_CAPBSET_DROP, cap_sys_time, 0, 0, 0])
            .expect("capbset drop");
        assert_eq!(expect_ret(drop), 0);
        assert_eq!(
            runtime.current_access_state().cap_bounding & super::super::types::CAP_SYS_TIME,
            0
        );

        let read = dispatch_prctl(&mut runtime, [PR_CAPBSET_READ, cap_sys_time, 0, 0, 0])
            .expect("capbset reread");
        assert_eq!(expect_ret(read), 0);

        let keepcaps =
            dispatch_prctl(&mut runtime, [PR_SET_KEEPCAPS, 1, 0, 0, 0]).expect("set keepcaps");
        assert_eq!(expect_ret(keepcaps), 0);
        let keepcaps =
            dispatch_prctl(&mut runtime, [PR_GET_KEEPCAPS, 0, 0, 0, 0]).expect("get keepcaps");
        assert_eq!(expect_ret(keepcaps), 1);

        let no_ambient_raise = super::super::types::SECBIT_NO_CAP_AMBIENT_RAISE;
        let securebits =
            dispatch_prctl(&mut runtime, [PR_SET_SECUREBITS, no_ambient_raise as u64, 0, 0, 0])
                .expect("set securebits");
        assert_eq!(expect_ret(securebits), 0);
        let securebits =
            dispatch_prctl(&mut runtime, [PR_GET_SECUREBITS, 0, 0, 0, 0]).expect("get securebits");
        assert_eq!(expect_ret(securebits), no_ambient_raise as i64);

        let cap_sys_resource = super::super::types::CAP_SYS_RESOURCE;
        let cap_sys_resource_arg = cap_arg(cap_sys_resource);
        {
            let pid = runtime.current_pid();
            let access = &mut runtime
                .processes
                .iter_mut()
                .find(|process| process.pid == pid)
                .unwrap()
                .access;
            access.cap_inheritable |= cap_sys_resource;
        }
        let denied_raise = dispatch_prctl(
            &mut runtime,
            [PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap_sys_resource_arg, 0, 0],
        )
        .expect("ambient raise denied");
        assert_eq!(expect_ret(denied_raise), -(ERR_EPERM as i64));

        let securebits = dispatch_prctl(&mut runtime, [PR_SET_SECUREBITS, 0, 0, 0, 0])
            .expect("clear securebits");
        assert_eq!(expect_ret(securebits), 0);
        let raise = dispatch_prctl(
            &mut runtime,
            [PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap_sys_resource_arg, 0, 0],
        )
        .expect("ambient raise");
        assert_eq!(expect_ret(raise), 0);
        let is_set = dispatch_prctl(
            &mut runtime,
            [PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, cap_sys_resource_arg, 0, 0],
        )
        .expect("ambient is set");
        assert_eq!(expect_ret(is_set), 1);

        let lower = dispatch_prctl(
            &mut runtime,
            [PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, cap_sys_resource_arg, 0, 0],
        )
        .expect("ambient lower");
        assert_eq!(expect_ret(lower), 0);
        assert_eq!(runtime.current_access_state().cap_ambient & cap_sys_resource, 0);
    }
}
