use alloc::vec::Vec;

use semantic_core::CredentialTransitionKind;
use service_core::seccomp::{
    AUDIT_ARCH_X86_64, LINUX_SECCOMP_NOTIF_ADDFD_SIZE, SECCOMP_ADDFD_FLAG_SEND,
    SECCOMP_ADDFD_FLAG_SETFD, SECCOMP_FILTER_FLAG_LOG, SECCOMP_FILTER_FLAG_NEW_LISTENER,
    SECCOMP_FILTER_FLAG_TSYNC, SECCOMP_IOCTL_NOTIF_ADDFD, SECCOMP_IOCTL_NOTIF_ID_VALID,
    SECCOMP_IOCTL_NOTIF_RECV, SECCOMP_IOCTL_NOTIF_SEND, SECCOMP_USER_NOTIF_FLAG_CONTINUE,
    SeccompDecision, SeccompFilterProgram, SeccompInstruction, linux_seccomp_notif_sizes_bytes,
    seccomp_action_available,
};
use vmos_abi::{
    ERR_EAGAIN, ERR_EBADF, ERR_EFAULT, ERR_EINVAL, ERR_EMFILE, ERR_ENOENT, ERR_ENOSYS,
    ERR_EOPNOTSUPP, ERR_EPERM, ERR_ESRCH,
};

use super::{
    events::Event,
    linux::{LinuxCallResult, LinuxPlan},
    process::{
        access_clear_ambient_capabilities, access_drop_bounding_capability,
        access_lower_ambient_capability, access_raise_ambient_capability, access_set_keepcaps,
        access_set_securebits,
    },
    runtime::PrototypeRuntime,
    types::{
        CAP_SETPCAP, CAP_SYS_ADMIN, FdEntry, FdResource, LINUX_KNOWN_CAPS, SeccompNotification,
        SeccompNotificationCompletion, SeccompNotificationResponse, SeccompNotificationState,
        SeccompTraceCompletion, SeccompTraceEvent, SeccompTraceOutcome, SeccompTraceResponse,
        SeccompTraceState, SeccompUserNotifOutcome, WaitToken,
    },
    wait::WaitRegistration,
};
use crate::interrupts;

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
const MAX_SECCOMP_PENDING_NOTIFICATIONS_PER_LISTENER: usize = 64;
const ERR_ENOTTY: i32 = 25;
const LINUX_O_CLOEXEC: u32 = 0o2000000;
const LINUX_FD_CLOEXEC: u32 = 1;

impl<'engine> PrototypeRuntime<'engine> {
    pub(super) fn apply_generic_seccomp_decision(
        &mut self,
        syscall: u64,
        instruction_pointer: u64,
        args: [u64; 6],
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
            SeccompDecision::Trap { errno } => {
                let syscall_nr = syscall.min(u32::MAX as u64) as u32;
                self.queue_seccomp_trap_to_thread(
                    self.current_tid(),
                    0,
                    syscall_nr,
                    AUDIT_ARCH_X86_64,
                    errno,
                );
                Some(LinuxCallResult::Ret(syscall.min(i64::MAX as u64) as i64))
            }
            SeccompDecision::UserNotif => Some(
                match self.queue_seccomp_user_notification(syscall, instruction_pointer, args) {
                    Ok(token) => LinuxCallResult::Pending(token),
                    Err(errno) => errno_ret(errno),
                },
            ),
            SeccompDecision::Trace { data } => Some(
                match self.queue_seccomp_trace_event(syscall, instruction_pointer, args, data) {
                    Ok(token) => LinuxCallResult::Pending(token),
                    Err(errno) => errno_ret(errno),
                },
            ),
            SeccompDecision::Kill { signal } => {
                crate::kwarn!("generic seccomp killed syscall {}", syscall);
                let status = 128 + signal as i32;
                let pid = self.current_pid();
                self.close_active_fd_table_for_process_exit();
                self.process_exit(pid, status);
                Some(LinuxCallResult::Exit(status))
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

    pub(super) fn plan_ioctl(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let fd = u32::try_from(plan.args[0]).map_err(|_| "ioctl fd overflowed")?;
        let ptr = u32::try_from(plan.args[2]).map_err(|_| "ioctl pointer overflowed")?;
        Ok(match self.seccomp_listener_ioctl(fd, plan.args[1], ptr) {
            Ok(ret) => LinuxCallResult::Ret(ret),
            Err(errno) => errno_ret(errno),
        })
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
                let listener_id = (flags & SECCOMP_FILTER_FLAG_NEW_LISTENER != 0)
                    .then_some(self.next_seccomp_listener_id);
                match self.set_seccomp_filter(
                    self.current_tid(),
                    program,
                    self.current_access_state().cap_effective & CAP_SYS_ADMIN != 0,
                    flags & SECCOMP_FILTER_FLAG_TSYNC != 0,
                    flags & SECCOMP_FILTER_FLAG_LOG != 0,
                    listener_id,
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

    pub(crate) fn next_seccomp_listener_id(&self) -> u64 {
        self.next_seccomp_listener_id
    }

    pub(crate) fn queue_seccomp_user_notification(
        &mut self,
        syscall: u64,
        instruction_pointer: u64,
        args: [u64; 6],
    ) -> Result<WaitToken, i32> {
        let tid = self.current_tid();
        let pid = self.current_pid();
        let listener_id = self
            .threads
            .iter()
            .find(|thread| thread.tid == tid)
            .and_then(|thread| thread.seccomp_user_notif_listener)
            .ok_or(ERR_ENOSYS)?;
        if !self.seccomp_listener_is_open(listener_id) {
            return Err(ERR_ENOSYS);
        }
        let pending_for_listener = self
            .seccomp_notifications
            .iter()
            .filter(|entry| {
                entry.listener_id == listener_id
                    && entry.state != SeccompNotificationState::Responded
            })
            .count();
        if pending_for_listener >= MAX_SECCOMP_PENDING_NOTIFICATIONS_PER_LISTENER {
            return Err(ERR_EAGAIN);
        }
        let notification_id = self.next_seccomp_notification_id;
        self.next_seccomp_notification_id = self.next_seccomp_notification_id.saturating_add(1);
        let token = self.waits.register(
            self.scheduler.current_task(),
            WaitRegistration::SeccompUserNotif { notification_id },
            interrupts::tick_count(),
            interrupts::TIMER_HZ,
        );
        self.record_wait_token(token);
        self.seccomp_notifications.push(SeccompNotification {
            id: notification_id,
            listener_id,
            pid,
            syscall: syscall.min(u32::MAX as u64) as u32,
            instruction_pointer,
            args,
            wait_token_id: token.id,
            response: None,
            state: SeccompNotificationState::Queued,
        });
        Ok(token)
    }

    pub(crate) fn block_on_seccomp_user_notification(
        &mut self,
        syscall: u64,
        instruction_pointer: u64,
        args: [u64; 6],
    ) -> Result<SeccompUserNotifOutcome, i32> {
        let token = self.queue_seccomp_user_notification(syscall, instruction_pointer, args)?;
        match self.block_on_wait("ring3_seccomp_user_notif", token).map_err(|_| ERR_EINVAL)? {
            LinuxCallResult::Ret(ret) => Ok(SeccompUserNotifOutcome::Return(ret)),
            LinuxCallResult::SeccompContinue { .. } => Ok(SeccompUserNotifOutcome::Continue),
            _ => Err(ERR_EINVAL),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn enable_seccomp_trace_listener(&mut self) {
        self.seccomp_trace_listener_enabled = true;
    }

    pub(crate) fn queue_seccomp_trace_event(
        &mut self,
        syscall: u64,
        instruction_pointer: u64,
        args: [u64; 6],
        data: u16,
    ) -> Result<WaitToken, i32> {
        if !self.seccomp_trace_listener_enabled {
            return Err(ERR_ENOSYS);
        }
        let trace_id = self.next_seccomp_trace_id;
        self.next_seccomp_trace_id = self.next_seccomp_trace_id.saturating_add(1);
        let token = self.waits.register(
            self.scheduler.current_task(),
            WaitRegistration::SeccompTrace { trace_id },
            interrupts::tick_count(),
            interrupts::TIMER_HZ,
        );
        self.record_wait_token(token);
        self.seccomp_trace_events.push(SeccompTraceEvent {
            id: trace_id,
            pid: self.current_pid(),
            tid: self.current_tid(),
            syscall: syscall.min(u32::MAX as u64) as u32,
            instruction_pointer,
            args,
            data,
            wait_token_id: token.id,
            response: None,
            state: SeccompTraceState::Queued,
        });
        Ok(token)
    }

    pub(crate) fn block_on_seccomp_trace_event(
        &mut self,
        syscall: u64,
        instruction_pointer: u64,
        args: [u64; 6],
        data: u16,
    ) -> Result<SeccompTraceOutcome, i32> {
        let token = self.queue_seccomp_trace_event(syscall, instruction_pointer, args, data)?;
        match self.block_on_wait("ring3_seccomp_trace", token).map_err(|_| ERR_EINVAL)? {
            LinuxCallResult::Ret(ret) => Ok(SeccompTraceOutcome::Return(ret)),
            LinuxCallResult::SeccompContinue { .. } => Ok(SeccompTraceOutcome::Continue),
            _ => Err(ERR_EINVAL),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn seccomp_trace_continue(&mut self, trace_id: u64) -> Result<(), i32> {
        self.seccomp_trace_respond(trace_id, SeccompTraceResponse::Continue)
    }

    #[allow(dead_code)]
    pub(crate) fn seccomp_trace_return(&mut self, trace_id: u64, ret: i64) -> Result<(), i32> {
        self.seccomp_trace_respond(trace_id, SeccompTraceResponse::Return(ret))
    }

    #[allow(dead_code)]
    fn seccomp_trace_respond(
        &mut self,
        trace_id: u64,
        response: SeccompTraceResponse,
    ) -> Result<(), i32> {
        let Some(event) = self
            .seccomp_trace_events
            .iter_mut()
            .find(|entry| entry.id == trace_id && entry.state == SeccompTraceState::Queued)
        else {
            return Err(ERR_ENOENT);
        };
        event.response = Some(response);
        event.state = SeccompTraceState::Responded;
        let wait_token_id = event.wait_token_id;
        self.scheduler.push_event(Event::WaitReady(wait_token_id));
        self.drain_event_queue();
        Ok(())
    }

    pub(crate) fn take_seccomp_trace_response(
        &mut self,
        trace_id: u64,
    ) -> Result<SeccompTraceCompletion, i32> {
        let index = self
            .seccomp_trace_events
            .iter()
            .position(|entry| entry.id == trace_id && entry.response.is_some())
            .ok_or(ERR_EAGAIN)?;
        let event = self.seccomp_trace_events.remove(index);
        Ok(SeccompTraceCompletion {
            response: event.response.expect("checked response"),
            syscall: event.syscall as u64,
            args: event.args,
        })
    }

    pub(crate) fn cancel_seccomp_trace_event(&mut self, trace_id: u64) -> bool {
        let Some(index) = self
            .seccomp_trace_events
            .iter()
            .position(|entry| entry.id == trace_id && entry.state != SeccompTraceState::Responded)
        else {
            return false;
        };
        self.seccomp_trace_events.remove(index);
        true
    }

    pub(crate) fn cancel_seccomp_listener_notifications(&mut self, listener_id: u64, errno: i32) {
        let mut wait_token_ids = Vec::new();
        for notification in self.seccomp_notifications.iter_mut().filter(|entry| {
            entry.listener_id == listener_id && entry.state != SeccompNotificationState::Responded
        }) {
            notification.response = Some(SeccompNotificationResponse::Return(-(errno as i64)));
            notification.state = SeccompNotificationState::Responded;
            wait_token_ids.push(notification.wait_token_id);
        }
        for wait_token_id in wait_token_ids {
            self.scheduler.push_event(Event::WaitReady(wait_token_id));
        }
        self.drain_event_queue();
    }

    pub(crate) fn cancel_seccomp_notification(&mut self, notification_id: u64) -> bool {
        let Some(index) = self.seccomp_notifications.iter().position(|entry| {
            entry.id == notification_id && entry.state != SeccompNotificationState::Responded
        }) else {
            return false;
        };
        self.seccomp_notifications.remove(index);
        true
    }

    fn seccomp_listener_is_open(&self, listener_id: u64) -> bool {
        self.fd_table.iter().filter_map(Option::as_ref).any(|entry| {
            matches!(entry.resource, FdResource::SeccompListener { listener_id: other } if other == listener_id)
        }) || self.hidden_fd_table_refs.iter().any(|table| {
            table.iter().filter_map(Option::as_ref).any(|entry| {
                matches!(entry.resource, FdResource::SeccompListener { listener_id: other } if other == listener_id)
            })
        })
    }

    pub(crate) fn seccomp_listener_id_for_fd(&mut self, fd: u32) -> Result<u64, i32> {
        self.validate_fd_handle(fd).map_err(|_| ERR_EBADF)?;
        match self.fd_entry(fd).map(|entry| &entry.resource) {
            Some(FdResource::SeccompListener { listener_id }) => Ok(*listener_id),
            Some(_) => Err(ERR_ENOTTY),
            None => Err(ERR_EBADF),
        }
    }

    pub(crate) fn seccomp_listener_recv_notification(
        &mut self,
        fd: u32,
    ) -> Result<(u64, [u8; 80]), i32> {
        let listener_id = self.seccomp_listener_id_for_fd(fd)?;
        let Some(notification) = self.seccomp_notifications.iter().find(|entry| {
            entry.listener_id == listener_id && entry.state == SeccompNotificationState::Queued
        }) else {
            return Err(ERR_EAGAIN);
        };
        Ok((notification.id, encode_seccomp_notification(notification)))
    }

    pub(crate) fn seccomp_listener_mark_notification_delivered(
        &mut self,
        fd: u32,
        notification_id: u64,
    ) -> Result<(), i32> {
        let listener_id = self.seccomp_listener_id_for_fd(fd)?;
        let Some(notification) = self.seccomp_notifications.iter_mut().find(|entry| {
            entry.listener_id == listener_id
                && entry.id == notification_id
                && entry.state == SeccompNotificationState::Queued
        }) else {
            return Err(ERR_ENOENT);
        };
        notification.state = SeccompNotificationState::Delivered;
        Ok(())
    }

    pub(crate) fn seccomp_listener_send_response(
        &mut self,
        fd: u32,
        bytes: &[u8],
    ) -> Result<i64, i32> {
        let listener_id = self.seccomp_listener_id_for_fd(fd)?;
        let id = read_u64_le(bytes, 0)?;
        let val = read_i64_le(bytes, 8)?;
        let error = read_i32_le(bytes, 16)?;
        let flags = read_u32_le(bytes, 20)?;
        if flags & !SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
            return Err(ERR_EINVAL);
        }
        let Some(notification) = self.seccomp_notifications.iter_mut().find(|entry| {
            entry.listener_id == listener_id
                && entry.id == id
                && entry.state == SeccompNotificationState::Delivered
        }) else {
            return Err(ERR_ENOENT);
        };
        let response = if flags & SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
            SeccompNotificationResponse::Continue
        } else if error == 0 {
            SeccompNotificationResponse::Return(val)
        } else if error < 0 {
            SeccompNotificationResponse::Return(error as i64)
        } else {
            SeccompNotificationResponse::Return(-(error as i64))
        };
        notification.response = Some(response);
        notification.state = SeccompNotificationState::Responded;
        let wait_token_id = notification.wait_token_id;
        self.scheduler.push_event(Event::WaitReady(wait_token_id));
        self.drain_event_queue();
        Ok(0)
    }

    pub(crate) fn seccomp_listener_add_fd(&mut self, fd: u32, bytes: &[u8]) -> Result<i64, i32> {
        let listener_id = self.seccomp_listener_id_for_fd(fd)?;
        let id = read_u64_le(bytes, 0)?;
        let flags = read_u32_le(bytes, 8)?;
        let srcfd = read_u32_le(bytes, 12)?;
        let newfd = read_u32_le(bytes, 16)?;
        let newfd_flags = read_u32_le(bytes, 20)?;
        if flags & !(SECCOMP_ADDFD_FLAG_SETFD | SECCOMP_ADDFD_FLAG_SEND) != 0 {
            return Err(ERR_EINVAL);
        }
        if newfd_flags & !LINUX_O_CLOEXEC != 0 {
            return Err(ERR_EINVAL);
        }
        if flags & SECCOMP_ADDFD_FLAG_SETFD != 0 && newfd == fd && srcfd != fd {
            return Err(ERR_EINVAL);
        }
        if !self.seccomp_notifications.iter().any(|entry| {
            entry.listener_id == listener_id
                && entry.id == id
                && entry.state == SeccompNotificationState::Delivered
        }) {
            return Err(ERR_ENOENT);
        }

        let requested_fd = if flags & SECCOMP_ADDFD_FLAG_SETFD != 0 { Some(newfd) } else { None };
        let fd_flags = if newfd_flags & LINUX_O_CLOEXEC != 0 { LINUX_FD_CLOEXEC } else { 0 };
        let installed_fd = self.add_seccomp_notif_fd(srcfd, requested_fd, fd_flags)?;
        if flags & SECCOMP_ADDFD_FLAG_SEND != 0 {
            let Some(notification) = self.seccomp_notifications.iter_mut().find(|entry| {
                entry.listener_id == listener_id
                    && entry.id == id
                    && entry.state == SeccompNotificationState::Delivered
            }) else {
                return Err(ERR_ENOENT);
            };
            notification.response = Some(SeccompNotificationResponse::Return(installed_fd as i64));
            notification.state = SeccompNotificationState::Responded;
            let wait_token_id = notification.wait_token_id;
            self.scheduler.push_event(Event::WaitReady(wait_token_id));
            self.drain_event_queue();
        }
        Ok(installed_fd as i64)
    }

    pub(crate) fn seccomp_listener_id_valid(&mut self, fd: u32, bytes: &[u8]) -> Result<i64, i32> {
        let listener_id = self.seccomp_listener_id_for_fd(fd)?;
        let id = read_u64_le(bytes, 0)?;
        if self.seccomp_notifications.iter().any(|entry| {
            entry.listener_id == listener_id
                && entry.id == id
                && entry.state != SeccompNotificationState::Responded
        }) {
            Ok(0)
        } else {
            Err(ERR_ENOENT)
        }
    }

    pub(crate) fn seccomp_listener_ioctl(
        &mut self,
        fd: u32,
        request: u64,
        ptr: u32,
    ) -> Result<i64, i32> {
        self.seccomp_listener_id_for_fd(fd)?;
        if ptr == 0 {
            return Err(ERR_EFAULT);
        }
        match request {
            SECCOMP_IOCTL_NOTIF_RECV => {
                let (notification_id, bytes) = self.seccomp_listener_recv_notification(fd)?;
                self.linux.write_bytes(ptr, &bytes).map_err(|_| ERR_EFAULT)?;
                self.seccomp_listener_mark_notification_delivered(fd, notification_id)?;
                Ok(0)
            }
            SECCOMP_IOCTL_NOTIF_SEND => {
                let bytes = self.linux.read_bytes(ptr, 24).map_err(|_| ERR_EFAULT)?;
                self.seccomp_listener_send_response(fd, &bytes)
            }
            SECCOMP_IOCTL_NOTIF_ID_VALID => {
                let bytes = self.linux.read_bytes(ptr, 8).map_err(|_| ERR_EFAULT)?;
                self.seccomp_listener_id_valid(fd, &bytes)
            }
            SECCOMP_IOCTL_NOTIF_ADDFD => {
                let bytes = self
                    .linux
                    .read_bytes(ptr, LINUX_SECCOMP_NOTIF_ADDFD_SIZE as u32)
                    .map_err(|_| ERR_EFAULT)?;
                self.seccomp_listener_add_fd(fd, &bytes)
            }
            _ => Err(ERR_ENOTTY),
        }
    }

    pub(crate) fn take_seccomp_notification_response(
        &mut self,
        notification_id: u64,
    ) -> Result<SeccompNotificationCompletion, i32> {
        let index = self
            .seccomp_notifications
            .iter()
            .position(|entry| entry.id == notification_id && entry.response.is_some())
            .ok_or(ERR_EAGAIN)?;
        let notification = self.seccomp_notifications.remove(index);
        Ok(SeccompNotificationCompletion {
            response: notification.response.expect("checked response"),
            syscall: notification.syscall as u64,
            args: notification.args,
        })
    }
}

fn is_supported_seccomp_action(action: u32) -> bool {
    seccomp_action_available(action)
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

fn encode_seccomp_notification(notification: &SeccompNotification) -> [u8; 80] {
    let mut out = [0u8; 80];
    write_u64_le(&mut out, 0, notification.id);
    write_u32_le(&mut out, 8, notification.pid);
    write_u32_le(&mut out, 12, 0);
    write_u32_le(&mut out, 16, notification.syscall);
    write_u32_le(&mut out, 20, AUDIT_ARCH_X86_64);
    write_u64_le(&mut out, 24, notification.instruction_pointer);
    for (index, arg) in notification.args.iter().copied().enumerate() {
        write_u64_le(&mut out, 32 + index * 8, arg);
    }
    out
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Result<u64, i32> {
    let raw = bytes.get(offset..offset + 8).ok_or(ERR_EINVAL)?;
    Ok(u64::from_le_bytes(raw.try_into().map_err(|_| ERR_EINVAL)?))
}

fn read_i64_le(bytes: &[u8], offset: usize) -> Result<i64, i32> {
    let raw = bytes.get(offset..offset + 8).ok_or(ERR_EINVAL)?;
    Ok(i64::from_le_bytes(raw.try_into().map_err(|_| ERR_EINVAL)?))
}

fn read_i32_le(bytes: &[u8], offset: usize) -> Result<i32, i32> {
    let raw = bytes.get(offset..offset + 4).ok_or(ERR_EINVAL)?;
    Ok(i32::from_le_bytes(raw.try_into().map_err(|_| ERR_EINVAL)?))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32, i32> {
    let raw = bytes.get(offset..offset + 4).ok_or(ERR_EINVAL)?;
    Ok(u32::from_le_bytes(raw.try_into().map_err(|_| ERR_EINVAL)?))
}

fn write_u64_le(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn write_u32_le(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use service_core::seccomp::{
        SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO, SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_LOG,
        SECCOMP_RET_TRACE, SECCOMP_RET_TRAP, SECCOMP_RET_USER_NOTIF,
    };
    use vmos_abi::{
        ERR_EACCES, ERR_EINTR, ERR_EINVAL, ERR_ENOSYS, SYS_GETPID, SYS_IOCTL, SYS_PRCTL,
        SyscallContext,
    };

    use super::{
        super::types::{
            ProcessRuntimeStateKind, SeccompAuditAction, SeccompNotificationState,
            ThreadRuntimeStateKind, WaitKind,
        },
        *,
    };
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

    fn expect_exit(result: LinuxCallResult) -> i32 {
        match result {
            LinuxCallResult::Exit(status) => status,
            other => panic!("expected Exit, got {other:?}"),
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
        write_return_filter(runtime, SECCOMP_RET_ALLOW)
    }

    fn write_return_filter(runtime: &mut PrototypeRuntime<'_>, ret: u32) -> u32 {
        const BPF_RET_K: u16 = 0x06;
        let mut seccomp_args = [0u8; 24];
        let (fprog_ptr, _) = runtime.linux.write_arg_bytes(&seccomp_args).expect("seccomp buffer");
        let filter_ptr = fprog_ptr + 16;

        seccomp_args[0..2].copy_from_slice(&1u16.to_le_bytes());
        seccomp_args[8..16].copy_from_slice(&(filter_ptr as u64).to_le_bytes());
        seccomp_args[16..18].copy_from_slice(&BPF_RET_K.to_le_bytes());
        seccomp_args[20..24].copy_from_slice(&ret.to_le_bytes());
        runtime.linux.write_bytes(fprog_ptr, &seccomp_args).expect("seccomp buffer write");
        fprog_ptr
    }

    fn addfd_bytes(id: u64, flags: u32, srcfd: u32, newfd: u32, newfd_flags: u32) -> [u8; 24] {
        let mut bytes = [0u8; 24];
        write_u64_le(&mut bytes, 0, id);
        write_u32_le(&mut bytes, 8, flags);
        write_u32_le(&mut bytes, 12, srcfd);
        write_u32_le(&mut bytes, 16, newfd);
        write_u32_le(&mut bytes, 20, newfd_flags);
        bytes
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
    fn generic_seccomp_log_records_structured_audit_event() {
        let mut runtime = test_runtime();
        runtime.set_no_new_privs(runtime.current_tid(), true);
        let fprog = write_return_filter(&mut runtime, SECCOMP_RET_LOG | 44);
        let install = runtime
            .install_generic_seccomp_mode(SECCOMP_MODE_FILTER, fprog as u64, 0)
            .expect("seccomp log install");
        assert_eq!(expect_ret(install), 0);

        let result = runtime
            .dispatch_linux_syscall_raw(
                "test_seccomp_log_audit",
                SyscallContext::new(SYS_GETPID, [0; 6]),
            )
            .expect("seccomp log dispatch");

        assert_eq!(expect_ret(result), runtime.current_pid() as i64);
        assert_eq!(runtime.seccomp_audit.len(), 1);
        let record = runtime.seccomp_audit[0];
        assert_eq!(record.pid, runtime.current_pid());
        assert_eq!(record.tid, runtime.current_tid());
        assert_eq!(record.syscall, SYS_GETPID);
        assert_eq!(record.action, SeccompAuditAction::Log);
        assert_eq!(record.data, 44);
        assert!(!record.filter_flag);
    }

    #[test]
    fn generic_seccomp_filter_log_flag_records_non_allow_audit_event() {
        let mut runtime = test_runtime();
        runtime.set_no_new_privs(runtime.current_tid(), true);
        let fprog = write_return_filter(&mut runtime, SECCOMP_RET_ERRNO | 13);
        let install = runtime
            .install_generic_seccomp_mode(
                SECCOMP_MODE_FILTER,
                fprog as u64,
                SECCOMP_FILTER_FLAG_LOG,
            )
            .expect("seccomp filter-log install");
        assert_eq!(expect_ret(install), 0);

        let result = runtime
            .dispatch_linux_syscall_raw(
                "test_seccomp_filter_log_audit",
                SyscallContext::new(SYS_GETPID, [0; 6]),
            )
            .expect("seccomp filter-log dispatch");

        assert_eq!(expect_ret(result), -13);
        assert_eq!(runtime.seccomp_audit.len(), 1);
        let record = runtime.seccomp_audit[0];
        assert_eq!(record.pid, runtime.current_pid());
        assert_eq!(record.tid, runtime.current_tid());
        assert_eq!(record.syscall, SYS_GETPID);
        assert_eq!(record.action, SeccompAuditAction::Errno);
        assert_eq!(record.data, 13);
        assert!(record.filter_flag);
    }

    #[test]
    fn generic_seccomp_kill_transitions_current_process() {
        let mut runtime = test_runtime();
        let fd = runtime.create_eventfd(0, 0).expect("eventfd");
        runtime.set_no_new_privs(runtime.current_tid(), true);
        let pid = runtime.current_pid();
        let tid = runtime.current_tid();
        let fprog = write_return_filter(&mut runtime, SECCOMP_RET_KILL_PROCESS);
        let install = runtime
            .install_generic_seccomp_mode(SECCOMP_MODE_FILTER, fprog as u64, 0)
            .expect("seccomp kill install");
        assert_eq!(expect_ret(install), 0);

        let result = runtime
            .dispatch_linux_syscall_raw(
                "test_seccomp_kill_process",
                SyscallContext::new(SYS_GETPID, [0; 6]),
            )
            .expect("seccomp kill dispatch");

        assert_eq!(expect_exit(result), 159);
        let process = runtime.query_process(pid).expect("process");
        assert_eq!(process.state, ProcessRuntimeStateKind::Zombie);
        assert_eq!(process.exit_code, Some(159));
        assert_eq!(runtime.query_thread(tid).expect("thread").state, ThreadRuntimeStateKind::Dead);
        assert!(!runtime.is_eventfd_fd(fd));
    }

    #[test]
    fn generic_seccomp_trace_without_listener_returns_enosys() {
        let mut runtime = test_runtime();
        runtime.set_no_new_privs(runtime.current_tid(), true);
        let fprog = write_return_filter(&mut runtime, SECCOMP_RET_TRACE | 77);
        let install = runtime
            .install_generic_seccomp_mode(SECCOMP_MODE_FILTER, fprog as u64, 0)
            .expect("seccomp trace install");
        assert_eq!(expect_ret(install), 0);

        let result = runtime
            .dispatch_linux_syscall_raw(
                "test_seccomp_trace_no_listener",
                SyscallContext::new(SYS_GETPID, [0; 6]),
            )
            .expect("seccomp trace dispatch");

        assert_eq!(expect_ret(result), -(ERR_ENOSYS as i64));
        assert!(runtime.seccomp_trace_events.is_empty());
    }

    #[test]
    fn generic_seccomp_trace_listener_continue_resumes_original_syscall() {
        let mut runtime = test_runtime();
        runtime.enable_seccomp_trace_listener();
        runtime.set_no_new_privs(runtime.current_tid(), true);
        let fprog = write_return_filter(&mut runtime, SECCOMP_RET_TRACE | 77);
        let install = runtime
            .install_generic_seccomp_mode(SECCOMP_MODE_FILTER, fprog as u64, 0)
            .expect("seccomp trace install");
        assert_eq!(expect_ret(install), 0);

        let pending = runtime
            .dispatch_linux_syscall_raw(
                "test_seccomp_trace_continue",
                SyscallContext::new(SYS_GETPID, [1, 2, 3, 4, 5, 6]),
            )
            .expect("seccomp trace dispatch");
        let token = match pending {
            LinuxCallResult::Pending(token) => token,
            other => panic!("expected pending seccomp trace, got {other:?}"),
        };
        assert_eq!(token.kind, WaitKind::SeccompTrace);
        assert_eq!(runtime.seccomp_trace_events.len(), 1);
        let event = &runtime.seccomp_trace_events[0];
        assert_eq!(event.pid, runtime.current_pid());
        assert_eq!(event.tid, runtime.current_tid());
        assert_eq!(event.syscall, SYS_GETPID as u32);
        assert_eq!(event.args, [1, 2, 3, 4, 5, 6]);
        assert_eq!(event.data, 77);
        let trace_id = event.id;

        runtime.seccomp_trace_continue(trace_id).expect("trace continue");
        let resumed =
            runtime.block_on_wait("test_seccomp_trace_continue_resume", token).expect("resume");
        let (syscall, args) = match resumed {
            LinuxCallResult::SeccompContinue { syscall, args } => (syscall, args),
            other => panic!("expected seccomp trace continue, got {other:?}"),
        };
        assert_eq!(syscall, SYS_GETPID);
        assert_eq!(args, [1, 2, 3, 4, 5, 6]);
        let continued = runtime
            .dispatch_linux_syscall_after_seccomp_continue(
                "test_seccomp_trace_continue_execute",
                SyscallContext::new(syscall, args),
            )
            .expect("continued syscall");
        assert_eq!(expect_ret(continued), runtime.current_pid() as i64);
        assert!(runtime.seccomp_trace_events.is_empty());
    }

    #[test]
    fn generic_seccomp_trace_listener_return_overrides_syscall() {
        let mut runtime = test_runtime();
        runtime.enable_seccomp_trace_listener();
        runtime.set_no_new_privs(runtime.current_tid(), true);
        let fprog = write_return_filter(&mut runtime, SECCOMP_RET_TRACE | 9);
        let install = runtime
            .install_generic_seccomp_mode(SECCOMP_MODE_FILTER, fprog as u64, 0)
            .expect("seccomp trace install");
        assert_eq!(expect_ret(install), 0);

        let pending = runtime
            .dispatch_linux_syscall_raw(
                "test_seccomp_trace_return",
                SyscallContext::new(SYS_GETPID, [0; 6]),
            )
            .expect("seccomp trace dispatch");
        let token = match pending {
            LinuxCallResult::Pending(token) => token,
            other => panic!("expected pending seccomp trace, got {other:?}"),
        };
        let trace_id = runtime.seccomp_trace_events[0].id;

        runtime.seccomp_trace_return(trace_id, 4321).expect("trace return");
        let resumed =
            runtime.block_on_wait("test_seccomp_trace_return_resume", token).expect("resume");
        assert_eq!(expect_ret(resumed), 4321);
        assert!(runtime.seccomp_trace_events.is_empty());
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
    fn generic_ioctl_routes_seccomp_listener_requests() {
        let mut runtime = test_runtime();
        let listener_fd = runtime.create_seccomp_listener_fd().expect("listener fd");
        let (id_ptr, _) = runtime.linux.write_arg_bytes(&1u64.to_le_bytes()).expect("id buffer");

        let result = runtime
            .dispatch_linux_syscall_raw(
                "test_seccomp_listener_ioctl",
                SyscallContext::new(
                    SYS_IOCTL,
                    [listener_fd as u64, SECCOMP_IOCTL_NOTIF_ID_VALID, id_ptr as u64, 0, 0, 0],
                ),
            )
            .expect("listener ioctl dispatch");

        assert_eq!(expect_ret(result), -(ERR_ENOENT as i64));
    }

    #[test]
    fn generic_seccomp_user_notif_addfd_installs_fd_and_keeps_notification_pending() {
        let mut runtime = test_runtime();
        let src_fd = runtime.create_eventfd(0, 0).expect("eventfd source");
        runtime.set_no_new_privs(runtime.current_tid(), true);
        let fprog = write_return_filter(&mut runtime, SECCOMP_RET_USER_NOTIF);
        let install = runtime
            .install_generic_seccomp_mode(
                SECCOMP_MODE_FILTER,
                fprog as u64,
                SECCOMP_FILTER_FLAG_NEW_LISTENER,
            )
            .expect("seccomp user-notif install");
        let listener_fd = expect_ret(install) as u32;
        let pending = runtime
            .dispatch_linux_syscall_raw(
                "test_seccomp_addfd_pending",
                SyscallContext::new(SYS_GETPID, [0; 6]),
            )
            .expect("seccomp user-notif dispatch");
        let token = match pending {
            LinuxCallResult::Pending(token) => token,
            other => panic!("expected pending seccomp notification, got {other:?}"),
        };

        let (notif_ptr, _) =
            runtime.linux.write_arg_bytes(&[0u8; 80]).expect("notification buffer");
        assert_eq!(
            runtime
                .seccomp_listener_ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_RECV, notif_ptr)
                .expect("recv notification"),
            0
        );
        let notif = runtime.linux.read_bytes(notif_ptr, 80).expect("read notification");
        let id = read_u64_le(&notif, 0).expect("notification id");
        let addfd = addfd_bytes(id, SECCOMP_ADDFD_FLAG_SETFD, src_fd, 42, LINUX_O_CLOEXEC);
        let (addfd_ptr, _) = runtime.linux.write_arg_bytes(&addfd).expect("addfd buffer");
        assert_eq!(
            runtime
                .seccomp_listener_ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_ADDFD, addfd_ptr)
                .expect("addfd"),
            42
        );
        assert!(runtime.is_eventfd_fd(src_fd));
        assert!(runtime.is_eventfd_fd(42));
        assert_eq!(runtime.fd_flags(42), Ok(LINUX_FD_CLOEXEC));
        assert_eq!(runtime.seccomp_notifications[0].state, SeccompNotificationState::Delivered);

        let mut response = [0u8; 24];
        response[0..8].copy_from_slice(&id.to_le_bytes());
        response[8..16].copy_from_slice(&5678i64.to_le_bytes());
        let (response_ptr, _) = runtime.linux.write_arg_bytes(&response).expect("response buffer");
        assert_eq!(
            runtime
                .seccomp_listener_ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, response_ptr)
                .expect("send response"),
            0
        );

        let resumed = runtime.block_on_wait("test_seccomp_addfd_resume", token).expect("resume");
        assert_eq!(expect_ret(resumed), 5678);
        assert!(runtime.seccomp_notifications.is_empty());
    }

    #[test]
    fn generic_seccomp_user_notif_addfd_send_wakes_with_added_fd() {
        let mut runtime = test_runtime();
        let src_fd = runtime.create_eventfd(0, 0).expect("eventfd source");
        runtime.set_no_new_privs(runtime.current_tid(), true);
        let fprog = write_return_filter(&mut runtime, SECCOMP_RET_USER_NOTIF);
        let install = runtime
            .install_generic_seccomp_mode(
                SECCOMP_MODE_FILTER,
                fprog as u64,
                SECCOMP_FILTER_FLAG_NEW_LISTENER,
            )
            .expect("seccomp user-notif install");
        let listener_fd = expect_ret(install) as u32;
        let pending = runtime
            .dispatch_linux_syscall_raw(
                "test_seccomp_addfd_send",
                SyscallContext::new(SYS_GETPID, [0; 6]),
            )
            .expect("seccomp user-notif dispatch");
        let token = match pending {
            LinuxCallResult::Pending(token) => token,
            other => panic!("expected pending seccomp notification, got {other:?}"),
        };

        let (notif_ptr, _) =
            runtime.linux.write_arg_bytes(&[0u8; 80]).expect("notification buffer");
        assert_eq!(
            runtime
                .seccomp_listener_ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_RECV, notif_ptr)
                .expect("recv notification"),
            0
        );
        let notif = runtime.linux.read_bytes(notif_ptr, 80).expect("read notification");
        let id = read_u64_le(&notif, 0).expect("notification id");
        let addfd = addfd_bytes(id, SECCOMP_ADDFD_FLAG_SEND, src_fd, 0, 0);
        let (addfd_ptr, _) = runtime.linux.write_arg_bytes(&addfd).expect("addfd buffer");
        let installed_fd = runtime
            .seccomp_listener_ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_ADDFD, addfd_ptr)
            .expect("addfd");
        assert!(installed_fd >= 3);
        assert!(runtime.is_eventfd_fd(installed_fd as u32));
        assert_eq!(runtime.seccomp_notifications[0].state, SeccompNotificationState::Responded);

        let resumed =
            runtime.block_on_wait("test_seccomp_addfd_send_resume", token).expect("resume");
        assert_eq!(expect_ret(resumed), installed_fd);
        assert!(runtime.seccomp_notifications.is_empty());
    }

    #[test]
    fn generic_seccomp_user_notif_addfd_rejects_unknown_flags() {
        let mut runtime = test_runtime();
        let listener_fd = runtime.create_seccomp_listener_fd().expect("listener fd");
        let addfd = addfd_bytes(1, 4, listener_fd, 0, 0);
        let (addfd_ptr, _) = runtime.linux.write_arg_bytes(&addfd).expect("addfd buffer");

        assert_eq!(
            runtime.seccomp_listener_ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_ADDFD, addfd_ptr),
            Err(ERR_EINVAL)
        );

        let addfd = addfd_bytes(1, 0, listener_fd, 0, LINUX_O_CLOEXEC << 1);
        let (addfd_ptr, _) = runtime.linux.write_arg_bytes(&addfd).expect("addfd buffer");
        assert_eq!(
            runtime.seccomp_listener_ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_ADDFD, addfd_ptr),
            Err(ERR_EINVAL)
        );
    }

    #[test]
    fn generic_seccomp_trap_queues_sigsys_metadata() {
        let mut runtime = test_runtime();
        runtime.set_no_new_privs(runtime.current_tid(), true);
        let fprog = write_return_filter(&mut runtime, SECCOMP_RET_TRAP | 77);
        let install = runtime
            .install_generic_seccomp_mode(SECCOMP_MODE_FILTER, fprog as u64, 0)
            .expect("seccomp trap install");
        assert_eq!(expect_ret(install), 0);

        let result = runtime
            .dispatch_linux_syscall_raw(
                "test_seccomp_trap",
                SyscallContext::new(SYS_GETPID, [0, 0, 0, 0, 0, 0]),
            )
            .expect("seccomp trap dispatch");
        assert_eq!(expect_ret(result), SYS_GETPID as i64);

        let current_tid = runtime.current_tid();
        let thread = runtime.query_thread(current_tid).expect("current thread");
        assert_eq!(thread.pending_signals.len(), 1);
        let signal = &thread.pending_signals[0];
        assert_eq!(signal.signo, 31);
        assert_eq!(signal.si_errno, 77);
        assert_eq!(signal.si_code, 1);
        assert_eq!(signal.si_call_addr, 0);
        assert_eq!(signal.si_syscall, SYS_GETPID as u32);
        assert_eq!(signal.si_arch, AUDIT_ARCH_X86_64);
    }

    #[test]
    fn generic_seccomp_user_notif_queues_recv_and_send_response() {
        let mut runtime = test_runtime();
        runtime.set_no_new_privs(runtime.current_tid(), true);
        let fprog = write_return_filter(&mut runtime, SECCOMP_RET_USER_NOTIF);
        let install = runtime
            .install_generic_seccomp_mode(
                SECCOMP_MODE_FILTER,
                fprog as u64,
                SECCOMP_FILTER_FLAG_NEW_LISTENER,
            )
            .expect("seccomp user-notif install");
        let listener_fd = expect_ret(install) as u32;

        let pending = runtime
            .dispatch_linux_syscall_raw(
                "test_seccomp_user_notif",
                SyscallContext::new(SYS_GETPID, [11, 22, 33, 44, 55, 66]),
            )
            .expect("seccomp user-notif dispatch");
        let token = match pending {
            LinuxCallResult::Pending(token) => token,
            other => panic!("expected pending seccomp notification, got {other:?}"),
        };
        assert_eq!(token.kind, WaitKind::SeccompUserNotif);
        assert_eq!(runtime.seccomp_notifications.len(), 1);
        assert_eq!(runtime.seccomp_notifications[0].state, SeccompNotificationState::Queued);

        let (notif_ptr, _) =
            runtime.linux.write_arg_bytes(&[0u8; 80]).expect("notification buffer");
        assert_eq!(
            runtime
                .seccomp_listener_ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_RECV, notif_ptr)
                .expect("recv notification"),
            0
        );
        let notif = runtime.linux.read_bytes(notif_ptr, 80).expect("read notification");
        let id = read_u64_le(&notif, 0).expect("notification id");
        assert_eq!(read_u32_le(&notif, 8).expect("notification pid"), runtime.current_pid());
        assert_eq!(read_u32_le(&notif, 12).expect("notification flags"), 0);
        assert_eq!(read_u32_le(&notif, 16).expect("syscall nr"), SYS_GETPID as u32);
        assert_eq!(read_u32_le(&notif, 20).expect("arch"), AUDIT_ARCH_X86_64);
        assert_eq!(read_u64_le(&notif, 24).expect("ip"), 0);
        assert_eq!(read_u64_le(&notif, 32).expect("arg0"), 11);
        assert_eq!(read_u64_le(&notif, 72).expect("arg5"), 66);
        assert_eq!(runtime.seccomp_notifications[0].state, SeccompNotificationState::Delivered);

        let (id_ptr, _) = runtime.linux.write_arg_bytes(&id.to_le_bytes()).expect("id buffer");
        assert_eq!(
            runtime
                .seccomp_listener_ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, id_ptr)
                .expect("id valid"),
            0
        );

        let mut response = [0u8; 24];
        response[0..8].copy_from_slice(&id.to_le_bytes());
        response[8..16].copy_from_slice(&1234i64.to_le_bytes());
        let (response_ptr, _) = runtime.linux.write_arg_bytes(&response).expect("response buffer");
        assert_eq!(
            runtime
                .seccomp_listener_ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, response_ptr)
                .expect("send response"),
            0
        );

        let resumed =
            runtime.block_on_wait("test_seccomp_user_notif_resume", token).expect("resume");
        assert_eq!(expect_ret(resumed), 1234);
        assert!(runtime.seccomp_notifications.is_empty());
        assert_eq!(
            runtime.seccomp_listener_ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, id_ptr),
            Err(ERR_ENOENT)
        );
    }

    #[test]
    fn generic_seccomp_user_notif_continue_resumes_original_syscall() {
        let mut runtime = test_runtime();
        runtime.set_no_new_privs(runtime.current_tid(), true);
        let fprog = write_return_filter(&mut runtime, SECCOMP_RET_USER_NOTIF);
        let install = runtime
            .install_generic_seccomp_mode(
                SECCOMP_MODE_FILTER,
                fprog as u64,
                SECCOMP_FILTER_FLAG_NEW_LISTENER,
            )
            .expect("seccomp user-notif install");
        let listener_fd = expect_ret(install) as u32;
        let pending = runtime
            .dispatch_linux_syscall_raw(
                "test_seccomp_user_notif_continue",
                SyscallContext::new(SYS_GETPID, [1, 2, 3, 4, 5, 6]),
            )
            .expect("seccomp user-notif dispatch");
        let token = match pending {
            LinuxCallResult::Pending(token) => token,
            other => panic!("expected pending seccomp notification, got {other:?}"),
        };

        let (notif_ptr, _) =
            runtime.linux.write_arg_bytes(&[0u8; 80]).expect("notification buffer");
        assert_eq!(
            runtime
                .seccomp_listener_ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_RECV, notif_ptr)
                .expect("recv notification"),
            0
        );
        let notif = runtime.linux.read_bytes(notif_ptr, 80).expect("read notification");
        let id = read_u64_le(&notif, 0).expect("notification id");
        let mut response = [0u8; 24];
        response[0..8].copy_from_slice(&id.to_le_bytes());
        response[20..24].copy_from_slice(&SECCOMP_USER_NOTIF_FLAG_CONTINUE.to_le_bytes());
        let (response_ptr, _) = runtime.linux.write_arg_bytes(&response).expect("response buffer");
        assert_eq!(
            runtime
                .seccomp_listener_ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, response_ptr)
                .expect("send continue response"),
            0
        );

        let resumed = runtime
            .block_on_wait("test_seccomp_user_notif_continue_resume", token)
            .expect("resume");
        let (syscall, args) = match resumed {
            LinuxCallResult::SeccompContinue { syscall, args } => (syscall, args),
            other => panic!("expected seccomp continue, got {other:?}"),
        };
        assert_eq!(syscall, SYS_GETPID);
        assert_eq!(args, [1, 2, 3, 4, 5, 6]);

        let continued = runtime
            .dispatch_linux_syscall_after_seccomp_continue(
                "test_seccomp_user_notif_continue_execute",
                SyscallContext::new(syscall, args),
            )
            .expect("continued syscall");
        assert_eq!(expect_ret(continued), runtime.current_pid() as i64);
        assert!(runtime.seccomp_notifications.is_empty());
    }

    #[test]
    fn generic_seccomp_user_notif_without_listener_fails_closed() {
        let mut runtime = test_runtime();
        runtime.set_no_new_privs(runtime.current_tid(), true);
        let fprog = write_return_filter(&mut runtime, SECCOMP_RET_USER_NOTIF);
        let install = runtime
            .install_generic_seccomp_mode(SECCOMP_MODE_FILTER, fprog as u64, 0)
            .expect("seccomp user-notif install without listener");
        assert_eq!(expect_ret(install), 0);

        let result = runtime
            .dispatch_linux_syscall_raw(
                "test_seccomp_user_notif_no_listener",
                SyscallContext::new(SYS_GETPID, [0; 6]),
            )
            .expect("seccomp user-notif dispatch without listener");
        assert_eq!(expect_ret(result), -(ERR_ENOSYS as i64));
        assert!(runtime.seccomp_notifications.is_empty());
    }

    #[test]
    fn generic_seccomp_user_notif_listener_close_wakes_pending_syscall() {
        let mut runtime = test_runtime();
        runtime.set_no_new_privs(runtime.current_tid(), true);
        let fprog = write_return_filter(&mut runtime, SECCOMP_RET_USER_NOTIF);
        let install = runtime
            .install_generic_seccomp_mode(
                SECCOMP_MODE_FILTER,
                fprog as u64,
                SECCOMP_FILTER_FLAG_NEW_LISTENER,
            )
            .expect("seccomp user-notif install");
        let listener_fd = expect_ret(install) as u32;
        let pending = runtime
            .dispatch_linux_syscall_raw(
                "test_seccomp_user_notif_close",
                SyscallContext::new(SYS_GETPID, [0; 6]),
            )
            .expect("seccomp user-notif dispatch");
        let token = match pending {
            LinuxCallResult::Pending(token) => token,
            other => panic!("expected pending seccomp notification, got {other:?}"),
        };

        runtime.close_fd_number(listener_fd).expect("close listener");
        let resumed =
            runtime.block_on_wait("test_seccomp_user_notif_close_resume", token).expect("resume");
        assert_eq!(expect_ret(resumed), -(ERR_ENOSYS as i64));
        assert!(runtime.seccomp_notifications.is_empty());

        let result = runtime
            .dispatch_linux_syscall_raw(
                "test_seccomp_user_notif_closed_listener",
                SyscallContext::new(SYS_GETPID, [0; 6]),
            )
            .expect("seccomp user-notif dispatch after listener close");
        assert_eq!(expect_ret(result), -(ERR_ENOSYS as i64));
    }

    #[test]
    fn generic_seccomp_user_notif_cancel_removes_notification() {
        let mut runtime = test_runtime();
        runtime.set_no_new_privs(runtime.current_tid(), true);
        let fprog = write_return_filter(&mut runtime, SECCOMP_RET_USER_NOTIF);
        let install = runtime
            .install_generic_seccomp_mode(
                SECCOMP_MODE_FILTER,
                fprog as u64,
                SECCOMP_FILTER_FLAG_NEW_LISTENER,
            )
            .expect("seccomp user-notif install");
        let listener_fd = expect_ret(install) as u32;
        let pending = runtime
            .dispatch_linux_syscall_raw(
                "test_seccomp_user_notif_cancel",
                SyscallContext::new(SYS_GETPID, [0; 6]),
            )
            .expect("seccomp user-notif dispatch");
        let token = match pending {
            LinuxCallResult::Pending(token) => token,
            other => panic!("expected pending seccomp notification, got {other:?}"),
        };
        assert_eq!(runtime.seccomp_notifications.len(), 1);
        let notification_id = runtime.seccomp_notifications[0].id;

        runtime.scheduler.push_event(Event::WaitCancelled(token.id, ERR_EINTR));
        runtime.drain_event_queue();
        let resumed =
            runtime.block_on_wait("test_seccomp_user_notif_cancel_resume", token).expect("resume");

        assert_eq!(expect_ret(resumed), -(ERR_EINTR as i64));
        assert!(runtime.seccomp_notifications.is_empty());
        let (id_ptr, _) =
            runtime.linux.write_arg_bytes(&notification_id.to_le_bytes()).expect("id buffer");
        assert_eq!(
            runtime.seccomp_listener_ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, id_ptr),
            Err(ERR_ENOENT)
        );
    }

    #[test]
    fn ring3_seccomp_user_notif_wait_is_interruptible_and_cleans_queue() {
        let mut runtime = test_runtime();
        runtime.set_no_new_privs(runtime.current_tid(), true);
        let fprog = write_return_filter(&mut runtime, SECCOMP_RET_USER_NOTIF);
        let install = runtime
            .install_generic_seccomp_mode(
                SECCOMP_MODE_FILTER,
                fprog as u64,
                SECCOMP_FILTER_FLAG_NEW_LISTENER,
            )
            .expect("seccomp user-notif install");
        assert!(expect_ret(install) >= 3);
        let pid = runtime.current_pid();
        let tid = runtime.current_tid();
        runtime.queue_signal_to_thread(tid, 2, 0, pid, 0);

        let ret = runtime
            .block_on_seccomp_user_notification(SYS_GETPID, 0x44, [1, 2, 3, 4, 5, 6])
            .expect("ring3 seccomp wait");

        assert_eq!(ret, SeccompUserNotifOutcome::Return(-(ERR_EINTR as i64)));
        assert!(runtime.seccomp_notifications.is_empty());
    }

    #[test]
    fn generic_seccomp_user_notif_queue_limit_fails_closed() {
        let mut runtime = test_runtime();
        runtime.set_no_new_privs(runtime.current_tid(), true);
        let fprog = write_return_filter(&mut runtime, SECCOMP_RET_USER_NOTIF);
        let install = runtime
            .install_generic_seccomp_mode(
                SECCOMP_MODE_FILTER,
                fprog as u64,
                SECCOMP_FILTER_FLAG_NEW_LISTENER,
            )
            .expect("seccomp user-notif install");
        assert!(expect_ret(install) >= 3);

        let listener_id = 1;
        let pid = runtime.current_pid();
        for index in 0..MAX_SECCOMP_PENDING_NOTIFICATIONS_PER_LISTENER {
            runtime.seccomp_notifications.push(SeccompNotification {
                id: 1_000 + index as u64,
                listener_id,
                pid,
                syscall: SYS_GETPID as u32,
                instruction_pointer: 0,
                args: [0; 6],
                wait_token_id: 10_000 + index as u64,
                response: None,
                state: SeccompNotificationState::Queued,
            });
        }

        let result = runtime
            .dispatch_linux_syscall_raw(
                "test_seccomp_user_notif_queue_limit",
                SyscallContext::new(SYS_GETPID, [0; 6]),
            )
            .expect("seccomp user-notif dispatch at queue limit");
        assert_eq!(expect_ret(result), -(ERR_EAGAIN as i64));
        assert_eq!(
            runtime.seccomp_notifications.len(),
            MAX_SECCOMP_PENDING_NOTIFICATIONS_PER_LISTENER
        );
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
