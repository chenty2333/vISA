use alloc::vec::Vec;

use super::{
    linux::{LinuxCallResult, LinuxPlan},
    runtime::PrototypeRuntime,
    types::{
        PendingSignal, Pid, ProcessRuntimeStateKind, RLIMIT_SIGPENDING, SigAction, SignalAltStack,
        TaskId, ThreadRuntimeStateKind, Tid, UserSignalDelivery,
    },
    wait::WaitRegistration,
};
use crate::{frontends::linux_elf::handle_user_fault, interrupts};

const SA_NODEFER: u64 = 0x4000_0000;
const SA_RESETHAND: u64 = 0x8000_0000;
const LINUX_SIGSET_BYTES: usize = 8;
const LINUX_SIGACTION_BYTES: usize = 32;

#[derive(Clone, Copy)]
enum KillTarget {
    Process(Pid),
    ProcessGroup(Pid),
    CurrentProcessGroup,
    Broadcast,
}

/// Linux signal default actions.
fn signal_default_action(signo: u8) -> SignalDefaultAction {
    match signo {
        // Linux x86_64 default dispositions for standard signals.
        17 | 23 | 28 => SignalDefaultAction::Ignore,
        18 => SignalDefaultAction::Continue,
        19..=22 => SignalDefaultAction::Stop,
        3 | 4 | 5 | 6 | 7 | 8 | 11 | 24 | 25 | 31 => SignalDefaultAction::Terminate { core: true },
        1 | 2 | 9 | 10 | 12 | 13 | 14 | 15 | 16 | 26 | 27 | 29 | 30 => {
            SignalDefaultAction::Terminate { core: false }
        }
        _ => SignalDefaultAction::Terminate { core: false },
    }
}

fn linux_signal_bit(signo: u8) -> u64 {
    if signo == 0 || signo > 64 { 0 } else { 1u64 << (signo - 1) }
}

fn waitable_signal_set(wait_set: u64) -> u64 {
    wait_set & !linux_signal_bit(9) & !linux_signal_bit(19)
}

fn decode_signal_arg(raw: u64) -> Result<u8, i32> {
    if raw >= 64 { Err(visa_abi::ERR_EINVAL) } else { Ok(raw as u8) }
}

fn decode_action_signal_arg(raw: u64) -> Result<u8, i32> {
    let signo = decode_signal_arg(raw)?;
    if signo == 0 { Err(visa_abi::ERR_EINVAL) } else { Ok(signo) }
}

fn decode_positive_u32_arg(raw: u64) -> Result<u32, i32> {
    match u32::try_from(raw) {
        Ok(value) if value != 0 => Ok(value),
        _ => Err(visa_abi::ERR_EINVAL),
    }
}

fn decode_kill_target(raw: u64) -> Result<KillTarget, i32> {
    let pid = raw as i32;
    if raw != pid as i64 as u64 {
        return Err(visa_abi::ERR_EINVAL);
    }
    kill_target_from_pid(pid)
}

fn kill_target_from_pid(pid: i32) -> Result<KillTarget, i32> {
    match pid {
        1..=i32::MAX => Ok(KillTarget::Process(pid as u32)),
        0 => Ok(KillTarget::CurrentProcessGroup),
        -1 => Ok(KillTarget::Broadcast),
        i32::MIN => Err(visa_abi::ERR_EINVAL),
        -2147483647..=-2 => Ok(KillTarget::ProcessGroup(pid.unsigned_abs())),
    }
}

fn checked_linux_ptr(raw: u64) -> Result<u32, i32> {
    u32::try_from(raw).map_err(|_| visa_abi::ERR_EFAULT)
}

fn decode_linux_sigaction(bytes: &[u8]) -> Result<SigAction, i32> {
    if bytes.len() < LINUX_SIGACTION_BYTES {
        return Err(visa_abi::ERR_EFAULT);
    }
    Ok(SigAction {
        handler: u64::from_le_bytes(bytes[0..8].try_into().map_err(|_| visa_abi::ERR_EFAULT)?),
        flags: u64::from_le_bytes(bytes[8..16].try_into().map_err(|_| visa_abi::ERR_EFAULT)?),
        restorer: u64::from_le_bytes(bytes[16..24].try_into().map_err(|_| visa_abi::ERR_EFAULT)?),
        mask: u64::from_le_bytes(bytes[24..32].try_into().map_err(|_| visa_abi::ERR_EFAULT)?),
    })
}

fn encode_linux_sigaction(action: SigAction) -> [u8; LINUX_SIGACTION_BYTES] {
    let mut out = [0u8; LINUX_SIGACTION_BYTES];
    out[0..8].copy_from_slice(&action.handler.to_le_bytes());
    out[8..16].copy_from_slice(&action.flags.to_le_bytes());
    out[16..24].copy_from_slice(&action.restorer.to_le_bytes());
    out[24..32].copy_from_slice(&action.mask.to_le_bytes());
    out
}

fn pending_signal_set(signals: &[PendingSignal]) -> u64 {
    signals.iter().fold(0, |set, signal| set | linux_signal_bit(signal.signo))
}

enum SignalDefaultAction {
    Terminate { core: bool },
    Stop,
    Continue,
    Ignore,
}

impl<'engine> PrototypeRuntime<'engine> {
    /// Queue a signal to a specific thread.
    pub(crate) fn queue_signal_to_thread(
        &mut self,
        tid: Tid,
        signo: u8,
        si_code: i32,
        si_pid: u32,
        si_uid: u32,
    ) {
        if signo == 0 || signo >= 64 {
            return;
        }
        if let Some(thread) = self
            .threads
            .iter_mut()
            .find(|t| t.tid == tid && t.state != ThreadRuntimeStateKind::Dead)
        {
            thread.pending_signals.push(PendingSignal::basic(signo, si_code, si_pid, si_uid));
        }
    }

    pub(crate) fn queue_seccomp_trap_to_thread(
        &mut self,
        tid: Tid,
        call_addr: u64,
        syscall: u32,
        arch: u32,
        errno: u16,
    ) {
        if let Some(thread) = self.threads.iter_mut().find(|t| t.tid == tid) {
            thread
                .pending_signals
                .push(PendingSignal::seccomp_trap(call_addr, syscall, arch, errno));
        }
    }

    /// Queue a signal to all threads in a process.
    pub(crate) fn queue_signal_to_process(
        &mut self,
        pid: Pid,
        signo: u8,
        si_code: i32,
        si_pid: u32,
        si_uid: u32,
    ) {
        if signo == 0 || signo >= 64 {
            return;
        }
        let tids: Vec<Tid> = self.threads.iter().filter(|t| t.pid == pid).map(|t| t.tid).collect();
        for tid in tids {
            self.queue_signal_to_thread(tid, signo, si_code, si_pid, si_uid);
        }
    }

    pub(super) fn plan_kill(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let target = match decode_kill_target(plan.args[0]) {
            Ok(target) => target,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        let signal = match decode_signal_arg(plan.args[1]) {
            Ok(signal) => signal,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        match self.queue_signal_to_kill_target(self.current_pid(), target, signal) {
            Ok(()) => Ok(LinuxCallResult::Ret(0)),
            Err(errno) => Ok(LinuxCallResult::Ret(-(errno as i64))),
        }
    }

    pub(super) fn plan_tgkill(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let tgid = match decode_positive_u32_arg(plan.args[0]) {
            Ok(tgid) => tgid,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        let tid = match decode_positive_u32_arg(plan.args[1]) {
            Ok(tid) => tid,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        let signal = match decode_signal_arg(plan.args[2]) {
            Ok(signal) => signal,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        match self.queue_signal_by_tgkill(self.current_pid(), tgid, tid, signal) {
            Ok(()) => Ok(LinuxCallResult::Ret(0)),
            Err(errno) => Ok(LinuxCallResult::Ret(-(errno as i64))),
        }
    }

    pub(super) fn plan_rt_sigaction(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        let signo = match decode_action_signal_arg(plan.args[0]) {
            Ok(signo) => signo,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        if plan.args[3] != LINUX_SIGSET_BYTES as u64 {
            return Ok(LinuxCallResult::Ret(-(visa_abi::ERR_EINVAL as i64)));
        }

        let pid = self.current_pid();
        let new_action = if plan.args[1] != 0 {
            let act_ptr = match checked_linux_ptr(plan.args[1]) {
                Ok(ptr) => ptr,
                Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
            };
            let bytes = match self.linux.read_bytes(act_ptr, LINUX_SIGACTION_BYTES as u32) {
                Ok(bytes) => bytes,
                Err(_) => return Ok(LinuxCallResult::Ret(-(visa_abi::ERR_EFAULT as i64))),
            };
            match decode_linux_sigaction(&bytes) {
                Ok(action) => Some(action),
                Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
            }
        } else {
            None
        };
        if new_action.is_some() && matches!(signo, 9 | 19) {
            return Ok(LinuxCallResult::Ret(-(visa_abi::ERR_EINVAL as i64)));
        }

        let old = self.get_sigaction(pid, signo).unwrap_or_default();
        if plan.args[2] != 0 {
            let old_ptr = match checked_linux_ptr(plan.args[2]) {
                Ok(ptr) => ptr,
                Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
            };
            if self.linux.write_bytes(old_ptr, &encode_linux_sigaction(old)).is_err() {
                return Ok(LinuxCallResult::Ret(-(visa_abi::ERR_EFAULT as i64)));
            }
        }

        if let Some(action) = new_action {
            if !self.set_sigaction(pid, signo, action) {
                return Ok(LinuxCallResult::Ret(-(visa_abi::ERR_EINVAL as i64)));
            }
        }

        Ok(LinuxCallResult::Ret(0))
    }

    pub(super) fn plan_rt_sigprocmask(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        if plan.args[3] != LINUX_SIGSET_BYTES as u64 {
            return Ok(LinuxCallResult::Ret(-(visa_abi::ERR_EINVAL as i64)));
        }

        let tid = self.current_tid();
        let old_mask = self.get_sigmask(tid).unwrap_or(0);
        if plan.args[2] != 0 {
            let old_ptr = match checked_linux_ptr(plan.args[2]) {
                Ok(ptr) => ptr,
                Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
            };
            if self.linux.write_bytes(old_ptr, &old_mask.to_le_bytes()).is_err() {
                return Ok(LinuxCallResult::Ret(-(visa_abi::ERR_EFAULT as i64)));
            }
        }

        if plan.args[1] != 0 {
            let set_ptr = match checked_linux_ptr(plan.args[1]) {
                Ok(ptr) => ptr,
                Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
            };
            let bytes = match self.linux.read_bytes(set_ptr, LINUX_SIGSET_BYTES as u32) {
                Ok(bytes) => bytes,
                Err(_) => return Ok(LinuxCallResult::Ret(-(visa_abi::ERR_EFAULT as i64))),
            };
            let set = match bytes[..LINUX_SIGSET_BYTES].try_into() {
                Ok(raw) => u64::from_le_bytes(raw),
                Err(_) => return Ok(LinuxCallResult::Ret(-(visa_abi::ERR_EFAULT as i64))),
            };
            let how = match u32::try_from(plan.args[0]) {
                Ok(how) => how,
                Err(_) => return Ok(LinuxCallResult::Ret(-(visa_abi::ERR_EINVAL as i64))),
            };
            if self.set_sigmask(tid, how, set).is_none() {
                return Ok(LinuxCallResult::Ret(-(visa_abi::ERR_EINVAL as i64)));
            }
        }

        Ok(LinuxCallResult::Ret(0))
    }

    pub(super) fn plan_rt_sigpending(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        if plan.args[1] != LINUX_SIGSET_BYTES as u64 {
            return Ok(LinuxCallResult::Ret(-(visa_abi::ERR_EINVAL as i64)));
        }
        let set_ptr = match checked_linux_ptr(plan.args[0]) {
            Ok(ptr) => ptr,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        let pending = match self.blocked_pending_signal_set(self.current_tid()) {
            Some(pending) => pending,
            None => return Ok(LinuxCallResult::Ret(-(visa_abi::ERR_ESRCH as i64))),
        };
        if self.linux.write_bytes(set_ptr, &pending.to_le_bytes()).is_err() {
            return Ok(LinuxCallResult::Ret(-(visa_abi::ERR_EFAULT as i64)));
        }
        Ok(LinuxCallResult::Ret(0))
    }

    pub(crate) fn queue_signal_by_tgkill(
        &mut self,
        sender_pid: Pid,
        tgid: Pid,
        tid: Tid,
        signal: u8,
    ) -> Result<(), i32> {
        if signal >= 64 {
            return Err(visa_abi::ERR_EINVAL);
        }
        let exists = self.threads.iter().any(|thread| {
            thread.pid == tgid && thread.tid == tid && thread.state != ThreadRuntimeStateKind::Dead
        });
        if !exists {
            return Err(visa_abi::ERR_ESRCH);
        }
        if signal == 0 {
            return Ok(());
        }
        self.queue_user_signal_to_threads(sender_pid, &[tid], signal)
    }

    pub(crate) fn queue_signal_by_kill_selector(
        &mut self,
        sender_pid: Pid,
        pid_arg: i32,
        signal: u8,
    ) -> Result<(), i32> {
        if signal >= 64 {
            return Err(visa_abi::ERR_EINVAL);
        }
        let target = kill_target_from_pid(pid_arg)?;
        self.queue_signal_to_kill_target(sender_pid, target, signal)
    }

    fn queue_signal_to_kill_target(
        &mut self,
        sender_pid: Pid,
        target: KillTarget,
        signal: u8,
    ) -> Result<(), i32> {
        let pids = self.kill_target_pids(target)?;
        if signal == 0 {
            return Ok(());
        }
        let tids = self
            .threads
            .iter()
            .filter(|thread| {
                pids.contains(&thread.pid) && thread.state != ThreadRuntimeStateKind::Dead
            })
            .map(|thread| thread.tid)
            .collect::<Vec<_>>();
        self.queue_user_signal_to_threads(sender_pid, &tids, signal)
    }

    fn kill_target_pids(&self, target: KillTarget) -> Result<Vec<Pid>, i32> {
        let pids: Vec<Pid> = match target {
            KillTarget::Process(pid) => self
                .processes
                .iter()
                .filter(|process| {
                    process.pid == pid && process.state != ProcessRuntimeStateKind::Dead
                })
                .map(|process| process.pid)
                .collect(),
            KillTarget::CurrentProcessGroup => {
                let Some(pgid) = self.query_process(self.current_pid()).map(|process| process.pgid)
                else {
                    return Err(visa_abi::ERR_ESRCH);
                };
                self.processes
                    .iter()
                    .filter(|process| {
                        process.pgid == pgid && process.state != ProcessRuntimeStateKind::Dead
                    })
                    .map(|process| process.pid)
                    .collect()
            }
            KillTarget::ProcessGroup(pgid) => self
                .processes
                .iter()
                .filter(|process| {
                    process.pgid == pgid && process.state != ProcessRuntimeStateKind::Dead
                })
                .map(|process| process.pid)
                .collect(),
            KillTarget::Broadcast => return Err(visa_abi::ERR_ENOSYS),
        };
        if pids.is_empty() { Err(visa_abi::ERR_ESRCH) } else { Ok(pids) }
    }

    fn queue_user_signal_to_threads(
        &mut self,
        sender_pid: Pid,
        tids: &[Tid],
        signal: u8,
    ) -> Result<(), i32> {
        let additions = u64::try_from(tids.len()).unwrap_or(u64::MAX);
        let sender_uid = self.check_user_signal_pending_limit(sender_pid, additions)?;
        for tid in tids {
            self.queue_signal_to_thread(*tid, signal, 0, sender_pid, sender_uid);
        }
        Ok(())
    }

    fn check_user_signal_pending_limit(&self, sender_pid: Pid, additions: u64) -> Result<u32, i32> {
        let Some(sender) = self.processes.iter().find(|process| {
            process.pid == sender_pid && process.state != ProcessRuntimeStateKind::Dead
        }) else {
            return Err(visa_abi::ERR_ESRCH);
        };
        let sender_uid = sender.access.real_uid;
        let limit = sender.rlimits[RLIMIT_SIGPENDING].cur;
        if limit != u64::MAX {
            let queued = self.pending_signal_count_for_uid(sender_uid);
            if queued.saturating_add(additions) > limit {
                return Err(visa_abi::ERR_EAGAIN);
            }
        }
        Ok(sender_uid)
    }

    fn pending_signal_count_for_uid(&self, real_uid: u32) -> u64 {
        self.threads
            .iter()
            .flat_map(|thread| thread.pending_signals.iter())
            .filter(|signal| signal.si_uid == real_uid)
            .count()
            .try_into()
            .unwrap_or(u64::MAX)
    }

    /// Check and deliver pending signals for the current thread.
    /// Called before returning to userspace (after syscall processing).
    /// Returns true if a signal was delivered (caller must re-check registers).
    pub(crate) fn deliver_pending_signals(&mut self, tid: Tid) -> bool {
        let current_pid = self.threads.iter().find(|t| t.tid == tid).map(|t| t.pid).unwrap_or(1);

        // Collect eligible pending signals
        let sigmask = self.threads.iter().find(|t| t.tid == tid).map(|t| t.sigmask).unwrap_or(0);

        let pending: Vec<PendingSignal> = self
            .threads
            .iter()
            .find(|t| t.tid == tid)
            .map(|t| {
                t.pending_signals
                    .iter()
                    .filter(|s| sigmask & linux_signal_bit(s.signo) == 0)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();

        if pending.is_empty() {
            return false;
        }

        // Take the first unblocked signal
        let signal = pending[0].clone();
        let signo = signal.signo;

        // Remove from queue
        if let Some(thread) = self.threads.iter_mut().find(|t| t.tid == tid) {
            if let Some(index) = thread.pending_signals.iter().position(|s| s.signo == signo) {
                thread.pending_signals.remove(index);
            }
            if let Some(restore_mask) = thread.sigsuspend_restore_mask.take() {
                thread.sigmask = restore_mask;
            }
        }

        // Look up disposition
        let disposition = self
            .processes
            .iter()
            .find(|p| p.pid == current_pid)
            .map(|p| p.sigactions[signo as usize])
            .unwrap_or_default();

        match disposition.handler {
            0 => {
                // SIG_DFL
                match signal_default_action(signo) {
                    SignalDefaultAction::Terminate { .. } => {
                        self.process_exit(current_pid, 128 + signo as i32);
                        handle_user_fault(signo);
                    }
                    SignalDefaultAction::Stop => {
                        if let Some(thread) = self.threads.iter_mut().find(|t| t.tid == tid) {
                            thread.state = ThreadRuntimeStateKind::Stopped;
                        }
                    }
                    SignalDefaultAction::Continue => {
                        if let Some(thread) = self.threads.iter_mut().find(|t| t.tid == tid) {
                            if thread.state == ThreadRuntimeStateKind::Stopped {
                                thread.state = ThreadRuntimeStateKind::Running;
                            }
                        }
                    }
                    SignalDefaultAction::Ignore => {}
                }
            }
            1 => {
                // SIG_IGN: discard
            }
            _ => {
                // Handler at VA — user-space signal delivery not yet implemented.
                // For now, treat as SIG_DFL.
                match signal_default_action(signo) {
                    SignalDefaultAction::Terminate { .. } => {
                        self.process_exit(current_pid, 128 + signo as i32);
                        handle_user_fault(signo);
                    }
                    _ => {}
                }
            }
        }

        true
    }

    pub(crate) fn take_pending_user_handler_signal(
        &mut self,
        tid: Tid,
    ) -> Option<UserSignalDelivery> {
        let thread_index = self.threads.iter().position(|thread| thread.tid == tid)?;
        let pid = self.threads[thread_index].pid;
        let current_sigmask = self.threads[thread_index].sigmask;
        let pending_index = self.threads[thread_index]
            .pending_signals
            .iter()
            .position(|signal| current_sigmask & linux_signal_bit(signal.signo) == 0)?;
        let signal = self.threads[thread_index].pending_signals[pending_index].clone();
        let action = self
            .processes
            .iter()
            .find(|process| process.pid == pid)
            .map(|process| process.sigactions[signal.signo as usize])
            .unwrap_or_default();
        if action.handler == 0 || action.handler == 1 {
            return None;
        }

        let signal = self.threads[thread_index].pending_signals.remove(pending_index);
        let old_sigmask =
            self.threads[thread_index].sigsuspend_restore_mask.take().unwrap_or(current_sigmask);
        let mut next_mask =
            old_sigmask | (action.mask & !linux_signal_bit(9) & !linux_signal_bit(19));
        if action.flags & SA_NODEFER == 0 {
            next_mask |= linux_signal_bit(signal.signo);
        }
        self.threads[thread_index].sigmask = next_mask;
        if action.flags & SA_RESETHAND != 0 {
            let _ = self.set_sigaction(pid, signal.signo, SigAction::default());
        }

        Some(UserSignalDelivery { signal, action, old_sigmask })
    }

    pub(crate) fn has_unblocked_pending_signal_for_task(&self, task_id: TaskId) -> bool {
        self.threads.iter().find(|thread| thread.task_id == task_id).is_some_and(|thread| {
            let pid = thread.pid;
            thread.pending_signals.iter().any(|signal| {
                thread.sigmask & linux_signal_bit(signal.signo) == 0
                    && self.signal_interrupts_wait(pid, signal.signo)
            })
        })
    }

    pub(crate) fn has_pending_signal_matching_set_for_task(
        &self,
        task_id: TaskId,
        wait_set: u64,
    ) -> bool {
        let wait_set = waitable_signal_set(wait_set);
        if wait_set == 0 {
            return false;
        }
        self.threads.iter().find(|thread| thread.task_id == task_id).is_some_and(|thread| {
            thread
                .pending_signals
                .iter()
                .any(|signal| wait_set & linux_signal_bit(signal.signo) != 0)
        })
    }

    pub(crate) fn take_pending_signal_matching_set(
        &mut self,
        tid: Tid,
        wait_set: u64,
    ) -> Option<PendingSignal> {
        let wait_set = waitable_signal_set(wait_set);
        if wait_set == 0 {
            return None;
        }
        let thread = self.threads.iter_mut().find(|thread| thread.tid == tid)?;
        let index = thread
            .pending_signals
            .iter()
            .position(|signal| wait_set & linux_signal_bit(signal.signo) != 0)?;
        Some(thread.pending_signals.remove(index))
    }

    pub(crate) fn block_on_signal_wait(&mut self) -> Result<(), i32> {
        let token = self.waits.register(
            self.scheduler.current_task(),
            WaitRegistration::Signal,
            interrupts::tick_count(),
            interrupts::TIMER_HZ,
        );
        self.record_wait_token(token);
        match self.block_on_wait("ring3_pause", token).map_err(|_| visa_abi::ERR_EINVAL)? {
            LinuxCallResult::Ret(ret) if ret < 0 => Err((-ret) as i32),
            LinuxCallResult::Ret(_) => Err(visa_abi::ERR_EINTR),
            _ => Err(visa_abi::ERR_EINVAL),
        }
    }

    pub(crate) fn begin_sigsuspend(&mut self, tid: Tid, set: u64) -> Option<u64> {
        let thread = self.threads.iter_mut().find(|thread| thread.tid == tid)?;
        let old = thread.sigmask;
        thread.sigmask = waitable_signal_set(set);
        thread.sigsuspend_restore_mask = Some(old);
        Some(old)
    }

    pub(crate) fn cancel_sigsuspend(&mut self, tid: Tid) -> Option<u64> {
        let thread = self.threads.iter_mut().find(|thread| thread.tid == tid)?;
        let restore_mask = thread.sigsuspend_restore_mask.take()?;
        thread.sigmask = restore_mask;
        Some(restore_mask)
    }

    pub(crate) fn block_on_signal_set_wait(
        &mut self,
        wait_set: u64,
        timeout_ms: Option<u32>,
    ) -> Result<(), i32> {
        let token = self.waits.register(
            self.scheduler.current_task(),
            WaitRegistration::SignalSet { wait_set: waitable_signal_set(wait_set), timeout_ms },
            interrupts::tick_count(),
            interrupts::TIMER_HZ,
        );
        self.record_wait_token(token);
        match self
            .block_on_wait("ring3_rt_sigtimedwait", token)
            .map_err(|_| visa_abi::ERR_EINVAL)?
        {
            LinuxCallResult::Ret(ret) if ret < 0 => Err((-ret) as i32),
            LinuxCallResult::Ret(_) => Ok(()),
            _ => Err(visa_abi::ERR_EINVAL),
        }
    }

    fn signal_interrupts_wait(&self, pid: Pid, signo: u8) -> bool {
        if signo == 0 || signo >= 64 {
            return false;
        }
        let action = self
            .processes
            .iter()
            .find(|process| process.pid == pid)
            .map(|process| process.sigactions[signo as usize])
            .unwrap_or_default();
        match action.handler {
            1 => false,
            0 => !matches!(signal_default_action(signo), SignalDefaultAction::Ignore),
            _ => true,
        }
    }

    /// Set signal action for a process.
    pub(crate) fn set_sigaction(&mut self, pid: Pid, signo: u8, action: SigAction) -> bool {
        if signo == 0 || signo >= 64 {
            return false;
        }
        // SIGKILL and SIGSTOP dispositions may be queried but cannot be changed.
        if signo == 9 || signo == 19 {
            return false;
        }
        if let Some(proc) = self.processes.iter_mut().find(|p| p.pid == pid) {
            proc.sigactions[signo as usize] = action;
            true
        } else {
            false
        }
    }

    /// Get signal action for a process.
    pub(crate) fn get_sigaction(&self, pid: Pid, signo: u8) -> Option<SigAction> {
        if signo == 0 || signo >= 64 {
            return None;
        }
        self.processes.iter().find(|p| p.pid == pid).map(|p| p.sigactions[signo as usize])
    }

    /// Set signal mask for a thread.
    pub(crate) fn set_sigmask(&mut self, tid: Tid, how: u32, set: u64) -> Option<u64> {
        let thread = self.threads.iter_mut().find(|t| t.tid == tid)?;
        let old = thread.sigmask;
        let set = set & !(linux_signal_bit(9) | linux_signal_bit(19));
        match how {
            0 => thread.sigmask |= set,  // SIG_BLOCK
            1 => thread.sigmask &= !set, // SIG_UNBLOCK
            2 => thread.sigmask = set,   // SIG_SETMASK
            _ => return None,
        }
        Some(old)
    }

    /// Get signal mask for a thread.
    pub(crate) fn get_sigmask(&self, tid: Tid) -> Option<u64> {
        self.threads.iter().find(|t| t.tid == tid).map(|t| t.sigmask)
    }

    pub(crate) fn blocked_pending_signal_set(&self, tid: Tid) -> Option<u64> {
        let thread = self.threads.iter().find(|t| t.tid == tid)?;
        Some(pending_signal_set(&thread.pending_signals) & thread.sigmask)
    }

    pub(crate) fn signal_alt_stack(&self, tid: Tid) -> Option<SignalAltStack> {
        self.threads.iter().find(|t| t.tid == tid).map(|t| t.sigaltstack)
    }

    pub(crate) fn set_signal_alt_stack(
        &mut self,
        tid: Tid,
        stack: SignalAltStack,
    ) -> Option<SignalAltStack> {
        let thread = self.threads.iter_mut().find(|t| t.tid == tid)?;
        let old = thread.sigaltstack;
        thread.sigaltstack = stack;
        Some(old)
    }

    pub(crate) fn signal_alt_stack_for_delivery(
        &self,
        tid: Tid,
        current_rsp: u64,
    ) -> Option<SignalAltStack> {
        let stack = self.signal_alt_stack(tid)?;
        if stack.is_disabled() || stack.contains(current_rsp) { None } else { Some(stack) }
    }

    pub(crate) fn reset_signal_state_for_exec(&mut self, pid: Pid, tid: Tid) -> bool {
        let Some(process) = self.processes.iter_mut().find(|process| process.pid == pid) else {
            return false;
        };
        for action in &mut process.sigactions {
            if action.handler != 1 {
                *action = SigAction::default();
            }
        }

        let Some(thread) = self.threads.iter_mut().find(|thread| thread.tid == tid) else {
            return false;
        };
        thread.sigaltstack = SignalAltStack::default();
        thread.sigsuspend_restore_mask = None;
        thread.robust_list = None;
        thread.rseq = None;
        true
    }
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;

    use visa_abi::{
        ERR_EAGAIN, ERR_EINVAL, ERR_ENOSYS, ERR_ESRCH, SYS_KILL, SYS_RT_SIGACTION,
        SYS_RT_SIGPENDING, SYS_RT_SIGPROCMASK, SYS_TGKILL, SyscallContext,
    };

    use super::*;
    use crate::supervisor::{engine::RuntimeOnlyExecutor, types::Rlimit};

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

    #[test]
    fn pending_signal_set_ignores_invalid_signal_numbers() {
        let signals = alloc::vec![
            PendingSignal::basic(2, 0, 0, 0),
            PendingSignal::basic(31, 0, 0, 0),
            PendingSignal::basic(0, 0, 0, 0),
            PendingSignal::basic(65, 0, 0, 0),
        ];

        assert_eq!(pending_signal_set(&signals), linux_signal_bit(2) | linux_signal_bit(31));
    }

    #[test]
    fn waitable_signal_set_removes_kill_and_stop() {
        let set = linux_signal_bit(2) | linux_signal_bit(9) | linux_signal_bit(19);

        assert_eq!(waitable_signal_set(set), linux_signal_bit(2));
    }

    #[test]
    fn reset_hand_handler_resets_disposition_when_taken() {
        let mut runtime = test_runtime();
        let pid = runtime.current_pid();
        let tid = runtime.current_tid();
        let action = SigAction {
            handler: 0x4000,
            flags: SA_RESETHAND,
            restorer: 0x5000,
            mask: linux_signal_bit(3),
        };
        assert!(runtime.set_sigaction(pid, 2, action));
        runtime.queue_signal_to_thread(tid, 2, 0, pid, 0);

        let delivery = runtime.take_pending_user_handler_signal(tid).expect("handler delivery");
        assert_eq!(delivery.signal.signo, 2);
        assert_eq!(delivery.action, action);
        assert_eq!(runtime.get_sigaction(pid, 2), Some(SigAction::default()));
        let thread = runtime.query_thread(tid).expect("thread");
        assert_eq!(thread.sigmask, linux_signal_bit(2) | linux_signal_bit(3));
        assert!(thread.pending_signals.is_empty());
    }

    #[test]
    fn generic_kill_queues_signal_and_checks_process_existence() {
        let mut runtime = test_runtime();
        let pid = runtime.current_pid();
        let tid = runtime.current_tid();

        let exists = runtime
            .dispatch_linux_syscall_raw(
                "test_kill_zero",
                SyscallContext::new(SYS_KILL, [pid as u64, 0, 0, 0, 0, 0]),
            )
            .expect("kill zero dispatch");
        assert_eq!(expect_ret(exists), 0);
        assert!(runtime.query_thread(tid).unwrap().pending_signals.is_empty());

        let queued = runtime
            .dispatch_linux_syscall_raw(
                "test_kill",
                SyscallContext::new(SYS_KILL, [pid as u64, 10, 0, 0, 0, 0]),
            )
            .expect("kill dispatch");
        assert_eq!(expect_ret(queued), 0);
        let pending = &runtime.query_thread(tid).unwrap().pending_signals;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].signo, 10);
        assert_eq!(pending[0].si_pid, pid);

        let missing = runtime
            .dispatch_linux_syscall_raw(
                "test_kill_missing",
                SyscallContext::new(SYS_KILL, [99_999, 10, 0, 0, 0, 0]),
            )
            .expect("missing kill dispatch");
        assert_eq!(expect_ret(missing), -(ERR_ESRCH as i64));

        let invalid = runtime
            .dispatch_linux_syscall_raw(
                "test_kill_invalid_signal",
                SyscallContext::new(SYS_KILL, [pid as u64, 64, 0, 0, 0, 0]),
            )
            .expect("invalid signal kill dispatch");
        assert_eq!(expect_ret(invalid), -(ERR_EINVAL as i64));
    }

    #[test]
    fn generic_kill_current_process_group_targets_live_group_members() {
        let mut runtime = test_runtime();
        let parent_pid = runtime.current_pid();
        let parent_tid = runtime.current_tid();
        let child_pid = runtime.allocate_process(parent_pid, parent_pid, parent_pid);
        let child_task = runtime.allocate_task();
        let child_tid = runtime.allocate_thread(child_task, child_pid);

        let queued = runtime
            .dispatch_linux_syscall_raw(
                "test_kill_pgrp",
                SyscallContext::new(SYS_KILL, [0, 15, 0, 0, 0, 0]),
            )
            .expect("kill process group dispatch");
        assert_eq!(expect_ret(queued), 0);

        let parent_pending = &runtime.query_thread(parent_tid).unwrap().pending_signals;
        assert_eq!(parent_pending.len(), 1);
        assert_eq!(parent_pending[0].signo, 15);
        let child_pending = &runtime.query_thread(child_tid).unwrap().pending_signals;
        assert_eq!(child_pending.len(), 1);
        assert_eq!(child_pending[0].signo, 15);
    }

    #[test]
    fn generic_rt_sigaction_updates_and_reports_disposition() {
        let mut runtime = test_runtime();
        let pid = runtime.current_pid();
        let new_action =
            SigAction { handler: 0x4000, flags: 0x0400_0004, restorer: 0x5000, mask: 0x22 };
        let mut buffer = alloc::vec![0u8; LINUX_SIGACTION_BYTES * 2];
        buffer[0..LINUX_SIGACTION_BYTES].copy_from_slice(&encode_linux_sigaction(new_action));
        let (base, _) = runtime.linux.write_arg_bytes(&buffer).expect("arg buffer");
        let old_ptr = base + LINUX_SIGACTION_BYTES as u32;

        let installed = runtime
            .dispatch_linux_syscall_raw(
                "test_rt_sigaction",
                SyscallContext::new(
                    SYS_RT_SIGACTION,
                    [2, base as u64, old_ptr as u64, LINUX_SIGSET_BYTES as u64, 0, 0],
                ),
            )
            .expect("rt_sigaction dispatch");
        assert_eq!(expect_ret(installed), 0);
        assert_eq!(runtime.get_sigaction(pid, 2), Some(new_action));
        let old = runtime
            .linux
            .read_bytes(old_ptr, LINUX_SIGACTION_BYTES as u32)
            .expect("old action writeback");
        assert_eq!(decode_linux_sigaction(&old), Ok(SigAction::default()));

        let mut old_only = alloc::vec![0u8; LINUX_SIGACTION_BYTES];
        let (old_only_ptr, _) = runtime.linux.write_arg_bytes(&old_only).expect("arg buffer");
        let queried = runtime
            .dispatch_linux_syscall_raw(
                "test_rt_sigaction_old",
                SyscallContext::new(
                    SYS_RT_SIGACTION,
                    [2, 0, old_only_ptr as u64, LINUX_SIGSET_BYTES as u64, 0, 0],
                ),
            )
            .expect("rt_sigaction old dispatch");
        assert_eq!(expect_ret(queried), 0);
        old_only = runtime
            .linux
            .read_bytes(old_only_ptr, LINUX_SIGACTION_BYTES as u32)
            .expect("old action query");
        assert_eq!(decode_linux_sigaction(&old_only), Ok(new_action));

        let rejected = runtime
            .dispatch_linux_syscall_raw(
                "test_rt_sigaction_sigkill",
                SyscallContext::new(
                    SYS_RT_SIGACTION,
                    [9, base as u64, 0, LINUX_SIGSET_BYTES as u64, 0, 0],
                ),
            )
            .expect("rt_sigaction SIGKILL dispatch");
        assert_eq!(expect_ret(rejected), -(ERR_EINVAL as i64));
    }

    #[test]
    fn generic_rt_sigprocmask_updates_mask_and_reports_old_value() {
        let mut runtime = test_runtime();
        let tid = runtime.current_tid();
        let requested = linux_signal_bit(2) | linux_signal_bit(9) | linux_signal_bit(19);
        let mut buffer = alloc::vec![0u8; LINUX_SIGSET_BYTES * 2];
        buffer[0..LINUX_SIGSET_BYTES].copy_from_slice(&requested.to_le_bytes());
        let (base, _) = runtime.linux.write_arg_bytes(&buffer).expect("arg buffer");
        let old_ptr = base + LINUX_SIGSET_BYTES as u32;

        let blocked = runtime
            .dispatch_linux_syscall_raw(
                "test_rt_sigprocmask",
                SyscallContext::new(
                    SYS_RT_SIGPROCMASK,
                    [0, base as u64, old_ptr as u64, LINUX_SIGSET_BYTES as u64, 0, 0],
                ),
            )
            .expect("rt_sigprocmask dispatch");
        assert_eq!(expect_ret(blocked), 0);
        assert_eq!(runtime.get_sigmask(tid), Some(linux_signal_bit(2)));
        let old = runtime.linux.read_bytes(old_ptr, LINUX_SIGSET_BYTES as u32).expect("old mask");
        assert_eq!(u64::from_le_bytes(old[..8].try_into().unwrap()), 0);

        let invalid = runtime
            .dispatch_linux_syscall_raw(
                "test_rt_sigprocmask_bad_size",
                SyscallContext::new(SYS_RT_SIGPROCMASK, [0, 0, 0, 4, 0, 0]),
            )
            .expect("invalid rt_sigprocmask dispatch");
        assert_eq!(expect_ret(invalid), -(ERR_EINVAL as i64));
    }

    #[test]
    fn generic_rt_sigpending_reports_blocked_pending_signals() {
        let mut runtime = test_runtime();
        let pid = runtime.current_pid();
        let tid = runtime.current_tid();
        let requested = linux_signal_bit(2);
        let mut buffer = alloc::vec![0u8; LINUX_SIGSET_BYTES * 2];
        buffer[0..LINUX_SIGSET_BYTES].copy_from_slice(&requested.to_le_bytes());
        let (base, _) = runtime.linux.write_arg_bytes(&buffer).expect("arg buffer");
        let pending_ptr = base + LINUX_SIGSET_BYTES as u32;

        let blocked = runtime
            .dispatch_linux_syscall_raw(
                "test_rt_sigpending_mask",
                SyscallContext::new(
                    SYS_RT_SIGPROCMASK,
                    [0, base as u64, 0, LINUX_SIGSET_BYTES as u64, 0, 0],
                ),
            )
            .expect("rt_sigprocmask dispatch");
        assert_eq!(expect_ret(blocked), 0);
        runtime.queue_signal_to_thread(tid, 2, 0, pid, 0);
        runtime.queue_signal_to_thread(tid, 3, 0, pid, 0);

        let pending = runtime
            .dispatch_linux_syscall_raw(
                "test_rt_sigpending",
                SyscallContext::new(
                    SYS_RT_SIGPENDING,
                    [pending_ptr as u64, LINUX_SIGSET_BYTES as u64, 0, 0, 0, 0],
                ),
            )
            .expect("rt_sigpending dispatch");
        assert_eq!(expect_ret(pending), 0);
        let bytes =
            runtime.linux.read_bytes(pending_ptr, LINUX_SIGSET_BYTES as u32).expect("pending set");
        assert_eq!(u64::from_le_bytes(bytes[..8].try_into().unwrap()), linux_signal_bit(2));

        let invalid = runtime
            .dispatch_linux_syscall_raw(
                "test_rt_sigpending_bad_size",
                SyscallContext::new(SYS_RT_SIGPENDING, [pending_ptr as u64, 4, 0, 0, 0, 0]),
            )
            .expect("invalid rt_sigpending dispatch");
        assert_eq!(expect_ret(invalid), -(ERR_EINVAL as i64));
    }

    #[test]
    fn generic_tgkill_targets_thread_and_rejects_broadcast_kill() {
        let mut runtime = test_runtime();
        let pid = runtime.current_pid();
        let tid = runtime.current_tid();

        let queued = runtime
            .dispatch_linux_syscall_raw(
                "test_tgkill",
                SyscallContext::new(SYS_TGKILL, [pid as u64, tid as u64, 12, 0, 0, 0]),
            )
            .expect("tgkill dispatch");
        assert_eq!(expect_ret(queued), 0);
        let pending = &runtime.query_thread(tid).unwrap().pending_signals;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].signo, 12);
        assert_eq!(pending[0].si_pid, pid);

        let unsupported = runtime
            .dispatch_linux_syscall_raw(
                "test_kill_broadcast",
                SyscallContext::new(SYS_KILL, [-1i64 as u64, 12, 0, 0, 0, 0]),
            )
            .expect("broadcast kill dispatch");
        assert_eq!(expect_ret(unsupported), -(ERR_ENOSYS as i64));

        let invalid = runtime
            .dispatch_linux_syscall_raw(
                "test_tgkill_invalid_signal",
                SyscallContext::new(SYS_TGKILL, [pid as u64, tid as u64, 64, 0, 0, 0]),
            )
            .expect("invalid signal tgkill dispatch");
        assert_eq!(expect_ret(invalid), -(ERR_EINVAL as i64));
    }

    #[test]
    fn generic_signal_queue_honors_rlimit_sigpending_for_sender_uid() {
        let mut runtime = test_runtime();
        let pid = runtime.current_pid();
        let tid = runtime.current_tid();
        let process = runtime
            .processes
            .iter_mut()
            .find(|process| process.pid == pid)
            .expect("current process");
        process.access.real_uid = 1000;
        assert!(runtime.set_rlimit(pid, RLIMIT_SIGPENDING, Rlimit { cur: 1, max: 1 }));

        let first = runtime
            .dispatch_linux_syscall_raw(
                "test_tgkill_rlimit_sigpending_first",
                SyscallContext::new(SYS_TGKILL, [pid as u64, tid as u64, 12, 0, 0, 0]),
            )
            .expect("first tgkill dispatch");
        assert_eq!(expect_ret(first), 0);
        let pending = &runtime.query_thread(tid).unwrap().pending_signals;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].si_uid, 1000);

        let second = runtime
            .dispatch_linux_syscall_raw(
                "test_tgkill_rlimit_sigpending_denied",
                SyscallContext::new(SYS_TGKILL, [pid as u64, tid as u64, 13, 0, 0, 0]),
            )
            .expect("second tgkill dispatch");
        assert_eq!(expect_ret(second), -(ERR_EAGAIN as i64));
        let pending = &runtime.query_thread(tid).unwrap().pending_signals;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].signo, 12);
    }
}
