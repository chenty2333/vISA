use alloc::vec::Vec;

use super::{
    runtime::PrototypeRuntime,
    types::{
        PendingSignal, Pid, SigAction, TaskId, ThreadRuntimeStateKind, Tid, UserSignalDelivery,
    },
};
use crate::frontends::linux_elf::handle_user_fault;

const SA_NODEFER: u64 = 0x4000_0000;

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
        if let Some(thread) = self.threads.iter_mut().find(|t| t.tid == tid) {
            thread.pending_signals.push(PendingSignal { signo, si_code, si_pid, si_uid });
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
            thread.pending_signals.retain(|s| s.signo != signo);
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
        let old_sigmask = self.threads[thread_index].sigmask;
        let pending_index = self.threads[thread_index]
            .pending_signals
            .iter()
            .position(|signal| old_sigmask & linux_signal_bit(signal.signo) == 0)?;
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
        let mut next_mask =
            old_sigmask | (action.mask & !linux_signal_bit(9) & !linux_signal_bit(19));
        if action.flags & SA_NODEFER == 0 {
            next_mask |= linux_signal_bit(signal.signo);
        }
        self.threads[thread_index].sigmask = next_mask;

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
        // SIGKILL and SIGSTOP cannot be caught
        if signo == 9 || signo == 19 {
            return true; // silently ignored per POSIX
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
}
