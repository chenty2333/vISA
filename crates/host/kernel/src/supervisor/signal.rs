use alloc::vec::Vec;

use crate::frontends::linux_elf::handle_user_fault;

use super::{
    runtime::PrototypeRuntime,
    types::{
        PendingSignal, Pid, ProcessRuntimeStateKind, SigAction, ThreadRuntimeStateKind, Tid,
    },
};

/// Linux signal default actions.
fn signal_default_action(signo: u8) -> SignalDefaultAction {
    match signo {
        // POSIX: terminate
        1 | 2 | 3 | 4 | 6 | 7 | 8 | 10 | 11 | 12 | 13 | 14 | 15 => {
            SignalDefaultAction::Terminate { core: signo == 3 || signo == 4 || signo == 6
                || signo == 8 || signo == 11 }
        }
        // POSIX: stop
        17 | 19 | 20 | 22 | 23 | 24 | 25 => SignalDefaultAction::Stop,
        // POSIX: continue
        18 => SignalDefaultAction::Continue,
        // POSIX: ignore
        9 | 16 | 28 | 30 | 31 => SignalDefaultAction::Terminate { core: false },
        _ => SignalDefaultAction::Terminate { core: false },
    }
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
            thread.pending_signals.push(PendingSignal {
                signo,
                si_code,
                si_pid,
                si_uid,
            });
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
        let tids: Vec<Tid> = self
            .threads
            .iter()
            .filter(|t| t.pid == pid)
            .map(|t| t.tid)
            .collect();
        for tid in tids {
            self.queue_signal_to_thread(tid, signo, si_code, si_pid, si_uid);
        }
    }

    /// Check and deliver pending signals for the current thread.
    /// Called before returning to userspace (after syscall processing).
    /// Returns true if a signal was delivered (caller must re-check registers).
    pub(crate) fn deliver_pending_signals(&mut self, tid: Tid) -> bool {
        let current_pid = self
            .threads
            .iter()
            .find(|t| t.tid == tid)
            .map(|t| t.pid)
            .unwrap_or(1);

        // Collect eligible pending signals
        let sigmask = self
            .threads
            .iter()
            .find(|t| t.tid == tid)
            .map(|t| t.sigmask)
            .unwrap_or(0);

        let pending: Vec<PendingSignal> = self
            .threads
            .iter()
            .find(|t| t.tid == tid)
            .map(|t| {
                t.pending_signals
                    .iter()
                    .filter(|s| sigmask & (1u64 << s.signo) == 0)
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
        self.processes
            .iter()
            .find(|p| p.pid == pid)
            .map(|p| p.sigactions[signo as usize])
    }

    /// Set signal mask for a thread.
    pub(crate) fn set_sigmask(&mut self, tid: Tid, how: u32, set: u64) -> Option<u64> {
        let thread = self.threads.iter_mut().find(|t| t.tid == tid)?;
        let old = thread.sigmask;
        match how {
            0 => thread.sigmask = set,                    // SIG_BLOCK
            1 => thread.sigmask |= set,                   // SIG_UNBLOCK
            2 => thread.sigmask = set,                    // SIG_SETMASK
            _ => return Some(old),
        }
        Some(old)
    }

    /// Get signal mask for a thread.
    pub(crate) fn get_sigmask(&self, tid: Tid) -> Option<u64> {
        self.threads
            .iter()
            .find(|t| t.tid == tid)
            .map(|t| t.sigmask)
    }
}
