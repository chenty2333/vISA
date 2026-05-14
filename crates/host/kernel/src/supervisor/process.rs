use semantic_core::ProcessState;

use super::{
    runtime::PrototypeRuntime,
    types::{Pid, ProcessRuntimeStateKind, ThreadRuntimeStateKind},
};

// Linux clone flags
const CLONE_VM: u64 = 0x100;
const CLONE_SIGHAND: u64 = 0x800;
const CLONE_VFORK: u64 = 0x4000;
const CLONE_THREAD: u64 = 0x10000;
const CLONE_NEWNS: u64 = 0x20000;
const CLONE_SETTLS: u64 = 0x80000;
const CLONE_PARENT_SETTID: u64 = 0x100000;
const CLONE_CHILD_SETTID: u64 = 0x1000000;
const CLONE_NEWCGROUP: u64 = 0x2000000;
const CLONE_NEWUTS: u64 = 0x4000000;
const CLONE_NEWIPC: u64 = 0x8000000;
const CLONE_NEWUSER: u64 = 0x10000000;
const CLONE_NEWPID: u64 = 0x20000000;
const CLONE_NEWNET: u64 = 0x40000000;
const CLONE_IO: u64 = 0x80000000;
const WNOHANG: u64 = 0x1;
const WUNTRACED: u64 = 0x2;
const WCONTINUED: u64 = 0x8;
const SUPPORTED_WAIT_OPTIONS: u64 = WNOHANG | WUNTRACED | WCONTINUED;

// Flags that require namespace support (currently unsupported)
const CLONE_NS_MASK: u64 = CLONE_NEWNS
    | CLONE_NEWCGROUP
    | CLONE_NEWUTS
    | CLONE_NEWIPC
    | CLONE_NEWUSER
    | CLONE_NEWPID
    | CLONE_NEWNET
    | CLONE_IO;

impl<'engine> PrototypeRuntime<'engine> {
    /// Linux clone/fork boundary.
    ///
    /// No mode returns success yet because a real success needs a runnable
    /// child user context with correct parent/child return values. This method
    /// still validates Linux flag dependency errors before reporting unsupported
    /// execution support.
    pub(crate) fn do_clone(
        &mut self,
        flags: u64,
        _stack: u64,
        _parent_tid_ptr: u64,
        _child_tid_ptr: u64,
        _tls: u64,
        _parent_pid: Pid,
    ) -> Result<i64, i32> {
        // Namespace creation not supported
        if flags & CLONE_NS_MASK != 0 {
            return Err(vmos_abi::ERR_ENOSYS);
        }
        if flags & CLONE_SIGHAND != 0 && flags & CLONE_VM == 0 {
            return Err(vmos_abi::ERR_EINVAL);
        }
        if flags & CLONE_THREAD != 0 && flags & CLONE_SIGHAND == 0 {
            return Err(vmos_abi::ERR_EINVAL);
        }
        if flags & CLONE_VFORK != 0
            || flags & CLONE_SETTLS != 0
            || flags & CLONE_PARENT_SETTID != 0
            || flags & CLONE_CHILD_SETTID != 0
        {
            return Err(vmos_abi::ERR_ENOSYS);
        }

        // A successful Linux clone/fork must create a runnable child context that
        // returns to userspace independently. The current ring3 path has one
        // active SyscallFrame and no resume queue, so returning success would be
        // a fake child. Keep the unsupported boundary explicit until context
        // cloning/resume is implemented.
        Err(vmos_abi::ERR_ENOSYS)
    }

    /// Transition a process to Zombie state with the given exit code.
    pub(crate) fn process_exit(&mut self, pid: Pid, exit_code: i32) {
        if let Some(proc) = self.processes.iter_mut().find(|p| p.pid == pid) {
            proc.state = ProcessRuntimeStateKind::Zombie;
            proc.exit_code = Some(exit_code);
        }
        for thread in self.threads.iter_mut().filter(|thread| thread.pid == pid) {
            thread.state = ThreadRuntimeStateKind::Dead;
        }
        self.semantic.transition_process_state_by_pid(pid, ProcessState::Zombie { exit_code });
    }

    pub(crate) fn query_wait4(
        &self,
        caller_pid: Pid,
        selector: i64,
        options: u64,
    ) -> Result<Option<(Pid, u32)>, i32> {
        if options & !SUPPORTED_WAIT_OPTIONS != 0 {
            return Err(vmos_abi::ERR_EINVAL);
        }
        let caller_pgid =
            self.processes.iter().find(|process| process.pid == caller_pid).map(|p| p.pgid);
        let mut saw_matching_child = false;
        let mut zombie_index = None;

        for (idx, process) in self.processes.iter().enumerate() {
            if process.ppid != caller_pid || process.state == ProcessRuntimeStateKind::Dead {
                continue;
            }
            if !wait_selector_matches(selector, process.pid, process.pgid, caller_pgid) {
                continue;
            }
            saw_matching_child = true;
            if process.state == ProcessRuntimeStateKind::Zombie {
                zombie_index = Some(idx);
                break;
            }
        }

        let Some(idx) = zombie_index else {
            if saw_matching_child && options & WNOHANG != 0 {
                return Ok(None);
            }
            return if saw_matching_child {
                Err(vmos_abi::ERR_ENOSYS)
            } else {
                Err(vmos_abi::ERR_ECHILD)
            };
        };

        let child = &self.processes[idx];
        let pid = child.pid;
        let status = wait_exit_status(child.exit_code.unwrap_or(0));
        Ok(Some((pid, status)))
    }

    pub(crate) fn reap_wait4_child(&mut self, caller_pid: Pid, child_pid: Pid) -> Result<(), i32> {
        let Some(child) = self.processes.iter_mut().find(|process| {
            process.ppid == caller_pid
                && process.pid == child_pid
                && process.state == ProcessRuntimeStateKind::Zombie
        }) else {
            return Err(vmos_abi::ERR_ECHILD);
        };
        child.state = ProcessRuntimeStateKind::Dead;
        child.exit_code = None;
        self.semantic.transition_process_state_by_pid(child_pid, ProcessState::Dead);
        Ok(())
    }
}

fn wait_selector_matches(
    selector: i64,
    child_pid: Pid,
    child_pgid: Pid,
    caller_pgid: Option<Pid>,
) -> bool {
    if selector == -1 {
        return true;
    }
    if selector == 0 {
        return caller_pgid.is_some_and(|pgid| child_pgid == pgid);
    }
    if selector > 0 {
        return child_pid as i64 == selector;
    }
    child_pgid as i64 == selector.saturating_abs()
}

fn wait_exit_status(exit_code: i32) -> u32 {
    ((exit_code as u32) & 0xff) << 8
}
