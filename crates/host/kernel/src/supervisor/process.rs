use super::{
    runtime::PrototypeRuntime,
    types::{
        Pid, ProcessRuntimeState, ProcessRuntimeStateKind, TaskId, ThreadRuntimeState,
        ThreadRuntimeStateKind, Tid,
    },
};

// Linux clone flags
const CLONE_VM: u64 = 0x100;
const CLONE_FS: u64 = 0x200;
const CLONE_FILES: u64 = 0x400;
const CLONE_SIGHAND: u64 = 0x800;
const CLONE_PIDFD: u64 = 0x1000;
const CLONE_PTRACE: u64 = 0x2000;
const CLONE_VFORK: u64 = 0x4000;
const CLONE_PARENT: u64 = 0x8000;
const CLONE_THREAD: u64 = 0x10000;
const CLONE_NEWNS: u64 = 0x20000;
const CLONE_SYSVSEM: u64 = 0x40000;
const CLONE_SETTLS: u64 = 0x80000;
const CLONE_PARENT_SETTID: u64 = 0x100000;
const CLONE_CHILD_CLEARTID: u64 = 0x200000;
const CLONE_DETACHED: u64 = 0x400000;
const CLONE_UNTRACED: u64 = 0x800000;
const CLONE_CHILD_SETTID: u64 = 0x1000000;
const CLONE_NEWCGROUP: u64 = 0x2000000;
const CLONE_NEWUTS: u64 = 0x4000000;
const CLONE_NEWIPC: u64 = 0x8000000;
const CLONE_NEWUSER: u64 = 0x10000000;
const CLONE_NEWPID: u64 = 0x20000000;
const CLONE_NEWNET: u64 = 0x40000000;
const CLONE_IO: u64 = 0x80000000;

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
    /// Shared-mode clone.
    ///
    /// Supported:
    /// - CLONE_VM: new thread shares parent's address space
    /// - CLONE_FILES: new thread shares parent's fd table
    /// - CLONE_THREAD: new thread shares parent's thread group
    /// - CLONE_CHILD_CLEARTID: store child tid at ctid address
    /// - CLONE_CHILD_SETTID: store child tid at ctid address
    ///
    /// Not yet supported:
    /// - clone without CLONE_VM: requires COW fork
    /// - CLONE_VFORK: requires parent suspension
    /// - namespace flags: NEWNS, NEWCGROUP, etc.
    pub(crate) fn do_clone(
        &mut self,
        flags: u64,
        _stack: u64,
        parent_tid_ptr: u64,
        child_tid_ptr: u64,
        _tls: u64,
        parent_pid: Pid,
    ) -> Result<i64, i32> {
        // Namespace creation not supported
        if flags & CLONE_NS_MASK != 0 {
            return Err(vmos_abi::ERR_ENOSYS);
        }
        // Private address space (fork) not yet supported
        if flags & CLONE_VM == 0 {
            return Err(vmos_abi::ERR_ENOSYS);
        }
        // VFORK not supported
        if flags & CLONE_VFORK != 0 {
            return Err(vmos_abi::ERR_ENOSYS);
        }

        let task_id = self.allocate_task();
        self.set_current_task(task_id);

        let child_pid = if flags & CLONE_THREAD != 0 {
            // Thread in same process
            parent_pid
        } else {
            // New process sharing address space
            self.allocate_process(parent_pid, parent_pid, parent_pid)
        };

        let child_tid = self.allocate_thread(task_id, child_pid);

        // If CLONE_CHILD_CLEARTID: store child_tid at child_tid_ptr
        // futex wake on clear not yet implemented
        if flags & CLONE_CHILD_CLEARTID != 0 {
            if let Some(thread) = self.threads.iter_mut().find(|t| t.tid == child_tid) {
                thread.clear_child_tid = Some(child_tid_ptr);
            }
        }

        // If CLONE_CHILD_SETTID: write child_tid to ctid
        // (requires user memory access, deferred to bridge.rs)

        // If CLONE_PARENT_SETTID: write child_tid to parent_tid_ptr
        // (requires user memory access, deferred to bridge.rs)

        Ok(child_tid as i64)
    }

    /// Transition a process to Zombie state with the given exit code.
    pub(crate) fn process_exit(&mut self, pid: Pid, exit_code: i32) {
        if let Some(proc) = self.processes.iter_mut().find(|p| p.pid == pid) {
            proc.state = ProcessRuntimeStateKind::Zombie;
            proc.exit_code = Some(exit_code);
        }
    }

    /// Transition a thread to Dead state.
    pub(crate) fn thread_exit(&mut self, tid: Tid) {
        if let Some(thread) = self.threads.iter_mut().find(|t| t.tid == tid) {
            thread.state = ThreadRuntimeStateKind::Dead;
        }
    }
}
