use alloc::vec::Vec;

use semantic_core::{
    CredentialTransitionKind, GuestAddressSpaceRef, LinuxCapSets, ProcessState, TaskState,
};

use super::{
    events::Event,
    linux::LinuxCallResult,
    runtime::PrototypeRuntime,
    types::{
        Pid, ProcessRuntimeState, ProcessRuntimeStateKind, RobustListRegistration, TaskId,
        ThreadRuntimeState, ThreadRuntimeStateKind, Tid,
    },
    wait::{WaitRegistration, WaitSource},
};
use crate::interrupts;

// Linux clone flags
const CLONE_EXIT_SIGNAL_MASK: u64 = 0xff;
const CLONE_VM: u64 = 0x100;
const CLONE_FS: u64 = 0x200;
const CLONE_FILES: u64 = 0x400;
const CLONE_SIGHAND: u64 = 0x800;
const CLONE_SETTLS: u64 = 0x80000;
const CLONE_THREAD: u64 = 0x10000;
const CLONE_NEWNS: u64 = 0x20000;
const CLONE_PARENT_SETTID: u64 = 0x100000;
const CLONE_CHILD_CLEARTID: u64 = 0x200000;
const CLONE_NEWCGROUP: u64 = 0x2000000;
const CLONE_NEWUTS: u64 = 0x4000000;
const CLONE_NEWIPC: u64 = 0x8000000;
const CLONE_CHILD_SETTID: u64 = 0x1000000;
const CLONE_NEWUSER: u64 = 0x10000000;
const CLONE_NEWPID: u64 = 0x20000000;
const CLONE_NEWNET: u64 = 0x40000000;
const CLONE_IO: u64 = 0x80000000;
const SUPPORTED_SHARED_VM_CLONE_MASK: u64 = CLONE_EXIT_SIGNAL_MASK
    | CLONE_VM
    | CLONE_FS
    | CLONE_FILES
    | CLONE_SETTLS
    | CLONE_PARENT_SETTID
    | CLONE_CHILD_CLEARTID
    | CLONE_CHILD_SETTID;
const SUPPORTED_INDEPENDENT_VM_CLONE_MASK: u64 = CLONE_EXIT_SIGNAL_MASK
    | CLONE_FS
    | CLONE_FILES
    | CLONE_SETTLS
    | CLONE_PARENT_SETTID
    | CLONE_CHILD_CLEARTID
    | CLONE_CHILD_SETTID;
const WNOHANG: u64 = 0x1;
const WUNTRACED: u64 = 0x2;
const WCONTINUED: u64 = 0x8;
const SIGCHLD: u8 = 17;
const CLD_EXITED: i32 = 1;
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
    pub(crate) fn record_credential_transition(
        &mut self,
        pid: Pid,
        uid: u32,
        euid: u32,
        suid: u32,
        gid: u32,
        egid: u32,
        sgid: u32,
        supplementary_groups: Vec<u32>,
        capability_sets: LinuxCapSets,
        kind: CredentialTransitionKind,
    ) -> bool {
        self.semantic
            .transition_process_credential_by_pid(
                pid,
                uid,
                euid,
                suid,
                euid,
                gid,
                egid,
                sgid,
                egid,
                supplementary_groups,
                capability_sets,
                kind,
            )
            .is_some()
    }

    /// Create the runtime and semantic records for a vfork child.
    ///
    /// This is intentionally narrower than general fork/clone support: the
    /// child shares the current address space and gets resumed immediately on
    /// the same user stack. The parent is restored only when the child exits
    /// through the syscall path.
    pub(crate) fn create_vfork_child(
        &mut self,
        parent_pid: Pid,
        parent_tid: Tid,
        uid: u32,
        euid: u32,
        suid: u32,
        gid: u32,
        egid: u32,
        sgid: u32,
        supplementary_groups: Vec<u32>,
        capability_sets: LinuxCapSets,
    ) -> Result<(TaskId, Pid, Tid), i32> {
        let parent = self
            .processes
            .iter()
            .find(|process| process.pid == parent_pid)
            .ok_or(vmos_abi::ERR_ESRCH)?
            .clone();
        if parent.state != ProcessRuntimeStateKind::Running {
            return Err(vmos_abi::ERR_ESRCH);
        }
        let parent_thread = self
            .threads
            .iter()
            .find(|thread| thread.tid == parent_tid && thread.pid == parent_pid)
            .ok_or(vmos_abi::ERR_ESRCH)?
            .clone();
        if parent_thread.state != ThreadRuntimeStateKind::Running {
            return Err(vmos_abi::ERR_ESRCH);
        }

        let child_pid = self.next_pid.max(self.next_tid);
        let Some(next_id) = child_pid.checked_add(1) else {
            return Err(vmos_abi::ERR_EAGAIN);
        };
        let child_tid = child_pid;
        if child_pid == 0
            || self.processes.iter().any(|process| process.pid == child_pid)
            || self.threads.iter().any(|thread| thread.tid == child_tid)
        {
            return Err(vmos_abi::ERR_EAGAIN);
        }

        let child_task_id = self.allocate_task();
        if !self.semantic.create_process_family_root_with_credential(
            child_pid,
            Some(parent_pid),
            parent.pgid,
            parent.sid,
            child_task_id as u64,
            GuestAddressSpaceRef::new(1, 1),
            uid,
            euid,
            suid,
            euid,
            gid,
            egid,
            sgid,
            egid,
            supplementary_groups,
            capability_sets,
        ) {
            return Err(vmos_abi::ERR_EINVAL);
        }
        self.next_pid = next_id;
        self.next_tid = next_id;
        self.processes.push(ProcessRuntimeState {
            pid: child_pid,
            ppid: parent_pid,
            pgid: parent.pgid,
            sid: parent.sid,
            tgid: child_tid,
            exit_signal: Some(SIGCHLD),
            state: ProcessRuntimeStateKind::Running,
            exit_code: None,
            sigactions: parent.sigactions,
            rlimits: parent.rlimits,
        });
        self.threads.push(ThreadRuntimeState {
            tid: child_tid,
            task_id: child_task_id,
            pid: child_pid,
            state: ThreadRuntimeStateKind::Running,
            clear_child_tid: None,
            robust_list: None,
            sigmask: parent_thread.sigmask,
            pending_signals: Vec::new(),
            seccomp: parent_thread.seccomp,
        });

        Ok((child_task_id, child_pid, child_tid))
    }

    pub(crate) fn create_shared_vm_clone_child(
        &mut self,
        flags: u64,
        child_stack: u64,
        parent_pid: Pid,
        parent_tid: Tid,
        uid: u32,
        euid: u32,
        suid: u32,
        gid: u32,
        egid: u32,
        sgid: u32,
        supplementary_groups: Vec<u32>,
        capability_sets: LinuxCapSets,
        clear_child_tid: Option<u64>,
    ) -> Result<(TaskId, Pid, Tid), i32> {
        // This is the first non-vfork executable clone subset. The Linux ELF
        // context snapshots cwd/fd-table state when CLONE_FS/CLONE_FILES are
        // not requested. Non-CLONE_VM fork stays ENOSYS until address-space
        // cloning/COW exists.
        if flags & CLONE_NS_MASK != 0 {
            return Err(vmos_abi::ERR_ENOSYS);
        }
        if flags & CLONE_SIGHAND != 0 && flags & CLONE_VM == 0 {
            return Err(vmos_abi::ERR_EINVAL);
        }
        if flags & CLONE_THREAD != 0 && flags & CLONE_SIGHAND == 0 {
            return Err(vmos_abi::ERR_EINVAL);
        }
        if flags & !SUPPORTED_SHARED_VM_CLONE_MASK != 0 {
            return Err(vmos_abi::ERR_ENOSYS);
        }
        if flags & CLONE_VM == 0 {
            return Err(vmos_abi::ERR_ENOSYS);
        }
        if child_stack == 0 {
            return Err(vmos_abi::ERR_EINVAL);
        }
        let exit_signal = (flags & CLONE_EXIT_SIGNAL_MASK) as u8;
        if exit_signal >= 64 {
            return Err(vmos_abi::ERR_EINVAL);
        }

        let parent = self
            .processes
            .iter()
            .find(|process| process.pid == parent_pid)
            .ok_or(vmos_abi::ERR_ESRCH)?
            .clone();
        if parent.state != ProcessRuntimeStateKind::Running {
            return Err(vmos_abi::ERR_ESRCH);
        }
        let parent_thread = self
            .threads
            .iter()
            .find(|thread| thread.tid == parent_tid && thread.pid == parent_pid)
            .ok_or(vmos_abi::ERR_ESRCH)?
            .clone();
        if parent_thread.state != ThreadRuntimeStateKind::Running {
            return Err(vmos_abi::ERR_ESRCH);
        }

        let child_pid = self.next_pid.max(self.next_tid);
        let Some(next_id) = child_pid.checked_add(1) else {
            return Err(vmos_abi::ERR_EAGAIN);
        };
        let child_tid = child_pid;
        if child_pid == 0
            || self.processes.iter().any(|process| process.pid == child_pid)
            || self.threads.iter().any(|thread| thread.tid == child_tid)
        {
            return Err(vmos_abi::ERR_EAGAIN);
        }

        let child_task_id = self.allocate_task();
        if !self.semantic.create_process_family_root_with_credential(
            child_pid,
            Some(parent_pid),
            parent.pgid,
            parent.sid,
            child_task_id as u64,
            GuestAddressSpaceRef::new(1, 1),
            uid,
            euid,
            suid,
            euid,
            gid,
            egid,
            sgid,
            egid,
            supplementary_groups,
            capability_sets,
        ) {
            return Err(vmos_abi::ERR_EINVAL);
        }
        if clear_child_tid.is_some()
            && !self.semantic.set_thread_clear_child_tid_by_tid(child_tid, clear_child_tid)
        {
            return Err(vmos_abi::ERR_EINVAL);
        }

        self.next_pid = next_id;
        self.next_tid = next_id;
        self.processes.push(ProcessRuntimeState {
            pid: child_pid,
            ppid: parent_pid,
            pgid: parent.pgid,
            sid: parent.sid,
            tgid: child_tid,
            exit_signal: if exit_signal == 0 { None } else { Some(exit_signal) },
            state: ProcessRuntimeStateKind::Running,
            exit_code: None,
            sigactions: parent.sigactions,
            rlimits: parent.rlimits,
        });
        self.threads.push(ThreadRuntimeState {
            tid: child_tid,
            task_id: child_task_id,
            pid: child_pid,
            state: ThreadRuntimeStateKind::Running,
            clear_child_tid,
            robust_list: None,
            sigmask: parent_thread.sigmask,
            pending_signals: Vec::new(),
            seccomp: parent_thread.seccomp,
        });

        Ok((child_task_id, child_pid, child_tid))
    }

    pub(crate) fn create_independent_vm_clone_child(
        &mut self,
        flags: u64,
        parent_pid: Pid,
        parent_tid: Tid,
        uid: u32,
        euid: u32,
        suid: u32,
        gid: u32,
        egid: u32,
        sgid: u32,
        supplementary_groups: Vec<u32>,
        capability_sets: LinuxCapSets,
        clear_child_tid: Option<u64>,
    ) -> Result<(TaskId, Pid, Tid), i32> {
        if flags & CLONE_NS_MASK != 0 {
            return Err(vmos_abi::ERR_ENOSYS);
        }
        if flags & CLONE_VM != 0 {
            return Err(vmos_abi::ERR_EINVAL);
        }
        if flags & CLONE_SIGHAND != 0 {
            return Err(vmos_abi::ERR_EINVAL);
        }
        if flags & CLONE_THREAD != 0 {
            return Err(vmos_abi::ERR_EINVAL);
        }
        if flags & !SUPPORTED_INDEPENDENT_VM_CLONE_MASK != 0 {
            return Err(vmos_abi::ERR_ENOSYS);
        }
        let exit_signal = (flags & CLONE_EXIT_SIGNAL_MASK) as u8;
        if exit_signal >= 64 {
            return Err(vmos_abi::ERR_EINVAL);
        }

        let parent = self
            .processes
            .iter()
            .find(|process| process.pid == parent_pid)
            .ok_or(vmos_abi::ERR_ESRCH)?
            .clone();
        if parent.state != ProcessRuntimeStateKind::Running {
            return Err(vmos_abi::ERR_ESRCH);
        }
        let parent_thread = self
            .threads
            .iter()
            .find(|thread| thread.tid == parent_tid && thread.pid == parent_pid)
            .ok_or(vmos_abi::ERR_ESRCH)?
            .clone();
        if parent_thread.state != ThreadRuntimeStateKind::Running {
            return Err(vmos_abi::ERR_ESRCH);
        }

        let child_pid = self.next_pid.max(self.next_tid);
        let Some(next_id) = child_pid.checked_add(1) else {
            return Err(vmos_abi::ERR_EAGAIN);
        };
        let child_tid = child_pid;
        if child_pid == 0
            || self.processes.iter().any(|process| process.pid == child_pid)
            || self.threads.iter().any(|thread| thread.tid == child_tid)
        {
            return Err(vmos_abi::ERR_EAGAIN);
        }

        let child_task_id = self.allocate_task();
        if !self.semantic.create_process_family_root_with_credential(
            child_pid,
            Some(parent_pid),
            parent.pgid,
            parent.sid,
            child_task_id as u64,
            GuestAddressSpaceRef::new(child_pid as u64, 1),
            uid,
            euid,
            suid,
            euid,
            gid,
            egid,
            sgid,
            egid,
            supplementary_groups,
            capability_sets,
        ) {
            return Err(vmos_abi::ERR_EINVAL);
        }
        if clear_child_tid.is_some()
            && !self.semantic.set_thread_clear_child_tid_by_tid(child_tid, clear_child_tid)
        {
            return Err(vmos_abi::ERR_EINVAL);
        }

        self.next_pid = next_id;
        self.next_tid = next_id;
        self.processes.push(ProcessRuntimeState {
            pid: child_pid,
            ppid: parent_pid,
            pgid: parent.pgid,
            sid: parent.sid,
            tgid: child_tid,
            exit_signal: if exit_signal == 0 { None } else { Some(exit_signal) },
            state: ProcessRuntimeStateKind::Running,
            exit_code: None,
            sigactions: parent.sigactions,
            rlimits: parent.rlimits,
        });
        self.threads.push(ThreadRuntimeState {
            tid: child_tid,
            task_id: child_task_id,
            pid: child_pid,
            state: ThreadRuntimeStateKind::Running,
            clear_child_tid,
            robust_list: None,
            sigmask: parent_thread.sigmask,
            pending_signals: Vec::new(),
            seccomp: parent_thread.seccomp,
        });

        Ok((child_task_id, child_pid, child_tid))
    }

    pub(crate) fn set_thread_clear_child_tid(
        &mut self,
        tid: Tid,
        clear_child_tid: Option<u64>,
    ) -> Result<(), i32> {
        if !self.threads.iter().any(|thread| thread.tid == tid) {
            return Err(vmos_abi::ERR_ESRCH);
        }
        if clear_child_tid == Some(0) {
            return Err(vmos_abi::ERR_EINVAL);
        }
        if !self.semantic.set_thread_clear_child_tid_by_tid(tid, clear_child_tid) {
            return Err(vmos_abi::ERR_EINVAL);
        }
        let thread =
            self.threads.iter_mut().find(|thread| thread.tid == tid).ok_or(vmos_abi::ERR_ESRCH)?;
        thread.clear_child_tid = clear_child_tid;
        Ok(())
    }

    pub(crate) fn take_thread_clear_child_tid(&mut self, tid: Tid) -> Option<u64> {
        let clear_child_tid = self
            .threads
            .iter_mut()
            .find(|thread| thread.tid == tid)
            .and_then(|thread| thread.clear_child_tid.take());
        if clear_child_tid.is_some() {
            let _ = self.semantic.set_thread_clear_child_tid_by_tid(tid, None);
        }
        clear_child_tid
    }

    pub(crate) fn set_thread_robust_list(
        &mut self,
        tid: Tid,
        registration: Option<RobustListRegistration>,
    ) -> Result<(), i32> {
        if !self.threads.iter().any(|thread| thread.tid == tid) {
            return Err(vmos_abi::ERR_ESRCH);
        }
        let (head, len) = match registration {
            Some(registration) => {
                if registration.head == 0 {
                    return Err(vmos_abi::ERR_EINVAL);
                }
                let len = usize::try_from(registration.len).map_err(|_| vmos_abi::ERR_EINVAL)?;
                (Some(registration.head), len)
            }
            None => (None, 0),
        };
        if !self.semantic.set_thread_robust_list_by_tid(tid, head, len) {
            return Err(vmos_abi::ERR_EINVAL);
        }
        let thread =
            self.threads.iter_mut().find(|thread| thread.tid == tid).ok_or(vmos_abi::ERR_ESRCH)?;
        thread.robust_list = registration;
        Ok(())
    }

    pub(crate) fn take_thread_robust_list(&mut self, tid: Tid) -> Option<RobustListRegistration> {
        let registration = self
            .threads
            .iter_mut()
            .find(|thread| thread.tid == tid)
            .and_then(|thread| thread.robust_list.take());
        if registration.is_some() {
            let _ = self.semantic.set_thread_robust_list_by_tid(tid, None, 0);
        }
        registration
    }

    /// Transition a process to Zombie state with the given exit code.
    pub(crate) fn process_exit(&mut self, pid: Pid, exit_code: i32) {
        let mut parent_signal = None;
        if let Some(proc) = self.processes.iter_mut().find(|p| p.pid == pid) {
            if proc.state != ProcessRuntimeStateKind::Zombie
                && proc.state != ProcessRuntimeStateKind::Dead
            {
                parent_signal = proc.exit_signal.map(|signal| (proc.ppid, signal));
            }
            proc.state = ProcessRuntimeStateKind::Zombie;
            proc.exit_code = Some(exit_code);
        }
        let mut exited_tasks = Vec::new();
        for thread in self.threads.iter_mut().filter(|thread| thread.pid == pid) {
            thread.state = ThreadRuntimeStateKind::Dead;
            exited_tasks.push(thread.task_id);
        }
        for task in exited_tasks {
            self.semantic.set_task_state(task, TaskState::Exited);
        }
        self.release_file_locks_for_pid(pid);
        if let Some((parent_pid, signal)) = parent_signal {
            if parent_pid != 0 && signal != 0 {
                self.queue_signal_to_process(parent_pid, signal, CLD_EXITED, pid, 0);
            }
        }
        self.semantic.transition_process_state_by_pid(pid, ProcessState::Zombie { exit_code });
        self.notify_child_exit_waiters();
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

    pub(crate) fn wait4_child_is_ready(&self, caller_pid: Pid, selector: i64) -> bool {
        self.query_wait4(caller_pid, selector, WNOHANG).ok().flatten().is_some()
    }

    pub(crate) fn block_on_wait4_child_exit(
        &mut self,
        caller_pid: Pid,
        selector: i64,
    ) -> Result<(), i32> {
        let token = self.waits.register(
            self.scheduler.current_task(),
            WaitRegistration::ChildExit { caller_pid, selector },
            interrupts::tick_count(),
            interrupts::TIMER_HZ,
        );
        self.record_wait_token(token);
        match self.block_on_wait("ring3_wait4", token).map_err(|_| vmos_abi::ERR_EINVAL)? {
            LinuxCallResult::Ret(0) => Ok(()),
            LinuxCallResult::Ret(ret) if ret < 0 => Err((-ret) as i32),
            _ => Err(vmos_abi::ERR_EINVAL),
        }
    }

    fn notify_child_exit_waiters(&mut self) {
        let ready_waits: Vec<u64> = self
            .waits
            .pending_sources()
            .into_iter()
            .filter_map(|(token, source)| {
                let WaitSource::ChildExit { caller_pid, selector } = source else {
                    return None;
                };
                self.wait4_child_is_ready(caller_pid, selector).then_some(token.id)
            })
            .collect();
        for wait_id in ready_waits {
            self.scheduler.push_event(Event::WaitReady(wait_id));
        }
        self.drain_event_queue();
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
