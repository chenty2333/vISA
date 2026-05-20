use alloc::vec::Vec;

use semantic_core::{
    CredentialTransitionKind, GuestAddressSpaceRef, LinuxCapSets, ProcessState, TaskState,
};

use super::{
    events::Event,
    linux::{LinuxCallResult, LinuxPlan},
    runtime::PrototypeRuntime,
    types::{
        CAP_SYS_PTRACE, Pid, ProcessAccessState, ProcessRuntimeState, ProcessRuntimeStateKind,
        RobustListRegistration, RseqRegistration, SignalAltStack, TaskId, ThreadRuntimeState,
        ThreadRuntimeStateKind, Tid,
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
const LINUX_RUSAGE_SIZE: usize = 144;

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
        fsuid: u32,
        gid: u32,
        egid: u32,
        sgid: u32,
        fsgid: u32,
        supplementary_groups: Vec<u32>,
        capability_sets: LinuxCapSets,
        kind: CredentialTransitionKind,
    ) -> bool {
        if self.processes.iter().all(|process| process.pid != pid) {
            return false;
        }
        let runtime_access = ProcessAccessState::from_credentials(
            uid,
            euid,
            suid,
            fsuid,
            gid,
            egid,
            sgid,
            fsgid,
            supplementary_groups.clone(),
            capability_sets.permitted,
            capability_sets.effective,
        );
        let transitioned = self
            .semantic
            .transition_process_credential_by_pid(
                pid,
                uid,
                euid,
                suid,
                fsuid,
                gid,
                egid,
                sgid,
                fsgid,
                supplementary_groups,
                capability_sets,
                kind,
            )
            .is_some();
        if transitioned
            && let Some(process) = self.processes.iter_mut().find(|process| process.pid == pid)
        {
            let old_access = process.access.clone();
            process.access = runtime_access;
            if old_access.credential_ids_differ(&process.access) {
                process.dumpable = false;
            }
        }
        transitioned
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
        fsuid: u32,
        gid: u32,
        egid: u32,
        sgid: u32,
        fsgid: u32,
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

        let runtime_access = ProcessAccessState::from_credentials(
            uid,
            euid,
            suid,
            fsuid,
            gid,
            egid,
            sgid,
            fsgid,
            supplementary_groups.clone(),
            capability_sets.permitted,
            capability_sets.effective,
        );
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
            fsuid,
            gid,
            egid,
            sgid,
            fsgid,
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
            access: runtime_access,
            dumpable: parent.dumpable,
            execed: false,
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
            sigaltstack: parent_thread.sigaltstack,
            sigmask: parent_thread.sigmask,
            sigsuspend_restore_mask: None,
            pending_signals: Vec::new(),
            seccomp: parent_thread.seccomp.clone(),
            no_new_privs: parent_thread.no_new_privs,
            rseq: None,
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
        fsuid: u32,
        gid: u32,
        egid: u32,
        sgid: u32,
        fsgid: u32,
        supplementary_groups: Vec<u32>,
        capability_sets: LinuxCapSets,
        clear_child_tid: Option<u64>,
    ) -> Result<(TaskId, Pid, Tid), i32> {
        // This is the first non-vfork executable clone subset. The Linux ELF
        // context snapshots cwd/fd-table state when CLONE_FS/CLONE_FILES are
        // not requested; independent-VM fork/clone uses the sibling helper.
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

        let runtime_access = ProcessAccessState::from_credentials(
            uid,
            euid,
            suid,
            fsuid,
            gid,
            egid,
            sgid,
            fsgid,
            supplementary_groups.clone(),
            capability_sets.permitted,
            capability_sets.effective,
        );
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
            fsuid,
            gid,
            egid,
            sgid,
            fsgid,
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
            access: runtime_access,
            dumpable: parent.dumpable,
            execed: false,
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
            sigaltstack: SignalAltStack::default(),
            sigmask: parent_thread.sigmask,
            sigsuspend_restore_mask: None,
            pending_signals: Vec::new(),
            seccomp: parent_thread.seccomp.clone(),
            no_new_privs: parent_thread.no_new_privs,
            rseq: None,
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
        fsuid: u32,
        gid: u32,
        egid: u32,
        sgid: u32,
        fsgid: u32,
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

        let runtime_access = ProcessAccessState::from_credentials(
            uid,
            euid,
            suid,
            fsuid,
            gid,
            egid,
            sgid,
            fsgid,
            supplementary_groups.clone(),
            capability_sets.permitted,
            capability_sets.effective,
        );
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
            fsuid,
            gid,
            egid,
            sgid,
            fsgid,
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
            access: runtime_access,
            dumpable: parent.dumpable,
            execed: false,
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
            sigaltstack: parent_thread.sigaltstack,
            sigmask: parent_thread.sigmask,
            sigsuspend_restore_mask: None,
            pending_signals: Vec::new(),
            seccomp: parent_thread.seccomp.clone(),
            no_new_privs: parent_thread.no_new_privs,
            rseq: None,
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
            if !self.semantic.set_thread_clear_child_tid_by_tid(tid, None) {
                crate::kwarn!("failed to clear semantic clear_child_tid for tid {}", tid);
            }
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
            if !self.semantic.set_thread_robust_list_by_tid(tid, None, 0) {
                crate::kwarn!("failed to clear semantic robust_list for tid {}", tid);
            }
        }
        registration
    }

    pub(crate) fn get_thread_robust_list_for_caller(
        &self,
        caller_pid: Pid,
        caller_tid: Tid,
        target_tid: Tid,
    ) -> Result<Option<RobustListRegistration>, i32> {
        let caller_thread = self
            .threads
            .iter()
            .find(|thread| thread.tid == caller_tid && thread.pid == caller_pid)
            .ok_or(vmos_abi::ERR_ESRCH)?;
        if caller_thread.state == ThreadRuntimeStateKind::Dead {
            return Err(vmos_abi::ERR_ESRCH);
        }
        let target_thread = self
            .threads
            .iter()
            .find(|thread| thread.tid == target_tid)
            .ok_or(vmos_abi::ERR_ESRCH)?;
        if target_thread.state == ThreadRuntimeStateKind::Dead {
            return Err(vmos_abi::ERR_ESRCH);
        }
        if target_thread.tid == caller_thread.tid || target_thread.pid == caller_pid {
            return Ok(target_thread.robust_list);
        }

        let caller_process = self
            .processes
            .iter()
            .find(|process| {
                process.pid == caller_pid && process.state != ProcessRuntimeStateKind::Dead
            })
            .ok_or(vmos_abi::ERR_ESRCH)?;
        let target_process = self
            .processes
            .iter()
            .find(|process| {
                process.pid == target_thread.pid && process.state != ProcessRuntimeStateKind::Dead
            })
            .ok_or(vmos_abi::ERR_ESRCH)?;
        if robust_list_ptrace_may_access(caller_process, target_process) {
            Ok(target_thread.robust_list)
        } else {
            Err(vmos_abi::ERR_EPERM)
        }
    }

    pub(crate) fn thread_rseq_registration(&self, tid: Tid) -> Option<RseqRegistration> {
        self.threads.iter().find(|thread| thread.tid == tid).and_then(|thread| thread.rseq)
    }

    pub(crate) fn register_thread_rseq(
        &mut self,
        tid: Tid,
        registration: RseqRegistration,
    ) -> Result<(), i32> {
        let Some(thread) = self.threads.iter_mut().find(|thread| thread.tid == tid) else {
            return Err(vmos_abi::ERR_ESRCH);
        };
        if thread.rseq.is_some() {
            return Err(vmos_abi::ERR_EBUSY);
        }
        thread.rseq = Some(registration);
        Ok(())
    }

    pub(crate) fn unregister_thread_rseq(
        &mut self,
        tid: Tid,
        registration: RseqRegistration,
    ) -> Result<(), i32> {
        let Some(thread) = self.threads.iter_mut().find(|thread| thread.tid == tid) else {
            return Err(vmos_abi::ERR_ESRCH);
        };
        if thread.rseq != Some(registration) {
            return Err(vmos_abi::ERR_EINVAL);
        }
        thread.rseq = None;
        Ok(())
    }

    pub(crate) fn process_dumpable(&self, pid: Pid) -> Result<bool, i32> {
        self.processes
            .iter()
            .find(|process| process.pid == pid && process.state != ProcessRuntimeStateKind::Dead)
            .map(|process| process.dumpable)
            .ok_or(vmos_abi::ERR_ESRCH)
    }

    pub(crate) fn set_process_dumpable(&mut self, pid: Pid, dumpable: bool) -> Result<(), i32> {
        let process = self
            .processes
            .iter_mut()
            .find(|process| process.pid == pid && process.state != ProcessRuntimeStateKind::Dead)
            .ok_or(vmos_abi::ERR_ESRCH)?;
        process.dumpable = dumpable;
        Ok(())
    }

    pub(crate) fn mark_process_execed(&mut self, pid: Pid) -> bool {
        let Some(process) = self.processes.iter_mut().find(|process| {
            process.pid == pid && process.state == ProcessRuntimeStateKind::Running
        }) else {
            return false;
        };
        process.execed = true;
        true
    }

    pub(crate) fn get_process_group_id(&self, caller_pid: Pid, pid_arg: i32) -> Result<Pid, i32> {
        let target_pid = resolve_pid_arg(caller_pid, pid_arg)?;
        self.processes
            .iter()
            .find(|process| {
                process.pid == target_pid && process.state != ProcessRuntimeStateKind::Dead
            })
            .map(|process| process.pgid)
            .ok_or(vmos_abi::ERR_ESRCH)
    }

    pub(crate) fn get_session_id(&self, caller_pid: Pid, pid_arg: i32) -> Result<Pid, i32> {
        let target_pid = resolve_pid_arg(caller_pid, pid_arg)?;
        self.processes
            .iter()
            .find(|process| {
                process.pid == target_pid && process.state != ProcessRuntimeStateKind::Dead
            })
            .map(|process| process.sid)
            .ok_or(vmos_abi::ERR_ESRCH)
    }

    pub(crate) fn set_process_group_id(
        &mut self,
        caller_pid: Pid,
        pid_arg: i32,
        pgid_arg: i32,
    ) -> Result<(), i32> {
        if pgid_arg < 0 {
            return Err(vmos_abi::ERR_EINVAL);
        }
        let target_pid = resolve_pid_arg(caller_pid, pid_arg)?;
        let caller = self
            .processes
            .iter()
            .find(|process| {
                process.pid == caller_pid && process.state != ProcessRuntimeStateKind::Dead
            })
            .cloned()
            .ok_or(vmos_abi::ERR_ESRCH)?;
        let target = self
            .processes
            .iter()
            .find(|process| {
                process.pid == target_pid && process.state == ProcessRuntimeStateKind::Running
            })
            .cloned()
            .ok_or(vmos_abi::ERR_ESRCH)?;

        if target_pid != caller_pid && target.ppid != caller_pid {
            return Err(vmos_abi::ERR_ESRCH);
        }
        if target_pid != caller_pid && target.execed {
            return Err(vmos_abi::ERR_EACCES);
        }
        if target.sid != caller.sid || target.sid == target.pid {
            return Err(vmos_abi::ERR_EPERM);
        }

        let new_pgid = if pgid_arg == 0 { target_pid } else { pgid_arg as Pid };
        let existing_group_session = self
            .processes
            .iter()
            .find(|process| {
                process.state != ProcessRuntimeStateKind::Dead && process.pgid == new_pgid
            })
            .map(|process| process.sid);
        match existing_group_session {
            Some(session) if session != caller.sid => return Err(vmos_abi::ERR_EPERM),
            Some(_) => {}
            None if new_pgid != target_pid => return Err(vmos_abi::ERR_EPERM),
            None => {}
        }

        if !self.semantic.set_process_group_by_pid(target_pid, new_pgid) {
            return Err(vmos_abi::ERR_EINVAL);
        }
        let Some(target) = self.processes.iter_mut().find(|process| process.pid == target_pid)
        else {
            return Err(vmos_abi::ERR_ESRCH);
        };
        target.pgid = new_pgid;
        Ok(())
    }

    pub(crate) fn create_session_for_process(&mut self, caller_pid: Pid) -> Result<Pid, i32> {
        let caller = self
            .processes
            .iter()
            .find(|process| {
                process.pid == caller_pid && process.state == ProcessRuntimeStateKind::Running
            })
            .cloned()
            .ok_or(vmos_abi::ERR_ESRCH)?;
        if caller.pgid == caller.pid {
            return Err(vmos_abi::ERR_EPERM);
        }
        if !self.semantic.set_process_session_by_pid(caller_pid, caller_pid, caller_pid) {
            return Err(vmos_abi::ERR_EINVAL);
        }
        let Some(caller) = self.processes.iter_mut().find(|process| process.pid == caller_pid)
        else {
            return Err(vmos_abi::ERR_ESRCH);
        };
        caller.sid = caller_pid;
        caller.pgid = caller_pid;
        Ok(caller_pid)
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
            self.scheduler.mark_task_exited(task);
            self.semantic.set_task_state(task, TaskState::Exited);
            self.release_all_futex_pi_boosts_for_task(task);
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

    pub(super) fn plan_wait4(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let selector = plan.args[0] as i64;
        let status_ptr = match optional_linux_ptr(plan.args[1]) {
            Ok(ptr) => ptr,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        let options = plan.args[2];
        let rusage_ptr = match optional_linux_ptr(plan.args[3]) {
            Ok(ptr) => ptr,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        let caller_pid = self.current_pid();

        loop {
            match self.query_wait4(caller_pid, selector, options) {
                Ok(Some((pid, status))) => {
                    if let Some(ptr) = status_ptr {
                        if self.linux.read_bytes(ptr, 4).is_err() {
                            return Ok(LinuxCallResult::Ret(-(vmos_abi::ERR_EFAULT as i64)));
                        }
                    }
                    if let Some(ptr) = rusage_ptr {
                        if self.linux.read_bytes(ptr, LINUX_RUSAGE_SIZE as u32).is_err() {
                            return Ok(LinuxCallResult::Ret(-(vmos_abi::ERR_EFAULT as i64)));
                        }
                    }
                    if let Some(ptr) = status_ptr {
                        if self.linux.write_bytes(ptr, &status.to_le_bytes()).is_err() {
                            return Ok(LinuxCallResult::Ret(-(vmos_abi::ERR_EFAULT as i64)));
                        }
                    }
                    if let Some(ptr) = rusage_ptr {
                        if self.linux.write_bytes(ptr, &[0u8; LINUX_RUSAGE_SIZE]).is_err() {
                            return Ok(LinuxCallResult::Ret(-(vmos_abi::ERR_EFAULT as i64)));
                        }
                    }
                    match self.reap_wait4_child(caller_pid, pid) {
                        Ok(()) => return Ok(LinuxCallResult::Ret(pid as i64)),
                        Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
                    }
                }
                Ok(None) => return Ok(LinuxCallResult::Ret(0)),
                Err(vmos_abi::ERR_ENOSYS) => {
                    match self.block_on_wait4_child_exit(caller_pid, selector) {
                        Ok(()) => {}
                        Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
                    }
                }
                Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
            }
        }
    }

    pub(super) fn plan_exit(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let code = plan.args[0] as i32;
        let pid = self.current_pid();
        self.close_active_fd_table_for_process_exit();
        self.process_exit(pid, code);
        Ok(LinuxCallResult::Exit(code))
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

fn optional_linux_ptr(raw: u64) -> Result<Option<u32>, i32> {
    if raw == 0 { Ok(None) } else { u32::try_from(raw).map(Some).map_err(|_| vmos_abi::ERR_EFAULT) }
}

fn robust_list_ptrace_may_access(
    caller: &ProcessRuntimeState,
    target: &ProcessRuntimeState,
) -> bool {
    caller.access.cap_permitted & CAP_SYS_PTRACE != 0
        || (target.dumpable && ptrace_credentials_match(&caller.access, &target.access))
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;

    use vmos_abi::{ERR_EFAULT, SYS_EXIT, SYS_WAIT4, SyscallContext};

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

    fn expect_exit(result: LinuxCallResult) -> i32 {
        match result {
            LinuxCallResult::Exit(code) => code,
            other => panic!("expected Exit, got {other:?}"),
        }
    }

    fn create_zombie_child(runtime: &mut PrototypeRuntime<'static>, exit_code: i32) -> Pid {
        let parent = runtime.current_pid();
        let child = runtime.allocate_process(parent, parent, parent);
        let task = runtime.allocate_task();
        runtime.allocate_thread(task, child);
        runtime.process_exit(child, exit_code);
        child
    }

    #[test]
    fn generic_wait4_reaps_zombie_and_writes_status() {
        let mut runtime = test_runtime();
        let child = create_zombie_child(&mut runtime, 7);
        let (base, _) = runtime
            .linux
            .write_arg_bytes(&alloc::vec![0xff; 4 + LINUX_RUSAGE_SIZE])
            .expect("arg buffer");
        let status_ptr = base;
        let rusage_ptr = base + 4;

        let waited = runtime
            .dispatch_linux_syscall_raw(
                "test_wait4_zombie",
                SyscallContext::new(
                    SYS_WAIT4,
                    [child as u64, status_ptr as u64, 0, rusage_ptr as u64, 0, 0],
                ),
            )
            .expect("wait4 dispatch");

        assert_eq!(expect_ret(waited), child as i64);
        let status = runtime.linux.read_bytes(status_ptr, 4).expect("status");
        assert_eq!(u32::from_le_bytes(status[..4].try_into().unwrap()), wait_exit_status(7));
        let rusage = runtime.linux.read_bytes(rusage_ptr, LINUX_RUSAGE_SIZE as u32).unwrap();
        assert!(rusage.iter().all(|byte| *byte == 0));
        assert_eq!(runtime.query_process(child).unwrap().state, ProcessRuntimeStateKind::Dead);
    }

    #[test]
    fn generic_wait4_writeback_failure_does_not_reap_child() {
        let mut runtime = test_runtime();
        let child = create_zombie_child(&mut runtime, 3);

        let waited = runtime
            .dispatch_linux_syscall_raw(
                "test_wait4_bad_status",
                SyscallContext::new(SYS_WAIT4, [child as u64, 0xdead_beef, 0, 0, 0, 0]),
            )
            .expect("wait4 dispatch");

        assert_eq!(expect_ret(waited), -(ERR_EFAULT as i64));
        assert_eq!(runtime.query_process(child).unwrap().state, ProcessRuntimeStateKind::Zombie);
    }

    #[test]
    fn generic_wait4_pointer_overflow_returns_efault_without_reaping() {
        let mut runtime = test_runtime();
        let child = create_zombie_child(&mut runtime, 5);

        let waited = runtime
            .dispatch_linux_syscall_raw(
                "test_wait4_overflow_status",
                SyscallContext::new(SYS_WAIT4, [child as u64, u32::MAX as u64 + 1, 0, 0, 0, 0]),
            )
            .expect("wait4 dispatch");

        assert_eq!(expect_ret(waited), -(ERR_EFAULT as i64));
        assert_eq!(runtime.query_process(child).unwrap().state, ProcessRuntimeStateKind::Zombie);
    }

    #[test]
    fn generic_exit_marks_process_zombie_and_closes_fds() {
        let mut runtime = test_runtime();
        let pid = runtime.current_pid();
        let tid = runtime.current_tid();
        let (read_fd, write_fd) = runtime.create_pipe_pair().expect("pipe pair");
        assert!(runtime.is_pipe_fd(read_fd));
        assert!(runtime.is_pipe_fd(write_fd));

        let exited = runtime
            .dispatch_linux_syscall_raw(
                "test_exit",
                SyscallContext::new(SYS_EXIT, [23, 0, 0, 0, 0, 0]),
            )
            .expect("exit dispatch");

        assert_eq!(expect_exit(exited), 23);
        let process = runtime.query_process(pid).expect("current process");
        assert_eq!(process.state, ProcessRuntimeStateKind::Zombie);
        assert_eq!(process.exit_code, Some(23));
        assert_eq!(runtime.query_thread(tid).unwrap().state, ThreadRuntimeStateKind::Dead);
        assert!(!runtime.is_pipe_fd(read_fd));
        assert!(!runtime.is_pipe_fd(write_fd));
    }
}

fn ptrace_credentials_match(caller: &ProcessAccessState, target: &ProcessAccessState) -> bool {
    caller.real_uid == target.real_uid
        && caller.real_uid == target.uid
        && caller.real_uid == target.saved_uid
        && caller.real_gid == target.real_gid
        && caller.real_gid == target.gid
        && caller.real_gid == target.saved_gid
}

fn resolve_pid_arg(caller_pid: Pid, pid_arg: i32) -> Result<Pid, i32> {
    if pid_arg < 0 {
        Err(vmos_abi::ERR_EINVAL)
    } else if pid_arg == 0 {
        Ok(caller_pid)
    } else {
        Ok(pid_arg as Pid)
    }
}
