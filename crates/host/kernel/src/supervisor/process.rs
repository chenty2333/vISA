use alloc::vec::Vec;

use semantic_core::{
    CredentialTransitionKind, GuestAddressSpaceRef, LinuxCapSets, ProcessState, TaskState,
};

use super::{
    events::Event,
    linux::{LinuxCallResult, LinuxPlan},
    runtime::PrototypeRuntime,
    types::{
        CAP_SETGID, CAP_SETUID, CAP_SYS_PTRACE, LINUX_KNOWN_CAPS, Pid, ProcessAccessState,
        ProcessRuntimeState, ProcessRuntimeStateKind, RobustListRegistration, RseqRegistration,
        SignalAltStack, TaskId, ThreadRuntimeState, ThreadRuntimeStateKind, Tid,
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
const SA_NOCLDWAIT: u64 = 0x2;
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
        let mut auto_reap = false;
        let mut exited_live_process = false;
        if let Some(proc) = self.processes.iter().find(|p| p.pid == pid) {
            exited_live_process = proc.state != ProcessRuntimeStateKind::Zombie
                && proc.state != ProcessRuntimeStateKind::Dead;
            if exited_live_process && proc.exit_signal == Some(SIGCHLD) {
                let parent_sigchld = self
                    .processes
                    .iter()
                    .find(|parent| parent.pid == proc.ppid)
                    .map(|parent| parent.sigactions[SIGCHLD as usize])
                    .unwrap_or_default();
                auto_reap = parent_sigchld.handler == 1 || parent_sigchld.flags & SA_NOCLDWAIT != 0;
                if parent_sigchld.handler != 1 {
                    parent_signal = Some((proc.ppid, SIGCHLD));
                }
            } else if exited_live_process {
                parent_signal = proc.exit_signal.map(|signal| (proc.ppid, signal));
            }
        }
        if let Some(proc) = self.processes.iter_mut().find(|p| p.pid == pid) {
            if proc.state != ProcessRuntimeStateKind::Zombie
                && proc.state != ProcessRuntimeStateKind::Dead
            {
                if auto_reap {
                    proc.state = ProcessRuntimeStateKind::Dead;
                    proc.exit_code = None;
                } else {
                    proc.state = ProcessRuntimeStateKind::Zombie;
                    proc.exit_code = Some(exit_code);
                }
            }
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
        if exited_live_process {
            let state =
                if auto_reap { ProcessState::Dead } else { ProcessState::Zombie { exit_code } };
            self.semantic.transition_process_state_by_pid(pid, state);
        }
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
        match self.query_wait4(caller_pid, selector, WNOHANG) {
            Ok(Some(_)) | Err(vmos_abi::ERR_ECHILD) => true,
            Ok(None) | Err(_) => false,
        }
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

    pub(super) fn plan_getpid(
        &mut self,
        _plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        Ok(LinuxCallResult::Ret(self.current_pid() as i64))
    }

    pub(super) fn plan_getppid(
        &mut self,
        _plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        let pid = self.current_pid();
        let ppid = self.query_process(pid).map(|process| process.ppid).unwrap_or(pid);
        Ok(LinuxCallResult::Ret(ppid as i64))
    }

    pub(super) fn plan_gettid(
        &mut self,
        _plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        Ok(LinuxCallResult::Ret(self.current_tid() as i64))
    }

    pub(super) fn plan_getuid(
        &mut self,
        _plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        Ok(LinuxCallResult::Ret(self.current_access_state().real_uid as i64))
    }

    pub(super) fn plan_getgid(
        &mut self,
        _plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        Ok(LinuxCallResult::Ret(self.current_access_state().real_gid as i64))
    }

    pub(super) fn plan_geteuid(
        &mut self,
        _plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        Ok(LinuxCallResult::Ret(self.current_access_state().uid as i64))
    }

    pub(super) fn plan_getegid(
        &mut self,
        _plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        Ok(LinuxCallResult::Ret(self.current_access_state().gid as i64))
    }

    pub(super) fn plan_setuid(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let uid = match linux_id_arg(plan.args[0]) {
            Ok(value) => value,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        let before = self.current_access_state();
        let old = before.real_uid;
        let Some(after) = access_setuid(before, uid) else {
            return Ok(LinuxCallResult::Ret(-(vmos_abi::ERR_EPERM as i64)));
        };
        self.apply_current_credential_transition(
            after.clone(),
            CredentialTransitionKind::SetUid { old, new: after.real_uid },
        )
    }

    pub(super) fn plan_setgid(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let gid = match linux_id_arg(plan.args[0]) {
            Ok(value) => value,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        let before = self.current_access_state();
        let old = before.real_gid;
        let Some(after) = access_setgid(before, gid) else {
            return Ok(LinuxCallResult::Ret(-(vmos_abi::ERR_EPERM as i64)));
        };
        self.apply_current_credential_transition(
            after.clone(),
            CredentialTransitionKind::SetGid { old, new: after.real_gid },
        )
    }

    pub(super) fn plan_setreuid(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        let ruid = match optional_linux_id_arg(plan.args[0]) {
            Ok(value) => value,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        let euid = match optional_linux_id_arg(plan.args[1]) {
            Ok(value) => value,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        let Some(after) = access_setreuid(self.current_access_state(), ruid, euid) else {
            return Ok(LinuxCallResult::Ret(-(vmos_abi::ERR_EPERM as i64)));
        };
        self.apply_current_credential_transition(
            after.clone(),
            CredentialTransitionKind::SetReUid { ruid: after.real_uid, euid: after.uid },
        )
    }

    pub(super) fn plan_setregid(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        let rgid = match optional_linux_id_arg(plan.args[0]) {
            Ok(value) => value,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        let egid = match optional_linux_id_arg(plan.args[1]) {
            Ok(value) => value,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        let Some(after) = access_setregid(self.current_access_state(), rgid, egid) else {
            return Ok(LinuxCallResult::Ret(-(vmos_abi::ERR_EPERM as i64)));
        };
        self.apply_current_credential_transition(
            after.clone(),
            CredentialTransitionKind::SetReGid { rgid: after.real_gid, egid: after.gid },
        )
    }

    pub(super) fn plan_setresuid(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        let ruid = match optional_linux_id_arg(plan.args[0]) {
            Ok(value) => value,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        let euid = match optional_linux_id_arg(plan.args[1]) {
            Ok(value) => value,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        let suid = match optional_linux_id_arg(plan.args[2]) {
            Ok(value) => value,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        let before = self.current_access_state();
        let Some(after) = access_setresuid(before.clone(), ruid, euid, suid) else {
            return Ok(LinuxCallResult::Ret(-(vmos_abi::ERR_EPERM as i64)));
        };
        if before.credential_ids_differ(&after)
            || before.cap_permitted != after.cap_permitted
            || before.cap_effective != after.cap_effective
        {
            return self.apply_current_credential_transition(
                after.clone(),
                CredentialTransitionKind::SetResUid {
                    ruid: after.real_uid,
                    euid: after.uid,
                    suid: after.saved_uid,
                },
            );
        }
        Ok(LinuxCallResult::Ret(0))
    }

    pub(super) fn plan_getresuid(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        let access = self.current_access_state();
        match self.write_linux_u32(plan.args[0], access.real_uid) {
            Ok(()) => {}
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        }
        match self.write_linux_u32(plan.args[1], access.uid) {
            Ok(()) => {}
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        }
        match self.write_linux_u32(plan.args[2], access.saved_uid) {
            Ok(()) => {}
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        }
        Ok(LinuxCallResult::Ret(0))
    }

    pub(super) fn plan_setresgid(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        let rgid = match optional_linux_id_arg(plan.args[0]) {
            Ok(value) => value,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        let egid = match optional_linux_id_arg(plan.args[1]) {
            Ok(value) => value,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        let sgid = match optional_linux_id_arg(plan.args[2]) {
            Ok(value) => value,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        let before = self.current_access_state();
        let Some(after) = access_setresgid(before.clone(), rgid, egid, sgid) else {
            return Ok(LinuxCallResult::Ret(-(vmos_abi::ERR_EPERM as i64)));
        };
        if before.credential_ids_differ(&after) {
            return self.apply_current_credential_transition(
                after.clone(),
                CredentialTransitionKind::SetResGid {
                    rgid: after.real_gid,
                    egid: after.gid,
                    sgid: after.saved_gid,
                },
            );
        }
        Ok(LinuxCallResult::Ret(0))
    }

    pub(super) fn plan_getresgid(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        let access = self.current_access_state();
        match self.write_linux_u32(plan.args[0], access.real_gid) {
            Ok(()) => {}
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        }
        match self.write_linux_u32(plan.args[1], access.gid) {
            Ok(()) => {}
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        }
        match self.write_linux_u32(plan.args[2], access.saved_gid) {
            Ok(()) => {}
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        }
        Ok(LinuxCallResult::Ret(0))
    }

    pub(super) fn plan_getgroups(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        let size = match usize::try_from(plan.args[0]) {
            Ok(value) => value,
            Err(_) => return Ok(LinuxCallResult::Ret(-(vmos_abi::ERR_EINVAL as i64))),
        };
        let groups = self.current_access_state().supplementary_groups;
        if size == 0 {
            return Ok(LinuxCallResult::Ret(groups.len() as i64));
        }
        if size < groups.len() {
            return Ok(LinuxCallResult::Ret(-(vmos_abi::ERR_EINVAL as i64)));
        }
        let mut encoded = Vec::with_capacity(groups.len() * 4);
        for group in &groups {
            encoded.extend_from_slice(&group.to_le_bytes());
        }
        match self.write_linux_bytes(plan.args[1], &encoded) {
            Ok(()) => Ok(LinuxCallResult::Ret(groups.len() as i64)),
            Err(errno) => Ok(LinuxCallResult::Ret(-(errno as i64))),
        }
    }

    pub(super) fn plan_setgroups(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        const NGROUPS_MAX: usize = 65_536;

        let size = match usize::try_from(plan.args[0]) {
            Ok(value) => value,
            Err(_) => return Ok(LinuxCallResult::Ret(-(vmos_abi::ERR_EINVAL as i64))),
        };
        if size > NGROUPS_MAX {
            return Ok(LinuxCallResult::Ret(-(vmos_abi::ERR_EINVAL as i64)));
        }
        if !access_has_capability(&self.current_access_state(), CAP_SETGID) {
            return Ok(LinuxCallResult::Ret(-(vmos_abi::ERR_EPERM as i64)));
        }
        let len = match size.checked_mul(4).and_then(|value| u32::try_from(value).ok()) {
            Some(value) => value,
            None => return Ok(LinuxCallResult::Ret(-(vmos_abi::ERR_EINVAL as i64))),
        };
        let bytes = if size == 0 {
            Vec::new()
        } else {
            match self.read_linux_bytes(plan.args[1], len) {
                Ok(bytes) => bytes,
                Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
            }
        };
        let mut groups = Vec::with_capacity(size);
        for chunk in bytes.chunks_exact(4) {
            groups.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
        }
        let mut after = self.current_access_state();
        let old_len = after.supplementary_groups.len();
        after.supplementary_groups = groups;
        self.apply_current_credential_transition(
            after,
            CredentialTransitionKind::SetGroups { old_len, new_len: size },
        )
    }

    pub(super) fn plan_capget(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let (version, pid) = match self.read_linux_cap_header(plan.args[0]) {
            Ok(header) => header,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        if let Err(errno) = self.validate_capability_pid(pid) {
            return Ok(LinuxCallResult::Ret(-(errno as i64)));
        }
        let Some(data_len) = capability_data_len(version) else {
            let _ = self.write_linux_u32(plan.args[0], LINUX_CAPABILITY_VERSION_3);
            return Ok(LinuxCallResult::Ret(-(vmos_abi::ERR_EINVAL as i64)));
        };
        if plan.args[1] != 0 {
            let access = self.current_access_state();
            let encoded = encode_capability_data(access.cap_effective, access.cap_permitted, 0);
            if let Err(errno) = self.write_linux_bytes(plan.args[1], &encoded[..data_len]) {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
        }
        Ok(LinuxCallResult::Ret(0))
    }

    pub(super) fn plan_capset(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        if plan.args[1] == 0 {
            return Ok(LinuxCallResult::Ret(-(vmos_abi::ERR_EFAULT as i64)));
        }
        let (version, pid) = match self.read_linux_cap_header(plan.args[0]) {
            Ok(header) => header,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        if let Err(errno) = self.validate_capability_pid(pid) {
            return Ok(LinuxCallResult::Ret(-(errno as i64)));
        }
        let Some(data_len) = capability_data_len(version) else {
            let _ = self.write_linux_u32(plan.args[0], LINUX_CAPABILITY_VERSION_3);
            return Ok(LinuxCallResult::Ret(-(vmos_abi::ERR_EINVAL as i64)));
        };
        let bytes = match self.read_linux_bytes(plan.args[1], data_len as u32) {
            Ok(bytes) => bytes,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        let (effective, permitted, inheritable) = match decode_capability_data(&bytes) {
            Ok(values) => values,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        let before = self.current_access_state();
        let Some(after) = access_capset(before.clone(), permitted, effective, inheritable) else {
            return Ok(LinuxCallResult::Ret(-(vmos_abi::ERR_EPERM as i64)));
        };
        self.apply_current_credential_transition(
            after.clone(),
            CredentialTransitionKind::CapSet {
                bounding: false,
                inheritable: false,
                permitted: before.cap_permitted != after.cap_permitted,
                effective: before.cap_effective != after.cap_effective,
                ambient: false,
                securebits: false,
            },
        )
    }

    fn apply_current_credential_transition(
        &mut self,
        access: ProcessAccessState,
        kind: CredentialTransitionKind,
    ) -> Result<LinuxCallResult, &'static str> {
        let pid = self.current_pid();
        if self.record_credential_transition(
            pid,
            access.real_uid,
            access.uid,
            access.saved_uid,
            access.fsuid,
            access.real_gid,
            access.gid,
            access.saved_gid,
            access.fsgid,
            access.supplementary_groups.clone(),
            linux_cap_sets_from_access(&access),
            kind,
        ) {
            Ok(LinuxCallResult::Ret(0))
        } else {
            Ok(LinuxCallResult::Ret(-(vmos_abi::ERR_EINVAL as i64)))
        }
    }

    fn read_linux_bytes(&mut self, ptr: u64, len: u32) -> Result<Vec<u8>, i32> {
        let ptr = checked_linux_ptr(ptr)?;
        self.linux.read_bytes(ptr, len).map_err(|_| vmos_abi::ERR_EFAULT)
    }

    fn write_linux_bytes(&mut self, ptr: u64, bytes: &[u8]) -> Result<(), i32> {
        let ptr = checked_linux_ptr(ptr)?;
        self.linux.write_bytes(ptr, bytes).map_err(|_| vmos_abi::ERR_EFAULT)
    }

    fn write_linux_u32(&mut self, ptr: u64, value: u32) -> Result<(), i32> {
        self.write_linux_bytes(ptr, &value.to_le_bytes())
    }

    fn read_linux_cap_header(&mut self, ptr: u64) -> Result<(u32, i32), i32> {
        let bytes = self.read_linux_bytes(ptr, 8)?;
        let version = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let pid = i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        Ok((version, pid))
    }

    fn validate_capability_pid(&self, pid: i32) -> Result<(), i32> {
        if pid < 0 {
            return Err(vmos_abi::ERR_EINVAL);
        }
        if pid != 0 && pid as u32 != self.current_pid() {
            return Err(vmos_abi::ERR_ESRCH);
        }
        Ok(())
    }

    pub(super) fn plan_getpgid(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        let pid_arg = match linux_i32_arg(plan.args[0]) {
            Ok(value) => value,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        match self.get_process_group_id(self.current_pid(), pid_arg) {
            Ok(pgid) => Ok(LinuxCallResult::Ret(pgid as i64)),
            Err(errno) => Ok(LinuxCallResult::Ret(-(errno as i64))),
        }
    }

    pub(super) fn plan_getsid(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let pid_arg = match linux_i32_arg(plan.args[0]) {
            Ok(value) => value,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        match self.get_session_id(self.current_pid(), pid_arg) {
            Ok(sid) => Ok(LinuxCallResult::Ret(sid as i64)),
            Err(errno) => Ok(LinuxCallResult::Ret(-(errno as i64))),
        }
    }

    pub(super) fn plan_setpgid(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        let pid_arg = match linux_i32_arg(plan.args[0]) {
            Ok(value) => value,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        let pgid_arg = match linux_i32_arg(plan.args[1]) {
            Ok(value) => value,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        match self.set_process_group_id(self.current_pid(), pid_arg, pgid_arg) {
            Ok(()) => Ok(LinuxCallResult::Ret(0)),
            Err(errno) => Ok(LinuxCallResult::Ret(-(errno as i64))),
        }
    }

    pub(super) fn plan_setsid(
        &mut self,
        _plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        match self.create_session_for_process(self.current_pid()) {
            Ok(sid) => Ok(LinuxCallResult::Ret(sid as i64)),
            Err(errno) => Ok(LinuxCallResult::Ret(-(errno as i64))),
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

fn optional_linux_ptr(raw: u64) -> Result<Option<u32>, i32> {
    if raw == 0 { Ok(None) } else { u32::try_from(raw).map(Some).map_err(|_| vmos_abi::ERR_EFAULT) }
}

fn checked_linux_ptr(raw: u64) -> Result<u32, i32> {
    if raw == 0 {
        Err(vmos_abi::ERR_EFAULT)
    } else {
        u32::try_from(raw).map_err(|_| vmos_abi::ERR_EFAULT)
    }
}

fn linux_i32_arg(raw: u64) -> Result<i32, i32> {
    let value = raw as i32;
    if raw == value as i64 as u64 { Ok(value) } else { Err(vmos_abi::ERR_EINVAL) }
}

fn linux_id_arg(raw: u64) -> Result<u32, i32> {
    u32::try_from(raw).map_err(|_| vmos_abi::ERR_EINVAL)
}

fn optional_linux_id_arg(raw: u64) -> Result<Option<u32>, i32> {
    if raw == u64::MAX || raw as u32 == u32::MAX { Ok(None) } else { linux_id_arg(raw).map(Some) }
}

fn access_setuid(mut access: ProcessAccessState, uid: u32) -> Option<ProcessAccessState> {
    let old_real = access.real_uid;
    let old_effective = access.uid;
    let old_saved = access.saved_uid;
    if access_has_capability(&access, CAP_SETUID) {
        access.real_uid = uid;
        access.uid = uid;
        access.saved_uid = uid;
        access.fsuid = access.uid;
        fixup_access_caps_after_uid_change(&mut access, old_real, old_effective, old_saved);
        return Some(access);
    }
    if uid == access.real_uid || uid == access.uid || uid == access.saved_uid {
        access.uid = uid;
        access.fsuid = access.uid;
        fixup_access_caps_after_uid_change(&mut access, old_real, old_effective, old_saved);
        return Some(access);
    }
    None
}

fn access_setgid(mut access: ProcessAccessState, gid: u32) -> Option<ProcessAccessState> {
    if access_has_capability(&access, CAP_SETGID) {
        access.real_gid = gid;
        access.gid = gid;
        access.saved_gid = gid;
        access.fsgid = access.gid;
        return Some(access);
    }
    if gid == access.real_gid || gid == access.gid || gid == access.saved_gid {
        access.gid = gid;
        access.fsgid = access.gid;
        return Some(access);
    }
    None
}

fn access_setreuid(
    mut access: ProcessAccessState,
    ruid: Option<u32>,
    euid: Option<u32>,
) -> Option<ProcessAccessState> {
    let privileged = access_has_capability(&access, CAP_SETUID);
    let old_real = access.real_uid;
    let old_effective = access.uid;
    let old_saved = access.saved_uid;
    if !privileged {
        for uid in [ruid, euid].into_iter().flatten() {
            if uid != old_real && uid != old_effective && uid != old_saved {
                return None;
            }
        }
    }
    if let Some(uid) = ruid {
        access.real_uid = uid;
    }
    if let Some(uid) = euid {
        access.uid = uid;
        access.fsuid = access.uid;
    }
    if (privileged && (ruid.is_some() || euid.is_some()))
        || ruid.is_some()
        || euid.is_some_and(|uid| uid != old_real)
    {
        access.saved_uid = access.uid;
    }
    fixup_access_caps_after_uid_change(&mut access, old_real, old_effective, old_saved);
    Some(access)
}

fn access_setregid(
    mut access: ProcessAccessState,
    rgid: Option<u32>,
    egid: Option<u32>,
) -> Option<ProcessAccessState> {
    let privileged = access_has_capability(&access, CAP_SETGID);
    let old_real = access.real_gid;
    let old_effective = access.gid;
    let old_saved = access.saved_gid;
    if !privileged {
        for gid in [rgid, egid].into_iter().flatten() {
            if gid != old_real && gid != old_effective && gid != old_saved {
                return None;
            }
        }
    }
    if let Some(gid) = rgid {
        access.real_gid = gid;
    }
    if let Some(gid) = egid {
        access.gid = gid;
        access.fsgid = access.gid;
    }
    if (privileged && (rgid.is_some() || egid.is_some()))
        || rgid.is_some()
        || egid.is_some_and(|gid| gid != old_real)
    {
        access.saved_gid = access.gid;
    }
    Some(access)
}

fn access_setresuid(
    mut access: ProcessAccessState,
    ruid: Option<u32>,
    euid: Option<u32>,
    suid: Option<u32>,
) -> Option<ProcessAccessState> {
    let privileged = access_has_capability(&access, CAP_SETUID);
    let old_real = access.real_uid;
    let old_effective = access.uid;
    let old_saved = access.saved_uid;
    if !privileged {
        for uid in [ruid, euid, suid].into_iter().flatten() {
            if uid != old_real && uid != old_effective && uid != old_saved {
                return None;
            }
        }
    }
    if let Some(uid) = ruid {
        access.real_uid = uid;
    }
    if let Some(uid) = euid {
        access.uid = uid;
    }
    if let Some(uid) = suid {
        access.saved_uid = uid;
    }
    if ruid.is_some() || euid.is_some() || suid.is_some() {
        access.fsuid = access.uid;
        fixup_access_caps_after_uid_change(&mut access, old_real, old_effective, old_saved);
    }
    Some(access)
}

fn access_setresgid(
    mut access: ProcessAccessState,
    rgid: Option<u32>,
    egid: Option<u32>,
    sgid: Option<u32>,
) -> Option<ProcessAccessState> {
    let privileged = access_has_capability(&access, CAP_SETGID);
    let old_real = access.real_gid;
    let old_effective = access.gid;
    let old_saved = access.saved_gid;
    if !privileged {
        for gid in [rgid, egid, sgid].into_iter().flatten() {
            if gid != old_real && gid != old_effective && gid != old_saved {
                return None;
            }
        }
    }
    if let Some(gid) = rgid {
        access.real_gid = gid;
    }
    if let Some(gid) = egid {
        access.gid = gid;
    }
    if let Some(gid) = sgid {
        access.saved_gid = gid;
    }
    if rgid.is_some() || egid.is_some() || sgid.is_some() {
        access.fsgid = access.gid;
    }
    Some(access)
}

fn access_capset(
    mut access: ProcessAccessState,
    permitted: u64,
    effective: u64,
    inheritable: u64,
) -> Option<ProcessAccessState> {
    let permitted = permitted & LINUX_KNOWN_CAPS;
    let effective = effective & LINUX_KNOWN_CAPS;
    let inheritable = inheritable & LINUX_KNOWN_CAPS;
    if inheritable != 0 || permitted & !access.cap_permitted != 0 || effective & !permitted != 0 {
        return None;
    }
    access.cap_permitted = permitted;
    access.cap_effective = effective;
    Some(access)
}

fn access_has_capability(access: &ProcessAccessState, capability: u64) -> bool {
    access.cap_effective & capability != 0
}

fn fixup_access_caps_after_uid_change(
    access: &mut ProcessAccessState,
    old_real: u32,
    old_effective: u32,
    old_saved: u32,
) {
    let had_root_uid = old_real == 0 || old_effective == 0 || old_saved == 0;
    let has_root_uid = access.real_uid == 0 || access.uid == 0 || access.saved_uid == 0;
    if had_root_uid && !has_root_uid {
        access.cap_effective = 0;
        access.cap_permitted = 0;
        return;
    }
    if old_effective == 0 && access.uid != 0 {
        access.cap_effective = 0;
        return;
    }
    if old_effective != 0 && access.uid == 0 {
        access.cap_effective = access.cap_permitted & LINUX_KNOWN_CAPS;
    }
}

fn linux_cap_sets_from_access(access: &ProcessAccessState) -> LinuxCapSets {
    LinuxCapSets {
        bounding: LINUX_KNOWN_CAPS,
        inheritable: 0,
        permitted: access.cap_permitted & LINUX_KNOWN_CAPS,
        effective: access.cap_effective & LINUX_KNOWN_CAPS,
        ambient: 0,
        securebits: 0,
    }
}

const LINUX_CAPABILITY_VERSION_1: u32 = 0x1998_0330;
const LINUX_CAPABILITY_VERSION_2: u32 = 0x2007_1026;
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

fn capability_data_len(version: u32) -> Option<usize> {
    match version {
        LINUX_CAPABILITY_VERSION_1 => Some(12),
        LINUX_CAPABILITY_VERSION_2 | LINUX_CAPABILITY_VERSION_3 => Some(24),
        _ => None,
    }
}

fn encode_capability_data(effective: u64, permitted: u64, inheritable: u64) -> [u8; 24] {
    let words = [
        effective as u32,
        permitted as u32,
        inheritable as u32,
        (effective >> 32) as u32,
        (permitted >> 32) as u32,
        (inheritable >> 32) as u32,
    ];
    let mut out = [0u8; 24];
    let mut index = 0;
    while index < words.len() {
        out[index * 4..index * 4 + 4].copy_from_slice(&words[index].to_le_bytes());
        index += 1;
    }
    out
}

fn decode_capability_data(bytes: &[u8]) -> Result<(u64, u64, u64), i32> {
    if bytes.len() != 12 && bytes.len() != 24 {
        return Err(vmos_abi::ERR_EINVAL);
    }
    let read = |index: usize| -> u32 {
        u32::from_le_bytes([
            bytes[index * 4],
            bytes[index * 4 + 1],
            bytes[index * 4 + 2],
            bytes[index * 4 + 3],
        ])
    };
    let effective = read(0) as u64 | if bytes.len() == 24 { (read(3) as u64) << 32 } else { 0 };
    let permitted = read(1) as u64 | if bytes.len() == 24 { (read(4) as u64) << 32 } else { 0 };
    let inheritable = read(2) as u64 | if bytes.len() == 24 { (read(5) as u64) << 32 } else { 0 };
    Ok((effective, permitted, inheritable))
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
    use alloc::{boxed::Box, vec::Vec};

    use vmos_abi::{
        ERR_ECHILD, ERR_EFAULT, ERR_EINVAL, ERR_EPERM, SYS_CAPGET, SYS_CAPSET, SYS_EXIT,
        SYS_GETEGID, SYS_GETEUID, SYS_GETGID, SYS_GETGROUPS, SYS_GETPGID, SYS_GETPID, SYS_GETPPID,
        SYS_GETRESGID, SYS_GETRESUID, SYS_GETSID, SYS_GETTID, SYS_GETUID, SYS_SETGID,
        SYS_SETGROUPS, SYS_SETPGID, SYS_SETREGID, SYS_SETRESGID, SYS_SETRESUID, SYS_SETREUID,
        SYS_SETSID, SYS_SETUID, SYS_WAIT4, SyscallContext,
    };

    use super::*;
    use crate::supervisor::{engine::RuntimeOnlyExecutor, types::SigAction};

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
        let child = create_running_child(runtime);
        runtime.process_exit(child, exit_code);
        child
    }

    fn create_running_child(runtime: &mut PrototypeRuntime<'static>) -> Pid {
        let parent = runtime.current_pid();
        let child = runtime.allocate_process(parent, parent, parent);
        let task = runtime.allocate_task();
        runtime.allocate_thread(task, child);
        child
    }

    fn create_running_sigchld_child(runtime: &mut PrototypeRuntime<'static>) -> Pid {
        let child = create_running_child(runtime);
        runtime
            .processes
            .iter_mut()
            .find(|process| process.pid == child)
            .expect("child process")
            .exit_signal = Some(SIGCHLD);
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

    #[test]
    fn generic_process_metadata_queries_use_runtime_state() {
        let mut runtime = test_runtime();
        let pid = runtime.current_pid();
        let tid = runtime.current_tid();
        let Some(process) = runtime.processes.iter_mut().find(|process| process.pid == pid) else {
            panic!("current process missing");
        };
        process.access = ProcessAccessState::from_credentials(
            1000,
            2000,
            3000,
            4000,
            100,
            200,
            300,
            400,
            Vec::new(),
            0,
            0,
        );

        let getpid = runtime
            .dispatch_linux_syscall_raw(
                "test_getpid",
                SyscallContext::new(SYS_GETPID, [0, 0, 0, 0, 0, 0]),
            )
            .expect("getpid dispatch");
        assert_eq!(expect_ret(getpid), pid as i64);

        let gettid = runtime
            .dispatch_linux_syscall_raw(
                "test_gettid",
                SyscallContext::new(SYS_GETTID, [0, 0, 0, 0, 0, 0]),
            )
            .expect("gettid dispatch");
        assert_eq!(expect_ret(gettid), tid as i64);

        let getuid = runtime
            .dispatch_linux_syscall_raw(
                "test_getuid",
                SyscallContext::new(SYS_GETUID, [0, 0, 0, 0, 0, 0]),
            )
            .expect("getuid dispatch");
        assert_eq!(expect_ret(getuid), 1000);

        let geteuid = runtime
            .dispatch_linux_syscall_raw(
                "test_geteuid",
                SyscallContext::new(SYS_GETEUID, [0, 0, 0, 0, 0, 0]),
            )
            .expect("geteuid dispatch");
        assert_eq!(expect_ret(geteuid), 2000);

        let getgid = runtime
            .dispatch_linux_syscall_raw(
                "test_getgid",
                SyscallContext::new(SYS_GETGID, [0, 0, 0, 0, 0, 0]),
            )
            .expect("getgid dispatch");
        assert_eq!(expect_ret(getgid), 100);

        let getegid = runtime
            .dispatch_linux_syscall_raw(
                "test_getegid",
                SyscallContext::new(SYS_GETEGID, [0, 0, 0, 0, 0, 0]),
            )
            .expect("getegid dispatch");
        assert_eq!(expect_ret(getegid), 200);

        let getppid = runtime
            .dispatch_linux_syscall_raw(
                "test_getppid",
                SyscallContext::new(SYS_GETPPID, [0, 0, 0, 0, 0, 0]),
            )
            .expect("getppid dispatch");
        assert_eq!(expect_ret(getppid), 0);

        let getpgid = runtime
            .dispatch_linux_syscall_raw(
                "test_getpgid",
                SyscallContext::new(SYS_GETPGID, [0, 0, 0, 0, 0, 0]),
            )
            .expect("getpgid dispatch");
        assert_eq!(expect_ret(getpgid), pid as i64);

        let getsid = runtime
            .dispatch_linux_syscall_raw(
                "test_getsid",
                SyscallContext::new(SYS_GETSID, [0, 0, 0, 0, 0, 0]),
            )
            .expect("getsid dispatch");
        assert_eq!(expect_ret(getsid), pid as i64);
    }

    #[test]
    fn generic_process_group_and_session_mutations_report_runtime_errors() {
        let mut runtime = test_runtime();
        let pid = runtime.current_pid();

        let setsid = runtime
            .dispatch_linux_syscall_raw(
                "test_setsid",
                SyscallContext::new(SYS_SETSID, [0, 0, 0, 0, 0, 0]),
            )
            .expect("setsid dispatch");
        assert_eq!(expect_ret(setsid), -(vmos_abi::ERR_EPERM as i64));

        let bad_pgid = runtime
            .dispatch_linux_syscall_raw(
                "test_setpgid_bad",
                SyscallContext::new(SYS_SETPGID, [pid as u64, u64::MAX, 0, 0, 0, 0]),
            )
            .expect("bad setpgid dispatch");
        assert_eq!(expect_ret(bad_pgid), -(vmos_abi::ERR_EINVAL as i64));
    }

    #[test]
    fn generic_credential_mutations_update_runtime_state() {
        let mut runtime = test_runtime();

        let setgid = runtime
            .dispatch_linux_syscall_raw(
                "test_setgid",
                SyscallContext::new(SYS_SETGID, [100, 0, 0, 0, 0, 0]),
            )
            .expect("setgid dispatch");
        assert_eq!(expect_ret(setgid), 0);
        let access = runtime.current_access_state();
        assert_eq!(access.real_gid, 100);
        assert_eq!(access.gid, 100);
        assert_eq!(access.saved_gid, 100);
        assert_eq!(access.fsgid, 100);

        let setuid = runtime
            .dispatch_linux_syscall_raw(
                "test_setuid",
                SyscallContext::new(SYS_SETUID, [1000, 0, 0, 0, 0, 0]),
            )
            .expect("setuid dispatch");
        assert_eq!(expect_ret(setuid), 0);
        let access = runtime.current_access_state();
        assert_eq!(access.real_uid, 1000);
        assert_eq!(access.uid, 1000);
        assert_eq!(access.saved_uid, 1000);
        assert_eq!(access.fsuid, 1000);
        assert_eq!(access.cap_permitted, 0);
        assert_eq!(access.cap_effective, 0);

        let denied = runtime
            .dispatch_linux_syscall_raw(
                "test_setuid_denied",
                SyscallContext::new(SYS_SETUID, [0, 0, 0, 0, 0, 0]),
            )
            .expect("setuid denied dispatch");
        assert_eq!(expect_ret(denied), -(ERR_EPERM as i64));
    }

    #[test]
    fn generic_reuid_regid_mutations_follow_saved_id_rules() {
        let mut runtime = test_runtime();

        let setreuid = runtime
            .dispatch_linux_syscall_raw(
                "test_setreuid",
                SyscallContext::new(SYS_SETREUID, [1000, 2000, 0, 0, 0, 0]),
            )
            .expect("setreuid dispatch");
        assert_eq!(expect_ret(setreuid), 0);
        let access = runtime.current_access_state();
        assert_eq!(access.real_uid, 1000);
        assert_eq!(access.uid, 2000);
        assert_eq!(access.saved_uid, 2000);
        assert_eq!(access.fsuid, 2000);
        assert_eq!(access.cap_permitted, 0);
        assert_eq!(access.cap_effective, 0);

        let regain_saved = runtime
            .dispatch_linux_syscall_raw(
                "test_setreuid_saved",
                SyscallContext::new(SYS_SETREUID, [u64::MAX, 1000, 0, 0, 0, 0]),
            )
            .expect("setreuid saved dispatch");
        assert_eq!(expect_ret(regain_saved), 0);
        assert_eq!(runtime.current_access_state().uid, 1000);

        let denied = runtime
            .dispatch_linux_syscall_raw(
                "test_setreuid_denied",
                SyscallContext::new(SYS_SETREUID, [u64::MAX, 3000, 0, 0, 0, 0]),
            )
            .expect("setreuid denied dispatch");
        assert_eq!(expect_ret(denied), -(ERR_EPERM as i64));

        let mut runtime = test_runtime();
        let setregid = runtime
            .dispatch_linux_syscall_raw(
                "test_setregid",
                SyscallContext::new(SYS_SETREGID, [100, 200, 0, 0, 0, 0]),
            )
            .expect("setregid dispatch");
        assert_eq!(expect_ret(setregid), 0);
        let access = runtime.current_access_state();
        assert_eq!(access.real_gid, 100);
        assert_eq!(access.gid, 200);
        assert_eq!(access.saved_gid, 200);
        assert_eq!(access.fsgid, 200);
    }

    #[test]
    fn generic_resuid_resgid_and_groups_use_runtime_credentials() {
        let mut runtime = test_runtime();

        let setresuid = runtime
            .dispatch_linux_syscall_raw(
                "test_setresuid",
                SyscallContext::new(SYS_SETRESUID, [1000, 2000, 3000, 0, 0, 0]),
            )
            .expect("setresuid dispatch");
        assert_eq!(expect_ret(setresuid), 0);
        let access = runtime.current_access_state();
        assert_eq!(access.real_uid, 1000);
        assert_eq!(access.uid, 2000);
        assert_eq!(access.saved_uid, 3000);
        assert_eq!(access.fsuid, 2000);
        assert_eq!(access.cap_permitted, 0);
        assert_eq!(access.cap_effective, 0);

        let denied = runtime
            .dispatch_linux_syscall_raw(
                "test_setresuid_denied",
                SyscallContext::new(SYS_SETRESUID, [u64::MAX, 4000, u64::MAX, 0, 0, 0]),
            )
            .expect("setresuid denied dispatch");
        assert_eq!(expect_ret(denied), -(ERR_EPERM as i64));

        let (uid_ptr, _) = runtime.linux.write_arg_bytes(&[0; 12]).expect("uid buffer");
        let getresuid = runtime
            .dispatch_linux_syscall_raw(
                "test_getresuid",
                SyscallContext::new(
                    SYS_GETRESUID,
                    [uid_ptr as u64, uid_ptr as u64 + 4, uid_ptr as u64 + 8, 0, 0, 0],
                ),
            )
            .expect("getresuid dispatch");
        assert_eq!(expect_ret(getresuid), 0);
        let uid_bytes = runtime.linux.read_bytes(uid_ptr, 12).expect("uid bytes");
        assert_eq!(u32::from_le_bytes(uid_bytes[0..4].try_into().unwrap()), 1000);
        assert_eq!(u32::from_le_bytes(uid_bytes[4..8].try_into().unwrap()), 2000);
        assert_eq!(u32::from_le_bytes(uid_bytes[8..12].try_into().unwrap()), 3000);

        let mut runtime = test_runtime();
        let empty_null = runtime
            .dispatch_linux_syscall_raw(
                "test_getgroups_empty_null",
                SyscallContext::new(SYS_GETGROUPS, [1, 0, 0, 0, 0, 0]),
            )
            .expect("getgroups empty null dispatch");
        assert_eq!(expect_ret(empty_null), -(ERR_EFAULT as i64));

        let setgroups_bytes = [10u32.to_le_bytes(), 20u32.to_le_bytes()].concat();
        let (groups_ptr, _) =
            runtime.linux.write_arg_bytes(&setgroups_bytes).expect("groups input");
        let setgroups = runtime
            .dispatch_linux_syscall_raw(
                "test_setgroups",
                SyscallContext::new(SYS_SETGROUPS, [2, groups_ptr as u64, 0, 0, 0, 0]),
            )
            .expect("setgroups dispatch");
        assert_eq!(expect_ret(setgroups), 0);
        assert_eq!(runtime.current_access_state().supplementary_groups, &[10, 20]);

        let count_only = runtime
            .dispatch_linux_syscall_raw(
                "test_getgroups_count",
                SyscallContext::new(SYS_GETGROUPS, [0, 0, 0, 0, 0, 0]),
            )
            .expect("getgroups count dispatch");
        assert_eq!(expect_ret(count_only), 2);

        let (groups_out_ptr, _) = runtime.linux.write_arg_bytes(&[0; 8]).expect("groups output");
        let getgroups = runtime
            .dispatch_linux_syscall_raw(
                "test_getgroups",
                SyscallContext::new(SYS_GETGROUPS, [2, groups_out_ptr as u64, 0, 0, 0, 0]),
            )
            .expect("getgroups dispatch");
        assert_eq!(expect_ret(getgroups), 2);
        let out = runtime.linux.read_bytes(groups_out_ptr, 8).expect("groups bytes");
        assert_eq!(u32::from_le_bytes(out[0..4].try_into().unwrap()), 10);
        assert_eq!(u32::from_le_bytes(out[4..8].try_into().unwrap()), 20);

        let short = runtime
            .dispatch_linux_syscall_raw(
                "test_getgroups_short",
                SyscallContext::new(SYS_GETGROUPS, [1, groups_out_ptr as u64, 0, 0, 0, 0]),
            )
            .expect("getgroups short dispatch");
        assert_eq!(expect_ret(short), -(ERR_EINVAL as i64));

        let setresgid = runtime
            .dispatch_linux_syscall_raw(
                "test_setresgid",
                SyscallContext::new(SYS_SETRESGID, [100, 200, 300, 0, 0, 0]),
            )
            .expect("setresgid dispatch");
        assert_eq!(expect_ret(setresgid), 0);
        let access = runtime.current_access_state();
        assert_eq!(access.real_gid, 100);
        assert_eq!(access.gid, 200);
        assert_eq!(access.saved_gid, 300);
        assert_eq!(access.fsgid, 200);

        let (gid_ptr, _) = runtime.linux.write_arg_bytes(&[0; 12]).expect("gid buffer");
        let getresgid = runtime
            .dispatch_linux_syscall_raw(
                "test_getresgid",
                SyscallContext::new(
                    SYS_GETRESGID,
                    [gid_ptr as u64, gid_ptr as u64 + 4, gid_ptr as u64 + 8, 0, 0, 0],
                ),
            )
            .expect("getresgid dispatch");
        assert_eq!(expect_ret(getresgid), 0);
        let gid_bytes = runtime.linux.read_bytes(gid_ptr, 12).expect("gid bytes");
        assert_eq!(u32::from_le_bytes(gid_bytes[0..4].try_into().unwrap()), 100);
        assert_eq!(u32::from_le_bytes(gid_bytes[4..8].try_into().unwrap()), 200);
        assert_eq!(u32::from_le_bytes(gid_bytes[8..12].try_into().unwrap()), 300);
    }

    #[test]
    fn generic_capget_capset_uses_bounded_runtime_capability_sets() {
        let mut runtime = test_runtime();
        let mut cap_buffer = Vec::new();
        cap_buffer.extend_from_slice(&LINUX_CAPABILITY_VERSION_3.to_le_bytes());
        cap_buffer.extend_from_slice(&0i32.to_le_bytes());
        cap_buffer.extend_from_slice(&[0; 24]);
        let (header_ptr, _) = runtime.linux.write_arg_bytes(&cap_buffer).expect("cap buffer");
        let data_ptr = header_ptr + 8;

        let capget = runtime
            .dispatch_linux_syscall_raw(
                "test_capget",
                SyscallContext::new(SYS_CAPGET, [header_ptr as u64, data_ptr as u64, 0, 0, 0, 0]),
            )
            .expect("capget dispatch");
        assert_eq!(expect_ret(capget), 0);
        let data = runtime.linux.read_bytes(data_ptr, 24).expect("capget data");
        assert_eq!(u32::from_le_bytes(data[0..4].try_into().unwrap()), LINUX_KNOWN_CAPS as u32);
        assert_eq!(u32::from_le_bytes(data[4..8].try_into().unwrap()), LINUX_KNOWN_CAPS as u32);
        assert_eq!(u32::from_le_bytes(data[8..12].try_into().unwrap()), 0);

        let lowered = encode_capability_data(CAP_SETUID, CAP_SETUID, 0);
        runtime.linux.write_bytes(data_ptr, &lowered).expect("capset data");
        let capset = runtime
            .dispatch_linux_syscall_raw(
                "test_capset",
                SyscallContext::new(SYS_CAPSET, [header_ptr as u64, data_ptr as u64, 0, 0, 0, 0]),
            )
            .expect("capset dispatch");
        assert_eq!(expect_ret(capset), 0);
        let access = runtime.current_access_state();
        assert_eq!(access.cap_permitted, CAP_SETUID);
        assert_eq!(access.cap_effective, CAP_SETUID);

        let raised = encode_capability_data(LINUX_KNOWN_CAPS, LINUX_KNOWN_CAPS, 0);
        runtime.linux.write_bytes(data_ptr, &raised).expect("raised capset data");
        let denied = runtime
            .dispatch_linux_syscall_raw(
                "test_capset_raise_denied",
                SyscallContext::new(SYS_CAPSET, [header_ptr as u64, data_ptr as u64, 0, 0, 0, 0]),
            )
            .expect("capset raise denied dispatch");
        assert_eq!(expect_ret(denied), -(ERR_EPERM as i64));

        let inheritable = encode_capability_data(CAP_SETUID, CAP_SETUID, CAP_SETUID);
        runtime.linux.write_bytes(data_ptr, &inheritable).expect("inheritable capset data");
        let denied = runtime
            .dispatch_linux_syscall_raw(
                "test_capset_inheritable_denied",
                SyscallContext::new(SYS_CAPSET, [header_ptr as u64, data_ptr as u64, 0, 0, 0, 0]),
            )
            .expect("capset inheritable denied dispatch");
        assert_eq!(expect_ret(denied), -(ERR_EPERM as i64));
    }

    #[test]
    fn ignored_sigchld_auto_reaps_child_and_wait4_reports_echild() {
        let mut runtime = test_runtime();
        let parent = runtime.current_pid();
        assert!(runtime.set_sigaction(
            parent,
            SIGCHLD,
            SigAction { handler: 1, ..SigAction::default() },
        ));
        let child = create_running_sigchld_child(&mut runtime);

        runtime.process_exit(child, 9);

        let process = runtime.query_process(child).expect("child process");
        assert_eq!(process.state, ProcessRuntimeStateKind::Dead);
        assert_eq!(process.exit_code, None);
        let waited = runtime
            .dispatch_linux_syscall_raw(
                "test_wait4_ignored_sigchld",
                SyscallContext::new(SYS_WAIT4, [child as u64, 0, 0, 0, 0, 0]),
            )
            .expect("wait4 dispatch");
        assert_eq!(expect_ret(waited), -(ERR_ECHILD as i64));
    }

    #[test]
    fn no_cldwait_auto_reaps_child_but_keeps_sigchld_delivery() {
        let mut runtime = test_runtime();
        let parent = runtime.current_pid();
        let parent_tid = runtime.current_tid();
        assert!(runtime.set_sigaction(
            parent,
            SIGCHLD,
            SigAction { flags: SA_NOCLDWAIT, ..SigAction::default() },
        ));
        let child = create_running_sigchld_child(&mut runtime);

        runtime.process_exit(child, 11);

        let process = runtime.query_process(child).expect("child process");
        assert_eq!(process.state, ProcessRuntimeStateKind::Dead);
        assert_eq!(process.exit_code, None);
        let parent_thread = runtime.query_thread(parent_tid).expect("parent thread");
        assert!(parent_thread.pending_signals.iter().any(|signal| signal.signo == SIGCHLD));
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
