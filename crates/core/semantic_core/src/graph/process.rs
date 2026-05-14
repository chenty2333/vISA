use alloc::{format, string::String};

use super::*;

impl SemanticGraph {
    // ── Process ──

    pub fn create_process(
        &mut self,
        pid: u32,
        parent_pid: Option<u32>,
        pgid: u32,
        sid: u32,
        thread_group: ContractObjectRef,
        exit_signal: Option<u8>,
    ) -> Option<ProcessId> {
        let id = self.domains.process.next_process_id;
        self.domains.process.next_process_id = id.max(id + 1);
        if self.create_process_with_id(id, pid, parent_pid, pgid, sid, thread_group, exit_signal) {
            Some(id)
        } else {
            self.domains.process.next_process_id = id; // rollback
            None
        }
    }

    pub fn create_process_with_id(
        &mut self,
        id: ProcessId,
        pid: u32,
        parent_pid: Option<u32>,
        pgid: u32,
        sid: u32,
        thread_group: ContractObjectRef,
        exit_signal: Option<u8>,
    ) -> bool {
        if id == 0 || self.domains.process.processes.iter().any(|r| r.id == id) {
            return false;
        }
        if thread_group.kind != ContractObjectKind::ThreadGroup || thread_group.id == 0 {
            return false;
        }
        let recorded_at_event =
            self.event_log.push("process", EventKind::ProcessCreated { pid, parent_pid });
        self.domains.process.processes.push(ProcessRecord {
            id,
            pid,
            parent_pid,
            pgid,
            sid,
            thread_group,
            children: Vec::new(),
            state: ProcessState::Running,
            exit_signal,
            recorded_at_event,
            generation: 1,
            note: String::new(),
        });
        true
    }

    pub fn query_process(&self, id: ProcessId) -> Option<&ProcessRecord> {
        self.domains.process.processes.iter().find(|r| r.id == id)
    }

    pub fn transition_process_state(
        &mut self,
        id: ProcessId,
        generation: Generation,
        new_state: ProcessState,
    ) -> bool {
        let Some(record) = self
            .domains
            .process
            .processes
            .iter_mut()
            .find(|r| r.id == id && r.generation == generation)
        else {
            return false;
        };
        let old_state = record.state.clone();
        let old_str = format!("{0:?}", old_state);
        record.state = new_state;
        let new_str = format!("{0:?}", record.state);
        record.generation += 1;
        self.event_log.push(
            "process",
            EventKind::ProcessStateChanged {
                pid: record.pid,
                old_state: old_str,
                new_state: new_str,
            },
        );
        true
    }

    // ── Thread ──

    pub fn create_thread(
        &mut self,
        tid: u32,
        task_id: u64,
        process: ContractObjectRef,
        aspace: ContractObjectRef,
        fd_table: ContractObjectRef,
        credential: ContractObjectRef,
        thread_group: ContractObjectRef,
    ) -> Option<ThreadId> {
        let id = self.domains.process.next_thread_id;
        self.domains.process.next_thread_id = id.max(id + 1);
        if self.create_thread_with_id(
            id,
            tid,
            task_id,
            process,
            aspace,
            fd_table,
            credential,
            thread_group,
        ) {
            Some(id)
        } else {
            self.domains.process.next_thread_id = id;
            None
        }
    }

    pub fn create_thread_with_id(
        &mut self,
        id: ThreadId,
        tid: u32,
        task_id: u64,
        process: ContractObjectRef,
        aspace: ContractObjectRef,
        fd_table: ContractObjectRef,
        credential: ContractObjectRef,
        thread_group: ContractObjectRef,
    ) -> bool {
        if id == 0 || self.domains.process.threads.iter().any(|r| r.id == id) {
            return false;
        }
        // Validate cross-ref kinds
        if process.kind != ContractObjectKind::Process || process.id == 0 {
            return false;
        }
        if aspace.kind != ContractObjectKind::GuestAddressSpace || aspace.id == 0 {
            return false;
        }
        if fd_table.kind != ContractObjectKind::FdTable || fd_table.id == 0 {
            return false;
        }
        if credential.kind != ContractObjectKind::Credential || credential.id == 0 {
            return false;
        }
        if thread_group.kind != ContractObjectKind::ThreadGroup || thread_group.id == 0 {
            return false;
        }
        // Validate cross-ref existence
        if !self.domains.process.processes.iter().any(|r| r.object_ref() == process) {
            return false;
        }
        if !self.domains.process.fd_tables.iter().any(|r| r.object_ref() == fd_table) {
            return false;
        }
        if !self.domains.process.credentials.iter().any(|r| r.object_ref() == credential) {
            return false;
        }
        if !self.domains.process.thread_groups.iter().any(|r| r.object_ref() == thread_group) {
            return false;
        }
        let recorded_at_event =
            self.event_log.push("thread", EventKind::ThreadCreated { tid, task_id });
        self.domains.process.threads.push(ThreadRecord {
            id,
            tid,
            task_id,
            process,
            aspace,
            fd_table,
            credential,
            thread_group,
            interrupted_activation: None,
            arch_regs_evidence: None,
            clear_child_tid: None,
            robust_list_head: None,
            robust_list_len: 0,
            state: ThreadState::Running,
            recorded_at_event,
            generation: 1,
            note: String::new(),
        });
        true
    }

    pub fn query_thread(&self, id: ThreadId) -> Option<&ThreadRecord> {
        self.domains.process.threads.iter().find(|r| r.id == id)
    }

    // ── ThreadGroup ──

    pub fn create_thread_group(
        &mut self,
        tgid: u32,
        leader: ContractObjectRef,
    ) -> Option<ThreadGroupId> {
        let id = self.domains.process.next_thread_group_id;
        self.domains.process.next_thread_group_id = id.max(id + 1);
        if self.create_thread_group_with_id(id, tgid, leader) {
            Some(id)
        } else {
            self.domains.process.next_thread_group_id = id;
            None
        }
    }

    pub fn create_thread_group_with_id(
        &mut self,
        id: ThreadGroupId,
        tgid: u32,
        leader: ContractObjectRef,
    ) -> bool {
        if id == 0 || self.domains.process.thread_groups.iter().any(|r| r.id == id) {
            return false;
        }
        if leader.kind != ContractObjectKind::Thread || leader.id == 0 {
            return false;
        }
        if !self.domains.process.threads.iter().any(|r| r.object_ref() == leader) {
            return false;
        }
        let recorded_at_event =
            self.event_log.push("thread-group", EventKind::ThreadGroupCreated { tgid });
        self.domains.process.thread_groups.push(ThreadGroupRecord {
            id,
            tgid,
            leader,
            signal_disposition: None,
            recorded_at_event,
            generation: 1,
            note: String::new(),
        });
        true
    }

    pub fn query_thread_group(&self, id: ThreadGroupId) -> Option<&ThreadGroupRecord> {
        self.domains.process.thread_groups.iter().find(|r| r.id == id)
    }

    // ── FdTable ──

    pub fn create_fd_table(
        &mut self,
        owner_thread_group: ContractObjectRef,
        shared: bool,
    ) -> Option<FdTableId> {
        let id = self.domains.process.next_fd_table_id;
        self.domains.process.next_fd_table_id = id.max(id + 1);
        if self.create_fd_table_with_id(id, owner_thread_group, shared) {
            Some(id)
        } else {
            self.domains.process.next_fd_table_id = id;
            None
        }
    }

    pub fn create_fd_table_with_id(
        &mut self,
        id: FdTableId,
        owner_thread_group: ContractObjectRef,
        shared: bool,
    ) -> bool {
        if id == 0 || self.domains.process.fd_tables.iter().any(|r| r.id == id) {
            return false;
        }
        if owner_thread_group.kind != ContractObjectKind::ThreadGroup || owner_thread_group.id == 0
        {
            return false;
        }
        if !self.domains.process.thread_groups.iter().any(|r| r.object_ref() == owner_thread_group)
        {
            return false;
        }
        let recorded_at_event =
            self.event_log.push("fd-table", EventKind::FdTableCreated { shared });
        self.domains.process.fd_tables.push(FdTableRecord {
            id,
            owner_thread_group,
            shared,
            recorded_at_event,
            generation: 1,
            note: String::new(),
        });
        true
    }

    pub fn query_fd_table(&self, id: FdTableId) -> Option<&FdTableRecord> {
        self.domains.process.fd_tables.iter().find(|r| r.id == id)
    }

    // ── Credential ──

    pub fn create_credential(
        &mut self,
        owner_process: ContractObjectRef,
        uid: u32,
        euid: u32,
        suid: u32,
        fsuid: u32,
        gid: u32,
        egid: u32,
        sgid: u32,
        fsgid: u32,
    ) -> Option<CredentialId> {
        let id = self.domains.process.next_credential_id;
        self.domains.process.next_credential_id = id.max(id + 1);
        if self.create_credential_with_id(
            id,
            owner_process,
            uid,
            euid,
            suid,
            fsuid,
            gid,
            egid,
            sgid,
            fsgid,
        ) {
            Some(id)
        } else {
            self.domains.process.next_credential_id = id;
            None
        }
    }

    pub fn create_credential_with_id(
        &mut self,
        id: CredentialId,
        owner_process: ContractObjectRef,
        uid: u32,
        euid: u32,
        suid: u32,
        fsuid: u32,
        gid: u32,
        egid: u32,
        sgid: u32,
        fsgid: u32,
    ) -> bool {
        if id == 0 || self.domains.process.credentials.iter().any(|r| r.id == id) {
            return false;
        }
        if owner_process.kind != ContractObjectKind::Process || owner_process.id == 0 {
            return false;
        }
        if !self.domains.process.processes.iter().any(|r| r.object_ref() == owner_process) {
            return false;
        }
        let recorded_at_event =
            self.event_log.push("credential", EventKind::CredentialCreated { uid, gid });
        self.domains.process.credentials.push(CredentialRecord {
            id,
            owner_process,
            uid,
            euid,
            suid,
            fsuid,
            gid,
            egid,
            sgid,
            fsgid,
            supplementary_groups: Vec::new(),
            capability_sets: LinuxCapSets::default(),
            recorded_at_event,
            generation: 1,
            note: String::new(),
        });
        true
    }

    pub fn query_credential(&self, id: CredentialId) -> Option<&CredentialRecord> {
        self.domains.process.credentials.iter().find(|r| r.id == id)
    }

    // ── CredentialTransition ──

    pub fn record_credential_transition(
        &mut self,
        from: ContractObjectRef,
        to: ContractObjectRef,
        kind: CredentialTransitionKind,
        broadcast: bool,
    ) -> Option<CredentialTransitionId> {
        if from.kind != ContractObjectKind::Credential || from.id == 0 {
            return None;
        }
        if to.kind != ContractObjectKind::Credential || to.id == 0 {
            return None;
        }
        if !self.domains.process.credentials.iter().any(|r| r.object_ref() == from) {
            return None;
        }
        if !self.domains.process.credentials.iter().any(|r| r.object_ref() == to) {
            return None;
        }
        let id = self.domains.process.next_credential_transition_id;
        self.domains.process.next_credential_transition_id = id.max(id + 1);
        let recorded_at_event =
            self.event_log.push("credential", EventKind::CredentialTransition { from_id: from.id });
        self.domains.process.credential_transitions.push(CredentialTransitionRecord {
            id,
            from_credential: from,
            to_credential: to,
            transition_kind: kind,
            broadcast_to_thread_group: broadcast,
            recorded_at_event,
            generation: 1,
            note: String::new(),
        });
        Some(id)
    }

    // ── Invariants ──

    pub fn check_process_invariants(&self) -> Vec<String> {
        let mut violations = Vec::new();
        for process in &self.domains.process.processes {
            if process.id == 0 {
                violations.push(format!("process {}: id=0", process.pid));
            }
            if process.generation == 0 {
                violations.push(format!("process {}: gen=0", process.pid));
            }
            if process.thread_group.id == 0 {
                violations.push(format!("process {}: missing thread_group", process.pid));
            }
            if !self
                .domains
                .process
                .thread_groups
                .iter()
                .any(|tg| tg.object_ref() == process.thread_group)
            {
                violations.push(format!("process {}: dangling thread_group", process.pid));
            }
        }
        for thread in &self.domains.process.threads {
            if thread.id == 0 {
                violations.push(format!("thread {}: id=0", thread.tid));
            }
            if thread.generation == 0 {
                violations.push(format!("thread {}: gen=0", thread.tid));
            }
            if thread.process.id == 0 {
                violations.push(format!("thread {}: missing process", thread.tid));
            }
            if thread.credential.id == 0 {
                violations.push(format!("thread {}: missing credential", thread.tid));
            }
            if !self.domains.process.processes.iter().any(|p| p.object_ref() == thread.process) {
                violations.push(format!("thread {}: dangling process", thread.tid));
            }
            if !self.domains.process.credentials.iter().any(|c| c.object_ref() == thread.credential)
            {
                violations.push(format!("thread {}: dangling credential", thread.tid));
            }
        }
        for cred in &self.domains.process.credentials {
            if cred.id == 0 {
                violations.push(format!("cred {}: id=0", cred.id));
            }
            if cred.generation == 0 {
                violations.push(format!("cred {}: gen=0", cred.id));
            }
        }
        for fd_table in &self.domains.process.fd_tables {
            if fd_table.id == 0 {
                violations.push(format!("fd_table {}: id=0", fd_table.id));
            }
            if fd_table.generation == 0 {
                violations.push(format!("fd_table {}: gen=0", fd_table.id));
            }
        }
        violations
    }
}
