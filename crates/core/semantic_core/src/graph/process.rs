use alloc::{format, string::String};

use super::*;

impl SemanticGraph {
    // ── Process ──

    pub fn create_process_family_root(
        &mut self,
        pid: u32,
        parent_pid: Option<u32>,
        pgid: u32,
        sid: u32,
        task_id: u64,
        aspace: GuestAddressSpaceRef,
        uid: u32,
        gid: u32,
    ) -> bool {
        if pid == 0
            || pgid == 0
            || sid == 0
            || task_id == 0
            || aspace.id() == 0
            || aspace.generation() == 0
            || self.domains.process.processes.iter().any(|record| record.pid == pid)
        {
            return false;
        }

        let leader = ContractObjectRef::new(
            ContractObjectKind::Thread,
            self.domains.process.next_thread_id,
            1,
        );
        let Some(thread_group_id) = self.create_thread_group(pid, leader) else {
            return false;
        };
        let Some(thread_group) =
            self.query_thread_group(thread_group_id).map(|record| record.object_ref())
        else {
            return false;
        };
        let Some(process_id) = self.create_process(pid, parent_pid, pgid, sid, thread_group, None)
        else {
            return false;
        };
        let Some(process) = self.query_process(process_id).map(|record| record.object_ref()) else {
            return false;
        };
        let Some(fd_table_id) = self.create_fd_table(thread_group, true) else {
            return false;
        };
        let Some(fd_table) = self.query_fd_table(fd_table_id).map(|record| record.object_ref())
        else {
            return false;
        };
        let Some(credential_id) =
            self.create_credential(process, uid, uid, uid, uid, gid, gid, gid, gid)
        else {
            return false;
        };
        let Some(credential) =
            self.query_credential(credential_id).map(|record| record.object_ref())
        else {
            return false;
        };
        self.create_thread(
            pid,
            task_id,
            process,
            aspace.object_ref(),
            fd_table,
            credential,
            thread_group,
        )
        .is_some()
    }

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

    pub fn transition_process_state_by_pid(&mut self, pid: u32, new_state: ProcessState) -> bool {
        let Some(record) = self.domains.process.processes.iter_mut().find(|r| r.pid == pid) else {
            return false;
        };
        if record.state == new_state {
            return true;
        }
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
        if process.generation == 0
            || aspace.generation == 0
            || fd_table.generation == 0
            || credential.generation == 0
            || thread_group.generation == 0
        {
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
        if leader.kind != ContractObjectKind::Thread || leader.id == 0 || leader.generation == 0 {
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
        if owner_thread_group.generation == 0 {
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
        self.create_credential_with_groups(
            owner_process,
            uid,
            euid,
            suid,
            fsuid,
            gid,
            egid,
            sgid,
            fsgid,
            Vec::new(),
        )
    }

    pub fn create_credential_with_groups(
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
        supplementary_groups: Vec<u32>,
    ) -> Option<CredentialId> {
        let id = self.domains.process.next_credential_id;
        self.domains.process.next_credential_id = id.max(id + 1);
        if self.create_credential_with_id_and_groups(
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
            supplementary_groups,
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
        self.create_credential_with_id_and_groups(
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
            Vec::new(),
        )
    }

    fn create_credential_with_id_and_groups(
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
        supplementary_groups: Vec<u32>,
    ) -> bool {
        if id == 0 || self.domains.process.credentials.iter().any(|r| r.id == id) {
            return false;
        }
        if owner_process.kind != ContractObjectKind::Process || owner_process.id == 0 {
            return false;
        }
        if owner_process.generation == 0 {
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
            supplementary_groups,
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

    pub fn transition_process_credential_by_pid(
        &mut self,
        pid: u32,
        uid: u32,
        euid: u32,
        suid: u32,
        fsuid: u32,
        gid: u32,
        egid: u32,
        sgid: u32,
        fsgid: u32,
        supplementary_groups: Vec<u32>,
        kind: CredentialTransitionKind,
    ) -> Option<CredentialId> {
        let process = self.domains.process.processes.iter().find(|record| record.pid == pid)?;
        let process_ref = process.object_ref();
        let from_credential = self
            .domains
            .process
            .threads
            .iter()
            .find(|thread| thread.process.id == process_ref.id)
            .map(|thread| thread.credential)?;
        let to_id = self.create_credential_with_groups(
            process_ref,
            uid,
            euid,
            suid,
            fsuid,
            gid,
            egid,
            sgid,
            fsgid,
            supplementary_groups,
        )?;
        let to_credential = self.query_credential(to_id)?.object_ref();
        self.record_credential_transition(from_credential, to_credential, kind, true)?;

        let mut updated_threads = Vec::new();
        for thread in self
            .domains
            .process
            .threads
            .iter_mut()
            .filter(|thread| thread.process.id == process_ref.id)
        {
            thread.credential = to_credential;
            thread.generation += 1;
            updated_threads.push(thread.object_ref());
        }
        for thread_group in &mut self.domains.process.thread_groups {
            if let Some(updated) =
                updated_threads.iter().find(|thread_ref| thread_ref.id == thread_group.leader.id)
            {
                thread_group.leader = *updated;
            }
        }
        Some(to_id)
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

    // ── Restore ──

    pub fn restore_process_records(
        &mut self,
        processes: &[ProcessRecord],
        threads: &[ThreadRecord],
        thread_groups: &[ThreadGroupRecord],
        fd_tables: &[FdTableRecord],
        open_file_descriptions: &[OpenFileDescriptionRecord],
        credentials: &[CredentialRecord],
        credential_transitions: &[CredentialTransitionRecord],
    ) -> bool {
        if !self.domains.process.processes.is_empty()
            || !self.domains.process.threads.is_empty()
            || !self.domains.process.thread_groups.is_empty()
            || !self.domains.process.fd_tables.is_empty()
            || !self.domains.process.open_file_descriptions.is_empty()
            || !self.domains.process.credentials.is_empty()
            || !self.domains.process.credential_transitions.is_empty()
        {
            return false;
        }
        if !process_records_are_valid(
            processes,
            threads,
            thread_groups,
            fd_tables,
            open_file_descriptions,
            credentials,
            credential_transitions,
        ) {
            return false;
        }

        self.domains.process.next_process_id = next_id(processes, |record| record.id);
        self.domains.process.next_thread_id = next_id(threads, |record| record.id);
        self.domains.process.next_thread_group_id = next_id(thread_groups, |record| record.id);
        self.domains.process.next_fd_table_id = next_id(fd_tables, |record| record.id);
        self.domains.process.next_open_file_description_id =
            next_id(open_file_descriptions, |record| record.id);
        self.domains.process.next_credential_id = next_id(credentials, |record| record.id);
        self.domains.process.next_credential_transition_id =
            next_id(credential_transitions, |record| record.id);

        self.domains.process.processes = processes.to_vec();
        self.domains.process.threads = threads.to_vec();
        self.domains.process.thread_groups = thread_groups.to_vec();
        self.domains.process.fd_tables = fd_tables.to_vec();
        self.domains.process.open_file_descriptions = open_file_descriptions.to_vec();
        self.domains.process.credentials = credentials.to_vec();
        self.domains.process.credential_transitions = credential_transitions.to_vec();
        true
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
            if !valid_ref_kind(process.thread_group, ContractObjectKind::ThreadGroup) {
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
            for child in &process.children {
                if !valid_ref_kind(*child, ContractObjectKind::Process) {
                    violations.push(format!("process {}: invalid child ref", process.pid));
                }
                if !self.domains.process.processes.iter().any(|p| p.object_ref() == *child) {
                    violations.push(format!("process {}: dangling child", process.pid));
                }
            }
        }
        for thread in &self.domains.process.threads {
            if thread.id == 0 {
                violations.push(format!("thread {}: id=0", thread.tid));
            }
            if thread.generation == 0 {
                violations.push(format!("thread {}: gen=0", thread.tid));
            }
            if thread.task_id == 0 {
                violations.push(format!("thread {}: task_id=0", thread.tid));
            }
            if !valid_ref_kind(thread.process, ContractObjectKind::Process) {
                violations.push(format!("thread {}: missing process", thread.tid));
            }
            if !valid_ref_kind(thread.aspace, ContractObjectKind::GuestAddressSpace) {
                violations.push(format!("thread {}: missing address space", thread.tid));
            }
            if !valid_ref_kind(thread.fd_table, ContractObjectKind::FdTable) {
                violations.push(format!("thread {}: missing fd_table", thread.tid));
            }
            if !valid_ref_kind(thread.credential, ContractObjectKind::Credential) {
                violations.push(format!("thread {}: missing credential", thread.tid));
            }
            if !valid_ref_kind(thread.thread_group, ContractObjectKind::ThreadGroup) {
                violations.push(format!("thread {}: missing thread_group", thread.tid));
            }
            if !self.domains.process.processes.iter().any(|p| p.object_ref() == thread.process) {
                violations.push(format!("thread {}: dangling process", thread.tid));
            }
            if !self.domains.process.fd_tables.iter().any(|f| f.object_ref() == thread.fd_table) {
                violations.push(format!("thread {}: dangling fd_table", thread.tid));
            }
            if !self.domains.process.credentials.iter().any(|c| c.object_ref() == thread.credential)
            {
                violations.push(format!("thread {}: dangling credential", thread.tid));
            }
            if !self
                .domains
                .process
                .thread_groups
                .iter()
                .any(|tg| tg.object_ref() == thread.thread_group)
            {
                violations.push(format!("thread {}: dangling thread_group", thread.tid));
            }
        }
        for thread_group in &self.domains.process.thread_groups {
            if thread_group.id == 0 {
                violations.push(format!("thread_group {}: id=0", thread_group.tgid));
            }
            if thread_group.generation == 0 {
                violations.push(format!("thread_group {}: gen=0", thread_group.tgid));
            }
            if !valid_ref_kind(thread_group.leader, ContractObjectKind::Thread) {
                violations.push(format!("thread_group {}: missing leader", thread_group.tgid));
            }
            if !self
                .domains
                .process
                .threads
                .iter()
                .any(|thread| thread.object_ref() == thread_group.leader)
            {
                violations.push(format!("thread_group {}: dangling leader", thread_group.tgid));
            }
        }
        for cred in &self.domains.process.credentials {
            if cred.id == 0 {
                violations.push(format!("cred {}: id=0", cred.id));
            }
            if cred.generation == 0 {
                violations.push(format!("cred {}: gen=0", cred.id));
            }
            if !valid_ref_kind(cred.owner_process, ContractObjectKind::Process) {
                violations.push(format!("cred {}: missing owner_process", cred.id));
            }
            if !self
                .domains
                .process
                .processes
                .iter()
                .any(|process| process.object_ref() == cred.owner_process)
            {
                violations.push(format!("cred {}: dangling owner_process", cred.id));
            }
        }
        for fd_table in &self.domains.process.fd_tables {
            if fd_table.id == 0 {
                violations.push(format!("fd_table {}: id=0", fd_table.id));
            }
            if fd_table.generation == 0 {
                violations.push(format!("fd_table {}: gen=0", fd_table.id));
            }
            if !valid_ref_kind(fd_table.owner_thread_group, ContractObjectKind::ThreadGroup) {
                violations.push(format!("fd_table {}: missing owner_thread_group", fd_table.id));
            }
            if !self
                .domains
                .process
                .thread_groups
                .iter()
                .any(|thread_group| thread_group.object_ref() == fd_table.owner_thread_group)
            {
                violations.push(format!("fd_table {}: dangling owner_thread_group", fd_table.id));
            }
        }
        for description in &self.domains.process.open_file_descriptions {
            if description.id == 0 {
                violations.push(format!("open_file_description {}: id=0", description.id));
            }
            if description.generation == 0 {
                violations.push(format!("open_file_description {}: gen=0", description.id));
            }
            if description.inode_ref.id == 0 || description.inode_ref.generation == 0 {
                violations
                    .push(format!("open_file_description {}: missing inode_ref", description.id));
            }
        }
        for transition in &self.domains.process.credential_transitions {
            if transition.id == 0 {
                violations.push(format!("credential_transition {}: id=0", transition.id));
            }
            if transition.generation == 0 {
                violations.push(format!("credential_transition {}: gen=0", transition.id));
            }
            if !valid_ref_kind(transition.from_credential, ContractObjectKind::Credential) {
                violations.push(format!(
                    "credential_transition {}: missing from_credential",
                    transition.id
                ));
            }
            if !valid_ref_kind(transition.to_credential, ContractObjectKind::Credential) {
                violations.push(format!(
                    "credential_transition {}: missing to_credential",
                    transition.id
                ));
            }
            if !self
                .domains
                .process
                .credentials
                .iter()
                .any(|credential| credential.object_ref() == transition.from_credential)
            {
                violations.push(format!(
                    "credential_transition {}: dangling from_credential",
                    transition.id
                ));
            }
            if !self
                .domains
                .process
                .credentials
                .iter()
                .any(|credential| credential.object_ref() == transition.to_credential)
            {
                violations.push(format!(
                    "credential_transition {}: dangling to_credential",
                    transition.id
                ));
            }
        }
        violations
    }
}

fn process_records_are_valid(
    processes: &[ProcessRecord],
    threads: &[ThreadRecord],
    thread_groups: &[ThreadGroupRecord],
    fd_tables: &[FdTableRecord],
    open_file_descriptions: &[OpenFileDescriptionRecord],
    credentials: &[CredentialRecord],
    credential_transitions: &[CredentialTransitionRecord],
) -> bool {
    if !ids_are_unique(processes, |record| record.id)
        || !ids_are_unique(threads, |record| record.id)
        || !ids_are_unique(thread_groups, |record| record.id)
        || !ids_are_unique(fd_tables, |record| record.id)
        || !ids_are_unique(open_file_descriptions, |record| record.id)
        || !ids_are_unique(credentials, |record| record.id)
        || !ids_are_unique(credential_transitions, |record| record.id)
    {
        return false;
    }

    processes.iter().all(|process| {
        process.id != 0
            && process.generation != 0
            && contains_thread_group_ref(thread_groups, process.thread_group)
            && process.children.iter().all(|child| contains_process_ref(processes, *child))
    }) && threads.iter().all(|thread| {
        thread.id != 0
            && thread.generation != 0
            && thread.task_id != 0
            && valid_ref_kind(thread.aspace, ContractObjectKind::GuestAddressSpace)
            && contains_process_ref(processes, thread.process)
            && contains_fd_table_ref(fd_tables, thread.fd_table)
            && contains_credential_ref(credentials, thread.credential)
            && contains_thread_group_ref(thread_groups, thread.thread_group)
    }) && thread_groups.iter().all(|thread_group| {
        thread_group.id != 0
            && thread_group.generation != 0
            && contains_thread_ref(threads, thread_group.leader)
    }) && fd_tables.iter().all(|fd_table| {
        fd_table.id != 0
            && fd_table.generation != 0
            && contains_thread_group_ref(thread_groups, fd_table.owner_thread_group)
    }) && open_file_descriptions.iter().all(|description| {
        description.id != 0
            && description.generation != 0
            && description.inode_ref.id != 0
            && description.inode_ref.generation != 0
    }) && credentials.iter().all(|credential| {
        credential.id != 0
            && credential.generation != 0
            && contains_process_ref(processes, credential.owner_process)
    }) && credential_transitions.iter().all(|transition| {
        transition.id != 0
            && transition.generation != 0
            && contains_credential_ref(credentials, transition.from_credential)
            && contains_credential_ref(credentials, transition.to_credential)
    })
}

fn valid_ref_kind(reference: ContractObjectRef, kind: ContractObjectKind) -> bool {
    reference.kind == kind && reference.id != 0 && reference.generation != 0
}

fn contains_process_ref(records: &[ProcessRecord], reference: ContractObjectRef) -> bool {
    valid_ref_kind(reference, ContractObjectKind::Process)
        && records.iter().any(|record| record.object_ref() == reference)
}

fn contains_thread_ref(records: &[ThreadRecord], reference: ContractObjectRef) -> bool {
    valid_ref_kind(reference, ContractObjectKind::Thread)
        && records.iter().any(|record| record.object_ref() == reference)
}

fn contains_thread_group_ref(records: &[ThreadGroupRecord], reference: ContractObjectRef) -> bool {
    valid_ref_kind(reference, ContractObjectKind::ThreadGroup)
        && records.iter().any(|record| record.object_ref() == reference)
}

fn contains_fd_table_ref(records: &[FdTableRecord], reference: ContractObjectRef) -> bool {
    valid_ref_kind(reference, ContractObjectKind::FdTable)
        && records.iter().any(|record| record.object_ref() == reference)
}

fn contains_credential_ref(records: &[CredentialRecord], reference: ContractObjectRef) -> bool {
    valid_ref_kind(reference, ContractObjectKind::Credential)
        && records.iter().any(|record| record.object_ref() == reference)
}

fn ids_are_unique<T>(records: &[T], mut id_of: impl FnMut(&T) -> u64) -> bool {
    for (index, record) in records.iter().enumerate() {
        let id = id_of(record);
        if id == 0 || records.iter().skip(index + 1).any(|other| id_of(other) == id) {
            return false;
        }
    }
    true
}

fn next_id<T>(records: &[T], mut id: impl FnMut(&T) -> u64) -> u64 {
    records.iter().map(|record| id(record)).max().unwrap_or(0) + 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validate_contract_graph;

    fn graph_with_bootstrapped_process_family() -> SemanticGraph {
        let mut graph = SemanticGraph::new();
        graph.ensure_task(1, FrontendKind::LinuxElf, "init");
        assert!(graph.create_process_family_root(
            1,
            None,
            1,
            1,
            1,
            GuestAddressSpaceRef::new(1, 1),
            0,
            0,
        ));
        graph
    }

    #[test]
    fn process_family_bootstrap_can_close_thread_group_cycle() {
        let graph = graph_with_bootstrapped_process_family();
        assert!(graph.check_invariants().is_ok());

        let mut snapshot = graph.snapshot();
        let task = snapshot.tasks[0].object_ref();
        let process = snapshot.processes[0].object_ref();
        snapshot.explicit_edges.push(ContractEdgeRecord::new(
            task,
            process,
            ContractEdgeMode::Live,
            "task-process",
            1,
        ));

        let violations = validate_contract_graph(&snapshot);
        assert!(violations.is_empty(), "process refs must validate: {violations:?}");
    }

    #[test]
    fn process_state_can_transition_by_pid() {
        let mut graph = graph_with_bootstrapped_process_family();

        assert!(graph.transition_process_state_by_pid(1, ProcessState::Zombie { exit_code: 7 }));
        let process = graph.query_process(1).unwrap();
        assert_eq!(process.state, ProcessState::Zombie { exit_code: 7 });
        assert_eq!(process.generation, 2);

        assert!(graph.transition_process_state_by_pid(1, ProcessState::Dead));
        let process = graph.query_process(1).unwrap();
        assert_eq!(process.state, ProcessState::Dead);
        assert_eq!(process.generation, 3);
    }

    #[test]
    fn credential_transition_updates_thread_refs_and_preserves_invariants() {
        let mut graph = graph_with_bootstrapped_process_family();
        let before = graph.snapshot();
        let before_thread = before.threads[0].object_ref();

        let mut groups = Vec::new();
        groups.push(200);
        groups.push(300);
        let credential_id = graph
            .transition_process_credential_by_pid(
                1,
                1000,
                1001,
                1002,
                1001,
                100,
                101,
                102,
                101,
                groups,
                CredentialTransitionKind::SetGroups { old_len: 0, new_len: 2 },
            )
            .expect("credential transition should be recorded");

        let snapshot = graph.snapshot();
        let credential = graph.query_credential(credential_id).unwrap();
        assert_eq!(credential.supplementary_groups, [200, 300]);
        assert_eq!(snapshot.credentials.len(), 2);
        assert_eq!(snapshot.credential_transitions.len(), 1);
        assert_eq!(snapshot.threads[0].credential, credential.object_ref());
        assert_eq!(snapshot.threads[0].generation, before_thread.generation + 1);
        assert_eq!(snapshot.thread_groups[0].leader, snapshot.threads[0].object_ref());
        assert!(graph.check_invariants().is_ok());
    }

    #[test]
    fn process_family_restore_preserves_snapshot_records() {
        let graph = graph_with_bootstrapped_process_family();
        let snapshot = graph.snapshot().portable_subset();
        let mut restored = SemanticGraph::new();

        assert!(restored.restore_process_records(
            &snapshot.processes,
            &snapshot.threads,
            &snapshot.thread_groups,
            &snapshot.fd_tables,
            &snapshot.open_file_descriptions,
            &snapshot.credentials,
            &snapshot.credential_transitions,
        ));
        assert!(restored.check_invariants().is_ok());

        let restored_snapshot = restored.snapshot();
        assert_eq!(restored_snapshot.processes, snapshot.processes);
        assert_eq!(restored_snapshot.threads, snapshot.threads);
        assert_eq!(restored_snapshot.thread_groups, snapshot.thread_groups);
        assert_eq!(restored_snapshot.fd_tables, snapshot.fd_tables);
        assert_eq!(restored_snapshot.credentials, snapshot.credentials);
    }
}
