use alloc::{string::String, vec::Vec};

use super::super::*;

// ── Process ──

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessRecord {
    pub id: ProcessId,
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub pgid: u32,
    pub sid: u32,
    pub thread_group: ContractObjectRef,
    pub children: Vec<ContractObjectRef>,
    pub state: ProcessState,
    pub exit_signal: Option<u8>,
    pub recorded_at_event: EventId,
    pub generation: Generation,
    pub note: String,
}

impl ProcessRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::Process, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcessState {
    Running,
    Zombie { exit_code: i32 },
    Dead,
}

// ── Thread ──

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreadRecord {
    pub id: ThreadId,
    pub tid: u32,
    pub task_id: u64,
    pub process: ContractObjectRef,
    pub aspace: ContractObjectRef, // GuestAddressSpace
    pub fd_table: ContractObjectRef,
    pub credential: ContractObjectRef,
    pub thread_group: ContractObjectRef,
    pub interrupted_activation: Option<ContractObjectRef>, // Activation ref
    pub arch_regs_evidence: Option<ContractObjectRef>,     // host-specific evidence
    pub clear_child_tid: Option<u64>,
    pub robust_list_head: Option<u64>,
    pub robust_list_len: usize,
    pub state: ThreadState,
    pub recorded_at_event: EventId,
    pub generation: Generation,
    pub note: String,
}

impl ThreadRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::Thread, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ThreadState {
    Running,
    Blocked,
    Stopped,
    Dead,
}

// ── ThreadGroup ──

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreadGroupRecord {
    pub id: ThreadGroupId,
    pub tgid: u32,
    pub leader: ContractObjectRef, // Thread
    pub signal_disposition: Option<ContractObjectRef>,
    pub recorded_at_event: EventId,
    pub generation: Generation,
    pub note: String,
}

impl ThreadGroupRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::ThreadGroup, self.id, self.generation)
    }
}

// ── FdTable ──

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FdTableRecord {
    pub id: FdTableId,
    pub owner_thread_group: ContractObjectRef,
    pub shared: bool, // CLONE_FILES
    pub recorded_at_event: EventId,
    pub generation: Generation,
    pub note: String,
}

impl FdTableRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::FdTable, self.id, self.generation)
    }
}

// ── OpenFileDescription ──

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenFileDescriptionRecord {
    pub id: OpenFileDescriptionId,
    pub inode_ref: ContractObjectRef,
    pub flags: u32,
    pub cursor: u64,
    pub recorded_at_event: EventId,
    pub generation: Generation,
    pub note: String,
}

impl OpenFileDescriptionRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::OpenFileDescription, self.id, self.generation)
    }
}

// ── Credential ──

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialRecord {
    pub id: CredentialId,
    pub owner_process: ContractObjectRef,
    pub uid: u32,
    pub euid: u32,
    pub suid: u32,
    pub fsuid: u32,
    pub gid: u32,
    pub egid: u32,
    pub sgid: u32,
    pub fsgid: u32,
    pub supplementary_groups: Vec<u32>,
    pub capability_sets: LinuxCapSets,
    pub recorded_at_event: EventId,
    pub generation: Generation,
    pub note: String,
}

impl CredentialRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::Credential, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct LinuxCapSets {
    pub bounding: u64,
    pub inheritable: u64,
    pub permitted: u64,
    pub effective: u64,
    pub ambient: u64,
    pub securebits: u32,
}

// ── CredentialTransition ──

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialTransitionRecord {
    pub id: CredentialTransitionId,
    pub from_credential: ContractObjectRef,
    pub to_credential: ContractObjectRef,
    pub transition_kind: CredentialTransitionKind,
    pub broadcast_to_thread_group: bool,
    pub recorded_at_event: EventId,
    pub generation: Generation,
    pub note: String,
}

impl CredentialTransitionRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::CredentialTransition, self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialTransitionKind {
    SetUid {
        old: u32,
        new: u32,
    },
    SetGid {
        old: u32,
        new: u32,
    },
    SetReUid {
        ruid: u32,
        euid: u32,
    },
    SetReGid {
        rgid: u32,
        egid: u32,
    },
    SetResUid {
        ruid: u32,
        euid: u32,
        suid: u32,
    },
    SetResGid {
        rgid: u32,
        egid: u32,
        sgid: u32,
    },
    SetFsuid {
        old: u32,
        new: u32,
    },
    SetFsgid {
        old: u32,
        new: u32,
    },
    SetGroups {
        old_len: usize,
        new_len: usize,
    },
    CapSet {
        bounding: bool,
        inheritable: bool,
        permitted: bool,
        effective: bool,
        ambient: bool,
        securebits: bool,
    },
}
