use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::*;

fn stable_authority_id(label: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in label.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let id = hash & 0x7fff_ffff_ffff_ffff;
    if id == 0 { 1 } else { id }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationSet {
    operations: Vec<String>,
}

impl OperationSet {
    pub fn from_static(operations: &[&str]) -> Self {
        Self {
            operations: operations.iter().map(|op| (*op).to_string()).collect(),
        }
    }

    pub fn contains_all(&self, requested: &[&str]) -> bool {
        requested
            .iter()
            .all(|requested| self.operations.iter().any(|op| op == requested))
    }

    pub fn contains(&self, requested: &str) -> bool {
        self.operations.iter().any(|op| op == requested)
    }

    pub fn as_slice(&self) -> &[String] {
        &self.operations
    }

    pub fn from_owned(operations: Vec<String>) -> Self {
        Self { operations }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityClass {
    ServiceImport,
    Device,
    PacketDevice,
    CodePublish,
    MmioRegion,
    DmaBuffer,
    IrqLine,
    VirtioQueue,
    DmwWindow,
    Timer,
    Snapshot,
    FaultDomain,
    EventLog,
    StoreControl,
    NetInterface,
    NetSocket,
    GuestMemoryAccess,
}

impl CapabilityClass {
    pub fn from_object(object: &str) -> Self {
        if object.starts_with("packet-device.") {
            Self::PacketDevice
        } else if object.starts_with("code-publish.") || object.starts_with("code-object.") {
            Self::CodePublish
        } else if object.starts_with("device.") {
            Self::Device
        } else if object.starts_with("mmio.") {
            Self::MmioRegion
        } else if object.starts_with("dma.") {
            Self::DmaBuffer
        } else if object.starts_with("irq.") {
            Self::IrqLine
        } else if object.starts_with("virtqueue.") {
            Self::VirtioQueue
        } else if object.starts_with("dmw.") {
            Self::DmwWindow
        } else if object.starts_with("timer.") {
            Self::Timer
        } else if object.starts_with("snapshot.") {
            Self::Snapshot
        } else if object.starts_with("fault-domain.") {
            Self::FaultDomain
        } else if object.starts_with("event-log.") {
            Self::EventLog
        } else if object.starts_with("store-control.") {
            Self::StoreControl
        } else if object.starts_with("net.interface") {
            Self::NetInterface
        } else if object.starts_with("net.socket") {
            Self::NetSocket
        } else if object.starts_with("guest-memory.") {
            Self::GuestMemoryAccess
        } else {
            Self::ServiceImport
        }
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ServiceImport => "service-import",
            Self::Device => "device",
            Self::PacketDevice => "packet-device",
            Self::CodePublish => "code-publish",
            Self::MmioRegion => "mmio-region",
            Self::DmaBuffer => "dma-buffer",
            Self::IrqLine => "irq-line",
            Self::VirtioQueue => "virtio-queue",
            Self::DmwWindow => "dmw-window",
            Self::Timer => "timer",
            Self::Snapshot => "snapshot",
            Self::FaultDomain => "fault-domain",
            Self::EventLog => "event-log",
            Self::StoreControl => "store-control",
            Self::NetInterface => "net-interface",
            Self::NetSocket => "net-socket",
            Self::GuestMemoryAccess => "guest-memory-access",
        }
    }

    pub const fn as_u16(self) -> u16 {
        match self {
            Self::ServiceImport => 0,
            Self::Device => 1,
            Self::PacketDevice => 2,
            Self::CodePublish => 3,
            Self::MmioRegion => 4,
            Self::DmaBuffer => 5,
            Self::IrqLine => 6,
            Self::VirtioQueue => 7,
            Self::DmwWindow => 8,
            Self::Timer => 9,
            Self::Snapshot => 10,
            Self::FaultDomain => 11,
            Self::EventLog => 12,
            Self::StoreControl => 13,
            Self::NetInterface => 14,
            Self::NetSocket => 15,
            Self::GuestMemoryAccess => 16,
        }
    }

    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::ServiceImport),
            1 => Some(Self::Device),
            2 => Some(Self::PacketDevice),
            3 => Some(Self::CodePublish),
            4 => Some(Self::MmioRegion),
            5 => Some(Self::DmaBuffer),
            6 => Some(Self::IrqLine),
            7 => Some(Self::VirtioQueue),
            8 => Some(Self::DmwWindow),
            9 => Some(Self::Timer),
            10 => Some(Self::Snapshot),
            11 => Some(Self::FaultDomain),
            12 => Some(Self::EventLog),
            13 => Some(Self::StoreControl),
            14 => Some(Self::NetInterface),
            15 => Some(Self::NetSocket),
            16 => Some(Self::GuestMemoryAccess),
            _ => None,
        }
    }

    pub const fn default_object_kind(self) -> ContractObjectKind {
        match self {
            Self::CodePublish => ContractObjectKind::CodeObject,
            Self::Snapshot | Self::GuestMemoryAccess | Self::DmwWindow => {
                ContractObjectKind::MemoryObject
            }
            Self::FaultDomain => ContractObjectKind::FaultDomain,
            Self::EventLog => ContractObjectKind::EventLog,
            Self::StoreControl => ContractObjectKind::Store,
            Self::ServiceImport
            | Self::Device
            | Self::PacketDevice
            | Self::MmioRegion
            | Self::DmaBuffer
            | Self::IrqLine
            | Self::VirtioQueue
            | Self::Timer
            | Self::NetInterface
            | Self::NetSocket => ContractObjectKind::Resource,
        }
    }

    pub const fn requires_manifest_declaration(self) -> bool {
        !matches!(self, Self::ServiceImport)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityObjectRef {
    Internal {
        class: CapabilityClass,
        object: ContractObjectRef,
    },
    External {
        class: CapabilityClass,
        object: ContractObjectRef,
    },
}

impl AuthorityObjectRef {
    pub const fn internal(class: CapabilityClass, object: ContractObjectRef) -> Self {
        Self::Internal { class, object }
    }

    pub const fn external(class: CapabilityClass, object: ContractObjectRef) -> Self {
        Self::External { class, object }
    }

    pub fn from_label(class: CapabilityClass, label: &str) -> Self {
        Self::Internal {
            class,
            object: ContractObjectRef::new(
                class.default_object_kind(),
                stable_authority_id(label),
                1,
            ),
        }
    }

    pub const fn class(self) -> CapabilityClass {
        match self {
            Self::Internal { class, .. } | Self::External { class, .. } => class,
        }
    }

    pub const fn object(self) -> ContractObjectRef {
        match self {
            Self::Internal { object, .. } | Self::External { object, .. } => object,
        }
    }

    pub fn summary(self) -> String {
        match self {
            Self::Internal { class, object } => {
                format!("internal:{}:{}", class.as_str(), object.summary())
            }
            Self::External { class, object } => {
                format!("external:{}:{}", class.as_str(), object.summary())
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityHandle {
    pub cap: CapabilityId,
    pub generation: Generation,
    pub rights_hint: OperationSet,
    pub class_hint: CapabilityClass,
}

impl CapabilityHandle {
    pub fn new(
        cap: CapabilityId,
        generation: Generation,
        rights_hint: Vec<String>,
        class_hint: CapabilityClass,
    ) -> Self {
        Self {
            cap,
            generation,
            rights_hint: OperationSet::from_owned(rights_hint),
            class_hint,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityRecord {
    pub id: CapabilityId,
    pub subject: String,
    pub object: String,
    pub object_ref: Option<AuthorityObjectRef>,
    pub operations: OperationSet,
    pub lifetime: String,
    pub class: CapabilityClass,
    pub owner_store: Option<StoreId>,
    pub owner_task: Option<TaskId>,
    pub source: String,
    pub generation: Generation,
    pub parent: Option<CapabilityId>,
    pub manifest_decl: bool,
    pub debug_object_label: String,
    pub revoked: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityOwnerSummary {
    pub subject: String,
    pub active: usize,
    pub revoked: usize,
    pub generation_high_watermark: Generation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityRevocationReport {
    pub subject: String,
    pub revoked: Vec<CapabilityId>,
}

impl CapabilityRevocationReport {
    pub fn count(&self) -> usize {
        self.revoked.len()
    }
}

#[derive(Clone, Debug)]
pub struct CapabilityLedger {
    next_id: CapabilityId,
    records: Vec<CapabilityRecord>,
}

impl CapabilityLedger {
    pub const fn new() -> Self {
        Self {
            next_id: 1,
            records: Vec::new(),
        }
    }

    pub fn grant(
        &mut self,
        subject: &str,
        object: &str,
        operations: &[&str],
        lifetime: &str,
    ) -> CapabilityId {
        self.grant_manifest_binding(
            subject,
            object,
            operations,
            lifetime,
            CapabilityClass::from_object(object),
            None,
            None,
            "runtime-grant",
        )
    }

    pub fn grant_manifest_binding(
        &mut self,
        subject: &str,
        object: &str,
        operations: &[&str],
        lifetime: &str,
        class: CapabilityClass,
        owner_store: Option<StoreId>,
        owner_task: Option<TaskId>,
        source: &str,
    ) -> CapabilityId {
        let object_ref = Some(AuthorityObjectRef::from_label(class, object));
        if let Some(record) = self.records.iter_mut().find(|record| {
            record.subject == subject
                && (record.object_ref == object_ref || record.object == object)
        }) {
            record.operations = OperationSet::from_static(operations);
            record.lifetime = lifetime.to_string();
            record.class = class;
            record.object_ref = object_ref;
            record.owner_store = owner_store;
            record.owner_task = owner_task;
            record.source = source.to_string();
            record.manifest_decl = true;
            record.debug_object_label = object.to_string();
            record.generation += 1;
            record.revoked = false;
            return record.id;
        }

        let id = self.next_id;
        self.next_id += 1;
        self.records.push(CapabilityRecord {
            id,
            subject: subject.to_string(),
            object: object.to_string(),
            object_ref,
            operations: OperationSet::from_static(operations),
            lifetime: lifetime.to_string(),
            class,
            owner_store,
            owner_task,
            source: source.to_string(),
            generation: 1,
            parent: None,
            manifest_decl: true,
            debug_object_label: object.to_string(),
            revoked: false,
        });
        id
    }

    pub fn grant_with_authority_ref(
        &mut self,
        subject: &str,
        debug_object_label: &str,
        object_ref: AuthorityObjectRef,
        operations: &[&str],
        lifetime: &str,
        owner_store: Option<StoreId>,
        owner_task: Option<TaskId>,
        source: &str,
        manifest_decl: bool,
    ) -> CapabilityId {
        if let Some(record) = self
            .records
            .iter_mut()
            .find(|record| record.subject == subject && record.object_ref == Some(object_ref))
        {
            record.object = debug_object_label.to_string();
            record.debug_object_label = debug_object_label.to_string();
            record.operations = OperationSet::from_static(operations);
            record.lifetime = lifetime.to_string();
            record.class = object_ref.class();
            record.owner_store = owner_store;
            record.owner_task = owner_task;
            record.source = source.to_string();
            record.manifest_decl = manifest_decl;
            record.generation += 1;
            record.revoked = false;
            return record.id;
        }
        let id = self.next_id;
        self.next_id += 1;
        self.records.push(CapabilityRecord {
            id,
            subject: subject.to_string(),
            object: debug_object_label.to_string(),
            object_ref: Some(object_ref),
            operations: OperationSet::from_static(operations),
            lifetime: lifetime.to_string(),
            class: object_ref.class(),
            owner_store,
            owner_task,
            source: source.to_string(),
            generation: 1,
            parent: None,
            manifest_decl,
            debug_object_label: debug_object_label.to_string(),
            revoked: false,
        });
        id
    }

    pub fn grant_debug_label_only_for_test(
        &mut self,
        subject: &str,
        object: &str,
        operations: &[&str],
        lifetime: &str,
    ) -> CapabilityId {
        let id = self.next_id;
        self.next_id += 1;
        self.records.push(CapabilityRecord {
            id,
            subject: subject.to_string(),
            object: object.to_string(),
            object_ref: None,
            operations: OperationSet::from_static(operations),
            lifetime: lifetime.to_string(),
            class: CapabilityClass::from_object(object),
            owner_store: None,
            owner_task: None,
            source: "debug-label-only-test".to_string(),
            generation: 1,
            parent: None,
            manifest_decl: true,
            debug_object_label: object.to_string(),
            revoked: false,
        });
        id
    }

    pub fn delegate(
        &mut self,
        parent_id: CapabilityId,
        subject: &str,
        lifetime: &str,
    ) -> Option<CapabilityId> {
        let parent = self.active(parent_id)?.clone();
        let operations = parent
            .operations
            .as_slice()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let object_ref = parent.object_ref?;
        let delegated = self.grant_with_authority_ref(
            subject,
            &parent.object,
            object_ref,
            &operations,
            lifetime,
            parent.owner_store,
            parent.owner_task,
            "delegated",
            parent.manifest_decl,
        );
        if let Some(record) = self
            .records
            .iter_mut()
            .find(|record| record.id == delegated)
        {
            record.object_ref = parent.object_ref;
            record.manifest_decl = parent.manifest_decl;
            record.parent = Some(parent_id);
        }
        Some(delegated)
    }

    pub fn attenuate(
        &mut self,
        parent_id: CapabilityId,
        subject: &str,
        operations: &[&str],
        lifetime: &str,
    ) -> Option<CapabilityId> {
        let parent = self.active(parent_id)?.clone();
        if !parent.operations.contains_all(operations) {
            return None;
        }
        let object_ref = parent.object_ref?;
        let attenuated = self.grant_with_authority_ref(
            subject,
            &parent.object,
            object_ref,
            operations,
            lifetime,
            parent.owner_store,
            parent.owner_task,
            "attenuated",
            parent.manifest_decl,
        );
        if let Some(record) = self
            .records
            .iter_mut()
            .find(|record| record.id == attenuated)
        {
            record.object_ref = parent.object_ref;
            record.manifest_decl = parent.manifest_decl;
            record.parent = Some(parent_id);
        }
        Some(attenuated)
    }

    pub fn revoke(&mut self, id: CapabilityId) -> bool {
        let Some(record) = self.records.iter_mut().find(|record| record.id == id) else {
            return false;
        };
        record.revoked = true;
        record.generation += 1;
        true
    }

    pub fn revoke_by_subject_object(
        &mut self,
        subject: &str,
        object: &str,
    ) -> Option<CapabilityId> {
        let record = self
            .records
            .iter_mut()
            .find(|record| record.subject == subject && record.object == object)?;
        record.revoked = true;
        record.generation += 1;
        Some(record.id)
    }

    pub fn revoke_subject(&mut self, subject: &str) -> usize {
        self.revoke_subject_report(subject).count()
    }

    pub fn revoke_owner_store(&mut self, owner_store: StoreId) -> Vec<CapabilityId> {
        let mut revoked = Vec::new();
        for record in &mut self.records {
            if record.owner_store == Some(owner_store) && !record.revoked {
                record.revoked = true;
                record.generation += 1;
                revoked.push(record.id);
            }
        }
        revoked
    }

    pub fn revoke_subject_report(&mut self, subject: &str) -> CapabilityRevocationReport {
        let mut revoked_ids = Vec::new();
        for record in &mut self.records {
            if record.subject == subject && !record.revoked {
                record.revoked = true;
                record.generation += 1;
                revoked_ids.push(record.id);
            }
        }
        CapabilityRevocationReport {
            subject: subject.to_string(),
            revoked: revoked_ids,
        }
    }

    pub fn owner_summary(&self, subject: &str) -> CapabilityOwnerSummary {
        let mut active = 0;
        let mut revoked = 0;
        let mut generation_high_watermark = 0;
        for record in self
            .records
            .iter()
            .filter(|record| record.subject == subject)
        {
            if record.revoked {
                revoked += 1;
            } else {
                active += 1;
            }
            generation_high_watermark = generation_high_watermark.max(record.generation);
        }
        CapabilityOwnerSummary {
            subject: subject.to_string(),
            active,
            revoked,
            generation_high_watermark,
        }
    }

    pub fn active(&self, id: CapabilityId) -> Option<&CapabilityRecord> {
        self.records
            .iter()
            .find(|record| record.id == id && !record.revoked)
    }

    pub fn check(
        &self,
        subject: &str,
        object: &str,
        operation: &str,
    ) -> Result<&CapabilityRecord, CapabilityDenyReason> {
        self.check_authority(
            subject,
            AuthorityObjectRef::from_label(CapabilityClass::from_object(object), object),
            operation,
            None,
        )
    }

    pub fn check_authority(
        &self,
        subject: &str,
        object_ref: AuthorityObjectRef,
        operation: &str,
        handle: Option<&CapabilityHandle>,
    ) -> Result<&CapabilityRecord, CapabilityDenyReason> {
        if let Some(handle) = handle {
            let Some(record) = self.records.iter().find(|record| record.id == handle.cap) else {
                return Err(CapabilityDenyReason::Missing);
            };
            if record.subject != subject {
                return Err(CapabilityDenyReason::SubjectMismatch);
            }
            if record.generation != handle.generation {
                return Err(CapabilityDenyReason::GenerationMismatch);
            }
            if record.class != handle.class_hint {
                return Err(CapabilityDenyReason::ClassMismatch);
            }
            if record.object_ref != Some(object_ref) {
                return Err(CapabilityDenyReason::ObjectMismatch);
            }
            return Self::validate_record_authorizes(record, operation);
        }

        let Some(record) = self
            .records
            .iter()
            .find(|record| record.subject == subject && record.object_ref == Some(object_ref))
        else {
            return Err(CapabilityDenyReason::Missing);
        };
        Self::validate_record_authorizes(record, operation)
    }

    fn validate_record_authorizes<'a>(
        record: &'a CapabilityRecord,
        operation: &str,
    ) -> Result<&'a CapabilityRecord, CapabilityDenyReason> {
        if record.object_ref.is_none() {
            return Err(CapabilityDenyReason::ObjectMismatch);
        }
        if record.class.requires_manifest_declaration() && !record.manifest_decl {
            return Err(CapabilityDenyReason::ManifestDeclarationMissing);
        }
        if record.revoked {
            return Err(CapabilityDenyReason::Revoked);
        }
        if !record.operations.contains(operation) {
            return Err(CapabilityDenyReason::OperationDenied);
        }
        Ok(record)
    }

    pub fn generation_of(&self, subject: &str, object: &str) -> Option<Generation> {
        self.generation_of_authority(
            subject,
            AuthorityObjectRef::from_label(CapabilityClass::from_object(object), object),
        )
    }

    pub fn generation_of_authority(
        &self,
        subject: &str,
        object_ref: AuthorityObjectRef,
    ) -> Option<Generation> {
        self.records
            .iter()
            .find(|record| record.subject == subject && record.object_ref == Some(object_ref))
            .map(|record| record.generation)
    }

    pub fn records(&self) -> &[CapabilityRecord] {
        &self.records
    }

    pub fn active_count(&self) -> usize {
        self.records.iter().filter(|record| !record.revoked).count()
    }
}

impl Default for CapabilityLedger {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityDenyReason {
    Missing,
    Revoked,
    OperationDenied,
    GenerationMismatch,
    SubjectMismatch,
    ObjectMismatch,
    ClassMismatch,
    ManifestDeclarationMissing,
}

impl CapabilityDenyReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Revoked => "revoked",
            Self::OperationDenied => "operation-denied",
            Self::GenerationMismatch => "generation-mismatch",
            Self::SubjectMismatch => "subject-mismatch",
            Self::ObjectMismatch => "object-mismatch",
            Self::ClassMismatch => "class-mismatch",
            Self::ManifestDeclarationMissing => "manifest-declaration-missing",
        }
    }
}
