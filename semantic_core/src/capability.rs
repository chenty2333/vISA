use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::*;

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
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityRecord {
    pub id: CapabilityId,
    pub subject: String,
    pub object: String,
    pub operations: OperationSet,
    pub lifetime: String,
    pub class: CapabilityClass,
    pub owner_store: Option<StoreId>,
    pub owner_task: Option<TaskId>,
    pub source: String,
    pub generation: Generation,
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
        self.grant_with_metadata(
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

    pub fn grant_with_metadata(
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
        if let Some(record) = self
            .records
            .iter_mut()
            .find(|record| record.subject == subject && record.object == object)
        {
            record.operations = OperationSet::from_static(operations);
            record.lifetime = lifetime.to_string();
            record.class = class;
            record.owner_store = owner_store;
            record.owner_task = owner_task;
            record.source = source.to_string();
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
            operations: OperationSet::from_static(operations),
            lifetime: lifetime.to_string(),
            class,
            owner_store,
            owner_task,
            source: source.to_string(),
            generation: 1,
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
        Some(self.grant_with_metadata(
            subject,
            &parent.object,
            &operations,
            lifetime,
            parent.class,
            parent.owner_store,
            parent.owner_task,
            "delegated",
        ))
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
        Some(self.grant_with_metadata(
            subject,
            &parent.object,
            operations,
            lifetime,
            parent.class,
            parent.owner_store,
            parent.owner_task,
            "attenuated",
        ))
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
        let Some(record) = self
            .records
            .iter()
            .find(|record| record.subject == subject && record.object == object)
        else {
            return Err(CapabilityDenyReason::Missing);
        };
        if record.revoked {
            return Err(CapabilityDenyReason::Revoked);
        }
        if !record.operations.contains(operation) {
            return Err(CapabilityDenyReason::OperationDenied);
        }
        Ok(record)
    }

    pub fn generation_of(&self, subject: &str, object: &str) -> Option<Generation> {
        self.records
            .iter()
            .find(|record| record.subject == subject && record.object == object)
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
}

impl CapabilityDenyReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Revoked => "revoked",
            Self::OperationDenied => "operation-denied",
            Self::GenerationMismatch => "generation-mismatch",
        }
    }
}
