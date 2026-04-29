use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use crate::{EvidenceBoundaryLevel, target_executor::RecordMode};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryClass {
    StoreLinearMemory,
    StoreLocalHeap,
    GuestMemory,
    CodeMemory,
    ActivationStack,
    DmaMemory,
    MmioWindowMemory,
    DmwWindowMemory,
    HostcallTableMemory,
    TrapFrameMemory,
    ReadonlyMetadataMemory,
    StoreTableMemory,
    SnapshotMetadataMemory,
}

impl MemoryClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StoreLinearMemory => "store-linear-memory",
            Self::StoreLocalHeap => "store-local-heap",
            Self::GuestMemory => "guest-memory",
            Self::CodeMemory => "code-memory",
            Self::ActivationStack => "activation-stack",
            Self::DmaMemory => "dma-memory",
            Self::MmioWindowMemory => "mmio-window-memory",
            Self::DmwWindowMemory => "dmw-window-memory",
            Self::HostcallTableMemory => "hostcall-table-memory",
            Self::TrapFrameMemory => "trap-frame-memory",
            Self::ReadonlyMetadataMemory => "readonly-metadata-memory",
            Self::StoreTableMemory => "store-table-memory",
            Self::SnapshotMetadataMemory => "snapshot-metadata-memory",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerKind {
    Store,
    CodePublisher,
    TargetExecutor,
    Substrate,
    Shared,
}

impl OwnerKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Store => "store",
            Self::CodePublisher => "code-publisher",
            Self::TargetExecutor => "target-executor",
            Self::Substrate => "substrate",
            Self::Shared => "shared",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PermSet {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl PermSet {
    pub const fn new(read: bool, write: bool, execute: bool) -> Self {
        Self { read, write, execute }
    }

    pub fn summary(self) -> String {
        let mut flags = String::new();
        flags.push(if self.read { 'r' } else { '-' });
        flags.push(if self.write { 'w' } else { '-' });
        flags.push(if self.execute { 'x' } else { '-' });
        flags
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationPolicy {
    Migrated,
    Rebuilt,
    NeverMigrated,
    QuiesceRequired,
    SemanticBuffer,
}

impl MigrationPolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Migrated => "migrated",
            Self::Rebuilt => "rebuilt",
            Self::NeverMigrated => "never-migrated",
            Self::QuiesceRequired => "quiesce-required",
            Self::SemanticBuffer => "semantic-buffer",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotPolicy {
    Include,
    Rebuild,
    RejectIfLive,
    RejectRawBinding,
    ConvertToLogicalImport,
    Exclude,
}

impl SnapshotPolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Include => "include",
            Self::Rebuild => "rebuild",
            Self::RejectIfLive => "reject-if-live",
            Self::RejectRawBinding => "reject-raw-binding",
            Self::ConvertToLogicalImport => "convert-to-logical-import",
            Self::Exclude => "exclude",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanupPolicy {
    DropWithStore,
    ReleaseOnCleanup,
    QuiesceBeforeSnapshot,
    RebuildOnRestore,
    PreserveSemantic,
}

impl CleanupPolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DropWithStore => "drop-with-store",
            Self::ReleaseOnCleanup => "release-on-cleanup",
            Self::QuiesceBeforeSnapshot => "quiesce-before-snapshot",
            Self::RebuildOnRestore => "rebuild-on-restore",
            Self::PreserveSemantic => "preserve-semantic",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryClassPolicy {
    pub class: MemoryClass,
    pub owner_kind: OwnerKind,
    pub permissions: PermSet,
    pub migratable: MigrationPolicy,
    pub snapshot_policy: SnapshotPolicy,
    pub cleanup_policy: CleanupPolicy,
    pub can_alias_guest_memory: bool,
    pub can_cross_pending: bool,
    pub can_be_executable: bool,
}

impl MemoryClassPolicy {
    pub fn summary(self) -> String {
        format!(
            "memory-policy class={} owner={} perms={} migration={} snapshot={} cleanup={} alias_guest={} cross_pending={} executable={}",
            self.class.as_str(),
            self.owner_kind.as_str(),
            self.permissions.summary(),
            self.migratable.as_str(),
            self.snapshot_policy.as_str(),
            self.cleanup_policy.as_str(),
            self.can_alias_guest_memory,
            self.can_cross_pending,
            self.can_be_executable
        )
    }
}

pub const MEMORY_CLASS_POLICIES: [MemoryClassPolicy; 13] = [
    MemoryClassPolicy {
        class: MemoryClass::StoreLinearMemory,
        owner_kind: OwnerKind::Store,
        permissions: PermSet::new(true, true, false),
        migratable: MigrationPolicy::Migrated,
        snapshot_policy: SnapshotPolicy::Include,
        cleanup_policy: CleanupPolicy::DropWithStore,
        can_alias_guest_memory: true,
        can_cross_pending: true,
        can_be_executable: false,
    },
    MemoryClassPolicy {
        class: MemoryClass::StoreLocalHeap,
        owner_kind: OwnerKind::Store,
        permissions: PermSet::new(true, true, false),
        migratable: MigrationPolicy::Migrated,
        snapshot_policy: SnapshotPolicy::Include,
        cleanup_policy: CleanupPolicy::DropWithStore,
        can_alias_guest_memory: false,
        can_cross_pending: true,
        can_be_executable: false,
    },
    MemoryClassPolicy {
        class: MemoryClass::GuestMemory,
        owner_kind: OwnerKind::Store,
        permissions: PermSet::new(true, true, false),
        migratable: MigrationPolicy::Migrated,
        snapshot_policy: SnapshotPolicy::Include,
        cleanup_policy: CleanupPolicy::DropWithStore,
        can_alias_guest_memory: true,
        can_cross_pending: true,
        can_be_executable: false,
    },
    MemoryClassPolicy {
        class: MemoryClass::CodeMemory,
        owner_kind: OwnerKind::CodePublisher,
        permissions: PermSet::new(true, false, true),
        migratable: MigrationPolicy::Rebuilt,
        snapshot_policy: SnapshotPolicy::Rebuild,
        cleanup_policy: CleanupPolicy::RebuildOnRestore,
        can_alias_guest_memory: false,
        can_cross_pending: true,
        can_be_executable: true,
    },
    MemoryClassPolicy {
        class: MemoryClass::ActivationStack,
        owner_kind: OwnerKind::TargetExecutor,
        permissions: PermSet::new(true, true, false),
        migratable: MigrationPolicy::NeverMigrated,
        snapshot_policy: SnapshotPolicy::RejectIfLive,
        cleanup_policy: CleanupPolicy::ReleaseOnCleanup,
        can_alias_guest_memory: false,
        can_cross_pending: false,
        can_be_executable: false,
    },
    MemoryClassPolicy {
        class: MemoryClass::DmaMemory,
        owner_kind: OwnerKind::Substrate,
        permissions: PermSet::new(true, true, false),
        migratable: MigrationPolicy::QuiesceRequired,
        snapshot_policy: SnapshotPolicy::RejectRawBinding,
        cleanup_policy: CleanupPolicy::QuiesceBeforeSnapshot,
        can_alias_guest_memory: true,
        can_cross_pending: false,
        can_be_executable: false,
    },
    MemoryClassPolicy {
        class: MemoryClass::MmioWindowMemory,
        owner_kind: OwnerKind::Substrate,
        permissions: PermSet::new(true, true, false),
        migratable: MigrationPolicy::NeverMigrated,
        snapshot_policy: SnapshotPolicy::RejectRawBinding,
        cleanup_policy: CleanupPolicy::ReleaseOnCleanup,
        can_alias_guest_memory: false,
        can_cross_pending: false,
        can_be_executable: false,
    },
    MemoryClassPolicy {
        class: MemoryClass::DmwWindowMemory,
        owner_kind: OwnerKind::Substrate,
        permissions: PermSet::new(true, true, false),
        migratable: MigrationPolicy::NeverMigrated,
        snapshot_policy: SnapshotPolicy::RejectIfLive,
        cleanup_policy: CleanupPolicy::ReleaseOnCleanup,
        can_alias_guest_memory: true,
        can_cross_pending: false,
        can_be_executable: false,
    },
    MemoryClassPolicy {
        class: MemoryClass::HostcallTableMemory,
        owner_kind: OwnerKind::TargetExecutor,
        permissions: PermSet::new(true, false, false),
        migratable: MigrationPolicy::Rebuilt,
        snapshot_policy: SnapshotPolicy::ConvertToLogicalImport,
        cleanup_policy: CleanupPolicy::RebuildOnRestore,
        can_alias_guest_memory: false,
        can_cross_pending: true,
        can_be_executable: false,
    },
    MemoryClassPolicy {
        class: MemoryClass::TrapFrameMemory,
        owner_kind: OwnerKind::Substrate,
        permissions: PermSet::new(true, true, false),
        migratable: MigrationPolicy::NeverMigrated,
        snapshot_policy: SnapshotPolicy::Exclude,
        cleanup_policy: CleanupPolicy::ReleaseOnCleanup,
        can_alias_guest_memory: false,
        can_cross_pending: false,
        can_be_executable: false,
    },
    MemoryClassPolicy {
        class: MemoryClass::ReadonlyMetadataMemory,
        owner_kind: OwnerKind::Shared,
        permissions: PermSet::new(true, false, false),
        migratable: MigrationPolicy::Migrated,
        snapshot_policy: SnapshotPolicy::Include,
        cleanup_policy: CleanupPolicy::PreserveSemantic,
        can_alias_guest_memory: false,
        can_cross_pending: true,
        can_be_executable: false,
    },
    MemoryClassPolicy {
        class: MemoryClass::StoreTableMemory,
        owner_kind: OwnerKind::Store,
        permissions: PermSet::new(true, true, false),
        migratable: MigrationPolicy::Migrated,
        snapshot_policy: SnapshotPolicy::ConvertToLogicalImport,
        cleanup_policy: CleanupPolicy::DropWithStore,
        can_alias_guest_memory: false,
        can_cross_pending: true,
        can_be_executable: false,
    },
    MemoryClassPolicy {
        class: MemoryClass::SnapshotMetadataMemory,
        owner_kind: OwnerKind::TargetExecutor,
        permissions: PermSet::new(true, true, false),
        migratable: MigrationPolicy::Migrated,
        snapshot_policy: SnapshotPolicy::Include,
        cleanup_policy: CleanupPolicy::PreserveSemantic,
        can_alias_guest_memory: false,
        can_cross_pending: true,
        can_be_executable: false,
    },
];

pub fn memory_class_policies() -> &'static [MemoryClassPolicy] {
    &MEMORY_CLASS_POLICIES
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundaryValidatorKind {
    SnapshotBarrier,
    PackageReplay,
}

impl BoundaryValidatorKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SnapshotBarrier => "snapshot-barrier",
            Self::PackageReplay => "package-replay",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundaryValidationErrorKind {
    ActiveDmwLease,
    ActiveNonConvertibleActivation,
    InFlightDma,
    UnsealedEventLog,
    UnflushedTrapRecords,
    PendingCleanup,
    NativeActivationStackLive,
    RawHostPointer,
    RawReturnAddress,
    ActiveFramebufferWindowLease,
    ActiveFramebufferMapping,
    DirtyFramebufferRegion,
    UnknownObjectClass,
    StaleGeneration,
    MissingArtifactIdentity,
    DanglingCapabilityObject,
    RecordModeMismatch,
    UnsupportedRecordMode,
    RawDmaBinding,
    RawMmioBinding,
}

impl BoundaryValidationErrorKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ActiveDmwLease => "active-dmw-lease",
            Self::ActiveNonConvertibleActivation => "active-non-convertible-activation",
            Self::InFlightDma => "in-flight-dma",
            Self::UnsealedEventLog => "unsealed-event-log",
            Self::UnflushedTrapRecords => "unflushed-trap-records",
            Self::PendingCleanup => "pending-cleanup",
            Self::NativeActivationStackLive => "native-activation-stack-live",
            Self::RawHostPointer => "raw-host-pointer",
            Self::RawReturnAddress => "raw-return-address",
            Self::ActiveFramebufferWindowLease => "active-framebuffer-window-lease",
            Self::ActiveFramebufferMapping => "active-framebuffer-mapping",
            Self::DirtyFramebufferRegion => "dirty-framebuffer-region",
            Self::UnknownObjectClass => "unknown-object-class",
            Self::StaleGeneration => "stale-generation",
            Self::MissingArtifactIdentity => "missing-artifact-identity",
            Self::DanglingCapabilityObject => "dangling-capability-object",
            Self::RecordModeMismatch => "record-mode-mismatch",
            Self::UnsupportedRecordMode => "unsupported-record-mode",
            Self::RawDmaBinding => "raw-dma-binding",
            Self::RawMmioBinding => "raw-mmio-binding",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundaryValidationViolation {
    pub validator: BoundaryValidatorKind,
    pub kind: BoundaryValidationErrorKind,
    pub object: String,
    pub detail: String,
}

impl BoundaryValidationViolation {
    pub fn new(
        validator: BoundaryValidatorKind,
        kind: BoundaryValidationErrorKind,
        object: &str,
        detail: &str,
    ) -> Self {
        Self { validator, kind, object: object.to_string(), detail: detail.to_string() }
    }

    pub fn summary(&self) -> String {
        format!(
            "boundary-validation validator={} kind={} object={} detail={}",
            self.validator.as_str(),
            self.kind.as_str(),
            self.object,
            self.detail
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundaryValidationReport {
    pub validator: BoundaryValidatorKind,
    pub evidence_boundary: EvidenceBoundaryLevel,
    pub violations: Vec<BoundaryValidationViolation>,
}

impl BoundaryValidationReport {
    pub fn new(
        validator: BoundaryValidatorKind,
        violations: Vec<BoundaryValidationViolation>,
    ) -> Self {
        Self::with_evidence_boundary(validator, EvidenceBoundaryLevel::SemanticModel, violations)
    }

    pub fn with_evidence_boundary(
        validator: BoundaryValidatorKind,
        evidence_boundary: EvidenceBoundaryLevel,
        violations: Vec<BoundaryValidationViolation>,
    ) -> Self {
        Self { validator, evidence_boundary, violations }
    }

    pub fn is_ok(&self) -> bool {
        self.violations.is_empty()
    }

    pub fn summary(&self) -> String {
        format!(
            "boundary-validation validator={} evidence={} ok={} violations={}",
            self.validator.as_str(),
            self.evidence_boundary.as_str(),
            self.is_ok(),
            self.violations.len()
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SnapshotBarrierValidationState {
    pub active_dmw_lease_count: u32,
    pub active_nonconvertible_activation_count: u32,
    pub in_flight_dma_count: u32,
    pub unsealed_event_log: bool,
    pub unflushed_trap_record_count: u32,
    pub pending_cleanup_count: u32,
    pub native_activation_stack_live: bool,
    pub raw_dma_binding_count: u32,
    pub raw_mmio_binding_count: u32,
    pub active_framebuffer_window_lease_count: u32,
    pub active_framebuffer_mapping_count: u32,
    pub dirty_framebuffer_region_count: u32,
}

pub struct SnapshotBarrierValidator;

impl SnapshotBarrierValidator {
    pub fn validate(state: &SnapshotBarrierValidationState) -> BoundaryValidationReport {
        let validator = BoundaryValidatorKind::SnapshotBarrier;
        let mut violations = Vec::new();
        if state.active_dmw_lease_count != 0 {
            violations.push(BoundaryValidationViolation::new(
                validator,
                BoundaryValidationErrorKind::ActiveDmwLease,
                "dmw",
                "active DMW leases cannot cross snapshot barrier",
            ));
        }
        if state.active_nonconvertible_activation_count != 0 {
            violations.push(BoundaryValidationViolation::new(
                validator,
                BoundaryValidationErrorKind::ActiveNonConvertibleActivation,
                "activation",
                "native activation stack is still live",
            ));
        }
        if state.in_flight_dma_count != 0 {
            violations.push(BoundaryValidationViolation::new(
                validator,
                BoundaryValidationErrorKind::InFlightDma,
                "dma",
                "in-flight DMA must quiesce before snapshot",
            ));
        }
        if state.unsealed_event_log {
            violations.push(BoundaryValidationViolation::new(
                validator,
                BoundaryValidationErrorKind::UnsealedEventLog,
                "event-log",
                "event log must be sealed at the snapshot cursor",
            ));
        }
        if state.unflushed_trap_record_count != 0 {
            violations.push(BoundaryValidationViolation::new(
                validator,
                BoundaryValidationErrorKind::UnflushedTrapRecords,
                "trap",
                "trap records must be flushed before snapshot",
            ));
        }
        if state.pending_cleanup_count != 0 {
            violations.push(BoundaryValidationViolation::new(
                validator,
                BoundaryValidationErrorKind::PendingCleanup,
                "cleanup",
                "pending cleanup transactions block snapshot",
            ));
        }
        if state.native_activation_stack_live {
            violations.push(BoundaryValidationViolation::new(
                validator,
                BoundaryValidationErrorKind::NativeActivationStackLive,
                "activation-stack",
                "native activation stacks are never migrated in v1",
            ));
        }
        if state.raw_dma_binding_count != 0 {
            violations.push(BoundaryValidationViolation::new(
                validator,
                BoundaryValidationErrorKind::RawDmaBinding,
                "dma",
                "raw DMA bindings cannot be serialized",
            ));
        }
        if state.raw_mmio_binding_count != 0 {
            violations.push(BoundaryValidationViolation::new(
                validator,
                BoundaryValidationErrorKind::RawMmioBinding,
                "mmio",
                "raw MMIO bindings cannot be serialized",
            ));
        }
        if state.active_framebuffer_window_lease_count != 0 {
            violations.push(BoundaryValidationViolation::new(
                validator,
                BoundaryValidationErrorKind::ActiveFramebufferWindowLease,
                "display",
                "active framebuffer window leases cannot cross snapshot barrier",
            ));
        }
        if state.active_framebuffer_mapping_count != 0 {
            violations.push(BoundaryValidationViolation::new(
                validator,
                BoundaryValidationErrorKind::ActiveFramebufferMapping,
                "display",
                "active framebuffer mappings cannot cross snapshot barrier",
            ));
        }
        if state.dirty_framebuffer_region_count != 0 {
            violations.push(BoundaryValidationViolation::new(
                validator,
                BoundaryValidationErrorKind::DirtyFramebufferRegion,
                "display",
                "dirty framebuffer regions must be flushed before snapshot",
            ));
        }
        BoundaryValidationReport::new(validator, violations)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayPackageValidationState {
    pub raw_host_pointer_count: u32,
    pub raw_return_address_count: u32,
    pub unknown_object_class_count: u32,
    pub stale_generation_count: u32,
    pub missing_artifact_identity_count: u32,
    pub dangling_capability_object_count: u32,
    pub raw_dma_binding_count: u32,
    pub raw_mmio_binding_count: u32,
    pub record_modes: Vec<RecordMode>,
    pub supported_record_modes: Vec<RecordMode>,
}

impl ReplayPackageValidationState {
    pub fn clean(record_modes: Vec<RecordMode>) -> Self {
        Self {
            raw_host_pointer_count: 0,
            raw_return_address_count: 0,
            unknown_object_class_count: 0,
            stale_generation_count: 0,
            missing_artifact_identity_count: 0,
            dangling_capability_object_count: 0,
            raw_dma_binding_count: 0,
            raw_mmio_binding_count: 0,
            record_modes,
            supported_record_modes: PackageReplayValidator::supported_record_modes_v1(),
        }
    }
}

impl Default for ReplayPackageValidationState {
    fn default() -> Self {
        Self::clean(Vec::new())
    }
}

pub struct PackageReplayValidator;

impl PackageReplayValidator {
    pub fn supported_record_modes_v1() -> Vec<RecordMode> {
        vec![
            RecordMode::Deterministic,
            RecordMode::RecordInput,
            RecordMode::RecordOutput,
            RecordMode::RecordInputOutput,
        ]
    }

    pub fn validate(state: &ReplayPackageValidationState) -> BoundaryValidationReport {
        let validator = BoundaryValidatorKind::PackageReplay;
        let mut violations = Vec::new();
        Self::push_count(
            &mut violations,
            validator,
            BoundaryValidationErrorKind::RawHostPointer,
            "memory",
            state.raw_host_pointer_count,
            "raw host pointers are never serialized",
        );
        Self::push_count(
            &mut violations,
            validator,
            BoundaryValidationErrorKind::RawReturnAddress,
            "activation",
            state.raw_return_address_count,
            "raw return addresses are never replay objects",
        );
        Self::push_count(
            &mut violations,
            validator,
            BoundaryValidationErrorKind::UnknownObjectClass,
            "object",
            state.unknown_object_class_count,
            "package contains an unknown object class",
        );
        Self::push_count(
            &mut violations,
            validator,
            BoundaryValidationErrorKind::StaleGeneration,
            "object-ref",
            state.stale_generation_count,
            "package contains stale object generations",
        );
        Self::push_count(
            &mut violations,
            validator,
            BoundaryValidationErrorKind::MissingArtifactIdentity,
            "artifact",
            state.missing_artifact_identity_count,
            "artifact identity is missing",
        );
        Self::push_count(
            &mut violations,
            validator,
            BoundaryValidationErrorKind::DanglingCapabilityObject,
            "capability",
            state.dangling_capability_object_count,
            "capability references an unknown object",
        );
        Self::push_count(
            &mut violations,
            validator,
            BoundaryValidationErrorKind::RawDmaBinding,
            "dma",
            state.raw_dma_binding_count,
            "raw DMA bindings cannot be serialized",
        );
        Self::push_count(
            &mut violations,
            validator,
            BoundaryValidationErrorKind::RawMmioBinding,
            "mmio",
            state.raw_mmio_binding_count,
            "raw MMIO bindings cannot be serialized",
        );
        for mode in &state.record_modes {
            if *mode == RecordMode::ForbiddenDuringReplay {
                violations.push(BoundaryValidationViolation::new(
                    validator,
                    BoundaryValidationErrorKind::RecordModeMismatch,
                    mode.as_str(),
                    "hostcall mode is forbidden during replay",
                ));
            } else if !state.supported_record_modes.iter().any(|supported| supported == mode) {
                violations.push(BoundaryValidationViolation::new(
                    validator,
                    BoundaryValidationErrorKind::UnsupportedRecordMode,
                    mode.as_str(),
                    "record mode is not supported by this replay validator",
                ));
            }
        }
        BoundaryValidationReport::new(validator, violations)
    }

    fn push_count(
        violations: &mut Vec<BoundaryValidationViolation>,
        validator: BoundaryValidatorKind,
        kind: BoundaryValidationErrorKind,
        object: &str,
        count: u32,
        detail: &str,
    ) {
        if count == 0 {
            return;
        }
        violations.push(BoundaryValidationViolation::new(
            validator,
            kind,
            object,
            &format!("{detail}; count={count}"),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(class: MemoryClass) -> MemoryClassPolicy {
        *memory_class_policies().iter().find(|policy| policy.class == class).unwrap()
    }

    #[test]
    fn memory_class_policy_table_enforces_v1_invariants() {
        assert_eq!(policy(MemoryClass::DmwWindowMemory).class, MemoryClass::DmwWindowMemory);
        assert_eq!(policy(MemoryClass::DmwWindowMemory).owner_kind, OwnerKind::Substrate);
        assert_ne!(
            policy(MemoryClass::DmwWindowMemory).class,
            policy(MemoryClass::StoreLinearMemory).class
        );
        assert_eq!(
            policy(MemoryClass::StoreLocalHeap).cleanup_policy,
            CleanupPolicy::DropWithStore
        );
        assert!(policy(MemoryClass::GuestMemory).can_alias_guest_memory);
        assert_eq!(policy(MemoryClass::CodeMemory).migratable, MigrationPolicy::Rebuilt);
        assert!(policy(MemoryClass::CodeMemory).can_be_executable);
        assert_eq!(policy(MemoryClass::ActivationStack).migratable, MigrationPolicy::NeverMigrated);
        assert_eq!(policy(MemoryClass::DmaMemory).migratable, MigrationPolicy::QuiesceRequired);
        assert_eq!(
            policy(MemoryClass::MmioWindowMemory).migratable,
            MigrationPolicy::NeverMigrated
        );
        assert!(!policy(MemoryClass::HostcallTableMemory).permissions.write);
        assert_eq!(
            policy(MemoryClass::ReadonlyMetadataMemory).snapshot_policy,
            SnapshotPolicy::Include
        );
        assert_eq!(
            policy(MemoryClass::StoreTableMemory).snapshot_policy,
            SnapshotPolicy::ConvertToLogicalImport
        );
        assert_eq!(
            policy(MemoryClass::SnapshotMetadataMemory).owner_kind,
            OwnerKind::TargetExecutor
        );
    }

    #[test]
    fn snapshot_barrier_validator_rejects_live_native_boundaries() {
        let state = SnapshotBarrierValidationState {
            active_dmw_lease_count: 1,
            active_nonconvertible_activation_count: 1,
            in_flight_dma_count: 1,
            unsealed_event_log: true,
            unflushed_trap_record_count: 1,
            pending_cleanup_count: 1,
            native_activation_stack_live: true,
            raw_dma_binding_count: 1,
            raw_mmio_binding_count: 1,
            active_framebuffer_window_lease_count: 1,
            active_framebuffer_mapping_count: 1,
            dirty_framebuffer_region_count: 1,
        };
        let report = SnapshotBarrierValidator::validate(&state);
        assert!(!report.is_ok());
        for kind in [
            BoundaryValidationErrorKind::ActiveDmwLease,
            BoundaryValidationErrorKind::ActiveNonConvertibleActivation,
            BoundaryValidationErrorKind::InFlightDma,
            BoundaryValidationErrorKind::UnsealedEventLog,
            BoundaryValidationErrorKind::UnflushedTrapRecords,
            BoundaryValidationErrorKind::PendingCleanup,
            BoundaryValidationErrorKind::NativeActivationStackLive,
            BoundaryValidationErrorKind::RawDmaBinding,
            BoundaryValidationErrorKind::RawMmioBinding,
            BoundaryValidationErrorKind::ActiveFramebufferWindowLease,
            BoundaryValidationErrorKind::ActiveFramebufferMapping,
            BoundaryValidationErrorKind::DirtyFramebufferRegion,
        ] {
            assert!(report.violations.iter().any(|violation| violation.kind == kind));
        }
        assert!(SnapshotBarrierValidator::validate(&Default::default()).is_ok());
    }

    #[test]
    fn package_replay_validator_rejects_raw_state_and_bad_record_modes() {
        let mut record_modes = Vec::new();
        record_modes.push(RecordMode::Deterministic);
        record_modes.push(RecordMode::ForbiddenDuringReplay);
        record_modes.push(RecordMode::RecordOutput);
        let mut supported_record_modes = Vec::new();
        supported_record_modes.push(RecordMode::Deterministic);
        let state = ReplayPackageValidationState {
            raw_host_pointer_count: 1,
            raw_return_address_count: 1,
            unknown_object_class_count: 1,
            stale_generation_count: 1,
            missing_artifact_identity_count: 1,
            dangling_capability_object_count: 1,
            raw_dma_binding_count: 1,
            raw_mmio_binding_count: 1,
            record_modes,
            supported_record_modes,
        };
        let report = PackageReplayValidator::validate(&state);
        assert!(!report.is_ok());
        for kind in [
            BoundaryValidationErrorKind::RawHostPointer,
            BoundaryValidationErrorKind::RawReturnAddress,
            BoundaryValidationErrorKind::UnknownObjectClass,
            BoundaryValidationErrorKind::StaleGeneration,
            BoundaryValidationErrorKind::MissingArtifactIdentity,
            BoundaryValidationErrorKind::DanglingCapabilityObject,
            BoundaryValidationErrorKind::RawDmaBinding,
            BoundaryValidationErrorKind::RawMmioBinding,
            BoundaryValidationErrorKind::RecordModeMismatch,
            BoundaryValidationErrorKind::UnsupportedRecordMode,
        ] {
            assert!(report.violations.iter().any(|violation| violation.kind == kind));
        }
        let mut clean_modes = Vec::new();
        clean_modes.push(RecordMode::Deterministic);
        clean_modes.push(RecordMode::RecordInput);
        clean_modes.push(RecordMode::RecordOutput);
        clean_modes.push(RecordMode::RecordInputOutput);
        let clean = ReplayPackageValidationState::clean(clean_modes);
        assert!(PackageReplayValidator::validate(&clean).is_ok());
    }
}
