use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetArtifactKind {
    Cwasm,
    SupervisorCore,
    NativeStub,
}

impl TargetArtifactKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cwasm => "cwasm",
            Self::SupervisorCore => "supervisor-core",
            Self::NativeStub => "native-stub",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetMemoryPlan {
    pub max_memory_pages: u32,
    pub max_table_elements: u32,
    pub max_hostcalls_per_activation: u32,
}

impl TargetMemoryPlan {
    pub const fn new(
        max_memory_pages: u32,
        max_table_elements: u32,
        max_hostcalls_per_activation: u32,
    ) -> Self {
        Self {
            max_memory_pages,
            max_table_elements,
            max_hostcalls_per_activation,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeRangePermission {
    ReadWrite,
    ReadOnly,
    ReadExecute,
}

impl CodeRangePermission {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadWrite => "rw",
            Self::ReadOnly => "ro",
            Self::ReadExecute => "rx",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TargetAddressRange {
    pub start: u64,
    pub len: u64,
    pub permission: CodeRangePermission,
}

impl TargetAddressRange {
    pub const fn new(start: u64, len: u64, permission: CodeRangePermission) -> Self {
        Self {
            start,
            len,
            permission,
        }
    }

    pub const fn end(self) -> u64 {
        self.start + self.len
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetAddressMapEntry {
    pub symbol: String,
    pub offset: u64,
    pub len: u64,
}

impl TargetAddressMapEntry {
    pub fn new(symbol: &str, offset: u64, len: u64) -> Self {
        Self {
            symbol: symbol.to_string(),
            offset,
            len,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetTrapMetadata {
    pub class: TargetTrapClass,
    pub symbol: String,
    pub offset: u64,
}

impl TargetTrapMetadata {
    pub fn new(class: TargetTrapClass, symbol: &str, offset: u64) -> Self {
        Self {
            class,
            symbol: symbol.to_string(),
            offset,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostcallCategory {
    Service,
    Device,
    PacketDevice,
    Mmio,
    Dma,
    Irq,
    Virtqueue,
    Dmw,
    CodePublish,
    Snapshot,
    GuestMemory,
    Timer,
    Wait,
}

impl HostcallCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Service => "service",
            Self::Device => "device",
            Self::PacketDevice => "packet-device",
            Self::Mmio => "mmio",
            Self::Dma => "dma",
            Self::Irq => "irq",
            Self::Virtqueue => "virtqueue",
            Self::Dmw => "dmw",
            Self::CodePublish => "code-publish",
            Self::Snapshot => "snapshot",
            Self::GuestMemory => "guest-memory",
            Self::Timer => "timer",
            Self::Wait => "wait",
        }
    }

    pub const fn requires_capability(self) -> bool {
        matches!(
            self,
            Self::Device
                | Self::PacketDevice
                | Self::Mmio
                | Self::Dma
                | Self::Irq
                | Self::Virtqueue
                | Self::Dmw
                | Self::CodePublish
                | Self::Snapshot
                | Self::GuestMemory
                | Self::Timer
        )
    }
}

pub const fn capability_class_requires_hostcall_gate(class: CapabilityClass) -> bool {
    matches!(
        class,
        CapabilityClass::Device
            | CapabilityClass::PacketDevice
            | CapabilityClass::MmioRegion
            | CapabilityClass::DmaBuffer
            | CapabilityClass::IrqLine
            | CapabilityClass::VirtioQueue
            | CapabilityClass::DmwWindow
            | CapabilityClass::Timer
            | CapabilityClass::Snapshot
            | CapabilityClass::NetInterface
            | CapabilityClass::NetSocket
            | CapabilityClass::GuestMemoryAccess
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostcallSpec {
    pub number: u32,
    pub name: String,
    pub category: HostcallCategory,
    pub object: String,
    pub operation: String,
    pub may_pending: bool,
}

impl HostcallSpec {
    pub fn new(
        number: u32,
        name: &str,
        category: HostcallCategory,
        object: &str,
        operation: &str,
        may_pending: bool,
    ) -> Self {
        Self {
            number,
            name: name.to_string(),
            category,
            object: object.to_string(),
            operation: operation.to_string(),
            may_pending,
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "hostcall:{}:{}:{}:{}:pending{}",
            self.number,
            self.category.as_str(),
            self.object,
            self.operation,
            self.may_pending
        )
    }

    pub fn requires_capability(&self) -> bool {
        self.category.requires_capability()
            || capability_class_requires_hostcall_gate(CapabilityClass::from_object(&self.object))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetCapabilitySpec {
    pub object: String,
    pub operations: Vec<String>,
    pub lifetime: String,
    pub class: CapabilityClass,
}

impl TargetCapabilitySpec {
    pub fn new(object: &str, operations: &[&str], lifetime: &str) -> Self {
        Self {
            object: object.to_string(),
            operations: operations
                .iter()
                .map(|operation| (*operation).to_string())
                .collect(),
            lifetime: lifetime.to_string(),
            class: CapabilityClass::from_object(object),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetArtifactImage {
    pub id: TargetArtifactId,
    pub package: String,
    pub artifact_name: String,
    pub role: String,
    pub kind: TargetArtifactKind,
    pub target_profile: String,
    pub abi_fingerprint: String,
    pub manifest_binding_hash: String,
    pub code_hash: String,
    pub imports: Vec<String>,
    pub exports: Vec<String>,
    pub memory_plan: TargetMemoryPlan,
    pub trap_metadata: Vec<TargetTrapMetadata>,
    pub address_map: Vec<TargetAddressMapEntry>,
    pub capabilities: Vec<TargetCapabilitySpec>,
    pub hostcalls: Vec<HostcallSpec>,
    pub payload_len: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedTargetArtifact {
    pub package: String,
    pub artifact_name: String,
    pub target_profile: String,
    pub abi_fingerprint: String,
    pub manifest_binding_hash: String,
    pub code_hash: String,
}

impl ExpectedTargetArtifact {
    pub fn new(
        package: &str,
        artifact_name: &str,
        target_profile: &str,
        abi_fingerprint: &str,
        manifest_binding_hash: &str,
        code_hash: &str,
    ) -> Self {
        Self {
            package: package.to_string(),
            artifact_name: artifact_name.to_string(),
            target_profile: target_profile.to_string(),
            abi_fingerprint: abi_fingerprint.to_string(),
            manifest_binding_hash: manifest_binding_hash.to_string(),
            code_hash: code_hash.to_string(),
        }
    }
}

impl TargetArtifactImage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: TargetArtifactId,
        package: &str,
        artifact_name: &str,
        role: &str,
        target_profile: &str,
        abi_fingerprint: &str,
        manifest_binding_hash: &str,
        code_hash: &str,
        memory_plan: TargetMemoryPlan,
    ) -> Self {
        Self {
            id,
            package: package.to_string(),
            artifact_name: artifact_name.to_string(),
            role: role.to_string(),
            kind: TargetArtifactKind::Cwasm,
            target_profile: target_profile.to_string(),
            abi_fingerprint: abi_fingerprint.to_string(),
            manifest_binding_hash: manifest_binding_hash.to_string(),
            code_hash: code_hash.to_string(),
            imports: Vec::new(),
            exports: Vec::new(),
            memory_plan,
            trap_metadata: Vec::new(),
            address_map: Vec::new(),
            capabilities: Vec::new(),
            hostcalls: Vec::new(),
            payload_len: 0,
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "target-artifact id={} package={} artifact={} kind={} profile={} abi={} binding={} hash={} exports={} hostcalls={} caps={}",
            self.id,
            self.package,
            self.artifact_name,
            self.kind.as_str(),
            self.target_profile,
            self.abi_fingerprint,
            self.manifest_binding_hash,
            self.code_hash,
            self.exports.len(),
            self.hostcalls.len(),
            self.capabilities.len()
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedArtifact {
    pub artifact_id: TargetArtifactId,
    pub package: String,
    pub artifact_name: String,
    pub role: String,
    pub target_profile: String,
    pub abi_fingerprint: String,
    pub manifest_binding_hash: String,
    pub code_hash: String,
    pub memory_plan: TargetMemoryPlan,
    pub trap_metadata: Vec<TargetTrapMetadata>,
    pub address_map: Vec<TargetAddressMapEntry>,
    pub capabilities: Vec<TargetCapabilitySpec>,
    pub hostcalls: Vec<HostcallSpec>,
    pub payload_len: usize,
    pub generation: Generation,
}

impl VerifiedArtifact {
    pub fn summary(&self) -> String {
        format!(
            "verified-artifact id={} package={} profile={} abi={} binding={} hash={} generation={}",
            self.artifact_id,
            self.package,
            self.target_profile,
            self.abi_fingerprint,
            self.manifest_binding_hash,
            self.code_hash,
            self.generation
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactRegistryError {
    EmptyIdentity,
    EmptyManifestBinding,
    EmptyCodeHash,
    EmptyTargetProfile,
    EmptyAbiFingerprint,
    DuplicateArtifact,
    UnexpectedArtifact,
    TargetProfileMismatch,
    AbiFingerprintMismatch,
    ManifestBindingMismatch,
    CodeHashMismatch,
}

impl ArtifactRegistryError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::EmptyIdentity => "artifact identity is incomplete",
            Self::EmptyManifestBinding => "artifact manifest binding hash is empty",
            Self::EmptyCodeHash => "artifact code hash is empty",
            Self::EmptyTargetProfile => "artifact target profile is empty",
            Self::EmptyAbiFingerprint => "artifact ABI fingerprint is empty",
            Self::DuplicateArtifact => "artifact identity was already verified",
            Self::UnexpectedArtifact => "artifact is not present in expected manifest policy",
            Self::TargetProfileMismatch => "artifact target profile does not match expected policy",
            Self::AbiFingerprintMismatch => {
                "artifact ABI fingerprint does not match expected policy"
            }
            Self::ManifestBindingMismatch => {
                "artifact manifest binding hash does not match expected policy"
            }
            Self::CodeHashMismatch => "artifact code hash does not match expected policy",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ArtifactRegistry {
    expected: Vec<ExpectedTargetArtifact>,
    verified: Vec<VerifiedArtifact>,
}

impl ArtifactRegistry {
    pub const fn new() -> Self {
        Self {
            expected: Vec::new(),
            verified: Vec::new(),
        }
    }

    pub fn with_expected(expected: Vec<ExpectedTargetArtifact>) -> Self {
        Self {
            expected,
            verified: Vec::new(),
        }
    }

    pub fn verify(
        &mut self,
        image: TargetArtifactImage,
    ) -> Result<VerifiedArtifact, ArtifactRegistryError> {
        if image.id == 0 || image.package.is_empty() || image.artifact_name.is_empty() {
            return Err(ArtifactRegistryError::EmptyIdentity);
        }
        if image.manifest_binding_hash.is_empty() {
            return Err(ArtifactRegistryError::EmptyManifestBinding);
        }
        if image.code_hash.is_empty() {
            return Err(ArtifactRegistryError::EmptyCodeHash);
        }
        if image.target_profile.is_empty() {
            return Err(ArtifactRegistryError::EmptyTargetProfile);
        }
        if image.abi_fingerprint.is_empty() {
            return Err(ArtifactRegistryError::EmptyAbiFingerprint);
        }
        if self
            .verified
            .iter()
            .any(|verified| verified.artifact_id == image.id)
        {
            return Err(ArtifactRegistryError::DuplicateArtifact);
        }
        if !self.expected.is_empty() {
            let Some(expected) = self.expected.iter().find(|expected| {
                expected.package == image.package && expected.artifact_name == image.artifact_name
            }) else {
                return Err(ArtifactRegistryError::UnexpectedArtifact);
            };
            if expected.target_profile != image.target_profile {
                return Err(ArtifactRegistryError::TargetProfileMismatch);
            }
            if expected.abi_fingerprint != image.abi_fingerprint {
                return Err(ArtifactRegistryError::AbiFingerprintMismatch);
            }
            if expected.manifest_binding_hash != image.manifest_binding_hash {
                return Err(ArtifactRegistryError::ManifestBindingMismatch);
            }
            if expected.code_hash != image.code_hash {
                return Err(ArtifactRegistryError::CodeHashMismatch);
            }
        }
        let verified = VerifiedArtifact {
            artifact_id: image.id,
            package: image.package,
            artifact_name: image.artifact_name,
            role: image.role,
            target_profile: image.target_profile,
            abi_fingerprint: image.abi_fingerprint,
            manifest_binding_hash: image.manifest_binding_hash,
            code_hash: image.code_hash,
            memory_plan: image.memory_plan,
            trap_metadata: image.trap_metadata,
            address_map: image.address_map,
            capabilities: image.capabilities,
            hostcalls: image.hostcalls,
            payload_len: image.payload_len,
            generation: 1,
        };
        self.verified.push(verified.clone());
        Ok(verified)
    }

    pub fn verified(&self) -> &[VerifiedArtifact] {
        &self.verified
    }
}

impl Default for ArtifactRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeObjectState {
    AllocatedRw,
    Filled,
    Sealed,
    PublishedRx,
    BoundToStore,
    Faulted,
    Retired,
    Unpublished,
}

impl CodeObjectState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AllocatedRw => "allocated-rw",
            Self::Filled => "filled",
            Self::Sealed => "sealed",
            Self::PublishedRx => "published-rx",
            Self::BoundToStore => "bound-to-store",
            Self::Faulted => "faulted",
            Self::Retired => "retired",
            Self::Unpublished => "unpublished",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeObject {
    pub id: CodeObjectId,
    pub artifact_id: TargetArtifactId,
    pub package: String,
    pub owner_profile: String,
    pub generation: Generation,
    pub text: TargetAddressRange,
    pub rodata: TargetAddressRange,
    pub trap_metadata: Vec<TargetTrapMetadata>,
    pub address_map: Vec<TargetAddressMapEntry>,
    pub hostcall_table: Option<HostcallTableId>,
    pub hostcalls: Vec<HostcallSpec>,
    pub state: CodeObjectState,
    pub bound_store: Option<StoreId>,
    pub code_hash: String,
}

impl CodeObject {
    pub fn summary(&self) -> String {
        let store = self
            .bound_store
            .map(|store| store.to_string())
            .unwrap_or_else(|| "none".to_string());
        let hostcall_table = self
            .hostcall_table
            .map(|table| table.to_string())
            .unwrap_or_else(|| "none".to_string());
        format!(
            "code-object id={} artifact={} package={} state={} generation={} store={} hostcall_table={} text={:#x}-{:#x} rodata={:#x}-{:#x}",
            self.id,
            self.artifact_id,
            self.package,
            self.state.as_str(),
            self.generation,
            store,
            hostcall_table,
            self.text.start,
            self.text.end(),
            self.rodata.start,
            self.rodata.end()
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodePublisherError {
    CodeObjectMissing,
    InvalidTransition,
    ArtifactNotVerified,
    StoreMissing,
}

impl CodePublisherError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::CodeObjectMissing => "code object is missing",
            Self::InvalidTransition => "invalid code object transition",
            Self::ArtifactNotVerified => "artifact is not verified",
            Self::StoreMissing => "store is missing",
        }
    }
}

#[derive(Clone, Debug)]
pub struct CodePublisher {
    next_code_id: CodeObjectId,
    objects: Vec<CodeObject>,
}

impl CodePublisher {
    pub const fn new() -> Self {
        Self {
            next_code_id: 1,
            objects: Vec::new(),
        }
    }

    pub fn allocate(
        &mut self,
        artifact: &VerifiedArtifact,
    ) -> Result<CodeObjectId, CodePublisherError> {
        if artifact.generation == 0 {
            return Err(CodePublisherError::ArtifactNotVerified);
        }
        let id = self.next_code_id;
        self.next_code_id += 1;
        let base = 0x1000_0000 + id * 0x10_0000;
        self.objects.push(CodeObject {
            id,
            artifact_id: artifact.artifact_id,
            package: artifact.package.clone(),
            owner_profile: artifact.target_profile.clone(),
            generation: 1,
            text: TargetAddressRange::new(base, 0x8000, CodeRangePermission::ReadWrite),
            rodata: TargetAddressRange::new(base + 0x8000, 0x4000, CodeRangePermission::ReadOnly),
            trap_metadata: artifact.trap_metadata.clone(),
            address_map: artifact.address_map.clone(),
            hostcall_table: None,
            hostcalls: artifact.hostcalls.clone(),
            state: CodeObjectState::AllocatedRw,
            bound_store: None,
            code_hash: artifact.code_hash.clone(),
        });
        Ok(id)
    }

    pub fn fill(&mut self, id: CodeObjectId) -> Result<(), CodePublisherError> {
        self.transition(id, CodeObjectState::AllocatedRw, CodeObjectState::Filled)
    }

    pub fn seal(&mut self, id: CodeObjectId) -> Result<(), CodePublisherError> {
        self.transition(id, CodeObjectState::Filled, CodeObjectState::Sealed)
    }

    pub fn publish_rx(&mut self, id: CodeObjectId) -> Result<(), CodePublisherError> {
        let object = self.object_mut(id)?;
        if object.state != CodeObjectState::Sealed {
            return Err(CodePublisherError::InvalidTransition);
        }
        object.state = CodeObjectState::PublishedRx;
        object.text.permission = CodeRangePermission::ReadExecute;
        object.generation += 1;
        Ok(())
    }

    pub fn bind_to_store(
        &mut self,
        id: CodeObjectId,
        store: StoreId,
    ) -> Result<(), CodePublisherError> {
        if store == 0 {
            return Err(CodePublisherError::StoreMissing);
        }
        let object = self.object_mut(id)?;
        if object.state != CodeObjectState::PublishedRx {
            return Err(CodePublisherError::InvalidTransition);
        }
        object.state = CodeObjectState::BoundToStore;
        object.bound_store = Some(store);
        object.hostcall_table = Some(1000 + id);
        object.generation += 1;
        Ok(())
    }

    pub fn fault(&mut self, id: CodeObjectId) -> Result<(), CodePublisherError> {
        let object = self.object_mut(id)?;
        if matches!(
            object.state,
            CodeObjectState::Retired | CodeObjectState::Unpublished
        ) {
            return Err(CodePublisherError::InvalidTransition);
        }
        object.state = CodeObjectState::Faulted;
        object.generation += 1;
        Ok(())
    }

    pub fn retire(&mut self, id: CodeObjectId) -> Result<(), CodePublisherError> {
        let object = self.object_mut(id)?;
        if object.state == CodeObjectState::Unpublished {
            return Err(CodePublisherError::InvalidTransition);
        }
        object.state = CodeObjectState::Retired;
        object.generation += 1;
        Ok(())
    }

    pub fn unpublish(&mut self, id: CodeObjectId) -> Result<(), CodePublisherError> {
        let object = self.object_mut(id)?;
        if object.state != CodeObjectState::Retired {
            return Err(CodePublisherError::InvalidTransition);
        }
        object.state = CodeObjectState::Unpublished;
        object.bound_store = None;
        object.hostcall_table = None;
        object.generation += 1;
        Ok(())
    }

    pub fn object(&self, id: CodeObjectId) -> Option<&CodeObject> {
        self.objects.iter().find(|object| object.id == id)
    }

    pub fn objects(&self) -> &[CodeObject] {
        &self.objects
    }

    fn transition(
        &mut self,
        id: CodeObjectId,
        from: CodeObjectState,
        to: CodeObjectState,
    ) -> Result<(), CodePublisherError> {
        let object = self.object_mut(id)?;
        if object.state != from {
            return Err(CodePublisherError::InvalidTransition);
        }
        object.state = to;
        object.generation += 1;
        Ok(())
    }

    fn object_mut(&mut self, id: CodeObjectId) -> Result<&mut CodeObject, CodePublisherError> {
        self.objects
            .iter_mut()
            .find(|object| object.id == id)
            .ok_or(CodePublisherError::CodeObjectMissing)
    }
}

impl Default for CodePublisher {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedStoreRecord {
    pub store: StoreRecord,
    pub resource_arena: String,
    pub rebind_policy: String,
}

impl ManagedStoreRecord {
    pub fn summary(&self) -> String {
        format!(
            "store id={} package={} state={} generation={} domain={} arena={} rebind_policy={}",
            self.store.id,
            self.store.package,
            self.store.state.as_str(),
            self.store.generation,
            self.store.fault_domain,
            self.resource_arena,
            self.rebind_policy
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetStoreManagerError {
    StoreMissing,
    InvalidTransition,
}

impl TargetStoreManagerError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::StoreMissing => "store is missing",
            Self::InvalidTransition => "invalid store lifecycle transition",
        }
    }
}

#[derive(Clone, Debug)]
pub struct TargetStoreManager {
    next_store_id: StoreId,
    records: Vec<ManagedStoreRecord>,
}

impl TargetStoreManager {
    pub const fn new() -> Self {
        Self {
            next_store_id: 1,
            records: Vec::new(),
        }
    }

    pub fn register_verified_artifact(
        &mut self,
        artifact: &VerifiedArtifact,
        fault_policy: &str,
        rebind_policy: &str,
    ) -> StoreId {
        let id = self.next_store_id;
        self.next_store_id += 1;
        self.register_verified_artifact_with_id(id, artifact, fault_policy, rebind_policy)
    }

    pub fn register_verified_artifact_with_id(
        &mut self,
        store_id: StoreId,
        artifact: &VerifiedArtifact,
        fault_policy: &str,
        rebind_policy: &str,
    ) -> StoreId {
        self.next_store_id = self.next_store_id.max(store_id + 1);
        self.records.push(ManagedStoreRecord {
            store: StoreRecord {
                id: store_id,
                package: artifact.package.clone(),
                artifact: artifact.artifact_name.clone(),
                role: artifact.role.clone(),
                fault_policy: fault_policy.to_string(),
                fault_domain: store_id,
                resource: None,
                state: StoreState::Instantiating,
                generation: 1,
                restart_count: 0,
            },
            resource_arena: format!("store-arena:{}", artifact.package),
            rebind_policy: rebind_policy.to_string(),
        });
        store_id
    }

    pub fn set_running(&mut self, store: StoreId) -> Result<(), TargetStoreManagerError> {
        self.set_state(store, StoreState::Running)
    }

    pub fn begin_draining(&mut self, store: StoreId) -> Result<(), TargetStoreManagerError> {
        self.set_state(store, StoreState::Draining)
    }

    pub fn drop_store(&mut self, store: StoreId) -> Result<(), TargetStoreManagerError> {
        self.set_state(store, StoreState::Dead)
    }

    pub fn rebind_store(&mut self, store: StoreId) -> Result<(), TargetStoreManagerError> {
        let record = self.record_mut(store)?;
        if !matches!(
            record.store.state,
            StoreState::Restarting | StoreState::Dead
        ) {
            return Err(TargetStoreManagerError::InvalidTransition);
        }
        record.store.state = StoreState::Rebinding;
        record.store.generation += 1;
        record.store.restart_count += 1;
        Ok(())
    }

    pub fn record(&self, store: StoreId) -> Option<&ManagedStoreRecord> {
        self.records.iter().find(|record| record.store.id == store)
    }

    pub fn records(&self) -> &[ManagedStoreRecord] {
        &self.records
    }

    fn set_state(
        &mut self,
        store: StoreId,
        state: StoreState,
    ) -> Result<(), TargetStoreManagerError> {
        let record = self.record_mut(store)?;
        record.store.state = state;
        record.store.generation += 1;
        Ok(())
    }

    fn record_mut(
        &mut self,
        store: StoreId,
    ) -> Result<&mut ManagedStoreRecord, TargetStoreManagerError> {
        self.records
            .iter_mut()
            .find(|record| record.store.id == store)
            .ok_or(TargetStoreManagerError::StoreMissing)
    }
}

impl Default for TargetStoreManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActivationEntry {
    Symbol(String),
    Hostcall(u32),
}

impl ActivationEntry {
    pub fn summary(&self) -> String {
        match self {
            Self::Symbol(symbol) => format!("symbol:{symbol}"),
            Self::Hostcall(hostcall) => format!("hostcall:{hostcall}"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivationState {
    Running,
    Pending,
    Trapped,
    Returned,
    Dropped,
}

impl ActivationState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Pending => "pending",
            Self::Trapped => "trapped",
            Self::Returned => "returned",
            Self::Dropped => "dropped",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostcallReturnTag {
    Ok,
    Errno,
    Pending,
    Trap,
    KillStore,
    RestartSyscall,
}

impl HostcallReturnTag {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Errno => "errno",
            Self::Pending => "pending",
            Self::Trap => "trap",
            Self::KillStore => "kill-store",
            Self::RestartSyscall => "restart-syscall",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivationRecord {
    pub id: ActivationId,
    pub store: StoreId,
    pub store_generation: Generation,
    pub code_object: CodeObjectId,
    pub code_generation: Generation,
    pub artifact: TargetArtifactId,
    pub entry: ActivationEntry,
    pub generation: Generation,
    pub state: ActivationState,
    pub start_event: EventId,
    pub exit_event: Option<EventId>,
    pub active_dmw_leases: u32,
    pub blocked_wait: Option<WaitId>,
    pub trap: Option<TargetTrapId>,
    pub return_tag: Option<HostcallReturnTag>,
}

impl ActivationRecord {
    pub fn summary(&self) -> String {
        let exit = self
            .exit_event
            .map(|event| event.to_string())
            .unwrap_or_else(|| "none".to_string());
        let wait = self
            .blocked_wait
            .map(|wait| wait.to_string())
            .unwrap_or_else(|| "none".to_string());
        let trap = self
            .trap
            .map(|trap| trap.to_string())
            .unwrap_or_else(|| "none".to_string());
        let return_tag = self.return_tag.map(|tag| tag.as_str()).unwrap_or("none");
        format!(
            "activation id={} store={} store_generation={} code={} code_generation={} artifact={} entry={} state={} generation={} start={} exit={} dmw_leases={} wait={} trap={} return={}",
            self.id,
            self.store,
            self.store_generation,
            self.code_object,
            self.code_generation,
            self.artifact,
            self.entry.summary(),
            self.state.as_str(),
            self.generation,
            self.start_event,
            exit,
            self.active_dmw_leases,
            wait,
            trap,
            return_tag
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetTrapClass {
    GuestTrap,
    SupervisorStoreTrap,
    CapabilityTrap,
    WindowTrap,
    HostcallTrap,
    CodeObjectTrap,
    SubstrateFault,
}

impl TargetTrapClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GuestTrap => "guest-trap",
            Self::SupervisorStoreTrap => "supervisor-store-trap",
            Self::CapabilityTrap => "capability-trap",
            Self::WindowTrap => "window-trap",
            Self::HostcallTrap => "hostcall-trap",
            Self::CodeObjectTrap => "code-object-trap",
            Self::SubstrateFault => "substrate-fault",
        }
    }

    pub const fn legacy_trap(self) -> TrapClass {
        match self {
            Self::GuestTrap => TrapClass::GuestIllegalInstruction,
            Self::SupervisorStoreTrap => TrapClass::ServiceTrap,
            Self::CapabilityTrap => TrapClass::CapabilityDenied,
            Self::WindowTrap => TrapClass::WindowViolationTrap,
            Self::HostcallTrap => TrapClass::ServiceTrap,
            Self::CodeObjectTrap => TrapClass::WasmBoundsTrap,
            Self::SubstrateFault => TrapClass::SubstrateFault,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetTrapRecord {
    pub id: TargetTrapId,
    pub class: TargetTrapClass,
    pub store: Option<StoreId>,
    pub activation: Option<ActivationId>,
    pub code_object: Option<CodeObjectId>,
    pub artifact: Option<TargetArtifactId>,
    pub offset: Option<u64>,
    pub hostcall: Option<String>,
    pub fault_policy: String,
    pub effect: FailureEffect,
    pub detail: String,
}

impl TargetTrapRecord {
    pub fn summary(&self) -> String {
        let store = self
            .store
            .map(|store| store.to_string())
            .unwrap_or_else(|| "none".to_string());
        let activation = self
            .activation
            .map(|activation| activation.to_string())
            .unwrap_or_else(|| "none".to_string());
        let code = self
            .code_object
            .map(|code| code.to_string())
            .unwrap_or_else(|| "none".to_string());
        let artifact = self
            .artifact
            .map(|artifact| artifact.to_string())
            .unwrap_or_else(|| "none".to_string());
        let offset = self
            .offset
            .map(|offset| format!("{offset:#x}"))
            .unwrap_or_else(|| "none".to_string());
        let hostcall = self.hostcall.as_deref().unwrap_or("none");
        format!(
            "trap id={} class={} store={} activation={} code={} artifact={} offset={} hostcall={} policy={} effect={} detail={}",
            self.id,
            self.class.as_str(),
            store,
            activation,
            code,
            artifact,
            offset,
            hostcall,
            self.fault_policy,
            self.effect.summary(),
            self.detail
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityHandleArg {
    pub id: CapabilityId,
    pub object: String,
    pub generation: Generation,
    pub rights_mask: u64,
    pub rights: Vec<String>,
}

impl CapabilityHandleArg {
    pub fn new(
        id: CapabilityId,
        object: &str,
        generation: Generation,
        rights_mask: u64,
        rights: &[&str],
    ) -> Self {
        Self {
            id,
            object: object.to_string(),
            generation,
            rights_mask,
            rights: rights.iter().map(|right| (*right).to_string()).collect(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostcallFrame {
    pub abi_version: String,
    pub flags: u32,
    pub activation: ActivationId,
    pub store: StoreId,
    pub store_generation: Generation,
    pub code_object: CodeObjectId,
    pub code_generation: Generation,
    pub artifact: TargetArtifactId,
    pub hostcall_number: u32,
    pub subject: String,
    pub object: String,
    pub operation: String,
    pub generation: Generation,
    pub args: [u64; 6],
    pub cap_args: Vec<CapabilityHandleArg>,
    pub ret_tag: HostcallReturnTag,
    pub ret0: u64,
    pub ret1: u64,
    pub trap_out: Option<TargetTrapId>,
    pub wait_token_out: Option<WaitId>,
}

impl HostcallFrame {
    pub const ABI_VERSION: &'static str = "vmos-target-hostcall-frame-v1";

    pub fn new(
        activation: ActivationId,
        store: StoreId,
        hostcall_number: u32,
        subject: &str,
        object: &str,
        operation: &str,
        generation: Generation,
    ) -> Self {
        Self {
            abi_version: Self::ABI_VERSION.to_string(),
            flags: 0,
            activation,
            store,
            store_generation: 0,
            code_object: 0,
            code_generation: 0,
            artifact: 0,
            hostcall_number,
            subject: subject.to_string(),
            object: object.to_string(),
            operation: operation.to_string(),
            generation,
            args: [0; 6],
            cap_args: Vec::new(),
            ret_tag: HostcallReturnTag::Ok,
            ret0: 0,
            ret1: 0,
            trap_out: None,
            wait_token_out: None,
        }
    }

    pub fn new_bound(
        activation: ActivationId,
        store: &StoreRecord,
        code: &CodeObject,
        hostcall_number: u32,
        object: &str,
        operation: &str,
        generation: Generation,
    ) -> Self {
        let mut frame = Self::new(
            activation,
            store.id,
            hostcall_number,
            &code.package,
            object,
            operation,
            generation,
        );
        frame.store_generation = store.generation;
        frame.code_object = code.id;
        frame.code_generation = code.generation;
        frame.artifact = code.artifact_id;
        frame
    }

    pub fn with_args(mut self, args: [u64; 6]) -> Self {
        self.args = args;
        self
    }

    pub fn with_cap_args(mut self, cap_args: Vec<CapabilityHandleArg>) -> Self {
        self.cap_args = cap_args;
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostcallTraceRecord {
    pub abi_version: String,
    pub flags: u32,
    pub activation: ActivationId,
    pub store: StoreId,
    pub store_generation: Generation,
    pub code_object: CodeObjectId,
    pub code_generation: Generation,
    pub artifact: TargetArtifactId,
    pub hostcall_number: u32,
    pub name: String,
    pub category: HostcallCategory,
    pub subject: String,
    pub object: String,
    pub operation: String,
    pub args: [u64; 6],
    pub cap_args: Vec<CapabilityHandleArg>,
    pub allowed: bool,
    pub result: String,
    pub ret_tag: HostcallReturnTag,
    pub ret0: u64,
    pub ret1: u64,
    pub trap_out: Option<TargetTrapId>,
    pub wait_token_out: Option<WaitId>,
}

impl HostcallTraceRecord {
    pub fn summary(&self) -> String {
        format!(
            "hostcall abi={} activation={} store={} store_generation={} code={} code_generation={} artifact={} number={} name={} category={} subject={} object={} op={} allowed={} result={} ret={}",
            self.abi_version,
            self.activation,
            self.store,
            self.store_generation,
            self.code_object,
            self.code_generation,
            self.artifact,
            self.hostcall_number,
            self.name,
            self.category.as_str(),
            self.subject,
            self.object,
            self.operation,
            self.allowed,
            self.result,
            self.ret_tag.as_str()
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationObjectClass {
    Migrated,
    Rebuilt,
    NeverMigrated,
}

impl MigrationObjectClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Migrated => "migrated",
            Self::Rebuilt => "rebuilt",
            Self::NeverMigrated => "never-migrated",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationObjectRecord {
    pub object: String,
    pub class: MigrationObjectClass,
    pub reason: String,
}

impl MigrationObjectRecord {
    pub fn new(object: &str, class: MigrationObjectClass, reason: &str) -> Self {
        Self {
            object: object.to_string(),
            class,
            reason: reason.to_string(),
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "migration-object object={} class={} reason={}",
            self.object,
            self.class.as_str(),
            self.reason
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DmwLeaseRecord {
    pub id: DmwLeaseId,
    pub activation: ActivationId,
    pub handle: String,
    pub generation: Generation,
    pub active: bool,
}

impl DmwLeaseRecord {
    pub fn summary(&self) -> String {
        format!(
            "dmw-lease id={} activation={} handle={} generation={} active={}",
            self.id, self.activation, self.handle, self.generation, self.active
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetExecutorError {
    StoreNotRunning,
    CodeObjectNotBound,
    ActivationMissing,
    ActivationNotRunning,
    ActivationStoreMismatch,
    CodeObjectMismatch,
    HostcallFrameMismatch,
    HostcallSubjectMismatch,
    HostcallAbiMismatch,
    HostcallNotDeclared,
    CapabilityDenied,
    DmwLeaseActive,
    DmwLeaseMissing,
}

impl TargetExecutorError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::StoreNotRunning => "store is not running",
            Self::CodeObjectNotBound => "code object is not bound to the store",
            Self::ActivationMissing => "activation is missing",
            Self::ActivationNotRunning => "activation is not running",
            Self::ActivationStoreMismatch => "activation/store mismatch",
            Self::CodeObjectMismatch => "activation/code object attribution mismatch",
            Self::HostcallFrameMismatch => "hostcall frame does not match declared hostcall",
            Self::HostcallSubjectMismatch => "hostcall subject does not match code object package",
            Self::HostcallAbiMismatch => "hostcall frame ABI version mismatch",
            Self::HostcallNotDeclared => "hostcall is not declared by code object",
            Self::CapabilityDenied => "hostcall capability gate denied access",
            Self::DmwLeaseActive => "active DMW lease cannot cross exit boundary",
            Self::DmwLeaseMissing => "DMW lease is missing",
        }
    }
}

#[derive(Clone, Debug)]
pub struct TargetExecutor {
    next_activation_id: ActivationId,
    next_trap_id: TargetTrapId,
    next_lease_id: DmwLeaseId,
    next_event_id: EventId,
    activations: Vec<ActivationRecord>,
    traps: Vec<TargetTrapRecord>,
    dmw_leases: Vec<DmwLeaseRecord>,
    hostcall_trace: Vec<HostcallTraceRecord>,
    event_log: Vec<String>,
}

impl TargetExecutor {
    pub const fn new() -> Self {
        Self {
            next_activation_id: 1,
            next_trap_id: 1,
            next_lease_id: 1,
            next_event_id: 1,
            activations: Vec::new(),
            traps: Vec::new(),
            dmw_leases: Vec::new(),
            hostcall_trace: Vec::new(),
            event_log: Vec::new(),
        }
    }

    pub fn start_activation(
        &mut self,
        store: &StoreRecord,
        code: &CodeObject,
        entry: ActivationEntry,
    ) -> Result<ActivationId, TargetExecutorError> {
        if store.state != StoreState::Running {
            return Err(TargetExecutorError::StoreNotRunning);
        }
        if code.state != CodeObjectState::BoundToStore || code.bound_store != Some(store.id) {
            return Err(TargetExecutorError::CodeObjectNotBound);
        }
        let id = self.next_activation_id;
        self.next_activation_id += 1;
        let start_event = self.next_event("activation-started");
        self.activations.push(ActivationRecord {
            id,
            store: store.id,
            store_generation: store.generation,
            code_object: code.id,
            code_generation: code.generation,
            artifact: code.artifact_id,
            entry,
            generation: 1,
            state: ActivationState::Running,
            start_event,
            exit_event: None,
            active_dmw_leases: 0,
            blocked_wait: None,
            trap: None,
            return_tag: None,
        });
        Ok(id)
    }

    pub fn invoke_hostcall(
        &mut self,
        code: &CodeObject,
        frame: HostcallFrame,
        capabilities: &CapabilityLedger,
    ) -> Result<(), TargetExecutorError> {
        let abi_mismatch = frame.abi_version != HostcallFrame::ABI_VERSION;
        if abi_mismatch {
            self.event_log.push(format!(
                "HostcallAbiMismatch activation={} abi={} expected={}",
                frame.activation,
                frame.abi_version,
                HostcallFrame::ABI_VERSION
            ));
        }
        let activation_index = self.activation_index(frame.activation)?;
        let activation = self.activations[activation_index].clone();
        if activation.state != ActivationState::Running {
            return Err(TargetExecutorError::ActivationNotRunning);
        }
        if activation.store != frame.store || activation.store_generation != frame.store_generation
        {
            return Err(TargetExecutorError::ActivationStoreMismatch);
        }
        if activation.code_object != code.id
            || activation.code_generation != code.generation
            || activation.artifact != code.artifact_id
            || frame.code_object != code.id
            || frame.code_generation != code.generation
            || frame.artifact != code.artifact_id
            || code.bound_store != Some(frame.store)
        {
            self.record_trap_for_activation(
                activation_index,
                TargetTrapClass::CodeObjectTrap,
                Some(code),
                Some(format!("hostcall#{}", frame.hostcall_number)),
                "attribution-failure",
                FailureEffect::CompleteWithErrno(5),
                "hostcall frame did not match activation code object attribution",
            );
            return Err(TargetExecutorError::CodeObjectMismatch);
        }
        if abi_mismatch {
            let spec = code
                .hostcalls
                .iter()
                .find(|spec| spec.number == frame.hostcall_number)
                .cloned()
                .unwrap_or_else(|| {
                    HostcallSpec::new(
                        frame.hostcall_number,
                        "hostcall.bad-abi",
                        HostcallCategory::Service,
                        &frame.object,
                        &frame.operation,
                        false,
                    )
                });
            let trap = self.record_trap_for_activation(
                activation_index,
                TargetTrapClass::HostcallTrap,
                Some(code),
                Some(spec.name.clone()),
                "bad-hostcall-abi",
                FailureEffect::CompleteWithErrno(22),
                "hostcall frame ABI version mismatch",
            );
            self.record_trace(
                &frame,
                &spec,
                false,
                "bad-hostcall-abi",
                HostcallReturnTag::Trap,
                Some(trap),
                None,
            );
            return Err(TargetExecutorError::HostcallAbiMismatch);
        }
        let Some(spec) = code
            .hostcalls
            .iter()
            .find(|spec| spec.number == frame.hostcall_number)
        else {
            let trap = self.record_trap_for_activation(
                activation_index,
                TargetTrapClass::HostcallTrap,
                Some(code),
                Some(format!("hostcall#{}", frame.hostcall_number)),
                "restart",
                FailureEffect::CompleteWithErrno(38),
                "hostcall not declared by artifact",
            );
            self.record_trace(
                &frame,
                &HostcallSpec::new(
                    frame.hostcall_number,
                    "hostcall.undeclared",
                    HostcallCategory::Service,
                    &frame.object,
                    &frame.operation,
                    false,
                ),
                false,
                "undeclared",
                HostcallReturnTag::Trap,
                Some(trap),
                None,
            );
            return Err(TargetExecutorError::HostcallNotDeclared);
        };
        if frame.object != spec.object || frame.operation != spec.operation {
            let trap = self.record_trap_for_activation(
                activation_index,
                TargetTrapClass::HostcallTrap,
                Some(code),
                Some(spec.name.clone()),
                "frame-mismatch",
                FailureEffect::CompleteWithErrno(22),
                "hostcall frame object/operation did not match manifest declaration",
            );
            self.record_trace(
                &frame,
                spec,
                false,
                "frame-mismatch",
                HostcallReturnTag::Trap,
                Some(trap),
                None,
            );
            return Err(TargetExecutorError::HostcallFrameMismatch);
        }
        if frame.subject != code.package {
            self.event_log.push(format!(
                "HostcallSubjectMismatch activation={} subject={} expected={}",
                frame.activation, frame.subject, code.package
            ));
            let trap = self.record_trap_for_activation(
                activation_index,
                TargetTrapClass::CapabilityTrap,
                Some(code),
                Some(spec.name.clone()),
                "subject-mismatch",
                FailureEffect::CompleteWithErrno(1),
                "hostcall subject did not match activation code object package",
            );
            self.record_trace(
                &frame,
                spec,
                false,
                "subject-mismatch",
                HostcallReturnTag::Trap,
                Some(trap),
                None,
            );
            return Err(TargetExecutorError::HostcallSubjectMismatch);
        }
        self.event_log.push(format!(
            "HostcallEntered activation={} name={} category={} subject={} object={} op={}",
            frame.activation,
            spec.name,
            spec.category.as_str(),
            frame.subject,
            frame.object,
            frame.operation
        ));
        if spec.may_pending && self.activations[activation_index].active_dmw_leases != 0 {
            let trap = self.record_trap_for_activation(
                activation_index,
                TargetTrapClass::WindowTrap,
                Some(code),
                Some(spec.name.clone()),
                "restart",
                FailureEffect::CompleteWithErrno(14),
                "pending hostcall attempted with active DMW lease",
            );
            self.record_trace(
                &frame,
                spec,
                false,
                "dmw-lease-active",
                HostcallReturnTag::Trap,
                Some(trap),
                None,
            );
            return Err(TargetExecutorError::DmwLeaseActive);
        }
        let requires_capability = spec.requires_capability()
            || capabilities
                .generation_of(&frame.subject, &frame.object)
                .is_some();
        if requires_capability {
            if let Some(reason) = Self::cap_arg_denial_reason(&frame, spec, capabilities) {
                self.event_log.push(format!(
                    "CapabilityDenied activation={} subject={} object={} op={} reason={reason}",
                    frame.activation, frame.subject, frame.object, frame.operation
                ));
                let trap = self.record_trap_for_activation(
                    activation_index,
                    TargetTrapClass::CapabilityTrap,
                    Some(code),
                    Some(spec.name.clone()),
                    "capability-handle",
                    FailureEffect::CompleteWithErrno(1),
                    "hostcall capability handle argument failed validation",
                );
                self.record_trace(
                    &frame,
                    spec,
                    false,
                    reason,
                    HostcallReturnTag::Trap,
                    Some(trap),
                    None,
                );
                return Err(TargetExecutorError::CapabilityDenied);
            }
            match capabilities.check(&frame.subject, &frame.object, &frame.operation) {
                Ok(capability) => {
                    if capability.generation != frame.generation {
                        self.event_log.push(format!(
                            "CapabilityGenerationMismatch activation={} subject={} object={} op={} expected={} actual={}",
                            frame.activation,
                            frame.subject,
                            frame.object,
                            frame.operation,
                            frame.generation,
                            capability.generation
                        ));
                        let trap = self.record_trap_for_activation(
                            activation_index,
                            TargetTrapClass::CapabilityTrap,
                            Some(code),
                            Some(spec.name.clone()),
                            "rebind-or-fail",
                            FailureEffect::CompleteWithErrno(1),
                            "capability generation mismatch",
                        );
                        self.record_trace(
                            &frame,
                            spec,
                            false,
                            "capability-generation",
                            HostcallReturnTag::Trap,
                            Some(trap),
                            None,
                        );
                        return Err(TargetExecutorError::CapabilityDenied);
                    }
                }
                Err(reason) => {
                    self.event_log.push(format!(
                        "CapabilityDenied activation={} subject={} object={} op={} reason={}",
                        frame.activation,
                        frame.subject,
                        frame.object,
                        frame.operation,
                        reason.as_str()
                    ));
                    let trap = self.record_trap_for_activation(
                        activation_index,
                        TargetTrapClass::CapabilityTrap,
                        Some(code),
                        Some(spec.name.clone()),
                        "rebind-or-fail",
                        FailureEffect::CompleteWithErrno(1),
                        "hostcall capability gate denied access",
                    );
                    self.record_trace(
                        &frame,
                        spec,
                        false,
                        reason.as_str(),
                        HostcallReturnTag::Trap,
                        Some(trap),
                        None,
                    );
                    return Err(TargetExecutorError::CapabilityDenied);
                }
            }
        }
        self.record_trace(
            &frame,
            spec,
            true,
            "complete",
            HostcallReturnTag::Ok,
            None,
            None,
        );
        let activation = &mut self.activations[activation_index];
        activation.return_tag = Some(HostcallReturnTag::Ok);
        activation.generation += 1;
        Ok(())
    }

    pub fn acquire_dmw_lease(
        &mut self,
        activation: ActivationId,
        handle: &str,
    ) -> Result<DmwLeaseId, TargetExecutorError> {
        let activation_index = self.activation_index(activation)?;
        if self.activations[activation_index].state != ActivationState::Running {
            return Err(TargetExecutorError::ActivationNotRunning);
        }
        let id = self.next_lease_id;
        self.next_lease_id += 1;
        self.dmw_leases.push(DmwLeaseRecord {
            id,
            activation,
            handle: handle.to_string(),
            generation: 1,
            active: true,
        });
        self.activations[activation_index].active_dmw_leases += 1;
        self.event_log.push(format!(
            "DmwLeaseAcquired activation={activation} lease={id} handle={handle}"
        ));
        Ok(id)
    }

    pub fn release_dmw_lease(&mut self, lease: DmwLeaseId) -> Result<(), TargetExecutorError> {
        let Some(lease_index) = self.dmw_leases.iter().position(|record| record.id == lease) else {
            return Err(TargetExecutorError::DmwLeaseMissing);
        };
        if !self.dmw_leases[lease_index].active {
            return Ok(());
        }
        let activation = self.dmw_leases[lease_index].activation;
        let activation_index = self.activation_index(activation)?;
        self.dmw_leases[lease_index].active = false;
        self.dmw_leases[lease_index].generation += 1;
        self.activations[activation_index].active_dmw_leases = self.activations[activation_index]
            .active_dmw_leases
            .saturating_sub(1);
        self.event_log.push(format!(
            "DmwLeaseReleased activation={activation} lease={lease}"
        ));
        Ok(())
    }

    pub fn release_all_leases_for_activation(
        &mut self,
        activation: ActivationId,
        reason: &str,
    ) -> Result<u32, TargetExecutorError> {
        self.activation_index(activation)?;
        Ok(self.release_all_leases_for_activation_id(activation, reason))
    }

    pub fn pending_exit(
        &mut self,
        activation: ActivationId,
        wait: WaitId,
    ) -> Result<(), TargetExecutorError> {
        let activation_index = self.activation_index(activation)?;
        if self.activations[activation_index].active_dmw_leases != 0 {
            self.record_trap_for_activation(
                activation_index,
                TargetTrapClass::WindowTrap,
                None,
                None,
                "restart",
                FailureEffect::CompleteWithErrno(14),
                "activation attempted to enter pending with an active DMW lease",
            );
            return Err(TargetExecutorError::DmwLeaseActive);
        }
        let exit_event = self.next_event("activation-pending");
        let activation = &mut self.activations[activation_index];
        activation.state = ActivationState::Pending;
        activation.blocked_wait = Some(wait);
        activation.return_tag = Some(HostcallReturnTag::Pending);
        activation.exit_event = Some(exit_event);
        activation.generation += 1;
        Ok(())
    }

    pub fn return_exit(&mut self, activation: ActivationId) -> Result<(), TargetExecutorError> {
        let activation_index = self.activation_index(activation)?;
        if self.activations[activation_index].active_dmw_leases != 0 {
            self.record_trap_for_activation(
                activation_index,
                TargetTrapClass::WindowTrap,
                None,
                None,
                "restart",
                FailureEffect::CompleteWithErrno(14),
                "activation attempted to return with an active DMW lease",
            );
            return Err(TargetExecutorError::DmwLeaseActive);
        }
        let exit_event = self.next_event("activation-returned");
        let activation = &mut self.activations[activation_index];
        activation.state = ActivationState::Returned;
        activation.return_tag = Some(HostcallReturnTag::Ok);
        activation.exit_event = Some(exit_event);
        activation.generation += 1;
        Ok(())
    }

    pub fn trap_exit(
        &mut self,
        activation: ActivationId,
        class: TargetTrapClass,
        code: Option<&CodeObject>,
        detail: &str,
    ) -> Result<TargetTrapId, TargetExecutorError> {
        let activation_index = self.activation_index(activation)?;
        if self.activations[activation_index].active_dmw_leases != 0 {
            self.record_trap_for_activation(
                activation_index,
                TargetTrapClass::WindowTrap,
                code,
                None,
                "restart",
                FailureEffect::CompleteWithErrno(14),
                "activation attempted to trap with an active DMW lease",
            );
            return Err(TargetExecutorError::DmwLeaseActive);
        }
        Ok(self.record_trap_for_activation(
            activation_index,
            class,
            code,
            None,
            "trap-policy",
            FailureEffect::CompleteWithErrno(5),
            detail,
        ))
    }

    pub fn synthetic_trap(
        &mut self,
        class: TargetTrapClass,
        store: StoreId,
        activation: Option<ActivationId>,
        code: Option<&CodeObject>,
        hostcall: Option<&str>,
        detail: &str,
    ) -> TargetTrapId {
        let id = self.next_trap_id;
        self.next_trap_id += 1;
        self.traps.push(TargetTrapRecord {
            id,
            class,
            store: Some(store),
            activation,
            code_object: code.map(|code| code.id),
            artifact: code.map(|code| code.artifact_id),
            offset: Some(0),
            hostcall: hostcall.map(|hostcall| hostcall.to_string()),
            fault_policy: "harness-classification".to_string(),
            effect: FailureEffect::CompleteWithErrno(5),
            detail: detail.to_string(),
        });
        self.event_log.push(format!(
            "TrapClassified trap={id} class={} store={store} detail={detail}",
            class.as_str()
        ));
        id
    }

    pub fn snapshot_barrier(&self) -> Result<(), TargetExecutorError> {
        if self.dmw_leases.iter().any(|lease| lease.active) {
            return Err(TargetExecutorError::DmwLeaseActive);
        }
        Ok(())
    }

    pub fn classify_migration_objects(
        &self,
        code_objects: &[CodeObject],
    ) -> Vec<MigrationObjectRecord> {
        let mut records = Vec::new();
        records.push(MigrationObjectRecord::new(
            "semantic-object-graph",
            MigrationObjectClass::Migrated,
            "semantic roots are serialized",
        ));
        records.push(MigrationObjectRecord::new(
            "store-records",
            MigrationObjectClass::Migrated,
            "StoreRecord lifecycle state is semantic",
        ));
        for code in code_objects {
            records.push(MigrationObjectRecord::new(
                &format!("code-object:{}", code.id),
                MigrationObjectClass::Rebuilt,
                "target republishes executable code from verified artifact",
            ));
        }
        records.push(MigrationObjectRecord::new(
            "native-stack",
            MigrationObjectClass::NeverMigrated,
            "native stacks are substrate state",
        ));
        records.push(MigrationObjectRecord::new(
            "dmw-pointer",
            MigrationObjectClass::NeverMigrated,
            "handle-mode leases cannot cross snapshot barrier",
        ));
        records
    }

    pub fn activations(&self) -> &[ActivationRecord] {
        &self.activations
    }

    pub fn traps(&self) -> &[TargetTrapRecord] {
        &self.traps
    }

    pub fn dmw_leases(&self) -> &[DmwLeaseRecord] {
        &self.dmw_leases
    }

    pub fn hostcall_trace(&self) -> &[HostcallTraceRecord] {
        &self.hostcall_trace
    }

    pub fn event_log(&self) -> &[String] {
        &self.event_log
    }

    fn cap_arg_denial_reason(
        frame: &HostcallFrame,
        spec: &HostcallSpec,
        capabilities: &CapabilityLedger,
    ) -> Option<&'static str> {
        if frame.cap_args.is_empty() {
            return None;
        }
        let mut matched_frame_object = false;
        for handle in &frame.cap_args {
            let Some(record) = capabilities.active(handle.id) else {
                return Some("cap-arg-missing");
            };
            if record.subject != frame.subject {
                return Some("cap-arg-subject");
            }
            if record.object != handle.object {
                return Some("cap-arg-object");
            }
            if record.generation != handle.generation {
                return Some("cap-arg-generation");
            }
            if handle.rights.is_empty() {
                return Some("cap-arg-empty-rights");
            }
            if handle.rights_mask == 0 {
                return Some("cap-arg-rights-mask");
            }
            for right in &handle.rights {
                if !record.operations.contains(right) {
                    return Some("cap-arg-rights");
                }
            }
            let Some(rights_mask) = Self::capability_rights_mask(record, &handle.rights) else {
                return Some("cap-arg-rights-mask");
            };
            if rights_mask != handle.rights_mask {
                return Some("cap-arg-rights-mask");
            }
            if handle.object == frame.object
                && handle.rights.iter().any(|right| right == &frame.operation)
            {
                matched_frame_object = true;
            }
        }
        if spec.requires_capability() && !matched_frame_object {
            return Some("cap-arg-frame-right");
        }
        None
    }

    fn capability_rights_mask(record: &CapabilityRecord, rights: &[String]) -> Option<u64> {
        let mut mask = 0u64;
        for right in rights {
            let index = record
                .operations
                .as_slice()
                .iter()
                .position(|operation| operation == right)?;
            if index >= u64::BITS as usize {
                return None;
            }
            mask |= 1u64 << index;
        }
        Some(mask)
    }

    fn record_trace(
        &mut self,
        frame: &HostcallFrame,
        spec: &HostcallSpec,
        allowed: bool,
        result: &str,
        ret_tag: HostcallReturnTag,
        trap_out: Option<TargetTrapId>,
        wait_token_out: Option<WaitId>,
    ) {
        self.hostcall_trace.push(HostcallTraceRecord {
            abi_version: frame.abi_version.clone(),
            flags: frame.flags,
            activation: frame.activation,
            store: frame.store,
            store_generation: frame.store_generation,
            code_object: frame.code_object,
            code_generation: frame.code_generation,
            artifact: frame.artifact,
            hostcall_number: spec.number,
            name: spec.name.clone(),
            category: spec.category,
            subject: frame.subject.clone(),
            object: spec.object.clone(),
            operation: spec.operation.clone(),
            args: frame.args,
            cap_args: frame.cap_args.clone(),
            allowed,
            result: result.to_string(),
            ret_tag,
            ret0: frame.ret0,
            ret1: frame.ret1,
            trap_out,
            wait_token_out,
        });
    }

    fn record_trap_for_activation(
        &mut self,
        activation_index: usize,
        class: TargetTrapClass,
        code: Option<&CodeObject>,
        hostcall: Option<String>,
        fault_policy: &str,
        effect: FailureEffect,
        detail: &str,
    ) -> TargetTrapId {
        let activation_id = self.activations[activation_index].id;
        let store = self.activations[activation_index].store;
        self.release_all_leases_for_activation_id(activation_id, "trap-quarantine");
        let id = self.next_trap_id;
        self.next_trap_id += 1;
        self.traps.push(TargetTrapRecord {
            id,
            class,
            store: Some(store),
            activation: Some(activation_id),
            code_object: code.map(|code| code.id),
            artifact: code.map(|code| code.artifact_id),
            offset: Some(0),
            hostcall,
            fault_policy: fault_policy.to_string(),
            effect,
            detail: detail.to_string(),
        });
        let exit_event = self.next_event("activation-trapped");
        let activation = &mut self.activations[activation_index];
        activation.state = ActivationState::Trapped;
        activation.trap = Some(id);
        activation.return_tag = Some(HostcallReturnTag::Trap);
        activation.exit_event = Some(exit_event);
        activation.generation += 1;
        id
    }

    fn release_all_leases_for_activation_id(
        &mut self,
        activation: ActivationId,
        reason: &str,
    ) -> u32 {
        let mut released = 0;
        for lease in &mut self.dmw_leases {
            if lease.activation == activation && lease.active {
                lease.active = false;
                lease.generation += 1;
                released += 1;
                self.event_log.push(format!(
                    "DmwLeaseReleased activation={activation} lease={} reason={reason}",
                    lease.id
                ));
            }
        }
        if released != 0 {
            if let Some(index) = self
                .activations
                .iter()
                .position(|record| record.id == activation)
            {
                self.activations[index].active_dmw_leases = self.activations[index]
                    .active_dmw_leases
                    .saturating_sub(released);
            }
            self.event_log.push(format!(
                "DmwLeaseQuarantined activation={activation} released={released} reason={reason}"
            ));
        }
        released
    }

    fn activation_index(&self, activation: ActivationId) -> Result<usize, TargetExecutorError> {
        self.activations
            .iter()
            .position(|record| record.id == activation)
            .ok_or(TargetExecutorError::ActivationMissing)
    }

    fn next_event(&mut self, label: &str) -> EventId {
        let id = self.next_event_id;
        self.next_event_id += 1;
        self.event_log
            .push(format!("TargetExecutorEvent id={id} label={label}"));
        id
    }
}

impl Default for TargetExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image() -> TargetArtifactImage {
        let mut image = TargetArtifactImage::new(
            1,
            "driver_virtio_net",
            "driver_virtio_net.cwasm",
            "driver",
            "host-validation",
            "abi-1",
            "binding-1",
            "hash-1",
            TargetMemoryPlan::new(16, 32, 64),
        );
        image.exports.push("vmos_service_entry".to_string());
        image
            .address_map
            .push(TargetAddressMapEntry::new("_start", 0, 64));
        image.trap_metadata.push(TargetTrapMetadata::new(
            TargetTrapClass::CodeObjectTrap,
            "_start",
            0,
        ));
        image.capabilities.push(TargetCapabilitySpec::new(
            "mmio.virtio-net",
            &["map"],
            "store",
        ));
        image.hostcalls.push(HostcallSpec::new(
            1,
            "hostcall.mmio.map",
            HostcallCategory::Mmio,
            "mmio.virtio-net",
            "map",
            false,
        ));
        image.hostcalls.push(HostcallSpec::new(
            2,
            "hostcall.mmio.denied",
            HostcallCategory::Mmio,
            "mmio.denied",
            "map",
            false,
        ));
        image.hostcalls.push(HostcallSpec::new(
            3,
            "hostcall.dma.denied",
            HostcallCategory::Dma,
            "dma.denied",
            "map",
            false,
        ));
        image.hostcalls.push(HostcallSpec::new(
            4,
            "hostcall.irq.denied",
            HostcallCategory::Irq,
            "irq.denied",
            "bind",
            false,
        ));
        image.hostcalls.push(HostcallSpec::new(
            5,
            "hostcall.dmw.denied",
            HostcallCategory::Dmw,
            "dmw.denied",
            "open",
            false,
        ));
        image.hostcalls.push(HostcallSpec::new(
            6,
            "hostcall.code-publish.denied",
            HostcallCategory::CodePublish,
            "code-publish.denied",
            "publish",
            false,
        ));
        image.hostcalls.push(HostcallSpec::new(
            7,
            "hostcall.packet-device.denied",
            HostcallCategory::PacketDevice,
            "packet-device.net0",
            "rx",
            false,
        ));
        image.hostcalls.push(HostcallSpec::new(
            8,
            "hostcall.wait.pending",
            HostcallCategory::Wait,
            "wait.timer",
            "park",
            true,
        ));
        image
    }

    fn running_store_and_code() -> (
        VerifiedArtifact,
        ManagedStoreRecord,
        CodeObject,
        CapabilityLedger,
    ) {
        let mut registry = ArtifactRegistry::new();
        let verified = registry.verify(image()).unwrap();
        let mut stores = TargetStoreManager::new();
        let store_id =
            stores.register_verified_artifact(&verified, "restartable", "rebuild-from-artifact");
        stores.set_running(store_id).unwrap();
        let mut publisher = CodePublisher::new();
        let code_id = publisher.allocate(&verified).unwrap();
        publisher.fill(code_id).unwrap();
        publisher.seal(code_id).unwrap();
        publisher.publish_rx(code_id).unwrap();
        publisher.bind_to_store(code_id, store_id).unwrap();
        let mut capabilities = CapabilityLedger::new();
        capabilities.grant_with_metadata(
            "driver_virtio_net",
            "mmio.virtio-net",
            &["map"],
            "store",
            CapabilityClass::MmioRegion,
            Some(store_id),
            None,
            "target-executor-test",
        );
        (
            verified,
            stores.record(store_id).unwrap().clone(),
            publisher.object(code_id).unwrap().clone(),
            capabilities,
        )
    }

    #[test]
    fn registry_only_verifies_artifact_identity_and_code_publisher_owns_publish_state() {
        let mut registry = ArtifactRegistry::new();
        let verified = registry.verify(image()).unwrap();
        assert_eq!(registry.verified().len(), 1);
        assert_eq!(verified.artifact_id, 1);

        let mut publisher = CodePublisher::new();
        let code_id = publisher.allocate(&verified).unwrap();
        assert_eq!(
            publisher.object(code_id).unwrap().state,
            CodeObjectState::AllocatedRw
        );
        assert_eq!(
            publisher.publish_rx(code_id),
            Err(CodePublisherError::InvalidTransition)
        );
        publisher.fill(code_id).unwrap();
        publisher.seal(code_id).unwrap();
        publisher.publish_rx(code_id).unwrap();
        assert_eq!(
            publisher.object(code_id).unwrap().text.permission,
            CodeRangePermission::ReadExecute
        );

        let mut stores = TargetStoreManager::new();
        let store_id =
            stores.register_verified_artifact(&verified, "restartable", "rebuild-from-artifact");
        stores.set_running(store_id).unwrap();
        publisher.bind_to_store(code_id, store_id).unwrap();
        assert_eq!(
            publisher.object(code_id).unwrap().state,
            CodeObjectState::BoundToStore
        );
        assert_eq!(
            stores.record(store_id).unwrap().store.state,
            StoreState::Running
        );
    }

    #[test]
    fn registry_policy_rejects_manifest_binding_and_hash_mismatch() {
        let expected = ExpectedTargetArtifact::new(
            "driver_virtio_net",
            "driver_virtio_net.cwasm",
            "host-validation",
            "abi-1",
            "binding-1",
            "hash-1",
        );
        let mut expected_list = Vec::new();
        expected_list.push(expected);
        let mut registry = ArtifactRegistry::with_expected(expected_list);
        let mut bad = image();
        bad.code_hash = "hash-2".to_string();
        assert_eq!(
            registry.verify(bad),
            Err(ArtifactRegistryError::CodeHashMismatch)
        );

        let mut expected_list = Vec::new();
        expected_list.push(ExpectedTargetArtifact::new(
            "driver_virtio_net",
            "driver_virtio_net.cwasm",
            "host-validation",
            "abi-1",
            "binding-1",
            "hash-1",
        ));
        let mut registry = ArtifactRegistry::with_expected(expected_list);
        let verified = registry.verify(image()).unwrap();
        assert_eq!(verified.manifest_binding_hash, "binding-1");
    }

    #[test]
    fn hostcall_capability_gate_allows_granted_mmio_and_traps_ungranted_privileged_hostcalls() {
        let (_artifact, store, code, capabilities) = running_store_and_code();
        let mut executor = TargetExecutor::new();
        let activation = executor
            .start_activation(
                &store.store,
                &code,
                ActivationEntry::Symbol("_start".to_string()),
            )
            .unwrap();
        executor
            .invoke_hostcall(
                &code,
                HostcallFrame::new_bound(
                    activation,
                    &store.store,
                    &code,
                    1,
                    "mmio.virtio-net",
                    "map",
                    1,
                ),
                &capabilities,
            )
            .unwrap();
        assert!(executor.hostcall_trace()[0].allowed);

        for (number, object, operation) in [
            (2, "mmio.denied", "map"),
            (3, "dma.denied", "map"),
            (4, "irq.denied", "bind"),
            (5, "dmw.denied", "open"),
            (6, "code-publish.denied", "publish"),
            (7, "packet-device.net0", "rx"),
        ] {
            let activation = executor
                .start_activation(
                    &store.store,
                    &code,
                    ActivationEntry::Symbol("_start".to_string()),
                )
                .unwrap();
            assert_eq!(
                executor.invoke_hostcall(
                    &code,
                    HostcallFrame::new_bound(
                        activation,
                        &store.store,
                        &code,
                        number,
                        object,
                        operation,
                        1,
                    ),
                    &capabilities,
                ),
                Err(TargetExecutorError::CapabilityDenied)
            );
        }
        assert_eq!(executor.traps().len(), 6);
        assert!(
            executor
                .traps()
                .iter()
                .all(|trap| trap.class == TargetTrapClass::CapabilityTrap)
        );
        assert!(
            executor
                .event_log()
                .iter()
                .any(|event| event.contains("CapabilityDenied"))
        );
    }

    #[test]
    fn hostcall_rejects_code_object_attribution_mismatch() {
        let (_artifact, store, code, capabilities) = running_store_and_code();
        let mut other_code = code.clone();
        other_code.id = code.id + 100;
        let mut executor = TargetExecutor::new();
        let activation = executor
            .start_activation(
                &store.store,
                &code,
                ActivationEntry::Symbol("_start".to_string()),
            )
            .unwrap();
        assert_eq!(
            executor.invoke_hostcall(
                &other_code,
                HostcallFrame::new_bound(
                    activation,
                    &store.store,
                    &other_code,
                    1,
                    "mmio.virtio-net",
                    "map",
                    1,
                ),
                &capabilities,
            ),
            Err(TargetExecutorError::CodeObjectMismatch)
        );
        assert_eq!(executor.traps()[0].class, TargetTrapClass::CodeObjectTrap);
    }

    #[test]
    fn hostcall_rejects_spoofed_subject_and_bad_abi_with_trace() {
        let (_artifact, store, code, capabilities) = running_store_and_code();
        let mut executor = TargetExecutor::new();
        let activation = executor
            .start_activation(
                &store.store,
                &code,
                ActivationEntry::Symbol("_start".to_string()),
            )
            .unwrap();
        let mut frame = HostcallFrame::new_bound(
            activation,
            &store.store,
            &code,
            1,
            "mmio.virtio-net",
            "map",
            1,
        );
        frame.subject = "other_store".to_string();
        assert_eq!(
            executor.invoke_hostcall(&code, frame, &capabilities),
            Err(TargetExecutorError::HostcallSubjectMismatch)
        );
        assert_eq!(executor.traps()[0].class, TargetTrapClass::CapabilityTrap);
        assert_eq!(executor.hostcall_trace()[0].result, "subject-mismatch");

        let activation = executor
            .start_activation(
                &store.store,
                &code,
                ActivationEntry::Symbol("_start".to_string()),
            )
            .unwrap();
        let mut frame = HostcallFrame::new_bound(
            activation,
            &store.store,
            &code,
            1,
            "mmio.virtio-net",
            "map",
            1,
        );
        frame.abi_version = "bad-hostcall-abi".to_string();
        assert_eq!(
            executor.invoke_hostcall(&code, frame, &capabilities),
            Err(TargetExecutorError::HostcallAbiMismatch)
        );
        assert!(
            executor
                .hostcall_trace()
                .iter()
                .any(|trace| trace.result == "bad-hostcall-abi")
        );
        assert!(
            executor
                .traps()
                .iter()
                .any(|trap| trap.class == TargetTrapClass::HostcallTrap
                    && trap.fault_policy == "bad-hostcall-abi")
        );
    }

    #[test]
    fn cap_args_are_checked_against_ledger_generation_and_rights() {
        let (_artifact, store, code, capabilities) = running_store_and_code();
        let cap = capabilities
            .check("driver_virtio_net", "mmio.virtio-net", "map")
            .unwrap()
            .clone();
        let mut executor = TargetExecutor::new();
        let activation = executor
            .start_activation(
                &store.store,
                &code,
                ActivationEntry::Symbol("_start".to_string()),
            )
            .unwrap();
        let mut cap_args = Vec::new();
        cap_args.push(CapabilityHandleArg::new(
            cap.id,
            &cap.object,
            cap.generation,
            1,
            &["map"],
        ));
        executor
            .invoke_hostcall(
                &code,
                HostcallFrame::new_bound(
                    activation,
                    &store.store,
                    &code,
                    1,
                    "mmio.virtio-net",
                    "map",
                    cap.generation,
                )
                .with_cap_args(cap_args),
                &capabilities,
            )
            .unwrap();

        let activation = executor
            .start_activation(
                &store.store,
                &code,
                ActivationEntry::Symbol("_start".to_string()),
            )
            .unwrap();
        let mut stale_cap_args = Vec::new();
        stale_cap_args.push(CapabilityHandleArg::new(
            cap.id,
            &cap.object,
            cap.generation + 1,
            1,
            &["map"],
        ));
        assert_eq!(
            executor.invoke_hostcall(
                &code,
                HostcallFrame::new_bound(
                    activation,
                    &store.store,
                    &code,
                    1,
                    "mmio.virtio-net",
                    "map",
                    cap.generation,
                )
                .with_cap_args(stale_cap_args),
                &capabilities,
            ),
            Err(TargetExecutorError::CapabilityDenied)
        );
        assert!(
            executor
                .hostcall_trace()
                .iter()
                .any(|trace| trace.result == "cap-arg-generation")
        );

        let activation = executor
            .start_activation(
                &store.store,
                &code,
                ActivationEntry::Symbol("_start".to_string()),
            )
            .unwrap();
        let mut bad_mask_cap_args = Vec::new();
        bad_mask_cap_args.push(CapabilityHandleArg::new(
            cap.id,
            &cap.object,
            cap.generation,
            0,
            &["map"],
        ));
        assert_eq!(
            executor.invoke_hostcall(
                &code,
                HostcallFrame::new_bound(
                    activation,
                    &store.store,
                    &code,
                    1,
                    "mmio.virtio-net",
                    "map",
                    cap.generation,
                )
                .with_cap_args(bad_mask_cap_args),
                &capabilities,
            ),
            Err(TargetExecutorError::CapabilityDenied)
        );
        assert!(
            executor
                .hostcall_trace()
                .iter()
                .any(|trace| trace.result == "cap-arg-rights-mask")
        );
    }

    #[test]
    fn dmw_handle_mode_lease_cannot_cross_pending_or_snapshot_barrier() {
        let (_artifact, store, code, capabilities) = running_store_and_code();
        let mut executor = TargetExecutor::new();
        let activation = executor
            .start_activation(
                &store.store,
                &code,
                ActivationEntry::Symbol("_start".to_string()),
            )
            .unwrap();
        let lease = executor
            .acquire_dmw_lease(activation, "dmw.handle.1")
            .unwrap();
        assert_eq!(
            executor.snapshot_barrier(),
            Err(TargetExecutorError::DmwLeaseActive)
        );
        assert_eq!(
            executor.invoke_hostcall(
                &code,
                HostcallFrame::new_bound(
                    activation,
                    &store.store,
                    &code,
                    8,
                    "wait.timer",
                    "park",
                    1,
                ),
                &capabilities,
            ),
            Err(TargetExecutorError::DmwLeaseActive)
        );
        assert_eq!(executor.traps()[0].class, TargetTrapClass::WindowTrap);
        assert!(!executor.dmw_leases()[0].active);
        executor.release_dmw_lease(lease).unwrap();
        assert_eq!(executor.snapshot_barrier(), Ok(()));
    }

    #[test]
    fn typed_trap_surface_and_migration_classification_are_queryable() {
        let (_artifact, store, code, _capabilities) = running_store_and_code();
        let mut executor = TargetExecutor::new();
        let activation = executor
            .start_activation(
                &store.store,
                &code,
                ActivationEntry::Symbol("_start".to_string()),
            )
            .unwrap();
        for class in [
            TargetTrapClass::GuestTrap,
            TargetTrapClass::SupervisorStoreTrap,
            TargetTrapClass::CapabilityTrap,
            TargetTrapClass::WindowTrap,
            TargetTrapClass::HostcallTrap,
            TargetTrapClass::CodeObjectTrap,
            TargetTrapClass::SubstrateFault,
        ] {
            executor.synthetic_trap(
                class,
                store.store.id,
                Some(activation),
                Some(&code),
                None,
                "typed trap harness",
            );
        }
        assert_eq!(executor.traps().len(), 7);
        assert!(
            executor
                .traps()
                .iter()
                .any(|trap| trap.class == TargetTrapClass::CodeObjectTrap
                    && trap.code_object == Some(code.id)
                    && trap.artifact == Some(code.artifact_id))
        );
        let migration = executor.classify_migration_objects(core::slice::from_ref(&code));
        assert!(
            migration
                .iter()
                .any(|record| record.class == MigrationObjectClass::Migrated)
        );
        assert!(
            migration
                .iter()
                .any(|record| record.class == MigrationObjectClass::Rebuilt)
        );
        assert!(
            migration
                .iter()
                .any(|record| record.class == MigrationObjectClass::NeverMigrated)
        );
    }
}
