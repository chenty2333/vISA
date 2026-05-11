use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetArtifactKind {
    TargetArtifactImageV1,
    CwasmPayload,
    SupervisorCore,
    NativeStub,
}

impl TargetArtifactKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TargetArtifactImageV1 => "target-artifact-image-v1",
            Self::CwasmPayload => "cwasm-payload",
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
        Self { max_memory_pages, max_table_elements, max_hostcalls_per_activation }
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
        Self { start, len, permission }
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
        Self { symbol: symbol.to_string(), offset, len }
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
        Self { class, symbol: symbol.to_string(), offset }
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
    FaultDomain,
    EventLog,
    StoreControl,
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
            Self::FaultDomain => "fault-domain",
            Self::EventLog => "event-log",
            Self::StoreControl => "store-control",
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
                | Self::FaultDomain
                | Self::EventLog
                | Self::StoreControl
                | Self::Timer
        )
    }
}

pub const fn capability_class_requires_hostcall_gate(class: CapabilityClass) -> bool {
    matches!(
        class,
        CapabilityClass::Device
            | CapabilityClass::PacketDevice
            | CapabilityClass::CodePublish
            | CapabilityClass::MmioRegion
            | CapabilityClass::DmaBuffer
            | CapabilityClass::IrqLine
            | CapabilityClass::VirtioQueue
            | CapabilityClass::DmwWindow
            | CapabilityClass::Timer
            | CapabilityClass::Snapshot
            | CapabilityClass::FaultDomain
            | CapabilityClass::EventLog
            | CapabilityClass::StoreControl
            | CapabilityClass::NetInterface
            | CapabilityClass::NetSocket
            | CapabilityClass::GuestMemoryAccess
            | CapabilityClass::Display
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

    pub fn validate(&self) -> Result<(), HostcallSpecValidationError> {
        if self.number == 0 {
            return Err(HostcallSpecValidationError::ZeroNumber);
        }
        if self.name.is_empty() {
            return Err(HostcallSpecValidationError::EmptyName(self.number));
        }
        if self.object.is_empty() {
            return Err(HostcallSpecValidationError::EmptyObject(self.number));
        }
        if self.operation.is_empty() {
            return Err(HostcallSpecValidationError::EmptyOperation(self.number));
        }
        Ok(())
    }

    pub fn validate_table(hostcalls: &[Self]) -> Result<(), HostcallSpecValidationError> {
        let mut numbers = Vec::new();
        for hostcall in hostcalls {
            hostcall.validate()?;
            if numbers.contains(&hostcall.number) {
                return Err(HostcallSpecValidationError::DuplicateNumber(hostcall.number));
            }
            numbers.push(hostcall.number);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostcallSpecValidationError {
    ZeroNumber,
    DuplicateNumber(u32),
    EmptyName(u32),
    EmptyObject(u32),
    EmptyOperation(u32),
}

impl HostcallSpecValidationError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ZeroNumber => "hostcall-zero-number",
            Self::DuplicateNumber(_) => "hostcall-duplicate-number",
            Self::EmptyName(_) => "hostcall-empty-name",
            Self::EmptyObject(_) => "hostcall-empty-object",
            Self::EmptyOperation(_) => "hostcall-empty-operation",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityMatrixError {
    UnknownObjectClass,
    UnknownOperation,
}

impl AuthorityMatrixError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownObjectClass => "authority-unknown-object-class",
            Self::UnknownOperation => "authority-unknown-operation",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityMatrixDecision {
    pub class: CapabilityClass,
    pub requires_capability: bool,
    pub required_right: Option<String>,
}

pub struct AuthorityMatrix;

impl AuthorityMatrix {
    pub fn check(
        object: &str,
        operation: &str,
        declared_capability: bool,
    ) -> Result<AuthorityMatrixDecision, AuthorityMatrixError> {
        let class = CapabilityClass::from_object(object);
        let right = match class {
            CapabilityClass::MmioRegion => match operation {
                "read" | "read8" | "read16" | "read32" | "read64" => Some("read"),
                "write" | "write8" | "write16" | "write32" | "write64" => Some("write"),
                "fence" => Some("fence"),
                "map" => Some("map"),
                _ => return Err(AuthorityMatrixError::UnknownOperation),
            },
            CapabilityClass::DmaBuffer => match operation {
                "device_addr" => Some("device_addr"),
                "sync_for_device" | "sync_for_cpu" => Some("sync"),
                "free" => Some("free"),
                "submit" | "complete" | "cancel" | "map" => Some(operation),
                _ => return Err(AuthorityMatrixError::UnknownOperation),
            },
            CapabilityClass::IrqLine => match operation {
                "bind" | "ack" | "mask" | "unmask" | "deliver" => Some(operation),
                _ => return Err(AuthorityMatrixError::UnknownOperation),
            },
            CapabilityClass::DmwWindow => match operation {
                "map_user_window" => Some("map"),
                "unmap_user_window" => Some("unmap"),
                "read_window" | "write_window" => Some("access"),
                "open" | "close" | "acquire" | "release" => Some(operation),
                _ => return Err(AuthorityMatrixError::UnknownOperation),
            },
            CapabilityClass::CodePublish => match operation {
                "publish" | "retire" => Some(operation),
                _ => return Err(AuthorityMatrixError::UnknownOperation),
            },
            CapabilityClass::Snapshot => match operation {
                "enter_barrier" => Some("enter"),
                "export_package" => Some("export"),
                "import_package" => Some("import"),
                "enter" | "validate" | "replay" => Some(operation),
                _ => return Err(AuthorityMatrixError::UnknownOperation),
            },
            CapabilityClass::FaultDomain => match operation {
                "kill_store" => Some("kill"),
                "restart_store" => Some("restart"),
                "kill" | "restart" => Some(operation),
                _ => return Err(AuthorityMatrixError::UnknownOperation),
            },
            CapabilityClass::PacketDevice => match operation {
                "rx" | "tx" | "configure" | "poll" | "irq" | "dma" => Some(operation),
                _ => return Err(AuthorityMatrixError::UnknownOperation),
            },
            CapabilityClass::VirtioQueue => match operation {
                "notify" => Some("kick"),
                "consume" => Some("read"),
                "reset" => Some("reset"),
                "read" | "write" | "kick" => Some(operation),
                _ => return Err(AuthorityMatrixError::UnknownOperation),
            },
            CapabilityClass::Device => match operation {
                "probe" | "read" | "configure" | "reset" | "poll" => Some(operation),
                _ => return Err(AuthorityMatrixError::UnknownOperation),
            },
            CapabilityClass::GuestMemoryAccess => match operation {
                "read" | "write" | "map" | "unmap" => Some(operation),
                _ => return Err(AuthorityMatrixError::UnknownOperation),
            },
            CapabilityClass::Timer => match operation {
                "arm" | "cancel" | "read" => Some(operation),
                _ => return Err(AuthorityMatrixError::UnknownOperation),
            },
            CapabilityClass::EventLog => match operation {
                "append" | "inspect" => Some(operation),
                _ => return Err(AuthorityMatrixError::UnknownOperation),
            },
            CapabilityClass::StoreControl => match operation {
                "start" | "stop" | "restart" | "kill" => Some(operation),
                _ => return Err(AuthorityMatrixError::UnknownOperation),
            },
            CapabilityClass::NetInterface | CapabilityClass::NetSocket => Some(operation),
            CapabilityClass::FileHandle => match operation {
                "open" | "read" | "write" | "close" | "stat" | "seek" => Some(operation),
                _ => return Err(AuthorityMatrixError::UnknownOperation),
            },
            CapabilityClass::Display => match operation {
                "flush" | "present" | "lease" | "inspect" => Some(operation),
                _ => return Err(AuthorityMatrixError::UnknownOperation),
            },
            CapabilityClass::ServiceImport => {
                if object.contains('.') || declared_capability {
                    Some(operation)
                } else {
                    return Err(AuthorityMatrixError::UnknownObjectClass);
                }
            }
        };
        let requires_capability = capability_class_requires_hostcall_gate(class)
            || declared_capability
            || class != CapabilityClass::ServiceImport;
        Ok(AuthorityMatrixDecision {
            class,
            requires_capability,
            required_right: right.map(ToString::to_string),
        })
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
            operations: operations.iter().map(|operation| (*operation).to_string()).collect(),
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
    pub artifact_hash: String,
    pub hash_status: String,
    pub abi_fingerprint: String,
    pub manifest_binding_hash: String,
    pub code_hash: String,
    pub signature_scheme: String,
    pub signature_status: String,
    pub signature_verified: bool,
    pub signer: String,
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
    pub artifact_hash: String,
    pub hash_status: String,
    pub abi_fingerprint: String,
    pub manifest_binding_hash: String,
    pub code_hash: String,
    pub signature_scheme: String,
    pub signature_status: String,
    pub signature_verified: bool,
    pub signer: String,
}

impl ExpectedTargetArtifact {
    pub fn new(
        package: &str,
        artifact_name: &str,
        target_profile: &str,
        artifact_hash: &str,
        abi_fingerprint: &str,
        manifest_binding_hash: &str,
        code_hash: &str,
    ) -> Self {
        Self {
            package: package.to_string(),
            artifact_name: artifact_name.to_string(),
            target_profile: target_profile.to_string(),
            artifact_hash: artifact_hash.to_string(),
            hash_status: "unknown".to_string(),
            abi_fingerprint: abi_fingerprint.to_string(),
            manifest_binding_hash: manifest_binding_hash.to_string(),
            code_hash: code_hash.to_string(),
            signature_scheme: "unknown".to_string(),
            signature_status: "unknown".to_string(),
            signature_verified: false,
            signer: "unknown".to_string(),
        }
    }

    pub fn with_policy_status(
        mut self,
        hash_status: &str,
        signature_scheme: &str,
        signature_status: &str,
        signature_verified: bool,
        signer: &str,
    ) -> Self {
        self.hash_status = hash_status.to_string();
        self.signature_scheme = signature_scheme.to_string();
        self.signature_status = signature_status.to_string();
        self.signature_verified = signature_verified;
        self.signer = signer.to_string();
        self
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
        artifact_hash: &str,
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
            kind: TargetArtifactKind::TargetArtifactImageV1,
            target_profile: target_profile.to_string(),
            artifact_hash: artifact_hash.to_string(),
            hash_status: "unknown".to_string(),
            abi_fingerprint: abi_fingerprint.to_string(),
            manifest_binding_hash: manifest_binding_hash.to_string(),
            code_hash: code_hash.to_string(),
            signature_scheme: "unknown".to_string(),
            signature_status: "unknown".to_string(),
            signature_verified: false,
            signer: "unknown".to_string(),
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
            "target-artifact id={} package={} artifact={} kind={} profile={} artifact_hash={} hash_status={} abi={} binding={} code_hash={} signature={} signature_status={} signature_verified={} signer={} exports={} hostcalls={} caps={}",
            self.id,
            self.package,
            self.artifact_name,
            self.kind.as_str(),
            self.target_profile,
            self.artifact_hash,
            self.hash_status,
            self.abi_fingerprint,
            self.manifest_binding_hash,
            self.code_hash,
            self.signature_scheme,
            self.signature_status,
            self.signature_verified,
            self.signer,
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
    pub artifact_hash: String,
    pub hash_status: String,
    pub abi_fingerprint: String,
    pub manifest_binding_hash: String,
    pub code_hash: String,
    pub signature_scheme: String,
    pub signature_status: String,
    pub signature_verified: bool,
    pub signer: String,
    pub imports: Vec<String>,
    pub exports: Vec<String>,
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
            "verified-artifact id={} package={} profile={} artifact_hash={} hash_status={} abi={} binding={} code_hash={} signature={} signature_status={} signature_verified={} signer={} generation={}",
            self.artifact_id,
            self.package,
            self.target_profile,
            self.artifact_hash,
            self.hash_status,
            self.abi_fingerprint,
            self.manifest_binding_hash,
            self.code_hash,
            self.signature_scheme,
            self.signature_status,
            self.signature_verified,
            self.signer,
            self.generation
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactRegistryError {
    EmptyIdentity,
    EmptyManifestBinding,
    EmptyArtifactHash,
    EmptyCodeHash,
    EmptyTargetProfile,
    EmptyAbiFingerprint,
    InvalidHostcallSpec,
    DuplicateArtifact,
    UnexpectedArtifact,
    TargetProfileMismatch,
    AbiFingerprintMismatch,
    ManifestBindingMismatch,
    ArtifactHashMismatch,
    CodeHashMismatch,
    HashStatusMismatch,
    SignatureStatusMismatch,
}

impl ArtifactRegistryError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::EmptyIdentity => "artifact identity is incomplete",
            Self::EmptyManifestBinding => "artifact manifest binding hash is empty",
            Self::EmptyArtifactHash => "artifact hash is empty",
            Self::EmptyCodeHash => "artifact code hash is empty",
            Self::EmptyTargetProfile => "artifact target profile is empty",
            Self::EmptyAbiFingerprint => "artifact ABI fingerprint is empty",
            Self::InvalidHostcallSpec => "artifact hostcall table is malformed",
            Self::DuplicateArtifact => "artifact identity was already verified",
            Self::UnexpectedArtifact => "artifact is not present in expected manifest policy",
            Self::TargetProfileMismatch => "artifact target profile does not match expected policy",
            Self::AbiFingerprintMismatch => {
                "artifact ABI fingerprint does not match expected policy"
            }
            Self::ManifestBindingMismatch => {
                "artifact manifest binding hash does not match expected policy"
            }
            Self::ArtifactHashMismatch => "artifact hash does not match expected policy",
            Self::CodeHashMismatch => "artifact code hash does not match expected policy",
            Self::HashStatusMismatch => "artifact hash status does not match expected policy",
            Self::SignatureStatusMismatch => {
                "artifact signature status does not match expected policy"
            }
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
        Self { expected: Vec::new(), verified: Vec::new() }
    }

    pub fn with_expected(expected: Vec<ExpectedTargetArtifact>) -> Self {
        Self { expected, verified: Vec::new() }
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
        if image.artifact_hash.is_empty() {
            return Err(ArtifactRegistryError::EmptyArtifactHash);
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
        if HostcallSpec::validate_table(&image.hostcalls).is_err() {
            return Err(ArtifactRegistryError::InvalidHostcallSpec);
        }
        if self.verified.iter().any(|verified| verified.artifact_id == image.id) {
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
            if expected.artifact_hash != image.artifact_hash {
                return Err(ArtifactRegistryError::ArtifactHashMismatch);
            }
            if expected.code_hash != image.code_hash {
                return Err(ArtifactRegistryError::CodeHashMismatch);
            }
            if expected.hash_status != image.hash_status {
                return Err(ArtifactRegistryError::HashStatusMismatch);
            }
            if expected.signature_scheme != image.signature_scheme
                || expected.signature_status != image.signature_status
                || expected.signature_verified != image.signature_verified
                || expected.signer != image.signer
            {
                return Err(ArtifactRegistryError::SignatureStatusMismatch);
            }
        }
        let verified = VerifiedArtifact {
            artifact_id: image.id,
            package: image.package,
            artifact_name: image.artifact_name,
            role: image.role,
            target_profile: image.target_profile,
            artifact_hash: image.artifact_hash,
            hash_status: image.hash_status,
            abi_fingerprint: image.abi_fingerprint,
            manifest_binding_hash: image.manifest_binding_hash,
            code_hash: image.code_hash,
            signature_scheme: image.signature_scheme,
            signature_status: image.signature_status,
            signature_verified: image.signature_verified,
            signer: image.signer,
            imports: image.imports,
            exports: image.exports,
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

    pub fn restore_verified_records(&mut self, verified: &[VerifiedArtifact]) -> bool {
        let mut restored = Vec::new();
        for record in verified {
            if record.artifact_id == 0
                || record.generation == 0
                || record.package.is_empty()
                || record.artifact_name.is_empty()
                || HostcallSpec::validate_table(&record.hostcalls).is_err()
                || restored
                    .iter()
                    .any(|existing: &VerifiedArtifact| existing.artifact_id == record.artifact_id)
            {
                return false;
            }
            restored.push(record.clone());
        }
        self.verified = restored;
        true
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeObjectSimdRequirementStatus {
    ScalarOnly,
    Declared,
    MissingDeclaration,
}

impl CodeObjectSimdRequirementStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ScalarOnly => "scalar-only",
            Self::Declared => "declared",
            Self::MissingDeclaration => "missing-declaration",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeObjectSimdRequirement {
    pub uses_simd: bool,
    pub declared: bool,
    pub required_abi: String,
    pub min_vector_register_count: u16,
    pub min_vector_register_bits: u16,
    pub target_feature_set: Option<ContractObjectRef>,
    pub status: CodeObjectSimdRequirementStatus,
    pub note: String,
}

impl CodeObjectSimdRequirement {
    pub fn scalar_only(note: &str) -> Self {
        Self {
            uses_simd: false,
            declared: true,
            required_abi: String::new(),
            min_vector_register_count: 0,
            min_vector_register_bits: 0,
            target_feature_set: None,
            status: CodeObjectSimdRequirementStatus::ScalarOnly,
            note: note.to_string(),
        }
    }

    pub fn declared_simd(
        required_abi: &str,
        min_vector_register_count: u16,
        min_vector_register_bits: u16,
        target_feature_set: ContractObjectRef,
        note: &str,
    ) -> Self {
        Self {
            uses_simd: true,
            declared: true,
            required_abi: required_abi.to_string(),
            min_vector_register_count,
            min_vector_register_bits,
            target_feature_set: Some(target_feature_set),
            status: CodeObjectSimdRequirementStatus::Declared,
            note: note.to_string(),
        }
    }

    pub fn is_valid(&self) -> bool {
        match self.status {
            CodeObjectSimdRequirementStatus::ScalarOnly => {
                !self.uses_simd
                    && self.declared
                    && self.required_abi.is_empty()
                    && self.min_vector_register_count == 0
                    && self.min_vector_register_bits == 0
                    && self.target_feature_set.is_none()
            }
            CodeObjectSimdRequirementStatus::Declared => {
                self.uses_simd
                    && self.declared
                    && !self.required_abi.is_empty()
                    && self.min_vector_register_count > 0
                    && self.min_vector_register_bits > 0
                    && self.target_feature_set.is_some_and(|feature| {
                        feature.kind == ContractObjectKind::TargetFeatureSet
                            && feature.id != 0
                            && feature.generation != 0
                    })
            }
            CodeObjectSimdRequirementStatus::MissingDeclaration => false,
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
    pub bound_store_generation: Option<Generation>,
    pub code_hash: String,
    pub simd_requirement: CodeObjectSimdRequirement,
}

impl CodeObject {
    pub fn summary(&self) -> String {
        let store = self
            .bound_store
            .map(|store| {
                format!(
                    "{store}@{}",
                    self.bound_store_generation
                        .map(|generation| generation.to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                )
            })
            .unwrap_or_else(|| "none".to_string());
        let hostcall_table = self
            .hostcall_table
            .map(|table| table.to_string())
            .unwrap_or_else(|| "none".to_string());
        format!(
            "code-object id={} artifact={} package={} state={} generation={} store={} hostcall_table={} simd_requirement={} text={:#x}-{:#x} rodata={:#x}-{:#x}",
            self.id,
            self.artifact_id,
            self.package,
            self.state.as_str(),
            self.generation,
            store,
            hostcall_table,
            self.simd_requirement.status.as_str(),
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
    InvalidSimdRequirement,
}

impl CodePublisherError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::CodeObjectMissing => "code object is missing",
            Self::InvalidTransition => "invalid code object transition",
            Self::ArtifactNotVerified => "artifact is not verified",
            Self::StoreMissing => "store is missing",
            Self::InvalidSimdRequirement => "invalid code object SIMD requirement",
        }
    }
}

#[derive(Clone, Debug)]
pub struct CodePublisher {
    next_code_id: CodeObjectId,
    next_tombstone_event: EventId,
    objects: Vec<CodeObject>,
    tombstones: Vec<TombstoneRecord>,
}

impl CodePublisher {
    pub const fn new() -> Self {
        Self {
            next_code_id: 1,
            next_tombstone_event: 1,
            objects: Vec::new(),
            tombstones: Vec::new(),
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
            bound_store_generation: None,
            code_hash: artifact.code_hash.clone(),
            simd_requirement: CodeObjectSimdRequirement::scalar_only(
                "default scalar-only code object",
            ),
        });
        Ok(id)
    }

    pub fn declare_simd_requirement(
        &mut self,
        id: CodeObjectId,
        target_feature_set: ContractObjectRef,
        required_abi: &str,
        min_vector_register_count: u16,
        min_vector_register_bits: u16,
        note: &str,
    ) -> Result<(), CodePublisherError> {
        if target_feature_set.kind != ContractObjectKind::TargetFeatureSet
            || target_feature_set.id == 0
            || target_feature_set.generation == 0
            || required_abi.is_empty()
            || min_vector_register_count == 0
            || min_vector_register_bits == 0
        {
            return Err(CodePublisherError::InvalidSimdRequirement);
        }
        let object = self.object_mut(id)?;
        if matches!(
            object.state,
            CodeObjectState::Faulted | CodeObjectState::Retired | CodeObjectState::Unpublished
        ) {
            return Err(CodePublisherError::InvalidTransition);
        }
        object.simd_requirement = CodeObjectSimdRequirement::declared_simd(
            required_abi,
            min_vector_register_count,
            min_vector_register_bits,
            target_feature_set,
            note,
        );
        object.generation += 1;
        Ok(())
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
        store: &StoreRecord,
    ) -> Result<(), CodePublisherError> {
        if store.id == 0 {
            return Err(CodePublisherError::StoreMissing);
        }
        let object = self.object_mut(id)?;
        if object.state != CodeObjectState::PublishedRx {
            return Err(CodePublisherError::InvalidTransition);
        }
        object.state = CodeObjectState::BoundToStore;
        object.bound_store = Some(store.id);
        object.bound_store_generation = Some(store.generation);
        object.hostcall_table = Some(1000 + id);
        object.generation += 1;
        Ok(())
    }

    pub fn fault(&mut self, id: CodeObjectId) -> Result<(), CodePublisherError> {
        let object = self.object_mut(id)?;
        if matches!(object.state, CodeObjectState::Retired | CodeObjectState::Unpublished) {
            return Err(CodePublisherError::InvalidTransition);
        }
        object.state = CodeObjectState::Faulted;
        object.generation += 1;
        let generation = object.generation;
        self.record_tombstone(ContractObjectKind::CodeObject, id, generation, "code-faulted");
        Ok(())
    }

    pub fn retire(&mut self, id: CodeObjectId) -> Result<(), CodePublisherError> {
        let object = self.object_mut(id)?;
        if object.state == CodeObjectState::Unpublished {
            return Err(CodePublisherError::InvalidTransition);
        }
        object.state = CodeObjectState::Retired;
        object.generation += 1;
        let generation = object.generation;
        self.record_tombstone(ContractObjectKind::CodeObject, id, generation, "code-retired");
        Ok(())
    }

    pub fn unpublish(&mut self, id: CodeObjectId) -> Result<(), CodePublisherError> {
        let object = self.object_mut(id)?;
        if object.state != CodeObjectState::Retired {
            return Err(CodePublisherError::InvalidTransition);
        }
        object.state = CodeObjectState::Unpublished;
        object.bound_store = None;
        object.bound_store_generation = None;
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

    pub fn tombstones(&self) -> &[TombstoneRecord] {
        &self.tombstones
    }

    pub fn restore_records(
        &mut self,
        objects: &[CodeObject],
        tombstones: &[TombstoneRecord],
    ) -> bool {
        let mut restored_objects = Vec::new();
        for object in objects {
            if object.id == 0
                || object.generation == 0
                || object.artifact_id == 0
                || restored_objects.iter().any(|existing: &CodeObject| existing.id == object.id)
            {
                return false;
            }
            restored_objects.push(object.clone());
        }
        let mut restored_tombstones = Vec::new();
        for tombstone in tombstones {
            if tombstone.kind != ContractObjectKind::CodeObject
                || tombstone.id == 0
                || tombstone.generation == 0
                || restored_tombstones.iter().any(|existing: &TombstoneRecord| {
                    existing.object_ref() == tombstone.object_ref()
                })
            {
                return false;
            }
            restored_tombstones.push(tombstone.clone());
        }
        let object_next = restored_objects.iter().map(|object| object.id + 1).max().unwrap_or(1);
        let tombstone_next =
            restored_tombstones.iter().map(|tombstone| tombstone.id + 1).max().unwrap_or(1);
        self.next_code_id = object_next.max(tombstone_next);
        self.next_tombstone_event =
            restored_tombstones.iter().map(|tombstone| tombstone.died_at + 1).max().unwrap_or(1);
        self.objects = restored_objects;
        self.tombstones = restored_tombstones;
        true
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

    pub fn object_mut(&mut self, id: CodeObjectId) -> Result<&mut CodeObject, CodePublisherError> {
        self.objects
            .iter_mut()
            .find(|object| object.id == id)
            .ok_or(CodePublisherError::CodeObjectMissing)
    }

    fn record_tombstone(
        &mut self,
        kind: ContractObjectKind,
        id: u64,
        generation: Generation,
        reason: &str,
    ) {
        let event = self.next_tombstone_event;
        self.next_tombstone_event += 1;
        self.tombstones.push(TombstoneRecord::new(kind, id, generation, event, reason));
    }

    pub fn record_current_tombstone(
        &mut self,
        id: CodeObjectId,
        reason: &str,
    ) -> Result<(), CodePublisherError> {
        let generation = self.object(id).ok_or(CodePublisherError::CodeObjectMissing)?.generation;
        self.record_tombstone(ContractObjectKind::CodeObject, id, generation, reason);
        Ok(())
    }
}

impl Default for CodePublisher {
    fn default() -> Self {
        Self::new()
    }
}
