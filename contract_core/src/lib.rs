use std::error::Error;
use std::fmt;

use artifact_manifest::{
    ArtifactBundleManifest, CapabilityManifest, InterfaceRequirementManifest,
    MigrationPackageManifest, ModuleArtifactManifest, ResourceLimitsManifest,
    SupervisorContractManifest,
};
use service_core::net_contract::NETWORK_CONTRACT_VERSION;
use sha2::{Digest, Sha256};
use substrate_api::{
    AuthorityMismatch, AuthorityRequirementSet, SubstrateAuthorityRequirements,
    SubstrateCapabilitySet, SubstrateCompatibilityReport, SubstrateProfile,
};
use supervisor_catalog::{
    ARTIFACT_SIGNATURE_PROFILE, CAPABILITY_ABI_VERSION, COMPONENT_MODEL_VERSION, CapabilitySpec,
    DMW_LAYOUT, HOSTCALL_ABI_VERSION, LINUX_ABI_PROFILE, MACHINE_ABI_VERSION,
    RUNTIME_ONLY_EXECUTOR_ABI, SEMANTIC_CONTRACT_SCHEMA_VERSION, SUPERVISOR_ABI_VERSION,
    SUPERVISOR_ARTIFACT_FORMAT, SUPERVISOR_CODE_PAYLOAD_FORMAT, SUPERVISOR_COMPILER_ENGINE,
    SUPERVISOR_CONTRACT_VERSION, SUPERVISOR_EXECUTION_MODE, SUPERVISOR_WASM_MODULES,
    SUPERVISOR_WORLD, WASI_PROFILE_NONE, WASM_FEATURE_PROFILE, WIT_PACKAGE_VERSION, WasmModuleSpec,
    catalog_contract_fingerprint, module_dependencies, module_interface_spec,
    package_set_fingerprint,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractError {
    message: String,
}

impl ContractError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for ContractError {}

pub type ContractResult<T> = Result<T, ContractError>;

pub const CONTRACT_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new("semantic-contract-v0.1");
pub const CONTRACT_SCHEMA: &str = CONTRACT_SCHEMA_VERSION.name;
pub const VIEW_SCHEMA_V1: u16 = 1;
pub const EDGE_SCHEMA_V1: u16 = 1;
pub const EVENT_SCHEMA_V1: u16 = 1;
pub const TRACE_SCHEMA_V1: u16 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchemaVersion {
    pub name: &'static str,
}

impl SchemaVersion {
    pub const fn new(name: &'static str) -> Self {
        Self { name }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectKind {
    Hart,
    Task,
    RunnableQueue,
    ActivationContext,
    SavedContext,
    TimerInterrupt,
    IpiEvent,
    RemotePreempt,
    RemotePark,
    Preemption,
    SchedulerDecision,
    CrossHartSchedulerDecision,
    ActivationMigration,
    SmpSafePoint,
    StopTheWorldRendezvous,
    SmpCodePublishBarrier,
    SmpCleanupQuiescence,
    SmpSnapshotBarrier,
    SmpStressRun,
    SmpScalingBenchmark,
    DeviceObject,
    QueueObject,
    DescriptorObject,
    DmaBufferObject,
    MmioRegionObject,
    IrqLineObject,
    ActivationResume,
    ActivationWait,
    ActivationCleanup,
    PreemptionLatency,
    HartEventAttribution,
    Resource,
    Capability,
    WaitToken,
    FaultDomain,
    Store,
    StoreActivation,
    Activation,
    Artifact,
    CodeObject,
    Boundary,
    Transaction,
    Event,
    Trap,
    Hostcall,
    Cleanup,
    MemoryObject,
    GuestAddressSpace,
    VmaRegion,
    PageObject,
    Tombstone,
    External,
}

impl ObjectKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hart => "hart",
            Self::Task => "task",
            Self::RunnableQueue => "runnable-queue",
            Self::ActivationContext => "activation-context",
            Self::SavedContext => "saved-context",
            Self::TimerInterrupt => "timer-interrupt",
            Self::IpiEvent => "ipi-event",
            Self::RemotePreempt => "remote-preempt",
            Self::RemotePark => "remote-park",
            Self::Preemption => "preemption",
            Self::SchedulerDecision => "scheduler-decision",
            Self::CrossHartSchedulerDecision => "cross-hart-scheduler-decision",
            Self::ActivationMigration => "activation-migration",
            Self::SmpSafePoint => "smp-safe-point",
            Self::StopTheWorldRendezvous => "stop-the-world-rendezvous",
            Self::SmpCodePublishBarrier => "smp-code-publish-barrier",
            Self::SmpCleanupQuiescence => "smp-cleanup-quiescence",
            Self::SmpSnapshotBarrier => "smp-snapshot-barrier",
            Self::SmpStressRun => "smp-stress-run",
            Self::SmpScalingBenchmark => "smp-scaling-benchmark",
            Self::DeviceObject => "device-object",
            Self::QueueObject => "queue-object",
            Self::DescriptorObject => "descriptor-object",
            Self::DmaBufferObject => "dma-buffer-object",
            Self::MmioRegionObject => "mmio-region-object",
            Self::IrqLineObject => "irq-line-object",
            Self::ActivationResume => "activation-resume",
            Self::ActivationWait => "activation-wait",
            Self::ActivationCleanup => "activation-cleanup",
            Self::PreemptionLatency => "preemption-latency",
            Self::HartEventAttribution => "hart-event-attribution",
            Self::Resource => "resource",
            Self::Capability => "capability",
            Self::WaitToken => "wait-token",
            Self::FaultDomain => "fault-domain",
            Self::Store => "store",
            Self::StoreActivation => "store-activation",
            Self::Activation => "activation",
            Self::Artifact => "artifact",
            Self::CodeObject => "code-object",
            Self::Boundary => "boundary",
            Self::Transaction => "transaction",
            Self::Event => "event",
            Self::Trap => "trap",
            Self::Hostcall => "hostcall",
            Self::Cleanup => "cleanup",
            Self::MemoryObject => "memory-object",
            Self::GuestAddressSpace => "guest-address-space",
            Self::VmaRegion => "vma-region",
            Self::PageObject => "page-object",
            Self::Tombstone => "tombstone",
            Self::External => "external",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectRef {
    pub kind: ObjectKind,
    pub id: u64,
    pub generation: u64,
}

impl ObjectRef {
    pub fn new(kind: ObjectKind, id: u64, generation: u64) -> ContractResult<Self> {
        let reference = Self {
            kind,
            id,
            generation,
        };
        reference.validate()?;
        Ok(reference)
    }

    pub const fn unchecked(kind: ObjectKind, id: u64, generation: u64) -> Self {
        Self {
            kind,
            id,
            generation,
        }
    }

    pub fn validate(self) -> ContractResult<()> {
        if self.id == 0 {
            return Err(ContractError::new("object ref id=0 is invalid"));
        }
        if self.generation == 0 && self.kind != ObjectKind::External {
            return Err(ContractError::new(
                "object ref generation=0 is invalid for internal objects",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefMode {
    Live,
    Historical,
    CleanupEffect,
    External,
}

impl RefMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Historical => "historical",
            Self::CleanupEffect => "cleanup-effect",
            Self::External => "external",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractEdge {
    pub from: ObjectRef,
    pub to: ObjectRef,
    pub mode: RefMode,
    pub label: String,
    pub epoch: u64,
}

impl ContractEdge {
    pub fn new(from: ObjectRef, to: ObjectRef, mode: RefMode, label: &str, epoch: u64) -> Self {
        Self {
            from,
            to,
            mode,
            label: label.to_owned(),
            epoch,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TombstoneRecord {
    pub object: ObjectRef,
    pub died_at_event: u64,
    pub reason: String,
}

impl TombstoneRecord {
    pub fn new(object: ObjectRef, died_at_event: u64, reason: &str) -> Self {
        Self {
            object,
            died_at_event,
            reason: reason.to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TypedRefError {
    KindMismatch {
        expected: ObjectKind,
        actual: ObjectKind,
    },
    InvalidRef,
}

impl fmt::Display for TypedRefError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KindMismatch { expected, actual } => write!(
                f,
                "typed ref kind mismatch: expected {}, got {}",
                expected.as_str(),
                actual.as_str()
            ),
            Self::InvalidRef => f.write_str("invalid object ref"),
        }
    }
}

impl Error for TypedRefError {}

macro_rules! typed_ref {
    ($name:ident, $kind:expr) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct $name(pub ObjectRef);

        impl $name {
            pub fn new(id: u64, generation: u64) -> ContractResult<Self> {
                Ok(Self(ObjectRef::new($kind, id, generation)?))
            }

            pub fn try_from_ref(reference: ObjectRef) -> Result<Self, TypedRefError> {
                reference
                    .validate()
                    .map_err(|_| TypedRefError::InvalidRef)?;
                if reference.kind != $kind {
                    return Err(TypedRefError::KindMismatch {
                        expected: $kind,
                        actual: reference.kind,
                    });
                }
                Ok(Self(reference))
            }

            pub const fn object_ref(self) -> ObjectRef {
                self.0
            }
        }
    };
}

typed_ref!(StoreRef, ObjectKind::Store);
typed_ref!(HartRef, ObjectKind::Hart);
typed_ref!(CapabilityRef, ObjectKind::Capability);
typed_ref!(WaitTokenRef, ObjectKind::WaitToken);
typed_ref!(CleanupRef, ObjectKind::Cleanup);
typed_ref!(TaskRef, ObjectKind::Task);
typed_ref!(RunnableQueueRef, ObjectKind::RunnableQueue);
typed_ref!(ActivationContextRef, ObjectKind::ActivationContext);
typed_ref!(SavedContextRef, ObjectKind::SavedContext);
typed_ref!(TimerInterruptRef, ObjectKind::TimerInterrupt);
typed_ref!(IpiEventRef, ObjectKind::IpiEvent);
typed_ref!(RemotePreemptRef, ObjectKind::RemotePreempt);
typed_ref!(RemoteParkRef, ObjectKind::RemotePark);
typed_ref!(PreemptionRef, ObjectKind::Preemption);
typed_ref!(SchedulerDecisionRef, ObjectKind::SchedulerDecision);
typed_ref!(
    CrossHartSchedulerDecisionRef,
    ObjectKind::CrossHartSchedulerDecision
);
typed_ref!(ActivationMigrationRef, ObjectKind::ActivationMigration);
typed_ref!(SmpSafePointRef, ObjectKind::SmpSafePoint);
typed_ref!(
    StopTheWorldRendezvousRef,
    ObjectKind::StopTheWorldRendezvous
);
typed_ref!(SmpCodePublishBarrierRef, ObjectKind::SmpCodePublishBarrier);
typed_ref!(SmpCleanupQuiescenceRef, ObjectKind::SmpCleanupQuiescence);
typed_ref!(SmpSnapshotBarrierRef, ObjectKind::SmpSnapshotBarrier);
typed_ref!(SmpStressRunRef, ObjectKind::SmpStressRun);
typed_ref!(SmpScalingBenchmarkRef, ObjectKind::SmpScalingBenchmark);
typed_ref!(DeviceObjectRef, ObjectKind::DeviceObject);
typed_ref!(QueueObjectRef, ObjectKind::QueueObject);
typed_ref!(DescriptorObjectRef, ObjectKind::DescriptorObject);
typed_ref!(DmaBufferObjectRef, ObjectKind::DmaBufferObject);
typed_ref!(MmioRegionObjectRef, ObjectKind::MmioRegionObject);
typed_ref!(IrqLineObjectRef, ObjectKind::IrqLineObject);
typed_ref!(ActivationResumeRef, ObjectKind::ActivationResume);
typed_ref!(ActivationWaitRef, ObjectKind::ActivationWait);
typed_ref!(ActivationCleanupRef, ObjectKind::ActivationCleanup);
typed_ref!(PreemptionLatencyRef, ObjectKind::PreemptionLatency);
typed_ref!(HartEventAttributionRef, ObjectKind::HartEventAttribution);
typed_ref!(FaultDomainRef, ObjectKind::FaultDomain);
typed_ref!(ArtifactRef, ObjectKind::Artifact);
typed_ref!(CodeObjectRef, ObjectKind::CodeObject);
typed_ref!(ActivationRef, ObjectKind::Activation);
typed_ref!(TrapRef, ObjectKind::Trap);
typed_ref!(HostcallTraceRef, ObjectKind::Hostcall);
typed_ref!(GuestAddressSpaceRef, ObjectKind::GuestAddressSpace);
typed_ref!(VmaRegionRef, ObjectKind::VmaRegion);
typed_ref!(PageObjectRef, ObjectKind::PageObject);
typed_ref!(ExternalObjectRef, ObjectKind::External);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreViewV1 {
    pub schema: u16,
    pub kind: ObjectKind,
    pub object: ObjectRef,
    pub state: String,
    pub owner: Option<ObjectRef>,
    pub references: Vec<ContractEdge>,
    pub last_transition: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityViewV1 {
    pub schema: u16,
    pub kind: ObjectKind,
    pub object: ObjectRef,
    pub state: String,
    pub subject: ObjectRef,
    pub owner: Option<ObjectRef>,
    pub references: Vec<ContractEdge>,
    pub last_transition: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WaitViewV1 {
    pub schema: u16,
    pub kind: ObjectKind,
    pub object: ObjectRef,
    pub state: String,
    pub owner: Option<ObjectRef>,
    pub references: Vec<ContractEdge>,
    pub last_transition: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanupViewV1 {
    pub schema: u16,
    pub kind: ObjectKind,
    pub object: ObjectRef,
    pub state: String,
    pub owner: Option<ObjectRef>,
    pub references: Vec<ContractEdge>,
    pub last_transition: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractViolationViewV1 {
    pub code: String,
    pub severity: String,
    pub subject: ObjectRef,
    pub relation: String,
    pub ref_mode: RefMode,
    pub expected_generation: Option<u64>,
    pub actual_generation: Option<u64>,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractValidationViewV1 {
    pub schema: u16,
    pub kind: &'static str,
    pub package_id: String,
    pub ok: bool,
    pub violation_count: usize,
    pub violations: Vec<ContractViolationViewV1>,
}

pub const RUNTIME_MODE_RESEARCH: &str = "research";
pub const RUNTIME_MODE_PRODUCTION: &str = "production";
pub const RUNTIME_MODE_REPLAY: &str = "replay";
pub const TARGET_ARTIFACT_FORMAT_V1: &str = "target-artifact-image-v1";
pub const CODE_PAYLOAD_FORMAT_CWASM: &str = SUPERVISOR_CODE_PAYLOAD_FORMAT;
pub const WASMTIME_CRATE_VERSION: &str = "43.0.1";
pub const WASMTIME_COMPILATION_STRATEGY: &str = "cranelift";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedArtifactPlan {
    pub artifact_profile: String,
    pub runtime_mode: String,
    pub contract_version: String,
    pub supervisor_world: String,
    pub target_arch: String,
    pub compiler_engine: String,
    pub compiler_execution_mode: String,
    pub artifact_format: String,
    pub target_artifact_format: String,
    pub runtime_executor_abi: String,
    pub modules: Vec<ValidatedArtifactEntry>,
}

impl ValidatedArtifactPlan {
    pub fn module_count(&self) -> usize {
        self.modules.len()
    }

    pub fn capability_count(&self) -> usize {
        self.modules
            .iter()
            .map(|entry| entry.capabilities.len())
            .sum()
    }

    pub fn expected_export_count(&self) -> usize {
        self.modules
            .iter()
            .map(|entry| entry.expected_exports.len())
            .sum()
    }

    pub fn entry(&self, package: &str) -> Option<&ValidatedArtifactEntry> {
        self.modules.iter().find(|entry| entry.package == package)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedArtifactEntry {
    pub package: String,
    pub artifact_name: String,
    pub role: String,
    pub fault_policy: String,
    pub wasm_path: String,
    pub cwasm_path: String,
    pub target_artifact_path: String,
    pub wasm_sha256: String,
    pub cwasm_sha256: String,
    pub target_artifact_sha256: String,
    pub code_payload_format: String,
    pub expected_exports: Vec<String>,
    pub capabilities: Vec<CapabilityManifest>,
    pub abi_fingerprint: String,
    pub service_dependencies: Vec<String>,
    pub resource_limits: ResourceLimitsManifest,
    pub interfaces: InterfaceRequirementManifest,
    pub signature_scheme: String,
    pub signer: String,
    pub manifest_binding_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubstrateCompatibilityItem {
    pub authority: String,
    pub expected: String,
    pub actual: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleSubstrateCompatibilityReport {
    pub package: String,
    pub substrate_profile_required: String,
    pub ok: bool,
    pub profile_ok: bool,
    pub authority_ok: bool,
    pub missing_required: Vec<SubstrateCompatibilityItem>,
    pub degraded_optional: Vec<SubstrateCompatibilityItem>,
    pub forbidden_requested: Vec<String>,
    pub forbidden_authorities: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactSubstrateCompatibilityReport {
    pub artifact_profile: String,
    pub module_count: usize,
    pub ok: bool,
    pub modules: Vec<ModuleSubstrateCompatibilityReport>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceHostCapabilitySet {
    pub wasi_worlds: Vec<String>,
    pub custom_wit_worlds: Vec<String>,
    pub component_model_version: String,
    pub wasi_profile: String,
    pub hostcall_abi_version: String,
    pub capability_abi_version: String,
    pub semantic_contract_version: String,
}

impl InterfaceHostCapabilitySet {
    pub fn empty() -> Self {
        Self {
            wasi_worlds: Vec::new(),
            custom_wit_worlds: Vec::new(),
            component_model_version: COMPONENT_MODEL_VERSION.to_owned(),
            wasi_profile: WASI_PROFILE_NONE.to_owned(),
            hostcall_abi_version: HOSTCALL_ABI_VERSION.to_owned(),
            capability_abi_version: CAPABILITY_ABI_VERSION.to_owned(),
            semantic_contract_version: SEMANTIC_CONTRACT_SCHEMA_VERSION.to_owned(),
        }
    }

    pub fn host_validation() -> Self {
        let mut capabilities = Self::empty();
        for module in SUPERVISOR_WASM_MODULES {
            let interfaces = module_interface_spec(module);
            for world in interfaces.required_wasi_worlds {
                push_unique(&mut capabilities.wasi_worlds, world);
            }
            for world in interfaces.optional_wasi_worlds {
                push_unique(&mut capabilities.wasi_worlds, world);
            }
            for world in interfaces.custom_wit_worlds {
                push_unique(&mut capabilities.custom_wit_worlds, world);
            }
        }
        capabilities
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceVersionMismatch {
    pub field: String,
    pub expected: String,
    pub actual: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleInterfaceCompatibilityReport {
    pub package: String,
    pub ok: bool,
    pub missing_required_wasi_worlds: Vec<String>,
    pub degraded_optional_wasi_worlds: Vec<String>,
    pub missing_custom_wit_worlds: Vec<String>,
    pub version_mismatches: Vec<InterfaceVersionMismatch>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactInterfaceCompatibilityReport {
    pub artifact_profile: String,
    pub module_count: usize,
    pub ok: bool,
    pub modules: Vec<ModuleInterfaceCompatibilityReport>,
}

pub fn contract_hex(value: u64) -> String {
    format!("{value:016x}")
}

pub fn expected_supervisor_contract() -> SupervisorContractManifest {
    SupervisorContractManifest {
        contract_version: SUPERVISOR_CONTRACT_VERSION.to_owned(),
        supervisor_world: SUPERVISOR_WORLD.to_owned(),
        catalog_fingerprint: contract_hex(catalog_contract_fingerprint()),
        package_set_fingerprint: contract_hex(package_set_fingerprint()),
        module_count: SUPERVISOR_WASM_MODULES.len(),
        required_packages: SUPERVISOR_WASM_MODULES
            .iter()
            .map(|module| module.package.to_owned())
            .collect(),
    }
}

pub fn validate_artifact_manifest(manifest: &ArtifactBundleManifest) -> ContractResult<()> {
    if manifest.schema_version != 1 {
        return Err(ContractError::new("unsupported manifest schema version"));
    }
    validate_runtime_mode(&manifest.runtime_mode)?;
    validate_supervisor_contract(manifest)?;
    if manifest.compiler.engine != SUPERVISOR_COMPILER_ENGINE {
        return Err(ContractError::new("manifest compiler engine mismatch"));
    }
    if manifest.compiler.artifact_format != SUPERVISOR_ARTIFACT_FORMAT {
        return Err(ContractError::new("manifest artifact format mismatch"));
    }
    if normalized_target_artifact_format(&manifest.compiler) != TARGET_ARTIFACT_FORMAT_V1 {
        return Err(ContractError::new(
            "manifest target artifact format mismatch",
        ));
    }
    if manifest.compiler.execution_mode != SUPERVISOR_EXECUTION_MODE {
        return Err(ContractError::new("manifest execution mode mismatch"));
    }
    if manifest.compiler.runtime_executor_abi != RUNTIME_ONLY_EXECUTOR_ABI {
        return Err(ContractError::new("manifest runtime executor ABI mismatch"));
    }
    if manifest.target.linux_abi_profile != LINUX_ABI_PROFILE {
        return Err(ContractError::new("manifest Linux ABI profile mismatch"));
    }
    if manifest.target.artifact_signature_profile != ARTIFACT_SIGNATURE_PROFILE {
        return Err(ContractError::new(
            "manifest artifact signature profile mismatch",
        ));
    }
    if manifest.target.machine_abi_version != MACHINE_ABI_VERSION {
        return Err(ContractError::new("manifest machine ABI mismatch"));
    }
    if manifest.target.supervisor_abi_version != SUPERVISOR_ABI_VERSION {
        return Err(ContractError::new("manifest supervisor ABI mismatch"));
    }
    if manifest.target.wasm_feature_profile != WASM_FEATURE_PROFILE {
        return Err(ContractError::new("manifest Wasm feature profile mismatch"));
    }
    if manifest.target.dmw_layout != DMW_LAYOUT {
        return Err(ContractError::new("manifest DMW layout mismatch"));
    }
    if manifest.target.network_contract_version != NETWORK_CONTRACT_VERSION {
        return Err(ContractError::new("manifest network contract mismatch"));
    }
    for spec in SUPERVISOR_WASM_MODULES {
        let entry = manifest_entry_for_spec(manifest, spec)?;
        validate_manifest_entry(spec, entry)?;
    }
    Ok(())
}

pub fn build_validated_artifact_plan(
    manifest: &ArtifactBundleManifest,
) -> ContractResult<ValidatedArtifactPlan> {
    validate_artifact_manifest(manifest)?;
    let modules = SUPERVISOR_WASM_MODULES
        .iter()
        .map(|spec| {
            let entry = manifest_entry_for_spec(manifest, spec)?;
            Ok(ValidatedArtifactEntry {
                package: entry.package.clone(),
                artifact_name: entry.artifact_name.clone(),
                role: entry.role.clone(),
                fault_policy: entry.fault_policy.clone(),
                wasm_path: entry.wasm_path.clone(),
                cwasm_path: entry.cwasm_path.clone(),
                target_artifact_path: entry.target_artifact_path.clone(),
                wasm_sha256: entry.wasm_sha256.clone(),
                cwasm_sha256: entry.cwasm_sha256.clone(),
                target_artifact_sha256: entry.target_artifact_sha256.clone(),
                code_payload_format: normalized_code_payload_format(entry).to_owned(),
                expected_exports: entry.expected_exports.clone(),
                capabilities: entry.capabilities.clone(),
                abi_fingerprint: entry.abi_fingerprint.clone(),
                service_dependencies: entry.service_dependencies.clone(),
                resource_limits: entry.resource_limits.clone(),
                interfaces: entry.interfaces.clone(),
                signature_scheme: entry.signature.scheme.clone(),
                signer: entry.signature.signer.clone(),
                manifest_binding_hash: entry.signature.manifest_binding_hash.clone(),
            })
        })
        .collect::<ContractResult<Vec<_>>>()?;

    Ok(ValidatedArtifactPlan {
        artifact_profile: manifest.artifact_profile.clone(),
        runtime_mode: normalized_runtime_mode(&manifest.runtime_mode).to_owned(),
        contract_version: manifest.contract.contract_version.clone(),
        supervisor_world: manifest.contract.supervisor_world.clone(),
        target_arch: manifest.target.arch.clone(),
        compiler_engine: manifest.compiler.engine.clone(),
        compiler_execution_mode: manifest.compiler.execution_mode.clone(),
        artifact_format: manifest.compiler.artifact_format.clone(),
        target_artifact_format: normalized_target_artifact_format(&manifest.compiler).to_owned(),
        runtime_executor_abi: manifest.compiler.runtime_executor_abi.clone(),
        modules,
    })
}

pub fn check_artifact_manifest_substrate_compatibility(
    manifest: &ArtifactBundleManifest,
    capabilities: SubstrateCapabilitySet,
) -> ContractResult<ArtifactSubstrateCompatibilityReport> {
    let plan = build_validated_artifact_plan(manifest)?;
    let modules = plan
        .modules
        .iter()
        .map(|module| check_module_substrate_compatibility(module, capabilities))
        .collect::<ContractResult<Vec<_>>>()?;
    let ok = modules.iter().all(|module| module.ok);
    Ok(ArtifactSubstrateCompatibilityReport {
        artifact_profile: plan.artifact_profile,
        module_count: modules.len(),
        ok,
        modules,
    })
}

pub fn check_artifact_manifest_interface_compatibility(
    manifest: &ArtifactBundleManifest,
    capabilities: &InterfaceHostCapabilitySet,
) -> ContractResult<ArtifactInterfaceCompatibilityReport> {
    let plan = build_validated_artifact_plan(manifest)?;
    let modules = plan
        .modules
        .iter()
        .map(|module| check_module_interface_compatibility(module, capabilities))
        .collect::<Vec<_>>();
    let ok = modules.iter().all(|module| module.ok);
    Ok(ArtifactInterfaceCompatibilityReport {
        artifact_profile: plan.artifact_profile,
        module_count: modules.len(),
        ok,
        modules,
    })
}

pub fn check_module_interface_compatibility(
    module: &ValidatedArtifactEntry,
    capabilities: &InterfaceHostCapabilitySet,
) -> ModuleInterfaceCompatibilityReport {
    let missing_required_wasi_worlds = missing_interfaces(
        &module.interfaces.required_wasi_worlds,
        &capabilities.wasi_worlds,
    );
    let degraded_optional_wasi_worlds = missing_interfaces(
        &module.interfaces.optional_wasi_worlds,
        &capabilities.wasi_worlds,
    );
    let missing_custom_wit_worlds = missing_interfaces(
        &module.interfaces.custom_wit_worlds,
        &capabilities.custom_wit_worlds,
    );
    let version_mismatches = interface_version_mismatches(module, capabilities);
    let ok = missing_required_wasi_worlds.is_empty()
        && missing_custom_wit_worlds.is_empty()
        && version_mismatches.is_empty();
    ModuleInterfaceCompatibilityReport {
        package: module.package.clone(),
        ok,
        missing_required_wasi_worlds,
        degraded_optional_wasi_worlds,
        missing_custom_wit_worlds,
        version_mismatches,
    }
}

pub fn check_module_substrate_compatibility(
    module: &ValidatedArtifactEntry,
    capabilities: SubstrateCapabilitySet,
) -> ContractResult<ModuleSubstrateCompatibilityReport> {
    let Some(profile) = SubstrateProfile::parse(&module.interfaces.substrate_profile_required)
    else {
        return Err(ContractError::new(format!(
            "{} unknown substrate profile {}",
            module.package, module.interfaces.substrate_profile_required
        )));
    };
    let profile_report = capabilities.check_profile(profile);
    let required = parse_authority_requirements(
        &module.package,
        "required",
        &module.interfaces.substrate_authorities.required,
    )?;
    let optional = parse_authority_requirements(
        &module.package,
        "optional",
        &module.interfaces.substrate_authorities.optional,
    )?;
    let authority_report = SubstrateAuthorityRequirements {
        required,
        optional,
        forbidden: AuthorityRequirementSet::default(),
    }
    .check(capabilities);
    let forbidden_requested = forbidden_requested_by_module(module);
    let missing_required = combine_missing(&profile_report, &authority_report);
    let degraded_optional =
        compatibility_items_from_mismatches(&authority_report.degraded_optional);
    let profile_ok = profile_report.ok;
    let authority_ok = authority_report.ok;
    Ok(ModuleSubstrateCompatibilityReport {
        package: module.package.clone(),
        substrate_profile_required: module.interfaces.substrate_profile_required.clone(),
        ok: profile_ok && authority_ok && forbidden_requested.is_empty(),
        profile_ok,
        authority_ok,
        missing_required,
        degraded_optional,
        forbidden_requested,
        forbidden_authorities: module.interfaces.substrate_authorities.forbidden.clone(),
    })
}

fn parse_authority_requirements(
    package: &str,
    list_name: &str,
    tokens: &[String],
) -> ContractResult<AuthorityRequirementSet> {
    AuthorityRequirementSet::from_tokens(tokens.iter().map(String::as_str)).map_err(|err| {
        ContractError::new(format!(
            "{package} has invalid {list_name} substrate authority token `{}`: {}",
            err.token, err.reason
        ))
    })
}

fn push_unique(values: &mut Vec<String>, value: &str) {
    if !values.iter().any(|existing| existing == value) {
        values.push(value.to_owned());
    }
}

fn missing_interfaces(required: &[String], available: &[String]) -> Vec<String> {
    required
        .iter()
        .filter(|required| !available.iter().any(|available| available == *required))
        .cloned()
        .collect()
}

fn interface_version_mismatches(
    module: &ValidatedArtifactEntry,
    capabilities: &InterfaceHostCapabilitySet,
) -> Vec<InterfaceVersionMismatch> {
    let interfaces = &module.interfaces;
    let mut mismatches = Vec::new();
    push_version_mismatch(
        &mut mismatches,
        "component_model_version",
        &interfaces.component_model_version,
        &capabilities.component_model_version,
    );
    push_version_mismatch(
        &mut mismatches,
        "wasi_profile",
        &interfaces.wasi_profile,
        &capabilities.wasi_profile,
    );
    push_version_mismatch(
        &mut mismatches,
        "hostcall_abi_version",
        &interfaces.hostcall_abi_version,
        &capabilities.hostcall_abi_version,
    );
    push_version_mismatch(
        &mut mismatches,
        "capability_abi_version",
        &interfaces.capability_abi_version,
        &capabilities.capability_abi_version,
    );
    push_version_mismatch(
        &mut mismatches,
        "semantic_contract_version",
        &interfaces.semantic_contract_version,
        &capabilities.semantic_contract_version,
    );
    mismatches
}

fn push_version_mismatch(
    mismatches: &mut Vec<InterfaceVersionMismatch>,
    field: &str,
    expected: &str,
    actual: &str,
) {
    if expected != actual {
        mismatches.push(InterfaceVersionMismatch {
            field: field.to_owned(),
            expected: expected.to_owned(),
            actual: actual.to_owned(),
        });
    }
}

fn forbidden_requested_by_module(module: &ValidatedArtifactEntry) -> Vec<String> {
    module
        .interfaces
        .substrate_authorities
        .forbidden
        .iter()
        .filter(|forbidden| {
            module
                .interfaces
                .substrate_authorities
                .required
                .iter()
                .any(|required| required == *forbidden)
                || module
                    .interfaces
                    .substrate_authorities
                    .optional
                    .iter()
                    .any(|optional| optional == *forbidden)
                || module.capabilities.iter().any(|capability| {
                    capability_matches_forbidden_authority(&capability.name, forbidden)
                })
        })
        .cloned()
        .collect()
}

fn capability_matches_forbidden_authority(capability: &str, forbidden: &str) -> bool {
    match forbidden {
        "direct-dma" => capability == "direct-dma" || capability.starts_with("dma."),
        "raw-mmio" => capability == "raw-mmio" || capability.starts_with("mmio."),
        "raw-irq" => capability == "raw-irq" || capability.starts_with("irq."),
        other => capability == other,
    }
}

fn combine_missing(
    profile_report: &SubstrateCompatibilityReport,
    authority_report: &SubstrateCompatibilityReport,
) -> Vec<SubstrateCompatibilityItem> {
    let mut out = compatibility_items_from_mismatches(&profile_report.missing_required);
    for item in compatibility_items_from_mismatches(&authority_report.missing_required) {
        if !out.iter().any(|existing| {
            existing.authority == item.authority
                && existing.expected == item.expected
                && existing.actual == item.actual
        }) {
            out.push(item);
        }
    }
    out
}

fn compatibility_items_from_mismatches(
    items: &[AuthorityMismatch],
) -> Vec<SubstrateCompatibilityItem> {
    items
        .iter()
        .map(|item| SubstrateCompatibilityItem {
            authority: item.authority.to_owned(),
            expected: item.required.to_owned(),
            actual: item.actual.to_owned(),
        })
        .collect()
}

pub fn manifest_entry_for_package<'a>(
    manifest: &'a ArtifactBundleManifest,
    package: &str,
) -> ContractResult<&'a ModuleArtifactManifest> {
    manifest
        .modules
        .iter()
        .find(|entry| entry.package == package)
        .ok_or_else(|| ContractError::new(format!("manifest is missing {package}")))
}

pub fn normalized_runtime_mode(mode: &str) -> &'static str {
    if mode.is_empty() {
        RUNTIME_MODE_RESEARCH
    } else if mode == RUNTIME_MODE_PRODUCTION {
        RUNTIME_MODE_PRODUCTION
    } else if mode == RUNTIME_MODE_REPLAY {
        RUNTIME_MODE_REPLAY
    } else {
        RUNTIME_MODE_RESEARCH
    }
}

pub fn normalized_target_artifact_format(compiler: &artifact_manifest::CompilerManifest) -> &str {
    if compiler.target_artifact_format.is_empty() {
        TARGET_ARTIFACT_FORMAT_V1
    } else {
        &compiler.target_artifact_format
    }
}

pub fn normalized_code_payload_format(entry: &ModuleArtifactManifest) -> &str {
    if entry.code_payload_format.is_empty() {
        CODE_PAYLOAD_FORMAT_CWASM
    } else {
        &entry.code_payload_format
    }
}

pub fn canonical_wasmtime_config_fingerprint(host_arch: &str, target_arch: &str) -> String {
    let canonical = format!(
        "engine={};engine_version={};host_arch={};target_arch={};strategy={};wasm_feature_profile={};memory64=false;multi_memory=false;component_model=false",
        SUPERVISOR_COMPILER_ENGINE,
        WASMTIME_CRATE_VERSION,
        host_arch,
        target_arch,
        WASMTIME_COMPILATION_STRATEGY,
        WASM_FEATURE_PROFILE,
    );
    hex::encode(Sha256::digest(canonical.as_bytes()))
}

fn manifest_entry_for_spec<'a>(
    manifest: &'a ArtifactBundleManifest,
    spec: &WasmModuleSpec,
) -> ContractResult<&'a ModuleArtifactManifest> {
    manifest_entry_for_package(manifest, spec.package)
}

fn validate_runtime_mode(mode: &str) -> ContractResult<()> {
    if mode.is_empty()
        || mode == RUNTIME_MODE_RESEARCH
        || mode == RUNTIME_MODE_PRODUCTION
        || mode == RUNTIME_MODE_REPLAY
    {
        return Ok(());
    }
    Err(ContractError::new("unsupported runtime mode"))
}

pub fn validate_supervisor_contract(manifest: &ArtifactBundleManifest) -> ContractResult<()> {
    let expected = expected_supervisor_contract();
    let contract = &manifest.contract;
    if contract.contract_version != expected.contract_version {
        return Err(ContractError::new("supervisor contract version mismatch"));
    }
    if contract.supervisor_world != expected.supervisor_world {
        return Err(ContractError::new("supervisor world mismatch"));
    }
    if contract.catalog_fingerprint != expected.catalog_fingerprint {
        return Err(ContractError::new(
            "supervisor catalog fingerprint mismatch",
        ));
    }
    if contract.package_set_fingerprint != expected.package_set_fingerprint {
        return Err(ContractError::new(
            "supervisor package set fingerprint mismatch",
        ));
    }
    if contract.module_count != SUPERVISOR_WASM_MODULES.len()
        || manifest.modules.len() != SUPERVISOR_WASM_MODULES.len()
        || contract.required_packages.len() != SUPERVISOR_WASM_MODULES.len()
    {
        return Err(ContractError::new("supervisor module count mismatch"));
    }
    for (index, spec) in SUPERVISOR_WASM_MODULES.iter().enumerate() {
        let Some(package) = contract.required_packages.get(index) else {
            return Err(ContractError::new("supervisor package order mismatch"));
        };
        if package != spec.package {
            return Err(ContractError::new("supervisor package order mismatch"));
        }
        let count = manifest
            .modules
            .iter()
            .filter(|entry| entry.package == spec.package)
            .count();
        if count != 1 {
            return Err(ContractError::new(format!(
                "manifest has invalid module count for {}",
                spec.package
            )));
        }
    }
    for entry in &manifest.modules {
        if !SUPERVISOR_WASM_MODULES
            .iter()
            .any(|spec| spec.package == entry.package)
        {
            return Err(ContractError::new(format!(
                "manifest contains unknown module {}",
                entry.package
            )));
        }
    }
    Ok(())
}

pub fn validate_manifest_entry(
    spec: &WasmModuleSpec,
    entry: &ModuleArtifactManifest,
) -> ContractResult<()> {
    if entry.artifact_name != spec.artifact_name {
        return Err(ContractError::new(format!(
            "{} artifact name mismatch",
            spec.package
        )));
    }
    if entry.role != spec.role.as_str() {
        return Err(ContractError::new(format!(
            "{} role mismatch",
            spec.package
        )));
    }
    if entry.fault_policy != spec.fault_policy.as_str() {
        return Err(ContractError::new(format!(
            "{} fault policy mismatch",
            spec.package
        )));
    }
    let expected_dependencies = module_dependencies(spec);
    if entry.service_dependencies.len() != expected_dependencies.len()
        || expected_dependencies.iter().any(|dependency| {
            !entry
                .service_dependencies
                .iter()
                .any(|entry| entry == dependency)
        })
    {
        return Err(ContractError::new(format!(
            "{} service dependency mismatch",
            spec.package
        )));
    }
    if entry.signature.scheme != ARTIFACT_SIGNATURE_PROFILE {
        return Err(ContractError::new(format!(
            "{} signature scheme mismatch",
            spec.package
        )));
    }
    if entry.abi_fingerprint != module_abi_fingerprint(spec) {
        return Err(ContractError::new(format!(
            "{} ABI fingerprint mismatch",
            spec.package
        )));
    }
    if normalized_code_payload_format(entry) != CODE_PAYLOAD_FORMAT_CWASM {
        return Err(ContractError::new(format!(
            "{} code payload format mismatch",
            spec.package
        )));
    }
    if entry.target_artifact_path.is_empty() || !entry.target_artifact_path.ends_with(".tart") {
        return Err(ContractError::new(format!(
            "{} target artifact path is not a TargetArtifactImage",
            spec.package
        )));
    }
    if entry.target_artifact_sha256.is_empty() {
        return Err(ContractError::new(format!(
            "{} target artifact hash is empty",
            spec.package
        )));
    }
    if entry.signature.artifact_hash != entry.target_artifact_sha256 {
        return Err(ContractError::new(format!(
            "{} signature artifact hash mismatch",
            spec.package
        )));
    }
    if entry.signature.public_key_hint.is_empty() || entry.signature.signature.is_empty() {
        return Err(ContractError::new(format!(
            "{} signature payload is incomplete",
            spec.package
        )));
    }
    let expected_binding = manifest_binding_hash(
        spec,
        &entry.wasm_sha256,
        &entry.cwasm_sha256,
        &entry.abi_fingerprint,
    );
    if entry.signature.manifest_binding_hash != expected_binding {
        return Err(ContractError::new(format!(
            "{} manifest binding hash mismatch",
            spec.package
        )));
    }
    if !entry.cwasm_path.ends_with(".cwasm") {
        return Err(ContractError::new(format!(
            "{} code payload path is not a cwasm module",
            spec.package
        )));
    }
    validate_capabilities(spec, entry)?;
    validate_interface_requirements(spec, entry)?;
    Ok(())
}

fn validate_interface_requirements(
    spec: &WasmModuleSpec,
    entry: &ModuleArtifactManifest,
) -> ContractResult<()> {
    let expected = module_interface_spec(spec);
    let interfaces = &entry.interfaces;
    validate_string_list(
        spec,
        "required WASI worlds",
        &interfaces.required_wasi_worlds,
        expected.required_wasi_worlds,
    )?;
    validate_string_list(
        spec,
        "optional WASI worlds",
        &interfaces.optional_wasi_worlds,
        expected.optional_wasi_worlds,
    )?;
    validate_string_list(
        spec,
        "custom WIT worlds",
        &interfaces.custom_wit_worlds,
        expected.custom_wit_worlds,
    )?;
    validate_string_list(
        spec,
        "WIT package versions",
        &interfaces.wit_package_versions,
        expected.wit_package_versions,
    )?;
    validate_string_list(
        spec,
        "required substrate authorities",
        &interfaces.substrate_authorities.required,
        expected.substrate_required,
    )?;
    validate_string_list(
        spec,
        "optional substrate authorities",
        &interfaces.substrate_authorities.optional,
        expected.substrate_optional,
    )?;
    validate_string_list(
        spec,
        "forbidden substrate authorities",
        &interfaces.substrate_authorities.forbidden,
        expected.substrate_forbidden,
    )?;
    validate_interface_field(
        spec,
        "component model version",
        &interfaces.component_model_version,
        expected.component_model_version,
    )?;
    validate_interface_field(
        spec,
        "WASI profile",
        &interfaces.wasi_profile,
        expected.wasi_profile,
    )?;
    validate_interface_field(
        spec,
        "hostcall ABI version",
        &interfaces.hostcall_abi_version,
        expected.hostcall_abi_version,
    )?;
    validate_interface_field(
        spec,
        "capability ABI version",
        &interfaces.capability_abi_version,
        expected.capability_abi_version,
    )?;
    validate_interface_field(
        spec,
        "semantic contract version",
        &interfaces.semantic_contract_version,
        expected.semantic_contract_version,
    )?;
    validate_interface_field(
        spec,
        "substrate profile",
        &interfaces.substrate_profile_required,
        expected.substrate_profile_required,
    )?;
    if interfaces.component_model_version != COMPONENT_MODEL_VERSION
        || interfaces.wasi_profile != WASI_PROFILE_NONE
        || interfaces.hostcall_abi_version != HOSTCALL_ABI_VERSION
        || interfaces.capability_abi_version != CAPABILITY_ABI_VERSION
        || interfaces.semantic_contract_version != SEMANTIC_CONTRACT_SCHEMA_VERSION
        || !interfaces
            .wit_package_versions
            .iter()
            .any(|entry| entry == WIT_PACKAGE_VERSION)
    {
        return Err(ContractError::new(format!(
            "{} interface ABI boundary mismatch",
            spec.package
        )));
    }
    Ok(())
}

fn validate_interface_field(
    spec: &WasmModuleSpec,
    label: &str,
    actual: &str,
    expected: &str,
) -> ContractResult<()> {
    if actual == expected {
        return Ok(());
    }
    Err(ContractError::new(format!(
        "{} {label} mismatch",
        spec.package
    )))
}

fn validate_string_list(
    spec: &WasmModuleSpec,
    label: &str,
    actual: &[String],
    expected: &[&str],
) -> ContractResult<()> {
    if actual.len() == expected.len()
        && expected
            .iter()
            .zip(actual.iter())
            .all(|(expected, actual)| actual == expected)
    {
        return Ok(());
    }
    Err(ContractError::new(format!(
        "{} {label} mismatch",
        spec.package
    )))
}

pub fn validate_migration_package(package: &MigrationPackageManifest) -> ContractResult<()> {
    if package.schema_version != 1 {
        return Err(ContractError::new(
            "unsupported semantic package schema version",
        ));
    }
    if package.package_format != "vmos-semantic-package-v1" {
        return Err(ContractError::new("unsupported semantic package format"));
    }
    if package.guest.canonical_isa != "riscv64" {
        return Err(ContractError::new("unsupported canonical guest ISA"));
    }
    if package.semantic.active_transaction_count != 0 {
        return Err(ContractError::new(
            "package contains active semantic transactions",
        ));
    }
    if package.logical_capabilities.len() != package.semantic.capability_count {
        return Err(ContractError::new("package capability list/count mismatch"));
    }
    for capability in &package.logical_capabilities {
        if capability.subject.is_empty()
            || capability.object.is_empty()
            || capability.rights.is_empty()
            || capability.generation == 0
        {
            return Err(ContractError::new(
                "package contains an invalid logical capability",
            ));
        }
    }
    validate_semantic_roots(package)?;
    Ok(())
}

pub fn validate_migration_against_manifest(
    package: &MigrationPackageManifest,
    manifest: &ArtifactBundleManifest,
) -> ContractResult<()> {
    validate_artifact_manifest(manifest)?;
    validate_migration_package(package)?;
    let required = &package.required_artifact_profile;
    if required.target_arch != "target-native" && required.target_arch != manifest.target.arch {
        return Err(ContractError::new(
            "package target arch is incompatible with manifest",
        ));
    }
    if required.machine_abi_version != manifest.target.machine_abi_version {
        return Err(ContractError::new("package machine ABI mismatch"));
    }
    if required.supervisor_abi_version != manifest.target.supervisor_abi_version {
        return Err(ContractError::new("package supervisor ABI mismatch"));
    }
    if required.wasm_feature_profile != manifest.target.wasm_feature_profile {
        return Err(ContractError::new("package Wasm feature profile mismatch"));
    }
    if required.memory64 != manifest.target.memory64
        || required.multi_memory != manifest.target.multi_memory
    {
        return Err(ContractError::new("package Wasm memory model mismatch"));
    }
    if required.dmw_layout != manifest.target.dmw_layout {
        return Err(ContractError::new("package DMW layout mismatch"));
    }
    if required.network_contract_version != manifest.target.network_contract_version {
        return Err(ContractError::new("package network contract mismatch"));
    }
    if required.compiler_engine != manifest.compiler.engine
        || required.compiler_execution_mode != manifest.compiler.execution_mode
        || required.artifact_format != manifest.compiler.artifact_format
        || required.runtime_executor_abi != manifest.compiler.runtime_executor_abi
    {
        return Err(ContractError::new(
            "package compiler/artifact mode mismatch",
        ));
    }
    if package.semantic.artifact_verification_count != 0
        && package.semantic.artifact_verification_count != manifest.modules.len()
    {
        return Err(ContractError::new(
            "package artifact verification count does not match manifest",
        ));
    }
    if package.semantic.store_activation_count != 0
        && package.semantic.store_activation_count != manifest.modules.len()
    {
        return Err(ContractError::new(
            "package store activation count does not match manifest",
        ));
    }
    Ok(())
}

pub fn validate_replay_quiescent(package: &MigrationPackageManifest) -> ContractResult<()> {
    validate_migration_package(package)?;
    if package.substrate_boundary.pending_dma_completions != 0
        || package.substrate_boundary.pending_network_inputs != 0
        || package.substrate_boundary.active_dmw_lease_count != 0
        || package.substrate_boundary.active_mmio_authority_count != 0
        || package.substrate_boundary.active_dma_authority_count != 0
        || package.substrate_boundary.active_irq_authority_count != 0
        || package
            .substrate_boundary
            .active_packet_device_authority_count
            != 0
        || package
            .substrate_boundary
            .active_virtio_queue_authority_count
            != 0
    {
        return Err(ContractError::new("package is not replay-quiescent"));
    }
    if package.substrate_boundary.background_copy_pages != 0 {
        return Err(ContractError::new(
            "package contains unfinished background COW copies",
        ));
    }
    Ok(())
}

pub fn validate_semantic_roots(package: &MigrationPackageManifest) -> ContractResult<()> {
    let roots = &package.semantic.roots;
    if roots.hart_roots.len() != package.semantic.hart_count
        || package.semantic.hart_records.len() != package.semantic.hart_count
    {
        return Err(ContractError::new("hart root/count mismatch"));
    }
    if roots.task_roots.len() != package.semantic.task_count {
        return Err(ContractError::new("task root/count mismatch"));
    }
    if package.semantic.task_records.len() != package.semantic.task_record_count {
        return Err(ContractError::new("task record count mismatch"));
    }
    if roots.task_record_roots.len() != package.semantic.task_record_count {
        return Err(ContractError::new("task record root/count mismatch"));
    }
    if roots.runtime_activation_roots.len() != package.semantic.runtime_activation_count
        || package.semantic.runtime_activation_records.len()
            != package.semantic.runtime_activation_count
    {
        return Err(ContractError::new("runtime activation root/count mismatch"));
    }
    if roots.runnable_queue_roots.len() != package.semantic.runnable_queue_count
        || package.semantic.runnable_queues.len() != package.semantic.runnable_queue_count
    {
        return Err(ContractError::new("runnable queue root/count mismatch"));
    }
    if roots.activation_context_roots.len() != package.semantic.activation_context_count
        || package.semantic.activation_contexts.len() != package.semantic.activation_context_count
    {
        return Err(ContractError::new("activation context root/count mismatch"));
    }
    if roots.saved_context_roots.len() != package.semantic.saved_context_count
        || package.semantic.saved_contexts.len() != package.semantic.saved_context_count
    {
        return Err(ContractError::new("saved context root/count mismatch"));
    }
    if roots.timer_interrupt_roots.len() != package.semantic.timer_interrupt_count
        || package.semantic.timer_interrupts.len() != package.semantic.timer_interrupt_count
    {
        return Err(ContractError::new("timer interrupt root/count mismatch"));
    }
    if roots.ipi_event_roots.len() != package.semantic.ipi_event_count
        || package.semantic.ipi_events.len() != package.semantic.ipi_event_count
    {
        return Err(ContractError::new("ipi event root/count mismatch"));
    }
    if roots.remote_preempt_roots.len() != package.semantic.remote_preempt_count
        || package.semantic.remote_preempts.len() != package.semantic.remote_preempt_count
    {
        return Err(ContractError::new("remote preempt root/count mismatch"));
    }
    if roots.remote_park_roots.len() != package.semantic.remote_park_count
        || package.semantic.remote_parks.len() != package.semantic.remote_park_count
    {
        return Err(ContractError::new("remote park root/count mismatch"));
    }
    if roots.preemption_roots.len() != package.semantic.preemption_count
        || package.semantic.preemptions.len() != package.semantic.preemption_count
    {
        return Err(ContractError::new("preemption root/count mismatch"));
    }
    if roots.scheduler_decision_roots.len() != package.semantic.scheduler_decision_count
        || package.semantic.scheduler_decisions.len() != package.semantic.scheduler_decision_count
    {
        return Err(ContractError::new("scheduler decision root/count mismatch"));
    }
    if roots.cross_hart_scheduler_decision_roots.len()
        != package.semantic.cross_hart_scheduler_decision_count
        || package.semantic.cross_hart_scheduler_decisions.len()
            != package.semantic.cross_hart_scheduler_decision_count
    {
        return Err(ContractError::new(
            "cross-hart scheduler decision root/count mismatch",
        ));
    }
    if roots.activation_migration_roots.len() != package.semantic.activation_migration_count
        || package.semantic.activation_migrations.len()
            != package.semantic.activation_migration_count
    {
        return Err(ContractError::new(
            "activation migration root/count mismatch",
        ));
    }
    if roots.smp_safe_point_roots.len() != package.semantic.smp_safe_point_count
        || package.semantic.smp_safe_points.len() != package.semantic.smp_safe_point_count
    {
        return Err(ContractError::new("smp safe point root/count mismatch"));
    }
    if roots.stop_the_world_rendezvous_roots.len()
        != package.semantic.stop_the_world_rendezvous_count
        || package.semantic.stop_the_world_rendezvous.len()
            != package.semantic.stop_the_world_rendezvous_count
    {
        return Err(ContractError::new(
            "stop-the-world rendezvous root/count mismatch",
        ));
    }
    if roots.smp_code_publish_barrier_roots.len() != package.semantic.smp_code_publish_barrier_count
        || package.semantic.smp_code_publish_barriers.len()
            != package.semantic.smp_code_publish_barrier_count
    {
        return Err(ContractError::new(
            "smp code publish barrier root/count mismatch",
        ));
    }
    if roots.smp_cleanup_quiescence_roots.len() != package.semantic.smp_cleanup_quiescence_count
        || package.semantic.smp_cleanup_quiescence.len()
            != package.semantic.smp_cleanup_quiescence_count
    {
        return Err(ContractError::new(
            "smp cleanup quiescence root/count mismatch",
        ));
    }
    if roots.smp_snapshot_barrier_roots.len() != package.semantic.smp_snapshot_barrier_count
        || package.semantic.smp_snapshot_barriers.len()
            != package.semantic.smp_snapshot_barrier_count
    {
        return Err(ContractError::new(
            "smp snapshot barrier root/count mismatch",
        ));
    }
    if roots.smp_stress_run_roots.len() != package.semantic.smp_stress_run_count
        || package.semantic.smp_stress_runs.len() != package.semantic.smp_stress_run_count
    {
        return Err(ContractError::new("smp stress run root/count mismatch"));
    }
    if roots.smp_scaling_benchmark_roots.len() != package.semantic.smp_scaling_benchmark_count
        || package.semantic.smp_scaling_benchmarks.len()
            != package.semantic.smp_scaling_benchmark_count
    {
        return Err(ContractError::new(
            "smp scaling benchmark root/count mismatch",
        ));
    }
    if roots.device_object_roots.len() != package.semantic.device_object_count
        || package.semantic.device_objects.len() != package.semantic.device_object_count
    {
        return Err(ContractError::new("device object root/count mismatch"));
    }
    if roots.queue_object_roots.len() != package.semantic.queue_object_count
        || package.semantic.queue_objects.len() != package.semantic.queue_object_count
    {
        return Err(ContractError::new("queue object root/count mismatch"));
    }
    if roots.descriptor_object_roots.len() != package.semantic.descriptor_object_count
        || package.semantic.descriptor_objects.len() != package.semantic.descriptor_object_count
    {
        return Err(ContractError::new("descriptor object root/count mismatch"));
    }
    if roots.dma_buffer_object_roots.len() != package.semantic.dma_buffer_object_count
        || package.semantic.dma_buffer_objects.len() != package.semantic.dma_buffer_object_count
    {
        return Err(ContractError::new("dma buffer object root/count mismatch"));
    }
    if roots.mmio_region_object_roots.len() != package.semantic.mmio_region_object_count
        || package.semantic.mmio_region_objects.len() != package.semantic.mmio_region_object_count
    {
        return Err(ContractError::new("mmio region object root/count mismatch"));
    }
    if roots.irq_line_object_roots.len() != package.semantic.irq_line_object_count
        || package.semantic.irq_line_objects.len() != package.semantic.irq_line_object_count
    {
        return Err(ContractError::new("irq line object root/count mismatch"));
    }
    if roots.activation_resume_roots.len() != package.semantic.activation_resume_count
        || package.semantic.activation_resumes.len() != package.semantic.activation_resume_count
    {
        return Err(ContractError::new("activation resume root/count mismatch"));
    }
    if roots.activation_wait_roots.len() != package.semantic.activation_wait_count
        || package.semantic.activation_waits.len() != package.semantic.activation_wait_count
    {
        return Err(ContractError::new("activation wait root/count mismatch"));
    }
    if roots.activation_cleanup_roots.len() != package.semantic.activation_cleanup_count
        || package.semantic.activation_cleanups.len() != package.semantic.activation_cleanup_count
    {
        return Err(ContractError::new("activation cleanup root/count mismatch"));
    }
    if roots.preemption_latency_roots.len() != package.semantic.preemption_latency_sample_count
        || package.semantic.preemption_latency_samples.len()
            != package.semantic.preemption_latency_sample_count
    {
        return Err(ContractError::new("preemption latency root/count mismatch"));
    }
    if roots.hart_event_attribution_roots.len() != package.semantic.hart_event_attribution_count
        || package.semantic.hart_event_attributions.len()
            != package.semantic.hart_event_attribution_count
    {
        return Err(ContractError::new(
            "hart event attribution root/count mismatch",
        ));
    }
    if roots.resource_roots.len() != package.semantic.resource_count {
        return Err(ContractError::new("resource root/count mismatch"));
    }
    if roots.authority_roots.len() != package.semantic.authority_count {
        return Err(ContractError::new("authority root/count mismatch"));
    }
    if package.semantic.active_authority_count > package.semantic.authority_count {
        return Err(ContractError::new(
            "active authority count exceeds authority count",
        ));
    }
    if roots.wait_roots.len() != package.semantic.wait_token_count {
        return Err(ContractError::new("wait root/count mismatch"));
    }
    if roots.store_roots.len() != package.semantic.store_count {
        return Err(ContractError::new("store root/count mismatch"));
    }
    if roots.capability_roots.len() != package.semantic.capability_count {
        return Err(ContractError::new("capability root/count mismatch"));
    }
    if roots.fast_path_roots.len() != package.semantic.fast_path_plan_count {
        return Err(ContractError::new("fastpath root/count mismatch"));
    }
    if roots.boundary_roots.len() != package.semantic.boundary_count {
        return Err(ContractError::new("boundary root/count mismatch"));
    }
    if roots.artifact_verification_roots.len() != package.semantic.artifact_verification_count {
        return Err(ContractError::new(
            "artifact verification root/count mismatch",
        ));
    }
    if roots.store_activation_roots.len() != package.semantic.store_activation_count {
        return Err(ContractError::new("store activation root/count mismatch"));
    }
    if roots.executor_transition_roots.len() != package.semantic.executor_transition_count {
        return Err(ContractError::new(
            "executor transition root/count mismatch",
        ));
    }
    if roots.target_artifact_roots.len() != package.semantic.target_artifact_count
        || package.semantic.target_artifacts.len() != package.semantic.target_artifact_count
    {
        return Err(ContractError::new("target artifact root/count mismatch"));
    }
    if roots.code_object_roots.len() != package.semantic.code_object_count
        || package.semantic.code_objects.len() != package.semantic.code_object_count
    {
        return Err(ContractError::new("code object root/count mismatch"));
    }
    if package.semantic.store_records.len() != package.semantic.store_record_count {
        return Err(ContractError::new("store record count mismatch"));
    }
    if roots.target_store_record_roots.len() != package.semantic.store_record_count {
        return Err(ContractError::new(
            "target store record root/count mismatch",
        ));
    }
    if package.semantic.capability_records.len() != package.semantic.capability_record_count {
        return Err(ContractError::new("capability record count mismatch"));
    }
    if roots.target_capability_record_roots.len() != package.semantic.capability_record_count {
        return Err(ContractError::new(
            "target capability record root/count mismatch",
        ));
    }
    if roots.activation_record_roots.len() != package.semantic.activation_record_count
        || package.semantic.activation_records.len() != package.semantic.activation_record_count
    {
        return Err(ContractError::new("activation record root/count mismatch"));
    }
    if roots.trap_roots.len() != package.semantic.trap_record_count
        || package.semantic.trap_records.len() != package.semantic.trap_record_count
    {
        return Err(ContractError::new("trap record root/count mismatch"));
    }
    if roots.hostcall_trace_roots.len() != package.semantic.hostcall_trace_count
        || package.semantic.hostcall_trace.len() != package.semantic.hostcall_trace_count
    {
        return Err(ContractError::new("hostcall trace root/count mismatch"));
    }
    if roots.migration_object_roots.len() != package.semantic.migration_object_count
        || package.semantic.migration_objects.len() != package.semantic.migration_object_count
    {
        return Err(ContractError::new("migration object root/count mismatch"));
    }
    if roots.cleanup_roots.len() != package.semantic.cleanup_transaction_count
        || package.semantic.cleanup_transactions.len() != package.semantic.cleanup_transaction_count
    {
        return Err(ContractError::new(
            "cleanup transaction root/count mismatch",
        ));
    }
    if roots.memory_policy_roots.len() != package.semantic.memory_policy_count
        || package.semantic.memory_policies.len() != package.semantic.memory_policy_count
    {
        return Err(ContractError::new("memory policy root/count mismatch"));
    }
    if roots.substrate_event_roots.len() != package.semantic.substrate_event_count
        || package.semantic.substrate_events.len() != package.semantic.substrate_event_count
    {
        return Err(ContractError::new("substrate event root/count mismatch"));
    }
    if roots.command_result_roots.len() != package.semantic.command_result_count
        || package.semantic.command_results.len() != package.semantic.command_result_count
    {
        return Err(ContractError::new("command result root/count mismatch"));
    }
    if roots.interface_event_roots.len() != package.semantic.interface_event_count
        || package.semantic.interface_events.len() != package.semantic.interface_event_count
    {
        return Err(ContractError::new("interface event root/count mismatch"));
    }
    if package.semantic.snapshot_validation.violations.len()
        != package.semantic.snapshot_validation_violation_count
    {
        return Err(ContractError::new(
            "snapshot validation violation count mismatch",
        ));
    }
    if package.semantic.replay_validation.violations.len()
        != package.semantic.replay_validation_violation_count
    {
        return Err(ContractError::new(
            "replay validation violation count mismatch",
        ));
    }
    if roots.event_log_tail.is_empty() && package.semantic.event_log_cursor != 0 {
        return Err(ContractError::new(
            "event log cursor is nonzero but package has no event tail",
        ));
    }
    Ok(())
}

pub fn manifest_binding_hash(
    spec: &WasmModuleSpec,
    wasm_sha256: &str,
    cwasm_sha256: &str,
    abi_fingerprint: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(spec.package.as_bytes());
    hasher.update(b"\0");
    hasher.update(spec.artifact_name.as_bytes());
    hasher.update(b"\0");
    hasher.update(spec.role.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(spec.fault_policy.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(wasm_sha256.as_bytes());
    hasher.update(b"\0");
    hasher.update(cwasm_sha256.as_bytes());
    hasher.update(b"\0");
    hasher.update(abi_fingerprint.as_bytes());
    for export in spec.expected_exports {
        hasher.update(b"\0");
        hasher.update(export.as_bytes());
    }
    hex::encode(hasher.finalize())
}

pub fn module_abi_fingerprint(spec: &WasmModuleSpec) -> String {
    let mut hasher = Sha256::new();
    hasher.update(spec.package.as_bytes());
    hasher.update(b"\0");
    hasher.update(spec.artifact_name.as_bytes());
    hasher.update(b"\0");
    hasher.update(spec.role.as_str().as_bytes());
    for export in spec.expected_exports {
        hasher.update(b"\0export:");
        hasher.update(export.as_bytes());
    }
    for capability in spec.capabilities {
        hasher.update(b"\0cap:");
        hasher.update(capability.name.as_bytes());
        hasher.update(b":");
        hasher.update(capability.lifetime.as_bytes());
        for right in capability.rights {
            hasher.update(b":");
            hasher.update(right.as_bytes());
        }
    }
    let interfaces = module_interface_spec(spec);
    hasher.update(b"\0component-model:");
    hasher.update(interfaces.component_model_version.as_bytes());
    hasher.update(b"\0wasi-profile:");
    hasher.update(interfaces.wasi_profile.as_bytes());
    hasher.update(b"\0hostcall-abi:");
    hasher.update(interfaces.hostcall_abi_version.as_bytes());
    hasher.update(b"\0capability-abi:");
    hasher.update(interfaces.capability_abi_version.as_bytes());
    hasher.update(b"\0semantic-contract:");
    hasher.update(interfaces.semantic_contract_version.as_bytes());
    hasher.update(b"\0substrate-profile:");
    hasher.update(interfaces.substrate_profile_required.as_bytes());
    for entry in interfaces.required_wasi_worlds {
        hasher.update(b"\0required-wasi:");
        hasher.update(entry.as_bytes());
    }
    for entry in interfaces.optional_wasi_worlds {
        hasher.update(b"\0optional-wasi:");
        hasher.update(entry.as_bytes());
    }
    for entry in interfaces.custom_wit_worlds {
        hasher.update(b"\0custom-wit:");
        hasher.update(entry.as_bytes());
    }
    for entry in interfaces.wit_package_versions {
        hasher.update(b"\0wit-package:");
        hasher.update(entry.as_bytes());
    }
    for entry in interfaces.substrate_required {
        hasher.update(b"\0substrate-required:");
        hasher.update(entry.as_bytes());
    }
    for entry in interfaces.substrate_optional {
        hasher.update(b"\0substrate-optional:");
        hasher.update(entry.as_bytes());
    }
    for entry in interfaces.substrate_forbidden {
        hasher.update(b"\0substrate-forbidden:");
        hasher.update(entry.as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn validate_capabilities(
    spec: &WasmModuleSpec,
    entry: &ModuleArtifactManifest,
) -> ContractResult<()> {
    if entry.capabilities.len() != spec.capabilities.len() {
        return Err(ContractError::new(format!(
            "{} capability count mismatch",
            spec.package
        )));
    }
    for capability in spec.capabilities {
        let Some(entry_capability) = entry
            .capabilities
            .iter()
            .find(|candidate| candidate.name == capability.name)
        else {
            return Err(ContractError::new(format!(
                "{} missing capability {}",
                spec.package, capability.name
            )));
        };
        if entry_capability.lifetime != capability.lifetime {
            return Err(ContractError::new(format!(
                "{} capability lifetime mismatch",
                spec.package
            )));
        }
        if entry_capability.rights != rights_vec(capability) {
            return Err(ContractError::new(format!(
                "{} capability rights mismatch",
                spec.package
            )));
        }
    }
    Ok(())
}

fn rights_vec(capability: &CapabilitySpec) -> Vec<String> {
    capability
        .rights
        .iter()
        .map(|right| (*right).to_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use artifact_manifest::{
        CommandResultManifest, CompilerManifest, ExternManifest, GuestStateManifest,
        InterfaceEventManifest, MigrationHostManifest, MigrationPackageManifest,
        MigrationTargetManifest, RequiredArtifactProfileManifest, RuntimeActivationRecordManifest,
        SemanticRootSetManifest, SemanticSnapshotManifest, SignatureManifest,
        SubstrateAuthorityRequirementManifest, SubstrateBoundaryManifest, SubstrateEventManifest,
        TargetManifest,
    };

    #[test]
    fn wasmtime_config_fingerprint_is_stable_and_arch_sensitive() {
        let host_fingerprint = canonical_wasmtime_config_fingerprint("x86_64", "x86_64");
        assert_eq!(host_fingerprint.len(), 64);
        assert_eq!(
            host_fingerprint,
            canonical_wasmtime_config_fingerprint("x86_64", "x86_64")
        );
        assert_ne!(
            host_fingerprint,
            canonical_wasmtime_config_fingerprint("x86_64", "riscv64")
        );
    }

    fn valid_manifest() -> ArtifactBundleManifest {
        let modules = SUPERVISOR_WASM_MODULES
            .iter()
            .map(|spec| {
                let wasm_sha256 = format!("{}-wasm", spec.package);
                let cwasm_sha256 = format!("{}-cwasm", spec.package);
                let target_artifact_sha256 = format!("{}-target-artifact", spec.package);
                let abi_fingerprint = module_abi_fingerprint(spec);
                let manifest_binding_hash =
                    manifest_binding_hash(spec, &wasm_sha256, &cwasm_sha256, &abi_fingerprint);
                ModuleArtifactManifest {
                    package: spec.package.to_owned(),
                    artifact_name: spec.artifact_name.to_owned(),
                    role: spec.role.as_str().to_owned(),
                    fault_policy: spec.fault_policy.as_str().to_owned(),
                    wasm_path: format!("target/test/{}.wasm", spec.package),
                    cwasm_path: format!("target/test/{}.cwasm", spec.package),
                    target_artifact_path: format!("target/test/{}.tart", spec.package),
                    wasm_sha256,
                    cwasm_sha256: cwasm_sha256.clone(),
                    target_artifact_sha256: target_artifact_sha256.clone(),
                    code_payload_format: CODE_PAYLOAD_FORMAT_CWASM.to_owned(),
                    expected_exports: spec
                        .expected_exports
                        .iter()
                        .map(|export| (*export).to_owned())
                        .collect(),
                    exports: spec
                        .expected_exports
                        .iter()
                        .map(|export| ExternManifest {
                            name: (*export).to_owned(),
                            kind: if *export == "memory" {
                                "memory"
                            } else {
                                "func"
                            }
                            .to_owned(),
                        })
                        .collect(),
                    imports: Vec::new(),
                    capabilities: spec
                        .capabilities
                        .iter()
                        .map(|capability| CapabilityManifest {
                            name: capability.name.to_owned(),
                            rights: capability
                                .rights
                                .iter()
                                .map(|right| (*right).to_owned())
                                .collect(),
                            lifetime: capability.lifetime.to_owned(),
                        })
                        .collect(),
                    abi_fingerprint,
                    service_dependencies: module_dependencies(spec)
                        .iter()
                        .map(|dependency| (*dependency).to_owned())
                        .collect(),
                    resource_limits: ResourceLimitsManifest {
                        max_memory_pages: 16,
                        max_table_elements: 0,
                        max_hostcalls_per_activation: 64,
                    },
                    interfaces: interface_manifest(spec),
                    signature: SignatureManifest {
                        scheme: ARTIFACT_SIGNATURE_PROFILE.to_owned(),
                        artifact_hash: target_artifact_sha256,
                        manifest_binding_hash,
                        signer: "test-signer".to_owned(),
                        public_key_hint: "test-key".to_owned(),
                        signature: "test-signature".to_owned(),
                    },
                }
            })
            .collect();

        ArtifactBundleManifest {
            schema_version: 1,
            artifact_profile: "host-validation".to_owned(),
            runtime_mode: RUNTIME_MODE_RESEARCH.to_owned(),
            contract: expected_supervisor_contract(),
            target: TargetManifest {
                arch: "x86_64".to_owned(),
                machine_abi_version: MACHINE_ABI_VERSION.to_owned(),
                supervisor_abi_version: SUPERVISOR_ABI_VERSION.to_owned(),
                wasm_feature_profile: WASM_FEATURE_PROFILE.to_owned(),
                memory64: false,
                multi_memory: false,
                dmw_layout: DMW_LAYOUT.to_owned(),
                linux_abi_profile: LINUX_ABI_PROFILE.to_owned(),
                artifact_signature_profile: ARTIFACT_SIGNATURE_PROFILE.to_owned(),
                network_contract_version: NETWORK_CONTRACT_VERSION.to_owned(),
            },
            compiler: CompilerManifest {
                engine: SUPERVISOR_COMPILER_ENGINE.to_owned(),
                engine_version: "test".to_owned(),
                execution_mode: SUPERVISOR_EXECUTION_MODE.to_owned(),
                artifact_format: SUPERVISOR_ARTIFACT_FORMAT.to_owned(),
                target_artifact_format: TARGET_ARTIFACT_FORMAT_V1.to_owned(),
                runtime_executor_abi: RUNTIME_ONLY_EXECUTOR_ABI.to_owned(),
            },
            modules,
        }
    }

    fn interface_manifest(spec: &WasmModuleSpec) -> InterfaceRequirementManifest {
        let interfaces = module_interface_spec(spec);
        InterfaceRequirementManifest {
            required_wasi_worlds: interfaces
                .required_wasi_worlds
                .iter()
                .map(|entry| (*entry).to_owned())
                .collect(),
            optional_wasi_worlds: interfaces
                .optional_wasi_worlds
                .iter()
                .map(|entry| (*entry).to_owned())
                .collect(),
            custom_wit_worlds: interfaces
                .custom_wit_worlds
                .iter()
                .map(|entry| (*entry).to_owned())
                .collect(),
            wit_package_versions: interfaces
                .wit_package_versions
                .iter()
                .map(|entry| (*entry).to_owned())
                .collect(),
            component_model_version: interfaces.component_model_version.to_owned(),
            wasi_profile: interfaces.wasi_profile.to_owned(),
            hostcall_abi_version: interfaces.hostcall_abi_version.to_owned(),
            capability_abi_version: interfaces.capability_abi_version.to_owned(),
            semantic_contract_version: interfaces.semantic_contract_version.to_owned(),
            substrate_profile_required: interfaces.substrate_profile_required.to_owned(),
            substrate_authorities: SubstrateAuthorityRequirementManifest {
                required: interfaces
                    .substrate_required
                    .iter()
                    .map(|entry| (*entry).to_owned())
                    .collect(),
                optional: interfaces
                    .substrate_optional
                    .iter()
                    .map(|entry| (*entry).to_owned())
                    .collect(),
                forbidden: interfaces
                    .substrate_forbidden
                    .iter()
                    .map(|entry| (*entry).to_owned())
                    .collect(),
            },
        }
    }

    fn minimal_migration_package() -> MigrationPackageManifest {
        MigrationPackageManifest {
            schema_version: 1,
            package_format: "vmos-semantic-package-v1".to_owned(),
            package_id: "contract-root-test".to_owned(),
            source: MigrationHostManifest {
                arch: "x86_64".to_owned(),
            },
            target: MigrationTargetManifest {
                arch_requirement: "target-native".to_owned(),
            },
            required_artifact_profile: RequiredArtifactProfileManifest {
                artifact_profile: "host-validation".to_owned(),
                target_arch: "target-native".to_owned(),
                machine_abi_version: MACHINE_ABI_VERSION.to_owned(),
                supervisor_abi_version: SUPERVISOR_ABI_VERSION.to_owned(),
                wasm_feature_profile: WASM_FEATURE_PROFILE.to_owned(),
                memory64: false,
                multi_memory: false,
                dmw_layout: DMW_LAYOUT.to_owned(),
                network_contract_version: NETWORK_CONTRACT_VERSION.to_owned(),
                compiler_engine: SUPERVISOR_COMPILER_ENGINE.to_owned(),
                compiler_execution_mode: SUPERVISOR_EXECUTION_MODE.to_owned(),
                artifact_format: SUPERVISOR_ARTIFACT_FORMAT.to_owned(),
                runtime_executor_abi: RUNTIME_ONLY_EXECUTOR_ABI.to_owned(),
            },
            guest: GuestStateManifest {
                canonical_isa: "riscv64".to_owned(),
                register_count: 33,
                memory_page_count: 0,
                vma_count: 0,
                signal_queue_count: 0,
                note: "root validation test".to_owned(),
            },
            semantic: SemanticSnapshotManifest {
                barrier_id: 1,
                event_log_cursor: 0,
                roots: SemanticRootSetManifest::default(),
                pending_wait_count: 0,
                hart_count: 0,
                task_count: 0,
                task_record_count: 0,
                runtime_activation_count: 0,
                runnable_queue_count: 0,
                activation_context_count: 0,
                saved_context_count: 0,
                timer_interrupt_count: 0,
                ipi_event_count: 0,
                remote_preempt_count: 0,
                remote_park_count: 0,
                preemption_count: 0,
                scheduler_decision_count: 0,
                cross_hart_scheduler_decision_count: 0,
                activation_migration_count: 0,
                smp_safe_point_count: 0,
                stop_the_world_rendezvous_count: 0,
                smp_code_publish_barrier_count: 0,
                smp_cleanup_quiescence_count: 0,
                smp_snapshot_barrier_count: 0,
                smp_stress_run_count: 0,
                smp_scaling_benchmark_count: 0,
                device_object_count: 0,
                queue_object_count: 0,
                descriptor_object_count: 0,
                dma_buffer_object_count: 0,
                mmio_region_object_count: 0,
                irq_line_object_count: 0,
                activation_resume_count: 0,
                activation_wait_count: 0,
                activation_cleanup_count: 0,
                preemption_latency_sample_count: 0,
                hart_event_attribution_count: 0,
                resource_count: 0,
                authority_count: 0,
                active_authority_count: 0,
                wait_token_count: 0,
                wait_record_count: 0,
                capability_count: 0,
                capability_record_count: 0,
                fault_domain_count: 0,
                store_count: 0,
                store_record_count: 0,
                transaction_count: 0,
                active_transaction_count: 0,
                fast_path_plan_count: 0,
                active_fast_path_plan_count: 0,
                boundary_count: 0,
                artifact_verification_count: 0,
                store_activation_count: 0,
                executor_transition_count: 0,
                target_artifact_count: 0,
                code_object_count: 0,
                activation_record_count: 0,
                trap_record_count: 0,
                hostcall_trace_count: 0,
                migration_object_count: 0,
                tombstone_count: 0,
                contract_violation_count: 0,
                cleanup_transaction_count: 0,
                memory_policy_count: 0,
                snapshot_validation_violation_count: 0,
                replay_validation_violation_count: 0,
                substrate_event_count: 0,
                command_result_count: 0,
                interface_event_count: 0,
                target_artifacts: Vec::new(),
                hart_records: Vec::new(),
                task_records: Vec::new(),
                runtime_activation_records: Vec::new(),
                runnable_queues: Vec::new(),
                activation_contexts: Vec::new(),
                saved_contexts: Vec::new(),
                timer_interrupts: Vec::new(),
                ipi_events: Vec::new(),
                remote_preempts: Vec::new(),
                remote_parks: Vec::new(),
                preemptions: Vec::new(),
                scheduler_decisions: Vec::new(),
                cross_hart_scheduler_decisions: Vec::new(),
                activation_migrations: Vec::new(),
                smp_safe_points: Vec::new(),
                stop_the_world_rendezvous: Vec::new(),
                smp_code_publish_barriers: Vec::new(),
                smp_cleanup_quiescence: Vec::new(),
                smp_snapshot_barriers: Vec::new(),
                smp_stress_runs: Vec::new(),
                smp_scaling_benchmarks: Vec::new(),
                device_objects: Vec::new(),
                queue_objects: Vec::new(),
                descriptor_objects: Vec::new(),
                dma_buffer_objects: Vec::new(),
                mmio_region_objects: Vec::new(),
                irq_line_objects: Vec::new(),
                activation_resumes: Vec::new(),
                activation_waits: Vec::new(),
                activation_cleanups: Vec::new(),
                preemption_latency_samples: Vec::new(),
                hart_event_attributions: Vec::new(),
                code_objects: Vec::new(),
                store_records: Vec::new(),
                capability_records: Vec::new(),
                wait_records: Vec::new(),
                activation_records: Vec::new(),
                trap_records: Vec::new(),
                hostcall_trace: Vec::new(),
                migration_objects: Vec::new(),
                tombstones: Vec::new(),
                contract_violations: Vec::new(),
                cleanup_transactions: Vec::new(),
                memory_policies: Vec::new(),
                snapshot_validation: Default::default(),
                replay_validation: Default::default(),
                substrate_events: Vec::new(),
                command_results: Vec::new(),
                interface_events: Vec::new(),
                network_socket_count: 0,
                network_rx_queue_bytes: 0,
            },
            logical_capabilities: Vec::new(),
            substrate_boundary: SubstrateBoundaryManifest {
                timer_epoch: 0,
                pending_irq_causes: 0,
                pending_dma_completions: 0,
                active_dmw_lease_count: 0,
                active_mmio_authority_count: 0,
                active_dma_authority_count: 0,
                active_irq_authority_count: 0,
                active_packet_device_authority_count: 0,
                active_virtio_queue_authority_count: 0,
                pending_network_inputs: 0,
                random_epoch: 0,
                scheduler_decision_cursor: 0,
                cow_epoch: 0,
                background_copy_pages: 0,
                native_state_policy: "test".to_owned(),
            },
            not_migrated: Vec::new(),
        }
    }

    #[test]
    fn validated_plan_preserves_manifest_order_and_totals() {
        let manifest = valid_manifest();
        let plan = build_validated_artifact_plan(&manifest).expect("valid plan");

        assert_eq!(plan.module_count(), SUPERVISOR_WASM_MODULES.len());
        assert_eq!(plan.runtime_mode, RUNTIME_MODE_RESEARCH);
        assert_eq!(plan.modules[0].package, SUPERVISOR_WASM_MODULES[0].package);
        assert_eq!(
            plan.modules[0].interfaces.semantic_contract_version,
            SEMANTIC_CONTRACT_SCHEMA_VERSION
        );
        assert_eq!(
            plan.modules[0].interfaces.hostcall_abi_version,
            HOSTCALL_ABI_VERSION
        );
        assert_eq!(
            plan.capability_count(),
            SUPERVISOR_WASM_MODULES
                .iter()
                .map(|spec| spec.capabilities.len())
                .sum()
        );
    }

    #[test]
    fn manifest_validation_rejects_bad_entry_binding() {
        let mut manifest = valid_manifest();
        manifest.modules[0].signature.manifest_binding_hash = "stale-binding".to_owned();

        let err = validate_artifact_manifest(&manifest).expect_err("bad binding must fail");
        assert!(err.to_string().contains("manifest binding hash mismatch"));
    }

    #[test]
    fn semantic_roots_reject_substrate_event_count_mismatch() {
        let mut package = minimal_migration_package();
        package
            .semantic
            .substrate_events
            .push(SubstrateEventManifest {
                id: 1,
                epoch: 7,
                event_kind: "unsupported".to_owned(),
                authority: "DmaAuthority".to_owned(),
                operation: "dma_alloc".to_owned(),
                requester: Some("test".to_owned()),
                artifact: None,
                store: None,
                capability: None,
                explanation: "unsupported probe".to_owned(),
            });
        package
            .semantic
            .roots
            .substrate_event_roots
            .push("substrate-event:unsupported:DmaAuthority:dma_alloc".to_owned());

        let err = validate_migration_package(&package).expect_err("count mismatch must fail");
        assert_eq!(err.to_string(), "substrate event root/count mismatch");
    }

    #[test]
    fn semantic_roots_reject_runtime_scheduler_root_mismatch() {
        let mut package = minimal_migration_package();
        package.semantic.runtime_activation_count = 1;
        package
            .semantic
            .runtime_activation_records
            .push(RuntimeActivationRecordManifest {
                id: 11,
                owner_task: 7,
                owner_task_generation: 1,
                owner_store: None,
                owner_store_generation: None,
                code_object: None,
                generation: 1,
                state: "runnable".to_owned(),
                runnable_queue: Some(1),
                runnable_queue_generation: Some(1),
                last_event: Some(3),
            });

        let err = validate_migration_package(&package).expect_err("root mismatch must fail");
        assert_eq!(err.to_string(), "runtime activation root/count mismatch");
    }

    #[test]
    fn semantic_roots_reject_activation_context_root_mismatch() {
        let mut package = minimal_migration_package();
        package.semantic.activation_context_count = 1;
        package
            .semantic
            .activation_contexts
            .push(artifact_manifest::ActivationContextManifest {
                id: 12,
                activation: 11,
                activation_generation: 2,
                owner_task: 7,
                owner_task_generation: 1,
                owner_store: None,
                owner_store_generation: None,
                generation: 1,
                state: "created".to_owned(),
                current_saved_context: None,
                current_saved_context_generation: None,
                last_event: Some(4),
            });

        let err = validate_migration_package(&package).expect_err("root mismatch must fail");
        assert_eq!(err.to_string(), "activation context root/count mismatch");
    }

    #[test]
    fn semantic_roots_reject_timer_interrupt_root_mismatch() {
        let mut package = minimal_migration_package();
        package.semantic.timer_interrupt_count = 1;
        package
            .semantic
            .timer_interrupts
            .push(artifact_manifest::TimerInterruptManifest {
                id: 3,
                timer_epoch: 1,
                hart: 1,
                hart_generation: Some(2),
                hardware_hart: Some(0),
                target_activation: Some(11),
                target_activation_generation: Some(2),
                target_task: Some(7),
                target_task_generation: Some(1),
                generation: 1,
                state: "recorded".to_owned(),
                recorded_at_event: 5,
                note: "test".to_owned(),
            });

        let err = validate_migration_package(&package).expect_err("root mismatch must fail");
        assert_eq!(err.to_string(), "timer interrupt root/count mismatch");
    }

    #[test]
    fn semantic_roots_reject_ipi_event_root_mismatch() {
        let mut package = minimal_migration_package();
        package.semantic.ipi_event_count = 1;
        package
            .semantic
            .ipi_events
            .push(artifact_manifest::IpiEventManifest {
                id: 4,
                source_hart: 1,
                source_hart_generation: 2,
                source_hardware_hart: 0,
                target_hart: 2,
                target_hart_generation: 2,
                target_hardware_hart: 1,
                kind: "scheduler-kick".to_owned(),
                generation: 1,
                state: "recorded".to_owned(),
                recorded_at_event: 5,
                reason: "test".to_owned(),
                note: "test".to_owned(),
            });

        let err = validate_migration_package(&package).expect_err("root mismatch must fail");
        assert_eq!(err.to_string(), "ipi event root/count mismatch");
    }

    #[test]
    fn semantic_roots_reject_remote_preempt_root_mismatch() {
        let mut package = minimal_migration_package();
        package.semantic.remote_preempt_count = 1;
        package
            .semantic
            .remote_preempts
            .push(artifact_manifest::RemotePreemptManifest {
                id: 4,
                ipi: 3,
                ipi_generation: 1,
                source_hart: 1,
                source_hart_generation: 2,
                target_hart: 2,
                target_hart_generation_before: 3,
                target_hart_generation_after: 4,
                activation: 11,
                activation_generation_before: 3,
                activation_generation_after: 4,
                queue: 2,
                queue_generation: 1,
                generation: 1,
                state: "applied".to_owned(),
                preempted_at_event: 6,
                note: "test".to_owned(),
            });

        let err = validate_migration_package(&package).expect_err("root mismatch must fail");
        assert_eq!(err.to_string(), "remote preempt root/count mismatch");
    }

    #[test]
    fn semantic_roots_reject_remote_park_root_mismatch() {
        let mut package = minimal_migration_package();
        package.semantic.remote_park_count = 1;
        package
            .semantic
            .remote_parks
            .push(artifact_manifest::RemoteParkManifest {
                id: 5,
                ipi: 3,
                ipi_generation: 1,
                source_hart: 1,
                source_hart_generation: 2,
                target_hart: 2,
                target_hart_generation_before: 3,
                target_hart_generation_after: 4,
                generation: 1,
                state: "parked".to_owned(),
                parked_at_event: 6,
                reason: "test".to_owned(),
                note: "test".to_owned(),
            });

        let err = validate_migration_package(&package).expect_err("root mismatch must fail");
        assert_eq!(err.to_string(), "remote park root/count mismatch");
    }

    #[test]
    fn semantic_roots_reject_preemption_root_mismatch() {
        let mut package = minimal_migration_package();
        package.semantic.preemption_count = 1;
        package
            .semantic
            .preemptions
            .push(artifact_manifest::PreemptionManifest {
                id: 4,
                activation: 11,
                activation_generation_before: 3,
                activation_generation_after: 4,
                timer_interrupt: 3,
                timer_interrupt_generation: 1,
                queue: 1,
                queue_generation: 1,
                generation: 1,
                state: "applied".to_owned(),
                preempted_at_event: 6,
                note: "test".to_owned(),
            });

        let err = validate_migration_package(&package).expect_err("root mismatch must fail");
        assert_eq!(err.to_string(), "preemption root/count mismatch");
    }

    #[test]
    fn semantic_roots_reject_scheduler_decision_root_mismatch() {
        let mut package = minimal_migration_package();
        package.semantic.scheduler_decision_count = 1;
        package
            .semantic
            .scheduler_decisions
            .push(artifact_manifest::SchedulerDecisionManifest {
                id: 5,
                queue: 1,
                queue_generation: 1,
                selected_activation: 11,
                selected_activation_generation: 4,
                owner_task: 7,
                owner_task_generation: 1,
                generation: 1,
                state: "recorded".to_owned(),
                decided_at_event: 7,
                reason: "runnable-available".to_owned(),
                note: "test".to_owned(),
            });

        let err = validate_migration_package(&package).expect_err("root mismatch must fail");
        assert_eq!(err.to_string(), "scheduler decision root/count mismatch");
    }

    #[test]
    fn semantic_roots_reject_cross_hart_scheduler_decision_root_mismatch() {
        let mut package = minimal_migration_package();
        package.semantic.cross_hart_scheduler_decision_count = 1;
        package.semantic.cross_hart_scheduler_decisions.push(
            artifact_manifest::CrossHartSchedulerDecisionManifest {
                id: 6,
                scheduler_decision: 5,
                scheduler_decision_generation: 1,
                deciding_hart: 1,
                deciding_hart_generation: 2,
                target_hart: 2,
                target_hart_generation: 4,
                queue: 1,
                queue_generation: 2,
                queue_owner_hart_generation: 2,
                selected_activation: 11,
                selected_activation_generation: 4,
                generation: 1,
                state: "recorded".to_owned(),
                decided_at_event: 8,
                reason: "remote-runnable".to_owned(),
                note: "test".to_owned(),
            },
        );

        let err = validate_migration_package(&package).expect_err("root mismatch must fail");
        assert_eq!(
            err.to_string(),
            "cross-hart scheduler decision root/count mismatch"
        );
    }

    #[test]
    fn semantic_roots_reject_activation_migration_root_mismatch() {
        let mut package = minimal_migration_package();
        package.semantic.activation_migration_count = 1;
        package.semantic.activation_migrations.push(
            artifact_manifest::ActivationMigrationManifest {
                id: 7,
                activation: 11,
                activation_generation_before: 4,
                activation_generation_after: 5,
                owner_task: 7,
                owner_task_generation: 1,
                source_hart: 2,
                source_hart_generation: 4,
                target_hart: 1,
                target_hart_generation: 2,
                source_queue: 2,
                source_queue_generation: 2,
                source_queue_owner_hart_generation: 2,
                target_queue: 3,
                target_queue_generation: 2,
                target_queue_owner_hart_generation: 2,
                generation: 1,
                state: "applied".to_owned(),
                migrated_at_event: 9,
                reason: "rebalance".to_owned(),
                note: "test".to_owned(),
            },
        );

        let err = validate_migration_package(&package).expect_err("root mismatch must fail");
        assert_eq!(err.to_string(), "activation migration root/count mismatch");
    }

    #[test]
    fn semantic_roots_reject_smp_safe_point_root_mismatch() {
        let mut package = minimal_migration_package();
        package.semantic.smp_safe_point_count = 1;
        package
            .semantic
            .smp_safe_points
            .push(artifact_manifest::SmpSafePointManifest {
                id: 8,
                coordinator_hart: 1,
                coordinator_hart_generation: 2,
                participants: vec![
                    artifact_manifest::SmpSafePointParticipantManifest {
                        hart: 1,
                        hart_generation: 2,
                        hardware_hart: 0,
                        hart_state: "idle".to_owned(),
                        current_activation: None,
                        current_activation_generation: None,
                    },
                    artifact_manifest::SmpSafePointParticipantManifest {
                        hart: 2,
                        hart_generation: 4,
                        hardware_hart: 1,
                        hart_state: "idle".to_owned(),
                        current_activation: None,
                        current_activation_generation: None,
                    },
                ],
                generation: 1,
                state: "recorded".to_owned(),
                recorded_at_event: 10,
                reason: "smp-safe-point".to_owned(),
                note: "test".to_owned(),
            });

        let err = validate_migration_package(&package).expect_err("root mismatch must fail");
        assert_eq!(err.to_string(), "smp safe point root/count mismatch");
    }

    #[test]
    fn semantic_roots_reject_stop_the_world_rendezvous_root_mismatch() {
        let mut package = minimal_migration_package();
        package.semantic.stop_the_world_rendezvous_count = 1;
        package.semantic.stop_the_world_rendezvous.push(
            artifact_manifest::StopTheWorldRendezvousManifest {
                id: 9,
                epoch: 1,
                safe_point: 8,
                safe_point_generation: 1,
                coordinator_hart: 1,
                coordinator_hart_generation: 2,
                participants: vec![
                    artifact_manifest::StopTheWorldRendezvousParticipantManifest {
                        hart: 1,
                        hart_generation: 2,
                        hardware_hart: 0,
                        hart_state: "idle".to_owned(),
                    },
                    artifact_manifest::StopTheWorldRendezvousParticipantManifest {
                        hart: 2,
                        hart_generation: 4,
                        hardware_hart: 1,
                        hart_state: "idle".to_owned(),
                    },
                ],
                stop_new_activations: true,
                generation: 1,
                state: "completed".to_owned(),
                completed_at_event: 11,
                reason: "stop-the-world".to_owned(),
                note: "test".to_owned(),
            },
        );

        let err = validate_migration_package(&package).expect_err("root mismatch must fail");
        assert_eq!(
            err.to_string(),
            "stop-the-world rendezvous root/count mismatch"
        );
    }

    #[test]
    fn semantic_roots_reject_smp_code_publish_barrier_root_mismatch() {
        let mut package = minimal_migration_package();
        package.semantic.smp_code_publish_barrier_count = 1;
        package.semantic.smp_code_publish_barriers.push(
            artifact_manifest::SmpCodePublishBarrierManifest {
                id: 10,
                rendezvous: 9,
                rendezvous_generation: 1,
                rendezvous_epoch: 1,
                code_publish_epoch_before: 0,
                code_publish_epoch_after: 1,
                participants: vec![
                    artifact_manifest::SmpCodePublishBarrierParticipantManifest {
                        hart: 1,
                        hart_generation: 2,
                        hardware_hart: 0,
                        last_seen_code_epoch_before: 0,
                        last_seen_code_epoch_after: 1,
                        semantic_icache_sync: true,
                    },
                    artifact_manifest::SmpCodePublishBarrierParticipantManifest {
                        hart: 2,
                        hart_generation: 4,
                        hardware_hart: 1,
                        last_seen_code_epoch_before: 0,
                        last_seen_code_epoch_after: 1,
                        semantic_icache_sync: true,
                    },
                ],
                remote_icache_sync_required: true,
                code_publish_executed: false,
                generation: 1,
                state: "validated".to_owned(),
                validated_at_event: 12,
                reason: "smp-code-publish-barrier".to_owned(),
                note: "test".to_owned(),
            },
        );

        let err = validate_migration_package(&package).expect_err("root mismatch must fail");
        assert_eq!(
            err.to_string(),
            "smp code publish barrier root/count mismatch"
        );
    }

    #[test]
    fn semantic_roots_reject_smp_cleanup_quiescence_root_mismatch() {
        let mut package = minimal_migration_package();
        package.semantic.smp_cleanup_quiescence_count = 1;
        package.semantic.smp_cleanup_quiescence.push(
            artifact_manifest::SmpCleanupQuiescenceManifest {
                id: 11,
                cleanup: 10,
                cleanup_generation: 1,
                store: 7,
                target_store_generation: 2,
                result_store_generation: 4,
                activation: 12,
                activation_generation_after: 5,
                rendezvous: 9,
                rendezvous_generation: 1,
                rendezvous_epoch: 2,
                participants: vec![
                    artifact_manifest::SmpCleanupQuiescenceParticipantManifest {
                        hart: 1,
                        hart_generation: 4,
                        hardware_hart: 0,
                        hart_state: "idle".to_owned(),
                        current_activation: None,
                        current_activation_generation: None,
                        current_store: None,
                        current_store_generation: None,
                        quiesced: true,
                    },
                    artifact_manifest::SmpCleanupQuiescenceParticipantManifest {
                        hart: 2,
                        hart_generation: 5,
                        hardware_hart: 1,
                        hart_state: "parked".to_owned(),
                        current_activation: None,
                        current_activation_generation: None,
                        current_store: None,
                        current_store_generation: None,
                        quiesced: true,
                    },
                ],
                no_running_activation: true,
                no_pending_wait: true,
                no_live_capability: true,
                no_live_resource: true,
                generation: 1,
                state: "validated".to_owned(),
                validated_at_event: 13,
                reason: "smp-cleanup-quiescence".to_owned(),
                note: "test".to_owned(),
            },
        );

        let err = validate_migration_package(&package).expect_err("root mismatch must fail");
        assert_eq!(
            err.to_string(),
            "smp cleanup quiescence root/count mismatch"
        );
    }

    #[test]
    fn semantic_roots_reject_smp_snapshot_barrier_root_mismatch() {
        let mut package = minimal_migration_package();
        package.semantic.smp_snapshot_barrier_count = 1;
        package.semantic.smp_snapshot_barriers.push(
            artifact_manifest::SmpSnapshotBarrierManifest {
                id: 12,
                rendezvous: 9,
                rendezvous_generation: 1,
                rendezvous_epoch: 3,
                event_log_cursor: 42,
                participants: vec![
                    artifact_manifest::SmpSnapshotBarrierParticipantManifest {
                        hart: 1,
                        hart_generation: 4,
                        hardware_hart: 0,
                        hart_state: "idle".to_owned(),
                        event_log_cursor_observed: 42,
                        snapshot_safe: true,
                    },
                    artifact_manifest::SmpSnapshotBarrierParticipantManifest {
                        hart: 2,
                        hart_generation: 5,
                        hardware_hart: 1,
                        hart_state: "parked".to_owned(),
                        event_log_cursor_observed: 42,
                        snapshot_safe: true,
                    },
                ],
                pending_wait_count: 0,
                active_transaction_count: 0,
                active_dmw_lease_count: 0,
                active_nonconvertible_activation_count: 0,
                in_flight_dma_count: 0,
                unsealed_event_log: false,
                unflushed_trap_record_count: 0,
                pending_cleanup_count: 0,
                native_activation_stack_live: false,
                raw_dma_binding_count: 0,
                raw_mmio_binding_count: 0,
                snapshot_validation_ok: true,
                generation: 1,
                state: "validated".to_owned(),
                validated_at_event: 43,
                reason: "smp-snapshot-barrier".to_owned(),
                note: "test".to_owned(),
            },
        );

        let err = validate_migration_package(&package).expect_err("root mismatch must fail");
        assert_eq!(err.to_string(), "smp snapshot barrier root/count mismatch");
    }

    #[test]
    fn semantic_roots_reject_smp_stress_run_root_mismatch() {
        let mut package = minimal_migration_package();
        package.semantic.smp_stress_run_count = 1;
        package
            .semantic
            .smp_stress_runs
            .push(artifact_manifest::SmpStressRunManifest {
                id: 15,
                scenario: "smp-stress".to_owned(),
                iterations: 3,
                hart_count: 2,
                event_log_cursor: 50,
                observed_safe_point_count: 3,
                observed_rendezvous_count: 3,
                observed_code_publish_barrier_count: 1,
                observed_cleanup_quiescence_count: 1,
                observed_snapshot_barrier_count: 1,
                observed_activation_migration_count: 1,
                observed_remote_preempt_count: 1,
                observed_remote_park_count: 1,
                invariant_checks: 3,
                property_failures: 0,
                last_safe_point: 3,
                last_safe_point_generation: 1,
                last_rendezvous: 3,
                last_rendezvous_generation: 1,
                last_code_publish_barrier: 1,
                last_code_publish_barrier_generation: 1,
                last_cleanup_quiescence: 1,
                last_cleanup_quiescence_generation: 1,
                last_snapshot_barrier: 1,
                last_snapshot_barrier_generation: 1,
                last_activation_migration: 1,
                last_activation_migration_generation: 1,
                last_remote_preempt: 1,
                last_remote_preempt_generation: 1,
                last_remote_park: 1,
                last_remote_park_generation: 1,
                generation: 1,
                state: "recorded".to_owned(),
                recorded_at_event: 51,
                reason: "smp-stress-property".to_owned(),
                note: "test".to_owned(),
            });

        let err = validate_migration_package(&package).expect_err("root mismatch must fail");
        assert_eq!(err.to_string(), "smp stress run root/count mismatch");
    }

    #[test]
    fn semantic_roots_reject_smp_scaling_benchmark_root_mismatch() {
        let mut package = minimal_migration_package();
        package.semantic.smp_scaling_benchmark_count = 1;
        package.semantic.smp_scaling_benchmarks.push(
            artifact_manifest::SmpScalingBenchmarkManifest {
                id: 16,
                scenario: "smp-scaling".to_owned(),
                stress_run: 15,
                stress_run_generation: 1,
                hart_count: 2,
                workload_units: 6,
                baseline_single_hart_nanos: 120_000,
                measured_smp_nanos: 72_000,
                budget_nanos: 90_000,
                speedup_milli: 1_666,
                efficiency_milli: 833,
                event_log_cursor: 51,
                stress_safe_point_count: 3,
                stress_rendezvous_count: 3,
                stress_property_failures: 0,
                generation: 1,
                state: "recorded".to_owned(),
                recorded_at_event: 52,
                note: "test".to_owned(),
            },
        );

        let err = validate_migration_package(&package).expect_err("root mismatch must fail");
        assert_eq!(err.to_string(), "smp scaling benchmark root/count mismatch");
    }

    #[test]
    fn semantic_roots_reject_device_object_root_mismatch() {
        let mut package = minimal_migration_package();
        package.semantic.device_object_count = 1;
        package
            .semantic
            .device_objects
            .push(artifact_manifest::DeviceObjectManifest {
                id: 17,
                name: "fake-io0".to_owned(),
                class: "fake-device".to_owned(),
                resource: 3,
                resource_generation: 1,
                backend: "fake-io-backend".to_owned(),
                bus: "semantic-harness".to_owned(),
                vendor: "vmos".to_owned(),
                model: "fake-io-v1".to_owned(),
                generation: 1,
                state: "registered".to_owned(),
                recorded_at_event: 53,
                note: "test".to_owned(),
            });

        let err = validate_migration_package(&package).expect_err("root mismatch must fail");
        assert_eq!(err.to_string(), "device object root/count mismatch");
    }

    #[test]
    fn semantic_roots_reject_queue_object_root_mismatch() {
        let mut package = minimal_migration_package();
        package.semantic.queue_object_count = 1;
        package
            .semantic
            .queue_objects
            .push(artifact_manifest::QueueObjectManifest {
                id: 18,
                name: "fake-io0-rx".to_owned(),
                role: "rx".to_owned(),
                queue_index: 0,
                depth: 64,
                device: 17,
                device_generation: 1,
                generation: 1,
                state: "registered".to_owned(),
                recorded_at_event: 54,
                note: "test".to_owned(),
            });

        let err = validate_migration_package(&package).expect_err("root mismatch must fail");
        assert_eq!(err.to_string(), "queue object root/count mismatch");
    }

    #[test]
    fn semantic_roots_reject_descriptor_object_root_mismatch() {
        let mut package = minimal_migration_package();
        package.semantic.descriptor_object_count = 1;
        package
            .semantic
            .descriptor_objects
            .push(artifact_manifest::DescriptorObjectManifest {
                id: 19,
                queue: 18,
                queue_generation: 1,
                slot: 0,
                access: "read-write".to_owned(),
                length: 2048,
                generation: 1,
                state: "registered".to_owned(),
                recorded_at_event: 55,
                note: "test".to_owned(),
            });

        let err = validate_migration_package(&package).expect_err("root mismatch must fail");
        assert_eq!(err.to_string(), "descriptor object root/count mismatch");
    }

    #[test]
    fn semantic_roots_reject_dma_buffer_object_root_mismatch() {
        let mut package = minimal_migration_package();
        package.semantic.dma_buffer_object_count = 1;
        package
            .semantic
            .dma_buffer_objects
            .push(artifact_manifest::DmaBufferObjectManifest {
                id: 20,
                descriptor: 19,
                descriptor_generation: 1,
                resource: 21,
                resource_generation: 1,
                access: "read-write".to_owned(),
                length: 2048,
                generation: 1,
                state: "registered".to_owned(),
                recorded_at_event: 56,
                note: "test".to_owned(),
            });

        let err = validate_migration_package(&package).expect_err("root mismatch must fail");
        assert_eq!(err.to_string(), "dma buffer object root/count mismatch");
    }

    #[test]
    fn semantic_roots_reject_mmio_region_object_root_mismatch() {
        let mut package = minimal_migration_package();
        package.semantic.mmio_region_object_count = 1;
        package
            .semantic
            .mmio_region_objects
            .push(artifact_manifest::MmioRegionObjectManifest {
                id: 21,
                device: 17,
                device_generation: 1,
                resource: 22,
                resource_generation: 1,
                region_index: 0,
                offset: 0x1000,
                length: 0x100,
                access: "read-write".to_owned(),
                generation: 1,
                state: "registered".to_owned(),
                recorded_at_event: 57,
                note: "test".to_owned(),
            });

        let err = validate_migration_package(&package).expect_err("root mismatch must fail");
        assert_eq!(err.to_string(), "mmio region object root/count mismatch");
    }

    #[test]
    fn semantic_roots_reject_irq_line_object_root_mismatch() {
        let mut package = minimal_migration_package();
        package.semantic.irq_line_object_count = 1;
        package
            .semantic
            .irq_line_objects
            .push(artifact_manifest::IrqLineObjectManifest {
                id: 22,
                device: 17,
                device_generation: 1,
                resource: 23,
                resource_generation: 1,
                irq_number: 5,
                trigger: "level".to_owned(),
                polarity: "active-high".to_owned(),
                generation: 1,
                state: "registered".to_owned(),
                recorded_at_event: 58,
                note: "test".to_owned(),
            });

        let err = validate_migration_package(&package).expect_err("root mismatch must fail");
        assert_eq!(err.to_string(), "irq line object root/count mismatch");
    }

    #[test]
    fn semantic_roots_reject_activation_resume_root_mismatch() {
        let mut package = minimal_migration_package();
        package.semantic.activation_resume_count = 1;
        package
            .semantic
            .activation_resumes
            .push(artifact_manifest::ActivationResumeManifest {
                id: 6,
                scheduler_decision: 5,
                scheduler_decision_generation: 1,
                activation: 11,
                activation_generation_before: 4,
                activation_generation_after: 5,
                owner_task: 7,
                owner_task_generation: 1,
                queue: 1,
                queue_generation: 1,
                context: None,
                context_generation_before: None,
                context_generation_after: None,
                saved_context: None,
                saved_context_generation: None,
                generation: 1,
                state: "applied".to_owned(),
                resumed_at_event: 8,
                note: "test".to_owned(),
            });

        let err = validate_migration_package(&package).expect_err("root mismatch must fail");
        assert_eq!(err.to_string(), "activation resume root/count mismatch");
    }

    #[test]
    fn semantic_roots_reject_activation_wait_root_mismatch() {
        let mut package = minimal_migration_package();
        package.semantic.activation_wait_count = 1;
        package
            .semantic
            .activation_waits
            .push(artifact_manifest::ActivationWaitManifest {
                id: 9,
                activation: 11,
                activation_generation_before: 5,
                activation_generation_after_block: 6,
                activation_generation_after_cancel: None,
                wait: 41,
                wait_generation: 1,
                owner_task: 7,
                owner_task_generation: 2,
                queue: None,
                queue_generation: None,
                generation: 1,
                state: "pending".to_owned(),
                blocked_at_event: 8,
                completed_at_event: None,
                cancel_reason: None,
                note: "test".to_owned(),
            });

        let err = validate_migration_package(&package).expect_err("root mismatch must fail");
        assert_eq!(err.to_string(), "activation wait root/count mismatch");
    }

    #[test]
    fn semantic_roots_reject_activation_cleanup_root_mismatch() {
        let mut package = minimal_migration_package();
        package.semantic.activation_cleanup_count = 1;
        package
            .semantic
            .activation_cleanups
            .push(artifact_manifest::ActivationCleanupManifest {
                id: 10,
                store: 7,
                target_store_generation: 2,
                result_store_generation: 4,
                activation: 11,
                activation_generation_before: 5,
                activation_generation_after: 6,
                wait: Some(41),
                wait_generation: Some(1),
                owner_task: 9,
                owner_task_generation_before: 2,
                owner_task_generation_after: 3,
                generation: 1,
                state: "completed".to_owned(),
                reason: "store-fault".to_owned(),
                started_at_event: 8,
                completed_at_event: 9,
                steps: Vec::new(),
                note: "test".to_owned(),
            });

        let err = validate_migration_package(&package).expect_err("root mismatch must fail");
        assert_eq!(err.to_string(), "activation cleanup root/count mismatch");
    }

    #[test]
    fn semantic_roots_reject_preemption_latency_root_mismatch() {
        let mut package = minimal_migration_package();
        package.semantic.preemption_latency_sample_count = 1;
        package.semantic.preemption_latency_samples.push(
            artifact_manifest::PreemptionLatencySampleManifest {
                id: 11,
                timer_interrupt: 5,
                timer_interrupt_generation: 1,
                preemption: 6,
                preemption_generation: 1,
                scheduler_decision: 7,
                scheduler_decision_generation: 1,
                activation_resume: 8,
                activation_resume_generation: 1,
                activation: 12,
                activation_generation_before: 3,
                activation_generation_after: 5,
                queue: 2,
                queue_generation: 1,
                interrupt_recorded_at_event: 10,
                preempted_at_event: 11,
                decided_at_event: 12,
                resumed_at_event: 13,
                interrupt_to_preempt_events: 1,
                preempt_to_decision_events: 1,
                decision_to_resume_events: 1,
                interrupt_to_resume_events: 3,
                measured_nanos: 500,
                budget_nanos: 50_000,
                generation: 1,
                state: "recorded".to_owned(),
                recorded_at_event: 14,
                note: "test".to_owned(),
            },
        );

        let err = validate_migration_package(&package).expect_err("root mismatch must fail");
        assert_eq!(err.to_string(), "preemption latency root/count mismatch");
    }

    #[test]
    fn semantic_roots_reject_hart_event_attribution_root_mismatch() {
        let mut package = minimal_migration_package();
        package.semantic.hart_event_attribution_count = 1;
        package.semantic.hart_event_attributions.push(
            artifact_manifest::HartEventAttributionManifest {
                id: 12,
                hart: 1,
                hart_generation: 2,
                hardware_hart: 0,
                event: 10,
                event_source: "timer".to_owned(),
                event_kind: "TimerInterruptRecorded".to_owned(),
                activation: Some(11),
                activation_generation: Some(3),
                task: Some(7),
                task_generation: Some(1),
                store: None,
                store_generation: None,
                generation: 1,
                state: "recorded".to_owned(),
                note: "test".to_owned(),
            },
        );

        let err = validate_migration_package(&package).expect_err("root mismatch must fail");
        assert_eq!(
            err.to_string(),
            "hart event attribution root/count mismatch"
        );
    }

    #[test]
    fn semantic_roots_reject_hart_root_mismatch() {
        let mut package = minimal_migration_package();
        package.semantic.hart_count = 1;
        package
            .semantic
            .hart_records
            .push(artifact_manifest::HartRecordManifest {
                id: 1,
                hardware_id: 0,
                label: "boot-hart0".to_owned(),
                state: "idle".to_owned(),
                generation: 2,
                boot: true,
                current_activation: None,
                current_activation_generation: None,
                current_task: None,
                current_task_generation: None,
                current_store: None,
                current_store_generation: None,
                last_event: Some(2),
                last_current_event: None,
                note: "test".to_owned(),
            });

        let err = validate_migration_package(&package).expect_err("root mismatch must fail");
        assert_eq!(err.to_string(), "hart root/count mismatch");
    }

    #[test]
    fn semantic_roots_reject_command_result_root_mismatch() {
        let mut package = minimal_migration_package();
        package.semantic.command_result_count = 1;
        package
            .semantic
            .command_results
            .push(CommandResultManifest {
                id: 1,
                issuer: "contract-test".to_owned(),
                command: "create-wait".to_owned(),
                status: "rejected".to_owned(),
                events: Vec::new(),
                effects: Vec::new(),
                violations: vec!["missing owner".to_owned()],
            });

        let err = validate_migration_package(&package).expect_err("root mismatch must fail");
        assert_eq!(err.to_string(), "command result root/count mismatch");
    }

    #[test]
    fn semantic_roots_reject_interface_event_count_mismatch() {
        let mut package = minimal_migration_package();
        package.semantic.interface_event_count = 1;
        package
            .semantic
            .interface_events
            .push(InterfaceEventManifest {
                id: 1,
                epoch: 9,
                interface_kind: "standard-wasi".to_owned(),
                interface: "wasi:clocks/monotonic-clock".to_owned(),
                operation: "subscribe".to_owned(),
                requester: Some("contract-test".to_owned()),
                artifact: None,
                store: None,
                explanation: "unsupported interface".to_owned(),
            });
        package
            .semantic
            .roots
            .interface_event_roots
            .push("interface-event:standard-wasi:wasi:clocks/monotonic-clock:subscribe".to_owned());
        package.semantic.interface_events.clear();

        let err = validate_migration_package(&package).expect_err("vector mismatch must fail");
        assert_eq!(err.to_string(), "interface event root/count mismatch");
    }

    #[test]
    fn substrate_compatibility_accepts_host_validation_capabilities() {
        let manifest = valid_manifest();
        let report = check_artifact_manifest_substrate_compatibility(
            &manifest,
            SubstrateCapabilitySet::host_validation(),
        )
        .expect("compatibility report");

        assert!(report.ok);
        assert_eq!(report.module_count, SUPERVISOR_WASM_MODULES.len());
        assert!(report.modules.iter().all(|module| module.ok));
    }

    #[test]
    fn interface_compatibility_accepts_host_validation_worlds() {
        let manifest = valid_manifest();
        let capabilities = InterfaceHostCapabilitySet::host_validation();
        let report = check_artifact_manifest_interface_compatibility(&manifest, &capabilities)
            .expect("interface compatibility report");

        assert!(report.ok);
        assert_eq!(report.module_count, SUPERVISOR_WASM_MODULES.len());
        assert!(report.modules.iter().all(|module| module.ok));
    }

    #[test]
    fn interface_compatibility_reports_missing_custom_wit_world() {
        let manifest = valid_manifest();
        let capabilities = InterfaceHostCapabilitySet::empty();
        let report = check_artifact_manifest_interface_compatibility(&manifest, &capabilities)
            .expect("interface compatibility report");
        let driver = report
            .modules
            .iter()
            .find(|module| module.package == "driver_virtio_net")
            .expect("driver report");

        assert!(!report.ok);
        assert!(!driver.ok);
        assert!(
            driver
                .missing_custom_wit_worlds
                .iter()
                .any(|world| world == "semantic:driverkit")
        );
        assert!(driver.version_mismatches.is_empty());
    }

    #[test]
    fn interface_compatibility_reports_version_mismatch_separately() {
        let manifest = valid_manifest();
        let mut capabilities = InterfaceHostCapabilitySet::host_validation();
        capabilities.hostcall_abi_version = "wire-v0".to_owned();
        let report = check_artifact_manifest_interface_compatibility(&manifest, &capabilities)
            .expect("interface compatibility report");
        let linux = report
            .modules
            .iter()
            .find(|module| module.package == "linux_syscall")
            .expect("linux report");

        assert!(!report.ok);
        assert!(
            linux
                .version_mismatches
                .iter()
                .any(|mismatch| mismatch.field == "hostcall_abi_version"
                    && mismatch.expected == HOSTCALL_ABI_VERSION
                    && mismatch.actual == "wire-v0")
        );
    }

    #[test]
    fn substrate_compatibility_reports_missing_required_authority() {
        let manifest = valid_manifest();
        let report = check_artifact_manifest_substrate_compatibility(
            &manifest,
            SubstrateCapabilitySet::semantic_harness(),
        )
        .expect("compatibility report");
        let driver = report
            .modules
            .iter()
            .find(|module| module.package == "driver_virtio_net")
            .expect("driver report");

        assert!(!report.ok);
        assert!(!driver.ok);
        assert!(
            driver
                .missing_required
                .iter()
                .any(|item| item.authority == "dma")
        );
        assert!(
            driver
                .missing_required
                .iter()
                .any(|item| item.authority == "mmio")
        );
        assert!(driver.forbidden_requested.is_empty());
    }

    #[test]
    fn substrate_compatibility_rejects_unknown_required_authority() {
        let manifest = valid_manifest();
        let plan = build_validated_artifact_plan(&manifest).expect("valid plan");
        let mut linux = plan.entry("linux_syscall").expect("linux module").clone();
        linux
            .interfaces
            .substrate_authorities
            .required
            .push("raw-mmio".to_owned());

        let err =
            check_module_substrate_compatibility(&linux, SubstrateCapabilitySet::host_validation())
                .expect_err("raw requirement token must fail before load");

        assert!(
            err.to_string()
                .contains("invalid required substrate authority token")
        );
    }

    #[test]
    fn substrate_compatibility_rejects_forbidden_capability_manifest() {
        let manifest = valid_manifest();
        let plan = build_validated_artifact_plan(&manifest).expect("valid plan");
        let mut linux = plan.entry("linux_syscall").expect("linux module").clone();
        linux.capabilities.push(CapabilityManifest {
            name: "mmio.pci.bar0".to_owned(),
            rights: vec!["read".to_owned()],
            lifetime: "store".to_owned(),
        });

        let report =
            check_module_substrate_compatibility(&linux, SubstrateCapabilitySet::host_validation())
                .expect("compatibility report");

        assert!(!report.ok);
        assert_eq!(report.forbidden_requested, vec!["raw-mmio".to_owned()]);
    }

    #[test]
    fn manifest_validation_rejects_interface_boundary_mismatch() {
        let mut manifest = valid_manifest();
        let linux = manifest
            .modules
            .iter_mut()
            .find(|entry| entry.package == "linux_syscall")
            .expect("linux syscall entry exists");
        linux.interfaces.substrate_profile_required = "device-capable".to_owned();

        let err = validate_artifact_manifest(&manifest).expect_err("bad interface must fail");
        assert!(err.to_string().contains("substrate profile mismatch"));
    }

    #[test]
    fn manifest_validation_rejects_unknown_runtime_mode() {
        let mut manifest = valid_manifest();
        manifest.runtime_mode = "max-debug-production-replay".to_owned();

        assert_eq!(
            validate_artifact_manifest(&manifest)
                .unwrap_err()
                .to_string(),
            "unsupported runtime mode"
        );
    }

    #[test]
    fn object_ref_rejects_null_identity() {
        assert!(ObjectRef::new(ObjectKind::Store, 0, 1).is_err());
        assert!(ObjectRef::new(ObjectKind::Store, 1, 0).is_err());
        assert!(ObjectRef::new(ObjectKind::External, 1, 0).is_ok());
    }

    #[test]
    fn same_id_different_generation_is_distinct() {
        let first = ObjectRef::new(ObjectKind::Store, 7, 1).unwrap();
        let second = ObjectRef::new(ObjectKind::Store, 7, 2).unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn typed_object_kind_mismatch_is_detected() {
        let cap = ObjectRef::new(ObjectKind::Capability, 3, 1).unwrap();

        assert!(matches!(
            StoreRef::try_from_ref(cap),
            Err(TypedRefError::KindMismatch {
                expected: ObjectKind::Store,
                actual: ObjectKind::Capability,
            })
        ));
        assert!(CapabilityRef::try_from_ref(cap).is_ok());
        let saved = ObjectRef::new(ObjectKind::SavedContext, 4, 1).unwrap();
        assert!(SavedContextRef::try_from_ref(saved).is_ok());
        assert!(matches!(
            ActivationContextRef::try_from_ref(saved),
            Err(TypedRefError::KindMismatch {
                expected: ObjectKind::ActivationContext,
                actual: ObjectKind::SavedContext,
            })
        ));
        let timer = ObjectRef::new(ObjectKind::TimerInterrupt, 5, 1).unwrap();
        assert!(TimerInterruptRef::try_from_ref(timer).is_ok());
        let ipi = ObjectRef::new(ObjectKind::IpiEvent, 6, 1).unwrap();
        assert!(IpiEventRef::try_from_ref(ipi).is_ok());
        let remote_preempt = ObjectRef::new(ObjectKind::RemotePreempt, 6, 1).unwrap();
        assert!(RemotePreemptRef::try_from_ref(remote_preempt).is_ok());
        let remote_park = ObjectRef::new(ObjectKind::RemotePark, 6, 1).unwrap();
        assert!(RemoteParkRef::try_from_ref(remote_park).is_ok());
        let preemption = ObjectRef::new(ObjectKind::Preemption, 6, 1).unwrap();
        assert!(PreemptionRef::try_from_ref(preemption).is_ok());
        let decision = ObjectRef::new(ObjectKind::SchedulerDecision, 7, 1).unwrap();
        assert!(SchedulerDecisionRef::try_from_ref(decision).is_ok());
        let cross_decision = ObjectRef::new(ObjectKind::CrossHartSchedulerDecision, 8, 1).unwrap();
        assert!(CrossHartSchedulerDecisionRef::try_from_ref(cross_decision).is_ok());
        let migration = ObjectRef::new(ObjectKind::ActivationMigration, 9, 1).unwrap();
        assert!(ActivationMigrationRef::try_from_ref(migration).is_ok());
        let safe_point = ObjectRef::new(ObjectKind::SmpSafePoint, 10, 1).unwrap();
        assert!(SmpSafePointRef::try_from_ref(safe_point).is_ok());
        let rendezvous = ObjectRef::new(ObjectKind::StopTheWorldRendezvous, 11, 1).unwrap();
        assert!(StopTheWorldRendezvousRef::try_from_ref(rendezvous).is_ok());
        let code_publish_barrier =
            ObjectRef::new(ObjectKind::SmpCodePublishBarrier, 12, 1).unwrap();
        assert!(SmpCodePublishBarrierRef::try_from_ref(code_publish_barrier).is_ok());
        let cleanup_quiescence = ObjectRef::new(ObjectKind::SmpCleanupQuiescence, 13, 1).unwrap();
        assert!(SmpCleanupQuiescenceRef::try_from_ref(cleanup_quiescence).is_ok());
        let snapshot_barrier = ObjectRef::new(ObjectKind::SmpSnapshotBarrier, 14, 1).unwrap();
        assert!(SmpSnapshotBarrierRef::try_from_ref(snapshot_barrier).is_ok());
        let stress_run = ObjectRef::new(ObjectKind::SmpStressRun, 15, 1).unwrap();
        assert!(SmpStressRunRef::try_from_ref(stress_run).is_ok());
        let scaling_benchmark = ObjectRef::new(ObjectKind::SmpScalingBenchmark, 16, 1).unwrap();
        assert!(SmpScalingBenchmarkRef::try_from_ref(scaling_benchmark).is_ok());
        let device_object = ObjectRef::new(ObjectKind::DeviceObject, 17, 1).unwrap();
        assert!(DeviceObjectRef::try_from_ref(device_object).is_ok());
        let queue_object = ObjectRef::new(ObjectKind::QueueObject, 18, 1).unwrap();
        assert!(QueueObjectRef::try_from_ref(queue_object).is_ok());
        let descriptor_object = ObjectRef::new(ObjectKind::DescriptorObject, 19, 1).unwrap();
        assert!(DescriptorObjectRef::try_from_ref(descriptor_object).is_ok());
        let dma_buffer_object = ObjectRef::new(ObjectKind::DmaBufferObject, 20, 1).unwrap();
        assert!(DmaBufferObjectRef::try_from_ref(dma_buffer_object).is_ok());
        let mmio_region_object = ObjectRef::new(ObjectKind::MmioRegionObject, 21, 1).unwrap();
        assert!(MmioRegionObjectRef::try_from_ref(mmio_region_object).is_ok());
        let irq_line_object = ObjectRef::new(ObjectKind::IrqLineObject, 22, 1).unwrap();
        assert!(IrqLineObjectRef::try_from_ref(irq_line_object).is_ok());
        let resume = ObjectRef::new(ObjectKind::ActivationResume, 8, 1).unwrap();
        assert!(ActivationResumeRef::try_from_ref(resume).is_ok());
        let activation_wait = ObjectRef::new(ObjectKind::ActivationWait, 9, 1).unwrap();
        assert!(ActivationWaitRef::try_from_ref(activation_wait).is_ok());
        let hart_event = ObjectRef::new(ObjectKind::HartEventAttribution, 10, 1).unwrap();
        assert!(HartEventAttributionRef::try_from_ref(hart_event).is_ok());
    }

    #[test]
    fn tombstone_preserves_exact_generation() {
        let dead_store = ObjectRef::new(ObjectKind::Store, 9, 4).unwrap();
        let tombstone = TombstoneRecord::new(dead_store, 88, "cleanup-store-dead");

        assert_eq!(tombstone.object, dead_store);
        assert_eq!(tombstone.object.generation, 4);
        assert_eq!(tombstone.died_at_event, 88);
    }

    #[test]
    fn schema_versions_are_referenced_by_views_edges_events_and_traces() {
        let store = StoreRef::new(1, 1).unwrap().object_ref();
        let code = CodeObjectRef::new(2, 1).unwrap().object_ref();
        let edge = ContractEdge::new(store, code, RefMode::Live, "store->code", 7);
        let view = StoreViewV1 {
            schema: VIEW_SCHEMA_V1,
            kind: ObjectKind::Store,
            object: store,
            state: "running".to_owned(),
            owner: None,
            references: vec![edge.clone()],
            last_transition: Some("bound->running".to_owned()),
            last_error: None,
        };

        assert_eq!(CONTRACT_SCHEMA_VERSION.name, "semantic-contract-v0.1");
        assert_eq!(CONTRACT_SCHEMA, CONTRACT_SCHEMA_VERSION.name);
        assert_eq!(view.schema, VIEW_SCHEMA_V1);
        assert_eq!(edge.mode, RefMode::Live);
        assert_eq!(EDGE_SCHEMA_V1, 1);
        assert_eq!(EVENT_SCHEMA_V1, 1);
        assert_eq!(TRACE_SCHEMA_V1, 1);
    }
}
