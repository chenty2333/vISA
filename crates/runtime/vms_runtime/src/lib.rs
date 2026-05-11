//! vISA artifact execution loop.
//!
//! This crate is the runtime bridge for the Semantic Virtual ISA primary path:
//! `TargetArtifactImage -> CodeObject -> Activation -> HostcallFrame -> TrapMap
//! -> substrate trait dispatch -> event`.
//!
//! It is not a Linux compatibility layer and not an evidence scenario
//! generator. Frontend personalities produce typed vISA hostcall requests, and
//! substrate ports implement the authority traits consumed here.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use contract_core::EvidenceBoundaryLevel;
use semantic_core::{
    ActivationId, ArtifactVerificationState, BoundaryKind, BoundaryStatus, CapabilityId,
    CapabilityLedger, CodeObjectId, CodePublishState, CommandEnvelope, ContractGraphSnapshot,
    ContractGraphSnapshotInputs, EntrypointState, EventId, EventKind, FrontendKind, Generation,
    HostcallClass, HostcallLinkState, MemoryLayoutState, NonPortableStateKind, RuntimeMode,
    SemanticCommand, SemanticGraph, StoreId, StoreState, TargetArtifactId, TrapSurfaceState,
    target_executor::{
        ActivationEntry, ArtifactRegistry, CapabilityHandleArg, CodeObject, CodePublisher,
        ContractObjectKind, ContractObjectRef, HostcallFrame, HostcallSpec, ManagedStoreRecord,
        TargetArtifactImage, TargetCapabilitySpec, TargetExecutor, TargetExecutorError,
        TargetMemoryPlan, TargetStoreManager, TombstoneRecord, VerifiedArtifact,
    },
};
use substrate_api::{
    ArtifactAuthority, ArtifactImageRef, CodeObjectRef, CodePublisherAuthority, ConsoleAuthority,
    DmaAllocRequest, DmaAuthority, DmaBufferCapability, DmwAuthority, EventQueueAuthority,
    GuestBytes, GuestMemoryAuthority, IrqAuthority, IrqLine, MmioAuthority, MmioRegionRef,
    PublishedCodeRef, SnapshotAuthority, SnapshotBarrierRef, StoreRef, SubstrateError,
    SubstrateEvent, SubstrateRequester, TimerAuthority, UserMemoryHandle, VirtualTime,
    WaitTokenRef, WindowLeaseRef, WindowPerms,
};
use target_abi::{SectionKindV1, TargetArtifactError, TargetArtifactImage as WireArtifactImage};
use visa_profile::{SubstrateCapabilitySet, SubstrateCompatibilityReport, SubstrateProfile};

pub trait VisaSubstrate:
    ArtifactAuthority
    + CodePublisherAuthority
    + ConsoleAuthority
    + TimerAuthority
    + EventQueueAuthority
    + GuestMemoryAuthority
    + DmwAuthority
    + MmioAuthority
    + DmaAuthority
    + IrqAuthority
    + SnapshotAuthority
{
}

impl<T> VisaSubstrate for T where
    T: ArtifactAuthority
        + CodePublisherAuthority
        + ConsoleAuthority
        + TimerAuthority
        + EventQueueAuthority
        + GuestMemoryAuthority
        + DmwAuthority
        + MmioAuthority
        + DmaAuthority
        + IrqAuthority
        + SnapshotAuthority
{
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VisaRuntimeConfig {
    pub required_profile: SubstrateProfile,
    pub reported_profile: SubstrateProfile,
    pub enforced_capabilities: SubstrateCapabilitySet,
    pub evidence_level: EvidenceBoundaryLevel,
    pub runtime_mode: RuntimeMode,
}

impl VisaRuntimeConfig {
    pub const fn for_profile(profile: SubstrateProfile) -> Self {
        Self {
            required_profile: profile,
            reported_profile: profile,
            enforced_capabilities: SubstrateCapabilitySet::for_profile(profile),
            evidence_level: EvidenceBoundaryLevel::PortableArtifactExecution,
            runtime_mode: RuntimeMode::Production,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VisaArtifactDescriptor {
    pub id: TargetArtifactId,
    pub package: String,
    pub artifact_name: String,
    pub role: String,
    pub target_profile: SubstrateProfile,
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
    pub capabilities: Vec<TargetCapabilitySpec>,
    pub hostcalls: Vec<HostcallSpec>,
}

impl VisaArtifactDescriptor {
    pub fn new(
        id: TargetArtifactId,
        package: &str,
        artifact_name: &str,
        target_profile: SubstrateProfile,
    ) -> Self {
        Self {
            id,
            package: package.to_string(),
            artifact_name: artifact_name.to_string(),
            role: "service".to_string(),
            target_profile,
            artifact_hash: format!("{package}-artifact-hash"),
            hash_status: "verified".to_string(),
            abi_fingerprint: format!("{package}-abi"),
            manifest_binding_hash: format!("{package}-manifest-binding"),
            code_hash: format!("{package}-code-hash"),
            signature_scheme: "dev".to_string(),
            signature_status: "verified".to_string(),
            signature_verified: true,
            signer: "dev-key".to_string(),
            imports: Vec::new(),
            exports: Vec::new(),
            memory_plan: TargetMemoryPlan::new(16, 16, 128),
            capabilities: Vec::new(),
            hostcalls: Vec::new(),
        }
    }

    pub fn with_role(mut self, role: &str) -> Self {
        self.role = role.to_string();
        self
    }

    pub fn with_capability(mut self, object: &str, operations: &[&str], lifetime: &str) -> Self {
        self.capabilities.push(TargetCapabilitySpec::new(object, operations, lifetime));
        self
    }

    pub fn with_hostcall(mut self, hostcall: HostcallSpec) -> Self {
        self.hostcalls.push(hostcall);
        self
    }
}

pub struct VisaArtifactInput<'a> {
    pub bytes: &'a [u8],
    pub descriptor: VisaArtifactDescriptor,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedVisaArtifact {
    pub artifact_id: TargetArtifactId,
    pub package: String,
    pub store_id: u64,
    pub code_object_id: CodeObjectId,
    pub evidence_level: EvidenceBoundaryLevel,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivationHandle {
    pub artifact_id: TargetArtifactId,
    pub store_id: u64,
    pub code_object_id: CodeObjectId,
    pub activation_id: ActivationId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VisaHostcallPayload {
    None,
    ConsoleWrite { bytes: Vec<u8> },
    TimerNow,
    TimerArm { deadline_ticks: u64, token: WaitTokenRef },
    GuestMemoryCopyIn { memory: UserMemoryHandle, ptr: u64, len: usize },
    GuestMemoryCopyOut { memory: UserMemoryHandle, ptr: u64, bytes: Vec<u8> },
    DmwMap { memory: UserMemoryHandle, ptr: u64, len: usize, perms: WindowPerms },
    DmwUnmap { lease: WindowLeaseRef },
    MmioRead32 { region: MmioRegionRef, offset: u64 },
    MmioWrite32 { region: MmioRegionRef, offset: u64, value: u32 },
    DmaAlloc { request: DmaAllocRequest },
    DmaFree { capability: DmaBufferCapability },
    IrqAck { irq: IrqLine },
    IrqMask { irq: IrqLine },
    IrqUnmask { irq: IrqLine },
    SnapshotEnter,
    SnapshotExit { barrier: SnapshotBarrierRef },
}

impl VisaHostcallPayload {
    fn args(&self) -> [u64; 6] {
        match self {
            Self::None | Self::TimerNow | Self::SnapshotEnter => [0; 6],
            Self::ConsoleWrite { bytes } => [bytes.len() as u64, 0, 0, 0, 0, 0],
            Self::TimerArm { deadline_ticks, token } => {
                [*deadline_ticks, token.id, token.generation, 0, 0, 0]
            }
            Self::GuestMemoryCopyIn { memory, ptr, len } => {
                [memory.id, memory.generation, *ptr, *len as u64, 0, 0]
            }
            Self::GuestMemoryCopyOut { memory, ptr, bytes } => {
                [memory.id, memory.generation, *ptr, bytes.len() as u64, 0, 0]
            }
            Self::DmwMap { memory, ptr, len, perms } => [
                memory.id,
                memory.generation,
                *ptr,
                *len as u64,
                (perms.read as u64) | ((perms.write as u64) << 1) | ((perms.execute as u64) << 2),
                0,
            ],
            Self::DmwUnmap { lease } => [lease.id, lease.generation, 0, 0, 0, 0],
            Self::MmioRead32 { region, offset } => [region.id, region.generation, *offset, 0, 0, 0],
            Self::MmioWrite32 { region, offset, value } => {
                [region.id, region.generation, *offset, *value as u64, 0, 0]
            }
            Self::DmaAlloc { request } => {
                [request.device, request.bytes as u64, request.alignment as u64, 0, 0, 0]
            }
            Self::DmaFree { capability } => [capability.id, capability.generation, 0, 0, 0, 0],
            Self::IrqAck { irq } | Self::IrqMask { irq } | Self::IrqUnmask { irq } => {
                [irq.id, irq.generation, 0, 0, 0, 0]
            }
            Self::SnapshotExit { barrier } => [barrier.id, barrier.generation, 0, 0, 0, 0],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VisaHostcallValue {
    None,
    Bytes(GuestBytes),
    U32(u32),
    U64(u64),
    WindowLease(WindowLeaseRef),
    DmaBuffer(DmaBufferCapability),
    SnapshotBarrier(SnapshotBarrierRef),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostcallDispatchReport {
    pub hostcall_number: u32,
    pub object: String,
    pub operation: String,
    pub value: VisaHostcallValue,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VisaExecutionStep {
    pub hostcall_number: u32,
    pub payload: VisaHostcallPayload,
}

impl VisaExecutionStep {
    pub const fn new(hostcall_number: u32, payload: VisaHostcallPayload) -> Self {
        Self { hostcall_number, payload }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VisaExecutionReport {
    pub loaded: LoadedVisaArtifact,
    pub activation: ActivationHandle,
    pub hostcalls: Vec<HostcallDispatchReport>,
    pub events: Vec<VisaRuntimeEvent>,
}

impl VisaExecutionReport {
    pub fn evidence_summary(&self) -> VisaExecutionEvidenceReport {
        let artifact_loaded = self.events.iter().any(|event| {
            matches!(
                event,
                VisaRuntimeEvent::ArtifactLoaded {
                    artifact_id,
                    store_id
                } if *artifact_id == self.loaded.artifact_id && *store_id == self.loaded.store_id
            )
        });
        let code_published = self.events.iter().any(|event| {
            matches!(
                event,
                VisaRuntimeEvent::CodePublished {
                    artifact_id,
                    code_object_id
                } if *artifact_id == self.loaded.artifact_id
                    && *code_object_id == self.loaded.code_object_id
            )
        });
        let activation_started = self.events.iter().any(|event| {
            matches!(
                event,
                VisaRuntimeEvent::ActivationStarted {
                    activation_id,
                    store_id,
                    code_object_id
                } if *activation_id == self.activation.activation_id
                    && *store_id == self.activation.store_id
                    && *code_object_id == self.activation.code_object_id
            )
        });
        let hostcall_dispatches = self
            .events
            .iter()
            .filter(|event| matches!(event, VisaRuntimeEvent::HostcallDispatched { .. }))
            .count();
        let substrate_authority_extractions = self
            .events
            .iter()
            .filter(|event| matches!(event, VisaRuntimeEvent::SubstrateAuthorityExtracted { .. }))
            .count();
        let evidence_boundary_sufficient =
            self.loaded.evidence_level.can_claim(EvidenceBoundaryLevel::PortableArtifactExecution);

        VisaExecutionEvidenceReport {
            evidence_level: self.loaded.evidence_level,
            artifact_id: self.loaded.artifact_id,
            store_id: self.loaded.store_id,
            code_object_id: self.loaded.code_object_id,
            activation_id: self.activation.activation_id,
            artifact_loaded,
            code_published,
            activation_started,
            hostcall_dispatches,
            substrate_authority_extractions,
            evidence_boundary_sufficient,
            can_claim_portable_artifact_execution: evidence_boundary_sufficient
                && artifact_loaded
                && code_published
                && activation_started
                && hostcall_dispatches == self.hostcalls.len(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VisaExecutionEvidenceReport {
    pub evidence_level: EvidenceBoundaryLevel,
    pub artifact_id: TargetArtifactId,
    pub store_id: u64,
    pub code_object_id: CodeObjectId,
    pub activation_id: ActivationId,
    pub artifact_loaded: bool,
    pub code_published: bool,
    pub activation_started: bool,
    pub hostcall_dispatches: usize,
    pub substrate_authority_extractions: usize,
    pub evidence_boundary_sufficient: bool,
    pub can_claim_portable_artifact_execution: bool,
}

#[derive(Clone, Debug)]
pub struct VisaRuntimeEvidenceSnapshot {
    pub contract_graph: ContractGraphSnapshot,
    pub event_log_cursor: EventId,
    pub runtime_events: Vec<VisaRuntimeEvent>,
    pub authority_extractions: Vec<VisaSubstrateAuthorityExtractionEvidence>,
    pub unsupported_substrate_events: Vec<VisaSubstrateUnsupportedEvidence>,
}

impl VisaRuntimeEvidenceSnapshot {
    pub fn authority_extraction_count(&self) -> usize {
        self.authority_extractions.len()
    }

    pub fn unsupported_substrate_event_count(&self) -> usize {
        self.unsupported_substrate_events.len()
    }

    pub fn hostcall_trace_count(&self) -> usize {
        self.contract_graph.hostcalls.len()
    }

    pub fn has_substrate_authority_extraction_evidence(&self) -> bool {
        !self.authority_extractions.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VisaSubstrateAuthorityExtractionEvidence {
    pub event_id: EventId,
    pub event_epoch: u64,
    pub authority: String,
    pub operation: String,
    pub requester: Option<String>,
    pub artifact_id: Option<TargetArtifactId>,
    pub store_id: Option<StoreId>,
    pub capability_id: Option<CapabilityId>,
    pub capability_generation: Option<Generation>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VisaSubstrateUnsupportedEvidence {
    pub event_id: EventId,
    pub event_epoch: u64,
    pub authority: String,
    pub operation: String,
    pub requester: Option<String>,
    pub artifact_id: Option<TargetArtifactId>,
    pub store_id: Option<StoreId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VisaRuntimeEvent {
    BoundaryPublished {
        name: String,
        level: EvidenceBoundaryLevel,
    },
    ArtifactParsed {
        artifact_id: TargetArtifactId,
        package: String,
    },
    ArtifactLoaded {
        artifact_id: TargetArtifactId,
        store_id: u64,
    },
    CodePublished {
        artifact_id: TargetArtifactId,
        code_object_id: CodeObjectId,
    },
    ActivationStarted {
        activation_id: ActivationId,
        store_id: u64,
        code_object_id: CodeObjectId,
    },
    HostcallDispatched {
        activation_id: ActivationId,
        hostcall_number: u32,
        object: String,
        operation: String,
    },
    SubstrateAuthorityExtracted {
        authority: String,
        operation: String,
        artifact_id: TargetArtifactId,
        store_id: Option<u64>,
    },
    SubstrateUnsupported {
        authority: &'static str,
        operation: &'static str,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VisaRuntimeError {
    Artifact(TargetArtifactError),
    MissingCodeObjectSection,
    ProfileGateRejected {
        required: SubstrateProfile,
        reported: SubstrateProfile,
        report: SubstrateCompatibilityReport,
    },
    Registry(&'static str),
    Store(&'static str),
    CodePublisher(&'static str),
    Executor(TargetExecutorError),
    SemanticCommandRejected(Vec<String>),
    NonPortableSnapshot(Vec<NonPortableStateKind>),
    InvalidPortableSnapshot(&'static str),
    MissingLoadedArtifact(TargetArtifactId),
    MissingStore(u64),
    MissingCodeObject(CodeObjectId),
    MissingHostcall(u32),
    MissingActivation(ActivationId),
    CapabilityGrant(&'static str),
    SubstrateDispatch {
        authority: &'static str,
        operation: &'static str,
        error: SubstrateError,
    },
}

impl From<TargetArtifactError> for VisaRuntimeError {
    fn from(error: TargetArtifactError) -> Self {
        Self::Artifact(error)
    }
}

pub struct VisaRuntime {
    config: VisaRuntimeConfig,
    semantic: SemanticGraph,
    registry: ArtifactRegistry,
    publisher: CodePublisher,
    store_manager: TargetStoreManager,
    executor: TargetExecutor,
    ledger: CapabilityLedger,
    events: Vec<VisaRuntimeEvent>,
    next_command_id: u64,
}

impl VisaRuntime {
    pub fn new(config: VisaRuntimeConfig) -> Self {
        let mut semantic = SemanticGraph::with_runtime_mode(config.runtime_mode);
        semantic.ensure_task(1, FrontendKind::Supervisor, "vms-runtime");
        semantic.set_task_state(1, semantic_core::TaskState::Running);

        let mut runtime = Self {
            config,
            semantic,
            registry: ArtifactRegistry::new(),
            publisher: CodePublisher::new(),
            store_manager: TargetStoreManager::new(),
            executor: TargetExecutor::new(),
            ledger: CapabilityLedger::new(),
            events: Vec::new(),
            next_command_id: 1,
        };
        runtime.publish_runtime_boundaries();
        runtime
    }

    pub fn config(&self) -> &VisaRuntimeConfig {
        &self.config
    }

    pub fn semantic(&self) -> &SemanticGraph {
        &self.semantic
    }

    pub fn executor(&self) -> &TargetExecutor {
        &self.executor
    }

    pub fn events(&self) -> &[VisaRuntimeEvent] {
        &self.events
    }

    pub fn load_artifact<B: VisaSubstrate + ?Sized>(
        &mut self,
        input: VisaArtifactInput<'_>,
        backend: &mut B,
    ) -> Result<LoadedVisaArtifact, VisaRuntimeError> {
        let parsed = WireArtifactImage::parse(input.bytes)?;
        let code_payload = parsed
            .section_payload(SectionKindV1::CodeObject)?
            .ok_or(VisaRuntimeError::MissingCodeObjectSection)?;
        let profile_report = self.profile_gate_report(input.descriptor.target_profile);
        let required_profile =
            stronger_profile(self.config.required_profile, input.descriptor.target_profile);
        if !profile_report.ok || !self.config.reported_profile.satisfies(required_profile) {
            return Err(VisaRuntimeError::ProfileGateRejected {
                required: required_profile,
                reported: self.config.reported_profile,
                report: profile_report,
            });
        }

        let image = semantic_image_from_descriptor(input.descriptor, code_payload.len());
        self.semantic.record_artifact_verification(
            &image.package,
            &image.artifact_name,
            &image.manifest_binding_hash,
            &image.artifact_hash,
            &image.hash_status,
            &image.abi_fingerprint,
            &image.signature_scheme,
            &image.signature_status,
            image.signature_verified,
            &image.signer,
            ArtifactVerificationState::HostValidated,
            Some("vms-runtime-target-artifact-image"),
        );
        let verified = self
            .registry
            .verify(image)
            .map_err(|error| VisaRuntimeError::Registry(error.message()))?;
        self.dispatch_artifact_load(backend, &verified)?;

        let store_id = self.semantic.register_store(
            &verified.package,
            &verified.artifact_name,
            &verified.role,
            "restartable",
        );
        self.semantic.set_store_state(store_id, StoreState::Instantiating);
        self.semantic.set_store_state(store_id, StoreState::Running);
        self.semantic.record_store_activation(
            store_id,
            &verified.package,
            &verified.manifest_binding_hash,
            &verified.code_hash,
            CodePublishState::Published,
            MemoryLayoutState::Verified,
            HostcallLinkState::Linked,
            TrapSurfaceState::ContractDeclared,
            EntrypointState::Runnable,
            Some("vms-runtime-loop"),
        );

        let store_id = self.store_manager.register_verified_artifact_with_id(
            store_id,
            &verified,
            "restartable",
            "vms-runtime",
        );
        self.store_manager
            .set_running(store_id)
            .map_err(|error| VisaRuntimeError::Store(error.message()))?;

        let store_generation = self.store_generation(store_id)?;
        grant_verified_capabilities(&mut self.ledger, &verified, store_id, store_generation)?;

        let code_id = self
            .publisher
            .allocate(&verified)
            .map_err(|error| VisaRuntimeError::CodePublisher(error.message()))?;
        self.publisher
            .fill(code_id)
            .map_err(|error| VisaRuntimeError::CodePublisher(error.message()))?;
        self.publisher
            .seal(code_id)
            .map_err(|error| VisaRuntimeError::CodePublisher(error.message()))?;
        self.publisher
            .publish_rx(code_id)
            .map_err(|error| VisaRuntimeError::CodePublisher(error.message()))?;
        let store = self.store_record(store_id)?.store.clone();
        self.publisher
            .bind_to_store(code_id, &store)
            .map_err(|error| VisaRuntimeError::CodePublisher(error.message()))?;
        let code = self.code_object(code_id)?.clone();
        self.dispatch_code_publish(backend, &verified, &code)?;

        self.events.push(VisaRuntimeEvent::ArtifactParsed {
            artifact_id: verified.artifact_id,
            package: verified.package.clone(),
        });
        self.events
            .push(VisaRuntimeEvent::ArtifactLoaded { artifact_id: verified.artifact_id, store_id });
        self.events.push(VisaRuntimeEvent::CodePublished {
            artifact_id: verified.artifact_id,
            code_object_id: code_id,
        });

        Ok(LoadedVisaArtifact {
            artifact_id: verified.artifact_id,
            package: verified.package,
            store_id,
            code_object_id: code_id,
            evidence_level: self.config.evidence_level,
        })
    }

    pub fn run<B: VisaSubstrate + ?Sized>(
        &mut self,
        input: VisaArtifactInput<'_>,
        entry: ActivationEntry,
        steps: impl IntoIterator<Item = VisaExecutionStep>,
        backend: &mut B,
    ) -> Result<VisaExecutionReport, VisaRuntimeError> {
        let event_start = self.events.len();
        let loaded = self.load_artifact(input, backend)?;
        let activation = self.start_activation(&loaded, entry)?;
        let mut hostcalls = Vec::new();
        for step in steps {
            hostcalls.push(self.invoke_hostcall(
                &activation,
                step.hostcall_number,
                step.payload,
                backend,
            )?);
        }
        Ok(VisaExecutionReport {
            loaded,
            activation,
            hostcalls,
            events: self.events[event_start..].to_vec(),
        })
    }

    pub fn start_activation(
        &mut self,
        loaded: &LoadedVisaArtifact,
        entry: ActivationEntry,
    ) -> Result<ActivationHandle, VisaRuntimeError> {
        let store = self.store_record(loaded.store_id)?.store.clone();
        let code = self.code_object(loaded.code_object_id)?.clone();
        let activation_id = self
            .executor
            .start_activation(&store, &code, entry)
            .map_err(VisaRuntimeError::Executor)?;
        let semantic_store_generation = self
            .semantic
            .stores()
            .iter()
            .find(|record| record.id == loaded.store_id)
            .map(|record| record.generation);
        let command_id = self.next_command_id();
        let result = self.semantic.apply_envelope(CommandEnvelope::new(
            command_id,
            "vms-runtime",
            SemanticCommand::CreateRuntimeActivation {
                activation: activation_id,
                owner_task: 1,
                owner_task_generation: 2,
                owner_store: Some(loaded.store_id),
                owner_store_generation: semantic_store_generation,
                code_object: Some(ContractObjectRef::new(
                    ContractObjectKind::CodeObject,
                    loaded.code_object_id,
                    code.generation,
                )),
            },
        ));
        if !result.violations.is_empty() {
            return Err(VisaRuntimeError::SemanticCommandRejected(result.violations));
        }
        self.events.push(VisaRuntimeEvent::ActivationStarted {
            activation_id,
            store_id: loaded.store_id,
            code_object_id: loaded.code_object_id,
        });
        Ok(ActivationHandle {
            artifact_id: loaded.artifact_id,
            store_id: loaded.store_id,
            code_object_id: loaded.code_object_id,
            activation_id,
        })
    }

    pub fn invoke_hostcall<B: VisaSubstrate + ?Sized>(
        &mut self,
        activation: &ActivationHandle,
        hostcall_number: u32,
        payload: VisaHostcallPayload,
        backend: &mut B,
    ) -> Result<HostcallDispatchReport, VisaRuntimeError> {
        let store = self.store_record(activation.store_id)?.store.clone();
        let code = self.code_object(activation.code_object_id)?.clone();
        let spec = code
            .hostcalls
            .iter()
            .find(|spec| spec.number == hostcall_number)
            .cloned()
            .ok_or(VisaRuntimeError::MissingHostcall(hostcall_number))?;
        let current_activation_generation = self
            .executor
            .activations()
            .iter()
            .find(|record| record.id == activation.activation_id)
            .map(|record| record.generation)
            .ok_or(VisaRuntimeError::MissingActivation(activation.activation_id))?;
        let mut frame = HostcallFrame::new_bound(
            activation.activation_id,
            &store,
            &code,
            spec.number,
            &spec.object,
            &spec.operation,
            self.capability_generation(&code.package, &spec),
        )
        .with_args(payload.args());
        frame.activation_generation = current_activation_generation;
        let capability_arg = if spec.requires_capability() {
            capability_handle_arg_for(&self.ledger, &code.package, &spec)
        } else {
            None
        };
        if spec.requires_capability()
            && let Some(cap_arg) = capability_arg.clone()
        {
            frame = frame.with_cap_args(vec![cap_arg]);
        }
        self.semantic.record_hostcall(
            &spec.name,
            HostcallClass::ImmediatePrivilegedOp,
            &code.package,
            &spec.object,
            &spec.operation,
        );
        let prepared_hostcall = self
            .executor
            .preflight_hostcall(&code, frame.to_wire_frame(), &self.ledger)
            .map_err(VisaRuntimeError::Executor)?;
        let substrate_authority = substrate_authority_for_payload(&payload);
        let value = self.dispatch_hostcall_payload(backend, &code, &spec, payload)?;
        self.executor
            .commit_hostcall_success(prepared_hostcall)
            .map_err(VisaRuntimeError::Executor)?;
        if let Some((authority, operation)) = substrate_authority {
            self.semantic.record_substrate_authority_extracted(
                authority,
                operation,
                Some(code.package.clone()),
                Some(code.artifact_id),
                code.bound_store,
                capability_arg.as_ref().map(|capability| capability.id),
                capability_arg.as_ref().map(|capability| capability.generation),
            );
            self.events.push(VisaRuntimeEvent::SubstrateAuthorityExtracted {
                authority: authority.to_string(),
                operation: operation.to_string(),
                artifact_id: code.artifact_id,
                store_id: code.bound_store,
            });
        }
        self.events.push(VisaRuntimeEvent::HostcallDispatched {
            activation_id: activation.activation_id,
            hostcall_number,
            object: spec.object.clone(),
            operation: spec.operation.clone(),
        });
        Ok(HostcallDispatchReport {
            hostcall_number,
            object: spec.object,
            operation: spec.operation,
            value,
        })
    }

    fn publish_runtime_boundaries(&mut self) {
        for (name, kind, status) in [
            ("artifact-loader", BoundaryKind::ArtifactLoader, BoundaryStatus::RuntimeContract),
            ("runtime-executor", BoundaryKind::RuntimeExecutor, BoundaryStatus::Runnable),
            ("hostcall-table", BoundaryKind::HostcallTable, BoundaryStatus::HostcallsLinked),
            ("target-executor", BoundaryKind::TargetExecutor, BoundaryStatus::Runnable),
        ] {
            self.semantic.publish_boundary(
                name,
                kind,
                status,
                self.config.evidence_level,
                self.config.reported_profile.as_str(),
                None,
            );
            self.events.push(VisaRuntimeEvent::BoundaryPublished {
                name: name.to_string(),
                level: self.config.evidence_level,
            });
        }
    }

    fn profile_gate_report(
        &self,
        artifact_profile: SubstrateProfile,
    ) -> SubstrateCompatibilityReport {
        let required_profile = stronger_profile(self.config.required_profile, artifact_profile);
        self.config.enforced_capabilities.check_profile(required_profile)
    }

    fn dispatch_artifact_load<B: VisaSubstrate + ?Sized>(
        &mut self,
        backend: &mut B,
        artifact: &VerifiedArtifact,
    ) -> Result<(), VisaRuntimeError> {
        let artifact_ref = ArtifactImageRef::new(artifact.artifact_id, artifact.generation);
        match backend.load_artifact_image(artifact_ref) {
            Ok(()) => Ok(()),
            Err(error) => self.substrate_error(
                backend,
                "ArtifactAuthority",
                "load_artifact_image",
                requester_for(artifact).with_artifact(artifact_ref),
                error,
            ),
        }
    }

    fn dispatch_code_publish<B: VisaSubstrate + ?Sized>(
        &mut self,
        backend: &mut B,
        artifact: &VerifiedArtifact,
        code: &CodeObject,
    ) -> Result<PublishedCodeRef, VisaRuntimeError> {
        let artifact_ref = ArtifactImageRef::new(artifact.artifact_id, artifact.generation);
        let code_ref = CodeObjectRef::new(code.id, code.generation);
        match backend.publish_code(artifact_ref, code_ref) {
            Ok(published) => Ok(published),
            Err(error) => {
                self.substrate_error(
                    backend,
                    "CodePublisherAuthority",
                    "publish_code",
                    requester_for(artifact).with_artifact(artifact_ref).with_store(StoreRef::new(
                        code.bound_store.unwrap_or(0),
                        code.bound_store_generation.unwrap_or(0),
                    )),
                    error,
                )?;
                unreachable!("substrate_error always returns Err")
            }
        }
    }

    fn dispatch_hostcall_payload<B: VisaSubstrate + ?Sized>(
        &mut self,
        backend: &mut B,
        code: &CodeObject,
        spec: &HostcallSpec,
        payload: VisaHostcallPayload,
    ) -> Result<VisaHostcallValue, VisaRuntimeError> {
        match payload {
            VisaHostcallPayload::None => Ok(VisaHostcallValue::None),
            VisaHostcallPayload::ConsoleWrite { bytes } => {
                let written = backend.console_write(&bytes).map_err(|error| {
                    self.map_hostcall_substrate_error(
                        backend,
                        code,
                        spec,
                        "ConsoleAuthority",
                        "console_write",
                        error,
                    )
                })?;
                Ok(VisaHostcallValue::U64(written as u64))
            }
            VisaHostcallPayload::TimerNow => {
                let now = backend.now().map_err(|error| {
                    self.map_hostcall_substrate_error(
                        backend,
                        code,
                        spec,
                        "TimerAuthority",
                        "now",
                        error,
                    )
                })?;
                Ok(VisaHostcallValue::U64(now.ticks))
            }
            VisaHostcallPayload::TimerArm { deadline_ticks, token } => {
                backend.arm_timer(VirtualTime::from_ticks(deadline_ticks), token).map_err(
                    |error| {
                        self.map_hostcall_substrate_error(
                            backend,
                            code,
                            spec,
                            "TimerAuthority",
                            "arm_timer",
                            error,
                        )
                    },
                )?;
                Ok(VisaHostcallValue::None)
            }
            VisaHostcallPayload::GuestMemoryCopyIn { memory, ptr, len } => {
                let bytes = backend.copyin(memory, ptr, len).map_err(|error| {
                    self.map_hostcall_substrate_error(
                        backend,
                        code,
                        spec,
                        "GuestMemoryAuthority",
                        "copyin",
                        error,
                    )
                })?;
                Ok(VisaHostcallValue::Bytes(bytes))
            }
            VisaHostcallPayload::GuestMemoryCopyOut { memory, ptr, bytes } => {
                backend.copyout(memory, ptr, &bytes).map_err(|error| {
                    self.map_hostcall_substrate_error(
                        backend,
                        code,
                        spec,
                        "GuestMemoryAuthority",
                        "copyout",
                        error,
                    )
                })?;
                Ok(VisaHostcallValue::None)
            }
            VisaHostcallPayload::DmwMap { memory, ptr, len, perms } => {
                let lease = backend.map_user_window(memory, ptr, len, perms).map_err(|error| {
                    self.map_hostcall_substrate_error(
                        backend,
                        code,
                        spec,
                        "DmwAuthority",
                        "map_user_window",
                        error,
                    )
                })?;
                Ok(VisaHostcallValue::WindowLease(lease))
            }
            VisaHostcallPayload::DmwUnmap { lease } => {
                backend.unmap_user_window(lease).map_err(|error| {
                    self.map_hostcall_substrate_error(
                        backend,
                        code,
                        spec,
                        "DmwAuthority",
                        "unmap_user_window",
                        error,
                    )
                })?;
                Ok(VisaHostcallValue::None)
            }
            VisaHostcallPayload::MmioRead32 { region, offset } => {
                let value = backend.mmio_read32(region, offset).map_err(|error| {
                    self.map_hostcall_substrate_error(
                        backend,
                        code,
                        spec,
                        "MmioAuthority",
                        "mmio_read32",
                        error,
                    )
                })?;
                Ok(VisaHostcallValue::U32(value))
            }
            VisaHostcallPayload::MmioWrite32 { region, offset, value } => {
                backend.mmio_write32(region, offset, value).map_err(|error| {
                    self.map_hostcall_substrate_error(
                        backend,
                        code,
                        spec,
                        "MmioAuthority",
                        "mmio_write32",
                        error,
                    )
                })?;
                Ok(VisaHostcallValue::None)
            }
            VisaHostcallPayload::DmaAlloc { request } => {
                let buffer = backend.dma_alloc(request).map_err(|error| {
                    self.map_hostcall_substrate_error(
                        backend,
                        code,
                        spec,
                        "DmaAuthority",
                        "dma_alloc",
                        error,
                    )
                })?;
                Ok(VisaHostcallValue::DmaBuffer(buffer))
            }
            VisaHostcallPayload::DmaFree { capability } => {
                backend.dma_free(capability).map_err(|error| {
                    self.map_hostcall_substrate_error(
                        backend,
                        code,
                        spec,
                        "DmaAuthority",
                        "dma_free",
                        error,
                    )
                })?;
                Ok(VisaHostcallValue::None)
            }
            VisaHostcallPayload::IrqAck { irq } => {
                backend.irq_ack(irq).map_err(|error| {
                    self.map_hostcall_substrate_error(
                        backend,
                        code,
                        spec,
                        "IrqAuthority",
                        "irq_ack",
                        error,
                    )
                })?;
                Ok(VisaHostcallValue::None)
            }
            VisaHostcallPayload::IrqMask { irq } => {
                backend.irq_mask(irq).map_err(|error| {
                    self.map_hostcall_substrate_error(
                        backend,
                        code,
                        spec,
                        "IrqAuthority",
                        "irq_mask",
                        error,
                    )
                })?;
                Ok(VisaHostcallValue::None)
            }
            VisaHostcallPayload::IrqUnmask { irq } => {
                backend.irq_unmask(irq).map_err(|error| {
                    self.map_hostcall_substrate_error(
                        backend,
                        code,
                        spec,
                        "IrqAuthority",
                        "irq_unmask",
                        error,
                    )
                })?;
                Ok(VisaHostcallValue::None)
            }
            VisaHostcallPayload::SnapshotEnter => {
                let barrier = backend.enter_snapshot_barrier().map_err(|error| {
                    self.map_hostcall_substrate_error(
                        backend,
                        code,
                        spec,
                        "SnapshotAuthority",
                        "enter_snapshot_barrier",
                        error,
                    )
                })?;
                Ok(VisaHostcallValue::SnapshotBarrier(barrier))
            }
            VisaHostcallPayload::SnapshotExit { barrier } => {
                backend.exit_snapshot_barrier(barrier).map_err(|error| {
                    self.map_hostcall_substrate_error(
                        backend,
                        code,
                        spec,
                        "SnapshotAuthority",
                        "exit_snapshot_barrier",
                        error,
                    )
                })?;
                Ok(VisaHostcallValue::None)
            }
        }
    }

    fn map_hostcall_substrate_error<B: VisaSubstrate + ?Sized>(
        &mut self,
        backend: &mut B,
        code: &CodeObject,
        spec: &HostcallSpec,
        authority: &'static str,
        operation: &'static str,
        error: SubstrateError,
    ) -> VisaRuntimeError {
        let requester = SubstrateRequester::new(code.package.clone())
            .with_artifact(ArtifactImageRef::new(code.artifact_id, 1))
            .with_store(StoreRef::new(
                code.bound_store.unwrap_or(0),
                code.bound_store_generation.unwrap_or(0),
            ));
        let _ = self.substrate_error(backend, authority, operation, requester, error.clone());
        VisaRuntimeError::SubstrateDispatch {
            authority,
            operation: if operation.is_empty() {
                static_operation(&spec.operation)
            } else {
                operation
            },
            error,
        }
    }

    fn substrate_error<B: VisaSubstrate + ?Sized>(
        &mut self,
        backend: &mut B,
        authority: &'static str,
        operation: &'static str,
        requester: SubstrateRequester,
        error: SubstrateError,
    ) -> Result<(), VisaRuntimeError> {
        if let SubstrateError::Unsupported { authority, operation } = error {
            self.semantic.record_substrate_unsupported(
                authority,
                operation,
                Some(requester.subject.clone()),
                requester.artifact.map(|artifact| artifact.id),
                requester.store.map(|store| store.id),
            );
            let event = SubstrateEvent::unsupported(authority, operation, Some(requester));
            let _ = backend.push_event(event);
            self.events.push(VisaRuntimeEvent::SubstrateUnsupported { authority, operation });
            return Err(VisaRuntimeError::SubstrateDispatch { authority, operation, error });
        }
        Err(VisaRuntimeError::SubstrateDispatch { authority, operation, error })
    }

    fn store_record(&self, store: u64) -> Result<&ManagedStoreRecord, VisaRuntimeError> {
        self.store_manager.record(store).ok_or(VisaRuntimeError::MissingStore(store))
    }

    fn store_generation(&self, store: u64) -> Result<u64, VisaRuntimeError> {
        Ok(self.store_record(store)?.store.generation)
    }

    fn code_object(&self, code: CodeObjectId) -> Result<&CodeObject, VisaRuntimeError> {
        self.publisher.object(code).ok_or(VisaRuntimeError::MissingCodeObject(code))
    }

    fn capability_generation(&self, subject: &str, spec: &HostcallSpec) -> u64 {
        self.ledger
            .check(subject, &spec.object, &spec.operation)
            .map(|record| record.generation)
            .unwrap_or(0)
    }

    /// Restore portable vISA state from a contract graph snapshot.
    /// The input must already be a portable subset; full snapshots with
    /// host-specific records are rejected so migration cannot silently drop
    /// substrate state.
    pub fn restore_portable_subset(
        &mut self,
        snapshot: &ContractGraphSnapshot,
    ) -> Result<(), VisaRuntimeError> {
        let non_portable = snapshot.non_portable_summary();
        if !non_portable.is_empty() {
            return Err(VisaRuntimeError::NonPortableSnapshot(non_portable));
        }
        if let Some(field) = unsupported_portable_record(snapshot) {
            return Err(VisaRuntimeError::InvalidPortableSnapshot(field));
        }

        let mut semantic = SemanticGraph::with_runtime_mode(self.config.runtime_mode);
        for task in &snapshot.tasks {
            if !semantic.restore_task_record(task.clone()) {
                return Err(VisaRuntimeError::InvalidPortableSnapshot("invalid task record"));
            }
        }

        for store_record in &snapshot.stores {
            if !semantic.restore_store_record(store_record.clone()) {
                return Err(VisaRuntimeError::InvalidPortableSnapshot("invalid store record"));
            }
        }

        for activation in &snapshot.runtime_activations {
            if !semantic.restore_runtime_activation_record(activation.clone()) {
                return Err(VisaRuntimeError::InvalidPortableSnapshot(
                    "invalid runtime activation record",
                ));
            }
        }

        let mut ledger = CapabilityLedger::new();
        for cap in &snapshot.capabilities {
            if !ledger.restore_record(cap.clone()) {
                return Err(VisaRuntimeError::InvalidPortableSnapshot("invalid capability record"));
            }
        }

        let mut registry = ArtifactRegistry::new();
        if !registry.restore_verified_records(&snapshot.artifacts) {
            return Err(VisaRuntimeError::InvalidPortableSnapshot("invalid artifact record"));
        }

        let code_tombstones = tombstones_for_kind(snapshot, ContractObjectKind::CodeObject);
        let mut publisher = CodePublisher::new();
        if !publisher.restore_records(&snapshot.code_objects, &code_tombstones) {
            return Err(VisaRuntimeError::InvalidPortableSnapshot("invalid code object record"));
        }

        let managed_store_records: Vec<ManagedStoreRecord> = snapshot
            .stores
            .iter()
            .cloned()
            .map(|store| ManagedStoreRecord {
                resource_arena: format!("store-arena:{}", store.package),
                rebind_policy: "restore".to_string(),
                store,
            })
            .collect();
        let store_tombstones = tombstones_for_kind(snapshot, ContractObjectKind::Store);
        let mut store_manager = TargetStoreManager::new();
        if !store_manager.restore_records(&managed_store_records, &store_tombstones) {
            return Err(VisaRuntimeError::InvalidPortableSnapshot("invalid managed store record"));
        }

        let executor_tombstones: Vec<TombstoneRecord> = snapshot
            .tombstones
            .iter()
            .filter(|tombstone| {
                !matches!(
                    tombstone.kind,
                    ContractObjectKind::CodeObject | ContractObjectKind::Store
                )
            })
            .cloned()
            .collect();
        let mut executor = TargetExecutor::new();
        if !executor.restore_records(
            &snapshot.activations,
            &snapshot.traps,
            &snapshot.hostcalls,
            &snapshot.cleanup_transactions,
            &executor_tombstones,
        ) {
            return Err(VisaRuntimeError::InvalidPortableSnapshot("invalid executor record"));
        }

        self.semantic = semantic;
        self.registry = registry;
        self.publisher = publisher;
        self.store_manager = store_manager;
        self.executor = executor;
        self.ledger = ledger;
        self.events.clear();
        self.next_command_id = 1;
        self.publish_runtime_boundaries();
        Ok(())
    }

    pub fn snapshot(&self) -> ContractGraphSnapshot {
        let cap_records = self.ledger.records().to_vec();
        let mut tombstones = Vec::new();
        tombstones.extend_from_slice(self.publisher.tombstones());
        tombstones.extend_from_slice(self.store_manager.tombstones());
        tombstones.extend_from_slice(self.executor.tombstones());
        let inputs = ContractGraphSnapshotInputs {
            claimed_evidence_level: self.config.evidence_level,
            artifacts: self.registry.verified(),
            code_objects: self.publisher.objects(),
            activations: self.executor.activations(),
            traps: self.executor.traps(),
            hostcalls: self.executor.hostcall_trace(),
            capabilities: &cap_records,
            cleanup_transactions: self.executor.cleanup_transactions(),
            tombstones: &tombstones,
            ..Default::default()
        };
        self.semantic.snapshot_with(inputs)
    }

    pub fn evidence_snapshot(&self) -> VisaRuntimeEvidenceSnapshot {
        let event_log = self.semantic.event_log();
        let authority_extractions = event_log
            .events()
            .iter()
            .filter_map(|event| match &event.kind {
                EventKind::SubstrateAuthorityExtracted {
                    authority,
                    operation,
                    requester,
                    artifact,
                    store,
                    capability,
                    capability_generation,
                } => Some(VisaSubstrateAuthorityExtractionEvidence {
                    event_id: event.id,
                    event_epoch: event.epoch,
                    authority: authority.clone(),
                    operation: operation.clone(),
                    requester: requester.clone(),
                    artifact_id: *artifact,
                    store_id: *store,
                    capability_id: *capability,
                    capability_generation: *capability_generation,
                }),
                _ => None,
            })
            .collect();
        let unsupported_substrate_events = event_log
            .events()
            .iter()
            .filter_map(|event| match &event.kind {
                EventKind::SubstrateUnsupported {
                    authority,
                    operation,
                    requester,
                    artifact,
                    store,
                } => Some(VisaSubstrateUnsupportedEvidence {
                    event_id: event.id,
                    event_epoch: event.epoch,
                    authority: authority.clone(),
                    operation: operation.clone(),
                    requester: requester.clone(),
                    artifact_id: *artifact,
                    store_id: *store,
                }),
                _ => None,
            })
            .collect();

        VisaRuntimeEvidenceSnapshot {
            contract_graph: self.snapshot(),
            event_log_cursor: event_log.cursor(),
            runtime_events: self.events.clone(),
            authority_extractions,
            unsupported_substrate_events,
        }
    }

    pub fn record_trap(&mut self, activation_id: ActivationId, store_id: u64, detail: &str) {
        let activation = self.executor.activations().iter().find(|a| a.id == activation_id);
        let code_object = activation.and_then(|a| self.publisher.object(a.code_object));

        self.executor.synthetic_trap(
            semantic_core::target_executor::TargetTrapClass::GuestTrap,
            store_id,
            Some(activation_id),
            code_object,
            None,
            detail,
        );
    }

    fn next_command_id(&mut self) -> u64 {
        let id = self.next_command_id;
        self.next_command_id += 1;
        id
    }
}

fn tombstones_for_kind(
    snapshot: &ContractGraphSnapshot,
    kind: ContractObjectKind,
) -> Vec<TombstoneRecord> {
    snapshot.tombstones.iter().filter(|tombstone| tombstone.kind == kind).cloned().collect()
}

fn unsupported_portable_record(snapshot: &ContractGraphSnapshot) -> Option<&'static str> {
    macro_rules! reject {
        ($field:ident) => {
            if !snapshot.$field.is_empty() {
                return Some(concat!("unsupported portable record: ", stringify!($field)));
            }
        };
    }

    reject!(target_feature_sets);
    reject!(vector_states);
    reject!(simd_fault_injections);
    reject!(simd_benchmarks);
    reject!(simd_context_switch_benchmarks);
    reject!(framebuffer_objects);
    reject!(display_objects);
    reject!(display_capabilities);
    reject!(framebuffer_window_leases);
    reject!(framebuffer_mappings);
    reject!(framebuffer_writes);
    reject!(framebuffer_flush_regions);
    reject!(framebuffer_dirty_regions);
    reject!(display_event_logs);
    reject!(display_cleanups);
    reject!(display_snapshot_barriers);
    reject!(display_panic_last_frames);
    reject!(framebuffer_benchmarks);
    reject!(integrated_display_scheduler_loads);
    reject!(integrated_snapshot_io_lease_barriers);
    reject!(integrated_code_publish_smp_workloads);
    reject!(integrated_display_panics);
    reject!(integrated_osctl_trace_replays);
    reject!(integrated_smp_preemption_cleanups);
    reject!(integrated_smp_network_faults);
    reject!(integrated_disk_preempt_faults);
    reject!(integrated_simd_migrations);
    reject!(integrated_network_disk_ios);
    reject!(network_benchmarks);
    reject!(block_benchmarks);
    reject!(fake_block_backends);
    reject!(network_driver_cleanups);
    reject!(device_objects);
    reject!(packet_device_objects);
    reject!(network_stack_adapters);
    reject!(socket_objects);
    reject!(virtio_net_backends);
    reject!(io_cleanups);
    reject!(block_pending_io_policies);
    reject!(block_waits);
    reject!(block_request_objects);
    reject!(block_device_objects);
    reject!(block_range_objects);
    reject!(block_request_queues);
    reject!(block_dma_buffers);
    reject!(harts);
    reject!(runnable_queues);
    reject!(scheduler_decisions);
    reject!(activation_contexts);
    reject!(activation_migrations);
    reject!(smp_safe_points);
    reject!(stop_the_world_rendezvous);
    reject!(smp_code_publish_barriers);
    reject!(saved_contexts);
    reject!(timer_interrupts);
    reject!(remote_preempts);
    reject!(activation_cleanups);
    reject!(smp_cleanup_quiescence);
    reject!(smp_snapshot_barriers);
    reject!(smp_stress_runs);
    reject!(preemptions);
    reject!(activation_resumes);
    reject!(waits);
    reject!(external_objects);
    reject!(explicit_edges);
    None
}

fn semantic_image_from_descriptor(
    descriptor: VisaArtifactDescriptor,
    payload_len: usize,
) -> TargetArtifactImage {
    let mut image = TargetArtifactImage::new(
        descriptor.id,
        &descriptor.package,
        &descriptor.artifact_name,
        &descriptor.role,
        descriptor.target_profile.as_str(),
        &descriptor.artifact_hash,
        &descriptor.abi_fingerprint,
        &descriptor.manifest_binding_hash,
        &descriptor.code_hash,
        descriptor.memory_plan,
    );
    image.hash_status = descriptor.hash_status;
    image.signature_scheme = descriptor.signature_scheme;
    image.signature_status = descriptor.signature_status;
    image.signature_verified = descriptor.signature_verified;
    image.signer = descriptor.signer;
    image.imports = descriptor.imports;
    image.exports = descriptor.exports;
    image.capabilities = descriptor.capabilities;
    image.hostcalls = descriptor.hostcalls;
    image.payload_len = payload_len;
    image
}

fn grant_verified_capabilities(
    ledger: &mut CapabilityLedger,
    verified: &VerifiedArtifact,
    store_id: u64,
    store_generation: u64,
) -> Result<(), VisaRuntimeError> {
    for capability in &verified.capabilities {
        let operations = capability.operations.iter().map(String::as_str).collect::<Vec<_>>();
        ledger
            .grant_manifest_binding(
                &verified.package,
                &capability.object,
                &operations,
                &capability.lifetime,
                capability.class,
                Some(store_id),
                Some(store_generation),
                None,
                "vms-runtime",
            )
            .map_err(|error| VisaRuntimeError::CapabilityGrant(error.message()))?;
    }
    Ok(())
}

fn capability_handle_arg_for(
    ledger: &CapabilityLedger,
    subject: &str,
    spec: &HostcallSpec,
) -> Option<CapabilityHandleArg> {
    let capability = ledger.check(subject, &spec.object, &spec.operation).ok()?;
    let index =
        capability.operations.as_slice().iter().position(|right| right == &spec.operation)?;
    Some(CapabilityHandleArg::from_record(capability, 1u64 << index, &[spec.operation.as_str()]))
}

fn substrate_authority_for_payload(
    payload: &VisaHostcallPayload,
) -> Option<(&'static str, &'static str)> {
    match payload {
        VisaHostcallPayload::None => None,
        VisaHostcallPayload::ConsoleWrite { .. } => Some(("ConsoleAuthority", "console_write")),
        VisaHostcallPayload::TimerNow => Some(("TimerAuthority", "now")),
        VisaHostcallPayload::TimerArm { .. } => Some(("TimerAuthority", "arm_timer")),
        VisaHostcallPayload::GuestMemoryCopyIn { .. } => Some(("GuestMemoryAuthority", "copyin")),
        VisaHostcallPayload::GuestMemoryCopyOut { .. } => Some(("GuestMemoryAuthority", "copyout")),
        VisaHostcallPayload::DmwMap { .. } => Some(("DmwAuthority", "map_user_window")),
        VisaHostcallPayload::DmwUnmap { .. } => Some(("DmwAuthority", "unmap_user_window")),
        VisaHostcallPayload::MmioRead32 { .. } => Some(("MmioAuthority", "mmio_read32")),
        VisaHostcallPayload::MmioWrite32 { .. } => Some(("MmioAuthority", "mmio_write32")),
        VisaHostcallPayload::DmaAlloc { .. } => Some(("DmaAuthority", "dma_alloc")),
        VisaHostcallPayload::DmaFree { .. } => Some(("DmaAuthority", "dma_free")),
        VisaHostcallPayload::IrqAck { .. } => Some(("IrqAuthority", "irq_ack")),
        VisaHostcallPayload::IrqMask { .. } => Some(("IrqAuthority", "irq_mask")),
        VisaHostcallPayload::IrqUnmask { .. } => Some(("IrqAuthority", "irq_unmask")),
        VisaHostcallPayload::SnapshotEnter => Some(("SnapshotAuthority", "enter_snapshot_barrier")),
        VisaHostcallPayload::SnapshotExit { .. } => {
            Some(("SnapshotAuthority", "exit_snapshot_barrier"))
        }
    }
}

fn requester_for(artifact: &VerifiedArtifact) -> SubstrateRequester {
    SubstrateRequester::new(artifact.package.clone())
}

fn stronger_profile(left: SubstrateProfile, right: SubstrateProfile) -> SubstrateProfile {
    if left.satisfies(right) { left } else { right }
}

fn static_operation(operation: &str) -> &'static str {
    match operation {
        "console_write" => "console_write",
        "now" => "now",
        "arm_timer" => "arm_timer",
        "copyin" => "copyin",
        "copyout" => "copyout",
        "map_user_window" => "map_user_window",
        "unmap_user_window" => "unmap_user_window",
        "mmio_read32" => "mmio_read32",
        "mmio_write32" => "mmio_write32",
        "dma_alloc" => "dma_alloc",
        "dma_free" => "dma_free",
        "irq_ack" => "irq_ack",
        "irq_mask" => "irq_mask",
        "irq_unmask" => "irq_unmask",
        "enter_snapshot_barrier" => "enter_snapshot_barrier",
        "exit_snapshot_barrier" => "exit_snapshot_barrier",
        _ => "hostcall",
    }
}

pub mod personality {
    pub mod native {
        use alloc::{string::String, vec::Vec};

        use semantic_core::target_executor::{
            HostcallCategory, HostcallSpec, TargetCapabilitySpec,
        };
        use substrate_api::{
            DmaAllocRequest, DmaBufferCapability, IrqLine, MmioRegionRef, SnapshotBarrierRef,
            UserMemoryHandle, WaitTokenRef, WindowLeaseRef, WindowPerms,
        };
        use visa_profile::SubstrateProfile;

        use crate::{VisaArtifactDescriptor, VisaHostcallPayload};

        pub const VISA_CONSOLE_WRITE: u32 = 1;
        pub const VISA_TIMER_NOW: u32 = 2;
        pub const VISA_TIMER_ARM: u32 = 3;
        pub const VISA_MEMORY_COPYIN: u32 = 4;
        pub const VISA_MEMORY_COPYOUT: u32 = 5;
        pub const VISA_DMW_MAP: u32 = 6;
        pub const VISA_DMW_UNMAP: u32 = 7;
        pub const VISA_MMIO_READ32: u32 = 8;
        pub const VISA_MMIO_WRITE32: u32 = 9;
        pub const VISA_DMA_ALLOC: u32 = 10;
        pub const VISA_DMA_FREE: u32 = 11;
        pub const VISA_IRQ_ACK: u32 = 12;
        pub const VISA_IRQ_MASK: u32 = 13;
        pub const VISA_IRQ_UNMASK: u32 = 14;
        pub const VISA_SNAPSHOT_ENTER: u32 = 15;
        pub const VISA_SNAPSHOT_EXIT: u32 = 16;

        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct VisaNativePersonality {
            pub package: String,
            pub profile: SubstrateProfile,
        }

        impl VisaNativePersonality {
            pub fn new(package: &str, profile: SubstrateProfile) -> Self {
                Self { package: package.into(), profile }
            }

            pub fn descriptor(&self, artifact_id: u64) -> VisaArtifactDescriptor {
                let mut descriptor = VisaArtifactDescriptor::new(
                    artifact_id,
                    &self.package,
                    "visa-native-artifact",
                    self.profile,
                )
                .with_role("visa-native-workload")
                .with_hostcall(HostcallSpec::new(
                    VISA_CONSOLE_WRITE,
                    "visa.console.write",
                    HostcallCategory::Service,
                    "visa.console",
                    "write",
                    false,
                ))
                .with_hostcall(HostcallSpec::new(
                    VISA_TIMER_NOW,
                    "visa.timer.now",
                    HostcallCategory::Timer,
                    "visa.timer",
                    "now",
                    false,
                ))
                .with_hostcall(HostcallSpec::new(
                    VISA_TIMER_ARM,
                    "visa.timer.arm",
                    HostcallCategory::Timer,
                    "visa.timer",
                    "arm",
                    true,
                ));
                descriptor.capabilities.push(TargetCapabilitySpec::new(
                    "visa.timer",
                    &["now", "arm"],
                    "activation",
                ));

                if self.profile.satisfies(SubstrateProfile::GuestFrontend) {
                    descriptor = descriptor
                        .with_hostcall(HostcallSpec::new(
                            VISA_MEMORY_COPYIN,
                            "visa.memory.copyin",
                            HostcallCategory::GuestMemory,
                            "visa.memory",
                            "copyin",
                            false,
                        ))
                        .with_hostcall(HostcallSpec::new(
                            VISA_MEMORY_COPYOUT,
                            "visa.memory.copyout",
                            HostcallCategory::GuestMemory,
                            "visa.memory",
                            "copyout",
                            false,
                        ))
                        .with_hostcall(HostcallSpec::new(
                            VISA_DMW_MAP,
                            "visa.dmw.map",
                            HostcallCategory::Dmw,
                            "visa.dmw",
                            "map",
                            false,
                        ))
                        .with_hostcall(HostcallSpec::new(
                            VISA_DMW_UNMAP,
                            "visa.dmw.unmap",
                            HostcallCategory::Dmw,
                            "visa.dmw",
                            "unmap",
                            false,
                        ));
                    descriptor.capabilities.push(TargetCapabilitySpec::new(
                        "visa.memory",
                        &["copyin", "copyout"],
                        "activation",
                    ));
                    descriptor.capabilities.push(TargetCapabilitySpec::new(
                        "visa.dmw",
                        &["map", "unmap"],
                        "activation",
                    ));
                }

                if self.profile.satisfies(SubstrateProfile::DeviceCapable) {
                    descriptor = descriptor
                        .with_hostcall(HostcallSpec::new(
                            VISA_MMIO_READ32,
                            "visa.mmio.read32",
                            HostcallCategory::Mmio,
                            "visa.mmio",
                            "read32",
                            false,
                        ))
                        .with_hostcall(HostcallSpec::new(
                            VISA_MMIO_WRITE32,
                            "visa.mmio.write32",
                            HostcallCategory::Mmio,
                            "visa.mmio",
                            "write32",
                            false,
                        ))
                        .with_hostcall(HostcallSpec::new(
                            VISA_DMA_ALLOC,
                            "visa.dma.alloc",
                            HostcallCategory::Dma,
                            "visa.dma",
                            "alloc",
                            false,
                        ))
                        .with_hostcall(HostcallSpec::new(
                            VISA_DMA_FREE,
                            "visa.dma.free",
                            HostcallCategory::Dma,
                            "visa.dma",
                            "free",
                            false,
                        ))
                        .with_hostcall(HostcallSpec::new(
                            VISA_IRQ_ACK,
                            "visa.irq.ack",
                            HostcallCategory::Irq,
                            "visa.irq",
                            "ack",
                            false,
                        ))
                        .with_hostcall(HostcallSpec::new(
                            VISA_IRQ_MASK,
                            "visa.irq.mask",
                            HostcallCategory::Irq,
                            "visa.irq",
                            "mask",
                            false,
                        ))
                        .with_hostcall(HostcallSpec::new(
                            VISA_IRQ_UNMASK,
                            "visa.irq.unmask",
                            HostcallCategory::Irq,
                            "visa.irq",
                            "unmask",
                            false,
                        ));
                    descriptor.capabilities.push(TargetCapabilitySpec::new(
                        "visa.mmio",
                        &["read32", "write32"],
                        "activation",
                    ));
                    descriptor.capabilities.push(TargetCapabilitySpec::new(
                        "visa.dma",
                        &["alloc", "free"],
                        "activation",
                    ));
                    descriptor.capabilities.push(TargetCapabilitySpec::new(
                        "visa.irq",
                        &["ack", "mask", "unmask"],
                        "activation",
                    ));
                }

                if self.profile.satisfies(SubstrateProfile::SnapshotReplayCapable) {
                    descriptor = descriptor
                        .with_hostcall(HostcallSpec::new(
                            VISA_SNAPSHOT_ENTER,
                            "visa.snapshot.enter",
                            HostcallCategory::Snapshot,
                            "visa.snapshot",
                            "enter",
                            false,
                        ))
                        .with_hostcall(HostcallSpec::new(
                            VISA_SNAPSHOT_EXIT,
                            "visa.snapshot.exit",
                            HostcallCategory::Snapshot,
                            "visa.snapshot",
                            "exit",
                            false,
                        ));
                    descriptor.capabilities.push(TargetCapabilitySpec::new(
                        "visa.snapshot",
                        &["enter", "exit"],
                        "activation",
                    ));
                }

                descriptor.exports.push("visa_start".into());
                descriptor
            }

            pub fn console_write(&self, bytes: &[u8]) -> VisaHostcallPayload {
                VisaHostcallPayload::ConsoleWrite { bytes: Vec::from(bytes) }
            }

            pub const fn timer_now(&self) -> VisaHostcallPayload {
                VisaHostcallPayload::TimerNow
            }

            pub const fn timer_arm(
                &self,
                deadline_ticks: u64,
                token: WaitTokenRef,
            ) -> VisaHostcallPayload {
                VisaHostcallPayload::TimerArm { deadline_ticks, token }
            }

            pub const fn memory_copyin(
                &self,
                memory: UserMemoryHandle,
                ptr: u64,
                len: usize,
            ) -> VisaHostcallPayload {
                VisaHostcallPayload::GuestMemoryCopyIn { memory, ptr, len }
            }

            pub fn memory_copyout(
                &self,
                memory: UserMemoryHandle,
                ptr: u64,
                bytes: &[u8],
            ) -> VisaHostcallPayload {
                VisaHostcallPayload::GuestMemoryCopyOut { memory, ptr, bytes: Vec::from(bytes) }
            }

            pub const fn dmw_map(
                &self,
                memory: UserMemoryHandle,
                ptr: u64,
                len: usize,
                perms: WindowPerms,
            ) -> VisaHostcallPayload {
                VisaHostcallPayload::DmwMap { memory, ptr, len, perms }
            }

            pub const fn dmw_unmap(&self, lease: WindowLeaseRef) -> VisaHostcallPayload {
                VisaHostcallPayload::DmwUnmap { lease }
            }

            pub const fn mmio_read32(
                &self,
                region: MmioRegionRef,
                offset: u64,
            ) -> VisaHostcallPayload {
                VisaHostcallPayload::MmioRead32 { region, offset }
            }

            pub const fn mmio_write32(
                &self,
                region: MmioRegionRef,
                offset: u64,
                value: u32,
            ) -> VisaHostcallPayload {
                VisaHostcallPayload::MmioWrite32 { region, offset, value }
            }

            pub const fn dma_alloc(&self, request: DmaAllocRequest) -> VisaHostcallPayload {
                VisaHostcallPayload::DmaAlloc { request }
            }

            pub const fn dma_free(&self, capability: DmaBufferCapability) -> VisaHostcallPayload {
                VisaHostcallPayload::DmaFree { capability }
            }

            pub const fn irq_ack(&self, irq: IrqLine) -> VisaHostcallPayload {
                VisaHostcallPayload::IrqAck { irq }
            }

            pub const fn irq_mask(&self, irq: IrqLine) -> VisaHostcallPayload {
                VisaHostcallPayload::IrqMask { irq }
            }

            pub const fn irq_unmask(&self, irq: IrqLine) -> VisaHostcallPayload {
                VisaHostcallPayload::IrqUnmask { irq }
            }

            pub const fn snapshot_enter(&self) -> VisaHostcallPayload {
                VisaHostcallPayload::SnapshotEnter
            }

            pub const fn snapshot_exit(&self, barrier: SnapshotBarrierRef) -> VisaHostcallPayload {
                VisaHostcallPayload::SnapshotExit { barrier }
            }
        }
    }

    pub mod wasi {
        use alloc::{string::String, vec::Vec};

        use semantic_core::target_executor::{
            HostcallCategory, HostcallSpec, TargetCapabilitySpec,
        };
        use substrate_api::WaitTokenRef;
        use visa_profile::SubstrateProfile;

        use crate::{VisaArtifactDescriptor, VisaHostcallPayload};

        pub const WASI_FD_WRITE: u32 = 1;
        pub const WASI_CLOCK_TIME_GET: u32 = 2;
        pub const WASI_TIMER_ARM: u32 = 3;

        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct WasiPersonality {
            pub package: String,
            pub profile: SubstrateProfile,
        }

        impl WasiPersonality {
            pub fn new(package: &str, profile: SubstrateProfile) -> Self {
                Self { package: package.into(), profile }
            }

            pub fn descriptor(&self, artifact_id: u64) -> VisaArtifactDescriptor {
                let mut descriptor = VisaArtifactDescriptor::new(
                    artifact_id,
                    &self.package,
                    "wasi-personality",
                    self.profile,
                )
                .with_role("frontend-personality")
                .with_hostcall(HostcallSpec::new(
                    WASI_FD_WRITE,
                    "wasi.fd_write",
                    HostcallCategory::Service,
                    "wasi.fd",
                    "write",
                    false,
                ))
                .with_hostcall(HostcallSpec::new(
                    WASI_CLOCK_TIME_GET,
                    "wasi.clock_time_get",
                    HostcallCategory::Timer,
                    "timer.wasi",
                    "read",
                    false,
                ))
                .with_hostcall(HostcallSpec::new(
                    WASI_TIMER_ARM,
                    "wasi.timer_arm",
                    HostcallCategory::Timer,
                    "timer.wasi",
                    "arm",
                    true,
                ));
                descriptor.capabilities.push(TargetCapabilitySpec::new(
                    "timer.wasi",
                    &["read", "arm"],
                    "activation",
                ));
                descriptor.exports.push("wasi_start".into());
                descriptor
            }

            pub fn fd_write(&self, bytes: &[u8]) -> VisaHostcallPayload {
                VisaHostcallPayload::ConsoleWrite { bytes: Vec::from(bytes) }
            }

            pub const fn clock_time_get(&self) -> VisaHostcallPayload {
                VisaHostcallPayload::TimerNow
            }

            pub const fn timer_arm(
                &self,
                deadline_ticks: u64,
                token: WaitTokenRef,
            ) -> VisaHostcallPayload {
                VisaHostcallPayload::TimerArm { deadline_ticks, token }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use semantic_core::{EventKind, target_executor::HostcallCategory};
    use sha2::{Digest, Sha256};
    use substrate_api::SubstrateResult;
    use target_abi::{
        TargetArtifactHeaderV1, TargetSectionHeaderV1, canonical_zero_field_image_hash,
    };

    use super::*;

    const REQUIRED_SECTIONS: [SectionKindV1; 7] = [
        SectionKindV1::Manifest,
        SectionKindV1::CodeObject,
        SectionKindV1::HostcallImportTable,
        SectionKindV1::TrapMap,
        SectionKindV1::PcRangeTable,
        SectionKindV1::ProfileRequirements,
        SectionKindV1::Signature,
    ];

    #[derive(Default)]
    struct MockSubstrate {
        loaded: Vec<ArtifactImageRef>,
        published: Vec<(ArtifactImageRef, CodeObjectRef)>,
        console: Vec<u8>,
        fail_console: bool,
        timers: Vec<(VirtualTime, WaitTokenRef)>,
        events: Vec<SubstrateEvent>,
        now: u64,
    }

    impl ArtifactAuthority for MockSubstrate {
        fn load_artifact_image(&mut self, artifact: ArtifactImageRef) -> SubstrateResult<()> {
            self.loaded.push(artifact);
            Ok(())
        }
    }

    impl CodePublisherAuthority for MockSubstrate {
        fn publish_code(
            &mut self,
            artifact: ArtifactImageRef,
            code: CodeObjectRef,
        ) -> SubstrateResult<PublishedCodeRef> {
            self.published.push((artifact, code));
            Ok(PublishedCodeRef::new(code.id, code.generation))
        }
    }

    impl ConsoleAuthority for MockSubstrate {
        fn console_write(&mut self, bytes: &[u8]) -> SubstrateResult<usize> {
            if self.fail_console {
                return Err(SubstrateError::unsupported("ConsoleAuthority", "console_write"));
            }
            self.console.extend_from_slice(bytes);
            Ok(bytes.len())
        }
    }

    impl TimerAuthority for MockSubstrate {
        fn now(&self) -> SubstrateResult<VirtualTime> {
            Ok(VirtualTime::from_ticks(self.now))
        }

        fn arm_timer(&mut self, deadline: VirtualTime, token: WaitTokenRef) -> SubstrateResult<()> {
            self.timers.push((deadline, token));
            Ok(())
        }
    }

    impl EventQueueAuthority for MockSubstrate {
        fn push_event(&mut self, event: SubstrateEvent) -> SubstrateResult<()> {
            self.events.push(event);
            Ok(())
        }

        fn pop_event(&mut self) -> Option<SubstrateEvent> {
            if self.events.is_empty() { None } else { Some(self.events.remove(0)) }
        }
    }

    impl GuestMemoryAuthority for MockSubstrate {}
    impl DmwAuthority for MockSubstrate {}
    impl MmioAuthority for MockSubstrate {}
    impl DmaAuthority for MockSubstrate {}
    impl IrqAuthority for MockSubstrate {}
    impl SnapshotAuthority for MockSubstrate {}

    #[test]
    fn runtime_loads_artifact_publishes_code_and_starts_activation() {
        let mut runtime = VisaRuntime::new(VisaRuntimeConfig::for_profile(
            SubstrateProfile::SnapshotReplayCapable,
        ));
        let mut substrate = MockSubstrate::default();
        let artifact = fake_image(&REQUIRED_SECTIONS);
        let descriptor = VisaArtifactDescriptor::new(
            7,
            "demo",
            "demo-artifact",
            SubstrateProfile::GuestFrontend,
        )
        .with_hostcall(HostcallSpec::new(
            1,
            "demo.write",
            HostcallCategory::Service,
            "demo.console",
            "write",
            false,
        ));

        let loaded = runtime
            .load_artifact(VisaArtifactInput { bytes: &artifact, descriptor }, &mut substrate)
            .expect("load artifact");
        let activation = runtime
            .start_activation(&loaded, ActivationEntry::Symbol("entry".into()))
            .expect("start activation");

        assert_eq!(substrate.loaded, vec![ArtifactImageRef::new(7, 1)]);
        assert_eq!(substrate.published.len(), 1);
        assert_eq!(activation.artifact_id, 7);
        assert_eq!(runtime.semantic().runtime_activation_count(), 1);
        assert!(runtime.events().iter().any(|event| {
            matches!(event, VisaRuntimeEvent::ActivationStarted { activation_id: 1, .. })
        }));
    }

    #[test]
    fn runtime_rejects_profile_before_substrate_dispatch() {
        let mut runtime =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::SemanticHarness));
        let mut substrate = MockSubstrate::default();
        let artifact = fake_image(&REQUIRED_SECTIONS);
        let descriptor = VisaArtifactDescriptor::new(
            8,
            "device-driver",
            "device-driver-artifact",
            SubstrateProfile::DeviceCapable,
        );

        let err = runtime
            .load_artifact(VisaArtifactInput { bytes: &artifact, descriptor }, &mut substrate)
            .expect_err("profile gate rejects");

        assert!(matches!(err, VisaRuntimeError::ProfileGateRejected { .. }));
        assert!(substrate.loaded.is_empty());
        assert!(substrate.published.is_empty());
    }

    #[test]
    fn run_loop_loads_activates_and_repeats_hostcalls() {
        let personality =
            personality::wasi::WasiPersonality::new("wasi-app", SubstrateProfile::GuestFrontend);
        let mut runtime =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::GuestFrontend));
        let mut substrate = MockSubstrate { now: 42, ..MockSubstrate::default() };
        let artifact = fake_image(&REQUIRED_SECTIONS);
        let token = WaitTokenRef::new(31, 1);

        let report = runtime
            .run(
                VisaArtifactInput { bytes: &artifact, descriptor: personality.descriptor(9) },
                ActivationEntry::Symbol("wasi_start".into()),
                [
                    VisaExecutionStep::new(
                        personality::wasi::WASI_FD_WRITE,
                        personality.fd_write(b"hello"),
                    ),
                    VisaExecutionStep::new(
                        personality::wasi::WASI_CLOCK_TIME_GET,
                        personality.clock_time_get(),
                    ),
                    VisaExecutionStep::new(
                        personality::wasi::WASI_TIMER_ARM,
                        personality.timer_arm(75, token),
                    ),
                ],
                &mut substrate,
            )
            .expect("run wasi");

        assert_eq!(report.loaded.artifact_id, 9);
        assert_eq!(report.activation.activation_id, 1);
        assert_eq!(report.hostcalls.len(), 3);
        assert_eq!(report.hostcalls[0].value, VisaHostcallValue::U64(5));
        assert_eq!(report.hostcalls[1].value, VisaHostcallValue::U64(42));
        assert_eq!(report.hostcalls[2].value, VisaHostcallValue::None);
        assert_eq!(substrate.console, b"hello");
        assert_eq!(substrate.timers, vec![(VirtualTime::from_ticks(75), token)]);
        assert_eq!(runtime.executor().hostcall_trace().len(), 3);
        let extracted = runtime
            .semantic()
            .event_log()
            .events()
            .iter()
            .filter_map(|event| match &event.kind {
                EventKind::SubstrateAuthorityExtracted {
                    authority,
                    operation,
                    requester,
                    artifact,
                    store,
                    ..
                } => Some((
                    authority.as_str(),
                    operation.as_str(),
                    requester.as_deref(),
                    *artifact,
                    *store,
                    event.summary(),
                )),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(extracted.len(), 3);
        assert!(extracted.iter().any(
            |(authority, operation, requester, artifact, store, summary)| {
                *authority == "ConsoleAuthority"
                    && *operation == "console_write"
                    && *requester == Some("wasi-app")
                    && *artifact == Some(9)
                    && *store == Some(1)
                    && summary.contains("SubstrateAuthorityExtracted")
            }
        ));
        assert!(extracted.iter().any(|(authority, operation, ..)| {
            *authority == "TimerAuthority" && *operation == "now"
        }));
        assert!(extracted.iter().any(|(authority, operation, ..)| {
            *authority == "TimerAuthority" && *operation == "arm_timer"
        }));
        let summary = report.evidence_summary();
        assert_eq!(summary.hostcall_dispatches, 3);
        assert_eq!(summary.substrate_authority_extractions, 3);
        assert!(summary.can_claim_portable_artifact_execution);
        let evidence = runtime.evidence_snapshot();
        assert_eq!(evidence.event_log_cursor, runtime.semantic().event_log().cursor());
        assert_eq!(evidence.hostcall_trace_count(), 3);
        assert_eq!(evidence.authority_extraction_count(), 3);
        assert_eq!(evidence.unsupported_substrate_event_count(), 0);
        assert_eq!(evidence.contract_graph.artifacts.len(), 1);
        assert_eq!(evidence.contract_graph.code_objects.len(), 1);
        assert_eq!(evidence.contract_graph.activations.len(), 1);
        assert_eq!(evidence.contract_graph.hostcalls.len(), 3);
        assert_eq!(
            evidence.authority_extractions[0],
            VisaSubstrateAuthorityExtractionEvidence {
                event_id: evidence.authority_extractions[0].event_id,
                event_epoch: evidence.authority_extractions[0].event_epoch,
                authority: "ConsoleAuthority".into(),
                operation: "console_write".into(),
                requester: Some("wasi-app".into()),
                artifact_id: Some(9),
                store_id: Some(1),
                capability_id: None,
                capability_generation: None,
            }
        );
        assert!(report.events.iter().any(|event| {
            matches!(
                event,
                VisaRuntimeEvent::HostcallDispatched {
                    hostcall_number: personality::wasi::WASI_TIMER_ARM,
                    ..
                }
            )
        }));
    }

    #[test]
    fn failed_substrate_hostcall_does_not_commit_success_trace() {
        let personality =
            personality::wasi::WasiPersonality::new("wasi-app", SubstrateProfile::GuestFrontend);
        let mut runtime =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::GuestFrontend));
        let mut substrate = MockSubstrate { fail_console: true, ..MockSubstrate::default() };
        let artifact = fake_image(&REQUIRED_SECTIONS);

        let err = runtime
            .run(
                VisaArtifactInput { bytes: &artifact, descriptor: personality.descriptor(44) },
                ActivationEntry::Symbol("wasi_start".into()),
                [VisaExecutionStep::new(
                    personality::wasi::WASI_FD_WRITE,
                    personality.fd_write(b"blocked"),
                )],
                &mut substrate,
            )
            .expect_err("substrate dispatch failure must reject execution");

        assert!(matches!(
            err,
            VisaRuntimeError::SubstrateDispatch {
                authority: "ConsoleAuthority",
                operation: "console_write",
                ..
            }
        ));
        assert!(runtime.executor().hostcall_trace().is_empty());
        assert!(runtime.snapshot().hostcalls.is_empty());
        let evidence = runtime.evidence_snapshot();
        assert_eq!(evidence.hostcall_trace_count(), 0);
        assert_eq!(evidence.authority_extraction_count(), 0);
        assert_eq!(evidence.unsupported_substrate_event_count(), 1);
        assert_eq!(
            evidence.unsupported_substrate_events[0],
            VisaSubstrateUnsupportedEvidence {
                event_id: evidence.unsupported_substrate_events[0].event_id,
                event_epoch: evidence.unsupported_substrate_events[0].event_epoch,
                authority: "ConsoleAuthority".into(),
                operation: "console_write".into(),
                requester: Some("wasi-app".into()),
                artifact_id: Some(44),
                store_id: Some(1),
            }
        );
        assert_eq!(runtime.executor().activations()[0].generation, 1);
        assert!(
            !runtime.semantic().event_log().events().iter().any(|event| {
                matches!(&event.kind, EventKind::SubstrateAuthorityExtracted { .. })
            })
        );
        assert!(
            !runtime
                .events()
                .iter()
                .any(|event| matches!(event, VisaRuntimeEvent::HostcallDispatched { .. }))
        );
        assert!(!runtime.events().iter().any(|event| {
            matches!(event, VisaRuntimeEvent::SubstrateAuthorityExtracted { .. })
        }));
    }

    #[test]
    fn execution_summary_does_not_overclaim_weaker_evidence_boundary() {
        let personality =
            personality::wasi::WasiPersonality::new("wasi-app", SubstrateProfile::GuestFrontend);
        let mut runtime = VisaRuntime::new(VisaRuntimeConfig {
            required_profile: SubstrateProfile::GuestFrontend,
            reported_profile: SubstrateProfile::GuestFrontend,
            enforced_capabilities: SubstrateCapabilitySet::for_profile(
                SubstrateProfile::GuestFrontend,
            ),
            evidence_level: EvidenceBoundaryLevel::SemanticModel,
            runtime_mode: RuntimeMode::Production,
        });
        let mut substrate = MockSubstrate::default();
        let artifact = fake_image(&REQUIRED_SECTIONS);

        let report = runtime
            .run(
                VisaArtifactInput { bytes: &artifact, descriptor: personality.descriptor(27) },
                ActivationEntry::Symbol("wasi_start".into()),
                [VisaExecutionStep::new(
                    personality::wasi::WASI_FD_WRITE,
                    personality.fd_write(b"semantic-only"),
                )],
                &mut substrate,
            )
            .expect("run semantic-level workload");

        let summary = report.evidence_summary();
        assert!(summary.artifact_loaded);
        assert!(summary.code_published);
        assert!(summary.activation_started);
        assert_eq!(summary.hostcall_dispatches, report.hostcalls.len());
        assert_eq!(summary.substrate_authority_extractions, report.hostcalls.len());
        assert!(!summary.evidence_boundary_sufficient);
        assert!(!summary.can_claim_portable_artifact_execution);
    }

    #[test]
    fn visa_native_personality_runs_without_linux_or_wasi_frontend() {
        let personality = personality::native::VisaNativePersonality::new(
            "native-visa-app",
            SubstrateProfile::MinimalBareMetal,
        );
        let mut runtime =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::MinimalBareMetal));
        let mut substrate = MockSubstrate { now: 99, ..MockSubstrate::default() };
        let artifact = fake_image(&REQUIRED_SECTIONS);
        let token = WaitTokenRef::new(77, 1);

        let report = runtime
            .run(
                VisaArtifactInput { bytes: &artifact, descriptor: personality.descriptor(17) },
                ActivationEntry::Symbol("visa_start".into()),
                [
                    VisaExecutionStep::new(
                        personality::native::VISA_CONSOLE_WRITE,
                        personality.console_write(b"vISA"),
                    ),
                    VisaExecutionStep::new(
                        personality::native::VISA_TIMER_NOW,
                        personality.timer_now(),
                    ),
                    VisaExecutionStep::new(
                        personality::native::VISA_TIMER_ARM,
                        personality.timer_arm(128, token),
                    ),
                ],
                &mut substrate,
            )
            .expect("run native vISA workload");

        assert_eq!(report.loaded.artifact_id, 17);
        assert_eq!(report.activation.activation_id, 1);
        assert_eq!(report.hostcalls.len(), 3);
        assert_eq!(report.hostcalls[0].object, "visa.console");
        assert_eq!(report.hostcalls[1].object, "visa.timer");
        assert_eq!(report.hostcalls[2].operation, "arm");
        assert!(report.evidence_summary().can_claim_portable_artifact_execution);
        assert_eq!(substrate.console, b"vISA");
        assert_eq!(substrate.timers, vec![(VirtualTime::from_ticks(128), token)]);
        assert!(runtime.snapshot().artifacts.iter().any(|artifact| {
            artifact.role == "visa-native-workload"
                && artifact.artifact_name == "visa-native-artifact"
        }));
    }

    #[test]
    fn visa_native_descriptor_scales_with_substrate_profile() {
        let guest = personality::native::VisaNativePersonality::new(
            "guest",
            SubstrateProfile::GuestFrontend,
        )
        .descriptor(21);
        assert!(guest.hostcalls.iter().any(|h| h.object == "visa.memory"));
        assert!(!guest.hostcalls.iter().any(|h| h.object == "visa.mmio"));

        let device = personality::native::VisaNativePersonality::new(
            "device",
            SubstrateProfile::DeviceCapable,
        )
        .descriptor(22);
        assert!(device.hostcalls.iter().any(|h| h.object == "visa.mmio"));
        assert!(device.hostcalls.iter().any(|h| h.object == "visa.dma"));
        assert!(!device.hostcalls.iter().any(|h| h.object == "visa.snapshot"));

        let replay = personality::native::VisaNativePersonality::new(
            "replay",
            SubstrateProfile::SnapshotReplayCapable,
        )
        .descriptor(23);
        assert!(replay.hostcalls.iter().any(|h| h.object == "visa.snapshot"));
    }

    #[test]
    fn runtime_rejects_reported_profile_below_required_even_if_capabilities_exist() {
        let mut runtime = VisaRuntime::new(VisaRuntimeConfig {
            required_profile: SubstrateProfile::GuestFrontend,
            reported_profile: SubstrateProfile::SemanticHarness,
            enforced_capabilities: SubstrateCapabilitySet::for_profile(
                SubstrateProfile::GuestFrontend,
            ),
            evidence_level: EvidenceBoundaryLevel::PortableArtifactExecution,
            runtime_mode: RuntimeMode::Production,
        });
        let mut substrate = MockSubstrate::default();
        let artifact = fake_image(&REQUIRED_SECTIONS);
        let descriptor = VisaArtifactDescriptor::new(
            10,
            "profile-underclaim",
            "profile-underclaim-artifact",
            SubstrateProfile::GuestFrontend,
        );

        let err = runtime
            .load_artifact(VisaArtifactInput { bytes: &artifact, descriptor }, &mut substrate)
            .expect_err("reported profile gate rejects");

        assert!(matches!(err, VisaRuntimeError::ProfileGateRejected { .. }));
        assert!(substrate.loaded.is_empty());
    }

    fn fake_image(kinds: &[SectionKindV1]) -> Vec<u8> {
        let header_len = core::mem::size_of::<TargetArtifactHeaderV1>();
        let section_len = core::mem::size_of::<TargetSectionHeaderV1>();
        let payload_len = 16;
        let section_table_len = kinds.len() * section_len;
        let payload_base = header_len + section_table_len;
        let image_len = payload_base + kinds.len() * payload_len;
        let mut image = vec![0; image_len];

        let header = TargetArtifactHeaderV1::fake_riscv64(kinds.len() as u32, image_len as u64);
        header.write_to(&mut image).expect("header");

        for (index, kind) in kinds.iter().copied().enumerate() {
            let offset = payload_base + index * payload_len;
            image[offset..offset + payload_len].fill(kind as u32 as u8);
            let mut section =
                TargetSectionHeaderV1::new(kind, offset as u64, payload_len as u64, 1);
            section.hash = Sha256::digest(&image[offset..offset + payload_len]).into();
            let section_off = header_len + index * section_len;
            section.write_to(&mut image[section_off..section_off + section_len]).expect("section");
        }

        let mut header = TargetArtifactHeaderV1::parse(&image).expect("parse header");
        let (manifest_start, manifest_end) = section_payload_range(&image, SectionKindV1::Manifest);
        header.manifest_hash = Sha256::digest(&image[manifest_start..manifest_end]).into();
        header.write_to(&mut image).expect("manifest hash");
        refresh_image_hash(&mut image);
        image
    }

    fn section_payload_range(image: &[u8], kind: SectionKindV1) -> (usize, usize) {
        let header = TargetArtifactHeaderV1::parse(image).expect("header");
        let section_len = core::mem::size_of::<TargetSectionHeaderV1>();
        for index in 0..header.section_count as usize {
            let section_off = core::mem::size_of::<TargetArtifactHeaderV1>() + index * section_len;
            let section =
                TargetSectionHeaderV1::parse(&image[section_off..section_off + section_len])
                    .expect("section");
            if section.kind == kind {
                let start = section.offset as usize;
                return (start, start + section.len as usize);
            }
        }
        panic!("missing section")
    }

    fn refresh_image_hash(image: &mut [u8]) {
        let mut header = TargetArtifactHeaderV1::parse(image).expect("header");
        header.image_hash = [0; 32];
        header.write_to(image).expect("zero image hash");
        let hash = canonical_zero_field_image_hash(image).expect("canonical hash");
        let mut header = TargetArtifactHeaderV1::parse(image).expect("header");
        header.image_hash = hash;
        header.write_to(image).expect("image hash");
    }

    #[test]
    fn portable_state_survives_profile_change() {
        // Step 1: Run on DeviceCapable profile
        let mut rt_a =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::DeviceCapable));
        let mut substrate_a = MockSubstrate::default();
        let artifact = fake_image(&REQUIRED_SECTIONS);
        let descriptor = VisaArtifactDescriptor::new(
            1,
            "driver.fake_net",
            "fake-net-driver",
            SubstrateProfile::DeviceCapable,
        )
        .with_role("driver")
        .with_capability("mmio.virtio-net", &["map"], "store")
        .with_capability("irq.virtio-net", &["ack", "mask", "unmask"], "store");

        let loaded = rt_a
            .load_artifact(VisaArtifactInput { bytes: &artifact, descriptor }, &mut substrate_a)
            .expect("load device driver");
        rt_a.start_activation(&loaded, ActivationEntry::Symbol("init".into())).expect("activate");

        let snapshot_a = rt_a.snapshot();
        assert_eq!(
            snapshot_a.claimed_evidence_level,
            EvidenceBoundaryLevel::PortableArtifactExecution
        );
        assert!(!snapshot_a.artifacts.is_empty());
        assert!(!snapshot_a.code_objects.is_empty());
        assert!(!snapshot_a.activations.is_empty());
        assert!(!snapshot_a.stores.is_empty());
        assert!(!snapshot_a.capabilities.is_empty());

        let portable = snapshot_a.portable_subset();
        // Portable state must be self-consistent
        assert!(
            portable.non_portable_summary().is_empty(),
            "portable subset must have no non-portable state: {:?}",
            portable.non_portable_summary()
        );
        // Core portable records present
        assert!(!portable.stores.is_empty(), "portable must preserve stores");
        assert!(!portable.capabilities.is_empty(), "portable must preserve capabilities");

        // Step 2: Restore into SnapshotReplayCapable runtime
        let mut rt_b = VisaRuntime::new(VisaRuntimeConfig::for_profile(
            SubstrateProfile::SnapshotReplayCapable,
        ));
        rt_b.restore_portable_subset(&portable).expect("restore");
        assert!(
            rt_b.semantic().check_invariants().is_ok(),
            "restored semantic graph must remain invariant-clean"
        );

        // Step 3: Portable state preserved
        let snapshot_b = rt_b.snapshot();
        assert_eq!(snapshot_b.tasks, portable.tasks, "task identity must survive profile change");
        assert_eq!(
            snapshot_b.stores, portable.stores,
            "store identity must survive profile change"
        );
        assert_eq!(
            snapshot_b.runtime_activations, portable.runtime_activations,
            "semantic runtime activation identity must survive profile change"
        );
        assert_eq!(
            snapshot_b.capabilities, portable.capabilities,
            "capability identity must survive profile change"
        );
        assert_eq!(
            snapshot_b.artifacts, portable.artifacts,
            "artifact identity must survive profile change"
        );
        assert_eq!(
            snapshot_b.code_objects, portable.code_objects,
            "code object identity must survive profile change"
        );
        assert_eq!(
            snapshot_b.activations, portable.activations,
            "activation identity must survive profile change"
        );
    }

    #[test]
    fn restore_rejects_non_portable_snapshot_without_mutating_runtime() {
        let mut rt =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::DeviceCapable));
        let mut substrate = MockSubstrate::default();
        let artifact = fake_image(&REQUIRED_SECTIONS);
        let descriptor = VisaArtifactDescriptor::new(
            99,
            "old.pkg",
            "old-artifact",
            SubstrateProfile::MinimalBareMetal,
        );
        rt.load_artifact(VisaArtifactInput { bytes: &artifact, descriptor }, &mut substrate)
            .expect("load old artifact");
        let before = rt.snapshot();

        let mut graph = SemanticGraph::new();
        graph.ensure_task(1, FrontendKind::Supervisor, "non-portable");
        let resource =
            graph.register_resource(semantic_core::ResourceKind::BlockDevice, Some(1), "blk0");
        assert!(graph.record_device_object_with_id(
            1,
            "dev0",
            "block-device",
            resource,
            1,
            "virtio-blk",
            "pci",
            "vmos",
            "bench",
            "test",
        ));
        let non_portable = graph.snapshot();

        let error = rt
            .restore_portable_subset(&non_portable)
            .expect_err("non-portable snapshot must be rejected");
        assert!(matches!(error, VisaRuntimeError::NonPortableSnapshot(kinds) if !kinds.is_empty()));
        let after = rt.snapshot();
        assert_eq!(after.artifacts, before.artifacts);
        assert_eq!(after.code_objects, before.code_objects);
        assert_eq!(after.stores, before.stores);
        assert_eq!(after.capabilities, before.capabilities);
    }

    #[test]
    fn restore_rejects_unsupported_portable_records_without_mutating_runtime() {
        let mut rt =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::MinimalBareMetal));
        let before = rt.snapshot();

        let mut snapshot = ContractGraphSnapshot::default();
        snapshot.external_objects.push(semantic_core::ExternalObjectDeclaration::new(
            ContractObjectRef::new(ContractObjectKind::EventLog, 1, 1),
            "debugger",
            "external-event-log",
            "event-log",
        ));

        let error = rt
            .restore_portable_subset(&snapshot)
            .expect_err("unsupported portable fields must be rejected");
        assert_eq!(
            error,
            VisaRuntimeError::InvalidPortableSnapshot(
                "unsupported portable record: external_objects"
            )
        );
        assert_eq!(rt.snapshot().artifacts, before.artifacts);
        assert_eq!(rt.snapshot().code_objects, before.code_objects);
        assert_eq!(rt.snapshot().stores, before.stores);
    }

    #[test]
    fn restore_rejects_unsupported_tombstone_kind_without_mutating_runtime() {
        let mut rt =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::MinimalBareMetal));
        let before = rt.snapshot();
        let mut snapshot = before.portable_subset();
        snapshot.tombstones.push(TombstoneRecord::new(
            ContractObjectKind::DeviceObject,
            7,
            1,
            1,
            "device tombstone is not runtime-portable",
        ));

        let error = rt
            .restore_portable_subset(&snapshot)
            .expect_err("unsupported tombstone kind must be rejected");
        assert!(matches!(
            error,
            VisaRuntimeError::InvalidPortableSnapshot("invalid executor record")
        ));
        assert_eq!(rt.snapshot().artifacts, before.artifacts);
        assert_eq!(rt.snapshot().code_objects, before.code_objects);
        assert_eq!(rt.snapshot().stores, before.stores);
    }

    #[test]
    fn restore_clears_previous_runtime_owned_state() {
        let artifact = fake_image(&REQUIRED_SECTIONS);
        let mut substrate_a = MockSubstrate::default();
        let mut rt_a =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::MinimalBareMetal));
        let loaded_a = rt_a
            .load_artifact(
                VisaArtifactInput {
                    bytes: &artifact,
                    descriptor: VisaArtifactDescriptor::new(
                        1,
                        "portable.pkg",
                        "portable-artifact",
                        SubstrateProfile::MinimalBareMetal,
                    ),
                },
                &mut substrate_a,
            )
            .expect("load portable artifact");
        rt_a.start_activation(&loaded_a, ActivationEntry::Symbol("main".into()))
            .expect("activate portable artifact");
        let portable = rt_a.snapshot().portable_subset();

        let mut substrate_b = MockSubstrate::default();
        let mut rt_b =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::MinimalBareMetal));
        rt_b.load_artifact(
            VisaArtifactInput {
                bytes: &artifact,
                descriptor: VisaArtifactDescriptor::new(
                    99,
                    "stale.pkg",
                    "stale-artifact",
                    SubstrateProfile::MinimalBareMetal,
                ),
            },
            &mut substrate_b,
        )
        .expect("load stale artifact");

        rt_b.restore_portable_subset(&portable).expect("restore portable state");
        assert!(
            rt_b.semantic().check_invariants().is_ok(),
            "restore must rebuild graph-internal resource and fault-domain records"
        );
        let restored = rt_b.snapshot();
        assert_eq!(restored.artifacts, portable.artifacts);
        assert!(restored.artifacts.iter().all(|artifact| artifact.artifact_id != 99));

        let loaded_after_restore = rt_b
            .load_artifact(
                VisaArtifactInput {
                    bytes: &artifact,
                    descriptor: VisaArtifactDescriptor::new(
                        99,
                        "stale.pkg",
                        "stale-artifact",
                        SubstrateProfile::MinimalBareMetal,
                    ),
                },
                &mut substrate_b,
            )
            .expect("stale artifact id must be reusable after restore reset");
        let activation_after_restore = rt_b
            .start_activation(&loaded_after_restore, ActivationEntry::Symbol("main".into()))
            .expect("activation ids must continue after restored high watermark");
        let restored_activation_max =
            portable.activations.iter().map(|activation| activation.id).max().unwrap_or(0);
        assert!(activation_after_restore.activation_id > restored_activation_max);
        assert!(
            rt_b.snapshot()
                .runtime_activations
                .iter()
                .any(|activation| activation.id == activation_after_restore.activation_id)
        );
    }
}
