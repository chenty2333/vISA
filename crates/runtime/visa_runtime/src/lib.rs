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

use contract_core::{CONTRACT_GRAPH_SNAPSHOT_ARTIFACT_SCHEMA_VERSION, EvidenceBoundaryLevel};
use semantic_core::{
    ActivationId, ArtifactVerificationState, BoundaryKind, BoundaryStatus, CapabilityId,
    CapabilityLedger, CodeObjectId, CodePublishState, CommandEnvelope, ContractEdgeRecord,
    ContractGraphSnapshot, ContractGraphSnapshotInputs, EntrypointState, EventId, EventKind,
    ExternalObjectDeclaration, FrontendKind, Generation, HostcallClass, HostcallLinkState,
    MemoryLayoutState, NonPortableStateKind, RestartPolicy, RuntimeMode, SemanticCommand,
    SemanticGraph, SemanticWaitKind, StoreId, StoreState, TargetArtifactId, TrapSurfaceState,
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
use visa_profile::{
    AuthorityFamily, AuthorityMismatch, SubstrateCapabilitySet, SubstrateCompatibilityReport,
    SubstrateProfile,
};

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
    EventPush { event: SubstrateEvent },
    EventPop,
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
            Self::EventPush { .. } | Self::EventPop => [0; 6],
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

    const fn wait_token_out(&self) -> Option<WaitTokenRef> {
        match self {
            Self::TimerArm { token, .. } => Some(*token),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VisaHostcallValue {
    None,
    Bytes(GuestBytes),
    Event(Option<SubstrateEvent>),
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
                && hostcall_dispatches > 0
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
    pub denied_substrate_events: Vec<VisaSubstrateCapabilityDeniedEvidence>,
    pub profile_gate_rejections: Vec<VisaProfileGateRejectionEvidence>,
}

impl VisaRuntimeEvidenceSnapshot {
    pub fn authority_extraction_count(&self) -> usize {
        self.authority_extractions.len()
    }

    pub fn unsupported_substrate_event_count(&self) -> usize {
        self.unsupported_substrate_events.len()
    }

    pub fn denied_substrate_event_count(&self) -> usize {
        self.denied_substrate_events.len()
    }

    pub fn profile_gate_rejection_count(&self) -> usize {
        self.profile_gate_rejections.len()
    }

    pub fn hostcall_trace_count(&self) -> usize {
        self.contract_graph.hostcalls.len()
    }

    pub fn has_substrate_authority_extraction_evidence(&self) -> bool {
        !self.authority_extractions.is_empty()
    }

    pub fn authority_extractions_jsonl(&self) -> String {
        let mut out = String::new();
        for extraction in &self.authority_extractions {
            extraction.write_json_line(&mut out);
            out.push('\n');
        }
        out
    }

    pub fn unsupported_substrate_events_jsonl(&self) -> String {
        let mut out = String::new();
        for event in &self.unsupported_substrate_events {
            event.write_json_line(&mut out);
            out.push('\n');
        }
        out
    }

    pub fn denied_substrate_events_jsonl(&self) -> String {
        let mut out = String::new();
        for event in &self.denied_substrate_events {
            event.write_json_line(&mut out);
            out.push('\n');
        }
        out
    }

    pub fn substrate_events_jsonl(&self) -> String {
        let mut events = Vec::with_capacity(
            self.authority_extractions.len()
                + self.unsupported_substrate_events.len()
                + self.denied_substrate_events.len(),
        );
        for event in &self.authority_extractions {
            events.push(SubstrateEventJsonLine::AuthorityExtracted(event));
        }
        for event in &self.unsupported_substrate_events {
            events.push(SubstrateEventJsonLine::Unsupported(event));
        }
        for event in &self.denied_substrate_events {
            events.push(SubstrateEventJsonLine::CapabilityDenied(event));
        }
        events.sort_by_key(|event| (event.epoch(), event.id()));

        let mut out = String::new();
        for event in events {
            event.write_json_line(&mut out);
            out.push('\n');
        }
        out
    }

    pub fn profile_gate_rejections_jsonl(&self) -> String {
        let mut out = String::new();
        for rejection in &self.profile_gate_rejections {
            rejection.write_json_line(&mut out);
            out.push('\n');
        }
        out
    }

    /// Serializes authority extraction events with caller-supplied target identity.
    ///
    /// The target fields are evidence context, not proof. Supplying them does not
    /// upgrade the snapshot's boundary; callers must only use this for real-target
    /// claims when execution evidence independently establishes that target.
    pub fn authority_extractions_jsonl_with_target_context(
        &self,
        target_arch: &str,
        target_board: &str,
    ) -> String {
        let mut out = String::new();
        for extraction in &self.authority_extractions {
            extraction.write_json_line_with_target_context(&mut out, target_arch, target_board);
            out.push('\n');
        }
        out
    }

    pub fn contract_graph_snapshot_artifact_json(&self) -> String {
        let snapshot = &self.contract_graph;
        let mut out = String::new();
        out.push('{');
        push_json_str_field(
            &mut out,
            "schema_version",
            CONTRACT_GRAPH_SNAPSHOT_ARTIFACT_SCHEMA_VERSION,
        );
        out.push(',');
        push_json_str_field(
            &mut out,
            "claimed_evidence_level",
            snapshot.claimed_evidence_level.as_str(),
        );
        out.push(',');
        push_json_identity_array_field(&mut out, "artifacts", &snapshot.artifacts, |artifact| {
            (artifact.artifact_id, artifact.generation)
        });
        out.push(',');
        push_json_identity_array_field(&mut out, "code_objects", &snapshot.code_objects, |code| {
            (code.id, code.generation)
        });
        out.push(',');
        push_json_identity_array_field(&mut out, "stores", &snapshot.stores, |store| {
            (store.id, store.generation)
        });
        out.push(',');
        push_json_identity_array_field(
            &mut out,
            "activations",
            &snapshot.activations,
            |activation| (activation.id, activation.generation),
        );
        out.push(',');
        push_json_identity_array_field(&mut out, "hostcalls", &snapshot.hostcalls, |hostcall| {
            (hostcall.id, hostcall.generation)
        });
        out.push(',');
        push_json_identity_array_field(&mut out, "traps", &snapshot.traps, |trap| {
            (trap.id, trap.generation)
        });
        out.push(',');
        push_json_identity_array_field(&mut out, "capabilities", &snapshot.capabilities, |cap| {
            (cap.id, cap.generation)
        });
        out.push(',');
        push_json_identity_array_field(&mut out, "waits", &snapshot.waits, |wait| {
            (wait.id, wait.generation)
        });
        out.push(',');
        push_json_identity_array_field(
            &mut out,
            "cleanup_transactions",
            &snapshot.cleanup_transactions,
            |cleanup| (cleanup.id, cleanup.generation),
        );
        out.push(',');
        push_json_tombstone_array_field(&mut out, "tombstones", &snapshot.tombstones);
        out.push(',');
        push_json_external_object_array_field(
            &mut out,
            "external_objects",
            &snapshot.external_objects,
        );
        out.push(',');
        push_json_contract_edge_array_field(&mut out, "explicit_edges", &snapshot.explicit_edges);
        out.push('}');
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VisaSubstrateAuthorityExtractionEvidence {
    pub event_id: EventId,
    pub event_epoch: u64,
    pub authority_family: String,
    pub authority: String,
    pub operation: String,
    pub requester: Option<String>,
    pub artifact_id: Option<TargetArtifactId>,
    pub store_id: Option<StoreId>,
    pub capability_id: Option<CapabilityId>,
    pub capability_generation: Option<Generation>,
}

impl VisaSubstrateAuthorityExtractionEvidence {
    fn write_json_line(&self, out: &mut String) {
        out.push('{');
        self.write_json_fields(out);
        out.push('}');
    }

    fn write_json_line_with_target_context(
        &self,
        out: &mut String,
        target_arch: &str,
        target_board: &str,
    ) {
        out.push('{');
        self.write_json_fields(out);
        out.push(',');
        push_json_str_field(out, "target_arch", target_arch);
        out.push(',');
        push_json_str_field(out, "target_board", target_board);
        out.push('}');
    }

    fn write_json_fields(&self, out: &mut String) {
        push_json_u64_field(out, "event_id", self.event_id);
        out.push(',');
        push_json_u64_field(out, "event_epoch", self.event_epoch);
        out.push(',');
        push_json_str_field(out, "event_kind", "authority-extracted");
        out.push(',');
        push_json_str_field(out, "authority_family", &self.authority_family);
        out.push(',');
        push_json_str_field(out, "authority", &self.authority);
        out.push(',');
        push_json_str_field(out, "operation", &self.operation);
        out.push(',');
        push_json_optional_str_field(out, "requester", self.requester.as_deref());
        out.push(',');
        push_json_optional_u64_field(out, "artifact_id", self.artifact_id);
        out.push(',');
        push_json_optional_u64_field(out, "store_id", self.store_id);
        out.push(',');
        push_json_optional_u64_field(out, "capability_id", self.capability_id);
        out.push(',');
        push_json_optional_u64_field(out, "capability_generation", self.capability_generation);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VisaSubstrateUnsupportedEvidence {
    pub event_id: EventId,
    pub event_epoch: u64,
    pub authority_family: String,
    pub authority: String,
    pub operation: String,
    pub requester: Option<String>,
    pub artifact_id: Option<TargetArtifactId>,
    pub store_id: Option<StoreId>,
}

impl VisaSubstrateUnsupportedEvidence {
    fn write_json_line(&self, out: &mut String) {
        out.push('{');
        push_json_u64_field(out, "event_id", self.event_id);
        out.push(',');
        push_json_u64_field(out, "event_epoch", self.event_epoch);
        out.push(',');
        push_json_str_field(out, "event_kind", "unsupported");
        out.push(',');
        push_json_str_field(out, "authority_family", &self.authority_family);
        out.push(',');
        push_json_str_field(out, "authority", &self.authority);
        out.push(',');
        push_json_str_field(out, "operation", &self.operation);
        out.push(',');
        push_json_optional_str_field(out, "requester", self.requester.as_deref());
        out.push(',');
        push_json_optional_u64_field(out, "artifact", self.artifact_id);
        out.push(',');
        push_json_optional_u64_field(out, "store", self.store_id);
        out.push('}');
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VisaSubstrateCapabilityDeniedEvidence {
    pub event_id: EventId,
    pub event_epoch: u64,
    pub authority_family: String,
    pub authority: String,
    pub operation: String,
    pub requester: Option<String>,
    pub artifact_id: Option<TargetArtifactId>,
    pub store_id: Option<StoreId>,
    pub capability_id: Option<CapabilityId>,
    pub capability_generation: Option<Generation>,
}

impl VisaSubstrateCapabilityDeniedEvidence {
    fn write_json_line(&self, out: &mut String) {
        out.push('{');
        push_json_u64_field(out, "event_id", self.event_id);
        out.push(',');
        push_json_u64_field(out, "event_epoch", self.event_epoch);
        out.push(',');
        push_json_str_field(out, "event_kind", "capability-denied");
        out.push(',');
        push_json_str_field(out, "authority_family", &self.authority_family);
        out.push(',');
        push_json_str_field(out, "authority", &self.authority);
        out.push(',');
        push_json_str_field(out, "operation", &self.operation);
        out.push(',');
        push_json_optional_str_field(out, "requester", self.requester.as_deref());
        out.push(',');
        push_json_optional_u64_field(out, "artifact", self.artifact_id);
        out.push(',');
        push_json_optional_u64_field(out, "store", self.store_id);
        out.push(',');
        push_json_optional_u64_field(out, "capability", self.capability_id);
        out.push(',');
        push_json_optional_u64_field(out, "capability_generation", self.capability_generation);
        out.push('}');
    }
}

enum SubstrateEventJsonLine<'a> {
    AuthorityExtracted(&'a VisaSubstrateAuthorityExtractionEvidence),
    Unsupported(&'a VisaSubstrateUnsupportedEvidence),
    CapabilityDenied(&'a VisaSubstrateCapabilityDeniedEvidence),
}

impl SubstrateEventJsonLine<'_> {
    fn id(&self) -> EventId {
        match self {
            Self::AuthorityExtracted(event) => event.event_id,
            Self::Unsupported(event) => event.event_id,
            Self::CapabilityDenied(event) => event.event_id,
        }
    }

    fn epoch(&self) -> u64 {
        match self {
            Self::AuthorityExtracted(event) => event.event_epoch,
            Self::Unsupported(event) => event.event_epoch,
            Self::CapabilityDenied(event) => event.event_epoch,
        }
    }

    fn write_json_line(&self, out: &mut String) {
        match self {
            Self::AuthorityExtracted(event) => event.write_json_line(out),
            Self::Unsupported(event) => event.write_json_line(out),
            Self::CapabilityDenied(event) => event.write_json_line(out),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VisaProfileGateRejectionEvidence {
    pub event_id: EventId,
    pub event_epoch: u64,
    pub package: String,
    pub artifact: String,
    pub artifact_id: Option<TargetArtifactId>,
    pub required_profile: String,
    pub reported_profile: String,
    pub enforced_profile: String,
    pub reason: String,
    pub missing_required: Vec<String>,
    pub degraded_optional: Vec<String>,
    pub forbidden_present: Vec<String>,
}

impl VisaProfileGateRejectionEvidence {
    fn write_json_line(&self, out: &mut String) {
        out.push('{');
        push_json_u64_field(out, "event_id", self.event_id);
        out.push(',');
        push_json_u64_field(out, "event_epoch", self.event_epoch);
        out.push(',');
        push_json_str_field(out, "event_kind", "profile-gate-rejected");
        out.push(',');
        push_json_str_field(out, "package", &self.package);
        out.push(',');
        push_json_str_field(out, "artifact", &self.artifact);
        out.push(',');
        push_json_optional_u64_field(out, "artifact_id", self.artifact_id);
        out.push(',');
        push_json_str_field(out, "required_profile", &self.required_profile);
        out.push(',');
        push_json_str_field(out, "reported_profile", &self.reported_profile);
        out.push(',');
        push_json_str_field(out, "enforced_profile", &self.enforced_profile);
        out.push(',');
        push_json_str_field(out, "reason", &self.reason);
        out.push(',');
        push_json_str_array_field(out, "missing_required", &self.missing_required);
        out.push(',');
        push_json_str_array_field(out, "degraded_optional", &self.degraded_optional);
        out.push(',');
        push_json_str_array_field(out, "forbidden_present", &self.forbidden_present);
        out.push('}');
    }
}

fn push_json_u64_field(out: &mut String, key: &str, value: u64) {
    push_json_key(out, key);
    out.push_str(&value.to_string());
}

fn push_json_optional_u64_field(out: &mut String, key: &str, value: Option<u64>) {
    push_json_key(out, key);
    match value {
        Some(value) => out.push_str(&value.to_string()),
        None => out.push_str("null"),
    }
}

fn push_json_str_field(out: &mut String, key: &str, value: &str) {
    push_json_key(out, key);
    push_json_string(out, value);
}

fn push_json_optional_str_field(out: &mut String, key: &str, value: Option<&str>) {
    push_json_key(out, key);
    match value {
        Some(value) => push_json_string(out, value),
        None => out.push_str("null"),
    }
}

fn push_json_str_array_field(out: &mut String, key: &str, values: &[String]) {
    push_json_key(out, key);
    out.push('[');
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        push_json_string(out, value);
    }
    out.push(']');
}

fn push_json_identity_array_field<T, F>(out: &mut String, key: &str, items: &[T], mut identity: F)
where
    F: FnMut(&T) -> (u64, u64),
{
    push_json_key(out, key);
    out.push('[');
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        let (id, generation) = identity(item);
        push_json_identity_object(out, id, generation);
    }
    out.push(']');
}

fn push_json_identity_object(out: &mut String, id: u64, generation: u64) {
    out.push('{');
    push_json_u64_field(out, "id", id);
    out.push(',');
    push_json_u64_field(out, "generation", generation);
    out.push('}');
}

fn push_json_tombstone_array_field(out: &mut String, key: &str, items: &[TombstoneRecord]) {
    push_json_key(out, key);
    out.push('[');
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push('{');
        push_json_str_field(out, "kind", item.kind.as_str());
        out.push(',');
        push_json_u64_field(out, "id", item.id);
        out.push(',');
        push_json_u64_field(out, "generation", item.generation);
        out.push('}');
    }
    out.push(']');
}

fn push_json_external_object_array_field(
    out: &mut String,
    key: &str,
    items: &[ExternalObjectDeclaration],
) {
    push_json_key(out, key);
    out.push('[');
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push('{');
        push_json_ref_field(out, "object", item.object);
        out.push(',');
        push_json_str_field(out, "provider", &item.provider);
        out.push(',');
        push_json_str_field(out, "class", &item.class);
        out.push('}');
    }
    out.push(']');
}

fn push_json_contract_edge_array_field(out: &mut String, key: &str, items: &[ContractEdgeRecord]) {
    push_json_key(out, key);
    out.push('[');
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push('{');
        push_json_ref_field(out, "from", item.from);
        out.push(',');
        push_json_ref_field(out, "to", item.to);
        out.push(',');
        push_json_str_field(out, "mode", item.mode.as_str());
        out.push(',');
        push_json_str_field(out, "evidence_level", item.evidence_level.as_str());
        out.push(',');
        push_json_str_field(out, "label", &item.label);
        out.push(',');
        push_json_u64_field(out, "epoch", item.epoch);
        out.push('}');
    }
    out.push(']');
}

fn push_json_ref_field(out: &mut String, key: &str, value: ContractObjectRef) {
    push_json_key(out, key);
    out.push('{');
    push_json_str_field(out, "kind", value.kind.as_str());
    out.push(',');
    push_json_u64_field(out, "id", value.id);
    out.push(',');
    push_json_u64_field(out, "generation", value.generation);
    out.push('}');
}

fn push_json_key(out: &mut String, key: &str) {
    push_json_string(out, key);
    out.push(':');
}

fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => {
                out.push_str("\\u");
                let code = ch as u32;
                out.push(hex_digit((code >> 12) & 0xf));
                out.push(hex_digit((code >> 8) & 0xf));
                out.push(hex_digit((code >> 4) & 0xf));
                out.push(hex_digit(code & 0xf));
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
}

fn hex_digit(value: u32) -> char {
    match value {
        0..=9 => char::from(b'0' + value as u8),
        10..=15 => char::from(b'a' + (value as u8 - 10)),
        _ => '0',
    }
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
        authority_family: String,
        authority: String,
        operation: String,
        artifact_id: TargetArtifactId,
        store_id: Option<u64>,
    },
    SubstrateUnsupported {
        authority_family: &'static str,
        authority: &'static str,
        operation: &'static str,
    },
    FaultCleanupStarted {
        activation_id: ActivationId,
        store_id: u64,
        code_object_id: CodeObjectId,
        cleanup_id: u64,
        reason: String,
    },
    FaultCleanupCompleted {
        activation_id: ActivationId,
        store_id: u64,
        code_object_id: CodeObjectId,
        cleanup_id: u64,
        reason: String,
    },
    ProfileGateRejected {
        package: String,
        artifact: String,
        artifact_id: TargetArtifactId,
        required_profile: SubstrateProfile,
        reported_profile: SubstrateProfile,
        enforced_profile: String,
        reason: String,
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
        semantic.ensure_task(1, FrontendKind::Supervisor, "visa-runtime");
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
            self.record_profile_gate_rejection(
                &input.descriptor,
                required_profile,
                &profile_report,
            );
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
            Some("visa-runtime-target-artifact-image"),
        );
        let verified = self
            .registry
            .verify(image)
            .map_err(|error| VisaRuntimeError::Registry(error.message()))?;
        self.dispatch_artifact_load(backend, &verified)?;

        let store_id = self.semantic.register_store_instance(
            &verified.package,
            &verified.artifact_name,
            &verified.role,
            "restartable",
        );
        self.semantic.set_store_owner_profile(store_id, &verified.target_profile);
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
            Some("visa-runtime-loop"),
        );

        let semantic_store = self
            .semantic
            .stores()
            .iter()
            .find(|record| record.id == store_id)
            .cloned()
            .ok_or(VisaRuntimeError::MissingStore(store_id))?;
        let store_id = self
            .store_manager
            .register_store_record(semantic_store, "visa-runtime")
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
            "visa-runtime",
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
        let (_store, code, spec, frame, capability_arg) =
            self.prepare_runtime_hostcall_frame(activation, hostcall_number, &payload)?;
        if let Some(token) = payload.wait_token_out() {
            debug_assert_eq!(frame.wait_token_out, Some(token.id));
            debug_assert_eq!(frame.wait_token_generation_out, Some(token.generation));
        }
        let substrate_authority = substrate_authority_for_payload(&payload);
        self.semantic.record_hostcall(
            &spec.name,
            HostcallClass::ImmediatePrivilegedOp,
            &code.package,
            &spec.object,
            &spec.operation,
        );
        let prepared_hostcall =
            match self.executor.preflight_hostcall(&code, frame.to_wire_frame(), &self.ledger) {
                Ok(prepared) => prepared,
                Err(error) => {
                    if matches!(error, TargetExecutorError::CapabilityDenied)
                        && let Some(authority) = substrate_authority
                    {
                        self.record_substrate_capability_denied_for_hostcall(
                            &code,
                            authority,
                            capability_arg.as_ref(),
                        );
                    }
                    return Err(VisaRuntimeError::Executor(error));
                }
            };
        let value = self.dispatch_hostcall_payload(backend, &code, &spec, payload)?;
        self.executor
            .commit_hostcall_success(prepared_hostcall)
            .map_err(VisaRuntimeError::Executor)?;
        if let Some(authority) = substrate_authority {
            self.semantic.record_substrate_authority_extracted(
                authority.family.as_str(),
                authority.authority,
                authority.operation,
                Some(code.package.clone()),
                Some(code.artifact_id),
                code.bound_store,
                capability_arg.as_ref().map(|capability| capability.id),
                capability_arg.as_ref().map(|capability| capability.generation),
            );
            self.events.push(VisaRuntimeEvent::SubstrateAuthorityExtracted {
                authority_family: authority.family.as_str().to_string(),
                authority: authority.authority.to_string(),
                operation: authority.operation.to_string(),
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

    #[cfg(test)]
    #[allow(dead_code)]
    fn preflight_hostcall_frame_for_test(
        &mut self,
        activation: &ActivationHandle,
        hostcall_number: u32,
        payload: &VisaHostcallPayload,
        mutate: impl FnOnce(&mut semantic_core::target_executor::ExecutorHostcallFrameV1),
    ) -> Result<(), VisaRuntimeError> {
        let (_, code, _, frame, _) =
            self.prepare_runtime_hostcall_frame(activation, hostcall_number, payload)?;
        let mut wire_frame = frame.to_wire_frame();
        mutate(&mut wire_frame);
        self.executor
            .preflight_hostcall(&code, wire_frame, &self.ledger)
            .map(|_| ())
            .map_err(VisaRuntimeError::Executor)
    }

    #[cfg(test)]
    #[allow(dead_code)]
    fn record_trap_by_pc_for_test(
        &mut self,
        activation: &ActivationHandle,
        pc: u64,
        trap_map: &[target_abi::TrapMapEntryV1],
    ) -> Result<u64, VisaRuntimeError> {
        let code = self.code_object(activation.code_object_id)?.clone();
        self.executor
            .trap_exit_by_pc(activation.activation_id, &code, pc, trap_map)
            .map_err(VisaRuntimeError::Executor)
    }

    pub fn begin_fault_cleanup(
        &mut self,
        activation: &ActivationHandle,
        reason: &str,
    ) -> Result<u64, VisaRuntimeError> {
        let store = self.store_record(activation.store_id)?.store.clone();
        let code = self.code_object(activation.code_object_id)?.clone();
        let cleanup_id = self.executor.begin_fault_cleanup_transaction(
            &store,
            Some(activation.activation_id),
            Some(&code),
            reason,
        );
        self.events.push(VisaRuntimeEvent::FaultCleanupStarted {
            activation_id: activation.activation_id,
            store_id: activation.store_id,
            code_object_id: activation.code_object_id,
            cleanup_id,
            reason: reason.to_string(),
        });
        Ok(cleanup_id)
    }

    pub fn complete_fault_cleanup(
        &mut self,
        activation: &ActivationHandle,
        reason: &str,
    ) -> Result<u64, VisaRuntimeError> {
        let store = &mut self
            .store_manager
            .record_mut(activation.store_id)
            .map_err(|error| VisaRuntimeError::Store(error.message()))?
            .store;
        let code = self
            .publisher
            .object_mut(activation.code_object_id)
            .map_err(|error| VisaRuntimeError::CodePublisher(error.message()))?;
        let cleanup_id = self
            .executor
            .run_fault_cleanup(
                store,
                Some(activation.activation_id),
                Some(code),
                &mut self.ledger,
                reason,
            )
            .map_err(VisaRuntimeError::Executor)?;
        self.sync_semantic_store_record(activation.store_id)?;
        self.events.push(VisaRuntimeEvent::FaultCleanupCompleted {
            activation_id: activation.activation_id,
            store_id: activation.store_id,
            code_object_id: activation.code_object_id,
            cleanup_id,
            reason: reason.to_string(),
        });
        Ok(cleanup_id)
    }

    fn sync_semantic_store_record(&mut self, store_id: StoreId) -> Result<(), VisaRuntimeError> {
        let store = self.store_record(store_id)?.store.clone();
        let Some(current) = self.semantic.stores().iter().find(|record| record.id == store_id)
        else {
            return Err(VisaRuntimeError::MissingStore(store_id));
        };
        if current.generation == store.generation && current.state == store.state {
            return Ok(());
        }
        if current.generation + 1 != store.generation {
            return Err(VisaRuntimeError::Store("runtime store generation drift"));
        }
        self.semantic.set_store_state(store_id, store.state);
        Ok(())
    }

    fn prepare_runtime_hostcall_frame(
        &self,
        activation: &ActivationHandle,
        hostcall_number: u32,
        payload: &VisaHostcallPayload,
    ) -> Result<
        (
            semantic_core::StoreRecord,
            CodeObject,
            HostcallSpec,
            HostcallFrame,
            Option<CapabilityHandleArg>,
        ),
        VisaRuntimeError,
    > {
        let store = self.store_record(activation.store_id)?.store.clone();
        let code = self.code_object(activation.code_object_id)?.clone();
        let spec = code
            .hostcalls
            .iter()
            .find(|spec| spec.number == hostcall_number)
            .cloned()
            .unwrap_or_else(|| {
                HostcallSpec::new(
                    hostcall_number,
                    "hostcall.unsupported",
                    semantic_core::target_executor::HostcallCategory::Service,
                    "hostcall.unsupported",
                    "decode",
                    false,
                )
            });
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
        if let Some(token) = payload.wait_token_out() {
            frame.wait_token_out = Some(token.id);
            frame.wait_token_generation_out = Some(token.generation);
        }
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

        Ok((store, code, spec, frame, capability_arg))
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

    fn record_profile_gate_rejection(
        &mut self,
        descriptor: &VisaArtifactDescriptor,
        required_profile: SubstrateProfile,
        report: &SubstrateCompatibilityReport,
    ) {
        let enforced_profile =
            SubstrateProfile::strongest_satisfied_by(self.config.enforced_capabilities)
                .map(SubstrateProfile::as_str)
                .unwrap_or("none")
                .to_string();
        let reason =
            profile_gate_rejection_reason(self.config.reported_profile, required_profile, report)
                .to_string();
        let missing_required =
            report.missing_required.iter().map(profile_mismatch_summary).collect::<Vec<_>>();
        let degraded_optional =
            report.degraded_optional.iter().map(profile_mismatch_summary).collect::<Vec<_>>();
        let forbidden_present = report
            .forbidden_present
            .iter()
            .map(|present| format!("{}:actual={}", present.authority, present.actual))
            .collect::<Vec<_>>();

        self.semantic.record_profile_gate_rejected(
            descriptor.package.clone(),
            descriptor.artifact_name.clone(),
            Some(descriptor.id),
            required_profile.as_str(),
            self.config.reported_profile.as_str(),
            enforced_profile.clone(),
            reason.clone(),
            missing_required,
            degraded_optional,
            forbidden_present,
        );
        self.events.push(VisaRuntimeEvent::ProfileGateRejected {
            package: descriptor.package.clone(),
            artifact: descriptor.artifact_name.clone(),
            artifact_id: descriptor.id,
            required_profile,
            reported_profile: self.config.reported_profile,
            enforced_profile,
            reason,
        });
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
                    requester_with_optional_store(
                        requester_for(artifact).with_artifact(artifact_ref),
                        code.bound_store,
                        code.bound_store_generation,
                    ),
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
                self.semantic.record_wait_created_with_details(
                    token.id,
                    None,
                    code.bound_store,
                    code.bound_store_generation,
                    SemanticWaitKind::Timer,
                    token.generation,
                    Vec::new(),
                    Some(deadline_ticks),
                    RestartPolicy::RestartIfAllowed,
                    Some(format!("hostcall:{}:{}", spec.object, spec.operation)),
                );
                Ok(VisaHostcallValue::None)
            }
            VisaHostcallPayload::EventPush { event } => {
                backend.push_event(event).map_err(|error| {
                    self.map_hostcall_substrate_error(
                        backend,
                        code,
                        spec,
                        "EventQueueAuthority",
                        "push_event",
                        error,
                    )
                })?;
                Ok(VisaHostcallValue::None)
            }
            VisaHostcallPayload::EventPop => Ok(VisaHostcallValue::Event(backend.pop_event())),
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
            .with_artifact(ArtifactImageRef::new(code.artifact_id, 1));
        let requester =
            requester_with_optional_store(requester, code.bound_store, code.bound_store_generation);
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
            let authority_family = authority_family_for_authority(authority);
            self.semantic.record_substrate_unsupported(
                authority_family,
                authority,
                operation,
                Some(requester.subject.clone()),
                requester.artifact.map(|artifact| artifact.id),
                requester.store.map(|store| store.id),
            );
            let event = SubstrateEvent::unsupported(authority, operation, Some(requester));
            let _ = backend.push_event(event);
            self.events.push(VisaRuntimeEvent::SubstrateUnsupported {
                authority_family,
                authority,
                operation,
            });
            return Err(VisaRuntimeError::SubstrateDispatch { authority, operation, error });
        }
        if let SubstrateError::Denied { capability } = error {
            let authority_family = authority_family_for_authority(authority);
            self.semantic.record_substrate_capability_denied(
                authority_family,
                authority,
                operation,
                Some(requester.subject.clone()),
                requester.artifact.map(|artifact| artifact.id),
                requester.store.map(|store| store.id),
                capability.map(|capability| capability.id),
                capability.map(|capability| capability.generation),
            );
            let event = SubstrateEvent::CapabilityDenied {
                authority,
                operation,
                requester: Some(requester),
                capability,
            };
            let _ = backend.push_event(event);
            return Err(VisaRuntimeError::SubstrateDispatch { authority, operation, error });
        }
        Err(VisaRuntimeError::SubstrateDispatch { authority, operation, error })
    }

    fn record_substrate_capability_denied_for_hostcall(
        &mut self,
        code: &CodeObject,
        authority: SubstrateAuthorityDescriptor,
        capability: Option<&CapabilityHandleArg>,
    ) {
        self.semantic.record_substrate_capability_denied(
            authority.family.as_str(),
            authority.authority,
            authority.operation,
            Some(code.package.clone()),
            Some(code.artifact_id),
            code.bound_store,
            capability.map(|capability| capability.id),
            capability.map(|capability| capability.generation),
        );
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
        if let Some(field) = snapshot.unsupported_runtime_restore_record() {
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

        if !semantic.restore_process_records(
            &snapshot.processes,
            &snapshot.threads,
            &snapshot.thread_groups,
            &snapshot.fd_tables,
            &snapshot.open_file_descriptions,
            &snapshot.credentials,
            &snapshot.credential_transitions,
        ) {
            return Err(VisaRuntimeError::InvalidPortableSnapshot("invalid process record"));
        }

        if !semantic.restore_guest_memory_records(
            &snapshot.guest_address_spaces,
            &snapshot.vma_regions,
            &snapshot.page_objects,
            &snapshot.guest_memory_faults,
        ) {
            return Err(VisaRuntimeError::InvalidPortableSnapshot("invalid guest memory record"));
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
        let explicit_edges = self.runtime_artifact_path_edges();
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
            explicit_edges: &explicit_edges,
            ..Default::default()
        };
        self.semantic.snapshot_with(inputs)
    }

    fn runtime_artifact_path_edges(&self) -> Vec<ContractEdgeRecord> {
        let mut edges = Vec::new();
        for code in self.publisher.objects() {
            let Some(artifact) = self
                .registry
                .verified()
                .iter()
                .find(|artifact| artifact.artifact_id == code.artifact_id)
            else {
                continue;
            };
            let code_edge_mode = if matches!(
                code.state,
                semantic_core::target_executor::CodeObjectState::Faulted
                    | semantic_core::target_executor::CodeObjectState::Retired
                    | semantic_core::target_executor::CodeObjectState::Unpublished
            ) {
                semantic_core::ContractEdgeMode::Historical
            } else {
                semantic_core::ContractEdgeMode::Live
            };
            edges.push(runtime_artifact_path_edge(
                artifact.object_ref(),
                code.object_ref(),
                code_edge_mode,
                "artifact-loads-code-object",
            ));

            let mut store_refs = Vec::new();
            if let (Some(store_id), Some(store_generation)) =
                (code.bound_store, code.bound_store_generation)
            {
                push_unique_store_ref(&mut store_refs, store_id, store_generation);
            }
            for activation in self.executor.activations().iter().filter(|activation| {
                activation.code_object == code.id
                    && activation.code_generation == code.generation
                    && activation.artifact == artifact.artifact_id
            }) {
                push_unique_store_ref(
                    &mut store_refs,
                    activation.store,
                    activation.store_generation,
                );
            }
            for cleanup in self.executor.cleanup_transactions().iter().filter(|cleanup| {
                cleanup.code_object == Some(code.id)
                    && cleanup.code_generation == Some(code.generation)
            }) {
                push_unique_store_ref(&mut store_refs, cleanup.store, cleanup.store_generation);
                if let Some(result_generation) = cleanup.result_store_generation {
                    push_unique_store_ref(&mut store_refs, cleanup.store, result_generation);
                }
            }

            for (store_id, store_generation) in store_refs {
                let Some(store) = self
                    .semantic
                    .stores()
                    .iter()
                    .find(|store| store.id == store_id && store.generation == store_generation)
                else {
                    continue;
                };
                let store_edge_mode = if code_edge_mode == semantic_core::ContractEdgeMode::Live
                    && store.state != StoreState::Dead
                {
                    semantic_core::ContractEdgeMode::Live
                } else {
                    semantic_core::ContractEdgeMode::Historical
                };
                edges.push(runtime_artifact_path_edge(
                    code.object_ref(),
                    store.object_ref(),
                    store_edge_mode,
                    "code-object-bound-to-store",
                ));

                for activation in self.executor.activations().iter().filter(|activation| {
                    activation.store == store.id
                        && activation.store_generation == store.generation
                        && activation.code_object == code.id
                        && activation.code_generation == code.generation
                        && activation.artifact == artifact.artifact_id
                }) {
                    let activation_edge_mode = if matches!(
                        activation.state,
                        semantic_core::target_executor::ActivationState::Running
                            | semantic_core::target_executor::ActivationState::Pending
                    ) && store_edge_mode
                        == semantic_core::ContractEdgeMode::Live
                    {
                        semantic_core::ContractEdgeMode::Live
                    } else {
                        semantic_core::ContractEdgeMode::Historical
                    };
                    edges.push(runtime_artifact_path_edge(
                        store.object_ref(),
                        activation.object_ref(),
                        activation_edge_mode,
                        "store-starts-activation",
                    ));

                    for hostcall in self.executor.hostcall_trace().iter().filter(|hostcall| {
                        hostcall.activation == activation.id
                            && hostcall.store == activation.store
                            && hostcall.code_object == code.id
                            && hostcall.artifact == artifact.artifact_id
                            && hostcall.artifact_generation == artifact.generation
                    }) {
                        edges.push(runtime_artifact_path_edge(
                            activation.object_ref(),
                            hostcall.object_ref(),
                            activation_edge_mode,
                            "activation-dispatches-hostcall-frame",
                        ));
                        if let Some(wait_id) = hostcall.wait_token_out
                            && let Some(wait) =
                                self.semantic.wait_records().iter().find(|wait| wait.id == wait_id)
                        {
                            edges.push(runtime_artifact_path_edge(
                                hostcall.object_ref(),
                                wait.object_ref(),
                                activation_edge_mode,
                                "hostcall-produces-wait-token",
                            ));
                        }
                    }

                    for trap in self.executor.traps().iter().filter(|trap| {
                        trap.activation == Some(activation.id)
                            && trap.store == Some(activation.store)
                            && trap.code_object == Some(code.id)
                            && trap.artifact == Some(artifact.artifact_id)
                            && trap.artifact_generation == Some(artifact.generation)
                    }) {
                        edges.push(runtime_artifact_path_edge(
                            activation.object_ref(),
                            trap.object_ref(),
                            activation_edge_mode,
                            "activation-records-trap-map",
                        ));
                    }
                }

                for cleanup in self.executor.cleanup_transactions().iter().filter(|cleanup| {
                    cleanup.store == store.id
                        && (cleanup.store_generation == store.generation
                            || cleanup.result_store_generation == Some(store.generation))
                        && cleanup.code_object == Some(code.id)
                        && cleanup.code_generation == Some(code.generation)
                }) {
                    let cleanup_edge_mode = if cleanup.state
                        == semantic_core::target_executor::CleanupTransactionState::Pending
                        && store_edge_mode == semantic_core::ContractEdgeMode::Live
                    {
                        semantic_core::ContractEdgeMode::Live
                    } else {
                        semantic_core::ContractEdgeMode::Historical
                    };
                    edges.push(runtime_artifact_path_edge(
                        store.object_ref(),
                        cleanup.object_ref(),
                        cleanup_edge_mode,
                        "store-starts-cleanup-transaction",
                    ));
                    if let Some(activation_id) = cleanup.activation
                        && let Some(activation) = self
                            .executor
                            .activations()
                            .iter()
                            .find(|activation| activation.id == activation_id)
                    {
                        edges.push(runtime_artifact_path_edge(
                            activation.object_ref(),
                            cleanup.object_ref(),
                            cleanup_edge_mode,
                            "activation-enters-cleanup-transaction",
                        ));
                    }
                }
            }
        }
        edges
    }

    pub fn evidence_snapshot(&self) -> VisaRuntimeEvidenceSnapshot {
        let event_log = self.semantic.event_log();
        let authority_extractions = event_log
            .events()
            .iter()
            .filter_map(|event| match &event.kind {
                EventKind::SubstrateAuthorityExtracted {
                    authority_family,
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
                    authority_family: authority_family.clone(),
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
                    authority_family,
                    authority,
                    operation,
                    requester,
                    artifact,
                    store,
                } => Some(VisaSubstrateUnsupportedEvidence {
                    event_id: event.id,
                    event_epoch: event.epoch,
                    authority_family: authority_family.clone(),
                    authority: authority.clone(),
                    operation: operation.clone(),
                    requester: requester.clone(),
                    artifact_id: *artifact,
                    store_id: *store,
                }),
                _ => None,
            })
            .collect();
        let denied_substrate_events = event_log
            .events()
            .iter()
            .filter_map(|event| match &event.kind {
                EventKind::SubstrateCapabilityDenied {
                    authority_family,
                    authority,
                    operation,
                    requester,
                    artifact,
                    store,
                    capability,
                    capability_generation,
                } => Some(VisaSubstrateCapabilityDeniedEvidence {
                    event_id: event.id,
                    event_epoch: event.epoch,
                    authority_family: authority_family.clone(),
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
        let profile_gate_rejections = event_log
            .events()
            .iter()
            .filter_map(|event| match &event.kind {
                EventKind::ProfileGateRejected {
                    package,
                    artifact,
                    artifact_id,
                    required_profile,
                    reported_profile,
                    enforced_profile,
                    reason,
                    missing_required,
                    degraded_optional,
                    forbidden_present,
                } => Some(VisaProfileGateRejectionEvidence {
                    event_id: event.id,
                    event_epoch: event.epoch,
                    package: package.clone(),
                    artifact: artifact.clone(),
                    artifact_id: *artifact_id,
                    required_profile: required_profile.clone(),
                    reported_profile: reported_profile.clone(),
                    enforced_profile: enforced_profile.clone(),
                    reason: reason.clone(),
                    missing_required: missing_required.clone(),
                    degraded_optional: degraded_optional.clone(),
                    forbidden_present: forbidden_present.clone(),
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
            denied_substrate_events,
            profile_gate_rejections,
        }
    }

    pub fn record_synthetic_trap(
        &mut self,
        activation_id: ActivationId,
        store_id: u64,
        detail: &str,
    ) {
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
                "visa-runtime",
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SubstrateAuthorityDescriptor {
    family: AuthorityFamily,
    authority: &'static str,
    operation: &'static str,
}

const fn authority_descriptor(
    family: AuthorityFamily,
    authority: &'static str,
    operation: &'static str,
) -> SubstrateAuthorityDescriptor {
    SubstrateAuthorityDescriptor { family, authority, operation }
}

fn substrate_authority_for_payload(
    payload: &VisaHostcallPayload,
) -> Option<SubstrateAuthorityDescriptor> {
    match payload {
        VisaHostcallPayload::None => None,
        VisaHostcallPayload::ConsoleWrite { .. } => Some(authority_descriptor(
            AuthorityFamily::Console,
            "ConsoleAuthority",
            "console_write",
        )),
        VisaHostcallPayload::TimerNow => {
            Some(authority_descriptor(AuthorityFamily::Timer, "TimerAuthority", "now"))
        }
        VisaHostcallPayload::TimerArm { .. } => {
            Some(authority_descriptor(AuthorityFamily::Timer, "TimerAuthority", "arm_timer"))
        }
        VisaHostcallPayload::EventPush { .. } => {
            Some(authority_descriptor(AuthorityFamily::Event, "EventQueueAuthority", "push_event"))
        }
        VisaHostcallPayload::EventPop => {
            Some(authority_descriptor(AuthorityFamily::Event, "EventQueueAuthority", "pop_event"))
        }
        VisaHostcallPayload::GuestMemoryCopyIn { .. } => {
            Some(authority_descriptor(AuthorityFamily::Memory, "GuestMemoryAuthority", "copyin"))
        }
        VisaHostcallPayload::GuestMemoryCopyOut { .. } => {
            Some(authority_descriptor(AuthorityFamily::Memory, "GuestMemoryAuthority", "copyout"))
        }
        VisaHostcallPayload::DmwMap { .. } => {
            Some(authority_descriptor(AuthorityFamily::Dmw, "DmwAuthority", "map_user_window"))
        }
        VisaHostcallPayload::DmwUnmap { .. } => {
            Some(authority_descriptor(AuthorityFamily::Dmw, "DmwAuthority", "unmap_user_window"))
        }
        VisaHostcallPayload::MmioRead32 { .. } => {
            Some(authority_descriptor(AuthorityFamily::Mmio, "MmioAuthority", "mmio_read32"))
        }
        VisaHostcallPayload::MmioWrite32 { .. } => {
            Some(authority_descriptor(AuthorityFamily::Mmio, "MmioAuthority", "mmio_write32"))
        }
        VisaHostcallPayload::DmaAlloc { .. } => {
            Some(authority_descriptor(AuthorityFamily::Dma, "DmaAuthority", "dma_alloc"))
        }
        VisaHostcallPayload::DmaFree { .. } => {
            Some(authority_descriptor(AuthorityFamily::Dma, "DmaAuthority", "dma_free"))
        }
        VisaHostcallPayload::IrqAck { .. } => {
            Some(authority_descriptor(AuthorityFamily::Irq, "IrqAuthority", "irq_ack"))
        }
        VisaHostcallPayload::IrqMask { .. } => {
            Some(authority_descriptor(AuthorityFamily::Irq, "IrqAuthority", "irq_mask"))
        }
        VisaHostcallPayload::IrqUnmask { .. } => {
            Some(authority_descriptor(AuthorityFamily::Irq, "IrqAuthority", "irq_unmask"))
        }
        VisaHostcallPayload::SnapshotEnter => Some(authority_descriptor(
            AuthorityFamily::Snapshot,
            "SnapshotAuthority",
            "enter_snapshot_barrier",
        )),
        VisaHostcallPayload::SnapshotExit { .. } => Some(authority_descriptor(
            AuthorityFamily::Snapshot,
            "SnapshotAuthority",
            "exit_snapshot_barrier",
        )),
    }
}

fn authority_family_for_authority(authority: &str) -> &'static str {
    AuthorityFamily::from_authority_trait(authority)
        .map(AuthorityFamily::as_str)
        .unwrap_or("unknown")
}

fn requester_for(artifact: &VerifiedArtifact) -> SubstrateRequester {
    SubstrateRequester::new(artifact.package.clone())
}

fn requester_with_optional_store(
    requester: SubstrateRequester,
    store: Option<u64>,
    generation: Option<u64>,
) -> SubstrateRequester {
    match (store, generation) {
        (Some(store), Some(generation)) => requester.with_store(StoreRef::new(store, generation)),
        _ => requester,
    }
}

fn stronger_profile(left: SubstrateProfile, right: SubstrateProfile) -> SubstrateProfile {
    if left.satisfies(right) { left } else { right }
}

fn profile_gate_rejection_reason(
    reported_profile: SubstrateProfile,
    required_profile: SubstrateProfile,
    report: &SubstrateCompatibilityReport,
) -> &'static str {
    if !reported_profile.satisfies(required_profile) {
        "reported-profile-below-required"
    } else if !report.missing_required.is_empty() {
        "missing-required-authority"
    } else if !report.forbidden_present.is_empty() {
        "forbidden-authority-present"
    } else {
        "profile-gate-rejected"
    }
}

fn profile_mismatch_summary(mismatch: &AuthorityMismatch) -> String {
    format!("{}:required={}:actual={}", mismatch.authority, mismatch.required, mismatch.actual)
}

fn runtime_artifact_path_edge(
    from: ContractObjectRef,
    to: ContractObjectRef,
    mode: semantic_core::ContractEdgeMode,
    label: &str,
) -> ContractEdgeRecord {
    ContractEdgeRecord::new(from, to, mode, label, 1)
        .with_evidence_level(EvidenceBoundaryLevel::PortableArtifactExecution)
}

fn push_unique_store_ref(
    refs: &mut Vec<(StoreId, Generation)>,
    id: StoreId,
    generation: Generation,
) {
    if !refs.iter().any(|(existing_id, existing_generation)| {
        *existing_id == id && *existing_generation == generation
    }) {
        refs.push((id, generation));
    }
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
            SubstrateEvent, UserMemoryHandle, WaitTokenRef, WindowLeaseRef, WindowPerms,
        };
        use visa_profile::SubstrateProfile;

        use crate::{VisaArtifactDescriptor, VisaHostcallPayload};

        pub const VISA_CONSOLE_WRITE: u32 = 1;
        pub const VISA_TIMER_NOW: u32 = 2;
        pub const VISA_TIMER_ARM: u32 = 3;
        pub const VISA_EVENT_PUSH: u32 = 4;
        pub const VISA_EVENT_POP: u32 = 5;
        pub const VISA_MEMORY_COPYIN: u32 = 6;
        pub const VISA_MEMORY_COPYOUT: u32 = 7;
        pub const VISA_DMW_MAP: u32 = 8;
        pub const VISA_DMW_UNMAP: u32 = 9;
        pub const VISA_MMIO_READ32: u32 = 10;
        pub const VISA_MMIO_WRITE32: u32 = 11;
        pub const VISA_DMA_ALLOC: u32 = 12;
        pub const VISA_DMA_FREE: u32 = 13;
        pub const VISA_IRQ_ACK: u32 = 14;
        pub const VISA_IRQ_MASK: u32 = 15;
        pub const VISA_IRQ_UNMASK: u32 = 16;
        pub const VISA_SNAPSHOT_ENTER: u32 = 17;
        pub const VISA_SNAPSHOT_EXIT: u32 = 18;

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
                    HostcallCategory::Console,
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
                ))
                .with_hostcall(HostcallSpec::new(
                    VISA_EVENT_PUSH,
                    "visa.event.push",
                    HostcallCategory::EventLog,
                    "event-log.visa",
                    "append",
                    false,
                ))
                .with_hostcall(HostcallSpec::new(
                    VISA_EVENT_POP,
                    "visa.event.pop",
                    HostcallCategory::EventLog,
                    "event-log.visa",
                    "inspect",
                    false,
                ));
                descriptor.capabilities.push(TargetCapabilitySpec::new(
                    "visa.console",
                    &["write"],
                    "activation",
                ));
                descriptor.capabilities.push(TargetCapabilitySpec::new(
                    "visa.timer",
                    &["now", "arm"],
                    "activation",
                ));
                descriptor.capabilities.push(TargetCapabilitySpec::new(
                    "event-log.visa",
                    &["append", "inspect"],
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

            pub const fn event_push(&self, event: SubstrateEvent) -> VisaHostcallPayload {
                VisaHostcallPayload::EventPush { event }
            }

            pub const fn event_pop(&self) -> VisaHostcallPayload {
                VisaHostcallPayload::EventPop
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
                    HostcallCategory::Console,
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
                    "wasi.fd",
                    &["write"],
                    "activation",
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
    use std::{collections::BTreeMap, fs, vec};

    use semantic_core::{
        ContractEdgeMode, EventKind,
        target_executor::{ContractObjectRef, HostcallCategory, HostcallReturnTag},
        validate_contract_graph,
    };
    use sha2::{Digest, Sha256};
    use substrate_api::SubstrateResult;
    use target_abi::{
        OBJECT_KIND_CODE_OBJECT_V1, ObjectRefRaw, TargetArtifactHeaderV1, TargetSectionHeaderV1,
        TrapKindV1, TrapMapEntryV1, canonical_zero_field_image_hash,
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

    #[test]
    fn requester_optional_store_does_not_invent_zero_identity() {
        let requester = SubstrateRequester::new("test").with_artifact(ArtifactImageRef::new(7, 1));

        assert_eq!(requester_with_optional_store(requester.clone(), None, None).store, None);
        assert_eq!(requester_with_optional_store(requester.clone(), Some(9), None).store, None);
        assert_eq!(requester_with_optional_store(requester.clone(), None, Some(2)).store, None);
        assert_eq!(
            requester_with_optional_store(requester, Some(9), Some(2)).store,
            Some(StoreRef::new(9, 2))
        );
    }

    #[derive(Default)]
    struct MockSubstrate {
        loaded: Vec<ArtifactImageRef>,
        published: Vec<(ArtifactImageRef, CodeObjectRef)>,
        console: Vec<u8>,
        fail_console: bool,
        deny_console: bool,
        timers: Vec<(VirtualTime, WaitTokenRef)>,
        events: Vec<SubstrateEvent>,
        memory_writes: Vec<(UserMemoryHandle, u64, Vec<u8>)>,
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
            if self.deny_console {
                return Err(SubstrateError::denied(Some(substrate_api::CapabilityHandle::new(
                    55, 1,
                ))));
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

    impl GuestMemoryAuthority for MockSubstrate {
        fn copyin(
            &self,
            _mem: UserMemoryHandle,
            _ptr: u64,
            len: usize,
        ) -> SubstrateResult<GuestBytes> {
            Ok(vec![0x76; len])
        }

        fn copyout(&mut self, mem: UserMemoryHandle, ptr: u64, data: &[u8]) -> SubstrateResult<()> {
            self.memory_writes.push((mem, ptr, data.to_vec()));
            Ok(())
        }
    }
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
        let mut descriptor = VisaArtifactDescriptor::new(
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
        descriptor.imports.push("visa.hostcall_1".into());
        descriptor.exports.push("entry".into());

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
        let snapshot = runtime.snapshot().portable_subset();
        assert_eq!(snapshot.artifacts[0].imports, vec![String::from("visa.hostcall_1")]);
        assert_eq!(snapshot.artifacts[0].exports, vec![String::from("entry")]);

        runtime.restore_portable_subset(&snapshot).expect("restore portable snapshot");
        let restored = runtime.snapshot();
        assert_eq!(restored.artifacts[0].imports, vec![String::from("visa.hostcall_1")]);
        assert_eq!(restored.artifacts[0].exports, vec![String::from("entry")]);
    }

    #[test]
    fn runtime_profile_gate_accepts_p0_p4_before_code_start() {
        for (index, profile) in SubstrateProfile::ALL_ASCENDING.into_iter().enumerate() {
            let mut runtime = VisaRuntime::new(VisaRuntimeConfig::for_profile(profile));
            let mut substrate = MockSubstrate::default();
            let artifact = fake_image(&REQUIRED_SECTIONS);
            let descriptor = VisaArtifactDescriptor::new(
                100 + index as u64,
                &format!("profile-{}", profile.as_str()),
                "profile-artifact",
                profile,
            );

            let loaded = runtime
                .load_artifact(VisaArtifactInput { bytes: &artifact, descriptor }, &mut substrate)
                .unwrap_or_else(|error| panic!("{} should pass: {error:?}", profile.as_str()));

            assert_eq!(loaded.artifact_id, 100 + index as u64);
            assert_eq!(substrate.loaded, vec![ArtifactImageRef::new(100 + index as u64, 1)]);
            assert_eq!(substrate.published.len(), 1);
            assert_eq!(runtime.evidence_snapshot().profile_gate_rejection_count(), 0);
            assert!(
                runtime
                    .snapshot()
                    .stores
                    .iter()
                    .any(|store| { store.owner_profile == profile.as_str() })
            );
        }
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
        assert!(runtime.events().iter().any(|event| {
            matches!(
                event,
                VisaRuntimeEvent::ProfileGateRejected {
                    package,
                    artifact_id: 8,
                    required_profile: SubstrateProfile::DeviceCapable,
                    reported_profile: SubstrateProfile::SemanticHarness,
                    reason,
                    ..
                } if package == "device-driver" && reason == "reported-profile-below-required"
            )
        }));
        let profile_event = runtime
            .semantic()
            .event_log()
            .events()
            .iter()
            .find(|event| matches!(event.kind, EventKind::ProfileGateRejected { .. }))
            .expect("profile gate rejection event");
        assert!(profile_event.summary().contains(
            "ProfileGateRejected package=device-driver artifact=device-driver-artifact artifact_id=8"
        ));
        assert!(profile_event.summary().contains(
            "required=device-capable reported=semantic-harness enforced=semantic-harness reason=reported-profile-below-required"
        ));
        let evidence = runtime.evidence_snapshot();
        assert_eq!(evidence.profile_gate_rejection_count(), 1);
        assert_eq!(evidence.profile_gate_rejections[0].required_profile, "device-capable");
        assert_eq!(evidence.profile_gate_rejections[0].reported_profile, "semantic-harness");
        assert_eq!(evidence.profile_gate_rejections[0].reason, "reported-profile-below-required");
        let profile_gate_jsonl = evidence.profile_gate_rejections_jsonl();
        assert!(profile_gate_jsonl.contains("\"event_kind\":\"profile-gate-rejected\""));
        assert!(profile_gate_jsonl.contains("\"artifact_id\":8"));
        let root = temp_runtime_test_dir("profile-gate-trace");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("profile-gate.jsonl");
        fs::write(&path, profile_gate_jsonl.as_bytes()).unwrap();
        let conformance_report = visa_conformance::ConformanceReport {
            schema_version: visa_conformance::REPORT_SCHEMA_VERSION.to_string(),
            suite_id: "visa-layered-conformance".to_string(),
            target: "visa-runtime-unit".to_string(),
            generated_by: "visa-runtime-test".to_string(),
            results: vec![visa_conformance::TestResult {
                spec_id: "visa.artifact.load".to_string(),
                outcome: visa_conformance::Outcome::Pass,
                observed_boundary: visa_conformance::Boundary::PortableArtifactExecution,
                observed_profile: Some(
                    SubstrateProfile::SemanticHarness.canonical_id().to_string(),
                ),
                evidence: "runtime recorded artifact profile gate rejection".to_string(),
                remaining_uncertainty:
                    "profile gate rejection is failure evidence, not successful code start"
                        .to_string(),
                metrics: BTreeMap::from([("profile_gate_rejection_count".to_string(), 1.0)]),
                evidence_artifacts: vec![visa_conformance::EvidenceArtifact {
                    kind: visa_conformance::EvidenceArtifactKind::ProfileGateTrace,
                    uri: "profile-gate.jsonl".to_string(),
                    sha256: test_sha256_hex(profile_gate_jsonl.as_bytes()),
                    description: "runtime profile gate rejection trace".to_string(),
                }],
            }],
        };
        let validation = visa_conformance::validate_report_artifacts(&conformance_report, &root);
        assert!(validation.ok, "{:#?}", validation.findings);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn runtime_profile_gate_rejects_each_p0_p4_downgrade_before_substrate_dispatch() {
        let profiles = SubstrateProfile::ALL_ASCENDING;
        for pair in profiles.windows(2) {
            let reported = pair[0];
            let required = pair[1];
            let mut runtime = VisaRuntime::new(VisaRuntimeConfig {
                required_profile: reported,
                reported_profile: reported,
                enforced_capabilities: SubstrateCapabilitySet::for_profile(reported),
                evidence_level: EvidenceBoundaryLevel::PortableArtifactExecution,
                runtime_mode: RuntimeMode::Production,
            });
            let mut substrate = MockSubstrate::default();
            let artifact = fake_image(&REQUIRED_SECTIONS);
            let descriptor = VisaArtifactDescriptor::new(
                200 + reported as u64,
                &format!("downgrade-{}-{}", reported.as_str(), required.as_str()),
                "downgrade-artifact",
                required,
            );

            let error = runtime
                .load_artifact(VisaArtifactInput { bytes: &artifact, descriptor }, &mut substrate)
                .expect_err("profile downgrade should reject");

            assert!(matches!(
                error,
                VisaRuntimeError::ProfileGateRejected { required: observed_required, reported: observed_reported, .. }
                    if observed_required == required && observed_reported == reported
            ));
            assert!(substrate.loaded.is_empty());
            assert!(substrate.published.is_empty());
            let evidence = runtime.evidence_snapshot();
            assert_eq!(evidence.profile_gate_rejection_count(), 1);
            assert_eq!(evidence.profile_gate_rejections[0].required_profile, required.as_str());
            assert_eq!(evidence.profile_gate_rejections[0].reported_profile, reported.as_str());
            assert_eq!(evidence.profile_gate_rejections[0].enforced_profile, reported.as_str());
            assert_eq!(
                evidence.profile_gate_rejections[0].reason,
                "reported-profile-below-required"
            );
        }
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
        assert!(
            evidence.contract_graph.waits.iter().any(|wait| wait.id == 31 && wait.generation == 1)
        );
        let timer_hostcall = evidence
            .contract_graph
            .hostcalls
            .iter()
            .find(|hostcall| hostcall.hostcall_number == personality::wasi::WASI_TIMER_ARM)
            .expect("timer arm hostcall trace");
        assert_eq!(timer_hostcall.wait_token_out, Some(31));
        assert_eq!(timer_hostcall.wait_token_generation_out, Some(1));
        let wait_ref = evidence
            .contract_graph
            .waits
            .iter()
            .find(|wait| wait.id == 31)
            .expect("timer wait")
            .object_ref();
        assert!(evidence.contract_graph.explicit_edges.iter().any(|edge| {
            edge.from == timer_hostcall.object_ref()
                && edge.to == wait_ref
                && edge.mode == ContractEdgeMode::Live
                && edge.evidence_level == EvidenceBoundaryLevel::PortableArtifactExecution
                && edge.label == "hostcall-produces-wait-token"
        }));
        assert_eq!(
            evidence.authority_extractions[0],
            VisaSubstrateAuthorityExtractionEvidence {
                event_id: evidence.authority_extractions[0].event_id,
                event_epoch: evidence.authority_extractions[0].event_epoch,
                authority_family: "console".into(),
                authority: "ConsoleAuthority".into(),
                operation: "console_write".into(),
                requester: Some("wasi-app".into()),
                artifact_id: Some(9),
                store_id: Some(1),
                capability_id: Some(1),
                capability_generation: Some(1),
            }
        );
        let extraction_jsonl = evidence.authority_extractions_jsonl();
        assert_eq!(extraction_jsonl.lines().count(), 3);
        assert!(extraction_jsonl.contains("\"authority_family\":\"console\""));
        assert!(extraction_jsonl.contains("\"authority_family\":\"timer\""));
        assert!(extraction_jsonl.contains("\"authority\":\"ConsoleAuthority\""));
        assert!(extraction_jsonl.contains("\"operation\":\"console_write\""));
        assert!(extraction_jsonl.contains("\"requester\":\"wasi-app\""));
        assert!(extraction_jsonl.contains("\"artifact_id\":9"));
        assert!(extraction_jsonl.contains("\"store_id\":1"));

        let snapshot_json = evidence.contract_graph_snapshot_artifact_json();
        assert!(snapshot_json.contains(CONTRACT_GRAPH_SNAPSHOT_ARTIFACT_SCHEMA_VERSION));
        assert!(
            snapshot_json.contains("\"claimed_evidence_level\":\"portable-artifact-execution\"")
        );
        assert!(snapshot_json.contains("\"hostcalls\":[{\"id\":1,\"generation\":1}"));
        assert!(snapshot_json.contains("\"waits\":[{\"id\":31,\"generation\":1}]"));
        assert!(snapshot_json.contains("\"label\":\"hostcall-produces-wait-token\""));
        let root = temp_runtime_test_dir("snapshot-artifact");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("contract-graph-snapshot.json");
        fs::write(&path, snapshot_json.as_bytes()).unwrap();
        let conformance_report = visa_conformance::ConformanceReport {
            schema_version: visa_conformance::REPORT_SCHEMA_VERSION.to_string(),
            suite_id: "visa-layered-conformance".to_string(),
            target: "visa-runtime-unit".to_string(),
            generated_by: "visa-runtime-test".to_string(),
            results: vec![visa_conformance::TestResult {
                spec_id: "visa.artifact.load".to_string(),
                outcome: visa_conformance::Outcome::Pass,
                observed_boundary: visa_conformance::Boundary::PortableArtifactExecution,
                observed_profile: Some(SubstrateProfile::GuestFrontend.canonical_id().to_string()),
                evidence: "runtime produced contract graph snapshot artifact json".to_string(),
                remaining_uncertainty: "unit fixture validates artifact gate compatibility"
                    .to_string(),
                metrics: BTreeMap::new(),
                evidence_artifacts: vec![visa_conformance::EvidenceArtifact {
                    kind: visa_conformance::EvidenceArtifactKind::ContractGraphSnapshot,
                    uri: "contract-graph-snapshot.json".to_string(),
                    sha256: test_sha256_hex(snapshot_json.as_bytes()),
                    description: "runtime contract graph snapshot artifact".to_string(),
                }],
            }],
        };
        let validation = visa_conformance::validate_report_artifacts(&conformance_report, &root);
        assert!(validation.ok, "{:#?}", validation.findings);

        let extraction_with_target_jsonl =
            evidence.authority_extractions_jsonl_with_target_context("riscv64", "qemu-virt");
        assert!(extraction_with_target_jsonl.contains("\"target_arch\":\"riscv64\""));
        assert!(extraction_with_target_jsonl.contains("\"target_board\":\"qemu-virt\""));
        let extraction_path = root.join("substrate-extraction.jsonl");
        fs::write(&extraction_path, extraction_with_target_jsonl.as_bytes()).unwrap();
        let real_target_artifact_report = visa_conformance::ConformanceReport {
            schema_version: visa_conformance::REPORT_SCHEMA_VERSION.to_string(),
            suite_id: "visa-layered-conformance".to_string(),
            target: "visa-runtime-unit".to_string(),
            generated_by: "visa-runtime-test".to_string(),
            results: vec![visa_conformance::TestResult {
                spec_id: "substrate.profile.guest-frontend".to_string(),
                outcome: visa_conformance::Outcome::Pass,
                observed_boundary: visa_conformance::Boundary::RealTargetSubstrate,
                observed_profile: Some(SubstrateProfile::GuestFrontend.canonical_id().to_string()),
                evidence: "runtime exported target-context substrate extraction JSONL".to_string(),
                remaining_uncertainty:
                    "target identity is caller supplied and does not prove real execution"
                        .to_string(),
                metrics: BTreeMap::new(),
                evidence_artifacts: vec![visa_conformance::EvidenceArtifact {
                    kind: visa_conformance::EvidenceArtifactKind::SubstrateExtractionTrace,
                    uri: "substrate-extraction.jsonl".to_string(),
                    sha256: test_sha256_hex(extraction_with_target_jsonl.as_bytes()),
                    description: "target-context substrate extraction trace".to_string(),
                }],
            }],
        };
        let target_trace_validation =
            visa_conformance::validate_report_artifacts(&real_target_artifact_report, &root);
        assert!(target_trace_validation.ok, "{:#?}", target_trace_validation.findings);
        let _ = fs::remove_dir_all(root);
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
    fn authority_extraction_json_escaping_is_stable() {
        let mut out = String::new();
        push_json_string(&mut out, "quote\" slash\\ newline\n tab\t control\u{0007}");

        assert_eq!(out, "\"quote\\\" slash\\\\ newline\\n tab\\t control\\u0007\"");
    }

    fn temp_runtime_test_dir(name: &str) -> std::path::PathBuf {
        let nonce =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        std::env::temp_dir().join(format!("visa-runtime-{name}-{}-{nonce}", std::process::id()))
    }

    fn test_sha256_hex(bytes: &[u8]) -> String {
        let digest = Sha256::digest(bytes);
        let mut out = String::with_capacity(64);
        for byte in digest {
            use core::fmt::Write as _;
            write!(&mut out, "{byte:02x}").unwrap();
        }
        out
    }

    fn assert_no_success_dispatch(runtime: &VisaRuntime) {
        assert!(
            !runtime
                .events()
                .iter()
                .any(|event| matches!(event, VisaRuntimeEvent::HostcallDispatched { .. }))
        );
        assert!(!runtime.events().iter().any(|event| {
            matches!(event, VisaRuntimeEvent::SubstrateAuthorityExtracted { .. })
        }));
        assert!(
            !runtime.semantic().event_log().events().iter().any(|event| {
                matches!(&event.kind, EventKind::SubstrateAuthorityExtracted { .. })
            })
        );
    }

    fn assert_snapshot_has_portable_failure_path(
        evidence: &VisaRuntimeEvidenceSnapshot,
        activation: &ActivationHandle,
        hostcall_result: Option<&str>,
        trap_kind: Option<&str>,
    ) {
        assert_eq!(validate_contract_graph(&evidence.contract_graph), Vec::new());
        assert_eq!(evidence.contract_graph.artifacts.len(), 1);
        assert_eq!(evidence.contract_graph.code_objects.len(), 1);
        assert_eq!(evidence.contract_graph.stores.len(), 1);
        assert_eq!(evidence.contract_graph.activations.len(), 1);
        assert_eq!(evidence.contract_graph.traps.len(), 1);
        if let Some(hostcall_result) = hostcall_result {
            assert_eq!(evidence.contract_graph.hostcalls.len(), 1);
            let hostcall = &evidence.contract_graph.hostcalls[0];
            assert!(!hostcall.allowed);
            assert_eq!(hostcall.result, hostcall_result);
            assert_eq!(hostcall.activation, activation.activation_id);
            assert_eq!(hostcall.store, activation.store_id);
            assert_eq!(hostcall.code_object, activation.code_object_id);
            assert_eq!(hostcall.artifact, activation.artifact_id);
            assert_eq!(hostcall.trap_out, Some(evidence.contract_graph.traps[0].id));
        }
        let trap = &evidence.contract_graph.traps[0];
        assert_eq!(trap.activation, Some(activation.activation_id));
        assert_eq!(trap.store, Some(activation.store_id));
        assert_eq!(trap.code_object, Some(activation.code_object_id));
        assert_eq!(trap.artifact, Some(activation.artifact_id));
        if let Some(trap_kind) = trap_kind {
            assert_eq!(trap.trap_kind.as_deref(), Some(trap_kind));
        }

        let artifact_ref = evidence.contract_graph.artifacts[0].object_ref();
        let code_ref = evidence.contract_graph.code_objects[0].object_ref();
        let store_ref = evidence.contract_graph.stores[0].object_ref();
        let activation_ref = evidence.contract_graph.activations[0].object_ref();
        assert_portable_path_edge(
            evidence,
            artifact_ref,
            code_ref,
            &[ContractEdgeMode::Live],
            "artifact-loads-code-object",
        );
        assert_portable_path_edge(
            evidence,
            code_ref,
            store_ref,
            &[ContractEdgeMode::Live],
            "code-object-bound-to-store",
        );
        assert_portable_path_edge(
            evidence,
            store_ref,
            activation_ref,
            &[ContractEdgeMode::Live, ContractEdgeMode::Historical],
            "store-starts-activation",
        );
        if let Some(hostcall) = evidence.contract_graph.hostcalls.first() {
            assert_portable_path_edge(
                evidence,
                activation_ref,
                hostcall.object_ref(),
                &[ContractEdgeMode::Live, ContractEdgeMode::Historical],
                "activation-dispatches-hostcall-frame",
            );
        }
        assert_portable_path_edge(
            evidence,
            activation_ref,
            trap.object_ref(),
            &[ContractEdgeMode::Live, ContractEdgeMode::Historical],
            "activation-records-trap-map",
        );
    }

    fn assert_portable_path_edge(
        evidence: &VisaRuntimeEvidenceSnapshot,
        from: ContractObjectRef,
        to: ContractObjectRef,
        allowed_modes: &[ContractEdgeMode],
        label: &str,
    ) {
        assert!(evidence.contract_graph.explicit_edges.iter().any(|edge| {
            edge.from == from
                && edge.to == to
                && allowed_modes.contains(&edge.mode)
                && edge.evidence_level == EvidenceBoundaryLevel::PortableArtifactExecution
                && edge.label == label
        }));
    }

    fn assert_contract_graph_snapshot_artifact_gate_accepts(
        evidence: &VisaRuntimeEvidenceSnapshot,
        name: &str,
    ) {
        let snapshot_json = evidence.contract_graph_snapshot_artifact_json();
        let root = temp_runtime_test_dir(name);
        fs::create_dir_all(&root).unwrap();
        let path = root.join("contract-graph-snapshot.json");
        fs::write(&path, snapshot_json.as_bytes()).unwrap();
        let conformance_report = visa_conformance::ConformanceReport {
            schema_version: visa_conformance::REPORT_SCHEMA_VERSION.to_string(),
            suite_id: "visa-layered-conformance".to_string(),
            target: "visa-runtime-unit".to_string(),
            generated_by: "visa-runtime-test".to_string(),
            results: vec![visa_conformance::TestResult {
                spec_id: "visa.artifact.failure".to_string(),
                outcome: visa_conformance::Outcome::Pass,
                observed_boundary: visa_conformance::Boundary::PortableArtifactExecution,
                observed_profile: Some(SubstrateProfile::GuestFrontend.canonical_id().to_string()),
                evidence: "runtime produced artifact-path failure contract graph snapshot"
                    .to_string(),
                remaining_uncertainty:
                    "failure snapshot proves attribution, not successful dispatch".to_string(),
                metrics: BTreeMap::new(),
                evidence_artifacts: vec![visa_conformance::EvidenceArtifact {
                    kind: visa_conformance::EvidenceArtifactKind::ContractGraphSnapshot,
                    uri: "contract-graph-snapshot.json".to_string(),
                    sha256: test_sha256_hex(snapshot_json.as_bytes()),
                    description: "runtime failure contract graph snapshot artifact".to_string(),
                }],
            }],
        };
        let validation = visa_conformance::validate_report_artifacts(&conformance_report, &root);
        assert!(validation.ok, "{:#?}", validation.findings);
        let _ = fs::remove_dir_all(root);
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
                authority_family: "console".into(),
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
        let unsupported_jsonl = evidence.unsupported_substrate_events_jsonl();
        assert!(unsupported_jsonl.contains("\"event_kind\":\"unsupported\""));
        assert!(unsupported_jsonl.contains("\"authority_family\":\"console\""));
        assert!(unsupported_jsonl.contains("\"artifact\":44"));
        let root = temp_runtime_test_dir("unsupported-substrate-trace");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("substrate-events.jsonl");
        fs::write(&path, unsupported_jsonl.as_bytes()).unwrap();
        let conformance_report = visa_conformance::ConformanceReport {
            schema_version: visa_conformance::REPORT_SCHEMA_VERSION.to_string(),
            suite_id: "visa-layered-conformance".to_string(),
            target: "visa-runtime-unit".to_string(),
            generated_by: "visa-runtime-test".to_string(),
            results: vec![visa_conformance::TestResult {
                spec_id: "visa.capability.hostcall".to_string(),
                outcome: visa_conformance::Outcome::Pass,
                observed_boundary: visa_conformance::Boundary::PortableArtifactExecution,
                observed_profile: Some(SubstrateProfile::GuestFrontend.canonical_id().to_string()),
                evidence: "runtime recorded unsupported substrate dispatch evidence".to_string(),
                remaining_uncertainty: "unsupported dispatch is failure evidence and does not commit a successful hostcall trace".to_string(),
                metrics: BTreeMap::from([(
                    "unsupported_substrate_event_count".to_string(),
                    1.0,
                )]),
                evidence_artifacts: vec![visa_conformance::EvidenceArtifact {
                    kind: visa_conformance::EvidenceArtifactKind::SubstrateEventTrace,
                    uri: "substrate-events.jsonl".to_string(),
                    sha256: test_sha256_hex(unsupported_jsonl.as_bytes()),
                    description: "runtime unsupported substrate event trace".to_string(),
                }],
            }],
        };
        let validation = visa_conformance::validate_report_artifacts(&conformance_report, &root);
        assert!(validation.ok, "{:#?}", validation.findings);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn denied_substrate_dispatch_records_event_log_and_trace_evidence() {
        let personality =
            personality::wasi::WasiPersonality::new("wasi-app", SubstrateProfile::GuestFrontend);
        let mut runtime =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::GuestFrontend));
        let mut substrate = MockSubstrate { deny_console: true, ..MockSubstrate::default() };
        let artifact = fake_image(&REQUIRED_SECTIONS);

        let err = runtime
            .run(
                VisaArtifactInput { bytes: &artifact, descriptor: personality.descriptor(62) },
                ActivationEntry::Symbol("wasi_start".into()),
                [VisaExecutionStep::new(
                    personality::wasi::WASI_FD_WRITE,
                    personality.fd_write(b"denied"),
                )],
                &mut substrate,
            )
            .expect_err("denied substrate dispatch must reject execution");

        assert!(matches!(
            err,
            VisaRuntimeError::SubstrateDispatch {
                authority: "ConsoleAuthority",
                operation: "console_write",
                error: SubstrateError::Denied { .. },
            }
        ));
        assert_eq!(substrate.console, b"");
        assert!(matches!(
            substrate.events.as_slice(),
            [SubstrateEvent::CapabilityDenied {
                authority: "ConsoleAuthority",
                operation: "console_write",
                ..
            }]
        ));
        let evidence = runtime.evidence_snapshot();
        assert_eq!(evidence.authority_extraction_count(), 0);
        assert_eq!(evidence.unsupported_substrate_event_count(), 0);
        assert_eq!(evidence.denied_substrate_event_count(), 1);
        assert_eq!(evidence.denied_substrate_events[0].authority_family, "console");
        assert_eq!(evidence.denied_substrate_events[0].capability_id, Some(55));
        assert_eq!(evidence.denied_substrate_events[0].capability_generation, Some(1));
        assert!(runtime.semantic().event_log().events().iter().any(|event| {
            matches!(
                &event.kind,
                EventKind::SubstrateCapabilityDenied {
                    authority_family,
                    authority,
                    operation,
                    artifact: Some(62),
                    store: Some(1),
                    capability: Some(55),
                    capability_generation: Some(1),
                    ..
                } if authority_family == "console"
                    && authority == "ConsoleAuthority"
                    && operation == "console_write"
            )
        }));
        let substrate_events_jsonl = evidence.substrate_events_jsonl();
        assert!(substrate_events_jsonl.contains("\"event_kind\":\"capability-denied\""));
        assert!(substrate_events_jsonl.contains("\"authority_family\":\"console\""));
        assert!(substrate_events_jsonl.contains("\"capability\":55"));

        let root = temp_runtime_test_dir("denied-substrate-dispatch");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("substrate-events.jsonl");
        fs::write(&path, substrate_events_jsonl.as_bytes()).unwrap();
        let conformance_report = visa_conformance::ConformanceReport {
            schema_version: visa_conformance::REPORT_SCHEMA_VERSION.to_string(),
            suite_id: "visa-layered-conformance".to_string(),
            target: "visa-runtime-unit".to_string(),
            generated_by: "visa-runtime-test".to_string(),
            results: vec![visa_conformance::TestResult {
                spec_id: "visa.capability.hostcall".to_string(),
                outcome: visa_conformance::Outcome::Pass,
                observed_boundary: visa_conformance::Boundary::PortableArtifactExecution,
                observed_profile: Some(SubstrateProfile::GuestFrontend.canonical_id().to_string()),
                evidence: "runtime recorded substrate denied dispatch evidence".to_string(),
                remaining_uncertainty:
                    "denied dispatch proves failure visibility, not successful operation"
                        .to_string(),
                metrics: BTreeMap::from([("denied_substrate_event_count".to_string(), 1.0)]),
                evidence_artifacts: vec![visa_conformance::EvidenceArtifact {
                    kind: visa_conformance::EvidenceArtifactKind::SubstrateEventTrace,
                    uri: "substrate-events.jsonl".to_string(),
                    sha256: test_sha256_hex(substrate_events_jsonl.as_bytes()),
                    description: "runtime denied substrate event trace".to_string(),
                }],
            }],
        };
        let validation = visa_conformance::validate_report_artifacts(&conformance_report, &root);
        assert!(validation.ok, "{:#?}", validation.findings);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn runtime_rejects_malformed_artifact_images_before_contract_state() {
        let mut runtime =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::GuestFrontend));
        let initial_events = runtime.events().len();
        let mut substrate = MockSubstrate::default();
        let descriptor = VisaArtifactDescriptor::new(
            45,
            "bad-image",
            "bad-image-artifact",
            SubstrateProfile::GuestFrontend,
        );

        let err = runtime
            .load_artifact(
                VisaArtifactInput { bytes: b"not-a-target-artifact", descriptor },
                &mut substrate,
            )
            .expect_err("bad wire image must be rejected");

        assert_eq!(err, VisaRuntimeError::Artifact(TargetArtifactError::ImageTooSmall));
        assert!(substrate.loaded.is_empty());
        assert!(substrate.published.is_empty());
        assert_eq!(runtime.events().len(), initial_events);
        let evidence = runtime.evidence_snapshot();
        assert!(evidence.contract_graph.artifacts.is_empty());
        assert!(evidence.contract_graph.code_objects.is_empty());
        assert!(evidence.contract_graph.stores.is_empty());
        assert!(evidence.contract_graph.activations.is_empty());
        assert_eq!(evidence.hostcall_trace_count(), 0);
    }

    #[test]
    fn runtime_rejects_artifact_without_code_object_before_substrate_dispatch() {
        let mut runtime =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::GuestFrontend));
        let initial_events = runtime.events().len();
        let mut substrate = MockSubstrate::default();
        let artifact = fake_image(&[
            SectionKindV1::Manifest,
            SectionKindV1::HostcallImportTable,
            SectionKindV1::TrapMap,
            SectionKindV1::PcRangeTable,
            SectionKindV1::ProfileRequirements,
            SectionKindV1::Signature,
        ]);
        let descriptor = VisaArtifactDescriptor::new(
            46,
            "missing-code",
            "missing-code-artifact",
            SubstrateProfile::GuestFrontend,
        );

        let err = runtime
            .load_artifact(VisaArtifactInput { bytes: &artifact, descriptor }, &mut substrate)
            .expect_err("missing CodeObject section must be rejected");

        assert_eq!(
            err,
            VisaRuntimeError::Artifact(TargetArtifactError::MissingRequiredSection(
                SectionKindV1::CodeObject
            ))
        );
        assert!(substrate.loaded.is_empty());
        assert!(substrate.published.is_empty());
        assert_eq!(runtime.events().len(), initial_events);
        assert!(runtime.snapshot().artifacts.is_empty());
        assert!(runtime.snapshot().code_objects.is_empty());
        assert!(runtime.snapshot().stores.is_empty());
    }

    #[test]
    fn runtime_unsupported_hostcall_records_artifact_path_failure_evidence() {
        let mut runtime =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::GuestFrontend));
        let mut substrate = MockSubstrate::default();
        let artifact = fake_image(&REQUIRED_SECTIONS);
        let descriptor = VisaArtifactDescriptor::new(
            49,
            "unsupported-hostcall-app",
            "unsupported-hostcall-artifact",
            SubstrateProfile::GuestFrontend,
        )
        .with_hostcall(HostcallSpec::new(
            1,
            "declared.noop",
            HostcallCategory::Service,
            "declared.noop",
            "call",
            false,
        ));
        let loaded = runtime
            .load_artifact(VisaArtifactInput { bytes: &artifact, descriptor }, &mut substrate)
            .expect("load artifact");
        let activation = runtime
            .start_activation(&loaded, ActivationEntry::Symbol("entry".into()))
            .expect("start activation");

        let err = runtime
            .invoke_hostcall(&activation, 404, VisaHostcallPayload::None, &mut substrate)
            .expect_err("undeclared hostcall must be trapped by executor attribution");

        assert!(matches!(
            err,
            VisaRuntimeError::Executor(TargetExecutorError::HostcallNotDeclared)
        ));
        assert_no_success_dispatch(&runtime);
        let evidence = runtime.evidence_snapshot();
        assert_eq!(evidence.authority_extraction_count(), 0);
        assert_eq!(evidence.unsupported_substrate_event_count(), 0);
        assert_snapshot_has_portable_failure_path(
            &evidence,
            &activation,
            Some("unsupported-call"),
            None,
        );
        let hostcall = &evidence.contract_graph.hostcalls[0];
        assert_eq!(hostcall.hostcall_number, 404);
        assert_eq!(hostcall.name, "hostcall.unsupported");
        assert_eq!(hostcall.ret_tag, HostcallReturnTag::BadAbi);
        let trap = &evidence.contract_graph.traps[0];
        assert_eq!(trap.class, semantic_core::target_executor::TargetTrapClass::HostcallTrap);
        assert_eq!(trap.fault_policy, "unsupported-hostcall");
        assert_eq!(trap.detail, "hostcall unsupported by artifact import table");
        assert_contract_graph_snapshot_artifact_gate_accepts(
            &evidence,
            "unsupported-hostcall-snapshot-artifact",
        );
    }

    #[test]
    fn runtime_console_capability_denial_records_trap_before_substrate_dispatch() {
        let mut runtime =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::GuestFrontend));
        let mut substrate = MockSubstrate::default();
        let artifact = fake_image(&REQUIRED_SECTIONS);
        let descriptor = VisaArtifactDescriptor::new(
            63,
            "console-cap-denied-app",
            "console-cap-denied-artifact",
            SubstrateProfile::GuestFrontend,
        )
        .with_hostcall(HostcallSpec::new(
            1,
            "visa.console.write",
            HostcallCategory::Console,
            "visa.console",
            "write",
            false,
        ));
        let loaded = runtime
            .load_artifact(VisaArtifactInput { bytes: &artifact, descriptor }, &mut substrate)
            .expect("load artifact");
        let activation = runtime
            .start_activation(&loaded, ActivationEntry::Symbol("entry".into()))
            .expect("start activation");

        let err = runtime
            .invoke_hostcall(
                &activation,
                1,
                VisaHostcallPayload::ConsoleWrite { bytes: b"no-cap".to_vec() },
                &mut substrate,
            )
            .expect_err("missing console capability must deny before substrate call");

        assert!(matches!(err, VisaRuntimeError::Executor(TargetExecutorError::CapabilityDenied)));
        assert_eq!(substrate.console, b"");
        assert_no_success_dispatch(&runtime);
        let evidence = runtime.evidence_snapshot();
        assert_eq!(evidence.authority_extraction_count(), 0);
        assert_eq!(evidence.unsupported_substrate_event_count(), 0);
        assert_eq!(evidence.denied_substrate_event_count(), 1);
        assert_eq!(evidence.denied_substrate_events[0].authority_family, "console");
        assert_eq!(evidence.denied_substrate_events[0].authority, "ConsoleAuthority");
        assert_eq!(evidence.denied_substrate_events[0].operation, "console_write");
        assert_eq!(
            evidence.denied_substrate_events[0].requester.as_deref(),
            Some("console-cap-denied-app")
        );
        assert_eq!(evidence.denied_substrate_events[0].artifact_id, Some(63));
        assert_eq!(evidence.denied_substrate_events[0].store_id, Some(1));
        assert!(evidence.denied_substrate_events[0].capability_id.is_none());
        assert!(evidence.denied_substrate_events[0].capability_generation.is_none());
        assert_snapshot_has_portable_failure_path(
            &evidence,
            &activation,
            Some("cap-arg-required"),
            None,
        );
        let hostcall = &evidence.contract_graph.hostcalls[0];
        assert_eq!(hostcall.category, HostcallCategory::Console);
        assert_eq!(hostcall.object, "visa.console");
        assert_eq!(hostcall.operation, "write");
        assert_eq!(hostcall.ret_tag, HostcallReturnTag::Trap);
        assert_eq!(hostcall.denial_reason.as_deref(), Some("cap-arg-required"));
        let trap = &evidence.contract_graph.traps[0];
        assert_eq!(trap.class, semantic_core::target_executor::TargetTrapClass::CapabilityTrap);
        assert_eq!(trap.fault_policy, "capability-handle");
        assert_eq!(trap.detail, "hostcall capability handle argument failed validation");
        assert!(runtime.semantic().event_log().events().iter().any(|event| {
            matches!(
                &event.kind,
                EventKind::SubstrateCapabilityDenied {
                    authority_family,
                    authority,
                    operation,
                    requester,
                    artifact: Some(63),
                    store: Some(1),
                    capability: None,
                    capability_generation: None,
                } if authority_family == "console"
                    && authority == "ConsoleAuthority"
                    && operation == "console_write"
                    && requester.as_deref() == Some("console-cap-denied-app")
            )
        }));
        let denied_jsonl = evidence.denied_substrate_events_jsonl();
        assert!(denied_jsonl.contains("\"event_kind\":\"capability-denied\""));
        assert!(denied_jsonl.contains("\"authority_family\":\"console\""));
        assert!(denied_jsonl.contains("\"artifact\":63"));
        let root = temp_runtime_test_dir("console-capability-denied-substrate-trace");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("substrate-events.jsonl");
        fs::write(&path, denied_jsonl.as_bytes()).unwrap();
        let conformance_report = visa_conformance::ConformanceReport {
            schema_version: visa_conformance::REPORT_SCHEMA_VERSION.to_string(),
            suite_id: "visa-layered-conformance".to_string(),
            target: "visa-runtime-unit".to_string(),
            generated_by: "visa-runtime-test".to_string(),
            results: vec![visa_conformance::TestResult {
                spec_id: "visa.capability.hostcall".to_string(),
                outcome: visa_conformance::Outcome::Pass,
                observed_boundary: visa_conformance::Boundary::PortableArtifactExecution,
                observed_profile: Some(SubstrateProfile::GuestFrontend.canonical_id().to_string()),
                evidence: "runtime recorded console capability denied substrate evidence"
                    .to_string(),
                remaining_uncertainty:
                    "denial evidence proves failure attribution, not successful dispatch"
                        .to_string(),
                metrics: BTreeMap::from([("denied_substrate_event_count".to_string(), 1.0)]),
                evidence_artifacts: vec![visa_conformance::EvidenceArtifact {
                    kind: visa_conformance::EvidenceArtifactKind::SubstrateEventTrace,
                    uri: "substrate-events.jsonl".to_string(),
                    sha256: test_sha256_hex(denied_jsonl.as_bytes()),
                    description: "runtime console capability denied substrate event trace"
                        .to_string(),
                }],
            }],
        };
        let validation = visa_conformance::validate_report_artifacts(&conformance_report, &root);
        assert!(validation.ok, "{:#?}", validation.findings);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn runtime_capability_denial_records_trap_before_substrate_dispatch() {
        let mut runtime =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::GuestFrontend));
        let mut substrate = MockSubstrate::default();
        let artifact = fake_image(&REQUIRED_SECTIONS);
        let descriptor = VisaArtifactDescriptor::new(
            50,
            "cap-denied-app",
            "cap-denied-artifact",
            SubstrateProfile::GuestFrontend,
        )
        .with_hostcall(HostcallSpec::new(
            8,
            "guest.memory.read",
            HostcallCategory::GuestMemory,
            "guest-memory.main",
            "read",
            true,
        ));
        let loaded = runtime
            .load_artifact(VisaArtifactInput { bytes: &artifact, descriptor }, &mut substrate)
            .expect("load artifact");
        let activation = runtime
            .start_activation(&loaded, ActivationEntry::Symbol("entry".into()))
            .expect("start activation");

        let err = runtime
            .invoke_hostcall(
                &activation,
                8,
                VisaHostcallPayload::GuestMemoryCopyIn {
                    memory: UserMemoryHandle::new(7, 1),
                    ptr: 0,
                    len: 4,
                },
                &mut substrate,
            )
            .expect_err("missing capability handle must deny before substrate call");

        assert!(matches!(err, VisaRuntimeError::Executor(TargetExecutorError::CapabilityDenied)));
        assert_no_success_dispatch(&runtime);
        let evidence = runtime.evidence_snapshot();
        assert_eq!(evidence.authority_extraction_count(), 0);
        assert_eq!(evidence.unsupported_substrate_event_count(), 0);
        assert_eq!(evidence.denied_substrate_event_count(), 1);
        assert_eq!(evidence.denied_substrate_events[0].authority_family, "memory");
        assert_eq!(evidence.denied_substrate_events[0].authority, "GuestMemoryAuthority");
        assert_eq!(evidence.denied_substrate_events[0].operation, "copyin");
        assert_eq!(
            evidence.denied_substrate_events[0].requester.as_deref(),
            Some("cap-denied-app")
        );
        assert_eq!(evidence.denied_substrate_events[0].artifact_id, Some(50));
        assert_eq!(evidence.denied_substrate_events[0].store_id, Some(1));
        assert_snapshot_has_portable_failure_path(
            &evidence,
            &activation,
            Some("cap-arg-required"),
            None,
        );
        let hostcall = &evidence.contract_graph.hostcalls[0];
        assert_eq!(hostcall.ret_tag, HostcallReturnTag::Trap);
        assert_eq!(hostcall.denial_reason.as_deref(), Some("cap-arg-required"));
        let trap = &evidence.contract_graph.traps[0];
        assert_eq!(trap.class, semantic_core::target_executor::TargetTrapClass::CapabilityTrap);
        assert_eq!(trap.fault_policy, "capability-handle");
        assert_eq!(trap.detail, "hostcall capability handle argument failed validation");
        assert_contract_graph_snapshot_artifact_gate_accepts(
            &evidence,
            "capability-denial-snapshot-artifact",
        );
        let denied_jsonl = evidence.denied_substrate_events_jsonl();
        assert!(denied_jsonl.contains("\"event_kind\":\"capability-denied\""));
        assert!(denied_jsonl.contains("\"authority_family\":\"memory\""));
        assert!(denied_jsonl.contains("\"artifact\":50"));
        let root = temp_runtime_test_dir("capability-denied-substrate-trace");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("substrate-events.jsonl");
        fs::write(&path, denied_jsonl.as_bytes()).unwrap();
        let conformance_report = visa_conformance::ConformanceReport {
            schema_version: visa_conformance::REPORT_SCHEMA_VERSION.to_string(),
            suite_id: "visa-layered-conformance".to_string(),
            target: "visa-runtime-unit".to_string(),
            generated_by: "visa-runtime-test".to_string(),
            results: vec![visa_conformance::TestResult {
                spec_id: "visa.capability.hostcall".to_string(),
                outcome: visa_conformance::Outcome::Pass,
                observed_boundary: visa_conformance::Boundary::PortableArtifactExecution,
                observed_profile: Some(SubstrateProfile::GuestFrontend.canonical_id().to_string()),
                evidence: "runtime recorded capability denied substrate evidence".to_string(),
                remaining_uncertainty:
                    "denial evidence proves failure attribution, not successful dispatch"
                        .to_string(),
                metrics: BTreeMap::from([("denied_substrate_event_count".to_string(), 1.0)]),
                evidence_artifacts: vec![visa_conformance::EvidenceArtifact {
                    kind: visa_conformance::EvidenceArtifactKind::SubstrateEventTrace,
                    uri: "substrate-events.jsonl".to_string(),
                    sha256: test_sha256_hex(denied_jsonl.as_bytes()),
                    description: "runtime capability denied substrate event trace".to_string(),
                }],
            }],
        };
        let validation = visa_conformance::validate_report_artifacts(&conformance_report, &root);
        assert!(validation.ok, "{:#?}", validation.findings);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn runtime_bad_hostcall_abi_records_failure_trace_without_dispatch() {
        let mut runtime =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::GuestFrontend));
        let mut substrate = MockSubstrate::default();
        let artifact = fake_image(&REQUIRED_SECTIONS);
        let descriptor = VisaArtifactDescriptor::new(
            51,
            "bad-abi-app",
            "bad-abi-artifact",
            SubstrateProfile::GuestFrontend,
        )
        .with_hostcall(HostcallSpec::new(
            1,
            "abi.noop",
            HostcallCategory::Service,
            "abi.noop",
            "call",
            false,
        ));
        let loaded = runtime
            .load_artifact(VisaArtifactInput { bytes: &artifact, descriptor }, &mut substrate)
            .expect("load artifact");
        let activation = runtime
            .start_activation(&loaded, ActivationEntry::Symbol("entry".into()))
            .expect("start activation");

        let err = runtime
            .preflight_hostcall_frame_for_test(
                &activation,
                1,
                &VisaHostcallPayload::None,
                |frame| {
                    frame.abi_version = 0xffff;
                },
            )
            .expect_err("bad hostcall ABI must trap during preflight");

        assert!(matches!(
            err,
            VisaRuntimeError::Executor(TargetExecutorError::HostcallAbiMismatch)
        ));
        assert_no_success_dispatch(&runtime);
        let evidence = runtime.evidence_snapshot();
        assert_snapshot_has_portable_failure_path(
            &evidence,
            &activation,
            Some("bad-hostcall-abi"),
            None,
        );
        let hostcall = &evidence.contract_graph.hostcalls[0];
        assert_eq!(hostcall.ret_tag, HostcallReturnTag::BadAbi);
        assert_eq!(hostcall.abi_version, "wire-v65535");
        let trap = &evidence.contract_graph.traps[0];
        assert_eq!(trap.class, semantic_core::target_executor::TargetTrapClass::HostcallTrap);
        assert_eq!(trap.fault_policy, "bad-hostcall-abi");
        assert_eq!(trap.detail, "hostcall frame ABI version mismatch");
        assert_contract_graph_snapshot_artifact_gate_accepts(
            &evidence,
            "bad-abi-snapshot-artifact",
        );
    }

    #[test]
    fn runtime_wasm_trap_map_records_portable_artifact_failure_evidence() {
        let mut runtime =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::GuestFrontend));
        let mut substrate = MockSubstrate::default();
        let artifact = fake_image(&REQUIRED_SECTIONS);
        let loaded = runtime
            .load_artifact(
                VisaArtifactInput {
                    bytes: &artifact,
                    descriptor: VisaArtifactDescriptor::new(
                        52,
                        "wasm-trap-app",
                        "wasm-trap-artifact",
                        SubstrateProfile::GuestFrontend,
                    ),
                },
                &mut substrate,
            )
            .expect("load artifact");
        let activation = runtime
            .start_activation(&loaded, ActivationEntry::Symbol("entry".into()))
            .expect("start activation");
        let code = runtime.code_object(activation.code_object_id).expect("code object").clone();
        let trap_offset = 0x20;
        let trap_map = [TrapMapEntryV1::new(
            ObjectRefRaw::new(OBJECT_KIND_CODE_OBJECT_V1, code.id, code.generation),
            trap_offset,
            trap_offset + 4,
            TrapKindV1::WasmUnreachable,
            3,
            0x44,
            9,
        )];

        let trap_id = runtime
            .record_trap_by_pc_for_test(&activation, code.text.start + trap_offset, &trap_map)
            .expect("record trap by pc");

        assert_no_success_dispatch(&runtime);
        let evidence = runtime.evidence_snapshot();
        assert_eq!(evidence.contract_graph.hostcalls.len(), 0);
        assert_snapshot_has_portable_failure_path(
            &evidence,
            &activation,
            None,
            Some("wasm-unreachable"),
        );
        let trap = &evidence.contract_graph.traps[0];
        assert_eq!(trap.id, trap_id);
        assert_eq!(trap.class, semantic_core::target_executor::TargetTrapClass::GuestTrap);
        assert_eq!(trap.attribution_status, "trap-map-attributed");
        assert_eq!(trap.target_pc, Some(code.text.start + trap_offset));
        assert_eq!(trap.offset, Some(trap_offset));
        assert_eq!(trap.function_index, Some(3));
        assert_eq!(trap.wasm_offset, Some(0x44));
        assert_eq!(trap.debug_symbol, Some(9));
        assert_contract_graph_snapshot_artifact_gate_accepts(
            &evidence,
            "wasm-trap-snapshot-artifact",
        );
    }

    #[test]
    fn runtime_trap_evidence_preserves_activation_path_identities() {
        let mut runtime =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::GuestFrontend));
        let mut substrate = MockSubstrate::default();
        let artifact = fake_image(&REQUIRED_SECTIONS);
        let loaded = runtime
            .load_artifact(
                VisaArtifactInput {
                    bytes: &artifact,
                    descriptor: VisaArtifactDescriptor::new(
                        47,
                        "trap-demo",
                        "trap-demo-artifact",
                        SubstrateProfile::GuestFrontend,
                    ),
                },
                &mut substrate,
            )
            .expect("load artifact");
        let activation = runtime
            .start_activation(&loaded, ActivationEntry::Symbol("entry".into()))
            .expect("start activation");

        runtime.record_synthetic_trap(
            activation.activation_id,
            activation.store_id,
            "runtime evidence trap",
        );

        let evidence = runtime.evidence_snapshot();
        assert_eq!(validate_contract_graph(&evidence.contract_graph), Vec::new());
        assert_eq!(evidence.contract_graph.artifacts.len(), 1);
        assert_eq!(evidence.contract_graph.code_objects.len(), 1);
        assert_eq!(evidence.contract_graph.stores.len(), 1);
        assert_eq!(evidence.contract_graph.activations.len(), 1);
        assert_eq!(evidence.contract_graph.traps.len(), 1);
        let trap = &evidence.contract_graph.traps[0];
        assert_eq!(trap.store, Some(activation.store_id));
        assert_eq!(trap.activation, Some(activation.activation_id));
        assert_eq!(trap.code_object, Some(activation.code_object_id));
        assert_eq!(trap.artifact, Some(activation.artifact_id));
        assert_eq!(trap.attribution_status, "synthetic");
        assert_eq!(trap.detail, "runtime evidence trap");

        let snapshot_json = evidence.contract_graph_snapshot_artifact_json();
        assert!(snapshot_json.contains("\"artifacts\":[{\"id\":47,\"generation\":1}]"));
        assert!(snapshot_json.contains(&format!(
            "\"code_objects\":[{{\"id\":{},\"generation\":{}}}]",
            activation.code_object_id, evidence.contract_graph.code_objects[0].generation
        )));
        assert!(snapshot_json.contains(&format!(
            "\"stores\":[{{\"id\":{},\"generation\":{}}}]",
            activation.store_id, evidence.contract_graph.stores[0].generation
        )));
        assert!(snapshot_json.contains(&format!(
            "\"activations\":[{{\"id\":{},\"generation\":{}}}]",
            activation.activation_id, evidence.contract_graph.activations[0].generation
        )));
        assert!(snapshot_json.contains(&format!(
            "\"traps\":[{{\"id\":{},\"generation\":{}}}]",
            trap.id, trap.generation
        )));
    }

    #[test]
    fn runtime_cleanup_evidence_preserves_activation_path_identities() {
        let mut runtime =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::GuestFrontend));
        let mut substrate = MockSubstrate::default();
        let artifact = fake_image(&REQUIRED_SECTIONS);
        let descriptor = VisaArtifactDescriptor::new(
            48,
            "cleanup-app",
            "cleanup-artifact",
            SubstrateProfile::GuestFrontend,
        )
        .with_hostcall(HostcallSpec::new(
            99,
            "cleanup.noop",
            HostcallCategory::Service,
            "cleanup.noop",
            "call",
            false,
        ));
        let loaded = runtime
            .load_artifact(VisaArtifactInput { bytes: &artifact, descriptor }, &mut substrate)
            .expect("load artifact");
        let activation = runtime
            .start_activation(&loaded, ActivationEntry::Symbol("wasi_start".into()))
            .expect("start activation");
        runtime
            .invoke_hostcall(&activation, 99, VisaHostcallPayload::None, &mut substrate)
            .expect("dispatch hostcall");

        let cleanup_id = runtime
            .begin_fault_cleanup(&activation, "portable-cleanup-evidence")
            .expect("begin cleanup");
        assert!(runtime.events().iter().any(|event| {
            matches!(
                event,
                VisaRuntimeEvent::FaultCleanupStarted {
                    activation_id,
                    store_id,
                    code_object_id,
                    cleanup_id: observed_cleanup_id,
                    reason,
                } if *activation_id == activation.activation_id
                    && *store_id == activation.store_id
                    && *code_object_id == activation.code_object_id
                    && *observed_cleanup_id == cleanup_id
                    && reason == "portable-cleanup-evidence"
            )
        }));
        assert!(!runtime.events().iter().any(|event| {
            matches!(event, VisaRuntimeEvent::FaultCleanupCompleted { cleanup_id: observed_cleanup_id, .. } if *observed_cleanup_id == cleanup_id)
        }));

        let evidence = runtime.evidence_snapshot();
        assert_eq!(validate_contract_graph(&evidence.contract_graph), Vec::new());
        assert_eq!(evidence.contract_graph.cleanup_transactions.len(), 1);
        let cleanup = &evidence.contract_graph.cleanup_transactions[0];
        assert_eq!(cleanup.id, cleanup_id);
        assert_eq!(cleanup.store, activation.store_id);
        assert_eq!(cleanup.activation, Some(activation.activation_id));
        assert_eq!(cleanup.code_object, Some(activation.code_object_id));
        assert_eq!(cleanup.reason, "portable-cleanup-evidence");
        let store_ref = evidence
            .contract_graph
            .stores
            .iter()
            .find(|store| store.id == activation.store_id)
            .expect("cleanup store")
            .object_ref();
        let activation_ref = evidence
            .contract_graph
            .activations
            .iter()
            .find(|record| record.id == activation.activation_id)
            .expect("cleanup activation")
            .object_ref();
        let cleanup_ref = cleanup.object_ref();
        assert!(evidence.contract_graph.explicit_edges.iter().any(|edge| {
            edge.from == store_ref
                && edge.to == cleanup_ref
                && edge.mode == ContractEdgeMode::Live
                && edge.evidence_level == EvidenceBoundaryLevel::PortableArtifactExecution
                && edge.label == "store-starts-cleanup-transaction"
        }));
        assert!(evidence.contract_graph.explicit_edges.iter().any(|edge| {
            edge.from == activation_ref
                && edge.to == cleanup_ref
                && edge.mode == ContractEdgeMode::Live
                && edge.evidence_level == EvidenceBoundaryLevel::PortableArtifactExecution
                && edge.label == "activation-enters-cleanup-transaction"
        }));

        let snapshot_json = evidence.contract_graph_snapshot_artifact_json();
        assert!(snapshot_json.contains(&format!(
            "\"cleanup_transactions\":[{{\"id\":{},\"generation\":{}}}]",
            cleanup.id, cleanup.generation
        )));
        assert!(snapshot_json.contains("\"label\":\"store-starts-cleanup-transaction\""));
        assert!(snapshot_json.contains("\"label\":\"activation-enters-cleanup-transaction\""));
        let root = temp_runtime_test_dir("cleanup-snapshot-artifact");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("contract-graph-snapshot.json");
        fs::write(&path, snapshot_json.as_bytes()).unwrap();
        let conformance_report = visa_conformance::ConformanceReport {
            schema_version: visa_conformance::REPORT_SCHEMA_VERSION.to_string(),
            suite_id: "visa-layered-conformance".to_string(),
            target: "visa-runtime-unit".to_string(),
            generated_by: "visa-runtime-test".to_string(),
            results: vec![visa_conformance::TestResult {
                spec_id: "visa.artifact.cleanup".to_string(),
                outcome: visa_conformance::Outcome::Pass,
                observed_boundary: visa_conformance::Boundary::PortableArtifactExecution,
                observed_profile: Some(SubstrateProfile::GuestFrontend.canonical_id().to_string()),
                evidence: "runtime produced artifact-path cleanup contract graph snapshot"
                    .to_string(),
                remaining_uncertainty: "cleanup transaction is pending; completed cleanup generation synchronization is covered separately".to_string(),
                metrics: BTreeMap::new(),
                evidence_artifacts: vec![visa_conformance::EvidenceArtifact {
                    kind: visa_conformance::EvidenceArtifactKind::ContractGraphSnapshot,
                    uri: "contract-graph-snapshot.json".to_string(),
                    sha256: test_sha256_hex(snapshot_json.as_bytes()),
                    description: "runtime cleanup contract graph snapshot artifact".to_string(),
                }],
            }],
        };
        let validation = visa_conformance::validate_report_artifacts(&conformance_report, &root);
        assert!(validation.ok, "{:#?}", validation.findings);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn runtime_completed_cleanup_synchronizes_generations_and_preserves_history_edges() {
        let mut runtime =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::GuestFrontend));
        let mut substrate = MockSubstrate::default();
        let artifact = fake_image(&REQUIRED_SECTIONS);
        let descriptor = VisaArtifactDescriptor::new(
            53,
            "completed-cleanup-app",
            "completed-cleanup-artifact",
            SubstrateProfile::GuestFrontend,
        )
        .with_hostcall(HostcallSpec::new(
            1,
            "completed.cleanup.noop",
            HostcallCategory::Service,
            "completed.cleanup",
            "call",
            false,
        ));
        let loaded = runtime
            .load_artifact(VisaArtifactInput { bytes: &artifact, descriptor }, &mut substrate)
            .expect("load artifact");
        let activation = runtime
            .start_activation(&loaded, ActivationEntry::Symbol("entry".into()))
            .expect("start activation");
        runtime
            .invoke_hostcall(&activation, 1, VisaHostcallPayload::None, &mut substrate)
            .expect("dispatch hostcall");

        let cleanup_id = runtime
            .complete_fault_cleanup(&activation, "completed-cleanup-evidence")
            .expect("complete cleanup");
        assert!(runtime.events().iter().any(|event| {
            matches!(
                event,
                VisaRuntimeEvent::FaultCleanupCompleted {
                    activation_id,
                    store_id,
                    code_object_id,
                    cleanup_id: observed_cleanup_id,
                    reason,
                } if *activation_id == activation.activation_id
                    && *store_id == activation.store_id
                    && *code_object_id == activation.code_object_id
                    && *observed_cleanup_id == cleanup_id
                    && reason == "completed-cleanup-evidence"
            )
        }));
        assert!(!runtime.events().iter().any(|event| {
            matches!(event, VisaRuntimeEvent::FaultCleanupStarted { cleanup_id: observed_cleanup_id, .. } if *observed_cleanup_id == cleanup_id)
        }));

        let evidence = runtime.evidence_snapshot();
        assert_eq!(validate_contract_graph(&evidence.contract_graph), Vec::new());
        assert_eq!(evidence.contract_graph.cleanup_transactions.len(), 1);
        let store = evidence
            .contract_graph
            .stores
            .iter()
            .find(|store| store.id == activation.store_id)
            .expect("store");
        assert_eq!(store.state, StoreState::Dead);
        let code = evidence
            .contract_graph
            .code_objects
            .iter()
            .find(|code| code.id == activation.code_object_id)
            .expect("code");
        assert_eq!(code.state, semantic_core::target_executor::CodeObjectState::Retired);
        assert_eq!(code.bound_store, None);
        let activation_record = evidence
            .contract_graph
            .activations
            .iter()
            .find(|record| record.id == activation.activation_id)
            .expect("activation");
        assert_eq!(
            activation_record.state,
            semantic_core::target_executor::ActivationState::Dropped
        );
        assert_eq!(activation_record.store_generation, store.generation);
        assert_eq!(activation_record.code_generation, code.generation);
        let cleanup = &evidence.contract_graph.cleanup_transactions[0];
        assert_eq!(cleanup.id, cleanup_id);
        assert_eq!(
            cleanup.state,
            semantic_core::target_executor::CleanupTransactionState::Completed
        );
        assert_eq!(cleanup.result_store_generation, Some(store.generation));
        assert_eq!(cleanup.activation_generation, Some(activation_record.generation));
        assert_eq!(cleanup.code_generation, Some(code.generation));
        assert!(cleanup.unbound_code_object);
        assert!(cleanup.revoked_capabilities.is_empty());
        assert!(evidence.contract_graph.tombstones.iter().any(|tombstone| {
            tombstone.kind == ContractObjectKind::Store
                && tombstone.id == store.id
                && tombstone.generation == store.generation
        }));
        assert!(evidence.contract_graph.tombstones.iter().any(|tombstone| {
            tombstone.kind == ContractObjectKind::CodeObject
                && tombstone.id == code.id
                && tombstone.generation + 1 == code.generation
        }));
        assert!(evidence.contract_graph.explicit_edges.iter().any(|edge| {
            edge.from == code.object_ref()
                && edge.to == store.object_ref()
                && edge.mode == ContractEdgeMode::Historical
                && edge.evidence_level == EvidenceBoundaryLevel::PortableArtifactExecution
                && edge.label == "code-object-bound-to-store"
        }));
        assert!(evidence.contract_graph.explicit_edges.iter().any(|edge| {
            edge.from == store.object_ref()
                && edge.to == cleanup.object_ref()
                && edge.mode == ContractEdgeMode::Historical
                && edge.evidence_level == EvidenceBoundaryLevel::PortableArtifactExecution
                && edge.label == "store-starts-cleanup-transaction"
        }));
        assert!(evidence.contract_graph.explicit_edges.iter().any(|edge| {
            edge.from == activation_record.object_ref()
                && edge.to == cleanup.object_ref()
                && edge.mode == ContractEdgeMode::Historical
                && edge.evidence_level == EvidenceBoundaryLevel::PortableArtifactExecution
                && edge.label == "activation-enters-cleanup-transaction"
        }));
        assert_contract_graph_snapshot_artifact_gate_accepts(
            &evidence,
            "completed-cleanup-snapshot-artifact",
        );
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
    fn execution_summary_requires_observable_hostcall_step() {
        let personality = personality::native::VisaNativePersonality::new(
            "native-visa-empty",
            SubstrateProfile::MinimalBareMetal,
        );
        let mut runtime =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::MinimalBareMetal));
        let mut substrate = MockSubstrate::default();
        let artifact = fake_image(&REQUIRED_SECTIONS);

        let report = runtime
            .run(
                VisaArtifactInput { bytes: &artifact, descriptor: personality.descriptor(28) },
                ActivationEntry::Symbol("visa_start".into()),
                [],
                &mut substrate,
            )
            .expect("load and activate without hostcalls");

        let summary = report.evidence_summary();
        assert!(summary.artifact_loaded);
        assert!(summary.code_published);
        assert!(summary.activation_started);
        assert_eq!(summary.hostcall_dispatches, 0);
        assert!(summary.evidence_boundary_sufficient);
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
    fn runtime_records_console_timer_event_and_memory_authority_families() {
        let personality = personality::native::VisaNativePersonality::new(
            "authority-family-app",
            SubstrateProfile::GuestFrontend,
        );
        let mut runtime =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::GuestFrontend));
        let mut substrate = MockSubstrate { now: 13, ..MockSubstrate::default() };
        let artifact = fake_image(&REQUIRED_SECTIONS);
        let token = WaitTokenRef::new(88, 1);
        let memory = UserMemoryHandle::new(3, 1);

        let report = runtime
            .run(
                VisaArtifactInput { bytes: &artifact, descriptor: personality.descriptor(61) },
                ActivationEntry::Symbol("visa_start".into()),
                [
                    VisaExecutionStep::new(
                        personality::native::VISA_CONSOLE_WRITE,
                        personality.console_write(b"family"),
                    ),
                    VisaExecutionStep::new(
                        personality::native::VISA_TIMER_NOW,
                        personality.timer_now(),
                    ),
                    VisaExecutionStep::new(
                        personality::native::VISA_TIMER_ARM,
                        personality.timer_arm(144, token),
                    ),
                    VisaExecutionStep::new(
                        personality::native::VISA_EVENT_PUSH,
                        personality.event_push(SubstrateEvent::unsupported(
                            "ConsoleAuthority",
                            "console_write",
                            Some(SubstrateRequester::new("authority-family-app")),
                        )),
                    ),
                    VisaExecutionStep::new(
                        personality::native::VISA_EVENT_POP,
                        personality.event_pop(),
                    ),
                    VisaExecutionStep::new(
                        personality::native::VISA_MEMORY_COPYIN,
                        personality.memory_copyin(memory, 0x1000, 4),
                    ),
                    VisaExecutionStep::new(
                        personality::native::VISA_MEMORY_COPYOUT,
                        personality.memory_copyout(memory, 0x1004, b"out"),
                    ),
                ],
                &mut substrate,
            )
            .expect("run authority family workload");

        assert_eq!(report.hostcalls.len(), 7);
        assert_eq!(report.hostcalls[5].value, VisaHostcallValue::Bytes(vec![0x76; 4]));
        assert_eq!(substrate.memory_writes, vec![(memory, 0x1004, b"out".to_vec())]);
        let evidence = runtime.evidence_snapshot();
        assert_eq!(evidence.authority_extraction_count(), 7);
        let family_operations = evidence
            .authority_extractions
            .iter()
            .map(|event| (event.authority_family.as_str(), event.operation.as_str()))
            .collect::<Vec<_>>();
        for expected in [
            ("console", "console_write"),
            ("timer", "now"),
            ("timer", "arm_timer"),
            ("event", "push_event"),
            ("event", "pop_event"),
            ("memory", "copyin"),
            ("memory", "copyout"),
        ] {
            assert!(family_operations.contains(&expected), "{family_operations:?}");
        }
        assert!(evidence.denied_substrate_events.is_empty());
        assert!(evidence.unsupported_substrate_events.is_empty());

        let substrate_events_jsonl = evidence.substrate_events_jsonl();
        assert_eq!(substrate_events_jsonl.lines().count(), 7);
        for family in ["console", "timer", "event", "memory"] {
            assert!(
                substrate_events_jsonl.contains(&format!("\"authority_family\":\"{family}\"")),
                "{substrate_events_jsonl}"
            );
        }

        let root = temp_runtime_test_dir("authority-family-substrate-events");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("substrate-events.jsonl");
        fs::write(&path, substrate_events_jsonl.as_bytes()).unwrap();
        let conformance_report = visa_conformance::ConformanceReport {
            schema_version: visa_conformance::REPORT_SCHEMA_VERSION.to_string(),
            suite_id: "visa-layered-conformance".to_string(),
            target: "visa-runtime-unit".to_string(),
            generated_by: "visa-runtime-test".to_string(),
            results: vec![visa_conformance::TestResult {
                spec_id: "visa.capability.hostcall".to_string(),
                outcome: visa_conformance::Outcome::Pass,
                observed_boundary: visa_conformance::Boundary::PortableArtifactExecution,
                observed_profile: Some(SubstrateProfile::GuestFrontend.canonical_id().to_string()),
                evidence: "runtime recorded family-tagged substrate authority evidence".to_string(),
                remaining_uncertainty:
                    "unit fixture validates authority families, not real target substrate"
                        .to_string(),
                metrics: BTreeMap::from([(
                    "authority_extraction_event_count".to_string(),
                    evidence.authority_extraction_count() as f64,
                )]),
                evidence_artifacts: vec![visa_conformance::EvidenceArtifact {
                    kind: visa_conformance::EvidenceArtifactKind::SubstrateEventTrace,
                    uri: "substrate-events.jsonl".to_string(),
                    sha256: test_sha256_hex(substrate_events_jsonl.as_bytes()),
                    description: "family-tagged substrate event trace".to_string(),
                }],
            }],
        };
        let validation = visa_conformance::validate_report_artifacts(&conformance_report, &root);
        assert!(validation.ok, "{:#?}", validation.findings);
        let _ = fs::remove_dir_all(root);
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
        assert!(runtime.events().iter().any(|event| {
            matches!(
                event,
                VisaRuntimeEvent::ProfileGateRejected {
                    package,
                    artifact_id: 10,
                    required_profile: SubstrateProfile::GuestFrontend,
                    reported_profile: SubstrateProfile::SemanticHarness,
                    reason,
                    ..
                } if package == "profile-underclaim" && reason == "reported-profile-below-required"
            )
        }));
        let evidence = runtime.evidence_snapshot();
        assert_eq!(evidence.profile_gate_rejection_count(), 1);
        assert_eq!(evidence.profile_gate_rejections[0].artifact_id, Some(10));
        assert_eq!(evidence.profile_gate_rejections[0].enforced_profile, "guest-frontend");
        assert_eq!(evidence.profile_gate_rejections[0].reason, "reported-profile-below-required");
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
            "visa",
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

    fn portable_process_family_snapshot() -> ContractGraphSnapshot {
        let mut graph = SemanticGraph::new();
        graph.ensure_task(1, FrontendKind::LinuxElf, "init");

        let leader = ContractObjectRef::new(ContractObjectKind::Thread, 1, 1);
        let thread_group_id = graph.create_thread_group(1, leader).expect("create thread group");
        let thread_group = graph.query_thread_group(thread_group_id).unwrap().object_ref();
        let process_id =
            graph.create_process(1, None, 1, 1, thread_group, None).expect("create process");
        let process = graph.query_process(process_id).unwrap().object_ref();
        let fd_table_id = graph.create_fd_table(thread_group, true).expect("create fd table");
        let fd_table = graph.query_fd_table(fd_table_id).unwrap().object_ref();
        let credential_id =
            graph.create_credential(process, 0, 0, 0, 0, 0, 0, 0, 0).expect("create credential");
        let credential = graph.query_credential(credential_id).unwrap().object_ref();
        let aspace = ContractObjectRef::new(ContractObjectKind::GuestAddressSpace, 1, 1);
        graph
            .create_thread(1, 1, process, aspace, fd_table, credential, thread_group)
            .expect("create thread");

        graph.snapshot().portable_subset()
    }

    #[test]
    fn restore_portable_subset_preserves_process_family_records() {
        let snapshot = portable_process_family_snapshot();
        assert!(!snapshot.processes.is_empty());
        assert!(!snapshot.threads.is_empty());
        assert!(!snapshot.thread_groups.is_empty());

        let mut rt =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::MinimalBareMetal));
        rt.restore_portable_subset(&snapshot)
            .expect("process-family portable snapshot must restore");
        let restored = rt.snapshot();

        assert_eq!(restored.processes, snapshot.processes);
        assert_eq!(restored.threads, snapshot.threads);
        assert_eq!(restored.thread_groups, snapshot.thread_groups);
        assert_eq!(restored.fd_tables, snapshot.fd_tables);
        assert_eq!(restored.credentials, snapshot.credentials);
    }

    #[test]
    fn restore_portable_subset_preserves_guest_memory_records() {
        let mut memory = semantic_core::GuestMemoryManager::new();
        let store = ContractObjectRef::new(ContractObjectKind::Store, 7, 3);
        let aspace = memory.create_address_space(store);
        let page = memory
            .create_page(semantic_core::PageBacking::Anonymous, semantic_core::CowState::None);
        memory
            .map_region(
                aspace,
                semantic_core::GuestVaRange::new(0x4000, 0x1000),
                semantic_core::GuestPerms::READ_WRITE,
                semantic_core::VmaFlags::anonymous(),
                page,
            )
            .expect("map region");
        memory.record_page_fault(page, "copyin-efault");

        let mut graph = SemanticGraph::new();
        assert!(graph.record_guest_memory_manager(&memory));
        let snapshot = graph.snapshot().portable_subset();
        assert_eq!(snapshot.guest_address_spaces.len(), 1);
        assert_eq!(snapshot.vma_regions.len(), 1);
        assert_eq!(snapshot.page_objects.len(), 1);
        assert_eq!(snapshot.guest_memory_faults.len(), 1);

        let mut rt =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::MinimalBareMetal));
        rt.restore_portable_subset(&snapshot).expect("guest-memory portable snapshot must restore");
        let restored = rt.snapshot();

        assert_eq!(restored.guest_address_spaces, snapshot.guest_address_spaces);
        assert_eq!(restored.vma_regions, snapshot.vma_regions);
        assert_eq!(restored.page_objects, snapshot.page_objects);
        assert_eq!(restored.guest_memory_faults, snapshot.guest_memory_faults);
        assert!(rt.semantic().check_invariants().is_ok());
    }

    #[test]
    fn portable_subset_strips_restore_unsupported_records() {
        let mut snapshot = ContractGraphSnapshot::default();
        snapshot.external_objects.push(semantic_core::ExternalObjectDeclaration::new(
            ContractObjectRef::new(ContractObjectKind::EventLog, 1, 1),
            "debugger",
            "external-event-log",
            "event-log",
        ));
        snapshot.explicit_edges.push(
            semantic_core::ContractEdgeRecord::new(
                ContractObjectRef::new(ContractObjectKind::Store, 1, 1),
                ContractObjectRef::new(ContractObjectKind::Task, 1, 1),
                semantic_core::ContractEdgeMode::Live,
                "test-edge",
                1,
            )
            .with_evidence_level(EvidenceBoundaryLevel::SemanticModel),
        );

        let portable = snapshot.portable_subset();
        assert!(portable.external_objects.is_empty());
        assert!(portable.explicit_edges.is_empty());

        let mut rt =
            VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::MinimalBareMetal));
        rt.restore_portable_subset(&portable)
            .expect("portable subset must be accepted after stripping unsupported records");
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
