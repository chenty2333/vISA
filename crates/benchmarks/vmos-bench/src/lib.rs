use semantic_core::{
    ActivationVectorState, CommandEnvelope, CommandStatus, ContractGraphSnapshot, FrontendKind,
    HartState, HostcallLinkState, MemoryLayoutState, PacketQueueRole, ResourceKind,
    RuntimeActivationState, SemanticCommand, SemanticGraph, StoreState, TaskState,
    VectorStateState,
    target_executor::{
        ActivationEntry, ContractObjectKind, ContractObjectRef, HostcallCategory, HostcallSpec,
    },
};
use sha2::{Digest, Sha256};
use substrate_api::{
    ArtifactAuthority, ArtifactImageRef, CodeObjectRef, CodePublisherAuthority, ConsoleAuthority,
    DmaAuthority, DmwAuthority, EventQueueAuthority, GuestMemoryAuthority, IrqAuthority,
    MmioAuthority, PublishedCodeRef, SnapshotAuthority, SubstrateResult, TimerAuthority,
    VirtualTime,
};
use target_abi::{
    SectionKindV1, TargetArtifactHeaderV1, TargetSectionHeaderV1, canonical_zero_field_image_hash,
};
use visa_profile::SubstrateProfile;
use vms_runtime::{
    ActivationHandle, LoadedVisaArtifact, VisaArtifactDescriptor, VisaArtifactInput,
    VisaHostcallPayload, VisaHostcallValue, VisaRuntime, VisaRuntimeConfig,
};

// ── derive benchmarks (pure math, no SemanticGraph) ──────────────────────────

pub fn derive_block_iops_sample() -> u64 {
    let mut acc = 0;
    for sample in 1..=64 {
        let requests = sample * 2;
        let bytes = u64::from(requests) * 4096;
        let nanos = u64::from(sample) * 40_000;
        let iops = SemanticGraph::derive_block_iops(requests, nanos).unwrap();
        let throughput =
            SemanticGraph::derive_block_throughput_bytes_per_sec(bytes, nanos).unwrap();
        acc ^= iops ^ throughput;
    }
    acc
}

pub fn derive_network_throughput_sample() -> u64 {
    let mut acc = 0;
    for sample in 1..=64 {
        let bytes = u64::from(sample) * 1500 * 4;
        let nanos = u64::from(sample) * 120_000;
        let throughput =
            SemanticGraph::derive_network_throughput_bytes_per_sec(bytes, nanos).unwrap();
        acc ^= throughput.rotate_left(sample % 31);
    }
    acc
}

// ── vms_runtime fixtures ────────────────────────────────────────────────────

const REQUIRED_ARTIFACT_SECTIONS: [SectionKindV1; 7] = [
    SectionKindV1::Manifest,
    SectionKindV1::CodeObject,
    SectionKindV1::HostcallImportTable,
    SectionKindV1::TrapMap,
    SectionKindV1::PcRangeTable,
    SectionKindV1::ProfileRequirements,
    SectionKindV1::Signature,
];
const ARTIFACT_SECTION_PAYLOAD_LEN: usize = 16;
const TARGET_ARTIFACT_HEADER_LEN: usize = TargetArtifactHeaderV1::WIRE_LEN;
const TARGET_SECTION_HEADER_LEN: usize = TargetSectionHeaderV1::WIRE_LEN;
const IMAGE_HASH_OFFSET: usize = 88;
const IMAGE_HASH_LEN: usize = 32;

#[derive(Default)]
pub struct BenchSubstrate {
    pub loaded: Vec<ArtifactImageRef>,
    pub published: Vec<(ArtifactImageRef, CodeObjectRef)>,
    pub console_bytes: usize,
    pub now_ticks: u64,
}

impl ArtifactAuthority for BenchSubstrate {
    fn load_artifact_image(&mut self, artifact: ArtifactImageRef) -> SubstrateResult<()> {
        self.loaded.push(artifact);
        Ok(())
    }
}

impl CodePublisherAuthority for BenchSubstrate {
    fn publish_code(
        &mut self,
        artifact: ArtifactImageRef,
        code: CodeObjectRef,
    ) -> SubstrateResult<PublishedCodeRef> {
        self.published.push((artifact, code));
        Ok(PublishedCodeRef::new(code.id, code.generation))
    }
}

impl ConsoleAuthority for BenchSubstrate {
    fn console_write(&mut self, bytes: &[u8]) -> SubstrateResult<usize> {
        self.console_bytes += bytes.len();
        Ok(bytes.len())
    }
}

impl TimerAuthority for BenchSubstrate {
    fn now(&self) -> SubstrateResult<VirtualTime> {
        Ok(VirtualTime::from_ticks(self.now_ticks))
    }
}

impl EventQueueAuthority for BenchSubstrate {}
impl GuestMemoryAuthority for BenchSubstrate {}
impl DmwAuthority for BenchSubstrate {}
impl MmioAuthority for BenchSubstrate {}
impl DmaAuthority for BenchSubstrate {}
impl IrqAuthority for BenchSubstrate {}
impl SnapshotAuthority for BenchSubstrate {}

pub fn bench_artifact_descriptor(artifact_id: u64) -> VisaArtifactDescriptor {
    let mut descriptor = VisaArtifactDescriptor::new(
        artifact_id,
        "vmos-bench",
        "bench-artifact",
        SubstrateProfile::MinimalBareMetal,
    )
    .with_role("visa-native-workload")
    .with_hostcall(HostcallSpec::new(
        1,
        "bench.console.write",
        HostcallCategory::Service,
        "bench.console",
        "write",
        false,
    ));
    descriptor.imports.push("vms.hostcall_1".to_string());
    descriptor.exports.push("entry".to_string());
    descriptor
}

pub fn runtime_loaded_artifact_fixture() -> (VisaRuntime, BenchSubstrate, LoadedVisaArtifact) {
    let mut runtime =
        VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::MinimalBareMetal));
    let mut substrate = BenchSubstrate::default();
    let artifact = fake_target_artifact_image();
    let descriptor = bench_artifact_descriptor(7);
    let loaded = runtime
        .load_artifact(VisaArtifactInput { bytes: &artifact, descriptor }, &mut substrate)
        .expect("load benchmark artifact");
    (runtime, substrate, loaded)
}

pub fn runtime_hostcall_fixture() -> (VisaRuntime, BenchSubstrate, ActivationHandle) {
    let (mut runtime, substrate, loaded) = runtime_loaded_artifact_fixture();
    let activation = runtime
        .start_activation(&loaded, ActivationEntry::Symbol("entry".to_string()))
        .expect("start benchmark activation");
    (runtime, substrate, activation)
}

pub fn runtime_restore_fixture() -> (VisaRuntime, ContractGraphSnapshot) {
    let (mut source, _substrate, loaded) = runtime_loaded_artifact_fixture();
    source
        .start_activation(&loaded, ActivationEntry::Symbol("entry".to_string()))
        .expect("start benchmark activation");
    let snapshot = source.snapshot().portable_subset();
    let target =
        VisaRuntime::new(VisaRuntimeConfig::for_profile(SubstrateProfile::MinimalBareMetal));
    (target, snapshot)
}

pub fn invoke_bench_console_hostcall(
    runtime: &mut VisaRuntime,
    substrate: &mut BenchSubstrate,
    activation: &ActivationHandle,
) -> usize {
    let report = runtime
        .invoke_hostcall(
            activation,
            1,
            VisaHostcallPayload::ConsoleWrite { bytes: vec![0x76, 0x49, 0x53, 0x41] },
            substrate,
        )
        .expect("dispatch benchmark hostcall");
    match report.value {
        VisaHostcallValue::U64(written) => written as usize,
        _ => 0,
    }
}

pub fn fake_target_artifact_image() -> Vec<u8> {
    let section_table_len = REQUIRED_ARTIFACT_SECTIONS.len() * TARGET_SECTION_HEADER_LEN;
    let payload_base = TARGET_ARTIFACT_HEADER_LEN + section_table_len;
    let image_len = payload_base + REQUIRED_ARTIFACT_SECTIONS.len() * ARTIFACT_SECTION_PAYLOAD_LEN;
    let mut image = vec![0; image_len];

    let header = TargetArtifactHeaderV1::fake_riscv64(
        REQUIRED_ARTIFACT_SECTIONS.len() as u32,
        image_len as u64,
    );
    header.write_to(&mut image).expect("write artifact header");

    for (index, kind) in REQUIRED_ARTIFACT_SECTIONS.iter().copied().enumerate() {
        let offset = payload_base + index * ARTIFACT_SECTION_PAYLOAD_LEN;
        image[offset..offset + ARTIFACT_SECTION_PAYLOAD_LEN].fill(kind as u32 as u8);

        let mut section =
            TargetSectionHeaderV1::new(kind, offset as u64, ARTIFACT_SECTION_PAYLOAD_LEN as u64, 1);
        section.hash = Sha256::digest(&image[offset..offset + ARTIFACT_SECTION_PAYLOAD_LEN]).into();
        let section_off = TARGET_ARTIFACT_HEADER_LEN + index * TARGET_SECTION_HEADER_LEN;
        section
            .write_to(&mut image[section_off..section_off + TARGET_SECTION_HEADER_LEN])
            .expect("write artifact section");
    }

    let mut header = TargetArtifactHeaderV1::parse(&image).expect("parse artifact header");
    if let Some((manifest_start, manifest_end)) =
        artifact_section_payload_range(&image, SectionKindV1::Manifest)
    {
        header.manifest_hash = Sha256::digest(&image[manifest_start..manifest_end]).into();
        header.write_to(&mut image).expect("write manifest hash");
    }
    refresh_artifact_image_hash(&mut image);
    image
}

fn artifact_section_payload_range(image: &[u8], kind: SectionKindV1) -> Option<(usize, usize)> {
    let header = TargetArtifactHeaderV1::parse(image).expect("parse artifact header");
    for index in 0..header.section_count as usize {
        let section_off = TARGET_ARTIFACT_HEADER_LEN + index * TARGET_SECTION_HEADER_LEN;
        let section = TargetSectionHeaderV1::parse(
            &image[section_off..section_off + TARGET_SECTION_HEADER_LEN],
        )
        .expect("parse artifact section");
        if section.kind == kind {
            let start = section.offset as usize;
            return Some((start, start + section.len as usize));
        }
    }
    None
}

fn refresh_artifact_image_hash(image: &mut [u8]) {
    image[IMAGE_HASH_OFFSET..IMAGE_HASH_OFFSET + IMAGE_HASH_LEN].fill(0);
    let hash = canonical_zero_field_image_hash(image).expect("hash artifact image");
    image[IMAGE_HASH_OFFSET..IMAGE_HASH_OFFSET + IMAGE_HASH_LEN].copy_from_slice(&hash);
}

// ── shared helpers ───────────────────────────────────────────────────────────

fn base_fixture(task_id: u32, label: &str) -> (SemanticGraph, u64) {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(task_id, FrontendKind::Supervisor, label);
    graph.set_task_state(task_id, TaskState::Running);
    let store = graph.register_store(label, "bench-artifact", "service", "restartable");
    graph.set_store_state(store, StoreState::Running);
    graph.record_store_activation(
        store,
        label,
        "bench-binding",
        "bench-code",
        semantic_core::CodePublishState::Published,
        MemoryLayoutState::Verified,
        HostcallLinkState::Linked,
        semantic_core::TrapSurfaceState::ContractDeclared,
        semantic_core::EntrypointState::Runnable,
        Some("criterion"),
    );
    (graph, store)
}

// ── scheduler domain fixtures ────────────────────────────────────────────────

pub fn scheduler_2hart_fixture() -> SemanticGraph {
    let (mut graph, _store) = base_fixture(7, "criterion-scheduler");
    assert!(graph.register_hart_with_id(1, 0, "hart0", true, "criterion hart0"));
    assert!(graph.set_hart_state(1, 1, HartState::Running, "boot", "criterion hart0 running"));
    assert!(graph.register_hart_with_id(2, 1, "hart1", false, "criterion hart1"));
    assert!(graph.set_hart_state(2, 1, HartState::Running, "boot", "criterion hart1 running"));
    assert!(graph.create_runnable_queue_with_id(1, "main-rq"));
    assert!(graph.create_runtime_activation_with_id(
        11,
        7,
        2,
        Some(1),
        Some(2),
        Some(ContractObjectRef::new(ContractObjectKind::CodeObject, 3, 1)),
    ));
    assert!(graph.enqueue_runnable_activation(1, 11, 1));
    assert!(graph.dequeue_runnable_activation(1, 11));
    assert_eq!(graph.runtime_activations()[0].state, RuntimeActivationState::Running);
    assert_eq!(graph.runtime_activations()[0].generation, 3);
    graph
}

// ── block domain fixtures ────────────────────────────────────────────────────

pub fn block_request_fixture() -> SemanticGraph {
    let (mut graph, _store) = base_fixture(7, "criterion-block");
    let dev_res = graph.register_resource(ResourceKind::BlockDevice, Some(7), "blk-dev-res");
    assert!(graph.record_device_object_with_id(
        1,
        "blk0",
        "block-device",
        dev_res,
        1,
        "virtio-blk",
        "pci",
        "vmos",
        "bench-virtio",
        "criterion",
    ));
    assert!(graph.record_block_device_object_with_id(
        1,
        "bench-blk",
        1,
        1,
        512,
        2_097_152,
        false,
        256,
        "criterion",
    ));
    assert!(graph.record_fake_block_backend_object_with_id(
        1,
        "bench-fake-blk",
        1,
        1,
        "service_core",
        "fake-block-v1",
        512,
        2_097_152,
        false,
        256,
        42,
        "criterion fake backend",
    ));
    assert!(graph.record_block_range_object_with_id(1, 1, 1, 0, 256, "criterion block range",));
    graph
}

// ── network domain fixtures ──────────────────────────────────────────────────

pub fn network_packet_fixture() -> SemanticGraph {
    let (mut graph, _store) = base_fixture(7, "criterion-net");
    let dev_res = graph.register_resource(ResourceKind::PacketDevice, Some(7), "net-dev-res");
    assert!(graph.record_device_object_with_id(
        1,
        "net0",
        "packet-device",
        dev_res,
        1,
        "virtio-net",
        "pci",
        "vmos",
        "bench-virtio-net",
        "criterion",
    ));
    let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    assert!(graph.record_packet_device_object_with_id(
        1,
        "pkt0",
        1,
        1,
        1500,
        64,
        64,
        mac,
        1,
        65536,
        "criterion",
    ));
    assert!(graph.record_packet_queue_object_with_id(
        1,
        "rxq",
        1,
        1,
        PacketQueueRole::Rx,
        0,
        64,
        "criterion rx",
    ));
    assert!(graph.record_packet_queue_object_with_id(
        2,
        "txq",
        1,
        1,
        PacketQueueRole::Tx,
        0,
        64,
        "criterion tx",
    ));
    graph
}

// ── display domain fixture ───────────────────────────────────────────────────

pub fn display_framebuffer_fixture() -> SemanticGraph {
    let (mut graph, _store) = base_fixture(7, "criterion-display");
    let fb_res = graph.register_resource(ResourceKind::Framebuffer, Some(7), "fb-res");
    assert!(graph.record_framebuffer_object_with_id(
        1,
        "fb0",
        fb_res,
        1,
        1920,
        1080,
        7680,
        "bgra8888",
        8_294_400,
        "criterion",
    ));
    graph
}

// ── SIMD domain fixture ──────────────────────────────────────────────────────

pub fn simd_vector_fixture() -> SemanticGraph {
    let (mut graph, _store) = base_fixture(7, "criterion-simd");
    assert!(graph.record_target_feature_set_with_id(
        21_002,
        "bench-riscv-v",
        "criterion",
        "guest-frontend",
        "riscv64",
        "rv64gc",
        "riscv-v",
        true,
        32,
        128,
        true,
        "",
        "criterion simd feature set",
    ));
    graph
}

// ── legacy helpers (single-sample, kept for comparative testing) ────────────

pub fn preemption_latency_sample() -> usize {
    let mut graph = scheduler_2hart_fixture();
    assert!(graph.record_timer_interrupt_with_id(1, 1, 1, 2, Some(11), Some(3), "bench timer"));
    assert!(graph.preempt_running_activation_with_id(1, 11, 3, 1, 1, 1, "bench preempt"));
    assert!(graph.record_scheduler_decision_with_id(1, 1, 1, 11, 4, "preempted", "bench decision"));
    assert!(graph.resume_activation_with_id(1, 1, 1, 11, 4, "bench resume"));
    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "vmos-bench-preemption",
        SemanticCommand::RecordPreemptionLatencySample {
            sample: 1,
            timer_interrupt: 1,
            timer_interrupt_generation: 1,
            preemption: 1,
            preemption_generation: 1,
            scheduler_decision: 1,
            scheduler_decision_generation: 1,
            activation_resume: 1,
            activation_resume_generation: 1,
            measured_nanos: 8_500,
            budget_nanos: 50_000,
            note: "criterion preemption latency sample".to_owned(),
        },
    ));
    assert_eq!(result.status, CommandStatus::Applied, "{:?}", result.violations);
    graph.preemption_latency_samples().len() + graph.event_count()
}

pub fn simd_context_switch_sample() -> usize {
    let mut graph = scheduler_2hart_fixture();
    assert!(graph.record_target_feature_set_with_id(
        21_002,
        "bench-riscv-v",
        "criterion",
        "guest-frontend",
        "riscv64",
        "rv64gc",
        "riscv-v",
        true,
        32,
        128,
        true,
        "",
        "criterion target feature set",
    ));
    assert!(graph.record_timer_interrupt_with_id(1, 1, 1, 2, Some(11), Some(3), "bench timer"));
    assert!(graph.preempt_running_activation_with_id(1, 11, 3, 1, 1, 1, "bench preempt"));
    assert!(graph.save_preempted_context_with_ids(12, 13, 1, 1, 0x1000, 0x8000, 0, "bench save"));
    let activation = ContractObjectRef::new(ContractObjectKind::Activation, 11, 4);
    let owner_store = ContractObjectRef::new(ContractObjectKind::Store, 1, 1);
    let code_object = ContractObjectRef::new(ContractObjectKind::CodeObject, 3, 1);
    let tf_set = ContractObjectRef::new(ContractObjectKind::TargetFeatureSet, 21_002, 1);
    let saved_vector = ContractObjectRef::new(ContractObjectKind::VectorState, 22_002, 1);
    assert!(graph.record_vector_state_with_id(
        22_002,
        activation,
        owner_store,
        code_object,
        tf_set,
        "riscv-v",
        32,
        128,
        512,
        VectorStateState::Reserved,
        "criterion dirty vector",
    ));
    assert!(graph.update_activation_context_vector_state(
        12,
        2,
        Some(saved_vector),
        ActivationVectorState::Dirty,
        "criterion dirty vector context",
    ));
    assert!(graph.save_dirty_vector_state_on_preempt(
        12,
        3,
        13,
        1,
        1,
        1,
        saved_vector,
        "criterion save dirty vector",
    ));
    assert!(graph.record_scheduler_decision_with_id(1, 1, 1, 11, 4, "preempted", "bench decision"));
    assert!(graph.resume_activation_with_id(1, 1, 1, 11, 4, "bench resume"));
    let restored_vector = ContractObjectRef::new(ContractObjectKind::VectorState, 22_003, 1);
    assert!(graph.record_simd_context_switch_benchmark_with_id(
        22_012,
        ContractObjectRef::new(ContractObjectKind::Preemption, 1, 1),
        ContractObjectRef::new(ContractObjectKind::ActivationResume, 1, 1),
        saved_vector,
        restored_vector,
        tf_set,
        "riscv-v",
        32,
        128,
        64,
        30_000,
        46_384,
        16_384,
        50_000,
        "criterion SIMD context switch",
    ));
    graph.simd_context_switch_benchmarks().len() + graph.vector_states().len()
}
