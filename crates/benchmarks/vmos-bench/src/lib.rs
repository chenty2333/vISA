use semantic_core::{
    ActivationVectorState, CommandEnvelope, CommandStatus, FrontendKind, HartState,
    HostcallLinkState, MemoryLayoutState, ResourceKind, RuntimeActivationState, SemanticCommand,
    SemanticGraph, StoreState, TaskState, VectorStateState, PacketQueueRole,
    target_executor::{ContractObjectKind, ContractObjectRef},
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
        11, 7, 2, Some(1), Some(2),
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
        1, "blk0", "block-device", dev_res, 1, "virtio-blk", "pci", "vmos", "bench-virtio", "criterion",
    ));
    assert!(graph.record_block_device_object_with_id(
        1, "bench-blk", 1, 1, 512, 2_097_152, false, 256, "criterion",
    ));
    assert!(graph.record_fake_block_backend_object_with_id(
        1, "bench-fake-blk", 1, 1, "service_core", "fake-block-v1",
        512, 2_097_152, false, 256, 42, "criterion fake backend",
    ));
    assert!(graph.record_block_range_object_with_id(
        1, 1, 1, 0, 256, "criterion block range",
    ));
    graph
}

// ── network domain fixtures ──────────────────────────────────────────────────

pub fn network_packet_fixture() -> SemanticGraph {
    let (mut graph, _store) = base_fixture(7, "criterion-net");
    let dev_res = graph.register_resource(ResourceKind::PacketDevice, Some(7), "net-dev-res");
    assert!(graph.record_device_object_with_id(
        1, "net0", "packet-device", dev_res, 1, "virtio-net", "pci", "vmos", "bench-virtio-net", "criterion",
    ));
    let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    assert!(graph.record_packet_device_object_with_id(
        1, "pkt0", 1, 1, 1500, 64, 64, mac, 1, 65536, "criterion",
    ));
    // rx queue (id=1, role=Rx)
    assert!(graph.record_packet_queue_object_with_id(
        1, "rxq", 1, 1, PacketQueueRole::Rx, 0, 64, "criterion rx",
    ));
    // tx queue (id=2, role=Tx)
    assert!(graph.record_packet_queue_object_with_id(
        2, "txq", 1, 1, PacketQueueRole::Tx, 0, 64, "criterion tx",
    ));
    assert!(graph.record_fake_net_backend_object_with_id(
        1, "fake-net", 1, 1, "service_core", "fake-net-v1",
        1500, 64, 64, mac, 1, 65536, 42, "criterion fake net",
    ));
    let backend_ref = ContractObjectRef::new(ContractObjectKind::FakeNetBackendObject, 1, 1);
    assert!(graph.record_network_stack_adapter_with_id(
        1, backend_ref, 1, 1, 1, 1, 2, 1,
        "smoltcp", "0.13.0", "smoltcp-0.13.0-ethernet-ipv4-tcp-v1", "ethernet",
        mac, [10, 0, 0, 1], 24, 1500,
        64, 64, 65536, 0,
        "criterion adapter",
    ));
    graph
}

// ── display domain fixture ───────────────────────────────────────────────────

pub fn display_framebuffer_fixture() -> SemanticGraph {
    let (mut graph, _store) = base_fixture(7, "criterion-display");
    let fb_res = graph.register_resource(ResourceKind::Framebuffer, Some(7), "fb-res");
    assert!(graph.record_framebuffer_object_with_id(
        1, "fb0", fb_res, 1, 1920, 1080, 7680, "bgra8888", 8_294_400, "criterion",
    ));
    assert!(graph.record_display_object_with_id(
        1, "disp0", 1, 1, "1920x1080", 1920, 1080, 60_000, "criterion display",
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
        true, 32, 128, true,
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
        1, "vmos-bench-preemption",
        SemanticCommand::RecordPreemptionLatencySample {
            sample: 1,
            timer_interrupt: 1, timer_interrupt_generation: 1,
            preemption: 1, preemption_generation: 1,
            scheduler_decision: 1, scheduler_decision_generation: 1,
            activation_resume: 1, activation_resume_generation: 1,
            measured_nanos: 8_500, budget_nanos: 50_000,
            note: "criterion preemption latency sample".to_owned(),
        },
    ));
    assert_eq!(result.status, CommandStatus::Applied, "{:?}", result.violations);
    graph.preemption_latency_samples().len() + graph.event_count()
}

pub fn simd_context_switch_sample() -> usize {
    let mut graph = scheduler_2hart_fixture();
    assert!(graph.record_target_feature_set_with_id(
        21_002, "bench-riscv-v", "criterion", "guest-frontend",
        "riscv64", "rv64gc", "riscv-v", true, 32, 128, true, "",
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
        22_002, activation, owner_store, code_object, tf_set,
        "riscv-v", 32, 128, 512, VectorStateState::Reserved, "criterion dirty vector",
    ));
    assert!(graph.update_activation_context_vector_state(
        12, 2, Some(saved_vector), ActivationVectorState::Dirty,
        "criterion dirty vector context",
    ));
    assert!(graph.save_dirty_vector_state_on_preempt(
        12, 3, 13, 1, 1, 1, saved_vector, "criterion save dirty vector",
    ));
    assert!(graph.record_scheduler_decision_with_id(1, 1, 1, 11, 4, "preempted", "bench decision"));
    assert!(graph.resume_activation_with_id(1, 1, 1, 11, 4, "bench resume"));
    let restored_vector = ContractObjectRef::new(ContractObjectKind::VectorState, 22_003, 1);
    assert!(graph.record_simd_context_switch_benchmark_with_id(
        22_012,
        ContractObjectRef::new(ContractObjectKind::Preemption, 1, 1),
        ContractObjectRef::new(ContractObjectKind::ActivationResume, 1, 1),
        saved_vector, restored_vector, tf_set,
        "riscv-v", 32, 128, 64, 30_000, 46_384, 16_384, 50_000,
        "criterion SIMD context switch",
    ));
    graph.simd_context_switch_benchmarks().len() + graph.vector_states().len()
}
