use semantic_core::{
    ActivationVectorState, CommandEnvelope, CommandStatus, FrontendKind, HartState,
    HostcallLinkState, MemoryLayoutState, RuntimeActivationState, SemanticCommand, SemanticGraph,
    StoreState, TaskState, VectorStateState,
    target_executor::{ContractObjectKind, ContractObjectRef},
};

pub fn block_iops_sample() -> u64 {
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

pub fn network_throughput_sample() -> u64 {
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

pub fn preemption_latency_sample() -> usize {
    let mut graph = scheduler_fixture();
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
    let mut graph = scheduler_fixture();
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
    let target_feature_set =
        ContractObjectRef::new(ContractObjectKind::TargetFeatureSet, 21_002, 1);
    let saved_vector = ContractObjectRef::new(ContractObjectKind::VectorState, 22_002, 1);
    assert!(graph.record_vector_state_with_id(
        22_002,
        activation,
        owner_store,
        code_object,
        target_feature_set,
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
        target_feature_set,
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

fn scheduler_fixture() -> SemanticGraph {
    let mut graph = SemanticGraph::new();
    graph.ensure_task(7, FrontendKind::Supervisor, "criterion-task");
    graph.set_task_state(7, TaskState::Running);
    let store = graph.register_store("bench-store", "bench-artifact", "service", "restartable");
    graph.set_store_state(store, StoreState::Running);
    graph.record_store_activation(
        store,
        "bench-store",
        "bench-binding",
        "bench-code",
        semantic_core::CodePublishState::Published,
        MemoryLayoutState::Verified,
        HostcallLinkState::Linked,
        semantic_core::TrapSurfaceState::ContractDeclared,
        semantic_core::EntrypointState::Runnable,
        Some("criterion"),
    );
    assert!(graph.register_hart_with_id(1, 0, "hart0", true, "criterion hart"));
    assert!(graph.set_hart_state(1, 1, HartState::Running, "boot", "criterion hart running"));
    assert!(graph.create_runnable_queue_with_id(1, "main-rq"));
    assert!(graph.create_runtime_activation_with_id(
        11,
        7,
        2,
        Some(store),
        Some(2),
        Some(ContractObjectRef::new(ContractObjectKind::CodeObject, 3, 1)),
    ));
    assert!(graph.enqueue_runnable_activation(1, 11, 1));
    assert!(graph.dequeue_runnable_activation(1, 11));
    assert_eq!(graph.runtime_activations()[0].state, RuntimeActivationState::Running);
    assert_eq!(graph.runtime_activations()[0].generation, 3);
    graph
}
