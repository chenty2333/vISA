use super::*;

pub(in crate::tests) fn v11_supported_simd_benchmark_graph() -> SemanticGraph {
    let mut graph = SemanticGraph::new();
    assert!(graph.record_target_feature_set_with_id(
        21_011,
        "riscv64-vector-benchmark-test-target",
        "semantic-contract-v11-test",
        "riscv64-vector-benchmark-test",
        "riscv64",
        "rv64gcv",
        "riscv-v",
        true,
        32,
        128,
        true,
        "",
        "v11 supported SIMD benchmark fixture",
    ));
    graph
}

#[test]
pub(in crate::tests) fn simd_runtime_v11_benchmark_records_scalar_vs_vector_speedup() {
    let mut graph = v11_supported_simd_benchmark_graph();

    let result = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v11-test",
        SemanticCommand::RecordSimdBenchmark {
            benchmark: 22_011,
            target_feature_set: ContractObjectRef::new(
                ContractObjectKind::TargetFeatureSet,
                21_011,
                1,
            ),
            scalar_code_object: ContractObjectRef::new(ContractObjectKind::CodeObject, 9, 4),
            vector_code_object: ContractObjectRef::new(ContractObjectKind::CodeObject, 10, 4),
            simd_abi: "riscv-v".to_string(),
            vector_register_count: 32,
            vector_register_bits: 128,
            workload_units: 4096,
            scalar_nanos: 120_000,
            vector_nanos: 40_000,
            speedup_milli: 3000,
            context_overhead_nanos: 80_000,
            note: "record scalar/vector SIMD benchmark".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
    assert_eq!(graph.simd_benchmark_count(), 1);
    let benchmark = &graph.simd_benchmarks()[0];
    assert_eq!(
        benchmark.object_ref(),
        ContractObjectRef::new(ContractObjectKind::SimdBenchmark, 22_011, 1)
    );
    assert_eq!(benchmark.scalar_code_object.generation, 4);
    assert_eq!(benchmark.vector_code_object.generation, 4);
    assert_eq!(benchmark.speedup_milli, 3000);
    assert_eq!(benchmark.context_overhead_nanos, 80_000);
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "SimdBenchmarkRecorded benchmark=22011 target_feature_set=target-feature-set:21011@1 scalar_code_object=code-object:9@4 vector_code_object=code-object:10@4 simd_abi=riscv-v vector_register_count=32 vector_register_bits=128 workload_units=4096 scalar_nanos=120000 vector_nanos=40000 speedup_milli=3000 context_overhead_nanos=80000 generation=1"
    );
}

#[test]
pub(in crate::tests) fn simd_runtime_v11_rejects_vector_slower_than_scalar() {
    let mut graph = v11_supported_simd_benchmark_graph();

    let rejected = graph.apply_envelope(CommandEnvelope::new(
        1,
        "v11-test",
        SemanticCommand::RecordSimdBenchmark {
            benchmark: 22_011,
            target_feature_set: ContractObjectRef::new(
                ContractObjectKind::TargetFeatureSet,
                21_011,
                1,
            ),
            scalar_code_object: ContractObjectRef::new(ContractObjectKind::CodeObject, 9, 4),
            vector_code_object: ContractObjectRef::new(ContractObjectKind::CodeObject, 10, 4),
            simd_abi: "riscv-v".to_string(),
            vector_register_count: 32,
            vector_register_bits: 128,
            workload_units: 4096,
            scalar_nanos: 40_000,
            vector_nanos: 120_000,
            speedup_milli: 333,
            context_overhead_nanos: 0,
            note: "bad slower vector benchmark".to_string(),
        },
    ));

    assert_eq!(rejected.status, CommandStatus::Rejected);
    assert_eq!(
        rejected.violations,
        vec!["SIMD benchmark vector path must be faster than scalar path".to_string()]
    );
    assert!(graph.simd_benchmarks().is_empty());
}

#[test]
pub(in crate::tests) fn simd_runtime_v11_invariants_reject_metric_drift() {
    let mut graph = v11_supported_simd_benchmark_graph();
    assert!(graph.record_simd_benchmark_with_id(
        22_011,
        ContractObjectRef::new(ContractObjectKind::TargetFeatureSet, 21_011, 1),
        ContractObjectRef::new(ContractObjectKind::CodeObject, 9, 4),
        ContractObjectRef::new(ContractObjectKind::CodeObject, 10, 4),
        "riscv-v",
        32,
        128,
        4096,
        120_000,
        40_000,
        3000,
        80_000,
        "v11 scalar/vector benchmark",
    ));
    graph.corrupt_simd_benchmark_speedup_for_test(22_011, 2999);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::SimdBenchmarkInvalid { benchmark: 22_011 })
    );
}

pub(in crate::tests) fn v12_resumed_vector_context() -> SemanticGraph {
    let mut graph = v8_saved_vector_context_with_decision();
    let resumed = graph.apply_envelope(CommandEnvelope::new(
        3,
        "v12-test",
        SemanticCommand::ResumeActivation {
            resume: 15,
            scheduler_decision: 14,
            scheduler_decision_generation: 1,
            activation: 11,
            activation_generation: 4,
            note: "resume restores vector state before benchmark".to_string(),
        },
    ));
    assert_eq!(resumed.status, CommandStatus::Applied, "{resumed:?}");
    graph
}

#[test]
pub(in crate::tests) fn simd_runtime_v12_context_switch_benchmark_records_vector_overhead() {
    let mut graph = v12_resumed_vector_context();

    let result = graph.apply_envelope(CommandEnvelope::new(
        4,
        "v12-test",
        SemanticCommand::RecordSimdContextSwitchBenchmark {
            benchmark: 22_012,
            preemption: ContractObjectRef::new(ContractObjectKind::Preemption, 6, 1),
            activation_resume: ContractObjectRef::new(ContractObjectKind::ActivationResume, 15, 1),
            saved_vector_state: ContractObjectRef::new(ContractObjectKind::VectorState, 22_002, 1),
            restored_vector_state: ContractObjectRef::new(
                ContractObjectKind::VectorState,
                22_003,
                1,
            ),
            target_feature_set: ContractObjectRef::new(
                ContractObjectKind::TargetFeatureSet,
                21_002,
                1,
            ),
            simd_abi: "riscv-v".to_string(),
            vector_register_count: 32,
            vector_register_bits: 128,
            sample_count: 64,
            scalar_context_switch_nanos: 30_000,
            vector_context_switch_nanos: 46_384,
            overhead_nanos: 16_384,
            budget_nanos: 50_000,
            note: "record SIMD context switch overhead".to_string(),
        },
    ));

    assert_eq!(result.status, CommandStatus::Applied, "{result:?}");
    assert_eq!(graph.simd_context_switch_benchmark_count(), 1);
    let benchmark = &graph.simd_context_switch_benchmarks()[0];
    assert_eq!(
        benchmark.object_ref(),
        ContractObjectRef::new(ContractObjectKind::SimdContextSwitchBenchmark, 22_012, 1)
    );
    assert_eq!(benchmark.preemption.generation, 1);
    assert_eq!(benchmark.activation_resume.generation, 1);
    assert_eq!(benchmark.saved_vector_state.id, 22_002);
    assert_eq!(benchmark.restored_vector_state.id, 22_003);
    assert_eq!(benchmark.overhead_nanos, 16_384);
    assert!(graph.check_invariants().is_ok());
    assert_eq!(
        graph.event_log_tail(1)[0].kind.summary(),
        "SimdContextSwitchBenchmarkRecorded benchmark=22012 preemption=preemption:6@1 activation_resume=activation-resume:15@1 saved_vector_state=vector-state:22002@1 restored_vector_state=vector-state:22003@1 target_feature_set=target-feature-set:21002@1 simd_abi=riscv-v vector_register_count=32 vector_register_bits=128 sample_count=64 scalar_context_switch_nanos=30000 vector_context_switch_nanos=46384 overhead_nanos=16384 budget_nanos=50000 generation=1"
    );
}

#[test]
pub(in crate::tests) fn simd_runtime_v12_rejects_overhead_budget_violation() {
    let mut graph = v12_resumed_vector_context();

    let rejected = graph.apply_envelope(CommandEnvelope::new(
        4,
        "v12-test",
        SemanticCommand::RecordSimdContextSwitchBenchmark {
            benchmark: 22_012,
            preemption: ContractObjectRef::new(ContractObjectKind::Preemption, 6, 1),
            activation_resume: ContractObjectRef::new(ContractObjectKind::ActivationResume, 15, 1),
            saved_vector_state: ContractObjectRef::new(ContractObjectKind::VectorState, 22_002, 1),
            restored_vector_state: ContractObjectRef::new(
                ContractObjectKind::VectorState,
                22_003,
                1,
            ),
            target_feature_set: ContractObjectRef::new(
                ContractObjectKind::TargetFeatureSet,
                21_002,
                1,
            ),
            simd_abi: "riscv-v".to_string(),
            vector_register_count: 32,
            vector_register_bits: 128,
            sample_count: 64,
            scalar_context_switch_nanos: 30_000,
            vector_context_switch_nanos: 46_384,
            overhead_nanos: 16_384,
            budget_nanos: 10_000,
            note: "bad SIMD context switch budget".to_string(),
        },
    ));

    assert_eq!(rejected.status, CommandStatus::Rejected);
    assert_eq!(
        rejected.violations,
        vec!["SIMD context switch benchmark overhead exceeds budget".to_string()]
    );
    assert!(graph.simd_context_switch_benchmarks().is_empty());
}

#[test]
pub(in crate::tests) fn simd_runtime_v12_invariants_reject_overhead_drift() {
    let mut graph = v12_resumed_vector_context();
    assert!(graph.record_simd_context_switch_benchmark_with_id(
        22_012,
        ContractObjectRef::new(ContractObjectKind::Preemption, 6, 1),
        ContractObjectRef::new(ContractObjectKind::ActivationResume, 15, 1),
        ContractObjectRef::new(ContractObjectKind::VectorState, 22_002, 1),
        ContractObjectRef::new(ContractObjectKind::VectorState, 22_003, 1),
        ContractObjectRef::new(ContractObjectKind::TargetFeatureSet, 21_002, 1),
        "riscv-v",
        32,
        128,
        64,
        30_000,
        46_384,
        16_384,
        50_000,
        "v12 context switch benchmark",
    ));
    graph.corrupt_simd_context_switch_overhead_for_test(22_012, 16_383);

    assert_eq!(
        graph.check_invariants(),
        Err(SemanticInvariantError::SimdContextSwitchBenchmarkInvalid { benchmark: 22_012 })
    );
}
