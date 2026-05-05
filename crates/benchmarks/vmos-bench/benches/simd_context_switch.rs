use criterion::{Criterion, black_box, criterion_group, criterion_main};
use semantic_core::VectorStateState;
use semantic_core::target_executor::{ContractObjectKind, ContractObjectRef};
use vmos_bench::simd_vector_fixture;

fn bench_simd_vector_state_record_mutation(c: &mut Criterion) {
    c.bench_function("simd_vector_state_record_mutation", |b| {
        b.iter_batched(
            simd_vector_fixture,
            |mut graph| {
                let activation = ContractObjectRef::new(ContractObjectKind::Activation, 1, 1);
                let store = ContractObjectRef::new(ContractObjectKind::Store, 1, 1);
                let code = ContractObjectRef::new(ContractObjectKind::CodeObject, 3, 1);
                let tf = ContractObjectRef::new(ContractObjectKind::TargetFeatureSet, 21002, 1);
                assert!(graph.record_vector_state_with_id(
                    22002, activation, store, code, tf,
                    "riscv-v", 32, 128, 512, VectorStateState::Reserved,
                    "criterion vector state",
                ));
                black_box(graph.vector_states().len())
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, bench_simd_vector_state_record_mutation);
criterion_main!(benches);
