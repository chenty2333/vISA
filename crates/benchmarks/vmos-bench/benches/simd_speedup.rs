use criterion::{Criterion, black_box, criterion_group, criterion_main};
use semantic_core::target_executor::{ContractObjectKind, ContractObjectRef};
use vmos_bench::simd_vector_fixture;

fn bench_simd_speedup_mutation(c: &mut Criterion) {
    c.bench_function("simd_speedup_mutation", |b| {
        b.iter_batched(
            simd_vector_fixture,
            |mut graph| {
                let tf = ContractObjectRef::new(ContractObjectKind::TargetFeatureSet, 21002, 1);
                let scalar = ContractObjectRef::new(ContractObjectKind::CodeObject, 1, 1);
                let vector = ContractObjectRef::new(ContractObjectKind::CodeObject, 2, 1);
                assert!(graph.record_simd_benchmark_with_id(
                    1,
                    tf,
                    scalar,
                    vector,
                    "riscv-v",
                    32,
                    128,
                    100_000,
                    12_000_000,
                    8_000_000,
                    1500,
                    4_000_000,
                    "criterion SIMD speedup",
                ));
                black_box(graph.simd_benchmark_count())
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, bench_simd_speedup_mutation);
criterion_main!(benches);
