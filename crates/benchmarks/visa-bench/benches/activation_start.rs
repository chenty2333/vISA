use criterion::{Criterion, black_box, criterion_group, criterion_main};
use semantic_core::target_executor::ActivationEntry;
use visa_bench::runtime_loaded_artifact_fixture;

fn bench_artifact_load_activation_start(c: &mut Criterion) {
    c.bench_function("artifact_load_activation_start", |b| {
        b.iter_batched(
            runtime_loaded_artifact_fixture,
            |(mut runtime, _substrate, loaded)| {
                let activation = runtime
                    .start_activation(&loaded, ActivationEntry::Symbol("entry".to_string()))
                    .expect("start benchmark activation");
                black_box(activation.activation_id)
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, bench_artifact_load_activation_start);
criterion_main!(benches);
