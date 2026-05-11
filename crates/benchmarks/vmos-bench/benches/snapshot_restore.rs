use criterion::{Criterion, black_box, criterion_group, criterion_main};
use vmos_bench::runtime_restore_fixture;

fn bench_portable_snapshot_restore_latency(c: &mut Criterion) {
    c.bench_function("portable_snapshot_restore_latency", |b| {
        b.iter_batched(
            runtime_restore_fixture,
            |(mut runtime, snapshot)| {
                runtime.restore_portable_subset(&snapshot).expect("restore portable snapshot");
                black_box(runtime.snapshot().artifacts.len())
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, bench_portable_snapshot_restore_latency);
criterion_main!(benches);
