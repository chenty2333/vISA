use criterion::{Criterion, black_box, criterion_group, criterion_main};
use vmos_bench::preemption_latency_sample;

fn bench_preemption_latency(c: &mut Criterion) {
    c.bench_function("preemption_stop_the_world", |b| {
        b.iter(|| {
            black_box(preemption_latency_sample());
        });
    });
}

criterion_group!(benches, bench_preemption_latency);
criterion_main!(benches);
