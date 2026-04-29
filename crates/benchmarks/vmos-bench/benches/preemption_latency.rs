// Preemption latency benchmarks.
// Ported from semantic_core::graph::latency.
use criterion::{Criterion, black_box, criterion_group, criterion_main};

fn bench_preemption_latency(c: &mut Criterion) {
    c.bench_function("preemption_stop_the_world", |b| {
        b.iter(|| {
            // TODO: extract from semantic_core latency logic
            black_box(());
        });
    });
}

criterion_group!(benches, bench_preemption_latency);
criterion_main!(benches);
