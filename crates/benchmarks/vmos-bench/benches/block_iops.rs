// Block IOPS and latency benchmarks.
// Ported from semantic_core::graph::block_benchmark.
use criterion::{Criterion, black_box, criterion_group, criterion_main};

fn bench_block_iops(c: &mut Criterion) {
    c.bench_function("block_read_iops", |b| {
        b.iter(|| {
            // TODO: extract from semantic_core block_benchmark logic
            black_box(());
        });
    });
}

criterion_group!(benches, bench_block_iops);
criterion_main!(benches);
