use criterion::{Criterion, black_box, criterion_group, criterion_main};
use vmos_bench::block_iops_sample;

fn bench_block_iops(c: &mut Criterion) {
    c.bench_function("block_read_iops", |b| {
        b.iter(|| {
            black_box(block_iops_sample());
        });
    });
}

criterion_group!(benches, bench_block_iops);
criterion_main!(benches);
