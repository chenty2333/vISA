use criterion::{Criterion, black_box, criterion_group, criterion_main};
use semantic_core::BlockRequestOperation;
use vmos_bench::{block_request_fixture, derive_block_iops_sample};

fn bench_derive_block_iops(c: &mut Criterion) {
    c.bench_function("block_read_iops_derive", |b| {
        b.iter(|| {
            black_box(derive_block_iops_sample());
        });
    });
}

fn bench_block_request_submit_mutation(c: &mut Criterion) {
    c.bench_function("block_request_submit_mutation_64", |b| {
        b.iter_batched(
            block_request_fixture,
            |mut graph| {
                for i in 0..64 {
                    assert!(graph.record_block_request_object_with_id(
                        1 + i, 1, 1, 1, 1,
                        BlockRequestOperation::Read,
                        1 + i, "bench req",
                    ));
                }
                black_box(graph.block_request_object_count())
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, bench_derive_block_iops, bench_block_request_submit_mutation);
criterion_main!(benches);
