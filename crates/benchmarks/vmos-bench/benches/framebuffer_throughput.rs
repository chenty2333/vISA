use criterion::{Criterion, black_box, criterion_group, criterion_main};
use vmos_bench::display_framebuffer_fixture;

fn bench_display_record_mutation(c: &mut Criterion) {
    c.bench_function("display_record_mutation", |b| {
        b.iter_batched(
            display_framebuffer_fixture,
            |mut graph| {
                assert!(graph.record_display_object_with_id(
                    1,
                    "disp0",
                    1,
                    1,
                    "1920x1080",
                    1920,
                    1080,
                    60_000,
                    "bench",
                ));
                black_box(graph.display_object_count())
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, bench_display_record_mutation);
criterion_main!(benches);
