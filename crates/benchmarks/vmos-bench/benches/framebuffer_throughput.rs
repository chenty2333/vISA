use criterion::{Criterion, black_box, criterion_group, criterion_main};
use vmos_bench::display_framebuffer_fixture;

fn bench_framebuffer_setup_mutation(c: &mut Criterion) {
    c.bench_function("framebuffer_display_setup_mutation", |b| {
        b.iter_batched(
            display_framebuffer_fixture,
            |graph| {
                black_box((
                    graph.framebuffer_object_count(),
                    graph.display_object_count(),
                ))
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, bench_framebuffer_setup_mutation);
criterion_main!(benches);
