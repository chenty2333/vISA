use criterion::{Criterion, black_box, criterion_group, criterion_main};
use vmos_bench::simd_context_switch_sample;

fn bench_simd_context_switch(c: &mut Criterion) {
    c.bench_function("simd_save_restore_vector_state", |b| {
        b.iter(|| {
            black_box(simd_context_switch_sample());
        });
    });
}

criterion_group!(benches, bench_simd_context_switch);
criterion_main!(benches);
