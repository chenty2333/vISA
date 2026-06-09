use criterion::{Criterion, black_box, criterion_group, criterion_main};
use visa_bench::{invoke_bench_console_hostcall, runtime_hostcall_fixture};

fn bench_hostcall_dispatch_latency(c: &mut Criterion) {
    c.bench_function("hostcall_dispatch_latency", |b| {
        b.iter_batched(
            runtime_hostcall_fixture,
            |(mut runtime, mut substrate, activation)| {
                black_box(invoke_bench_console_hostcall(&mut runtime, &mut substrate, &activation))
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, bench_hostcall_dispatch_latency);
criterion_main!(benches);
