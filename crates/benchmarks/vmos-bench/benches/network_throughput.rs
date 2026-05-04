use criterion::{Criterion, black_box, criterion_group, criterion_main};
use vmos_bench::network_throughput_sample;

fn bench_network_throughput(c: &mut Criterion) {
    c.bench_function("network_rx_throughput", |b| {
        b.iter(|| {
            black_box(network_throughput_sample());
        });
    });
}

criterion_group!(benches, bench_network_throughput);
criterion_main!(benches);
