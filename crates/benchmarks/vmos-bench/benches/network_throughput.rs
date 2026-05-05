use criterion::{Criterion, black_box, criterion_group, criterion_main};
use vmos_bench::{derive_network_throughput_sample, network_packet_fixture};

fn bench_derive_network_throughput(c: &mut Criterion) {
    c.bench_function("network_rx_throughput_derive", |b| {
        b.iter(|| {
            black_box(derive_network_throughput_sample());
        });
    });
}

fn bench_network_packet_setup_mutation(c: &mut Criterion) {
    c.bench_function("network_packet_device_setup_mutation", |b| {
        b.iter_batched(
            network_packet_fixture,
            |graph| {
                black_box(graph.packet_device_object_count())
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, bench_derive_network_throughput, bench_network_packet_setup_mutation);
criterion_main!(benches);
