use criterion::{Criterion, black_box, criterion_group, criterion_main};
use semantic_core::target_executor::{ContractObjectKind, ContractObjectRef};
use vmos_bench::{derive_network_throughput_sample, network_packet_fixture};

fn bench_derive_network_throughput(c: &mut Criterion) {
    c.bench_function("network_rx_throughput_derive", |b| {
        b.iter(|| {
            black_box(derive_network_throughput_sample());
        });
    });
}

fn bench_network_adapter_record_mutation(c: &mut Criterion) {
    c.bench_function("network_adapter_record_mutation", |b| {
        b.iter_batched(
            network_packet_fixture,
            |mut graph| {
                let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
                assert!(graph.record_fake_net_backend_object_with_id(
                    1,
                    "fake-net",
                    1,
                    1,
                    "service_core",
                    "fake-net-v1",
                    1500,
                    64,
                    64,
                    mac,
                    1,
                    65536,
                    42,
                    "bench",
                ));
                let backend_ref =
                    ContractObjectRef::new(ContractObjectKind::FakeNetBackendObject, 1, 1);
                assert!(graph.record_network_stack_adapter_with_id(
                    1,
                    backend_ref,
                    1,
                    1,
                    1,
                    1,
                    2,
                    1,
                    "smoltcp",
                    "0.13.0",
                    "smoltcp-0.13.0-ethernet-ipv4-tcp-v1",
                    "ethernet",
                    mac,
                    [10, 0, 0, 1],
                    24,
                    1500,
                    64,
                    64,
                    65536,
                    0,
                    "bench adapter",
                ));
                black_box(graph.network_stack_adapter_count())
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, bench_derive_network_throughput, bench_network_adapter_record_mutation);
criterion_main!(benches);
