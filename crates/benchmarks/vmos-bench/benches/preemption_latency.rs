use criterion::{Criterion, black_box, criterion_group, criterion_main};
use semantic_core::{CommandEnvelope, CommandStatus, SemanticCommand};
use vmos_bench::scheduler_2hart_fixture;

fn bench_preemption_latency_mutation(c: &mut Criterion) {
    c.bench_function("preemption_latency_mutation", |b| {
        b.iter_batched(
            scheduler_2hart_fixture,
            |mut graph| {
                assert!(graph.record_timer_interrupt_with_id(
                    1, 1, 1, 2, Some(11), Some(3), "bench timer",
                ));
                assert!(graph.preempt_running_activation_with_id(
                    1, 11, 3, 1, 1, 1, "bench preempt",
                ));
                assert!(graph.record_scheduler_decision_with_id(
                    1, 1, 1, 11, 4, "preempted", "bench decision",
                ));
                assert!(graph.resume_activation_with_id(
                    1, 1, 1, 11, 4, "bench resume",
                ));
                let result = graph.apply_envelope(CommandEnvelope::new(
                    1, "vmos-bench-preemption",
                    SemanticCommand::RecordPreemptionLatencySample {
                        sample: 1, timer_interrupt: 1, timer_interrupt_generation: 1,
                        preemption: 1, preemption_generation: 1,
                        scheduler_decision: 1, scheduler_decision_generation: 1,
                        activation_resume: 1, activation_resume_generation: 1,
                        measured_nanos: 8_500, budget_nanos: 50_000,
                        note: "criterion preemption latency".to_owned(),
                    },
                ));
                assert_eq!(result.status, CommandStatus::Applied, "{:?}", result.violations);
                black_box((
                    graph.preemption_latency_samples().len(),
                    graph.event_count(),
                ))
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, bench_preemption_latency_mutation);
criterion_main!(benches);
