use super::{super::*, *};
pub(crate) fn activation_resume_view_v1(resume: &ActivationResumeManifest) -> serde_json::Value {
    let vector_status =
        if resume.vector_status.is_empty() { "absent" } else { resume.vector_status.as_str() };
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "activation-resume",
        "id": resume.id,
        "generation": resume.generation,
        "state": resume.state,
        "owner": {
            "scheduler": 1,
            "task": resume.owner_task,
            "task_generation": resume.owner_task_generation,
        },
        "references": {
            "scheduler_decision": {
                "id": resume.scheduler_decision,
                "generation": resume.scheduler_decision_generation,
            },
            "activation": {
                "id": resume.activation,
                "generation_before": resume.activation_generation_before,
                "generation_after": resume.activation_generation_after,
            },
            "queue": {
                "id": resume.queue,
                "generation": resume.queue_generation,
            },
            "activation_context": resume.context.map(|id| serde_json::json!({
                "id": id,
                "generation_before": resume.context_generation_before,
                "generation_after": resume.context_generation_after,
            })),
            "saved_context": resume.saved_context.map(|id| serde_json::json!({
                "id": id,
                "generation": resume.saved_context_generation,
            })),
            "saved_vector_state": resume.saved_vector_state.as_ref().map(object_ref_manifest_json),
            "restored_vector_state": resume.restored_vector_state.as_ref().map(object_ref_manifest_json),
        },
        "vector_restore": {
            "status": vector_status,
            "saved_vector_state": resume.saved_vector_state.as_ref().map(object_ref_manifest_json),
            "restored_vector_state": resume.restored_vector_state.as_ref().map(object_ref_manifest_json),
            "restored_at_event": resume.vector_restored_at_event,
        },
        "note": resume.note,
        "last_transition": {
            "resumed_at_event": resume.resumed_at_event,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn activation_wait_view_v1(wait: &ActivationWaitManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "activation-wait",
        "id": wait.id,
        "generation": wait.generation,
        "state": wait.state,
        "owner": {
            "task": wait.owner_task,
            "task_generation": wait.owner_task_generation,
        },
        "references": {
            "activation": {
                "id": wait.activation,
                "generation_before": wait.activation_generation_before,
                "generation_after_block": wait.activation_generation_after_block,
                "generation_after_cancel": wait.activation_generation_after_cancel,
            },
            "wait": {
                "id": wait.wait,
                "generation": wait.wait_generation,
            },
            "queue": wait.queue.map(|id| serde_json::json!({
                "id": id,
                "generation": wait.queue_generation,
            })),
        },
        "cancel_reason": wait.cancel_reason,
        "note": wait.note,
        "last_transition": {
            "blocked_at_event": wait.blocked_at_event,
            "completed_at_event": wait.completed_at_event,
        },
        "last_error": wait.cancel_reason,
    })
}

pub(crate) fn activation_cleanup_view_v1(cleanup: &ActivationCleanupManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "activation-cleanup",
        "id": cleanup.id,
        "generation": cleanup.generation,
        "state": cleanup.state,
        "owner": {
            "store": cleanup.store,
            "target_store_generation": cleanup.target_store_generation,
            "result_store_generation": cleanup.result_store_generation,
            "task": cleanup.owner_task,
            "task_generation_before": cleanup.owner_task_generation_before,
            "task_generation_after": cleanup.owner_task_generation_after,
        },
        "references": {
            "activation": {
                "id": cleanup.activation,
                "generation_before": cleanup.activation_generation_before,
                "generation_after": cleanup.activation_generation_after,
            },
            "wait": cleanup.wait.map(|id| serde_json::json!({
                "id": id,
                "generation": cleanup.wait_generation,
            })),
            "steps": cleanup.steps.iter().map(|step| serde_json::json!({
                "kind": step.kind,
                "target": step.target,
                "observed_generation": step.observed_generation,
                "status": step.status,
                "event": step.event,
            })).collect::<Vec<_>>(),
        },
        "reason": cleanup.reason,
        "note": cleanup.note,
        "last_transition": {
            "started_at_event": cleanup.started_at_event,
            "completed_at_event": cleanup.completed_at_event,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn preemption_latency_view_v1(
    sample: &PreemptionLatencySampleManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "preemption-latency",
        "id": sample.id,
        "generation": sample.generation,
        "state": sample.state,
        "owner": {
            "activation": sample.activation,
            "activation_generation_before": sample.activation_generation_before,
            "activation_generation_after": sample.activation_generation_after,
            "queue": sample.queue,
            "queue_generation": sample.queue_generation,
        },
        "references": {
            "timer_interrupt": {
                "id": sample.timer_interrupt,
                "generation": sample.timer_interrupt_generation,
            },
            "preemption": {
                "id": sample.preemption,
                "generation": sample.preemption_generation,
            },
            "scheduler_decision": {
                "id": sample.scheduler_decision,
                "generation": sample.scheduler_decision_generation,
            },
            "activation_resume": {
                "id": sample.activation_resume,
                "generation": sample.activation_resume_generation,
            },
        },
        "event_window": {
            "interrupt_recorded_at_event": sample.interrupt_recorded_at_event,
            "preempted_at_event": sample.preempted_at_event,
            "decided_at_event": sample.decided_at_event,
            "resumed_at_event": sample.resumed_at_event,
            "interrupt_to_preempt_events": sample.interrupt_to_preempt_events,
            "preempt_to_decision_events": sample.preempt_to_decision_events,
            "decision_to_resume_events": sample.decision_to_resume_events,
            "interrupt_to_resume_events": sample.interrupt_to_resume_events,
        },
        "metrics": {
            "measured_nanos": sample.measured_nanos,
            "budget_nanos": sample.budget_nanos,
            "within_budget": sample.measured_nanos <= sample.budget_nanos,
        },
        "last_transition": {
            "recorded_at_event": sample.recorded_at_event,
        },
        "last_error": serde_json::Value::Null,
        "note": sample.note,
    })
}

pub(crate) fn guest_address_space_view_v1(aspace: &GuestAddressSpaceManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "guest-address-space",
        "id": aspace.id,
        "generation": aspace.generation,
        "state": aspace.state,
        "owner": {
            "object": object_ref_manifest_json(&aspace.owner),
        },
        "references": {
            "owner": object_ref_manifest_json(&aspace.owner),
            "root_region": aspace.root_region.as_ref().map(object_ref_manifest_json),
        },
        "memory_generation": {
            "vma_generation": aspace.vma_generation,
            "page_map_generation": aspace.page_map_generation,
        },
        "last_transition": {
            "generation": aspace.generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn vma_region_view_v1(region: &VmaRegionManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "vma-region",
        "id": region.id,
        "generation": region.generation,
        "state": region.state,
        "owner": {
            "aspace": object_ref_manifest_json(&region.aspace),
        },
        "references": {
            "aspace": object_ref_manifest_json(&region.aspace),
            "backing": object_ref_manifest_json(&region.backing),
        },
        "range": {
            "start": region.range.start,
            "len": region.range.len,
            "end": region.range.start.saturating_add(region.range.len),
        },
        "permissions": {
            "readable": region.perms.readable,
            "writable": region.perms.writable,
            "executable": region.perms.executable,
        },
        "flags": {
            "cow": region.flags.cow,
            "shared": region.flags.shared,
            "device": region.flags.device,
        },
        "last_transition": {
            "generation": region.generation,
            "page_generation": region.backing.generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn page_object_view_v1(page: &PageObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "page-object",
        "id": page.id,
        "generation": page.generation,
        "state": page.state,
        "owner": {
            "memory_model": "guest-memory",
        },
        "references": {},
        "page": {
            "backing": page.backing,
            "cow": page.cow,
            "dirty_generation": page.dirty_generation,
        },
        "last_transition": {
            "generation": page.generation,
            "dirty_generation": page.dirty_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn guest_memory_fault_view_v1(fault: &GuestMemoryFaultManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "page-fault-event",
        "id": fault.id,
        "generation": fault.generation,
        "state": if fault.historical { "historical" } else { "active" },
        "owner": {
            "page": object_ref_manifest_json(&fault.page),
        },
        "references": {
            "page": object_ref_manifest_json(&fault.page),
        },
        "fault": {
            "reason": fault.reason,
            "historical": fault.historical,
        },
        "last_transition": {
            "generation": fault.generation,
            "page_generation": fault.page.generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn scheduler_view_v1(package: &MigrationPackageManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "scheduler",
        "id": 1,
        "generation": 1,
        "state": "active",
        "owner": {
            "package": package.package_id,
        },
        "references": {
            "harts": package.semantic.hart_records.iter().map(|hart| serde_json::json!({
                "id": hart.id,
                "hardware_id": hart.hardware_id,
                "generation": hart.generation,
                "state": hart.state,
                "boot": hart.boot,
                "current_activation": hart.current_activation,
                "current_activation_generation": hart.current_activation_generation,
            })).collect::<Vec<_>>(),
            "current_activation_owners": package.semantic.hart_records.iter().filter_map(|hart| {
                let activation = hart.current_activation?;
                let activation_generation = hart.current_activation_generation?;
                Some(serde_json::json!({
                    "hart": {
                        "id": hart.id,
                        "generation": hart.generation,
                        "hardware_id": hart.hardware_id,
                    },
                    "activation": {
                        "id": activation,
                        "generation": activation_generation,
                    },
                    "task": hart.current_task.map(|id| serde_json::json!({
                        "id": id,
                        "generation": hart.current_task_generation,
                    })),
                    "store": hart.current_store.map(|id| serde_json::json!({
                        "id": id,
                        "generation": hart.current_store_generation,
                    })),
                }))
            }).collect::<Vec<_>>(),
            "tasks": package.semantic.task_records.iter().map(|task| serde_json::json!({
                "id": task.id,
                "generation": task.generation,
            })).collect::<Vec<_>>(),
            "activations": package.semantic.runtime_activation_records.iter().map(|activation| serde_json::json!({
                "id": activation.id,
                "generation": activation.generation,
                "state": activation.state,
            })).collect::<Vec<_>>(),
            "queues": package.semantic.runnable_queues.iter().map(|queue| serde_json::json!({
                "id": queue.id,
                "generation": queue.generation,
                "entries": queue.entries.len(),
                "owner_hart": queue.owner_hart,
                "owner_hart_generation": queue.owner_hart_generation,
            })).collect::<Vec<_>>(),
            "activation_contexts": package.semantic.activation_contexts.iter().map(|context| serde_json::json!({
                "id": context.id,
                "generation": context.generation,
                "activation": context.activation,
                "activation_generation": context.activation_generation,
            })).collect::<Vec<_>>(),
            "saved_contexts": package.semantic.saved_contexts.iter().map(|saved| serde_json::json!({
                "id": saved.id,
                "generation": saved.generation,
                "context": saved.context,
                "context_generation": saved.context_generation,
                "vector_status": saved.vector_status,
                "vector_state": saved.vector_state.as_ref().map(object_ref_manifest_json),
            })).collect::<Vec<_>>(),
            "timer_interrupts": package.semantic.timer_interrupts.iter().map(|interrupt| serde_json::json!({
                "id": interrupt.id,
                "generation": interrupt.generation,
                "timer_epoch": interrupt.timer_epoch,
                "target_activation": interrupt.target_activation,
                "target_activation_generation": interrupt.target_activation_generation,
            })).collect::<Vec<_>>(),
            "ipi_events": package.semantic.ipi_events.iter().map(|ipi| serde_json::json!({
                "id": ipi.id,
                "generation": ipi.generation,
                "kind": ipi.kind,
                "source_hart": ipi.source_hart,
                "source_hart_generation": ipi.source_hart_generation,
                "target_hart": ipi.target_hart,
                "target_hart_generation": ipi.target_hart_generation,
                "state": ipi.state,
            })).collect::<Vec<_>>(),
            "remote_preempts": package.semantic.remote_preempts.iter().map(|remote| serde_json::json!({
                "id": remote.id,
                "generation": remote.generation,
                "ipi": remote.ipi,
                "ipi_generation": remote.ipi_generation,
                "source_hart": remote.source_hart,
                "source_hart_generation": remote.source_hart_generation,
                "target_hart": remote.target_hart,
                "target_hart_generation_before": remote.target_hart_generation_before,
                "target_hart_generation_after": remote.target_hart_generation_after,
                "activation": remote.activation,
                "activation_generation_before": remote.activation_generation_before,
                "activation_generation_after": remote.activation_generation_after,
                "queue": remote.queue,
                "queue_generation": remote.queue_generation,
                "state": remote.state,
            })).collect::<Vec<_>>(),
            "remote_parks": package.semantic.remote_parks.iter().map(|remote| serde_json::json!({
                "id": remote.id,
                "generation": remote.generation,
                "ipi": remote.ipi,
                "ipi_generation": remote.ipi_generation,
                "source_hart": remote.source_hart,
                "source_hart_generation": remote.source_hart_generation,
                "target_hart": remote.target_hart,
                "target_hart_generation_before": remote.target_hart_generation_before,
                "target_hart_generation_after": remote.target_hart_generation_after,
                "state": remote.state,
                "reason": remote.reason,
            })).collect::<Vec<_>>(),
            "hart_event_attributions": package.semantic.hart_event_attributions.iter().map(|attribution| serde_json::json!({
                "id": attribution.id,
                "generation": attribution.generation,
                "hart": attribution.hart,
                "hart_generation": attribution.hart_generation,
                "event": attribution.event,
                "event_kind": attribution.event_kind,
            })).collect::<Vec<_>>(),
            "preemptions": package.semantic.preemptions.iter().map(|preemption| serde_json::json!({
                "id": preemption.id,
                "generation": preemption.generation,
                "activation": preemption.activation,
                "activation_generation_after": preemption.activation_generation_after,
                "queue": preemption.queue,
                "queue_generation": preemption.queue_generation,
            })).collect::<Vec<_>>(),
            "scheduler_decisions": package.semantic.scheduler_decisions.iter().map(|decision| serde_json::json!({
                "id": decision.id,
                "generation": decision.generation,
                "selected_activation": decision.selected_activation,
                "selected_activation_generation": decision.selected_activation_generation,
                "queue": decision.queue,
                "queue_generation": decision.queue_generation,
            })).collect::<Vec<_>>(),
            "cross_hart_scheduler_decisions": package.semantic.cross_hart_scheduler_decisions.iter().map(|decision| serde_json::json!({
                "id": decision.id,
                "generation": decision.generation,
                "scheduler_decision": decision.scheduler_decision,
                "scheduler_decision_generation": decision.scheduler_decision_generation,
                "deciding_hart": decision.deciding_hart,
                "deciding_hart_generation": decision.deciding_hart_generation,
                "target_hart": decision.target_hart,
                "target_hart_generation": decision.target_hart_generation,
                "queue": decision.queue,
                "queue_generation": decision.queue_generation,
                "selected_activation": decision.selected_activation,
                "selected_activation_generation": decision.selected_activation_generation,
            })).collect::<Vec<_>>(),
            "activation_migrations": package.semantic.activation_migrations.iter().map(|migration| serde_json::json!({
                "id": migration.id,
                "generation": migration.generation,
                "activation": migration.activation,
                "activation_generation_before": migration.activation_generation_before,
                "activation_generation_after": migration.activation_generation_after,
                "source_hart": migration.source_hart,
                "source_hart_generation": migration.source_hart_generation,
                "target_hart": migration.target_hart,
                "target_hart_generation": migration.target_hart_generation,
                "source_queue": migration.source_queue,
                "source_queue_generation": migration.source_queue_generation,
                "target_queue": migration.target_queue,
                "target_queue_generation": migration.target_queue_generation,
            })).collect::<Vec<_>>(),
            "smp_safe_points": package.semantic.smp_safe_points.iter().map(|safe_point| serde_json::json!({
                "id": safe_point.id,
                "generation": safe_point.generation,
                "coordinator_hart": safe_point.coordinator_hart,
                "coordinator_hart_generation": safe_point.coordinator_hart_generation,
                "participant_count": safe_point.participants.len(),
                "state": safe_point.state,
            })).collect::<Vec<_>>(),
            "stop_the_world_rendezvous": package.semantic.stop_the_world_rendezvous.iter().map(|rendezvous| serde_json::json!({
                "id": rendezvous.id,
                "generation": rendezvous.generation,
                "epoch": rendezvous.epoch,
                "safe_point": rendezvous.safe_point,
                "safe_point_generation": rendezvous.safe_point_generation,
                "coordinator_hart": rendezvous.coordinator_hart,
                "coordinator_hart_generation": rendezvous.coordinator_hart_generation,
                "participant_count": rendezvous.participants.len(),
                "state": rendezvous.state,
            })).collect::<Vec<_>>(),
            "smp_code_publish_barriers": package.semantic.smp_code_publish_barriers.iter().map(|barrier| serde_json::json!({
                "id": barrier.id,
                "generation": barrier.generation,
                "rendezvous": barrier.rendezvous,
                "rendezvous_generation": barrier.rendezvous_generation,
                "code_publish_epoch_before": barrier.code_publish_epoch_before,
                "code_publish_epoch_after": barrier.code_publish_epoch_after,
                "participant_count": barrier.participants.len(),
                "remote_icache_sync_required": barrier.remote_icache_sync_required,
                "code_publish_executed": barrier.code_publish_executed,
                "state": barrier.state,
            })).collect::<Vec<_>>(),
            "smp_cleanup_quiescence": package.semantic.smp_cleanup_quiescence.iter().map(|quiescence| serde_json::json!({
                "id": quiescence.id,
                "generation": quiescence.generation,
                "cleanup": quiescence.cleanup,
                "cleanup_generation": quiescence.cleanup_generation,
                "store": quiescence.store,
                "target_store_generation": quiescence.target_store_generation,
                "result_store_generation": quiescence.result_store_generation,
                "rendezvous": quiescence.rendezvous,
                "rendezvous_generation": quiescence.rendezvous_generation,
                "participant_count": quiescence.participants.len(),
                "state": quiescence.state,
            })).collect::<Vec<_>>(),
            "smp_snapshot_barriers": package.semantic.smp_snapshot_barriers.iter().map(|barrier| serde_json::json!({
                "id": barrier.id,
                "generation": barrier.generation,
                "rendezvous": barrier.rendezvous,
                "rendezvous_generation": barrier.rendezvous_generation,
                "rendezvous_epoch": barrier.rendezvous_epoch,
                "event_log_cursor": barrier.event_log_cursor,
                "participant_count": barrier.participants.len(),
                "snapshot_validation_ok": barrier.snapshot_validation_ok,
                "state": barrier.state,
            })).collect::<Vec<_>>(),
            "smp_stress_runs": package.semantic.smp_stress_runs.iter().map(|run| serde_json::json!({
                "id": run.id,
                "generation": run.generation,
                "scenario": run.scenario,
                "iterations": run.iterations,
                "hart_count": run.hart_count,
                "safe_point_count": run.observed_safe_point_count,
                "rendezvous_count": run.observed_rendezvous_count,
                "property_failures": run.property_failures,
                "state": run.state,
            })).collect::<Vec<_>>(),
            "smp_scaling_benchmarks": package.semantic.smp_scaling_benchmarks.iter().map(|benchmark| serde_json::json!({
                "id": benchmark.id,
                "generation": benchmark.generation,
                "scenario": benchmark.scenario,
                "stress_run": object_ref_json("smp-stress-run", benchmark.stress_run, benchmark.stress_run_generation),
                "hart_count": benchmark.hart_count,
                "workload_units": benchmark.workload_units,
                "measured_smp_nanos": benchmark.measured_smp_nanos,
                "speedup_milli": benchmark.speedup_milli,
                "efficiency_milli": benchmark.efficiency_milli,
                "state": benchmark.state,
            })).collect::<Vec<_>>(),
            "activation_resumes": package.semantic.activation_resumes.iter().map(|resume| serde_json::json!({
                "id": resume.id,
                "generation": resume.generation,
                "scheduler_decision": resume.scheduler_decision,
                "scheduler_decision_generation": resume.scheduler_decision_generation,
                "activation": resume.activation,
                "activation_generation_after": resume.activation_generation_after,
            })).collect::<Vec<_>>(),
            "activation_waits": package.semantic.activation_waits.iter().map(|wait| serde_json::json!({
                "id": wait.id,
                "generation": wait.generation,
                "activation": wait.activation,
                "activation_generation_after_block": wait.activation_generation_after_block,
                "wait": wait.wait,
                "wait_generation": wait.wait_generation,
                "state": wait.state,
            })).collect::<Vec<_>>(),
            "activation_cleanups": package.semantic.activation_cleanups.iter().map(|cleanup| serde_json::json!({
                "id": cleanup.id,
                "generation": cleanup.generation,
                "store": cleanup.store,
                "result_store_generation": cleanup.result_store_generation,
                "activation": cleanup.activation,
                "activation_generation_after": cleanup.activation_generation_after,
                "state": cleanup.state,
            })).collect::<Vec<_>>(),
            "preemption_latency_samples": package.semantic.preemption_latency_samples.iter().map(|sample| serde_json::json!({
                "id": sample.id,
                "generation": sample.generation,
                "activation": sample.activation,
                "interrupt_to_resume_events": sample.interrupt_to_resume_events,
                "measured_nanos": sample.measured_nanos,
                "budget_nanos": sample.budget_nanos,
                "state": sample.state,
            })).collect::<Vec<_>>(),
        },
        "last_transition": {
            "scheduler_decision_cursor": package.substrate_boundary.scheduler_decision_cursor,
            "timer_epoch": package.substrate_boundary.timer_epoch,
            "hart_count": package.semantic.hart_count,
            "task_count": package.semantic.task_record_count,
            "activation_count": package.semantic.runtime_activation_count,
            "queue_count": package.semantic.runnable_queue_count,
            "activation_context_count": package.semantic.activation_context_count,
            "saved_context_count": package.semantic.saved_context_count,
            "timer_interrupt_count": package.semantic.timer_interrupt_count,
            "ipi_event_count": package.semantic.ipi_event_count,
            "remote_preempt_count": package.semantic.remote_preempt_count,
            "remote_park_count": package.semantic.remote_park_count,
            "hart_event_attribution_count": package.semantic.hart_event_attribution_count,
            "preemption_count": package.semantic.preemption_count,
            "scheduler_decision_count": package.semantic.scheduler_decision_count,
            "cross_hart_scheduler_decision_count": package.semantic.cross_hart_scheduler_decision_count,
            "activation_migration_count": package.semantic.activation_migration_count,
            "smp_safe_point_count": package.semantic.smp_safe_point_count,
            "stop_the_world_rendezvous_count": package.semantic.stop_the_world_rendezvous_count,
            "smp_code_publish_barrier_count": package.semantic.smp_code_publish_barrier_count,
            "smp_cleanup_quiescence_count": package.semantic.smp_cleanup_quiescence_count,
            "smp_snapshot_barrier_count": package.semantic.smp_snapshot_barrier_count,
            "smp_stress_run_count": package.semantic.smp_stress_run_count,
            "smp_scaling_benchmark_count": package.semantic.smp_scaling_benchmark_count,
            "activation_resume_count": package.semantic.activation_resume_count,
            "activation_wait_count": package.semantic.activation_wait_count,
            "activation_cleanup_count": package.semantic.activation_cleanup_count,
            "preemption_latency_sample_count": package.semantic.preemption_latency_sample_count,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn artifact_view_v1(artifact: &TargetArtifactImageManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "artifact",
        "id": artifact.id,
        "generation": 1,
        "state": "accepted",
        "owner": {
            "package": artifact.package,
            "role": artifact.role,
            "target_profile": artifact.target_profile,
        },
        "references": {
            "artifact_name": artifact.artifact_name,
            "artifact_hash": artifact.artifact_hash,
            "hash_status": artifact.hash_status,
            "manifest_binding_hash": artifact.manifest_binding_hash,
            "abi_fingerprint": artifact.abi_fingerprint,
            "code_hash": artifact.code_hash,
        },
        "verification": {
            "hash_status": artifact.hash_status,
            "signature_scheme": artifact.signature_scheme,
            "signature_status": artifact.signature_status,
            "signature_verified": artifact.signature_verified,
            "signer": artifact.signer,
        },
        "exports": artifact.exports,
        "imports": artifact.imports,
        "hostcall_count": artifact.hostcalls.len(),
        "capability_count": artifact.capabilities.len(),
        "memory_plan": artifact.memory_plan,
        "last_transition": {
            "kind": artifact.kind,
            "payload_len": artifact.payload_len,
            "trap_metadata_count": artifact.trap_metadata.len(),
            "address_map_count": artifact.address_map.len(),
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn code_object_view_v1(code: &CodeObjectManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "code-object",
        "id": code.id,
        "generation": code.generation,
        "state": code.state,
        "owner": {
            "package": code.package,
            "profile": code.owner_profile,
        },
        "references": {
            "artifact": {
                "id": code.artifact_id,
                "generation": 1,
            },
            "bound_store": code.bound_store.map(|id| serde_json::json!({
                "id": id,
                "generation": code.bound_store_generation,
            })),
            "hostcall_table": code.hostcall_table,
            "code_hash": code.code_hash,
        },
        "memory": {
            "text": {
                "start": code.text_start,
                "len": code.text_len,
                "permission": code.text_permission,
            },
            "rodata": {
                "start": code.rodata_start,
                "len": code.rodata_len,
                "permission": code.rodata_permission,
            },
        },
        "hostcall_count": code.hostcalls.len(),
        "trap_metadata_count": code.trap_metadata.len(),
        "address_map_count": code.address_map.len(),
        "simd_requirement": {
            "uses_simd": code.simd_requirement.uses_simd,
            "declared": code.simd_requirement.declared,
            "required_abi": code.simd_requirement.required_abi,
            "min_vector_register_count": code.simd_requirement.min_vector_register_count,
            "min_vector_register_bits": code.simd_requirement.min_vector_register_bits,
            "target_feature_set": code.simd_requirement.target_feature_set.as_ref().map(|feature| serde_json::json!({
                "kind": feature.kind,
                "id": feature.id,
                "generation": feature.generation,
            })),
            "status": code.simd_requirement.status,
            "note": code.simd_requirement.note,
        },
        "last_transition": serde_json::Value::Null,
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn activation_view_v1(activation: &ActivationRecordManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "activation",
        "id": activation.id,
        "generation": activation.generation,
        "state": activation.state,
        "owner": {
            "store": activation.store,
            "store_generation": activation.store_generation,
            "profile": activation.profile,
        },
        "references": {
            "code_object": {
                "id": activation.code_object,
                "generation": activation.code_generation,
            },
            "artifact": {
                "id": activation.artifact,
                "generation": 1,
            },
            "blocked_wait": activation.blocked_wait,
            "trap": activation.trap,
        },
        "entry": activation.entry,
        "start_event": activation.start_event,
        "exit_event": activation.exit_event,
        "last_transition": {
            "active_dmw_leases": activation.active_dmw_leases,
            "return_tag": activation.return_tag,
        },
        "last_error": activation.trap,
    })
}

pub(crate) fn trap_view_v1(trap: &TrapRecordManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "trap",
        "id": trap.id,
        "generation": trap.generation,
        "state": "recorded",
        "owner": {
            "store": trap.store,
            "store_generation": trap.store_generation,
            "activation": trap.activation,
            "activation_generation": trap.activation_generation,
        },
        "references": {
            "code_object": trap.code_object.map(|id| serde_json::json!({
                "id": id,
                "generation": trap.code_generation,
            })),
            "artifact": trap.artifact.map(|id| serde_json::json!({
                "id": id,
                "generation": trap.artifact_generation,
            })),
            "hostcall": trap.hostcall,
        },
        "trap_class": trap.class,
        "offset": trap.offset,
        "target_pc": trap.target_pc,
        "trap_kind": trap.trap_kind,
        "function_index": trap.function_index,
        "wasm_offset": trap.wasm_offset,
        "debug_symbol": trap.debug_symbol,
        "classification_status": trap.classification_status,
        "attribution_status": trap.attribution_status,
        "attribution": {
            "status": trap.attribution_status,
            "target_pc": trap.target_pc,
            "code_offset": trap.offset,
            "trap_kind": trap.trap_kind,
        },
        "simd_attribution": trap.simd_attribution.as_ref().map(|attribution| serde_json::json!({
            "classification": attribution.classification,
            "required_abi": attribution.required_abi,
            "min_vector_register_count": attribution.min_vector_register_count,
            "min_vector_register_bits": attribution.min_vector_register_bits,
            "target_feature_set": attribution.target_feature_set.as_ref().map(|feature| serde_json::json!({
                "kind": feature.kind,
                "id": feature.id,
                "generation": feature.generation,
            })),
            "code_requirement_status": attribution.code_requirement_status,
            "note": attribution.note,
        })),
        "detail": trap.detail,
        "last_transition": {
            "fault_policy": trap.fault_policy,
            "effect": trap.effect,
        },
        "last_error": trap.detail,
    })
}

pub(crate) fn hostcall_trace_view_v1(hostcall: &HostcallTraceManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "hostcall",
        "id": hostcall.id,
        "generation": hostcall.generation,
        "state": hostcall.result,
        "owner": {
            "activation": hostcall.activation,
            "activation_generation": hostcall.activation_generation,
            "store": hostcall.store,
            "store_generation": hostcall.store_generation,
        },
        "references": {
            "code_object": {
                "id": hostcall.code_object,
                "generation": hostcall.code_generation,
            },
            "artifact": {
                "id": hostcall.artifact,
                "generation": hostcall.artifact_generation,
            },
            "trap_out": hostcall.trap_out,
            "trap_generation_out": hostcall.trap_generation_out,
            "wait_token_out": hostcall.wait_token_out,
            "wait_token_generation_out": hostcall.wait_token_generation_out,
        },
        "abi": {
            "version": hostcall.abi_version,
            "frame_size": hostcall.frame_size,
            "flags": hostcall.flags,
        },
        "call": {
            "number": hostcall.hostcall_number,
            "sequence": hostcall.hostcall_seq,
            "caller_offset": hostcall.caller_offset,
            "name": hostcall.name,
            "category": hostcall.category,
            "subject": hostcall.subject,
            "subject_source": hostcall.subject_source,
            "object": hostcall.object,
            "operation": hostcall.operation,
            "record_mode": hostcall.record_mode,
        },
        "gate": {
            "subject_source": hostcall.subject_source,
            "status": hostcall.gate_status,
            "allowed": hostcall.allowed,
            "denial_reason": hostcall.denial_reason,
            "capability_handle_count": hostcall.cap_args.len(),
        },
        "args": hostcall.args,
        "cap_args": hostcall.cap_args,
        "return": {
            "tag": hostcall.ret_tag,
            "ret0": hostcall.ret0,
            "ret1": hostcall.ret1,
        },
        "last_transition": {
            "allowed": hostcall.allowed,
        },
        "last_error": if hostcall.allowed {
            serde_json::Value::Null
        } else {
            serde_json::json!(hostcall.denial_reason.as_deref().unwrap_or(&hostcall.result))
        },
    })
}

pub(crate) fn store_view_v1(store: &StoreRecordManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "store",
        "id": store.id,
        "generation": store.generation,
        "state": store.state,
        "owner": {
            "package": store.package,
            "role": store.role,
            "profile": store.owner_profile,
        },
        "references": {
            "artifact": store.artifact,
            "fault_domain": store.fault_domain,
            "resource": store.resource,
        },
        "last_transition": {
            "restart_count": store.restart_count,
            "fault_policy": store.fault_policy,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn capability_view_v1(capability: &CapabilityRecordManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "capability",
        "id": capability.id,
        "generation": capability.generation,
        "state": if capability.revoked { "revoked" } else { "active" },
        "subject": capability.subject,
        "owner": {
            "store": capability.owner_store,
            "store_generation": capability.owner_store_generation,
            "task": capability.owner_task,
        },
        "references": {
            "object_ref": capability.object_ref,
            "debug_object_label": if capability.debug_object_label.is_empty() {
                &capability.object
            } else {
                &capability.debug_object_label
            },
            "parent": capability.parent,
            "manifest_decl": capability.manifest_decl,
        },
        "rights": capability.rights,
        "class": display_capability_class(&capability.class, &capability.object),
        "lifetime": capability.lifetime,
        "last_transition": {
            "source": capability.source,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn wait_view_v1(wait: &WaitRecordManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "wait",
        "id": wait.id,
        "generation": wait.generation,
        "state": wait.state,
        "owner": {
            "task": wait.owner_task,
            "task_generation": wait.owner_task_generation,
            "store": wait.owner_store,
            "store_generation": wait.owner_store_generation,
        },
        "references": {
            "blockers": wait.blockers,
        },
        "kind_name": wait.kind,
        "deadline": wait.deadline,
        "cancel_reason": wait.cancel_reason,
        "restart_policy": wait.restart_policy,
        "saved_context": wait.saved_context,
        "last_transition": serde_json::Value::Null,
        "last_error": wait.cancel_reason,
    })
}

pub(crate) fn cleanup_view_v1(cleanup: &CleanupTransactionManifest) -> serde_json::Value {
    let target_generation = if cleanup.target_store_generation == 0 {
        cleanup.store_generation
    } else {
        cleanup.target_store_generation
    };
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "cleanup",
        "id": cleanup.id,
        "generation": cleanup.generation,
        "state": cleanup.state,
        "owner": {
            "store": cleanup.store,
        },
        "references": {
            "target_store": {
                "id": cleanup.store,
                "generation": target_generation,
            },
            "result_store": {
                "id": cleanup.store,
                "generation": cleanup.result_store_generation,
            },
            "activation": cleanup.activation.map(|id| serde_json::json!({
                "id": id,
                "generation": cleanup.activation_generation,
            })),
            "code": cleanup.code_object.map(|id| serde_json::json!({
                "id": id,
                "generation": cleanup.code_generation,
            })),
            "revoked_capabilities": cleanup.revoked_capability_refs,
        },
        "started_at": cleanup.started_at,
        "finished_at": cleanup.finished_at,
        "reason": cleanup.reason,
        "steps": cleanup.steps,
        "effects": cleanup.effects,
        "idempotence": {
            "state_digest": cleanup.state_digest,
            "state_digest_present": !cleanup.state_digest.is_empty(),
        },
        "last_transition": {
            "released_dmw_leases": cleanup.released_dmw_leases,
            "cancelled_waits": cleanup.cancelled_waits,
            "dropped_resources": cleanup.dropped_resources,
            "unbound_code_object": cleanup.unbound_code_object,
        },
        "last_error": if cleanup.state.contains("skipped") {
            Some("stale-generation")
        } else {
            None
        },
    })
}

pub(crate) fn framebuffer_benchmark_view_v1(
    benchmark: &FramebufferBenchmarkManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "framebuffer-benchmark",
        "id": benchmark.id,
        "generation": benchmark.generation,
        "state": benchmark.state,
        "owner": {
            "store": object_ref_json(
                "store",
                benchmark.owner_store,
                benchmark.owner_store_generation,
            ),
            "display": object_ref_json(
                "display-object",
                benchmark.display,
                benchmark.display_generation,
            ),
            "framebuffer": object_ref_json(
                "framebuffer-object",
                benchmark.framebuffer,
                benchmark.framebuffer_generation,
            ),
        },
        "references": {
            "display_capability": object_ref_json(
                "display-capability",
                benchmark.display_capability,
                benchmark.display_capability_generation,
            ),
            "framebuffer_write": object_ref_json(
                "framebuffer-write",
                benchmark.framebuffer_write,
                benchmark.framebuffer_write_generation,
            ),
            "framebuffer_flush_region": object_ref_json(
                "framebuffer-flush-region",
                benchmark.framebuffer_flush_region,
                benchmark.framebuffer_flush_region_generation,
            ),
            "display_event_log": object_ref_json(
                "display-event-log",
                benchmark.display_event_log,
                benchmark.display_event_log_generation,
            ),
            "display_snapshot_barrier": object_ref_json(
                "display-snapshot-barrier",
                benchmark.display_snapshot_barrier,
                benchmark.display_snapshot_barrier_generation,
            ),
            "event": {
                "id": benchmark.recorded_at_event,
            },
        },
        "benchmark": {
            "scenario": benchmark.scenario,
            "sample_frames": benchmark.sample_frames,
            "sample_bytes": benchmark.sample_bytes,
            "frame_area_pixels": benchmark.frame_area_pixels,
            "write_nanos": benchmark.write_nanos,
            "flush_nanos": benchmark.flush_nanos,
            "measured_nanos": benchmark.measured_nanos,
            "budget_nanos": benchmark.budget_nanos,
            "throughput_bytes_per_sec": benchmark.throughput_bytes_per_sec,
            "flushes_per_sec_milli": benchmark.flushes_per_sec_milli,
            "p50_latency_nanos": benchmark.p50_latency_nanos,
            "p99_latency_nanos": benchmark.p99_latency_nanos,
        },
        "authority": {
            "real_scanout_measured": false,
            "real_gpu_pipeline_measured": false,
            "uses_semantic_write_flush_evidence": true,
            "requires_quiescent_snapshot_barrier": true,
        },
        "note": benchmark.note,
        "last_transition": {
            "recorded_at_event": benchmark.recorded_at_event,
            "owner_store_generation": benchmark.owner_store_generation,
            "display_generation": benchmark.display_generation,
            "framebuffer_generation": benchmark.framebuffer_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn stable_views_for_kind(
    kind: &str,
    package: &MigrationPackageManifest,
) -> Result<Vec<serde_json::Value>, Box<dyn Error>> {
    match kind {
        "hart" => Ok(package.semantic.hart_records.iter().map(hart_view_v1).collect()),
        "task" => Ok(package.semantic.task_records.iter().map(task_view_v1).collect()),
        "artifact" | "target-artifact" | "target-artifact-image" => {
            Ok(package.semantic.target_artifacts.iter().map(artifact_view_v1).collect())
        }
        "code-object" | "target-code-object" => {
            Ok(package.semantic.code_objects.iter().map(code_object_view_v1).collect())
        }
        "activation-record" | "target-activation" | "target-activation-record" => {
            Ok(package.semantic.activation_records.iter().map(activation_view_v1).collect())
        }
        "trap" | "trap-record" => {
            Ok(package.semantic.trap_records.iter().map(trap_view_v1).collect())
        }
        "hostcall" | "hostcall-trace" => {
            Ok(package.semantic.hostcall_trace.iter().map(hostcall_trace_view_v1).collect())
        }
        "activation" | "runtime-activation" => Ok(package
            .semantic
            .runtime_activation_records
            .iter()
            .map(runtime_activation_view_v1)
            .collect()),
        "scheduler" => Ok(vec![scheduler_view_v1(package)]),
        "runnable-queue" => {
            Ok(package.semantic.runnable_queues.iter().map(runnable_queue_view_v1).collect())
        }
        "activation-context" | "context" => Ok(package
            .semantic
            .activation_contexts
            .iter()
            .map(activation_context_view_v1)
            .collect()),
        "saved-context" => {
            Ok(package.semantic.saved_contexts.iter().map(saved_context_view_v1).collect())
        }
        "timer-interrupt" => {
            Ok(package.semantic.timer_interrupts.iter().map(timer_interrupt_view_v1).collect())
        }
        "ipi" | "ipi-event" => {
            Ok(package.semantic.ipi_events.iter().map(ipi_event_view_v1).collect())
        }
        "remote-preempt" => {
            Ok(package.semantic.remote_preempts.iter().map(remote_preempt_view_v1).collect())
        }
        "remote-park" => {
            Ok(package.semantic.remote_parks.iter().map(remote_park_view_v1).collect())
        }
        "preemption" => Ok(package.semantic.preemptions.iter().map(preemption_view_v1).collect()),
        "scheduler-decision" => Ok(package
            .semantic
            .scheduler_decisions
            .iter()
            .map(scheduler_decision_view_v1)
            .collect()),
        "cross-hart-scheduler-decision" => Ok(package
            .semantic
            .cross_hart_scheduler_decisions
            .iter()
            .map(cross_hart_scheduler_decision_view_v1)
            .collect()),
        "activation-migration" => Ok(package
            .semantic
            .activation_migrations
            .iter()
            .map(activation_migration_view_v1)
            .collect()),
        "smp-safe-point" | "safepoint" => {
            Ok(package.semantic.smp_safe_points.iter().map(smp_safe_point_view_v1).collect())
        }
        "stop-the-world-rendezvous" | "stop-the-world" | "stw" => Ok(package
            .semantic
            .stop_the_world_rendezvous
            .iter()
            .map(stop_the_world_rendezvous_view_v1)
            .collect()),
        "smp-code-publish-barrier" | "code-publish-barrier" | "publish-barrier" => Ok(package
            .semantic
            .smp_code_publish_barriers
            .iter()
            .map(smp_code_publish_barrier_view_v1)
            .collect()),
        "smp-cleanup-quiescence" | "cleanup-quiescence" => Ok(package
            .semantic
            .smp_cleanup_quiescence
            .iter()
            .map(smp_cleanup_quiescence_view_v1)
            .collect()),
        "smp-snapshot-barrier" | "snapshot-barrier" => Ok(package
            .semantic
            .smp_snapshot_barriers
            .iter()
            .map(smp_snapshot_barrier_view_v1)
            .collect()),
        "smp-stress-run" | "smp-stress" => {
            Ok(package.semantic.smp_stress_runs.iter().map(smp_stress_run_view_v1).collect())
        }
        "smp-scaling-benchmark" | "smp-scaling" => Ok(package
            .semantic
            .smp_scaling_benchmarks
            .iter()
            .map(smp_scaling_benchmark_view_v1)
            .collect()),
        "integrated-smp-preemption-cleanup"
        | "integrated-smp-cleanup"
        | "smp-preemption-cleanup" => Ok(package
            .semantic
            .integrated_smp_preemption_cleanups
            .iter()
            .map(integrated_smp_preemption_cleanup_view_v1)
            .collect()),
        "integrated-smp-network-fault" | "smp-network-fault" | "integrated-network-fault" => {
            Ok(package
                .semantic
                .integrated_smp_network_faults
                .iter()
                .map(integrated_smp_network_fault_view_v1)
                .collect())
        }
        "integrated-disk-preempt-fault"
        | "disk-preempt-fault"
        | "integrated-block-preempt-fault" => Ok(package
            .semantic
            .integrated_disk_preempt_faults
            .iter()
            .map(integrated_disk_preempt_fault_view_v1)
            .collect()),
        "integrated-simd-migration" | "simd-migration" | "integrated-vector-migration" => {
            Ok(package
                .semantic
                .integrated_simd_migrations
                .iter()
                .map(integrated_simd_migration_view_v1)
                .collect())
        }
        "integrated-network-disk-io" | "network-disk-io" | "integrated-io-concurrency" => {
            Ok(package
                .semantic
                .integrated_network_disk_ios
                .iter()
                .map(integrated_network_disk_io_view_v1)
                .collect())
        }
        "integrated-display-scheduler-load"
        | "display-scheduler-load"
        | "integrated-display-load" => Ok(package
            .semantic
            .integrated_display_scheduler_loads
            .iter()
            .map(integrated_display_scheduler_load_view_v1)
            .collect()),
        "integrated-snapshot-io-lease-barrier"
        | "snapshot-io-lease-barrier"
        | "snapshot-io-barrier" => Ok(package
            .semantic
            .integrated_snapshot_io_lease_barriers
            .iter()
            .map(integrated_snapshot_io_lease_barrier_view_v1)
            .collect()),
        "integrated-code-publish-smp-workload"
        | "code-publish-smp-workload"
        | "integrated-code-publish-workload" => Ok(package
            .semantic
            .integrated_code_publish_smp_workloads
            .iter()
            .map(integrated_code_publish_smp_workload_view_v1)
            .collect()),
        "integrated-display-panic" | "display-panic" | "panic-ring-extraction" => Ok(package
            .semantic
            .integrated_display_panics
            .iter()
            .map(integrated_display_panic_view_v1)
            .collect()),
        "integrated-osctl-trace-replay" | "osctl-trace-replay" | "full-osctl-trace-replay" => {
            Ok(package
                .semantic
                .integrated_osctl_trace_replays
                .iter()
                .map(integrated_osctl_trace_replay_view_v1)
                .collect())
        }
        "device" | "device-object" => {
            Ok(package.semantic.device_objects.iter().map(device_object_view_v1).collect())
        }
        "queue" | "queue-object" => {
            Ok(package.semantic.queue_objects.iter().map(queue_object_view_v1).collect())
        }
        "descriptor" | "descriptor-object" => {
            Ok(package.semantic.descriptor_objects.iter().map(descriptor_object_view_v1).collect())
        }
        "dma-buffer" | "dma-buffer-object" => {
            Ok(package.semantic.dma_buffer_objects.iter().map(dma_buffer_object_view_v1).collect())
        }
        "mmio-region" | "mmio-region-object" => Ok(package
            .semantic
            .mmio_region_objects
            .iter()
            .map(mmio_region_object_view_v1)
            .collect()),
        "irq-line" | "irq-line-object" => {
            Ok(package.semantic.irq_line_objects.iter().map(irq_line_object_view_v1).collect())
        }
        "irq-event" => Ok(package.semantic.irq_events.iter().map(irq_event_view_v1).collect()),
        "device-capability" | "io-capability" => {
            Ok(package.semantic.device_capabilities.iter().map(device_capability_view_v1).collect())
        }
        "driver-store-binding" | "driver-binding" => Ok(package
            .semantic
            .driver_store_bindings
            .iter()
            .map(driver_store_binding_view_v1)
            .collect()),
        "io-wait" | "io-wait-token" => {
            Ok(package.semantic.io_waits.iter().map(io_wait_view_v1).collect())
        }
        "io-cleanup" => Ok(package.semantic.io_cleanups.iter().map(io_cleanup_view_v1).collect()),
        "io-fault" | "io-fault-injection" => Ok(package
            .semantic
            .io_fault_injections
            .iter()
            .map(io_fault_injection_view_v1)
            .collect()),
        "io-validation" | "io-validation-report" | "io-validator" => Ok(package
            .semantic
            .io_validation_reports
            .iter()
            .map(io_validation_report_view_v1)
            .collect()),
        "packet-device" | "packet-device-object" | "net-device" => Ok(package
            .semantic
            .packet_device_objects
            .iter()
            .map(packet_device_object_view_v1)
            .collect()),
        "packet-buffer" | "packet-buffer-object" => Ok(package
            .semantic
            .packet_buffer_objects
            .iter()
            .map(packet_buffer_object_view_v1)
            .collect()),
        "packet-queue" | "packet-queue-object" | "rx-queue" | "tx-queue" => Ok(package
            .semantic
            .packet_queue_objects
            .iter()
            .map(packet_queue_object_view_v1)
            .collect()),
        "packet-descriptor" | "packet-descriptor-object" => Ok(package
            .semantic
            .packet_descriptors
            .iter()
            .map(packet_descriptor_object_view_v1)
            .collect()),
        "fake-net-backend" | "fake-net-backend-object" => Ok(package
            .semantic
            .fake_net_backends
            .iter()
            .map(fake_net_backend_object_view_v1)
            .collect()),
        "virtio-net-backend" | "virtio-net-backend-object" => Ok(package
            .semantic
            .virtio_net_backends
            .iter()
            .map(virtio_net_backend_object_view_v1)
            .collect()),
        "network-rx-interrupt" | "rx-interrupt" => Ok(package
            .semantic
            .network_rx_interrupts
            .iter()
            .map(network_rx_interrupt_view_v1)
            .collect()),
        "network-rx-wait-resolution" | "rx-wait-resolution" => Ok(package
            .semantic
            .network_rx_wait_resolutions
            .iter()
            .map(network_rx_wait_resolution_view_v1)
            .collect()),
        "network-tx-capability-gate" | "tx-capability-gate" => Ok(package
            .semantic
            .network_tx_capability_gates
            .iter()
            .map(network_tx_capability_gate_view_v1)
            .collect()),
        "network-tx-completion" | "tx-completion" => Ok(package
            .semantic
            .network_tx_completions
            .iter()
            .map(network_tx_completion_view_v1)
            .collect()),
        "network-stack-adapter" | "smoltcp-adapter" => Ok(package
            .semantic
            .network_stack_adapters
            .iter()
            .map(network_stack_adapter_view_v1)
            .collect()),
        "socket-object" | "socket" => {
            Ok(package.semantic.socket_objects.iter().map(socket_object_view_v1).collect())
        }
        "endpoint-object" | "endpoint" => {
            Ok(package.semantic.endpoint_objects.iter().map(endpoint_object_view_v1).collect())
        }
        "socket-operation" | "socket-op" => {
            Ok(package.semantic.socket_operations.iter().map(socket_operation_view_v1).collect())
        }
        "socket-wait" | "socket-wait-token" => {
            Ok(package.semantic.socket_waits.iter().map(socket_wait_view_v1).collect())
        }
        "network-backpressure" | "backpressure" | "drop-policy" => Ok(package
            .semantic
            .network_backpressures
            .iter()
            .map(network_backpressure_view_v1)
            .collect()),
        "network-driver-cleanup" | "network-cleanup" => Ok(package
            .semantic
            .network_driver_cleanups
            .iter()
            .map(network_driver_cleanup_view_v1)
            .collect()),
        "network-generation-audit" | "generation-audit" | "stale-generation-audit" => Ok(package
            .semantic
            .network_generation_audits
            .iter()
            .map(network_generation_audit_view_v1)
            .collect()),
        "network-fault-injection" | "packet-loss" | "packet-error" => Ok(package
            .semantic
            .network_fault_injections
            .iter()
            .map(network_fault_injection_view_v1)
            .collect()),
        "network-benchmark" | "network-throughput" | "network-latency" => {
            Ok(package.semantic.network_benchmarks.iter().map(network_benchmark_view_v1).collect())
        }
        "network-recovery-benchmark" | "network-recovery" => Ok(package
            .semantic
            .network_recovery_benchmarks
            .iter()
            .map(network_recovery_benchmark_view_v1)
            .collect()),
        "block-device" | "block-device-object" | "block" => Ok(package
            .semantic
            .block_device_objects
            .iter()
            .map(block_device_object_view_v1)
            .collect()),
        "block-range" | "block-range-object" | "sector-range" => Ok(package
            .semantic
            .block_range_objects
            .iter()
            .map(block_range_object_view_v1)
            .collect()),
        "block-request" | "block-request-object" => Ok(package
            .semantic
            .block_request_objects
            .iter()
            .map(block_request_object_view_v1)
            .collect()),
        "block-completion" | "block-completion-object" => Ok(package
            .semantic
            .block_completion_objects
            .iter()
            .map(block_completion_object_view_v1)
            .collect()),
        "block-wait" | "block-wait-token" => {
            Ok(package.semantic.block_waits.iter().map(block_wait_view_v1).collect())
        }
        "fake-block-backend" | "fake-block-backend-object" => Ok(package
            .semantic
            .fake_block_backends
            .iter()
            .map(fake_block_backend_object_view_v1)
            .collect()),
        "virtio-blk-backend" | "virtio-blk-backend-object" => Ok(package
            .semantic
            .virtio_blk_backends
            .iter()
            .map(virtio_blk_backend_object_view_v1)
            .collect()),
        "block-read-path" | "block-read" => {
            Ok(package.semantic.block_read_paths.iter().map(block_read_path_view_v1).collect())
        }
        "block-write-path" | "block-write" => {
            Ok(package.semantic.block_write_paths.iter().map(block_write_path_view_v1).collect())
        }
        "block-request-queue" | "block-queue" => Ok(package
            .semantic
            .block_request_queues
            .iter()
            .map(block_request_queue_view_v1)
            .collect()),
        "block-dma-buffer" | "block-buffer" => {
            Ok(package.semantic.block_dma_buffers.iter().map(block_dma_buffer_view_v1).collect())
        }
        "block-page-object" | "block-page" => {
            Ok(package.semantic.block_page_objects.iter().map(block_page_object_view_v1).collect())
        }
        "guest-address-space" | "guest-aspace" | "address-space" => Ok(package
            .semantic
            .guest_address_spaces
            .iter()
            .map(guest_address_space_view_v1)
            .collect()),
        "vma-region" | "vma" => {
            Ok(package.semantic.vma_regions.iter().map(vma_region_view_v1).collect())
        }
        "page-object" | "guest-page" => {
            Ok(package.semantic.page_objects.iter().map(page_object_view_v1).collect())
        }
        "guest-memory-fault" | "page-fault-event" | "page-fault" => Ok(package
            .semantic
            .guest_memory_faults
            .iter()
            .map(guest_memory_fault_view_v1)
            .collect()),
        "buffer-cache-object" | "buffer-cache" | "fs-cache" => Ok(package
            .semantic
            .buffer_cache_objects
            .iter()
            .map(buffer_cache_object_view_v1)
            .collect()),
        "file-object" | "file" => {
            Ok(package.semantic.file_objects.iter().map(file_object_view_v1).collect())
        }
        "directory-object" | "directory" => {
            Ok(package.semantic.directory_objects.iter().map(directory_object_view_v1).collect())
        }
        "fat-adapter-object" | "fat-adapter" => Ok(package
            .semantic
            .fat_adapter_objects
            .iter()
            .map(fat_adapter_object_view_v1)
            .collect()),
        "ext4-adapter-object" | "ext4-adapter" => Ok(package
            .semantic
            .ext4_adapter_objects
            .iter()
            .map(ext4_adapter_object_view_v1)
            .collect()),
        "file-handle-capability" | "file-handle" | "file-capability" => Ok(package
            .semantic
            .file_handle_capabilities
            .iter()
            .map(file_handle_capability_view_v1)
            .collect()),
        "fs-wait" | "filesystem-wait" | "file-wait" => {
            Ok(package.semantic.fs_waits.iter().map(fs_wait_view_v1).collect())
        }
        "block-driver-cleanup" | "disk-driver-cleanup" | "disk-cleanup" => Ok(package
            .semantic
            .block_driver_cleanups
            .iter()
            .map(block_driver_cleanup_view_v1)
            .collect()),
        "block-pending-io-policy" | "pending-block-io" | "pending-io-policy" => Ok(package
            .semantic
            .block_pending_io_policies
            .iter()
            .map(block_pending_io_policy_view_v1)
            .collect()),
        "block-request-generation-audit"
        | "stale-block-request-generation"
        | "block-generation-audit" => Ok(package
            .semantic
            .block_request_generation_audits
            .iter()
            .map(block_request_generation_audit_view_v1)
            .collect()),
        "block-benchmark" | "disk-benchmark" | "block-iops" => {
            Ok(package.semantic.block_benchmarks.iter().map(block_benchmark_view_v1).collect())
        }
        "block-recovery-benchmark" | "disk-recovery-benchmark" | "disk-recovery" => Ok(package
            .semantic
            .block_recovery_benchmarks
            .iter()
            .map(block_recovery_benchmark_view_v1)
            .collect()),
        "target-feature-set" | "target-feature" | "target-feature-set-object" => Ok(package
            .semantic
            .target_feature_sets
            .iter()
            .map(target_feature_set_view_v1)
            .collect()),
        "vector-state" | "vector" | "simd-vector-state" => {
            Ok(package.semantic.vector_states.iter().map(vector_state_view_v1).collect())
        }
        "simd-fault-injection" | "simd-fault" => Ok(package
            .semantic
            .simd_fault_injections
            .iter()
            .map(simd_fault_injection_view_v1)
            .collect()),
        "simd-benchmark" | "simd-scalar-vector-benchmark" => {
            Ok(package.semantic.simd_benchmarks.iter().map(simd_benchmark_view_v1).collect())
        }
        "simd-context-switch-benchmark" | "simd-context-switch" | "simd-switch-benchmark" => {
            Ok(package
                .semantic
                .simd_context_switch_benchmarks
                .iter()
                .map(simd_context_switch_benchmark_view_v1)
                .collect())
        }
        "framebuffer-object" | "framebuffer" | "fb" => Ok(package
            .semantic
            .framebuffer_objects
            .iter()
            .map(framebuffer_object_view_v1)
            .collect()),
        "display-object" | "display" | "display-mode" => {
            Ok(package.semantic.display_objects.iter().map(display_object_view_v1).collect())
        }
        "display-capability" | "display-cap" => Ok(package
            .semantic
            .display_capabilities
            .iter()
            .map(display_capability_view_v1)
            .collect()),
        "framebuffer-window-lease" | "fb-window-lease" | "display-lease" => Ok(package
            .semantic
            .framebuffer_window_leases
            .iter()
            .map(framebuffer_window_lease_view_v1)
            .collect()),
        "framebuffer-mapping" | "fb-mapping" | "display-mapping" => Ok(package
            .semantic
            .framebuffer_mappings
            .iter()
            .map(framebuffer_mapping_view_v1)
            .collect()),
        "framebuffer-write" | "fb-write" | "display-write" => {
            Ok(package.semantic.framebuffer_writes.iter().map(framebuffer_write_view_v1).collect())
        }
        "framebuffer-flush-region" | "flush-region" | "display-flush" => Ok(package
            .semantic
            .framebuffer_flush_regions
            .iter()
            .map(framebuffer_flush_region_view_v1)
            .collect()),
        "framebuffer-dirty-region" | "dirty-region" | "display-dirty" => Ok(package
            .semantic
            .framebuffer_dirty_regions
            .iter()
            .map(framebuffer_dirty_region_view_v1)
            .collect()),
        "display-event-log" | "display-log" => {
            Ok(package.semantic.display_event_logs.iter().map(display_event_log_view_v1).collect())
        }
        "display-cleanup" => {
            Ok(package.semantic.display_cleanups.iter().map(display_cleanup_view_v1).collect())
        }
        "display-snapshot-barrier" | "display-snapshot" => Ok(package
            .semantic
            .display_snapshot_barriers
            .iter()
            .map(display_snapshot_barrier_view_v1)
            .collect()),
        "display-panic-last-frame" | "panic-last-frame" => Ok(package
            .semantic
            .display_panic_last_frames
            .iter()
            .map(display_panic_last_frame_view_v1)
            .collect()),
        "framebuffer-benchmark" | "fb-benchmark" | "display-benchmark" => Ok(package
            .semantic
            .framebuffer_benchmarks
            .iter()
            .map(framebuffer_benchmark_view_v1)
            .collect()),
        "activation-resume" => {
            Ok(package.semantic.activation_resumes.iter().map(activation_resume_view_v1).collect())
        }
        "activation-wait" => {
            Ok(package.semantic.activation_waits.iter().map(activation_wait_view_v1).collect())
        }
        "activation-cleanup" => Ok(package
            .semantic
            .activation_cleanups
            .iter()
            .map(activation_cleanup_view_v1)
            .collect()),
        "preemption-latency" => Ok(package
            .semantic
            .preemption_latency_samples
            .iter()
            .map(preemption_latency_view_v1)
            .collect()),
        "hart-event" | "hart-event-attribution" => Ok(package
            .semantic
            .hart_event_attributions
            .iter()
            .map(hart_event_attribution_view_v1)
            .collect()),
        "store" => Ok(package.semantic.store_records.iter().map(store_view_v1).collect()),
        "cap" | "capability" => {
            Ok(package.semantic.capability_records.iter().map(capability_view_v1).collect())
        }
        "wait" => Ok(package.semantic.wait_records.iter().map(wait_view_v1).collect()),
        "cleanup" => {
            Ok(package.semantic.cleanup_transactions.iter().map(cleanup_view_v1).collect())
        }
        "command" => {
            Ok(package.semantic.command_results.iter().map(command_result_view_v1).collect())
        }
        _ => Err(format!("stable view does not support `{kind}`").into()),
    }
}
