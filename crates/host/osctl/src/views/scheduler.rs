use super::super::*;
pub(crate) fn hart_view_v1(hart: &HartRecordManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "hart",
        "id": hart.id,
        "generation": hart.generation,
        "state": hart.state,
        "owner": {
            "hardware_id": hart.hardware_id,
            "boot": hart.boot,
        },
        "references": {
            "scheduler": {
                "id": 1,
                "generation": 1,
            },
            "current_activation": hart.current_activation.map(|id| serde_json::json!({
                "id": id,
                "generation": hart.current_activation_generation,
            })),
            "current_task": hart.current_task.map(|id| serde_json::json!({
                "id": id,
                "generation": hart.current_task_generation,
            })),
            "current_store": hart.current_store.map(|id| serde_json::json!({
                "id": id,
                "generation": hart.current_store_generation,
            })),
        },
        "label": hart.label,
        "note": hart.note,
        "last_transition": {
            "last_event": hart.last_event,
            "last_current_event": hart.last_current_event,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn task_view_v1(task: &TaskRecordManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "task",
        "id": task.id,
        "generation": task.generation,
        "state": task.state,
        "owner": {
            "frontend": task.frontend,
        },
        "references": {
            "fault_domain": task.fault_domain,
            "pending_wait": task.pending_wait,
            "resources": task.resources,
        },
        "label": task.label,
        "last_transition": serde_json::Value::Null,
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn runtime_activation_view_v1(
    activation: &RuntimeActivationRecordManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "activation",
        "id": activation.id,
        "generation": activation.generation,
        "state": activation.state,
        "owner": {
            "task": activation.owner_task,
            "task_generation": activation.owner_task_generation,
            "store": activation.owner_store,
            "store_generation": activation.owner_store_generation,
        },
        "references": {
            "code_object": activation.code_object,
            "runnable_queue": activation.runnable_queue.map(|id| serde_json::json!({
                "id": id,
                "generation": activation.runnable_queue_generation,
            })),
        },
        "last_transition": {
            "last_event": activation.last_event,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn runnable_queue_view_v1(queue: &RunnableQueueManifest) -> serde_json::Value {
    let owner_hart = match (queue.owner_hart, queue.owner_hart_generation) {
        (Some(id), Some(generation)) => serde_json::json!({
            "kind": "hart",
            "id": id,
            "generation": generation,
        }),
        _ => serde_json::Value::Null,
    };
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "runnable-queue",
        "id": queue.id,
        "generation": queue.generation,
        "state": queue.state,
        "owner": {
            "hart": owner_hart,
        },
        "references": {
            "entries": queue.entries.iter().map(|entry| serde_json::json!({
                "activation": {
                    "id": entry.activation,
                    "generation": entry.activation_generation,
                },
                "enqueued_at": entry.enqueued_at,
            })).collect::<Vec<_>>(),
        },
        "label": queue.label,
        "last_transition": {
            "entry_count": queue.entries.len(),
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn activation_context_view_v1(context: &ActivationContextManifest) -> serde_json::Value {
    let vector_status =
        if context.vector_status.is_empty() { "absent" } else { context.vector_status.as_str() };
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "activation-context",
        "id": context.id,
        "generation": context.generation,
        "state": context.state,
        "owner": {
            "task": context.owner_task,
            "task_generation": context.owner_task_generation,
            "store": context.owner_store,
            "store_generation": context.owner_store_generation,
        },
        "references": {
            "activation": {
                "id": context.activation,
                "generation": context.activation_generation,
            },
            "current_saved_context": context.current_saved_context.map(|id| serde_json::json!({
                "id": id,
                "generation": context.current_saved_context_generation,
            })),
            "vector_state": context.vector_state.as_ref().map(object_ref_manifest_json),
        },
        "vector_context": {
            "status": vector_status,
            "vector_state": context.vector_state.as_ref().map(object_ref_manifest_json),
            "last_event": context.vector_state_event,
        },
        "last_transition": {
            "last_event": context.last_event,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn saved_context_view_v1(saved: &SavedContextManifest) -> serde_json::Value {
    let vector_status =
        if saved.vector_status.is_empty() { "absent" } else { saved.vector_status.as_str() };
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "saved-context",
        "id": saved.id,
        "generation": saved.generation,
        "state": saved.state,
        "owner": {
            "task": saved.owner_task,
            "task_generation": saved.owner_task_generation,
        },
        "references": {
            "activation_context": {
                "id": saved.context,
                "generation": saved.context_generation,
            },
            "activation": {
                "id": saved.activation,
                "generation": saved.activation_generation,
            },
            "source_preemption": saved.source_preemption.map(|id| serde_json::json!({
                "id": id,
                "generation": saved.source_preemption_generation,
            })),
            "vector_state": saved.vector_state.as_ref().map(object_ref_manifest_json),
        },
        "machine_frame": {
            "pc": saved.pc,
            "sp": saved.sp,
            "flags": saved.flags,
            "integer_registers": saved.integer_registers,
        },
        "vector_context": {
            "status": vector_status,
            "vector_state": saved.vector_state.as_ref().map(object_ref_manifest_json),
            "saved_at_event": saved.vector_saved_at_event,
        },
        "reason": saved.reason,
        "note": saved.note,
        "last_transition": {
            "saved_at_event": saved.saved_at_event,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn timer_interrupt_view_v1(interrupt: &TimerInterruptManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "timer-interrupt",
        "id": interrupt.id,
        "generation": interrupt.generation,
        "state": interrupt.state,
        "owner": {
            "hart": {
                "id": interrupt.hart,
                "generation": interrupt.hart_generation,
                "hardware_id": interrupt.hardware_hart,
            },
            "timer_epoch": interrupt.timer_epoch,
        },
        "references": {
            "activation": interrupt.target_activation.map(|id| serde_json::json!({
                "id": id,
                "generation": interrupt.target_activation_generation,
            })),
            "task": interrupt.target_task.map(|id| serde_json::json!({
                "id": id,
                "generation": interrupt.target_task_generation,
            })),
        },
        "note": interrupt.note,
        "last_transition": {
            "recorded_at_event": interrupt.recorded_at_event,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn ipi_event_view_v1(ipi: &IpiEventManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "ipi-event",
        "id": ipi.id,
        "generation": ipi.generation,
        "state": ipi.state,
        "owner": {
            "source_hart": {
                "id": ipi.source_hart,
                "generation": ipi.source_hart_generation,
                "hardware_id": ipi.source_hardware_hart,
            },
            "target_hart": {
                "id": ipi.target_hart,
                "generation": ipi.target_hart_generation,
                "hardware_id": ipi.target_hardware_hart,
            },
        },
        "references": {
            "source_hart": {
                "id": ipi.source_hart,
                "generation": ipi.source_hart_generation,
                "hardware_id": ipi.source_hardware_hart,
            },
            "target_hart": {
                "id": ipi.target_hart,
                "generation": ipi.target_hart_generation,
                "hardware_id": ipi.target_hardware_hart,
            },
            "event": {
                "id": ipi.recorded_at_event,
            },
        },
        "ipi_kind": ipi.kind,
        "reason": ipi.reason,
        "note": ipi.note,
        "last_transition": {
            "recorded_at_event": ipi.recorded_at_event,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn remote_preempt_view_v1(remote: &RemotePreemptManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "remote-preempt",
        "id": remote.id,
        "generation": remote.generation,
        "state": remote.state,
        "owner": {
            "source_hart": {
                "id": remote.source_hart,
                "generation": remote.source_hart_generation,
            },
            "target_hart": {
                "id": remote.target_hart,
                "generation_before": remote.target_hart_generation_before,
                "generation_after": remote.target_hart_generation_after,
            },
        },
        "references": {
            "ipi": {
                "id": remote.ipi,
                "generation": remote.ipi_generation,
            },
            "activation": {
                "id": remote.activation,
                "generation_before": remote.activation_generation_before,
                "generation_after": remote.activation_generation_after,
            },
            "queue": {
                "id": remote.queue,
                "generation": remote.queue_generation,
            },
            "event": {
                "id": remote.preempted_at_event,
            },
        },
        "note": remote.note,
        "last_transition": {
            "preempted_at_event": remote.preempted_at_event,
            "target_hart_generation_after": remote.target_hart_generation_after,
            "activation_generation_after": remote.activation_generation_after,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn remote_park_view_v1(remote: &RemoteParkManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "remote-park",
        "id": remote.id,
        "generation": remote.generation,
        "state": remote.state,
        "owner": {
            "source_hart": {
                "id": remote.source_hart,
                "generation": remote.source_hart_generation,
            },
            "target_hart": {
                "id": remote.target_hart,
                "generation_before": remote.target_hart_generation_before,
                "generation_after": remote.target_hart_generation_after,
            },
        },
        "references": {
            "ipi": {
                "id": remote.ipi,
                "generation": remote.ipi_generation,
            },
            "event": {
                "id": remote.parked_at_event,
            },
        },
        "reason": remote.reason,
        "note": remote.note,
        "last_transition": {
            "parked_at_event": remote.parked_at_event,
            "target_hart_generation_after": remote.target_hart_generation_after,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn hart_event_attribution_view_v1(
    attribution: &HartEventAttributionManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "hart-event-attribution",
        "id": attribution.id,
        "generation": attribution.generation,
        "state": attribution.state,
        "owner": {
            "hart": {
                "id": attribution.hart,
                "generation": attribution.hart_generation,
                "hardware_id": attribution.hardware_hart,
            },
        },
        "references": {
            "event": {
                "id": attribution.event,
                "source": attribution.event_source,
                "kind": attribution.event_kind,
            },
            "activation": attribution.activation.map(|id| serde_json::json!({
                "id": id,
                "generation": attribution.activation_generation,
            })),
            "task": attribution.task.map(|id| serde_json::json!({
                "id": id,
                "generation": attribution.task_generation,
            })),
            "store": attribution.store.map(|id| serde_json::json!({
                "id": id,
                "generation": attribution.store_generation,
            })),
        },
        "note": attribution.note,
        "last_transition": {
            "event": attribution.event,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn preemption_view_v1(preemption: &PreemptionManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "preemption",
        "id": preemption.id,
        "generation": preemption.generation,
        "state": preemption.state,
        "owner": {
            "scheduler": 1,
        },
        "references": {
            "activation": {
                "id": preemption.activation,
                "generation_before": preemption.activation_generation_before,
                "generation_after": preemption.activation_generation_after,
            },
            "timer_interrupt": {
                "id": preemption.timer_interrupt,
                "generation": preemption.timer_interrupt_generation,
            },
            "queue": {
                "id": preemption.queue,
                "generation": preemption.queue_generation,
            },
        },
        "note": preemption.note,
        "last_transition": {
            "preempted_at_event": preemption.preempted_at_event,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn scheduler_decision_view_v1(
    decision: &SchedulerDecisionManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "scheduler-decision",
        "id": decision.id,
        "generation": decision.generation,
        "state": decision.state,
        "owner": {
            "scheduler": 1,
            "task": decision.owner_task,
            "task_generation": decision.owner_task_generation,
        },
        "references": {
            "queue": {
                "id": decision.queue,
                "generation": decision.queue_generation,
            },
            "selected_activation": {
                "id": decision.selected_activation,
                "generation": decision.selected_activation_generation,
            },
        },
        "reason": decision.reason,
        "note": decision.note,
        "last_transition": {
            "decided_at_event": decision.decided_at_event,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn cross_hart_scheduler_decision_view_v1(
    decision: &CrossHartSchedulerDecisionManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "cross-hart-scheduler-decision",
        "id": decision.id,
        "generation": decision.generation,
        "state": decision.state,
        "owner": {
            "scheduler": 1,
            "deciding_hart": {
                "id": decision.deciding_hart,
                "generation": decision.deciding_hart_generation,
            },
            "target_hart": {
                "id": decision.target_hart,
                "generation": decision.target_hart_generation,
            },
        },
        "references": {
            "scheduler_decision": {
                "id": decision.scheduler_decision,
                "generation": decision.scheduler_decision_generation,
            },
            "queue": {
                "id": decision.queue,
                "generation": decision.queue_generation,
                "owner_hart_generation": decision.queue_owner_hart_generation,
            },
            "selected_activation": {
                "id": decision.selected_activation,
                "generation": decision.selected_activation_generation,
            },
            "event": {
                "id": decision.decided_at_event,
            },
        },
        "reason": decision.reason,
        "note": decision.note,
        "last_transition": {
            "decided_at_event": decision.decided_at_event,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn activation_migration_view_v1(
    migration: &ActivationMigrationManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "activation-migration",
        "id": migration.id,
        "generation": migration.generation,
        "state": migration.state,
        "owner": {
            "task": migration.owner_task,
            "task_generation": migration.owner_task_generation,
            "source_hart": {
                "id": migration.source_hart,
                "generation": migration.source_hart_generation,
            },
            "target_hart": {
                "id": migration.target_hart,
                "generation": migration.target_hart_generation,
            },
        },
        "references": {
            "activation": {
                "id": migration.activation,
                "generation_before": migration.activation_generation_before,
                "generation_after": migration.activation_generation_after,
            },
            "context": migration.context.map(|context| serde_json::json!({
                "id": context,
                "generation_before": migration.context_generation_before,
                "generation_after": migration.context_generation_after,
            })),
            "source_vector_state": migration.source_vector_state.as_ref().map(object_ref_manifest_json),
            "migrated_vector_state": migration.migrated_vector_state.as_ref().map(object_ref_manifest_json),
            "source_queue": {
                "id": migration.source_queue,
                "generation": migration.source_queue_generation,
                "owner_hart_generation": migration.source_queue_owner_hart_generation,
            },
            "target_queue": {
                "id": migration.target_queue,
                "generation": migration.target_queue_generation,
                "owner_hart_generation": migration.target_queue_owner_hart_generation,
            },
            "event": {
                "id": migration.migrated_at_event,
            },
        },
        "vector_migration": {
            "status": if migration.vector_status.is_empty() {
                "absent"
            } else {
                migration.vector_status.as_str()
            },
            "source_vector_state": migration.source_vector_state.as_ref().map(object_ref_manifest_json),
            "migrated_vector_state": migration.migrated_vector_state.as_ref().map(object_ref_manifest_json),
            "event": migration.vector_migrated_at_event,
        },
        "reason": migration.reason,
        "note": migration.note,
        "last_transition": {
            "migrated_at_event": migration.migrated_at_event,
            "activation_generation_after": migration.activation_generation_after,
            "vector_migrated_at_event": migration.vector_migrated_at_event,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn smp_safe_point_view_v1(safe_point: &SmpSafePointManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "smp-safe-point",
        "id": safe_point.id,
        "generation": safe_point.generation,
        "state": safe_point.state,
        "owner": {
            "coordinator_hart": {
                "id": safe_point.coordinator_hart,
                "generation": safe_point.coordinator_hart_generation,
            },
        },
        "references": {
            "participants": safe_point.participants.iter().map(|participant| serde_json::json!({
                "hart": {
                    "id": participant.hart,
                    "generation": participant.hart_generation,
                },
                "hardware_hart": participant.hardware_hart,
                "hart_state": participant.hart_state,
                "current_activation": participant.current_activation,
                "current_activation_generation": participant.current_activation_generation,
            })).collect::<Vec<_>>(),
            "event": {
                "id": safe_point.recorded_at_event,
            },
        },
        "reason": safe_point.reason,
        "note": safe_point.note,
        "last_transition": {
            "recorded_at_event": safe_point.recorded_at_event,
            "participant_count": safe_point.participants.len(),
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn stop_the_world_rendezvous_view_v1(
    rendezvous: &StopTheWorldRendezvousManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "stop-the-world-rendezvous",
        "id": rendezvous.id,
        "generation": rendezvous.generation,
        "state": rendezvous.state,
        "owner": {
            "coordinator_hart": {
                "id": rendezvous.coordinator_hart,
                "generation": rendezvous.coordinator_hart_generation,
            },
        },
        "references": {
            "safe_point": {
                "id": rendezvous.safe_point,
                "generation": rendezvous.safe_point_generation,
            },
            "participants": rendezvous.participants.iter().map(|participant| serde_json::json!({
                "hart": {
                    "id": participant.hart,
                    "generation": participant.hart_generation,
                },
                "hardware_hart": participant.hardware_hart,
                "hart_state": participant.hart_state,
            })).collect::<Vec<_>>(),
            "event": {
                "id": rendezvous.completed_at_event,
            },
        },
        "epoch": rendezvous.epoch,
        "stop_new_activations": rendezvous.stop_new_activations,
        "reason": rendezvous.reason,
        "note": rendezvous.note,
        "last_transition": {
            "completed_at_event": rendezvous.completed_at_event,
            "participant_count": rendezvous.participants.len(),
            "epoch": rendezvous.epoch,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn smp_code_publish_barrier_view_v1(
    barrier: &SmpCodePublishBarrierManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "smp-code-publish-barrier",
        "id": barrier.id,
        "generation": barrier.generation,
        "state": barrier.state,
        "owner": {
            "rendezvous": {
                "id": barrier.rendezvous,
                "generation": barrier.rendezvous_generation,
            },
            "code_publish_epoch": {
                "before": barrier.code_publish_epoch_before,
                "after": barrier.code_publish_epoch_after,
            },
        },
        "references": {
            "rendezvous": {
                "kind": "stop-the-world-rendezvous",
                "id": barrier.rendezvous,
                "generation": barrier.rendezvous_generation,
                "epoch": barrier.rendezvous_epoch,
            },
            "participants": barrier.participants.iter().map(|participant| serde_json::json!({
                "hart": {
                    "kind": "hart",
                    "id": participant.hart,
                    "generation": participant.hart_generation,
                },
                "hardware_hart": participant.hardware_hart,
                "last_seen_code_epoch_before": participant.last_seen_code_epoch_before,
                "last_seen_code_epoch_after": participant.last_seen_code_epoch_after,
                "semantic_icache_sync": participant.semantic_icache_sync,
            })).collect::<Vec<_>>(),
            "event": {
                "id": barrier.validated_at_event,
            },
        },
        "remote_icache_sync_required": barrier.remote_icache_sync_required,
        "code_publish_executed": barrier.code_publish_executed,
        "reason": barrier.reason,
        "note": barrier.note,
        "last_transition": {
            "validated_at_event": barrier.validated_at_event,
            "participant_count": barrier.participants.len(),
            "code_publish_epoch_before": barrier.code_publish_epoch_before,
            "code_publish_epoch_after": barrier.code_publish_epoch_after,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn smp_cleanup_quiescence_view_v1(
    quiescence: &SmpCleanupQuiescenceManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "smp-cleanup-quiescence",
        "id": quiescence.id,
        "generation": quiescence.generation,
        "state": quiescence.state,
        "owner": {
            "store": {
                "id": quiescence.store,
                "target_generation": quiescence.target_store_generation,
                "result_generation": quiescence.result_store_generation,
            },
            "cleanup": {
                "id": quiescence.cleanup,
                "generation": quiescence.cleanup_generation,
            },
        },
        "references": {
            "cleanup": {
                "kind": "activation-cleanup",
                "id": quiescence.cleanup,
                "generation": quiescence.cleanup_generation,
            },
            "store": {
                "kind": "store",
                "id": quiescence.store,
                "target_generation": quiescence.target_store_generation,
                "result_generation": quiescence.result_store_generation,
            },
            "activation": {
                "kind": "activation",
                "id": quiescence.activation,
                "generation_after": quiescence.activation_generation_after,
            },
            "rendezvous": {
                "kind": "stop-the-world-rendezvous",
                "id": quiescence.rendezvous,
                "generation": quiescence.rendezvous_generation,
                "epoch": quiescence.rendezvous_epoch,
            },
            "participants": quiescence.participants.iter().map(|participant| serde_json::json!({
                "hart": {
                    "kind": "hart",
                    "id": participant.hart,
                    "generation": participant.hart_generation,
                },
                "hardware_hart": participant.hardware_hart,
                "hart_state": participant.hart_state,
                "current_activation": participant.current_activation,
                "current_activation_generation": participant.current_activation_generation,
                "current_store": participant.current_store,
                "current_store_generation": participant.current_store_generation,
                "quiesced": participant.quiesced,
            })).collect::<Vec<_>>(),
            "event": {
                "id": quiescence.validated_at_event,
            },
        },
        "postconditions": {
            "no_running_activation": quiescence.no_running_activation,
            "no_pending_wait": quiescence.no_pending_wait,
            "no_live_capability": quiescence.no_live_capability,
            "no_live_resource": quiescence.no_live_resource,
        },
        "reason": quiescence.reason,
        "note": quiescence.note,
        "last_transition": {
            "validated_at_event": quiescence.validated_at_event,
            "participant_count": quiescence.participants.len(),
            "rendezvous_epoch": quiescence.rendezvous_epoch,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn smp_snapshot_barrier_view_v1(
    barrier: &SmpSnapshotBarrierManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "smp-snapshot-barrier",
        "id": barrier.id,
        "generation": barrier.generation,
        "state": barrier.state,
        "owner": {
            "rendezvous": {
                "id": barrier.rendezvous,
                "generation": barrier.rendezvous_generation,
                "epoch": barrier.rendezvous_epoch,
            },
        },
        "references": {
            "rendezvous": {
                "kind": "stop-the-world-rendezvous",
                "id": barrier.rendezvous,
                "generation": barrier.rendezvous_generation,
                "epoch": barrier.rendezvous_epoch,
            },
            "participants": barrier.participants.iter().map(|participant| serde_json::json!({
                "hart": {
                    "kind": "hart",
                    "id": participant.hart,
                    "generation": participant.hart_generation,
                },
                "hardware_hart": participant.hardware_hart,
                "hart_state": participant.hart_state,
                "event_log_cursor_observed": participant.event_log_cursor_observed,
                "snapshot_safe": participant.snapshot_safe,
            })).collect::<Vec<_>>(),
            "event": {
                "id": barrier.validated_at_event,
            },
        },
        "postconditions": {
            "snapshot_validation_ok": barrier.snapshot_validation_ok,
            "pending_wait_count": barrier.pending_wait_count,
            "active_transaction_count": barrier.active_transaction_count,
            "active_dmw_lease_count": barrier.active_dmw_lease_count,
            "active_nonconvertible_activation_count": barrier.active_nonconvertible_activation_count,
            "in_flight_dma_count": barrier.in_flight_dma_count,
            "unsealed_event_log": barrier.unsealed_event_log,
            "unflushed_trap_record_count": barrier.unflushed_trap_record_count,
            "pending_cleanup_count": barrier.pending_cleanup_count,
            "native_activation_stack_live": barrier.native_activation_stack_live,
            "raw_dma_binding_count": barrier.raw_dma_binding_count,
            "raw_mmio_binding_count": barrier.raw_mmio_binding_count,
        },
        "reason": barrier.reason,
        "note": barrier.note,
        "last_transition": {
            "event_log_cursor": barrier.event_log_cursor,
            "validated_at_event": barrier.validated_at_event,
            "participant_count": barrier.participants.len(),
            "rendezvous_epoch": barrier.rendezvous_epoch,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn smp_stress_run_view_v1(run: &SmpStressRunManifest) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "smp-stress-run",
        "id": run.id,
        "generation": run.generation,
        "state": run.state,
        "owner": {
            "scenario": run.scenario,
        },
        "references": {
            "last_safe_point": object_ref_json("smp-safe-point", run.last_safe_point, run.last_safe_point_generation),
            "last_rendezvous": object_ref_json("stop-the-world-rendezvous", run.last_rendezvous, run.last_rendezvous_generation),
            "last_code_publish_barrier": object_ref_json("smp-code-publish-barrier", run.last_code_publish_barrier, run.last_code_publish_barrier_generation),
            "last_cleanup_quiescence": object_ref_json("smp-cleanup-quiescence", run.last_cleanup_quiescence, run.last_cleanup_quiescence_generation),
            "last_snapshot_barrier": object_ref_json("smp-snapshot-barrier", run.last_snapshot_barrier, run.last_snapshot_barrier_generation),
            "last_activation_migration": object_ref_json("activation-migration", run.last_activation_migration, run.last_activation_migration_generation),
            "last_remote_preempt": object_ref_json("remote-preempt", run.last_remote_preempt, run.last_remote_preempt_generation),
            "last_remote_park": object_ref_json("remote-park", run.last_remote_park, run.last_remote_park_generation),
            "event": {
                "id": run.recorded_at_event,
            },
        },
        "coverage": {
            "iterations": run.iterations,
            "hart_count": run.hart_count,
            "safe_points": run.observed_safe_point_count,
            "stop_the_world_rendezvous": run.observed_rendezvous_count,
            "code_publish_barriers": run.observed_code_publish_barrier_count,
            "cleanup_quiescence": run.observed_cleanup_quiescence_count,
            "snapshot_barriers": run.observed_snapshot_barrier_count,
            "activation_migrations": run.observed_activation_migration_count,
            "remote_preempts": run.observed_remote_preempt_count,
            "remote_parks": run.observed_remote_park_count,
            "invariant_checks": run.invariant_checks,
            "property_failures": run.property_failures,
        },
        "reason": run.reason,
        "note": run.note,
        "last_transition": {
            "event_log_cursor": run.event_log_cursor,
            "recorded_at_event": run.recorded_at_event,
            "scenario": run.scenario,
            "property_failures": run.property_failures,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn smp_scaling_benchmark_view_v1(
    benchmark: &SmpScalingBenchmarkManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "smp-scaling-benchmark",
        "id": benchmark.id,
        "generation": benchmark.generation,
        "state": benchmark.state,
        "owner": {
            "scenario": benchmark.scenario,
        },
        "references": {
            "stress_run": object_ref_json("smp-stress-run", benchmark.stress_run, benchmark.stress_run_generation),
            "event": {
                "id": benchmark.recorded_at_event,
            },
        },
        "metrics": {
            "hart_count": benchmark.hart_count,
            "workload_units": benchmark.workload_units,
            "baseline_single_hart_nanos": benchmark.baseline_single_hart_nanos,
            "measured_smp_nanos": benchmark.measured_smp_nanos,
            "budget_nanos": benchmark.budget_nanos,
            "speedup_milli": benchmark.speedup_milli,
            "efficiency_milli": benchmark.efficiency_milli,
        },
        "coverage": {
            "stress_safe_points": benchmark.stress_safe_point_count,
            "stress_rendezvous": benchmark.stress_rendezvous_count,
            "stress_property_failures": benchmark.stress_property_failures,
        },
        "note": benchmark.note,
        "last_transition": {
            "event_log_cursor": benchmark.event_log_cursor,
            "recorded_at_event": benchmark.recorded_at_event,
            "scenario": benchmark.scenario,
            "within_budget": benchmark.measured_smp_nanos <= benchmark.budget_nanos,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn integrated_smp_preemption_cleanup_view_v1(
    record: &IntegratedSmpPreemptionCleanupManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "integrated-smp-preemption-cleanup",
        "id": record.id,
        "generation": record.generation,
        "state": record.state,
        "owner": {
            "scenario": record.scenario,
            "cleanup_store": object_ref_json("store", record.cleanup_store, record.target_store_generation),
            "runtime_activation": {
                "id": record.cleanup_activation,
                "generation_after_cleanup": record.cleanup_activation_generation_after,
                "note": "runtime-preemptive-activation-not-target-executor-object",
            },
        },
        "references": {
            "smp_stress_run": object_ref_json("smp-stress-run", record.stress_run, record.stress_run_generation),
            "preemption": object_ref_json("preemption", record.preemption, record.preemption_generation),
            "timer_interrupt": object_ref_json("timer-interrupt", record.timer_interrupt, record.timer_interrupt_generation),
            "saved_context": object_ref_json("saved-context", record.saved_context, record.saved_context_generation),
            "remote_preempt": object_ref_json("remote-preempt", record.remote_preempt, record.remote_preempt_generation),
            "activation_cleanup": object_ref_json(
                "activation-cleanup",
                record.activation_cleanup,
                record.activation_cleanup_generation,
            ),
            "smp_cleanup_quiescence": object_ref_json(
                "smp-cleanup-quiescence",
                record.smp_cleanup_quiescence,
                record.smp_cleanup_quiescence_generation,
            ),
            "event": {
                "id": record.recorded_at_event,
            },
        },
        "closure": {
            "hart_count": record.hart_count,
            "invariant_checks": record.invariant_checks,
            "target_store_generation": record.target_store_generation,
            "result_store_generation": record.result_store_generation,
            "cleanup_generation_safe": record.result_store_generation > record.target_store_generation,
            "requires_no_resume_after_cleanup": true,
            "requires_wait_cancelling_cleanup": true,
        },
        "authority": {
            "uses_semantic_preemption_cleanup_evidence": true,
            "real_smp_preemption_executed": false,
            "real_cross_hart_substrate_interrupt_executed": false,
        },
        "note": record.note,
        "last_transition": {
            "recorded_at_event": record.recorded_at_event,
            "scenario": record.scenario,
            "cleanup_store_generation_after": record.result_store_generation,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn integrated_smp_network_fault_view_v1(
    record: &IntegratedSmpNetworkFaultManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "integrated-smp-network-fault",
        "id": record.id,
        "generation": record.generation,
        "state": record.state,
        "owner": {
            "scenario": record.scenario,
            "driver_store": {
                "kind": "store",
                "id": record.driver_store,
                "generation": record.driver_store_generation,
                "note": "semantic driver store generation, not adapter-internal state",
            },
            "packet_device": object_ref_json(
                "packet-device-object",
                record.packet_device,
                record.packet_device_generation,
            ),
        },
        "references": {
            "network_driver_cleanup": object_ref_json(
                "network-driver-cleanup",
                record.network_driver_cleanup,
                record.network_driver_cleanup_generation,
            ),
            "smp_stress_run": object_ref_json(
                "smp-stress-run",
                record.smp_stress_run,
                record.smp_stress_run_generation,
            ),
            "remote_preempt": object_ref_json(
                "remote-preempt",
                record.remote_preempt,
                record.remote_preempt_generation,
            ),
            "smp_cleanup_quiescence": object_ref_json(
                "smp-cleanup-quiescence",
                record.smp_cleanup_quiescence,
                record.smp_cleanup_quiescence_generation,
            ),
            "network_stack_adapter": object_ref_json(
                "network-stack-adapter",
                record.adapter,
                record.adapter_generation,
            ),
            "backend": object_ref_json(
                &record.backend.kind,
                record.backend.id,
                record.backend.generation,
            ),
            "io_cleanup": object_ref_json(
                "io-cleanup",
                record.io_cleanup,
                record.io_cleanup_generation,
            ),
            "event": {
                "id": record.recorded_at_event,
            },
        },
        "closure": {
            "hart_count": record.hart_count,
            "invariant_checks": record.invariant_checks,
            "cancelled_socket_wait_count": record.cancelled_socket_wait_count,
            "cancelled_wait_token_count": record.cancelled_wait_token_count,
            "revoked_packet_capability_count": record.revoked_packet_capability_count,
            "requires_completed_network_driver_cleanup": true,
            "requires_cross_hart_preempt_evidence": true,
            "requires_smp_quiescence_evidence": true,
        },
        "authority": {
            "uses_semantic_network_cleanup_evidence": true,
            "uses_smp_stress_evidence": true,
            "real_network_driver_fault_executed": false,
            "real_cross_hart_substrate_interrupt_executed": false,
            "adapter_internal_state_is_not_semantic_truth": true,
        },
        "note": record.note,
        "last_transition": {
            "event": record.recorded_at_event,
            "state": record.state,
        },
    })
}

pub(crate) fn integrated_disk_preempt_fault_view_v1(
    record: &IntegratedDiskPreemptFaultManifest,
) -> serde_json::Value {
    let retry_request = match (record.retry_request, record.retry_request_generation) {
        (Some(id), Some(generation)) => object_ref_json("block-request-object", id, generation),
        _ => serde_json::Value::Null,
    };
    let owner = match (record.driver_store, record.driver_store_generation) {
        (Some(id), Some(generation)) => serde_json::json!({
            "driver_store": {
                "kind": "store",
                "id": id,
                "generation": generation,
                "note": "semantic wait owner store generation, not adapter-internal state",
            }
        }),
        _ => serde_json::json!({
            "driver_store": null,
        }),
    };
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "integrated-disk-preempt-fault",
        "id": record.id,
        "generation": record.generation,
        "state": record.state,
        "owner": owner,
        "references": {
            "preemption": object_ref_json(
                "preemption",
                record.preemption,
                record.preemption_generation,
            ),
            "timer_interrupt": object_ref_json(
                "timer-interrupt",
                record.timer_interrupt,
                record.timer_interrupt_generation,
            ),
            "block_pending_io_policy": object_ref_json(
                "block-pending-io-policy",
                record.block_pending_io_policy,
                record.block_pending_io_policy_generation,
            ),
            "block_wait": object_ref_json(
                "block-wait",
                record.block_wait,
                record.block_wait_generation,
            ),
            "wait": object_ref_json("wait-token", record.wait, record.wait_generation),
            "block_request": object_ref_json(
                "block-request-object",
                record.block_request,
                record.block_request_generation,
            ),
            "retry_request": retry_request,
            "block_device": object_ref_json(
                "block-device-object",
                record.block_device,
                record.block_device_generation,
            ),
            "block_range": object_ref_json(
                "block-range-object",
                record.block_range,
                record.block_range_generation,
            ),
            "event": {
                "id": record.recorded_at_event,
            },
        },
        "closure": {
            "scenario": record.scenario,
            "action": record.action,
            "errno": record.errno,
            "preempted_activation": object_ref_json(
                "activation",
                record.preempted_activation,
                record.preempted_activation_generation_after,
            ),
            "invariant_checks": record.invariant_checks,
            "requires_applied_preemption": true,
            "requires_cancelled_block_wait": true,
            "requires_device_fault_wait_cancel": true,
        },
        "authority": {
            "uses_semantic_block_pending_io_policy": true,
            "real_disk_fault_executed": false,
            "real_preemption_interrupt_executed": false,
            "adapter_internal_state_is_not_semantic_truth": true,
        },
        "note": record.note,
        "last_transition": {
            "event": record.recorded_at_event,
            "state": record.state,
        },
    })
}

pub(crate) fn integrated_simd_migration_view_v1(
    record: &IntegratedSimdMigrationManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "integrated-simd-migration",
        "id": record.id,
        "generation": record.generation,
        "state": record.state,
        "owner": {
            "activation": {
                "kind": "activation",
                "id": record.activation,
                "generation_before": record.activation_generation_before,
                "generation_after": record.activation_generation_after,
            },
            "source_hart": {
                "kind": "hart",
                "id": record.source_hart,
                "generation": record.source_hart_generation,
            },
            "target_hart": {
                "kind": "hart",
                "id": record.target_hart,
                "generation": record.target_hart_generation,
            },
        },
        "references": {
            "activation_migration": object_ref_json(
                "activation-migration",
                record.activation_migration,
                record.activation_migration_generation,
            ),
            "target_feature_set": object_ref_json(
                "target-feature-set",
                record.target_feature_set,
                record.target_feature_set_generation,
            ),
            "source_vector_state": object_ref_manifest_json(&record.source_vector_state),
            "migrated_vector_state": object_ref_manifest_json(&record.migrated_vector_state),
            "context": object_ref_json(
                "activation-context",
                record.context,
                record.context_generation_after,
            ),
            "source_queue": object_ref_json(
                "runnable-queue",
                record.source_queue,
                record.source_queue_generation,
            ),
            "target_queue": object_ref_json(
                "runnable-queue",
                record.target_queue,
                record.target_queue_generation,
            ),
            "event": {
                "id": record.recorded_at_event,
            },
        },
        "closure": {
            "scenario": record.scenario,
            "simd_abi": record.simd_abi,
            "vector_register_count": record.vector_register_count,
            "vector_register_bits": record.vector_register_bits,
            "invariant_checks": record.invariant_checks,
            "requires_clean_vector_context": true,
            "requires_source_vector_dropped": true,
            "requires_migrated_vector_reserved": true,
            "requires_cross_hart_migration": true,
        },
        "authority": {
            "uses_semantic_activation_migration": true,
            "uses_semantic_vector_state_refs": true,
            "real_vector_register_payload_migrated": false,
            "real_cross_hart_substrate_interrupt_executed": false,
            "adapter_internal_state_is_not_semantic_truth": true,
        },
        "note": record.note,
        "last_transition": {
            "event": record.recorded_at_event,
            "state": record.state,
        },
    })
}

pub(crate) fn integrated_network_disk_io_view_v1(
    record: &IntegratedNetworkDiskIoManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "integrated-network-disk-io",
        "id": record.id,
        "generation": record.generation,
        "state": record.state,
        "owner": {
            "network_owner_store": object_ref_json(
                "store",
                record.network_owner_store,
                record.network_owner_store_generation,
            ),
            "packet_device": object_ref_json(
                "packet-device-object",
                record.packet_device,
                record.packet_device_generation,
            ),
            "block_device": object_ref_json(
                "block-device-object",
                record.block_device,
                record.block_device_generation,
            ),
        },
        "references": {
            "network_benchmark": object_ref_json(
                "network-benchmark",
                record.network_benchmark,
                record.network_benchmark_generation,
            ),
            "block_benchmark": object_ref_json(
                "block-benchmark",
                record.block_benchmark,
                record.block_benchmark_generation,
            ),
            "network_adapter": object_ref_json(
                "network-stack-adapter",
                record.network_adapter,
                record.network_adapter_generation,
            ),
            "socket": object_ref_json(
                "socket-object",
                record.socket,
                record.socket_generation,
            ),
            "block_backend": object_ref_manifest_json(&record.block_backend),
            "block_request_queue": object_ref_json(
                "block-request-queue",
                record.block_request_queue,
                record.block_request_queue_generation,
            ),
            "block_dma_buffer": object_ref_json(
                "block-dma-buffer",
                record.block_dma_buffer,
                record.block_dma_buffer_generation,
            ),
            "event": {
                "id": record.recorded_at_event,
            },
        },
        "closure": {
            "scenario": record.scenario,
            "network_sample_packets": record.network_sample_packets,
            "block_sample_requests": record.block_sample_requests,
            "network_sample_bytes": record.network_sample_bytes,
            "block_sample_bytes": record.block_sample_bytes,
            "concurrent_window_nanos": record.concurrent_window_nanos,
            "combined_throughput_bytes_per_sec": record.combined_throughput_bytes_per_sec,
            "max_p99_latency_nanos": record.max_p99_latency_nanos,
            "invariant_checks": record.invariant_checks,
            "requires_recorded_network_benchmark": true,
            "requires_recorded_block_benchmark": true,
            "requires_exact_generation_refs": true,
        },
        "authority": {
            "uses_semantic_network_benchmark": true,
            "uses_semantic_block_benchmark": true,
            "real_concurrent_hardware_io_executed": false,
            "real_virtio_or_dma_execution": false,
            "adapter_internal_state_is_not_semantic_truth": true,
        },
        "note": record.note,
        "last_transition": {
            "event": record.recorded_at_event,
            "state": record.state,
        },
    })
}

pub(crate) fn integrated_display_scheduler_load_view_v1(
    record: &IntegratedDisplaySchedulerLoadManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "integrated-display-scheduler-load",
        "id": record.id,
        "generation": record.generation,
        "state": record.state,
        "owner": {
            "store": object_ref_json(
                "store",
                record.owner_store,
                record.owner_store_generation,
            ),
            "task": object_ref_json(
                "task",
                record.owner_task,
                record.owner_task_generation,
            ),
            "display": object_ref_json(
                "display-object",
                record.display,
                record.display_generation,
            ),
            "framebuffer": object_ref_json(
                "framebuffer-object",
                record.framebuffer,
                record.framebuffer_generation,
            ),
        },
        "references": {
            "framebuffer_benchmark": object_ref_json(
                "framebuffer-benchmark",
                record.framebuffer_benchmark,
                record.framebuffer_benchmark_generation,
            ),
            "scheduler_decision": object_ref_json(
                "scheduler-decision",
                record.scheduler_decision,
                record.scheduler_decision_generation,
            ),
            "runnable_queue": object_ref_json(
                "runnable-queue",
                record.queue,
                record.queue_generation,
            ),
            "selected_activation": object_ref_json(
                "activation",
                record.selected_activation,
                record.selected_activation_generation,
            ),
            "display_capability": object_ref_json(
                "display-capability",
                record.display_capability,
                record.display_capability_generation,
            ),
            "framebuffer_write": object_ref_json(
                "framebuffer-write",
                record.framebuffer_write,
                record.framebuffer_write_generation,
            ),
            "framebuffer_flush_region": object_ref_json(
                "framebuffer-flush-region",
                record.framebuffer_flush_region,
                record.framebuffer_flush_region_generation,
            ),
            "display_event_log": object_ref_json(
                "display-event-log",
                record.display_event_log,
                record.display_event_log_generation,
            ),
            "event": {
                "id": record.recorded_at_event,
            },
        },
        "closure": {
            "scenario": record.scenario,
            "sample_frames": record.sample_frames,
            "sample_bytes": record.sample_bytes,
            "scheduler_load_units": record.scheduler_load_units,
            "display_measured_nanos": record.display_measured_nanos,
            "scheduler_decided_at_event": record.scheduler_decided_at_event,
            "display_recorded_at_event": record.display_recorded_at_event,
            "invariant_checks": record.invariant_checks,
            "requires_recorded_framebuffer_benchmark": true,
            "requires_generation_exact_scheduler_decision": true,
        },
        "authority": {
            "uses_semantic_framebuffer_benchmark": true,
            "uses_semantic_scheduler_decision": true,
            "real_display_hardware_executed": false,
            "real_preemptive_scheduler_executed": false,
            "adapter_internal_state_is_not_semantic_truth": true,
        },
        "note": record.note,
        "last_transition": {
            "event": record.recorded_at_event,
            "state": record.state,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn integrated_snapshot_io_lease_barrier_view_v1(
    record: &IntegratedSnapshotIoLeaseBarrierManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "integrated-snapshot-io-lease-barrier",
        "id": record.id,
        "generation": record.generation,
        "state": record.state,
        "owner": {
            "driver_store": object_ref_json(
                "store",
                record.driver_store,
                record.driver_store_generation,
            ),
            "device": object_ref_json(
                "device-object",
                record.device,
                record.device_generation,
            ),
            "display": object_ref_json(
                "display-object",
                record.display,
                record.display_generation,
            ),
            "framebuffer": object_ref_json(
                "framebuffer-object",
                record.framebuffer,
                record.framebuffer_generation,
            ),
        },
        "references": {
            "smp_snapshot_barrier": object_ref_json(
                "smp-snapshot-barrier",
                record.smp_snapshot_barrier,
                record.smp_snapshot_barrier_generation,
            ),
            "io_cleanup": object_ref_json(
                "io-cleanup",
                record.io_cleanup,
                record.io_cleanup_generation,
            ),
            "display_snapshot_barrier": object_ref_json(
                "display-snapshot-barrier",
                record.display_snapshot_barrier,
                record.display_snapshot_barrier_generation,
            ),
            "event": {
                "id": record.recorded_at_event,
            },
        },
        "closure": {
            "scenario": record.scenario,
            "active_dmw_lease_count": record.active_dmw_lease_count,
            "in_flight_dma_count": record.in_flight_dma_count,
            "raw_dma_binding_count": record.raw_dma_binding_count,
            "raw_mmio_binding_count": record.raw_mmio_binding_count,
            "active_framebuffer_window_lease_count": record.active_framebuffer_window_lease_count,
            "active_framebuffer_mapping_count": record.active_framebuffer_mapping_count,
            "dirty_framebuffer_region_count": record.dirty_framebuffer_region_count,
            "released_dma_buffers": record.released_dma_buffers,
            "released_mmio_regions": record.released_mmio_regions,
            "released_irq_lines": record.released_irq_lines,
            "released_framebuffer_window_leases": record.released_framebuffer_window_leases,
            "revoked_device_capabilities": record.revoked_device_capabilities,
            "revoked_display_capabilities": record.revoked_display_capabilities,
            "smp_barrier_event": record.smp_barrier_event,
            "io_cleanup_completed_event": record.io_cleanup_completed_event,
            "display_barrier_event": record.display_barrier_event,
            "invariant_checks": record.invariant_checks,
            "requires_clean_smp_snapshot_barrier": true,
            "requires_completed_io_cleanup": true,
            "requires_clean_display_snapshot_barrier": true,
        },
        "authority": {
            "uses_semantic_snapshot_barrier": true,
            "uses_semantic_io_cleanup": true,
            "uses_semantic_display_snapshot_barrier": true,
            "real_snapshot_or_dma_hardware_executed": false,
            "real_display_hardware_executed": false,
            "adapter_internal_state_is_not_semantic_truth": true,
        },
        "note": record.note,
        "last_transition": {
            "event": record.recorded_at_event,
            "state": record.state,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn integrated_code_publish_smp_workload_view_v1(
    record: &IntegratedCodePublishSmpWorkloadManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "integrated-code-publish-smp-workload",
        "id": record.id,
        "generation": record.generation,
        "state": record.state,
        "owner": {
            "hart_count": record.hart_count,
            "workload_iterations": record.workload_iterations,
        },
        "references": {
            "smp_stress_run": object_ref_json(
                "smp-stress-run",
                record.smp_stress_run,
                record.smp_stress_run_generation,
            ),
            "smp_code_publish_barrier": object_ref_json(
                "smp-code-publish-barrier",
                record.smp_code_publish_barrier,
                record.smp_code_publish_barrier_generation,
            ),
            "publish_rendezvous": object_ref_json(
                "stop-the-world-rendezvous",
                record.publish_rendezvous,
                record.publish_rendezvous_generation,
            ),
            "publish_safe_point": object_ref_json(
                "smp-safe-point",
                record.publish_safe_point,
                record.publish_safe_point_generation,
            ),
            "event": {
                "id": record.recorded_at_event,
            },
        },
        "closure": {
            "scenario": record.scenario,
            "observed_safe_point_count": record.observed_safe_point_count,
            "observed_rendezvous_count": record.observed_rendezvous_count,
            "observed_code_publish_barrier_count": record.observed_code_publish_barrier_count,
            "code_publish_epoch_before": record.code_publish_epoch_before,
            "code_publish_epoch_after": record.code_publish_epoch_after,
            "remote_icache_sync_required": record.remote_icache_sync_required,
            "code_publish_executed": record.code_publish_executed,
            "participant_count": record.participant_count,
            "stress_event_log_cursor": record.stress_event_log_cursor,
            "barrier_event": record.barrier_event,
            "stress_recorded_at_event": record.stress_recorded_at_event,
            "invariant_checks": record.invariant_checks,
            "requires_clean_smp_stress_run": true,
            "requires_semantic_code_publish_barrier": true,
            "requires_generation_exact_publish_refs": true,
        },
        "authority": {
            "uses_semantic_stress_run": true,
            "uses_semantic_code_publish_barrier": true,
            "real_smp_dynamic_code_publish_executed": false,
            "real_wx_page_publish_executed": false,
            "adapter_internal_state_is_not_semantic_truth": true,
        },
        "note": record.note,
        "last_transition": {
            "event": record.recorded_at_event,
            "state": record.state,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn integrated_display_panic_view_v1(
    record: &IntegratedDisplayPanicManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "integrated-display-panic",
        "id": record.id,
        "generation": record.generation,
        "state": record.state,
        "owner": {
            "panic_epoch": record.substrate_panic_epoch,
            "panic_cpu": record.substrate_panic_cpu,
        },
        "references": {
            "substrate_panic_event": {
                "id": record.substrate_panic_event,
                "epoch": record.substrate_panic_epoch,
                "reason_code": record.substrate_panic_reason_code,
            },
            "display_panic_last_frame": object_ref_json(
                "display-panic-last-frame",
                record.display_panic_last_frame,
                record.display_panic_last_frame_generation,
            ),
            "event": {
                "id": record.recorded_at_event,
            },
        },
        "panic_ring": {
            "ring_bytes": record.panic_ring_bytes,
            "record_max_bytes": record.panic_record_max_bytes,
            "oldest_seq": record.panic_ring_oldest_seq,
            "newest_seq": record.panic_ring_newest_seq,
            "record_count": record.panic_ring_record_count,
            "lost_count": record.panic_ring_lost_count,
            "jsonl_frame_count": record.jsonl_frame_count,
            "contract_panic_summary_records": record.contract_panic_summary_records,
            "last_frame_summary_records": record.last_frame_summary_records,
            "corrupt_record_count": record.corrupt_record_count,
            "truncated_record_count": record.truncated_record_count,
            "summary_record_bytes": record.summary_record_bytes,
            "raw_framebuffer_bytes_exported": record.raw_framebuffer_bytes_exported,
        },
        "closure": {
            "scenario": record.scenario,
            "requires_substrate_panic_event": true,
            "requires_bounded_panic_ring_record": true,
            "requires_display_panic_last_frame": true,
            "requires_no_raw_framebuffer_bytes": true,
            "requires_no_corrupt_or_truncated_records": true,
            "panic_path_allocates": record.panic_path_allocates,
            "invariant_checks": record.invariant_checks,
        },
        "authority": {
            "target_to_host_extraction_only": true,
            "panic_path_allocates": record.panic_path_allocates,
            "raw_framebuffer_bytes_exported": record.raw_framebuffer_bytes_exported,
            "real_substrate_halt_executed": false,
            "adapter_internal_state_is_not_semantic_truth": true,
        },
        "note": record.note,
        "last_transition": {
            "event": record.recorded_at_event,
            "state": record.state,
        },
        "last_error": serde_json::Value::Null,
    })
}

pub(crate) fn integrated_osctl_trace_replay_view_v1(
    record: &IntegratedOsctlTraceReplayManifest,
) -> serde_json::Value {
    serde_json::json!({
        "schema": VIEW_SCHEMA_V1,
        "kind": "integrated-osctl-trace-replay",
        "id": record.id,
        "generation": record.generation,
        "state": record.state,
        "owner": {
            "scenario": record.scenario,
            "integrated_scenario_count": record.integrated_scenario_count,
        },
        "references": {
            "x0_smp_preemption_cleanup": object_ref_json(
                "integrated-smp-preemption-cleanup",
                record.integrated_smp_preemption_cleanup,
                record.integrated_smp_preemption_cleanup_generation,
            ),
            "x1_smp_network_fault": object_ref_json(
                "integrated-smp-network-fault",
                record.integrated_smp_network_fault,
                record.integrated_smp_network_fault_generation,
            ),
            "x2_disk_preempt_fault": object_ref_json(
                "integrated-disk-preempt-fault",
                record.integrated_disk_preempt_fault,
                record.integrated_disk_preempt_fault_generation,
            ),
            "x3_simd_migration": object_ref_json(
                "integrated-simd-migration",
                record.integrated_simd_migration,
                record.integrated_simd_migration_generation,
            ),
            "x4_network_disk_io": object_ref_json(
                "integrated-network-disk-io",
                record.integrated_network_disk_io,
                record.integrated_network_disk_io_generation,
            ),
            "x5_display_scheduler_load": object_ref_json(
                "integrated-display-scheduler-load",
                record.integrated_display_scheduler_load,
                record.integrated_display_scheduler_load_generation,
            ),
            "x6_snapshot_io_lease_barrier": object_ref_json(
                "integrated-snapshot-io-lease-barrier",
                record.integrated_snapshot_io_lease_barrier,
                record.integrated_snapshot_io_lease_barrier_generation,
            ),
            "x7_code_publish_smp_workload": object_ref_json(
                "integrated-code-publish-smp-workload",
                record.integrated_code_publish_smp_workload,
                record.integrated_code_publish_smp_workload_generation,
            ),
            "x8_display_panic": object_ref_json(
                "integrated-display-panic",
                record.integrated_display_panic,
                record.integrated_display_panic_generation,
            ),
            "event": {
                "id": record.recorded_at_event,
            },
        },
        "replay": {
            "event_cursor": record.replay_event_cursor,
            "stable_view_count": record.stable_view_count,
            "historical_edge_count": record.historical_edge_count,
            "replayed_root_count": record.replayed_root_count,
            "integrated_scenario_count": record.integrated_scenario_count,
            "replay_fixture_count": record.replay_fixture_count,
            "contract_validation_ok": record.contract_validation_ok,
            "replay_validation_ok": record.replay_validation_ok,
            "graph_history_ok": record.graph_history_ok,
            "roots_match_counts": record.roots_match_counts,
        },
        "closure": {
            "scenario": record.scenario,
            "requires_x0_to_x8_integrated_evidence": true,
            "requires_stable_osctl_view_v1": true,
            "requires_historical_graph_edges": true,
            "requires_contract_validate_ok": true,
            "requires_replay_validate_ok": true,
            "invariant_checks": record.invariant_checks,
        },
        "authority": {
            "osctl_is_read_only_control_plane": true,
            "adapter_internal_state_is_not_semantic_truth": true,
            "no_substrate_mapping_as_semantic_truth": true,
        },
        "note": record.note,
        "last_transition": {
            "event": record.recorded_at_event,
            "state": record.state,
        },
        "last_error": serde_json::Value::Null,
    })
}
