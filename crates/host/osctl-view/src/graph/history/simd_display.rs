use super::super::*;

pub(super) fn push_simd_display_history_edges(
    package: &MigrationPackageManifest,
    edges: &mut Vec<serde_json::Value>,
) {
    for feature in &package.semantic.target_feature_sets {
        let event = Some(feature.recorded_at_event);
        edges.push(graph_edge(
            object_ref_json("target-feature-set", feature.id, feature.generation),
            object_ref_json("event", feature.recorded_at_event, 1),
            "target-feature-set->event",
            "historical",
            event,
        ));
    }
    for vector_state in &package.semantic.vector_states {
        let event = Some(vector_state.recorded_at_event);
        let from = object_ref_json("vector-state", vector_state.id, vector_state.generation);
        for (target, label, mode) in [
            (
                &vector_state.owner_activation,
                "vector-state->activation",
                if vector_state.state == "reserved" { "live" } else { "historical" },
            ),
            (
                &vector_state.owner_store,
                "vector-state->store",
                if vector_state.state == "reserved" { "live" } else { "historical" },
            ),
            (
                &vector_state.code_object,
                "vector-state->code-object",
                if vector_state.state == "reserved" { "live" } else { "historical" },
            ),
            (
                &vector_state.target_feature_set,
                "vector-state->target-feature-set",
                if vector_state.state == "reserved" { "live" } else { "historical" },
            ),
        ] {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(target),
                label,
                mode,
                event,
            ));
        }
        edges.push(graph_edge(
            from,
            object_ref_json("event", vector_state.recorded_at_event, 1),
            "vector-state->event",
            "historical",
            event,
        ));
    }
    for injection in &package.semantic.simd_fault_injections {
        let event = Some(injection.recorded_at_event);
        let from = object_ref_json("simd-fault-injection", injection.id, injection.generation);
        for (target, label) in [
            (&injection.activation, "simd-fault-injection->activation"),
            (&injection.code_object, "simd-fault-injection->code-object"),
            (&injection.trap, "simd-fault-injection->trap"),
            (&injection.target_feature_set, "simd-fault-injection->target-feature-set"),
        ] {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(target),
                label,
                "historical",
                event,
            ));
        }
        if let Some(vector_state) = &injection.vector_state {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(vector_state),
                "simd-fault-injection->vector-state",
                "historical",
                event,
            ));
        }
        edges.push(graph_edge(
            from,
            object_ref_json("event", injection.recorded_at_event, 1),
            "simd-fault-injection->event",
            "historical",
            event,
        ));
    }
    for benchmark in &package.semantic.simd_benchmarks {
        let event = Some(benchmark.recorded_at_event);
        let from = object_ref_json("simd-benchmark", benchmark.id, benchmark.generation);
        for (target, label) in [
            (&benchmark.target_feature_set, "simd-benchmark->target-feature-set"),
            (&benchmark.scalar_code_object, "simd-benchmark->scalar-code-object"),
            (&benchmark.vector_code_object, "simd-benchmark->vector-code-object"),
        ] {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(target),
                label,
                "historical",
                event,
            ));
        }
        edges.push(graph_edge(
            from,
            object_ref_json("event", benchmark.recorded_at_event, 1),
            "simd-benchmark->event",
            "historical",
            event,
        ));
    }
    for benchmark in &package.semantic.simd_context_switch_benchmarks {
        let event = Some(benchmark.recorded_at_event);
        let from =
            object_ref_json("simd-context-switch-benchmark", benchmark.id, benchmark.generation);
        for (target, label) in [
            (&benchmark.preemption, "simd-context-switch-benchmark->preemption"),
            (&benchmark.activation_resume, "simd-context-switch-benchmark->activation-resume"),
            (&benchmark.saved_vector_state, "simd-context-switch-benchmark->saved-vector-state"),
            (
                &benchmark.restored_vector_state,
                "simd-context-switch-benchmark->restored-vector-state",
            ),
            (&benchmark.target_feature_set, "simd-context-switch-benchmark->target-feature-set"),
        ] {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(target),
                label,
                "historical",
                event,
            ));
        }
        edges.push(graph_edge(
            from,
            object_ref_json("event", benchmark.recorded_at_event, 1),
            "simd-context-switch-benchmark->event",
            "historical",
            event,
        ));
    }
    for framebuffer in &package.semantic.framebuffer_objects {
        let event = Some(framebuffer.recorded_at_event);
        let from = object_ref_json("framebuffer-object", framebuffer.id, framebuffer.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("resource", framebuffer.resource, framebuffer.resource_generation),
            "framebuffer-object->resource",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("event", framebuffer.recorded_at_event, 1),
            "framebuffer-object->event",
            "historical",
            event,
        ));
    }
    for display in &package.semantic.display_objects {
        let event = Some(display.recorded_at_event);
        let from = object_ref_json("display-object", display.id, display.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-object",
                display.framebuffer,
                display.framebuffer_generation,
            ),
            "display-object->framebuffer-object",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("event", display.recorded_at_event, 1),
            "display-object->event",
            "historical",
            event,
        ));
    }
    for capability in &package.semantic.display_capabilities {
        let event = Some(capability.recorded_at_event);
        let from = object_ref_json("display-capability", capability.id, capability.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", capability.owner_store, capability.owner_store_generation),
            "display-capability->owner-store",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("display-object", capability.display, capability.display_generation),
            "display-capability->display-object",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-object",
                capability.framebuffer,
                capability.framebuffer_generation,
            ),
            "display-capability->framebuffer-object",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("capability", capability.capability, capability.capability_generation),
            "display-capability->capability",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("event", capability.recorded_at_event, 1),
            "display-capability->event",
            "historical",
            event,
        ));
    }
    for lease in &package.semantic.framebuffer_window_leases {
        let event = Some(lease.recorded_at_event);
        let from = object_ref_json("framebuffer-window-lease", lease.id, lease.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", lease.owner_store, lease.owner_store_generation),
            "framebuffer-window-lease->owner-store",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "display-capability",
                lease.display_capability,
                lease.display_capability_generation,
            ),
            "framebuffer-window-lease->display-capability",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("display-object", lease.display, lease.display_generation),
            "framebuffer-window-lease->display-object",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("framebuffer-object", lease.framebuffer, lease.framebuffer_generation),
            "framebuffer-window-lease->framebuffer-object",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("event", lease.recorded_at_event, 1),
            "framebuffer-window-lease->event",
            "historical",
            event,
        ));
    }
    for mapping in &package.semantic.framebuffer_mappings {
        let event = Some(mapping.recorded_at_event);
        let from = object_ref_json("framebuffer-mapping", mapping.id, mapping.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", mapping.owner_store, mapping.owner_store_generation),
            "framebuffer-mapping->owner-store",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-window-lease",
                mapping.framebuffer_window_lease,
                mapping.framebuffer_window_lease_generation,
            ),
            "framebuffer-mapping->framebuffer-window-lease",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "display-capability",
                mapping.display_capability,
                mapping.display_capability_generation,
            ),
            "framebuffer-mapping->display-capability",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("display-object", mapping.display, mapping.display_generation),
            "framebuffer-mapping->display-object",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-object",
                mapping.framebuffer,
                mapping.framebuffer_generation,
            ),
            "framebuffer-mapping->framebuffer-object",
            "live",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("event", mapping.recorded_at_event, 1),
            "framebuffer-mapping->event",
            "historical",
            event,
        ));
    }
    for write in &package.semantic.framebuffer_writes {
        let event = Some(write.recorded_at_event);
        let from = object_ref_json("framebuffer-write", write.id, write.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", write.owner_store, write.owner_store_generation),
            "framebuffer-write->owner-store",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-mapping",
                write.framebuffer_mapping,
                write.framebuffer_mapping_generation,
            ),
            "framebuffer-write->framebuffer-mapping",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-window-lease",
                write.framebuffer_window_lease,
                write.framebuffer_window_lease_generation,
            ),
            "framebuffer-write->framebuffer-window-lease",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "display-capability",
                write.display_capability,
                write.display_capability_generation,
            ),
            "framebuffer-write->display-capability",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("display-object", write.display, write.display_generation),
            "framebuffer-write->display-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("framebuffer-object", write.framebuffer, write.framebuffer_generation),
            "framebuffer-write->framebuffer-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("event", write.recorded_at_event, 1),
            "framebuffer-write->event",
            "historical",
            event,
        ));
    }
    for flush in &package.semantic.framebuffer_flush_regions {
        let event = Some(flush.recorded_at_event);
        let from = object_ref_json("framebuffer-flush-region", flush.id, flush.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", flush.owner_store, flush.owner_store_generation),
            "framebuffer-flush-region->owner-store",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-write",
                flush.framebuffer_write,
                flush.framebuffer_write_generation,
            ),
            "framebuffer-flush-region->framebuffer-write",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "display-capability",
                flush.display_capability,
                flush.display_capability_generation,
            ),
            "framebuffer-flush-region->display-capability",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("display-object", flush.display, flush.display_generation),
            "framebuffer-flush-region->display-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("framebuffer-object", flush.framebuffer, flush.framebuffer_generation),
            "framebuffer-flush-region->framebuffer-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("event", flush.recorded_at_event, 1),
            "framebuffer-flush-region->event",
            "historical",
            event,
        ));
    }
    for dirty in &package.semantic.framebuffer_dirty_regions {
        let event = Some(dirty.recorded_at_event);
        let from = object_ref_json("framebuffer-dirty-region", dirty.id, dirty.generation);
        let owner_mode = if dirty.state == "dirty" { "live" } else { "historical" };
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", dirty.owner_store, dirty.owner_store_generation),
            "framebuffer-dirty-region->owner-store",
            owner_mode,
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-write",
                dirty.framebuffer_write,
                dirty.framebuffer_write_generation,
            ),
            "framebuffer-dirty-region->framebuffer-write",
            "historical",
            event,
        ));
        if let (Some(flush), Some(generation)) =
            (dirty.framebuffer_flush_region, dirty.framebuffer_flush_region_generation)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("framebuffer-flush-region", flush, generation),
                "framebuffer-dirty-region->framebuffer-flush-region",
                "historical",
                event,
            ));
        }
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "display-capability",
                dirty.display_capability,
                dirty.display_capability_generation,
            ),
            "framebuffer-dirty-region->display-capability",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("display-object", dirty.display, dirty.display_generation),
            "framebuffer-dirty-region->display-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("framebuffer-object", dirty.framebuffer, dirty.framebuffer_generation),
            "framebuffer-dirty-region->framebuffer-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("event", dirty.recorded_at_event, 1),
            "framebuffer-dirty-region->event",
            "historical",
            event,
        ));
    }
    for log in &package.semantic.display_event_logs {
        let event = Some(log.recorded_at_event);
        let from = object_ref_json("display-event-log", log.id, log.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", log.owner_store, log.owner_store_generation),
            "display-event-log->owner-store",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-dirty-region",
                log.framebuffer_dirty_region,
                log.framebuffer_dirty_region_generation,
            ),
            "display-event-log->framebuffer-dirty-region",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "display-capability",
                log.display_capability,
                log.display_capability_generation,
            ),
            "display-event-log->display-capability",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("display-object", log.display, log.display_generation),
            "display-event-log->display-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("framebuffer-object", log.framebuffer, log.framebuffer_generation),
            "display-event-log->framebuffer-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("event", log.recorded_at_event, 1),
            "display-event-log->event",
            "historical",
            event,
        ));
    }
    for cleanup in &package.semantic.display_cleanups {
        let event = Some(cleanup.completed_at_event);
        let from = object_ref_json("display-cleanup", cleanup.id, cleanup.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", cleanup.owner_store, cleanup.owner_store_generation),
            "display-cleanup->owner-store",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "display-capability",
                cleanup.display_capability,
                cleanup.display_capability_generation,
            ),
            "display-cleanup->display-capability",
            "cleanup-effect",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("display-object", cleanup.display, cleanup.display_generation),
            "display-cleanup->display-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-object",
                cleanup.framebuffer,
                cleanup.framebuffer_generation,
            ),
            "display-cleanup->framebuffer-object",
            "historical",
            event,
        ));
        for mapping in &cleanup.unmapped_framebuffer_mappings {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json(&mapping.kind, mapping.id, mapping.generation),
                "display-cleanup->unmapped-framebuffer-mapping",
                "cleanup-effect",
                event,
            ));
        }
        for lease in &cleanup.released_framebuffer_window_leases {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json(&lease.kind, lease.id, lease.generation),
                "display-cleanup->released-framebuffer-window-lease",
                "cleanup-effect",
                event,
            ));
        }
        for display_capability in &cleanup.revoked_display_capabilities {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json(
                    &display_capability.kind,
                    display_capability.id,
                    display_capability.generation,
                ),
                "display-cleanup->revoked-display-capability",
                "cleanup-effect",
                event,
            ));
        }
        for capability in &cleanup.revoked_capabilities {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json(&capability.kind, capability.id, capability.generation),
                "display-cleanup->revoked-capability",
                "cleanup-effect",
                event,
            ));
        }
    }
    for barrier in &package.semantic.display_snapshot_barriers {
        let event = Some(barrier.validated_at_event);
        let from = object_ref_json("display-snapshot-barrier", barrier.id, barrier.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", barrier.owner_store, barrier.owner_store_generation),
            "display-snapshot-barrier->owner-store",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("display-object", barrier.display, barrier.display_generation),
            "display-snapshot-barrier->display-object",
            "historical",
            event,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "framebuffer-object",
                barrier.framebuffer,
                barrier.framebuffer_generation,
            ),
            "display-snapshot-barrier->framebuffer-object",
            "historical",
            event,
        ));
        if let (Some(cleanup), Some(cleanup_generation)) =
            (barrier.display_cleanup, barrier.display_cleanup_generation)
        {
            edges.push(graph_edge(
                from,
                object_ref_json("display-cleanup", cleanup, cleanup_generation),
                "display-snapshot-barrier->display-cleanup",
                "historical",
                event,
            ));
        }
    }
    for frame in &package.semantic.display_panic_last_frames {
        let event = Some(frame.recorded_at_event);
        let from = object_ref_json("display-panic-last-frame", frame.id, frame.generation);
        for (relation, to) in [
            (
                "display-panic-last-frame->owner-store",
                object_ref_json("store", frame.owner_store, frame.owner_store_generation),
            ),
            (
                "display-panic-last-frame->display-object",
                object_ref_json("display-object", frame.display, frame.display_generation),
            ),
            (
                "display-panic-last-frame->framebuffer-object",
                object_ref_json(
                    "framebuffer-object",
                    frame.framebuffer,
                    frame.framebuffer_generation,
                ),
            ),
            (
                "display-panic-last-frame->snapshot-barrier",
                object_ref_json(
                    "display-snapshot-barrier",
                    frame.display_snapshot_barrier,
                    frame.display_snapshot_barrier_generation,
                ),
            ),
            (
                "display-panic-last-frame->display-event-log",
                object_ref_json(
                    "display-event-log",
                    frame.display_event_log,
                    frame.display_event_log_generation,
                ),
            ),
            (
                "display-panic-last-frame->framebuffer-write",
                object_ref_json(
                    "framebuffer-write",
                    frame.framebuffer_write,
                    frame.framebuffer_write_generation,
                ),
            ),
            (
                "display-panic-last-frame->framebuffer-flush-region",
                object_ref_json(
                    "framebuffer-flush-region",
                    frame.framebuffer_flush_region,
                    frame.framebuffer_flush_region_generation,
                ),
            ),
        ] {
            edges.push(graph_edge(from.clone(), to, relation, "historical", event));
        }
    }
    for benchmark in &package.semantic.framebuffer_benchmarks {
        let event = Some(benchmark.recorded_at_event);
        let from = object_ref_json("framebuffer-benchmark", benchmark.id, benchmark.generation);
        for (relation, to) in [
            (
                "framebuffer-benchmark->owner-store",
                object_ref_json("store", benchmark.owner_store, benchmark.owner_store_generation),
            ),
            (
                "framebuffer-benchmark->display-object",
                object_ref_json("display-object", benchmark.display, benchmark.display_generation),
            ),
            (
                "framebuffer-benchmark->framebuffer-object",
                object_ref_json(
                    "framebuffer-object",
                    benchmark.framebuffer,
                    benchmark.framebuffer_generation,
                ),
            ),
            (
                "framebuffer-benchmark->display-capability",
                object_ref_json(
                    "display-capability",
                    benchmark.display_capability,
                    benchmark.display_capability_generation,
                ),
            ),
            (
                "framebuffer-benchmark->framebuffer-write",
                object_ref_json(
                    "framebuffer-write",
                    benchmark.framebuffer_write,
                    benchmark.framebuffer_write_generation,
                ),
            ),
            (
                "framebuffer-benchmark->framebuffer-flush-region",
                object_ref_json(
                    "framebuffer-flush-region",
                    benchmark.framebuffer_flush_region,
                    benchmark.framebuffer_flush_region_generation,
                ),
            ),
            (
                "framebuffer-benchmark->display-event-log",
                object_ref_json(
                    "display-event-log",
                    benchmark.display_event_log,
                    benchmark.display_event_log_generation,
                ),
            ),
            (
                "framebuffer-benchmark->display-snapshot-barrier",
                object_ref_json(
                    "display-snapshot-barrier",
                    benchmark.display_snapshot_barrier,
                    benchmark.display_snapshot_barrier_generation,
                ),
            ),
        ] {
            edges.push(graph_edge(from.clone(), to, relation, "historical", event));
        }
    }
}
