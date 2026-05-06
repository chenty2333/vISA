use super::super::*;

pub(super) fn push_device_runtime_history_edges(
    package: &MigrationPackageManifest,
    edges: &mut Vec<serde_json::Value>,
) {
    for device in &package.semantic.device_objects {
        edges.push(graph_edge(
            object_ref_json("device", device.id, device.generation),
            object_ref_json("resource", device.resource, device.resource_generation),
            "device-resource",
            "live",
            Some(device.recorded_at_event),
        ));
    }
    for queue in &package.semantic.queue_objects {
        edges.push(graph_edge(
            object_ref_json("queue", queue.id, queue.generation),
            object_ref_json("device", queue.device, queue.device_generation),
            "queue-device",
            "live",
            Some(queue.recorded_at_event),
        ));
    }
    for descriptor in &package.semantic.descriptor_objects {
        edges.push(graph_edge(
            object_ref_json("descriptor", descriptor.id, descriptor.generation),
            object_ref_json("queue", descriptor.queue, descriptor.queue_generation),
            "descriptor-queue",
            "live",
            Some(descriptor.recorded_at_event),
        ));
    }
    for dma_buffer in &package.semantic.dma_buffer_objects {
        edges.push(graph_edge(
            object_ref_json("dma-buffer", dma_buffer.id, dma_buffer.generation),
            object_ref_json("descriptor", dma_buffer.descriptor, dma_buffer.descriptor_generation),
            "dma-buffer-descriptor",
            "live",
            Some(dma_buffer.recorded_at_event),
        ));
        edges.push(graph_edge(
            object_ref_json("dma-buffer", dma_buffer.id, dma_buffer.generation),
            object_ref_json("resource", dma_buffer.resource, dma_buffer.resource_generation),
            "dma-buffer-resource",
            "live",
            Some(dma_buffer.recorded_at_event),
        ));
    }
    for mmio_region in &package.semantic.mmio_region_objects {
        edges.push(graph_edge(
            object_ref_json("mmio-region", mmio_region.id, mmio_region.generation),
            object_ref_json("device", mmio_region.device, mmio_region.device_generation),
            "mmio-region-device",
            "live",
            Some(mmio_region.recorded_at_event),
        ));
        edges.push(graph_edge(
            object_ref_json("mmio-region", mmio_region.id, mmio_region.generation),
            object_ref_json("resource", mmio_region.resource, mmio_region.resource_generation),
            "mmio-region-resource",
            "live",
            Some(mmio_region.recorded_at_event),
        ));
    }
    for irq_line in &package.semantic.irq_line_objects {
        edges.push(graph_edge(
            object_ref_json("irq-line", irq_line.id, irq_line.generation),
            object_ref_json("device", irq_line.device, irq_line.device_generation),
            "irq-line-device",
            "live",
            Some(irq_line.recorded_at_event),
        ));
        edges.push(graph_edge(
            object_ref_json("irq-line", irq_line.id, irq_line.generation),
            object_ref_json("resource", irq_line.resource, irq_line.resource_generation),
            "irq-line-resource",
            "live",
            Some(irq_line.recorded_at_event),
        ));
    }
    for irq_event in &package.semantic.irq_events {
        let from = object_ref_json("irq-event", irq_event.id, irq_event.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("irq-line", irq_event.irq_line, irq_event.irq_line_generation),
            "irq-event-line",
            "historical",
            Some(irq_event.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("device", irq_event.device, irq_event.device_generation),
            "irq-event-device",
            "historical",
            Some(irq_event.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("store", irq_event.driver_store, irq_event.driver_store_generation),
            "irq-event-driver-store",
            "historical",
            Some(irq_event.recorded_at_event),
        ));
    }
    for device_capability in &package.semantic.device_capabilities {
        let from = object_ref_json(
            "device-capability",
            device_capability.id,
            device_capability.generation,
        );
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "store",
                device_capability.driver_store,
                device_capability.driver_store_generation,
            ),
            "device-capability-driver-store",
            "live",
            Some(device_capability.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_manifest_json(&device_capability.target),
            "device-capability-target",
            "live",
            Some(device_capability.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "capability",
                device_capability.capability,
                device_capability.capability_generation,
            ),
            "device-capability-ledger",
            "live",
            Some(device_capability.recorded_at_event),
        ));
    }
    for binding in &package.semantic.driver_store_bindings {
        let from = object_ref_json("driver-store-binding", binding.id, binding.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", binding.driver_store, binding.driver_store_generation),
            "driver-store-binding-store",
            "live",
            Some(binding.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("device", binding.device, binding.device_generation),
            "driver-store-binding-device",
            "live",
            Some(binding.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "device-capability",
                binding.device_capability,
                binding.device_capability_generation,
            ),
            "driver-store-binding-device-capability",
            "live",
            Some(binding.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("capability", binding.capability, binding.capability_generation),
            "driver-store-binding-ledger",
            "live",
            Some(binding.recorded_at_event),
        ));
    }
    for io_wait in &package.semantic.io_waits {
        let from = object_ref_json("io-wait", io_wait.id, io_wait.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("wait-token", io_wait.wait, io_wait.wait_generation),
            "io-wait-token",
            "historical",
            Some(io_wait.created_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", io_wait.driver_store, io_wait.driver_store_generation),
            "io-wait-driver-store",
            "historical",
            Some(io_wait.created_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("device", io_wait.device, io_wait.device_generation),
            "io-wait-device",
            "historical",
            Some(io_wait.created_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "driver-store-binding",
                io_wait.driver_binding,
                io_wait.driver_binding_generation,
            ),
            "io-wait-driver-binding",
            "historical",
            Some(io_wait.created_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_manifest_json(&io_wait.blocker),
            "io-wait-blocker",
            "historical",
            Some(io_wait.created_at_event),
        ));
        if let (Some(irq_event), Some(irq_event_generation)) =
            (io_wait.completion_irq_event, io_wait.completion_irq_event_generation)
        {
            edges.push(graph_edge(
                from,
                object_ref_json("irq-event", irq_event, irq_event_generation),
                "io-wait-completion-irq",
                "historical",
                io_wait.completed_at_event,
            ));
        }
    }
    for cleanup in &package.semantic.io_cleanups {
        let from = object_ref_json("io-cleanup", cleanup.id, cleanup.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", cleanup.driver_store, cleanup.driver_store_generation),
            "io-cleanup-driver-store",
            "historical",
            Some(cleanup.started_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("device", cleanup.device, cleanup.device_generation),
            "io-cleanup-device",
            "historical",
            Some(cleanup.started_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "driver-store-binding",
                cleanup.driver_binding,
                cleanup.driver_binding_generation,
            ),
            "io-cleanup-driver-binding",
            "historical",
            Some(cleanup.started_at_event),
        ));
        for io_wait in &cleanup.cancelled_io_waits {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(io_wait),
                "cancelled-io-wait",
                "cleanup-effect",
                Some(cleanup.completed_at_event),
            ));
        }
        for device_capability in &cleanup.revoked_device_capabilities {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(device_capability),
                "revoked-device-capability",
                "cleanup-effect",
                Some(cleanup.completed_at_event),
            ));
        }
        for capability in &cleanup.revoked_capabilities {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(capability),
                "revoked-capability",
                "cleanup-effect",
                Some(cleanup.completed_at_event),
            ));
        }
        for dma_buffer in &cleanup.released_dma_buffers {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(dma_buffer),
                "released-dma-buffer",
                "cleanup-effect",
                Some(cleanup.completed_at_event),
            ));
        }
        for mmio_region in &cleanup.released_mmio_regions {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(mmio_region),
                "released-mmio-region",
                "cleanup-effect",
                Some(cleanup.completed_at_event),
            ));
        }
        for irq_line in &cleanup.released_irq_lines {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(irq_line),
                "released-irq-line",
                "cleanup-effect",
                Some(cleanup.completed_at_event),
            ));
        }
    }
    for fault in &package.semantic.io_fault_injections {
        let from = object_ref_json("io-fault-injection", fault.id, fault.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", fault.driver_store, fault.driver_store_generation),
            "io-fault-driver-store",
            "historical",
            Some(fault.injected_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("device", fault.device, fault.device_generation),
            "io-fault-device",
            "historical",
            Some(fault.injected_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "driver-store-binding",
                fault.driver_binding,
                fault.driver_binding_generation,
            ),
            "io-fault-driver-binding",
            "historical",
            Some(fault.injected_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_manifest_json(&fault.target),
            "io-fault-target",
            "historical",
            Some(fault.injected_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json("io-cleanup", fault.cleanup, fault.cleanup_generation),
            "triggered-cleanup",
            "cleanup-effect",
            Some(fault.injected_at_event),
        ));
    }
    for report in &package.semantic.io_validation_reports {
        let from = object_ref_json("io-validation-report", report.id, report.generation);
        for violation in &report.violations {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(&violation.subject),
                &violation.relation,
                "historical",
                Some(report.validated_at_event),
            ));
        }
    }
    for resume in &package.semantic.activation_resumes {
        let from = object_ref_json("activation-resume", resume.id, resume.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "scheduler-decision",
                resume.scheduler_decision,
                resume.scheduler_decision_generation,
            ),
            "consumed-decision",
            "historical",
            Some(resume.resumed_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("activation", resume.activation, resume.activation_generation_before),
            "resumed-from",
            "historical",
            Some(resume.resumed_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("activation", resume.activation, resume.activation_generation_after),
            "resumed-to",
            "historical",
            Some(resume.resumed_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("runnable-queue", resume.queue, resume.queue_generation),
            "dequeued-from",
            "historical",
            Some(resume.resumed_at_event),
        ));
        if let (Some(context), Some(generation)) = (resume.context, resume.context_generation_after)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("activation-context", context, generation),
                "restored-context",
                "historical",
                Some(resume.resumed_at_event),
            ));
        }
        if let (Some(saved), Some(generation)) =
            (resume.saved_context, resume.saved_context_generation)
        {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("saved-context", saved, generation),
                "restored-saved-context",
                "historical",
                Some(resume.resumed_at_event),
            ));
        }
        if let Some(saved_vector_state) = &resume.saved_vector_state {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(saved_vector_state),
                "restores-saved-vector-state",
                "historical",
                resume.vector_restored_at_event.or(Some(resume.resumed_at_event)),
            ));
        }
        if let Some(restored_vector_state) = &resume.restored_vector_state {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(restored_vector_state),
                "restored-vector-state",
                "historical",
                resume.vector_restored_at_event.or(Some(resume.resumed_at_event)),
            ));
        }
    }
    for activation_wait in &package.semantic.activation_waits {
        let from =
            object_ref_json("activation-wait", activation_wait.id, activation_wait.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "activation",
                activation_wait.activation,
                activation_wait.activation_generation_before,
            ),
            "blocked-from",
            "historical",
            Some(activation_wait.blocked_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "activation",
                activation_wait.activation,
                activation_wait.activation_generation_after_block,
            ),
            "blocked-to",
            "historical",
            Some(activation_wait.blocked_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("wait-token", activation_wait.wait, activation_wait.wait_generation),
            "created-wait",
            "historical",
            Some(activation_wait.blocked_at_event),
        ));
        if let Some(cancel_generation) = activation_wait.activation_generation_after_cancel {
            edges.push(graph_edge(
                from,
                object_ref_json("activation", activation_wait.activation, cancel_generation),
                "cancelled-to",
                "historical",
                activation_wait.completed_at_event,
            ));
        }
    }
    for cleanup in &package.semantic.activation_cleanups {
        let from = object_ref_json("activation-cleanup", cleanup.id, cleanup.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", cleanup.store, cleanup.target_store_generation),
            "cleanup-target",
            "historical",
            Some(cleanup.started_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", cleanup.store, cleanup.result_store_generation),
            "marked-dead",
            "cleanup-effect",
            Some(cleanup.completed_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("activation", cleanup.activation, cleanup.activation_generation_before),
            "sealed-from",
            "historical",
            Some(cleanup.started_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("activation", cleanup.activation, cleanup.activation_generation_after),
            "sealed-to",
            "cleanup-effect",
            Some(cleanup.completed_at_event),
        ));
        if let (Some(wait), Some(wait_generation)) = (cleanup.wait, cleanup.wait_generation) {
            edges.push(graph_edge(
                from,
                object_ref_json("wait-token", wait, wait_generation),
                "cancelled-wait",
                "cleanup-effect",
                Some(cleanup.completed_at_event),
            ));
        }
    }
    for sample in &package.semantic.preemption_latency_samples {
        let from = object_ref_json("preemption-latency", sample.id, sample.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "timer-interrupt",
                sample.timer_interrupt,
                sample.timer_interrupt_generation,
            ),
            "measured-from-timer",
            "historical",
            Some(sample.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("preemption", sample.preemption, sample.preemption_generation),
            "measured-preemption",
            "historical",
            Some(sample.recorded_at_event),
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json(
                "scheduler-decision",
                sample.scheduler_decision,
                sample.scheduler_decision_generation,
            ),
            "measured-decision",
            "historical",
            Some(sample.recorded_at_event),
        ));
        edges.push(graph_edge(
            from,
            object_ref_json(
                "activation-resume",
                sample.activation_resume,
                sample.activation_resume_generation,
            ),
            "measured-resume",
            "historical",
            Some(sample.recorded_at_event),
        ));
    }
    for trap in &package.semantic.trap_records {
        let from = object_ref_json("trap", trap.id, trap.generation);
        if let Some(store) = trap.store {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("store", store, trap.store_generation.unwrap_or(0)),
                "recorded",
                "historical",
                None,
            ));
        }
        if let Some(activation) = trap.activation {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("activation", activation, trap.activation_generation.unwrap_or(0)),
                "recorded",
                "historical",
                None,
            ));
        }
        if let Some(code_object) = trap.code_object {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("code-object", code_object, trap.code_generation.unwrap_or(0)),
                "recorded",
                "historical",
                None,
            ));
        }
        if let Some(artifact) = trap.artifact {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("artifact", artifact, trap.artifact_generation.unwrap_or(1)),
                "recorded",
                "historical",
                None,
            ));
        }
    }
    for hostcall in &package.semantic.hostcall_trace {
        let from = object_ref_json("hostcall", hostcall.id, hostcall.generation);
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("activation", hostcall.activation, hostcall.activation_generation),
            "recorded",
            "historical",
            None,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", hostcall.store, hostcall.store_generation),
            "recorded",
            "historical",
            None,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("code-object", hostcall.code_object, hostcall.code_generation),
            "recorded",
            "historical",
            None,
        ));
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("artifact", hostcall.artifact, hostcall.artifact_generation),
            "recorded",
            "historical",
            None,
        ));
        if let Some(trap) = hostcall.trap_out {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("trap", trap, hostcall.trap_generation_out.unwrap_or(0)),
                "caused",
                "historical",
                None,
            ));
        }
        if let Some(wait) = hostcall.wait_token_out {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json(
                    "wait-token",
                    wait,
                    hostcall.wait_token_generation_out.unwrap_or(0),
                ),
                "caused",
                "historical",
                None,
            ));
        }
    }
    for cleanup in &package.semantic.cleanup_transactions {
        let from = object_ref_json("cleanup", cleanup.id, cleanup.generation);
        let target_generation = if cleanup.target_store_generation == 0 {
            cleanup.store_generation
        } else {
            cleanup.target_store_generation
        };
        edges.push(graph_edge(
            from.clone(),
            object_ref_json("store", cleanup.store, target_generation),
            "killed",
            "cleanup-effect",
            Some(cleanup.started_at),
        ));
        if let Some(activation) = cleanup.activation {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json(
                    "activation",
                    activation,
                    cleanup.activation_generation.unwrap_or(0),
                ),
                "released",
                "cleanup-effect",
                cleanup.finished_at,
            ));
        }
        if let Some(code) = cleanup.code_object {
            edges.push(graph_edge(
                from.clone(),
                object_ref_json("code-object", code, cleanup.code_generation.unwrap_or(0)),
                "unbound",
                "cleanup-effect",
                cleanup.finished_at,
            ));
        }
        for capability in &cleanup.revoked_capability_refs {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(capability),
                "revoked",
                "cleanup-effect",
                cleanup.finished_at,
            ));
        }
        for effect in &cleanup.effects {
            edges.push(graph_edge(
                from.clone(),
                object_ref_manifest_json(&effect.target),
                &effect.kind,
                "cleanup-effect",
                Some(effect.event_seq),
            ));
        }
    }
}
