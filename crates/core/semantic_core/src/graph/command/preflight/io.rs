use super::*;

impl SemanticGraph {
    pub(super) fn preflight_io_command(
        &self,
        command: &SemanticCommand,
    ) -> Result<(), CommandError> {
        match command {
            SemanticCommand::RecordQueueObject {
                queue,
                name,
                role,
                queue_index,
                depth,
                device,
                device_generation,
                ..
            } => self
                .validate_queue_object(
                    *queue,
                    name,
                    *role,
                    *queue_index,
                    *depth,
                    *device,
                    *device_generation,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordDescriptorObject {
                descriptor,
                queue,
                queue_generation,
                slot,
                access,
                length,
                ..
            } => self
                .validate_descriptor_object(
                    *descriptor,
                    *queue,
                    *queue_generation,
                    *slot,
                    *access,
                    *length,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordDmaBufferObject {
                dma_buffer,
                descriptor,
                descriptor_generation,
                resource,
                resource_generation,
                access,
                length,
                ..
            } => self
                .validate_dma_buffer_object(
                    *dma_buffer,
                    *descriptor,
                    *descriptor_generation,
                    *resource,
                    *resource_generation,
                    *access,
                    *length,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordMmioRegionObject {
                mmio_region,
                device,
                device_generation,
                resource,
                resource_generation,
                region_index,
                offset,
                length,
                access,
                ..
            } => self
                .validate_mmio_region_object(
                    *mmio_region,
                    *device,
                    *device_generation,
                    *resource,
                    *resource_generation,
                    *region_index,
                    *offset,
                    *length,
                    *access,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordIrqLineObject {
                irq_line,
                device,
                device_generation,
                resource,
                resource_generation,
                irq_number,
                trigger,
                polarity,
                ..
            } => self
                .validate_irq_line_object(
                    *irq_line,
                    *device,
                    *device_generation,
                    *resource,
                    *resource_generation,
                    *irq_number,
                    *trigger,
                    *polarity,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordIrqEvent {
                irq_event,
                irq_line,
                irq_line_generation,
                device,
                device_generation,
                driver_store,
                driver_store_generation,
                sequence,
                ..
            } => self
                .validate_irq_event(
                    *irq_event,
                    *irq_line,
                    *irq_line_generation,
                    *device,
                    *device_generation,
                    *driver_store,
                    *driver_store_generation,
                    *sequence,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordDeviceCapability {
                device_capability,
                driver_store,
                driver_store_generation,
                target,
                class,
                operation,
                handle,
                ..
            } => self
                .validate_device_capability(
                    *device_capability,
                    *driver_store,
                    *driver_store_generation,
                    *target,
                    *class,
                    operation,
                    handle,
                )
                .map(|_| ())
                .map_err(CommandError::precondition),
            SemanticCommand::BindDriverStore {
                binding,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                device_capability,
                device_capability_generation,
                ..
            } => self
                .validate_driver_store_binding(
                    *binding,
                    *driver_store,
                    *driver_store_generation,
                    *device,
                    *device_generation,
                    *device_capability,
                    *device_capability_generation,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::RecordIoWait {
                io_wait,
                wait,
                wait_generation,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                driver_binding,
                driver_binding_generation,
                blocker,
                ..
            } => self
                .validate_io_wait(
                    *io_wait,
                    *wait,
                    *wait_generation,
                    *driver_store,
                    *driver_store_generation,
                    *device,
                    *device_generation,
                    *driver_binding,
                    *driver_binding_generation,
                    *blocker,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::ResolveIoWait {
                io_wait,
                io_wait_generation,
                irq_event,
                irq_event_generation,
                ..
            } => {
                let Some(record) = self.domains.io.io_waits.iter().find(|record| {
                    record.id == *io_wait
                        && record.generation == *io_wait_generation
                        && record.state == IoWaitState::Pending
                }) else {
                    return Err(CommandError::precondition(
                        "io wait generation is missing or not pending",
                    ));
                };
                let Some(irq_record) = self.irq_events.iter().find(|irq| {
                    irq.id == *irq_event
                        && irq.generation == *irq_event_generation
                        && irq.state == IrqEventState::Recorded
                }) else {
                    return Err(CommandError::precondition(
                        "io wait irq event generation is missing",
                    ));
                };
                if record.blocker.kind == ContractObjectKind::IrqLineObject
                    && (record.blocker.id != irq_record.irq_line
                        || record.blocker.generation != irq_record.irq_line_generation)
                {
                    return Err(CommandError::precondition(
                        "io wait irq line attribution mismatch",
                    ));
                }
                if !self.domains.wait.waits.iter().any(|wait| {
                    wait.id == record.wait
                        && wait.generation == record.wait_generation
                        && wait.state == WaitState::Pending
                }) {
                    return Err(CommandError::precondition(
                        "io wait token generation is missing or not pending",
                    ));
                }
                if irq_record.device == record.device
                    && irq_record.device_generation == record.device_generation
                    && irq_record.driver_store == record.driver_store
                    && irq_record.driver_store_generation == record.driver_store_generation
                {
                    Ok(())
                } else {
                    Err(CommandError::precondition("io wait irq event attribution mismatch"))
                }
            }
            SemanticCommand::CancelIoWait { io_wait, io_wait_generation, reason, .. } => {
                if !matches!(
                    reason,
                    WaitCancelReason::DeviceFault
                        | WaitCancelReason::CapabilityRevoked
                        | WaitCancelReason::ResourceDropped
                        | WaitCancelReason::GenerationMismatch
                ) {
                    return Err(CommandError::precondition(
                        "io wait cancellation reason is not an io reason",
                    ));
                }
                if self.domains.io.io_waits.iter().any(|record| {
                    record.id == *io_wait
                        && record.generation == *io_wait_generation
                        && record.state == IoWaitState::Pending
                }) {
                    Ok(())
                } else {
                    Err(CommandError::precondition("io wait generation is missing or not pending"))
                }
            }
            SemanticCommand::CleanupIoDriver {
                cleanup,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                driver_binding,
                driver_binding_generation,
                reason,
                ..
            } => self
                .validate_io_cleanup(
                    *cleanup,
                    *driver_store,
                    *driver_store_generation,
                    *device,
                    *device_generation,
                    *driver_binding,
                    *driver_binding_generation,
                    reason,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::InjectIoFault {
                fault,
                cleanup,
                driver_store,
                driver_store_generation,
                device,
                device_generation,
                driver_binding,
                driver_binding_generation,
                target,
                kind,
                ..
            } => self
                .validate_io_fault_injection(
                    *fault,
                    *driver_store,
                    *driver_store_generation,
                    *device,
                    *device_generation,
                    *driver_binding,
                    *driver_binding_generation,
                    *target,
                    *cleanup,
                    *kind,
                )
                .map_err(CommandError::precondition),
            SemanticCommand::ValidateIoRuntime { report, .. } => {
                self.validate_io_validation_report(*report).map_err(CommandError::precondition)
            }
            _ => unreachable!("preflight handler called with wrong command domain"),
        }
    }
}
