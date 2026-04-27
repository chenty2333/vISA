use super::*;

impl SemanticGraph {
    pub(crate) fn validate_io_validation_report(
        &self,
        report: IoValidationReportId,
    ) -> Result<(), &'static str> {
        if report == 0 {
            return Err("io validation report id=0 is invalid");
        }
        if self
            .io_validation_reports
            .iter()
            .any(|record| record.id == report)
        {
            return Err("io validation report already exists");
        }
        Ok(())
    }

    pub fn record_io_validation_report_with_id(
        &mut self,
        report: IoValidationReportId,
        note: &str,
    ) -> bool {
        if self.validate_io_validation_report(report).is_err() {
            return false;
        }
        let violations = self.build_io_validation_violations();
        let state = if violations.is_empty() {
            IoValidationReportState::Passed
        } else {
            IoValidationReportState::Failed
        };
        let generation = 1;
        self.next_io_validation_report_id = self.next_io_validation_report_id.max(report + 1);
        let event_log_cursor = self.event_log.cursor();
        let validated_at_event = self.event_log.push(
            "io",
            EventKind::IoValidationReportRecorded {
                report,
                ok: violations.is_empty(),
                violation_count: violations.len(),
                device_count: self.device_objects.len(),
                dma_buffer_count: self.dma_buffer_objects.len(),
                irq_event_count: self.irq_events.len(),
                cleanup_count: self.io_cleanups.len(),
                fault_injection_count: self.io_fault_injections.len(),
                generation,
            },
        );
        self.io_validation_reports.push(IoValidationReportRecord {
            id: report,
            generation,
            state,
            validated_at_event,
            event_log_cursor,
            observed_device_count: self.device_objects.len(),
            observed_queue_count: self.queue_objects.len(),
            observed_descriptor_count: self.descriptor_objects.len(),
            observed_dma_buffer_count: self.dma_buffer_objects.len(),
            observed_mmio_region_count: self.mmio_region_objects.len(),
            observed_irq_line_count: self.irq_line_objects.len(),
            observed_irq_event_count: self.irq_events.len(),
            observed_device_capability_count: self.device_capabilities.len(),
            observed_driver_binding_count: self.driver_store_bindings.len(),
            observed_io_wait_count: self.io_waits.len(),
            observed_io_cleanup_count: self.io_cleanups.len(),
            observed_io_fault_injection_count: self.io_fault_injections.len(),
            violations,
            note: note.to_string(),
        });
        true
    }

    pub fn io_validation_reports(&self) -> &[IoValidationReportRecord] {
        &self.io_validation_reports
    }

    pub fn io_validation_report_count(&self) -> usize {
        self.io_validation_reports.len()
    }

    pub fn build_io_validation_violations(&self) -> Vec<IoValidationViolationRecord> {
        let mut violations = Vec::new();
        self.validate_io_devices(&mut violations);
        self.validate_io_queues(&mut violations);
        self.validate_io_descriptors(&mut violations);
        self.validate_io_dma_buffers(&mut violations);
        self.validate_io_mmio_regions(&mut violations);
        self.validate_io_irq_lines(&mut violations);
        self.validate_io_irq_events(&mut violations);
        self.validate_io_device_capabilities(&mut violations);
        self.validate_io_driver_bindings(&mut violations);
        self.validate_io_wait_records(&mut violations);
        self.validate_io_cleanup_records(&mut violations);
        self.validate_io_fault_injection_records(&mut violations);
        violations
    }

    fn push_io_validation_violation(
        violations: &mut Vec<IoValidationViolationRecord>,
        code: IoValidationViolationCode,
        subject: ContractObjectRef,
        relation: &str,
        message: &str,
    ) {
        violations.push(IoValidationViolationRecord {
            code,
            subject,
            relation: relation.to_string(),
            message: message.to_string(),
        });
    }

    fn validate_io_devices(&self, violations: &mut Vec<IoValidationViolationRecord>) {
        for device in &self.device_objects {
            if device.id == 0 || device.generation == 0 || device.name.is_empty() {
                Self::push_io_validation_violation(
                    violations,
                    IoValidationViolationCode::StaleGeneration,
                    device.object_ref(),
                    "device.identity",
                    "device identity must be nonzero and named",
                );
            }
            if !self.resource_exists(device.resource, device.resource_generation) {
                Self::push_io_validation_violation(
                    violations,
                    IoValidationViolationCode::MissingResource,
                    device.object_ref(),
                    "device->resource",
                    "device resource generation is missing",
                );
            }
        }
    }

    fn validate_io_queues(&self, violations: &mut Vec<IoValidationViolationRecord>) {
        for queue in &self.queue_objects {
            if !self.device_exists(queue.device, queue.device_generation) {
                Self::push_io_validation_violation(
                    violations,
                    IoValidationViolationCode::MissingDevice,
                    queue.object_ref(),
                    "queue->device",
                    "queue device generation is missing",
                );
            }
        }
    }

    fn validate_io_descriptors(&self, violations: &mut Vec<IoValidationViolationRecord>) {
        for descriptor in &self.descriptor_objects {
            if !self.queue_exists(descriptor.queue, descriptor.queue_generation) {
                Self::push_io_validation_violation(
                    violations,
                    IoValidationViolationCode::MissingQueue,
                    descriptor.object_ref(),
                    "descriptor->queue",
                    "descriptor queue generation is missing",
                );
            }
            if descriptor.length == 0 {
                Self::push_io_validation_violation(
                    violations,
                    IoValidationViolationCode::StaleGeneration,
                    descriptor.object_ref(),
                    "descriptor.length",
                    "descriptor length must be nonzero",
                );
            }
        }
    }

    fn validate_io_dma_buffers(&self, violations: &mut Vec<IoValidationViolationRecord>) {
        for dma in &self.dma_buffer_objects {
            if !self.descriptor_exists(dma.descriptor, dma.descriptor_generation) {
                Self::push_io_validation_violation(
                    violations,
                    IoValidationViolationCode::MissingDescriptor,
                    dma.object_ref(),
                    "dma-buffer->descriptor",
                    "dma buffer descriptor generation is missing",
                );
            }
            if !self.resource_exists(dma.resource, dma.resource_generation) {
                Self::push_io_validation_violation(
                    violations,
                    IoValidationViolationCode::MissingResource,
                    dma.object_ref(),
                    "dma-buffer->resource",
                    "dma buffer resource generation is missing",
                );
            }
            if dma.state == DmaBufferObjectState::Registered
                && self.device_for_dma_buffer(dma).is_none()
            {
                Self::push_io_validation_violation(
                    violations,
                    IoValidationViolationCode::StaleGeneration,
                    dma.object_ref(),
                    "dma-buffer->device-chain",
                    "dma buffer cannot be traced through descriptor and queue to a device",
                );
            }
        }
    }

    fn validate_io_mmio_regions(&self, violations: &mut Vec<IoValidationViolationRecord>) {
        for mmio in &self.mmio_region_objects {
            if !self.device_exists(mmio.device, mmio.device_generation) {
                Self::push_io_validation_violation(
                    violations,
                    IoValidationViolationCode::MissingDevice,
                    mmio.object_ref(),
                    "mmio-region->device",
                    "MMIO region device generation is missing",
                );
            }
            if !self.resource_exists(mmio.resource, mmio.resource_generation) {
                Self::push_io_validation_violation(
                    violations,
                    IoValidationViolationCode::MissingResource,
                    mmio.object_ref(),
                    "mmio-region->resource",
                    "MMIO region resource generation is missing",
                );
            }
        }
    }

    fn validate_io_irq_lines(&self, violations: &mut Vec<IoValidationViolationRecord>) {
        for irq in &self.irq_line_objects {
            if !self.device_exists(irq.device, irq.device_generation) {
                Self::push_io_validation_violation(
                    violations,
                    IoValidationViolationCode::MissingDevice,
                    irq.object_ref(),
                    "irq-line->device",
                    "IRQ line device generation is missing",
                );
            }
            if !self.resource_exists(irq.resource, irq.resource_generation) {
                Self::push_io_validation_violation(
                    violations,
                    IoValidationViolationCode::MissingResource,
                    irq.object_ref(),
                    "irq-line->resource",
                    "IRQ line resource generation is missing",
                );
            }
        }
    }

    fn validate_io_irq_events(&self, violations: &mut Vec<IoValidationViolationRecord>) {
        for irq_event in &self.irq_events {
            let subject = irq_event.object_ref();
            let Some(irq_line) = self.irq_line_objects.iter().find(|record| {
                record.id == irq_event.irq_line
                    && record.generation == irq_event.irq_line_generation
            }) else {
                Self::push_io_validation_violation(
                    violations,
                    IoValidationViolationCode::StaleGeneration,
                    subject,
                    "irq-event->irq-line",
                    "IRQ event line generation is missing",
                );
                continue;
            };
            if irq_line.device != irq_event.device
                || irq_line.device_generation != irq_event.device_generation
                || irq_line.irq_number != irq_event.irq_number
            {
                Self::push_io_validation_violation(
                    violations,
                    IoValidationViolationCode::StaleGeneration,
                    subject,
                    "irq-event->device",
                    "IRQ event attribution does not match line device generation",
                );
            }
            if !self.store_exists(irq_event.driver_store, irq_event.driver_store_generation) {
                Self::push_io_validation_violation(
                    violations,
                    IoValidationViolationCode::MissingStore,
                    subject,
                    "irq-event->driver-store",
                    "IRQ event driver store generation is missing",
                );
            }
        }
    }

    fn validate_io_device_capabilities(&self, violations: &mut Vec<IoValidationViolationRecord>) {
        for device_capability in &self.device_capabilities {
            let subject = device_capability.object_ref();
            if !self.store_exists(
                device_capability.driver_store,
                device_capability.driver_store_generation,
            ) {
                Self::push_io_validation_violation(
                    violations,
                    IoValidationViolationCode::MissingStore,
                    subject,
                    "device-capability->driver-store",
                    "device capability driver store generation is missing",
                );
            }
            if !self.io_validation_live_object_exists(device_capability.target) {
                Self::push_io_validation_violation(
                    violations,
                    IoValidationViolationCode::StaleGeneration,
                    subject,
                    "device-capability->target",
                    "device capability target generation is missing",
                );
            }
            let Some(capability) = self.capabilities.record(device_capability.capability) else {
                Self::push_io_validation_violation(
                    violations,
                    IoValidationViolationCode::MissingCapability,
                    subject,
                    "device-capability->capability",
                    "capability ledger entry is missing",
                );
                continue;
            };
            if device_capability.state == DeviceCapabilityState::Active {
                if capability.revoked
                    || capability.generation != device_capability.capability_generation
                {
                    Self::push_io_validation_violation(
                        violations,
                        IoValidationViolationCode::StaleGeneration,
                        subject,
                        "device-capability->capability",
                        "active device capability points to stale or revoked capability generation",
                    );
                }
                if !self.active_driver_binding_for_capability(device_capability) {
                    Self::push_io_validation_violation(
                        violations,
                        IoValidationViolationCode::ActiveCapabilityWithoutBinding,
                        subject,
                        "device-capability->driver-binding",
                        "active device capability has no bound driver-store binding for its device generation",
                    );
                }
            }
        }
    }

    fn validate_io_driver_bindings(&self, violations: &mut Vec<IoValidationViolationRecord>) {
        for binding in &self.driver_store_bindings {
            let subject = binding.object_ref();
            if !self.store_exists(binding.driver_store, binding.driver_store_generation) {
                Self::push_io_validation_violation(
                    violations,
                    IoValidationViolationCode::MissingStore,
                    subject,
                    "driver-binding->store",
                    "driver binding store generation is missing",
                );
            }
            if !self.device_exists(binding.device, binding.device_generation) {
                Self::push_io_validation_violation(
                    violations,
                    IoValidationViolationCode::MissingDevice,
                    subject,
                    "driver-binding->device",
                    "driver binding device generation is missing",
                );
            }
            let Some(device_capability) = self.device_capabilities.iter().find(|record| {
                record.id == binding.device_capability
                    && record.generation == binding.device_capability_generation
            }) else {
                Self::push_io_validation_violation(
                    violations,
                    IoValidationViolationCode::MissingCapability,
                    subject,
                    "driver-binding->device-capability",
                    "driver binding device capability generation is missing",
                );
                continue;
            };
            if binding.state == DriverStoreBindingState::Bound
                && device_capability.state != DeviceCapabilityState::Active
            {
                Self::push_io_validation_violation(
                    violations,
                    IoValidationViolationCode::StaleGeneration,
                    subject,
                    "driver-binding->device-capability",
                    "bound driver binding points to inactive device capability",
                );
            }
        }
    }

    fn validate_io_wait_records(&self, violations: &mut Vec<IoValidationViolationRecord>) {
        for io_wait in &self.io_waits {
            let subject = io_wait.object_ref();
            if !self.wait_exists(io_wait.wait, io_wait.wait_generation) {
                Self::push_io_validation_violation(
                    violations,
                    IoValidationViolationCode::MissingWait,
                    subject,
                    "io-wait->wait",
                    "IO wait token generation is missing",
                );
            }
            if !self.store_exists(io_wait.driver_store, io_wait.driver_store_generation) {
                Self::push_io_validation_violation(
                    violations,
                    IoValidationViolationCode::MissingStore,
                    subject,
                    "io-wait->driver-store",
                    "IO wait driver store generation is missing",
                );
            }
            if !self.device_exists(io_wait.device, io_wait.device_generation) {
                Self::push_io_validation_violation(
                    violations,
                    IoValidationViolationCode::MissingDevice,
                    subject,
                    "io-wait->device",
                    "IO wait device generation is missing",
                );
            }
            if !self
                .driver_binding_exists(io_wait.driver_binding, io_wait.driver_binding_generation)
            {
                Self::push_io_validation_violation(
                    violations,
                    IoValidationViolationCode::StaleGeneration,
                    subject,
                    "io-wait->driver-binding",
                    "IO wait driver binding generation is missing",
                );
            }
            if !self.io_validation_live_object_exists(io_wait.blocker) {
                Self::push_io_validation_violation(
                    violations,
                    IoValidationViolationCode::StaleGeneration,
                    subject,
                    "io-wait->blocker",
                    "IO wait blocker generation is missing",
                );
            }
            if io_wait.state == IoWaitState::Pending
                && self.io_cleanup_completed_for_driver_device_binding(
                    io_wait.driver_store,
                    io_wait.driver_store_generation,
                    io_wait.device,
                    io_wait.device_generation,
                    io_wait.driver_binding,
                    io_wait.driver_binding_generation,
                )
            {
                Self::push_io_validation_violation(
                    violations,
                    IoValidationViolationCode::PendingWaitAfterCleanup,
                    subject,
                    "io-wait->cleanup",
                    "pending IO wait remains after completed cleanup for its binding generation",
                );
            }
        }
    }

    fn validate_io_cleanup_records(&self, violations: &mut Vec<IoValidationViolationRecord>) {
        for cleanup in &self.io_cleanups {
            let subject = cleanup.object_ref();
            if self.io_cleanup_has_live_leak(cleanup) {
                Self::push_io_validation_violation(
                    violations,
                    IoValidationViolationCode::CleanupLiveLeak,
                    subject,
                    "io-cleanup->effects",
                    "completed cleanup left live IO authority or pending wait behind",
                );
            }
            for target in cleanup
                .cancelled_io_waits
                .iter()
                .chain(cleanup.revoked_device_capabilities.iter())
                .chain(cleanup.revoked_capabilities.iter())
                .chain(cleanup.released_dma_buffers.iter())
                .chain(cleanup.released_mmio_regions.iter())
                .chain(cleanup.released_irq_lines.iter())
            {
                if !self.io_validation_historical_object_exists(*target) {
                    Self::push_io_validation_violation(
                        violations,
                        IoValidationViolationCode::StaleGeneration,
                        subject,
                        "io-cleanup->effect",
                        "cleanup effect target generation is missing",
                    );
                }
            }
        }
    }

    fn validate_io_fault_injection_records(
        &self,
        violations: &mut Vec<IoValidationViolationRecord>,
    ) {
        for fault in &self.io_fault_injections {
            let subject = fault.object_ref();
            if !self.io_validation_historical_object_exists(fault.target) {
                Self::push_io_validation_violation(
                    violations,
                    IoValidationViolationCode::StaleGeneration,
                    subject,
                    "io-fault->target",
                    "fault injection target generation is missing",
                );
            }
            let Some(cleanup) = self.io_cleanups.iter().find(|record| {
                record.id == fault.cleanup && record.generation == fault.cleanup_generation
            }) else {
                Self::push_io_validation_violation(
                    violations,
                    IoValidationViolationCode::MissingCleanup,
                    subject,
                    "io-fault->cleanup",
                    "fault injection cleanup generation is missing",
                );
                continue;
            };
            if cleanup.driver_store != fault.driver_store
                || cleanup.driver_store_generation != fault.driver_store_generation
                || cleanup.device != fault.device
                || cleanup.device_generation != fault.device_generation
                || cleanup.driver_binding != fault.driver_binding
                || cleanup.driver_binding_generation != fault.driver_binding_generation
            {
                Self::push_io_validation_violation(
                    violations,
                    IoValidationViolationCode::FaultCleanupMismatch,
                    subject,
                    "io-fault->cleanup",
                    "fault injection cleanup does not match driver/device/binding generation",
                );
            }
        }
    }

    fn resource_exists(&self, resource: ResourceId, generation: Generation) -> bool {
        self.resources
            .iter()
            .any(|record| record.id == resource && record.generation == generation)
    }

    fn store_exists(&self, store: StoreId, generation: Generation) -> bool {
        self.stores
            .iter()
            .any(|record| record.id == store && record.generation == generation)
    }

    fn device_exists(&self, device: DeviceObjectId, generation: Generation) -> bool {
        self.device_objects
            .iter()
            .any(|record| record.id == device && record.generation == generation)
    }

    fn queue_exists(&self, queue: QueueObjectId, generation: Generation) -> bool {
        self.queue_objects
            .iter()
            .any(|record| record.id == queue && record.generation == generation)
    }

    fn descriptor_exists(&self, descriptor: DescriptorObjectId, generation: Generation) -> bool {
        self.descriptor_objects
            .iter()
            .any(|record| record.id == descriptor && record.generation == generation)
    }

    fn wait_exists(&self, wait: WaitId, generation: Generation) -> bool {
        self.waits
            .iter()
            .any(|record| record.id == wait && record.generation == generation)
    }

    fn driver_binding_exists(&self, binding: DriverStoreBindingId, generation: Generation) -> bool {
        self.driver_store_bindings
            .iter()
            .any(|record| record.id == binding && record.generation == generation)
    }

    fn io_validation_live_object_exists(&self, object: ContractObjectRef) -> bool {
        match object.kind {
            ContractObjectKind::Store => self.store_exists(object.id, object.generation),
            ContractObjectKind::Capability => self
                .capabilities
                .record(object.id)
                .is_some_and(|record| record.generation == object.generation && !record.revoked),
            ContractObjectKind::WaitToken => self.wait_exists(object.id, object.generation),
            ContractObjectKind::DeviceObject => self.device_exists(object.id, object.generation),
            ContractObjectKind::QueueObject => self.queue_exists(object.id, object.generation),
            ContractObjectKind::DescriptorObject => {
                self.descriptor_exists(object.id, object.generation)
            }
            ContractObjectKind::DmaBufferObject => self
                .dma_buffer_objects
                .iter()
                .any(|record| record.id == object.id && record.generation == object.generation),
            ContractObjectKind::MmioRegionObject => self
                .mmio_region_objects
                .iter()
                .any(|record| record.id == object.id && record.generation == object.generation),
            ContractObjectKind::IrqLineObject => self
                .irq_line_objects
                .iter()
                .any(|record| record.id == object.id && record.generation == object.generation),
            ContractObjectKind::IrqEvent => self
                .irq_events
                .iter()
                .any(|record| record.id == object.id && record.generation == object.generation),
            ContractObjectKind::DeviceCapability => self
                .device_capabilities
                .iter()
                .any(|record| record.id == object.id && record.generation == object.generation),
            ContractObjectKind::DriverStoreBinding => {
                self.driver_binding_exists(object.id, object.generation)
            }
            ContractObjectKind::IoWait => self
                .io_waits
                .iter()
                .any(|record| record.id == object.id && record.generation == object.generation),
            ContractObjectKind::IoCleanup => self
                .io_cleanups
                .iter()
                .any(|record| record.id == object.id && record.generation == object.generation),
            ContractObjectKind::IoFaultInjection => self
                .io_fault_injections
                .iter()
                .any(|record| record.id == object.id && record.generation == object.generation),
            ContractObjectKind::IoValidationReport => self
                .io_validation_reports
                .iter()
                .any(|record| record.id == object.id && record.generation == object.generation),
            ContractObjectKind::PacketDeviceObject => self
                .packet_device_objects
                .iter()
                .any(|record| record.id == object.id && record.generation == object.generation),
            ContractObjectKind::PacketBufferObject => self
                .packet_buffer_objects
                .iter()
                .any(|record| record.id == object.id && record.generation == object.generation),
            ContractObjectKind::PacketQueueObject => self
                .packet_queue_objects
                .iter()
                .any(|record| record.id == object.id && record.generation == object.generation),
            ContractObjectKind::PacketDescriptorObject => self
                .packet_descriptors
                .iter()
                .any(|record| record.id == object.id && record.generation == object.generation),
            ContractObjectKind::FakeNetBackendObject => self
                .fake_net_backends
                .iter()
                .any(|record| record.id == object.id && record.generation == object.generation),
            ContractObjectKind::VirtioNetBackendObject => self
                .virtio_net_backends
                .iter()
                .any(|record| record.id == object.id && record.generation == object.generation),
            ContractObjectKind::NetworkRxInterrupt => self
                .network_rx_interrupts
                .iter()
                .any(|record| record.id == object.id && record.generation == object.generation),
            ContractObjectKind::NetworkRxWaitResolution => self
                .network_rx_wait_resolutions
                .iter()
                .any(|record| record.id == object.id && record.generation == object.generation),
            _ => false,
        }
    }

    fn io_validation_historical_object_exists(&self, object: ContractObjectRef) -> bool {
        if object.kind == ContractObjectKind::Capability {
            return self
                .capabilities
                .record(object.id)
                .is_some_and(|record| record.generation >= object.generation);
        }
        self.io_validation_live_object_exists(object)
    }

    fn device_for_dma_buffer(
        &self,
        dma: &DmaBufferObjectRecord,
    ) -> Option<(DeviceObjectId, Generation)> {
        let descriptor = self.descriptor_objects.iter().find(|descriptor| {
            descriptor.id == dma.descriptor && descriptor.generation == dma.descriptor_generation
        })?;
        let queue = self.queue_objects.iter().find(|queue| {
            queue.id == descriptor.queue && queue.generation == descriptor.queue_generation
        })?;
        Some((queue.device, queue.device_generation))
    }

    fn device_for_capability_target(
        &self,
        target: ContractObjectRef,
    ) -> Option<(DeviceObjectId, Generation)> {
        match target.kind {
            ContractObjectKind::DeviceObject => Some((target.id, target.generation)),
            ContractObjectKind::DmaBufferObject => self
                .dma_buffer_objects
                .iter()
                .find(|record| record.id == target.id && record.generation == target.generation)
                .and_then(|record| self.device_for_dma_buffer(record)),
            ContractObjectKind::MmioRegionObject => self
                .mmio_region_objects
                .iter()
                .find(|record| record.id == target.id && record.generation == target.generation)
                .map(|record| (record.device, record.device_generation)),
            ContractObjectKind::IrqLineObject => self
                .irq_line_objects
                .iter()
                .find(|record| record.id == target.id && record.generation == target.generation)
                .map(|record| (record.device, record.device_generation)),
            _ => None,
        }
    }

    fn active_driver_binding_for_capability(&self, capability: &DeviceCapabilityRecord) -> bool {
        let Some((device, device_generation)) =
            self.device_for_capability_target(capability.target)
        else {
            return false;
        };
        self.driver_store_bindings.iter().any(|binding| {
            binding.driver_store == capability.driver_store
                && binding.driver_store_generation == capability.driver_store_generation
                && binding.device == device
                && binding.device_generation == device_generation
                && binding.state == DriverStoreBindingState::Bound
        })
    }

    fn io_cleanup_completed_for_driver_device_binding(
        &self,
        driver_store: StoreId,
        driver_store_generation: Generation,
        device: DeviceObjectId,
        device_generation: Generation,
        driver_binding: DriverStoreBindingId,
        driver_binding_generation: Generation,
    ) -> bool {
        self.io_cleanups.iter().any(|cleanup| {
            cleanup.driver_store == driver_store
                && cleanup.driver_store_generation == driver_store_generation
                && cleanup.device == device
                && cleanup.device_generation == device_generation
                && cleanup.driver_binding == driver_binding
                && cleanup.driver_binding_generation == driver_binding_generation
                && cleanup.state == IoCleanupState::Completed
        })
    }

    fn io_cleanup_has_live_leak(&self, cleanup: &IoCleanupRecord) -> bool {
        self.io_waits.iter().any(|record| {
            record.driver_store == cleanup.driver_store
                && record.driver_store_generation == cleanup.driver_store_generation
                && record.device == cleanup.device
                && record.device_generation == cleanup.device_generation
                && record.driver_binding == cleanup.driver_binding
                && record.driver_binding_generation == cleanup.driver_binding_generation
                && record.state == IoWaitState::Pending
        }) || self.device_capabilities.iter().any(|record| {
            record.driver_store == cleanup.driver_store
                && record.driver_store_generation == cleanup.driver_store_generation
                && record.state == DeviceCapabilityState::Active
                && self.io_cleanup_device_capability_belongs_to_device(
                    record,
                    cleanup.device,
                    cleanup.device_generation,
                )
        }) || self.driver_store_bindings.iter().any(|record| {
            record.id == cleanup.driver_binding
                && record.generation == cleanup.driver_binding_generation
                && record.state == DriverStoreBindingState::Bound
        }) || self.dma_buffer_objects.iter().any(|record| {
            record.state == DmaBufferObjectState::Registered
                && self.io_cleanup_dma_buffer_belongs_to_device(
                    record.id,
                    record.generation,
                    cleanup.device,
                    cleanup.device_generation,
                )
        }) || self.mmio_region_objects.iter().any(|record| {
            record.device == cleanup.device
                && record.device_generation == cleanup.device_generation
                && record.state == MmioRegionObjectState::Registered
        }) || self.irq_line_objects.iter().any(|record| {
            record.device == cleanup.device
                && record.device_generation == cleanup.device_generation
                && record.state == IrqLineObjectState::Registered
        })
    }

    pub fn check_io_validation_report_invariants(&self) -> Result<(), SemanticInvariantError> {
        for report in &self.io_validation_reports {
            if report.id == 0
                || report.generation == 0
                || (report.state == IoValidationReportState::Passed
                    && !report.violations.is_empty())
                || (report.state == IoValidationReportState::Failed && report.violations.is_empty())
            {
                return Err(SemanticInvariantError::IoValidationReportInvalid {
                    report: report.id,
                });
            }
            if !self.event_log.events.iter().any(|event| {
                event.id == report.validated_at_event
                    && matches!(
                        &event.kind,
                        EventKind::IoValidationReportRecorded {
                            report: id,
                            ok,
                            violation_count,
                            device_count,
                            dma_buffer_count,
                            irq_event_count,
                            cleanup_count,
                            fault_injection_count,
                            generation,
                        } if *id == report.id
                            && *ok == report.violations.is_empty()
                            && *violation_count == report.violations.len()
                            && *device_count == report.observed_device_count
                            && *dma_buffer_count == report.observed_dma_buffer_count
                            && *irq_event_count == report.observed_irq_event_count
                            && *cleanup_count == report.observed_io_cleanup_count
                            && *fault_injection_count == report.observed_io_fault_injection_count
                            && *generation == report.generation
                    )
            }) {
                return Err(SemanticInvariantError::IoValidationReportMissingEvent {
                    report: report.id,
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_io_wait_driver_binding_generation_for_test(
        &mut self,
        io_wait: IoWaitId,
        driver_binding_generation: Generation,
    ) {
        if let Some(record) = self.io_waits.iter_mut().find(|record| record.id == io_wait) {
            record.driver_binding_generation = driver_binding_generation;
        }
    }

    #[cfg(test)]
    pub(crate) fn corrupt_io_cleanup_revoked_capability_generation_for_test(
        &mut self,
        cleanup: IoCleanupId,
        generation: Generation,
    ) {
        if let Some(record) = self
            .io_cleanups
            .iter_mut()
            .find(|record| record.id == cleanup)
        {
            if let Some(capability) = record.revoked_capabilities.first_mut() {
                capability.generation = generation;
            }
        }
    }
}
