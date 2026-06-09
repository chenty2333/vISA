use super::*;

#[test]
fn semantic_roots_reject_device_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.device_object_count = 1;
    package.semantic.device_objects.push(artifact_manifest::DeviceObjectManifest {
        id: 17,
        name: "fake-io0".to_owned(),
        class: "fake-device".to_owned(),
        resource: 3,
        resource_generation: 1,
        backend: "fake-io-backend".to_owned(),
        bus: "semantic-harness".to_owned(),
        vendor: "visa".to_owned(),
        model: "fake-io-v1".to_owned(),
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 53,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "device object root/count mismatch");
}

#[test]
fn semantic_roots_reject_queue_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.queue_object_count = 1;
    package.semantic.queue_objects.push(artifact_manifest::QueueObjectManifest {
        id: 18,
        name: "fake-io0-rx".to_owned(),
        role: "rx".to_owned(),
        queue_index: 0,
        depth: 64,
        device: 17,
        device_generation: 1,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 54,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "queue object root/count mismatch");
}

#[test]
fn semantic_roots_reject_descriptor_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.descriptor_object_count = 1;
    package.semantic.descriptor_objects.push(artifact_manifest::DescriptorObjectManifest {
        id: 19,
        queue: 18,
        queue_generation: 1,
        slot: 0,
        access: "read-write".to_owned(),
        length: 2048,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 55,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "descriptor object root/count mismatch");
}

#[test]
fn semantic_roots_reject_dma_buffer_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.dma_buffer_object_count = 1;
    package.semantic.dma_buffer_objects.push(artifact_manifest::DmaBufferObjectManifest {
        id: 20,
        descriptor: 19,
        descriptor_generation: 1,
        resource: 21,
        resource_generation: 1,
        access: "read-write".to_owned(),
        length: 2048,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 56,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "dma buffer object root/count mismatch");
}

#[test]
fn semantic_roots_reject_mmio_region_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.mmio_region_object_count = 1;
    package.semantic.mmio_region_objects.push(artifact_manifest::MmioRegionObjectManifest {
        id: 21,
        device: 17,
        device_generation: 1,
        resource: 22,
        resource_generation: 1,
        region_index: 0,
        offset: 0x1000,
        length: 0x100,
        access: "read-write".to_owned(),
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 57,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "mmio region object root/count mismatch");
}

#[test]
fn semantic_roots_reject_irq_line_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.irq_line_object_count = 1;
    package.semantic.irq_line_objects.push(artifact_manifest::IrqLineObjectManifest {
        id: 22,
        device: 17,
        device_generation: 1,
        resource: 23,
        resource_generation: 1,
        irq_number: 5,
        trigger: "level".to_owned(),
        polarity: "active-high".to_owned(),
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 58,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "irq line object root/count mismatch");
}

#[test]
fn semantic_roots_reject_irq_event_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.irq_event_count = 1;
    package.semantic.irq_events.push(artifact_manifest::IrqEventManifest {
        id: 23,
        irq_line: 22,
        irq_line_generation: 1,
        device: 17,
        device_generation: 1,
        driver_store: 24,
        driver_store_generation: 3,
        irq_number: 5,
        sequence: 1,
        generation: 1,
        state: "recorded".to_owned(),
        recorded_at_event: 59,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "irq event root/count mismatch");
}

#[test]
fn semantic_roots_reject_device_capability_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.device_capability_count = 1;
    package.semantic.device_capabilities.push(artifact_manifest::DeviceCapabilityManifest {
        id: 24,
        driver_store: 2,
        driver_store_generation: 2,
        target: artifact_manifest::ContractObjectRefManifest {
            kind: "mmio-region-object".to_owned(),
            id: 21,
            generation: 1,
        },
        class: "mmio-region".to_owned(),
        operation: "write32".to_owned(),
        capability: 7,
        capability_generation: 1,
        handle_slot: 1,
        handle_generation: 1,
        handle_tag: 99,
        generation: 1,
        state: "active".to_owned(),
        recorded_at_event: 60,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "device capability root/count mismatch");
}

#[test]
fn semantic_roots_reject_driver_store_binding_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.driver_store_binding_count = 1;
    package.semantic.driver_store_bindings.push(artifact_manifest::DriverStoreBindingManifest {
        id: 25,
        driver_store: 2,
        driver_store_generation: 2,
        device: 17,
        device_generation: 1,
        device_capability: 24,
        device_capability_generation: 1,
        capability: 7,
        capability_generation: 1,
        generation: 1,
        state: "bound".to_owned(),
        recorded_at_event: 61,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "driver store binding root/count mismatch");
}

#[test]
fn semantic_roots_reject_io_wait_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.io_wait_count = 1;
    package.semantic.io_waits.push(artifact_manifest::IoWaitManifest {
        id: 26,
        wait: 41,
        wait_generation: 1,
        driver_store: 2,
        driver_store_generation: 2,
        device: 17,
        device_generation: 1,
        driver_binding: 25,
        driver_binding_generation: 1,
        blocker: artifact_manifest::ContractObjectRefManifest {
            kind: "irq-line-object".to_owned(),
            id: 23,
            generation: 1,
        },
        generation: 1,
        state: "pending".to_owned(),
        created_at_event: 62,
        completed_at_event: None,
        completion_irq_event: None,
        completion_irq_event_generation: None,
        cancel_reason: None,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "io wait root/count mismatch");
}

#[test]
fn semantic_roots_reject_io_cleanup_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.io_cleanup_count = 1;
    package.semantic.io_cleanups.push(artifact_manifest::IoCleanupManifest {
        id: 27,
        driver_store: 2,
        driver_store_generation: 2,
        device: 17,
        device_generation: 1,
        driver_binding: 25,
        driver_binding_generation: 1,
        generation: 1,
        state: "completed".to_owned(),
        reason: "device-fault".to_owned(),
        started_at_event: 63,
        completed_at_event: 64,
        cancelled_io_waits: Vec::new(),
        revoked_device_capabilities: Vec::new(),
        revoked_capabilities: Vec::new(),
        released_dma_buffers: Vec::new(),
        released_mmio_regions: Vec::new(),
        released_irq_lines: Vec::new(),
        steps: Vec::new(),
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "io cleanup root/count mismatch");
}

#[test]
fn semantic_roots_reject_io_fault_injection_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.io_fault_injection_count = 1;
    package.semantic.io_fault_injections.push(artifact_manifest::IoFaultInjectionManifest {
        id: 29,
        driver_store: 2,
        driver_store_generation: 2,
        device: 17,
        device_generation: 1,
        driver_binding: 25,
        driver_binding_generation: 1,
        target: artifact_manifest::ContractObjectRefManifest {
            kind: "irq-line-object".to_owned(),
            id: 22,
            generation: 1,
        },
        cleanup: 27,
        cleanup_generation: 1,
        generation: 1,
        kind: "device-fault".to_owned(),
        state: "completed".to_owned(),
        injected_at_event: 65,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "io fault injection root/count mismatch");
}

#[test]
fn semantic_roots_reject_io_validation_report_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.io_validation_report_count = 1;
    package.semantic.io_validation_reports.push(artifact_manifest::IoValidationReportManifest {
        id: 30,
        generation: 1,
        state: "passed".to_owned(),
        validated_at_event: 66,
        event_log_cursor: 65,
        observed_device_count: 1,
        observed_queue_count: 1,
        observed_descriptor_count: 1,
        observed_dma_buffer_count: 1,
        observed_mmio_region_count: 1,
        observed_irq_line_count: 1,
        observed_irq_event_count: 1,
        observed_device_capability_count: 1,
        observed_driver_binding_count: 1,
        observed_io_wait_count: 1,
        observed_io_cleanup_count: 1,
        observed_io_fault_injection_count: 1,
        violation_count: 0,
        violations: Vec::new(),
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "io validation report root/count mismatch");
}
