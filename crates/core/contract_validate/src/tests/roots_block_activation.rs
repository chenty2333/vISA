use super::*;

#[test]
fn semantic_roots_reject_block_device_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.block_device_object_count = 1;
    package.semantic.block_device_objects.push(artifact_manifest::BlockDeviceObjectManifest {
        id: 53,
        name: "fake-block0".to_owned(),
        device: 17,
        device_generation: 1,
        sector_size: 512,
        sector_count: 4096,
        read_only: false,
        max_transfer_sectors: 128,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 99,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "block device object root/count mismatch");
}

#[test]
fn semantic_roots_reject_block_range_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.block_range_object_count = 1;
    package.semantic.block_range_objects.push(artifact_manifest::BlockRangeObjectManifest {
        id: 54,
        block_device: 53,
        block_device_generation: 1,
        start_sector: 64,
        sector_count: 8,
        byte_offset: 32768,
        byte_len: 4096,
        generation: 1,
        state: "registered".to_owned(),
        recorded_at_event: 100,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "block range object root/count mismatch");
}

#[test]
fn semantic_roots_reject_block_request_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.block_request_object_count = 1;
    package.semantic.block_request_objects.push(artifact_manifest::BlockRequestObjectManifest {
        id: 55,
        block_device: 53,
        block_device_generation: 1,
        block_range: 54,
        block_range_generation: 1,
        operation: "read".to_owned(),
        sequence: 1,
        byte_len: 4096,
        generation: 1,
        state: "submitted".to_owned(),
        recorded_at_event: 101,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "block request object root/count mismatch");
}

#[test]
fn semantic_roots_reject_block_completion_object_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.block_completion_object_count = 1;
    package.semantic.block_completion_objects.push(
        artifact_manifest::BlockCompletionObjectManifest {
            id: 56,
            block_request: 55,
            block_request_generation: 1,
            block_device: 53,
            block_device_generation: 1,
            block_range: 54,
            block_range_generation: 1,
            sequence: 1,
            completed_bytes: 4096,
            status: "success".to_owned(),
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 102,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "block completion object root/count mismatch");
}

#[test]
fn semantic_roots_reject_block_wait_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.block_wait_count = 1;
    package.semantic.block_waits.push(artifact_manifest::BlockWaitManifest {
        id: 57,
        wait: 58,
        wait_generation: 1,
        block_request: 55,
        block_request_generation: 1,
        block_device: 53,
        block_device_generation: 1,
        block_range: 54,
        block_range_generation: 1,
        operation: "read".to_owned(),
        sequence: 1,
        byte_len: 4096,
        generation: 1,
        state: "pending".to_owned(),
        created_at_event: 103,
        completed_at_event: None,
        completion: None,
        completion_generation: None,
        cancel_reason: None,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "block wait root/count mismatch");
}

#[test]
fn semantic_roots_reject_activation_resume_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.activation_resume_count = 1;
    package.semantic.activation_resumes.push(artifact_manifest::ActivationResumeManifest {
        id: 6,
        scheduler_decision: 5,
        scheduler_decision_generation: 1,
        activation: 11,
        activation_generation_before: 4,
        activation_generation_after: 5,
        owner_task: 7,
        owner_task_generation: 1,
        queue: 1,
        queue_generation: 1,
        context: None,
        context_generation_before: None,
        context_generation_after: None,
        saved_context: None,
        saved_context_generation: None,
        saved_vector_state: None,
        restored_vector_state: None,
        vector_status: "absent".to_owned(),
        vector_restored_at_event: None,
        generation: 1,
        state: "applied".to_owned(),
        resumed_at_event: 8,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "activation resume root/count mismatch");
}

#[test]
fn semantic_roots_reject_activation_wait_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.activation_wait_count = 1;
    package.semantic.activation_waits.push(artifact_manifest::ActivationWaitManifest {
        id: 9,
        activation: 11,
        activation_generation_before: 5,
        activation_generation_after_block: 6,
        activation_generation_after_cancel: None,
        wait: 41,
        wait_generation: 1,
        owner_task: 7,
        owner_task_generation: 2,
        queue: None,
        queue_generation: None,
        generation: 1,
        state: "pending".to_owned(),
        blocked_at_event: 8,
        completed_at_event: None,
        cancel_reason: None,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "activation wait root/count mismatch");
}

#[test]
fn semantic_roots_reject_activation_cleanup_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.activation_cleanup_count = 1;
    package.semantic.activation_cleanups.push(artifact_manifest::ActivationCleanupManifest {
        id: 10,
        store: 7,
        target_store_generation: 2,
        result_store_generation: 4,
        activation: 11,
        activation_generation_before: 5,
        activation_generation_after: 6,
        wait: Some(41),
        wait_generation: Some(1),
        owner_task: 9,
        owner_task_generation_before: 2,
        owner_task_generation_after: 3,
        generation: 1,
        state: "completed".to_owned(),
        reason: "store-fault".to_owned(),
        started_at_event: 8,
        completed_at_event: 9,
        steps: Vec::new(),
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "activation cleanup root/count mismatch");
}

#[test]
fn semantic_roots_reject_preemption_latency_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.preemption_latency_sample_count = 1;
    package.semantic.preemption_latency_samples.push(
        artifact_manifest::PreemptionLatencySampleManifest {
            id: 11,
            timer_interrupt: 5,
            timer_interrupt_generation: 1,
            preemption: 6,
            preemption_generation: 1,
            scheduler_decision: 7,
            scheduler_decision_generation: 1,
            activation_resume: 8,
            activation_resume_generation: 1,
            activation: 12,
            activation_generation_before: 3,
            activation_generation_after: 5,
            queue: 2,
            queue_generation: 1,
            interrupt_recorded_at_event: 10,
            preempted_at_event: 11,
            decided_at_event: 12,
            resumed_at_event: 13,
            interrupt_to_preempt_events: 1,
            preempt_to_decision_events: 1,
            decision_to_resume_events: 1,
            interrupt_to_resume_events: 3,
            measured_nanos: 500,
            budget_nanos: 50_000,
            generation: 1,
            state: "recorded".to_owned(),
            recorded_at_event: 14,
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "preemption latency root/count mismatch");
}

#[test]
fn semantic_roots_reject_hart_event_attribution_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.hart_event_attribution_count = 1;
    package.semantic.hart_event_attributions.push(
        artifact_manifest::HartEventAttributionManifest {
            id: 12,
            hart: 1,
            hart_generation: 2,
            hardware_hart: 0,
            event: 10,
            event_source: "timer".to_owned(),
            event_kind: "TimerInterruptRecorded".to_owned(),
            activation: Some(11),
            activation_generation: Some(3),
            task: Some(7),
            task_generation: Some(1),
            store: None,
            store_generation: None,
            generation: 1,
            state: "recorded".to_owned(),
            note: "test".to_owned(),
        },
    );

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "hart event attribution root/count mismatch");
}

#[test]
fn semantic_roots_reject_hart_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.hart_count = 1;
    package.semantic.hart_records.push(artifact_manifest::HartRecordManifest {
        id: 1,
        hardware_id: 0,
        label: "boot-hart0".to_owned(),
        state: "idle".to_owned(),
        generation: 2,
        boot: true,
        current_activation: None,
        current_activation_generation: None,
        current_task: None,
        current_task_generation: None,
        current_store: None,
        current_store_generation: None,
        last_event: Some(2),
        last_current_event: None,
        note: "test".to_owned(),
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "hart root/count mismatch");
}

#[test]
fn semantic_roots_reject_command_result_root_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.command_result_count = 1;
    package.semantic.command_results.push(CommandResultManifest {
        id: 1,
        issuer: "contract-test".to_owned(),
        command: "create-wait".to_owned(),
        status: "rejected".to_owned(),
        events: Vec::new(),
        effects: Vec::new(),
        violations: vec!["missing owner".to_owned()],
    });

    let err = validate_migration_package(&package).expect_err("root mismatch must fail");
    assert_eq!(err.to_string(), "command result root/count mismatch");
}

#[test]
fn semantic_roots_reject_interface_event_count_mismatch() {
    let mut package = minimal_migration_package();
    package.semantic.interface_event_count = 1;
    package.semantic.interface_events.push(InterfaceEventManifest {
        id: 1,
        epoch: 9,
        interface_kind: "standard-wasi".to_owned(),
        interface: "wasi:clocks/monotonic-clock".to_owned(),
        operation: "subscribe".to_owned(),
        requester: Some("contract-test".to_owned()),
        artifact: None,
        store: None,
        explanation: "unsupported interface".to_owned(),
    });
    package
        .semantic
        .roots
        .interface_event_roots
        .push("interface-event:standard-wasi:wasi:clocks/monotonic-clock:subscribe".to_owned());
    package.semantic.interface_events.clear();

    let err = validate_migration_package(&package).expect_err("vector mismatch must fail");
    assert_eq!(err.to_string(), "interface event root/count mismatch");
}
