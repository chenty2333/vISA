use super::*;

#[test]
fn contract_graph_validator_reports_generation_dead_and_tombstone_edges() {
    let (artifact, store, code, _capabilities) = running_store_and_code();
    let mut executor = TargetExecutor::new();
    let activation_id = executor
        .start_activation(&store.store, &code, ActivationEntry::Symbol("_start".to_string()))
        .unwrap();
    let activation = executor
        .activations()
        .iter()
        .find(|activation| activation.id == activation_id)
        .unwrap()
        .clone();
    let mut stale_store = store.store.clone();
    stale_store.generation += 1;
    let mut retired_code = code.clone();
    retired_code.state = CodeObjectState::Retired;
    let tombstone = TombstoneRecord::new(
        ContractObjectKind::CodeObject,
        retired_code.id,
        retired_code.generation,
        42,
        "code-retired",
    );
    let trap = TargetTrapRecord {
        id: 99,
        generation: 1,
        class: TargetTrapClass::HostcallTrap,
        store: Some(stale_store.id),
        store_generation: Some(stale_store.generation),
        activation: Some(999),
        activation_generation: Some(1),
        code_object: Some(retired_code.id),
        code_generation: Some(retired_code.generation),
        artifact: Some(retired_code.artifact_id),
        artifact_generation: Some(1),
        offset: Some(0),
        target_pc: None,
        trap_kind: None,
        function_index: None,
        wasm_offset: None,
        debug_symbol: None,
        classification_status: None,
        attribution_status: "synthetic".to_string(),
        simd_attribution: None,
        hostcall: Some("hostcall.bad".to_string()),
        fault_policy: "debug".to_string(),
        effect: FailureEffect::CompleteWithErrno(22),
        detail: "dangling activation".to_string(),
    };
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        artifacts: {
            let mut artifacts = Vec::new();
            artifacts.push(artifact);
            artifacts
        },
        code_objects: {
            let mut objects = Vec::new();
            objects.push(retired_code);
            objects
        },
        target_feature_sets: Vec::new(),
        vector_states: Vec::new(),
        simd_fault_injections: Vec::new(),
        simd_benchmarks: Vec::new(),
        simd_context_switch_benchmarks: Vec::new(),
        framebuffer_objects: Vec::new(),
        display_objects: Vec::new(),
        display_capabilities: Vec::new(),
        framebuffer_window_leases: Vec::new(),
        framebuffer_mappings: Vec::new(),
        framebuffer_writes: Vec::new(),
        framebuffer_flush_regions: Vec::new(),
        framebuffer_dirty_regions: Vec::new(),
        display_event_logs: Vec::new(),
        display_cleanups: Vec::new(),
        display_snapshot_barriers: Vec::new(),
        display_panic_last_frames: Vec::new(),
        framebuffer_benchmarks: Vec::new(),
        integrated_display_scheduler_loads: Vec::new(),
        integrated_snapshot_io_lease_barriers: Vec::new(),
        integrated_code_publish_smp_workloads: Vec::new(),
        integrated_display_panics: Vec::new(),
        integrated_osctl_trace_replays: Vec::new(),
        integrated_smp_preemption_cleanups: Vec::new(),
        integrated_smp_network_faults: Vec::new(),
        integrated_disk_preempt_faults: Vec::new(),
        integrated_simd_migrations: Vec::new(),
        integrated_network_disk_ios: Vec::new(),
        network_benchmarks: Vec::new(),
        network_driver_cleanups: Vec::new(),
        device_objects: Vec::new(),
        packet_device_objects: Vec::new(),
        network_stack_adapters: Vec::new(),
        socket_objects: Vec::new(),
        fake_net_backends: Vec::new(),
        virtio_net_backends: Vec::new(),
        fake_block_backends: Vec::new(),
        virtio_blk_backends: Vec::new(),
        block_benchmarks: Vec::new(),
        io_cleanups: Vec::new(),
        block_pending_io_policies: Vec::new(),
        block_waits: Vec::new(),
        block_request_objects: Vec::new(),
        block_device_objects: Vec::new(),
        block_range_objects: Vec::new(),
        block_request_queues: Vec::new(),
        block_dma_buffers: Vec::new(),
        harts: Vec::new(),
        tasks: Vec::new(),
        runtime_activations: Vec::new(),
        runnable_queues: Vec::new(),
        scheduler_decisions: Vec::new(),
        activation_contexts: Vec::new(),
        activation_migrations: Vec::new(),
        smp_safe_points: Vec::new(),
        stop_the_world_rendezvous: Vec::new(),
        smp_code_publish_barriers: Vec::new(),
        saved_contexts: Vec::new(),
        timer_interrupts: Vec::new(),
        remote_preempts: Vec::new(),
        activation_cleanups: Vec::new(),
        smp_cleanup_quiescence: Vec::new(),
        smp_snapshot_barriers: Vec::new(),
        smp_stress_runs: Vec::new(),
        preemptions: Vec::new(),
        activation_resumes: Vec::new(),
        stores: {
            let mut stores = Vec::new();
            stores.push(stale_store);
            stores
        },
        activations: {
            let mut activations = Vec::new();
            activations.push(activation);
            activations
        },
        traps: {
            let mut traps = Vec::new();
            traps.push(trap);
            traps
        },
        hostcalls: Vec::new(),
        capabilities: Vec::new(),
        waits: Vec::new(),
        cleanup_transactions: Vec::new(),
        tombstones: {
            let mut tombstones = Vec::new();
            tombstones.push(tombstone);
            tombstones
        },
        external_objects: Vec::new(),
        explicit_edges: Vec::new(),
    };
    let violations = validate_contract_graph(&snapshot);
    assert!(violations.len() >= 4);
    assert!(violations.iter().any(|violation| {
        violation.kind == ContractViolationKind::GenerationMismatch
            && violation.edge == "activation->store"
    }));
    assert!(violations.iter().any(|violation| {
        violation.kind == ContractViolationKind::LiveObjectReferencesDeadObject
            && violation.edge == "activation->code"
    }));
    assert!(violations.iter().any(|violation| {
        violation.kind == ContractViolationKind::TombstoneReferencedByLiveEdge
            && violation.edge == "activation->code"
    }));
    assert!(violations.iter().any(|violation| {
        violation.kind == ContractViolationKind::DanglingEdge
            && violation.edge == "trap->activation"
    }));
}

#[test]
fn contract_graph_validator_rejects_cleanup_effect_mismatch() {
    let (artifact, store, code, capabilities) = running_store_and_code();
    let cleanup = FaultCleanupTransaction {
        id: 7,
        store: store.store.id,
        store_generation: store.store.generation,
        result_store_generation: Some(store.store.generation + 1),
        activation: None,
        activation_generation: None,
        code_object: Some(code.id),
        code_generation: Some(code.generation),
        generation: 1,
        started_at: 1,
        finished_at: Some(2),
        state: CleanupTransactionState::Completed,
        reason: "inconsistent-cleanup".to_string(),
        steps: Vec::new(),
        effects: Vec::new(),
        released_dmw_leases: 0,
        cancelled_waits: 0,
        revoked_capabilities: {
            let mut revoked = Vec::new();
            revoked.push(capabilities.records()[0].id);
            revoked
        },
        revoked_capability_refs: {
            let mut revoked = Vec::new();
            revoked.push(capabilities.records()[0].object_ref());
            revoked
        },
        dropped_resources: 1,
        unbound_code_object: true,
        state_digest: String::new(),
        effect: FailureEffect::CompleteWithErrno(5),
    };
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        artifacts: {
            let mut artifacts = Vec::new();
            artifacts.push(artifact);
            artifacts
        },
        code_objects: {
            let mut objects = Vec::new();
            objects.push(code);
            objects
        },
        target_feature_sets: Vec::new(),
        vector_states: Vec::new(),
        simd_fault_injections: Vec::new(),
        simd_benchmarks: Vec::new(),
        simd_context_switch_benchmarks: Vec::new(),
        framebuffer_objects: Vec::new(),
        display_objects: Vec::new(),
        display_capabilities: Vec::new(),
        framebuffer_window_leases: Vec::new(),
        framebuffer_mappings: Vec::new(),
        framebuffer_writes: Vec::new(),
        framebuffer_flush_regions: Vec::new(),
        framebuffer_dirty_regions: Vec::new(),
        display_event_logs: Vec::new(),
        display_cleanups: Vec::new(),
        display_snapshot_barriers: Vec::new(),
        display_panic_last_frames: Vec::new(),
        framebuffer_benchmarks: Vec::new(),
        integrated_display_scheduler_loads: Vec::new(),
        integrated_snapshot_io_lease_barriers: Vec::new(),
        integrated_code_publish_smp_workloads: Vec::new(),
        integrated_display_panics: Vec::new(),
        integrated_osctl_trace_replays: Vec::new(),
        integrated_smp_preemption_cleanups: Vec::new(),
        integrated_smp_network_faults: Vec::new(),
        integrated_disk_preempt_faults: Vec::new(),
        integrated_simd_migrations: Vec::new(),
        integrated_network_disk_ios: Vec::new(),
        network_benchmarks: Vec::new(),
        network_driver_cleanups: Vec::new(),
        device_objects: Vec::new(),
        packet_device_objects: Vec::new(),
        network_stack_adapters: Vec::new(),
        socket_objects: Vec::new(),
        fake_net_backends: Vec::new(),
        virtio_net_backends: Vec::new(),
        fake_block_backends: Vec::new(),
        virtio_blk_backends: Vec::new(),
        block_benchmarks: Vec::new(),
        io_cleanups: Vec::new(),
        block_pending_io_policies: Vec::new(),
        block_waits: Vec::new(),
        block_request_objects: Vec::new(),
        block_device_objects: Vec::new(),
        block_range_objects: Vec::new(),
        block_request_queues: Vec::new(),
        block_dma_buffers: Vec::new(),
        harts: Vec::new(),
        tasks: Vec::new(),
        runtime_activations: Vec::new(),
        runnable_queues: Vec::new(),
        scheduler_decisions: Vec::new(),
        activation_contexts: Vec::new(),
        activation_migrations: Vec::new(),
        smp_safe_points: Vec::new(),
        stop_the_world_rendezvous: Vec::new(),
        smp_code_publish_barriers: Vec::new(),
        saved_contexts: Vec::new(),
        timer_interrupts: Vec::new(),
        remote_preempts: Vec::new(),
        activation_cleanups: Vec::new(),
        smp_cleanup_quiescence: Vec::new(),
        smp_snapshot_barriers: Vec::new(),
        smp_stress_runs: Vec::new(),
        preemptions: Vec::new(),
        activation_resumes: Vec::new(),
        stores: {
            let mut stores = Vec::new();
            stores.push(store.store);
            stores
        },
        activations: Vec::new(),
        traps: Vec::new(),
        hostcalls: Vec::new(),
        capabilities: capabilities.records().to_vec(),
        waits: Vec::new(),
        cleanup_transactions: {
            let mut cleanups = Vec::new();
            cleanups.push(cleanup);
            cleanups
        },
        tombstones: Vec::new(),
        external_objects: Vec::new(),
        explicit_edges: Vec::new(),
    };
    let violations = validate_contract_graph(&snapshot);
    assert!(violations.iter().any(|violation| {
        violation.kind == ContractViolationKind::GenerationMismatch
            && violation.edge == "cleanup->result-store"
    }));
    assert!(violations.iter().any(|violation| {
        violation.kind == ContractViolationKind::LiveObjectReferencesDeadObject
            && violation.edge == "cleanup->code"
    }));
    assert!(violations.iter().any(|violation| {
        violation.kind == ContractViolationKind::LiveObjectReferencesDeadObject
            && violation.edge == "cleanup->capability"
    }));
}

#[test]
fn completed_cleanup_detects_code_still_bound_to_target_generation() {
    let (artifact, store, code, _capabilities) = running_store_and_code();
    let target_generation = store.store.generation;
    let mut dead_store = store.store.clone();
    dead_store.state = StoreState::Dead;
    dead_store.generation += 1;
    let cleanup = FaultCleanupTransaction {
        id: 19,
        store: dead_store.id,
        store_generation: target_generation,
        result_store_generation: Some(dead_store.generation),
        activation: None,
        activation_generation: None,
        code_object: Some(code.id),
        code_generation: Some(code.generation),
        generation: 1,
        started_at: 1,
        finished_at: Some(2),
        state: CleanupTransactionState::Completed,
        reason: "code-still-bound".to_string(),
        steps: Vec::new(),
        effects: Vec::new(),
        released_dmw_leases: 0,
        cancelled_waits: 0,
        revoked_capabilities: Vec::new(),
        revoked_capability_refs: Vec::new(),
        dropped_resources: 0,
        unbound_code_object: false,
        state_digest: String::new(),
        effect: FailureEffect::CompleteWithErrno(5),
    };
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        artifacts: {
            let mut artifacts = Vec::new();
            artifacts.push(artifact);
            artifacts
        },
        code_objects: {
            let mut code_objects = Vec::new();
            code_objects.push(code);
            code_objects
        },
        stores: {
            let mut stores = Vec::new();
            stores.push(dead_store);
            stores
        },
        cleanup_transactions: {
            let mut cleanups = Vec::new();
            cleanups.push(cleanup);
            cleanups
        },
        tombstones: {
            let mut tombstones = Vec::new();
            tombstones.push(TombstoneRecord::new(
                ContractObjectKind::Store,
                store.store.id,
                target_generation,
                2,
                "fault-cleanup-store-target-retired",
            ));
            tombstones
        },
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);
    assert!(violations.iter().any(|violation| {
        violation.kind == ContractViolationKind::LiveObjectReferencesDeadObject
            && violation.edge == "cleanup->code"
    }));
}

#[test]
fn completed_cleanup_result_allows_rebound_store_with_result_tombstone() {
    let (_artifact, store, _code, _capabilities) = running_store_and_code();
    let target_generation = store.store.generation;
    let result_generation = target_generation + 1;
    let mut rebound_store = store.store.clone();
    rebound_store.state = StoreState::Running;
    rebound_store.generation = result_generation + 1;
    let cleanup = FaultCleanupTransaction {
        id: 23,
        store: rebound_store.id,
        store_generation: target_generation,
        result_store_generation: Some(result_generation),
        activation: None,
        activation_generation: None,
        code_object: None,
        code_generation: None,
        generation: 1,
        started_at: 1,
        finished_at: Some(2),
        state: CleanupTransactionState::Completed,
        reason: "old-cleanup-before-rebind".to_string(),
        steps: Vec::new(),
        effects: Vec::new(),
        released_dmw_leases: 0,
        cancelled_waits: 0,
        revoked_capabilities: Vec::new(),
        revoked_capability_refs: Vec::new(),
        dropped_resources: 0,
        unbound_code_object: false,
        state_digest: String::new(),
        effect: FailureEffect::CompleteWithErrno(5),
    };
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        stores: {
            let mut stores = Vec::new();
            stores.push(rebound_store);
            stores
        },
        cleanup_transactions: {
            let mut cleanups = Vec::new();
            cleanups.push(cleanup);
            cleanups
        },
        tombstones: {
            let mut tombstones = Vec::new();
            tombstones.push(TombstoneRecord::new(
                ContractObjectKind::Store,
                store.store.id,
                target_generation,
                2,
                "fault-cleanup-store-target-retired",
            ));
            tombstones.push(TombstoneRecord::new(
                ContractObjectKind::Store,
                store.store.id,
                result_generation,
                2,
                "fault-cleanup-store-dead",
            ));
            tombstones
        },
        ..ContractGraphSnapshot::default()
    };
    assert_eq!(validate_contract_graph(&snapshot), Vec::new());
}

#[test]
fn contract_graph_validator_allows_historical_hostcall_to_tombstoned_generation() {
    let (artifact, store, code, capabilities) = running_store_and_code();
    let mut executor = TargetExecutor::new();
    let activation = executor
        .start_activation(&store.store, &code, ActivationEntry::Symbol("_start".to_string()))
        .unwrap();
    let mut cap_args = Vec::new();
    cap_args.push(cap_arg_for(&capabilities, "driver_virtio_net", "mmio.virtio-net", "map"));
    executor
        .invoke_hostcall(
            &code,
            HostcallFrame::new_bound(
                activation,
                &store.store,
                &code,
                1,
                "mmio.virtio-net",
                "map",
                1,
            )
            .with_cap_args(cap_args)
            .to_wire_frame(),
            &capabilities,
        )
        .unwrap();
    let mut current_code = code.clone();
    let historical_generation = current_code.generation;
    current_code.generation += 1;
    let mut activation_record = executor.activations()[0].clone();
    activation_record.code_generation = current_code.generation;
    let mut trace = executor.hostcall_trace()[0].clone();
    assert_eq!(trace.activation_generation, 1);
    assert_eq!(activation_record.generation, 2);
    trace.code_generation = historical_generation;
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        artifacts: {
            let mut artifacts = Vec::new();
            artifacts.push(artifact);
            artifacts
        },
        code_objects: {
            let mut objects = Vec::new();
            objects.push(current_code);
            objects
        },
        target_feature_sets: Vec::new(),
        vector_states: Vec::new(),
        simd_fault_injections: Vec::new(),
        simd_benchmarks: Vec::new(),
        simd_context_switch_benchmarks: Vec::new(),
        framebuffer_objects: Vec::new(),
        display_objects: Vec::new(),
        display_capabilities: Vec::new(),
        framebuffer_window_leases: Vec::new(),
        framebuffer_mappings: Vec::new(),
        framebuffer_writes: Vec::new(),
        framebuffer_flush_regions: Vec::new(),
        framebuffer_dirty_regions: Vec::new(),
        display_event_logs: Vec::new(),
        display_cleanups: Vec::new(),
        display_snapshot_barriers: Vec::new(),
        display_panic_last_frames: Vec::new(),
        framebuffer_benchmarks: Vec::new(),
        integrated_display_scheduler_loads: Vec::new(),
        integrated_snapshot_io_lease_barriers: Vec::new(),
        integrated_code_publish_smp_workloads: Vec::new(),
        integrated_display_panics: Vec::new(),
        integrated_osctl_trace_replays: Vec::new(),
        integrated_smp_preemption_cleanups: Vec::new(),
        integrated_smp_network_faults: Vec::new(),
        integrated_disk_preempt_faults: Vec::new(),
        integrated_simd_migrations: Vec::new(),
        integrated_network_disk_ios: Vec::new(),
        network_benchmarks: Vec::new(),
        network_driver_cleanups: Vec::new(),
        device_objects: Vec::new(),
        packet_device_objects: Vec::new(),
        network_stack_adapters: Vec::new(),
        socket_objects: Vec::new(),
        fake_net_backends: Vec::new(),
        virtio_net_backends: Vec::new(),
        fake_block_backends: Vec::new(),
        virtio_blk_backends: Vec::new(),
        block_benchmarks: Vec::new(),
        io_cleanups: Vec::new(),
        block_pending_io_policies: Vec::new(),
        block_waits: Vec::new(),
        block_request_objects: Vec::new(),
        block_device_objects: Vec::new(),
        block_range_objects: Vec::new(),
        block_request_queues: Vec::new(),
        block_dma_buffers: Vec::new(),
        harts: Vec::new(),
        tasks: Vec::new(),
        runtime_activations: Vec::new(),
        runnable_queues: Vec::new(),
        scheduler_decisions: Vec::new(),
        activation_contexts: Vec::new(),
        activation_migrations: Vec::new(),
        smp_safe_points: Vec::new(),
        stop_the_world_rendezvous: Vec::new(),
        smp_code_publish_barriers: Vec::new(),
        saved_contexts: Vec::new(),
        timer_interrupts: Vec::new(),
        remote_preempts: Vec::new(),
        activation_cleanups: Vec::new(),
        smp_cleanup_quiescence: Vec::new(),
        smp_snapshot_barriers: Vec::new(),
        smp_stress_runs: Vec::new(),
        preemptions: Vec::new(),
        activation_resumes: Vec::new(),
        stores: {
            let mut stores = Vec::new();
            stores.push(store.store);
            stores
        },
        activations: {
            let mut activations = Vec::new();
            activations.push(activation_record);
            activations
        },
        traps: Vec::new(),
        hostcalls: {
            let mut hostcalls = Vec::new();
            hostcalls.push(trace);
            hostcalls
        },
        capabilities: Vec::new(),
        waits: Vec::new(),
        cleanup_transactions: Vec::new(),
        tombstones: {
            let mut tombstones = executor.tombstones().to_vec();
            tombstones.push(TombstoneRecord::new(
                ContractObjectKind::CodeObject,
                code.id,
                historical_generation,
                99,
                "code-generation-retired",
            ));
            tombstones
        },
        external_objects: Vec::new(),
        explicit_edges: Vec::new(),
    };
    let violations = validate_contract_graph(&snapshot);
    assert!(!violations.iter().any(|violation| {
        violation.edge == "hostcall->code"
            && matches!(
                violation.kind,
                ContractViolationKind::GenerationMismatch
                    | ContractViolationKind::TombstoneReferencedByLiveEdge
            )
    }));
}

#[test]
fn contract_graph_validator_enforces_live_cleanup_and_external_edges() {
    let (artifact, store, code, capabilities) = running_store_and_code();
    let mut dead_store = store.store.clone();
    dead_store.state = StoreState::Dead;
    let mut activation = ActivationRecord {
        id: 55,
        store: dead_store.id,
        store_generation: dead_store.generation,
        code_object: code.id,
        code_generation: code.generation,
        artifact: code.artifact_id,
        entry: ActivationEntry::Symbol("_start".to_string()),
        generation: 1,
        state: ActivationState::Running,
        start_event: 1,
        exit_event: None,
        active_dmw_leases: 1,
        blocked_wait: None,
        trap: None,
        return_tag: None,
    };
    activation.active_dmw_leases = 1;
    let wait = WaitRecord {
        id: 77,
        owner_task: None,
        owner_task_generation: None,
        owner_store: Some(dead_store.id),
        owner_store_generation: Some(dead_store.generation),
        kind: SemanticWaitKind::Futex,
        generation: 1,
        state: WaitState::Pending,
        blockers: {
            let mut blockers = Vec::new();
            blockers.push(ContractObjectRef::new(ContractObjectKind::Resource, 1, 1));
            blockers
        },
        deadline: None,
        cancel_reason: None,
        restart_policy: RestartPolicy::RestartIfAllowed,
        saved_context: None,
    };
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        artifacts: {
            let mut artifacts = Vec::new();
            artifacts.push(artifact);
            artifacts
        },
        code_objects: {
            let mut objects = Vec::new();
            objects.push(code.clone());
            objects
        },
        target_feature_sets: Vec::new(),
        vector_states: Vec::new(),
        simd_fault_injections: Vec::new(),
        simd_benchmarks: Vec::new(),
        simd_context_switch_benchmarks: Vec::new(),
        framebuffer_objects: Vec::new(),
        display_objects: Vec::new(),
        display_capabilities: Vec::new(),
        framebuffer_window_leases: Vec::new(),
        framebuffer_mappings: Vec::new(),
        framebuffer_writes: Vec::new(),
        framebuffer_flush_regions: Vec::new(),
        framebuffer_dirty_regions: Vec::new(),
        display_event_logs: Vec::new(),
        display_cleanups: Vec::new(),
        display_snapshot_barriers: Vec::new(),
        display_panic_last_frames: Vec::new(),
        framebuffer_benchmarks: Vec::new(),
        integrated_display_scheduler_loads: Vec::new(),
        integrated_snapshot_io_lease_barriers: Vec::new(),
        integrated_code_publish_smp_workloads: Vec::new(),
        integrated_display_panics: Vec::new(),
        integrated_osctl_trace_replays: Vec::new(),
        integrated_smp_preemption_cleanups: Vec::new(),
        integrated_smp_network_faults: Vec::new(),
        integrated_disk_preempt_faults: Vec::new(),
        integrated_simd_migrations: Vec::new(),
        integrated_network_disk_ios: Vec::new(),
        network_benchmarks: Vec::new(),
        network_driver_cleanups: Vec::new(),
        device_objects: Vec::new(),
        packet_device_objects: Vec::new(),
        network_stack_adapters: Vec::new(),
        socket_objects: Vec::new(),
        fake_net_backends: Vec::new(),
        virtio_net_backends: Vec::new(),
        fake_block_backends: Vec::new(),
        virtio_blk_backends: Vec::new(),
        block_benchmarks: Vec::new(),
        io_cleanups: Vec::new(),
        block_pending_io_policies: Vec::new(),
        block_waits: Vec::new(),
        block_request_objects: Vec::new(),
        block_device_objects: Vec::new(),
        block_range_objects: Vec::new(),
        block_request_queues: Vec::new(),
        block_dma_buffers: Vec::new(),
        harts: Vec::new(),
        tasks: Vec::new(),
        runtime_activations: Vec::new(),
        runnable_queues: Vec::new(),
        scheduler_decisions: Vec::new(),
        activation_contexts: Vec::new(),
        activation_migrations: Vec::new(),
        smp_safe_points: Vec::new(),
        stop_the_world_rendezvous: Vec::new(),
        smp_code_publish_barriers: Vec::new(),
        saved_contexts: Vec::new(),
        timer_interrupts: Vec::new(),
        remote_preempts: Vec::new(),
        activation_cleanups: Vec::new(),
        smp_cleanup_quiescence: Vec::new(),
        smp_snapshot_barriers: Vec::new(),
        smp_stress_runs: Vec::new(),
        preemptions: Vec::new(),
        activation_resumes: Vec::new(),
        stores: {
            let mut stores = Vec::new();
            stores.push(dead_store.clone());
            stores
        },
        activations: {
            let mut activations = Vec::new();
            activations.push(activation);
            activations
        },
        traps: Vec::new(),
        hostcalls: Vec::new(),
        capabilities: capabilities.records().to_vec(),
        waits: {
            let mut waits = Vec::new();
            waits.push(wait);
            waits
        },
        cleanup_transactions: Vec::new(),
        tombstones: {
            let mut tombstones = Vec::new();
            tombstones.push(TombstoneRecord::new(
                ContractObjectKind::CodeObject,
                code.id,
                code.generation + 1,
                99,
                "old-code-generation",
            ));
            tombstones
        },
        external_objects: Vec::new(),
        explicit_edges: {
            let mut edges = Vec::new();
            edges.push(ContractEdgeRecord::new(
                dead_store.object_ref(),
                ContractObjectRef::new(
                    ContractObjectKind::CodeObject,
                    code.id,
                    code.generation + 1,
                ),
                ContractEdgeMode::Live,
                "store->stale-code-live",
                1,
            ));
            edges.push(ContractEdgeRecord::new(
                dead_store.object_ref(),
                ContractObjectRef::new(
                    ContractObjectKind::CodeObject,
                    code.id,
                    code.generation + 2,
                ),
                ContractEdgeMode::Historical,
                "store->missing-code-history",
                1,
            ));
            edges.push(ContractEdgeRecord::new(
                dead_store.object_ref(),
                capabilities.records()[0].object_ref(),
                ContractEdgeMode::CleanupEffect,
                "owns",
                1,
            ));
            edges.push(
                ContractEdgeRecord::new(
                    dead_store.object_ref(),
                    ContractObjectRef::new(ContractObjectKind::ExternalObject, 41, 0),
                    ContractEdgeMode::External,
                    "store->external-device",
                    1,
                )
                .with_external_metadata("pci", "device"),
            );
            edges
        },
    };
    let violations = validate_contract_graph(&snapshot);
    assert!(violations.iter().any(|violation| {
        violation.kind == ContractViolationKind::LiveObjectReferencesDeadObject
            && violation.edge == "activation->store"
    }));
    assert!(violations.iter().any(|violation| {
        violation.kind == ContractViolationKind::LiveObjectReferencesDeadObject
            && violation.edge == "activation->dmw-lease"
    }));
    assert!(violations.iter().any(|violation| {
        violation.kind == ContractViolationKind::LiveEdgeReferencesInactiveObject
            && violation.edge == "capability->owner-store"
    }));
    assert!(violations.iter().any(|violation| {
        violation.kind == ContractViolationKind::LiveEdgeReferencesInactiveObject
            && violation.edge == "wait->owner-store"
    }));
    assert!(violations.iter().any(|violation| {
        violation.kind == ContractViolationKind::TombstoneReferencedByLiveEdge
            && violation.edge == "store->stale-code-live"
    }));
    assert!(violations.iter().any(|violation| {
        violation.kind == ContractViolationKind::GenerationMismatch
            && violation.edge == "store->missing-code-history"
    }));
    assert!(violations.iter().any(|violation| {
        violation.kind == ContractViolationKind::CleanupEffectCreatesLiveOwnership
            && violation.edge == "owns"
    }));
    assert!(violations.iter().any(|violation| {
        violation.kind == ContractViolationKind::ExternalEdgeMissingDeclaration
            && violation.edge == "store->external-device"
    }));
}

#[test]
fn contract_graph_validator_allows_historical_cleanup_and_declared_external_edges() {
    let (artifact, store, code, capabilities) = running_store_and_code();
    let mut current_store = store.store.clone();
    let historical_store_generation = current_store.generation;
    current_store.generation += 1;
    let mut revoked_capability = capabilities.records()[0].clone();
    revoked_capability.revoked = true;
    let cleanup = FaultCleanupTransaction {
        id: 17,
        store: current_store.id,
        store_generation: current_store.generation,
        result_store_generation: None,
        activation: None,
        activation_generation: None,
        code_object: None,
        code_generation: None,
        generation: 1,
        started_at: 1,
        finished_at: None,
        state: CleanupTransactionState::Pending,
        reason: "edge-mode-test".to_string(),
        steps: Vec::new(),
        effects: Vec::new(),
        released_dmw_leases: 0,
        cancelled_waits: 0,
        revoked_capabilities: Vec::new(),
        revoked_capability_refs: Vec::new(),
        dropped_resources: 0,
        unbound_code_object: false,
        state_digest: String::new(),
        effect: FailureEffect::CompleteWithErrno(5),
    };
    let trap = TargetTrapRecord {
        id: 23,
        generation: 1,
        class: TargetTrapClass::SupervisorStoreTrap,
        store: Some(current_store.id),
        store_generation: Some(historical_store_generation),
        activation: None,
        activation_generation: None,
        code_object: None,
        code_generation: None,
        artifact: None,
        artifact_generation: None,
        offset: None,
        target_pc: None,
        trap_kind: None,
        function_index: None,
        wasm_offset: None,
        debug_symbol: None,
        classification_status: None,
        attribution_status: "synthetic".to_string(),
        simd_attribution: None,
        hostcall: None,
        fault_policy: "history-only".to_string(),
        effect: FailureEffect::CompleteWithErrno(5),
        detail: "store history".to_string(),
    };
    let external = ExternalObjectDeclaration::new(
        ContractObjectRef::new(ContractObjectKind::ExternalObject, 9, 0),
        "pci",
        "device",
        "virtio-net",
    );
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        artifacts: {
            let mut artifacts = Vec::new();
            artifacts.push(artifact);
            artifacts
        },
        code_objects: {
            let mut objects = Vec::new();
            objects.push(code.clone());
            objects
        },
        target_feature_sets: Vec::new(),
        vector_states: Vec::new(),
        simd_fault_injections: Vec::new(),
        simd_benchmarks: Vec::new(),
        simd_context_switch_benchmarks: Vec::new(),
        framebuffer_objects: Vec::new(),
        display_objects: Vec::new(),
        display_capabilities: Vec::new(),
        framebuffer_window_leases: Vec::new(),
        framebuffer_mappings: Vec::new(),
        framebuffer_writes: Vec::new(),
        framebuffer_flush_regions: Vec::new(),
        framebuffer_dirty_regions: Vec::new(),
        display_event_logs: Vec::new(),
        display_cleanups: Vec::new(),
        display_snapshot_barriers: Vec::new(),
        display_panic_last_frames: Vec::new(),
        framebuffer_benchmarks: Vec::new(),
        integrated_display_scheduler_loads: Vec::new(),
        integrated_snapshot_io_lease_barriers: Vec::new(),
        integrated_code_publish_smp_workloads: Vec::new(),
        integrated_display_panics: Vec::new(),
        integrated_osctl_trace_replays: Vec::new(),
        integrated_smp_preemption_cleanups: Vec::new(),
        integrated_smp_network_faults: Vec::new(),
        integrated_disk_preempt_faults: Vec::new(),
        integrated_simd_migrations: Vec::new(),
        integrated_network_disk_ios: Vec::new(),
        network_benchmarks: Vec::new(),
        network_driver_cleanups: Vec::new(),
        device_objects: Vec::new(),
        packet_device_objects: Vec::new(),
        network_stack_adapters: Vec::new(),
        socket_objects: Vec::new(),
        fake_net_backends: Vec::new(),
        virtio_net_backends: Vec::new(),
        fake_block_backends: Vec::new(),
        virtio_blk_backends: Vec::new(),
        block_benchmarks: Vec::new(),
        io_cleanups: Vec::new(),
        block_pending_io_policies: Vec::new(),
        block_waits: Vec::new(),
        block_request_objects: Vec::new(),
        block_device_objects: Vec::new(),
        block_range_objects: Vec::new(),
        block_request_queues: Vec::new(),
        block_dma_buffers: Vec::new(),
        harts: Vec::new(),
        tasks: Vec::new(),
        runtime_activations: Vec::new(),
        runnable_queues: Vec::new(),
        scheduler_decisions: Vec::new(),
        activation_contexts: Vec::new(),
        activation_migrations: Vec::new(),
        smp_safe_points: Vec::new(),
        stop_the_world_rendezvous: Vec::new(),
        smp_code_publish_barriers: Vec::new(),
        saved_contexts: Vec::new(),
        timer_interrupts: Vec::new(),
        remote_preempts: Vec::new(),
        activation_cleanups: Vec::new(),
        smp_cleanup_quiescence: Vec::new(),
        smp_snapshot_barriers: Vec::new(),
        smp_stress_runs: Vec::new(),
        preemptions: Vec::new(),
        activation_resumes: Vec::new(),
        stores: {
            let mut stores = Vec::new();
            stores.push(current_store.clone());
            stores
        },
        activations: Vec::new(),
        traps: {
            let mut traps = Vec::new();
            traps.push(trap.clone());
            traps
        },
        hostcalls: {
            let mut hostcalls = Vec::new();
            hostcalls.push(HostcallTraceRecord {
                id: 31,
                generation: 1,
                abi_version: HostcallFrame::ABI_VERSION.to_string(),
                frame_size: HostcallFrame::FRAME_SIZE,
                flags: 0,
                activation: 44,
                activation_generation: 1,
                store: current_store.id,
                store_generation: current_store.generation,
                code_object: code.id,
                code_generation: code.generation,
                artifact: code.artifact_id,
                artifact_generation: 1,
                hostcall_number: 1,
                hostcall_seq: 1,
                caller_offset: 0,
                name: "hostcall.history".to_string(),
                category: HostcallCategory::Mmio,
                subject: code.package.clone(),
                subject_source: HostcallTraceRecord::SUBJECT_SOURCE_ACTIVE_STATE.to_string(),
                object: "mmio.virtio-net".to_string(),
                operation: "map".to_string(),
                args: [0; 6],
                cap_args: Vec::new(),
                record_mode: RecordMode::Deterministic,
                allowed: true,
                gate_status: "exit".to_string(),
                result: "ok".to_string(),
                denial_reason: None,
                ret_tag: HostcallReturnTag::Ok,
                ret0: 0,
                ret1: 0,
                trap_out: None,
                trap_generation_out: None,
                wait_token_out: None,
                wait_token_generation_out: None,
            });
            hostcalls
        },
        capabilities: {
            let mut caps = Vec::new();
            caps.push(revoked_capability.clone());
            caps
        },
        waits: Vec::new(),
        cleanup_transactions: {
            let mut cleanups = Vec::new();
            cleanups.push(cleanup.clone());
            cleanups
        },
        tombstones: {
            let mut tombstones = Vec::new();
            tombstones.push(TombstoneRecord::new(
                ContractObjectKind::Store,
                current_store.id,
                historical_store_generation,
                70,
                "store-rebound",
            ));
            tombstones.push(TombstoneRecord::new(
                ContractObjectKind::Activation,
                44,
                1,
                71,
                "activation-finished",
            ));
            tombstones
        },
        external_objects: {
            let mut external_objects = Vec::new();
            external_objects.push(external.clone());
            external_objects
        },
        explicit_edges: {
            let mut edges = Vec::new();
            edges.push(ContractEdgeRecord::new(
                trap.object_ref(),
                ContractObjectRef::new(
                    ContractObjectKind::Store,
                    current_store.id,
                    historical_store_generation,
                ),
                ContractEdgeMode::Historical,
                "trap->store-history",
                72,
            ));
            edges.push(ContractEdgeRecord::new(
                cleanup.object_ref(),
                revoked_capability.object_ref(),
                ContractEdgeMode::CleanupEffect,
                "cleanup->capability-revoked",
                73,
            ));
            edges.push(
                ContractEdgeRecord::new(
                    current_store.object_ref(),
                    external.object,
                    ContractEdgeMode::External,
                    "store->declared-external",
                    74,
                )
                .with_external_metadata("pci", "device"),
            );
            edges
        },
    };
    let violations = validate_contract_graph(&snapshot);
    assert!(!violations.iter().any(|violation| {
        violation.edge == "trap->store-history"
            || violation.edge == "cleanup->capability-revoked"
            || violation.edge == "store->declared-external"
            || violation.edge == "hostcall->activation"
    }));
}

#[test]
fn fault_cleanup_transaction_is_idempotent_and_closes_owned_state() {
    let (_artifact, store, code, mut capabilities) = running_store_and_code();
    let mut store = store.store.clone();
    let mut code = code.clone();
    let mut executor = TargetExecutor::new();
    let activation = executor
        .start_activation(&store, &code, ActivationEntry::Symbol("_start".to_string()))
        .unwrap();
    executor.acquire_dmw_lease(activation, "dmw.cleanup.lease").unwrap();
    assert_eq!(executor.snapshot_barrier(), Err(TargetExecutorError::DmwLeaseActive));

    let cleanup_id = executor
        .run_fault_cleanup(
            &mut store,
            Some(activation),
            Some(&mut code),
            &mut capabilities,
            "fault-cleanup-test",
        )
        .unwrap();
    let cleanup = &executor.cleanup_transactions()[0];
    assert_eq!(cleanup.id, cleanup_id);
    assert_eq!(cleanup.state, CleanupTransactionState::Completed);
    assert_eq!(cleanup.released_dmw_leases, 1);
    assert_eq!(cleanup.cancelled_waits, 0);
    assert_eq!(cleanup.revoked_capabilities.len(), 1);
    assert_eq!(cleanup.dropped_resources, 1);
    assert!(cleanup.unbound_code_object);
    assert!(cleanup.steps.iter().all(|step| step.state == CleanupStepState::Done));
    assert!(executor.dmw_leases().iter().all(|lease| !lease.active && lease.generation == 2));
    let activation_record =
        executor.activations().iter().find(|record| record.id == activation).unwrap();
    assert_eq!(activation_record.state, ActivationState::Dropped);
    assert_eq!(activation_record.active_dmw_leases, 0);
    assert_eq!(activation_record.return_tag, Some(HostcallReturnTag::KillStore));
    assert_eq!(store.state, StoreState::Dead);
    assert_eq!(code.state, CodeObjectState::Retired);
    assert_eq!(code.bound_store, None);
    assert!(capabilities.records().iter().all(|record| record.revoked));
    assert!(
        executor.tombstones().iter().any(|tombstone| tombstone.kind == ContractObjectKind::Store
            && tombstone.id == store.id
            && tombstone.generation == store.generation)
    );
    assert!(cleanup.effects.iter().any(|effect| effect.kind == CleanupEffectKind::MarkStoreDead
        && effect.status == CleanupEffectStatus::Applied
        && effect.target == store.object_ref()));
    let digest_after_once = executor.cleanup_state_digest(&store, Some(&code), &capabilities);
    assert_eq!(executor.snapshot_barrier(), Ok(()));
    let completed_cleanup = &executor.cleanup_transactions()[0];
    assert_eq!(completed_cleanup.state_digest, digest_after_once);
    assert_eq!(completed_cleanup.result_store_generation, Some(store.generation));
    assert_eq!(completed_cleanup.activation_generation, Some(activation_record.generation));
    assert_eq!(completed_cleanup.code_generation, Some(code.generation));

    let cleanup_id_again = executor
        .run_fault_cleanup(
            &mut store,
            Some(activation),
            Some(&mut code),
            &mut capabilities,
            "fault-cleanup-test",
        )
        .unwrap();
    assert_eq!(cleanup_id_again, cleanup_id);
    assert_eq!(executor.cleanup_transactions().len(), 1);
    assert_eq!(
        executor.cleanup_state_digest(&store, Some(&code), &capabilities),
        digest_after_once
    );
    assert_eq!(executor.cleanup_transactions()[0].state_digest, digest_after_once);
    assert_eq!(executor.cleanup_transactions()[0].revoked_capabilities.len(), 1);
}

#[test]
fn completed_cleanup_for_old_generation_does_not_suppress_rebound_generation() {
    let (_artifact, store, code, mut capabilities) = running_store_and_code();
    let mut old_store = store.store.clone();
    let mut old_code = code.clone();
    let mut executor = TargetExecutor::new();

    let old_cleanup = executor
        .run_fault_cleanup(
            &mut old_store,
            None,
            Some(&mut old_code),
            &mut capabilities,
            "same-fault",
        )
        .unwrap();
    assert_eq!(old_store.state, StoreState::Dead);

    let mut rebound_store = old_store.clone();
    rebound_store.state = StoreState::Running;
    let mut rebound_code = old_code.clone();
    rebound_code.state = CodeObjectState::BoundToStore;
    rebound_code.bound_store = Some(rebound_store.id);
    rebound_code.bound_store_generation = Some(rebound_store.generation);
    rebound_code.generation += 1;

    let next_cleanup = executor
        .run_fault_cleanup(
            &mut rebound_store,
            None,
            Some(&mut rebound_code),
            &mut capabilities,
            "same-fault",
        )
        .unwrap();

    assert_ne!(next_cleanup, old_cleanup);
    assert_eq!(executor.cleanup_transactions().len(), 2);
    assert_eq!(rebound_store.state, StoreState::Dead);
    assert_eq!(rebound_code.bound_store, None);
}

#[test]
fn fault_cleanup_stale_generation_is_visible_and_does_not_mutate_rebound_store() {
    let (_artifact, store, mut code, mut capabilities) = running_store_and_code();
    let mut store = store.store.clone();
    let mut executor = TargetExecutor::new();
    let cleanup_id =
        executor.begin_fault_cleanup_transaction(&store, None, Some(&code), "stale-cleanup-test");
    assert_eq!(executor.snapshot_barrier(), Err(TargetExecutorError::PendingCleanupActive));

    store.generation += 1;
    store.state = StoreState::Running;
    let digest_before = executor.cleanup_state_digest(&store, Some(&code), &capabilities);
    executor
        .apply_fault_cleanup_transaction(cleanup_id, &mut store, Some(&mut code), &mut capabilities)
        .unwrap();
    assert_eq!(store.state, StoreState::Running);
    assert_eq!(code.state, CodeObjectState::BoundToStore);
    assert_eq!(code.bound_store, Some(store.id));
    assert!(capabilities.records().iter().all(|record| !record.revoked));
    assert_eq!(executor.cleanup_state_digest(&store, Some(&code), &capabilities), digest_before);
    let cleanup = &executor.cleanup_transactions()[0];
    assert_eq!(cleanup.state, CleanupTransactionState::SkippedStaleGeneration);
    assert_eq!(cleanup.state_digest, digest_before);
    assert!(
        cleanup.steps.iter().all(|step| step.state == CleanupStepState::SkippedStaleGeneration
            && step.observed_generation == Some(store.generation))
    );
    assert!(cleanup.effects.iter().any(|effect| {
        effect.status == CleanupEffectStatus::SkippedStaleGeneration
            && effect.target
                == ContractObjectRef::new(ContractObjectKind::Store, store.id, store.generation - 1)
    }));
    assert_eq!(executor.snapshot_barrier(), Ok(()));
}

#[test]
fn fault_cleanup_cancels_blocked_wait_and_pending_cleanup_blocks_snapshot() {
    let (_artifact, store, code, mut capabilities) = running_store_and_code();
    let mut store = store.store.clone();
    let mut code = code.clone();
    let mut executor = TargetExecutor::new();
    let activation = executor
        .start_activation(&store, &code, ActivationEntry::Symbol("_start".to_string()))
        .unwrap();
    executor.pending_exit(activation, 77).unwrap();
    assert_eq!(
        executor.activations().iter().find(|record| record.id == activation).unwrap().blocked_wait,
        Some(77)
    );

    let cleanup_id = executor
        .run_fault_cleanup(
            &mut store,
            Some(activation),
            Some(&mut code),
            &mut capabilities,
            "wait-cleanup-test",
        )
        .unwrap();
    let cleanup =
        executor.cleanup_transactions().iter().find(|cleanup| cleanup.id == cleanup_id).unwrap();
    assert_eq!(cleanup.cancelled_waits, 1);
    let activation_record =
        executor.activations().iter().find(|record| record.id == activation).unwrap();
    assert_eq!(activation_record.state, ActivationState::Dropped);
    assert_eq!(activation_record.blocked_wait, None);

    let (_artifact, store, code, _capabilities) = running_store_and_code();
    let mut executor = TargetExecutor::new();
    executor.begin_fault_cleanup_transaction(
        &store.store,
        None,
        Some(&code),
        "pending-cleanup-test",
    );
    assert_eq!(executor.snapshot_barrier(), Err(TargetExecutorError::PendingCleanupActive));
}
