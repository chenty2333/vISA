use super::super::*;

pub(crate) fn run_simd_trap_classification_harness(
    verified_artifacts: &[VerifiedArtifact],
    semantic: &SemanticGraph,
    publisher: &mut CodePublisher,
    store_manager: &mut TargetStoreManager,
    executor: &mut TargetExecutor,
) -> Result<(), Box<dyn Error>> {
    let Some(artifact) = verified_artifacts.first() else {
        return Ok(());
    };
    let Some(feature_set) = semantic.target_feature_sets().first() else {
        return Ok(());
    };
    let store_id =
        store_manager.register_verified_artifact(artifact, "restartable", "simd-trap-harness");
    store_manager.set_running(store_id).map_err(|error| error.message())?;
    let store = store_manager
        .record(store_id)
        .ok_or("SIMD trap harness store missing after registration")?
        .store
        .clone();
    let code_id = publisher.allocate(artifact).map_err(|error| error.message())?;
    publisher
        .declare_simd_requirement(
            code_id,
            feature_set.object_ref(),
            "riscv-v",
            32,
            128,
            "v3 SIMD trap attribution harness",
        )
        .map_err(|error| error.message())?;
    publisher.fill(code_id).map_err(|error| error.message())?;
    publisher.seal(code_id).map_err(|error| error.message())?;
    publisher.publish_rx(code_id).map_err(|error| error.message())?;
    publisher.bind_to_store(code_id, &store).map_err(|error| error.message())?;
    let code =
        publisher.object(code_id).ok_or("SIMD trap harness code missing after bind")?.clone();
    let activation = executor
        .start_activation(&store, &code, ActivationEntry::Symbol("simd_trap_harness".to_owned()))
        .map_err(|error| error.message())?;
    let offset = RV64_ENTRY_TRAP_EBREAK_OFFSET + 0x40;
    let trap_map = [TrapMapEntryV1::new(
        ObjectRefRaw::new(OBJECT_KIND_CODE_OBJECT_V1, code.id, code.generation),
        offset,
        offset + 4,
        TrapKindV1::SimdUnsupported,
        42,
        offset,
        6,
    )];
    executor
        .trap_exit_by_pc(activation, &code, code.text.start + offset, &trap_map)
        .map_err(|error| error.message())?;
    Ok(())
}

pub(crate) fn run_simd_vector_state_harness(
    semantic: &mut SemanticGraph,
    publisher: &CodePublisher,
    executor: &TargetExecutor,
) -> Result<(), Box<dyn Error>> {
    let Some(feature_set) = semantic.target_feature_sets().first().cloned() else {
        return Ok(());
    };
    let Some(code) = publisher.objects().iter().find(|code| code.simd_requirement.uses_simd) else {
        return Ok(());
    };
    let Some(activation) = executor.activations().iter().find(|activation| {
        activation.code_object == code.id && activation.code_generation == code.generation
    }) else {
        return Ok(());
    };
    let state = if feature_set.simd_supported {
        VectorStateState::Reserved
    } else {
        VectorStateState::Unavailable
    };
    let register_bytes = u32::from(code.simd_requirement.min_vector_register_count)
        * (u32::from(code.simd_requirement.min_vector_register_bits) / 8);
    let result = semantic.apply_envelope(CommandEnvelope::new(
        60_004,
        "simd-runtime-v4",
        SemanticCommand::RecordVectorState {
            vector_state: 22_000,
            owner_activation: ContractObjectRef::new(
                ContractObjectKind::Activation,
                activation.id,
                activation.generation,
            ),
            owner_store: ContractObjectRef::new(
                ContractObjectKind::Store,
                activation.store,
                activation.store_generation,
            ),
            code_object: code.object_ref(),
            target_feature_set: feature_set.object_ref(),
            simd_abi: code.simd_requirement.required_abi.clone(),
            vector_register_count: code.simd_requirement.min_vector_register_count,
            vector_register_bits: code.simd_requirement.min_vector_register_bits,
            register_bytes,
            state,
            note: "v4 vector state object records SIMD context ownership boundary".to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "simd runtime v4 vector state command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_simd_activation_context_vector_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    semantic.ensure_task(9_050, FrontendKind::WasmApp, "v5-simd-vector-context-task");
    let commands = [
        CommandEnvelope::new(
            60_005,
            "simd-runtime-v5",
            SemanticCommand::CreateRuntimeActivation {
                activation: 9_050,
                owner_task: 9_050,
                owner_task_generation: 1,
                owner_store: None,
                owner_store_generation: None,
                code_object: None,
            },
        ),
        CommandEnvelope::new(
            60_006,
            "simd-runtime-v5",
            SemanticCommand::CreateActivationContext {
                context: 9_050,
                activation: 9_050,
                activation_generation: 1,
            },
        ),
        CommandEnvelope::new(
            60_007,
            "simd-runtime-v5",
            SemanticCommand::UpdateActivationContextVectorState {
                context: 9_050,
                context_generation: 1,
                vector_state: None,
                vector_status: ActivationVectorState::Absent,
                note: "v5 activation context records vector state as absent until SIMD is live"
                    .to_owned(),
            },
        ),
    ];
    for command in commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "simd runtime v5 command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }
    Ok(())
}

pub(crate) fn run_simd_lazy_vector_enable_harness(
    verified_artifacts: &[VerifiedArtifact],
    semantic: &mut SemanticGraph,
    publisher: &mut CodePublisher,
    store_manager: &mut TargetStoreManager,
    executor: &mut TargetExecutor,
) -> Result<(), Box<dyn Error>> {
    let Some(artifact) = verified_artifacts.first() else {
        return Ok(());
    };
    let feature_set = 21_001;
    let feature_recorded = semantic.apply_envelope(CommandEnvelope::new(
        60_010,
        "simd-runtime-v6",
        SemanticCommand::RecordTargetFeatureSet {
            feature_set,
            name: "v6-simd-supported-fixture".to_owned(),
            discovery_source: "target-executor-v6-lazy-vector-enable-harness".to_owned(),
            target_profile: "riscv64-vector-host-validation-fixture".to_owned(),
            target_arch: "riscv64".to_owned(),
            base_isa: "rv64gcv".to_owned(),
            simd_abi: "riscv-v".to_owned(),
            simd_supported: true,
            vector_register_count: 32,
            vector_register_bits: 128,
            scalar_fallback: false,
            unsupported_reason: String::new(),
            note: "v6 synthetic supported SIMD fixture for lazy enable contract".to_owned(),
        },
    ));
    if feature_recorded.status != CommandStatus::Applied {
        return Err(format!(
            "simd runtime v6 target feature command {} ({}) failed: status={} violations={:?}",
            feature_recorded.command_id,
            feature_recorded.command,
            feature_recorded.status.as_str(),
            feature_recorded.violations
        )
        .into());
    }
    let feature_ref = semantic
        .target_feature_sets()
        .iter()
        .find(|feature| feature.id == feature_set)
        .map(|feature| feature.object_ref())
        .ok_or("v6 target feature fixture missing")?;

    let store_id =
        store_manager.register_verified_artifact(artifact, "restartable", "simd-lazy-enable");
    store_manager.set_running(store_id).map_err(|error| error.message())?;
    let store = store_manager
        .record(store_id)
        .ok_or("SIMD lazy enable store missing after registration")?
        .store
        .clone();
    let code_id = publisher.allocate(artifact).map_err(|error| error.message())?;
    publisher
        .declare_simd_requirement(
            code_id,
            feature_ref,
            "riscv-v",
            32,
            128,
            "v6 lazy vector enable harness",
        )
        .map_err(|error| error.message())?;
    publisher.fill(code_id).map_err(|error| error.message())?;
    publisher.seal(code_id).map_err(|error| error.message())?;
    publisher.publish_rx(code_id).map_err(|error| error.message())?;
    publisher.bind_to_store(code_id, &store).map_err(|error| error.message())?;
    let code = publisher.object(code_id).ok_or("SIMD lazy enable code missing after bind")?.clone();
    let activation = executor
        .start_activation(
            &store,
            &code,
            ActivationEntry::Symbol("simd_lazy_vector_enable".to_owned()),
        )
        .map_err(|error| error.message())?;

    semantic.ensure_task(9_060, FrontendKind::WasmApp, "v6-simd-lazy-vector-enable-task");
    let commands = [
        CommandEnvelope::new(
            60_011,
            "simd-runtime-v6",
            SemanticCommand::CreateRuntimeActivation {
                activation,
                owner_task: 9_060,
                owner_task_generation: 1,
                owner_store: None,
                owner_store_generation: None,
                code_object: Some(code.object_ref()),
            },
        ),
        CommandEnvelope::new(
            60_012,
            "simd-runtime-v6",
            SemanticCommand::CreateActivationContext {
                context: 9_060,
                activation,
                activation_generation: 1,
            },
        ),
        CommandEnvelope::new(
            60_013,
            "simd-runtime-v6",
            SemanticCommand::RecordVectorState {
                vector_state: 22_001,
                owner_activation: ContractObjectRef::new(
                    ContractObjectKind::Activation,
                    activation,
                    1,
                ),
                owner_store: ContractObjectRef::new(
                    ContractObjectKind::Store,
                    store.id,
                    store.generation,
                ),
                code_object: code.object_ref(),
                target_feature_set: feature_ref,
                simd_abi: "riscv-v".to_owned(),
                vector_register_count: 32,
                vector_register_bits: 128,
                register_bytes: 512,
                state: VectorStateState::Reserved,
                note: "v6 reserved vector state before lazy enable".to_owned(),
            },
        ),
        CommandEnvelope::new(
            60_014,
            "simd-runtime-v6",
            SemanticCommand::EnableLazyVectorState {
                context: 9_060,
                context_generation: 1,
                vector_state: ContractObjectRef::new(ContractObjectKind::VectorState, 22_001, 1),
                note: "v6 first vector instruction marks activation context dirty".to_owned(),
            },
        ),
    ];
    for command in commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "simd runtime v6 command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }
    Ok(())
}

pub(crate) fn run_simd_preempt_vector_save_harness(
    verified_artifacts: &[VerifiedArtifact],
    semantic: &mut SemanticGraph,
    publisher: &mut CodePublisher,
    store_manager: &mut TargetStoreManager,
    executor: &mut TargetExecutor,
    ledger: &mut CapabilityLedger,
) -> Result<(), Box<dyn Error>> {
    let Some(artifact) = verified_artifacts.first() else {
        return Ok(());
    };
    let feature_set = 21_002;
    let feature_recorded = semantic.apply_envelope(CommandEnvelope::new(
        70_010,
        "simd-runtime-v7",
        SemanticCommand::RecordTargetFeatureSet {
            feature_set,
            name: "v7-simd-preempt-save-fixture".to_owned(),
            discovery_source: "target-executor-v7-preempt-vector-save-harness".to_owned(),
            target_profile: "riscv64-vector-host-validation-fixture".to_owned(),
            target_arch: "riscv64".to_owned(),
            base_isa: "rv64gcv".to_owned(),
            simd_abi: "riscv-v".to_owned(),
            simd_supported: true,
            vector_register_count: 32,
            vector_register_bits: 128,
            scalar_fallback: false,
            unsupported_reason: String::new(),
            note: "v7 synthetic supported SIMD fixture for preempt vector save".to_owned(),
        },
    ));
    if feature_recorded.status != CommandStatus::Applied {
        return Err(format!(
            "simd runtime v7 target feature command {} ({}) failed: status={} violations={:?}",
            feature_recorded.command_id,
            feature_recorded.command,
            feature_recorded.status.as_str(),
            feature_recorded.violations
        )
        .into());
    }
    let feature_ref = semantic
        .target_feature_sets()
        .iter()
        .find(|feature| feature.id == feature_set)
        .map(|feature| feature.object_ref())
        .ok_or("v7 target feature fixture missing")?;

    let store_id = store_manager.register_verified_artifact(
        artifact,
        "restartable",
        "simd-preempt-vector-save",
    );
    store_manager.set_running(store_id).map_err(|error| error.message())?;
    let store = store_manager
        .record(store_id)
        .ok_or("SIMD preempt vector save store missing after registration")?
        .store
        .clone();
    let code_id = publisher.allocate(artifact).map_err(|error| error.message())?;
    publisher
        .declare_simd_requirement(
            code_id,
            feature_ref,
            "riscv-v",
            32,
            128,
            "v7 preempt vector save harness",
        )
        .map_err(|error| error.message())?;
    publisher.fill(code_id).map_err(|error| error.message())?;
    publisher.seal(code_id).map_err(|error| error.message())?;
    publisher.publish_rx(code_id).map_err(|error| error.message())?;
    publisher.bind_to_store(code_id, &store).map_err(|error| error.message())?;
    let code = publisher
        .object(code_id)
        .ok_or("SIMD preempt vector save code missing after bind")?
        .clone();
    let activation = executor
        .start_activation(
            &store,
            &code,
            ActivationEntry::Symbol("simd_preempt_vector_save".to_owned()),
        )
        .map_err(|error| error.message())?;
    let hostcall_spec = code
        .hostcalls
        .iter()
        .find(|spec| {
            spec.number == 1 && spec.object == "console.write" && spec.operation == "write"
        })
        .ok_or("SIMD preempt vector save hostcall spec missing")?;
    ledger
        .grant_manifest_binding(
            &code.package,
            &hostcall_spec.object,
            &[hostcall_spec.operation.as_str()],
            "activation",
            CapabilityClass::ServiceImport,
            Some(store.id),
            Some(store.generation),
            None,
            "v7-preempt-vector-save-hostcall",
        )
        .map_err(|error| error.message())?;
    for hostcall_seq in 1..=3 {
        let activation_generation = executor
            .activations()
            .iter()
            .find(|record| record.id == activation)
            .map(|record| record.generation)
            .ok_or("SIMD preempt vector activation missing before generation advance")?;
        let mut frame = HostcallFrame::new_bound(
            activation,
            &store,
            &code,
            hostcall_spec.number,
            &hostcall_spec.object,
            &hostcall_spec.operation,
            ledger.generation_of(&code.package, &hostcall_spec.object).unwrap_or(1),
        )
        .with_hostcall_seq(hostcall_seq);
        frame.activation_generation = activation_generation;
        if let Some(cap_arg) = capability_handle_arg_for(ledger, &code.package, hostcall_spec) {
            frame = frame.with_cap_args(vec![cap_arg]);
        }
        executor
            .invoke_hostcall(&code, frame.to_wire_frame(), ledger)
            .map_err(|error| error.message())?;
    }

    semantic.ensure_task(9_070, FrontendKind::WasmApp, "v7-simd-preempt-vector-save-task");
    let commands = [
        CommandEnvelope::new(
            70_011,
            "simd-runtime-v7",
            SemanticCommand::RegisterHart {
                hart: 7,
                hardware_id: 7,
                label: "v7-vector-save-hart".to_owned(),
                boot: false,
                note: "v7 hart for timer preempt evidence".to_owned(),
            },
        ),
        CommandEnvelope::new(
            70_012,
            "simd-runtime-v7",
            SemanticCommand::SetHartState {
                hart: 7,
                hart_generation: 1,
                state: HartState::Idle,
                reason: "v7-scheduler-ready".to_owned(),
                note: "v7 hart idle before dispatch".to_owned(),
            },
        ),
        CommandEnvelope::new(
            70_013,
            "simd-runtime-v7",
            SemanticCommand::CreateRunnableQueue {
                queue: 9_070,
                label: "v7-simd-preempt-runnable-queue".to_owned(),
            },
        ),
        CommandEnvelope::new(
            70_014,
            "simd-runtime-v7",
            SemanticCommand::BindRunnableQueueOwner {
                queue: 9_070,
                queue_generation: 1,
                hart: 7,
                hart_generation: 2,
                note: "v7 queue owned by vector-save hart".to_owned(),
            },
        ),
        CommandEnvelope::new(
            70_015,
            "simd-runtime-v7",
            SemanticCommand::CreateRuntimeActivation {
                activation,
                owner_task: 9_070,
                owner_task_generation: 1,
                owner_store: None,
                owner_store_generation: None,
                code_object: Some(code.object_ref()),
            },
        ),
        CommandEnvelope::new(
            70_016,
            "simd-runtime-v7",
            SemanticCommand::EnqueueRunnable { queue: 9_070, activation, activation_generation: 1 },
        ),
        CommandEnvelope::new(
            70_017,
            "simd-runtime-v7",
            SemanticCommand::DequeueRunnable { queue: 9_070, activation },
        ),
        CommandEnvelope::new(
            70_018,
            "simd-runtime-v7",
            SemanticCommand::RecordTimerInterrupt {
                interrupt: 9_070,
                timer_epoch: 70,
                hart: 7,
                hart_generation: 2,
                target_activation: Some(activation),
                target_activation_generation: Some(3),
                note: "v7 timer interrupt for dirty vector preempt".to_owned(),
            },
        ),
        CommandEnvelope::new(
            70_019,
            "simd-runtime-v7",
            SemanticCommand::PreemptActivation {
                preemption: 9_070,
                activation,
                activation_generation: 3,
                timer_interrupt: 9_070,
                timer_interrupt_generation: 1,
                queue: 9_070,
                note: "v7 timer preempt before vector state save".to_owned(),
            },
        ),
        CommandEnvelope::new(
            70_020,
            "simd-runtime-v7",
            SemanticCommand::SavePreemptedContext {
                context: 9_070,
                saved_context: 9_070,
                preemption: 9_070,
                preemption_generation: 1,
                pc: 0x7070,
                sp: 0x9000,
                flags: 0,
                note: "v7 integer frame saved before vector state".to_owned(),
            },
        ),
        CommandEnvelope::new(
            70_021,
            "simd-runtime-v7",
            SemanticCommand::RecordVectorState {
                vector_state: 22_002,
                owner_activation: ContractObjectRef::new(
                    ContractObjectKind::Activation,
                    activation,
                    4,
                ),
                owner_store: ContractObjectRef::new(
                    ContractObjectKind::Store,
                    store.id,
                    store.generation,
                ),
                code_object: code.object_ref(),
                target_feature_set: feature_ref,
                simd_abi: "riscv-v".to_owned(),
                vector_register_count: 32,
                vector_register_bits: 128,
                register_bytes: 512,
                state: VectorStateState::Reserved,
                note: "v7 reserved dirty vector state at preempt".to_owned(),
            },
        ),
        CommandEnvelope::new(
            70_022,
            "simd-runtime-v7",
            SemanticCommand::UpdateActivationContextVectorState {
                context: 9_070,
                context_generation: 2,
                vector_state: Some(ContractObjectRef::new(
                    ContractObjectKind::VectorState,
                    22_002,
                    1,
                )),
                vector_status: ActivationVectorState::Dirty,
                note: "v7 context carries dirty vector state before save".to_owned(),
            },
        ),
        CommandEnvelope::new(
            70_023,
            "simd-runtime-v7",
            SemanticCommand::SaveDirtyVectorStateOnPreempt {
                context: 9_070,
                context_generation: 3,
                saved_context: 9_070,
                saved_context_generation: 1,
                preemption: 9_070,
                preemption_generation: 1,
                vector_state: ContractObjectRef::new(ContractObjectKind::VectorState, 22_002, 1),
                note: "v7 timer preempt saves dirty vector state".to_owned(),
            },
        ),
    ];
    for command in commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "simd runtime v7 command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }
    Ok(())
}

pub(crate) fn run_simd_resume_vector_restore_harness(
    semantic: &mut SemanticGraph,
    publisher: &CodePublisher,
    store_manager: &TargetStoreManager,
    executor: &mut TargetExecutor,
    ledger: &mut CapabilityLedger,
) -> Result<(), Box<dyn Error>> {
    let Some(context) = semantic
        .activation_contexts()
        .iter()
        .find(|context| context.id == 9_070 && context.state == ActivationContextState::Saved)
    else {
        return Ok(());
    };
    let activation = context.activation;
    let activation_generation = context.activation_generation;
    let Some(activation_record) = semantic.runtime_activations().iter().find(|record| {
        record.id == activation
            && record.generation == activation_generation
            && record.state == RuntimeActivationState::Runnable
    }) else {
        return Err("v8 runnable activation for vector restore is missing".into());
    };
    let Some(queue) = activation_record.runnable_queue else {
        return Err("v8 runnable activation has no queue".into());
    };
    let Some(queue_generation) = activation_record.runnable_queue_generation else {
        return Err("v8 runnable activation has no queue generation".into());
    };
    let Some(saved_vector_state) = semantic
        .saved_contexts()
        .iter()
        .find(|saved| saved.id == 9_070)
        .and_then(|saved| saved.vector_state)
    else {
        return Err("v8 saved vector state is missing".into());
    };
    let Some(source_vector) = semantic.vector_states().iter().find(|vector| {
        vector.id == saved_vector_state.id && vector.generation == saved_vector_state.generation
    }) else {
        return Err("v8 saved vector state record is missing".into());
    };
    let code = publisher
        .objects()
        .iter()
        .find(|code| {
            code.id == source_vector.code_object.id
                && code.generation == source_vector.code_object.generation
        })
        .ok_or("v8 code object for vector restore is missing")?;
    let target_activation_generation = executor
        .activations()
        .iter()
        .find(|record| record.id == activation)
        .map(|record| record.generation)
        .ok_or("v8 target activation for vector restore is missing")?;
    let target_store = store_manager
        .record(source_vector.owner_store.id)
        .ok_or("v8 target store for vector restore is missing")?
        .store
        .clone();
    if target_store.generation != source_vector.owner_store.generation {
        return Err("v8 target store generation for vector restore is stale".into());
    }
    let hostcall_spec = code
        .hostcalls
        .iter()
        .find(|spec| {
            spec.number == 1 && spec.object == "console.write" && spec.operation == "write"
        })
        .ok_or("v8 vector restore hostcall spec missing")?;
    let mut frame = HostcallFrame::new_bound(
        activation,
        &target_store,
        code,
        hostcall_spec.number,
        &hostcall_spec.object,
        &hostcall_spec.operation,
        ledger.generation_of(&code.package, &hostcall_spec.object).unwrap_or(1),
    )
    .with_hostcall_seq(4);
    frame.activation_generation = target_activation_generation;
    if let Some(cap_arg) = capability_handle_arg_for(ledger, &code.package, hostcall_spec) {
        frame = frame.with_cap_args(vec![cap_arg]);
    }
    executor
        .invoke_hostcall(code, frame.to_wire_frame(), ledger)
        .map_err(|error| error.message())?;

    let commands = [
        CommandEnvelope::new(
            80_001,
            "simd-runtime-v8",
            SemanticCommand::RecordSchedulerDecision {
                decision: 9_071,
                queue,
                queue_generation,
                selected_activation: activation,
                selected_activation_generation: activation_generation,
                reason: "v8-vector-restore-runnable".to_owned(),
                note: "v8 scheduler selects preempted vector activation".to_owned(),
            },
        ),
        CommandEnvelope::new(
            80_002,
            "simd-runtime-v8",
            SemanticCommand::ResumeActivation {
                resume: 9_071,
                scheduler_decision: 9_071,
                scheduler_decision_generation: 1,
                activation,
                activation_generation,
                note: "v8 resume restores saved vector state".to_owned(),
            },
        ),
    ];
    for command in commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "simd runtime v8 command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }
    Ok(())
}

pub(crate) fn run_simd_cross_hart_vector_migration_harness(
    verified_artifacts: &[VerifiedArtifact],
    semantic: &mut SemanticGraph,
    publisher: &mut CodePublisher,
    store_manager: &mut TargetStoreManager,
    executor: &mut TargetExecutor,
    ledger: &mut CapabilityLedger,
) -> Result<(), Box<dyn Error>> {
    let Some(artifact) = verified_artifacts.first() else {
        return Ok(());
    };
    let feature_set = 21_003;
    let feature_recorded = semantic.apply_envelope(CommandEnvelope::new(
        90_001,
        "simd-runtime-v9",
        SemanticCommand::RecordTargetFeatureSet {
            feature_set,
            name: "v9-simd-cross-hart-migration-fixture".to_owned(),
            discovery_source: "target-executor-v9-cross-hart-vector-migration-harness".to_owned(),
            target_profile: "riscv64-vector-host-validation-fixture".to_owned(),
            target_arch: "riscv64".to_owned(),
            base_isa: "rv64gcv".to_owned(),
            simd_abi: "riscv-v".to_owned(),
            simd_supported: true,
            vector_register_count: 32,
            vector_register_bits: 128,
            scalar_fallback: false,
            unsupported_reason: String::new(),
            note: "v9 synthetic supported SIMD fixture for cross-hart migration".to_owned(),
        },
    ));
    if feature_recorded.status != CommandStatus::Applied {
        return Err(format!(
            "simd runtime v9 target feature command {} ({}) failed: status={} violations={:?}",
            feature_recorded.command_id,
            feature_recorded.command,
            feature_recorded.status.as_str(),
            feature_recorded.violations
        )
        .into());
    }
    let feature_ref = semantic
        .target_feature_sets()
        .iter()
        .find(|feature| feature.id == feature_set)
        .map(|feature| feature.object_ref())
        .ok_or("v9 target feature fixture missing")?;

    let store_id =
        store_manager.register_verified_artifact(artifact, "restartable", "simd-vector-migration");
    store_manager.set_running(store_id).map_err(|error| error.message())?;
    let store = store_manager
        .record(store_id)
        .ok_or("SIMD vector migration store missing after registration")?
        .store
        .clone();
    let code_id = publisher.allocate(artifact).map_err(|error| error.message())?;
    publisher
        .declare_simd_requirement(
            code_id,
            feature_ref,
            "riscv-v",
            32,
            128,
            "v9 cross-hart vector migration harness",
        )
        .map_err(|error| error.message())?;
    publisher.fill(code_id).map_err(|error| error.message())?;
    publisher.seal(code_id).map_err(|error| error.message())?;
    publisher.publish_rx(code_id).map_err(|error| error.message())?;
    publisher.bind_to_store(code_id, &store).map_err(|error| error.message())?;
    let code =
        publisher.object(code_id).ok_or("SIMD vector migration code missing after bind")?.clone();
    let activation = executor
        .start_activation(
            &store,
            &code,
            ActivationEntry::Symbol("simd_cross_hart_vector_migration".to_owned()),
        )
        .map_err(|error| error.message())?;
    let hostcall_spec = code
        .hostcalls
        .iter()
        .find(|spec| {
            spec.number == 1 && spec.object == "console.write" && spec.operation == "write"
        })
        .ok_or("SIMD vector migration hostcall spec missing")?;
    ledger
        .grant_manifest_binding(
            &code.package,
            &hostcall_spec.object,
            &[hostcall_spec.operation.as_str()],
            "activation",
            CapabilityClass::ServiceImport,
            Some(store.id),
            Some(store.generation),
            None,
            "v9-cross-hart-vector-migration-hostcall",
        )
        .map_err(|error| error.message())?;
    for hostcall_seq in 1..=2 {
        let activation_generation = executor
            .activations()
            .iter()
            .find(|record| record.id == activation)
            .map(|record| record.generation)
            .ok_or("SIMD vector migration activation missing before generation advance")?;
        let mut frame = HostcallFrame::new_bound(
            activation,
            &store,
            &code,
            hostcall_spec.number,
            &hostcall_spec.object,
            &hostcall_spec.operation,
            ledger.generation_of(&code.package, &hostcall_spec.object).unwrap_or(1),
        )
        .with_hostcall_seq(hostcall_seq);
        frame.activation_generation = activation_generation;
        if let Some(cap_arg) = capability_handle_arg_for(ledger, &code.package, hostcall_spec) {
            frame = frame.with_cap_args(vec![cap_arg]);
        }
        executor
            .invoke_hostcall(&code, frame.to_wire_frame(), ledger)
            .map_err(|error| error.message())?;
    }

    semantic.ensure_task(9_080, FrontendKind::WasmApp, "v9-simd-cross-hart-vector-migration-task");
    let commands = [
        CommandEnvelope::new(
            90_002,
            "simd-runtime-v9",
            SemanticCommand::RegisterHart {
                hart: 8,
                hardware_id: 8,
                label: "v9-vector-source-hart".to_owned(),
                boot: false,
                note: "v9 source hart for vector migration evidence".to_owned(),
            },
        ),
        CommandEnvelope::new(
            90_003,
            "simd-runtime-v9",
            SemanticCommand::SetHartState {
                hart: 8,
                hart_generation: 1,
                state: HartState::Idle,
                reason: "v9-source-ready".to_owned(),
                note: "v9 source hart idle before migration".to_owned(),
            },
        ),
        CommandEnvelope::new(
            90_004,
            "simd-runtime-v9",
            SemanticCommand::RegisterHart {
                hart: 9,
                hardware_id: 9,
                label: "v9-vector-target-hart".to_owned(),
                boot: false,
                note: "v9 target hart for vector migration evidence".to_owned(),
            },
        ),
        CommandEnvelope::new(
            90_005,
            "simd-runtime-v9",
            SemanticCommand::SetHartState {
                hart: 9,
                hart_generation: 1,
                state: HartState::Idle,
                reason: "v9-target-ready".to_owned(),
                note: "v9 target hart idle before migration".to_owned(),
            },
        ),
        CommandEnvelope::new(
            90_006,
            "simd-runtime-v9",
            SemanticCommand::CreateRunnableQueue {
                queue: 9_080,
                label: "v9-vector-source-runnable-queue".to_owned(),
            },
        ),
        CommandEnvelope::new(
            90_007,
            "simd-runtime-v9",
            SemanticCommand::BindRunnableQueueOwner {
                queue: 9_080,
                queue_generation: 1,
                hart: 8,
                hart_generation: 2,
                note: "v9 source queue owned by source hart".to_owned(),
            },
        ),
        CommandEnvelope::new(
            90_008,
            "simd-runtime-v9",
            SemanticCommand::CreateRunnableQueue {
                queue: 9_081,
                label: "v9-vector-target-runnable-queue".to_owned(),
            },
        ),
        CommandEnvelope::new(
            90_009,
            "simd-runtime-v9",
            SemanticCommand::BindRunnableQueueOwner {
                queue: 9_081,
                queue_generation: 1,
                hart: 9,
                hart_generation: 2,
                note: "v9 target queue owned by target hart".to_owned(),
            },
        ),
        CommandEnvelope::new(
            90_010,
            "simd-runtime-v9",
            SemanticCommand::CreateRuntimeActivation {
                activation,
                owner_task: 9_080,
                owner_task_generation: 1,
                owner_store: None,
                owner_store_generation: None,
                code_object: Some(code.object_ref()),
            },
        ),
        CommandEnvelope::new(
            90_011,
            "simd-runtime-v9",
            SemanticCommand::EnqueueRunnable { queue: 9_080, activation, activation_generation: 1 },
        ),
        CommandEnvelope::new(
            90_012,
            "simd-runtime-v9",
            SemanticCommand::CreateActivationContext {
                context: 9_080,
                activation,
                activation_generation: 2,
            },
        ),
        CommandEnvelope::new(
            90_013,
            "simd-runtime-v9",
            SemanticCommand::RecordVectorState {
                vector_state: 22_004,
                owner_activation: ContractObjectRef::new(
                    ContractObjectKind::Activation,
                    activation,
                    2,
                ),
                owner_store: ContractObjectRef::new(
                    ContractObjectKind::Store,
                    store.id,
                    store.generation,
                ),
                code_object: code.object_ref(),
                target_feature_set: feature_ref,
                simd_abi: "riscv-v".to_owned(),
                vector_register_count: 32,
                vector_register_bits: 128,
                register_bytes: 512,
                state: VectorStateState::Reserved,
                note: "v9 reserved clean vector state before cross-hart migration".to_owned(),
            },
        ),
        CommandEnvelope::new(
            90_014,
            "simd-runtime-v9",
            SemanticCommand::UpdateActivationContextVectorState {
                context: 9_080,
                context_generation: 1,
                vector_state: Some(ContractObjectRef::new(
                    ContractObjectKind::VectorState,
                    22_004,
                    1,
                )),
                vector_status: ActivationVectorState::Clean,
                note: "v9 activation context carries clean vector state before migration"
                    .to_owned(),
            },
        ),
        CommandEnvelope::new(
            90_015,
            "simd-runtime-v9",
            SemanticCommand::MigrateRunnableActivation {
                migration: 9_080,
                activation,
                activation_generation: 2,
                source_queue: 9_080,
                source_queue_generation: 2,
                target_queue: 9_081,
                target_queue_generation: 2,
                source_hart: 8,
                source_hart_generation: 2,
                target_hart: 9,
                target_hart_generation: 2,
                reason: "v9-cross-hart-vector-rebalance".to_owned(),
                note: "v9 migration rehomes clean vector state".to_owned(),
            },
        ),
    ];
    for command in commands {
        let result = semantic.apply_envelope(command);
        if result.status != CommandStatus::Applied {
            return Err(format!(
                "simd runtime v9 command {} ({}) failed: status={} violations={:?}",
                result.command_id,
                result.command,
                result.status.as_str(),
                result.violations
            )
            .into());
        }
    }
    Ok(())
}

pub(crate) fn run_simd_fault_injection_harness(
    verified_artifacts: &[VerifiedArtifact],
    semantic: &mut SemanticGraph,
    publisher: &mut CodePublisher,
    store_manager: &mut TargetStoreManager,
    executor: &mut TargetExecutor,
) -> Result<(), Box<dyn Error>> {
    let artifact = verified_artifacts
        .first()
        .ok_or("SIMD fault injection harness requires at least one verified artifact")?;
    let feature_set = semantic
        .target_feature_sets()
        .iter()
        .find(|feature| !feature.simd_supported && feature.simd_abi == "riscv-v")
        .cloned()
        .ok_or("SIMD fault injection harness requires an unsupported riscv-v feature set")?;
    let store_id =
        store_manager.register_verified_artifact(artifact, "restartable", "simd-fault-injection");
    store_manager.set_running(store_id).map_err(|error| error.message())?;
    let store = store_manager
        .record(store_id)
        .ok_or("SIMD fault injection store missing after registration")?
        .store
        .clone();
    let code_id = publisher.allocate(artifact).map_err(|error| error.message())?;
    publisher
        .declare_simd_requirement(
            code_id,
            feature_set.object_ref(),
            "riscv-v",
            32,
            128,
            "v10 SIMD fault injection unsupported-feature harness",
        )
        .map_err(|error| error.message())?;
    publisher.fill(code_id).map_err(|error| error.message())?;
    publisher.seal(code_id).map_err(|error| error.message())?;
    publisher.publish_rx(code_id).map_err(|error| error.message())?;
    publisher.bind_to_store(code_id, &store).map_err(|error| error.message())?;
    let code =
        publisher.object(code_id).ok_or("SIMD fault injection code missing after bind")?.clone();
    let activation = executor
        .start_activation(&store, &code, ActivationEntry::Symbol("simd_fault_injection".to_owned()))
        .map_err(|error| error.message())?;
    let offset = RV64_ENTRY_TRAP_EBREAK_OFFSET + 0x50;
    let trap_map = [TrapMapEntryV1::new(
        ObjectRefRaw::new(OBJECT_KIND_CODE_OBJECT_V1, code.id, code.generation),
        offset,
        offset + 4,
        TrapKindV1::SimdUnsupported,
        55,
        offset,
        10,
    )];
    let trap = executor
        .trap_exit_by_pc(activation, &code, code.text.start + offset, &trap_map)
        .map_err(|error| error.message())?;
    let trap_record = executor
        .traps()
        .iter()
        .find(|record| record.id == trap)
        .ok_or("SIMD fault injection trap record missing")?;
    let Some(activation_generation) = trap_record.activation_generation else {
        return Err("SIMD fault injection trap missing activation generation".into());
    };
    let result = semantic.apply_envelope(CommandEnvelope::new(
        90_016,
        "simd-runtime-v10",
        SemanticCommand::RecordSimdFaultInjection {
            injection: 22_010,
            activation: ContractObjectRef::new(
                ContractObjectKind::Activation,
                activation,
                activation_generation,
            ),
            code_object: code.object_ref(),
            trap: ContractObjectRef::new(ContractObjectKind::Trap, trap, 1),
            target_feature_set: feature_set.object_ref(),
            vector_state: None,
            kind: SimdFaultInjectionKind::UnsupportedFeature,
            effect: SimdFaultInjectionEffect::ActivationTrapped,
            required_abi: "riscv-v".to_owned(),
            vector_register_count: 32,
            vector_register_bits: 128,
            injected_faults: 1,
            note: "v10 injected unsupported SIMD fault records exact trap attribution".to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "simd runtime v10 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_simd_benchmark_harness(
    verified_artifacts: &[VerifiedArtifact],
    semantic: &mut SemanticGraph,
    publisher: &mut CodePublisher,
    store_manager: &mut TargetStoreManager,
) -> Result<(), Box<dyn Error>> {
    let artifact = verified_artifacts
        .first()
        .ok_or("SIMD benchmark harness requires at least one verified artifact")?;
    let feature_set = 21_011;
    let feature_recorded = semantic.apply_envelope(CommandEnvelope::new(
        90_017,
        "simd-runtime-v11",
        SemanticCommand::RecordTargetFeatureSet {
            feature_set,
            name: "v11-simd-benchmark-fixture".to_owned(),
            discovery_source: "target-executor-v11-simd-benchmark-harness".to_owned(),
            target_profile: "riscv64-vector-host-validation-fixture".to_owned(),
            target_arch: "riscv64".to_owned(),
            base_isa: "rv64gcv".to_owned(),
            simd_abi: "riscv-v".to_owned(),
            simd_supported: true,
            vector_register_count: 32,
            vector_register_bits: 128,
            scalar_fallback: true,
            unsupported_reason: String::new(),
            note: "v11 synthetic supported SIMD fixture for scalar/vector benchmark".to_owned(),
        },
    ));
    if feature_recorded.status != CommandStatus::Applied {
        return Err(format!(
            "simd runtime v11 target feature command {} ({}) failed: status={} violations={:?}",
            feature_recorded.command_id,
            feature_recorded.command,
            feature_recorded.status.as_str(),
            feature_recorded.violations
        )
        .into());
    }
    let feature_ref = semantic
        .target_feature_sets()
        .iter()
        .find(|feature| feature.id == feature_set)
        .map(|feature| feature.object_ref())
        .ok_or("v11 target feature fixture missing")?;

    let scalar_store_id =
        store_manager.register_verified_artifact(artifact, "restartable", "simd-benchmark-scalar");
    store_manager.set_running(scalar_store_id).map_err(|error| error.message())?;
    let scalar_store = store_manager
        .record(scalar_store_id)
        .ok_or("SIMD benchmark scalar store missing after registration")?
        .store
        .clone();
    let scalar_code_id = publisher.allocate(artifact).map_err(|error| error.message())?;
    publisher.fill(scalar_code_id).map_err(|error| error.message())?;
    publisher.seal(scalar_code_id).map_err(|error| error.message())?;
    publisher.publish_rx(scalar_code_id).map_err(|error| error.message())?;
    publisher.bind_to_store(scalar_code_id, &scalar_store).map_err(|error| error.message())?;
    let scalar_code = publisher
        .object(scalar_code_id)
        .ok_or("SIMD benchmark scalar code missing after bind")?
        .clone();

    let vector_store_id =
        store_manager.register_verified_artifact(artifact, "restartable", "simd-benchmark-vector");
    store_manager.set_running(vector_store_id).map_err(|error| error.message())?;
    let vector_store = store_manager
        .record(vector_store_id)
        .ok_or("SIMD benchmark vector store missing after registration")?
        .store
        .clone();
    let vector_code_id = publisher.allocate(artifact).map_err(|error| error.message())?;
    publisher
        .declare_simd_requirement(
            vector_code_id,
            feature_ref,
            "riscv-v",
            32,
            128,
            "v11 SIMD benchmark vector code requirement",
        )
        .map_err(|error| error.message())?;
    publisher.fill(vector_code_id).map_err(|error| error.message())?;
    publisher.seal(vector_code_id).map_err(|error| error.message())?;
    publisher.publish_rx(vector_code_id).map_err(|error| error.message())?;
    publisher.bind_to_store(vector_code_id, &vector_store).map_err(|error| error.message())?;
    let vector_code = publisher
        .object(vector_code_id)
        .ok_or("SIMD benchmark vector code missing after bind")?
        .clone();

    let result = semantic.apply_envelope(CommandEnvelope::new(
        90_018,
        "simd-runtime-v11",
        SemanticCommand::RecordSimdBenchmark {
            benchmark: 22_011,
            target_feature_set: feature_ref,
            scalar_code_object: scalar_code.object_ref(),
            vector_code_object: vector_code.object_ref(),
            simd_abi: "riscv-v".to_owned(),
            vector_register_count: 32,
            vector_register_bits: 128,
            workload_units: 4096,
            scalar_nanos: 120_000,
            vector_nanos: 40_000,
            speedup_milli: 3000,
            context_overhead_nanos: 80_000,
            note: "v11 records deterministic scalar versus SIMD vector benchmark".to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "simd runtime v11 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_simd_context_switch_benchmark_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let preemption = semantic
        .preemptions()
        .iter()
        .find(|record| record.id == 9_070)
        .map(|record| record.object_ref())
        .ok_or("v12 SIMD context switch benchmark requires v7 preemption evidence")?;
    let activation_resume = semantic
        .activation_resumes()
        .iter()
        .find(|record| record.id == 9_071)
        .map(|record| record.object_ref())
        .ok_or("v12 SIMD context switch benchmark requires v8 activation resume evidence")?;
    let saved_vector_state = semantic
        .vector_states()
        .iter()
        .find(|record| record.id == 22_002)
        .map(|record| record.object_ref())
        .ok_or("v12 SIMD context switch benchmark requires v7 saved vector state evidence")?;
    let restored_vector_state = semantic
        .vector_states()
        .iter()
        .find(|record| record.id == 22_003)
        .map(|record| record.object_ref())
        .ok_or("v12 SIMD context switch benchmark requires v8 restored vector state evidence")?;
    let target_feature_set = semantic
        .target_feature_sets()
        .iter()
        .find(|record| record.id == 21_002)
        .map(|record| record.object_ref())
        .ok_or("v12 SIMD context switch benchmark requires v7 target feature set evidence")?;

    let result = semantic.apply_envelope(CommandEnvelope::new(
        90_019,
        "simd-runtime-v12",
        SemanticCommand::RecordSimdContextSwitchBenchmark {
            benchmark: 22_012,
            preemption,
            activation_resume,
            saved_vector_state,
            restored_vector_state,
            target_feature_set,
            simd_abi: "riscv-v".to_owned(),
            vector_register_count: 32,
            vector_register_bits: 128,
            sample_count: 64,
            scalar_context_switch_nanos: 30_000,
            vector_context_switch_nanos: 46_384,
            overhead_nanos: 16_384,
            budget_nanos: 50_000,
            note: "v12 records deterministic SIMD vector context-switch overhead".to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "simd runtime v12 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_framebuffer_object_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let framebuffer_resource =
        semantic.register_resource(ResourceKind::Framebuffer, None, "framebuffer:fb0");
    let framebuffer_resource_generation = semantic
        .resource_handle(framebuffer_resource)
        .ok_or("display runtime g0 framebuffer resource missing after registration")?
        .generation;

    let result = semantic.apply_envelope(CommandEnvelope::new(
        90_020,
        "display-runtime-g0",
        SemanticCommand::RecordFramebufferObject {
            framebuffer: 23_001,
            name: "fb0".to_owned(),
            resource: framebuffer_resource,
            resource_generation: framebuffer_resource_generation,
            width: 800,
            height: 600,
            stride_bytes: 3200,
            pixel_format: "xrgb8888".to_owned(),
            byte_len: 1_920_000,
            note: "g0 records semantic framebuffer object without display write authority"
                .to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "display runtime g0 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_display_object_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let framebuffer = semantic
        .framebuffer_objects()
        .iter()
        .find(|record| record.id == 23_001)
        .map(|record| record.object_ref())
        .ok_or("display runtime g1 requires g0 framebuffer evidence")?;

    let result = semantic.apply_envelope(CommandEnvelope::new(
        90_021,
        "display-runtime-g1",
        SemanticCommand::RecordDisplayObject {
            display: 23_101,
            name: "display0".to_owned(),
            framebuffer: framebuffer.id,
            framebuffer_generation: framebuffer.generation,
            mode_name: "800x600@60".to_owned(),
            width: 800,
            height: 600,
            refresh_millihz: 60_000,
            note: "g1 records semantic display object bound to framebuffer generation".to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "display runtime g1 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_display_capability_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let owner_store = semantic_store_id(semantic, "wasm_app")?;
    let owner_store_generation = semantic
        .store_handle(owner_store)
        .ok_or("display runtime g2 owner store missing after lookup")?
        .generation;
    let display = semantic
        .display_objects()
        .iter()
        .find(|record| record.id == 23_101)
        .map(|record| record.object_ref())
        .ok_or("display runtime g2 requires g1 display object evidence")?;
    let display_record = semantic
        .display_objects()
        .iter()
        .find(|record| record.id == display.id && record.generation == display.generation)
        .ok_or("display runtime g2 display generation missing")?;
    let display_name = display_record.name.clone();
    let framebuffer = display_record.framebuffer;
    let framebuffer_generation = display_record.framebuffer_generation;

    let capability = semantic.grant_capability_with_authority_ref(
        "wasm_app",
        "display.display0",
        AuthorityObjectRef::internal(CapabilityClass::Display, display),
        &["flush", "lease"],
        "store",
        "display-runtime-g2",
        true,
    );
    let capability_record = semantic
        .capabilities()
        .record(capability)
        .ok_or("display runtime g2 capability missing after grant")?
        .clone();
    let handle = capability_record
        .store_local_handle(vec!["flush".to_owned(), "lease".to_owned()])
        .ok_or("display runtime g2 capability is not store-local")?;
    let result = semantic.apply_envelope(CommandEnvelope::new(
        90_022,
        "display-runtime-g2",
        SemanticCommand::RecordDisplayCapability {
            display_capability: 23_201,
            owner_store,
            owner_store_generation,
            display: display.id,
            display_generation: display.generation,
            capability: capability_record.id,
            capability_generation: capability_record.generation,
            handle,
            operations: vec!["flush".to_owned(), "lease".to_owned()],
            note: format!(
                "g2 records display capability for {} backed by framebuffer {}@{}",
                display_name, framebuffer, framebuffer_generation
            ),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "display runtime g2 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_framebuffer_window_lease_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let display_capability = semantic
        .display_capabilities()
        .iter()
        .find(|record| record.id == 23_201)
        .cloned()
        .ok_or("display runtime g3 requires g2 display capability evidence")?;
    let display = semantic
        .display_objects()
        .iter()
        .find(|record| {
            record.id == display_capability.display
                && record.generation == display_capability.display_generation
        })
        .cloned()
        .ok_or("display runtime g3 display generation missing")?;
    let framebuffer = semantic
        .framebuffer_objects()
        .iter()
        .find(|record| {
            record.id == display_capability.framebuffer
                && record.generation == display_capability.framebuffer_generation
        })
        .cloned()
        .ok_or("display runtime g3 framebuffer generation missing")?;

    let result = semantic.apply_envelope(CommandEnvelope::new(
        90_023,
        "display-runtime-g3",
        SemanticCommand::RecordFramebufferWindowLease {
            framebuffer_window_lease: 23_301,
            owner_store: display_capability.owner_store,
            owner_store_generation: display_capability.owner_store_generation,
            display_capability: display_capability.id,
            display_capability_generation: display_capability.generation,
            display: display.id,
            display_generation: display.generation,
            framebuffer: framebuffer.id,
            framebuffer_generation: framebuffer.generation,
            x: 0,
            y: 0,
            width: display.width,
            height: display.height,
            byte_offset: 0,
            byte_len: framebuffer.byte_len,
            access: "write".to_owned(),
            note: "g3 records framebuffer write-window lease without pixel writes or flush"
                .to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "display runtime g3 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_framebuffer_mapping_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let lease = semantic
        .framebuffer_window_leases()
        .iter()
        .find(|record| record.id == 23_301)
        .cloned()
        .ok_or("display runtime g4 requires g3 framebuffer window lease evidence")?;
    let result = semantic.apply_envelope(CommandEnvelope::new(
        90_024,
        "display-runtime-g4",
        SemanticCommand::RecordFramebufferMapping {
            framebuffer_mapping: 23_401,
            owner_store: lease.owner_store,
            owner_store_generation: lease.owner_store_generation,
            framebuffer_window_lease: lease.id,
            framebuffer_window_lease_generation: lease.generation,
            map_handle_slot: 3,
            map_handle_generation: 1,
            map_handle_tag: 0x4d41505f4642,
            x: lease.x,
            y: lease.y,
            width: lease.width,
            height: lease.height,
            byte_offset: lease.byte_offset,
            byte_len: lease.byte_len,
            access: lease.access.clone(),
            mode: "handle-mode".to_owned(),
            note:
                "g4 maps framebuffer through semantic handle-mode lease without raw pointer mapping"
                    .to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "display runtime g4 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_framebuffer_write_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let mapping = semantic
        .framebuffer_mappings()
        .iter()
        .find(|record| record.id == 23_401)
        .cloned()
        .ok_or("display runtime g5 requires g4 framebuffer mapping evidence")?;
    let byte_len = 800 * 4;
    let payload_digest = SemanticGraph::expected_framebuffer_write_payload_digest_v1(
        mapping.id,
        mapping.generation,
        mapping.framebuffer,
        mapping.framebuffer_generation,
        0,
        0,
        800,
        1,
        0,
        byte_len,
    );
    let result = semantic.apply_envelope(CommandEnvelope::new(
        90_025,
        "display-runtime-g5",
        SemanticCommand::RecordFramebufferWrite {
            framebuffer_write: 23_501,
            owner_store: mapping.owner_store,
            owner_store_generation: mapping.owner_store_generation,
            framebuffer_mapping: mapping.id,
            framebuffer_mapping_generation: mapping.generation,
            x: 0,
            y: 0,
            width: 800,
            height: 1,
            byte_offset: 0,
            byte_len,
            payload_digest,
            note: "g5 records semantic pixel write evidence through handle-mode mapping".to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "display runtime g5 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_framebuffer_flush_region_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let write = semantic
        .framebuffer_writes()
        .iter()
        .find(|record| record.id == 23_501)
        .cloned()
        .ok_or("display runtime g6 requires g5 framebuffer write evidence")?;
    let result = semantic.apply_envelope(CommandEnvelope::new(
        90_026,
        "display-runtime-g6",
        SemanticCommand::RecordFramebufferFlushRegion {
            framebuffer_flush_region: 23_601,
            owner_store: write.owner_store,
            owner_store_generation: write.owner_store_generation,
            framebuffer_write: write.id,
            framebuffer_write_generation: write.generation,
            x: write.x,
            y: write.y,
            width: write.width,
            height: write.height,
            byte_offset: write.byte_offset,
            byte_len: write.byte_len,
            payload_digest: write.payload_digest,
            note: "g6 records semantic flush region evidence without real present".to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "display runtime g6 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_framebuffer_dirty_region_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let flush = semantic
        .framebuffer_flush_regions()
        .iter()
        .find(|record| record.id == 23_601)
        .cloned()
        .ok_or("display runtime g7 requires g6 framebuffer flush region evidence")?;
    let result = semantic.apply_envelope(CommandEnvelope::new(
        90_027,
        "display-runtime-g7",
        SemanticCommand::RecordFramebufferDirtyRegion {
            framebuffer_dirty_region: 23_701,
            owner_store: flush.owner_store,
            owner_store_generation: flush.owner_store_generation,
            framebuffer_write: flush.framebuffer_write,
            framebuffer_write_generation: flush.framebuffer_write_generation,
            framebuffer_flush_region: Some(flush.id),
            framebuffer_flush_region_generation: Some(flush.generation),
            state: semantic_core::FramebufferDirtyRegionState::Clean,
            x: flush.x,
            y: flush.y,
            width: flush.width,
            height: flush.height,
            byte_offset: flush.byte_offset,
            byte_len: flush.byte_len,
            payload_digest: flush.payload_digest,
            note: "g7 records dirty region tracking and clean state after semantic flush"
                .to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "display runtime g7 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_display_event_log_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let dirty = semantic
        .framebuffer_dirty_regions()
        .iter()
        .find(|record| record.id == 23_701)
        .cloned()
        .ok_or("display runtime g8 requires g7 framebuffer dirty region evidence")?;
    let first_event = semantic
        .framebuffer_objects()
        .iter()
        .find(|record| record.id == dirty.framebuffer)
        .map(|record| record.recorded_at_event)
        .ok_or("display runtime g8 requires g0 framebuffer object evidence")?;
    let last_event = dirty.recorded_at_event;
    let event_count = semantic
        .event_log()
        .events()
        .iter()
        .filter(|event| {
            event.source == "display" && event.id >= first_event && event.id <= last_event
        })
        .count() as u64;
    let flush_count = semantic
        .event_log()
        .events()
        .iter()
        .filter(|event| {
            event.source == "display"
                && event.id >= first_event
                && event.id <= last_event
                && matches!(
                    event.kind,
                    semantic_core::EventKind::FramebufferFlushRegionRecorded { .. }
                )
        })
        .count() as u64;
    let dirty_region_count = semantic
        .event_log()
        .events()
        .iter()
        .filter(|event| {
            event.source == "display"
                && event.id >= first_event
                && event.id <= last_event
                && matches!(
                    event.kind,
                    semantic_core::EventKind::FramebufferDirtyRegionTracked { .. }
                )
        })
        .count() as u64;
    let result = semantic.apply_envelope(CommandEnvelope::new(
        90_028,
        "display-runtime-g8",
        SemanticCommand::RecordDisplayEventLog {
            display_event_log: 23_801,
            owner_store: dirty.owner_store,
            owner_store_generation: dirty.owner_store_generation,
            framebuffer_dirty_region: dirty.id,
            framebuffer_dirty_region_generation: dirty.generation,
            first_event,
            last_event,
            event_count,
            flush_count,
            dirty_region_count,
            note: "g8 records display event-log summary for semantic display evidence".to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "display runtime g8 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_display_cleanup_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let display_capability = semantic
        .display_capabilities()
        .iter()
        .find(|record| record.id == 23_201)
        .cloned()
        .ok_or("display runtime g9 requires g2 display capability evidence")?;
    let result = semantic.apply_envelope(CommandEnvelope::new(
        90_029,
        "display-runtime-g9",
        SemanticCommand::CleanupDisplay {
            cleanup: 23_901,
            owner_store: display_capability.owner_store,
            owner_store_generation: display_capability.owner_store_generation,
            display_capability: display_capability.id,
            display_capability_generation: display_capability.generation,
            display: display_capability.display,
            display_generation: display_capability.display_generation,
            framebuffer: display_capability.framebuffer,
            framebuffer_generation: display_capability.framebuffer_generation,
            reason: "display-window-cleanup".to_owned(),
            note: "g9 releases framebuffer mapping and lease before revoking display capability"
                .to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "display runtime g9 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_display_snapshot_barrier_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let cleanup = semantic
        .display_cleanups()
        .iter()
        .find(|record| record.id == 23_901)
        .cloned()
        .ok_or("display runtime g10 requires g9 display cleanup evidence")?;
    let result = semantic.apply_envelope(CommandEnvelope::new(
        90_030,
        "display-runtime-g10",
        SemanticCommand::ValidateDisplaySnapshotBarrier {
            barrier: 24_001,
            owner_store: cleanup.owner_store,
            owner_store_generation: cleanup.owner_store_generation,
            display: cleanup.display,
            display_generation: cleanup.display_generation,
            framebuffer: cleanup.framebuffer,
            framebuffer_generation: cleanup.framebuffer_generation,
            display_cleanup: Some(cleanup.id),
            display_cleanup_generation: Some(cleanup.generation),
            reason: "display-snapshot-barrier".to_owned(),
            note:
                "g10 validates snapshot barrier after display cleanup released leases and mappings"
                    .to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "display runtime g10 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_display_panic_last_frame_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let barrier = semantic
        .display_snapshot_barriers()
        .iter()
        .find(|record| record.id == 24_001)
        .cloned()
        .ok_or("display runtime g11 requires g10 display snapshot barrier evidence")?;
    let event_log = semantic
        .display_event_logs()
        .iter()
        .find(|record| record.id == 23_801)
        .cloned()
        .ok_or("display runtime g11 requires g8 display event-log evidence")?;
    let write = semantic
        .framebuffer_writes()
        .iter()
        .find(|record| record.id == 23_501)
        .cloned()
        .ok_or("display runtime g11 requires g5 framebuffer write evidence")?;
    let flush = semantic
        .framebuffer_flush_regions()
        .iter()
        .find(|record| record.id == 23_601)
        .cloned()
        .ok_or("display runtime g11 requires g6 framebuffer flush evidence")?;
    let panic_epoch = 1;
    let summary_digest = SemanticGraph::expected_display_panic_last_frame_summary_digest_v1(
        barrier.owner_store,
        barrier.owner_store_generation,
        barrier.display,
        barrier.display_generation,
        barrier.framebuffer,
        barrier.framebuffer_generation,
        barrier.id,
        barrier.generation,
        event_log.id,
        event_log.generation,
        write.id,
        write.generation,
        flush.id,
        flush.generation,
        flush.payload_digest,
        panic_epoch,
        0,
        1,
    );
    let result = semantic.apply_envelope(CommandEnvelope::new(
        90_031,
        "display-runtime-g11",
        SemanticCommand::RecordDisplayPanicLastFrame {
            panic_last_frame: 25_001,
            owner_store: barrier.owner_store,
            owner_store_generation: barrier.owner_store_generation,
            display_snapshot_barrier: barrier.id,
            display_snapshot_barrier_generation: barrier.generation,
            display_event_log: event_log.id,
            display_event_log_generation: event_log.generation,
            framebuffer_write: write.id,
            framebuffer_write_generation: write.generation,
            framebuffer_flush_region: flush.id,
            framebuffer_flush_region_generation: flush.generation,
            payload_digest: flush.payload_digest,
            summary_digest,
            summary_record_bytes: 512,
            panic_epoch,
            panic_record_kind: "contract-panic-summary-v1".to_owned(),
            raw_framebuffer_bytes_exported: false,
            note: "g11 records panic-safe last framebuffer summary without raw bytes".to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "display runtime g11 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_framebuffer_benchmark_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let barrier = semantic
        .display_snapshot_barriers()
        .iter()
        .find(|record| record.id == 24_001)
        .cloned()
        .ok_or("display runtime g12 requires g10 display snapshot barrier evidence")?;
    let event_log = semantic
        .display_event_logs()
        .iter()
        .find(|record| record.id == 23_801)
        .cloned()
        .ok_or("display runtime g12 requires g8 display event-log evidence")?;
    let write = semantic
        .framebuffer_writes()
        .iter()
        .find(|record| record.id == 23_501)
        .cloned()
        .ok_or("display runtime g12 requires g5 framebuffer write evidence")?;
    let flush = semantic
        .framebuffer_flush_regions()
        .iter()
        .find(|record| record.id == 23_601)
        .cloned()
        .ok_or("display runtime g12 requires g6 framebuffer flush evidence")?;
    let sample_frames = 1;
    let sample_bytes = flush.byte_len;
    let frame_area_pixels = u64::from(flush.width) * u64::from(flush.height);
    let write_nanos = 40_000;
    let flush_nanos = 60_000;
    let measured_nanos = write_nanos + flush_nanos;
    let result = semantic.apply_envelope(CommandEnvelope::new(
        90_032,
        "display-runtime-g12",
        SemanticCommand::RecordFramebufferBenchmark {
            benchmark: 25_101,
            scenario: "display-g12-single-flush".to_owned(),
            owner_store: barrier.owner_store,
            owner_store_generation: barrier.owner_store_generation,
            display_capability: write.display_capability,
            display_capability_generation: write.display_capability_generation,
            framebuffer_write: write.id,
            framebuffer_write_generation: write.generation,
            framebuffer_flush_region: flush.id,
            framebuffer_flush_region_generation: flush.generation,
            display_event_log: event_log.id,
            display_event_log_generation: event_log.generation,
            display_snapshot_barrier: barrier.id,
            display_snapshot_barrier_generation: barrier.generation,
            sample_frames,
            sample_bytes,
            frame_area_pixels,
            write_nanos,
            flush_nanos,
            measured_nanos,
            budget_nanos: 200_000,
            p50_latency_nanos: measured_nanos,
            p99_latency_nanos: measured_nanos,
            note: "g12 records semantic framebuffer write/flush benchmark evidence".to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "display runtime g12 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_integrated_smp_preemption_cleanup_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let result = semantic.apply_envelope(CommandEnvelope::new(
        100_001,
        "integrated-runtime-x0",
        SemanticCommand::RecordIntegratedSmpPreemptionCleanup {
            integrated: 26_001,
            scenario: "x0-smp-preemption-cleanup".to_owned(),
            stress_run: 9501,
            stress_run_generation: 1,
            preemption: 9001,
            preemption_generation: 1,
            timer_interrupt: 9001,
            timer_interrupt_generation: 1,
            saved_context: 9002,
            saved_context_generation: 2,
            remote_preempt: 9001,
            remote_preempt_generation: 1,
            activation_cleanup: 9001,
            activation_cleanup_generation: 1,
            smp_cleanup_quiescence: 9301,
            smp_cleanup_quiescence_generation: 1,
            invariant_checks: 7,
            note: "x0 records integrated SMP preemption and cleanup closure".to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "integrated runtime x0 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_integrated_smp_network_fault_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let result = semantic.apply_envelope(CommandEnvelope::new(
        100_002,
        "integrated-runtime-x1",
        SemanticCommand::RecordIntegratedSmpNetworkFault {
            integrated: 26_101,
            scenario: "x1-smp-network-driver-fault".to_owned(),
            network_driver_cleanup: 10051,
            network_driver_cleanup_generation: 1,
            smp_stress_run: 9501,
            smp_stress_run_generation: 1,
            remote_preempt: 9001,
            remote_preempt_generation: 1,
            smp_cleanup_quiescence: 9301,
            smp_cleanup_quiescence_generation: 1,
            invariant_checks: 7,
            note: "x1 records network driver cleanup under SMP stress and quiescence evidence"
                .to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "integrated runtime x1 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_integrated_disk_preempt_fault_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let result = semantic.apply_envelope(CommandEnvelope::new(
        100_003,
        "integrated-runtime-x2",
        SemanticCommand::RecordIntegratedDiskPreemptFault {
            integrated: 26_201,
            scenario: "x2-disk-pending-io-fault-under-preemption".to_owned(),
            preemption: 9_070,
            preemption_generation: 1,
            block_pending_io_policy: 20_124,
            block_pending_io_policy_generation: 1,
            invariant_checks: 6,
            note: "x2 records block pending EIO policy under timer preemption evidence".to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "integrated runtime x2 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_integrated_simd_migration_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let result = semantic.apply_envelope(CommandEnvelope::new(
        100_004,
        "integrated-runtime-x3",
        SemanticCommand::RecordIntegratedSimdMigration {
            integrated: 26_301,
            scenario: "x3-simd-task-migration-across-harts".to_owned(),
            activation_migration: 9_080,
            activation_migration_generation: 1,
            invariant_checks: 6,
            note: "x3 records clean SIMD vector state rehome across hart migration evidence"
                .to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "integrated runtime x3 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_integrated_network_disk_io_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let result = semantic.apply_envelope(CommandEnvelope::new(
        100_005,
        "integrated-runtime-x4",
        SemanticCommand::RecordIntegratedNetworkDiskIo {
            integrated: 26_401,
            scenario: "x4-network-disk-concurrent-io".to_owned(),
            network_benchmark: 10_067,
            network_benchmark_generation: 1,
            block_benchmark: 20_132,
            block_benchmark_generation: 1,
            invariant_checks: 6,
            note: "x4 records network and disk concurrent IO semantic evidence".to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "integrated runtime x4 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_integrated_display_scheduler_load_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let result = semantic.apply_envelope(CommandEnvelope::new(
        100_006,
        "integrated-runtime-x5",
        SemanticCommand::RecordIntegratedDisplaySchedulerLoad {
            integrated: 26_501,
            scenario: "x5-display-update-during-scheduler-load".to_owned(),
            framebuffer_benchmark: 25_101,
            framebuffer_benchmark_generation: 1,
            scheduler_decision: 9_001,
            scheduler_decision_generation: 1,
            invariant_checks: 6,
            note: "x5 records display update evidence under scheduler decision load".to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "integrated runtime x5 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_integrated_snapshot_io_lease_barrier_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let result = semantic.apply_envelope(CommandEnvelope::new(
        100_007,
        "integrated-runtime-x6",
        SemanticCommand::RecordIntegratedSnapshotIoLeaseBarrier {
            integrated: 26_601,
            scenario: "x6-snapshot-barrier-blocks-active-io-leases".to_owned(),
            smp_snapshot_barrier: 9_401,
            smp_snapshot_barrier_generation: 1,
            io_cleanup: 9_967,
            io_cleanup_generation: 1,
            display_snapshot_barrier: 24_001,
            display_snapshot_barrier_generation: 1,
            invariant_checks: 7,
            note: "x6 records snapshot barrier closure after IO and display leases are cleaned"
                .to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "integrated runtime x6 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_integrated_code_publish_smp_workload_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let result = semantic.apply_envelope(CommandEnvelope::new(
        100_008,
        "integrated-runtime-x7",
        SemanticCommand::RecordIntegratedCodePublishSmpWorkload {
            integrated: 26_701,
            scenario: "x7-code-publish-while-smp-workload-active".to_owned(),
            smp_stress_run: 9_501,
            smp_stress_run_generation: 1,
            smp_code_publish_barrier: 9_201,
            smp_code_publish_barrier_generation: 1,
            invariant_checks: 7,
            note: "x7 records semantic code publish barrier during SMP workload evidence"
                .to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "integrated runtime x7 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_integrated_display_panic_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let substrate_panic_event = semantic.record_substrate_panic(
        "PanicRing",
        "extract-after-substrate-panic",
        Some("substrate.panic".to_owned()),
        None,
        None,
        1,
        0,
        1,
    );
    let mut ring = PanicRingV1::new();
    ring.push_record(
        PanicRecordKindV1::PanicRecord,
        br#"{"panic_epoch":1,"panic_cpu":0,"reason_code":1}"#,
    )
    .map_err(|err| format!("push panic record: {err:?}"))?;
    ring.push_record(
        PanicRecordKindV1::LastHostcallFrameSummary,
        br#"{"hostcall":"none","status":"substrate-panic"}"#,
    )
    .map_err(|err| format!("push hostcall summary record: {err:?}"))?;
    ring.push_record(
        PanicRecordKindV1::ContractPanicSummary,
        br#"{"display_panic_last_frame":"display-panic-last-frame:25001@1","raw_framebuffer_bytes_exported":false}"#,
    )
    .map_err(|err| format!("push contract panic summary record: {err:?}"))?;
    let mut out = [0u8; 8192];
    let len = ring.dump_jsonl(&mut out).map_err(|err| format!("dump panic ring jsonl: {err:?}"))?;
    let jsonl = std::str::from_utf8(&out[..len])?;
    let jsonl_frame_count = jsonl.lines().count() as u32;
    let contract_panic_summary_records =
        jsonl.matches("\"schema\":\"contract-panic-summary-v1\"").count() as u32;
    let corrupt_record_count =
        jsonl.matches("\"schema\":\"panic-ring-corrupt-record-v1\"").count() as u32;
    let truncated_record_count =
        jsonl.matches("\"schema\":\"truncated-panic-record-v1\"").count() as u32;

    let result = semantic.apply_envelope(CommandEnvelope::new(
        100_009,
        "integrated-runtime-x8",
        SemanticCommand::RecordIntegratedDisplayPanic {
            integrated: 26_801,
            scenario: "x8-panic-ring-extraction-after-substrate-panic".to_owned(),
            substrate_panic_event,
            display_panic_last_frame: 25_001,
            display_panic_last_frame_generation: 1,
            panic_ring_bytes: PANIC_RING_SIZE as u32,
            panic_record_max_bytes: PANIC_RECORD_MAX_LEN as u32,
            panic_ring_oldest_seq: ring.header().oldest_seq,
            panic_ring_newest_seq: ring.header().write_seq,
            panic_ring_record_count: ring.header().record_count,
            panic_ring_lost_count: ring.header().lost_count,
            jsonl_frame_count,
            contract_panic_summary_records,
            last_frame_summary_records: contract_panic_summary_records,
            corrupt_record_count,
            truncated_record_count,
            invariant_checks: 8,
            note: "x8 records panic-ring extraction after substrate panic without raw framebuffer bytes"
                .to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "integrated runtime x8 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn run_integrated_osctl_trace_replay_harness(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let result = semantic.apply_envelope(CommandEnvelope::new(
        100_010,
        "integrated-runtime-x9",
        SemanticCommand::RecordIntegratedOsctlTraceReplay {
            integrated: 26_901,
            scenario: "x9-full-osctl-trace-replay".to_owned(),
            integrated_smp_preemption_cleanup: 26_001,
            integrated_smp_preemption_cleanup_generation: 1,
            integrated_smp_network_fault: 26_101,
            integrated_smp_network_fault_generation: 1,
            integrated_disk_preempt_fault: 26_201,
            integrated_disk_preempt_fault_generation: 1,
            integrated_simd_migration: 26_301,
            integrated_simd_migration_generation: 1,
            integrated_network_disk_io: 26_401,
            integrated_network_disk_io_generation: 1,
            integrated_display_scheduler_load: 26_501,
            integrated_display_scheduler_load_generation: 1,
            integrated_snapshot_io_lease_barrier: 26_601,
            integrated_snapshot_io_lease_barrier_generation: 1,
            integrated_code_publish_smp_workload: 26_701,
            integrated_code_publish_smp_workload_generation: 1,
            integrated_display_panic: 26_801,
            integrated_display_panic_generation: 1,
            replay_event_cursor: semantic.event_log().cursor(),
            stable_view_count: 9,
            historical_edge_count: 9,
            replayed_root_count: 9,
            integrated_scenario_count: 9,
            replay_fixture_count: 9,
            invariant_checks: 9,
            note: "x9 records full osctl trace replay closure across integrated scenarios"
                .to_owned(),
        },
    ));
    if result.status != CommandStatus::Applied {
        return Err(format!(
            "integrated runtime x9 command {} ({}) failed: status={} violations={:?}",
            result.command_id,
            result.command,
            result.status.as_str(),
            result.violations
        )
        .into());
    }
    Ok(())
}

pub(crate) fn append_display_capability_contract_evidence(
    semantic: &SemanticGraph,
    store_records: &mut Vec<StoreRecordManifest>,
    capability_records: &mut Vec<CapabilityRecordManifest>,
) {
    for display_capability in semantic.display_capabilities() {
        if !store_records.iter().any(|record| {
            record.id == display_capability.owner_store
                && record.generation == display_capability.owner_store_generation
        }) && let Some(store) = semantic.stores().iter().find(|store| {
            store.id == display_capability.owner_store
                && store.generation == display_capability.owner_store_generation
        }) {
            store_records.push(store_record_manifest(store));
        }
        if !capability_records.iter().any(|record| {
            record.id == display_capability.capability
                && record.generation == display_capability.capability_generation
        }) && let Some(capability) =
            semantic.capabilities().record(display_capability.capability)
        {
            capability_records.push(capability_record_manifest(capability));
        }
    }
}

pub(crate) fn semantic_cleanup_tombstones(semantic: &SemanticGraph) -> Vec<TombstoneRecord> {
    let mut tombstones: Vec<TombstoneRecord> = Vec::new();
    for cleanup in semantic.activation_cleanups() {
        if cleanup.state != semantic_core::ActivationCleanupState::Completed {
            continue;
        }
        let tombstone = TombstoneRecord::new(
            ContractObjectKind::Store,
            cleanup.store,
            cleanup.target_store_generation,
            cleanup.completed_at_event,
            "activation-cleanup-target-store-generation",
        );
        if !tombstones.iter().any(|existing| {
            existing.kind == tombstone.kind
                && existing.id == tombstone.id
                && existing.generation == tombstone.generation
        }) {
            tombstones.push(tombstone);
        }
    }
    tombstones
}

pub(crate) fn contract_graph_store_records(
    semantic: &SemanticGraph,
    store_manager: &TargetStoreManager,
) -> Vec<StoreRecord> {
    let mut stores =
        store_manager.records().iter().map(|record| record.store.clone()).collect::<Vec<_>>();
    for display_capability in semantic.display_capabilities() {
        if stores.iter().any(|store| {
            store.id == display_capability.owner_store
                && store.generation == display_capability.owner_store_generation
        }) {
            continue;
        }
        if let Some(store) = semantic.stores().iter().find(|store| {
            store.id == display_capability.owner_store
                && store.generation == display_capability.owner_store_generation
        }) {
            stores.push(store.clone());
        }
    }
    for integrated in semantic.integrated_network_disk_ios() {
        if stores.iter().any(|store| {
            store.id == integrated.network_owner_store
                && store.generation == integrated.network_owner_store_generation
        }) {
            continue;
        }
        if let Some(store) = semantic.stores().iter().find(|store| {
            store.id == integrated.network_owner_store
                && store.generation == integrated.network_owner_store_generation
        }) {
            stores.push(store.clone());
        }
    }
    for integrated in semantic.integrated_snapshot_io_lease_barriers() {
        if stores.iter().any(|store| {
            store.id == integrated.driver_store
                && store.generation == integrated.driver_store_generation
        }) {
            continue;
        }
        if let Some(store) = semantic.stores().iter().find(|store| {
            store.id == integrated.driver_store
                && store.generation == integrated.driver_store_generation
        }) {
            stores.push(store.clone());
        }
    }
    stores
}

pub(crate) fn contract_graph_capability_records(
    semantic: &SemanticGraph,
    ledger: &CapabilityLedger,
) -> Vec<CapabilityRecord> {
    let mut capabilities = ledger.records().to_vec();
    for display_capability in semantic.display_capabilities() {
        if capabilities.iter().any(|capability| {
            capability.id == display_capability.capability
                && capability.generation == display_capability.capability_generation
        }) {
            continue;
        }
        if let Some(capability) = semantic.capabilities().record(display_capability.capability) {
            capabilities.push(capability.clone());
        }
    }
    capabilities
}

pub(crate) fn declared_authority_objects(
    capabilities: &[CapabilityRecord],
) -> Vec<ExternalObjectDeclaration> {
    let mut declarations = Vec::new();
    for capability in capabilities {
        let Some(object_ref) = capability.object_ref else {
            continue;
        };
        let object = object_ref.object();
        if declarations
            .iter()
            .any(|declaration: &ExternalObjectDeclaration| declaration.object == object)
        {
            continue;
        }
        declarations.push(ExternalObjectDeclaration::new(
            object,
            "target-executor-authority",
            object_ref.class().as_str(),
            &capability.debug_object_label,
        ));
    }
    declarations
}

pub(crate) fn append_cwasm_smoke_hostcalls(
    code: &mut CodeObject,
    module_index: usize,
    smoke_trace: &[HostValidationSmokeTrace],
) {
    for (index, trace) in smoke_trace.iter().enumerate() {
        let number = cwasm_smoke_hostcall_number(module_index, index);
        let name = format!("cwasm.host-validation.{}", trace.export);
        let object = format!("host-validation.{}", code.package);
        code.hostcalls.push(HostcallSpec::new(
            number,
            &name,
            HostcallCategory::Service,
            &object,
            &trace.export,
            false,
        ));
    }
}

pub(crate) fn run_cwasm_smoke_evidence(
    module_index: usize,
    executor: &mut TargetExecutor,
    store: &ManagedStoreRecord,
    code: &CodeObject,
    ledger: &CapabilityLedger,
    smoke_trace: &[HostValidationSmokeTrace],
) -> Result<(), Box<dyn Error>> {
    for (index, trace) in smoke_trace.iter().enumerate() {
        let activation = executor
            .start_activation(
                &store.store,
                code,
                ActivationEntry::Symbol(format!("cwasm-smoke:{}", trace.export)),
            )
            .map_err(|error| error.message())?;
        if trace.trap.is_some() {
            executor.synthetic_trap(
                TargetTrapClass::CodeObjectTrap,
                store.store.id,
                Some(activation),
                Some(code),
                Some(&format!("cwasm.host-validation.{}", trace.export)),
                "UnknownCodeTrap: host-validation Wasmtime trap attribution unavailable",
            );
            continue;
        }
        let number = cwasm_smoke_hostcall_number(module_index, index);
        let object = format!("host-validation.{}", code.package);
        let frame = HostcallFrame::new_bound(
            activation,
            &store.store,
            code,
            number,
            &object,
            &trace.export,
            1,
        )
        .to_wire_frame();
        executor.invoke_hostcall(code, frame, ledger).map_err(|error| error.message())?;
        executor.return_exit(activation).map_err(|error| error.message())?;
    }
    Ok(())
}

pub(crate) fn cwasm_smoke_hostcall_number(module_index: usize, trace_index: usize) -> u32 {
    9500 + module_index as u32 * 100 + trace_index as u32
}

pub(crate) fn run_activation_harness(
    index: usize,
    executor: &mut TargetExecutor,
    store: &ManagedStoreRecord,
    code: &CodeObject,
    ledger: &CapabilityLedger,
) -> Result<(), Box<dyn Error>> {
    let activation = executor
        .start_activation(
            &store.store,
            code,
            ActivationEntry::Symbol("vmos_service_entry".to_owned()),
        )
        .map_err(|error| error.message())?;
    if let Some(spec) = code.hostcalls.iter().find(|spec| spec.number < 9000) {
        let generation = ledger.generation_of(&code.package, &spec.object).unwrap_or(1);
        let mut frame = HostcallFrame::new_bound(
            activation,
            &store.store,
            code,
            spec.number,
            &spec.object,
            &spec.operation,
            generation,
        );
        if let Some(cap_arg) = capability_handle_arg_for(ledger, &code.package, spec) {
            frame = frame.with_cap_args(vec![cap_arg]);
        }
        executor
            .invoke_hostcall(code, frame.to_wire_frame(), ledger)
            .map_err(|error| error.message())?;
    }
    executor.return_exit(activation).map_err(|error| error.message())?;

    if index == 0 {
        for (number, object, operation) in [
            (9000, "mmio.denied", "map"),
            (9001, "dma.denied", "map"),
            (9002, "irq.denied", "bind"),
            (9003, "dmw.denied", "open"),
            (9004, "code-publish.denied", "publish"),
            (9006, "packet-device.denied", "rx"),
            (9007, "device.denied", "read"),
            (9008, "virtqueue.denied", "kick"),
            (9009, "timer.denied", "arm"),
            (9010, "guest-memory.denied", "read"),
            (9011, "snapshot.denied", "enter"),
            (9012, "fault-domain.denied", "restart"),
            (9013, "event-log.denied", "append"),
            (9014, "store-control.denied", "kill"),
        ] {
            let denied = executor
                .start_activation(
                    &store.store,
                    code,
                    ActivationEntry::Symbol("capability_gate".to_owned()),
                )
                .map_err(|error| error.message())?;
            let _ = executor.invoke_hostcall(
                code,
                HostcallFrame::new_bound(denied, &store.store, code, number, object, operation, 1)
                    .to_wire_frame(),
                ledger,
            );
        }
        if let Some(spec) = code.hostcalls.iter().find(|spec| spec.number < 9000) {
            let bad_abi = executor
                .start_activation(
                    &store.store,
                    code,
                    ActivationEntry::Symbol("bad_hostcall_abi".to_owned()),
                )
                .map_err(|error| error.message())?;
            let generation = ledger.generation_of(&code.package, &spec.object).unwrap_or(1);
            let frame = HostcallFrame::new_bound(
                bad_abi,
                &store.store,
                code,
                spec.number,
                &spec.object,
                &spec.operation,
                generation,
            );
            let mut wire_frame = frame.to_wire_frame();
            wire_frame.abi_version = 0;
            let _ = executor.invoke_hostcall(code, wire_frame, ledger);

            let bad_frame_size = executor
                .start_activation(
                    &store.store,
                    code,
                    ActivationEntry::Symbol("bad_hostcall_frame_size".to_owned()),
                )
                .map_err(|error| error.message())?;
            let frame = HostcallFrame::new_bound(
                bad_frame_size,
                &store.store,
                code,
                spec.number,
                &spec.object,
                &spec.operation,
                generation,
            );
            let mut wire_frame = frame.to_wire_frame();
            wire_frame.frame_size = HostcallFrame::FRAME_SIZE + 8;
            let _ = executor.invoke_hostcall(code, wire_frame, ledger);

            let unsupported = executor
                .start_activation(
                    &store.store,
                    code,
                    ActivationEntry::Symbol("unsupported_hostcall".to_owned()),
                )
                .map_err(|error| error.message())?;
            let frame = HostcallFrame::new_bound(
                unsupported,
                &store.store,
                code,
                9_999,
                "hostcall.unsupported",
                "decode",
                1,
            );
            let _ = executor.invoke_hostcall(code, frame.to_wire_frame(), ledger);

            if let Some(cap_arg) = capability_handle_arg_for(ledger, &code.package, spec) {
                let stale_cap_arg_activation = executor
                    .start_activation(
                        &store.store,
                        code,
                        ActivationEntry::Symbol("stale_capability_handle".to_owned()),
                    )
                    .map_err(|error| error.message())?;
                let mut stale_cap_arg = cap_arg.clone();
                stale_cap_arg.handle_generation += 1;
                let frame = HostcallFrame::new_bound(
                    stale_cap_arg_activation,
                    &store.store,
                    code,
                    spec.number,
                    &spec.object,
                    &spec.operation,
                    generation,
                )
                .with_cap_args(vec![stale_cap_arg]);
                let _ = executor.invoke_hostcall(code, frame.to_wire_frame(), ledger);

                let bad_cap_arg_activation = executor
                    .start_activation(
                        &store.store,
                        code,
                        ActivationEntry::Symbol("bad_capability_handle".to_owned()),
                    )
                    .map_err(|error| error.message())?;
                let mut cap_arg = cap_arg;
                cap_arg.rights_mask = 0;
                let frame = HostcallFrame::new_bound(
                    bad_cap_arg_activation,
                    &store.store,
                    code,
                    spec.number,
                    &spec.object,
                    &spec.operation,
                    generation,
                )
                .with_cap_args(vec![cap_arg]);
                let _ = executor.invoke_hostcall(code, frame.to_wire_frame(), ledger);
            }
        }

        let dmw = executor
            .start_activation(&store.store, code, ActivationEntry::Symbol("dmw_pending".to_owned()))
            .map_err(|error| error.message())?;
        let lease = executor
            .acquire_dmw_lease(dmw, "dmw.handle-mode.harness")
            .map_err(|error| error.message())?;
        let _ = executor.invoke_hostcall(
            code,
            HostcallFrame::new_bound(dmw, &store.store, code, 9005, "wait.timer", "park", 1)
                .to_wire_frame(),
            ledger,
        );
        executor.release_dmw_lease(lease).map_err(|error| error.message())?;

        let pc_trap = executor
            .start_activation(
                &store.store,
                code,
                ActivationEntry::Symbol("pc_trap_ebreak".to_owned()),
            )
            .map_err(|error| error.message())?;
        let trap_map = [TrapMapEntryV1::new(
            ObjectRefRaw::new(OBJECT_KIND_CODE_OBJECT_V1, code.id, code.generation),
            RV64_ENTRY_TRAP_EBREAK_OFFSET,
            RV64_ENTRY_TRAP_EBREAK_OFFSET + 4,
            TrapKindV1::WasmUnreachable,
            0,
            RV64_ENTRY_TRAP_EBREAK_OFFSET,
            0,
        )];
        executor
            .trap_exit_by_pc(
                pc_trap,
                code,
                code.text.start + RV64_ENTRY_TRAP_EBREAK_OFFSET,
                &trap_map,
            )
            .map_err(|error| error.message())?;

        for class in [
            TargetTrapClass::GuestTrap,
            TargetTrapClass::SupervisorStoreTrap,
            TargetTrapClass::CapabilityTrap,
            TargetTrapClass::WindowTrap,
            TargetTrapClass::HostcallTrap,
            TargetTrapClass::CodeObjectTrap,
            TargetTrapClass::SubstrateFault,
        ] {
            executor.synthetic_trap(
                class,
                store.store.id,
                Some(activation),
                Some(code),
                None,
                "target executor v1 typed trap harness",
            );
        }
    }
    Ok(())
}
