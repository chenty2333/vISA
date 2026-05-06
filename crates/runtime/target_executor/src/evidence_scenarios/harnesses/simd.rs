use super::super::super::*;

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
