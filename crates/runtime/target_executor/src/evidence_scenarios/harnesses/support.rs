use super::super::super::*;

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
