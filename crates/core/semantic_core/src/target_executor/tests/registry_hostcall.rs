use super::*;

#[test]
fn simd_runtime_v1_code_object_declares_requirement() {
    let mut registry = ArtifactRegistry::new();
    let verified = registry.verify(image()).unwrap();
    let feature_set = target_feature_set_record();
    let mut publisher = CodePublisher::new();
    let code_id = publisher.allocate(&verified).unwrap();
    publisher
        .declare_simd_requirement(
            code_id,
            feature_set.object_ref(),
            "riscv-v",
            32,
            128,
            "requires RVV",
        )
        .unwrap();

    let code = publisher.object(code_id).unwrap().clone();
    assert!(code.simd_requirement.uses_simd);
    assert_eq!(code.simd_requirement.status, CodeObjectSimdRequirementStatus::Declared);
    assert_eq!(code.generation, 2);
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        artifacts: Vec::from([verified]),
        code_objects: Vec::from([code]),
        target_feature_sets: Vec::from([feature_set]),
        ..ContractGraphSnapshot::default()
    };
    assert_eq!(validate_contract_graph(&snapshot), Vec::new());
}

#[test]
fn simd_runtime_v1_rejects_missing_or_bad_requirement() {
    let mut registry = ArtifactRegistry::new();
    let verified = registry.verify(image()).unwrap();
    let mut publisher = CodePublisher::new();
    let code_id = publisher.allocate(&verified).unwrap();
    assert_eq!(
        publisher.declare_simd_requirement(
            code_id,
            ContractObjectRef::new(ContractObjectKind::CodeObject, 99, 1),
            "riscv-v",
            32,
            128,
            "wrong object kind",
        ),
        Err(CodePublisherError::InvalidSimdRequirement)
    );

    let mut code = publisher.object(code_id).unwrap().clone();
    code.simd_requirement = CodeObjectSimdRequirement {
        uses_simd: true,
        declared: false,
        required_abi: String::new(),
        min_vector_register_count: 0,
        min_vector_register_bits: 0,
        target_feature_set: None,
        status: CodeObjectSimdRequirementStatus::MissingDeclaration,
        note: "malformed test object".to_string(),
    };
    let snapshot = ContractGraphSnapshot {
        claimed_evidence_level: EvidenceBoundaryLevel::SemanticModel,
        artifacts: Vec::from([verified]),
        code_objects: Vec::from([code]),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);
    assert!(violations.iter().any(|violation| {
        violation.edge == "code->simd-requirement"
            && violation.kind == ContractViolationKind::ExternalEdgeMetadataMismatch
    }));
}

#[test]
fn registry_only_verifies_artifact_identity_and_code_publisher_owns_publish_state() {
    let mut registry = ArtifactRegistry::new();
    let verified = registry.verify(image()).unwrap();
    assert_eq!(registry.verified().len(), 1);
    assert_eq!(verified.artifact_id, 1);

    let mut publisher = CodePublisher::new();
    let code_id = publisher.allocate(&verified).unwrap();
    assert_eq!(publisher.object(code_id).unwrap().state, CodeObjectState::AllocatedRw);
    assert_eq!(publisher.publish_rx(code_id), Err(CodePublisherError::InvalidTransition));
    publisher.fill(code_id).unwrap();
    publisher.seal(code_id).unwrap();
    publisher.publish_rx(code_id).unwrap();
    assert_eq!(
        publisher.object(code_id).unwrap().text.permission,
        CodeRangePermission::ReadExecute
    );

    let mut stores = TargetStoreManager::new();
    let store_id =
        stores.register_verified_artifact(&verified, "restartable", "rebuild-from-artifact");
    stores.set_running(store_id).unwrap();
    let store_record = stores.record(store_id).unwrap().store.clone();
    publisher.bind_to_store(code_id, &store_record).unwrap();
    assert_eq!(publisher.object(code_id).unwrap().state, CodeObjectState::BoundToStore);
    assert_eq!(stores.record(store_id).unwrap().store.state, StoreState::Running);
}

#[test]
fn registry_rejects_malformed_hostcall_tables() {
    let mut registry = ArtifactRegistry::new();

    let mut zero_number = image();
    zero_number.hostcalls[0].number = 0;
    assert_eq!(registry.verify(zero_number), Err(ArtifactRegistryError::InvalidHostcallSpec));

    let mut duplicate_number = image();
    duplicate_number.hostcalls[1].number = duplicate_number.hostcalls[0].number;
    assert_eq!(registry.verify(duplicate_number), Err(ArtifactRegistryError::InvalidHostcallSpec));

    let mut empty_object = image();
    empty_object.hostcalls[0].object.clear();
    assert_eq!(registry.verify(empty_object), Err(ArtifactRegistryError::InvalidHostcallSpec));
}

#[test]
fn registry_restore_rejects_malformed_hostcall_tables() {
    let mut registry = ArtifactRegistry::new();
    let mut verified = registry.verify(image()).unwrap();
    verified.hostcalls[0].operation.clear();

    let mut restored = ArtifactRegistry::new();
    assert!(
        !restored.restore_verified_records(&[verified]),
        "restore must reject verified artifact records with malformed hostcall tables"
    );
    assert!(restored.verified().is_empty());
}

#[test]
fn registry_policy_rejects_manifest_binding_and_hash_mismatch() {
    let expected = ExpectedTargetArtifact::new(
        "driver_virtio_net",
        "driver_virtio_net.tart",
        "host-validation",
        "artifact-hash-1",
        "abi-1",
        "binding-1",
        "code-hash-1",
    );
    let mut expected_list = Vec::new();
    expected_list.push(expected);
    let mut registry = ArtifactRegistry::with_expected(expected_list);
    let mut bad = image();
    bad.code_hash = "hash-2".to_string();
    assert_eq!(registry.verify(bad), Err(ArtifactRegistryError::CodeHashMismatch));

    let expected = ExpectedTargetArtifact::new(
        "driver_virtio_net",
        "driver_virtio_net.tart",
        "host-validation",
        "artifact-hash-1",
        "abi-1",
        "binding-1",
        "code-hash-1",
    );
    let mut expected_list = Vec::new();
    expected_list.push(expected);
    let mut registry = ArtifactRegistry::with_expected(expected_list);
    let mut bad = image();
    bad.artifact_hash = "artifact-hash-2".to_string();
    assert_eq!(registry.verify(bad), Err(ArtifactRegistryError::ArtifactHashMismatch));

    let mut expected_list = Vec::new();
    expected_list.push(ExpectedTargetArtifact::new(
        "driver_virtio_net",
        "driver_virtio_net.tart",
        "host-validation",
        "artifact-hash-1",
        "abi-1",
        "binding-1",
        "code-hash-1",
    ));
    let mut registry = ArtifactRegistry::with_expected(expected_list);
    let verified = registry.verify(image()).unwrap();
    assert_eq!(verified.manifest_binding_hash, "binding-1");
}

#[test]
fn registry_policy_preserves_hash_and_signature_status() {
    let expected = ExpectedTargetArtifact::new(
        "driver_virtio_net",
        "driver_virtio_net.tart",
        "host-validation",
        "artifact-hash-1",
        "abi-1",
        "binding-1",
        "code-hash-1",
    )
    .with_policy_status(
        "manifest-bound",
        "prototype-self-signed-sha256",
        "profile-bound-unverified",
        false,
        "vmos-aotc-dev",
    );
    let mut expected_list = Vec::new();
    expected_list.push(expected);
    let mut registry = ArtifactRegistry::with_expected(expected_list);
    let mut good = image();
    good.hash_status = "manifest-bound".to_string();
    good.signature_scheme = "prototype-self-signed-sha256".to_string();
    good.signature_status = "profile-bound-unverified".to_string();
    good.signature_verified = false;
    good.signer = "vmos-aotc-dev".to_string();

    let verified = registry.verify(good).expect("policy status matches");
    assert_eq!(verified.hash_status, "manifest-bound");
    assert_eq!(verified.signature_status, "profile-bound-unverified");
    assert!(!verified.signature_verified);
    assert!(verified.summary().contains("signature_verified=false"));

    let expected = ExpectedTargetArtifact::new(
        "driver_virtio_net",
        "driver_virtio_net.tart",
        "host-validation",
        "artifact-hash-1",
        "abi-1",
        "binding-1",
        "code-hash-1",
    )
    .with_policy_status(
        "manifest-bound",
        "prototype-self-signed-sha256",
        "profile-bound-unverified",
        false,
        "vmos-aotc-dev",
    );
    let mut expected_list = Vec::new();
    expected_list.push(expected);
    let mut registry = ArtifactRegistry::with_expected(expected_list);
    let mut bad = image();
    bad.hash_status = "hash-unchecked".to_string();
    bad.signature_scheme = "prototype-self-signed-sha256".to_string();
    bad.signature_status = "profile-bound-unverified".to_string();
    bad.signer = "vmos-aotc-dev".to_string();
    assert_eq!(registry.verify(bad), Err(ArtifactRegistryError::HashStatusMismatch));
}

#[test]
fn hostcall_frame_v1_wire_abi_is_fixed_layout() {
    assert_eq!(
        ExecutorHostcallFrameV1::FRAME_SIZE as usize,
        core::mem::size_of::<ExecutorHostcallFrameV1>()
    );
    assert_eq!(ExecutorHostcallFrameV1::default().magic, ExecutorHostcallFrameV1::MAGIC);
    assert_eq!(ExecutorHostcallFrameV1::default().record_mode, RecordMode::Deterministic.as_u16());
    assert_eq!(ExecutorHostcallFrameV1::default().ret_tag, HostcallReturnTag::Ok.as_u16());
    assert_eq!(WireObjectRef::NULL, WireObjectRef::new(0, 0));
}

#[test]
fn hostcall_capability_gate_allows_granted_mmio_and_traps_ungranted_privileged_hostcalls() {
    let (_artifact, store, code, capabilities) = running_store_and_code();
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
    assert!(executor.hostcall_trace()[0].allowed);
    assert_eq!(executor.hostcall_trace()[0].artifact_generation, 1);

    for (number, object, operation) in [
        (2, "mmio.denied", "map"),
        (3, "dma.denied", "map"),
        (4, "irq.denied", "bind"),
        (5, "dmw.denied", "open"),
        (6, "code-publish.denied", "publish"),
        (7, "packet-device.net0", "rx"),
        (9, "device.denied", "read"),
        (10, "virtqueue.denied", "kick"),
        (11, "timer.denied", "arm"),
        (12, "guest-memory.denied", "read"),
        (13, "snapshot.denied", "enter"),
        (14, "fault-domain.denied", "restart"),
        (15, "event-log.denied", "append"),
        (16, "store-control.denied", "kill"),
    ] {
        let activation = executor
            .start_activation(&store.store, &code, ActivationEntry::Symbol("_start".to_string()))
            .unwrap();
        assert_eq!(
            executor.invoke_hostcall(
                &code,
                HostcallFrame::new_bound(
                    activation,
                    &store.store,
                    &code,
                    number,
                    object,
                    operation,
                    1,
                )
                .to_wire_frame(),
                &capabilities,
            ),
            Err(TargetExecutorError::CapabilityDenied)
        );
    }
    assert_eq!(executor.traps().len(), 14);
    assert!(executor.traps().iter().all(|trap| trap.class == TargetTrapClass::CapabilityTrap));
    assert!(executor.event_log().iter().any(|event| event.contains("CapabilityDenied")));
}

#[test]
fn hostcall_rejects_code_object_attribution_mismatch() {
    let (_artifact, store, code, capabilities) = running_store_and_code();
    let mut other_code = code.clone();
    other_code.id = code.id + 100;
    let mut executor = TargetExecutor::new();
    let activation = executor
        .start_activation(&store.store, &code, ActivationEntry::Symbol("_start".to_string()))
        .unwrap();
    assert_eq!(
        executor.invoke_hostcall(
            &other_code,
            HostcallFrame::new_bound(
                activation,
                &store.store,
                &other_code,
                1,
                "mmio.virtio-net",
                "map",
                1,
            )
            .to_wire_frame(),
            &capabilities,
        ),
        Err(TargetExecutorError::CodeObjectMismatch)
    );
    assert_eq!(executor.traps()[0].class, TargetTrapClass::CodeObjectTrap);
}

#[test]
fn hostcall_derives_subject_from_code_and_reports_bad_abi_with_trace() {
    let (_artifact, store, code, capabilities) = running_store_and_code();
    let mut executor = TargetExecutor::new();
    let activation = executor
        .start_activation(&store.store, &code, ActivationEntry::Symbol("_start".to_string()))
        .unwrap();
    let mut frame =
        HostcallFrame::new_bound(activation, &store.store, &code, 1, "mmio.virtio-net", "map", 1);
    let mut cap_args = Vec::new();
    cap_args.push(cap_arg_for(&capabilities, "driver_virtio_net", "mmio.virtio-net", "map"));
    frame = frame.with_cap_args(cap_args);
    frame.subject = "other_store".to_string();
    executor.invoke_hostcall(&code, frame.to_wire_frame(), &capabilities).unwrap();
    assert_eq!(executor.hostcall_trace()[0].subject, code.package);
    assert!(executor.hostcall_trace()[0].allowed);

    let activation = executor
        .start_activation(&store.store, &code, ActivationEntry::Symbol("_start".to_string()))
        .unwrap();
    let frame =
        HostcallFrame::new_bound(activation, &store.store, &code, 1, "mmio.virtio-net", "map", 1);
    let mut wire_frame = frame.to_wire_frame();
    wire_frame.abi_version = 0;
    assert_eq!(
        executor.invoke_hostcall(&code, wire_frame, &capabilities),
        Err(TargetExecutorError::HostcallAbiMismatch)
    );
    assert!(executor.hostcall_trace().iter().any(|trace| trace.result == "bad-hostcall-abi"));
    assert!(executor.traps().iter().any(|trap| trap.class == TargetTrapClass::HostcallTrap
        && trap.fault_policy == "bad-hostcall-abi"));

    let activation = executor
        .start_activation(&store.store, &code, ActivationEntry::Symbol("_start".to_string()))
        .unwrap();
    let frame =
        HostcallFrame::new_bound(activation, &store.store, &code, 1, "mmio.virtio-net", "map", 1);
    let mut wire_frame = frame.to_wire_frame();
    wire_frame.frame_size = HostcallFrame::FRAME_SIZE + 8;
    assert_eq!(
        executor.invoke_hostcall(&code, wire_frame, &capabilities),
        Err(TargetExecutorError::HostcallAbiMismatch)
    );
    assert!(executor.hostcall_trace().iter().any(
        |trace| trace.result == "bad-frame-size" && trace.ret_tag == HostcallReturnTag::BadAbi
    ));
}

#[test]
fn cap_args_are_checked_against_ledger_generation_and_rights() {
    let (_artifact, store, code, capabilities) = running_store_and_code();
    let cap = capabilities.check("driver_virtio_net", "mmio.virtio-net", "map").unwrap().clone();
    let mut executor = TargetExecutor::new();
    let activation = executor
        .start_activation(&store.store, &code, ActivationEntry::Symbol("_start".to_string()))
        .unwrap();
    let mut cap_args = Vec::new();
    cap_args.push(CapabilityHandleArg::from_record(&cap, 1, &["map"]));
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
                cap.generation,
            )
            .with_cap_args(cap_args)
            .to_wire_frame(),
            &capabilities,
        )
        .unwrap();

    let activation = executor
        .start_activation(&store.store, &code, ActivationEntry::Symbol("_start".to_string()))
        .unwrap();
    let mut stale_cap_args = Vec::new();
    let mut stale_arg = CapabilityHandleArg::from_record(&cap, 1, &["map"]);
    stale_arg.handle_generation += 1;
    stale_cap_args.push(stale_arg);
    assert_eq!(
        executor.invoke_hostcall(
            &code,
            HostcallFrame::new_bound(
                activation,
                &store.store,
                &code,
                1,
                "mmio.virtio-net",
                "map",
                cap.generation,
            )
            .with_cap_args(stale_cap_args)
            .to_wire_frame(),
            &capabilities,
        ),
        Err(TargetExecutorError::CapabilityDenied)
    );
    assert!(executor.hostcall_trace().iter().any(|trace| trace.result == "cap-arg-generation"));

    let activation = executor
        .start_activation(&store.store, &code, ActivationEntry::Symbol("_start".to_string()))
        .unwrap();
    let mut bad_mask_cap_args = Vec::new();
    bad_mask_cap_args.push(CapabilityHandleArg::from_record(&cap, 0, &["map"]));
    assert_eq!(
        executor.invoke_hostcall(
            &code,
            HostcallFrame::new_bound(
                activation,
                &store.store,
                &code,
                1,
                "mmio.virtio-net",
                "map",
                cap.generation,
            )
            .with_cap_args(bad_mask_cap_args)
            .to_wire_frame(),
            &capabilities,
        ),
        Err(TargetExecutorError::CapabilityDenied)
    );
    assert!(executor.hostcall_trace().iter().any(|trace| trace.result == "cap-arg-rights-mask"));

    let activation = executor
        .start_activation(&store.store, &code, ActivationEntry::Symbol("_start".to_string()))
        .unwrap();
    let mut forged_global_id_args = Vec::new();
    let mut forged_global_id = CapabilityHandleArg::from_record(&cap, 1, &["map"]);
    forged_global_id.handle_slot = cap.object_ref.expect("authority object ref").object().id as u32;
    forged_global_id.handle_tag = 0;
    forged_global_id_args.push(forged_global_id);
    assert_eq!(
        executor.invoke_hostcall(
            &code,
            HostcallFrame::new_bound(
                activation,
                &store.store,
                &code,
                1,
                "mmio.virtio-net",
                "map",
                cap.generation,
            )
            .with_cap_args(forged_global_id_args)
            .to_wire_frame(),
            &capabilities,
        ),
        Err(TargetExecutorError::CapabilityDenied)
    );
    assert!(
        executor
            .hostcall_trace()
            .iter()
            .any(|trace| trace.result == "cap-arg-missing" || trace.result == "cap-arg-tag")
    );
}

#[test]
fn hostcall_gate_closure_records_positive_and_negative_trace_reasons() {
    let (_artifact, store, code, capabilities) = running_store_and_code();
    let cap = capabilities.check("driver_virtio_net", "mmio.virtio-net", "map").unwrap().clone();
    let mut executor = TargetExecutor::new();

    let activation = executor
        .start_activation(
            &store.store,
            &code,
            ActivationEntry::Symbol("hostcall_gate_ok".to_string()),
        )
        .unwrap();
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
                cap.generation,
            )
            .with_cap_args(Vec::from([CapabilityHandleArg::from_record(&cap, 1, &["map"])]))
            .to_wire_frame(),
            &capabilities,
        )
        .unwrap();

    let activation = executor
        .start_activation(
            &store.store,
            &code,
            ActivationEntry::Symbol("hostcall_bad_frame".to_string()),
        )
        .unwrap();
    let mut wire_frame = HostcallFrame::new_bound(
        activation,
        &store.store,
        &code,
        1,
        "mmio.virtio-net",
        "map",
        cap.generation,
    )
    .to_wire_frame();
    wire_frame.frame_size = HostcallFrame::FRAME_SIZE + 8;
    assert_eq!(
        executor.invoke_hostcall(&code, wire_frame, &capabilities),
        Err(TargetExecutorError::HostcallAbiMismatch)
    );

    let activation = executor
        .start_activation(
            &store.store,
            &code,
            ActivationEntry::Symbol("hostcall_bad_abi".to_string()),
        )
        .unwrap();
    let mut wire_frame = HostcallFrame::new_bound(
        activation,
        &store.store,
        &code,
        1,
        "mmio.virtio-net",
        "map",
        cap.generation,
    )
    .to_wire_frame();
    wire_frame.abi_version = 0;
    assert_eq!(
        executor.invoke_hostcall(&code, wire_frame, &capabilities),
        Err(TargetExecutorError::HostcallAbiMismatch)
    );

    let activation = executor
        .start_activation(
            &store.store,
            &code,
            ActivationEntry::Symbol("hostcall_stale_cap".to_string()),
        )
        .unwrap();
    let mut stale_arg = CapabilityHandleArg::from_record(&cap, 1, &["map"]);
    stale_arg.handle_generation += 1;
    assert_eq!(
        executor.invoke_hostcall(
            &code,
            HostcallFrame::new_bound(
                activation,
                &store.store,
                &code,
                1,
                "mmio.virtio-net",
                "map",
                cap.generation,
            )
            .with_cap_args(Vec::from([stale_arg]))
            .to_wire_frame(),
            &capabilities,
        ),
        Err(TargetExecutorError::CapabilityDenied)
    );

    let activation = executor
        .start_activation(
            &store.store,
            &code,
            ActivationEntry::Symbol("hostcall_unsupported".to_string()),
        )
        .unwrap();
    assert_eq!(
        executor.invoke_hostcall(
            &code,
            HostcallFrame::new_bound(
                activation,
                &store.store,
                &code,
                77,
                "hostcall.unsupported",
                "decode",
                1,
            )
            .to_wire_frame(),
            &capabilities,
        ),
        Err(TargetExecutorError::HostcallNotDeclared)
    );

    let trace = |result: &str| {
        executor
            .hostcall_trace()
            .iter()
            .find(|trace| trace.result == result)
            .unwrap_or_else(|| panic!("missing hostcall trace result={result}"))
    };
    assert_eq!(trace("complete").gate_status, "exit");
    assert_eq!(trace("complete").denial_reason, None);
    for result in ["bad-frame-size", "bad-hostcall-abi", "cap-arg-generation", "unsupported-call"] {
        let trace = trace(result);
        assert_eq!(trace.subject_source, HostcallTraceRecord::SUBJECT_SOURCE_ACTIVE_STATE);
        assert_eq!(trace.denial_reason.as_deref(), Some(result));
        assert!(trace.trap_out.is_some());
    }
    assert_eq!(trace("cap-arg-generation").gate_status, "denied");
    assert_eq!(trace("bad-frame-size").gate_status, "trap");
    assert_eq!(trace("bad-hostcall-abi").gate_status, "trap");
    assert_eq!(trace("unsupported-call").gate_status, "trap");
}

#[test]
fn authority_matrix_covers_privileged_object_classes_and_fails_closed() {
    for (object, operation) in [
        ("mmio.regs", "read32"),
        ("dma.buf", "sync_for_device"),
        ("irq.net0", "ack"),
        ("dmw.window", "map_user_window"),
        ("code-publish.object", "publish"),
        ("snapshot.barrier", "enter"),
        ("packet-device.net0", "rx"),
        ("virtqueue.net0", "kick"),
        ("device.pulse", "read"),
        ("guest-memory.linear", "map"),
        ("timer.sleep", "arm"),
        ("fault-domain.driver", "restart"),
        ("event-log.store", "append"),
        ("store-control.driver", "kill"),
    ] {
        let decision = AuthorityMatrix::check(object, operation, false).unwrap();
        assert!(decision.requires_capability, "{object}:{operation}");
        assert!(decision.required_right.is_some(), "{object}:{operation}");
    }
    assert_eq!(
        AuthorityMatrix::check("mmio.regs", "teleport", false),
        Err(AuthorityMatrixError::UnknownOperation)
    );
    assert_eq!(
        AuthorityMatrix::check("unknown", "op", false),
        Err(AuthorityMatrixError::UnknownObjectClass)
    );
}
