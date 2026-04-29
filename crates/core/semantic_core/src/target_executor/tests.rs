use super::*;

fn image() -> TargetArtifactImage {
    let mut image = TargetArtifactImage::new(
        1,
        "driver_virtio_net",
        "driver_virtio_net.tart",
        "driver",
        "host-validation",
        "artifact-hash-1",
        "abi-1",
        "binding-1",
        "code-hash-1",
        TargetMemoryPlan::new(16, 32, 64),
    );
    image.exports.push("vmos_service_entry".to_string());
    image.address_map.push(TargetAddressMapEntry::new("_start", 0, 64));
    image.trap_metadata.push(TargetTrapMetadata::new(TargetTrapClass::CodeObjectTrap, "_start", 0));
    image.capabilities.push(TargetCapabilitySpec::new("mmio.virtio-net", &["map"], "store"));
    image.hostcalls.push(HostcallSpec::new(
        1,
        "hostcall.mmio.map",
        HostcallCategory::Mmio,
        "mmio.virtio-net",
        "map",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        2,
        "hostcall.mmio.denied",
        HostcallCategory::Mmio,
        "mmio.denied",
        "map",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        3,
        "hostcall.dma.denied",
        HostcallCategory::Dma,
        "dma.denied",
        "map",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        4,
        "hostcall.irq.denied",
        HostcallCategory::Irq,
        "irq.denied",
        "bind",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        5,
        "hostcall.dmw.denied",
        HostcallCategory::Dmw,
        "dmw.denied",
        "open",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        6,
        "hostcall.code-publish.denied",
        HostcallCategory::CodePublish,
        "code-publish.denied",
        "publish",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        7,
        "hostcall.packet-device.denied",
        HostcallCategory::PacketDevice,
        "packet-device.net0",
        "rx",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        8,
        "hostcall.wait.pending",
        HostcallCategory::Wait,
        "wait.timer",
        "park",
        true,
    ));
    image.hostcalls.push(HostcallSpec::new(
        9,
        "hostcall.device.denied",
        HostcallCategory::Device,
        "device.denied",
        "read",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        10,
        "hostcall.virtqueue.denied",
        HostcallCategory::Virtqueue,
        "virtqueue.denied",
        "kick",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        11,
        "hostcall.timer.denied",
        HostcallCategory::Timer,
        "timer.denied",
        "arm",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        12,
        "hostcall.guest-memory.denied",
        HostcallCategory::GuestMemory,
        "guest-memory.denied",
        "read",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        13,
        "hostcall.snapshot.denied",
        HostcallCategory::Snapshot,
        "snapshot.denied",
        "enter",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        14,
        "hostcall.fault-domain.denied",
        HostcallCategory::FaultDomain,
        "fault-domain.denied",
        "restart",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        15,
        "hostcall.event-log.denied",
        HostcallCategory::EventLog,
        "event-log.denied",
        "append",
        false,
    ));
    image.hostcalls.push(HostcallSpec::new(
        16,
        "hostcall.store-control.denied",
        HostcallCategory::StoreControl,
        "store-control.denied",
        "kill",
        false,
    ));
    image
}

fn running_store_and_code() -> (VerifiedArtifact, ManagedStoreRecord, CodeObject, CapabilityLedger)
{
    let mut registry = ArtifactRegistry::new();
    let verified = registry.verify(image()).unwrap();
    let mut stores = TargetStoreManager::new();
    let store_id =
        stores.register_verified_artifact(&verified, "restartable", "rebuild-from-artifact");
    stores.set_running(store_id).unwrap();
    let mut publisher = CodePublisher::new();
    let code_id = publisher.allocate(&verified).unwrap();
    publisher.fill(code_id).unwrap();
    publisher.seal(code_id).unwrap();
    publisher.publish_rx(code_id).unwrap();
    let store_record = stores.record(store_id).unwrap().store.clone();
    publisher.bind_to_store(code_id, &store_record).unwrap();
    let mut capabilities = CapabilityLedger::new();
    capabilities
        .grant_manifest_binding(
            "driver_virtio_net",
            "mmio.virtio-net",
            &["map"],
            "store",
            CapabilityClass::MmioRegion,
            Some(store_id),
            Some(store_record.generation),
            None,
            "target-executor-test",
        )
        .expect("test capability has owner store generation");
    (
        verified,
        stores.record(store_id).unwrap().clone(),
        publisher.object(code_id).unwrap().clone(),
        capabilities,
    )
}

fn target_feature_set_record() -> TargetFeatureSetRecord {
    TargetFeatureSetRecord {
        id: 21_000,
        name: "riscv64-qemu-virt-research-target".to_string(),
        discovery_source: "target-runtime-default-profile".to_string(),
        target_profile: "riscv64-qemu-virt-research".to_string(),
        target_arch: "riscv64".to_string(),
        base_isa: "rv64imac".to_string(),
        simd_abi: "riscv-v".to_string(),
        simd_supported: true,
        vector_register_count: 32,
        vector_register_bits: 128,
        scalar_fallback: true,
        unsupported_reason: String::new(),
        generation: 1,
        state: TargetFeatureSetState::Discovered,
        recorded_at_event: 1,
        note: "test target feature set".to_string(),
    }
}

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

fn cap_arg_for(
    capabilities: &CapabilityLedger,
    subject: &str,
    object: &str,
    operation: &str,
) -> CapabilityHandleArg {
    let cap = capabilities.check(subject, object, operation).unwrap();
    let index = cap.operations.as_slice().iter().position(|right| right == operation).unwrap();
    CapabilityHandleArg::from_record(cap, 1u64 << index, &[operation])
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
        virtio_net_backends: Vec::new(),
        fake_block_backends: Vec::new(),
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
        virtio_net_backends: Vec::new(),
        fake_block_backends: Vec::new(),
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
        virtio_net_backends: Vec::new(),
        fake_block_backends: Vec::new(),
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
        virtio_net_backends: Vec::new(),
        fake_block_backends: Vec::new(),
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
        virtio_net_backends: Vec::new(),
        fake_block_backends: Vec::new(),
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

#[test]
fn dmw_handle_mode_lease_cannot_cross_pending_or_snapshot_barrier() {
    let (_artifact, store, code, capabilities) = running_store_and_code();
    let mut executor = TargetExecutor::new();
    let activation = executor
        .start_activation(&store.store, &code, ActivationEntry::Symbol("_start".to_string()))
        .unwrap();
    let lease = executor.acquire_dmw_lease(activation, "dmw.handle.1").unwrap();
    assert_eq!(executor.snapshot_barrier(), Err(TargetExecutorError::DmwLeaseActive));
    assert_eq!(
        executor.invoke_hostcall(
            &code,
            HostcallFrame::new_bound(activation, &store.store, &code, 8, "wait.timer", "park", 1,)
                .to_wire_frame(),
            &capabilities,
        ),
        Err(TargetExecutorError::DmwLeaseActive)
    );
    assert_eq!(executor.traps()[0].class, TargetTrapClass::WindowTrap);
    assert!(!executor.dmw_leases()[0].active);
    executor.release_dmw_lease(lease).unwrap();
    assert_eq!(executor.snapshot_barrier(), Ok(()));
}

#[test]
fn typed_trap_surface_and_migration_classification_are_queryable() {
    let (_artifact, store, code, _capabilities) = running_store_and_code();
    let mut executor = TargetExecutor::new();
    let activation = executor
        .start_activation(&store.store, &code, ActivationEntry::Symbol("_start".to_string()))
        .unwrap();
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
            Some(&code),
            None,
            "typed trap harness",
        );
    }
    assert_eq!(executor.traps().len(), 7);
    assert!(executor.traps().iter().any(|trap| trap.class == TargetTrapClass::CodeObjectTrap
        && trap.code_object == Some(code.id)
        && trap.artifact == Some(code.artifact_id)));
    let migration = executor.classify_migration_objects(core::slice::from_ref(&code));
    assert!(migration.iter().any(|record| record.class == MigrationObjectClass::Migrated));
    assert!(migration.iter().any(|record| record.class == MigrationObjectClass::Rebuilt));
    assert!(migration.iter().any(|record| record.class == MigrationObjectClass::NeverMigrated));
}

#[test]
fn trap_record_uses_historical_refs() {
    let (_artifact, store, code, _capabilities) = running_store_and_code();
    let mut executor = TargetExecutor::new();
    let activation = executor
        .start_activation(
            &store.store,
            &code,
            ActivationEntry::Symbol("entry_trap_ebreak".to_string()),
        )
        .unwrap();
    let offset = target_abi::RV64_ENTRY_TRAP_EBREAK_OFFSET;
    let trap_map = [TrapMapEntryV1::new(
        ObjectRefRaw::new(OBJECT_KIND_CODE_OBJECT_V1, code.id, code.generation),
        offset,
        offset + 4,
        TrapKindV1::WasmUnreachable,
        1,
        0x20,
        7,
    )];

    let trap_id =
        executor.trap_exit_by_pc(activation, &code, code.text.start + offset, &trap_map).unwrap();
    let trap = executor.traps().iter().find(|trap| trap.id == trap_id).unwrap();

    assert_eq!(trap.store, Some(store.store.id));
    assert_eq!(trap.store_generation, Some(store.store.generation));
    assert_eq!(trap.activation, Some(activation));
    assert!(trap.activation_generation.is_some());
    assert_eq!(trap.code_object, Some(code.id));
    assert_eq!(trap.code_generation, Some(code.generation));
    assert_eq!(trap.artifact, Some(code.artifact_id));
    assert_eq!(trap.artifact_generation, Some(TARGET_ARTIFACT_GENERATION_V1));
    assert_eq!(trap.offset, Some(offset));
    assert_eq!(trap.trap_kind.as_deref(), Some("wasm-unreachable"));
    assert_eq!(trap.attribution_status, "trap-map-attributed");
    assert_eq!(trap.classification_status.as_deref(), Some("wasm-unreachable"));
}

#[test]
fn trap_map_records_success_and_failure_attribution_statuses() {
    let (_artifact, store, code, _capabilities) = running_store_and_code();
    let mut executor = TargetExecutor::new();
    let offset = target_abi::RV64_ENTRY_TRAP_EBREAK_OFFSET;
    let trap_map = [TrapMapEntryV1::new(
        ObjectRefRaw::new(OBJECT_KIND_CODE_OBJECT_V1, code.id, code.generation),
        offset,
        offset + 4,
        TrapKindV1::WasmUnreachable,
        1,
        0x20,
        7,
    )];

    let activation = executor
        .start_activation(&store.store, &code, ActivationEntry::Symbol("trap_success".to_string()))
        .unwrap();
    let success =
        executor.trap_exit_by_pc(activation, &code, code.text.start + offset, &trap_map).unwrap();
    assert_eq!(
        executor.traps().iter().find(|trap| trap.id == success).unwrap().attribution_status,
        "trap-map-attributed"
    );

    let activation = executor
        .start_activation(
            &store.store,
            &code,
            ActivationEntry::Symbol("trap_unknown_pc".to_string()),
        )
        .unwrap();
    let unknown_pc =
        executor.trap_exit_by_pc(activation, &code, code.text.end() + 0x1000, &trap_map).unwrap();
    let trap = executor.traps().iter().find(|trap| trap.id == unknown_pc).unwrap();
    assert_eq!(trap.attribution_status, "trap-map-unknown-pc");
    assert_eq!(trap.trap_kind.as_deref(), Some("unknown-code-fault"));
    assert_eq!(trap.code_object, None);

    let activation = executor
        .start_activation(
            &store.store,
            &code,
            ActivationEntry::Symbol("trap_missing_entry".to_string()),
        )
        .unwrap();
    let missing_entry =
        executor.trap_exit_by_pc(activation, &code, code.text.start + offset, &[]).unwrap();
    let trap = executor.traps().iter().find(|trap| trap.id == missing_entry).unwrap();
    assert_eq!(trap.attribution_status, "trap-map-missing-entry");
    assert_eq!(trap.trap_kind.as_deref(), Some("unknown-code-trap"));
    assert_eq!(trap.code_object, Some(code.id));

    let activation = executor
        .start_activation(
            &store.store,
            &code,
            ActivationEntry::Symbol("trap_stale_code".to_string()),
        )
        .unwrap();
    let mut retired_code = code.clone();
    retired_code.state = CodeObjectState::Retired;
    let stale = executor
        .trap_exit_by_pc(activation, &retired_code, retired_code.text.start + offset, &trap_map)
        .unwrap();
    let trap = executor.traps().iter().find(|trap| trap.id == stale).unwrap();
    assert_eq!(trap.attribution_status, "trap-map-stale-code");
    assert_eq!(trap.trap_kind.as_deref(), Some("stale-code-execution-fault"));
}

#[test]
fn simd_runtime_v3_trap_records_requirement_attribution() {
    let (artifact, store, mut code, _capabilities) = running_store_and_code();
    let feature_set = target_feature_set_record();
    code.simd_requirement = CodeObjectSimdRequirement::declared_simd(
        "riscv-v",
        32,
        128,
        feature_set.object_ref(),
        "v3 simd trap attribution",
    );
    code.generation += 1;
    let mut executor = TargetExecutor::new();
    let activation = executor
        .start_activation(&store.store, &code, ActivationEntry::Symbol("simd_fault".to_string()))
        .unwrap();
    let offset = 0x40;
    let trap_map = [TrapMapEntryV1::new(
        ObjectRefRaw::new(OBJECT_KIND_CODE_OBJECT_V1, code.id, code.generation),
        offset,
        offset + 4,
        TrapKindV1::SimdUnsupported,
        7,
        0x80,
        13,
    )];

    let trap_id =
        executor.trap_exit_by_pc(activation, &code, code.text.start + offset, &trap_map).unwrap();
    let trap = executor.traps().iter().find(|trap| trap.id == trap_id).unwrap();
    let simd = trap.simd_attribution.as_ref().expect("SIMD trap attribution");

    assert_eq!(trap.class, TargetTrapClass::CodeObjectTrap);
    assert_eq!(trap.trap_kind.as_deref(), Some("simd-unsupported"));
    assert_eq!(simd.classification, SimdTrapClassification::UnsupportedTargetProfile);
    assert_eq!(simd.required_abi, "riscv-v");
    assert_eq!(simd.target_feature_set, Some(feature_set.object_ref()));

    let snapshot = ContractGraphSnapshot {
        artifacts: Vec::from([artifact]),
        code_objects: Vec::from([code]),
        target_feature_sets: Vec::from([feature_set]),
        stores: Vec::from([store.store]),
        activations: executor.activations().to_vec(),
        traps: executor.traps().to_vec(),
        ..ContractGraphSnapshot::default()
    };
    assert_eq!(validate_contract_graph(&snapshot), Vec::new());
}

#[test]
fn simd_runtime_v3_rejects_simd_trap_without_requirement() {
    let (artifact, store, code, _capabilities) = running_store_and_code();
    let mut executor = TargetExecutor::new();
    let activation = executor
        .start_activation(
            &store.store,
            &code,
            ActivationEntry::Symbol("unexpected_simd_fault".to_string()),
        )
        .unwrap();
    let offset = 0x44;
    let trap_map = [TrapMapEntryV1::new(
        ObjectRefRaw::new(OBJECT_KIND_CODE_OBJECT_V1, code.id, code.generation),
        offset,
        offset + 4,
        TrapKindV1::SimdIllegalInstruction,
        8,
        0x84,
        14,
    )];
    executor.trap_exit_by_pc(activation, &code, code.text.start + offset, &trap_map).unwrap();

    let snapshot = ContractGraphSnapshot {
        artifacts: Vec::from([artifact]),
        code_objects: Vec::from([code]),
        stores: Vec::from([store.store]),
        activations: executor.activations().to_vec(),
        traps: executor.traps().to_vec(),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);
    assert!(violations.iter().any(|violation| {
        violation.edge == "trap->simd-requirement"
            && violation.kind == ContractViolationKind::ExternalEdgeMetadataMismatch
    }));
}

#[test]
fn simd_runtime_v10_fault_injection_validates_exact_trap_attribution() {
    let (artifact, store, mut code, _capabilities) = running_store_and_code();
    let mut feature_set = target_feature_set_record();
    feature_set.simd_supported = false;
    feature_set.vector_register_count = 0;
    feature_set.vector_register_bits = 0;
    feature_set.unsupported_reason = "RVV disabled for fault injection".to_string();
    code.simd_requirement = CodeObjectSimdRequirement::declared_simd(
        "riscv-v",
        32,
        128,
        feature_set.object_ref(),
        "v10 simd fault injection attribution",
    );
    code.generation += 1;
    let mut executor = TargetExecutor::new();
    let activation = executor
        .start_activation(
            &store.store,
            &code,
            ActivationEntry::Symbol("simd_fault_injection".to_string()),
        )
        .unwrap();
    let offset = 0x48;
    let trap_map = [TrapMapEntryV1::new(
        ObjectRefRaw::new(OBJECT_KIND_CODE_OBJECT_V1, code.id, code.generation),
        offset,
        offset + 4,
        TrapKindV1::SimdUnsupported,
        9,
        0x88,
        15,
    )];
    let trap_id =
        executor.trap_exit_by_pc(activation, &code, code.text.start + offset, &trap_map).unwrap();
    let trap = executor.traps().iter().find(|trap| trap.id == trap_id).unwrap();
    let injection = SimdFaultInjectionRecord {
        id: 22_010,
        activation: ContractObjectRef::new(
            ContractObjectKind::Activation,
            activation,
            trap.activation_generation.unwrap(),
        ),
        code_object: code.object_ref(),
        trap: trap.object_ref(),
        target_feature_set: feature_set.object_ref(),
        vector_state: None,
        kind: SimdFaultInjectionKind::UnsupportedFeature,
        effect: SimdFaultInjectionEffect::ActivationTrapped,
        required_abi: "riscv-v".to_string(),
        vector_register_count: 32,
        vector_register_bits: 128,
        injected_faults: 1,
        generation: 1,
        state: SimdFaultInjectionState::Recorded,
        recorded_at_event: 99,
        note: "v10 SIMD fault injection".to_string(),
    };
    let snapshot = ContractGraphSnapshot {
        artifacts: Vec::from([artifact]),
        code_objects: Vec::from([code]),
        target_feature_sets: Vec::from([feature_set]),
        stores: Vec::from([store.store]),
        activations: executor.activations().to_vec(),
        traps: executor.traps().to_vec(),
        simd_fault_injections: Vec::from([injection]),
        ..ContractGraphSnapshot::default()
    };

    assert_eq!(validate_contract_graph(&snapshot), Vec::new());
}

#[test]
fn simd_runtime_v10_rejects_fault_injection_trap_kind_mismatch() {
    let (artifact, store, mut code, _capabilities) = running_store_and_code();
    let mut feature_set = target_feature_set_record();
    feature_set.simd_supported = false;
    feature_set.vector_register_count = 0;
    feature_set.vector_register_bits = 0;
    feature_set.unsupported_reason = "RVV disabled for fault injection".to_string();
    code.simd_requirement = CodeObjectSimdRequirement::declared_simd(
        "riscv-v",
        32,
        128,
        feature_set.object_ref(),
        "v10 simd fault injection attribution",
    );
    code.generation += 1;
    let mut executor = TargetExecutor::new();
    let activation = executor
        .start_activation(
            &store.store,
            &code,
            ActivationEntry::Symbol("simd_fault_injection".to_string()),
        )
        .unwrap();
    let trap_map = [TrapMapEntryV1::new(
        ObjectRefRaw::new(OBJECT_KIND_CODE_OBJECT_V1, code.id, code.generation),
        0x48,
        0x4c,
        TrapKindV1::SimdUnsupported,
        9,
        0x88,
        15,
    )];
    let trap_id =
        executor.trap_exit_by_pc(activation, &code, code.text.start + 0x48, &trap_map).unwrap();
    let trap = executor.traps().iter().find(|trap| trap.id == trap_id).unwrap();
    let injection = SimdFaultInjectionRecord {
        id: 22_010,
        activation: ContractObjectRef::new(
            ContractObjectKind::Activation,
            activation,
            trap.activation_generation.unwrap(),
        ),
        code_object: code.object_ref(),
        trap: trap.object_ref(),
        target_feature_set: feature_set.object_ref(),
        vector_state: None,
        kind: SimdFaultInjectionKind::IllegalInstruction,
        effect: SimdFaultInjectionEffect::ActivationTrapped,
        required_abi: "riscv-v".to_string(),
        vector_register_count: 32,
        vector_register_bits: 128,
        injected_faults: 1,
        generation: 1,
        state: SimdFaultInjectionState::Recorded,
        recorded_at_event: 99,
        note: "bad V10 SIMD fault injection".to_string(),
    };
    let snapshot = ContractGraphSnapshot {
        artifacts: Vec::from([artifact]),
        code_objects: Vec::from([code]),
        target_feature_sets: Vec::from([feature_set]),
        stores: Vec::from([store.store]),
        activations: executor.activations().to_vec(),
        traps: executor.traps().to_vec(),
        simd_fault_injections: Vec::from([injection]),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "simd-fault-injection->trap"
            && violation.kind == ContractViolationKind::ExternalEdgeMetadataMismatch
    }));
    assert!(violations.iter().any(|violation| {
        violation.edge == "simd-fault-injection->target-feature-set"
            && violation.kind == ContractViolationKind::ExternalEdgeMetadataMismatch
    }));
}

#[test]
fn simd_runtime_v10_rejects_fault_injection_wrong_ref_kind() {
    let (artifact, store, code, _capabilities) = running_store_and_code();
    let mut feature_set = target_feature_set_record();
    feature_set.simd_supported = false;
    feature_set.vector_register_count = 0;
    feature_set.vector_register_bits = 0;
    feature_set.unsupported_reason = "RVV disabled for fault injection".to_string();
    let injection = SimdFaultInjectionRecord {
        id: 22_010,
        activation: store.store.object_ref(),
        code_object: code.object_ref(),
        trap: ContractObjectRef::new(ContractObjectKind::Trap, 33, 1),
        target_feature_set: feature_set.object_ref(),
        vector_state: None,
        kind: SimdFaultInjectionKind::UnsupportedFeature,
        effect: SimdFaultInjectionEffect::ActivationTrapped,
        required_abi: "riscv-v".to_string(),
        vector_register_count: 32,
        vector_register_bits: 128,
        injected_faults: 1,
        generation: 1,
        state: SimdFaultInjectionState::Recorded,
        recorded_at_event: 99,
        note: "bad V10 SIMD fault injection ref kind".to_string(),
    };
    let snapshot = ContractGraphSnapshot {
        artifacts: Vec::from([artifact]),
        code_objects: Vec::from([code]),
        target_feature_sets: Vec::from([feature_set]),
        stores: Vec::from([store.store]),
        simd_fault_injections: Vec::from([injection]),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "simd-fault-injection->activation"
            && violation.kind == ContractViolationKind::ExternalEdgeMetadataMismatch
    }));
}

#[test]
fn simd_runtime_v11_benchmark_validates_scalar_and_vector_code_requirements() {
    let (artifact, store, scalar_code, _capabilities) = running_store_and_code();
    let feature_set = target_feature_set_record();
    let mut vector_code = scalar_code.clone();
    vector_code.id += 1;
    vector_code.generation += 1;
    vector_code.simd_requirement = CodeObjectSimdRequirement::declared_simd(
        "riscv-v",
        32,
        128,
        feature_set.object_ref(),
        "v11 vector benchmark code",
    );
    let benchmark = SimdBenchmarkRecord {
        id: 22_011,
        target_feature_set: feature_set.object_ref(),
        scalar_code_object: scalar_code.object_ref(),
        vector_code_object: vector_code.object_ref(),
        simd_abi: "riscv-v".to_string(),
        vector_register_count: 32,
        vector_register_bits: 128,
        workload_units: 4096,
        scalar_nanos: 120_000,
        vector_nanos: 40_000,
        speedup_milli: 3000,
        context_overhead_nanos: 80_000,
        generation: 1,
        state: SimdBenchmarkState::Recorded,
        recorded_at_event: 99,
        note: "v11 scalar/vector benchmark".to_string(),
    };
    let snapshot = ContractGraphSnapshot {
        artifacts: Vec::from([artifact]),
        code_objects: Vec::from([scalar_code, vector_code]),
        target_feature_sets: Vec::from([feature_set]),
        stores: Vec::from([store.store]),
        simd_benchmarks: Vec::from([benchmark]),
        ..ContractGraphSnapshot::default()
    };

    assert_eq!(validate_contract_graph(&snapshot), Vec::new());
}

#[test]
fn simd_runtime_v11_rejects_benchmark_scalar_code_that_declares_simd() {
    let (artifact, store, mut scalar_code, _capabilities) = running_store_and_code();
    let feature_set = target_feature_set_record();
    scalar_code.simd_requirement = CodeObjectSimdRequirement::declared_simd(
        "riscv-v",
        32,
        128,
        feature_set.object_ref(),
        "bad v11 scalar benchmark code",
    );
    scalar_code.generation += 1;
    let mut vector_code = scalar_code.clone();
    vector_code.id += 1;
    vector_code.generation += 1;
    let benchmark = SimdBenchmarkRecord {
        id: 22_011,
        target_feature_set: feature_set.object_ref(),
        scalar_code_object: scalar_code.object_ref(),
        vector_code_object: vector_code.object_ref(),
        simd_abi: "riscv-v".to_string(),
        vector_register_count: 32,
        vector_register_bits: 128,
        workload_units: 4096,
        scalar_nanos: 120_000,
        vector_nanos: 40_000,
        speedup_milli: 3000,
        context_overhead_nanos: 80_000,
        generation: 1,
        state: SimdBenchmarkState::Recorded,
        recorded_at_event: 99,
        note: "bad v11 scalar/vector benchmark".to_string(),
    };
    let snapshot = ContractGraphSnapshot {
        artifacts: Vec::from([artifact]),
        code_objects: Vec::from([scalar_code, vector_code]),
        target_feature_sets: Vec::from([feature_set]),
        stores: Vec::from([store.store]),
        simd_benchmarks: Vec::from([benchmark]),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "simd-benchmark->scalar-code"
            && violation.kind == ContractViolationKind::ExternalEdgeMetadataMismatch
    }));
}

#[test]
fn simd_runtime_v12_context_switch_benchmark_validates_preempt_resume_vector_refs() {
    let (artifact, store, code, _capabilities) = running_store_and_code();
    let feature_set = target_feature_set_record();
    let activation = ActivationRecord {
        id: 11,
        store: store.store.id,
        store_generation: store.store.generation,
        code_object: code.id,
        code_generation: code.generation,
        artifact: artifact.artifact_id,
        entry: ActivationEntry::Symbol("v12_vector_context_switch".to_string()),
        generation: 5,
        state: ActivationState::Running,
        start_event: 1,
        exit_event: None,
        active_dmw_leases: 0,
        blocked_wait: None,
        trap: None,
        return_tag: None,
    };
    let preemption = PreemptionRecord {
        id: 9_070,
        activation: activation.id,
        activation_generation_before: 3,
        activation_generation_after: 4,
        timer_interrupt: 9_070,
        timer_interrupt_generation: 1,
        queue: 9_070,
        queue_generation: 2,
        generation: 1,
        state: PreemptionState::Applied,
        preempted_at_event: 10,
        note: "v12 preempt benchmark fixture".to_string(),
    };
    let saved_vector_state = VectorStateRecord {
        id: 22_002,
        owner_activation: ContractObjectRef::new(ContractObjectKind::Activation, 11, 5),
        owner_store: ContractObjectRef::new(
            ContractObjectKind::Store,
            store.store.id,
            store.store.generation,
        ),
        code_object: code.object_ref(),
        target_feature_set: feature_set.object_ref(),
        simd_abi: "riscv-v".to_string(),
        vector_register_count: 32,
        vector_register_bits: 128,
        register_bytes: 512,
        generation: 1,
        state: VectorStateState::Dropped,
        recorded_at_event: 11,
        note: "v12 saved vector state".to_string(),
    };
    let restored_vector_state = VectorStateRecord {
        id: 22_003,
        owner_activation: ContractObjectRef::new(ContractObjectKind::Activation, 11, 5),
        owner_store: ContractObjectRef::new(
            ContractObjectKind::Store,
            store.store.id,
            store.store.generation,
        ),
        code_object: code.object_ref(),
        target_feature_set: feature_set.object_ref(),
        simd_abi: "riscv-v".to_string(),
        vector_register_count: 32,
        vector_register_bits: 128,
        register_bytes: 512,
        generation: 1,
        state: VectorStateState::Reserved,
        recorded_at_event: 12,
        note: "v12 restored vector state".to_string(),
    };
    let resume = ActivationResumeRecord {
        id: 9_071,
        scheduler_decision: 9_071,
        scheduler_decision_generation: 1,
        activation: activation.id,
        activation_generation_before: 4,
        activation_generation_after: 5,
        owner_task: 9_070,
        owner_task_generation: 1,
        queue: 9_070,
        queue_generation: 2,
        context: Some(9_070),
        context_generation_before: Some(4),
        context_generation_after: Some(5),
        saved_context: Some(9_070),
        saved_context_generation: Some(2),
        saved_vector_state: Some(saved_vector_state.object_ref()),
        restored_vector_state: Some(restored_vector_state.object_ref()),
        vector_status: ActivationVectorState::Clean,
        vector_restored_at_event: Some(13),
        generation: 1,
        state: ActivationResumeState::Applied,
        resumed_at_event: 13,
        note: "v12 resume benchmark fixture".to_string(),
    };
    let benchmark = SimdContextSwitchBenchmarkRecord {
        id: 22_012,
        preemption: preemption.object_ref(),
        activation_resume: resume.object_ref(),
        saved_vector_state: saved_vector_state.object_ref(),
        restored_vector_state: restored_vector_state.object_ref(),
        target_feature_set: feature_set.object_ref(),
        simd_abi: "riscv-v".to_string(),
        vector_register_count: 32,
        vector_register_bits: 128,
        sample_count: 64,
        scalar_context_switch_nanos: 30_000,
        vector_context_switch_nanos: 46_384,
        overhead_nanos: 16_384,
        budget_nanos: 50_000,
        generation: 1,
        state: SimdContextSwitchBenchmarkState::Recorded,
        recorded_at_event: 99,
        note: "v12 context switch benchmark".to_string(),
    };
    let snapshot = ContractGraphSnapshot {
        artifacts: Vec::from([artifact]),
        code_objects: Vec::from([code]),
        target_feature_sets: Vec::from([feature_set]),
        vector_states: Vec::from([saved_vector_state, restored_vector_state]),
        simd_context_switch_benchmarks: Vec::from([benchmark]),
        preemptions: Vec::from([preemption]),
        activation_resumes: Vec::from([resume]),
        stores: Vec::from([store.store]),
        activations: Vec::from([activation]),
        ..ContractGraphSnapshot::default()
    };

    assert_eq!(validate_contract_graph(&snapshot), Vec::new());
}

#[test]
fn simd_runtime_v12_rejects_benchmark_resume_vector_mismatch() {
    let (artifact, store, code, _capabilities) = running_store_and_code();
    let feature_set = target_feature_set_record();
    let activation = ActivationRecord {
        id: 11,
        store: store.store.id,
        store_generation: store.store.generation,
        code_object: code.id,
        code_generation: code.generation,
        artifact: artifact.artifact_id,
        entry: ActivationEntry::Symbol("v12_vector_context_switch".to_string()),
        generation: 5,
        state: ActivationState::Running,
        start_event: 1,
        exit_event: None,
        active_dmw_leases: 0,
        blocked_wait: None,
        trap: None,
        return_tag: None,
    };
    let preemption = PreemptionRecord {
        id: 9_070,
        activation: activation.id,
        activation_generation_before: 3,
        activation_generation_after: 4,
        timer_interrupt: 9_070,
        timer_interrupt_generation: 1,
        queue: 9_070,
        queue_generation: 2,
        generation: 1,
        state: PreemptionState::Applied,
        preempted_at_event: 10,
        note: "v12 preempt benchmark fixture".to_string(),
    };
    let saved_vector_state = VectorStateRecord {
        id: 22_002,
        owner_activation: ContractObjectRef::new(ContractObjectKind::Activation, 11, 5),
        owner_store: ContractObjectRef::new(
            ContractObjectKind::Store,
            store.store.id,
            store.store.generation,
        ),
        code_object: code.object_ref(),
        target_feature_set: feature_set.object_ref(),
        simd_abi: "riscv-v".to_string(),
        vector_register_count: 32,
        vector_register_bits: 128,
        register_bytes: 512,
        generation: 1,
        state: VectorStateState::Dropped,
        recorded_at_event: 11,
        note: "v12 saved vector state".to_string(),
    };
    let restored_vector_state = VectorStateRecord {
        id: 22_003,
        owner_activation: ContractObjectRef::new(ContractObjectKind::Activation, 11, 5),
        owner_store: ContractObjectRef::new(
            ContractObjectKind::Store,
            store.store.id,
            store.store.generation,
        ),
        code_object: code.object_ref(),
        target_feature_set: feature_set.object_ref(),
        simd_abi: "riscv-v".to_string(),
        vector_register_count: 32,
        vector_register_bits: 128,
        register_bytes: 512,
        generation: 1,
        state: VectorStateState::Reserved,
        recorded_at_event: 12,
        note: "v12 restored vector state".to_string(),
    };
    let resume = ActivationResumeRecord {
        id: 9_071,
        scheduler_decision: 9_071,
        scheduler_decision_generation: 1,
        activation: activation.id,
        activation_generation_before: 4,
        activation_generation_after: 5,
        owner_task: 9_070,
        owner_task_generation: 1,
        queue: 9_070,
        queue_generation: 2,
        context: Some(9_070),
        context_generation_before: Some(4),
        context_generation_after: Some(5),
        saved_context: Some(9_070),
        saved_context_generation: Some(2),
        saved_vector_state: Some(saved_vector_state.object_ref()),
        restored_vector_state: None,
        vector_status: ActivationVectorState::Clean,
        vector_restored_at_event: Some(13),
        generation: 1,
        state: ActivationResumeState::Applied,
        resumed_at_event: 13,
        note: "bad v12 resume benchmark fixture".to_string(),
    };
    let benchmark = SimdContextSwitchBenchmarkRecord {
        id: 22_012,
        preemption: preemption.object_ref(),
        activation_resume: resume.object_ref(),
        saved_vector_state: saved_vector_state.object_ref(),
        restored_vector_state: restored_vector_state.object_ref(),
        target_feature_set: feature_set.object_ref(),
        simd_abi: "riscv-v".to_string(),
        vector_register_count: 32,
        vector_register_bits: 128,
        sample_count: 64,
        scalar_context_switch_nanos: 30_000,
        vector_context_switch_nanos: 46_384,
        overhead_nanos: 16_384,
        budget_nanos: 50_000,
        generation: 1,
        state: SimdContextSwitchBenchmarkState::Recorded,
        recorded_at_event: 99,
        note: "bad v12 context switch benchmark".to_string(),
    };
    let snapshot = ContractGraphSnapshot {
        artifacts: Vec::from([artifact]),
        code_objects: Vec::from([code]),
        target_feature_sets: Vec::from([feature_set]),
        vector_states: Vec::from([saved_vector_state, restored_vector_state]),
        simd_context_switch_benchmarks: Vec::from([benchmark]),
        preemptions: Vec::from([preemption]),
        activation_resumes: Vec::from([resume]),
        stores: Vec::from([store.store]),
        activations: Vec::from([activation]),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);

    assert!(violations.iter().any(|violation| {
        violation.edge == "simd-context-switch-benchmark->activation-resume"
            && violation.kind == ContractViolationKind::ExternalEdgeMetadataMismatch
    }));
}

#[test]
fn simd_runtime_v4_vector_state_edges_validate_exact_generations() {
    let (artifact, store, mut code, _capabilities) = running_store_and_code();
    let feature_set = target_feature_set_record();
    code.simd_requirement = CodeObjectSimdRequirement::declared_simd(
        "riscv-v",
        32,
        128,
        feature_set.object_ref(),
        "v4 vector state object",
    );
    code.generation += 1;
    let mut executor = TargetExecutor::new();
    executor
        .start_activation(
            &store.store,
            &code,
            ActivationEntry::Symbol("simd_vector_state".to_string()),
        )
        .unwrap();
    let activation = executor.activations()[0].clone();
    let vector_state = VectorStateRecord {
        id: 22_000,
        owner_activation: activation.object_ref(),
        owner_store: store.store.object_ref(),
        code_object: code.object_ref(),
        target_feature_set: feature_set.object_ref(),
        simd_abi: "riscv-v".to_string(),
        vector_register_count: 32,
        vector_register_bits: 128,
        register_bytes: 512,
        generation: 1,
        state: VectorStateState::Reserved,
        recorded_at_event: 1,
        note: "v4 vector state object".to_string(),
    };
    let snapshot = ContractGraphSnapshot {
        artifacts: Vec::from([artifact]),
        code_objects: Vec::from([code]),
        target_feature_sets: Vec::from([feature_set]),
        vector_states: Vec::from([vector_state]),
        stores: Vec::from([store.store]),
        activations: executor.activations().to_vec(),
        ..ContractGraphSnapshot::default()
    };
    assert_eq!(validate_contract_graph(&snapshot), Vec::new());
}

#[test]
fn simd_runtime_v4_rejects_live_vector_state_owned_by_dead_activation() {
    let (artifact, store, mut code, _capabilities) = running_store_and_code();
    let feature_set = target_feature_set_record();
    code.simd_requirement = CodeObjectSimdRequirement::declared_simd(
        "riscv-v",
        32,
        128,
        feature_set.object_ref(),
        "v4 vector state object",
    );
    code.generation += 1;
    let mut executor = TargetExecutor::new();
    executor
        .start_activation(
            &store.store,
            &code,
            ActivationEntry::Symbol("simd_vector_state".to_string()),
        )
        .unwrap();
    let mut activation = executor.activations()[0].clone();
    activation.state = ActivationState::Dropped;
    let vector_state = VectorStateRecord {
        id: 22_000,
        owner_activation: activation.object_ref(),
        owner_store: store.store.object_ref(),
        code_object: code.object_ref(),
        target_feature_set: feature_set.object_ref(),
        simd_abi: "riscv-v".to_string(),
        vector_register_count: 32,
        vector_register_bits: 128,
        register_bytes: 512,
        generation: 1,
        state: VectorStateState::Reserved,
        recorded_at_event: 1,
        note: "v4 vector state object".to_string(),
    };
    let snapshot = ContractGraphSnapshot {
        artifacts: Vec::from([artifact]),
        code_objects: Vec::from([code]),
        target_feature_sets: Vec::from([feature_set]),
        vector_states: Vec::from([vector_state]),
        stores: Vec::from([store.store]),
        activations: Vec::from([activation]),
        ..ContractGraphSnapshot::default()
    };
    let violations = validate_contract_graph(&snapshot);
    assert!(violations.iter().any(|violation| {
        violation.edge == "vector-state->activation"
            && violation.kind == ContractViolationKind::LiveEdgeReferencesInactiveObject
    }));
}

#[test]
fn cleanup_targets_exact_store_generation() {
    let (_artifact, mut store, mut code, mut capabilities) = running_store_and_code();
    let mut executor = TargetExecutor::new();
    let activation = executor
        .start_activation(
            &store.store,
            &code,
            ActivationEntry::Symbol("entry_trap_ebreak".to_string()),
        )
        .unwrap();
    let offset = target_abi::RV64_ENTRY_TRAP_EBREAK_OFFSET;
    let trap_map = [TrapMapEntryV1::new(
        ObjectRefRaw::new(OBJECT_KIND_CODE_OBJECT_V1, code.id, code.generation),
        offset,
        offset + 4,
        TrapKindV1::WasmUnreachable,
        1,
        0x20,
        7,
    )];
    executor.trap_exit_by_pc(activation, &code, code.text.start + offset, &trap_map).unwrap();
    let fault_generation = store.store.generation;

    let cleanup_id = executor
        .run_fault_cleanup(
            &mut store.store,
            Some(activation),
            Some(&mut code),
            &mut capabilities,
            "trap-cleanup",
        )
        .unwrap();
    let cleanup =
        executor.cleanup_transactions().iter().find(|cleanup| cleanup.id == cleanup_id).unwrap();

    assert_eq!(cleanup.store_generation, fault_generation);
    assert_eq!(cleanup.result_store_generation, Some(fault_generation + 1));
}

#[test]
fn trap_exit_rejects_code_object_attribution_mismatch() {
    let (_artifact, store, code, _capabilities) = running_store_and_code();
    let mut executor = TargetExecutor::new();
    let activation = executor
        .start_activation(
            &store.store,
            &code,
            ActivationEntry::Symbol("entry_trap_ebreak".to_string()),
        )
        .unwrap();
    let mut wrong_code = code.clone();
    wrong_code.id += 1;
    let offset = target_abi::RV64_ENTRY_TRAP_EBREAK_OFFSET;
    let trap_map = [TrapMapEntryV1::new(
        ObjectRefRaw::new(OBJECT_KIND_CODE_OBJECT_V1, wrong_code.id, wrong_code.generation),
        offset,
        offset + 4,
        TrapKindV1::WasmUnreachable,
        1,
        0x20,
        7,
    )];

    let result = executor.trap_exit_by_pc(
        activation,
        &wrong_code,
        wrong_code.text.start + offset,
        &trap_map,
    );

    assert_eq!(result, Err(TargetExecutorError::CodeObjectMismatch));
    let trap = executor.traps().last().expect("mismatch trap is visible");
    assert_eq!(trap.class, TargetTrapClass::CodeObjectTrap);
    assert_eq!(trap.fault_policy, "trap-attribution-failure");
    assert_eq!(trap.activation, Some(activation));
    assert!(trap.activation_generation.is_some());
}
