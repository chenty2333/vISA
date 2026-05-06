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

mod contract_graph_cleanup;
mod registry_hostcall;
mod traps_simd;
