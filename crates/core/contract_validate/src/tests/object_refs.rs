use super::*;

#[test]
fn object_ref_rejects_null_identity() {
    assert!(ObjectRef::new(ObjectKind::Store, 0, 1).is_err());
    assert!(ObjectRef::new(ObjectKind::Store, 1, 0).is_err());
    assert!(ObjectRef::new(ObjectKind::External, 1, 0).is_ok());
}

#[test]
fn same_id_different_generation_is_distinct() {
    let first = ObjectRef::new(ObjectKind::Store, 7, 1).unwrap();
    let second = ObjectRef::new(ObjectKind::Store, 7, 2).unwrap();

    assert_ne!(first, second);
}

#[test]
fn typed_object_kind_mismatch_is_detected() {
    let cap = ObjectRef::new(ObjectKind::Capability, 3, 1).unwrap();

    assert!(matches!(
        StoreRef::try_from_ref(cap),
        Err(TypedRefError::KindMismatch {
            expected: ObjectKind::Store,
            actual: ObjectKind::Capability,
        })
    ));
    assert!(CapabilityRef::try_from_ref(cap).is_ok());
    let saved = ObjectRef::new(ObjectKind::SavedContext, 4, 1).unwrap();
    assert!(SavedContextRef::try_from_ref(saved).is_ok());
    assert!(matches!(
        ActivationContextRef::try_from_ref(saved),
        Err(TypedRefError::KindMismatch {
            expected: ObjectKind::ActivationContext,
            actual: ObjectKind::SavedContext,
        })
    ));
    let timer = ObjectRef::new(ObjectKind::TimerInterrupt, 5, 1).unwrap();
    assert!(TimerInterruptRef::try_from_ref(timer).is_ok());
    let ipi = ObjectRef::new(ObjectKind::IpiEvent, 6, 1).unwrap();
    assert!(IpiEventRef::try_from_ref(ipi).is_ok());
    let remote_preempt = ObjectRef::new(ObjectKind::RemotePreempt, 6, 1).unwrap();
    assert!(RemotePreemptRef::try_from_ref(remote_preempt).is_ok());
    let remote_park = ObjectRef::new(ObjectKind::RemotePark, 6, 1).unwrap();
    assert!(RemoteParkRef::try_from_ref(remote_park).is_ok());
    let preemption = ObjectRef::new(ObjectKind::Preemption, 6, 1).unwrap();
    assert!(PreemptionRef::try_from_ref(preemption).is_ok());
    let decision = ObjectRef::new(ObjectKind::SchedulerDecision, 7, 1).unwrap();
    assert!(SchedulerDecisionRef::try_from_ref(decision).is_ok());
    let cross_decision = ObjectRef::new(ObjectKind::CrossHartSchedulerDecision, 8, 1).unwrap();
    assert!(CrossHartSchedulerDecisionRef::try_from_ref(cross_decision).is_ok());
    let migration = ObjectRef::new(ObjectKind::ActivationMigration, 9, 1).unwrap();
    assert!(ActivationMigrationRef::try_from_ref(migration).is_ok());
    let safe_point = ObjectRef::new(ObjectKind::SmpSafePoint, 10, 1).unwrap();
    assert!(SmpSafePointRef::try_from_ref(safe_point).is_ok());
    let rendezvous = ObjectRef::new(ObjectKind::StopTheWorldRendezvous, 11, 1).unwrap();
    assert!(StopTheWorldRendezvousRef::try_from_ref(rendezvous).is_ok());
    let code_publish_barrier = ObjectRef::new(ObjectKind::SmpCodePublishBarrier, 12, 1).unwrap();
    assert!(SmpCodePublishBarrierRef::try_from_ref(code_publish_barrier).is_ok());
    let cleanup_quiescence = ObjectRef::new(ObjectKind::SmpCleanupQuiescence, 13, 1).unwrap();
    assert!(SmpCleanupQuiescenceRef::try_from_ref(cleanup_quiescence).is_ok());
    let snapshot_barrier = ObjectRef::new(ObjectKind::SmpSnapshotBarrier, 14, 1).unwrap();
    assert!(SmpSnapshotBarrierRef::try_from_ref(snapshot_barrier).is_ok());
    let stress_run = ObjectRef::new(ObjectKind::SmpStressRun, 15, 1).unwrap();
    assert!(SmpStressRunRef::try_from_ref(stress_run).is_ok());
    let scaling_benchmark = ObjectRef::new(ObjectKind::SmpScalingBenchmark, 16, 1).unwrap();
    assert!(SmpScalingBenchmarkRef::try_from_ref(scaling_benchmark).is_ok());
    let integrated_smp = ObjectRef::new(ObjectKind::IntegratedSmpPreemptionCleanup, 17, 1).unwrap();
    assert!(IntegratedSmpPreemptionCleanupRef::try_from_ref(integrated_smp).is_ok());
    let integrated_network_fault =
        ObjectRef::new(ObjectKind::IntegratedSmpNetworkFault, 18, 1).unwrap();
    assert!(IntegratedSmpNetworkFaultRef::try_from_ref(integrated_network_fault).is_ok());
    let integrated_disk_fault =
        ObjectRef::new(ObjectKind::IntegratedDiskPreemptFault, 19, 1).unwrap();
    assert!(IntegratedDiskPreemptFaultRef::try_from_ref(integrated_disk_fault).is_ok());
    let integrated_simd_migration =
        ObjectRef::new(ObjectKind::IntegratedSimdMigration, 20, 1).unwrap();
    assert!(IntegratedSimdMigrationRef::try_from_ref(integrated_simd_migration).is_ok());
    let integrated_network_disk_io =
        ObjectRef::new(ObjectKind::IntegratedNetworkDiskIo, 21, 1).unwrap();
    assert!(IntegratedNetworkDiskIoRef::try_from_ref(integrated_network_disk_io).is_ok());
    let integrated_display_scheduler_load =
        ObjectRef::new(ObjectKind::IntegratedDisplaySchedulerLoad, 22, 1).unwrap();
    assert!(
        IntegratedDisplaySchedulerLoadRef::try_from_ref(integrated_display_scheduler_load).is_ok()
    );
    let integrated_snapshot_io_lease_barrier =
        ObjectRef::new(ObjectKind::IntegratedSnapshotIoLeaseBarrier, 23, 1).unwrap();
    assert!(
        IntegratedSnapshotIoLeaseBarrierRef::try_from_ref(integrated_snapshot_io_lease_barrier)
            .is_ok()
    );
    let integrated_code_publish_smp_workload =
        ObjectRef::new(ObjectKind::IntegratedCodePublishSmpWorkload, 24, 1).unwrap();
    assert!(
        IntegratedCodePublishSmpWorkloadRef::try_from_ref(integrated_code_publish_smp_workload,)
            .is_ok()
    );
    let integrated_display_panic =
        ObjectRef::new(ObjectKind::IntegratedDisplayPanic, 25, 1).unwrap();
    assert!(IntegratedDisplayPanicRef::try_from_ref(integrated_display_panic).is_ok());
    let integrated_osctl_trace_replay =
        ObjectRef::new(ObjectKind::IntegratedOsctlTraceReplay, 26, 1).unwrap();
    assert!(IntegratedOsctlTraceReplayRef::try_from_ref(integrated_osctl_trace_replay).is_ok());
    let device_object = ObjectRef::new(ObjectKind::DeviceObject, 17, 1).unwrap();
    assert!(DeviceObjectRef::try_from_ref(device_object).is_ok());
    let packet_device_object = ObjectRef::new(ObjectKind::PacketDeviceObject, 30, 1).unwrap();
    assert!(PacketDeviceObjectRef::try_from_ref(packet_device_object).is_ok());
    let packet_buffer_object = ObjectRef::new(ObjectKind::PacketBufferObject, 31, 1).unwrap();
    assert!(PacketBufferObjectRef::try_from_ref(packet_buffer_object).is_ok());
    let packet_queue_object = ObjectRef::new(ObjectKind::PacketQueueObject, 32, 1).unwrap();
    assert!(PacketQueueObjectRef::try_from_ref(packet_queue_object).is_ok());
    let packet_descriptor_object =
        ObjectRef::new(ObjectKind::PacketDescriptorObject, 33, 1).unwrap();
    assert!(PacketDescriptorObjectRef::try_from_ref(packet_descriptor_object).is_ok());
    let fake_net_backend_object = ObjectRef::new(ObjectKind::FakeNetBackendObject, 34, 1).unwrap();
    assert!(FakeNetBackendObjectRef::try_from_ref(fake_net_backend_object).is_ok());
    let virtio_net_backend_object =
        ObjectRef::new(ObjectKind::VirtioNetBackendObject, 35, 1).unwrap();
    assert!(VirtioNetBackendObjectRef::try_from_ref(virtio_net_backend_object).is_ok());
    let network_rx_interrupt = ObjectRef::new(ObjectKind::NetworkRxInterrupt, 36, 1).unwrap();
    assert!(NetworkRxInterruptRef::try_from_ref(network_rx_interrupt).is_ok());
    let network_rx_wait_resolution =
        ObjectRef::new(ObjectKind::NetworkRxWaitResolution, 37, 1).unwrap();
    assert!(NetworkRxWaitResolutionRef::try_from_ref(network_rx_wait_resolution).is_ok());
    let network_tx_capability_gate =
        ObjectRef::new(ObjectKind::NetworkTxCapabilityGate, 38, 1).unwrap();
    assert!(NetworkTxCapabilityGateRef::try_from_ref(network_tx_capability_gate).is_ok());
    let network_tx_completion = ObjectRef::new(ObjectKind::NetworkTxCompletion, 39, 1).unwrap();
    assert!(NetworkTxCompletionRef::try_from_ref(network_tx_completion).is_ok());
    let network_stack_adapter = ObjectRef::new(ObjectKind::NetworkStackAdapter, 40, 1).unwrap();
    assert!(NetworkStackAdapterRef::try_from_ref(network_stack_adapter).is_ok());
    let socket_object = ObjectRef::new(ObjectKind::SocketObject, 41, 1).unwrap();
    assert!(SocketObjectRef::try_from_ref(socket_object).is_ok());
    let endpoint_object = ObjectRef::new(ObjectKind::EndpointObject, 42, 1).unwrap();
    assert!(EndpointObjectRef::try_from_ref(endpoint_object).is_ok());
    let socket_operation = ObjectRef::new(ObjectKind::SocketOperation, 43, 1).unwrap();
    assert!(SocketOperationRef::try_from_ref(socket_operation).is_ok());
    let socket_wait = ObjectRef::new(ObjectKind::SocketWait, 44, 1).unwrap();
    assert!(SocketWaitRef::try_from_ref(socket_wait).is_ok());
    let network_backpressure = ObjectRef::new(ObjectKind::NetworkBackpressure, 45, 1).unwrap();
    assert!(NetworkBackpressureRef::try_from_ref(network_backpressure).is_ok());
    let network_driver_cleanup = ObjectRef::new(ObjectKind::NetworkDriverCleanup, 46, 1).unwrap();
    assert!(NetworkDriverCleanupRef::try_from_ref(network_driver_cleanup).is_ok());
    let network_generation_audit =
        ObjectRef::new(ObjectKind::NetworkGenerationAudit, 47, 1).unwrap();
    assert!(NetworkGenerationAuditRef::try_from_ref(network_generation_audit).is_ok());
    let network_fault_injection = ObjectRef::new(ObjectKind::NetworkFaultInjection, 48, 1).unwrap();
    assert!(NetworkFaultInjectionRef::try_from_ref(network_fault_injection).is_ok());
    let network_benchmark = ObjectRef::new(ObjectKind::NetworkBenchmark, 49, 1).unwrap();
    assert!(NetworkBenchmarkRef::try_from_ref(network_benchmark).is_ok());
    let network_recovery_benchmark =
        ObjectRef::new(ObjectKind::NetworkRecoveryBenchmark, 50, 1).unwrap();
    assert!(NetworkRecoveryBenchmarkRef::try_from_ref(network_recovery_benchmark).is_ok());
    let block_device_object = ObjectRef::new(ObjectKind::BlockDeviceObject, 51, 1).unwrap();
    assert!(BlockDeviceObjectRef::try_from_ref(block_device_object).is_ok());
    let block_range_object = ObjectRef::new(ObjectKind::BlockRangeObject, 52, 1).unwrap();
    assert!(BlockRangeObjectRef::try_from_ref(block_range_object).is_ok());
    let block_request_object = ObjectRef::new(ObjectKind::BlockRequestObject, 53, 1).unwrap();
    assert!(BlockRequestObjectRef::try_from_ref(block_request_object).is_ok());
    let block_completion_object = ObjectRef::new(ObjectKind::BlockCompletionObject, 54, 1).unwrap();
    assert!(BlockCompletionObjectRef::try_from_ref(block_completion_object).is_ok());
    let block_wait = ObjectRef::new(ObjectKind::BlockWait, 55, 1).unwrap();
    assert!(BlockWaitRef::try_from_ref(block_wait).is_ok());
    let fake_block_backend_object =
        ObjectRef::new(ObjectKind::FakeBlockBackendObject, 56, 1).unwrap();
    assert!(FakeBlockBackendObjectRef::try_from_ref(fake_block_backend_object).is_ok());
    let virtio_blk_backend_object =
        ObjectRef::new(ObjectKind::VirtioBlkBackendObject, 57, 1).unwrap();
    assert!(VirtioBlkBackendObjectRef::try_from_ref(virtio_blk_backend_object).is_ok());
    let block_read_path = ObjectRef::new(ObjectKind::BlockReadPath, 58, 1).unwrap();
    assert!(BlockReadPathRef::try_from_ref(block_read_path).is_ok());
    let block_write_path = ObjectRef::new(ObjectKind::BlockWritePath, 59, 1).unwrap();
    assert!(BlockWritePathRef::try_from_ref(block_write_path).is_ok());
    let block_request_queue = ObjectRef::new(ObjectKind::BlockRequestQueue, 60, 1).unwrap();
    assert!(BlockRequestQueueRef::try_from_ref(block_request_queue).is_ok());
    let block_dma_buffer = ObjectRef::new(ObjectKind::BlockDmaBuffer, 61, 1).unwrap();
    assert!(BlockDmaBufferRef::try_from_ref(block_dma_buffer).is_ok());
    let block_page_object = ObjectRef::new(ObjectKind::BlockPageObject, 62, 1).unwrap();
    assert!(BlockPageObjectRef::try_from_ref(block_page_object).is_ok());
    let buffer_cache_object = ObjectRef::new(ObjectKind::BufferCacheObject, 63, 1).unwrap();
    assert!(BufferCacheObjectRef::try_from_ref(buffer_cache_object).is_ok());
    let file_object = ObjectRef::new(ObjectKind::FileObject, 64, 1).unwrap();
    assert!(FileObjectRef::try_from_ref(file_object).is_ok());
    let directory_object = ObjectRef::new(ObjectKind::DirectoryObject, 65, 1).unwrap();
    assert!(DirectoryObjectRef::try_from_ref(directory_object).is_ok());
    let fat_adapter_object = ObjectRef::new(ObjectKind::FatAdapterObject, 66, 1).unwrap();
    assert!(FatAdapterObjectRef::try_from_ref(fat_adapter_object).is_ok());
    let ext4_adapter_object = ObjectRef::new(ObjectKind::Ext4AdapterObject, 67, 1).unwrap();
    assert!(Ext4AdapterObjectRef::try_from_ref(ext4_adapter_object).is_ok());
    let file_handle_capability = ObjectRef::new(ObjectKind::FileHandleCapability, 68, 1).unwrap();
    assert!(FileHandleCapabilityRef::try_from_ref(file_handle_capability).is_ok());
    let fs_wait = ObjectRef::new(ObjectKind::FsWait, 69, 1).unwrap();
    assert!(FsWaitRef::try_from_ref(fs_wait).is_ok());
    let block_driver_cleanup = ObjectRef::new(ObjectKind::BlockDriverCleanup, 70, 1).unwrap();
    assert!(BlockDriverCleanupRef::try_from_ref(block_driver_cleanup).is_ok());
    let block_pending_io_policy = ObjectRef::new(ObjectKind::BlockPendingIoPolicy, 71, 1).unwrap();
    assert!(BlockPendingIoPolicyRef::try_from_ref(block_pending_io_policy).is_ok());
    let block_request_generation_audit =
        ObjectRef::new(ObjectKind::BlockRequestGenerationAudit, 72, 1).unwrap();
    assert!(BlockRequestGenerationAuditRef::try_from_ref(block_request_generation_audit).is_ok());
    let block_benchmark = ObjectRef::new(ObjectKind::BlockBenchmark, 73, 1).unwrap();
    assert!(BlockBenchmarkRef::try_from_ref(block_benchmark).is_ok());
    let block_recovery_benchmark =
        ObjectRef::new(ObjectKind::BlockRecoveryBenchmark, 74, 1).unwrap();
    assert!(BlockRecoveryBenchmarkRef::try_from_ref(block_recovery_benchmark).is_ok());
    let target_feature_set = ObjectRef::new(ObjectKind::TargetFeatureSet, 75, 1).unwrap();
    assert!(TargetFeatureSetRef::try_from_ref(target_feature_set).is_ok());
    let vector_state = ObjectRef::new(ObjectKind::VectorState, 76, 1).unwrap();
    assert!(VectorStateRef::try_from_ref(vector_state).is_ok());
    let simd_fault_injection = ObjectRef::new(ObjectKind::SimdFaultInjection, 77, 1).unwrap();
    assert!(SimdFaultInjectionRef::try_from_ref(simd_fault_injection).is_ok());
    let simd_benchmark = ObjectRef::new(ObjectKind::SimdBenchmark, 78, 1).unwrap();
    assert!(SimdBenchmarkRef::try_from_ref(simd_benchmark).is_ok());
    let simd_context_switch_benchmark =
        ObjectRef::new(ObjectKind::SimdContextSwitchBenchmark, 79, 1).unwrap();
    assert!(SimdContextSwitchBenchmarkRef::try_from_ref(simd_context_switch_benchmark).is_ok());
    let framebuffer_object = ObjectRef::new(ObjectKind::FramebufferObject, 80, 1).unwrap();
    assert!(FramebufferObjectRef::try_from_ref(framebuffer_object).is_ok());
    let display_object = ObjectRef::new(ObjectKind::DisplayObject, 81, 1).unwrap();
    assert!(DisplayObjectRef::try_from_ref(display_object).is_ok());
    let display_capability = ObjectRef::new(ObjectKind::DisplayCapability, 82, 1).unwrap();
    assert!(DisplayCapabilityRef::try_from_ref(display_capability).is_ok());
    let framebuffer_window_lease =
        ObjectRef::new(ObjectKind::FramebufferWindowLease, 83, 1).unwrap();
    assert!(FramebufferWindowLeaseRef::try_from_ref(framebuffer_window_lease).is_ok());
    let framebuffer_mapping = ObjectRef::new(ObjectKind::FramebufferMapping, 84, 1).unwrap();
    assert!(FramebufferMappingRef::try_from_ref(framebuffer_mapping).is_ok());
    let framebuffer_write = ObjectRef::new(ObjectKind::FramebufferWrite, 85, 1).unwrap();
    assert!(FramebufferWriteRef::try_from_ref(framebuffer_write).is_ok());
    let framebuffer_flush_region =
        ObjectRef::new(ObjectKind::FramebufferFlushRegion, 86, 1).unwrap();
    assert!(FramebufferFlushRegionRef::try_from_ref(framebuffer_flush_region).is_ok());
    let framebuffer_dirty_region =
        ObjectRef::new(ObjectKind::FramebufferDirtyRegion, 87, 1).unwrap();
    assert!(FramebufferDirtyRegionRef::try_from_ref(framebuffer_dirty_region).is_ok());
    let display_event_log = ObjectRef::new(ObjectKind::DisplayEventLog, 88, 1).unwrap();
    assert!(DisplayEventLogRef::try_from_ref(display_event_log).is_ok());
    let display_cleanup = ObjectRef::new(ObjectKind::DisplayCleanup, 89, 1).unwrap();
    assert!(DisplayCleanupRef::try_from_ref(display_cleanup).is_ok());
    let display_snapshot_barrier =
        ObjectRef::new(ObjectKind::DisplaySnapshotBarrier, 90, 1).unwrap();
    assert!(DisplaySnapshotBarrierRef::try_from_ref(display_snapshot_barrier).is_ok());
    let display_panic_last_frame =
        ObjectRef::new(ObjectKind::DisplayPanicLastFrame, 91, 1).unwrap();
    assert!(DisplayPanicLastFrameRef::try_from_ref(display_panic_last_frame).is_ok());
    let framebuffer_benchmark = ObjectRef::new(ObjectKind::FramebufferBenchmark, 92, 1).unwrap();
    assert!(FramebufferBenchmarkRef::try_from_ref(framebuffer_benchmark).is_ok());
    let queue_object = ObjectRef::new(ObjectKind::QueueObject, 18, 1).unwrap();
    assert!(QueueObjectRef::try_from_ref(queue_object).is_ok());
    let descriptor_object = ObjectRef::new(ObjectKind::DescriptorObject, 19, 1).unwrap();
    assert!(DescriptorObjectRef::try_from_ref(descriptor_object).is_ok());
    let dma_buffer_object = ObjectRef::new(ObjectKind::DmaBufferObject, 20, 1).unwrap();
    assert!(DmaBufferObjectRef::try_from_ref(dma_buffer_object).is_ok());
    let mmio_region_object = ObjectRef::new(ObjectKind::MmioRegionObject, 21, 1).unwrap();
    assert!(MmioRegionObjectRef::try_from_ref(mmio_region_object).is_ok());
    let irq_line_object = ObjectRef::new(ObjectKind::IrqLineObject, 22, 1).unwrap();
    assert!(IrqLineObjectRef::try_from_ref(irq_line_object).is_ok());
    let irq_event = ObjectRef::new(ObjectKind::IrqEvent, 23, 1).unwrap();
    assert!(IrqEventRef::try_from_ref(irq_event).is_ok());
    let device_capability = ObjectRef::new(ObjectKind::DeviceCapability, 24, 1).unwrap();
    assert!(DeviceCapabilityRef::try_from_ref(device_capability).is_ok());
    let driver_binding = ObjectRef::new(ObjectKind::DriverStoreBinding, 25, 1).unwrap();
    assert!(DriverStoreBindingRef::try_from_ref(driver_binding).is_ok());
    let io_wait = ObjectRef::new(ObjectKind::IoWait, 26, 1).unwrap();
    assert!(IoWaitRef::try_from_ref(io_wait).is_ok());
    let io_cleanup = ObjectRef::new(ObjectKind::IoCleanup, 27, 1).unwrap();
    assert!(IoCleanupRef::try_from_ref(io_cleanup).is_ok());
    let io_fault = ObjectRef::new(ObjectKind::IoFaultInjection, 28, 1).unwrap();
    assert!(IoFaultInjectionRef::try_from_ref(io_fault).is_ok());
    let io_report = ObjectRef::new(ObjectKind::IoValidationReport, 29, 1).unwrap();
    assert!(IoValidationReportRef::try_from_ref(io_report).is_ok());
    let resume = ObjectRef::new(ObjectKind::ActivationResume, 8, 1).unwrap();
    assert!(ActivationResumeRef::try_from_ref(resume).is_ok());
    let activation_wait = ObjectRef::new(ObjectKind::ActivationWait, 9, 1).unwrap();
    assert!(ActivationWaitRef::try_from_ref(activation_wait).is_ok());
    let hart_event = ObjectRef::new(ObjectKind::HartEventAttribution, 10, 1).unwrap();
    assert!(HartEventAttributionRef::try_from_ref(hart_event).is_ok());
}

#[test]
fn tombstone_preserves_exact_generation() {
    let dead_store = ObjectRef::new(ObjectKind::Store, 9, 4).unwrap();
    let tombstone = TombstoneRecord::new(dead_store, 88, "cleanup-store-dead");

    assert_eq!(tombstone.object, dead_store);
    assert_eq!(tombstone.object.generation, 4);
    assert_eq!(tombstone.died_at_event, 88);
}

#[test]
fn schema_versions_are_referenced_by_views_edges_events_and_traces() {
    let store = StoreRef::new(1, 1).unwrap().object_ref();
    let code = CodeObjectRef::new(2, 1).unwrap().object_ref();
    let edge = ContractEdge::new(store, code, RefMode::Live, "store->code", 7);
    let view = StoreViewV1 {
        schema: VIEW_SCHEMA_V1,
        kind: ObjectKind::Store,
        object: store,
        state: "running".to_owned(),
        owner: None,
        references: vec![edge.clone()],
        last_transition: Some("bound->running".to_owned()),
        last_error: None,
    };

    assert_eq!(CONTRACT_SCHEMA_VERSION.name, "semantic-contract-v0.1");
    assert_eq!(CONTRACT_SCHEMA, CONTRACT_SCHEMA_VERSION.name);
    assert_eq!(view.schema, VIEW_SCHEMA_V1);
    assert_eq!(edge.mode, RefMode::Live);
    assert_eq!(EDGE_SCHEMA_V1, 1);
    assert_eq!(EVENT_SCHEMA_V1, 1);
    assert_eq!(TRACE_SCHEMA_V1, 1);
}
